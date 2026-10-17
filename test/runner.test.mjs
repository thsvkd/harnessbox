// The runner end to end with real bubblewrap boxes and fake `claude`, `codex` and `grok` CLIs (test/fake-cli.mjs): detection, the
// three login kinds, status and logout, jobs and their failures, the watchdog, locks and slots, purge. socat is test/fake-socat. No
// network beyond the boxes' own loopback (the one CONNECT a fake makes goes to a denied host), no model, no real login.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Busy, claudeCode, codex, createRunner, grok } from '../src/index.mjs';

const HERE = import.meta.dirname;
const FAKE = { 'claude-code': join(HERE, 'fake-claude'), codex: join(HERE, 'fake-codex'), grok: join(HERE, 'fake-grok') };
const canBox = spawnSync('bwrap', ['--unshare-all', '--die-with-parent', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '/usr/bin/true']).status === 0;
const BOX = { skip: !canBox && 'needs bubblewrap with user namespaces' };
const CRED = { 'claude-code': '.claude/.credentials.json', codex: '.codex/auth.json', grok: '.grok/auth.json' };
const IDS = Object.keys(CRED);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function started(dir) {
  for (let i = 0; i < 100; i++) { if (existsSync(join(dir, 'seen.json'))) return; await sleep(30); }
  throw new Error('the fake CLI did not start');
}
process.env.ANTHROPIC_API_KEY = 'sk-ant-must-not-reach'; // the runner's environment never gets into a box
process.env.XAI_API_KEY = 'xai-must-not-reach';

async function world({ env = {}, ...o } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'hb-runner-test-')), homes = join(root, 'homes'), logs = [];
  let n = 0;
  const hb = await createRunner({ homes, adapters: [claudeCode, codex, grok], bins: FAKE, socat: join(HERE, 'fake-socat'), log: (l) => logs.push(l), passEnv: env, ...o });
  const home = (u, id) => join(homes, u, id);
  const logIn = (u, id) => { mkdirSync(join(home(u, id), CRED[id], '..'), { recursive: true }); writeFileSync(join(home(u, id), CRED[id]), '{"fake":true}'); };
  const job = () => { const d = join(root, `job-${n++}`); mkdirSync(d); return d; };
  const seen = (d) => JSON.parse(readFileSync(join(d, 'seen.json'), 'utf8'));
  return { hb, root, homes, logs, home, logIn, job, seen, close: () => { hb.close(); rmSync(root, { recursive: true, force: true }); } };
}

test('detect: version, help options and the harness\'s own checks in a box; a pin, an old CLI, a broken sandbox or a missing binary is not usable', BOX, async () => {
  let w = await world();
  try {
    const rows = await w.hb.detect();
    assert.deepEqual(rows.map((r) => [r.id, r.version, r.usable]), [['claude-code', '2.1.300', true], ['codex', '0.162.1', true], ['grok', '1.0.52', true]]);
    assert.deepEqual([...rows[1].has], ['--ignore-rules']);
    assert.ok(!existsSync(join(w.homes, '.probe', 'codex')), 'the probe home is removed');
  } finally { w.close(); }
  w = await world({ pins: { codex: '0.170.0' }, bins: { ...FAKE, grok: '/nonexistent/grok' }, env: { FAKE_HELP: 'old' } });
  try {
    const rows = await w.hb.detect();
    assert.deepEqual(rows.map((r) => [r.id, r.usable, r.why]), [['claude-code', false, 'missing options: --restricted'], ['codex', false, 'version 0.162.1, pinned 0.170.0'], ['grok', false, 'binary not found']]);
    await assert.rejects(w.hb.run('u1', 'codex', { prompt: 'x', dir: w.root }), /not usable/);
    assert.deepEqual(await w.hb.status('u1', 'grok'), { installed: false, loggedIn: false, method: null, plan: null });
  } finally { w.close(); }
  w = await world({ env: { FAKE_SANDBOX: 'fail' } });
  try {
    const row = (await w.hb.detect()).find((r) => r.id === 'codex');
    assert.equal(row.usable, false);
    assert.match(row.why, /sandbox does not start/);
  } finally { w.close(); }
});

test('watchdog stops a box that hides disk usage behind unreadable directory permissions', BOX, async () => {
  const w = await world({ maxBytes: 128 * 1024 });
  const dir = w.job();
  try {
    await w.hb.detect();
    w.logIn('alice', 'claude-code');
    const r = await w.hb.run('alice', 'claude-code', { prompt: 'FAKE_MODE=hidden-disk', dir });
    assert.notEqual(r.code, 0);
    assert.match(r.why, /inspect|EACCES|disk/i);
  } finally {
    if (existsSync(join(dir, 'hidden'))) chmodSync(join(dir, 'hidden'), 0o700);
    await w.close();
  }
});

test('concurrent detect calls serialize access to the shared probe homes', BOX, async () => {
  const w = await world();
  let peak = 0;
  const polling = setInterval(() => { peak = Math.max(peak, w.hb.boxes.size); }, 2);
  try {
    const results = await Promise.allSettled([w.hb.detect(), w.hb.detect()]);
    assert.ok(peak <= 1, `overlapping probe boxes: ${peak}`);
    for (const result of results) {
      assert.equal(result.status, 'fulfilled', result.reason?.message);
      assert.ok(result.value.every((r) => r.usable));
    }
  } finally { clearInterval(polling); await w.close(); }
});

test('run stops cumulative stdout at maxOutputBytes before retaining unlimited Grok text', BOX, async () => {
  const w = await world({ maxOutputBytes: 128 * 1024 });
  try {
    await w.hb.detect();
    w.logIn('alice', 'grok');
    const r = await w.hb.run('alice', 'grok', { prompt: 'FAKE_MODE=flood', dir: w.job() });
    assert.notEqual(r.code, 0);
    assert.match(r.why, /output/i);
    assert.ok(Buffer.byteLength(r.text) <= 128 * 1024);
  } finally { await w.close(); }
});

test('run applies the output budget to stderr as well as stdout', BOX, async () => {
  const w = await world({ maxOutputBytes: 128 * 1024 });
  try {
    await w.hb.detect();
    w.logIn('alice', 'claude-code');
    const r = await w.hb.run('alice', 'claude-code', { prompt: 'FAKE_MODE=stderr-flood', dir: w.job() });
    assert.notEqual(r.code, 0);
    assert.match(r.why, /output/i);
    assert.ok(r.stderr.length <= 4000);
  } finally { await w.close(); }
});

test('an output-limit violation cannot report success after a fast child has already exited', BOX, async () => {
  const w = await world({ maxOutputBytes: 1024 });
  try {
    await w.hb.detect();
    w.logIn('alice', 'claude-code');
    const r = await w.hb.run('alice', 'claude-code', {
      prompt: 'FAKE_MODE=burst-exit', dir: w.job(),
      onEvent: () => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 300); },
    });
    assert.match(r.why, /output/i);
    assert.notEqual(r.code, 0);
  } finally { await w.close(); }
});

test('login cancel also stops its follow-up authentication-status box', BOX, async () => {
  const marker = '.claude/status-verification';
  const w = await world({ env: { FAKE_STATUS_MARKER: marker } });
  let session;
  try {
    await w.hb.detect();
    session = w.hb.login('alice', 'claude-code');
    await session.waiting;
    session.submitCode('good-code');
    const path = join(w.home('alice', 'claude-code'), marker);
    for (let i = 0; i < 100 && !existsSync(path); i++) await sleep(30);
    assert.ok(existsSync(path), 'the follow-up status box started');
    session.cancel();
    const r = await Promise.race([session.done, sleep(500).then(() => null)]);
    assert.deepEqual(r, { ok: false, error: 'canceled' });
    assert.equal(w.hb.boxes.size, 0);
  } finally { w.hb.close(); await session?.done; await w.close(); }
});

test('run abort also stops authentication-status verification after a failed CLI', BOX, async () => {
  const marker = '.claude/status-verification';
  const w = await world({ env: { FAKE_STATUS_MARKER: marker } });
  let pending;
  try {
    await w.hb.detect();
    w.logIn('alice', 'claude-code');
    const ac = new AbortController();
    pending = w.hb.run('alice', 'claude-code', { prompt: 'FAKE_MODE=fail', dir: w.job(), signal: ac.signal });
    const path = join(w.home('alice', 'claude-code'), marker);
    for (let i = 0; i < 100 && !existsSync(path); i++) await sleep(30);
    assert.ok(existsSync(path), 'the failed run is verifying its login');
    ac.abort();
    const r = await Promise.race([pending, sleep(500).then(() => null)]);
    assert.equal(r?.canceled, true);
    assert.equal(r.code, -1);
    assert.equal(r.loggedIn, undefined, 'a canceled check must not misreport logout');
    assert.equal(w.hb.boxes.size, 0);
  } finally { w.hb.close(); await pending; await w.close(); }
});

test('run decodes Korean and emoji across stdout byte boundaries', BOX, async () => {
  const w = await world();
  try {
    await w.hb.detect();
    w.logIn('alice', 'claude-code');
    const r = await w.hb.run('alice', 'claude-code', { prompt: 'FAKE_MODE=unicode', dir: w.job() });
    assert.equal(r.text, '한글🙂');
  } finally { await w.close(); }
});

test('run aborts promptly while waiting for either a user lock or a global job slot', BOX, async () => {
  for (const queuedUser of ['alice', 'bob']) {
    const w = await world({ maxJobs: 1 });
    let first, queued;
    try {
      await w.hb.detect();
      w.logIn('alice', 'claude-code');
      const d1 = w.job(), d2 = w.job(), ac = new AbortController();
      first = w.hb.run('alice', 'claude-code', { prompt: 'FAKE_MODE=hang', dir: d1, timeoutMs: 5000 });
      await started(d1);
      queued = w.hb.run(queuedUser, 'claude-code', { prompt: 'x', dir: d2, signal: ac.signal });
      await sleep(50);
      ac.abort();
      const r = await Promise.race([queued, sleep(500).then(() => null)]);
      assert.equal(r?.canceled, true, `queued behind ${queuedUser === 'alice' ? 'lock' : 'slot'}`);
      assert.ok(!existsSync(join(d2, 'seen.json')));
      assert.equal(w.hb.boxes.size, 1, 'cancel did not stop the running job');
    } finally {
      w.hb.close();
      await Promise.allSettled([first, queued]);
      await w.close();
    }
  }
});

test('close settles active and queued jobs without launching any more boxes', BOX, async () => {
  const w = await world({ maxJobs: 1 });
  let first, queued;
  try {
    await w.hb.detect();
    for (const u of ['alice', 'bob']) w.logIn(u, 'claude-code');
    const d1 = w.job(), d2 = w.job();
    first = w.hb.run('alice', 'claude-code', { prompt: 'FAKE_MODE=hang', dir: d1 });
    await started(d1);
    queued = w.hb.run('bob', 'claude-code', { prompt: 'x', dir: d2 });
    await sleep(50);
    await w.hb.close();
    assert.equal((await first).canceled, true);
    assert.equal((await queued).canceled, true);
    assert.ok(!existsSync(join(d2, 'seen.json')));
    assert.equal(w.hb.boxes.size, 0);
    await assert.rejects(w.hb.run('bob', 'claude-code', { prompt: 'x', dir: w.job() }), /closed/);
    await assert.rejects(w.hb.exec('bob', 'claude-code', ['true']), /closed/);
    assert.throws(() => w.hb.login('bob', 'claude-code'), /closed/);
  } finally {
    w.hb.close();
    await Promise.allSettled([first, queued]);
    await w.close();
  }
});

test('close waits for in-flight preparation and prevents a box from starting after shutdown', BOX, async () => {
  const w = await world();
  let pending;
  try {
    await w.hb.detect();
    const dir = w.job();
    pending = w.hb.run('alice', 'claude-code', { prompt: 'x', dir });
    await w.hb.close();
    assert.equal((await pending).canceled, true);
    assert.ok(!existsSync(join(dir, 'seen.json')));
    assert.equal(w.hb.boxes.size, 0);
  } finally { w.hb.close(); await Promise.allSettled([pending]); await w.close(); }
});

test('runner refuses startup when its seccomp architecture is unsupported', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'arch');
  const root = mkdtempSync(join(tmpdir(), 'hb-arch-test-'));
  let hb;
  try {
    Object.defineProperty(process, 'arch', { value: 'unsupported' });
    await assert.rejects(async () => { hb = await createRunner({ homes: root, adapters: [] }); }, /seccomp/);
  } finally { Object.defineProperty(process, 'arch', descriptor); await hb?.close(); rmSync(root, { recursive: true, force: true }); }
});

test('runner rejects invalid resource limits and duplicate adapter identities at startup', async () => {
  const root = mkdtempSync(join(tmpdir(), 'hb-options-test-'));
  try {
    for (const bad of [{ maxJobs: 0 }, { maxJobs: 1.5 }, { maxQuick: -1 }, { maxProcs: Infinity }, { maxBytes: NaN },
      { maxEntries: 0 }, { maxOutputBytes: 0 }, { maxOutputBytes: NaN }, { adapters: [claudeCode, claudeCode] }]) {
      let hb;
      try {
        await assert.rejects(async () => { hb = await createRunner({ homes: root, adapters: [claudeCode], bins: FAKE, socat: join(HERE, 'fake-socat'), ...bad }); }, /positive|integer|duplicate/i);
      } finally { await hb?.close(); }
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('runner detects a missing bubblewrap or socat before accepting any work', async () => {
  const root = mkdtempSync(join(tmpdir(), 'hb-tools-test-'));
  try {
    for (const bad of [{ bwrap: '/nonexistent/hb-bwrap' }, { socat: '/nonexistent/hb-socat' }]) {
      let hb;
      try {
        await assert.rejects(async () => { hb = await createRunner({ homes: root, adapters: [], socat: join(HERE, 'fake-socat'), ...bad }); }, /not found/);
      } finally { await hb?.close(); }
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('async event-handler rejection does not terminate the runner process', BOX, () => {
  const root = mkdtempSync(join(tmpdir(), 'hb-event-test-'));
  try {
    const child = spawnSync(process.execPath, [join(HERE, 'async-event-check.mjs'), root], { encoding: 'utf8', timeout: 15000, env: { ...process.env, TMPDIR: root } });
    assert.equal(child.status, 0, child.stderr);
    assert.match(child.stdout, /event handler survived/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('login: paste code (Claude Code), device code (Codex, Grok on stderr with ANSI) into each user\'s own harness home; status and logout', BOX, async () => {
  const w = await world();
  try {
    await w.hb.detect();
    const c = w.hb.login('alice', 'claude-code');
    assert.deepEqual(await c.waiting, { url: 'https://claude.com/cai/oauth/authorize?code=true&state=fake-state', code: null, needsCode: true });
    assert.equal(c.submitCode('has space'), false, 'not a code');
    assert.equal(c.submitCode('good-code'), true);
    assert.equal(c.submitCode('good-code'), false, 'once');
    assert.deepEqual(await c.done, { ok: true, status: { installed: true, loggedIn: true, method: 'claude.ai', plan: 'max' } });
    assert.equal(c.state, 'done');
    const x = w.hb.login('bob', 'codex');
    assert.deepEqual(await x.waiting, { url: 'https://auth.openai.com/codex/device', code: 'FAKE-12345', needsCode: false });
    assert.equal(x.submitCode('FAKE-12345'), false, 'a device login takes no code');
    assert.equal((await x.done).ok, true);
    const g = w.hb.login('bob', 'grok');
    assert.deepEqual(await g.waiting, { url: 'https://accounts.x.ai/oauth2/device?user_code=FAKE-ABCD', code: 'FAKE-ABCD', needsCode: false });
    assert.deepEqual(await g.done, { ok: true, status: { installed: true, loggedIn: true, method: null, plan: null } });

    assert.deepEqual(readdirSync(w.homes).sort(), ['alice', 'bob']);
    assert.deepEqual(readdirSync(join(w.homes, 'alice')), ['claude-code'], 'one home per harness: no other CLI sees this login');
    assert.ok(existsSync(join(w.home('alice', 'claude-code'), CRED['claude-code'])) && existsSync(join(w.home('bob', 'codex'), CRED.codex)) && existsSync(join(w.home('bob', 'grok'), CRED.grok)));
    assert.equal(statSync(w.home('alice', 'claude-code')).mode & 0o777, 0o700);
    assert.equal(statSync(join(w.homes, 'alice')).mode & 0o777, 0o700);
    // the next box scrubs the login's leftovers: Claude's account keys stay, its planted mcpServers go
    assert.equal((await w.hb.status('alice', 'claude-code')).loggedIn, true);
    assert.deepEqual(JSON.parse(readFileSync(join(w.home('alice', 'claude-code'), '.claude.json'), 'utf8')), { oauthAccount: { emailAddress: 'someone@example.com' }, userID: 'u1' });
    assert.equal((await w.hb.status('alice', 'codex')).loggedIn, false);
    assert.deepEqual(await w.hb.status('bob', 'codex'), { installed: true, loggedIn: true, method: 'chatgpt', plan: null });
    for (const [u, id] of [['alice', 'claude-code'], ['bob', 'codex'], ['bob', 'grok']]) {
      assert.equal((await w.hb.logout(u, id)).loggedIn, false, id);
      assert.ok(!existsSync(join(w.home(u, id), CRED[id])));
    }
    assert.throws(() => w.hb.login('../x', 'codex'), /bad user id/);
    assert.throws(() => w.hb.login('alice', 'nope'), /unknown harness/);
  } finally { w.close(); }
});

test('login: a URL off the harness\'s login hosts, a wrong code, cancel and a newer login all end the login without a credential', BOX, async () => {
  let w = await world({ env: { FAKE_LOGIN_URL: 'https://evil.example/oauth?x=1' } });
  try {
    await w.hb.detect();
    const s = w.hb.login('alice', 'claude-code');
    await assert.rejects(s.waiting);
    assert.deepEqual(await s.done, { ok: false, error: 'the login URL is not on the harness\'s list of login hosts' });
    assert.equal(s.url, null);
  } finally { w.close(); }
  w = await world({ env: { FAKE_DEVICE_MS: '20000' } });
  try {
    await w.hb.detect();
    const bad = w.hb.login('alice', 'claude-code');
    await bad.waiting;
    bad.submitCode('wrong');
    assert.deepEqual(await bad.done, { ok: false, error: 'the login failed (exit 1)' });
    const a = w.hb.login('alice', 'codex');
    await a.waiting;
    const b = w.hb.login('alice', 'codex'); // the app forgot the first one: the new one wins
    assert.deepEqual(await a.done, { ok: false, error: 'canceled' });
    await b.waiting;
    b.cancel();
    assert.deepEqual(await b.done, { ok: false, error: 'canceled' });
    assert.equal(b.state, 'failed');
    assert.ok(!existsSync(join(w.home('alice', 'codex'), CRED.codex)) && !existsSync(join(w.home('alice', 'claude-code'), CRED['claude-code'])));
  } finally { w.close(); }
  w = await world({ env: { FAKE_LOGIN_NOURL: '1' } });
  try {
    await w.hb.detect();
    const s = w.hb.login('alice', 'claude-code');
    await assert.rejects(s.waiting, /without a URL/, 'waiting settles when the CLI ends before printing a URL');
    assert.equal((await s.done).ok, true);
  } finally { w.close(); }
});

test('run: each harness\'s hardened command in the user\'s own box, cleared environment, last message and usage; outsiders invisible', BOX, async () => {
  const w = await world();
  try {
    await w.hb.detect();
    for (const id of IDS) { w.logIn('alice', id); w.logIn('bob', id); }
    writeFileSync(join(w.home('bob', 'claude-code'), 'canary'), 'BOB');
    writeFileSync(join(w.root, 'canary'), 'ROOT');
    const expect = { 'claude-code': { input: 900, output: 300 }, codex: { input: 700, output: 200 }, grok: { input: 350, output: 70 } };
    for (const id of IDS) {
      const dir = w.job();
      const r = await w.hb.run('alice', id, { prompt: 'write it', dir, args: ['--extra-flag'], env: { FAKE_PEEK: [w.home('bob', 'claude-code'), w.home('alice', id === 'grok' ? 'codex' : 'grok'), join(w.root, 'canary'), '/var/run/docker.sock'].join(',') } });
      assert.deepEqual([r.code, r.text, r.usage, r.why, r.timedOut, r.canceled], [0, 'done (ok)', expect[id], null, false, false], id);
      const s = w.seen(dir);
      assert.equal(s.home, w.home('alice', id));
      assert.equal(s.cwd, dir);
      assert.equal(s.tmp, join(dir, '.tmp'));
      assert.ok(!s.env.includes('ANTHROPIC_API_KEY') && !s.env.includes('XAI_API_KEY') && s.env.includes('HTTPS_PROXY'), id);
      assert.deepEqual(Object.values(s.peek), [false, false, false, false], `${id}: ${JSON.stringify(s.peek)}`);
      assert.deepEqual([s.users, s.harnesses], [['alice'], [id]], 'the folders above the home are empty mount points');
      assert.equal(s.userns, id === 'codex', 'only Codex\'s box may make a user namespace (its own sandbox)');
      assert.ok(s.args.includes('--extra-flag'));
      if (id === 'claude-code') for (const f of ['--permission-mode', 'dontAsk', '--restricted', '--strict-mcp-config', '--no-session-persistence']) assert.ok(s.args.includes(f), f);
      if (id === 'codex') { assert.ok(s.args.includes('--ignore-rules') && s.args.includes('--ignore-user-config') && s.args.at(-1) === '-'); assert.equal(s.prompt, 'write it'); }
      if (id === 'grok') { assert.deepEqual(s.homeFiles, ['.grok', '.grok/auth.json', '.grok/config.toml']); assert.ok(s.env.includes('GROK_DISABLE_AUTOUPDATER')); }
    }
    await assert.rejects(w.hb.run('alice', 'grok', { prompt: '--help', dir: w.job() }), /not starting with "-"/);
    await assert.rejects(w.hb.run('alice', 'grok', { prompt: 'a\0b', dir: w.job() }), /not starting with "-"/);
    // lines that are JSON but no event, and usage that is no number, neither end the runner nor poison the count
    let r;
    for (const id of IDS) {
      r = await w.hb.run('alice', id, { prompt: 'FAKE_MODE=junk', dir: w.job(), onEvent: () => { throw new Error('a caller bug'); } });
      assert.deepEqual([r.code, r.text, r.usage], [0, 'done (junk)', expect[id]], id);
    }
    const ac = new AbortController();
    ac.abort();
    r = await w.hb.run('alice', 'codex', { prompt: 'x', dir: w.job(), signal: ac.signal });
    assert.deepEqual([r.canceled, r.code], [true, -1], 'aborted before it started: no box');
  } finally { w.close(); }
});

test('run: webSearch reaches each adapter\'s command in the box (Claude Code: WebSearch allowed, WebFetch and MCP denied; Codex: web_search=live); Grok refuses it', BOX, async () => {
  const w = await world();
  try {
    const rows = await w.hb.detect();
    assert.deepEqual(rows.map((r) => [r.id, r.webSearch]), [['claude-code', true], ['codex', true], ['grok', false]]);
    for (const id of IDS) w.logIn('alice', id);
    const argsOf = async (id, more) => { const dir = w.job(); const r = await w.hb.run('alice', id, { prompt: 'x', dir, ...more }); assert.equal(r.code, 0, id); return w.seen(dir).args; };
    for (const more of [{}, { webSearch: false }]) {
      const c = await argsOf('claude-code', more), x = await argsOf('codex', more);
      assert.deepEqual(c.slice(c.indexOf('--disallowedTools'), c.indexOf('--disallowedTools') + 4), ['--disallowedTools', 'WebFetch', 'WebSearch', 'mcp__*']);
      assert.ok(!c.includes('--allowedTools'));
      assert.ok(x.includes('web_search=disabled') && !x.includes('web_search=live'));
    }
    const c = await argsOf('claude-code', { webSearch: true, args: ['--allowedTools', 'Read(//work/**)'] });
    assert.deepEqual(c.slice(c.indexOf('--disallowedTools'), c.indexOf('--disallowedTools') + 5), ['--disallowedTools', 'WebFetch', 'mcp__*', '--allowedTools', 'WebSearch']);
    assert.deepEqual(c.slice(-2), ['--allowedTools', 'Read(//work/**)'], 'the caller\'s own rules follow');
    const x = await argsOf('codex', { webSearch: true });
    assert.ok(x.includes('web_search=live') && !x.includes('web_search=disabled') && x.includes('sandbox_workspace_write.network_access=false'));
    await assert.rejects(w.hb.run('alice', 'grok', { prompt: 'x', dir: w.job(), webSearch: true }), /Grok has no web search/);
    await assert.rejects(w.hb.run('alice', 'codex', { prompt: 'x', dir: w.job(), webSearch: 'yes' }), /webSearch must be true or false/);
  } finally { w.close(); }
});

test('run: failures, an expired or missing login, the time limit, a cancel, a fork bomb, a planted home, an egress attempt, a symlinked output', BOX, async () => {
  const w = await world({ maxProcs: 20, env: { FAKE_PROCS: '200' } });
  try {
    await w.hb.detect();
    for (const id of IDS) w.logIn('alice', id);
    let r = await w.hb.run('alice', 'codex', { prompt: 'FAKE_MODE=fail', dir: w.job() });
    assert.deepEqual([r.code, r.loggedIn, r.usage.unknown], [3, true, true], 'a failure with the login intact');
    r = await w.hb.run('alice', 'claude-code', { prompt: 'FAKE_MODE=expired', dir: w.job() });
    assert.deepEqual([r.code, r.loggedIn, r.error], [1, false, 'Login expired · Please run /login']);
    r = await w.hb.run('carol', 'grok', { prompt: 'x', dir: w.job() });
    assert.deepEqual([r.code, r.loggedIn], [1, false]);
    assert.match(r.error, /^Not signed in/);

    let t = Date.now();
    r = await w.hb.run('alice', 'claude-code', { prompt: 'FAKE_MODE=hang', dir: w.job(), timeoutMs: 1500 });
    assert.deepEqual([r.timedOut, r.loggedIn], [true, undefined]);
    assert.ok(Date.now() - t < 10e3);
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 800);
    r = await w.hb.run('alice', 'codex', { prompt: 'FAKE_MODE=hang', dir: w.job(), signal: ac.signal });
    assert.equal(r.canceled, true);
    t = Date.now();
    r = await w.hb.run('alice', 'grok', { prompt: 'FAKE_MODE=forkbomb', dir: w.job() });
    assert.equal(r.why, 'more than 20 processes: box stopped');
    assert.ok(Date.now() - t < 15e3);

    const dir = w.job();
    r = await w.hb.run('alice', 'claude-code', { prompt: 'FAKE_MODE=plant', dir });
    assert.equal(r.code, 0);
    assert.deepEqual(readdirSync(w.home('alice', 'claude-code'), { recursive: true }).sort(), ['.claude'], 'scrubbed after the job: planted files and the credential turned link are gone');
    r = await w.hb.run('alice', 'claude-code', { prompt: 'FAKE_MODE=egress', dir: w.job() });
    assert.equal(r.loggedIn, false, 'the planted link cost the login, nothing else');

    w.logIn('alice', 'claude-code');
    const e = w.job();
    r = await w.hb.run('alice', 'claude-code', { prompt: 'FAKE_MODE=egress', dir: e });
    assert.equal(w.seen(e).egress.denied, 'HTTP/1.1 403 Forbidden');
    assert.ok(w.logs.includes('egress deny job=alice example.com:443 host'), w.logs.join('\n'));
    writeFileSync(join(w.root, 'secret'), 'CANARY');
    r = await w.hb.run('alice', 'codex', { prompt: 'FAKE_MODE=symlink', dir: w.job(), env: { FAKE_TARGET: join(w.root, 'secret') } });
    assert.equal(r.text, '', 'the last-message file was a link: not read');
  } finally { w.close(); }
});

test('locks and slots: one box at a time per user and harness, maxJobs at once, status Busy behind a job; exec and purge', BOX, async () => {
  const w = await world({ maxJobs: 1 });
  try {
    await w.hb.detect();
    for (const u of ['alice', 'bob']) w.logIn(u, 'claude-code');
    const d1 = w.job(), d2 = w.job();
    const first = w.hb.run('alice', 'claude-code', { prompt: 'FAKE_MODE=hang', dir: d1, timeoutMs: 2500 });
    await sleep(800);
    await assert.rejects(w.hb.status('alice', 'claude-code', { waitMs: 200 }), Busy);
    assert.equal((await w.hb.status('bob', 'claude-code')).loggedIn, true, 'another user is not behind alice\'s lock');
    const second = w.hb.run('bob', 'claude-code', { prompt: 'x', dir: d2 });
    await sleep(800);
    assert.ok(existsSync(join(d1, 'seen.json')) && !existsSync(join(d2, 'seen.json')), 'the second job waits for the only slot');
    assert.equal((await first).timedOut, true);
    assert.equal((await second).code, 0);

    const r = await w.hb.exec('alice', 'claude-code', ['/bin/bash', '-c', 'echo "$HOME"; ls -A /; cat /etc/hostname >/dev/null; exec 3<>/dev/tcp/1.1.1.1/443 && echo NET'], { dir: d1 });
    assert.equal(r.out.split('\n')[0], w.home('alice', 'claude-code'));
    assert.doesNotMatch(r.out, /NET/, 'no network by default');
    const l = w.hb.login('alice', 'codex');
    await l.waiting;
    await w.hb.purge('alice');
    assert.equal((await l.done).error, 'canceled');
    assert.ok(!existsSync(join(w.homes, 'alice')) && existsSync(join(w.homes, 'bob')));
    assert.ok(lstatSync(w.homes).isDirectory());
  } finally { w.close(); }
});
