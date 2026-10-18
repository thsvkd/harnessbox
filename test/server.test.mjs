// The service end to end: src/server.mjs on a unix socket, driven through src/client.mjs, over the real runner with real bubblewrap
// boxes and the fake CLIs (test/fake-cli.mjs). Two clients, their users kept apart; auth; logins; a review-automation-shaped draft
// job (files in, a read-only skill, out/ files back, a validator in a no-network box); cancel; caps; a restart. webSearch and events
// per client; the tests over a stand-in runner (fakeWorld) need no bubblewrap.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Busy, claudeCode, codex, createRunner, grok } from '../src/index.mjs';
import { harnessbox, HarnessboxError, older, VERSION as CLIENT_VERSION } from '../src/client.mjs';
import { BOX_DIR, createService, listenOf, MIN_CLIENT, VERSION } from '../src/server.mjs';

const HERE = import.meta.dirname;
const FAKE = { 'claude-code': join(HERE, 'fake-claude'), codex: join(HERE, 'fake-codex'), grok: join(HERE, 'fake-grok') };
const canBox = spawnSync('bwrap', ['--unshare-all', '--die-with-parent', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '/usr/bin/true']).status === 0;
const BOX = { skip: !canBox && 'needs bubblewrap with user namespaces' };
const TOKEN = { a: 'token-of-client-a-0123456789', b: 'token-of-client-b-0123456789', c: 'token-of-client-c-0123456789' };
const hex = (t) => createHash('sha256').update(t).digest('hex');
const CRED = { 'claude-code': '.claude/.credentials.json', codex: '.codex/auth.json', grok: '.grok/auth.json' };
const b64 = (s) => Buffer.from(s).toString('base64'), unb64 = (s) => (s === null ? null : Buffer.from(s, 'base64').toString());
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function world({ limits = {}, root = mkdtempSync(join(tmpdir(), 'hb-service-test-')), env = {} } = {}) {
  const homes = join(root, 'homes'), runs = join(root, 'runs'), sock = join(root, 'hb.sock'), logs = [];
  mkdirSync(runs, { recursive: true });
  const hb = await createRunner({ homes, adapters: [claudeCode, codex, grok], bins: FAKE, socat: join(HERE, 'fake-socat'), log: (l) => logs.push(l), passEnv: env });
  const svc = createService({ hb, harnesses: await hb.detect(), runs, log: (l) => logs.push(l), limits, models: { codex: ['gpt-5.5-codex'] },
    clients: [{ id: 'appa', tokenSha256: hex(TOKEN.a) }, { id: 'appb', tokenSha256: hex(TOKEN.b), harnesses: ['claude-code'] }, { id: 'appc', tokenSha256: hex(TOKEN.c), webSearch: true, events: true }] });
  await new Promise((r) => svc.server.listen(sock, r));
  const logIn = (client, user, id) => { const f = join(homes, client, user, id, CRED[id]); mkdirSync(join(f, '..'), { recursive: true }); writeFileSync(f, '{"fake":true}'); };
  return {
    root, homes, runs, sock, logs, logIn, a: harnessbox({ socketPath: sock, token: TOKEN.a }), b: harnessbox({ socketPath: sock, token: TOKEN.b }), c: harnessbox({ socketPath: sock, token: TOKEN.c }),
    close: async ({ keep = false } = {}) => { svc.close(); await hb.close(); if (!keep) rmSync(root, { recursive: true, force: true }); },
  };
}
const raw = (sock, method, path, headers = {}, body) => new Promise((done) => {
  const req = http.request({ socketPath: sock, method, path, headers }, (res) => { let t = ''; res.on('data', (d) => { t += d; }); res.on('end', () => done({ status: res.statusCode, body: t })); });
  req.on('error', (e) => done({ status: 0, body: e.code }));
  req.end(body);
});

test('service: auth, harness lists per client, logins through the API, status and logout, clients kept apart', BOX, async () => {
  const w = await world();
  try {
    assert.equal((await raw(w.sock, 'GET', '/v1/harnesses')).status, 401);
    assert.equal((await raw(w.sock, 'GET', '/v1/harnesses', { authorization: 'Bearer not-a-real-token-at-all' })).status, 401);
    assert.deepEqual((await w.a.harnesses()).harnesses.map((h) => [h.id, h.usable, h.webSearch]), [['claude-code', true, true], ['codex', true, true], ['grok', true, false]]);
    assert.deepEqual((await w.b.harnesses()).harnesses.map((h) => h.id), ['claude-code'], 'a client sees only its harnesses');
    await assert.rejects(w.b.status('u1', 'codex'), { status: 404, code: 'unknown_harness' });
    await assert.rejects(w.a.status('../x', 'codex'), { status: 400, code: 'bad_user' });

    // Claude Code: URL, then the pasted code; Codex: URL and device code
    let s = await w.a.login('u1', 'claude-code');
    assert.deepEqual([s.state, s.url, s.code, s.needsCode], ['waiting', 'https://claude.com/cai/oauth/authorize?code=true&state=fake-state', null, true]);
    assert.ok(Date.parse(s.expiresAt) - Date.parse(s.startedAt) > 10 * 60e3, 'the runner\'s: from its box, which starts after the request');
    await assert.rejects(w.a.submitCode('u1', 'claude-code', 'has space'), { status: 400 });
    assert.equal(await w.a.submitCode('u1', 'claude-code', 'good-code'), null);
    await assert.rejects(w.a.submitCode('u1', 'claude-code', 'good-code'), { status: 409 });
    for (let i = 0; i < 50 && (s = await w.a.loginState('u1', 'claude-code')).state !== 'done'; i++) await sleep(100);
    assert.deepEqual([s.state, s.url, s.status.loggedIn], ['done', 'https://claude.com/cai/oauth/authorize?code=true&state=fake-state', true]);
    s = await w.a.login('u1', 'codex');
    assert.deepEqual([s.state, s.url, s.code, s.needsCode], ['waiting', 'https://auth.openai.com/codex/device', 'FAKE-12345', false]);
    for (let i = 0; i < 50 && (s = await w.a.loginState('u1', 'codex')).state !== 'done'; i++) await sleep(100);
    assert.equal(s.state, 'done');
    assert.ok(existsSync(join(w.homes, 'appa', 'u1', 'claude-code', CRED['claude-code'])), 'the login is under /homes/<client>/<user>/<harness>');

    const list = (await w.a.statuses('u1')).harnesses;
    assert.deepEqual(list.map((h) => [h.harness, h.loggedIn]), [['claude-code', true], ['codex', true], ['grok', false]]);
    // the same user id at the other client is somebody else
    assert.equal((await w.b.status('u1', 'claude-code')).loggedIn, false);
    await assert.rejects(w.b.loginState('u1', 'claude-code'), { status: 404 });
    assert.equal((await w.a.logout('u1', 'codex')).loggedIn, false);
    assert.ok(!existsSync(join(w.homes, 'appa', 'u1', 'codex', CRED.codex)));

    // cancel a login; nothing about URLs or codes in the logs
    s = await w.a.login('u2', 'claude-code');
    assert.equal(await w.a.cancelLogin('u2', 'claude-code'), null);
    assert.equal((await w.a.loginState('u2', 'claude-code')).state, 'failed');
    assert.ok(!w.logs.some((l) => /https:|good-code|FAKE-12345/.test(l)), w.logs.join('\n'));
    assert.ok(w.logs.includes('login client=appa user=appa/u1 harness=claude-code done'));
  } finally { await w.close(); }
});

const RESULT_020 = ['code', 'text', 'usage', 'error', 'stderr', 'why', 'timedOut', 'canceled'];
const draftJob = (user, harness, more = {}) => ({
  user, harness, prompt: `Read ${BOX_DIR}/request.md. FAKE_MODE=rva`, model: undefined,
  files: [{ path: 'request.md', text: '# request\n' }, { path: 'materials/photos/p1.jpg', base64: b64('\xff\xd8 not really a jpeg'), copies: ['out/photos/p1.jpg'] }, { path: 'materials/memo.txt', text: '메모' },
    { path: 'skill/validate.sh', text: 'f=$1; [ -f "$f" ] && s=$(wc -c < "$f") || s=-1\nn=$( (exec 3<>/dev/tcp/1.1.1.1/443) 2>/dev/null && echo yes || echo no)\necho "{\\"size\\":$s,\\"net\\":\\"$n\\",\\"pwd\\":\\"$PWD\\"}"\n' }],
  readonly: ['skill'],
  outputs: ['out/draft.json', 'out/draft.md', 'out/handoff.md', 'out/missing.json', 'out/evil.json', 'out/big.txt', 'seen.json'],
  validate: { argv: ['/bin/bash', 'skill/validate.sh', 'out/draft.json'], net: 'none', timeoutMs: 30e3 },
  ...more,
});

test('service: a review-automation-shaped draft job per harness: files in, read-only skill, out/ back, validator offline; isolation', BOX, async () => {
  const w = await world({ limits: { output: 20000 } });
  try {
    for (const id of ['claude-code', 'codex', 'grok']) w.logIn('appa', 'u1', id);
    for (const id of ['claude-code', 'codex', 'grok']) {
      const started = await w.a.run(draftJob('u1', id, id === 'codex' ? { model: 'gpt-5.5-codex' } : {}));
      assert.equal(started.state, 'queued');
      const seen = [];
      const r = await w.a.events(started.id, (event, run) => seen.push(`${event}:${run.state}`));
      assert.equal(r.state, 'done', `${id}: ${JSON.stringify(r)}`);
      assert.ok(seen.includes('state:running') && seen.at(-1) === 'end:done', seen.join(' '));
      assert.equal(r.result.code, 0);
      assert.equal(r.result.text, 'done (rva)');
      assert.deepEqual(Object.keys(r.result), RESULT_020, 'a client without webSearch and events gets the 0.2.0 result');
      assert.ok(r.events > 0 && r.stage);
      const draft = JSON.parse(unb64(r.outputs['out/draft.json']));
      assert.deepEqual(draft.files, ['memo.txt', 'photos', 'photos/p1.jpg']);
      assert.deepEqual(JSON.parse(unb64(r.outputs['seen.json'])).outFiles, ['photos', 'photos/p1.jpg'], 'the copy is in out/ before the CLI starts');
      assert.equal(unb64(r.outputs['out/draft.md']), '# draft\n');
      assert.deepEqual([r.outputs['out/missing.json'], r.outputs['out/evil.json'], r.outputs['out/big.txt']], [null, null, null], 'missing, a link, over the size cap');
      assert.deepEqual(JSON.parse(r.validator.out), { size: Buffer.byteLength(unb64(r.outputs['out/draft.json'])), net: 'no', pwd: BOX_DIR });
      const s = JSON.parse(unb64(r.outputs['seen.json']));
      assert.equal(s.skillwrite, 'EROFS', 'the skill folder is read-only in the box');
      assert.equal(s.cwd, BOX_DIR);
      assert.equal(s.home, join(w.homes, 'appa', 'u1', id));
      assert.deepEqual(s.users, ['u1'], 'the box sees no other user of its client');
      if (id === 'codex') assert.ok(s.args.includes('--model') && s.args[s.args.indexOf('--model') + 1] === 'gpt-5.5-codex' && s.args.at(-1) === '-');
      assert.deepEqual(readdirSync(w.runs), [], 'the run folder is gone');
    }
    // client B cannot see or cancel A's run, and its own user u1 is not A's u1
    const r = await w.a.run(draftJob('u1', 'claude-code'));
    await assert.rejects(w.b.getRun(r.id), { status: 404 });
    await assert.rejects(w.b.cancelRun(r.id), { status: 404 });
    await w.a.events(r.id);
    const other = await w.b.events((await w.b.run(draftJob('u1', 'claude-code'))).id);
    assert.deepEqual([other.state, other.result.loggedIn, other.validator], ['failed', false, null], 'B\'s u1 has no login; no validator after a failed CLI');
    await assert.rejects(w.a.run(draftJob('u1', 'codex', { model: 'gpt-4o' })), { status: 400, code: 'bad_model' });
    // the client chooses the validator command: it runs with an empty home of its own, never the user's credential
    const v = await w.a.events((await w.a.run({ ...draftJob('u1', 'claude-code'), validate: { argv: ['/bin/bash', '-c', 'echo "home=$HOME"; ls -A "$HOME"; cat ~/.claude/.credentials.json'] } })).id);
    assert.equal(v.state, 'done');
    assert.doesNotMatch(v.validator.out, /fake/);
    assert.doesNotMatch(v.validator.out, new RegExp(join(w.homes, 'appa', 'u1')));
    assert.ok(!w.logs.some((l) => /FAKE_MODE|request\.md|draft by/.test(l)), 'no prompt or output in the logs');
  } finally { await w.close(); }
});

test('service: cancel, caps, bad requests, purge, and a restart forgets runs', BOX, async () => {
  let w = await world({ limits: { activeRuns: 2, body: 4096 } });
  try {
    w.logIn('appa', 'u1', 'claude-code');
    w.logIn('appa', 'u2', 'claude-code');
    const hang = await w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'FAKE_MODE=hang' });
    const queued = await w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x' }); // behind u1's lock
    await assert.rejects(w.a.run({ user: 'u2', harness: 'claude-code', prompt: 'x' }), { status: 429, code: 'too_many_runs' });
    await assert.rejects(w.a.status('u1', 'claude-code'), { status: 409, code: 'busy' });
    assert.deepEqual((await w.a.statuses('u1')).harnesses.find((h) => h.harness === 'claude-code').busy, true);
    assert.equal(await w.a.cancelRun(queued.id), null);
    const left = await w.a.events(queued.id);
    assert.deepEqual([left.state, left.startedAt], ['canceled', null], 'a queued run leaves the line at once, without a box');
    for (let i = 0; i < 50 && (await w.a.getRun(hang.id)).state !== 'running'; i++) await sleep(100);
    await w.a.cancelRun(hang.id);
    const done = await w.a.events(hang.id);
    assert.deepEqual([done.state, done.result.canceled], ['canceled', true]);

    for (const [body, code] of [[{ user: 'u1', harness: 'claude-code', prompt: '--help' }, 'bad_prompt'], [{ user: 'u1', harness: 'nope', prompt: 'x' }, 'unknown_harness'],
      [{ user: 'u1', harness: 'claude-code', prompt: 'x', files: [{ path: '../evil', text: 'x' }] }, 'bad_files'],
      [{ user: 'u1', harness: 'claude-code', prompt: 'x', files: [{ path: 'a', text: 'x' }, { path: 'a', text: 'y' }] }, 'bad_files'],
      [{ user: 'u1', harness: 'claude-code', prompt: 'x', outputs: ['/etc/passwd'] }, 'bad_path'], [{ user: 'u1', harness: 'claude-code', prompt: 'x', timeoutMs: 1 }, 'bad_timeout'],
      [{ user: 'u1', harness: 'claude-code', prompt: 'x', validate: { argv: ['true'], net: 'proxy' } }, 'bad_validate'],
      [{ user: 'u1', harness: 'claude-code', prompt: 'x', files: [{ path: 'a', text: 'x' }, { path: 'a/b', text: 'y' }] }, 'bad_files'],
      [{ user: 'u1', harness: 'claude-code', prompt: 'x', files: [{ path: 'out', text: 'x' }], outputs: ['out/x'] }, 'bad_path']]) {
      await assert.rejects(w.a.run(body), { code }, JSON.stringify(body));
    }
    await assert.rejects(w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', files: [{ path: 'big', text: 'x'.repeat(5000) }] }), { status: 413 });
    assert.equal((await raw(w.sock, 'POST', '/v1/runs', { authorization: `Bearer ${TOKEN.a}`, 'content-type': 'application/json' }, '{nope')).status, 400);
    assert.deepEqual(readdirSync(w.runs), [], 'refused runs leave no folder');

    // purge ends a user's runs, queued ones included, and does not wait behind them
    const h2 = await w.a.run({ user: 'u2', harness: 'claude-code', prompt: 'FAKE_MODE=hang' }), q2 = await w.a.run({ user: 'u2', harness: 'claude-code', prompt: 'x' });
    const t = Date.now();
    await w.a.purge('u2');
    assert.ok(Date.now() - t < 10e3);
    assert.deepEqual([(await w.a.events(h2.id)).state, (await w.a.events(q2.id)).state], ['canceled', 'canceled']);
    assert.ok(!existsSync(join(w.homes, 'appa', 'u2')) && existsSync(join(w.homes, 'appa', 'u1')));
    await w.close({ keep: true });
    // a new service over the same folders: the old run is unknown (the client requeues), the logins are still there
    w = await world({ root: w.root });
    await assert.rejects(w.a.getRun(hang.id), { status: 404, code: 'unknown_run' });
    assert.equal((await w.a.status('u1', 'claude-code')).loggedIn, true);
  } finally { await w.close(); }
});

test('main: configured from the environment, a 0666 socket, stale run folders removed at start, an output cap, SIGTERM ends it', BOX, async () => {
  const root = mkdtempSync(join(tmpdir(), 'hb-service-main-')), sock = join(root, 'sock', 'hb.sock'), runs = join(root, 'runs');
  mkdirSync(join(runs, 'run_old-x', 'work'), { recursive: true });
  mkdirSync(join(root, 'homes', 'appa', 'u1', 'codex', '.codex'), { recursive: true });
  writeFileSync(join(root, 'homes', 'appa', 'u1', 'codex', '.codex', 'auth.json'), '{"fake":true}');
  writeFileSync(join(root, 'clients.json'), JSON.stringify({ clients: [{ id: 'appa', tokenSha256: hex(TOKEN.a), harnesses: ['codex'] }] }));
  const { spawn } = await import('node:child_process');
  const child = spawn(process.execPath, [join(HERE, '..', 'src', 'server.mjs')], { stdio: ['ignore', 'pipe', 'pipe'], env: {
    PATH: process.env.PATH, HB_LISTEN: sock, HB_CLIENTS: join(root, 'clients.json'), HB_HOMES: join(root, 'homes'), HB_RUNS: runs, HB_HARNESSES: 'codex',
    HB_BIN_CODEX: FAKE.codex, HB_SOCAT: join(HERE, 'fake-socat'), HB_PIN_CODEX: '0.162.1', HB_MAX_OUTPUT_BYTES: '2000' } });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { out += d; });
  try {
    for (let i = 0; i < 100 && !out.includes('listening'); i++) await sleep(100);
    assert.match(out, /codex 0\.162\.1 usable/);
    const { statSync } = await import('node:fs');
    assert.equal(statSync(sock).mode & 0o777, 0o666);
    assert.deepEqual(readdirSync(runs), []);
    const hb = harnessbox({ socketPath: sock, token: TOKEN.a });
    assert.deepEqual((await hb.harnesses()).harnesses.map((h) => h.id), ['codex']);
    // HB_MAX_OUTPUT_BYTES reaches the runner: 5000 bytes of stderr stop a box capped at 2000
    const loud = await hb.events((await hb.run({ user: 'u1', harness: 'codex', prompt: 'FAKE_MODE=loud' })).id);
    assert.deepEqual([loud.state, loud.result.why], ['failed', 'more than 2000 output bytes: box stopped']);
  } finally {
    child.kill('SIGTERM');
    await new Promise((r) => child.on('exit', r));
    rmSync(root, { recursive: true, force: true });
  }
  assert.equal(child.signalCode, 'SIGTERM', out);
});

test('service: a client allowed webSearch and events gets the CLI\'s events through the real runner, a search-enabled command, and capped events', BOX, async () => {
  const w = await world({ limits: { eventBytes: 1000, eventsBytes: 1000 } });
  try {
    for (const id of ['claude-code', 'codex']) w.logIn('appc', 'u1', id);
    const c = await w.c.events((await w.c.run({ user: 'u1', harness: 'claude-code', prompt: 'x', webSearch: true, events: true, outputs: ['seen.json'] })).id);
    assert.equal(c.state, 'done');
    // the fake's events as it printed them; the line cut in the middle is not JSON and is skipped
    assert.deepEqual(c.result.events.map((e) => [e.type, e.subtype ?? e.result]), [['system', 'init'], ['result', 'first turn'], ['result', 'done (ok)']]);
    assert.deepEqual(c.result.events[0], { type: 'system', subtype: 'init', session_id: 's1', model: 'claude-sonnet-5-5' });
    assert.equal(c.result.eventsTruncated, false);
    assert.equal(c.events, 3);
    const args = JSON.parse(unb64(c.outputs['seen.json'])).args;
    assert.ok(args.includes('--allowedTools') && args.filter((a) => a === 'WebSearch').length === 1 && args.includes('WebFetch'));
    const x = await w.c.events((await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x', webSearch: true, events: true, outputs: ['seen.json'] })).id);
    assert.deepEqual(x.result.events.map((e) => e.type), ['thread.started', 'item.started', 'turn.completed']);
    assert.ok(JSON.parse(unb64(x.outputs['seen.json'])).args.includes('web_search=live'));
    // 64 events of 32 KiB each: every one over eventBytes, kept as { type, truncated } until eventsBytes is reached
    const f = await w.c.events((await w.c.run({ user: 'u1', harness: 'codex', prompt: 'FAKE_MODE=flood', events: true })).id);
    assert.equal(f.state, 'done');
    assert.deepEqual(f.result.events[0], { type: 'text', truncated: true });
    assert.equal(f.result.events.length, 30, '30 of 33 bytes each fit in 1000');
    assert.equal(f.result.eventsTruncated, true);
    assert.equal(f.events, 64);
    // the same client without the fields: the 0.2.0 result
    const plain = await w.c.events((await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x' })).id);
    assert.deepEqual(Object.keys(plain.result), RESULT_020);
  } finally { await w.close(); }
});

test('service: a box printing an event nested 4073, 5000 or 100000 deep: the run ends normally, the event is { type, truncated }, the service lives', BOX, async () => {
  const w = await world();
  try {
    for (const id of ['claude-code', 'codex']) w.logIn('appc', 'u1', id);
    for (const [harness, n] of [['codex', 4073], ['codex', 5000], ['codex', 100000], ['claude-code', 5000]]) {
      const id = (await w.c.run({ user: 'u1', harness, prompt: `FAKE_MODE=deep-${n}`, events: true })).id;
      const ended = await w.c.events(id), got = await w.c.getRun(id);
      assert.deepEqual(ended, got, `${harness} ${n}`);
      assert.equal(got.state, 'done');
      assert.equal(got.result.text, `done (deep-${n})`);
      assert.deepEqual(got.result.events[0], { type: 'deep', truncated: true });
      assert.deepEqual(got.result.events.slice(1).map((e) => e.type), harness === 'codex' ? ['thread.started', 'item.started', 'turn.completed'] : ['system', 'result', 'result']);
    }
    assert.equal((await w.a.harnesses()).harnesses.length, 3, 'the service still answers');
  } finally { await w.close(); }
});

test('main: a client entry whose webSearch or events is not true or false stops the service at start', BOX, () => {
  const root = mkdtempSync(join(tmpdir(), 'hb-service-clients-'));
  try {
    writeFileSync(join(root, 'clients.json'), JSON.stringify({ clients: [{ id: 'appa', tokenSha256: hex(TOKEN.a), events: 'yes' }] }));
    const r = spawnSync(process.execPath, [join(HERE, '..', 'src', 'server.mjs')], { encoding: 'utf8', timeout: 30e3, env: {
      PATH: process.env.PATH, HB_LISTEN: join(root, 'hb.sock'), HB_CLIENTS: join(root, 'clients.json'), HB_HOMES: join(root, 'homes'), HB_RUNS: join(root, 'runs'), HB_HARNESSES: 'codex',
      HB_BIN_CODEX: FAKE.codex, HB_SOCAT: join(HERE, 'fake-socat') } });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /bad client entry appa: events must be true or false/);
    assert.ok(!existsSync(join(root, 'hb.sock')), 'it never listened');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('main: a bad HB_MAX_OUTPUT_BYTES, HB_MAX_BODY, HB_MAX_JOBS or HB_MAX_QUICK stops the service at start', async () => {
  for (const name of ['HB_MAX_OUTPUT_BYTES', 'HB_MAX_BODY', 'HB_MAX_JOBS', 'HB_MAX_QUICK']) {
    for (const value of ['0', '-1', '1.5', '8MiB', '', ...(name === 'HB_MAX_BODY' ? [String(2 ** 29)] : name.includes('BYTES') ? [] : ['1001'])]) {
      const r = spawnSync(process.execPath, [join(HERE, '..', 'src', 'server.mjs')], { encoding: 'utf8', timeout: 30e3,
        env: { PATH: process.env.PATH, [name]: value, HB_CLIENTS: '/nonexistent/clients.json' } });
      assert.notEqual(r.status, 0, `${name}=${value}`);
      assert.match(r.stderr, new RegExp(`${name} must be a positive integer`), `${name}=${value}`);
    }
  }
});

test('client: an event that is not JSON rejects that subscription with bad_event, and the process lives on', async () => {
  const root = mkdtempSync(join(tmpdir(), 'hb-client-sse-')), sock = join(root, 'fake.sock');
  const fake = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('event: state\ndata: {"id":"run_x","state":"running"}\n\n');
    res.write('event: progress\ndata: {not json\n\n');
  });
  await new Promise((r) => fake.listen(sock, r));
  try {
    const seen = [];
    await assert.rejects(harnessbox({ socketPath: sock, token: TOKEN.a }).events('run_x', (event, run) => seen.push(`${event}:${run.state}`)), (e) => e instanceof HarnessboxError && e.code === 'bad_event');
    assert.deepEqual(seen, ['state:running'], 'the events before the broken one still arrived');
  } finally {
    fake.closeAllConnections();
    fake.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test('service: simultaneous uploads reserve the active-run limit before staging files', BOX, async () => {
  const w = await world({ limits: { activeRuns: 1 } });
  try {
    w.logIn('appa', 'u1', 'claude-code');
    await assert.rejects(w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', files: [{ path: '../bad', text: 'x' }] }), { status: 400 });
    const files = Array.from({ length: 64 }, (_, i) => ({ path: `f${i}.txt`, text: 'upload' }));
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'FAKE_MODE=hang', files })));
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
    const rejected = results.filter((r) => r.status === 'rejected');
    assert.equal(rejected.length, 7);
    assert.ok(rejected.every((r) => r.reason.status === 429 && r.reason.code === 'too_many_runs'));
  } finally { await w.close(); }
});

test('service: binary outputs round-trip without UTF-8 conversion', BOX, async () => {
  const w = await world();
  try {
    w.logIn('appa', 'u1', 'claude-code');
    const bytes = Buffer.from([0xff, 0xd8, 0x00, 0x80, 0xfe]);
    const r = await w.a.events((await w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', files: [{ path: 'photo.jpg', base64: bytes.toString('base64') }], outputs: ['photo.jpg'] })).id);
    assert.equal(r.state, 'done');
    assert.deepEqual(Buffer.from(r.outputs['photo.jpg'], 'base64'), bytes);
  } finally { await w.close(); }
});

test('service: a login can replace itself when the waiting-login limit is full', BOX, async () => {
  const w = await world({ limits: { logins: 1 } });
  try {
    assert.equal((await w.a.login('u1', 'claude-code')).state, 'waiting');
    assert.equal((await w.a.login('u1', 'claude-code')).state, 'waiting');
    await assert.rejects(w.a.login('u2', 'claude-code'), { status: 429, code: 'too_many_logins' });
    await w.a.cancelLogin('u1', 'claude-code');
  } finally { await w.close(); }
});

test('service: file copies count against the file-count limit', BOX, async () => {
  const w = await world({ limits: { files: 1 } });
  try {
    await assert.rejects(w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', files: [{ path: 'a', text: 'x', copies: ['b'] }] }), { status: 400, code: 'bad_files' });
    assert.deepEqual(readdirSync(w.runs), []);
  } finally { await w.close(); }
});

// ---- webSearch and events over a stand-in runner: what the service checks, passes on and keeps, without a box
const ROWS = [{ id: 'claude-code', name: 'Claude Code', version: '2.1.300', usable: true, why: null, webSearch: true },
  { id: 'codex', name: 'Codex', version: '0.162.1', usable: true, why: null, webSearch: true }, { id: 'grok', name: 'Grok', version: '1.0.52', usable: true, why: null, webSearch: false }];
const FAKE_RESULT = { code: 0, text: 'done', usage: { input: 1, output: 2 }, error: '', stderr: '', why: null, timedOut: false, canceled: false };
async function fakeWorld({ events = [], limits = {}, harnesses = ROWS, output = '', result = {}, hb: more = {}, service = {} } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'hb-fake-svc-')), runs = join(root, 'runs'), sock = join(root, 'hb.sock'), calls = [];
  mkdirSync(runs);
  const hb = {
    run: async (scoped, h, o) => {
      calls.push({ scoped, h, ...o });
      o.onStart();
      for (const e of typeof events === 'function' ? events() : events) o.onEvent(e, { stage: '' });
      for (const [name, text] of Object.entries(typeof output === 'string' ? (output ? { 'out.txt': output } : {}) : output)) writeFileSync(join(o.dir, name), text);
      return { ...FAKE_RESULT, ...result };
    },
    exec: async () => ({ code: 0, out: '{}', why: null }),
    ...more,
  };
  const svc = createService({ hb, harnesses, runs, limits, ...service,
    clients: [{ id: 'appa', tokenSha256: hex(TOKEN.a) }, { id: 'appc', tokenSha256: hex(TOKEN.c), webSearch: true, events: true }] });
  await new Promise((r) => svc.server.listen(sock, r));
  return { runs, sock, map: svc.runs, calls, a: harnessbox({ socketPath: sock, token: TOKEN.a }), c: harnessbox({ socketPath: sock, token: TOKEN.c }),
    close: () => { svc.close(); rmSync(root, { recursive: true, force: true }); } };
}

test('service: a client entry\'s webSearch and events must be true or false, else the service does not start', () => {
  for (const k of ['webSearch', 'events']) {
    for (const bad of ['true', 1, null, {}]) {
      assert.throws(() => createService({ hb: {}, harnesses: ROWS, runs: tmpdir(), clients: [{ id: 'appa', tokenSha256: hex(TOKEN.a), [k]: bad }] }),
        new RegExp(`bad client entry appa: ${k} must be true or false`), `${k}: ${JSON.stringify(bad)}`);
    }
    for (const ok of [true, false]) assert.ok(createService({ hb: {}, harnesses: ROWS, runs: tmpdir(), clients: [{ id: 'appa', tokenSha256: hex(TOKEN.a), [k]: ok }] }).server);
  }
});

test('service: webSearch and events are refused unless the client\'s entry allows them, and webSearch where the harness has none', async () => {
  const w = await fakeWorld();
  try {
    const run = { user: 'u1', harness: 'codex', prompt: 'x' };
    await assert.rejects(w.a.run({ ...run, webSearch: true }), { status: 400, code: 'web_search_not_allowed' });
    await assert.rejects(w.a.run({ ...run, events: true }), { status: 400, code: 'events_not_allowed' });
    await assert.rejects(w.c.run({ ...run, harness: 'grok', webSearch: true }), { status: 400, code: 'web_search_unsupported', message: 'Grok does not support webSearch on this service' });
    for (const k of ['webSearch', 'events']) for (const bad of ['true', 1, {}]) await assert.rejects(w.c.run({ ...run, [k]: bad }), { status: 400, code: 'bad_request' }, `${k}: ${JSON.stringify(bad)}`);
    assert.equal(w.calls.length, 0, 'a refused run never reaches the runner');
    assert.deepEqual(readdirSync(w.runs), [], 'and leaves no folder');
    // false is allowed everywhere, as is a Grok run without webSearch at a client that may search
    for (const [hb, body] of [[w.a, { ...run, webSearch: false, events: false }], [w.c, { ...run, harness: 'grok' }]]) assert.equal((await hb.events((await hb.run(body)).id)).state, 'done');
  } finally { w.close(); }
});

test('service: without webSearch and events a run reaches the runner and comes back as before; with webSearch the runner is told', async () => {
  const w = await fakeWorld({ events: [{ type: 'thread.started' }, { type: 'turn.completed', usage: { input_tokens: 1 } }] });
  try {
    for (const [hb, more] of [[w.a, {}], [w.a, { webSearch: false, events: false }], [w.c, {}], [w.c, { events: false }]]) {
      const id = (await hb.run({ user: 'u1', harness: 'codex', prompt: 'x', ...more })).id;
      const ended = await hb.events(id), got = await hb.getRun(id);
      assert.deepEqual(ended.result, FAKE_RESULT, JSON.stringify(more));
      assert.deepEqual(got, ended);
      assert.deepEqual(Object.keys(got.result), RESULT_020);
      assert.equal(got.events, 2, 'the event count is still there');
      assert.equal(w.calls.at(-1).webSearch, false);
    }
    await w.c.events((await w.c.run({ user: 'u1', harness: 'claude-code', prompt: 'x', webSearch: true })).id);
    assert.equal(w.calls.at(-1).webSearch, true);
  } finally { w.close(); }
});

test('service: events: true keeps the CLI\'s events in result.events, an oversized one as { type, truncated }, the first eventsBytes in total; GET and the end event agree', async () => {
  const small = (i) => ({ type: 'item.completed', item: { type: 'web_search', id: `ws_${i}`, query: `q${i}`, url: `https://example.com/${i}` } });
  const big = { type: 'item.completed', item: { type: 'command_execution', aggregated_output: 'x'.repeat(500) } }, untyped = { data: 'y'.repeat(500) };
  const events = [small(0), big, untyped, ...Array.from({ length: 40 }, (_, i) => small(i + 1))];
  const limits = { eventBytes: 300, eventsBytes: 1500 };
  // the expected prefix: each kept event costs its JSON bytes plus one
  const expect = [];
  let bytes = 0;
  for (const e of events) {
    const item = Buffer.byteLength(JSON.stringify(e)) > limits.eventBytes ? { type: typeof e.type === 'string' ? e.type : null, truncated: true } : e;
    if (bytes + Buffer.byteLength(JSON.stringify(item)) + 1 > limits.eventsBytes) break;
    bytes += Buffer.byteLength(JSON.stringify(item)) + 1;
    expect.push(item);
  }
  assert.ok(expect.length > 3 && expect.length < events.length, 'the limits cut the list');
  const w = await fakeWorld({ events, limits });
  try {
    const id = (await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x', events: true })).id;
    const ended = await w.c.events(id), got = await w.c.getRun(id);
    assert.deepEqual(ended, got, 'the end event and GET give the same run');
    assert.deepEqual(got.result, { ...FAKE_RESULT, events: expect, eventsTruncated: true });
    assert.deepEqual(got.result.events.slice(0, 3), [small(0), { type: 'item.completed', truncated: true }, { type: null, truncated: true }]);
    assert.ok(JSON.stringify(got.result.events).length <= limits.eventsBytes + 1);
    assert.equal(got.events, events.length, 'the count covers every event, kept or not');
  } finally { w.close(); }
  // under the caps: every event, eventsTruncated false
  const few = await fakeWorld({ events: [small(1), small(2)] });
  try {
    const r = await few.c.events((await few.c.run({ user: 'u1', harness: 'claude-code', prompt: 'x', events: true })).id);
    assert.deepEqual(r.result, { ...FAKE_RESULT, events: [small(1), small(2)], eventsTruncated: false });
  } finally { few.close(); }
});

test('service: kept events count against the ended runs\' memory cap', async () => {
  const events = Array.from({ length: 30 }, (_, i) => ({ type: 'text', data: `${i}`.padEnd(90, '.') })); // about 3000 bytes kept
  const w = await fakeWorld({ events, limits: { keptBytes: 5000 } });
  try {
    const run = async (hb, more) => { const id = (await hb.run({ user: 'u1', harness: 'codex', prompt: 'x', ...more })).id; await hb.events(id); return id; };
    const plain = [await run(w.c, {}), await run(w.c, {})];
    for (const id of plain) assert.equal((await w.c.getRun(id)).state, 'done', 'runs without events stay well under the cap');
    const first = await run(w.c, { events: true }), second = await run(w.c, { events: true });
    // the accounting follows the end (after the run folder is removed): wait for it
    for (let i = 0; i < 50 && (await w.c.getRun(first).then(() => true, () => false)); i++) await sleep(20);
    await assert.rejects(w.c.getRun(first), { status: 404, code: 'unknown_run' }, 'two runs of kept events pass 5000 bytes: the oldest ended runs go');
    assert.equal((await w.c.getRun(second)).result.events.length, 30);
  } finally { w.close(); }
});

test('service: GET /v1/harnesses says which harnesses support webSearch, the other fields as before', async () => {
  const w = await fakeWorld();
  try {
    const list = (await w.a.harnesses()).harnesses;
    assert.deepEqual(list.map((h) => Object.keys(h)), ROWS.map(() => ['id', 'name', 'version', 'usable', 'why', 'webSearch']));
    assert.deepEqual(list.map((h) => [h.id, h.webSearch]), [['claude-code', true], ['codex', true], ['grok', false]]);
  } finally { w.close(); }
});

const RVA_CLAUDE_ARGS = ['--tools', 'Read,Write,Edit,Agent,Bash', '--allowedTools', 'Read(//work/**)', 'Edit(//work/out/**)', 'Agent',
  'Bash(python3 -I /work/skill/write-review/scripts/validate_draft.py *)', '--max-turns', '80'];
test('service: args that name web search are refused for a client without webSearch; review-automation\'s args and a client allowed to search pass', async () => {
  const w = await fakeWorld();
  try {
    for (const [harness, args] of [['codex', ['-c', 'web_search=live']], ['codex', ['-c', 'WEB_SEARCH="live"']], ['codex', ['-c', 'tools.web_search={}']],
      ['codex', ['--enable', 'web_search_request']], ['claude-code', ['--allowedTools', 'WebSearch']], ['claude-code', ['--allowedTools', 'Read,WebSearch']],
      ['claude-code', ['--tools', 'Read,websearch']], ['claude-code', ['--allowed-tools=WebSearch']], ['claude-code', ['--settings', '{"permissions":{"allow":["WebSearch"]}}']],
      ['grok', ['--enable-web-search']], ['grok', ['--web search']]]) {
      await assert.rejects(w.a.run({ user: 'u1', harness, prompt: 'x', args }), { status: 400, code: 'web_search_not_allowed' }, JSON.stringify(args));
    }
    assert.equal(w.calls.length, 0);
    // review-automation's draft job (docs/service.md): its Claude Code options, none for Codex; a prompt is not checked
    for (const [harness, args] of [['claude-code', RVA_CLAUDE_ARGS], ['codex', []], ['codex', undefined]]) {
      const r = await w.a.events((await w.a.run({ user: 'u1', harness, prompt: 'Search the web for nothing; read /work/request.md.', ...(args ? { args } : {}) })).id);
      assert.equal(r.state, 'done');
      assert.deepEqual(w.calls.at(-1).args, args ?? []);
    }
    const r = await w.c.events((await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x', args: ['-c', 'web_search=live'] })).id);
    assert.equal(r.state, 'done', 'a client allowed webSearch keeps its options');
    // spelled otherwise: \u escapes and a --settings file are refused to a client without webSearch, a --settings JSON is not
    for (const [harness, args] of [['codex', ['-c', '"web_\\u0073earch"="live"']], ['codex', ['-c', 'tools.web_\\U00000073earch={}']],
      ['claude-code', ['--allowedTools', 'Web\\u0053earch']], ['claude-code', ['--settings', '/work/settings.json']], ['claude-code', ['--settings=/work/settings.json']],
      ['claude-code', ['--settings']]]) {
      await assert.rejects(w.a.run({ user: 'u1', harness, prompt: 'x', args }), { status: 400, code: 'bad_args' }, JSON.stringify(args));
    }
    for (const args of [['--settings', '{"model":"sonnet"}'], ['--settings={"model":"sonnet"}']]) assert.equal((await w.a.events((await w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', args })).id)).state, 'done');
  } finally { w.close(); }
});

test('service: the args check still refuses every spelling it refused, lets a backslash path through, and Codex gets web_search=disabled last', async () => {
  const w = await fakeWorld();
  try {
    const refused = [
      ['codex', ['-c', 'web_search=live'], 'web_search_not_allowed'], ['codex', ['--config=web_search=live'], 'web_search_not_allowed'],
      ['codex', ['-cweb_search=live'], 'web_search_not_allowed'], ['codex', ['-c', ' WEB_SEARCH = "live" '], 'web_search_not_allowed'],
      ['codex', ['-c', 'Web Search=live'], 'web_search_not_allowed'], ['codex', ['-c', '"web_\\u0073earch"="live"'], 'bad_args'],
      ['codex', ['-c', 'tools.web_\\U00000073earch={}'], 'bad_args'], ['codex', ['-c', 'web_\\u0053EARCH=1'], 'bad_args'],
      ['codex', ['-c', 'features={"web\\u005fsearch_request"=true}'], 'bad_args'], ['claude-code', ['--allowedTools', 'Web\\u0053earch'], 'bad_args'],
      ['claude-code', ['--settings', '/work/s.json'], 'bad_args'], ['claude-code', ['--settings={s.json'], 'bad_args'],
      // still refused, though they could not turn search on: the check reads no option's meaning (docs/service.md)
      ['claude-code', ['--append-system-prompt', 'Never use web search.'], 'web_search_not_allowed'], ['claude-code', ['--disallowedTools', 'WebSearch'], 'web_search_not_allowed'],
      ['claude-code', ['--append-system-prompt', 'See C:\\work\\u00e9t\\u00e9'], 'bad_args'],
    ];
    for (const [harness, args, code] of refused) await assert.rejects(w.a.run({ user: 'u1', harness, prompt: 'x', args }), { status: 400, code }, JSON.stringify(args));
    assert.equal(w.calls.length, 0);
    // a backslash that starts no \uXXXX escape (a Windows path) is no escape: 0.3.0 before this refused it
    for (const args of [['--append-system-prompt', 'Paths look like C:\\Users\\me'], ['--append-system-prompt', 'C:\\Users\\u'], ['--add-dir', 'C:\\u12']]) {
      assert.equal((await w.a.events((await w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', args })).id)).state, 'done', JSON.stringify(args));
      assert.deepEqual(w.calls.at(-1).args, args);
    }
    // whatever the args, a Codex run without webSearch ends -c web_search=disabled -: also for a client allowed webSearch, whose args are not checked
    for (const [hb, args] of [[w.a, ['-c', 'model_reasoning_effort="low"']], [w.c, ['-c', 'web_search=live']], [w.c, ['--config=web_search=live', '-c', '"web_\\u0073earch"="live"']]]) {
      assert.equal((await hb.events((await hb.run({ user: 'u1', harness: 'codex', prompt: 'x', args })).id)).state, 'done');
      const { args: extra, webSearch } = w.calls.at(-1);
      assert.deepEqual([extra, webSearch], [args, false]);
      assert.deepEqual(codex.job.command({ prompt: 'x', dir: BOX_DIR, has: new Set(), extra, webSearch }).args.slice(-3), ['-c', 'web_search=disabled', '-'], JSON.stringify(args));
    }
  } finally { w.close(); }
});

test('service: a --settings value is inline only when, trimmed, it parses as a JSON object; anything Claude Code would open as a file is refused', async () => {
  const w = await fakeWorld();
  try {
    // Claude Code 2.1.300 opens {s.json as a file (it does not end with }); [1], null and "x" are not objects (trimmed, none is {…})
    for (const v of ['{s.json', '{"model":"sonnet"', '{"model":"sonnet"}x', '[1]', '["{}"]', 'null', '"{}"', '', ' ', 'settings.json', '{}.json']) {
      for (const args of [['--settings', v], [`--settings=${v}`], ['--model', 'm', '--settings', v]]) {
        await assert.rejects(w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', args }), { status: 400, code: 'bad_args' }, JSON.stringify(args));
      }
    }
    assert.equal(w.calls.length, 0);
    // inline JSON with whitespace around it, which Claude Code trims, is no file
    for (const v of [' {"model":"sonnet"}', '{"model":"sonnet"} ', '\n\t{ "model": "sonnet" }\n', '{}']) {
      for (const args of [['--settings', v], [`--settings=${v}`]]) {
        assert.equal((await w.a.events((await w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', args })).id)).state, 'done', JSON.stringify(args));
        assert.deepEqual(w.calls.at(-1).args, args);
      }
    }
    assert.equal((await w.c.events((await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x', args: ['-c', '"web_\\u0073earch"="live"'] })).id)).state, 'done', 'a client allowed webSearch is not checked');
  } finally { w.close(); }
});

// {"type":"deep","a":{"a":…1…}} nested n objects under the top one: n + 1 deep, parsed the way the runner parses a line
const deepEvent = (n) => JSON.parse(`{"type":"deep","a":${'{"a":'.repeat(n)}1${'}'.repeat(n)}}`);
test('service: an event nested past the stack or past eventDepth is kept as { type, truncated }, and the end, GET and the service go on', async () => {
  const w = await fakeWorld({ events: () => [{ type: 'a' }, deepEvent(4073), deepEvent(5000), deepEvent(100000), deepEvent(63), deepEvent(64), { type: 'z' }] });
  try {
    const id = (await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x', events: true })).id;
    const ended = await w.c.events(id), got = await w.c.getRun(id);
    assert.deepEqual(ended, got);
    const cut = { type: 'deep', truncated: true };
    assert.deepEqual(got.result.events, [{ type: 'a' }, cut, cut, cut, deepEvent(63), cut, { type: 'z' }], '64 deep is kept, 65 is not');
    assert.equal(got.result.eventsTruncated, false);
    assert.equal(got.events, 7);
    assert.equal((await w.c.harnesses()).harnesses.length, 3, 'the service still answers');
  } finally { w.close(); }
});

test('service: eventsCount keeps exactly that many events; one more marks eventsTruncated; many small objects', async () => {
  for (const [n, kept, truncated] of [[5, 5, false], [6, 5, true]]) {
    const w = await fakeWorld({ events: Array.from({ length: n }, (_, i) => ({ type: 't', i })), limits: { eventsCount: 5 } });
    try {
      const r = await w.c.events((await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x', events: true })).id);
      assert.deepEqual([r.result.events.length, r.result.eventsTruncated, r.events], [kept, truncated, n], `${n} events`);
      assert.deepEqual(r.result.events.at(-1), { type: 't', i: kept - 1 });
    } finally { w.close(); }
  }
  for (const [n, truncated] of [[2000, false], [2001, true], [50000, true]]) {
    const w = await fakeWorld({ events: () => Array.from({ length: n }, () => ({})) });
    try {
      const r = await w.c.getRun((await w.c.events((await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x', events: true })).id)).id);
      assert.deepEqual([r.result.events.length, r.result.eventsTruncated], [2000, truncated], `${n} small events: the default 2000`);
    } finally { w.close(); }
  }
});

// streamer-manager's options (its harnessbox runs): none names web search, carries a \u escape or a --settings file
const SM_CODEX_ARGS = ['-c', 'features.shell_tool=false', '-c', 'features.unified_exec=false', '-c', 'features.apply_patch_freeform=false', '-c', 'forced_login_method="chatgpt"',
  '--image=/work/image.jpg', '-c', 'model_reasoning_effort="medium"'];
const SM_CLAUDE_ARGS = ['--tools', 'Read', '--allowedTools', 'Read(//work/**)', '--setting-sources', '', '--disable-slash-commands', '--no-chrome', '--prompt-suggestions', 'false',
  '--permission-prompts', 'none', '--effort', 'low', '--max-turns', '8'];
test('service: review-automation\'s and streamer-manager\'s options pass the args checks unchanged', async () => {
  const w = await fakeWorld();
  try {
    for (const [harness, args] of [['claude-code', RVA_CLAUDE_ARGS], ['claude-code', SM_CLAUDE_ARGS], ['codex', SM_CODEX_ARGS]]) {
      for (const hb of [w.a, w.c]) {
        const r = await hb.events((await hb.run({ user: 'u1', harness, prompt: 'x', args })).id);
        assert.equal(r.state, 'done', `${harness} ${JSON.stringify(args)}`);
        assert.deepEqual(w.calls.at(-1).args, args);
      }
    }
  } finally { w.close(); }
});

test('service: a forgotten run lets go of its events, outputs and result, whether the memory cap, the run cap or keepMs forgets it', async () => {
  const events = Array.from({ length: 30 }, (_, i) => ({ type: 'text', data: `${i}`.padEnd(90, '.') }));
  // outputs are read through /proc (readOutBytes): on Linux out.txt comes back, elsewhere it is null; either way it is dropped
  const linux = process.platform === 'linux';
  let w = await fakeWorld({ events, limits: { keptBytes: 8000 }, output: 'o'.repeat(2400) });
  try {
    const run = async () => { const id = (await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x', events: true, outputs: ['out.txt'] })).id; await w.c.events(id); return id; };
    const first = await run(), a = w.map.get(first);
    for (let i = 0; i < 50 && !a.timer; i++) await sleep(20); // the end's bookkeeping follows the end event
    assert.ok(a.kept && a.result && 'out.txt' in a.outputs && a.timer, 'an ended run holds its fields until it is forgotten');
    if (linux) assert.equal(Buffer.from(a.outputs['out.txt'], 'base64').length, 2400);
    const second = await run(), b = w.map.get(second);
    for (let i = 0; i < 50 && w.map.has(first); i++) await sleep(20);
    assert.ok(!w.map.has(first), 'two runs of 4410 bytes of events (and 2400 of output on Linux, 3200 as base64) pass 8000: the first goes');
    assert.deepEqual([a.kept, a.result, a.outputs, a.validator, a.timer, a.bytes], [null, null, null, null, null, 0], 'and holds nothing large any more');
    for (let i = 0; i < 50 && !b.timer; i++) await sleep(20);
    assert.ok(b.kept && b.result && 'out.txt' in b.outputs && b.timer, 'the run that stays keeps everything');
    if (linux) assert.equal(Buffer.from(b.outputs['out.txt'], 'base64').length, 2400);
    assert.equal((await w.c.getRun(second)).result.events.length, 30);
  } finally { w.close(); }
  w = await fakeWorld({ events, limits: { keptRuns: 1 }, output: 'o' });
  try {
    const first = (await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x', events: true, outputs: ['out.txt'] })).id;
    await w.c.events(first);
    const a = w.map.get(first);
    for (let i = 0; i < 50 && !a.timer; i++) await sleep(20);
    await w.c.events((await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x' })).id);
    assert.deepEqual([w.map.has(first), a.kept, a.outputs, a.timer], [false, null, null, null], 'the run cap forgets the oldest ended run the same way');
  } finally { w.close(); }
  w = await fakeWorld({ events, limits: { keepMs: 100 } });
  try {
    const id = (await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x', events: true })).id;
    await w.c.events(id);
    const a = w.map.get(id);
    for (let i = 0; i < 50 && w.map.has(id); i++) await sleep(20);
    assert.deepEqual([w.map.has(id), a.kept, a.result], [false, null, null], 'keepMs forgets it the same way');
    await assert.rejects(w.c.getRun(id), { status: 404 });
  } finally { w.close(); }
});

test('service: after the memory cap forgets runs, the heap holds about what is accounted, not every run ever kept', () => {
  // review 2's measurement: 40 runs of wide events (each about 2 MiB in memory), keptBytes 20 MiB, in a process with gc exposed
  const script = `
    import { mkdtempSync, mkdirSync } from 'node:fs'; import { tmpdir } from 'node:os'; import { join } from 'node:path'; import { createHash } from 'node:crypto';
    import { createService } from ${JSON.stringify(join(HERE, '..', 'src', 'server.mjs'))}; import { harnessbox } from ${JSON.stringify(join(HERE, '..', 'src', 'client.mjs'))};
    const root = mkdtempSync(join(tmpdir(), 'hb-heap-')), runs = join(root, 'runs'), sock = join(root, 's'); mkdirSync(runs);
    const line = JSON.stringify({ type: 'w', s: '一' + 'a'.repeat(60000) });
    const hb = { run: async (s, h, o) => { o.onStart(); for (let i = 0; i < 40; i++) o.onEvent(JSON.parse(line), { stage: '' }); return { code: 0, text: '', usage: { input: 0, output: 0 }, error: '', stderr: '', why: null, timedOut: false, canceled: false }; } };
    const token = 'token-of-client-c-0123456789';
    const svc = createService({ hb, harnesses: [{ id: 'codex', name: 'Codex', usable: true }], runs, limits: { keptBytes: 20 * 2 ** 20 },
      clients: [{ id: 'appc', tokenSha256: createHash('sha256').update(token).digest('hex'), events: true }] });
    await new Promise((r) => svc.server.listen(sock, r));
    const c = harnessbox({ socketPath: sock, token }), settle = async () => { for (let k = 0; k < 3; k++) { globalThis.gc(); await new Promise((r) => setTimeout(r, 100)); } };
    await settle();
    const h0 = process.memoryUsage().heapUsed;
    for (let i = 0; i < 40; i++) await c.events((await c.run({ user: 'u1', harness: 'codex', prompt: 'x', events: true })).id);
    await new Promise((r) => setTimeout(r, 300)); await settle();
    let accounted = 0; for (const r of svc.runs.values()) accounted += r.bytes ?? 0;
    console.log(JSON.stringify({ kept: svc.runs.size, accounted, heap: process.memoryUsage().heapUsed - h0 }));
    svc.close(); process.exit(0);`;
  const r = spawnSync(process.execPath, ['--expose-gc', '--input-type=module', '-e', script], { encoding: 'utf8', timeout: 120e3 });
  assert.equal(r.status, 0, r.stderr);
  const m = JSON.parse(r.stdout.trim().split('\n').at(-1));
  assert.ok(m.kept < 40 && m.accounted <= 20 * 2 ** 20, JSON.stringify(m));
  assert.ok(m.heap < m.accounted * 1.5, `heap grew ${(m.heap / 2 ** 20).toFixed(1)} MiB for ${(m.accounted / 2 ** 20).toFixed(1)} MiB accounted`);
});

test('service: U+2028 and U+2029 in an event and in result.text come back unchanged through events() and getRun, never raw on the wire', async () => {
  const title = 'line\u2028separator and paragraph\u2029separator', text = 'last\u2028message\u2029';
  const event = { type: 'item.completed', item: { type: 'web_search', title } };
  for (const events of [[event], []]) {
    const w = await fakeWorld({ events, result: { text } });
    try {
      const id = (await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x', events: events.length > 0 })).id;
      const seen = [];
      const ended = await w.c.events(id, (e, run) => seen.push(`${e}:${run.state}`)), got = await w.c.getRun(id);
      assert.deepEqual(ended, got);
      assert.equal(seen.at(-1), 'end:done');
      assert.equal(got.result.text, text);
      if (events.length) assert.deepEqual(got.result.events, [event]);
      // what a client copied from 0.3.0 reads (a regex whose $ also ends a line at U+2028): the server writes them escaped
      const wire = await new Promise((done) => {
        http.get({ socketPath: w.sock, path: `/v1/runs/${id}/events`, headers: { authorization: `Bearer ${TOKEN.c}` } }, (res) => {
          let t = ''; res.setEncoding('utf8'); res.on('data', (d) => { t += d; }); res.on('end', () => done(t));
        });
      });
      assert.doesNotMatch(wire, /[\u2028\u2029]/);
      assert.match(wire, /\\u2028/);
      assert.deepEqual(JSON.parse(/^data: (.+)$/m.exec(wire)[1]), got, 'the old client\'s parse gives the same run');
    } finally { w.close(); }
  }
});

test('client: a data line holding raw U+2028 and U+2029 (as a 0.3.0 server sent them) is one line', async () => {
  const root = mkdtempSync(join(tmpdir(), 'hb-client-sse-')), sock = join(root, 'fake.sock');
  const run = { id: 'run_x', state: 'done', result: { text: 'a\u2028b\u2029c' } };
  const fake = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end(`event: end\ndata: ${JSON.stringify(run)}\n\n`);
  });
  await new Promise((r) => fake.listen(sock, r));
  try {
    assert.match(JSON.stringify(run), /\u2028/, 'JSON.stringify leaves it raw');
    assert.deepEqual(await harnessbox({ socketPath: sock, token: TOKEN.a }).events('run_x'), run);
  } finally {
    fake.closeAllConnections();
    fake.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test('service: result.events holds objects only: an array, null or scalar handed to onEvent is not kept', async () => {
  const w = await fakeWorld({ events: [[1], { type: 'a' }, null, [{ type: 'x' }], 7, 'text', { type: 'z', n: 1.0 }] });
  try {
    const id = (await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x', events: true })).id;
    const ended = await w.c.events(id), got = await w.c.getRun(id);
    assert.deepEqual(ended, got);
    assert.equal(got.state, 'done');
    assert.deepEqual(got.result.events, [{ type: 'a' }, { type: 'z', n: 1 }]);
    assert.equal(got.result.eventsTruncated, false);
  } finally { w.close(); }
});

test('service: event and item types that are Object.prototype keys or end in half a surrogate pair stay plain strings', async () => {
  const pad = 'x'.repeat(70000);
  const w = await fakeWorld({ events: [{ type: `${'T'.repeat(99)}\u{1F600}`, pad }, { type: 'T'.repeat(200), pad }, { type: `${'S'.repeat(39)}\u{1F600}` }],
    harnesses: [...ROWS, { id: 'toString', name: 'Odd', version: '1.0.0', usable: true, why: null, webSearch: false }] });
  try {
    const r = await w.c.events((await w.c.run({ user: 'u1', harness: 'codex', prompt: 'x', events: true })).id);
    assert.deepEqual(r.result.events.slice(0, 2), [{ type: 'T'.repeat(99), truncated: true }, { type: 'T'.repeat(100), truncated: true }], 'never half a pair');
    assert.equal(r.stage, 'S'.repeat(39));
    // a harness id that is an Object.prototype key, with no models configured: any well-formed model, not a 500
    assert.equal((await w.a.events((await w.a.run({ user: 'u1', harness: 'toString', prompt: 'x', model: 'm1' })).id)).state, 'done');
  } finally { w.close(); }
});

test('service: outputs past outputsBytes are null without using up the room, and an output named __proto__ is kept', async () => {
  const w = await fakeWorld({ limits: { outputsBytes: 2000 }, output: { a: 'a'.repeat(1500), b: 'b'.repeat(1000), c: 'c'.repeat(10), ['__proto__']: 'p' } });
  try {
    const r = await w.a.events((await w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', outputs: ['a', 'b', 'c', '__proto__'] })).id);
    assert.deepEqual(Object.entries(r.outputs).map(([k, v]) => [k, unb64(v)?.length ?? null]), [['a', 1500], ['b', null], ['c', 10], ['__proto__', 1]]);
    assert.equal(w.map.get(r.id).bytes, Math.ceil(1511 / 3) * 4 + Buffer.byteLength(FAKE_RESULT.text), 'held outputs at their base64 size');
  } finally { w.close(); }
});

test('service: a request URL that does not parse is a 400; events() on an unknown run rejects with the service\'s code', async () => {
  const w = await fakeWorld();
  try {
    const r = await raw(w.sock, 'GET', 'http://[x/v1/harnesses', { authorization: `Bearer ${TOKEN.a}` });
    assert.equal(r.status, 400);
    assert.equal(JSON.parse(r.body).error.code, 'bad_request');
    await assert.rejects(w.a.events('run_nope'), (e) => e instanceof HarnessboxError && e.status === 404 && e.code === 'unknown_run');
  } finally { w.close(); }
});

test('service: a login started while a purge waits for the locks stays visible, counted and cancelable; expiresAt is the runner\'s', async () => {
  const root = mkdtempSync(join(tmpdir(), 'hb-purge-svc-')), sock = join(root, 'hb.sock'), made = [];
  let letPurge;
  const hb = {
    // a stand-in for the runner's session: its box (and its 10 minutes) and URL after 300 ms; the runner's purge cancels the user's
    // logins first, then waits
    login: (scoped) => {
      let ok, end;
      const s = { scoped, state: 'starting', url: null, code: null, needsCode: false, expiresAt: null, submitCode: () => false, waiting: new Promise((r) => { ok = r; }), done: new Promise((r) => { end = r; }),
        cancel() { if (s.state === 'starting' || s.state === 'waiting') { s.state = 'failed'; s.error = 'canceled'; end({ ok: false, error: 'canceled' }); } } };
      setTimeout(() => { if (s.state === 'starting') { Object.assign(s, { state: 'waiting', url: 'https://claude.ai/oauth', expiresAt: Date.now() + 10 * 60e3 }); ok({}); } }, 300);
      made.push(s);
      return s;
    },
    purge: (scoped) => { for (const s of made) if (s.scoped === scoped) s.cancel(); return new Promise((r) => { letPurge = r; }); },
  };
  const svc = createService({ hb, harnesses: ROWS, runs: root, limits: { logins: 1 }, clients: [{ id: 'appa', tokenSha256: hex(TOKEN.a) }] });
  await new Promise((r) => svc.server.listen(sock, r));
  const a = harnessbox({ socketPath: sock, token: TOKEN.a });
  try {
    const before = await a.login('u1', 'codex');
    assert.equal(before.state, 'waiting');
    assert.equal(Date.parse(before.expiresAt), made[0].expiresAt, 'the runner\'s deadline, which began with its box');
    assert.ok(Date.parse(before.expiresAt) - Date.parse(before.startedAt) >= 10 * 60e3 + 250, 'not counted from the request');
    const purge = a.purge('u1');
    await sleep(100);
    assert.equal((await a.login('u1', 'claude-code')).state, 'waiting');
    letPurge();
    await purge;
    await assert.rejects(a.loginState('u1', 'codex'), { status: 404, code: 'no_login' });
    assert.equal((await a.loginState('u1', 'claude-code')).state, 'waiting');
    await assert.rejects(a.login('u2', 'claude-code'), { status: 429, code: 'too_many_logins' });
    await a.cancelLogin('u1', 'claude-code');
  } finally { svc.close(); rmSync(root, { recursive: true, force: true }); }
});

test('service: answer bytes a client has not read are capped: a 429 for GET, an event stream closed, POST still answers; one answer always goes; inflight is at least the body cap', async () => {
  // answers of 1.4 MiB (a 1 MiB output as base64), past both the 1 MiB cap and what the kernel's socket buffers take
  const w = await fakeWorld({ limits: { answerBytes: 2 ** 20, body: 3000, inflightBytes: 100 }, output: 'o'.repeat(2 ** 20) });
  try {
    const run = await w.a.events((await w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x'.repeat(2500), outputs: ['out.txt'] })).id); // a body past inflightBytes
    assert.equal(run.state, 'done');
    assert.equal((await w.a.getRun(run.id)).id, run.id, 'nothing owed: an answer past the cap still goes');
    // a socket that asks and never reads: its answer waits in the service
    const stuck = net.connect(w.sock);
    stuck.write(`GET /v1/runs/${run.id} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${TOKEN.a}\r\n\r\n`);
    stuck.pause();
    await sleep(200);
    await assert.rejects(w.a.getRun(run.id), { status: 429, code: 'too_many_answers' });
    await assert.rejects(w.a.events(run.id), (e) => e instanceof HarnessboxError && e.code === 'stream_ended', 'the end event does not fit: the stream closes');
    const started = w.calls.length;
    assert.equal((await w.a.run({ user: 'u2', harness: 'claude-code', prompt: 'y' })).state !== undefined, true, 'POST answers with the run it started');
    assert.equal(w.calls.length, started + 1);
    stuck.destroy();
    await sleep(100);
    assert.equal((await w.a.getRun(run.id)).id, run.id, 'read (or gone), the bytes are paid back');
  } finally { w.close(); }
  // clients gone while their runs' files were still being written: their answers are never written, so never owed
  const w2 = await fakeWorld({ limits: { answerBytes: 2 ** 20 }, output: 'o'.repeat(2 ** 20) });
  try {
    const run = await w2.a.events((await w2.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', outputs: ['out.txt'] })).id);
    for (let i = 0; i < 3; i++) {
      const files = Array.from({ length: 1500 }, (_, n) => ({ path: `f${n}`, text: 'x' }));
      const data = JSON.stringify({ user: 'u3', harness: 'claude-code', prompt: 'z', files });
      const s = net.connect(w2.sock);
      s.on('error', () => {});
      s.write(`POST /v1/runs HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${TOKEN.a}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(data)}\r\n\r\n${data}`);
      const before = w2.map.size;
      while (w2.map.size === before) await new Promise(setImmediate); // admitted: its files are being written now
      s.destroy();
      await sleep(500);
    }
    assert.equal(w2.map.size, 4, 'the three runs were made');
    assert.equal((await w2.a.getRun(run.id)).id, run.id, 'nothing owed for answers that were never written');
  } finally { w2.close(); }
});

test('service: a run tmpfs with no room is a 507 no_space and leaves no folder; a path clash is still a 400', { skip: spawnSync('unshare', ['-rm', 'true']).status !== 0 && 'needs unshare -rm' }, () => {
  const root = mkdtempSync(join(tmpdir(), 'hb-nospace-')), runs = join(root, 'runs');
  mkdirSync(runs);
  // in a mount namespace of its own: runs/ is a 256 KiB tmpfs; a fake runner, a 1 MiB file
  const script = `
    import { createService } from ${JSON.stringify(join(HERE, '..', 'src', 'server.mjs'))};
    import { harnessbox } from ${JSON.stringify(join(HERE, '..', 'src', 'client.mjs'))};
    import { createHash } from 'node:crypto';
    import { readdirSync } from 'node:fs';
    const runs = ${JSON.stringify(runs)}, sock = ${JSON.stringify(join(root, 'hb.sock'))}, token = 'token-of-client-a-0123456789';
    const svc = createService({ hb: { run: async () => ({}) }, runs, harnesses: [{ id: 'claude-code', name: 'Claude Code', version: '2.1.300', usable: true, why: null }],
      clients: [{ id: 'appa', tokenSha256: createHash('sha256').update(token).digest('hex') }] });
    await new Promise((r) => svc.server.listen(sock, r));
    const a = harnessbox({ socketPath: sock, token }), out = [];
    for (const files of [[{ path: 'big', text: 'x'.repeat(2 ** 20) }], [{ path: 'a', text: 'x' }, { path: 'a/b', text: 'y' }]]) {
      await a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', files }).then(() => out.push('ok'), (e) => out.push(e.status + ' ' + e.code));
    }
    out.push(readdirSync(runs).length);
    console.log(JSON.stringify(out));
    svc.close();`;
  try {
    const r = spawnSync('unshare', ['-rm', 'sh', '-c', `mount -t tmpfs -o size=256k none "$1" && exec "$2" --input-type=module -e "$3"`, 'sh', runs, process.execPath, script], { encoding: 'utf8', timeout: 30e3 });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout.trim().split('\n').at(-1)), ['507 no_space', '400 bad_files', 0]);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('service: a status or logout box that failed is a 503 status_failed with its reason; busy stays a 409', async () => {
  let fail = new Error('the status check did not finish in time');
  const w = await fakeWorld({ hb: { status: async () => { throw fail; }, logout: async () => { throw fail; } } });
  try {
    await assert.rejects(w.a.status('u1', 'claude-code'), { status: 503, code: 'status_failed', message: 'the status check did not finish in time' });
    await assert.rejects(w.a.logout('u1', 'claude-code'), { status: 503, code: 'status_failed' });
    fail = new Busy('busy');
    await assert.rejects(w.a.logout('u1', 'claude-code'), { status: 409, code: 'busy' });
  } finally { w.close(); }
});

test('service: path segments are counted in bytes: a Korean file name past 255 bytes is a 400, one at 255 bytes is written', async () => {
  const w = await fakeWorld({ output: { ['사'.repeat(85)]: 'ok' } }); // 255 bytes
  try {
    const long = `materials/${'사진'.repeat(45)}.jpg`; // 274 bytes in its last segment
    await assert.rejects(w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', files: [{ path: long, text: 'x' }] }), { status: 400, code: 'bad_files' });
    await assert.rejects(w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', outputs: [`out/${'사진'.repeat(45)}/x`] }), { status: 400, code: 'bad_path' });
    await assert.rejects(w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', readonly: ['사'.repeat(86)] }), { status: 400, code: 'bad_path' });
    const r = await w.a.events((await w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', files: [{ path: `in/${'사'.repeat(85)}`, text: 'x' }], outputs: ['사'.repeat(85)] })).id);
    assert.equal(unb64(r.outputs['사'.repeat(85)]), 'ok');
  } finally { w.close(); }
});

test('service: a readonly folder given twice is a 400; a client entry whose harnesses is not an array of ids stops the service', async () => {
  const w = await fakeWorld();
  try {
    await assert.rejects(w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', readonly: ['skill', 'skill'] }), { status: 400, code: 'bad_path' });
    assert.equal((await w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', readonly: ['skill', 'other'] })).harness, 'claude-code');
  } finally { w.close(); }
  for (const harnesses of ['codex', [1], null]) {
    assert.throws(() => createService({ hb: {}, harnesses: ROWS, runs: '/nonexistent', clients: [{ id: 'appa', tokenSha256: hex(TOKEN.a), harnesses }] }), /harnesses must be an array of ids/, JSON.stringify(harnesses));
  }
});

test('service: an ended run\'s folder goes even when the box made folders in it 0555 or 000', async () => {
  const w = await fakeWorld({ hb: { run: async (scoped, h, o) => {
    o.onStart();
    mkdirSync(join(o.dir, 'd', 'e'), { recursive: true });
    writeFileSync(join(o.dir, 'd', 'e', 'big'), 'x'.repeat(1000));
    mkdirSync(join(o.dir, 'z'));
    chmodSync(join(o.dir, 'd', 'e'), 0o555);
    chmodSync(join(o.dir, 'd'), 0o555);
    chmodSync(join(o.dir, 'z'), 0o000);
    return { ...FAKE_RESULT };
  } } });
  try {
    for (let i = 0; i < 2; i++) assert.equal((await w.a.events((await w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x' })).id)).state, 'done');
    await sleep(100);
    assert.deepEqual(readdirSync(w.runs), []);
  } finally { w.close(); }
});

test('client: a url that is not http: is refused; an IPv6 url reaches the service', async (t) => {
  assert.throws(() => harnessbox({ url: 'https://127.0.0.1:8740', token: 'x'.repeat(20) }), /plain HTTP/);
  const srv = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ harnesses: [], auth: req.headers.authorization })); });
  try { await new Promise((ok, fail) => { srv.once('error', fail); srv.listen(0, '::1', ok); }); } catch { return t.skip('no IPv6 loopback'); }
  try {
    const r = await harnessbox({ url: `http://[::1]:${srv.address().port}`, token: 'token-0123456789abcdef' }).harnesses();
    assert.equal(r.auth, 'Bearer token-0123456789abcdef');
  } finally { srv.close(); }
});

test('main: an unknown HB_HARNESSES id stops the service at start; spaces around the commas are fine', () => {
  for (const [value, bad] of [['claude-code, Codex', 'Codex'], ['claude-code,,codex', '']]) {
    const r = spawnSync(process.execPath, [join(HERE, '..', 'src', 'server.mjs')], { encoding: 'utf8', timeout: 30e3, env: { PATH: process.env.PATH, HB_HARNESSES: value, HB_CLIENTS: '/nonexistent/clients.json' } });
    assert.notEqual(r.status, 0);
    assert.ok(r.stderr.includes(`HB_HARNESSES: no harness ${JSON.stringify(bad)}`), r.stderr);
  }
  const ok = spawnSync(process.execPath, [join(HERE, '..', 'src', 'server.mjs')], { encoding: 'utf8', timeout: 30e3, env: { PATH: process.env.PATH, HB_HARNESSES: 'claude-code, codex', HB_CLIENTS: '/nonexistent/clients.json' } });
  assert.ok(!ok.stderr.includes('HB_HARNESSES') && ok.stderr.includes('/nonexistent/clients.json'), 'past the harness check, to the clients file');
});

test('main: HB_LISTEN is host:port or [v6]:port for TCP, anything else a socket path', () => {
  assert.deepEqual(listenOf('0.0.0.0:8740'), { host: '0.0.0.0', port: 8740 });
  assert.deepEqual(listenOf('harnessbox:8740'), { host: 'harnessbox', port: 8740 });
  assert.deepEqual(listenOf('[::1]:8740'), { host: '::1', port: 8740 });
  assert.deepEqual(listenOf('[::]:8740'), { host: '::', port: 8740 });
  for (const p of ['/run/harnessbox/hb.sock', '[::1]', 'relative.sock', '/a:1']) assert.deepEqual(listenOf(p), { path: p });
});

test('client: neither socketPath nor url is refused (node:http would send the token to localhost:80)', () => {
  for (const o of [{}, { socketPath: undefined }, { url: '' }]) assert.throws(() => harnessbox({ ...o, token: 'x'.repeat(20) }), /socketPath or url is required/);
});

test('service: an ended run whose validator failed still counts its text and stderr against keptBytes', async () => {
  const w = await fakeWorld({ limits: { keptBytes: 6000 }, result: { text: 'x'.repeat(3000), stderr: 'e'.repeat(1000) }, hb: { exec: async () => { throw new Error('validator box failed'); } } });
  try {
    const job = () => w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', validate: { argv: ['true'] } });
    const first = await w.a.events((await job()).id);
    assert.equal(first.state, 'failed');
    for (let i = 0; i < 50 && w.map.get(first.id)?.bytes === undefined; i++) await sleep(20); // the end's bookkeeping follows the end event
    assert.equal(w.map.get(first.id).bytes, 4000);
    await w.a.events((await job()).id);
    for (let i = 0; i < 50 && w.map.has(first.id); i++) await sleep(20);
    await assert.rejects(w.a.getRun(first.id), { status: 404, code: 'unknown_run' }, 'two runs of 4000 pass 6000: the first goes');
  } finally { w.close(); }
});

test('service: a run canceled while its validator waits for a slot ends canceled like any cancel: no error, outputs read', async () => {
  let waiting;
  const w = await fakeWorld({ output: 'draft', hb: { exec: (u, h, argv, o) => new Promise((_, no) => { waiting = true; o.signal.addEventListener('abort', () => no(o.signal.reason)); }) } });
  try {
    const { id } = await w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', outputs: ['out.txt'], validate: { argv: ['true'] } });
    for (let i = 0; i < 50 && !waiting; i++) await sleep(20);
    assert.equal((await w.a.getRun(id)).state, 'validating');
    await w.a.cancelRun(id);
    const r = await w.a.events(id);
    assert.equal(r.state, 'canceled');
    assert.equal(r.error, undefined);
    assert.equal(r.validator, null);
    assert.equal(unb64(r.outputs['out.txt']), 'draft');
  } finally { w.close(); }
});

test('service: a validator box that bwrap could not set up is the run\'s error, as a spawn with no process is; never the validator\'s answer', async () => {
  for (const exec of [async () => ({ code: 1, out: 'bwrap: Creating new namespace failed\n', why: 'the box did not start' }), async () => { throw new Error('the box did not start (spawn failed)'); }]) {
    const w = await fakeWorld({ output: 'draft', hb: { exec } });
    try {
      const r = await w.a.events((await w.a.run({ user: 'u1', harness: 'claude-code', prompt: 'x', outputs: ['out.txt'], validate: { argv: ['true'] } })).id);
      assert.equal(r.state, 'failed');
      assert.match(r.error, /box did not start/);
      assert.equal(r.result.code, 0, 'the CLI\'s own result');
      assert.equal(r.validator, null);
      assert.equal(r.outputs, null);
    } finally { w.close(); }
  }
});

// ---- client versions: each released client (test/compat) against this service, and a client the service needs newer
const COMPAT = join(HERE, 'compat'), CLIENT_SRC = readFileSync(join(HERE, '..', 'src', 'client.mjs'), 'utf8');
const RELEASED = readdirSync(COMPAT).flatMap((f) => /^client-(\d+\.\d+\.\d+)\.mjs$/.exec(f)?.[1] ?? []).sort((x, y) => (older(x, y) ? -1 : 1));
const KEY_IN = (src) => /Buffer\.from\('([A-Za-z0-9+/=]+)', 'base64'\), format: 'der'/.exec(src)?.[1];
const loadClient = (src) => import(`data:text/javascript;base64,${Buffer.from(src).toString('base64')}`);

test('client: src/client.mjs is the released client of its VERSION (test/compat), signed by the key it trusts; MIN_CLIENT has its copy', () => {
  assert.equal(readFileSync(join(COMPAT, `client-${CLIENT_VERSION}.mjs`), 'utf8'), CLIENT_SRC, 'a changed client is a new VERSION, copied to test/compat');
  assert.ok(!older(VERSION, CLIENT_VERSION), 'the client\'s VERSION is a release of this package, at most this one');
  assert.ok(RELEASED.includes(MIN_CLIENT), 'the oldest client the service takes is tested');
  const key = { key: Buffer.from(KEY_IN(CLIENT_SRC), 'base64'), format: 'der', type: 'spki' };
  assert.ok(verify(null, Buffer.from(CLIENT_SRC), key, Buffer.from(readFileSync(join(HERE, '..', 'src', 'client.mjs.sig'), 'utf8'), 'base64')), 'npm run sign-client after changing the client');
});

test('compat: every released client from MIN_CLIENT on: harnesses, a login, a draft job with events and outputs, error codes, logout, purge', BOX, async () => {
  const w = await world();
  try {
    // the ones before 0.5.0 send no version and count as 0.4.0: they run as long as the service takes 0.4.0
    for (const v of RELEASED.filter((x) => !older(older(x, '0.5.0') ? '0.4.0' : x, MIN_CLIENT))) {
      const hb = (await import(join(COMPAT, `client-${v}.mjs`))).harnessbox({ socketPath: w.sock, token: TOKEN.a }), user = `compat${v.replaceAll('.', '')}`;
      assert.deepEqual((await hb.harnesses()).harnesses.map((h) => [h.id, h.usable]), [['claude-code', true], ['codex', true], ['grok', true]], v);
      assert.equal((await hb.status(user, 'codex')).loggedIn, false, v);
      let s = await hb.login(user, 'codex');
      assert.deepEqual([s.state, s.code], ['waiting', 'FAKE-12345'], v);
      for (let i = 0; i < 50 && (s = await hb.loginState(user, 'codex')).state !== 'done'; i++) await sleep(100);
      assert.deepEqual([s.state, s.status?.loggedIn], ['done', true], v);
      w.logIn('appa', user, 'claude-code');
      const seen = [], r = await hb.events((await hb.run(draftJob(user, 'claude-code'))).id, (event) => seen.push(event));
      assert.deepEqual([r.state, r.result.text, unb64(r.outputs['out/draft.md']), seen.at(-1)], ['done', 'done (rva)', '# draft\n', 'end'], v);
      assert.deepEqual(Object.keys(r.result), RESULT_020, v);
      assert.equal((await hb.getRun(r.id)).state, 'done', v);
      await assert.rejects(hb.getRun('nope'), { status: 404, code: 'unknown_run' }, v);
      assert.equal(await hb.cancelRun(r.id), null, v);
      assert.equal((await hb.logout(user, 'codex')).loggedIn, false, v);
      assert.equal(await hb.purge(user), null, v);
      assert.ok(w.logs.includes(`client appa uses client ${older(v, '0.5.0') ? 'before 0.5.0' : v}`), v);
    }
  } finally { await w.close(); }
});

test('service: a client version that is not x.y.z is a 400, one under minClient a 426 but for GET /v1/client; every answer names the service\'s version', async () => {
  const logs = [], w = await fakeWorld({ service: { minClient: '0.5.0', log: (l) => logs.push(l) } });
  try {
    const ask = (path, v) => raw(w.sock, 'GET', path, { authorization: `Bearer ${TOKEN.a}`, ...(v ? { 'harnessbox-client': v } : {}) });
    assert.equal((await ask('/v1/harnesses', 'x')).status, 400);
    assert.equal(JSON.parse((await ask('/v1/harnesses', '0.4.9')).body).error.code, 'client_too_old');
    assert.equal((await ask('/v1/harnesses')).status, 426, 'one without the header is from before 0.5.0');
    assert.equal((await ask('/v1/harnesses', '0.5.0')).status, 200);
    const c = JSON.parse((await ask('/v1/client', '0.2.0')).body);
    assert.deepEqual([c.version, c.minClient, c.source], [CLIENT_VERSION, '0.5.0', CLIENT_SRC]);
    const res = await new Promise((done) => http.get({ socketPath: w.sock, path: '/nope' }, done));
    assert.equal(res.headers['harnessbox-version'], VERSION);
    await assert.rejects((await import(join(COMPAT, 'client-0.4.0.mjs'))).harnessbox({ socketPath: w.sock, token: TOKEN.a }).harnesses(), { status: 426, code: 'client_too_old' });
    // each version logged once, at most 8 per client, then one line: a client sending many cannot hide another's
    for (let i = 0; i < 12; i++) await ask('/v1/harnesses', `1.0.${i}`);
    await raw(w.sock, 'GET', '/v1/harnesses', { authorization: `Bearer ${TOKEN.c}`, 'harnessbox-client': '0.5.0' });
    const lines = logs.filter((l) => l.startsWith('client '));
    assert.equal(lines.filter((l) => l.startsWith('client appa uses client ')).length, 8);
    assert.equal(lines.filter((l) => l === 'client appa uses more client versions (not logged)').length, 1);
    assert.ok(lines.includes('client appc uses client 0.5.0'));
  } finally { w.close(); }
});

test('client: under the service\'s minimum it loads the signed client the service hands out and asks again; unsigned, tampered, older or still too old is refused', async () => {
  const mine = generateKeyPairSync('ed25519'), theirs = generateKeyPairSync('ed25519');
  const pub = mine.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const variant = (v) => CLIENT_SRC.replace(/export const VERSION = '[^']+'/, `export const VERSION = '${v}'`).replace(KEY_IN(CLIENT_SRC), pub);
  const handOut = (v, { key = mine.privateKey, tamper = false } = {}) => ({ version: v, source: variant(v) + (tamper ? '\n// changed\n' : ''), signature: sign(null, Buffer.from(variant(v)), key).toString('base64') });
  let n = 0; // a module of its own per case: what a process loaded is kept per module
  const appCopy = () => loadClient(`${variant('0.5.0')}// copy ${n++}\n`); // the copy an app has, trusting the test key
  const cases = [
    [handOut('0.6.0'), null], [handOut('0.6.0', { tamper: true }), 'client_update_failed'], [handOut('0.6.0', { key: theirs.privateKey }), 'client_update_failed'],
    [{ ...handOut('0.6.0'), signature: 'not base64 at all' }, 'client_update_failed'], [handOut('0.4.0'), 'client_update_failed'], [handOut('0.5.5'), 'client_update_failed'],
  ];
  for (const [handed, code] of cases) {
    let downloads = 0;
    const client = { ...handed, get source() { downloads++; return handed.source; } };
    const logs = [], w = await fakeWorld({ service: { minClient: '0.6.0', client, log: (l) => logs.push(l) } }), app = await appCopy();
    try {
      const hb = app.harnessbox({ socketPath: w.sock, token: TOKEN.a });
      if (code) { await assert.rejects(hb.harnesses(), { status: 426, code }, `${handed.version} ${code}`); continue; }
      const all = await Promise.all([hb.harnesses(), hb.harnesses(), hb.harnesses(), hb.getRun('nope').catch((e) => e), hb.harnesses()]);
      assert.equal(all[0].harnesses.length, 3);
      assert.equal(downloads, 1, 'one download for calls at once');
      assert.deepEqual(logs.filter((l) => l.startsWith('client ')), ['client appa uses client 0.5.0', 'client appa uses client 0.6.0']);
      assert.ok(all[3] instanceof app.HarnessboxError && all[3] instanceof HarnessboxError && all[3].code === 'unknown_run', 'errors of the loaded copy are HarnessboxErrors of every copy');
      assert.equal((await hb.harnesses()).harnesses.length, 3);
      assert.equal((await app.harnessbox({ socketPath: w.sock, token: TOKEN.a }).harnesses()).harnesses.length, 3, 'a new client object starts from what the process loaded');
      assert.equal(downloads, 1);
      await assert.rejects(app.harnessbox({ socketPath: w.sock, token: TOKEN.a, autoUpdate: false }).harnesses(), { status: 426, code: 'client_too_old' }, 'autoUpdate: false is this copy only');
    } finally { w.close(); }
  }
  // a service that lies (426 to every client, a minimum of 0.1.0): it cannot roll a copy back under itself or under what the process
  // loaded, and an older signed client never runs, not even its top-level code
  const root = mkdtempSync(join(tmpdir(), 'hb-liar-')), sock = join(root, 'hb.sock');
  const side = (v) => { const h = handOut(v); const source = `${h.source}globalThis.hbRan = '${v}';\n`; return { ...h, source, signature: sign(null, Buffer.from(source), mine.privateKey).toString('base64') }; };
  const queue = [side('0.4.0'), handOut('0.7.0'), side('0.6.0'), side('0.6.5')], app = await appCopy();
  const liar = http.createServer((req, res) => {
    const [status, body] = req.url === '/v1/client' ? [200, { ...queue.shift(), minClient: '0.1.0' }] : [426, { error: { code: 'client_too_old', message: 'x' } }];
    res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
  });
  await new Promise((r) => liar.listen(sock, r));
  try {
    const hb = app.harnessbox({ socketPath: sock, token: TOKEN.a });
    await assert.rejects(hb.harnesses(), { status: 426, code: 'client_update_failed' }, '0.4.0 is older than the copy');
    await assert.rejects(hb.harnesses(), { status: 426, code: 'client_too_old' }, '0.7.0 loaded; the liar still says 426');
    await assert.rejects(hb.harnesses(), { status: 426, code: 'client_update_failed' }, '0.6.0 is older than the 0.7.0 loaded');
    await assert.rejects(app.harnessbox({ socketPath: sock, token: TOKEN.a }).harnesses(), { status: 426, code: 'client_update_failed' }, 'and so for a new client object');
    assert.equal(globalThis.hbRan, undefined, 'a refused client never ran');
  } finally { liar.close(); rmSync(root, { recursive: true, force: true }); }
  // the real thing: src/client.mjs and its .sig as the service hands them out, the maintainers' key in a copy that is behind
  const real = await fakeWorld({ service: { minClient: CLIENT_VERSION } });
  try {
    const behind = await loadClient(CLIENT_SRC.replace(/export const VERSION = '[^']+'/, "export const VERSION = '0.4.9'"));
    assert.equal((await behind.harnessbox({ socketPath: real.sock, token: TOKEN.a }).harnesses()).harnesses.length, 3, 'npm run sign-client');
  } finally { real.close(); }
  // each released copy that updates itself (0.5.0 on) takes today's client: its VERSION line, exports, /v1/client and error brand
  const today = (v) => CLIENT_SRC.replace(/export const VERSION = '[^']+'/, `export const VERSION = '${v}'`).replace(KEY_IN(CLIENT_SRC), pub);
  for (const v of RELEASED.filter((x) => !older(x, '0.5.0'))) {
    const released = await loadClient(`${readFileSync(join(COMPAT, `client-${v}.mjs`), 'utf8').replace(KEY_IN(CLIENT_SRC), pub)}// released ${v}\n`);
    const source = today('99.0.0'), w = await fakeWorld({ service: { minClient: '99.0.0', client: { version: '99.0.0', source, signature: sign(null, Buffer.from(source), mine.privateKey).toString('base64') } } });
    try {
      const hb = released.harnessbox({ socketPath: w.sock, token: TOKEN.a });
      assert.equal((await hb.harnesses()).harnesses.length, 3, v);
      const e = await hb.getRun('nope').catch((x) => x);
      assert.ok(e instanceof released.HarnessboxError && e.code === 'unknown_run', v);
    } finally { w.close(); }
  }
});
