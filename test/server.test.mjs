// The service end to end: src/server.mjs on a unix socket, driven through src/client.mjs, over the real runner with real bubblewrap
// boxes and the fake CLIs (test/fake-cli.mjs). Two clients, their users kept apart; auth; logins; a review-automation-shaped draft
// job (files in, a read-only skill, out/ files back, a validator in a no-network box); cancel; caps; a restart. webSearch and events
// per client; the tests over a stand-in runner (fakeWorld) need no bubblewrap.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { claudeCode, codex, createRunner, grok } from '../src/index.mjs';
import { harnessbox, HarnessboxError } from '../src/client.mjs';
import { BOX_DIR, createService } from '../src/server.mjs';

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
    assert.deepEqual((await w.a.harnesses()).harnesses.map((h) => [h.id, h.usable]), [['claude-code', true], ['codex', true], ['grok', true]]);
    assert.deepEqual((await w.b.harnesses()).harnesses.map((h) => h.id), ['claude-code'], 'a client sees only its harnesses');
    await assert.rejects(w.b.status('u1', 'codex'), { status: 404, code: 'unknown_harness' });
    await assert.rejects(w.a.status('../x', 'codex'), { status: 400, code: 'bad_user' });

    // Claude Code: URL, then the pasted code; Codex: URL and device code
    let s = await w.a.login('u1', 'claude-code');
    assert.deepEqual([s.state, s.url, s.code, s.needsCode], ['waiting', 'https://claude.com/cai/oauth/authorize?code=true&state=fake-state', null, true]);
    assert.ok(Date.parse(s.expiresAt) - Date.parse(s.startedAt) === 10 * 60e3);
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

test('main: a bad HB_MAX_OUTPUT_BYTES stops the service at start', async () => {
  for (const value of ['0', '-1', '1.5', '8MiB', '']) {
    const r = spawnSync(process.execPath, [join(HERE, '..', 'src', 'server.mjs')], { encoding: 'utf8', timeout: 30e3,
      env: { PATH: process.env.PATH, HB_MAX_OUTPUT_BYTES: value, HB_CLIENTS: '/nonexistent/clients.json' } });
    assert.notEqual(r.status, 0, value);
    assert.match(r.stderr, /HB_MAX_OUTPUT_BYTES must be a positive integer/, value);
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
async function fakeWorld({ events = [], limits = {} } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'hb-fake-svc-')), runs = join(root, 'runs'), sock = join(root, 'hb.sock'), calls = [];
  mkdirSync(runs);
  const hb = {
    run: async (scoped, h, o) => {
      calls.push({ scoped, h, ...o });
      o.onStart();
      for (const e of typeof events === 'function' ? events() : events) o.onEvent(e, { stage: '' });
      return { ...FAKE_RESULT };
    },
    exec: async () => ({ code: 0, out: '{}', why: null }),
  };
  const svc = createService({ hb, harnesses: ROWS, runs, limits,
    clients: [{ id: 'appa', tokenSha256: hex(TOKEN.a) }, { id: 'appc', tokenSha256: hex(TOKEN.c), webSearch: true, events: true }] });
  await new Promise((r) => svc.server.listen(sock, r));
  return { runs, calls, a: harnessbox({ socketPath: sock, token: TOKEN.a }), c: harnessbox({ socketPath: sock, token: TOKEN.c }),
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
