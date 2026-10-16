// box.mjs on its own: the egress proxy (stubbed DNS and upstream), the home scrub, the file reader, the /proc counts, the bwrap argv
// and the seccomp filter (in a real box when bubblewrap can make one).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BOX_TMP_BYTES, boxArgs, countDescendants, diskUse, parseStat, privateIp, readOut, scrubHome, seccompFilter, startProxy } from '../src/box.mjs';

const ALLOW = ['api.anthropic.com', 'platform.claude.com'];
const KEEP = ['.claude/.credentials.json', '.claude.json', '.codex/auth.json'], KEYS = { '.claude.json': ['oauthAccount', 'userID'] };

const tmp = () => mkdtempSync(join(tmpdir(), 'hb-box-test-'));

async function proxyWorld(addresses = {}) {
  const dir = tmp(), sock = join(dir, 'egress.sock'), logs = [], connects = [], lookups = [];
  // the "internet": one local echo server that every allowed CONNECT reaches, whatever IP the proxy dials
  const upstream = net.createServer((s) => { s.on('error', () => {}); s.on('data', (d) => s.write(`echo:${d}`)); });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const server = await startProxy(sock, {
    allow: ALLOW, label: 'job=j1', log: (l) => logs.push(l),
    lookup: async (host, o) => { lookups.push([host, o]); if (host in addresses) return { address: addresses[host], family: 4 }; return { address: '203.0.113.7', family: 4 }; },
    connect: (o) => { connects.push(o); return net.connect(upstream.address().port, '127.0.0.1'); },
  });
  // send raw bytes, collect everything the proxy answers until it closes (or ms pass)
  const talk = (chunks, ms = 1500) => new Promise((done) => {
    const c = net.connect(sock);
    let got = '';
    c.on('data', (d) => { got += d; });
    c.on('error', () => {});
    c.on('connect', async () => {
      for (const ch of chunks) { if (typeof ch === 'function') await ch(c); else c.write(ch); await new Promise((r) => setTimeout(r, 30)); }
    });
    const t = setTimeout(() => { c.destroy(); done(got); }, ms);
    c.on('close', () => { clearTimeout(t); done(got); });
  });
  const close = () => { server.close(); upstream.close(); rmSync(dir, { recursive: true, force: true }); };
  return { sock, logs, connects, lookups, talk, close, server, upstream };
}

test('proxy: an allowed CONNECT goes to the IP it checked on 443 and tunnels both ways; anything else is refused and logged with the label', async () => {
  const w = await proxyWorld({ 'platform.claude.com': '10.0.0.1', 'api.anthropic.com': '203.0.113.7' });
  try {
    assert.equal(statSync(w.sock).mode & 0o777, 0o600);
    // head split across two writes, bytes after the head forwarded
    const ok = await w.talk(['CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.an', 'thropic.com:443\r\n\r\nhello', 'again'], 800);
    assert.match(ok, /^HTTP\/1\.1 200 Connection Established\r\n\r\necho:hello/);
    assert.match(ok, /echo:again/);
    assert.deepEqual(w.lookups.at(-1), ['api.anthropic.com', { family: 4 }]);
    assert.deepEqual(w.connects, [{ host: '203.0.113.7', port: 443 }], 'the checked address, never the name');

    const denied = ['CONNECT example.com:443 HTTP/1.1', 'CONNECT api.anthropic.com:22 HTTP/1.1', 'CONNECT api.anthropic.com:80 HTTP/1.1', 'CONNECT api.anthropic.com:0443 HTTP/1.1',
      'CONNECT api.anthropic.com.:443 HTTP/1.1', 'CONNECT 1.1.1.1:443 HTTP/1.1', 'CONNECT [::1]:443 HTTP/1.1', 'CONNECT evil.api.anthropic.com:443 HTTP/1.1',
      'CONNECT api.anthropic.com.evil.com:443 HTTP/1.1', 'CONNECT chatgpt.com:443 HTTP/1.1', 'CONNECT platform.claude.com:443 HTTP/1.1'];
    for (const line of denied) assert.match(await w.talk([`${line}\r\n\r\n`]), /^HTTP\/1\.1 403 /, line);
    assert.match(await w.talk(['GET http://api.anthropic.com/ HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n']), /^HTTP\/1\.1 405 /);
    assert.match(await w.talk(['CONNECT api.anthropic.com:443 SPDY/3\r\n\r\n']), /^HTTP\/1\.1 405 /);
    assert.deepEqual(w.connects.length, 1, 'no upstream for any refusal, the private address included');
    assert.equal(w.logs.length, denied.length + 2);
    assert.ok(w.logs.every((l) => l.startsWith('egress deny job=j1 ')), w.logs.join('\n'));
    assert.ok(w.logs.includes('egress deny job=j1 platform.claude.com:443 private ip'));
    assert.ok(w.logs.includes('egress deny job=j1 [::1]:443 host') === false && w.logs.some((l) => /<bad>/.test(l)), 'a bracketed or odd host is not echoed');
    // a newline in the target cannot forge a log line
    await w.talk(['CONNECT a\nfake-line:443 HTTP/1.1\r\n\r\n']);
    assert.ok(!w.logs.some((l) => l.includes('fake-line')));
  } finally { w.close(); }
});

test('proxy: allowed names resolving to private, loopback, CGNAT or bridge addresses are refused', async () => {
  for (const ip of ['10.0.0.1', '100.64.0.1', '172.17.0.1', '127.0.0.1', '169.254.1.1', '192.168.0.1', '0.0.0.0', '224.0.0.1']) {
    const w = await proxyWorld({ 'api.anthropic.com': ip });
    try {
      assert.match(await w.talk(['CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n']), /^HTTP\/1\.1 403 /, ip);
      assert.deepEqual(w.connects, []);
    } finally { w.close(); }
  }
});

test('proxy: garbage, an oversized head, a reset mid-tunnel and an upstream error leave it serving the next CONNECT', async () => {
  const w = await proxyWorld();
  try {
    await w.talk([Buffer.from([0, 1, 2, 255, 13, 10, 13, 10])]);
    assert.match(await w.talk(['X'.repeat(9000)]), /^HTTP\/1\.1 431 /);
    await w.talk(['CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\nx', (c) => c.destroy()]);
    // the upstream resets the tunnel
    w.upstream.removeAllListeners('connection');
    w.upstream.on('connection', (s) => s.resetAndDestroy());
    await w.talk(['CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n']);
    w.upstream.removeAllListeners('connection');
    w.upstream.on('connection', (s) => { s.on('error', () => {}); s.on('data', (d) => s.write(`echo:${d}`)); });
    assert.match(await w.talk(['CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\nping'], 800), /echo:ping/);
    assert.equal(w.server.maxConnections, 64);
  } finally { w.close(); }
});

test('privateIp, parseStat and countDescendants', async () => {
  for (const ip of ['10.1.2.3', '127.0.0.1', '100.127.255.255', '172.31.0.1', '192.168.1.1', '169.254.0.1', '198.18.0.1', '192.0.0.8', '240.0.0.1', '::1', 'fe80::1', '::ffff:10.0.0.1', 'nonsense'])
    assert.equal(privateIp(ip), true, ip);
  for (const ip of ['1.1.1.1', '160.79.104.10', '100.128.0.1', '172.32.0.1', '203.0.113.7']) assert.equal(privateIp(ip), false, ip);
  assert.deepEqual(parseStat('4242 (a) (b) S 17 4242 4242 0 -1'), { pid: 4242, ppid: 17 });
  const proc = tmp();
  try {
    // 10 -> 11 -> 12, 11 -> 13; 20 -> 21; 30 alone; a non-numeric entry and an unreadable one are skipped
    for (const [pid, ppid] of [[10, 1], [11, 10], [12, 11], [13, 11], [20, 1], [21, 20], [30, 1]]) {
      mkdirSync(join(proc, String(pid)));
      writeFileSync(join(proc, String(pid), 'stat'), `${pid} (we) ird) S ${ppid} 1 1 0`);
    }
    mkdirSync(join(proc, 'self'));
    mkdirSync(join(proc, '99'));
    assert.deepEqual([...await countDescendants([10, 20, 30, 77], proc)], [[10, 3], [20, 1], [30, 0], [77, 0]]);
  } finally { rmSync(proc, { recursive: true, force: true }); }
});

test('scrubHome keeps only the credential files and the account keys of .claude.json, and never follows a link', async () => {
  const root = tmp(), home = join(root, 'alice'), other = join(root, 'bob');
  try {
    for (const d of [home, other, join(home, '.claude', 'hooks'), join(home, '.claude', 'projects', 'p'), join(home, '.codex'), join(home, '.config', 'anthropic'), join(other, '.claude')]) mkdirSync(d, { recursive: true });
    const files = { '.bashrc': 'evil', '.profile': 'evil', '.claude/settings.json': '{"hooks":{}}', '.claude/hooks/x': 'x', '.claude/projects/p/s.jsonl': '{}', '.codex/config.toml': 'x=1',
      '.config/anthropic/a': 'a', '.claude/.credentials.json': 'CLAUDE-CRED', '.codex/auth.json': 'CODEX-CRED', '.claude.json': JSON.stringify({ oauthAccount: { a: 1 }, userID: 'u1', projects: { '/tmp/rva-job-1': {} }, mcpServers: { x: { command: 'sh' } }, hooks: {} }) };
    for (const [f, t] of Object.entries(files)) writeFileSync(join(home, f), t);
    writeFileSync(join(other, '.claude', 'settings.json'), 'BOB');
    await scrubHome(home, KEEP, KEYS);
    assert.deepEqual(readdirSync(home, { recursive: true }).sort(), ['.claude', '.claude.json', '.claude/.credentials.json', '.codex', '.codex/auth.json']);
    assert.equal(readFileSync(join(home, '.claude', '.credentials.json'), 'utf8'), 'CLAUDE-CRED');
    assert.deepEqual(JSON.parse(readFileSync(join(home, '.claude.json'), 'utf8')), { oauthAccount: { a: 1 }, userID: 'u1' }, 'the account keys only: no planted mcpServers');
    assert.equal(statSync(join(home, '.claude.json')).mode & 0o777, 0o600);

    // links planted by a box: .claude -> another home, a credential file -> another user's, .claude.json -> elsewhere
    rmSync(join(home, '.claude'), { recursive: true });
    symlinkSync(join(other, '.claude'), join(home, '.claude'));
    symlinkSync(join(other, '.claude', 'settings.json'), join(home, '.codex', 'auth.json.tmp'));
    rmSync(join(home, '.codex', 'auth.json'));
    symlinkSync(join(other, '.claude', 'settings.json'), join(home, '.codex', 'auth.json'));
    rmSync(join(home, '.claude.json'));
    symlinkSync(join(other, '.claude', 'settings.json'), join(home, '.claude.json'));
    writeFileSync(join(home, 'broken.json'), '{not json');
    await scrubHome(home, KEEP, KEYS);
    assert.deepEqual(readdirSync(home, { recursive: true }).sort(), ['.codex']);
    assert.equal(readFileSync(join(other, '.claude', 'settings.json'), 'utf8'), 'BOB', 'the target is untouched');

    // a .claude.json that does not parse, or is padded past 1 MB to dodge the parse, is removed
    for (const text of ['{not json', JSON.stringify({ mcpServers: { x: { command: 'sh' } }, pad: 'x'.repeat(2 ** 20) })]) {
      writeFileSync(join(home, '.claude.json'), text);
      await scrubHome(home, KEEP, KEYS);
      assert.ok(!existsSync(join(home, '.claude.json')));
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('readOut reads only a regular file inside the real out/, never what a link points at', async () => {
  const root = tmp(), job = join(root, 'job'), victim = join(root, 'victim');
  try {
    mkdirSync(join(job, 'out'), { recursive: true });
    mkdirSync(victim);
    writeFileSync(join(victim, '.credentials.json'), 'CANARY');
    writeFileSync(join(job, 'out', 'draft.json'), '{"a":1}');
    assert.equal(await readOut(job, 'out/draft.json'), '{"a":1}');
    symlinkSync(join(victim, '.credentials.json'), join(job, 'out', 'evil.json'));
    assert.equal(await readOut(job, 'out/evil.json'), null);
    mkdirSync(join(job, 'out', 'dir'));
    assert.equal(await readOut(job, 'out/dir'), null);
    execFileSync('mkfifo', [join(job, 'out', 'fifo')]);
    assert.equal(await readOut(job, 'out/fifo'), null, 'a FIFO neither blocks nor reads');
    writeFileSync(join(job, 'out', 'big.txt'), 'x'.repeat(101));
    assert.equal(await readOut(job, 'out/big.txt', 100), null);
    assert.equal(await readOut(job, 'out/missing.json'), null);
    // out/ itself a link to the victim's home
    const job2 = join(root, 'job2');
    mkdirSync(job2);
    symlinkSync(victim, join(job2, 'out'));
    assert.equal(await readOut(job2, 'out/.credentials.json'), null);
    assert.ok(lstatSync(join(job2, 'out')).isSymbolicLink());
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('diskUse counts bytes (allocated ones too) without following links and stops at the entry cap', async () => {
  const root = tmp();
  try {
    mkdirSync(join(root, 'a', 'b'), { recursive: true });
    writeFileSync(join(root, 'a', 'b', 'f'), 'x'.repeat(5000));
    symlinkSync('/usr', join(root, 'a', 'usr'));
    const u = await diskUse([root]);
    assert.equal(u.entries, 4);
    assert.ok(u.bytes >= 5000 && u.bytes < 5000 + 3 * 65536, String(u.bytes));
    // space allocated past the size (fallocate --keep-size) counts
    writeFileSync(join(root, 'pad'), '');
    execFileSync('fallocate', ['-n', '-l', '8M', join(root, 'pad')]);
    assert.equal(statSync(join(root, 'pad')).size, 0);
    assert.ok((await diskUse([root])).bytes >= 8 * 2 ** 20);
    for (let i = 0; i < 30; i++) writeFileSync(join(root, `n${i}`), '');
    assert.ok((await diskUse([root], 10)).entries > 10);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('boxArgs: cleared environment, every namespace, no capabilities, sized /tmp and /run, only the own home and folder writable', () => {
  const a = boxArgs({ home: '/homes/alice/claude-code', dir: '/tmp/job-1', net: 'proxy', sock: '/tmp/hb-egress-1.sock', socat: '/usr/bin/socat', path: '/usr/bin:/bin',
    env: { TMPDIR: '/tmp/job-1/.tmp' }, roBinds: [['/app/skill', '/tmp/job-1/skill']], chdir: '/tmp/job-1', cmd: ['claude', '-p', 'x'], seccomp: true });
  const s = a.join(' ');
  for (const f of ['--die-with-parent', '--new-session', '--unshare-all', '--clearenv']) assert.ok(a.indexOf(f) >= 0 && a.indexOf(f) < a.indexOf('--ro-bind'), f);
  assert.match(s, /--cap-drop ALL/);
  assert.ok(!a.includes('--share-net'));
  assert.match(s, new RegExp(`--size ${BOX_TMP_BYTES} --tmpfs /tmp --size ${BOX_TMP_BYTES} --tmpfs /run`));
  const binds = a.flatMap((x, i) => (x === '--bind' ? [a[i + 1]] : []));
  assert.deepEqual(binds, ['/homes/alice/claude-code', '/tmp/job-1'], 'nothing else writable');
  assert.ok(!a.includes('/homes'));
  assert.ok(a.indexOf('/app/skill') > a.indexOf('/tmp/job-1'), 'a read-only bind lies over the writable folder');
  assert.match(s, /--ro-bind \/tmp\/hb-egress-1\.sock \/run\/egress\.sock/);
  assert.ok(a.indexOf('/run/egress.sock') > a.indexOf('/run'), 'the socket over the fresh /run');
  assert.match(s, /--seccomp 3 /);
  assert.match(s, /--setenv HTTPS_PROXY http:\/\/127\.0\.0\.1:3128/);
  assert.match(s, /--setenv TMPDIR \/tmp\/job-1\/\.tmp/);
  assert.deepEqual(a.slice(-5), ['box', '/usr/bin/socat', 'claude', '-p', 'x']);
  assert.match(a.at(-6), /^ulimit -u 512; /, 'the per-box task cap, set inside the box\'s user namespace');
  assert.ok(a.indexOf('--disable-userns') > a.indexOf('--unshare-user'), 'no nested user namespace by default');
  const nested = boxArgs({ home: '/homes/u/codex', dir: '/tmp/j', net: 'none', path: '/usr/bin', maxTasks: 64, nested: true, cmd: ['codex'] });
  assert.ok(!nested.includes('--disable-userns') && !nested.includes('--unshare-user') && !nested.includes('--seccomp'));
  assert.deepEqual(nested.slice(-4), ['-c', 'ulimit -u 64; exec "$@"', 'box', 'codex']);
  const none = boxArgs({ home: '/homes/u/claude-code', dir: '/tmp/j', net: 'none', path: '/usr/bin', cmd: ['python3', '-I', 'v.py'] });
  assert.ok(!none.join(' ').includes('egress') && !none.join(' ').includes('PROXY'));
  assert.deepEqual(none.slice(-3), ['python3', '-I', 'v.py']);
  assert.deepEqual(none.flatMap((x, i) => (x === '--setenv' ? [none[i + 1]] : [])), ['HOME', 'PATH', 'USER', 'LANG', 'SHELL']);
});

test('seccompFilter: one 8-byte instruction per entry, arm64 and x64 only', () => {
  for (const arch of ['arm64', 'x64']) {
    const f = seccompFilter(arch);
    assert.equal(f.length % 8, 0);
    assert.equal(f.readUInt32LE(12), arch === 'arm64' ? 0xc00000b7 : 0xc000003e, 'the arch check comes first');
    assert.equal(f.readUInt32LE(f.length - 4), 0x7fff0000, 'allow is the last word');
  }
  assert.throws(() => seccompFilter('ia32'), /no seccomp filter/);
});

const canBox = spawnSync('bwrap', ['--unshare-all', '--die-with-parent', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib', '--proc', '/proc', '--dev', '/dev', '/usr/bin/true']).status === 0;
const hasPython = spawnSync('python3', ['-c', '']).status === 0;
test('seccompFilter in a real box: io_uring and AF_VSOCK refused, AF_UNIX, AF_INET and socketpair open, a foreign arch killed', { skip: !(canBox && hasPython) && 'needs bubblewrap with user namespaces and python3' }, async () => {
  const home = tmp();
  const py = `import ctypes, socket
l = ctypes.CDLL(None, use_errno=True); l.syscall.restype = ctypes.c_long
def sock(f):
  try: socket.socket(f, socket.SOCK_STREAM).close(); return 'ok'
  except OSError as e: return e.errno
def ring():
  p = ctypes.create_string_buffer(120); r = l.syscall(425, 4, p); return 'ok' if r >= 0 else ctypes.get_errno()
socket.socketpair()
print(sock(socket.AF_UNIX), sock(40), sock(socket.AF_INET), ring())`;
  const box = (filter) => new Promise((done) => {
    const c = spawn('bwrap', boxArgs({ home, net: 'none', path: '/usr/bin:/bin', cmd: ['python3', '-c', py], seccomp: true }), { stdio: ['ignore', 'pipe', 'pipe', 'pipe'] });
    let out = '';
    c.stdout.on('data', (d) => { out += d; });
    c.stderr.on('data', (d) => { out += d; });
    c.stdio[3].on('error', () => {}).end(filter);
    c.on('close', (code, signal) => done({ code, signal, out: out.trim() }));
  });
  try {
    const r = await box(seccompFilter());
    assert.equal(r.code, 0, r.out);
    assert.equal(r.out, 'ok 1 ok 1', 'unix ok, vsock EPERM, inet ok, io_uring EPERM');
    const other = await box(seccompFilter(process.arch === 'arm64' ? 'x64' : 'arm64'));
    assert.notEqual(other.code, 0, 'a filter for the other architecture kills the first syscall');
  } finally { rmSync(home, { recursive: true, force: true }); }
});
