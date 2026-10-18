// box.mjs on its own: the egress proxy (stubbed DNS and upstream), the home scrub, the file reader, the /proc counts, the bwrap argv
// and the seccomp filter (in a real box when bubblewrap can make one).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BOX_TMP_BYTES, boxArgs, countDescendants, diskUse, parseStat, privateIp, readOut, rmTree, scrubHome, seccompFilter, startProxy } from '../src/box.mjs';

const ALLOW = ['api.anthropic.com', 'platform.claude.com'];
const KEEP = ['.claude/.credentials.json', '.claude.json', '.codex/auth.json'], KEYS = { '.claude.json': ['oauthAccount', 'userID'] };

const tmp = () => mkdtempSync(join(tmpdir(), 'hb-box-test-'));
// a TLS ClientHello record naming names (server_name), with the ECH extension when ech; the smallest one helloSni reads
const u16 = (n) => Buffer.from([n >> 8, n & 255]);
const tlv = (type, body) => Buffer.concat([u16(type), u16(body.length), body]);
const clientHello = (names, { ech = false } = {}) => {
  const list = Buffer.concat([].concat(names).map((n) => Buffer.concat([Buffer.from([0]), u16(n.length), Buffer.from(n, 'latin1')])));
  const exts = Buffer.concat([...(names.length ? [tlv(0, Buffer.concat([u16(list.length), list]))] : []), ...(ech ? [tlv(0xfe0d, Buffer.alloc(4))] : [])]);
  const body = Buffer.concat([Buffer.from([3, 3]), Buffer.alloc(32, 7), Buffer.from([0]), u16(2), Buffer.from([0x13, 0x01]), Buffer.from([1, 0]), u16(exts.length), exts]);
  const hs = Buffer.concat([Buffer.from([1, 0, body.length >> 8, body.length & 255]), body]);
  return Buffer.concat([Buffer.from([0x16, 3, 1]), u16(hs.length), hs]);
};

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
    // head split across two writes, bytes after the head forwarded: a ClientHello naming the host, itself split, then more
    const hello = clientHello(['api.anthropic.com']);
    const ok = await w.talk(['CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.an', Buffer.concat([Buffer.from('thropic.com:443\r\n\r\n'), hello.subarray(0, 9)]), hello.subarray(9), 'again'], 800);
    assert.ok(ok.startsWith('HTTP/1.1 200 Connection Established\r\n\r\necho:'), ok);
    assert.ok(ok.includes('api.anthropic.com') && ok.includes('echo:again'), 'the ClientHello and what follows reach the upstream');
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
    assert.match(await w.talk(['CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n', clientHello(['api.anthropic.com']), 'ping'], 800), /echo:ping/);
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
  assert.match(s, new RegExp(`--dev /dev --size ${BOX_TMP_BYTES} --tmpfs /dev/shm --remount-ro /dev --size ${BOX_TMP_BYTES} --tmpfs /tmp --size ${BOX_TMP_BYTES} --tmpfs /run`));
  const binds = a.flatMap((x, i) => (x === '--bind' ? [a[i + 1]] : []));
  assert.deepEqual(binds, ['/homes/alice/claude-code', '/tmp/job-1'], 'nothing else writable');
  assert.ok(!a.includes('/homes'));
  assert.ok(a.indexOf('/app/skill') > a.indexOf('/tmp/job-1'), 'a read-only bind lies over the writable folder');
  assert.match(s, /--ro-bind \/tmp\/hb-egress-1\.sock \/run\/egress\.sock/);
  assert.ok(a.indexOf('/run/egress.sock') > a.indexOf('/run'), 'the socket over the fresh /run');
  assert.equal(a.lastIndexOf('--remount-ro'), a.indexOf('/run/egress.sock') + 1, 'the root read-only after the last mount');
  assert.equal(a[a.lastIndexOf('--remount-ro') + 1], '/');
  const hidden = boxArgs({ home: '/h', net: 'none', path: '/usr/bin', hide: ['/etc/harnessbox/clients.json'], cmd: ['x'] });
  assert.ok(hidden.join(' ').includes('--ro-bind /etc /etc') && hidden.join(' ').includes('--ro-bind /dev/null /etc/harnessbox/clients.json'));
  assert.ok(hidden.indexOf('/etc/harnessbox/clients.json') > hidden.indexOf('/etc') && hidden.indexOf('/etc/harnessbox/clients.json') < hidden.lastIndexOf('--remount-ro'), 'over /etc, before the root goes read-only');
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

const canBox = spawnSync('bwrap', ['--unshare-all', '--die-with-parent', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '/usr/bin/true']).status === 0;
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

test('proxy: the tunnel carries only a ClientHello naming the CONNECT host; another name (fronting), none, two, ECH or no TLS ends it unsent', async () => {
  const w = await proxyWorld({ 'api.anthropic.com': '203.0.113.7' });
  try {
    const CONNECT = 'CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n';
    assert.match(await w.talk([CONNECT, clientHello(['API.Anthropic.com']), 'ping'], 800), /echo:ping/, 'the name is compared lowercased');
    const bad = { 'discord.com': clientHello(['discord.com']), none: clientHello([]), two: clientHello(['api.anthropic.com', 'discord.com']),
      ech: clientHello(['api.anthropic.com'], { ech: true }), 'trailing dot': clientHello(['api.anthropic.com.']), http: Buffer.from('GET / HTTP/1.1\r\nHost: discord.com\r\n\r\n'),
      'split over two records': Buffer.concat([clientHello(['api.anthropic.com']).subarray(0, 3), u16(20), clientHello(['api.anthropic.com']).subarray(5, 25)]) };
    for (const [why, bytes] of Object.entries(bad)) {
      const before = w.logs.length;
      const got = await w.talk([CONNECT, bytes, 'ping'], 800);
      assert.equal(got, 'HTTP/1.1 200 Connection Established\r\n\r\n', `${why}: nothing reaches the upstream`);
      assert.match(w.logs.slice(before).join('\n'), /^egress deny job=j1 api\.anthropic\.com:443 sni /, why);
    }
    assert.ok(!w.logs.some((l) => l.includes('GET')), 'what the box sent is not echoed into the log');
  } finally { w.close(); }
});

test('scrubHome removes a kept credential file past 1 MiB, which a box could grow to break the user\'s next boxes', async () => {
  const root = tmp(), home = join(root, 'alice');
  try {
    mkdirSync(join(home, '.claude'), { recursive: true });
    mkdirSync(join(home, '.codex'));
    writeFileSync(join(home, '.claude', '.credentials.json'), 'x'.repeat(1024 * 1024 + 1));
    writeFileSync(join(home, '.codex', 'auth.json'), 'x'.repeat(1024 * 1024));
    await scrubHome(home, KEEP, KEYS);
    assert.ok(!existsSync(join(home, '.claude', '.credentials.json')), 'past 1 MiB: removed');
    assert.ok(existsSync(join(home, '.codex', 'auth.json')), '1 MiB itself: kept');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('rmTree removes folders a box made 0555 or 000, and never follows a link out of the tree', async () => {
  const root = tmp(), tree = join(root, 'run'), outside = join(root, 'outside');
  try {
    mkdirSync(join(tree, 'a', 'b'), { recursive: true });
    mkdirSync(join(tree, 'c'));
    mkdirSync(outside);
    writeFileSync(join(tree, 'a', 'b', 'f'), 'x');
    writeFileSync(join(outside, 'keep'), 'k');
    chmodSync(outside, 0o555);
    symlinkSync(outside, join(tree, 'a', 'link'));
    chmodSync(join(tree, 'a', 'b'), 0o555);
    chmodSync(join(tree, 'a'), 0o555);
    chmodSync(join(tree, 'c'), 0o000);
    await rmTree(tree);
    assert.ok(!existsSync(tree));
    assert.equal(statSync(outside).mode & 0o777, 0o555, 'the link\'s target is not touched');
    assert.equal(readFileSync(join(outside, 'keep'), 'utf8'), 'k');
    await rmTree(join(root, 'missing')); // nothing there: no error
  } finally { chmodSync(outside, 0o755); rmSync(root, { recursive: true, force: true }); }
});

test('rmTree and scrubHome: a chain of folders past PATH_MAX with a file at the bottom goes; a home and kept folders a box made 0555, 000 or 0400 are scrubbed', async () => {
  const root = tmp();
  try {
    // 17 folders of 255 bytes: past 4096, where Node's rm on whole paths fails with ENAMETOOLONG
    const deep = join(root, 'run');
    mkdirSync(deep);
    const r = spawnSync('python3', ['-I', '-c', `import os\nos.chdir(${JSON.stringify(deep)})\nfor i in range(17):\n  os.mkdir('n' * 255); os.chdir('n' * 255)\nopen('hidden.bin', 'w').write('x' * 1000)\nos.chmod('.', 0o555)`]);
    assert.equal(r.status, 0, String(r.stderr));
    await rmTree(deep);
    assert.ok(!existsSync(deep), 'gone, the deep part too');
    for (const plant of ['home555', 'kept555', 'kept000', 'json400', 'deep']) {
      const home = join(root, plant);
      mkdirSync(join(home, '.claude'), { recursive: true });
      writeFileSync(join(home, '.claude', '.credentials.json'), 'CRED');
      writeFileSync(join(home, '.claude.json'), JSON.stringify({ userID: 'u1', junk: 1 }));
      writeFileSync(join(home, 'junk'), 'x');
      mkdirSync(join(home, '.claude', 'junk'));
      if (plant === 'home555') chmodSync(home, 0o555);
      if (plant === 'kept555') chmodSync(join(home, '.claude'), 0o555);
      if (plant === 'kept000') chmodSync(join(home, '.claude'), 0o000);
      if (plant === 'json400') { chmodSync(join(home, '.claude.json'), 0o400); chmodSync(join(home, '.claude', '.credentials.json'), 0o400); }
      if (plant === 'deep') spawnSync('python3', ['-I', '-c', `import os\nos.chdir(${JSON.stringify(home)})\nfor i in range(17):\n  os.mkdir('n' * 255); os.chdir('n' * 255)`]);
      await scrubHome(home, KEEP, KEYS);
      assert.deepEqual(readdirSync(home).sort(), ['.claude', '.claude.json'], plant);
      assert.deepEqual(readdirSync(join(home, '.claude')), ['.credentials.json'], plant);
      assert.equal(readFileSync(join(home, '.claude', '.credentials.json'), 'utf8'), 'CRED', plant);
      assert.deepEqual(JSON.parse(readFileSync(join(home, '.claude.json'), 'utf8')), { userID: 'u1' }, plant);
      assert.equal(statSync(home).mode & 0o777, 0o700, plant);
      assert.equal(statSync(join(home, '.claude', '.credentials.json')).mode & 0o777, 0o600, plant);
    }
  } finally { spawnSync('chmod', ['-R', 'u+rwx', root]); rmSync(root, { recursive: true, force: true }); }
});

test('diskUse counts under a name that is not UTF-8; scrubHome removes it', async () => {
  const root = tmp(), home = join(root, 'alice'), bad = Buffer.concat([Buffer.from(`${home}/`), Buffer.from([0xff])]);
  try {
    mkdirSync(join(home, '.claude'), { recursive: true });
    writeFileSync(join(home, '.claude', '.credentials.json'), 'CRED');
    mkdirSync(bad);
    writeFileSync(Buffer.concat([bad, Buffer.from('/big')]), 'x'.repeat(100000));
    const u = await diskUse([home]);
    assert.ok(u.bytes >= 100000 && u.entries === 4, JSON.stringify(u));
    await scrubHome(home, KEEP, KEYS);
    assert.deepEqual(readdirSync(home), ['.claude']);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
