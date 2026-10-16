// Box primitives: bubblewrap arguments, the per-box egress proxy, the box's seccomp filter, the home scrub, the safe file reader and
// the watchdog's /proc and disk counts. Pure helpers, no side effects on import; runner.mjs wires them up.
import dns from 'node:dns';
import { constants } from 'node:fs';
import { chmod, lstat, open, readdir, readFile, readlink, rm } from 'node:fs/promises';
import net from 'node:net';
import { join } from 'node:path';

/** User and harness ids: they become folder names under the homes root. */
export const ID = /^[A-Za-z0-9_-]{1,64}$/;
export const BOX_TMP_BYTES = 268435456;

const PRIVATE = new net.BlockList();
for (const [a, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 3]]) PRIVATE.addSubnet(a, p, 'ipv4');
/** Not a public IPv4 address (anything else, IPv6 included, counts as private: lookups ask for IPv4 only). */
export const privateIp = (ip) => !net.isIPv4(ip) || PRIVATE.check(ip, 'ipv4');

const clean = (s) => (/^[A-Za-z0-9.-]{1,253}$/.test(s ?? '') ? s : '<bad>'); // the box writes this string; never let it shape the log

/**
 * Per-box CONNECT proxy on a unix socket (0600). CONNECT <allowed host>:443 only, to the IPv4 address it checked; no plain-HTTP path.
 * Every socket has an error handler: a broken or hostile client never ends the runner. Resolves to the net.Server.
 */
export function startProxy(sockPath, { allow, label, log, lookup = dns.promises.lookup, connect = net.connect }) {
  const server = net.createServer((c) => {
    c.on('error', () => {});
    c.setTimeout(10e3, () => c.destroy());
    let head = Buffer.alloc(0);
    const deny = (host, port, why, status = '403 Forbidden') => {
      log(`egress deny ${label} ${clean(host)}:${/^\d{1,5}$/.test(port ?? '') ? port : '<bad>'} ${why}`);
      c.end(`HTTP/1.1 ${status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
    };
    const onData = async (d) => {
      head = Buffer.concat([head, d]);
      const end = head.indexOf('\r\n\r\n');
      if (end < 0) {
        if (head.length > 8192) { c.off('data', onData); deny('', '', 'head too large', '431 Request Header Fields Too Large'); }
        return;
      }
      c.off('data', onData);
      c.pause();
      const [method, target = '', version = ''] = head.subarray(0, head.indexOf('\r\n')).toString('latin1').split(' ');
      const m = /^([^:]*):([^:]*)$/.exec(target), host = (m?.[1] ?? target).toLowerCase(), port = m?.[2];
      if (method !== 'CONNECT' || !/^HTTP\/1\.[01]$/.test(version)) return deny(host, port, 'not CONNECT', '405 Method Not Allowed');
      if (port !== '443') return deny(host, port, 'port');
      if (!allow.includes(host)) return deny(host, port, 'host');
      let ip;
      try { ({ address: ip } = await lookup(host, { family: 4 })); } catch { return deny(host, port, 'lookup', '502 Bad Gateway'); }
      if (privateIp(ip)) return deny(host, port, 'private ip');
      if (c.destroyed) return;
      const up = connect({ host: ip, port: 443 });
      up.on('error', () => c.destroy());
      c.on('close', () => up.destroy());
      up.on('close', () => c.destroy());
      up.on('connect', () => {
        c.setTimeout(0);
        c.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        const rest = head.subarray(end + 4);
        if (rest.length) up.write(rest);
        c.pipe(up).pipe(c);
        c.resume();
      });
    };
    c.on('data', onData);
  });
  server.maxConnections = 64; // one box cannot use up the runner's file descriptors
  server.on('error', (e) => log(`egress proxy ${label}: ${e.code ?? e.message}`));
  return new Promise((done, fail) => {
    server.once('error', fail);
    server.listen(sockPath, () => { server.off('error', fail); chmod(sockPath, 0o600).then(() => done(server), fail); });
  });
}

/**
 * Remove everything in the home but the credential files: keep lists paths relative to the home ('.claude/.credentials.json'), kept
 * only while they are regular files in real folders (lstat only: a symlink is removed, never followed). jsonKeys: for a kept JSON
 * file, the top-level keys that survive; the rest of it is rewritten away (a file that does not parse or passes 1 MB is removed).
 */
export async function scrubHome(home, keep = [], jsonKeys = {}) {
  const walk = async (dir, rel) => {
    for (const name of await readdir(dir)) {
      const r = rel ? `${rel}/${name}` : name, p = join(dir, name), s = await lstat(p);
      if (s.isFile() && keep.includes(r)) { if (jsonKeys[r]) await keepKeys(p, s.size, jsonKeys[r]); continue; }
      if (s.isDirectory() && keep.some((k) => k.startsWith(`${r}/`))) { await walk(p, r); continue; }
      await rm(p, { recursive: true, force: true });
    }
  };
  await walk(home, '');
}
async function keepKeys(file, size, keys) {
  let fh, j = null;
  if (size <= 1024 * 1024) {
    try {
      fh = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      j = JSON.parse(await fh.readFile('utf8'));
    } catch { /* removed below */ } finally { await fh?.close(); }
  }
  if (!j || typeof j !== 'object' || Array.isArray(j)) return rm(file, { force: true });
  const out = await open(file, constants.O_WRONLY | constants.O_TRUNC | constants.O_NOFOLLOW);
  try { await out.chmod(0o600); await out.writeFile(JSON.stringify(Object.fromEntries(keys.filter((k) => k in j).map((k) => [k, j[k]])), null, 2)); } finally { await out.close(); }
}

/**
 * <realDir>/<name> or null: a regular file of at most max bytes whose real path is exactly that (no symlinked file or folder on the
 * way, no FIFO). A box wrote it; the runner reading it can see every user's home.
 */
export async function readOut(realDir, name, max = 2 * 1024 * 1024) {
  const want = join(realDir, name);
  let fh;
  try {
    fh = await open(want, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    if (!(await fh.stat()).isFile() || (await readlink(`/proc/self/fd/${fh.fd}`)) !== want) return null;
    const buf = Buffer.alloc(max + 1), { bytesRead } = await fh.read(buf, 0, max + 1, 0);
    return bytesRead > max ? null : buf.subarray(0, bytesRead).toString('utf8');
  } catch { return null; } finally { await fh?.close(); }
}

/** /proc/<pid>/stat -> { pid, ppid } (comm may hold spaces and ')': the fields after the last ')'). */
export function parseStat(text) {
  const rest = text.slice(text.lastIndexOf(')') + 2).split(' ');
  return { pid: Number.parseInt(text, 10), ppid: Number(rest[1]) };
}
/** Every descendant of each root pid, from one /proc scan: Map<rootPid, count>. */
export async function countDescendants(rootPids, procDir = '/proc') {
  const kids = new Map();
  for (const name of await readdir(procDir)) {
    if (!/^\d+$/.test(name)) continue;
    let s;
    try { s = parseStat(await readFile(join(procDir, name, 'stat'), 'utf8')); } catch { continue; } // gone meanwhile
    if (!kids.has(s.ppid)) kids.set(s.ppid, []);
    kids.get(s.ppid).push(s.pid);
  }
  const counts = new Map();
  for (const root of rootPids) {
    let n = 0;
    const todo = [...(kids.get(root) ?? [])];
    while (todo.length) { n++; todo.push(...(kids.get(todo.pop()) ?? [])); }
    counts.set(root, n);
  }
  return counts;
}

/** Bytes and entries under the given folders (lstat, links not followed), stopping once entries pass cap. Bytes are the larger of
 *  size and allocated blocks: fallocate --keep-size takes disk (or tmpfs memory) with size 0, truncate gives size without blocks. */
export async function diskUse(roots, cap = 20000) {
  let bytes = 0, entries = 0;
  const todo = [...roots];
  while (todo.length && entries <= cap) {
    const dir = todo.pop();
    let names;
    try { names = await readdir(dir); } catch { continue; }
    for (const n of names) {
      if (++entries > cap) break;
      try {
        const s = await lstat(join(dir, n));
        bytes += Math.max(s.size, s.blocks * 512);
        if (s.isDirectory()) todo.push(join(dir, n));
      } catch { /* gone meanwhile */ }
    }
  }
  return { bytes, entries };
}

/**
 * The box's own seccomp filter (classic BPF, for bwrap --seccomp): EPERM for io_uring_setup/enter/register (an io_uring ring does I/O
 * the container's syscall filter never sees) and socket(AF_VSOCK) (vsock is not covered by the network namespace); any other
 * architecture, and the x32 ABI on x86_64, is killed. AF_UNIX stays open: the box has no other unix socket to reach than its proxy's
 * (README, "sandbox-runtime"). Throws on an architecture it has no numbers for.
 */
const LD = 0x20, JEQ = 0x15, JGE = 0x35, RET = 0x06; // BPF_LD|W|ABS, BPF_JMP|JEQ|K, BPF_JMP|JGE|K, BPF_RET|K
const ALLOW = 0x7fff0000, EPERM = 0x00050001, KILL = 0x80000000; // RET_ALLOW, RET_ERRNO|EPERM, RET_KILL_PROCESS
const ARCH = { arm64: [0xc00000b7, 198], x64: [0xc000003e, 41] }; // AUDIT_ARCH_*, __NR_socket
export function seccompFilter(arch = process.arch) {
  const [audit, nrSocket] = ARCH[arch] ?? [];
  if (!audit) throw new Error(`no seccomp filter for ${arch}`);
  const families = [40]; // AF_VSOCK
  const p = [[LD, 4], [JEQ, audit, 1, 0], [RET, KILL], [LD, 0],
    ...(arch === 'x64' ? [[JGE, 0x40000000, 0, 1], [RET, KILL]] : []),
    ...[425, 426, 427].flatMap((nr) => [[JEQ, nr, 0, 1], [RET, EPERM]]), // the same numbers on both architectures
    [JEQ, nrSocket, 0, 1 + 2 * families.length], [LD, 16], // low 32 bits of the first argument (little-endian)
    ...families.flatMap((f) => [[JEQ, f, 0, 1], [RET, EPERM]]), [RET, ALLOW]];
  return Buffer.concat(p.map(([code, k, jt = 0, jf = 0]) => {
    const b = Buffer.alloc(8);
    b.writeUInt16LE(code, 0); b[2] = jt; b[3] = jf; b.writeUInt32LE(k >>> 0, 4);
    return b;
  }));
}

/**
 * bubblewrap argv for one box. Only <home> and <dir> are writable; /usr and /etc read-only; fresh /proc, /dev and 256 MB /tmp and
 * /run; no network but, with net 'proxy', loopback :3128 that socat bridges to the per-box proxy socket. env: variables on top of
 * HOME, PATH, USER, LANG and SHELL (nothing of the runner's environment gets in). roBinds: paths (or [src, dest]) bound read-only
 * after the home and the folder (CLI folders outside /usr, a pristine copy of something the box must not change). maxTasks:
 * RLIMIT_NPROC (processes and threads) set inside the box, where the kernel counts it per user namespace, so it caps this box alone.
 * nested: the box may create user namespaces (a CLI's own sandbox may need them); otherwise --disable-userns keeps the kernel's userns
 * surface away from the model's commands. seccomp: the filter (seccompFilter) is read from fd 3.
 */
export function boxArgs({ home, dir, net, sock, socat, path, env = {}, roBinds = [], chdir, cmd, maxTasks = 512, nested = false, seccomp = false }) {
  const a = ['--die-with-parent', '--new-session', '--unshare-all', ...(nested ? [] : ['--unshare-user', '--disable-userns']), '--cap-drop', 'ALL', '--clearenv',
    '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/sbin', '/sbin', '--symlink', 'usr/lib', '/lib', '--ro-bind', '/etc', '/etc',
    '--proc', '/proc', '--dev', '/dev', '--size', String(BOX_TMP_BYTES), '--tmpfs', '/tmp', '--size', String(BOX_TMP_BYTES), '--tmpfs', '/run',
    '--bind', home, home, ...(dir ? ['--bind', dir, dir] : [])];
  for (const b of roBinds) a.push('--ro-bind', ...(Array.isArray(b) ? b : [b, b]));
  if (chdir) a.push('--chdir', chdir);
  if (seccomp) a.push('--seccomp', '3');
  for (const [k, v] of Object.entries({ HOME: home, PATH: path, USER: 'box', LANG: 'C.UTF-8', SHELL: '/bin/bash', ...env })) a.push('--setenv', k, String(v));
  const nproc = `ulimit -u ${Math.max(1, Math.floor(Number(maxTasks)))}; `;
  if (net !== 'proxy') return [...a, '/bin/bash', '-c', `${nproc}exec "$@"`, 'box', ...cmd];
  const proxy = 'http://127.0.0.1:3128';
  a.push('--ro-bind', sock, '/run/egress.sock');
  for (const k of ['HTTPS_PROXY', 'HTTP_PROXY', 'https_proxy', 'http_proxy']) a.push('--setenv', k, proxy);
  for (const k of ['NO_PROXY', 'no_proxy']) a.push('--setenv', k, 'localhost,127.0.0.1');
  return [...a, '/bin/bash', '-c', `${nproc}s=$1; shift; "$s" TCP-LISTEN:3128,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/run/egress.sock 2>/dev/null & i=0; `
    + 'while [ $i -lt 50 ] && ! (exec 3<>/dev/tcp/127.0.0.1/3128) 2>/dev/null; do i=$((i+1)); sleep 0.02; done; exec "$@"', 'box', socat, ...cmd];
}
