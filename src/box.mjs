// Box primitives: bubblewrap arguments, the per-box egress proxy, the box's seccomp filter, the home scrub, the safe file reader and
// the watchdog's /proc and disk counts. Pure helpers, no side effects on import; runner.mjs wires them up.
import { execFile } from 'node:child_process';
import dns from 'node:dns';
import { constants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { chmod, lstat, open, opendir, readdir, readFile, readlink, rename, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { isAbsolute, join } from 'node:path';
import { promisify } from 'node:util';

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
 * The host name a TLS ClientHello at the start of buf asks for (its server_name, lowercased): undefined while the first record is
 * still incomplete; null when it is no ClientHello in one record, names no single host, or offers ECH (whose real name is hidden).
 */
export function helloSni(buf) {
  if (buf.length < 5) return undefined;
  if (buf[0] !== 0x16 || buf[1] !== 3) return null; // a handshake record
  const len = buf.readUInt16BE(3);
  if (len > 16384) return null;
  if (buf.length < 5 + len) return undefined;
  const h = buf.subarray(5, 5 + len);
  try {
    if (h[0] !== 1 || 4 + h.readUIntBE(1, 3) !== h.length) return null; // a ClientHello filling the record (not split over two)
    let i = 4 + 2 + 32; // type, length, version, random
    i += 1 + h[i]; // session id
    i += 2 + h.readUInt16BE(i); // cipher suites
    i += 1 + h[i]; // compression methods
    const end = i + 2 + h.readUInt16BE(i);
    if (end !== h.length) return null;
    let name = null;
    for (i += 2; i < end;) {
      const type = h.readUInt16BE(i), n = h.readUInt16BE(i + 2), d = h.subarray(i + 4, i + 4 + n);
      i += 4 + n;
      if (i > end || type === 0xfe0d) return null; // encrypted_client_hello
      if (type !== 0) continue;
      // server_name: a list holding exactly one host_name
      if (name !== null || d.length < 5 || d.readUInt16BE(0) !== d.length - 2 || d[2] !== 0 || 5 + d.readUInt16BE(3) !== d.length) return null;
      name = d.subarray(5).toString('latin1').toLowerCase();
    }
    return name;
  } catch { return null; } // read past the end
}

/**
 * Per-box CONNECT proxy on a unix socket (0600). CONNECT <allowed host>:443 only, to the IPv4 address it checked; no plain-HTTP path.
 * The tunnel carries TLS whose ClientHello names that same host (helloSni): an edge shared by many sites (Cloudflare's, behind
 * chatgpt.com and api.x.ai) routes by that name, so a CONNECT to an allowed host with another name inside would reach any of them.
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
        c.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        let hello = head.subarray(end + 4);
        const check = () => {
          const sni = helloSni(hello);
          if (sni === undefined) return; // more of the first record to come (within the 10 s timeout)
          c.off('data', more);
          if (sni !== host) { log(`egress deny ${label} ${clean(host)}:443 sni ${clean(sni)}`); return c.destroy(); }
          c.setTimeout(0);
          up.write(hello);
          c.pipe(up).pipe(c);
        };
        const more = (d) => { hello = Buffer.concat([hello, d]); check(); };
        c.on('data', more);
        c.resume();
        check();
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

const run = promisify(execFile);
/**
 * rm -rf that also takes what a box can make a plain rm fail on (a box runs as the runner's uid): folders it made 0555 or 000, and a
 * chain of folders deeper than PATH_MAX (Node's rm works on whole paths: ENAMETOOLONG). Only once a plain rm is refused: then
 * coreutils, which walk folder by folder (no path length limit) and never follow a link inside the tree: chmod -R u+rwx, rm -rf.
 * For trees no box is writing to any more (an ended run's folder, a home under its lock).
 */
export async function rmTree(path) {
  try { return await rm(path, { recursive: true, force: true }); } catch (e) { if (!['EACCES', 'EPERM', 'ENAMETOOLONG'].includes(e.code)) throw e; }
  if ((await lstat(path)).isSymbolicLink()) return rm(path, { force: true }); // the link itself, never what it points at
  await run('chmod', ['-R', 'u+rwx', '--', path]).catch(() => {}); // some entries may refuse; rm says what is left
  await run('rm', ['-rf', '--one-file-system', '--', path]);
}

const KEPT_MAX = 1024 * 1024;
/**
 * Remove everything in the home but the credential files: keep lists paths relative to the home ('.claude/.credentials.json'), kept
 * only while they are regular files in real folders (lstat only: a symlink is removed, never followed). jsonKeys: for a kept JSON
 * file, the top-level keys that survive; the rest of it is rewritten away (a file that does not parse is removed). A kept file past
 * 1 MiB is removed.
 */
export async function scrubHome(home, keep = [], jsonKeys = {}) {
  // the home and the folders kept in it back to 0700, kept files to 0600 (what the runner makes them): a box could chmod them so
  // that nothing in them can be removed, read or rewritten, and every later box of that user would fail
  const walk = async (dir, rel) => {
    await chmod(dir, 0o700); // a real folder: lstat said so (the home: below)
    // names as bytes: one that is not UTF-8 (a box can make it) read as a string is another name, which lstat does not find
    for (const raw of await readdir(dir, { encoding: 'buffer' })) {
      const name = raw.toString();
      if (!Buffer.from(name).equals(raw)) { // never a kept name: renamed to one coreutils can be handed, then removed
        const to = join(dir, `.hb-rm-${randomBytes(8).toString('hex')}`);
        await rename(Buffer.concat([Buffer.from(`${dir}/`), raw]), to);
        await rmTree(to);
        continue;
      }
      const r = rel ? `${rel}/${name}` : name, p = join(dir, name), s = await lstat(p);
      if (s.isFile() && keep.includes(r)) {
        if (s.size > KEPT_MAX) await rm(p, { force: true }); // no credential is that big: a box filled it to break the user's next boxes
        else if (jsonKeys[r]) await keepKeys(p, jsonKeys[r]);
        else await chmod(p, 0o600);
        continue;
      }
      if (s.isDirectory() && keep.some((k) => k.startsWith(`${r}/`))) { await walk(p, r); continue; }
      await rmTree(p);
    }
  };
  if (!(await lstat(home)).isDirectory()) throw new Error('the home is not a folder');
  await walk(home, '');
}
async function keepKeys(file, keys) { // at most KEPT_MAX bytes (scrubHome)
  let fh, j = null;
  try {
    fh = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    j = JSON.parse(await fh.readFile('utf8'));
  } catch { /* removed below */ } finally { await fh?.close(); }
  await rm(file, { force: true });
  if (!j || typeof j !== 'object' || Array.isArray(j)) return;
  // written anew (a box may have made the old one 0400)
  await writeFile(file, JSON.stringify(Object.fromEntries(keys.filter((k) => k in j).map((k) => [k, j[k]])), null, 2), { flag: 'wx', mode: 0o600 });
}

/**
 * <realDir>/<name> or null: a regular file of at most max bytes whose real path is exactly that (no symlinked file or folder on the
 * way, no FIFO). A box wrote it; the runner reading it can see every user's home. realDir must be a real path (realpath() it once):
 * otherwise every read is null.
 */
export async function readOut(realDir, name, max = 2 * 1024 * 1024) {
  return (await readOutBytes(realDir, name, max))?.toString('utf8') ?? null;
}

/** The same bounded, no-symlink read as readOut(), preserving arbitrary file bytes. */
export async function readOutBytes(realDir, name, max = 2 * 1024 * 1024) {
  if (isAbsolute(name) || name.split('/').includes('..')) return null;
  const want = join(realDir, name);
  let fh;
  try {
    fh = await open(want, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    if (!(await fh.stat()).isFile() || (await readlink(`/proc/self/fd/${fh.fd}`)) !== want) return null;
    const buf = Buffer.alloc(max + 1), { bytesRead } = await fh.read(buf, 0, max + 1, 0);
    return bytesRead > max ? null : buf.subarray(0, bytesRead);
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

/** Bytes and entries under the given folders, stopping once entries pass cap. Directory entries are streamed, not loaded all at
 * once. Only vanished paths are ignored: unreadable files or directories must stop the box, not hide its disk usage.
 * Bytes are the larger of size and allocated blocks (including fallocate --keep-size). */
export async function diskUse(roots, cap = 20000) {
  let bytes = 0, entries = 0;
  // paths as bytes: a name that is not UTF-8, read as a string, is another name that lstat does not find (and was never counted)
  const todo = roots.map((r) => Buffer.from(r)), slash = Buffer.from('/');
  while (todo.length && entries <= cap) {
    const dir = todo.pop();
    let directory;
    try { directory = await opendir(dir, { encoding: 'buffer' }); } catch (e) { if (e.code === 'ENOENT') continue; throw e; }
    for await (const entry of directory) {
      if (++entries > cap) break;
      try {
        const path = Buffer.concat([dir, slash, entry.name]), s = await lstat(path);
        bytes += Math.max(s.size, s.blocks * 512);
        if (s.isDirectory()) todo.push(path);
      } catch (e) { if (e.code !== 'ENOENT') throw e; }
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
 * bubblewrap argv for one box. Only <home> and <dir> (seen at boxDir inside, by default the same path) are writable; /usr and /etc read-only; fresh /proc, /dev and 256 MB /tmp and
 * /run and /dev/shm; the root and /dev themselves read-only (bwrap's own tmpfs, unsized: a write there would take memory past every
 * cap); no network but, with net 'proxy', loopback :3128 that socat bridges to the per-box proxy socket. env: variables on top of
 * HOME, PATH, USER, LANG and SHELL (nothing of the runner's environment gets in). roBinds: paths (or [src, dest]) bound read-only
 * after the home and the folder (CLI folders outside /usr, a pristine copy of something the box must not change). hide: files under
 * /usr or /etc the box cannot read (a service's clients file). maxTasks:
 * RLIMIT_NPROC (processes and threads) set inside the box, where the kernel counts it per user namespace, so it caps this box alone.
 * nested: the box may create user namespaces (a CLI's own sandbox may need them); otherwise --disable-userns keeps the kernel's userns
 * surface away from the model's commands. seccomp: the filter (seccompFilter) is read from fd 3. status: bwrap reports on fd 4 (its
 * "exit-code" line comes only from a command that ran: a box whose setup failed has none).
 */
export function boxArgs({ home, dir, boxDir = dir, net, sock, socat, path, env = {}, roBinds = [], hide = [], chdir, cmd, maxTasks = 512, nested = false, seccomp = false, status = false }) {
  const a = [...(status ? ['--json-status-fd', '4'] : []), '--die-with-parent', '--new-session', '--unshare-all', ...(nested ? [] : ['--unshare-user', '--disable-userns']), '--cap-drop', 'ALL', '--clearenv',
    '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/sbin', '/sbin', '--symlink', 'usr/lib', '/lib',
    '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc', '/etc', // x64 ELF binaries need /lib64/ld-linux-x86-64.so.2
    // --dev's own tmpfs is unsized: /dev read-only but for a sized /dev/shm (its nodes are binds, they still open)
    '--proc', '/proc', '--dev', '/dev', '--size', String(BOX_TMP_BYTES), '--tmpfs', '/dev/shm', '--remount-ro', '/dev', '--size', String(BOX_TMP_BYTES), '--tmpfs', '/tmp', '--size', String(BOX_TMP_BYTES), '--tmpfs', '/run',
    '--bind', home, home, ...(dir ? ['--bind', dir, boxDir] : [])];
  for (const b of roBinds) a.push('--ro-bind', ...(Array.isArray(b) ? b : [b, b]));
  for (const f of hide) a.push('--ro-bind', '/dev/null', f); // files of the runner's under /usr or /etc: a nodev device node there, unreadable
  if (chdir) a.push('--chdir', chdir);
  if (seccomp) a.push('--seccomp', '3');
  for (const [k, v] of Object.entries({ HOME: home, PATH: path, USER: 'box', LANG: 'C.UTF-8', SHELL: '/bin/bash', ...env })) a.push('--setenv', k, String(v));
  const nproc = `ulimit -u ${Math.max(1, Math.floor(Number(maxTasks)))}; `;
  const ro = ['--remount-ro', '/']; // after the last mount
  if (net !== 'proxy') return [...a, ...ro, '/bin/bash', '-c', `${nproc}exec "$@"`, 'box', ...cmd];
  const proxy = 'http://127.0.0.1:3128';
  a.push('--ro-bind', sock, '/run/egress.sock', ...ro);
  for (const k of ['HTTPS_PROXY', 'HTTP_PROXY', 'https_proxy', 'http_proxy']) a.push('--setenv', k, proxy);
  for (const k of ['NO_PROXY', 'no_proxy']) a.push('--setenv', k, 'localhost,127.0.0.1');
  return [...a, '/bin/bash', '-c', `${nproc}s=$1; shift; "$s" TCP-LISTEN:3128,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/run/egress.sock 2>/dev/null & i=0; `
    + 'while [ $i -lt 50 ] && ! (exec 3<>/dev/tcp/127.0.0.1/3128) 2>/dev/null; do i=$((i+1)); sleep 0.02; done; exec "$@"', 'box', socat, ...cmd];
}
