#!/usr/bin/env node
// Isolation probe and smoke test with the real CLIs, wired exactly as the runner wires them (createRunner). Run it where the runner
// runs (inside the runner container, or on a host for a smoke): it makes throwaway users hbprobe-a and hbprobe-b under HB_HOMES and
// removes them at the end. It never logs in; with HB_LOGIN_START=1 it starts each login far enough to see the URL, then cancels.
//
//   HB_HOMES=/homes/hbprobe HB_TARGETS=192.168.0.1:80,100.64.0.1:22 node deploy/probe.mjs
//
// HB_HOMES     homes root for the probe users (default: a new folder under the OS temp dir); removed afterwards
// HB_BIN_<ID>  binary per harness (HB_BIN_CLAUDE_CODE, HB_BIN_CODEX, HB_BIN_GROK); default: the name on PATH
// HB_SOCAT, HB_BWRAP   paths (default: on PATH)
// HB_TARGETS   host:port list a box must NOT reach directly (add your LAN, tailnet, Docker gateways, host services)
// HB_PEEK      paths a box must NOT see (default: docker.sock, /root, the runner user's ~/.ssh, ~/.claude, ~/.codex, ~/.grok/auth.json,
//              ~/.config; add your app's data and secrets)
// HB_ONLINE=0  skip the checks that need the internet (an allowed CONNECT, logged-out status of CLIs that ask their server)
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { claudeCode, codex, createRunner, grok } from '../src/index.mjs';

const env = process.env, online = env.HB_ONLINE !== '0';
const homes = env.HB_HOMES ?? await mkdtemp(join(tmpdir(), 'hbprobe-'));
const adapters = [claudeCode, codex, grok];
const bins = Object.fromEntries(adapters.flatMap((a) => { const v = env[`HB_BIN_${a.id.toUpperCase().replace(/-/g, '_')}`]; return v ? [[a.id, v]] : []; }));
const denies = [];
const hb = await createRunner({ homes, adapters, bins, socat: env.HB_SOCAT ?? 'socat', bwrap: env.HB_BWRAP ?? 'bwrap', log: (l) => { if (l.startsWith('egress deny')) denies.push(l); else console.log(`  [runner] ${l}`); } });
const results = [];
const check = (name, ok, ev = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${ev ? `\n    ${String(ev).replace(/\n/g, '\n    ').slice(0, 800)}` : ''}`); };
const A = 'hbprobe-a', B = 'hbprobe-b';
const TARGETS = (env.HB_TARGETS ?? '192.168.0.1:80,192.168.1.1:80,10.0.0.1:80,172.17.0.1:22,127.0.0.1:22,1.1.1.1:443,8.8.8.8:53').split(',').filter(Boolean);
// a host smoke binds CLI folders under the user's home read-only, so the home itself shows as an empty mount point: name its secrets
const PEEK = (env.HB_PEEK ?? ['/var/run/docker.sock', '/run/docker.sock', '/root', ...['.ssh', '.claude', '.codex', '.grok/auth.json', '.config'].map((p) => join(homedir(), p))].join(',')).split(',').filter(Boolean);

try {
  // 1. the CLIs in boxes: version, options, own checks (Codex's sandbox in a nested box); then each one's logged-out status
  const rows = await hb.detect();
  for (const r of rows) check(`${r.name}: ${r.usable ? `usable, ${r.version}` : `not usable (${r.why})`}`, r.usable || r.why === 'binary not found', r.bin ?? '');
  const ok = rows.filter((r) => r.usable);
  if (!ok.length) throw new Error('no usable harness: nothing more to probe');
  for (const r of ok) {
    if (!online && r.id === 'claude-code') continue; // `claude auth status` asks its server
    const s = await hb.status(A, r.id).catch((e) => ({ error: e.message }));
    check(`${r.name}: a fresh home is logged out`, s.installed && s.loggedIn === false, JSON.stringify(s));
  }
  if (env.HB_LOGIN_START === '1') {
    for (const r of ok) {
      const l = hb.login(A, r.id);
      const w = await Promise.race([l.waiting.catch((e) => ({ error: e.message })), new Promise((d) => setTimeout(() => d({ error: 'no URL within 30 s' }), 30e3))]);
      l.cancel();
      const done = await l.done;
      // shapes only: the URL's host and path and the code's pattern, never the values
      const u = w.url && URL.parse(w.url);
      check(`${r.name}: login starts and prints a URL on its login hosts (then canceled)`, u && done.error === 'canceled',
        w.error ?? `${u.host}${u.pathname} code=${w.code ? w.code.replace(/[A-Z]/g, 'A').replace(/[0-9]/g, '9') : 'none'} needsCode=${w.needsCode}`);
    }
  }

  // 2. two users at once: B holds a canary where its credential lives; A, in a proxy box of the first usable harness, looks around
  const h = ok[0], a = adapters.find((x) => x.id === h.id);
  const bHome = join(homes, B, h.id), canary = join(bHome, a.keep[0]);
  await mkdir(join(canary, '..'), { recursive: true, mode: 0o700 });
  await writeFile(canary, 'B-SECRET');
  const bBox = hb.exec(B, h.id, ['/bin/bash', '-c', 'sleep 12'], { ms: 20e3 });
  await new Promise((r) => setTimeout(r, 1500));
  const other = adapters.find((x) => x.id !== h.id).hosts[0];
  const probe = `
t() { timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null && echo "OPEN $1:$2" || echo "closed $1:$2"; }
p() { exec 3<>/dev/tcp/127.0.0.1/3128; printf "CONNECT $1 HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n" >&3; head -1 <&3 | tr -d '\\r'; exec 3>&-; }
f() { NODE_USE_ENV_PROXY=$2 timeout 15 node -e 'fetch(process.argv[1],{redirect:"manual",signal:AbortSignal.timeout(10000)}).then(r=>console.log(r.status),e=>console.log("000 "+(e.cause?.code||e.cause?.message||e.message)))' "$1" 2>&1; }
echo "bcanary: $(cat ${canary} 2>&1 | head -c 80)"
echo "bhome: $(test -e ${bHome} && echo yes || echo no)"
echo "proc_scan: $(cat /proc/*/root${canary} 2>/dev/null | head -c 40)"
echo "procs: $(ls -d /proc/[0-9]* | wc -l)"
for x in ${PEEK.join(' ')}; do echo "exists $x: $(test -e $x && echo yes || echo no)"; done
for hp in ${TARGETS.join(' ')}; do t \${hp%:*} \${hp#*:}; done
echo "userns: $(unshare -Ur true 2>&1 && echo ok || echo blocked)"
echo "env: $(env | cut -d= -f1 | sort | tr '\\n' ' ')"
echo "nproc: $(ulimit -u)"
echo "tmp: $(df -B1 --output=size /tmp | tail -1) run: $(df -B1 --output=size /run | tail -1)"
echo "caps: $(grep CapEff /proc/self/status | tr -d '\\t')"
echo "seccomp: $(grep '^Seccomp:' /proc/self/status | tr -d '\\t')"
command -v python3 >/dev/null && echo "sockets: $(python3 -I -c '
import ctypes, socket
l = ctypes.CDLL(None, use_errno=True); l.syscall.restype = ctypes.c_long
def s(f):
  try: socket.socket(f, socket.SOCK_STREAM).close(); return "ok"
  except OSError as e: return e.errno
p = ctypes.create_string_buffer(120); r = l.syscall(425, 4, p)
print("vsock", s(40), "io_uring", "ok" if r >= 0 else ctypes.get_errno())')"
echo "connect_other: $(p ${other}:443)"
echo "connect_port80: $(p ${a.hosts[0]}:80)"
echo "connect_iplit: $(p 1.1.1.1:443)"
echo "connect_example: $(p example.com:443)"
echo "connect_allowed: $(${online ? `p ${a.hosts[0]}:443` : 'echo skipped'})"
echo "fetch_plain_http: $(f http://${a.hosts[0]}/ 1)"
echo "fetch_direct: $(f https://${a.hosts[0]}/ '')"
echo "fetch_allowed: $(${online ? `f https://${a.hosts[0]}/ 1` : 'echo skipped'})"
`;
  const r = await hb.exec(A, h.id, ['/bin/bash', '-c', probe], { net: 'proxy', ms: 120e3 });
  console.log(`--- probe output (user ${A}, ${h.name} proxy box) ---\n${r.out.trim()}\n---`);
  const g = (k) => (new RegExp(`^${k}: (.*)$`, 'm').exec(r.out) ?? [])[1] ?? '';
  check('A cannot read B\'s credential canary, see B\'s home or reach it through /proc', !/B-SECRET/.test(r.out) && g('bhome') === 'no', `bcanary=${g('bcanary')} bhome=${g('bhome')}`);
  check('A sees only its own pid namespace', Number(g('procs')) < 10, g('procs'));
  check('peek paths absent', !/^exists \S+: yes/m.test(r.out), r.out.split('\n').filter((l) => l.startsWith('exists')).join('\n'));
  check('no direct connection to any target', !/^OPEN/m.test(r.out), r.out.split('\n').filter((l) => /^(OPEN|closed)/.test(l)).join('\n'));
  check('no nested user namespace', g('userns') !== 'ok', g('userns'));
  check('cleared environment', !/\b(SSH_|XDG_|TERM_PROGRAM|NVM_|ANTHROPIC_|OPENAI_|XAI_|GROK_API)/.test(g('env')), g('env'));
  check('RLIMIT_NPROC set inside the box', /^\d+$/.test(g('nproc')) && Number(g('nproc')) <= 4096, g('nproc'));
  check('/tmp and /run are 256 MiB', g('tmp') === '268435456 run: 268435456', g('tmp'));
  check('no capabilities, seccomp on', /CapEff:0000000000000000/.test(g('caps')) && /Seccomp:2/.test(g('seccomp')), `${g('caps')} ${g('seccomp')}`);
  if (g('sockets')) check('AF_VSOCK and io_uring refused (EPERM)', g('sockets') === 'vsock 1 io_uring 1', g('sockets'));
  check('proxy refuses another harness\'s host, port 80, an IP literal, an unlisted host',
    ['connect_other', 'connect_port80', 'connect_iplit', 'connect_example'].every((k) => /403/.test(g(k))), ['connect_other', 'connect_port80', 'connect_iplit', 'connect_example'].map((k) => `${k}=${g(k)}`).join(' '));
  check('no plain HTTP, no direct egress', /^(405|000)/.test(g('fetch_plain_http')) && g('fetch_direct').startsWith('000'), `plain=${g('fetch_plain_http')} direct=${g('fetch_direct')}`);
  if (online) check(`allowed ${a.hosts[0]}:443 goes through`, /200 Connection Established/.test(g('connect_allowed')) && /^[1-5]\d\d$/.test(g('fetch_allowed')), `${g('connect_allowed')} fetch=${g('fetch_allowed')}`);
  await bBox;
  const n = await hb.exec(A, h.id, ['/bin/bash', '-c', 'timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>&1 && echo OPEN; ls /run']);
  check('a net-none box has no network and no proxy socket', !/OPEN|egress/.test(n.out), n.out.trim());
  check('every denial is logged with the box\'s label', denies.length >= 4 && denies.every((d) => d.includes(`exec=${A}`)), denies.join('\n'));
} catch (e) {
  check('probe ran to the end', false, e.stack);
} finally {
  await hb.close();
  await rm(join(homes, A), { recursive: true, force: true });
  await rm(join(homes, B), { recursive: true, force: true });
  if (!env.HB_HOMES) await rm(homes, { recursive: true, force: true });
  console.log(`\nSUMMARY ${results.filter(Boolean).length}/${results.length} pass`);
  process.exitCode = results.every(Boolean) ? 0 : 1;
}
