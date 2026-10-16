// The runner: each user gets a persistent home per harness (<homes>/<userId>/<harnessId>), and every login, status, logout and job
// runs in a fresh bubblewrap box over that home (box.mjs) that reaches the internet only through a CONNECT proxy in this process for
// the harness's own hosts. The host app never sees a credential: the CLI writes it into the user's home itself, and only the login
// URL (and a device code, or the code the user pastes back) passes through. No dependencies, Node 24, Linux with bubblewrap.
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { access, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { boxArgs, countDescendants, diskUse, ID, readOut, scrubHome, seccompFilter, startProxy } from './box.mjs';

const LOGIN_MS = 10 * 60e3, PROBE_MS = 30e3;
const ANSI = /\x1b\[[0-9;?]*[A-Za-z]/g, CODE = /^[\x21-\x7e]{1,2048}$/;
const USER = new RegExp(`^${ID.source.slice(1, -1)}(/${ID.source.slice(1, -1)})?$`), MODEL = /^[A-Za-z0-9._:@/-]{1,100}$/;

/** A status or logout that could not get the user's lock (or a quick-box slot) in time: ask again later. */
export class Busy extends Error {}

async function which(bin) {
  for (const d of bin.includes('/') ? [''] : (process.env.PATH ?? '').split(':').filter(Boolean)) {
    const p = resolve(d, bin);
    try { await access(p, constants.X_OK); return await realpath(p); } catch { /* next */ }
  }
  return null;
}
const outside = (p) => (p && p !== '/usr' && !p.startsWith('/usr/') ? [p] : []);

// A FIFO gate shared by the job slots and per-credential locks. Canceled waiters leave the queue immediately. A timed-out quick
// operation resolves to null; abort rejects with the signal's reason. A permit is released at most once.
function gate(limit) {
  let active = 0;
  const waiting = new Set();
  return {
    get idle() { return active === 0 && waiting.size === 0; },
    acquire(signal, ms = Infinity) {
      return new Promise((done, fail) => {
        let timer;
        const clean = () => { clearTimeout(timer); signal?.removeEventListener('abort', abort); waiting.delete(grant); };
        const abort = () => { clean(); fail(signal.reason); };
        const grant = () => {
          clean();
          active++;
          let released = false;
          done(() => {
            if (released) return;
            released = true;
            active--;
            waiting.values().next().value?.();
          });
        };
        if (signal?.aborted) return abort();
        if (active < limit) return grant();
        waiting.add(grant);
        signal?.addEventListener('abort', abort, { once: true });
        if (ms !== Infinity) timer = setTimeout(() => { clean(); done(null); }, ms);
      });
    },
  };
}

function locker() {
  const locks = new Map();
  return async (key, ms, signal) => {
    if (!locks.has(key)) locks.set(key, gate(1));
    const g = locks.get(key);
    const clean = () => { if (g.idle && locks.get(key) === g) locks.delete(key); };
    try {
      const release = await g.acquire(signal, ms);
      if (!release) { clean(); return null; }
      return () => { release(); clean(); };
    } catch (e) { clean(); throw e; }
  };
}

/**
 * @param {object} o
 * @param {string} o.homes  root of the per-user homes (one uid owns them all: the box is the boundary)
 * @param {import('./adapters.mjs').Adapter[]} o.adapters
 * @param {Record<string,string>} [o.bins]   binary per harness id (default: the adapter's bin on PATH)
 * @param {Record<string,string>} [o.pins]   exact version per harness id; another version is not usable
 * @param {string} [o.bwrap]  @param {string} [o.socat]
 * @param {number} [o.maxJobs]  jobs at once (more wait for a slot)   @param {number} [o.maxQuick]  status/logout boxes at once (else Busy)
 * @param {number} [o.maxProcs]  processes per box (watchdog; the in-box RLIMIT_NPROC is 4x for threads)
 * @param {number} [o.maxBytes]  home + job folder per box   @param {number} [o.maxEntries]
 * @param {number} [o.maxOutputBytes]  cumulative stdout + stderr per job (default 8 MiB)
 * @param {(line: string) => void} [o.log]  egress denials and watchdog notes (never credentials, codes or URLs)
 * @param {Record<string,string>} [o.passEnv]  extra variables for every box (tests)
 */
export async function createRunner({ homes, adapters, bins = {}, pins = {}, bwrap = 'bwrap', socat = 'socat', maxJobs = 3, maxQuick = 2, maxProcs = 128,
  maxBytes = 2 ** 30, maxEntries = 20000, maxOutputBytes = 8 * 1024 * 1024, log = () => {}, passEnv = {} }) {
  const filter = seccompFilter(); // a missing security boundary is a startup error, never an optional warning
  if (typeof homes !== 'string' || !isAbsolute(homes)) throw new Error('homes must be an absolute path');
  if (!Array.isArray(adapters)) throw new Error('adapters must be an array');
  for (const [name, value] of Object.entries({ maxJobs, maxQuick, maxProcs, maxBytes, maxEntries, maxOutputBytes })) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive safe integer`);
  }
  const report = (line) => { try { Promise.resolve(log(line)).catch(() => {}); } catch { /* the log sink cannot stop users' boxes */ } };
  const byId = new Map(adapters.map((a) => [a.id, a]));
  if (byId.size !== adapters.length) throw new Error('duplicate harness id');
  for (const a of adapters) if (!ID.test(a.id)) throw new Error(`bad harness id ${a.id}`);
  const BIN = Object.fromEntries(await Promise.all(adapters.map(async (a) => [a.id, await which(bins[a.id] ?? a.bin)])));
  const BWRAP = await which(bwrap), SOCAT = await which(socat);
  if (!BWRAP) throw new Error(`bubblewrap binary not found: ${bwrap}`);
  if (!SOCAT) throw new Error(`socat binary not found: ${socat}`);
  // what of this host the boxes need read-only besides /usr: the CLIs' folders and Node's (a host's nvm node; in an image all is in /usr)
  const NODE_DIR = dirname(dirname(process.execPath));
  const BIN_DIRS = [...new Set([dirname(process.execPath), ...[...Object.values(BIN), SOCAT].filter((b) => b?.includes('/')).map((b) => dirname(b))])];
  const RO = [...new Set([...outside(NODE_DIR), ...BIN_DIRS.filter((d) => !`${d}/`.startsWith(`${NODE_DIR}/`)).flatMap(outside)])];
  const PATH_IN_BOX = [...BIN_DIRS.filter((d) => outside(d).length), '/usr/local/bin', '/usr/bin', '/bin'].join(':');
  const stop = new AbortController(), operations = new Set();
  const ensureOpen = () => { stop.signal.throwIfAborted(); };
  const track = (p) => { operations.add(p); p.then(() => operations.delete(p), () => operations.delete(p)); return p; };
  const operation = (fn) => async (...args) => { ensureOpen(); return track(fn(...args)); };
  const lock = locker();
  const key = (userId, a) => `${userId}/${a.id}`;
  const homeOf = (userId, a) => join(homes, userId, a.id);
  const cli = (a, args) => [BIN[a.id], ...(a.globalArgs ?? []), ...args];
  const harness = (id) => { const a = byId.get(id); if (!a) throw new Error(`unknown harness ${id}`); return a; };
  // a user id is `user` or `scope/user` (a service keeps each client's users under its own folder): one or two ids
  const user = (userId) => { if (!USER.test(userId ?? '')) throw new Error('bad user id'); return userId; };
  let detected = new Map(); // id -> detect() row
  const usable = (id) => { const a = harness(id); if (!detected.get(id)?.usable) throw new Error(`${a.name} is not usable on this runner`); return a; };

  // ---- boxes
  const boxes = new Map(); // bwrap pid -> box, for the watchdog and close()
  /** One box over one home, scrubbed to the harness's credentials (and seeded) first; with net 'proxy' a proxy of its own for the
   *  harness's hosts. Resolves to { child, closed (exit code), kill, why (set when the watchdog stopped it) }. */
  async function spawnBox(a, { home, net = 'none', dir, boxDir = dir, cmd, stdin = 'ignore', env = {}, label, roBinds = [], nested = false, signal = stop.signal }) {
    signal.throwIfAborted();
    await mkdir(home, { recursive: true, mode: 0o700 });
    await scrubHome(home, a.keep, a.keepJsonKeys);
    for (const [rel, text] of Object.entries(a.seed ?? {})) {
      await mkdir(dirname(join(home, rel)), { recursive: true, mode: 0o700 });
      await writeFile(join(home, rel), text, { flag: 'wx', mode: 0o600 }); // the scrub removed whatever was there
    }
    let proxy = null, sock = null;
    if (net === 'proxy') {
      sock = join(tmpdir(), `hb-egress-${randomBytes(8).toString('hex')}.sock`);
      proxy = await startProxy(sock, { allow: a.hosts, label, log: report });
    }
    // the kernel's per-box cap counts threads too (a CLI has a few dozen): the watchdog counts processes against maxProcs
    const args = boxArgs({ home, dir, boxDir, net, sock, socat: SOCAT, path: PATH_IN_BOX, env: { ...passEnv, ...a.env, ...env }, roBinds: [...RO, ...roBinds], chdir: boxDir ?? home,
      cmd, maxTasks: maxProcs * 4, nested, seccomp: !!filter });
    let child;
    try {
      signal.throwIfAborted();
      child = spawn(BWRAP, args, { stdio: [stdin, 'pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH } });
    } catch (e) {
      if (proxy) { proxy.close(); await rm(sock, { force: true }); } // an argument spawn refuses (a NUL byte, say) leaves nothing open
      throw e;
    }
    child.stdio[3].on('error', () => {}).end(filter);
    // Stopping a box is SIGKILL to bwrap: --die-with-parent takes everything in it (it is a session of its own, so a group kill would not).
    const b = { child, home, dir, why: null, kill: () => { try { child.kill('SIGKILL'); } catch { /* gone */ } } };
    const abort = () => b.kill();
    if (signal.aborted) abort(); else signal.addEventListener('abort', abort, { once: true });
    child.stdin?.on('error', () => {});
    if (child.pid) boxes.set(child.pid, b);
    b.closed = new Promise((done) => { child.on('error', () => done(-1)); child.on('close', (c) => done(c ?? -1)); }).then(async (code) => {
      signal.removeEventListener('abort', abort);
      boxes.delete(child.pid);
      if (proxy) { proxy.close(); await rm(sock, { force: true }); }
      return code;
    });
    return b;
  }
  /** A short command in a box: { code, out (64 KB at most, stdout and stderr), why }. */
  async function short(a, cmd, { ms = PROBE_MS, stdin, ...o }) {
    const b = await spawnBox(a, { ...o, cmd, stdin: stdin == null ? 'ignore' : 'pipe' });
    if (stdin != null) b.child.stdin.end(stdin);
    let out = '';
    const take = (d) => { out = (out + d).slice(0, 65536); };
    b.child.stdout.setEncoding('utf8');
    b.child.stderr.setEncoding('utf8');
    b.child.stdout.on('data', take);
    b.child.stderr.on('data', take);
    const t = setTimeout(b.kill, ms);
    const code = await b.closed;
    clearTimeout(t);
    return { code, out, why: b.why };
  }

  // The watchdog: every 2 s, each box's process count (the in-box RLIMIT_NPROC is the hard cap; this names the reason and stops it)
  // and the size of its home and folder (a job folder on a tmpfs counts against memory; homes share a disk). Over a limit: killed.
  let watching = false;
  const watchdog = setInterval(async () => {
    if (!boxes.size || watching) return;
    watching = true;
    try {
      const counts = await countDescendants([...boxes.keys()]);
      for (const [pid, b] of boxes) {
        if ((counts.get(pid) ?? 0) > maxProcs) { b.why ??= `more than ${maxProcs} processes: box stopped`; b.kill(); continue; }
        try {
          const u = await diskUse([b.home, ...(b.dir ? [b.dir] : [])], maxEntries);
          if (u.bytes > maxBytes || u.entries > maxEntries) { b.why ??= `more than ${maxBytes} bytes or ${maxEntries} files: box stopped`; b.kill(); }
        } catch (e) { b.why ??= `cannot inspect box disk usage (${e.code ?? 'error'}): box stopped`; b.kill(); }
      }
    } catch (e) { report(`watchdog: ${e.message}`); } finally { watching = false; }
  }, 2000);
  watchdog.unref();

  // ---- detect: which harnesses this runner can run, by version pin, the options the commands need and the harness's own checks, in a
  // box with no network and an empty home
  const probes = gate(1); // concurrent callers must not scrub or seed the same .probe home while another probe is using it
  async function detect() {
    const release = await probes.acquire(stop.signal);
    try { return await detectHarnesses(); } finally { release(); }
  }
  async function detectHarnesses() {
    const rows = new Map();
    for (const a of adapters) {
      const r = { id: a.id, name: a.name, bin: BIN[a.id], version: null, usable: false, why: null, has: new Set() }, home = join(homes, '.probe', a.id);
      const run = (args, nested = false) => short(a, cli(a, args), { home, label: 'probe', nested });
      try {
        if (!r.bin) { r.why = 'binary not found'; continue; }
        const v = await run(['--version']);
        r.version = /\d+\.\d+\.\d+/.exec(v.out)?.[0] ?? null;
        if (v.code !== 0 || !r.version) { r.why = `--version failed (exit ${v.code})`; continue; }
        if (pins[a.id] && pins[a.id] !== r.version) { r.why = `version ${r.version}, pinned ${pins[a.id]}`; continue; }
        if (a.flags) {
          const help = (await run(a.flags.args)).out, missing = a.flags.needs.filter((f) => !help.includes(f));
          for (const f of a.flags.optional ?? []) if (help.includes(f)) r.has.add(f);
          if (missing.length) { r.why = `missing options: ${missing.join(' ')}`; continue; }
        }
        for (const c of a.checks ?? []) if (!r.why && (await run(c.args, c.nested)).code !== 0) r.why = c.why;
        r.usable = !r.why;
      } finally {
        rows.set(a.id, r);
      }
    }
    await rm(join(homes, '.probe'), { recursive: true, force: true });
    detected = rows;
    return [...rows.values()];
  }

  // ---- status, logout, purge
  async function statusIn(userId, a, { signal = stop.signal } = {}) {
    const r = await short(a, cli(a, a.status.args), { home: homeOf(userId, a), net: 'proxy', label: `status=${userId}`, signal });
    if (r.why) throw new Error(r.why);
    return { installed: true, ...a.status.parse(r) };
  }
  let quick = 0;
  /** A quick box under the user's lock: never queued behind a long job (Busy after waitMs) nor past maxQuick at once. */
  async function quickly(userId, a, waitMs, fn) {
    if (quick >= maxQuick) throw new Busy('busy');
    quick++;
    try {
      const release = await lock(key(userId, a), waitMs, stop.signal);
      if (!release) throw new Busy('busy');
      try { return await fn(); } finally { release(); }
    } finally { quick--; }
  }
  /** The CLI's own login state in the user's box: { installed, loggedIn, method, plan }. */
  async function status(userId, id, { waitMs = 5e3 } = {}) {
    const a = harness(id);
    user(userId);
    if (!detected.get(id)?.usable) return { installed: false, loggedIn: false, method: null, plan: null };
    return quickly(userId, a, waitMs, () => statusIn(userId, a));
  }
  /** The CLI's own logout in the user's box, then its status. */
  async function logout(userId, id, { waitMs = 5e3 } = {}) {
    const a = usable(id);
    user(userId);
    return quickly(userId, a, waitMs, async () => {
      const r = await short(a, cli(a, a.logout), { home: homeOf(userId, a), net: 'proxy', label: `logout=${userId}` });
      if (r.why) throw new Error(r.why);
      return statusIn(userId, a);
    });
  }
  /** Remove the user's homes (every harness): a waiting login ends, a running job ends first (its lock). */
  async function purge(userId) {
    user(userId);
    for (const [k, s] of logins) if (k.startsWith(`${userId}/`)) s.cancel();
    const releases = [];
    try {
      for (const a of adapters) releases.push(await lock(key(userId, a), Infinity, stop.signal));
      await rm(join(homes, userId), { recursive: true, force: true });
    } finally { releases.forEach((r) => r()); }
  }

  // ---- login: the CLI's own login in the user's box. paste-code: a URL, then the code the login page shows goes to the CLI's stdin
  // once; device-code: a URL and a one-time code, then the CLI finishes by itself. Only those and the outcome come out; nothing of it
  // is logged.
  const logins = new Map(); // key -> session
  /**
   * @returns {{ state: 'starting'|'waiting'|'refused'|'done'|'failed', url: string|null, code: string|null, needsCode: boolean, error?: string,
   *   waiting: Promise<{url: string, code: string|null, needsCode: boolean}>, done: Promise<{ok: boolean, status?: object, error?: string}>,
   *   submitCode(code: string): boolean, cancel(): void }}
   */
  function login(userId, id) {
    ensureOpen();
    const a = usable(id), k = key(user(userId), a);
    logins.get(k)?.cancel(); // the app forgot it (a restart, a late reply): the new one wins
    let b = null, sent = false, canceled = false, settle;
    const cancel = new AbortController(), signal = AbortSignal.any([stop.signal, cancel.signal]);
    const s = {
      state: 'starting', url: null, code: null, needsCode: a.login.kind === 'paste-code',
      waiting: new Promise((ok, no) => { settle = { ok, no }; }),
      submitCode(code) {
        if (s.state !== 'waiting' || !s.needsCode || sent || typeof code !== 'string' || !CODE.test(code)) return false;
        sent = true;
        b.child.stdin.write(`${code}\n`);
        return true;
      },
      cancel() { canceled = true; cancel.abort(); b?.kill(); },
    };
    s.waiting.catch(() => {}); // a login that fails before its URL: the reason is in done
    const end = (r) => {
      s.state = r.ok ? 'done' : 'failed';
      if (!r.ok) s.error = r.error;
      settle.no(new Error(r.error ?? 'the login ended without a URL')); // a no-op once waiting resolved
      return r;
    };
    logins.set(k, s);
    s.done = track((async () => {
      let release;
      let timedOut = false;
      try {
        release = await lock(k, Infinity, signal);
        if (canceled) return end({ ok: false, error: 'canceled' });
        b = await spawnBox(a, { home: homeOf(userId, a), net: 'proxy', cmd: cli(a, a.login.args), stdin: 'pipe', label: `login=${userId}`, signal });
        if (canceled) b.kill();
        let seen = '';
        const read = (d) => {
          if (s.state !== 'starting') return; // all that is needed went: the rest is dropped
          seen = (seen + d).replace(ANSI, '').slice(-4096);
          let got = null;
          try { got = a.login.parse(seen); } catch { /* the CLI's output never ends the runner */ }
          if (!got) return;
          const u = URL.parse(got.url);
          if (u?.protocol !== 'https:' || !a.login.urlHosts.includes(u.hostname)) { s.state = 'refused'; b.kill(); return; }
          Object.assign(s, { state: 'waiting', url: u.href, code: typeof got.code === 'string' ? got.code : null });
          seen = '';
          settle.ok({ url: s.url, code: s.code, needsCode: s.needsCode });
        };
        b.child.stdout.on('data', read);
        b.child.stderr.on('data', read);
        const t = setTimeout(() => { timedOut = true; b.kill(); }, LOGIN_MS);
        const exit = await b.closed;
        clearTimeout(t);
        if (canceled) return end({ ok: false, error: 'canceled' });
        if (b.why) return end({ ok: false, error: b.why });
        if (s.state === 'refused') return end({ ok: false, error: 'the login URL is not on the harness\'s list of login hosts' });
        if (timedOut) return end({ ok: false, error: 'the login did not finish within 10 minutes' });
        if (exit !== 0) return end({ ok: false, error: `the login failed (exit ${exit})` });
        const status = await statusIn(userId, a, { signal });
        return canceled || signal.aborted ? end({ ok: false, error: 'canceled' }) : end({ ok: true, status });
      } catch (e) {
        return end({ ok: false, error: canceled || signal.aborted ? 'canceled' : e.message });
      } finally {
        if (logins.get(k) === s) logins.delete(k);
        release?.();
      }
    })());
    return s;
  }

  // ---- jobs
  const jobSlots = gate(maxJobs);
  /**
   * One non-interactive run in the user's box: the harness's hardened command (adapter.job) plus args, in dir (writable, the cwd;
   * TMPDIR is dir/.tmp). Waits for a job slot and the user's lock. Never rejects for the CLI's own failure: { code, text, usage
   * ({input, output[, unknown]}), error, stderr (tail), why (watchdog), timedOut, canceled, loggedIn (after a failure: false when the
   * login is gone, else the CLI's status) }. roBinds: read-only paths in the box (e.g. a pristine skill over dir/skill). boxDir: where
   * the box sees dir (default: the same path). model: the CLI's --model. onStart(): the box started (it waited for the lock and a
   * slot until then). onEvent(e, { stage }): each JSON event.
   */
  async function run(userId, id, { prompt, dir, boxDir, model, timeoutMs = 40 * 60e3, args = [], env = {}, roBinds = [], signal, onStart, onEvent } = {}) {
    const a = usable(id), k = key(user(userId), a);
    if (typeof prompt !== 'string' || !prompt || prompt.startsWith('-') || prompt.includes('\0')) throw new Error('prompt must be a non-empty string not starting with "-"');
    const canceledResult = () => ({ code: -1, text: '', usage: { input: 0, output: 0, unknown: true }, error: '', stderr: '', why: stop.signal.aborted ? 'runner closed' : null, timedOut: false, canceled: true });
    const activeSignal = signal ? AbortSignal.any([stop.signal, signal]) : stop.signal;
    let release, free;
    try {
      activeSignal.throwIfAborted();
      if (model != null && !MODEL.test(model)) throw new Error('bad model');
      dir = await realpath(dir); // the adapter's paths and readOut compare against the real path
      boxDir ??= dir;
      // One user's queued jobs wait on their own lock, not in slots other users need. Both waits are cancelable.
      release = await lock(k, Infinity, activeSignal);
      free = await jobSlots.acquire(activeSignal);
      activeSignal.throwIfAborted();
      await mkdir(join(dir, '.tmp'), { recursive: true });
      const tmp = join(boxDir, '.tmp'), c = a.job.command({ prompt, dir: boxDir, has: detected.get(id).has, extra: [...(model ? ['--model', model] : []), ...args] });
      const b = await spawnBox(a, { home: homeOf(userId, a), net: 'proxy', dir, boxDir, cmd: cli(a, c.args), stdin: c.stdin == null ? 'ignore' : 'pipe',
        env: { TMPDIR: tmp, TMP: tmp, TEMP: tmp, ...env }, label: `job=${userId}`, roBinds, nested: !!a.nested, signal: activeSignal });
      if (c.stdin != null) b.child.stdin.end(c.stdin);
      try { onStart?.(); } catch { /* the caller's */ }
      const acc = { text: '', usage: { input: 0, output: 0 }, reports: 0, error: '', stage: '' };
      let out = '', err = '', timedOut = false, canceled = false, outputBytes = 0, outputStopped = false;
      const stdout = new StringDecoder('utf8'), stderr = new StringDecoder('utf8');
      const budget = (d) => {
        if (outputStopped) return false;
        outputBytes += d.length;
        if (outputBytes <= maxOutputBytes) return true;
        outputStopped = true;
        b.why ??= `more than ${maxOutputBytes} output bytes: box stopped`;
        b.kill();
        return false;
      };
      // one JSON event a line; a line that does not parse (cut off by a stop, say) is skipped
      const line = (l) => {
        let e;
        try { e = JSON.parse(l); } catch { return; }
        if (!e || typeof e !== 'object') return;
        try { a.job.event(e, acc); } catch { /* hostile events cannot end the runner */ }
        try { Promise.resolve(onEvent?.(e, { stage: acc.stage })).catch(() => report('onEvent handler failed')); } catch { report('onEvent handler failed'); }
      };
      b.child.stdout.on('data', (d) => { if (budget(d)) { const lines = (out + stdout.write(d)).split('\n'); out = lines.pop(); lines.forEach(line); } });
      b.child.stderr.on('data', (d) => { if (budget(d)) err = (err + stderr.write(d)).slice(-4000); });
      const abort = () => { canceled = true; b.kill(); };
      if (activeSignal.aborted) abort(); else activeSignal.addEventListener('abort', abort, { once: true });
      const limit = setTimeout(() => { timedOut = true; b.kill(); }, timeoutMs);
      const code = await b.closed;
      clearTimeout(limit);
      activeSignal.removeEventListener('abort', abort);
      if (!outputStopped) line(out + stdout.end());
      err = (err + stderr.end()).slice(-4000);
      await a.job.finish?.(acc, { dir, readOut });
      canceled ||= activeSignal.aborted;
      // The process may have exited 0 before buffered output reached us. A resource violation or stop is still a failed run.
      const r = { code: b.why || timedOut || canceled ? -1 : code, text: acc.text, usage: acc.reports ? acc.usage : { ...acc.usage, unknown: true }, error: acc.error, stderr: err, why: b.why, timedOut, canceled };
      // the CLI's own login as it stands now, so a login that expired shows (status alone may only see that credentials exist)
      if (!b.why && !timedOut && !canceled && code !== 0) r.loggedIn = a.expired?.test(`${acc.error} ${err}`) ? false : (await statusIn(userId, a, { signal: activeSignal }).catch(() => null))?.loggedIn;
      if (activeSignal.aborted) {
        r.code = -1;
        r.canceled = true;
        if (stop.signal.aborted) r.why ??= 'runner closed';
        delete r.loggedIn; // an interrupted status check is not evidence that a credential expired
      }
      return r;
    } catch (e) {
      if (activeSignal.aborted) return canceledResult();
      throw e;
    } finally {
      if (release) await scrubHome(homeOf(userId, a), a.keep, a.keepJsonKeys).catch(() => report('home scrub failed'));
      free?.();
      release?.();
    }
  }

  /** Any command in the user's box for a harness (a validator over a job's output, say), under the user's lock: { code, out, why }.
   *  net 'none' by default; 'proxy' gives the harness's hosts. boxDir: where the box sees dir. */
  async function exec(userId, id, argv, { net = 'none', dir, boxDir, ms = 60e3, stdin, env, roBinds, nested = false, signal } = {}) {
    const a = harness(id), k = key(user(userId), a), active = signal ? AbortSignal.any([stop.signal, signal]) : stop.signal;
    const release = await lock(k, Infinity, active);
    try {
      return await short(a, argv, { home: homeOf(userId, a), net, dir: dir && await realpath(dir), boxDir, ms, stdin, env, roBinds, nested, signal: active, label: `exec=${userId}` });
    } finally { release(); }
  }

  /** Stop accepting work, cancel waiters, kill boxes, and wait for in-flight operations to finish their cleanup. Idempotent. */
  let closing;
  function close() {
    if (closing) return closing;
    stop.abort(new Error('runner is closed'));
    clearInterval(watchdog);
    for (const s of logins.values()) s.cancel();
    for (const b of boxes.values()) b.kill();
    closing = Promise.allSettled([...operations]).then(() => {});
    return closing;
  }

  return { detect: operation(detect), status: operation(status), login, logout: operation(logout), purge: operation(purge),
    run: operation(run), exec: operation(exec), close, boxes, bin: (id) => BIN[harness(id).id] };
}
