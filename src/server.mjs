#!/usr/bin/env node
// harnessbox as a service: one hardened container runs the boxes; web apps (clients) call it over HTTP on a unix socket they share
// with it (or a private TCP port) to manage their users' harness logins and to run jobs in those users' boxes. A client never holds
// a harness credential, and never sees another client's users: each client's users live under /homes/<client>/. Runs and login
// sessions are in memory; after a restart an unknown id is a 404 and the client asks again. docs/service.md is the API reference.
// Nothing here logs or keeps a URL, code, token, prompt or output: only ids, states and the runner's egress denials.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { dirname, join } from 'node:path';
import { claudeCode, codex, grok } from './adapters.mjs';
import { ID, readOut } from './box.mjs';
import { Busy, createRunner } from './runner.mjs';

/** Where every run's folder appears inside its box: prompts, files and tool rules can name /work/... before the run exists. */
export const BOX_DIR = '/work';
export const LIMITS = {
  body: 64 * 2 ** 20, prompt: 256 * 1024, files: 2000, filesBytes: 48 * 2 ** 20, outputs: 32, output: 2 * 2 ** 20, outputsBytes: 16 * 2 ** 20,
  activeRuns: 16, keptRuns: 200, keptBytes: 256 * 2 ** 20, inflightBytes: 128 * 2 ** 20, streams: 32, logins: 4, runTimeoutMs: 2 * 3600e3, validateMs: 10 * 60e3, keepMs: 30 * 60e3, statusFreshMs: 30e3, readyMs: 30e3,
};
const CODE = /^[\x21-\x7e]{1,2048}$/, MODEL = /^[A-Za-z0-9._:@/-]{1,100}$/;
const ACTIVE = new Set(['queued', 'running', 'validating']);

class HttpError extends Error { constructor(status, code, message) { super(message); Object.assign(this, { status, code }); } }
const no = (status, code, message) => { throw new HttpError(status, code, message); };
const sha = (s) => createHash('sha256').update(s).digest();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms).unref());
/** A relative path of plain segments: no '', '.', '..', NUL or backslash; at most 1024 bytes. */
const safePath = (p) => typeof p === 'string' && p.length <= 1024 && !p.startsWith('/') && p.split('/').every((s) => s && s !== '.' && s !== '..' && !/[\0\\]/.test(s) && s.length <= 255);
const strings = (v, max, what) => {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > max || !v.every((s) => typeof s === 'string' && s.length <= 4096 && !s.includes('\0'))) no(400, 'bad_request', `${what}: at most ${max} strings`);
  return v;
};

/**
 * @param {object} o
 * @param {ReturnType<typeof createRunner> extends Promise<infer R> ? R : never} o.hb  the runner (createRunner), already detected
 * @param {{id: string, name: string, version: string|null, usable: boolean, why: string|null}[]} o.harnesses  hb.detect()'s rows
 * @param {{id: string, tokenSha256: string, harnesses?: string[]}[]} o.clients
 * @param {string} o.runs  folder for the run folders (a tmpfs); emptied by main() at start
 * @param {Record<string, string[]>} [o.models]  allowed models per harness id (absent: any well-formed name)
 * @param {Partial<typeof LIMITS>} [o.limits]
 */
export function createService({ hb, harnesses, clients, runs: runsDir, models = {}, limits = {}, log = () => {} }) {
  const L = { ...LIMITS, ...limits };
  const known = new Map(harnesses.map((h) => [h.id, h]));
  const keys = clients.map((c) => {
    if (!ID.test(c.id ?? '') || !/^[0-9a-f]{64}$/.test(c.tokenSha256 ?? '')) throw new Error(`bad client entry ${c.id}`);
    return { id: c.id, hash: Buffer.from(c.tokenSha256, 'hex'), harnesses: c.harnesses ? new Set(c.harnesses) : null };
  });
  const auth = (req) => {
    const m = /^Bearer (\S{16,512})$/.exec(req.headers.authorization ?? '');
    const h = m && sha(m[1]);
    const c = h && keys.find((k) => timingSafeEqual(k.hash, h));
    return c ?? no(401, 'unauthorized', 'a valid bearer token is required');
  };
  const userOf = (c, user) => (typeof user === 'string' && ID.test(user) ? `${c.id}/${user}` : no(400, 'bad_user', 'user ids are [A-Za-z0-9_-]{1,64}'));
  const harnessOf = (c, id) => {
    const h = known.get(id);
    if (!h || (c.harnesses && !c.harnesses.has(id))) no(404, 'unknown_harness', `no harness ${id} for this client`);
    if (!h.usable) no(409, 'not_usable', `${h.name} is not usable on this service`);
    return h;
  };
  const allowed = (c) => harnesses.filter((h) => !c.harnesses || c.harnesses.has(h.id));

  // ---- status, with a short cache (each ask is a box); a login or run of that user and harness answers busy at once
  const statuses = new Map(); // `${scoped}/${harness}` -> { status, at }
  const sessions = new Map(); // `${scoped}/${harness}` -> session
  const runs = new Map(); // id -> run
  const busyNow = (scoped, h) => ['starting', 'waiting'].includes(sessions.get(`${scoped}/${h}`)?.s.state)
    || [...runs.values()].some((r) => r.scoped === scoped && r.harness === h && ACTIVE.has(r.state));
  async function status(scoped, h) {
    const k = `${scoped}/${h}`, cached = statuses.get(k);
    if (cached && Date.now() - cached.at < L.statusFreshMs) return { ...cached.status, checkedAt: new Date(cached.at).toISOString() };
    if (busyNow(scoped, h)) throw new Busy('busy');
    const s = await hb.status(scoped, h, { waitMs: 2000 });
    remember(scoped, h, s);
    return { ...s, checkedAt: new Date().toISOString() };
  }
  const remember = (scoped, h, s) => {
    if (!s) return;
    statuses.set(`${scoped}/${h}`, { status: s, at: Date.now() });
    if (statuses.size > 10000) for (const [k, v] of statuses) if (Date.now() - v.at > L.statusFreshMs) statuses.delete(k); // stale ones only serve busy answers
  };

  // ---- logins: the runner's session; the service keeps the outcome for keepMs after it ends
  const view = (x) => ({ state: x.s.state === 'refused' ? 'starting' : x.s.state, url: x.s.url, code: x.s.code, needsCode: x.s.needsCode, startedAt: x.startedAt, expiresAt: x.expiresAt,
    ...(x.s.error ? { error: x.s.error } : {}), ...(x.status ? { status: x.status } : {}) });
  async function startLogin(c, scoped, h) {
    if ([...sessions.entries()].filter(([k, x]) => k.startsWith(`${c.id}/`) && ['starting', 'waiting'].includes(x.s.state)).length >= L.logins) no(429, 'too_many_logins', `at most ${L.logins} logins waiting per client`);
    const k = `${scoped}/${h}`, s = hb.login(scoped, h), now = Date.now();
    const x = { s, startedAt: new Date(now).toISOString(), expiresAt: new Date(now + 10 * 60e3).toISOString(), status: null };
    sessions.set(k, x);
    statuses.delete(k);
    log(`login client=${c.id} user=${scoped} harness=${h} started`);
    void s.done.then((r) => {
      x.status = r.status ?? null;
      remember(scoped, h, r.status);
      log(`login client=${c.id} user=${scoped} harness=${h} ${s.state}`);
      setTimeout(() => { if (sessions.get(k) === x) sessions.delete(k); }, L.keepMs).unref();
    });
    await Promise.race([s.waiting.catch(() => {}), s.done, sleep(L.readyMs)]);
    return view(x);
  }

  // ---- runs
  const snapshot = (r, full = true) => ({
    id: r.id, user: r.user, harness: r.harness, model: r.model, state: r.state, createdAt: r.createdAt, startedAt: r.startedAt, endedAt: r.endedAt,
    stage: r.stage, events: r.events, ...(r.error ? { error: r.error } : {}), result: r.result, validator: r.validator, ...(full ? { outputs: r.outputs } : {}),
  });
  const emit = (r, event) => { for (const l of r.listeners) l(event); };
  const set = (r, state) => { if (r.state === state || !ACTIVE.has(r.state)) return; r.state = state; if (state === 'running') r.startedAt = new Date().toISOString(); emit(r, 'state'); };
  async function createRun(c, b) {
    if (!b || typeof b !== 'object') no(400, 'bad_request', 'a JSON object is required');
    const scoped = userOf(c, b.user), h = harnessOf(c, b.harness).id;
    if (typeof b.prompt !== 'string' || !b.prompt || b.prompt.startsWith('-') || b.prompt.includes('\0') || Buffer.byteLength(b.prompt) > L.prompt) no(400, 'bad_prompt', `prompt: a string of at most ${L.prompt} bytes, not starting with "-"`);
    if (b.model != null && (typeof b.model !== 'string' || !MODEL.test(b.model) || (models[h] && !models[h].includes(b.model)))) no(400, 'bad_model', `model not allowed for ${h}`);
    const timeoutMs = b.timeoutMs ?? 40 * 60e3;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > L.runTimeoutMs) no(400, 'bad_timeout', `timeoutMs: 1000..${L.runTimeoutMs}`);
    const args = strings(b.args, 64, 'args'), outputs = strings(b.outputs, L.outputs, 'outputs'), readonly = strings(b.readonly, 16, 'readonly');
    if (![...outputs, ...readonly].every(safePath) || new Set(outputs).size !== outputs.length) no(400, 'bad_path', 'outputs and readonly are distinct relative paths');
    if (readonly.some((p) => readonly.some((q) => q !== p && (q.startsWith(`${p}/`) || q === p)))) no(400, 'bad_path', 'readonly folders may not overlap');
    let validate = null;
    if (b.validate != null) {
      const argv = strings(b.validate.argv, 64, 'validate.argv'), ms = b.validate.timeoutMs ?? 60e3;
      if (!argv.length || (b.validate.net ?? 'none') !== 'none' || !Number.isInteger(ms) || ms < 1000 || ms > L.validateMs) no(400, 'bad_validate', `validate: { argv, net: 'none', timeoutMs ≤ ${L.validateMs} }`);
      validate = { argv, ms };
    }
    const files = b.files ?? [];
    if (!Array.isArray(files) || files.length > L.files) no(400, 'bad_files', `files: at most ${L.files}`);
    const mine = [...runs.values()].filter((r) => r.client === c.id);
    if (mine.filter((r) => ACTIVE.has(r.state)).length >= L.activeRuns) no(429, 'too_many_runs', `at most ${L.activeRuns} active runs per client`);
    if (mine.length >= L.keptRuns) {
      const old = mine.find((r) => !ACTIVE.has(r.state)); // the oldest ended one makes room
      if (!old) no(429, 'too_many_runs', 'too many runs');
      runs.delete(old.id);
    }

    // the folder: work/ is the box's /work; readonly folders are written beside it (ro/) and bound read-only over work/<folder>
    const id = `run_${randomBytes(12).toString('base64url')}`, root = await mkdtemp(join(runsDir, `${id}-`)), work = join(root, 'work');
    try {
      await mkdir(work);
      let bytes = 0;
      for (const f of files) {
        if (!f || !safePath(f.path) || (typeof f.base64 !== 'string') === (typeof f.text !== 'string')) no(400, 'bad_files', 'each file is { path, base64 } or { path, text }');
        const data = typeof f.text === 'string' ? Buffer.from(f.text) : Buffer.from(f.base64, 'base64');
        if ((bytes += data.length) > L.filesBytes) no(413, 'too_large', `files: at most ${L.filesBytes} bytes`);
        const ro = readonly.find((p) => f.path.startsWith(`${p}/`)), to = ro ? join(root, 'ro', f.path) : join(work, f.path);
        await mkdir(dirname(to), { recursive: true }).then(() => writeFile(to, data, { flag: 'wx' }))
          .catch((e) => no(400, 'bad_files', `file ${f.path} clashes with another file or folder (${e.code})`));
      }
      for (const p of [...readonly, ...outputs.map(dirname).filter((d) => d !== '.')]) await mkdir(join(work, p), { recursive: true }).catch((e) => no(400, 'bad_path', `folder ${p} clashes with a file (${e.code})`));
      for (const p of readonly) await mkdir(join(root, 'ro', p), { recursive: true }).catch((e) => no(400, 'bad_path', `folder ${p} clashes with a file (${e.code})`));
    } catch (e) { await rm(root, { recursive: true, force: true }); throw e; }
    const r = {
      id, client: c.id, user: b.user, scoped, harness: h, model: b.model ?? null, state: 'queued', createdAt: new Date().toISOString(), startedAt: null, endedAt: null,
      stage: '', events: 0, result: null, validator: null, outputs: null, error: null, ac: new AbortController(), listeners: new Set(),
    };
    runs.set(id, r);
    log(`run client=${c.id} run=${id} user=${scoped} harness=${h} queued`);
    void execute(r, { root, work, prompt: b.prompt, timeoutMs, args, outputs, validate, roBinds: readonly.map((p) => [join(root, 'ro', p), join(BOX_DIR, p)]) });
    return r;
  }
  async function execute(r, { root, work, prompt, timeoutMs, args, outputs, validate, roBinds }) {
    const signal = r.ac.signal;
    let last = 0;
    try {
      const res = await hb.run(r.scoped, r.harness, {
        prompt, dir: work, boxDir: BOX_DIR, model: r.model ?? undefined, timeoutMs, args, roBinds, signal,
        onStart: () => set(r, 'running'),
        onEvent: (e, { stage }) => {
          r.events++;
          r.stage = stage || (typeof e.type === 'string' ? e.type.slice(0, 40) : '');
          if (Date.now() - last >= 1000) { last = Date.now(); emit(r, 'progress'); }
        },
      });
      r.result = res;
      if (res.loggedIn !== undefined) remember(r.scoped, r.harness, res.loggedIn ? null : { installed: true, loggedIn: false, method: null, plan: null });
      // the validator in a second box, no network, over the same folder and the same read-only binds, with an empty home of its own:
      // the client chose the command, and it must not see the user's credential
      if (validate && !signal.aborted && !res.why && (res.code === 0 || res.timedOut)) {
        set(r, 'validating');
        const v = await hb.exec(r.scoped, r.harness, validate.argv, { dir: work, boxDir: BOX_DIR, roBinds, ms: validate.ms, signal, home: join(root, 'home') });
        r.validator = { code: v.code, out: v.out, why: v.why };
      }
      // outputs: regular files really at work/<path>, never through a link the box made; too big or missing: null
      const real = await realpath(work);
      let total = 0;
      r.outputs = {};
      for (const p of outputs) {
        const text = await readOut(real, p, L.output);
        if (text !== null && (total += Buffer.byteLength(text)) <= L.outputsBytes) r.outputs[p] = Buffer.from(text).toString('base64');
        else r.outputs[p] = null;
      }
      r.bytes = total + Buffer.byteLength(res.text) + Buffer.byteLength(res.stderr) + Buffer.byteLength(r.validator?.out ?? '');
      r.state = signal.aborted || res.canceled ? 'canceled' : res.code === 0 && !res.why ? 'done' : 'failed';
    } catch (e) {
      r.error = String(e.message).slice(0, 300);
      r.state = signal.aborted ? 'canceled' : 'failed';
    } finally {
      r.endedAt = new Date().toISOString();
      await rm(root, { recursive: true, force: true }).catch(() => {});
      log(`run client=${r.client} run=${r.id} ${r.state}`);
      emit(r, 'end');
      r.listeners.clear();
      setTimeout(() => runs.delete(r.id), L.keepMs).unref();
      // ended runs hold their outputs in memory: past keptBytes for everybody, the oldest ended runs go first
      let kept = 0;
      for (const x of runs.values()) kept += x.bytes ?? 0;
      for (const x of runs.values()) { if (kept <= L.keptBytes) break; if (!ACTIVE.has(x.state)) { kept -= x.bytes ?? 0; runs.delete(x.id); } }
    }
  }
  const runOf = (c, id) => { const r = runs.get(id); return r && r.client === c.id ? r : no(404, 'unknown_run', 'no such run (a restart forgets runs)'); };
  const streams = new Map(); // client -> open event streams
  function events(c, r, res) {
    if ((streams.get(c.id) ?? 0) >= L.streams) no(429, 'too_many_streams', `at most ${L.streams} event streams per client`);
    streams.set(c.id, (streams.get(c.id) ?? 0) + 1);
    res.on('close', () => streams.set(c.id, streams.get(c.id) - 1));
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
    const send = (event) => res.write(`event: ${event}\ndata: ${JSON.stringify(snapshot(r, event === 'end'))}\n\n`);
    if (!ACTIVE.has(r.state)) { send('end'); return res.end(); }
    send('state');
    const ping = setInterval(() => res.write(': ping\n\n'), 15e3);
    const l = (event) => { send(event); if (event === 'end') res.end(); };
    r.listeners.add(l);
    res.on('close', () => { clearInterval(ping); r.listeners.delete(l); });
  }

  // ---- HTTP
  const json = (res, status, body) => {
    const data = body === undefined ? '' : JSON.stringify(body);
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(data) });
    res.end(data);
  };
  const inflight = new Map(); // client -> body bytes being read
  const body = (c, req) => new Promise((done, fail) => {
    if (Number(req.headers['content-length'] ?? 0) > L.body) return fail(new HttpError(413, 'too_large', `request bodies are at most ${L.body} bytes`));
    const chunks = [];
    let n = 0, over = null;
    const add = (d) => inflight.set(c.id, (inflight.get(c.id) ?? 0) + d);
    const stop = (e) => { if (over) return; over = e; req.removeAllListeners('data'); req.resume(); add(-n); fail(e); };
    req.on('data', (d) => {
      n += d.length;
      add(d.length);
      if (n > L.body) stop(new HttpError(413, 'too_large', `request bodies are at most ${L.body} bytes`));
      else if (inflight.get(c.id) > L.inflightBytes) stop(new HttpError(429, 'too_many_uploads', 'too many request bytes in flight for this client'));
      else chunks.push(d);
    });
    req.on('end', () => { if (over) return; add(-n); try { done(n ? JSON.parse(Buffer.concat(chunks)) : null); } catch { fail(new HttpError(400, 'bad_json', 'the body is not JSON')); } });
    req.on('error', (e) => stop(e));
  });
  async function route(req, res) {
    const c = auth(req), url = new URL(req.url, 'http://x'), m = req.method, p = url.pathname.split('/').slice(1).map(decodeURIComponent);
    if (p[0] !== 'v1') no(404, 'not_found', 'not found');
    if (m === 'GET' && p.length === 2 && p[1] === 'harnesses') return json(res, 200, { harnesses: allowed(c).map(({ id, name, version, usable, why }) => ({ id, name, version, usable, why })) });
    if (p[1] === 'users' && p.length >= 3) {
      const scoped = userOf(c, p[2]);
      if (p.length === 3 && m === 'DELETE') {
        for (const r of runs.values()) if (r.scoped === scoped && ACTIVE.has(r.state)) r.ac.abort();
        await hb.purge(scoped);
        for (const k of [...statuses.keys(), ...sessions.keys()]) if (k.startsWith(`${scoped}/`)) { statuses.delete(k); sessions.delete(k); }
        log(`purge client=${c.id} user=${scoped}`);
        return json(res, 204);
      }
      if (p[3] !== 'harnesses') no(404, 'not_found', 'not found');
      if (p.length === 4 && m === 'GET') {
        // one after another: the runner allows maxQuick status boxes at once for everybody
        const list = [];
        for (const h of allowed(c).filter((x) => x.usable)) {
          try { list.push({ harness: h.id, ...(await status(scoped, h.id)) }); } catch (e) {
            if (e instanceof Busy) list.push({ harness: h.id, busy: true, ...(statuses.get(`${scoped}/${h.id}`)?.status ?? {}) });
            else list.push({ harness: h.id, error: String(e.message).slice(0, 200) });
          }
        }
        return json(res, 200, { harnesses: list });
      }
      const h = harnessOf(c, p[4]).id, k = `${scoped}/${h}`;
      if (p.length === 5 && m === 'GET') return json(res, 200, { harness: h, ...(await status(scoped, h)) });
      if (p.length === 6 && p[5] === 'logout' && m === 'POST') {
        const s = await hb.logout(scoped, h, { waitMs: 2000 });
        remember(scoped, h, s);
        log(`logout client=${c.id} user=${scoped} harness=${h}`);
        return json(res, 200, { harness: h, ...s });
      }
      if (p[5] === 'login') {
        if (p.length === 6 && m === 'POST') return json(res, 200, await startLogin(c, scoped, h));
        const x = sessions.get(k) ?? no(404, 'no_login', 'no login for this user and harness');
        if (p.length === 6 && m === 'GET') return json(res, 200, view(x));
        if (p.length === 6 && m === 'DELETE') { x.s.cancel(); await x.s.done; return json(res, 204); }
        if (p.length === 7 && p[6] === 'code' && m === 'POST') {
          const code = (await body(c, req))?.code;
          if (typeof code !== 'string' || !CODE.test(code)) no(400, 'bad_code', 'code: printable ASCII without spaces');
          return x.s.submitCode(code) ? json(res, 204) : no(409, 'not_waiting_for_code', 'this login takes no code now');
        }
      }
    }
    if (p[1] === 'runs') {
      if (p.length === 2 && m === 'POST') { const r = await createRun(c, await body(c, req)); return json(res, 202, snapshot(r)); }
      const r = runOf(c, p[2] ?? '');
      if (p.length === 3 && m === 'GET') return json(res, 200, snapshot(r));
      if (p.length === 3 && m === 'DELETE') {
        r.ac.abort(); // a queued run leaves the user's lock and the slot queue at once; the run ends canceled
        return json(res, 204);
      }
      if (p.length === 4 && p[3] === 'events' && m === 'GET') return events(c, r, res);
    }
    no(404, 'not_found', 'not found');
  }
  const server = http.createServer((req, res) => {
    route(req, res).catch((e) => {
      const err = e instanceof HttpError ? e : e instanceof Busy ? new HttpError(409, 'busy', 'this user\'s harness is busy (a login or a run); ask again later')
        : e instanceof URIError ? new HttpError(400, 'bad_request', 'bad path') : new HttpError(500, 'internal', 'internal error');
      if (err.status === 500) log(`error ${e.code ?? e.name}`); // never a message: it may carry a path or a value from the request
      if (res.headersSent) return res.destroy();
      if (err.status === 413) res.setHeader('connection', 'close'); // the rest of that body is not read
      json(res, err.status, { error: { code: err.code, message: err.message } });
    });
  });
  server.maxConnections = 512;
  server.requestTimeout = 5 * 60e3;
  return { server, runs, close: () => { for (const r of runs.values()) r.ac.abort(); server.close(); server.closeAllConnections(); } };
}

// ---- main: configuration from the environment (docs/service.md)
async function main() {
  const env = process.env, all = [claudeCode, codex, grok];
  const want = (env.HB_HARNESSES ?? all.map((a) => a.id).join(',')).split(',');
  const adapters = all.filter((a) => want.includes(a.id)), envKey = (a) => a.id.toUpperCase().replace(/-/g, '_');
  const pick = (prefix) => Object.fromEntries(adapters.flatMap((a) => (env[`${prefix}${envKey(a)}`] ? [[a.id, env[`${prefix}${envKey(a)}`]]] : [])));
  const clients = JSON.parse(await readFile(env.HB_CLIENTS ?? '/etc/harnessbox/clients.json', 'utf8')).clients;
  const runs = env.HB_RUNS ?? '/tmp/hb-runs', listen = env.HB_LISTEN ?? '/run/harnessbox/hb.sock';
  const log = (l) => console.log(`[harnessbox] ${l}`);
  // a restart forgets every run: their folders go too
  await mkdir(runs, { recursive: true, mode: 0o700 });
  for (const n of await readdir(runs)) await rm(join(runs, n), { recursive: true, force: true });
  const hb = await createRunner({ homes: env.HB_HOMES ?? '/homes', adapters, bins: pick('HB_BIN_'), pins: pick('HB_PIN_'), bwrap: env.HB_BWRAP ?? 'bwrap', socat: env.HB_SOCAT ?? 'socat',
    maxJobs: Number(env.HB_MAX_JOBS) || 3, maxQuick: Number(env.HB_MAX_QUICK) || 4, log });
  const harnesses = await hb.detect();
  for (const h of harnesses) log(`${h.id} ${h.version ?? '-'} ${h.usable ? 'usable' : `not usable: ${h.why}`}`);
  const models = Object.fromEntries(Object.entries(pick('HB_MODELS_')).map(([k, v]) => [k, v.split(',')]));
  const svc = createService({ hb, harnesses, clients, runs, models, limits: env.HB_MAX_BODY ? { body: Number(env.HB_MAX_BODY) } : {}, log });
  const tcp = /^([^/][^:]*):(\d+)$/.exec(listen);
  if (!tcp) { await mkdir(dirname(listen), { recursive: true }); await rm(listen, { force: true }); }
  await new Promise((done, fail) => { svc.server.once('error', fail); if (tcp) svc.server.listen(Number(tcp[2]), tcp[1], done); else svc.server.listen(listen, done); });
  // the socket's folder is a volume shared with the client apps only; the bearer token is the other half
  if (!tcp) await chmod(listen, 0o666);
  log(`listening on ${listen} for ${clients.length} client(s)`);
  for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => { svc.close(); hb.close(); process.kill(process.pid, sig); });
}
if (import.meta.main) await main();
