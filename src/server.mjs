#!/usr/bin/env node
// harnessbox as a service: one hardened container runs the boxes; web apps (clients) call it over HTTP on a unix socket they share
// with it (or a private TCP port) to manage their users' harness logins and to run jobs in those users' boxes. A client never holds
// a harness credential, and never sees another client's users: each client's users live under /homes/<client>/. Runs and login
// sessions are in memory; after a restart an unknown id is a 404 and the client asks again. docs/service.md is the API reference.
// Nothing here logs or keeps a URL, code, token, prompt or output: only ids, states and the runner's egress denials.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { dirname, join } from 'node:path';
import { claudeCode, clip, codex, grok } from './adapters.mjs';
import { ID, readOutBytes, rmTree } from './box.mjs';
import { VERSION as CLIENT_VERSION, older } from './client.mjs';
import { Busy, createRunner } from './runner.mjs';
import pkg from '../package.json' with { type: 'json' };

/** Where every run's folder appears inside its box: prompts, files and tool rules can name /work/... before the run exists. */
export const BOX_DIR = '/work';
export const LIMITS = {
  body: 64 * 2 ** 20, prompt: 256 * 1024, files: 2000, filesBytes: 48 * 2 ** 20, outputs: 32, output: 2 * 2 ** 20, outputsBytes: 16 * 2 ** 20,
  eventsBytes: 2 ** 20, eventBytes: 64 * 1024, eventDepth: 64, eventsCount: 2000, activeRuns: 16, keptRuns: 200, keptBytes: 256 * 2 ** 20, inflightBytes: 128 * 2 ** 20, answerBytes: 128 * 2 ** 20, streams: 32, logins: 4, runTimeoutMs: 2 * 3600e3, validateMs: 10 * 60e3, keepMs: 30 * 60e3, statusFreshMs: 30e3, readyMs: 30e3,
};
/** This service's version, in every answer's harnessbox-version header. */
export const VERSION = pkg.version;
/** The oldest client this service takes (an older one gets 426 client_too_old): raise it only for a change older clients cannot
 *  take, keeping the client's functions as they are (anything else is /v2). test/compat runs each released client from it on.
 *  Clients before 0.5.0 send no version and count as 0.4.0: a minimum over 0.2.0 and under 0.5.0 would refuse none of them. */
export const MIN_CLIENT = '0.2.0';
const SEMVER = /^\d{1,4}\.\d{1,4}\.\d{1,4}$/;
const CODE = /^[\x21-\x7e]{1,2048}$/, MODEL = /^[A-Za-z0-9._:@/-]{1,100}$/;
const ACTIVE = new Set(['queued', 'running', 'validating']);

class HttpError extends Error { constructor(status, code, message) { super(message); Object.assign(this, { status, code }); } }
const no = (status, code, message) => { throw new HttpError(status, code, message); };
const sha = (s) => createHash('sha256').update(s).digest();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms).unref());
/** A relative path of plain segments: no '', '.', '..', NUL or backslash; at most 1024 bytes. */
const safePath = (p) => typeof p === 'string' && Buffer.byteLength(p) <= 1024 && !p.startsWith('/') && p.split('/').every((s) => s && s !== '.' && s !== '..' && !/[\0\\]/.test(s) && Buffer.byteLength(s) <= 255);
const strings = (v, max, what) => {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > max || !v.every((s) => typeof s === 'string' && s.length <= 4096 && !s.includes('\0'))) no(400, 'bad_request', `${what}: at most ${max} strings`);
  return v;
};

// Claude Code reads a --settings value as inline JSON when, trimmed, it starts with { and ends with }, else as a file path (2.1.300).
// Inline here: a value whose trim parses as a JSON object, which Claude always reads inline; anything else counts as a file.
const jsonObject = (v) => { try { const j = JSON.parse(v.trim()); return j !== null && typeof j === 'object' && !Array.isArray(j); } catch { return false; } };

/**
 * @param {object} o
 * @param {ReturnType<typeof createRunner> extends Promise<infer R> ? R : never} o.hb  the runner (createRunner), already detected
 * @param {{id: string, name: string, version: string|null, usable: boolean, why: string|null, webSearch?: boolean}[]} o.harnesses  hb.detect()'s rows
 * @param {{id: string, tokenSha256: string, harnesses?: string[], webSearch?: boolean, events?: boolean}[]} o.clients  webSearch, events: what
 *   its runs may ask for (default false)
 * @param {string} o.runs  folder for the run folders (a tmpfs); emptied by main() at start
 * @param {Record<string, string[]>} [o.models]  allowed models per harness id (absent: any well-formed name)
 * @param {Partial<typeof LIMITS>} [o.limits]
 * @param {string} [o.minClient]  default MIN_CLIENT
 * @param {{version: string, source: string, signature: string}} [o.client]  what GET /v1/client hands out: default src/client.mjs and its .sig
 */
export function createService({ hb, harnesses, clients, runs: runsDir, models = {}, limits = {}, log = () => {}, minClient = MIN_CLIENT,
  client = { version: CLIENT_VERSION, source: readFileSync(new URL('./client.mjs', import.meta.url), 'utf8'), signature: readFileSync(new URL('./client.mjs.sig', import.meta.url), 'utf8').trim() } }) {
  const L = { ...LIMITS, ...limits };
  if (limits.body && !limits.filesBytes) L.filesBytes = Math.floor(limits.body * 0.75); // base64 in JSON
  L.inflightBytes = Math.max(L.inflightBytes, L.body); // else a body that size is a 429
  const known = new Map(harnesses.map((h) => [h.id, h]));
  const keys = clients.map((c) => {
    if (!ID.test(c.id ?? '') || !/^[0-9a-f]{64}$/.test(c.tokenSha256 ?? '')) throw new Error(`bad client entry ${c.id}`);
    for (const k of ['webSearch', 'events']) if (c[k] !== undefined && typeof c[k] !== 'boolean') throw new Error(`bad client entry ${c.id}: ${k} must be true or false`);
    if (c.harnesses !== undefined && !(Array.isArray(c.harnesses) && c.harnesses.every((h) => typeof h === 'string'))) throw new Error(`bad client entry ${c.id}: harnesses must be an array of ids`);
    return { id: c.id, hash: Buffer.from(c.tokenSha256, 'hex'), harnesses: c.harnesses ? new Set(c.harnesses) : null, webSearch: c.webSearch === true, events: c.events === true };
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
  // expiresAt: the runner's, once the CLI's box started; until then counted from the request (a login behind a run starts later)
  const view = (x) => ({ state: x.s.state === 'refused' ? 'starting' : x.s.state, url: x.s.url, code: x.s.code, needsCode: x.s.needsCode, startedAt: x.startedAt,
    expiresAt: x.s.expiresAt ? new Date(x.s.expiresAt).toISOString() : x.expiresAt,
    ...(x.s.error ? { error: x.s.error } : {}), ...(x.status ? { status: x.status } : {}) });
  async function startLogin(c, scoped, h) {
    const k = `${scoped}/${h}`;
    if ([...sessions.entries()].filter(([key, x]) => key !== k && key.startsWith(`${c.id}/`) && ['starting', 'waiting'].includes(x.s.state)).length >= L.logins) no(429, 'too_many_logins', `at most ${L.logins} logins waiting per client`);
    const s = hb.login(scoped, h), now = Date.now();
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
  // a run as JSON. Kept events are JSON text already (keep()), spliced in where result.events holds MARK: never parsed or serialized
  // again. Never throws (this runs in execute()'s finally, through emit): past a failure, the run without its events
  // (eventsTruncated) or, last, its id and state. U+2028 and U+2029, which JSON.stringify leaves raw and which only occur inside JSON
  // strings, are written as \u2028 and \u2029: the same JSON, and an SSE client that splits lines on them (as 0.3.0's client did) still
  // reads one data line.
  const MARK = `hb-events-${randomBytes(12).toString('hex')}`;
  const seps = (t) => t.replace(/[\u2028\u2029]/g, (ch) => (ch === '\u2028' ? '\\u2028' : '\\u2029'));
  const runJson = (r, full = true) => {
    const s = snapshot(r, full);
    try {
      const t = JSON.stringify(s), i = r.kept && s.result ? t.indexOf(`"${MARK}"`) : -1;
      return seps(i < 0 ? t : `${t.slice(0, i)}[${r.kept.list.join(',')}]${t.slice(i + MARK.length + 2)}`);
    } catch {
      try { return seps(JSON.stringify({ ...s, ...(s.result ? { result: { ...s.result, events: [], eventsTruncated: true } } : {}) })); } catch { return JSON.stringify({ id: r.id, state: r.state, error: 'the run could not be serialized' }); }
    }
  };
  // an ended run leaves the map and lets go of what it holds: its expiry timer is cleared (it would keep the run for keepMs) and the
  // large fields are dropped, so nothing that still refers to the object keeps them. Never an active run; one whose end event is
  // not sent yet (execute()'s finally) only leaves the map, and its finally lets go after the end event.
  const forget = (x) => {
    if (ACTIVE.has(x.state)) return;
    if (runs.get(x.id) === x) runs.delete(x.id);
    if (!x.final) return;
    clearTimeout(x.timer);
    Object.assign(x, { timer: null, kept: null, result: null, outputs: null, validator: null, bytes: 0 });
  };
  // the timer's closure holds only the id (made here, not inside execute(), whose closures share a context that holds the run)
  const expire = (id) => setTimeout(() => { const x = runs.get(id); if (x) forget(x); }, L.keepMs).unref();
  const emit = (r, event) => { for (const l of r.listeners) { try { l(event); } catch { /* one subscriber cannot end the run or the service */ } } };
  const set = (r, state) => { if (r.state === state || !ACTIVE.has(r.state)) return; r.state = state; if (state === 'running') r.startedAt = new Date().toISOString(); emit(r, 'state'); };
  // a path the client chose that meets another one is its 400; anything else (the run folders' tmpfs full, say) is not its fault
  const clash = (bad) => (e) => { if (['EEXIST', 'ENOTDIR', 'EISDIR'].includes(e.code)) return bad(e); throw e; };
  async function createRun(c, b) {
    if (!b || typeof b !== 'object') no(400, 'bad_request', 'a JSON object is required');
    const scoped = userOf(c, b.user), h = harnessOf(c, b.harness).id;
    if (typeof b.prompt !== 'string' || !b.prompt || b.prompt.startsWith('-') || b.prompt.includes('\0') || Buffer.byteLength(b.prompt) > L.prompt) no(400, 'bad_prompt', `prompt: a string of at most ${L.prompt} bytes, not starting with "-"`);
    if (b.model != null && (typeof b.model !== 'string' || !MODEL.test(b.model) || (Object.hasOwn(models, h) && !models[h].includes(b.model)))) no(400, 'bad_model', `model not allowed for ${h}`);
    const timeoutMs = b.timeoutMs ?? 40 * 60e3;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > L.runTimeoutMs) no(400, 'bad_timeout', `timeoutMs: 1000..${L.runTimeoutMs}`);
    // webSearch and events: off unless the client's entry allows them; false or absent is the run as before
    for (const k of ['webSearch', 'events']) if (b[k] != null && typeof b[k] !== 'boolean') no(400, 'bad_request', `${k}: true or false`);
    if (b.webSearch && !c.webSearch) no(400, 'web_search_not_allowed', 'webSearch is not allowed for this client');
    if (b.webSearch && !known.get(h).webSearch) no(400, 'web_search_unsupported', `${known.get(h).name} does not support webSearch on this service`);
    if (b.events && !c.events) no(400, 'events_not_allowed', 'events is not allowed for this client');
    const args = strings(b.args, 64, 'args'), outputs = strings(b.outputs, L.outputs, 'outputs'), readonly = strings(b.readonly, 16, 'readonly');
    // nor through its CLI options. The adapters hold the line (Codex: web_search=disabled again after the caller's args, and the last -c
    // wins; Claude Code: --disallowedTools WebSearch, and a deny beats any allow); on top, an element that names web search is refused,
    // even in a prompt-like value or a deny rule. Other options that widen the CLI are not checked (docs/service.md).
    if (!c.webSearch && args.some((a) => /web[\s_-]?search/i.test(a))) no(400, 'web_search_not_allowed', 'args may not name web search for this client');
    // a check by spelling only: TOML and JSON \u and \U escapes (always hex digits: a Windows path's \Users is none) and a --settings
    // file could spell it otherwise, so those are refused too
    if (!c.webSearch && args.some((a, i) => /\\u[0-9a-f]{4}/i.test(a) || (a === '--settings' && !jsonObject(args[i + 1])) || (a.startsWith('--settings=') && !jsonObject(a.slice(11))))) {
      no(400, 'bad_args', 'args may not carry \\u escapes or a --settings file for this client');
    }
    if (![...outputs, ...readonly].every(safePath) || new Set(outputs).size !== outputs.length) no(400, 'bad_path', 'outputs and readonly are distinct relative paths');
    if (readonly.some((p, i) => readonly.some((q, j) => i !== j && (q === p || q.startsWith(`${p}/`))))) no(400, 'bad_path', 'readonly folders may not overlap');
    let validate = null;
    if (b.validate != null) {
      const argv = strings(b.validate.argv, 64, 'validate.argv'), ms = b.validate.timeoutMs ?? 60e3;
      if (!argv.length || (b.validate.net ?? 'none') !== 'none' || !Number.isInteger(ms) || ms < 1000 || ms > L.validateMs) no(400, 'bad_validate', `validate: { argv, net: 'none', timeoutMs ≤ ${L.validateMs} }`);
      validate = { argv, ms };
    }
    const files = b.files ?? [];
    if (!Array.isArray(files) || files.reduce((n, f) => n + 1 + (Array.isArray(f?.copies) ? f.copies.length : 0), 0) > L.files) no(400, 'bad_files', `files: at most ${L.files}, including copies`);
    const mine = [...runs.values()].filter((r) => r.client === c.id);
    if (mine.filter((r) => ACTIVE.has(r.state)).length >= L.activeRuns) no(429, 'too_many_runs', `at most ${L.activeRuns} active runs per client`);
    if (mine.length >= L.keptRuns) {
      const old = mine.find((r) => !ACTIVE.has(r.state)); // the oldest ended one makes room
      if (!old) no(429, 'too_many_runs', 'too many runs');
      forget(old);
    }

    // the folder: work/ is the box's /work; readonly folders are written beside it (ro/) and bound read-only over work/<folder>
    const id = `run_${randomBytes(12).toString('base64url')}`;
    const r = {
      id, client: c.id, user: b.user, scoped, harness: h, model: b.model ?? null, state: 'queued', createdAt: new Date().toISOString(), startedAt: null, endedAt: null,
      stage: '', events: 0, result: null, validator: null, outputs: null, error: null, ac: new AbortController(), listeners: new Set(),
      kept: b.events ? { list: [], bytes: 0, mem: 0, truncated: false } : null,
    };
    // Reserve admission before the first filesystem await, including concurrent uploads still being staged.
    runs.set(id, r);
    let root, work;
    try {
      root = await mkdtemp(join(runsDir, `${id}-`));
      work = join(root, 'work');
      await mkdir(work);
      let bytes = 0;
      for (const f of files) {
        const copies = f?.copies ?? [];
        if (!f || !safePath(f.path) || (typeof f.base64 !== 'string') === (typeof f.text !== 'string') || !Array.isArray(copies) || copies.length > 8 || !copies.every(safePath)) {
          no(400, 'bad_files', 'each file is { path, base64 } or { path, text }, with copies: [paths] at most 8');
        }
        const data = typeof f.text === 'string' ? Buffer.from(f.text) : Buffer.from(f.base64, 'base64');
        for (const path of [f.path, ...copies]) {
          if ((bytes += data.length) > L.filesBytes) no(413, 'too_large', `files: at most ${L.filesBytes} bytes`);
          const ro = readonly.find((p) => path.startsWith(`${p}/`)), to = ro ? join(root, 'ro', path) : join(work, path);
          await mkdir(dirname(to), { recursive: true }).then(() => writeFile(to, data, { flag: 'wx' }))
            .catch(clash((e) => no(400, 'bad_files', `file ${path} clashes with another file or folder (${e.code})`)));
        }
      }
      for (const p of [...readonly, ...outputs.map(dirname).filter((d) => d !== '.')]) await mkdir(join(work, p), { recursive: true }).catch(clash((e) => no(400, 'bad_path', `folder ${p} clashes with a file (${e.code})`)));
      for (const p of readonly) await mkdir(join(root, 'ro', p), { recursive: true }).catch(clash((e) => no(400, 'bad_path', `folder ${p} clashes with a file (${e.code})`)));
    } catch (e) {
      runs.delete(id);
      if (root) await rmTree(root);
      if (e.code === 'ENOSPC' || e.code === 'EDQUOT') no(507, 'no_space', 'the service has no room for this run\'s files now; ask again later');
      throw e;
    }
    log(`run client=${c.id} run=${id} user=${scoped} harness=${h} queued`);
    execute(r, { root, work, prompt: b.prompt, timeoutMs, args, outputs, validate, webSearch: b.webSearch === true, roBinds: readonly.map((p) => [join(root, 'ro', p), join(BOX_DIR, p)]) })
      .catch((e) => log(`error run=${id} ${e?.name ?? 'error'}`)); // never an unhandled rejection: it would end the service
    return r;
  }
  // events: true keeps the CLI's JSON events for result.events as JSON text, the first L.eventsCount and L.eventsBytes of them (a comma
  // each). An event that does not serialize (nested past the stack), is over L.eventBytes or nests deeper than L.eventDepth is kept as
  // { type, truncated: true }: a client that parses and serializes it again must not hit its own stack limit. k.mem is what the texts
  // take in memory (two bytes a character when one is past U+00FF, plus a string's own header), for keptBytes.
  const depth = (t) => {
    let d = 0, max = 0, str = false;
    for (let i = 0; i < t.length; i++) {
      const ch = t.charCodeAt(i);
      if (str) { if (ch === 92) i++; else if (ch === 34) str = false; } else if (ch === 34) str = true;
      else if (ch === 123 || ch === 91) max = Math.max(max, ++d); else if (ch === 125 || ch === 93) d--;
    }
    return max;
  };
  const keep = (k, e) => {
    if (k.truncated || !e || typeof e !== 'object' || Array.isArray(e)) return; // objects only, as the runner passes them
    let t = null;
    try { t = JSON.stringify(e); } catch { /* too deep for this stack */ }
    if (typeof t !== 'string' || Buffer.byteLength(t) > L.eventBytes || depth(t) > L.eventDepth) t = JSON.stringify({ type: typeof e.type === 'string' ? clip(e.type, 100) : null, truncated: true });
    const size = Buffer.byteLength(t);
    if (k.list.length >= L.eventsCount || k.bytes + size + 1 > L.eventsBytes) { k.truncated = true; return; }
    k.bytes += size + 1;
    k.mem += (/[^\x00-\xff]/.test(t) ? 2 : 1) * t.length + 32;
    k.list.push(t);
  };
  async function execute(r, { root, work, prompt, timeoutMs, args, outputs, validate, webSearch, roBinds }) {
    const signal = r.ac.signal;
    let last = 0;
    try {
      const res = await hb.run(r.scoped, r.harness, {
        prompt, dir: work, boxDir: BOX_DIR, model: r.model ?? undefined, timeoutMs, args, roBinds, signal, webSearch,
        onStart: () => set(r, 'running'),
        onEvent: (e, { stage }) => {
          r.events++;
          if (r.kept) keep(r.kept, e);
          r.stage = stage || (typeof e?.type === 'string' ? clip(e.type, 40) : '');
          if (Date.now() - last >= 1000) { last = Date.now(); emit(r, 'progress'); }
        },
      });
      r.result = r.kept ? { ...res, events: MARK, eventsTruncated: r.kept.truncated } : res; // runJson puts the events in
      if (res.loggedIn !== undefined) remember(r.scoped, r.harness, res.loggedIn ? null : { installed: true, loggedIn: false, method: null, plan: null });
      // the validator in a second box, no network, over the same folder and the same read-only binds, with an empty home of its own:
      // the client chose the command, and it must not see the user's credential
      if (validate && !signal.aborted && !res.why && (res.code === 0 || res.timedOut)) {
        set(r, 'validating');
        // canceled while it waits for its slot: a cancel like any other (no error, the outputs still read)
        const v = await hb.exec(r.scoped, r.harness, validate.argv, { dir: work, boxDir: BOX_DIR, roBinds, ms: validate.ms, signal, home: join(root, 'home') })
          .catch((e) => { if (signal.aborted) return null; throw e; });
        // a box that never ran the client's command is the service's failure (as a spawn with no process is), not the validator's answer
        if (v?.why === 'the box did not start') throw new Error('the validator\'s box did not start');
        if (v) r.validator = { code: v.code, out: v.out, why: v.why };
      }
      // outputs: regular files really at work/<path>, never through a link the box made; too big or missing: null
      const real = await realpath(work);
      let total = 0;
      r.outputs = Object.create(null); // an output named __proto__ is a key like any other
      for (const p of outputs) {
        const bytes = await readOutBytes(real, p, L.output);
        if (bytes !== null && total + bytes.length <= L.outputsBytes) { total += bytes.length; r.outputs[p] = bytes.toString('base64'); } else r.outputs[p] = null;
      }
      r.bytes = Math.ceil(total / 3) * 4 + Buffer.byteLength(res.text) + Buffer.byteLength(res.stderr) + Buffer.byteLength(r.validator?.out ?? '') + (r.kept?.mem ?? 0);
      r.state = signal.aborted || res.canceled ? 'canceled' : res.code === 0 && !res.why ? 'done' : 'failed';
    } catch (e) {
      r.error = String(e.message).slice(0, 300);
      r.state = signal.aborted ? 'canceled' : 'failed';
    } finally {
      r.endedAt = new Date().toISOString();
      // a folder the box made 0555 too; one that still will not go takes room every client shares: say so
      await rmTree(root).catch((e) => log(`error run=${r.id} run folder not removed (${e.code ?? e.name})`));
      log(`run client=${r.client} run=${r.id} ${r.state}`);
      emit(r, 'end');
      r.listeners.clear();
      r.final = true;
      if (runs.get(r.id) === r) r.timer = expire(r.id); else forget(r); // forgotten before its end event
      // ended runs hold their outputs (and kept events) in memory: past keptBytes for everybody, the oldest ended runs go first
      // not counted above when the run failed past hb.run (its validator rejected, say): what it still holds
      r.bytes ??= (r.result ? Buffer.byteLength(r.result.text ?? '') + Buffer.byteLength(r.result.stderr ?? '') : 0) + (r.kept?.mem ?? 0);
      let kept = 0;
      for (const x of runs.values()) kept += x.bytes ?? 0;
      for (const x of runs.values()) { if (kept <= L.keptBytes) break; if (!ACTIVE.has(x.state)) { kept -= x.bytes ?? 0; forget(x); } }
    }
  }
  const runOf = (c, id) => { const r = runs.get(id); return r && r.client === c.id ? r : no(404, 'unknown_run', 'no such run (a restart forgets runs)'); };
  const streams = new Map(); // client -> open event streams
  function events(c, r, res) {
    if ((streams.get(c.id) ?? 0) >= L.streams) no(429, 'too_many_streams', `at most ${L.streams} event streams per client`);
    streams.set(c.id, (streams.get(c.id) ?? 0) + 1);
    res.on('close', () => streams.set(c.id, streams.get(c.id) - 1));
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
    res.flushHeaders(); // a stream the service closes early (send) is then a stream that ended, not a connection without an answer
    res.on('error', () => {}); // a subscriber gone mid-write is not the service's error
    const send = (event) => {
      const data = `event: ${event}\ndata: ${runJson(r, event === 'end')}\n\n`;
      if (owes(c, Buffer.byteLength(data))) return res.destroy(); // a subscriber that does not read: getRun has the run
      owe(c, res, data, false);
    };
    if (!ACTIVE.has(r.state)) { send('end'); return res.end(); }
    send('state');
    const ping = setInterval(() => res.write(': ping\n\n'), 15e3);
    const l = (event) => { send(event); if (event === 'end') res.end(); };
    r.listeners.add(l);
    res.on('close', () => { clearInterval(ping); r.listeners.delete(l); });
  }

  // ---- HTTP
  const json = (res, status, body) => {
    let data;
    try { data = body === undefined ? '' : JSON.stringify(body); } catch { status = 500; data = JSON.stringify({ error: { code: 'internal', message: 'internal error' } }); }
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(data) });
    res.end(data);
  };
  // answer bytes a client has not taken yet (the socket's buffer holds them): a run's answer can be tens of MiB, and a client asking
  // and never reading would hold the service's memory. One answer always goes (else a run bigger than the cap never could).
  // A write's bytes are paid back when the socket takes them (its callback) or, all that is left, when the answer closes.
  const owed = new Map(); // client -> bytes
  const pending = new WeakMap(); // answer -> { bytes: its own not yet taken, closed }
  const owes = (c, n) => (owed.get(c.id) ?? 0) > 0 && (owed.get(c.id) ?? 0) + n > L.answerBytes;
  const add = (c, n) => owed.set(c.id, (owed.get(c.id) ?? 0) + n);
  const owe = (c, res, data, end) => {
    if (res.destroyed) return; // the client is gone: Node drops the write and never calls back
    const n = Buffer.byteLength(data);
    let p = pending.get(res);
    if (!p) {
      p = { bytes: 0, closed: false };
      pending.set(res, p);
      res.once('close', () => { p.closed = true; add(c, -p.bytes); p.bytes = 0; });
    }
    p.bytes += n;
    add(c, n);
    let paid = false;
    const pay = () => { if (paid || p.closed) return; paid = true; p.bytes -= n; add(c, -n); };
    if (end) res.end(data, pay); else res.write(data, pay);
  };
  /** check: false for the answer to POST /v1/runs (the run started already; a 429 would leave the client without its id) */
  const runAnswer = (c, res, status, r, check = true) => {
    const data = runJson(r);
    if (check && owes(c, Buffer.byteLength(data))) no(429, 'too_many_answers', 'too many answer bytes this client has not read yet');
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(data) });
    owe(c, res, data, true);
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
  // a status or logout box that failed (out of time, its CLI's check broke) is the CLI's answer missing, not the service's error
  const versions = new Map(); // client -> the client versions logged for it, at most 8 (one client cannot hide another's)
  /** the client's version (none: one from before 0.5.0, which sent none), logged once per client and version; 426 under minClient */
  const clientVersion = (c, req, gettingClient) => {
    const sent = req.headers['harnessbox-client'], v = sent ?? '0.4.0';
    if (!SEMVER.test(v)) no(400, 'bad_client_version', 'harnessbox-client: x.y.z');
    const seen = versions.get(c.id) ?? versions.set(c.id, new Set()).get(c.id);
    if (!seen.has(v) && seen.size <= 8) {
      seen.add(v);
      log(seen.size > 8 ? `client ${c.id} uses more client versions (not logged)` : `client ${c.id} uses client ${sent ?? 'before 0.5.0'}`);
    }
    if (older(v, minClient) && !gettingClient) no(426, 'client_too_old', `this service (${VERSION}) needs a harnessbox client ${minClient} or later; this one is ${v}`);
  };
  const checked = (p) => p.catch((e) => { if (e instanceof Busy || e instanceof HttpError) throw e; no(503, 'status_failed', String(e.message).slice(0, 200)); });
  async function route(req, res) {
    const c = auth(req), url = URL.parse(req.url, 'http://x') ?? no(400, 'bad_request', 'bad path'), m = req.method, p = url.pathname.split('/').slice(1).map(decodeURIComponent);
    if (p[0] !== 'v1') no(404, 'not_found', 'not found');
    const gettingClient = m === 'GET' && p.length === 2 && p[1] === 'client';
    clientVersion(c, req, gettingClient);
    if (gettingClient) return json(res, 200, { version: client.version, minClient, source: client.source, signature: client.signature });
    if (m === 'GET' && p.length === 2 && p[1] === 'harnesses') return json(res, 200, { harnesses: allowed(c).map(({ id, name, version, usable, why, webSearch }) => ({ id, name, version, usable, why, webSearch: webSearch === true })) });
    if (p[1] === 'users' && p.length >= 3) {
      const scoped = userOf(c, p[2]);
      if (p.length === 3 && m === 'DELETE') {
        for (const r of runs.values()) if (r.scoped === scoped && ACTIVE.has(r.state)) r.ac.abort();
        // the logins the purge ends (the runner cancels them): one started while it waits for the locks stays, to see or cancel
        const ended = [...sessions].filter(([k]) => k.startsWith(`${scoped}/`));
        await hb.purge(scoped);
        for (const [k, x] of ended) if (sessions.get(k) === x) sessions.delete(k);
        for (const k of [...statuses.keys()]) if (k.startsWith(`${scoped}/`)) statuses.delete(k);
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
      if (p.length === 5 && m === 'GET') return json(res, 200, { harness: h, ...(await checked(status(scoped, h))) });
      if (p.length === 6 && p[5] === 'logout' && m === 'POST') {
        const s = await checked(hb.logout(scoped, h, { waitMs: 2000 }));
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
      if (p.length === 2 && m === 'POST') { const r = await createRun(c, await body(c, req)); return runAnswer(c, res, 202, r, false); }
      const r = runOf(c, p[2] ?? '');
      if (p.length === 3 && m === 'GET') return runAnswer(c, res, 200, r);
      if (p.length === 3 && m === 'DELETE') {
        r.ac.abort(); // a queued run leaves the user's lock and the slot queue at once; the run ends canceled
        return json(res, 204);
      }
      if (p.length === 4 && p[3] === 'events' && m === 'GET') return events(c, r, res);
    }
    no(404, 'not_found', 'not found');
  }
  // the timeouts below are checked every connectionsCheckingInterval (Node's default 30 s): each second, so 10 s means 10-11 s
  const server = http.createServer({ connectionsCheckingInterval: 1000 }, (req, res) => {
    res.setHeader('harnessbox-version', VERSION);
    route(req, res).catch((e) => {
      const err = e instanceof HttpError ? e : e instanceof Busy ? new HttpError(409, 'busy', 'this user\'s harness is busy (a login or a run); ask again later')
        : e instanceof URIError ? new HttpError(400, 'bad_request', 'bad path') : new HttpError(500, 'internal', 'internal error');
      if (err.status === 500) log(`error ${e.code ?? e.name}`); // never a message: it may carry a path or a value from the request
      if (res.headersSent) return res.destroy();
      if (err.status === 413) res.setHeader('connection', 'close'); // the rest of that body is not read
      json(res, err.status, { error: { code: err.code, message: err.message } });
    });
  });
  // for everybody on the socket, before any token: whoever can reach it can hold them (docs/service.md, one service per set of apps
  // that trust each other); a connection that has not sent its headers in 10 s goes
  server.maxConnections = 512;
  server.headersTimeout = 10e3;
  server.requestTimeout = 5 * 60e3;
  return { server, runs, close: () => { for (const r of runs.values()) r.ac.abort(); server.close(); server.closeAllConnections(); } };
}

/** HB_LISTEN: `host:port` or `[v6]:port` is TCP ({ host, port }); anything else ('/run/harnessbox/hb.sock', '[::1]') a socket path. */
export function listenOf(s) {
  const m = /^(?:\[([^\]]+)\]|([^/[][^:]*)):(\d+)$/.exec(s);
  return m ? { host: m[1] ?? m[2], port: Number(m[3]) } : { path: s };
}

// ---- main: configuration from the environment (docs/service.md)
async function main() {
  const env = process.env, all = [claudeCode, codex, grok];
  const intEnv = (name, { max = Number.MAX_SAFE_INTEGER, unit = '' } = {}) => {
    const v = env[name];
    if (v === undefined) return undefined;
    if (!/^[1-9][0-9]*$/.test(v) || Number(v) > max) throw new Error(`${name} must be a positive integer${unit}, at most ${max}`);
    return Number(v);
  };
  // a run's stdout + stderr together (Claude's stream-json carries every image it reads); unset: the runner's 8 MiB. A body is parsed
  // as one string: V8's longest is 2^29 - 24 characters
  const outputBytes = intEnv('HB_MAX_OUTPUT_BYTES', { unit: ' (bytes)' }), bodyBytes = intEnv('HB_MAX_BODY', { max: 2 ** 29 - 24, unit: ' (bytes)' });
  const maxJobs = intEnv('HB_MAX_JOBS', { max: 1000 }) ?? 3, maxQuick = intEnv('HB_MAX_QUICK', { max: 1000 }) ?? 4;
  const want = (env.HB_HARNESSES ?? all.map((a) => a.id).join(',')).split(',').map((s) => s.trim());
  for (const id of want) if (!all.some((a) => a.id === id)) throw new Error(`HB_HARNESSES: no harness ${JSON.stringify(id)} (${all.map((a) => a.id).join(', ')})`);
  const adapters = all.filter((a) => want.includes(a.id)), envKey = (a) => a.id.toUpperCase().replace(/-/g, '_');
  const pick = (prefix) => Object.fromEntries(adapters.flatMap((a) => (env[`${prefix}${envKey(a)}`] ? [[a.id, env[`${prefix}${envKey(a)}`]]] : [])));
  const clientsFile = await realpath(env.HB_CLIENTS ?? '/etc/harnessbox/clients.json');
  const clients = JSON.parse(await readFile(clientsFile, 'utf8')).clients;
  const runs = env.HB_RUNS ?? '/tmp/hb-runs', listen = env.HB_LISTEN ?? '/run/harnessbox/hb.sock';
  const log = (l) => console.log(`[harnessbox] ${l}`);
  // a restart forgets every run: their folders go too
  await mkdir(runs, { recursive: true, mode: 0o700 });
  for (const n of await readdir(runs)) await rmTree(join(runs, n));
  const hb = await createRunner({ homes: env.HB_HOMES ?? '/homes', adapters, bins: pick('HB_BIN_'), pins: pick('HB_PIN_'), bwrap: env.HB_BWRAP ?? 'bwrap', socat: env.HB_SOCAT ?? 'socat',
    maxJobs, maxQuick, maxOutputBytes: outputBytes, log,
    hide: /^\/(usr|etc)\//.test(clientsFile) ? [clientsFile] : [] }); // every box sees /etc and /usr: not the clients' token hashes
  const harnesses = await hb.detect();
  for (const h of harnesses) log(`${h.id} ${h.version ?? '-'} ${h.usable ? 'usable' : `not usable: ${h.why}`}`);
  const models = Object.fromEntries(Object.entries(pick('HB_MODELS_')).map(([k, v]) => [k, v.split(',').map((s) => s.trim()).filter(Boolean)]));
  const svc = createService({ hb, harnesses, clients, runs, models, limits: bodyBytes ? { body: bodyBytes } : {}, log });
  const at = listenOf(listen), tcp = !at.path;
  if (!tcp) { await mkdir(dirname(listen), { recursive: true }); await rm(listen, { force: true }); }
  await new Promise((done, fail) => { svc.server.once('error', fail); if (tcp) svc.server.listen(at.port, at.host, done); else svc.server.listen(listen, done); });
  // the socket's folder is a volume shared with the client apps only; the bearer token is the other half
  if (!tcp) await chmod(listen, 0o666);
  log(`listening on ${listen} for ${clients.length} client(s)`);
  for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => { svc.close(); void hb.close().finally(() => process.kill(process.pid, sig)); });
}
if (import.meta.main) await main();
