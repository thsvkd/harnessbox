// A client for the harnessbox service (src/server.mjs, docs/service.md): node:http over the service's unix socket or a TCP URL. No
// dependencies; copy this file into your app. Every call resolves to the JSON body, or rejects with a HarnessboxError (status, code)
// for an answer of the service, or with the socket's own Error when there is no answer. It sends its VERSION with every request; a
// service that needs a newer client answers 426 client_too_old, and this client then takes the one the service hands out (autoUpdate).
import { createPublicKey, verify } from 'node:crypto';
import http from 'node:http';

/** This client's version: the harnessbox release its code last changed in (test/compat holds each one). */
export const VERSION = '0.5.0';
// the harnessbox maintainers' Ed25519 key (scripts/sign-client.mjs): a client the service hands out runs here only when it signed it
const KEY = createPublicKey({ key: Buffer.from('MCowBQYDK2VwAyEABN/WVfaqUz+1LC7QJLfrNzU1K0fuO5l1yo7740WoXB4=', 'base64'), format: 'der', type: 'spki' });
const SEMVER = /^\d{1,4}\.\d{1,4}\.\d{1,4}$/;
/** a is older than b (x.y.z) */
export const older = (a, b) => {
  const x = a.split('.').map(Number), y = b.split('.').map(Number);
  const i = x.findIndex((n, k) => n !== y[k]);
  return i >= 0 && x[i] < y[i];
};

// one brand for every copy: after autoUpdate the errors come from the loaded copy's class, and instanceof still holds
const BRAND = Symbol.for('harnessbox.HarnessboxError');
export class HarnessboxError extends Error {
  constructor(status, code, message) { super(message ?? code ?? `HTTP ${status}`); Object.assign(this, { status, code, [BRAND]: true }); }
  static [Symbol.hasInstance](x) { return x?.[BRAND] === true; }
}

/**
 * @param {{ socketPath?: string, url?: string, token: string, autoUpdate?: boolean }} o  socketPath ('/run/harnessbox/hb.sock') or url
 *   ('http://harnessbox:8740'): one is required. autoUpdate (default true): on a 426 client_too_old, load the client the service hands
 *   out (GET /v1/client) in memory and ask again, when the maintainers' key signed it and it is no older than this one or the
 *   service's minimum; else that call rejects with client_update_failed. Each process does this again after a restart.
 */
// per process, for every client object: the client loaded (null: this copy) and the version nothing may go back under
let loaded = null, floor = VERSION;
const fail = (m) => { throw new HarnessboxError(426, 'client_update_failed', `the service needs a newer harnessbox client; ${m}`); };
export function harnessbox(o) {
  const fresh = () => (loaded && o.autoUpdate !== false ? loaded.harnessbox({ ...o, autoUpdate: false }) : connect(o)); // false: this copy only
  let impl = fresh(), from = loaded, updating = null; // a load under way: per object, through its own service
  const update = (cur) => (updating ??= (async () => {
    const c = await cur.client();
    const source = Buffer.from(typeof c?.source === 'string' ? c.source : '');
    let signed = false;
    try { signed = verify(null, source, KEY, Buffer.from(String(c?.signature), 'base64')); } catch { /* not a signature */ }
    if (!signed) fail('the one it hands out is not signed by the harnessbox key');
    // its version from the signed text, before any of it runs: an older signed client never runs here
    const v = /^export const VERSION = '(\d{1,4}\.\d{1,4}\.\d{1,4})';$/m.exec(source.toString())?.[1], min = c.minClient;
    if (!v || typeof min !== 'string' || !SEMVER.test(min) || older(v, floor) || older(v, min)) fail(`the one it hands out (${v ?? 'no version'}) is older than this one or its minimum`);
    const mod = await import(/* @vite-ignore */ `data:text/javascript;base64,${source.toString('base64')}`);
    if (mod.VERSION !== v) fail('the one it hands out does not say its version');
    if (older(v, floor)) fail(`the one it hands out (${v}) is older than one this process loaded meanwhile`);
    loaded = mod;
    floor = v;
  })().finally(() => { updating = null; }));
  return Object.fromEntries(Object.keys(impl).map((k) => [k, async (...a) => {
    const cur = impl;
    try { return await cur[k](...a); } catch (e) {
      if (o.autoUpdate === false || e?.code !== 'client_too_old') throw e;
      if (impl === cur && from === loaded) await update(cur); // else another call or client object loaded a newer one since
      if (from !== loaded) { impl = fresh(); from = loaded; }
      return impl[k](...a); // the service refused before doing anything: asking again does it once
    }
  }]));
}

function connect({ socketPath, url, token }) {
  if (!url && !socketPath) throw new Error('harnessbox: socketPath or url is required'); // else node:http asks localhost:80, token and all
  const base = url ? new URL(url) : null;
  if (base && base.protocol !== 'http:') throw new Error(`harnessbox: the service speaks plain HTTP on a private network, not ${base.protocol}`); // never the token in clear to a port meant for TLS
  const request = (method, path, body, onResponse) => {
    const data = body === undefined ? null : Buffer.from(JSON.stringify(body));
    return http.request({
      ...(base ? { host: base.hostname.replace(/^\[|\]$/g, ''), port: base.port || 80 } : { socketPath }), path, method,
      headers: { authorization: `Bearer ${token}`, 'harnessbox-client': VERSION, ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}) },
    }, onResponse).end(data);
  };
  /** the whole answer: its JSON body, or a HarnessboxError with the service's error code */
  const answer = (res, done, fail) => {
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => {
      let j = null;
      try { j = chunks.length ? JSON.parse(Buffer.concat(chunks)) : null; } catch { /* not JSON */ }
      if (res.statusCode >= 400) fail(new HarnessboxError(res.statusCode, j?.error?.code, j?.error?.message)); else done(j);
    });
    res.on('error', fail);
  };
  const call = (method, path, body) => new Promise((done, fail) => {
    request(method, path, body, (res) => answer(res, done, fail)).on('error', fail);
  });
  const u = (user, h) => `/v1/users/${encodeURIComponent(user)}/harnesses${h ? `/${encodeURIComponent(h)}` : ''}`;
  return {
    /** the client this service hands out: { version, minClient, source, signature } */
    client: () => call('GET', '/v1/client'),
    harnesses: () => call('GET', '/v1/harnesses'),
    statuses: (user) => call('GET', u(user)),
    status: (user, h) => call('GET', u(user, h)),
    login: (user, h) => call('POST', `${u(user, h)}/login`),
    loginState: (user, h) => call('GET', `${u(user, h)}/login`),
    submitCode: (user, h, code) => call('POST', `${u(user, h)}/login/code`, { code }),
    cancelLogin: (user, h) => call('DELETE', `${u(user, h)}/login`),
    logout: (user, h) => call('POST', `${u(user, h)}/logout`),
    purge: (user) => call('DELETE', `/v1/users/${encodeURIComponent(user)}`),
    /** body: { user, harness, prompt, model?, files: [{ path, base64 | text }], readonly?, outputs?, validate?, timeoutMs?, args?, webSearch?, events? } */
    run: (body) => call('POST', '/v1/runs', body),
    getRun: (id) => call('GET', `/v1/runs/${encodeURIComponent(id)}`),
    cancelRun: (id) => call('DELETE', `/v1/runs/${encodeURIComponent(id)}`),
    /** Follow a run's events (state, progress) until it ends; resolves to the final run, outputs included. Rejects with
     *  HarnessboxError code 'bad_event' when an event is not JSON, 'stream_ended' when the stream ends first. */
    events: (id, onEvent = () => {}) => new Promise((done, fail) => {
      request('GET', `/v1/runs/${encodeURIComponent(id)}/events`, undefined, (res) => {
        if (res.statusCode !== 200) return answer(res, () => fail(new HarnessboxError(res.statusCode)), fail);
        let buf = '', last = null;
        res.setEncoding('utf8');
        res.on('data', (d) => {
          buf += d;
          for (let i; (i = buf.indexOf('\n\n')) >= 0;) {
            const block = buf.slice(0, i);
            buf = buf.slice(i + 2);
            // lines end at \n only: a regex's . and $ would also end one at U+2028 or U+2029, which JSON strings may hold raw
            let event = '', data = '';
            for (const l of block.split('\n')) {
              if (l.startsWith('event: ')) event = l.slice(7);
              else if (l.startsWith('data: ')) data = l.slice(6);
            }
            if (!event || !data) continue;
            let run;
            try { run = JSON.parse(data); } catch {
              // a broken stream ends this subscription, never the app: an exception here would be uncaught
              res.destroy();
              return fail(new HarnessboxError(0, 'bad_event', 'the event stream sent data that is not JSON'));
            }
            if (event === 'end') last = run;
            try { onEvent(event, run); } catch { /* the caller's */ }
          }
        });
        // the service ended it (a restart, or this client's unread answer bytes past their cap) or the connection broke
        const ended = () => (last ? done(last) : fail(new HarnessboxError(0, 'stream_ended', 'the event stream ended before the run did')));
        res.on('end', ended);
        res.on('error', ended);
        res.on('close', ended);
      }).on('error', fail);
    }),
  };
}
