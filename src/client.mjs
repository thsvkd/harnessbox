// A client for the harnessbox service (src/server.mjs, docs/service.md): node:http over the service's unix socket or a TCP URL. No
// dependencies; copy this file into your app. Every call resolves to the JSON body, or rejects with a HarnessboxError (status, code).
import http from 'node:http';

export class HarnessboxError extends Error {
  constructor(status, code, message) { super(message ?? code ?? `HTTP ${status}`); Object.assign(this, { status, code }); }
}

/** @param {{ socketPath?: string, url?: string, token: string }} o  socketPath (default) or url ('http://harnessbox:8740') */
export function harnessbox({ socketPath, url, token }) {
  const base = url ? new URL(url) : null;
  const request = (method, path, body, onResponse) => {
    const data = body === undefined ? null : Buffer.from(JSON.stringify(body));
    return http.request({
      ...(base ? { host: base.hostname, port: base.port } : { socketPath }), path, method,
      headers: { authorization: `Bearer ${token}`, ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}) },
    }, onResponse).end(data);
  };
  const call = (method, path, body) => new Promise((done, fail) => {
    request(method, path, body, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        let j = null;
        try { j = chunks.length ? JSON.parse(Buffer.concat(chunks)) : null; } catch { /* not JSON */ }
        if (res.statusCode >= 400) fail(new HarnessboxError(res.statusCode, j?.error?.code, j?.error?.message)); else done(j);
      });
      res.on('error', fail);
    }).on('error', fail);
  });
  const u = (user, h) => `/v1/users/${encodeURIComponent(user)}/harnesses${h ? `/${encodeURIComponent(h)}` : ''}`;
  return {
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
        if (res.statusCode !== 200) { res.resume(); return fail(new HarnessboxError(res.statusCode)); }
        let buf = '', last = null;
        res.setEncoding('utf8');
        res.on('data', (d) => {
          buf += d;
          for (let i; (i = buf.indexOf('\n\n')) >= 0;) {
            const block = buf.slice(0, i);
            buf = buf.slice(i + 2);
            const event = /^event: (.+)$/m.exec(block)?.[1], data = /^data: (.+)$/m.exec(block)?.[1];
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
        res.on('end', () => (last ? done(last) : fail(new HarnessboxError(0, 'stream_ended', 'the event stream ended before the run did'))));
        res.on('error', fail);
      }).on('error', fail);
    }),
  };
}
