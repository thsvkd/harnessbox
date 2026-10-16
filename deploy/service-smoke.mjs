#!/usr/bin/env node
// Smoke test of a running service through its API, as a client app sees it: the harness list, a throwaway user's logged-out status,
// (HB_LOGIN_START=1) each login started far enough to see its URL and then canceled, one run per harness that must fail as logged
// out, then the user purged. It never logs in.
//
//   HB_SOCKET=/run/harnessbox/hb.sock HB_TOKEN=... node deploy/service-smoke.mjs     (or HB_URL=http://harnessbox:8740)
import { harnessbox } from '../src/client.mjs';

const env = process.env, user = `hbprobe-${Date.now().toString(36)}`;
const hb = harnessbox({ socketPath: env.HB_SOCKET ?? '/run/harnessbox/hb.sock', url: env.HB_URL, token: env.HB_TOKEN });
const results = [];
const check = (name, ok, ev = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${ev ? `\n    ${ev}` : ''}`); };
try {
  const list = (await hb.harnesses()).harnesses;
  for (const h of list) check(`${h.name}: ${h.usable ? `usable, ${h.version}` : `not usable (${h.why})`}`, h.usable);
  const usable = list.filter((h) => h.usable);
  const st = (await hb.statuses(user)).harnesses;
  for (const s of st) check(`${s.harness}: a new user is logged out`, s.loggedIn === false, JSON.stringify(s));
  if (env.HB_LOGIN_START === '1') {
    for (const h of usable) {
      const s = await hb.login(user, h.id);
      await hb.cancelLogin(user, h.id);
      const u = s.url && URL.parse(s.url);
      check(`${h.name}: login starts with a URL (then canceled)`, s.state === 'waiting' && u, u ? `${u.host}${u.pathname} needsCode=${s.needsCode} code=${s.code ? s.code.replace(/[A-Z]/g, 'A').replace(/\d/g, '9') : 'none'}` : JSON.stringify({ state: s.state, error: s.error }));
    }
  }
  for (const h of usable) {
    // Codex without a login keeps retrying api.openai.com (denied) until the time limit instead of failing
    const r = await hb.events((await hb.run({ user, harness: h.id, prompt: 'Say hi.', files: [{ path: 'note.txt', text: 'hi' }], outputs: ['note.txt'], timeoutMs: 30e3 })).id);
    check(`${h.name}: a run without a login fails (logged out, or out of time)`, r.state === 'failed' && (r.result?.loggedIn === false || r.result?.timedOut) && r.outputs['note.txt'] === Buffer.from('hi').toString('base64'),
      JSON.stringify({ state: r.state, code: r.result?.code, loggedIn: r.result?.loggedIn, timedOut: r.result?.timedOut, error: r.result?.error || r.error }));
  }
} catch (e) {
  check('smoke ran to the end', false, e.stack);
} finally {
  await hb.purge(user).catch(() => {});
  console.log(`\nSUMMARY ${results.filter(Boolean).length}/${results.length} pass`);
  process.exitCode = results.every(Boolean) ? 0 : 1;
}
