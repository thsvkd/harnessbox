// Compile the public consumer API. This file is never executed and never starts a real CLI.
import { Busy, claudeCode, codex, createRunner, diskUse, grok, readOut, type Adapter, type RunResult } from 'harnessbox';
import { harnessbox, HarnessboxError, type Run } from 'harnessbox/client';

const custom: Adapter = {
  ...grok,
  id: 'custom',
  job: {
    command: ({ prompt, extra }) => ({ args: ['run', ...extra], stdin: prompt }),
    event: (e, acc) => { if (typeof e.text === 'string') acc.text = e.text; },
    finish: async (acc, { dir, readOut }) => { acc.text = await readOut(dir, 'result.txt') ?? ''; },
  },
};
const runner = await createRunner({ homes: '/homes', adapters: [claudeCode, codex, custom], maxOutputBytes: 1024, log: async (line) => { console.log(line); } });
for (const row of await runner.detect()) row.has.has('--ignore-rules');
const login = runner.login('alice', 'codex');
login.cancel();
const waiting = await login.waiting;
const url: string = waiting.url;
void url;
const result: RunResult = await runner.run('alice', 'custom', {
  prompt: 'hello', dir: '/jobs/1', signal: new AbortController().signal,
  onEvent: async (event, { stage }) => { if (event.type === 'end') console.log(event, stage); },
  roBinds: [['/validator', '/jobs/1/validator'] as const],
  boxDir: '/work', model: 'sonnet', onStart: () => {}, webSearch: true,
});
const searches: boolean = (await runner.detect())[0].webSearch;
void searches;
await runner.exec('alice/u1', 'custom', ['true'], { dir: '/jobs/1', boxDir: '/work', home: '/tmp/empty', signal: new AbortController().signal });
const hb = harnessbox({ socketPath: '/run/harnessbox/hb.sock', token: 't' });
const started: Run = await hb.run({ user: 'u1', harness: 'codex', prompt: 'x', files: [{ path: 'a.jpg', base64: '', copies: ['out/a.jpg'] }], outputs: ['out/x'], validate: { argv: ['true'] } });
const ended: Run = await hb.events(started.id, (event, run) => { if (event === 'progress') console.log(run.stage); });
const draft: string | null | undefined = ended.outputs?.['out/x'];
void draft;
const searched: Run = await hb.run({ user: 'u1', harness: 'codex', prompt: 'x', webSearch: true, events: true });
const kept: Record<string, any>[] | undefined = searched.result?.events;
const cut: boolean | undefined = searched.result?.eventsTruncated;
void kept; void cut;
// @ts-expect-error events is true or false
hb.run({ user: 'u1', harness: 'codex', prompt: 'x', events: 'all' });
const hbError: Error = new HarnessboxError(409, 'busy');
void hbError;
// @ts-expect-error validators never get a network
hb.run({ user: 'u1', harness: 'codex', prompt: 'x', validate: { argv: ['true'], net: 'proxy' } });
const count: number = result.usage.input;
void count;
await runner.exec('alice', 'custom', ['true'], { net: 'none' });
await runner.status('alice', 'custom');
await runner.logout('alice', 'custom');
await runner.purge('alice');
await runner.close();
await readOut('/jobs/1', 'out/result.txt');
await diskUse(['/jobs/1']);
const error: Error = new Busy('retry');
void error;
// @ts-expect-error prompt is required
runner.run('alice', 'custom', { dir: '/jobs/1' });
// @ts-expect-error resource limits are numeric
createRunner({ homes: '/homes', adapters: [], maxOutputBytes: 'unlimited' });
// @ts-expect-error only none and proxy networking are supported
runner.exec('alice', 'custom', ['true'], { net: 'host' });
