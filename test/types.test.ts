// Compile the public consumer API. This file is never executed and never starts a real CLI.
import { Busy, claudeCode, codex, createRunner, diskUse, grok, readOut, type Adapter, type RunResult } from 'harnessbox';

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
  onEvent: async (event) => { if (event.type === 'end') console.log(event); },
  roBinds: [['/validator', '/jobs/1/validator'] as const],
});
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
