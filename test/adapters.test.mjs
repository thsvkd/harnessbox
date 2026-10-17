// The adapters' job commands as data, without a box: the hardened arguments of a default run are exactly the 0.2.0 ones, and
// webSearch changes only the search switch (Claude Code: WebSearch out of the deny list and into an allow rule; Codex: web_search=live).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { claudeCode, codex, grok } from '../src/index.mjs';

const P = 'Read /work/request.md.', DIR = '/work', EXTRA = ['--model', 'm', '--extra-flag'], HAS = new Set(['--ignore-rules']);
const CLAUDE_020 = ['-p', P, '--output-format', 'stream-json', '--verbose', '--permission-mode', 'dontAsk', '--strict-mcp-config', '--restricted',
  '--no-session-persistence', '--disallowedTools', 'WebFetch', 'WebSearch', 'mcp__*', ...EXTRA];
const CODEX_020 = ['exec', '--skip-git-repo-check', '--ignore-user-config', '--ignore-rules', '-C', DIR, '-s', 'workspace-write',
  '-c', 'approval_policy=never', '-c', 'sandbox_workspace_write.network_access=false',
  '-c', 'sandbox_workspace_write.exclude_slash_tmp=true', '-c', 'sandbox_workspace_write.exclude_tmpdir_env_var=true', '-c', 'mcp_servers={}',
  '-c', 'features.apps=false', '-c', 'features.plugins=false', '-c', 'features.remote_plugin=false', '-c', 'web_search=disabled', '-c', 'skills.include_instructions=false',
  '--disable', 'plugins', '--disable', 'apps', '--ephemeral', '--json', '-o', join(DIR, '.codex-last-message.txt'), ...EXTRA, '-'];
const GROK_020 = ['-p', P, '--output-format', 'streaming-json', '--cwd', DIR, '--disable-web-search', ...EXTRA];
const command = (a, more = {}) => a.job.command({ prompt: P, dir: DIR, has: HAS, extra: EXTRA, ...more });

test('adapters: a run without webSearch has exactly the 0.2.0 arguments', () => {
  for (const more of [{}, { webSearch: false }]) {
    assert.deepEqual(command(claudeCode, more), { args: CLAUDE_020 });
    assert.deepEqual(command(codex, more), { args: CODEX_020, stdin: P });
    assert.deepEqual(command(grok, more), { args: GROK_020 });
  }
});

test('adapters: webSearch lets only WebSearch through for Claude Code and turns Codex\'s web_search live; Grok has none', () => {
  assert.equal(claudeCode.webSearch, true);
  assert.equal(codex.webSearch, true);
  assert.equal(grok.webSearch, undefined, 'the runner refuses webSearch for it');

  const c = command(claudeCode, { webSearch: true }).args;
  const denied = c.slice(c.indexOf('--disallowedTools') + 1, c.indexOf('--allowedTools'));
  assert.deepEqual(denied, ['WebFetch', 'mcp__*'], 'WebFetch and every MCP tool stay denied');
  assert.deepEqual(c.slice(c.indexOf('--allowedTools'), c.indexOf('--allowedTools') + 2), ['--allowedTools', 'WebSearch']);
  assert.equal(c.filter((x) => x === 'WebSearch').length, 1, 'WebSearch is not denied anywhere');
  for (const f of ['--permission-mode', 'dontAsk', '--restricted', '--strict-mcp-config', '--no-session-persistence']) assert.ok(c.includes(f), f);
  assert.deepEqual(c.slice(-EXTRA.length), EXTRA, 'the caller\'s options still come last');
  assert.deepEqual(c.filter((x) => !['WebSearch', '--allowedTools'].includes(x)), CLAUDE_020.filter((x) => x !== 'WebSearch'), 'nothing else changed');

  const x = command(codex, { webSearch: true });
  assert.ok(x.args.includes('web_search=live') && !x.args.includes('web_search=disabled'));
  assert.deepEqual(x.args, CODEX_020.map((a) => (a === 'web_search=disabled' ? 'web_search=live' : a)), 'the value is replaced in place, nothing else changed');
  assert.ok(x.args.includes('sandbox_workspace_write.network_access=false'), 'the sandbox keeps its network off');
});
