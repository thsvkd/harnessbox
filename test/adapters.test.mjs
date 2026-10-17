// The adapters' job commands as data, without a box: the hardened arguments of a default run are the 0.2.0 ones (Claude Code's in
// another order, so that no option that takes many values comes right before the caller's; Codex's with web_search=disabled once more
// after the caller's), and webSearch changes only the search switch (Claude Code: WebSearch out of the deny list and into an allow
// rule; Codex: web_search=live, and no second one).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { claudeCode, codex, grok } from '../src/index.mjs';

const P = 'Read /work/request.md.', DIR = '/work', EXTRA = ['--model', 'm', '--extra-flag'], HAS = new Set(['--ignore-rules']);
const CLAUDE_020 = ['-p', P, '--output-format', 'stream-json', '--verbose', '--permission-mode', 'dontAsk', '--strict-mcp-config', '--restricted',
  '--no-session-persistence', '--disallowedTools', 'WebFetch', 'WebSearch', 'mcp__*', ...EXTRA];
const CLAUDE = ['-p', P, '--output-format', 'stream-json', '--verbose', '--permission-mode', 'dontAsk', '--disallowedTools', 'WebFetch', 'WebSearch', 'mcp__*',
  '--strict-mcp-config', '--restricted', '--no-session-persistence', ...EXTRA];
const CLAUDE_SEARCH = ['-p', P, '--output-format', 'stream-json', '--verbose', '--permission-mode', 'dontAsk', '--allowedTools', 'WebSearch', '--disallowedTools', 'WebFetch', 'mcp__*',
  '--strict-mcp-config', '--restricted', '--no-session-persistence', ...EXTRA];
const CODEX_020 = ['exec', '--skip-git-repo-check', '--ignore-user-config', '--ignore-rules', '-C', DIR, '-s', 'workspace-write',
  '-c', 'approval_policy=never', '-c', 'sandbox_workspace_write.network_access=false',
  '-c', 'sandbox_workspace_write.exclude_slash_tmp=true', '-c', 'sandbox_workspace_write.exclude_tmpdir_env_var=true', '-c', 'mcp_servers={}',
  '-c', 'features.apps=false', '-c', 'features.plugins=false', '-c', 'features.remote_plugin=false', '-c', 'web_search=disabled', '-c', 'skills.include_instructions=false',
  '--disable', 'plugins', '--disable', 'apps', '--ephemeral', '--json', '-o', join(DIR, '.codex-last-message.txt'), ...EXTRA, '-'];
const CODEX = [...CODEX_020.slice(0, -1), '-c', 'web_search=disabled', '-'];
const GROK_020 = ['-p', P, '--output-format', 'streaming-json', '--cwd', DIR, '--disable-web-search', ...EXTRA];
const command = (a, more = {}) => a.job.command({ prompt: P, dir: DIR, has: HAS, extra: EXTRA, ...more });

test('adapters: a run without webSearch has the 0.2.0 arguments (Claude Code\'s reordered; Codex\'s web_search=disabled again last)', () => {
  for (const more of [{}, { webSearch: false }]) {
    assert.deepEqual(command(claudeCode, more), { args: CLAUDE });
    assert.deepEqual([...CLAUDE].sort(), [...CLAUDE_020].sort(), 'the same elements as 0.2.0');
    assert.deepEqual(command(codex, more), { args: CODEX, stdin: P });
    assert.deepEqual(command(grok, more), { args: GROK_020 });
  }
});

test('adapters: webSearch lets only WebSearch through for Claude Code and turns Codex\'s web_search live; Grok has none', () => {
  assert.equal(claudeCode.webSearch, true);
  assert.equal(codex.webSearch, true);
  assert.equal(grok.webSearch, undefined, 'the runner refuses webSearch for it');

  const c = command(claudeCode, { webSearch: true }).args;
  assert.deepEqual(c, CLAUDE_SEARCH);
  const denied = c.slice(c.indexOf('--disallowedTools') + 1, c.indexOf('--strict-mcp-config'));
  assert.deepEqual(denied, ['WebFetch', 'mcp__*'], 'WebFetch and every MCP tool stay denied');
  assert.deepEqual(c.slice(c.indexOf('--allowedTools'), c.indexOf('--allowedTools') + 3), ['--allowedTools', 'WebSearch', '--disallowedTools']);
  assert.equal(c.filter((x) => x === 'WebSearch').length, 1, 'WebSearch is not denied anywhere');
  for (const f of ['--permission-mode', 'dontAsk', '--restricted', '--strict-mcp-config', '--no-session-persistence']) assert.ok(c.includes(f), f);
  assert.deepEqual(c.slice(-EXTRA.length), EXTRA, 'the caller\'s options still come last');
  assert.deepEqual(c.filter((x) => !['WebSearch', '--allowedTools'].includes(x)), CLAUDE.filter((x) => x !== 'WebSearch'), 'nothing else changed');

  const x = command(codex, { webSearch: true });
  assert.ok(x.args.includes('web_search=live') && !x.args.includes('web_search=disabled'));
  assert.deepEqual(x.args, CODEX_020.map((a) => (a === 'web_search=disabled' ? 'web_search=live' : a)), 'the value is replaced in place, nothing else changed');
  assert.ok(x.args.includes('sandbox_workspace_write.network_access=false'), 'the sandbox keeps its network off');
});

// --allowedTools and --disallowedTools take every value up to the next option (Claude Code 2.1.300 checked against a mock API: with the
// caller's args right after them, a leading Read was a deny rule without webSearch and an allow rule with it)
test('adapters: Claude Code\'s caller args never follow an option that takes many values, with webSearch or without', () => {
  const MANY = ['--allowedTools', '--disallowedTools', '--tools', '--add-dir', '--betas', '--mcp-config', '--plugin-dir'];
  for (const extra of [['Read', 'Bash', '--allowedTools', 'Read(//work/**)'], ['Read'], []]) {
    const argv = {};
    for (const webSearch of [false, true]) {
      const a = claudeCode.job.command({ prompt: P, dir: DIR, has: HAS, extra, webSearch }).args, own = a.slice(0, a.length - extra.length);
      assert.deepEqual(a.slice(own.length), extra);
      assert.deepEqual(own.slice(-3), ['--strict-mcp-config', '--restricted', '--no-session-persistence'], 'three flags without a value end the adapter\'s part');
      assert.ok(own.findLastIndex((x) => MANY.includes(x)) < own.length - 3, `${webSearch}: no many-valued option runs into the caller's args`);
      argv[webSearch] = a;
    }
    // the same caller args land after the same element either way: only the search switch differs
    assert.equal(argv.false.length + 1, argv.true.length);
    assert.deepEqual(argv.false.slice(-extra.length - 3), argv.true.slice(-extra.length - 3));
  }
});

// Codex takes the last -c for a key (0.162.1 checked against a mock API: a caller's -c web_search=live, --config=web_search=live,
// -cweb_search=live or ' web_search = "live" ' put the web_search tool in the request before, and none does with this argv)
test('adapters: without webSearch, Codex\'s web_search=disabled comes after every caller arg, right before the prompt marker', () => {
  for (const extra of [['-c', 'web_search=live'], ['--config=web_search=live'], ['-cweb_search=live'], ['-c', ' web_search = "live" '], []]) {
    const a = codex.job.command({ prompt: P, dir: DIR, has: HAS, extra, webSearch: false }).args;
    assert.deepEqual(a.slice(-3), ['-c', 'web_search=disabled', '-'], JSON.stringify(extra));
    assert.deepEqual(a.slice(-3 - extra.length, -3), extra);
    const w = codex.job.command({ prompt: P, dir: DIR, has: HAS, extra, webSearch: true }).args;
    assert.deepEqual(w.slice(-1 - extra.length), [...extra, '-'], 'with webSearch the caller\'s args are last, as before');
    assert.ok(!w.includes('web_search=disabled'));
  }
});

const acc = () => ({ text: '', usage: { input: 0, output: 0 }, reports: 0, error: '', stage: '' });
test('adapters: an item type that is an Object.prototype key is a plain stage, and box text is cut on a code point boundary', async () => {
  const { clip } = await import('../src/adapters.mjs');
  for (const t of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf']) {
    const a = acc();
    codex.job.event({ type: 'item.started', item: { type: t } }, a);
    assert.equal(a.stage, t, t);
  }
  const a = acc();
  codex.job.event({ type: 'item.started', item: { type: 'command_execution' } }, a);
  assert.equal(a.stage, 'command');
  codex.job.event({ type: 'item.started', item: { type: `${'S'.repeat(39)}\u{1F600}` } }, a);
  assert.equal(a.stage, 'S'.repeat(39));
  codex.job.event({ type: 'error', message: `${'e'.repeat(199)}\u{1F600}` }, a);
  assert.equal(a.error, 'e'.repeat(199));
  const c = acc();
  claudeCode.job.event({ type: 'result', is_error: true, result: `${'r'.repeat(199)}\u{1F600}`, usage: {} }, c);
  assert.equal(c.error, 'r'.repeat(199));
  const g = acc();
  grok.job.event({ type: 'error', message: `${'g'.repeat(199)}\u{1F600}` }, g);
  assert.equal(g.error, 'g'.repeat(199));
  assert.deepEqual([clip('ab\u{1F600}', 3), clip('ab\u{1F600}', 4), clip('ab\u{1F600}c', 4), clip('abc', 2), clip('a\ud800', 5)], ['ab', 'ab\u{1F600}', 'ab\u{1F600}', 'ab', 'a\ud800'],
    'only a pair the cut splits loses its half; text that already ends in a lone half is not the cut\'s');
});
