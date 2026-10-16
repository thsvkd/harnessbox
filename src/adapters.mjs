// The harness adapters: what the runner needs to know about one agent CLI, declared as data plus small parsers. docs/adapters.md says
// how to write one; README says what was verified for each.
import { join } from 'node:path';

/**
 * @typedef {object} Adapter
 * @property {string} id  folder name under each user's home root and the key in the runner's options ([A-Za-z0-9_-])
 * @property {string} name
 * @property {string} bin  default binary (a name on PATH or a path; the runner resolves its real path)
 * @property {string[]} [globalArgs]  before every subcommand
 * @property {string[]} hosts  the only hosts its boxes may CONNECT to, port 443 (the user's browser needs none of them)
 * @property {string[]} keep  credential files kept in the home between boxes, relative to it; everything else is removed before each box
 * @property {Record<string,string[]>} [keepJsonKeys]  for a kept JSON file: the top-level keys that stay
 * @property {Record<string,string>} [seed]  files written into the home before each box (after the scrub)
 * @property {Record<string,string>} [env]  variables in every box of this harness
 * @property {boolean} [nested]  its own sandbox needs user namespaces inside a job box
 * @property {{args: string[], needs: string[], optional?: string[]}} [flags]  help text that must name these options (optional: noted in detect().has)
 * @property {{args: string[], why: string, nested?: boolean}[]} [checks]  commands that must exit 0 in a box with no network
 * @property {{kind: 'paste-code'|'device-code', args: string[], urlHosts: string[], parse(text: string): {url: string, code?: string}|null}} login
 *   parse sees the CLI's output so far (ANSI stripped, last 4 KB); the URL must be https on one of urlHosts
 * @property {{args: string[], parse(r: {code: number, out: string}): {loggedIn: boolean, method?: string|null, plan?: string|null}}} status
 * @property {string[]} logout  args
 * @property {RegExp} [expired]  a failed run's output that means the login is gone
 * @property {{command(o: {prompt: string, dir: string, has: Set<string>, extra: string[]}): {args: string[], stdin?: string},
 *   event(e: any, acc: {text: string, usage: {input: number, output: number}, reports: number, error: string, stage: string}): void,
 *   finish?(acc: object, o: {dir: string, readOut: Function}): Promise<void>}} job
 *   event sees each JSON line of stdout; reports counts usage reports (none: the usage is marked unknown)
 */

const URL_RE = /https:\/\/[^\s"'<>`]+/;
const DEVICE_CODE = /\b[A-Z0-9]{4,}-[A-Z0-9]{4,}\b/;
/** The first https URL, then a device code printed after it. */
const deviceCode = (t) => {
  const url = URL_RE.exec(t)?.[0], code = url && DEVICE_CODE.exec(t.slice(t.indexOf(url) + url.length))?.[0];
  return code ? { url, code } : null;
};
const n = (x) => (Number.isFinite(x) ? x : 0); // a usage number from the box, or 0
const EXPIRED = /Login expired|Not logged in|Please run \/login|invalid_grant|token (has )?expired|401 Unauthorized/i;

// ~/.claude.json keeps Claude Code's account record next to user-scope settings a box could plant (mcpServers, per-folder trust under
// projects): only the account keys stay. The login itself is .credentials.json.
const CLAUDE_ACCOUNT = ['oauthAccount', 'userID', 'hasCompletedOnboarding', 'lastOnboardingVersion', 'firstStartTime'];

/**
 * Claude Code. Login: `claude auth login` prints a URL and waits for the code the login page shows on stdin. Job: --restricted ignores
 * the user, project and local settings files (so their hooks too); --strict-mcp-config with no config: no MCP server;
 * --no-session-persistence keeps the session out of ~/.claude/projects; dontAsk refuses every tool use no allow rule covers (the
 * caller adds --tools/--allowedTools rules in args, as absolute `//path` rules: a `./` rule moves with a Bash `cd`).
 * @type {Adapter}
 */
export const claudeCode = {
  id: 'claude-code', name: 'Claude Code', bin: 'claude',
  hosts: ['api.anthropic.com', 'platform.claude.com'],
  keep: ['.claude/.credentials.json', '.claude.json'], keepJsonKeys: { '.claude.json': CLAUDE_ACCOUNT },
  env: { CLAUDE_CODE_SHELL: '/bin/bash', DISABLE_AUTOUPDATER: '1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1' },
  flags: { args: ['--help'], needs: ['--print', '--output-format', 'stream-json', '--verbose', '--permission-mode', 'dontAsk', '--disallowedTools', '--strict-mcp-config', '--restricted', '--no-session-persistence'], optional: ['--max-turns'] },
  login: { kind: 'paste-code', args: ['auth', 'login'], urlHosts: ['claude.com', 'claude.ai'], parse: (t) => { const url = URL_RE.exec(t)?.[0]; return url ? { url } : null; } },
  status: {
    args: ['auth', 'status', '--json'],
    parse: ({ out }) => {
      let s = {};
      try { s = JSON.parse(out.slice(out.indexOf('{'))); } catch { /* no JSON */ }
      const ok = s.loggedIn === true;
      return { loggedIn: ok, method: ok ? s.authMethod ?? null : null, plan: ok ? s.subscriptionType ?? null : null };
    },
  },
  logout: ['auth', 'logout'],
  expired: EXPIRED,
  job: {
    command: ({ prompt, extra }) => ({ args: ['-p', prompt, '--output-format', 'stream-json', '--verbose', '--permission-mode', 'dontAsk', '--strict-mcp-config', '--restricted',
      '--no-session-persistence', '--disallowedTools', 'WebFetch', 'WebSearch', 'mcp__*', ...extra] }),
    // every result event counts (with a background Agent a run ends a turn and the Agent's notice opens another, each with a result of
    // its own usage); input counts the cache too; the last result is the model's last message; one marked as an error says why
    event: (e, acc) => {
      if (e?.type !== 'result') return;
      const u = e.usage ?? {};
      acc.reports++;
      acc.usage.input += n(u.input_tokens) + n(u.cache_creation_input_tokens) + n(u.cache_read_input_tokens);
      acc.usage.output += n(u.output_tokens);
      if (typeof e.result === 'string') acc.text = e.result;
      if (e.is_error === true && typeof e.result === 'string') acc.error = e.result.replace(/\s+/g, ' ').trim().slice(0, 200);
    },
  },
};

const CODEX_LAST = '.codex-last-message.txt';
const CODEX_STAGE = { command_execution: 'command', file_change: 'file change', agent_message: 'message', reasoning: 'reasoning', todo_list: 'todo', collab_tool_call: 'agent' };
/**
 * Codex. Credentials always in ~/.codex/auth.json, never a keyring (the box has no D-Bus). Login: `codex login --device-auth` prints
 * a URL and a one-time code, then polls until the user confirms (the user or workspace admin must allow device-code login). Job:
 * the user's config.toml and execpolicy rules are not read; the sandbox's network, MCP servers, apps, remote plugins, web search and
 * the user's skills list are off; workspace-write may not write /tmp or $TMPDIR. Its own sandbox needs user namespaces: nested.
 * @type {Adapter}
 */
export const codex = {
  id: 'codex', name: 'Codex', bin: 'codex', globalArgs: ['-c', 'cli_auth_credentials_store="file"'],
  hosts: ['auth.openai.com', 'chatgpt.com'],
  keep: ['.codex/auth.json'],
  nested: true,
  flags: { args: ['exec', '--help'], needs: ['--skip-git-repo-check', '--sandbox', '--ephemeral', '--json', '--output-last-message', '--ignore-user-config', '--disable'], optional: ['--ignore-rules'] },
  checks: [{ args: ['sandbox', '--', 'true'], nested: true, why: 'Codex\'s own sandbox does not start in a box (every command the model runs would fail)' }],
  login: { kind: 'device-code', args: ['login', '--device-auth'], urlHosts: ['auth.openai.com'], parse: deviceCode },
  status: { args: ['login', 'status'], parse: ({ code, out }) => ({ loggedIn: code === 0, method: code !== 0 ? null : /ChatGPT/.test(out) ? 'chatgpt' : /API key/i.test(out) ? 'api-key' : null, plan: null }) },
  logout: ['logout'],
  expired: EXPIRED,
  job: {
    command: ({ prompt, dir, has, extra }) => ({
      args: ['exec', '--skip-git-repo-check', '--ignore-user-config', ...(has.has('--ignore-rules') ? ['--ignore-rules'] : []), '-C', dir, '-s', 'workspace-write',
        '-c', 'approval_policy=never', '-c', 'sandbox_workspace_write.network_access=false',
        '-c', 'sandbox_workspace_write.exclude_slash_tmp=true', '-c', 'sandbox_workspace_write.exclude_tmpdir_env_var=true', '-c', 'mcp_servers={}',
        '-c', 'features.apps=false', '-c', 'features.plugins=false', '-c', 'features.remote_plugin=false', '-c', 'web_search=disabled', '-c', 'skills.include_instructions=false',
        '--disable', 'plugins', '--disable', 'apps', '--ephemeral', '--json', '-o', join(dir, CODEX_LAST), ...extra, '-'],
      stdin: prompt,
    }),
    event: (e, acc) => {
      if (e.item?.type) acc.stage = CODEX_STAGE[e.item.type] ?? String(e.item.type).slice(0, 40);
      if (e.type === 'turn.completed' && e.usage) { acc.reports++; acc.usage.input += n(e.usage.input_tokens); acc.usage.output += n(e.usage.output_tokens); }
      if (e.type === 'error' && typeof e.message === 'string') acc.error = e.message.slice(0, 200);
    },
    // the last message, from the file -o wrote in the job folder (readOut: never through a link the box made)
    finish: async (acc, { dir, readOut }) => { acc.text = (await readOut(dir, CODEX_LAST)) ?? acc.text; },
  },
};

// $GROK_HOME/config.toml (GROK_HOME is unset: ~/.grok), written before each box (docs/user-guide/05-configuration.md and
// 26-config-reference.md of 1.0.52): no reading of Claude Code or Cursor skills, rules, agents, MCP servers or hooks from the home or
// the job folder, no update check, no telemetry or trace upload, no memory. Project config in the job folder needs folder trust,
// which headless runs only get with --trust (never passed).
const off = (keys) => keys.map((k) => `${k} = false`).join('\n');
const GROK_CONFIG = `[cli]
auto_update = false

[features]
telemetry = false

[telemetry]
trace_upload = false

[memory]
enabled = false

[compat.claude]
${off(['skills', 'rules', 'agents', 'mcps', 'hooks', 'sessions'])}

[compat.cursor]
${off(['skills', 'rules', 'agents', 'mcps', 'hooks', 'sessions'])}

[compat.codex]
${off(['sessions'])}
`;
/**
 * Grok (the official xAI CLI, `curl -fsSL https://x.ai/cli/install.sh | bash -s <version>`). Credentials in ~/.grok/auth.json, no
 * keyring. Login: `grok login --device-auth` prints (on stderr) an accounts.x.ai URL and a one-time code, then polls auth.x.ai until
 * the user confirms. No status command: `grok models` says "You are not authenticated." when there is no login. Job: headless
 * `-p`, streaming-json; web search and fetch off; its own sandbox stays off (no nested user namespace).
 * @type {Adapter}
 */
export const grok = {
  id: 'grok', name: 'Grok', bin: 'grok',
  hosts: ['auth.x.ai', 'cli-chat-proxy.grok.com', 'api.x.ai'],
  keep: ['.grok/auth.json'],
  seed: { '.grok/config.toml': GROK_CONFIG },
  env: { GROK_DISABLE_AUTOUPDATER: '1', GROK_TELEMETRY_ENABLED: '0', DISABLE_TELEMETRY: '1', GROK_MEMORY: '0' },
  flags: { args: ['--help'], needs: ['--single', '--output-format', 'streaming-json', '--permission-mode', '--disallowed-tools', '--disable-web-search'] },
  login: { kind: 'device-code', args: ['login', '--device-auth'], urlHosts: ['accounts.x.ai'], parse: deviceCode },
  status: { args: ['models'], parse: ({ code, out }) => ({ loggedIn: code === 0 && !/not authenticated/i.test(out), method: null, plan: null }) },
  logout: ['logout'],
  expired: /Not signed in|not authenticated|invalid_grant|token (has )?expired|401 Unauthorized/i,
  job: {
    command: ({ prompt, dir, extra }) => ({ args: ['-p', prompt, '--output-format', 'streaming-json', '--cwd', dir, '--disable-web-search', ...extra] }),
    // text chunks since the last tool call are the last message; end carries the totals (input_tokens is uncached only)
    event: (e, acc) => {
      if (e.type === 'tool_call') acc.last = '';
      if (e.type === 'text' && typeof e.data === 'string') { acc.last = (acc.last ?? '') + e.data; acc.text = acc.last; }
      if ((e.type === 'end' || e.type === 'error') && e.usage) {
        const u = e.usage;
        acc.reports++;
        acc.usage.input += n(u.input_tokens) + n(u.cache_read_input_tokens) + n(u.cache_creation_input_tokens);
        acc.usage.output += n(u.output_tokens);
      }
      if (e.type === 'error' && typeof e.message === 'string') acc.error = e.message.replace(/\s+/g, ' ').trim().slice(0, 200);
    },
  },
};
