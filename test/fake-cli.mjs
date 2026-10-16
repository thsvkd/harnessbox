// A stand-in for the `claude`, `codex` and `grok` CLIs in runner.test.mjs, run inside the runner's real bubblewrap boxes. No network
// (but the box's proxy when asked), no model, no real login.
// Probes: --version, the help texts, `codex sandbox` (needs a user namespace of its own, like the real one; FAKE_SANDBOX=fail breaks it).
// FAKE_HELP=old: a Claude Code without --restricted.
// Login: logged in iff the real credential file exists (~/.claude/.credentials.json, ~/.codex/auth.json, ~/.grok/auth.json).
// `claude auth login` prints the URL (FAKE_LOGIN_URL overrides it) and waits for the code on stdin (good-code logs in); `codex login
// --device-auth` and `grok login --device-auth` print a URL and a one-time code (grok: on stderr, with ANSI) and log in after
// FAKE_DEVICE_MS. Status: `claude auth status --json`, `codex login status`, `grok models`; logout removes the file.
// Job: writes seen.json into its folder (argv, stdin, environment names, home listing, whether it may make a user namespace, which
// FAKE_PEEK paths it can see), then does what the prompt's `FAKE_MODE=<mode>` says: ok (default: events with usage and a last
// message, the way the real CLI prints them), fail (exit 3), expired (Claude's "Login expired" result), hang, forkbomb (FAKE_PROCS
// sleeping children), plant (shell and settings files in the home, a credential file replaced by a link), egress (CONNECT
// example.com:443 through the box's proxy), symlink (codex: the last-message file is a link to FAKE_TARGET), junk (JSON lines that
// are not objects and a result with non-numeric usage before the usual events), rva (review-automation's draft job: out/draft.json,
// draft.md, handoff.md, a try at rewriting skill/validate.sh, out/evil.json linked to the credential, a 50000-byte out/big.txt). FAKE_LOGIN_NOURL: `claude auth login` exits 0 at once.
import { spawn, spawnSync } from 'node:child_process';
import { accessSync, chmodSync, existsSync, mkdirSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { once } from 'node:events';
import net from 'node:net';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';

const CRED = { claude: '.claude/.credentials.json', codex: '.codex/auth.json', grok: '.grok/auth.json' };
const VERSION = { claude: '2.1.300 (Claude Code)', codex: 'codex-cli 0.162.1', grok: 'grok 1.0.52 (0920c8169e27)' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const connect = (host) => new Promise((done) => {
  const s = net.connect(3128, '127.0.0.1', () => s.write(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}:443\r\n\r\n`));
  let got = '';
  s.on('data', (d) => { got += d; s.destroy(); });
  s.on('error', (e) => done(`error ${e.code}`));
  s.on('close', () => done(got.split('\r\n')[0]));
});

export async function main(kind) {
  const args = process.argv.slice(2);
  while (args[0] === '-c') args.splice(0, 2); // codex's global -c (cli_auth_credentials_store)
  if (args[0] === '--version') return console.log(VERSION[kind]);
  if (kind === 'claude' && args[0] === '--help') return console.log(`-p, --print --output-format (choices: "text", "json", "stream-json") --verbose --permission-mode (choices: "dontAsk") --tools --allowedTools --disallowedTools --strict-mcp-config${process.env.FAKE_HELP === 'old' ? '' : ' --restricted'} --no-session-persistence --max-turns`);
  if (kind === 'codex' && args[0] === 'exec' && args[1] === '--help') return console.log('--skip-git-repo-check -s, --sandbox --ephemeral --ignore-user-config --ignore-rules --json -o, --output-last-message --enable --disable');
  if (kind === 'grok' && args[0] === '--help') return console.log('-p, --single <PROMPT> --output-format <plain|json|streaming-json> --cwd --permission-mode --disallowed-tools --disable-web-search --max-turns');
  const creds = join(homedir(), CRED[kind]), loggedIn = () => existsSync(creds);
  const logIn = () => { mkdirSync(dirname(creds), { recursive: true }); writeFileSync(creds, '{"fake":true}'); };
  const device = async (url, code, out) => {
    out(url, code);
    await sleep(Number(process.env.FAKE_DEVICE_MS ?? 300));
    logIn();
  };

  if (kind === 'claude' && args[0] === 'auth') {
    if (args[1] === 'status') {
      if (process.env.FAKE_STATUS_MARKER && loggedIn()) {
        writeFileSync(process.env.FAKE_STATUS_MARKER, 'verifying');
        await sleep(2000);
      }
      console.log(JSON.stringify(loggedIn() ? { loggedIn: true, authMethod: 'claude.ai', apiProvider: 'firstParty', subscriptionType: 'max' } : { loggedIn: false, authMethod: 'none' }, null, 2));
      return process.exit(loggedIn() ? 0 : 1);
    }
    if (args[1] === 'logout') { rmSync(creds, { force: true }); return console.log('Successfully logged out from your Anthropic account.'); }
    if (args[1] === 'login') {
      if (process.env.FAKE_LOGIN_NOURL) return console.log('Already logged in.');
      const url = process.env.FAKE_LOGIN_URL ?? 'https://claude.com/cai/oauth/authorize?code=true&state=fake-state';
      process.stdout.write(`Opening browser to sign in…\nIf the browser didn't open, visit: ${url}\nPaste code here if prompted > `);
      for await (const line of createInterface({ input: process.stdin })) {
        if (line.trim() === 'good-code') {
          logIn();
          writeFileSync(join(homedir(), '.claude.json'), JSON.stringify({ oauthAccount: { emailAddress: 'someone@example.com' }, userID: 'u1', mcpServers: {} }));
          console.log('Login successful.');
          return process.exit(0);
        }
        console.log('Login failed: Request failed with status code 400');
        return process.exit(1);
      }
      return process.exit(1);
    }
  }
  if (kind === 'codex' && args[0] === 'sandbox') {
    if (process.env.FAKE_SANDBOX === 'fail' || spawnSync('unshare', ['-Ur', 'true']).status !== 0) { console.error('bwrap: No permissions to create a new namespace'); return process.exit(1); }
    return;
  }
  if (kind === 'codex' && args[0] === 'logout') { rmSync(creds, { force: true }); return console.log('Successfully logged out'); }
  if (kind === 'codex' && args[0] === 'login') {
    if (args[1] === 'status') { console.log(loggedIn() ? 'Logged in using ChatGPT' : 'Not logged in'); return process.exit(loggedIn() ? 0 : 1); }
    if (args.includes('--device-auth')) {
      await device('https://auth.openai.com/codex/device', 'FAKE-12345', (url, code) => console.log(`\nWelcome to Codex [v\x1b[90m0.162.1\x1b[0m]\n\nFollow these steps to sign in with ChatGPT using device code authorization:\n\n1. Open this link in your browser and sign in to your account\n   \x1b[94m${url}\x1b[0m\n\n2. Enter this one-time code \x1b[90m(expires in 15 minutes)\x1b[0m\n   \x1b[94m${code}\x1b[0m\n`));
      return console.log('Successfully logged in');
    }
  }
  if (kind === 'grok' && args[0] === 'logout') { rmSync(creds, { force: true }); return console.error('Logged out.'); }
  if (kind === 'grok' && args[0] === 'models') { console.log(loggedIn() ? 'You are signed in with Grok.\n\nAvailable models:\n  grok-build' : 'You are not authenticated.'); return; }
  if (kind === 'grok' && args[0] === 'login' && args.includes('--device-auth')) {
    await device('https://accounts.x.ai/oauth2/device?user_code=FAKE-ABCD', 'FAKE-ABCD', (url, code) => process.stderr.write(`\x1b[1mTo sign in, open this URL in your browser:\x1b[0m\n  \x1b[36m${url}\x1b[0m\nConfirm this code in your browser:\n  \x1b[1m${code}\x1b[0m\nOnly continue with a code you requested. Don't share it with anyone.\nWaiting for authorization...\n`));
    return console.error('Signed in.');
  }

  // a job
  let prompt = kind === 'codex' ? '' : args[args.indexOf('-p') + 1];
  if (kind === 'codex') for await (const chunk of process.stdin) prompt += chunk;
  const dir = kind === 'codex' ? args[args.indexOf('-C') + 1] : process.cwd();
  const mode = /FAKE_MODE=(\S+)/.exec(prompt)?.[1] ?? 'ok';
  const seen = (p) => { try { accessSync(p); return true; } catch { return false; } };
  const saw = { kind, args, prompt, cwd: process.cwd(), env: Object.keys(process.env).sort(), tmp: process.env.TMPDIR, home: homedir(), homeFiles: readdirSync(homedir(), { recursive: true }).sort(), users: readdirSync(join(homedir(), '..', '..')), harnesses: readdirSync(join(homedir(), '..')),
    loggedIn: loggedIn(), userns: spawnSync('unshare', ['-Ur', 'true']).status === 0, peek: Object.fromEntries((process.env.FAKE_PEEK ?? '').split(',').filter(Boolean).map((p) => [p, seen(p)])) };
  if (mode === 'egress') saw.egress = { denied: await connect('example.com') }; // allowed tunneling is covered with a local upstream in box.test.mjs
  writeFileSync(join(dir, 'seen.json'), JSON.stringify(saw));
  const hang = () => { process.on('SIGTERM', () => process.exit(143)); setInterval(() => {}, 1000); };
  if (kind === 'claude') console.log(JSON.stringify({ type: 'system', subtype: 'init', session_id: 's1', model: 'claude-sonnet-5-5' }));
  if (!loggedIn()) {
    if (kind === 'claude') console.log(JSON.stringify({ type: 'result', is_error: true, result: 'Not logged in · Please run /login', usage: { input_tokens: 0, output_tokens: 0 } }));
    else if (kind === 'grok') console.log(JSON.stringify({ type: 'error', message: 'Not signed in. To authenticate without a browser, run:\n  grok login --device-code' }));
    else console.error('Not logged in');
    return process.exit(1);
  }
  if (mode === 'expired') { console.log(JSON.stringify({ type: 'result', is_error: true, result: 'Login expired · Please run /login', usage: { input_tokens: 0, output_tokens: 0 } })); return process.exit(1); }
  if (mode === 'fail') { console.error('fake failure'); return process.exit(3); }
  if (mode === 'hang') return hang();
  if (mode === 'burst-exit') {
    await sleep(20);
    process.stdout.write('x'.repeat(8192));
    return process.exit(0);
  }
  if (mode === 'hidden-disk') {
    const hidden = join(dir, 'hidden');
    mkdirSync(hidden);
    writeFileSync(join(hidden, 'payload'), Buffer.alloc(2 * 1024 * 1024));
    chmodSync(hidden, 0);
    await sleep(3500);
    chmodSync(hidden, 0o700);
  }
  if (mode === 'stderr-flood') {
    for (let i = 0; i < 64; i++) if (!process.stderr.write('x'.repeat(32768))) await once(process.stderr, 'drain');
    return;
  }
  if (mode === 'flood') {
    const line = `${JSON.stringify({ type: 'text', data: 'x'.repeat(32768) })}\n`;
    for (let i = 0; i < 64; i++) if (!process.stdout.write(line)) await once(process.stdout, 'drain');
    return;
  }
  if (mode === 'unicode') {
    const text = Buffer.from('한글🙂');
    process.stdout.write(Buffer.concat([Buffer.from('{"type":"result","result":"'), text.subarray(0, 1)]));
    await sleep(80);
    process.stdout.write(text.subarray(1, 7));
    await sleep(80);
    process.stdout.write(Buffer.concat([text.subarray(7), Buffer.from('","usage":{"input_tokens":1,"output_tokens":1}}\n')]));
    return;
  }
  if (mode === 'forkbomb') {
    // a spawn past the box's RLIMIT_NPROC fails (EAGAIN): no pid
    for (let i = 0; i < Number(process.env.FAKE_PROCS ?? 200); i++) spawn('sleep', ['300'], { stdio: 'ignore' }).on('error', () => {});
    return hang();
  }
  if (mode === 'plant') {
    writeFileSync(join(homedir(), '.bashrc'), 'echo planted');
    mkdirSync(join(homedir(), '.claude', 'hooks'), { recursive: true });
    writeFileSync(join(homedir(), '.claude', 'settings.json'), '{"hooks":{}}');
    rmSync(creds, { force: true });
    symlinkSync('/etc/passwd', creds);
  }
  if (mode === 'junk') for (const l of ['null', '"text"', '[1]', '7', JSON.stringify({ type: 'result', result: 'junk', usage: { input_tokens: '1e9x', output_tokens: null } })]) console.log(l);
  if (mode === 'rva') {
    // review-automation's draft job: out/ files, an attempt on the read-only validator, a link to the credential, an oversized file
    const out = join(dir, 'out');
    saw.outFiles = readdirSync(out, { recursive: true }).sort();
    writeFileSync(join(out, 'draft.json'), JSON.stringify({ schema_version: 1, title: `draft by ${kind}`, files: readdirSync(join(dir, 'materials'), { recursive: true }).sort() }));
    writeFileSync(join(out, 'draft.md'), '# draft\n');
    writeFileSync(join(out, 'handoff.md'), '# handoff\n');
    try { writeFileSync(join(dir, 'skill', 'validate.sh'), 'echo \'{"errors":[]}\''); saw.skillwrite = 'written'; } catch (e) { saw.skillwrite = e.code; }
    symlinkSync(creds, join(out, 'evil.json'));
    writeFileSync(join(out, 'big.txt'), 'x'.repeat(50000));
    writeFileSync(join(dir, 'seen.json'), JSON.stringify(saw));
  }
  if (kind === 'claude') {
    console.log(JSON.stringify({ type: 'result', is_error: false, result: 'first turn', usage: { input_tokens: 100, cache_creation_input_tokens: 50, cache_read_input_tokens: 250, output_tokens: 200 } }));
    console.log('{"type":"result","usage":{"input_tokens":9999');
    console.log(JSON.stringify({ type: 'result', is_error: false, result: `done (${mode})`, usage: { input_tokens: 400, cache_read_input_tokens: 100, output_tokens: 100 } }));
  } else if (kind === 'codex') {
    const last = args[args.indexOf('-o') + 1];
    if (mode === 'symlink') symlinkSync(process.env.FAKE_TARGET, last); else writeFileSync(last, `done (${mode})`);
    for (const e of [{ type: 'thread.started' }, { type: 'item.started', item: { type: 'command_execution' } }, { type: 'turn.completed', usage: { input_tokens: 700, output_tokens: 200 } }]) console.log(JSON.stringify(e));
  } else {
    // streaming-json as 14-headless-mode.md shows it: text chunks, a tool call, more text, per-response usage, then end with the totals
    for (const e of [{ type: 'text', data: 'Let me look.' }, { type: 'tool_call', toolCallId: 'call_1', title: 'Read', kind: 'read', status: 'in_progress', toolName: 'read_file' },
      { type: 'usage', messageId: 'r1', stopReason: 'tool_use', usage: { input_tokens: 100, output_tokens: 20 } }, { type: 'text', data: 'done ' }, { type: 'text', data: `(${mode})` },
      { type: 'usage', messageId: 'r2', stopReason: 'end_turn', usage: { input_tokens: 200, output_tokens: 50 } },
      { type: 'end', stopReason: 'end_turn', sessionId: 's1', cwd: dir, usage: { input_tokens: 300, cache_read_input_tokens: 50, cache_creation_input_tokens: 0, output_tokens: 70, reasoning_tokens: 5, total_tokens: 420 }, num_turns: 2 }]) console.log(JSON.stringify(e));
  }
}
