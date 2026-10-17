# Writing a harness adapter

An adapter is one object (`src/adapters.mjs` has the typedef and three examples). The runner does everything else: the box, the
proxy, the scrub, the lock, the login session, the watchdog. Write the adapter only from what you have verified on the CLI itself;
mark the rest in the README's adapter table.

## 1. Find out, with a throwaway HOME

Run every step with `env -i HOME=$(mktemp -d) PATH=/usr/bin:/bin <cli> ...` and never with your own home. Never finish a real login
while you explore; start it, read what it prints, kill it.

| Question | Why the runner needs it |
|---|---|
| Which files does a login write, relative to HOME? Any keyring or D-Bus? | `keep`. The box has no D-Bus: force file storage (Codex: `-c cli_auth_credentials_store="file"` in `globalArgs`). |
| Which other files hold settings a box could plant (MCP servers, hooks, trusted folders)? | Anything not in `keep` is removed before every box. If a kept file mixes the login with settings, list its safe keys in `keepJsonKeys`. |
| Which config must exist for safe runs (no update checks, no telemetry, no reading other tools' folders)? | `seed` (written after the scrub) and `env`. |
| Which hosts does it contact for login, refresh and inference? | `hosts`. Run it with `HTTPS_PROXY` at a logging CONNECT proxy that answers 403, or run `deploy/probe.mjs` and read the `egress deny` lines. Add only the CLI's own hosts; the user's browser needs none. |
| Is there a login that needs neither a browser on this machine nor a localhost callback? | `login`. `paste-code`: the CLI prints a URL and reads a code on stdin. `device-code`: it prints a URL and a code and polls by itself. A flow that only works with a TTY is not supported (the runner pipes stdin). |
| A status command, its output when logged in and out, its exit codes? Does it use the network? | `status.parse`. If there is none, find the cheapest command whose output differs (Grok: `grok models`). |
| A non-interactive mode: prompt in, final text and token usage out, preferably one JSON event a line? | `job.command`, `job.event`, `job.finish`. |
| Flags that keep it from reading user or project config, plugins, hooks, MCP servers? | `job.command` (they are the adapter's defaults; the caller adds its own `args`). |
| Does its own sandbox need user namespaces inside our box? Can it be turned off? | `nested: true` drops `--disable-userns` for job boxes only. Prefer off. |

## 2. Write the object

```js
export const mycli = {
  id: 'mycli', name: 'My CLI', bin: 'mycli',
  hosts: ['api.example.com', 'auth.example.com'],
  keep: ['.mycli/credentials.json'],
  seed: { '.mycli/config.toml': 'telemetry = false\n' },
  env: { MYCLI_NO_UPDATE: '1' },
  flags: { args: ['--help'], needs: ['--print', '--json'] },
  login: {
    kind: 'device-code', args: ['login', '--device'], urlHosts: ['example.com'],
    parse: (t) => { const m = /(https:\/\/example\.com\/device\S*)[\s\S]*?\b([A-Z0-9]{4}-[A-Z0-9]{4})\b/.exec(t); return m && { url: m[1], code: m[2] }; },
  },
  status: { args: ['whoami'], parse: ({ code, out }) => ({ loggedIn: code === 0 && !/not logged in/i.test(out) }) },
  logout: ['logout'],
  expired: /not logged in|token expired|401/i,
  job: {
    command: ({ prompt, dir, extra }) => ({ args: ['--print', '--json', '--cwd', dir, ...extra], stdin: prompt }),
    event: (e, acc) => {
      if (e.type === 'final') { acc.text = e.text; acc.reports++; acc.usage.input += e.usage.input; acc.usage.output += e.usage.output; }
      if (e.type === 'error') acc.error = String(e.message).slice(0, 200);
    },
  },
};
```

Rules the runner relies on:

- `login.parse` gets the output so far with ANSI codes removed (both streams, the last 4 KB) and returns `null` until it has
  everything. The runner refuses a URL that is not `https:` on one of `urlHosts`, so a planted or changed CLI cannot send the user
  elsewhere.
- `status.parse` never throws. Return `loggedIn: false` for anything it does not recognise.
- `job.event` gets each stdout line that parses as JSON. Count `acc.reports` only for real usage reports: with none, the runner marks
  the usage `unknown` instead of reporting zero. Prefer totals from a final event over summing per-turn events, and say in a comment
  whether the CLI's input count includes cache tokens.
- Anything the job writes and the runner reads (a last-message file, say) goes through `readOut(dir, name)` in `job.finish`, never
  `readFile`: the box could have replaced it with a link to another user's credentials.
- `webSearch: true` on the adapter says `job.command` honours `webSearch` (it is `false` unless the caller asked): turn on only the
  CLI's own server-side search, by replacing the value that turns it off, and never add a host for it. Without the property the
  runner refuses a run with `webSearch`.
- Keep the prompt off the command line if the CLI can read it from stdin or a file; the runner refuses prompts starting with `-` when
  they are an argument.

## 3. Prove it

1. Add the CLI to `test/fake-cli.mjs`: its `--version`, help text, login output (copied from the real one, codes replaced), status,
   logout and job events. Add it to the runner tests' `world()` and to the per-harness loops.
2. Run `npm test`.
3. Run `deploy/probe.mjs` with the real binary (`HB_BIN_<ID>=...`, `HB_LOGIN_START=1`): detect, a logged-out status and the start of
   a login in a box, and no `egress deny` line for the adapter's own commands.
4. One real login and one real job, with a test account, before calling the adapter verified.
