# The harnessbox service

`node src/server.mjs` (the image's default command) runs the runner behind an HTTP API, so web apps can let their users log in to
Claude Code, Codex or Grok and run jobs with those subscriptions without ever holding a credential. Each app is a **client** with
its own bearer token; its users live under `/homes/<client>/<user>/<harness>`, so two clients never see each other's users, even
with the same user ids. `src/client.mjs` is a dependency-free client: import it as `harnessbox/client` (types in
`src/client.d.ts`) or copy both files into your app.

## Configuration (environment)

| Variable | Default | |
|---|---|---|
| `HB_LISTEN` | `/run/harnessbox/hb.sock` | A unix socket path (made 0666; its folder is the boundary), or `host:port` for TCP on a private network. A socket path must stay under 108 bytes. |
| `HB_CLIENTS` | `/etc/harnessbox/clients.json` | `{"clients":[{"id":"myapp","tokenSha256":"<hex>","harnesses":["claude-code"]}]}`. `harnesses` is optional (default: all). Read at start; restart to rotate. Make a token with `openssl rand -base64 32`, its hash with `printf %s "$TOKEN" \| sha256sum`. |
| `HB_HOMES` | `/homes` | Users' homes. |
| `HB_RUNS` | `/tmp/hb-runs` | Run folders (put it on a tmpfs). Emptied at start. |
| `HB_HARNESSES` | `claude-code,codex,grok` | Which adapters to load. |
| `HB_BIN_<ID>`, `HB_PIN_<ID>` | on PATH, none | Binary and exact version per harness (`HB_BIN_CLAUDE_CODE`, `HB_PIN_CODEX`, …). A CLI of another version is not usable. |
| `HB_MODELS_<ID>` | any | Comma list of allowed `model` values for that harness. |
| `HB_MAX_JOBS` | 3 | CLI runs at once, all clients together. More wait (queued). |
| `HB_MAX_QUICK` | 4 | Status and logout boxes at once. |
| `HB_MAX_OUTPUT_BYTES` | 8 MiB | A run's CLI stdout and stderr together; past it the box is stopped (`result.why`). Claude Code's stream-json carries every image it reads, so raise it for jobs with many photos. A positive integer, else the service does not start. |
| `HB_MAX_BODY` | 64 MiB | Request body cap; the decoded files of a run may take three quarters of it. Size the container's `/tmp` tmpfs for `HB_MAX_JOBS` runs of that. |
| `HB_BWRAP`, `HB_SOCAT` | on PATH | |

Fixed limits (`LIMITS` in `src/server.mjs`): prompt 256 KiB; 2000 files, 48 MiB decoded; 32 outputs, 2 MiB each, 16 MiB together;
16 active runs and 200 kept runs per client; 256 MiB of ended runs' outputs for everybody (past it the oldest ended runs are
forgotten early); 128 MiB of request bodies in flight and 32 event streams per client; 4 waiting logins per client; run time
1 s–2 h (default 40 min); validator 1 s–10 min (default 60 s); runs and ended logins are kept 30 minutes; a status is cached 30 s.

## API v1

Every request carries `Authorization: Bearer <token>`. Bodies and answers are JSON. Errors are `{ "error": { "code", "message" } }`
with 400 (bad input), 401 (token), 404 (unknown, or another client's), 409 (busy, not usable, not waiting for a code), 413 (too
large), 429 (too many runs or logins). `:user` is `[A-Za-z0-9_-]{1,64}`, your own id for the user.

### Harnesses and logins

| Request | Answer |
|---|---|
| `GET /v1/harnesses` | `{ harnesses: [{ id, name, version, usable, why }] }`: what this client may use, as `detect()` found it at start. |
| `GET /v1/users/:user/harnesses` | `{ harnesses: [{ harness, installed, loggedIn, method, plan, checkedAt } \| { harness, busy: true, …last known } \| { harness, error }] }`: each usable harness, one after another. |
| `GET /v1/users/:user/harnesses/:h` | `{ harness, installed, loggedIn, method, plan, checkedAt }`: a status at most 30 s old, else asked in a box; 409 `busy` when it would have to ask while that user's login or run of `:h` holds the box. |
| `POST /v1/users/:user/harnesses/:h/login` | Starts the CLI's own login in the user's box and waits up to 30 s for its URL: `{ state, url, code, needsCode, startedAt, expiresAt }`. A newer login for the same user and harness replaces the old one. |
| `GET …/login` | The current (or, for 30 minutes, the last) login: `state` is `starting`, `waiting`, `done` (with `status`) or `failed` (with `error`). 404: none. |
| `POST …/login/code` `{ code }` | Paste-code logins (`needsCode: true`, Claude Code): the code the login page showed the user, to the CLI's stdin, once. 204, 409 when not waiting for one. |
| `DELETE …/login` | Cancel. 204. |
| `POST …/:h/logout` | The CLI's own logout, then its status. |
| `DELETE /v1/users/:user` | Cancels the user's runs (queued ones included) and logins, then deletes all their homes. 204. |

Show the user `url` (and `code` for a device login) and nothing else; the URL is always https on the harness's own login hosts.
A login ends by itself after 10 minutes. Device logins (Codex, Grok) finish when the user confirms in their browser: poll
`GET …/login` every few seconds.

### Runs

`POST /v1/runs` → 202 with the run (state `queued`):

```json
{
  "user": "u_123", "harness": "claude-code", "model": "sonnet",
  "prompt": "Read /work/request.md and follow it.",
  "files": [{ "path": "request.md", "text": "…" }, { "path": "materials/photos/p1.jpg", "base64": "…" }],
  "readonly": ["skill"],
  "outputs": ["out/draft.json", "out/draft.md", "out/handoff.md"],
  "validate": { "argv": ["python3", "-I", "skill/write-review/scripts/validate_draft.py", "out/draft.json"], "net": "none", "timeoutMs": 60000 },
  "timeoutMs": 2220000,
  "args": ["--tools", "Read,Write,Edit,Agent,Bash", "--allowedTools", "Read(//work/**)", "Edit(//work/out/**)"]
}
```

- The run's folder is `/work` inside the box (and the CLI's working directory), so the prompt, the files and the tool rules can
  name `/work/...` in advance. Paths are relative, plain segments; a path given twice is refused. A file may add `copies: [paths]`
  (up to 8) to be written there too, without sending the bytes again (they count against the files cap each time).
- `readonly`: folders whose files are bound read-only over `/work/<folder>` for the CLI and the validator: the model can read a
  skill and run its validator but not change them.
- `outputs`: files read back after the run: regular files only, never through a link, at most 2 MiB each; `null` when missing, a
  link, a FIFO or too big. The parent folders of every output are created before the run.
- `validate`: a command in a second box, no network, cwd `/work`, the same read-only folders and an empty home of its own (not the
  user's: it never sees their credential), after the CLI exited 0 or ran out of time (not after a failure or a cancel).
- `model`: passed as `--model` (all three CLIs). `args`: extra CLI options after the adapter's hardened ones. They cannot widen the
  box, but they can widen what the CLI lets the model do inside it (see the threat model). `timeoutMs` stops the CLI.

`GET /v1/runs/:id` → the run:

```json
{
  "id": "run_…", "user": "u_123", "harness": "claude-code", "model": "sonnet", "state": "done",
  "createdAt": "…", "startedAt": "…", "endedAt": "…", "stage": "result", "events": 41,
  "result": { "code": 0, "text": "the CLI's last message", "usage": { "input": 900, "output": 300 }, "error": "", "stderr": "…", "why": null, "timedOut": false, "canceled": false },
  "validator": { "code": 0, "out": "{\"errors\": []}", "why": null },
  "outputs": { "out/draft.json": "<base64>", "out/draft.md": "<base64>", "out/handoff.md": null }
}
```

- `state`: `queued` (waiting for the user's lock or a slot) → `running` → `validating` → `done` | `failed` | `canceled`. `failed`
  covers the CLI's own failure, a time limit (`result.timedOut`, outputs and validator still there) and the watchdog (`result.why`).
- `result.loggedIn`: present after a CLI failure; `false` means the user must log in again.
- `usage.unknown: true`: the CLI reported no usage. Claude's input counts cache tokens.
- `error`: the service could not run it at all.

`GET /v1/runs/:id/events` → Server-Sent Events: `state` (on each state change), `progress` (at most once a second while events
arrive: `stage`, `events`), and `end` (the full run, outputs included), then the stream closes. Each `data:` is the run as JSON.
`DELETE /v1/runs/:id` cancels (204): a running CLI is killed; a queued run leaves the user's lock and the slot queue at once and
ends without a box. Runs are kept 30 minutes after they end. **A restart forgets every run**: an unknown id is 404,
and the client starts the run again.

## Example: review-automation's draft job

What its pool runner (`app/runner/rva-runner.mjs`, `runJob`) prepared and checked, as one `POST /v1/runs`:

```js
const W = '/work', validator = ['python3', '-I', `${W}/skill/write-review/scripts/validate_draft.py`, `${W}/out/draft.json`];
await hb.run({
  user: job.userId, harness: job.engine, // 'claude-code' | 'codex'
  prompt: PROMPT, // unchanged: it names skill/…, request.md, materials/, out/ relative to the working folder
  files: [
    ...skillFiles.map((f) => ({ path: `skill/write-review/${f.rel}`, base64: f.bytes.toString('base64') })), // the pristine skill
    { path: 'request.md', text: requestMd(job, W, stopAt) },  // its validator line now says /work/...
    { path: 'materials/campaign.md', text: campaignMd(job) }, { path: 'materials/memo.txt', text: `${job.memo}\n` },
    // body photos also in out/photos/ (the contract's copies; Claude Code cannot copy a binary), reference photos once
    ...photos.map((p) => ({ path: `materials/photos/${p.name}`, base64: p.b64, ...(p.reference ? {} : { copies: [`out/photos/${p.name}`] }) })),
    ...docs.map((d) => ({ path: `materials/${d.name}`, base64: d.b64 })),
  ],
  readonly: ['skill'],
  outputs: ['out/draft.json', 'out/draft.md', 'out/handoff.md'],
  validate: { argv: validator, net: 'none', timeoutMs: 60e3 },
  timeoutMs: Date.parse(job.deadline) - Date.now() - 3 * 60e3, // its STOP_BEFORE_MS
  args: job.engine === 'claude-code'
    ? ['--tools', 'Read,Write,Edit,Agent,Bash', '--allowedTools', `Read(/${W}/**)`, `Edit(/${W}/out/**)`, 'Agent', `Bash(${validator.slice(0, 3).join(' ')} *)`, '--max-turns', '80']
    : [], // Codex: the adapter's flags are the runner's (--ignore-rules when the CLI has it)
});
```

Then, from the ended run: `outputs['out/draft.json']` (base64; `null` means not written) is the draft, `validator.out` is the
validator's JSON (`{ errors }`), `result.text` is the CLI's last message (Codex's from its `-o` file), `result.usage` the tokens
(`unknown` when none), `result.loggedIn === false` means the user must log in again, `result.timedOut` is the runner's "stopped
at the deadline" case (outputs and validator are still there), and a missing `out/draft.md` or `out/handoff.md` is `null`. The
job's lease and progress map onto the run: `GET /v1/runs/:id` or the event stream while it runs, `DELETE /v1/runs/:id` when the
user cancels, and a 404 after a service restart means queue it again.

Its existing homes (`/homes/<userId>/.claude/.credentials.json`, `.claude.json`, `.codex/auth.json`) move once with
`deploy/move-homes.sh` (credential files only, never through a link) to `/homes/<client>/<userId>/<engine>/`.

## Client module

```js
import { harnessbox } from 'harnessbox/client'; // or a copy of src/client.mjs
const hb = harnessbox({ socketPath: '/run/harnessbox/hb.sock', token: process.env.HARNESSBOX_TOKEN });
const login = await hb.login('u_123', 'codex');                 // show login.url and login.code
const { id } = await hb.run({ user: 'u_123', harness: 'codex', prompt: '…', files, outputs: ['out/draft.json'] });
const run = await hb.events(id, (event, r) => console.log(event, r.state, r.stage)); // resolves to the ended run
```

Calls reject with `HarnessboxError` (`status`, `code`).

## Deploy

`deploy/compose.yaml` shows the service and a client app: the app mounts only the socket volume (it may mount it read-only; the
socket still connects), keeps its token in its own secrets, and needs no network to the service. Checked on Docker 26.1.5 with the
shipped seccomp profile: a client container (another uid, `--network none`, the volume read-only) runs `deploy/service-smoke.mjs`
12/12 and cannot create or remove files in the socket folder.

After every deploy: `deploy/probe.mjs` inside the service container (isolation, with your network's addresses) and
`deploy/service-smoke.mjs` from a client (`HB_TOKEN`, `HB_SOCKET`, optionally `HB_LOGIN_START=1`).

## Threat model additions

- **A client is trusted for its own users.** It chooses the user ids, the prompts, the files and the CLI options of their runs, and
  it relays their logins: it can run jobs with any of its users' logins. It cannot reach another client's users: every path, lock,
  run and login is keyed by the client id taken from the token.
- **A client could get its own users' credentials out, on purpose.** In normal use no credential passes through it (only URLs,
  device codes and pasted codes). But the credential is a file in the user's box that the CLI must read, and the client writes the
  prompt and may add CLI options: a prompt asking Codex (whose own sandbox reads the whole box) or a Claude Code given Bash or broad
  Read to print the file returns it in the run's text or outputs. The validator cannot (its home is empty). harnessbox does not scan
  results for credentials. Only let clients you would trust with those credentials connect, and keep the CLIs' tool rules tight.
- **Tokens** are compared by their SHA-256; the clients file holds only hashes. Whoever can reach the socket or port and holds a
  token is that client. Keep the socket volume to the client apps and the TCP port on a private network.
- **What the service keeps**: runs (prompts never; outputs and the CLI's last message for 30 minutes) and login sessions (URL and
  code until 30 minutes after the end) in memory only. Logs carry ids, states and egress denials.
- **Busy, not queued**: a status during that user's run or login is a 409 instead of a box; runs queue on the user's lock, so one
  user's runs never take the slots other users need.
