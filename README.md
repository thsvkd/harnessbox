# harnessbox

Run agent CLIs (Claude Code, Codex, Grok) for many users on one server, each user with **their own login**, in a bubblewrap box per
call. The host app never holds a credential: the CLI's own login runs in the user's box and writes the credential into that user's
home; the app only relays the login URL and a code. A box sees only its user's home for that harness and the job folder, and reaches
the internet only through a CONNECT proxy that allows the harness's own hosts on port 443.

Extracted on 2026-10-16 from review-automation's per-user runner (`app/runner/box.mjs`, `rva-runner.mjs`), deployed there for
Claude Code and Codex. Node 24, Linux, bubblewrap, socat; no npm dependencies. Version 0.1.0, not published.

```
host app ── its own API ── runner process (your script, uid 10011, one hardened container)
                            ├─ createRunner(): detect, status, login, logout, purge, run, exec
                            ├─ per box: CONNECT proxy on a unix socket (this process), allowlist per harness
                            └─ bwrap box per call: /homes/<user>/<harness> and the job folder writable, nothing else
                                 └─ socat 127.0.0.1:3128 → /run/egress.sock → proxy → api.anthropic.com:443 …
```

## Use

```js
import { claudeCode, codex, createRunner, grok } from 'harnessbox';

const hb = await createRunner({ homes: '/homes', adapters: [claudeCode, codex, grok], socat: '/usr/bin/socat', maxJobs: 3, log: console.log });
await hb.detect(); // [{ id, version, usable, why, has }] — each CLI checked in a box: version pin, options, own checks

// login: relay url (and code) to the user; for a paste-code login, relay the code they paste back
const s = hb.login('u_alice', 'claude-code');
const { url, code, needsCode } = await s.waiting;
if (needsCode) s.submitCode(codeFromUser);  // once
const { ok, status, error } = await s.done; // done | failed (10 min cap, cancel(), a newer login, purge)

await hb.status('u_alice', 'codex');        // { installed, loggedIn, method, plan }; throws Busy behind a running job
const r = await hb.run('u_alice', 'claude-code', {
  prompt: 'Summarise notes.md into out/summary.md', dir: jobDir, timeoutMs: 20 * 60e3, signal,
  args: ['--allowedTools', `Read(/${jobDir}/**)`, `Edit(/${jobDir}/out/**)`], // the caller's tool rules
});
// r: { code, text, usage: { input, output[, unknown] }, error, stderr, why, timedOut, canceled, loggedIn? }
const draft = await readOut(jobDir, 'out/summary.md'); // never readFile on what a box wrote
await hb.exec('u_alice', 'claude-code', ['python3', '-I', '/opt/v/validate.py', `${jobDir}/out/x.json`], { dir: jobDir }); // no network
await hb.logout('u_alice', 'grok');
await hb.purge('u_alice');                  // every harness home of the user, after their running job
process.on('SIGTERM', () => { hb.close(); process.exit(143); });
```

| `createRunner` option | Default | |
|---|---|---|
| `homes` | (required) | Root of the per-user homes, one uid owns them all. `<homes>/<userId>/<harnessId>`, 0700. User and harness ids: `[A-Za-z0-9_-]{1,64}`. |
| `adapters` | (required) | `claudeCode`, `codex`, `grok`, or your own (docs/adapters.md). |
| `bins`, `pins` | PATH, none | Binary and exact version per harness id. Another version is not usable. |
| `bwrap`, `socat` | on PATH | |
| `maxJobs` | 3 | Jobs at once; more wait for a slot. Logins are one per user and harness; there is no global cap on them. |
| `maxQuick` | 2 | Status and logout boxes at once; more throw `Busy`. A status waits at most `waitMs` (5 s) for the user's lock. |
| `maxProcs` | 128 | Per box, watchdog (2 s). The in-box RLIMIT_NPROC is 4x (threads count). |
| `maxBytes`, `maxEntries` | 1 GiB, 20000 | Home + job folder per box, watchdog. |
| `log` | none | Egress denials (`egress deny <label> <host>:<port> <why>`) and watchdog notes. Never URLs, codes or credentials. |
| `passEnv` | `{}` | Extra variables in every box (tests). |

One lock per user and harness: a login, status, logout and job of the same credential never overlap (both Claude Code and Codex
rotate refresh tokens; two refreshes at once log the user out). The home is scrubbed to the adapter's credential files before every
box and after every job, so a box cannot plant hooks, shell start-up files or MCP servers for the next one.

## Adapters

| | Claude Code | Codex | Grok |
|---|---|---|---|
| Version checked | 2.1.300 | 0.162.1 (musl) | 1.0.52 (official xAI CLI) |
| Login | paste code: `claude auth login` | device code: `codex login --device-auth` | device code: `grok login --device-auth` |
| Status | `claude auth status --json` (asks its server) | `codex login status` (offline, file only) | `grok models` ("You are not authenticated.") |
| Credential kept | `.claude/.credentials.json`, `.claude.json` (account keys only) | `.codex/auth.json` (forced file store) | `.grok/auth.json` |
| Box hosts | api.anthropic.com, platform.claude.com | auth.openai.com, chatgpt.com | auth.x.ai, cli-chat-proxy.grok.com, api.x.ai |
| Job | `-p`, stream-json, dontAsk, `--restricted`, `--strict-mcp-config`, no session persistence, no web tools | `exec --json`, `--ignore-user-config`, workspace-write sandbox without network/MCP/apps/plugins/web search | `-p`, streaming-json, web search off |
| Nested userns | no | yes (its own sandbox) | no (its sandbox stays off) |

What was verified (2026-10-16, this repository's code, Raspberry Pi 5, kernel 6.18, bwrap 0.11.0):

- **All three, real binaries on the host** (`deploy/probe.mjs`, 24/24): `--version` and the required options in a box with no network and an
  empty home; a fresh home reports logged out; the login starts in a proxy box and prints a URL on the adapter's login hosts (Claude
  `claude.com/cai/oauth/authorize`, Codex `auth.openai.com/codex/device` with a `XXXX-XXXXX` code, Grok `accounts.x.ai/oauth2/device`
  with a `XXXX-XXXX` code), then is canceled; none of these produced an egress denial, so their hosts are on the lists. Codex's own
  sandbox starts in a nested box (`codex sandbox -- true`).
- **Isolation** (same run): another user's credential canary, home and /proc invisible; LAN, tailnet, Docker bridge, host loopback
  and direct internet unreachable; no capabilities, seccomp on, AF_VSOCK and io_uring EPERM, no nested user namespace; cleared
  environment; RLIMIT_NPROC 512, /tmp and /run 256 MiB; the proxy refuses another harness's host, port 80, an IP literal, an unlisted
  host and plain HTTP, and lets `api.anthropic.com:443` through; a net-none box has no network; every denial is logged with its label.
- **The same in the runner image under Docker** (`deploy/Dockerfile` built here, run with `deploy/compose.yaml`'s hardening and the
  shipped seccomp profile on Docker 26.1.5): 24/24, with Grok installed by xAI's installer and Codex through its npm wrapper.
- **Claude Code and Codex in review-automation** (same box design minus the per-harness home and the box seccomp filter) are
  deployed; their isolation probe passed 24/24 on that host. Real logins and jobs there are that project's own check list, not
  re-run from this repository.
- **Not verified**: a real login and a real job for Grok (its token exchange, its hosts after login, the logged-in output of
  `grok models`, its streaming-json from a real run — the parser follows `docs/user-guide/14-headless-mode.md` of 1.0.52); the
  `.claude.json` account-key list against a real `claude auth status` after a scrub (review-automation has it on its real-login list); Grok's own sandbox in a
  box; the Docker image on x86_64.
- **Grok on a Raspberry Pi 5**: the official linux-aarch64 build uses SHA-512 instructions the Cortex-A76 lacks and dies with SIGILL
  in its OAuth/crypto path. `--version`, `--help`, `models` and the start of a device login run natively; the token exchange was not
  tried. On such a CPU the binary needs qemu-user (`qemu-aarch64-static -cpu max`), which the image does not include.

Candidates not shipped (checked 2026-10-16, details in docs/terms.md):

- **Gemini CLI 0.64.0**: Google ended personal "Login with Google" for Gemini CLI on 2026-06-18; the remaining paste-code login and
  the API-key entry both need a TTY (`gemini` has no `auth` subcommand, headless auth fails with exit 41). Supportable only with a pty
  and only for Code Assist Standard/Enterprise or an API key typed into the CLI's own screen.
- **opencode 1.19.0**: device-code logins work without a TTY (`opencode auth login -p openai -m 'ChatGPT Pro/Plus (headless)'`;
  GitHub Copilot after one keypress), credentials in `$XDG_DATA_HOME/opencode/auth.json`, `opencode run --format json`. Not shipped:
  its inference hosts depend on the provider and were not checked, it also contacts models.opencode.ai and registry.npmjs.org, ignores
  SIGTERM and leaves stale locks when killed, and reads `~/.claude` unless `OPENCODE_DISABLE_CLAUDE_CODE=1`.

## Threat model

Protects against: a model (or a prompt injection in a job's material) running arbitrary commands as the CLI, and a user who controls
their own job. It must not reach another user's home or login, the host app, the runner's own secrets, the LAN, tailnet, Docker
networks or host services, or any internet host but its harness's; it must not leave anything behind that runs in the user's next
box; it must not take the runner down for everyone.

The boundaries, honestly:

- **Shared kernel.** Every box is namespaces on the runner's kernel. A kernel bug reachable from inside (user namespaces, mount, a
  syscall the filters allow) is an escape. The container's seccomp profile has to allow `unshare`, `clone`, `mount`, `umount2` and
  `pivot_root` for bubblewrap, which widens that surface for the runner process too.
- **One uid for all users.** All homes belong to the runner's uid; the box's mount namespace is what separates users. An escape from a
  box sees every home. Separate uids per user would need a setuid helper or root in the container; not done.
- **Nested user namespaces for Codex.** Codex's own sandbox needs them, so its job boxes run without `--disable-userns`.
- **Memory is not limited per box.** /tmp and /run in a box are 256 MiB tmpfs, the watchdog caps the home and job folder (1 GiB) and
  processes (128); a CLI's own memory is only bounded by the container's `mem_limit`, and only if the kernel's memory cgroup is on
  (the Raspberry Pi kernel ships with `cgroup_disable=memory`). One user can exhaust memory for all.
- **A user's own credential is readable in their own box** (the CLI must read it). The host allowlist is the only limit on where it
  can go. A box can also overwrite its own kept credential file, which then persists (it can only hurt its own login).
- **The runner process sees everything**: it owns all homes. Anything it reads from a job folder goes through `readOut` (no links, no
  FIFOs, real path checked), and validators run in a box. Keep the runner script small.
- **DNS** is resolved by the runner, not the box; the proxy refuses private, loopback, CGNAT, link-local and multicast results and
  dials the address it checked. IPv6 is not proxied.

Prefer a microVM (Firecracker, Kata) or gVisor when users are mutually hostile at scale, when you cannot accept a shared-kernel escape,
or when you need hard per-user memory limits. Measured on the same Pi: Firecracker costs about 160 MB per job and 0.45–1.4 s start
(rootfs 637 MB); gVisor did not start on its 16K-page kernel.

## Overhead

Measured 2026-10-16 on a Raspberry Pi 5 (16 GB, kernel 6.18, 16K pages), review-automation's isolation research; this repository's
box adds a seccomp filter and `--cap-drop ALL`, which were not benchmarked separately.

| | |
|---|---|
| `claude --version`, p50 / p95 | 44 / 57 ms in a box, 9 ms bare (3 users at once: 53 ms vs 18 ms) |
| `claude -p hi` (real start-up) | 598 ms in a box vs 613 ms bare: no measurable difference |
| Extra memory per box | 5.2 MB RSS, about 0 PSS |
| Disk per user | 0.13 MB plus the CLI's own state |
| New upstream TLS connection through the proxy | +60–70 ms |
| What limits concurrency | the CLIs' own memory (an idle `claude` is about 150 MB RSS) |

## Compared with sandbox-runtime

anthropic-experimental/sandbox-runtime (npm 0.0.79 and GitHub main 0ded0c8, 2026-10-16) on Linux:

| | sandbox-runtime | harnessbox |
|---|---|---|
| io_uring, AF_VSOCK | seccomp EPERM | seccomp EPERM (adopted; `seccompFilter`, via `bwrap --seccomp`) |
| Foreign arch, x32 | killed | killed (adopted) |
| Capabilities | `--cap-drop ALL` | `--cap-drop ALL` (adopted) |
| `socket(AF_UNIX)` | EPERM, applied after socat starts, command in a nested pid namespace, non-dumpable helper | **not blocked.** Mounts are an allowlist and abstract sockets are per network namespace, so the only reachable unix socket is the box's own proxy socket. Adopting it would need a post-socat seccomp helper binary and a socat the command cannot ptrace. |
| Namespace syscalls (unshare/setns/mount…) | EPERM (main) | `--disable-userns` except Codex's nested boxes |
| Filesystem | `/` read-only, write allowlist, read denylist, mandatory deny for dotfiles, `.git/hooks`, `.claude` | only `/usr`, `/etc`, CLI folders read-only; only the user's harness home and job folder writable; the home scrubbed to credentials around every box |
| Environment | inherited, with denied variables unset | `--clearenv` |
| Network | HTTP + SOCKS proxies, allow/deny lists with wildcards, private ranges optional | CONNECT only, exact hosts, port 443 only, private ranges and CGNAT always refused, IPv4 only |
| IPC/UTS/cgroup namespaces, private /tmp, process and size limits | no | yes |

## Deploy

- `deploy/Dockerfile`: the runner image (Node 24, bubblewrap, socat, python3, CLIs pinned by build args, uid 10011, `/homes`). Your
  host app builds FROM it with its runner script. The image's default command is the probe.
- `deploy/compose.yaml`: the container hardening: read-only root, `cap_drop: ALL`, `no-new-privileges`, the bubblewrap seccomp
  profile, `systempaths=unconfined` (for the box's fresh /proc), tmpfs /tmp, `pids_limit`, `mem_limit`.
- `deploy/seccomp/`: `mkprofile.py` and `seccomp-bwrap.json`, generated from moby v26.1.5's default profile. Regenerate it for your
  Docker version (the commands are at the top of `mkprofile.py`); older defaults (20.10) still allow io_uring, which the box filter
  then covers. AppArmor hosts need a profile that allows mount (not shipped).
- `deploy/probe.mjs`: run it inside the deployed container with your network's addresses (`HB_TARGETS`, `HB_PEEK`) before you open
  the runner to users, and after every Docker, kernel or CLI upgrade.

Before deploying, check on the host: `cat /proc/sys/user/max_user_namespaces` (> 0), `cat /sys/kernel/security/lsm` (AppArmor?),
`cat /sys/fs/cgroup/cgroup.controllers` (memory?), `docker version` (regenerate the profile).

## Tests

`npm test`: box primitives (proxy with stubbed DNS and upstream, scrub, reader, counts, argv, seccomp filter in a real box) and the
runner end to end with real bubblewrap boxes and fake CLIs (`test/fake-cli.mjs`). Tests that need bubblewrap with user namespaces
skip themselves without it. `node deploy/probe.mjs` with the real CLIs is the smoke test.

## How review-automation would use it

Not done yet; review-automation is unchanged. `app/runner/rva-runner.mjs` would keep its app protocol (long polls, leases, progress,
results, control commands) and its write-review job preparation, and replace its box layer with `createRunner`:
`box()`/`inBox()`/`detect()`/`cliStatus()`/`login()`/the purge and logout branches become `hb.detect/status/login/logout/purge`,
`runJob` calls `hb.run` with its Claude allow rules in `args` and the pristine skill in `roBinds`, and the validator box becomes
`hb.exec`. Two behaviour changes to plan for: homes move from `/homes/<userId>` to `/homes/<userId>/<engine>` (move `.claude*` and
`.codex` once, or log users in again), and the lock becomes per user and engine instead of per user. The Dockerfile's runner stage
and compose service map onto `deploy/` one to one.

## License

Not chosen yet.
