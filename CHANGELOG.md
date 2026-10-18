# Changelog

## 0.4.0

- Proxy: a tunnel carries only TLS whose ClientHello names the CONNECT host (`server_name`, one record, no ECH); anything else is
  closed unsent and logged `egress deny <label> <host>:443 sni <name>`. chatgpt.com, auth.openai.com and the x.ai hosts share
  Cloudflare's edge, which routes by that name: a CONNECT to them with another name inside reached any site behind it. Claude Code
  2.1.302, Codex 0.163.0, Grok 1.0.52 and curl send what passes.
- Boxes: the root and `/dev` are read-only (`--remount-ro` after the last mount), with a 256 MiB `/dev/shm`. Both were bwrap's own
  unsized tmpfs, so a write there took memory past every cap and the watchdog never saw it. Home, job folder, `/tmp`, `/run` and
  `/dev/shm` stay writable. Not closed (README): a tmpfs that a command in Codex's own sandbox mounts, and inodes in the sized ones.
- Runner: `exec` waits for a job slot like `run` (with `maxJobs` 3, a client's 16 validators no longer run at once; in the service a
  run canceled while its validator waits for one ends canceled as any cancel does, outputs read, no `error`, and a validator box
  that did not start is the run's `error`, never the validator's answer); `timeoutMs`, `ms`
  and `waitMs` must be whole milliseconds up to 2^31 - 1 (Node turned a larger one or `Infinity` into 1 ms); a status box that runs
  out of time or is stopped (`close()`) is an error, not "logged out" (`ShortResult.timedOut`); a kept credential file past 1 MiB is removed at the scrub; one
  user id form per runner, and `purge` cancels only that user's logins and asks for all its harness locks at once (a job or login
  for another harness that came meanwhile took that lock first and held the purge up to its time limit); a login session has
  `expiresAt` (its box's 10 minutes); startup refuses a Node or CLI folder, or `/usr` or `/etc` (every box binds them), that holds the runner
  user's home, the homes root (made first, so a link above it counts) or the temp folder (as real paths), or is `/`, and a temp folder too long for the boxes' sockets; no "home scrub failed" for a home never made.
- Service: a purge forgets only the logins it ended (one started meanwhile stays visible, counted and cancelable); a login's
  `expiresAt` is the runner's once the CLI's box started (a login behind a run starts later); answer bytes a client has not read
  are capped per client (128 MiB, one answer always goes; past it `GET /v1/runs/:id` is a 429 `too_many_answers` and an event
  stream is closed, which `events()` reports as `stream_ended`; `POST /v1/runs` always answers with the run it started): clients
  asking for big runs and never reading held the service's memory; a connection that has not sent its headers in 10 s is dropped
  (the 512 connections are for everybody on the socket, before any token: docs/service.md says to share a service only among apps
  that trust each other); a full run tmpfs is a 507 `no_space`, not
  a 400 "clashes"; an output that does not fit `outputsBytes`
  no longer uses up the room, outputs count at their base64 size in `keptBytes`, and an output named `__proto__` comes back; a bad
  `HB_MAX_BODY` (or one past 2^29 - 24, which V8 cannot parse), `HB_MAX_JOBS` or `HB_MAX_QUICK` stops the service at start (they
  turned the body cap off or became the default) and the bytes in flight per client are at least the body cap; a request URL that does not parse is a 400, not a 500; path segments are counted in bytes (255, 1024 for a path), so a Korean file name past them is a 400, not the file system's error;
  a `readonly` folder given twice is a 400, as documented; a client entry whose `harnesses` is not an array of ids stops the
  service at start (a string became a set of its letters); a status or logout box that failed (now also when out of time) is a 503 `status_failed`, not a 500.
- Runner and service: `createRunner({ hide })` makes files under `/usr` or `/etc` unreadable in every box (each a regular file,
  checked at start); the service hides its clients file there (the default `/etc/harnessbox/clients.json` was readable by every
  user's model: every client's token hash).
- Runner: a box that bwrap could not set up (out of pids or namespaces, a bind that fails) has `why: 'the box did not start'`, from
  bwrap's `--json-status-fd`: its status is an error and a run's `loggedIn` is not asked, where both read it as "logged out"; and
  `detect()` says so with bwrap's message at whichever probe step it was, instead of `--version failed (exit 1)`, a missing option
  or a failed check; a spawn that gets no process (out of file descriptors) rejects with that reason instead of ending the runner
  with an unhandled 'error' event.
- Service and runner: a run folder or a home holding what a box can make a plain rm fail on (a folder made 0555 or 000, a chain of
  folders deeper than PATH_MAX) is removed anyway (`rmTree` in box.mjs: when Node's rm is refused, coreutils' `chmod -R u+rwx` and
  `rm -rf`, which walk folder by folder and never follow a link in the tree): such a run folder stayed on the shared run tmpfs
  with no word until a restart (two of them could fill it: 507 for every client), and a purge of such a user was a 500 every
  time; a run folder that still will not go is logged. The scrub puts the home and its kept folders back to 0700 and kept files to
  0600, and writes a kept JSON file anew: a box that chmodded them made every later box of that user fail until a purge.
- Runner: the watchdog's disk count and the scrub read folder names as bytes: a box that named a folder with a byte that is not
  UTF-8 (`$'\xff'`) hid all under it from `maxBytes` and `maxEntries`, and then made the scrub fail for every later box of that
  user until a purge. `HB_HARNESSES` items are trimmed and an unknown one stops the service at start; `HB_MODELS_<ID>`
  items are trimmed; `HB_LISTEN` takes `[v6]:port`.
- Client: neither `socketPath` nor `url` is refused (node:http sent the token to localhost:80); a `url` that is not `http:` is refused (an `https:` URL sent the token in clear to a TLS port); an IPv6 `url` works.
- Client: `events()` rejects with the service's error code (`unknown_run`, `too_many_streams`), as every other call does.
- Package: `engines` is Node 24.2 or later, where `import.meta.main` exists (on 24.0 and 24.1 `node src/server.mjs` exited 0 at
  once, without a word). An ended run whose validator failed counts its result's text and stderr in `keptBytes`.
- Docs: the README's threat model and docs/adapters.md describe the SNI check and what it does not look at; the run folders'
  tmpfs is sized for queued runs too (their files are written at admission); `LoginView.status` has no
  `harness`; README's example imports `readOut`; adapters.md on events and prompts.

## 0.3.0

- Runner: `run({ webSearch: true })` turns on the CLI's own server-side web search for adapters that declare `webSearch`
  (Claude Code: `WebSearch` out of `--disallowedTools` and into `--allowedTools`, WebFetch and MCP tools still denied; Codex:
  `-c web_search=live` in place of `web_search=disabled`, its sandbox's network still off). Grok has none and refuses it. The box's
  host lists are unchanged. Without it the CLI arguments are the 0.2.0 ones (Claude Code's in another order, Codex's with one more
  `-c web_search=disabled`, below). `detect()` rows carry `webSearch`; `job.command` gets `webSearch`.
- Adapters: Claude Code's `--disallowedTools` (and with webSearch `--allowedTools`) come before `--strict-mcp-config --restricted
  --no-session-persistence` instead of last. Both take every value up to the next option, so a leading element of the caller's
  args that is no option (`Read`, say) became a deny rule, in 0.2.0 too, and with webSearch's `--allowedTools` last it would have
  become an allow rule. Now it is neither, with webSearch or without (checked with Claude Code 2.1.300 against a mock API).
- Service: a client entry may set `"webSearch": true` and `"events": true` (default false; another value stops the service at
  start). `POST /v1/runs` takes `webSearch` and `events`; asking for one the client is not allowed is a 400
  (`web_search_not_allowed`, `events_not_allowed`; `web_search_unsupported` for Grok). `events: true` puts the CLI's JSON events
  in `result.events` (2000 events and 1 MiB per run, 64 KiB and 64 levels of nesting per event, `eventsTruncated`): each stdout
  line that parsed as a JSON object, serialized again from the parsed object (not the bytes printed: numbers normalized, a
  repeated key's last value). They are kept as the JSON text measured on arrival and written into answers as such; an event
  that does not serialize or is too deep becomes `{ type, truncated: true }`, and a run's answer, SSE events included, falls back
  to the run without its events rather than throwing. Ended runs' kept events count against the 256 MiB at their in-memory size
  (an active run's once it ends). Runs without the fields are unchanged.
- Adapters: without webSearch, Codex gets `-c web_search=disabled` once more after the caller's args, right before `-`. Codex
  takes the last `-c` for a key, so a caller's `-c web_search=live` (or `--config=web_search=live`, `-cweb_search=live`) overrode
  the adapter's earlier one, in 0.2.0 too; now it does not, for any client (checked with Codex 0.162.1 against a mock API). With
  webSearch the arguments are as before.
- Service: a client without `webSearch` may not spell web search in `args` (400 `web_search_not_allowed`). For such a client an
  element with a `\uXXXX` or `\UXXXXXXXX` escape (a backslash before anything else, such as a Windows path, is none) or a
  `--settings` value that is not inline JSON (trimmed, a JSON object; anything else Claude Code may open as a file) is a 400
  `bad_args`. A check by spelling, not a boundary; other options in `args` still widen the CLI. It reads no option's meaning, so
  some `args` that 0.2.0 passed are now a 400 for such a client, also ones that could not turn search on: a deny rule naming
  `WebSearch`, a prompt-like value that mentions web search (`--append-system-prompt "Never use web search."`), an escape such
  as `\u00e9` in any element.
- Runner: a stdout line that parses as a JSON array is no event, like a scalar or `null` before it: `onEvent` and the adapter's
  `event` no longer see it (it reached `result.events` as an array).
- Service: a forgotten ended run (memory cap, run cap, keepMs) clears its expiry timer and drops its events, outputs and result,
  so the 30-minute timer no longer keeps every forgotten run in memory.
- Adapters: Codex's stage reads its item-type table by own keys only (`constructor`, `__proto__` and the like are plain stages);
  stages, error texts and a truncated event's type are cut on a code point boundary. The service's `models` and the runner's
  `bins` and `pins` are read by own keys.
- Service: `GET /v1/harnesses` rows carry `webSearch` (the adapter supports it).
- `harnessbox/client`: types for `webSearch`, `events`, `result.events`, `result.eventsTruncated` and the harness list's `webSearch`.
- `harnessbox/client`: `events()` splits the stream's lines at `\n` only. Its regex also ended a line at U+2028 or U+2029, which
  `JSON.stringify` leaves raw in strings (a search result's title, the last message), and the run then failed with `bad_event`, in
  0.2.0 too. The service now writes those two as `\u2028` and `\u2029` in every run it sends (the same JSON), so a client copied
  from an earlier release reads them too.

## 0.2.0

- The service: `node src/server.mjs` (the image's default command) serves an HTTP API on a unix socket (or a private TCP port)
  to client apps, each with its own bearer token and users under `/homes/<client>/<user>/<harness>`: harness status, logins
  with URL/code relay, logout, purge, and runs with files in, read-only folders, outputs back, a no-network validator with an
  empty home, SSE events and cancel (docs/service.md). `harnessbox/client` is its dependency-free client.
- Runner: user ids may be `scope/user`; `run()` takes `boxDir`, `model`, `onStart`, and `onEvent` gets `{ stage }`; `exec()` takes
  `boxDir`, `signal` and `home` (a throwaway home, no lock). `boxArgs()` takes `boxDir`.
- `harnessbox/client`: an event whose data is not JSON rejects `events()` with `bad_event` instead of throwing in the stream
  listener (which ended the calling app's process).
- The service reads `HB_MAX_OUTPUT_BYTES` (a run's stdout + stderr, default 8 MiB) and refuses to start on a bad value.
- Deploy: `deploy/service-smoke.mjs`, `deploy/move-homes.sh`; compose shows the service with a client app sharing the socket.
- Give the service test preflight the x64 loader alias so its real sandbox tests run on both supported architectures.
- Reserve run admission before staging concurrent uploads; include file copies in the file-count cap and allow replacing a login at its waiting-login cap.
- Preserve binary output bytes through the service; add `readOutBytes()` alongside the existing text reader.
- Skip symlinked credential directories when migrating homes.

## 0.1.1

- Stop boxes when disk usage cannot be inspected, and stream directory entries within the entry budget.
- Bound cumulative job stdout and stderr with `maxOutputBytes` (8 MiB by default).
- Decode split UTF-8 output correctly and contain rejected async `onEvent` callbacks.
- Cancel lock and slot waiters promptly. `close()` now cancels queued work, prevents new boxes, and can be awaited for cleanup.
- Require the seccomp filter, bubblewrap and socat at startup; reject invalid resource limits and duplicate harness ids.
- Serialize concurrent capability detection over the shared probe homes.
- Expose the read-only `/usr/lib64` loader path at `/lib64` for x64 ELF binaries.
- Include the probe, deployment kit, documentation and TypeScript declarations in package tarballs.
- Add isolated consumer checks and CI that requires working bubblewrap user namespaces.

Only Linux arm64 and x64 are supported. One process must exclusively own each homes root. Storage watchdogs remain soft limits;
the host app owns job-folder cleanup and may need filesystem quotas for hard storage limits.
