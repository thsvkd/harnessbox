# Changelog

## 0.3.0

- Runner: `run({ webSearch: true })` turns on the CLI's own server-side web search for adapters that declare `webSearch`
  (Claude Code: `WebSearch` out of `--disallowedTools` and into `--allowedTools`, WebFetch and MCP tools still denied; Codex:
  `-c web_search=live` in place of `web_search=disabled`, its sandbox's network still off). Grok has none and refuses it. The box's
  host lists are unchanged. Without it the CLI arguments are the 0.2.0 ones. `detect()` rows carry `webSearch`; `job.command` gets
  `webSearch`.
- Service: a client entry may set `"webSearch": true` and `"events": true` (default false; another value stops the service at
  start). `POST /v1/runs` takes `webSearch` and `events`; asking for one the client is not allowed is a 400
  (`web_search_not_allowed`, `events_not_allowed`; `web_search_unsupported` for Grok). `events: true` puts the CLI's JSON events
  in `result.events` (2000 events and 1 MiB per run, 64 KiB and 64 levels of nesting per event, `eventsTruncated`): each stdout
  line that parsed as a JSON object, serialized again from the parsed object (not the bytes printed: numbers normalized, a
  repeated key's last value). They are kept as the JSON text measured on arrival and written into answers as such; an event
  that does not serialize or is too deep becomes `{ type, truncated: true }`, and a run's answer, SSE events included, falls back
  to the run without its events rather than throwing. Ended runs' kept events count against the 256 MiB at their in-memory size
  (an active run's once it ends). Runs without the fields are unchanged.
- Service: a client without `webSearch` may not spell web search in `args` (400 `web_search_not_allowed`): Codex's later
  `-c web_search=live` overrode the adapter's `web_search=disabled`, in 0.2.0 too. For such a client an element with a `\u`
  escape or a `--settings` file path is a 400 `bad_args`. A check by spelling, not a boundary; other options in `args` still widen
  the CLI.
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
