# Changelog

## Unreleased

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
