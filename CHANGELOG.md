# Changelog

## 0.1.1

- Stop boxes when disk usage cannot be inspected, and stream directory entries within the entry budget.
- Bound cumulative job stdout and stderr with `maxOutputBytes` (8 MiB by default).
- Decode split UTF-8 output correctly and contain rejected async `onEvent` callbacks.
- Cancel lock and slot waiters promptly. `close()` now cancels queued work, prevents new boxes, and can be awaited for cleanup.
- Require the seccomp filter, bubblewrap and socat at startup; reject invalid resource limits and duplicate harness ids.
- Serialize concurrent capability detection over the shared probe homes.
- Include the probe, deployment kit, documentation and TypeScript declarations in package tarballs.
- Add isolated consumer checks and CI that requires working bubblewrap user namespaces.

Only Linux arm64 and x64 are supported. One process must exclusively own each homes root. Storage watchdogs remain soft limits;
the host app owns job-folder cleanup and may need filesystem quotas for hard storage limits.
