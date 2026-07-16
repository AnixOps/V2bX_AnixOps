# Changelog

## Unreleased

### Added

- Added the opt-in official plugin Supervisor with signed ZIP/tar/tar.gz Agent
  entrypoint extraction, immutable manifest/artifact verification, persisted
  lifecycle journal replay, Unix gRPC health checks, and the executable
  `machine-telemetry` reference package.
- Added `operation.cancel:v1` handling for running, queued, repeated, unknown,
  and session-teardown cases, plus unexpected plugin-process exit observation.

- Added a tag-pinned release installation guide and legacy migration runbook for fresh installs, same-fork updates, upstream config mapping, WireGuard canaries, rollback, and operator evidence.
- Hardened the Linux release installer with ZIP SHA-256 verification, exact-tag management script retrieval, previous-binary backups, and automatic binary restoration when restart fails; it continues to install from GitHub Release assets without cloning or local builds.
- Added initial P0 WireGuard runtime support: REST/gRPC config parsing, runtime peer fields, Linux `ip`/`wg` interface application, peer validation, and `wg show <iface> transfer` traffic delta parsing.
- Added initial WireGuard peer online-state reporting by parsing recent `wg show <iface> dump` handshakes and merging them into the existing node `/alive` report path.
- Added a tested WireGuard GOST TUN relay runtime slice: entry nodes can start GOST TUN over `relay+quic`/`relay+wss` and install source-based policy routing for the WireGuard CIDR, while exit nodes can start the matching GOST TUN listener and apply iptables NAT for the WireGuard CIDR.
- Added per-peer and node-level Linux `tc` shaping with dynamic-limit convergence, traffic-cursor rollback after rejected panel reports, and IPv4-only relay validation.
- Added GOST process supervision with cleanup/restart backoff and panel-visible WireGuard runtime health reporting over REST and gRPC.
- Added a release-gated, privileged GitHub Actions acceptance path that drives a real client WireGuard interface through V2bX entry routing, GOST `relay+quic` and certificate-verified `relay+wss`, V2bX exit NAT, and an isolated HTTP target.
- Made the WireGuard exit role relay-only: it no longer creates a local WireGuard interface, receives peer credentials, or reports user-peer counters.
- Prevented unchanged gRPC node-config responses from repeatedly rebuilding the WireGuard runtime.
- Added secure WSS relay configuration: entry nodes require SNI/certificate verification, exit nodes require certificate/private-key paths, and the RC/tag namespace acceptance matrix verifies both QUIC and WSS routes.

### Fixed

- Made enabled plugin configuration restart and health-check the real process,
  restore the previous config/process on failure, and fail closed when recovery
  cannot be completed.
- Treated a process that exits after forced kill as successfully stopped instead
  of returning the already-expired graceful-shutdown context error.

### Known Gaps

- `v2.5.0-rc.6` passed the release-gated QUIC and WSS namespace acceptance jobs. Real geographically separated dual-node evidence and real-client import evidence are still not complete. Runtime health reporting and GOST process supervision do not replace those production observations.
