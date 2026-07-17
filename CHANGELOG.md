# Changelog

## Unreleased

No changes yet.

## 4.0.0-alpha.2 - 2026-07-17

### Fixed

- Fixed the `nftables-forward` runtime and `--version` output to report the
  official signed package manifest version `1.0.0`.

## 4.0.0-alpha.1 - 2026-07-17

### Added

- Added authenticated, same-origin `plugin.install` delivery for official
  signed manifests and artifacts, with exact size/SHA-256/signature/key-ID
  checks, redirect rejection, 32 MiB bounds, immutable staging publication,
  and replay without a second download.

### Fixed

- Fixed update configuration ownership and same-revision interrupted-operation
  repair. Agent restart now defers automatic plugin restore while a mutating
  operation needs exact replay, joins terminal persistence failures with the
  operation error, and uses Linux parent-death signaling to avoid leaving the
  supervised plugin process running after an Agent crash.

## 3.1.0-alpha.1 - 2026-07-17

### Added

- Added the opt-in official plugin Supervisor with signed ZIP/tar/tar.gz Agent
  entrypoint extraction, immutable manifest/artifact verification, persisted
  lifecycle journal replay, Unix gRPC health checks, and the executable
  `machine-telemetry` reference package.
- Added `operation.cancel:v1` handling for running, queued, repeated, unknown,
  and session-teardown cases, plus unexpected plugin-process exit observation.
- Added the real `nat-egress` official plugin runtime with nftables IPv4/IPv6
  masquerade, fwmark policy routing, interface-bound marked health probes,
  strict conflict/configuration validation, and a crash-safe ownership journal.
- Added privileged `nat-egress` namespace acceptance proving marked forwarded
  traffic follows the plugin policy table and is masqueraded, wrong-mark
  traffic remains isolated, counters increment, normal exit removes the
  ownership journal, and rollback removes or restores owned host state.
- Added Supervisor `plugin.runtime-state` and `plugin.cleanup` capability
  enforcement with stable state paths, signed cleanup after crashes and
  lifecycle transitions, persisted `cleanup_pending`/cleanup-version recovery,
  and per-plugin serialization. A failed update-target cleanup leaves the old
  version disabled; automatic rollback starts it only after cleanup succeeds.
- Added signed auxiliary runtime entrypoints such as
  `runtime-gost-<goos>-<goarch>`, materialized into the immutable plugin
  version directory and reverified byte-for-byte before every start.
- Added the independent `gost-mesh` official plugin runtime. One signed plugin
  process manages aggregate entry/exit tunnels, starts pinned GOST v3.2.6
  children, owns TUN/source-policy state through a crash-safe journal, exposes
  gRPC health, and performs bounded restart with fail-closed cleanup.
- Added mandatory QUIC/WSS mutual TLS, source-bound remote health probes, IPv4
  forwarding and reverse-path-filter preflight, and privileged namespace
  acceptance proving wrong-SNI and unauthorized-client rejection, TCP/UDP
  traffic, transport-family counters, rollback, and preservation of unrelated
  policy state.
- Added a side-effect-free `gost-mesh --anixops-validate` release gate, strict
  canonical config parsing, bounded CIDR arrays, and entry-only policy table and
  priority ownership.

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

- Control production release-signing wiring for `nat-egress` is present, but
  production activation still requires a signed release, topology prerequisites,
  staged canary evidence, and operator approval. `gost-mesh` now has real QUIC
  and WSS runtime evidence; TUIC is intentionally outside GOST Mesh v1 because
  pinned GOST v3.2.6 does not implement it. Control status execution is now
  version-bound; Secret-ID materialization, GOST-to-NAT composition, and
  sustained canary evidence are still pending.
- `v2.5.0-rc.6` passed the release-gated QUIC and WSS namespace acceptance jobs. Real geographically separated dual-node evidence and real-client import evidence are still not complete. Runtime health reporting and GOST process supervision do not replace those production observations.
