# Changelog

## Unreleased

### Added

- `nftables-forward` now verifies the live kernel table immediately after an
  apply and continuously while active. The plugin's Unix-socket health endpoint
  changes to `NOT_SERVING` when the managed table, chain, rule identity, DNAT
  destination, or counter-free rule shape drifts from the signed configuration.

### Known Gaps

- This local readiness signal is the first alpha.6 building block. Structured
  ruleset fingerprints and per-rule counters still need transport to Control
  before topology promotion can use live kernel observation as release proof.

## 4.0.0-alpha.5 - 2026-07-17

### Added

- Added `nftables-forward` 1.1.0 runtime-state and signed cleanup support. The
  plugin accepts the canonical Control package contract, starts safely with
  `apply=false` and an empty rule set, and rejects active plans without rules
  or with rollback disabled.
- Added a durable private ownership journal containing the exact pre-apply
  nftables table snapshot and managed identity. Journal publication is atomic
  and fsynced before applying rules, while successful rollback removes it only
  after the original state is restored.
- Added `--anixops-state`, `--anixops-cleanup`, and `--anixops-validate` entry
  modes for Supervisor-owned recovery and preflight validation.

### Fixed

- Restored interrupted nftables ownership before every new apply, including
  hard process death and Agent restart. Rollback now checks whether the current
  table exists before deleting it, so missing or externally removed state does
  not turn cleanup into an invalid nftables transaction.
- Extended privileged namespace acceptance with `SIGKILL`, persisted-journal,
  restart recovery, TCP/UDP traffic, created-table deletion, and exact
  pre-existing table restoration evidence.

### Known Gaps

- This runtime remains opt-in and canary-only. Control must keep topology
  execution disabled until signed package import, staging restore, fallback,
  rollout, live kernel-observed health, and 72-hour canary evidence are
  recorded. Stable 4.0 remains unauthorized.

## 4.0.0-alpha.4 - 2026-07-17

### Added

- Added the signed `machine-telemetry` 1.1.0 Agent package runtime with a
  versioned local Unix gRPC snapshot RPC and bounded gopsutil-backed metrics.
- Added Supervisor telemetry aggregation and heartbeat namespacing, including
  plugin health, sample age, partial-failure handling, and deterministic metric
  ordering.

### Fixed

- Added context-aware Supervisor lifecycle admission and retryable close/cleanup
  fencing so concurrent operations cannot race shutdown or lose ownership state.
- Propagated operation deadline and cancellation decisions through queueing,
  handler execution, and plugin locks; timeout observations now use one stable
  wire message for Control reconciliation.
- Added a release-tag gate that requires CLI, registration, Docker, README,
  install/migration guides, and Changelog versions to match before publishing.

### Known Gaps

- This is an opt-in alpha. It does not imply production forwarding cutover;
  topology apply, Secret-ID materialization, and sustained canary evidence
  remain required before stable 4.0 authorization.

## 4.0.0-alpha.3 - 2026-07-17

### Changed

- Isolated every enabled official-plugin Supervisor by the final registered
  node ID. Fresh installations now keep plugin artifacts, operation journals,
  runtime state, and Unix sockets below a node-specific `nodes/<node_id>`
  namespace, so two nodes in one Agent process cannot share plugin state.
- Bound each node-scoped Supervisor and Agent Control stream to the same
  Control endpoint, TLS identity, and API-key fingerprint. Configurations that
  reuse a numeric node ID across different Controls now fail closed instead of
  mixing credentials or routing operations to another node's Supervisor.
- Preserved an existing non-namespaced Supervisor layout for a true
  single-node upgrade when legacy plugin state or sockets are present. A fresh
  single-node installation uses the namespaced layout; multi-node startup
  rejects ambiguous legacy state and requires an explicit migration.

### Fixed

- Made controller startup and teardown track acquired limiter and core-node
  resources independently, preventing cleanup of resources that were never
  created after a partial failure and preserving deterministic retry behavior.
- Serialized Agent lifecycle and file-watcher reload transactions. A failed
  configuration load leaves the active configuration unchanged, while staged
  controller cleanup prevents leaked or double-removed resources during
  restart and reload failures.
- Bounded Supervisor shutdown per node and changed aggregate close failures
  from process panics to explicit error logs, so a stuck plugin cannot block a
  configuration reload indefinitely or crash the Agent teardown path.

### Known Gaps

- This remains an opt-in alpha Supervisor release. Declarative topology apply,
  Secret-ID materialization, composed GOST-to-NAT deployment, and sustained
  production canary evidence are not complete; production traffic cutover is
  not implied by this release.

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
