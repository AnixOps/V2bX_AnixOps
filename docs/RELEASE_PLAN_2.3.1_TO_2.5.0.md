# V2bX AnixOps Release Plan: v2.3.1 to v2.5.0

Created: 2026-07-09

This plan defines the release line after `v2.3.1`. The target is to make `v2.5.0` the formal stable stop line for this cycle. After `v2.5.0`, only security fixes, production regressions, packaging fixes, and compatibility fixes should be accepted on the 2.x stable line unless a new release plan is approved.

## Release Principles

- Keep `dev_new` as the active integration branch.
- Release only from a green commit with tests, build smoke checks, and release notes.
- Treat REST and gRPC transports as first-class compatibility targets until `v2.5.0`.
- Avoid new large features after `v2.4.0`; use `v2.4.x` for hardening.
- Do not introduce breaking config changes without a compatibility shim, migration notes, and example config updates.
- Keep node behavior compatible with the matching `v2board_AnixOps` panel APIs.

## Version Targets

### P0 WireGuard Runtime Interlock

Purpose: close the immediate gap where the panel can issue WireGuard subscriptions but V2bX cannot apply the entry runtime.

Scope:
- Parse `wireguard` node configs over REST and gRPC.
- Receive panel-managed peer IP, peer public key, and preshared key from user sync.
- Add a `wireguard` core that applies the Linux WireGuard interface through `ip` and `wg`.
- Report peer traffic deltas from `wg show <iface> transfer`.
- Report initial peer online state from recent `wg show <iface> dump` handshakes through the existing `/alive` path.
- Add first tested GOST TUN relay runtime slice for entry policy routing, `relay+quic`/`relay+wss` command selection, exit listener command planning, and exit iptables NAT command application.
- Keep the target path documented as `WireGuard access -> domestic entry termination -> GOST relay+QUIC -> overseas exit NAT`.

Known remaining gaps:
- `v2.5.0-rc.6` passed release-gated GitHub Actions network-namespace routes
  for both QUIC and certificate-verified WSS with real WireGuard, GOST, and NAT
  processes. Real-machine GOST relay orchestration, overseas carrier-path/NAT
  observation, client import, and production speed-limit evidence still need
  integration evidence.
- WSS remains compatibility mode, not the default.
- Release builds must still come from GitHub Actions only.

### v2.3.2 - Patch Stabilization

Purpose: close the immediate gap after `v2.3.1` and make the current release safer to install.

Scope:
- Fix packaging, install/update script, and version metadata regressions.
- Verify release assets for Linux `amd64` and `arm64`.
- Confirm REST UniProxy config/user/push/alive compatibility with the panel.
- Confirm gRPC register/config/user/traffic/online/log reporting smoke paths.
- Clean local runtime artifacts from git status and ignore future build/log/debug outputs.
- Update operator docs for install, update, rollback, and config checks.

Exit gate:
- `GOEXPERIMENT=jsonv2 GOWORK=off go test ./...`
- Release workflow builds both Linux assets.
- Manual smoke install/update succeeds on a clean Linux host or container.
- No known credential, API key, or debug log leak in tracked files.

### v2.4.0 - Compatibility Freeze

Purpose: finish transport compatibility and runtime validation before final stabilization.

Scope:
- Make REST and gRPC behavior equivalent for node config, user sync, traffic report, online report, heartbeat, and node logs.
- Add config validation for required fields, transport-specific fields, and unsafe defaults.
- Harden auto-register credential loading, encrypted credential fallback, and clear error messages.
- Stabilize sync manager lifecycle: startup, reconnect, shutdown, and config reload.
- Add regression tests for protocol config parsing across Xray, Sing-box, and Hysteria2 where local tests are practical.
- Document the supported panel/node version matrix.

Exit gate:
- Unit tests and transport-focused tests pass.
- Release assets build from tag without manual patching.
- Config examples cover HTTP, gRPC, auto-register, and encrypted credential usage.
- No planned config shape changes remain for `v2.5.0`.

### v2.4.1 / v2.4.2 - Hardening Patches

Purpose: absorb production feedback without expanding the feature surface.

Allowed scope:
- Bug fixes for config parsing, reconnect loops, traffic accounting, online IP reporting, and install/update scripts.
- Logging improvements that do not expose secrets.
- Compatibility fixes for current panel APIs.
- CI/release workflow fixes.
- Documentation corrections.

Not allowed:
- New protocols.
- New transport modes.
- Breaking config changes.
- Large internal rewrites without a production-blocking reason.

Exit gate:
- The changed package has focused tests.
- Full test suite passes before tagging.
- Release notes include upgrade notes and rollback guidance when relevant.

### v2.5.0 - Formal Stable Stop Line

Purpose: publish the stable 2.x target for this development cycle.

Scope:
- Finalize supported protocol and transport matrix.
- Freeze config field names and example config structure for the 2.x line.
- Confirm release workflow, install script, update command, and rollback path.
- Confirm node and panel compatibility against the selected panel release commit/tag.
- Close or explicitly defer all blockers from the `v2.4.x` hardening cycle.

Exit gate:
- `GOEXPERIMENT=jsonv2 GOWORK=off go test ./...`
- Release workflow succeeds from tag `v2.5.0`.
- Linux `amd64` and `arm64` assets are downloadable and executable.
- Smoke tests cover:
  - HTTP transport startup and user sync.
  - gRPC transport startup and user sync.
  - Traffic report.
  - Online report.
  - Node log report.
  - Graceful shutdown.
- `README.md` and example configs match the released behavior.

Post-`v2.5.0` rule:
- The 2.x stable line accepts only security fixes, severe production bug fixes, panel compatibility fixes, and release packaging fixes.
- New features move to a new planning document and a new development line.

## Compatibility Matrix

Required before `v2.5.0`:

| Area | Required Coverage |
|------|-------------------|
| OS/Arch | Linux amd64, Linux arm64 |
| Transport | HTTP REST + WebSocket sync, gRPC |
| Core | Sing-box, Xray, Hysteria2 |
| Node auth | Static API key, auto-register credential, encrypted credential |
| Reports | Traffic, online IP, heartbeat/status, node logs |
| Operations | Fresh install, update to target version, rollback to prior tag |

## Release Checklist

Run before every tag:

- Push the candidate commit and wait for GitHub Actions to complete the full Go
  suite, focused WireGuard contract checks, formatting checks, and release
  packaging checks.
- Keep local verification limited to `git status --short`, `git diff --check`,
  and removal of stale build artifacts. Do not build or test release candidates
  from the local checkout.

For release candidates:

- Use a strict tag such as `v2.5.0-rc.1`; arbitrary `v*` tags do not publish a
  release.
- Trigger the GitHub Actions release workflow from the candidate commit or tag.
- Verify the uploaded `V2bX-linux-64.zip` and `V2bX-linux-arm64-v8a.zip` artifacts.
- Do not build release candidates from a local checkout.

Tag only after the release notes include:

- Summary of fixes.
- Upgrade notes.
- Config changes, if any.
- Known issues.
- Rollback command or rollback notes.

## Deferred Beyond v2.5.0

- New proxy protocols or large protocol behavior changes.
- New transport modes beyond HTTP/WebSocket and gRPC.
- Major installer redesign.
- Large-scale internal rewrites not required for correctness or security.
- Feature work that requires breaking panel compatibility.
