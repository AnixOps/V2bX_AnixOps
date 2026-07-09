# Changelog

## Unreleased

### Added

- Added initial P0 WireGuard runtime support: REST/gRPC config parsing, runtime peer fields, Linux `ip`/`wg` interface application, peer validation, and `wg show <iface> transfer` traffic delta parsing.

### Known Gaps

- Full dual-node GOST relay+QUIC routing, WSS compatibility mode, overseas exit NAT, online-state integration, speed-limit enforcement, and GitHub Actions relay-path verification are not complete.
