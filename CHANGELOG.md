# Changelog

## Unreleased

### Added

- Added initial P0 WireGuard runtime support: REST/gRPC config parsing, runtime peer fields, Linux `ip`/`wg` interface application, peer validation, and `wg show <iface> transfer` traffic delta parsing.
- Added initial WireGuard peer online-state reporting by parsing recent `wg show <iface> dump` handshakes and merging them into the existing node `/alive` report path.

### Known Gaps

- Full dual-node GOST relay+QUIC routing, WSS compatibility mode, overseas exit NAT, speed-limit enforcement, and GitHub Actions relay-path verification are not complete.
