# Changelog

## Unreleased

### Added

- Added initial P0 WireGuard runtime support: REST/gRPC config parsing, runtime peer fields, Linux `ip`/`wg` interface application, peer validation, and `wg show <iface> transfer` traffic delta parsing.
- Added initial WireGuard peer online-state reporting by parsing recent `wg show <iface> dump` handshakes and merging them into the existing node `/alive` report path.
- Added a tested WireGuard GOST TUN relay runtime slice: entry nodes can start GOST TUN over `relay+quic`/`relay+wss` and install source-based policy routing for the WireGuard CIDR, while exit nodes can start the matching GOST TUN listener and apply iptables NAT for the WireGuard CIDR.

### Known Gaps

- Real dual-node GOST relay+QUIC/WSS integration evidence, runtime health reporting, speed-limit enforcement, and GitHub Actions relay-path verification are not complete.
