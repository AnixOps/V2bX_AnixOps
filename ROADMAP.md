# Roadmap

## P0: WireGuard Protocol Support

Priority: P0, above ordinary v2.4.x/v2.5.0 hardening work while the panel can issue WireGuard subscriptions.

Target path:

```text
WireGuard access -> domestic entry termination -> GOST relay+QUIC -> overseas exit NAT
```

Current slice:

- V2bX parses WireGuard node config from REST and gRPC.
- V2bX receives peer IP, peer public key, and preshared key from panel user sync.
- The `wireguard` core applies a Linux WireGuard interface through `ip` and `wg`.
- Peer traffic deltas are parsed from `wg show <iface> transfer`.
- Initial peer online state is parsed from recent `wg show <iface> dump` handshakes and merged into the existing online report path.

Remaining before production-complete:

- Full GOST relay+QUIC routing between domestic entry and overseas exit.
- One-click WSS compatibility mode through GOST relay+WSS; WSS is compatibility mode, not the default.
- Overseas exit NAT runtime and evidence.
- Speed-limit enforcement for WireGuard peers.
- GitHub Actions relay-path verification and release artifacts from tag builds.
