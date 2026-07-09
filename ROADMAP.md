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
- V2bX now has a first tested GOST TUN relay runtime slice: entry nodes can start GOST TUN over `relay+quic` or `relay+wss` and install WireGuard-CIDR policy routing; exit nodes can start the matching listener and apply iptables NAT for the WireGuard CIDR.

Remaining before production-complete:

- Real-machine GOST relay+QUIC routing evidence between domestic entry and overseas exit.
- One-click WSS compatibility mode through GOST relay+WSS; WSS is compatibility mode, not the default.
- Overseas exit NAT integration evidence and runtime health reporting.
- Speed-limit enforcement for WireGuard peers.
- GitHub Actions relay-path verification and release artifacts from tag builds.
