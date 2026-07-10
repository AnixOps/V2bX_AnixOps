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
- WireGuard relay validation is IPv4-only until an equivalent IPv6 route/forward/NAT path is implemented.
- Per-peer and node-level speed limits converge through Linux `tc`, including dynamic speed-limit changes.
- GitHub Actions runs the full Go suite, relay/limit contract checks, and release-gated privileged QUIC/WSS network-namespace route acceptance jobs; release binaries remain CI-only.
- GOST relay process exits are supervised, retried, and reported as node runtime health to the panel.

Remaining before production-complete:

- Real-machine GOST relay+QUIC routing evidence between domestic entry and overseas exit.
- One-click WSS compatibility mode through GOST relay+WSS; WSS is compatibility mode, not the default.
- Overseas exit NAT integration evidence and real end-to-end health evidence.
