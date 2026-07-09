# TODO

## P0: WireGuard Dual-Node Entry/Exit Runtime

- [x] Parse panel `wireguard` node configs over REST and gRPC.
- [x] Receive panel-managed WireGuard peer IP, public key, and preshared key from user sync.
- [x] Add a `wireguard` core that applies Linux WireGuard interfaces with `ip` and `wg`.
- [x] Report peer traffic deltas from `wg show <iface> transfer`.
- [x] Integrate initial online-state reporting for WireGuard peers from recent `wg show <iface> dump` handshakes.
- [ ] Complete GOST relay+QUIC route orchestration for the default entry-to-exit tunnel.
- [ ] Complete GOST relay+WSS compatibility mode; WSS is not the default.
- [ ] Add overseas exit NAT runtime support and evidence.
- [ ] Integrate speed-limit enforcement for WireGuard peers.
- [ ] Add GitHub Actions relay-path verification for `WireGuard access -> domestic entry termination -> GOST relay+QUIC -> overseas exit NAT`.

Release builds must be produced by GitHub Actions only.
