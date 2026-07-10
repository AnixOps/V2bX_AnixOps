# TODO

## P0: WireGuard Dual-Node Entry/Exit Runtime

- [x] Parse panel `wireguard` node configs over REST and gRPC.
- [x] Receive panel-managed WireGuard peer IP, public key, and preshared key from user sync.
- [x] Add a `wireguard` core that applies Linux WireGuard interfaces with `ip` and `wg`.
- [x] Report peer traffic deltas from `wg show <iface> transfer`.
- [x] Integrate initial online-state reporting for WireGuard peers from recent `wg show <iface> dump` handshakes.
- [x] Add first tested GOST TUN relay runtime slice for entry policy routing and exit NAT command application.
- [x] Add a release-gated GitHub Actions network-namespace acceptance path for real WireGuard -> GOST relay+QUIC -> exit NAT routing.
- [ ] Archive a successful RC/tag acceptance artifact and prove GOST relay+QUIC route orchestration on geographically separated domestic-entry and overseas-exit machines.
- [x] Add release-gated GitHub Actions namespace acceptance for GOST relay+WSS compatibility mode; WSS remains non-default.
- [ ] Archive a successful WSS acceptance artifact and prove the compatibility mode on geographically separated machines.
- [ ] Add overseas exit NAT runtime integration evidence.
- [x] Integrate per-peer and node-level WireGuard speed-limit enforcement through Linux `tc`, including dynamic-limit convergence.
- [x] Supervise GOST relay exits, clean up relay state, retry startup, and report runtime health to the panel.
- [x] Add GitHub Actions verification for the `WireGuard access -> domestic entry termination -> GOST relay+QUIC -> overseas exit NAT` contract, including release-gated QUIC/WSS network-namespace route acceptance jobs.

Release builds must be produced by GitHub Actions only.
