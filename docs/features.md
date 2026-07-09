# Feature Status

## Product Feature Matrix

| Area | Feature | Status | Evidence | Notes |
|------|---------|--------|----------|-------|
| Core | VMess/VLESS/Trojan/Shadowsocks runtime | Implemented | Xray and Sing-box cores | Keep panel compatibility tests current. |
| Core | Hysteria2 runtime | Implemented | Hysteria2 core | Keep auth and traffic paths covered. |
| Core | WireGuard user access over dual-node relay | Partial/P0 | `core/wireguard`, REST/gRPC parsing, peer field sync, focused unit tests | Initial domestic-entry WireGuard interface and peer traffic slice exists. Full GOST relay+QUIC, WSS compatibility mode, overseas exit NAT, online/limit integration, and GitHub Actions relay verification remain incomplete. |
| WireGuard | WireGuard subscription runtime contract | Partial/P0 | `api/panel.NodeInfo`, `api/panel.UserInfo`, gRPC `extra` mapping | Requires matching `v2board_AnixOps` panel runtime peer fields. |
| WireGuard | GOST relay+QUIC tunnel backend | Planned/P0 | Relay config fields parsed and GOST process hook reserved | Complete routing and exit NAT before marking implemented. |
| WireGuard | WSS compatibility tunnel mode | Planned | `tunnel_type=wss` and relay `wss_compat` recognized | WSS is compatibility mode, not default. |

## Not Implemented Or Not Complete

| Feature | Status | Why It Is Not Complete |
|---------|--------|------------------------|
| P0 WireGuard dual-node relay | Partial/P0 | Initial entry WireGuard runtime and traffic delta parsing exist, but full GOST relay+QUIC routing, WSS compatibility, overseas exit NAT, online state, speed limits, real integration tests, and GitHub Actions relay-path verification remain. |
| Release builds | Policy | Release builds must run in GitHub Actions; do not produce local release artifacts. |
