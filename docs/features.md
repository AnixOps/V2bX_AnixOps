# Feature Status

## Product Feature Matrix

| Area | Feature | Status | Evidence | Notes |
|------|---------|--------|----------|-------|
| Core | VMess/VLESS/Trojan/Shadowsocks runtime | Implemented | Xray and Sing-box cores | Keep panel compatibility tests current. |
| Core | Hysteria2 runtime | Implemented | Hysteria2 core | Keep auth and traffic paths covered. |
| Core | WireGuard user access over dual-node relay | Partial/P0 | `core/wireguard`, REST/gRPC parsing, peer field sync, focused unit tests | Initial domestic-entry WireGuard interface, peer traffic slice, peer online-state reporting, GOST TUN relay command planning, entry policy routing, and exit NAT command application exist. Real dual-node GOST relay+QUIC/WSS evidence, speed-limit integration, and GitHub Actions relay verification remain incomplete. |
| WireGuard | WireGuard subscription runtime contract | Partial/P0 | `api/panel.NodeInfo`, `api/panel.UserInfo`, gRPC `extra` mapping | Requires matching `v2board_AnixOps` panel runtime peer fields. |
| WireGuard | GOST relay+QUIC tunnel backend | Partial/P0 | GOST TUN relay entry/exit command planning and unit tests | Default mode is `relay+quic`; real two-machine relay-path evidence is still required. |
| WireGuard | WSS compatibility tunnel mode | Partial | `tunnel_type=wss` and relay `wss_compat` select `relay+wss` | WSS is compatibility mode, not default; real compatibility evidence is still required. |

## Not Implemented Or Not Complete

| Feature | Status | Why It Is Not Complete |
|---------|--------|------------------------|
| P0 WireGuard dual-node relay | Partial/P0 | Initial entry WireGuard runtime, traffic delta parsing, online-state reporting, GOST TUN relay command planning, entry policy routing, and exit NAT command application exist, but real GOST relay+QUIC/WSS integration, speed limits, runtime health reporting, and GitHub Actions relay-path verification remain. |
| Release builds | Policy | Release builds must run in GitHub Actions; do not produce local release artifacts. |
