# WireGuard Runtime Test Notes

## Covered By Unit Tests

- `core/wireguard`: validates Linux WireGuard config rendering, peer field validation, transfer delta parsing, peer online-state parsing from recent `wg show <iface> dump` handshakes, GOST TUN relay entry command planning, source-based policy route application, exit listener command planning, and exit NAT command application.
- `node`: validates online-device merge and deduplication before reporting to the panel `/alive` path.

## Local Check

```bash
PATH=/usr/local/go/bin:$PATH GOEXPERIMENT=jsonv2 go test ./core/wireguard ./node -count=1
```

This is a test command only. Release builds must still run through GitHub Actions.

## Remaining Evidence Gaps

- No full real-machine integration proof yet for `WireGuard access -> domestic entry termination -> GOST relay+QUIC -> overseas exit NAT`.
- No GitHub Actions relay-path verification yet.
- No WireGuard peer speed-limit enforcement evidence yet.
- WSS remains compatibility mode, not the default tunnel mode.
