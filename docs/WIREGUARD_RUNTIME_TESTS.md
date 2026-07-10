# WireGuard Runtime Test Notes

## Covered By Unit Tests

- `core/wireguard`: validates Linux WireGuard config rendering, peer field validation, peer credential refresh, IPv4-only GOST relay guards, runtime-health defaults, transfer delta parsing, peer online-state parsing from recent `wg show <iface> dump` handshakes, per-peer Linux `tc` shaping/policing, GOST TUN relay entry command planning, source-based policy route application, stateful entry/exit firewall application, optional exit NAT, and the invariant that an exit role never creates a local WireGuard interface or reports user-peer traffic.
- `node`: validates online-device merge and deduplication before reporting to the panel `/alive` path.
- `api/grpc`: fingerprints deterministic node-config responses so unchanged WireGuard settings do not trigger a full runtime reload; relay or credential changes produce a new fingerprint.

## CI Check

GitHub Actions runs the full Go suite and the focused `WireGuard relay and peer
limit contract` job (`go test ./core/wireguard ./node -count=1`) before both
normal and `-rc.N` release artifacts are built. Only strict `vX.Y.Z` and
`vX.Y.Z-rc.N` tags publish GitHub releases. Local checkout builds and test runs
are intentionally not part of the release procedure.

For a valid release or RC tag, the release workflow additionally runs the
privileged `scripts/wireguard_relay_integration.sh` acceptance path for both
`relay+quic` and `relay+wss`. It creates isolated client, entry, exit, and
HTTP-target network namespaces; starts real V2bX WireGuard cores for entry and
exit; then requires an HTTP request to pass through WireGuard, entry policy
routing, the selected GOST relay transport, exit NAT, and the return path. The
entry and exit namespaces use a default-DROP `FORWARD` policy, so the test also
proves that V2bX installs stateful return traffic handling rather than relying
on a permissive host firewall. The GitHub release job cannot publish until both
jobs succeed, and uploads namespace
diagnostics on success or failure.

## Remaining Evidence Gaps

- `v2.5.0-rc.6` passed the privileged GitHub Actions QUIC and WSS namespace
  acceptance jobs. The workflow is the required CI evidence source for the
  real WireGuard/GOST/NAT route path.
- The GitHub Actions namespace test proves a production-shaped route but does
  not replace geographically separated domestic-entry and overseas-exit
  latency, firewall, or carrier-path evidence.
- No privileged two-machine WireGuard peer speed-limit evidence yet.
- Runtime health is reported through REST `/api/v2/node/runtime-health` or the gRPC node-log channel; it does not prove end-to-end reachability through the overseas exit.
- The WSS namespace test creates a short-lived CA certificate, starts the exit
  listener with that certificate, and requires the entry to verify it with SNI.
  It still does not replace production certificate rotation or geographically
  separated route evidence; WSS remains compatibility mode.
