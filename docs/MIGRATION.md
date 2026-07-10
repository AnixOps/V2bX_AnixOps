# V2bX Legacy Migration And Rollback

This plan covers migration to the `v2.5.0` release line without claiming that
all historical node configurations are interchangeable. Move one node at a
time, retain the old node until the replacement reports correctly, and keep a
tested rollback path.

## Supported Paths

| Source | Support level | Migration method |
|---|---|---|
| Earlier `V2bX_AnixOps` release | Supported | Back up `/etc/V2bX`, install an exact release tag, preserve config, restart and verify |
| Earlier upstream V2bX configuration | Operator-guided | Translate config fields and validate with a canary node before production cutover |
| WireGuard node without relay runtime | Operator-guided | Add Linux/GOST prerequisites and migrate one entry/exit pair with real client evidence |
| Unrelated node agent | Not automatic | Build a field mapping and re-register the node with a new panel API key |

## Preparation

1. Record the installed version, service state, panel node ID, transport, core,
   and listening ports.
2. Back up configuration and auto-register credentials with restrictive file
   permissions.
3. Capture recent service logs and current panel traffic/online counters.
4. Confirm that the target panel release exposes the same node API transport.
5. Prepare a maintenance window and keep the old executable available.

```bash
sudo systemctl status V2bX --no-pager
sudo install -d -m 0700 /root/v2bx-migration-backup
sudo tar -C /etc -czf /root/v2bx-migration-backup/V2bX-config.tgz V2bX
sudo sha256sum /root/v2bx-migration-backup/V2bX-config.tgz \
  | sudo tee /root/v2bx-migration-backup/V2bX-config.tgz.sha256
sudo cp -a /usr/local/V2bX/V2bX /root/v2bx-migration-backup/V2bX.binary
```

Never include `/root/v2bx-migration-backup` in a public repository, support
ticket, or unencrypted cloud bucket. The configuration may contain API keys,
certificate paths, and auto-register credentials.

## Same-Fork Upgrade

The release installer preserves `/etc/V2bX/config.json`, rule data, geo files,
and credentials. It verifies the downloaded ZIP before replacing the binary and
keeps the previous binary under `/usr/local/V2bX/backups/`.

```bash
export TARGET=v2.5.0
curl -fsSL \
  "https://raw.githubusercontent.com/AnixOps/V2bX_AnixOps/${TARGET}/scripts/install.sh" \
  -o /tmp/v2bx-install.sh
sudo bash /tmp/v2bx-install.sh "${TARGET}"
rm -f /tmp/v2bx-install.sh
```

Then verify in this order:

1. `sudo v2bx-anixops status` shows an active service.
2. `sudo v2bx-anixops log` contains no configuration or authentication error.
3. The panel reports the node heartbeat and current configuration pull.
4. A non-production user is synchronized and traffic/online reports appear.
5. Keep the old node in service until the new node has passed the agreed
   observation window.

If restart fails, the installer restores the previous executable automatically.
For a functional rollback after startup, install the prior release tag and then
restore the backed-up configuration only if the target configuration changed:

```bash
sudo v2bx-anixops update v2.4.9
sudo systemctl status V2bX --no-pager
```

Use an actually available, previously verified tag in place of `v2.4.9`.

## Upstream Or Foreign V2bX Configurations

Do not overwrite the current configuration with the wizard until field mapping
is complete. Compare the old JSON with
[`../example/config.json`](../example/config.json) and map at least:

- `ApiHost`, `ApiKey`, `NodeID`, and `NodeType`.
- Core type and core-specific settings.
- HTTP versus gRPC transport fields.
- Certificates, DNS provider environment, and file ownership.
- Traffic thresholds, device/online settings, and send/listen IPs.
- Custom inbound/outbound, DNS, route, and geo data paths.

Create a separate configuration copy, start only a canary node, and verify its
panel behavior before moving the production process. Rotate the API key when a
configuration was copied from an unknown or previously shared environment.

## WireGuard Entry/Exit Migration

WireGuard migration is not a regular core swap. The rollout must prove the
entire path:

`client WireGuard -> entry -> GOST relay+QUIC -> exit NAT -> target`

WSS is a compatibility mode, not the default transport. Before cutover:

1. Install `iproute2`, `wireguard-tools`, `iptables`, and make `/dev/net/tun`
   available on both entry and exit nodes.
2. Install a checksum-verified GOST v3 binary at the configured `GostPath`.
3. Create a new WireGuard node/protocol in the matching panel and generate new
   node API keys and WireGuard keys. Do not reuse secrets copied from an old
   panel without rotation.
4. Start one canary entry/exit pair with a non-production peer CIDR.
5. Verify configuration pull, interface creation, peer handshake, client
   traffic, panel traffic report, online report, exit NAT, and cleanup.
6. Verify WSS certificate/SNI behavior only if the fallback is required.
7. Move users in batches and preserve the old route until each batch is stable.

If the canary fails, stop the new node, restore the previous service/binary,
and revert the panel subscription/node assignment. Do not attempt a database
rollback for a node runtime failure unless a panel database migration was part
of the same approved change.

## Evidence To Retain

- Exact panel and node tags, release asset checksums, and GitHub Actions URLs.
- Config backup checksum and storage location.
- Pre/post node counters and a canary user ID with secrets removed.
- WireGuard entry/exit test evidence when relevant.
- Operator, maintenance window, and rollback decision record.
