# V2bX Release Installation

This guide installs `V2bX_AnixOps` from GitHub Release assets. The installer
downloads one script and the selected release ZIP; it does not clone the
repository and it does not compile Go code on the node host.

Supported release installers are Linux `amd64` and Linux `arm64`. Use a
version-pinned command for production so the installer, release archive, and
management script all come from the same tag.

## Fresh Install

Run as root on Debian/Ubuntu, RHEL-compatible Linux, Alpine, or Arch:

```bash
export VERSION=v2.5.0
curl -fsSL \
  "https://raw.githubusercontent.com/AnixOps/V2bX_AnixOps/${VERSION}/scripts/install.sh" \
  -o /tmp/v2bx-install.sh
sudo bash /tmp/v2bx-install.sh "${VERSION}"
rm -f /tmp/v2bx-install.sh
```

The installer installs base tools when required, downloads the matching
`V2bX-linux-64.zip` or `V2bX-linux-arm64-v8a.zip` asset, verifies its SHA-256
against the release `.dgst` file, and creates the service:

| Path | Purpose |
|---|---|
| `/usr/local/V2bX/V2bX` | GitHub Actions-built node binary |
| `/etc/V2bX/config.json` | Persistent node configuration |
| `/etc/V2bX/credential.json*` | Auto-register credential when used |
| `/usr/local/V2bX/backups/` | Previous binaries retained during update |
| `/usr/local/V2bX/.release-version` | Installed release tag |
| `v2bx-anixops` | Service and configuration manager |

First installation does not start a usable node until configuration is set.
Run the wizard, then inspect and start the service:

```bash
sudo v2bx-anixops initconfig
sudo v2bx-anixops config
sudo v2bx-anixops start
sudo v2bx-anixops status
sudo v2bx-anixops log
```

The wizard needs the panel URL, node ID, node API key, core type, and transport.
For gRPC, also supply `GRPCHost`, TLS preference, SNI, and keepalive as needed.
Do not paste API keys into shell history or public support logs.

## Update And Rollback

Update to an explicit stable tag with the same no-clone path:

```bash
export TARGET=v2.5.0
curl -fsSL \
  "https://raw.githubusercontent.com/AnixOps/V2bX_AnixOps/${TARGET}/scripts/install.sh" \
  -o /tmp/v2bx-install.sh
sudo bash /tmp/v2bx-install.sh "${TARGET}"
rm -f /tmp/v2bx-install.sh
```

The installer preserves `/etc/V2bX`, backs up the existing executable, and
restores that executable automatically if restarting the service fails. The
configuration is intentionally not overwritten. To roll back, install the
previous known-good release tag and then confirm service health:

```bash
sudo v2bx-anixops update v2.4.9
sudo v2bx-anixops status
```

`v2bx-anixops update <tag>` fetches the installer from that exact tag. The
unqualified `update` command uses the integration-branch installer to resolve
the latest stable GitHub Release; use an explicit tag in production.

## Panel Pairing

Use the matching panel release. Create or rotate the node API key in the panel,
then set it in `/etc/V2bX/config.json`. Verify these operations after startup:

1. Node configuration pull succeeds.
2. User list synchronization succeeds.
3. Traffic and online reports arrive at the panel.
4. HTTP/gRPC transport and TLS settings match the panel endpoint.

For a full panel installation, see
[v2board release installation](https://github.com/AnixOps/v2board_AnixOps/blob/v2.5.0/docs/guide/release-installation.md).

## WireGuard Relay Nodes

WireGuard entry/exit nodes require more than the base V2bX install:

1. Linux with `iproute2`, `wireguard-tools`, `iptables`, `tc`, and `/dev/net/tun`.
2. A verified GOST v3 binary on the configured `GostPath`.
3. A panel WireGuard protocol with entry/exit role, relay addresses, peer CIDR,
   and QUIC by default or certificate-verified WSS fallback.
4. One canary entry/exit pair before moving production users.

Install platform packages before starting a WireGuard core on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y iproute2 iptables wireguard-tools
sudo modprobe wireguard || true
test -c /dev/net/tun
```

Obtain GOST only from its upstream release and verify its published checksum.
The release workflow verifies the exact GOST v3 binary used in the QUIC/WSS
acceptance jobs. Do not substitute an unverified download or expose a WSS exit
private key in a shared configuration repository.

See [WIREGUARD_RUNTIME_TESTS.md](WIREGUARD_RUNTIME_TESTS.md) and
[MIGRATION.md](MIGRATION.md) before enabling WireGuard on production nodes.

## Operational Rules

- Release artifacts are built and tested by GitHub Actions, not on the node.
- Pin a tag for production and retain the downloaded checksum evidence.
- Back up `/etc/V2bX` before using `initconfig`; the wizard will offer a backup
  before it overwrites `config.json`.
- Upgrade one node at a time and observe panel reports before draining the old
  node.
