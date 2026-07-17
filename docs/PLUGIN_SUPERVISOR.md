# Official Plugin Supervisor

The Supervisor is opt-in and does not replace the existing proxy cores or
forwarding paths. When disabled, the Agent advertises and behaves exactly as a
legacy Agent Control client.

## Configuration

Add the following fields to the node `ApiConfig` that owns the physical Agent:

```json
{
  "AgentControlEnabled": true,
  "PluginSupervisorEnabled": true,
  "PluginRoot": "/var/lib/anixops/plugins",
  "PluginSocketDir": "/run/anixops/plugins",
  "PluginOfficialPublicKey": "BASE64_ED25519_PUBLIC_KEY"
}
```

All enabled node entries in one process must use the same root, socket
directory, and trust root. A plugin artifact must be an Agent-targeted manifest
published by `AnixOps`, signed with that key, and match its SHA-256 digest.
An omitted `architectures` list remains compatible with early manifests;
otherwise entries use `arch`, `os/arch`, or `os-arch` (with `any` for a
portable artifact) and must include the current Agent platform. Dependencies
and conflicts are plugin IDs; self references, duplicates, and overlap are
rejected. Entrypoints must be canonical relative paths.

## Runtime Contract

Each installed version is retained under `PluginRoot/<plugin>/<version>`.
Disabling stops the process but preserves its binary, configuration references,
state, and rollback version. The Supervisor writes `state.json` atomically and
journals operation ID, revision, and configuration hash before changing a
process. A package may be zip, tar, or tar.gz and uses a signed platform
entrypoint (`agent-<goos>-<goarch>`, `agent-any`, or `agent`). The original
package and materialized executable are both re-hashed before every start.

The signed executable receives:

```text
--anixops-socket /run/anixops/plugins/<plugin>.sock
--anixops-config /var/lib/anixops/plugins/<plugin>/<version>/config.json
```

A manifest that declares `plugin.runtime-state` also receives:

```text
--anixops-state /var/lib/anixops/plugins/<plugin>/runtime-state/ownership.json
```

The state path is stable across plugin-version and Agent-process changes. A
manifest may declare `plugin.cleanup` only together with
`plugin.runtime-state`; unsupported declared capabilities fail closed rather
than falling back to the stateless runner. Cleanup runs the verified executable
for the owning version with `--anixops-cleanup` plus the same socket, config,
and state paths.

It must expose the standard gRPC health service on the Unix socket. Business
traffic must not pass through the Supervisor. A protocol plugin owns its data
plane; nftables plugins program the kernel and then return control.

The first implementation supports inspect, configure, enable, disable, update,
rollback, health, and out-of-band `operation.cancel`. Enabled configuration
changes restart and health-check the process; failed recovery disables it and
records an unhealthy state. Unexpected CommandRunner exits are observed and
also fail closed.

For cleanup-capable plugins, the Supervisor persists `cleanup_pending` and
`cleanup_version` whenever stop or signed cleanup cannot be confirmed. Startup
and later lifecycle operations recover that exact version before starting a
process. Disable, configure, update, rollback, failed start/health, unexpected
exit, and Supervisor close all use the same serialized per-plugin cleanup path.
During update, target-version cleanup failure blocks automatic restart of the
old version; the old version is started only after target cleanup succeeds.
This intentionally prefers no stale nftables or policy-routing ownership over
automatic availability.

The current `nat-egress` runtime uses this contract for its private crash-safe
ownership journal. It programs nftables masquerade and fwmark policy routing,
then exposes the standard local gRPC health service. Its privileged namespace
acceptance proves marked forwarded traffic, wrong-mark isolation, NAT, policy
state and rollback behavior. The real `gost-mesh` runtime remains pending.
Artifact transport from Control, telemetry data transport, topology apply, and
sustained canary evidence are not complete. Production activation also requires
a signed release plus validated mark-producer and FORWARD-firewall prerequisites,
so this phase must not be described as production forwarding cutover.
