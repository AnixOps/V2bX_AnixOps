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

It must expose the standard gRPC health service on the Unix socket. Business
traffic must not pass through the Supervisor. A protocol plugin owns its data
plane; nftables plugins program the kernel and then return control.

The first implementation supports inspect, configure, enable, disable, update,
rollback, health, and out-of-band `operation.cancel`. Enabled configuration
changes restart and health-check the process; failed recovery disables it and
records an unhealthy state. Unexpected CommandRunner exits are observed and
also fail closed. Artifact transport from Control, telemetry data transport,
and topology apply are not advertised yet, so this phase must not be described
as production forwarding cutover.
