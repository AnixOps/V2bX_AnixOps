# anix.agent.v1 Control Stream

`AgentControlService.ControlStream` is the v3 primary Agent-first bidirectional
gRPC control channel. Authentication reuses the configured node ID and node API
key as `x-node-id` and `x-api-key` metadata.

The client declares capabilities in `Hello`, sends application heartbeats,
automatically reconnects with jittered exponential backoff, acknowledges
desired operations, and reports applying plus terminal `ObservedState`.
Operation execution is injected through `api/agent.OperationHandler`. When a
stream drops before terminal observation, Control replays the same operation ID
and revision; the Agent's completed-operation cache returns the terminal state
without executing a completed operation twice.

Each `OperationAck` carries the active `session_id` and operation `revision`,
and each `ObservedState` carries the active `session_id`. Control rejects a
message from a replaced session or with a revision that does not match its
retained desired operation. On reconnect, the Agent includes its latest
observed revision in `Hello`; Control reconciles its counter before replying
and sends retained operations as one serialized replay batch. The Agent checks
revision freshness both on receipt and immediately before execution, reporting
queued stale work as `SUPERSEDED` without invoking the runtime handler.

Delivery is at least once, so handlers must be idempotent. Control's retained
operation set is currently in memory, and the Agent's bounded completed-
operation cache is not durable across process restarts.

The first node integration supports `agent.ping`, `node.reload`, and
`users.reload`. It does not claim the existing forward runtime has been fully
migrated: there is no `forward.task` executor in this repository yet, so that
capability is intentionally not advertised and the legacy forward-agent path
remains available. Existing REST polling, v2board gRPC data services, and the
legacy WebSocket `SyncManager` remain compatibility/fallback paths during the
v3 migration.

`AgentControlEnabled` is a positive opt-in. It defaults to `false` when the
field is absent, so upgrading a legacy config does not create a reconnect loop
against a disabled Control port. The v3 example configs set it to `true` and
provide `GRPCHost` plus TLS settings where the endpoint is public.

The checked-in Go files are generated, not handwritten. Generation used:

```bash
PATH=/tmp/anix-protoc/tool/bin:/tmp/anix-protoc/bin:$PATH \
  protoc -I . \
  --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
  api/grpc/agent/v1/agent.proto
```

Verified generator versions: `libprotoc 29.2`, `protoc-gen-go v1.36.11`, and
`protoc-gen-go-grpc 1.6.1`.
