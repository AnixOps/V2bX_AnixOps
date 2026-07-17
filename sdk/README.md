# Anix Agent SDK

This nested Go module is the canonical source for public Anix Agent protocol
contracts. Consumers import the generated v1 bindings as:

```go
import agentv1pb "github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1"
```

The SDK must remain free of Agent runtime, filesystem, configuration, plugin,
and platform dependencies. Local development may use a shared `go.work`; CI
and released consumers must pin a published SDK version.

For paired local development, keep the workspace file outside both repositories.
It should `use` Control, Agent, and this SDK module, then add a version-specific
`replace` for the SDK version pinned by the root modules. The replacement stays
in the untracked workspace file; neither root `go.mod` may commit a `replace`.
