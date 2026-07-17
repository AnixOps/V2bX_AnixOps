# Anix Agent SDK

This nested Go module is the canonical source for public Anix Agent protocol
contracts. Consumers import the generated v1 bindings as:

```go
import agentv1pb "github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1"
```

The SDK must remain free of Agent runtime, filesystem, configuration, plugin,
and platform dependencies. Local development may use a shared `go.work`; CI
and released consumers must pin a published SDK version.
