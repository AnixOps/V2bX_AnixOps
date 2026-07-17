package gostmesh

import (
	"context"
	"time"
)

const networkCommandTimeout = 30 * time.Second

type NetworkManager interface {
	Preflight(context.Context, Config) error
	WaitTunnel(context.Context, Tunnel, time.Duration) (int, error)
	ApplyEntryRouting(context.Context, Tunnel) error
	VerifyTunnel(context.Context, Tunnel) error
	CleanupTunnel(context.Context, tunnelJournal) error
}

type Prober interface {
	Probe(context.Context, Tunnel) error
}
