//go:build !linux

package gostmesh

import (
	"context"
	"errors"
	"time"
)

type CommandNetworkManager struct{}

func (CommandNetworkManager) Preflight(context.Context, Config) error {
	return errors.New("gost-mesh networking is supported only on Linux")
}

func (CommandNetworkManager) WaitTunnel(context.Context, Tunnel, time.Duration) (int, error) {
	return 0, errors.New("gost-mesh networking is supported only on Linux")
}

func (CommandNetworkManager) ApplyEntryRouting(context.Context, Tunnel) error {
	return errors.New("gost-mesh networking is supported only on Linux")
}

func (CommandNetworkManager) VerifyTunnel(context.Context, Tunnel) error {
	return errors.New("gost-mesh networking is supported only on Linux")
}

func (CommandNetworkManager) CleanupTunnel(context.Context, tunnelJournal) error {
	return errors.New("gost-mesh networking is supported only on Linux")
}
