//go:build !linux

package gostmesh

import (
	"context"
	"errors"
)

type unsupportedProber struct{}

func newSystemProber() Prober {
	return unsupportedProber{}
}

func (unsupportedProber) Probe(context.Context, Tunnel) error {
	return errors.New("gost-mesh health probes are supported only on Linux")
}
