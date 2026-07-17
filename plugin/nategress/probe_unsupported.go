//go:build !linux

package nategress

import (
	"context"
	"errors"
)

type unsupportedProber struct{}

func newSystemProber() Prober {
	return unsupportedProber{}
}

func (unsupportedProber) Probe(context.Context, Config) error {
	return errors.New("marked egress health probes are supported only on Linux")
}
