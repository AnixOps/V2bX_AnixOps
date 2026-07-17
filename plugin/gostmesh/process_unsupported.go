//go:build !linux

package gostmesh

import (
	"context"
	"errors"
)

type unsupportedLauncher struct{}

func newSystemLauncher() Launcher {
	return unsupportedLauncher{}
}

func (unsupportedLauncher) Start(context.Context, string, []string) (ChildProcess, error) {
	return nil, errors.New("gost-mesh child processes are supported only on Linux")
}

func terminateRecordedProcess(context.Context, ProcessRecord) error {
	return errors.New("gost-mesh process cleanup is supported only on Linux")
}
