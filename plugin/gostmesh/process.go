package gostmesh

import (
	"context"
	"errors"
	"time"
)

const childStopTimeout = 2 * time.Second

type ProcessRecord struct {
	PID        int    `json:"pid"`
	StartTime  uint64 `json:"start_time"`
	Executable string `json:"executable"`
	BootID     string `json:"boot_id"`
}

func validBootID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index := range value {
		switch index {
		case 8, 13, 18, 23:
			if value[index] != '-' {
				return false
			}
		default:
			character := value[index]
			if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
				return false
			}
		}
	}
	return true
}

type ChildProcess interface {
	Record() ProcessRecord
	Exited() <-chan error
	Stop(context.Context) error
}

type Launcher interface {
	Start(context.Context, string, []string) (ChildProcess, error)
}

func stopChildWithTimeout(process ChildProcess) error {
	if process == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), childStopTimeout)
	defer cancel()
	return process.Stop(ctx)
}

func waitForExit(ctx context.Context, exited <-chan error) error {
	if exited == nil {
		return errors.New("child process does not expose an exit channel")
	}
	select {
	case err, ok := <-exited:
		if !ok {
			return nil
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
