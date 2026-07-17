//go:build linux

package gostmesh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type systemLauncher struct{}

func newSystemLauncher() Launcher {
	return systemLauncher{}
}

func (systemLauncher) Start(ctx context.Context, binary string, args []string) (ChildProcess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(binary)
	if err != nil {
		return nil, fmt.Errorf("resolve GOST runtime: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, fmt.Errorf("resolve absolute GOST runtime path: %w", err)
	}
	command := exec.Command(resolved, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start GOST child: %w", err)
	}
	record, err := readProcessRecord(command.Process.Pid, "/proc")
	if err != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_, _ = command.Process.Wait()
		return nil, fmt.Errorf("record GOST child identity: %w", err)
	}
	if !sameExecutable(record.Executable, resolved) {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_, _ = command.Process.Wait()
		return nil, errors.New("started GOST child executable does not match the signed runtime")
	}
	process := &systemChild{
		command: command,
		record:  record,
		done:    make(chan struct{}),
		exited:  make(chan error, 1),
	}
	go func() {
		waitErr := command.Wait()
		process.mu.Lock()
		stopping := process.stopping
		process.waitErr = waitErr
		process.mu.Unlock()
		if stopping {
			process.exited <- nil
		} else {
			process.exited <- waitErr
		}
		close(process.exited)
		close(process.done)
	}()
	return process, nil
}

type systemChild struct {
	command  *exec.Cmd
	record   ProcessRecord
	done     chan struct{}
	exited   chan error
	stopOnce sync.Once
	stopErr  error
	mu       sync.Mutex
	stopping bool
	waitErr  error
}

func (p *systemChild) Record() ProcessRecord {
	if p == nil {
		return ProcessRecord{}
	}
	return p.record
}

func (p *systemChild) Exited() <-chan error {
	if p == nil {
		closed := make(chan error)
		close(closed)
		return closed
	}
	return p.exited
}

func (p *systemChild) Stop(ctx context.Context) error {
	if p == nil || p.command == nil || p.command.Process == nil {
		return nil
	}
	p.stopOnce.Do(func() {
		p.mu.Lock()
		p.stopping = true
		p.mu.Unlock()
		if err := verifyProcessRecord(p.record, "/proc"); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return
			}
			p.stopErr = err
			return
		}
		if err := syscall.Kill(-p.record.PID, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			p.stopErr = fmt.Errorf("signal GOST process group: %w", err)
		}
	})
	if p.stopErr != nil {
		return p.stopErr
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		if err := verifyProcessRecord(p.record, "/proc"); err == nil {
			if killErr := syscall.Kill(-p.record.PID, syscall.SIGKILL); killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
				return errors.Join(ctx.Err(), fmt.Errorf("kill GOST process group: %w", killErr))
			}
		}
		select {
		case <-p.done:
			return nil
		case <-time.After(250 * time.Millisecond):
			return ctx.Err()
		}
	}
}

func terminateRecordedProcess(ctx context.Context, record ProcessRecord) error {
	if record.PID <= 0 {
		return nil
	}
	if err := verifyProcessRecord(record, "/proc"); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := syscall.Kill(-record.PID, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("signal recorded GOST process group: %w", err)
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := verifyProcessRecord(record, "/proc"); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			if err := verifyProcessRecord(record, "/proc"); err == nil {
				_ = syscall.Kill(-record.PID, syscall.SIGKILL)
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func readProcessRecord(pid int, procRoot string) (ProcessRecord, error) {
	if pid <= 0 {
		return ProcessRecord{}, errors.New("process PID must be positive")
	}
	statPath := filepath.Join(procRoot, strconv.Itoa(pid), "stat")
	contents, err := os.ReadFile(statPath)
	if err != nil {
		return ProcessRecord{}, err
	}
	closing := strings.LastIndex(string(contents), ") ")
	if closing < 0 {
		return ProcessRecord{}, errors.New("process stat has an invalid command field")
	}
	fields := strings.Fields(string(contents)[closing+2:])
	if len(fields) <= 19 {
		return ProcessRecord{}, errors.New("process stat is missing start time")
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTime == 0 {
		return ProcessRecord{}, errors.New("process stat has an invalid start time")
	}
	executable, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return ProcessRecord{}, err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return ProcessRecord{}, err
	}
	bootIDContents, err := os.ReadFile(filepath.Join(procRoot, "sys/kernel/random/boot_id"))
	if err != nil {
		return ProcessRecord{}, fmt.Errorf("read process boot ID: %w", err)
	}
	bootID := strings.TrimSpace(string(bootIDContents))
	if !validBootID(bootID) {
		return ProcessRecord{}, errors.New("process boot ID is invalid")
	}
	return ProcessRecord{PID: pid, StartTime: startTime, Executable: executable, BootID: bootID}, nil
}

func verifyProcessRecord(expected ProcessRecord, procRoot string) error {
	actual, err := readProcessRecord(expected.PID, procRoot)
	if err != nil {
		return err
	}
	if actual.StartTime != expected.StartTime || actual.BootID != expected.BootID || !sameExecutable(actual.Executable, expected.Executable) {
		return errors.New("recorded GOST process identity no longer matches")
	}
	return nil
}

func sameExecutable(left, right string) bool {
	leftResolved, leftErr := filepath.EvalSymlinks(left)
	rightResolved, rightErr := filepath.EvalSymlinks(right)
	if leftErr == nil {
		left = leftResolved
	}
	if rightErr == nil {
		right = rightResolved
	}
	return filepath.Clean(left) == filepath.Clean(right)
}
