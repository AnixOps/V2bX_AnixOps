package gostmesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	GOSTVersion          = "v3.2.6"
	startupTimeout       = 15 * time.Second
	gostVersionTimeout   = 10 * time.Second
	pluginCleanupTimeout = 4 * time.Second
)

type RuntimeVerifier interface {
	Verify(context.Context, string) error
}

type Options struct {
	SocketPath      string
	ConfigPath      string
	StatePath       string
	GOSTBinary      string
	Network         NetworkManager
	Prober          Prober
	Launcher        Launcher
	RuntimeVerifier RuntimeVerifier
}

type gostVersionVerifier struct {
	timeout time.Duration
}

func (v gostVersionVerifier) Verify(ctx context.Context, binary string) error {
	info, err := os.Lstat(binary)
	if err != nil {
		return fmt.Errorf("inspect signed GOST runtime: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("signed GOST runtime must be an executable regular file, not a symlink")
	}
	timeout := v.timeout
	if timeout <= 0 {
		timeout = gostVersionTimeout
	}
	versionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output, err := exec.CommandContext(versionCtx, binary, "-V").CombinedOutput()
	if err != nil {
		if versionCtx.Err() != nil {
			return fmt.Errorf("inspect GOST runtime version within %s: %w", timeout, versionCtx.Err())
		}
		return fmt.Errorf("inspect GOST runtime version: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if !strings.HasPrefix(strings.TrimSpace(string(output)), "gost "+GOSTVersion+" ") {
		return fmt.Errorf("unsupported GOST runtime version: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

type managedTunnel struct {
	tunnel   Tunnel
	spec     CommandSpec
	process  ChildProcess
	restarts int
}

type childExit struct {
	tunnelID string
	record   ProcessRecord
	err      error
}

func Run(ctx context.Context, options Options) (runErr error) {
	if ctx == nil {
		return errors.New("plugin context is required")
	}
	config, err := LoadConfig(options.ConfigPath)
	if err != nil {
		return err
	}
	statePath, err := privateStatePath(options.StatePath)
	if err != nil {
		return err
	}
	socketPath, err := validateSocketPath(options.SocketPath)
	if err != nil {
		return err
	}
	networkManager := options.Network
	if networkManager == nil {
		networkManager = CommandNetworkManager{}
	}
	if err := recoverOwnership(ctx, networkManager, statePath); err != nil {
		return fmt.Errorf("recover interrupted gost-mesh state: %w", err)
	}

	listener, err := listenUnixSocket(socketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = removeUnixSocket(socketPath)
	}()
	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(server, healthServer)
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()
	defer server.Stop()

	if !config.Apply {
		healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		healthServer.SetServingStatus(ID, healthpb.HealthCheckResponse_UNKNOWN)
		return waitForRuntimeExit(ctx, server, healthServer, serveResult)
	}
	if runtime.GOOS != "linux" {
		return errors.New("gost-mesh apply is supported only on Linux")
	}
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	healthServer.SetServingStatus(ID, healthpb.HealthCheckResponse_NOT_SERVING)

	gostBinary, err := resolveGOSTBinary(options.GOSTBinary)
	if err != nil {
		return err
	}
	verifier := options.RuntimeVerifier
	if verifier == nil {
		verifier = gostVersionVerifier{}
	}
	if err := verifier.Verify(ctx, gostBinary); err != nil {
		return err
	}
	if err := networkManager.Preflight(ctx, config); err != nil {
		return err
	}
	commands, err := BuildCommandSpecs(config, gostBinary)
	if err != nil {
		return err
	}
	launcher := options.Launcher
	if launcher == nil {
		launcher = newSystemLauncher()
	}
	prober := options.Prober
	if prober == nil {
		prober = newSystemProber()
	}

	journal := newOwnershipJournal(config, gostBinary)
	if err := writeOwnershipJournal(statePath, journal); err != nil {
		return err
	}
	managed := make(map[string]*managedTunnel, len(config.Tunnels))
	for index, tunnel := range config.Tunnels {
		managed[tunnel.ID] = &managedTunnel{tunnel: tunnel, spec: commands[index]}
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), pluginCleanupTimeout)
		defer cancel()
		runErr = errors.Join(runErr, rollbackOwnership(cleanupCtx, networkManager, statePath, &journal, managed))
	}()

	exits := make(chan childExit, len(managed)*2)
	for _, tunnel := range config.Tunnels {
		if err := startManagedTunnel(ctx, launcher, networkManager, statePath, &journal, managed[tunnel.ID], exits); err != nil {
			return err
		}
	}
	failures := make(map[string]int, len(managed))
	nextProbe := make(map[string]time.Time, len(managed))
	if serving, _ := probeManagedTunnels(ctx, healthServer, networkManager, prober, managed, failures, nextProbe, true); !serving {
		healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
		healthServer.SetServingStatus(ID, healthpb.HealthCheckResponse_NOT_SERVING)
	}
	ticker := time.NewTicker(minimumHealthInterval(config))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			healthServer.Shutdown()
			server.Stop()
			if err := <-serveResult; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				return fmt.Errorf("serve gost-mesh health API: %w", err)
			}
			return nil
		case err := <-serveResult:
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				return fmt.Errorf("serve gost-mesh health API: %w", err)
			}
			return nil
		case event := <-exits:
			current := managed[event.tunnelID]
			if current == nil || current.process == nil || current.process.Record() != event.record {
				continue
			}
			healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
			healthServer.SetServingStatus(ID, healthpb.HealthCheckResponse_NOT_SERVING)
			current.process = nil
			if current.restarts >= current.tunnel.Health.RestartLimit {
				return fmt.Errorf("tunnel %q GOST child exhausted %d restarts: %w", event.tunnelID, current.restarts, unexpectedExit(event.err))
			}
			current.restarts++
			if err := resetManagedTunnel(ctx, networkManager, statePath, &journal, current); err != nil {
				return fmt.Errorf("reset tunnel %q after child exit: %w", event.tunnelID, err)
			}
			timer := time.NewTimer(current.tunnel.Health.RestartDelay())
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			if err := startManagedTunnel(ctx, launcher, networkManager, statePath, &journal, current, exits); err != nil {
				return fmt.Errorf("restart tunnel %q: %w", event.tunnelID, err)
			}
			failures[event.tunnelID] = 0
			nextProbe[event.tunnelID] = time.Time{}
			_, _ = probeManagedTunnels(ctx, healthServer, networkManager, prober, managed, failures, nextProbe, true)
		case <-ticker.C:
			_, unhealthy := probeManagedTunnels(ctx, healthServer, networkManager, prober, managed, failures, nextProbe, false)
			if len(unhealthy) > 0 {
				current := managed[unhealthy[0]]
				if current == nil {
					return fmt.Errorf("health check referenced unknown tunnel %q", unhealthy[0])
				}
				if current.restarts >= current.tunnel.Health.RestartLimit {
					return fmt.Errorf("tunnel %q health exhausted %d restarts", current.tunnel.ID, current.restarts)
				}
				current.restarts++
				stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
				stopErr := current.process.Stop(stopCtx)
				stopCancel()
				current.process = nil
				if err := errors.Join(stopErr, resetManagedTunnel(ctx, networkManager, statePath, &journal, current)); err != nil {
					return fmt.Errorf("reset unhealthy tunnel %q: %w", current.tunnel.ID, err)
				}
				timer := time.NewTimer(current.tunnel.Health.RestartDelay())
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
				if err := startManagedTunnel(ctx, launcher, networkManager, statePath, &journal, current, exits); err != nil {
					return fmt.Errorf("restart unhealthy tunnel %q: %w", current.tunnel.ID, err)
				}
				failures[current.tunnel.ID] = 0
				nextProbe[current.tunnel.ID] = time.Time{}
			}
		}
	}
}

func Cleanup(ctx context.Context, options Options) error {
	if ctx == nil {
		return errors.New("plugin context is required")
	}
	statePath, err := privateStatePath(options.StatePath)
	if err != nil {
		return err
	}
	networkManager := options.Network
	if networkManager == nil {
		networkManager = CommandNetworkManager{}
	}
	result := recoverOwnership(ctx, networkManager, statePath)
	if strings.TrimSpace(options.SocketPath) != "" {
		if socketPath, socketErr := validateSocketPath(options.SocketPath); socketErr != nil {
			result = errors.Join(result, socketErr)
		} else {
			result = errors.Join(result, removeUnixSocket(socketPath))
		}
	}
	return result
}

func startManagedTunnel(ctx context.Context, launcher Launcher, networkManager NetworkManager, statePath string, journal *ownershipJournal, managed *managedTunnel, exits chan<- childExit) error {
	process, err := launcher.Start(ctx, managed.spec.Binary, managed.spec.Args)
	if err != nil {
		return fmt.Errorf("start tunnel %q GOST child: %w", managed.tunnel.ID, err)
	}
	managed.process = process
	entry, err := journal.tunnel(managed.tunnel.ID)
	if err != nil {
		_ = stopChildWithTimeout(process)
		return err
	}
	entry.Process = process.Record()
	entry.Phase = "started"
	if err := writeOwnershipJournal(statePath, *journal); err != nil {
		_ = stopChildWithTimeout(process)
		return err
	}
	interfaceIndex, err := networkManager.WaitTunnel(ctx, managed.tunnel, startupTimeout)
	if err != nil {
		return errors.Join(err, childResultIfExited(process))
	}
	entry.InterfaceIndex = interfaceIndex
	if err := writeOwnershipJournal(statePath, *journal); err != nil {
		return err
	}
	if err := networkManager.ApplyEntryRouting(ctx, managed.tunnel); err != nil {
		return err
	}
	if err := networkManager.VerifyTunnel(ctx, managed.tunnel); err != nil {
		return err
	}
	entry.Phase = "active"
	if err := writeOwnershipJournal(statePath, *journal); err != nil {
		return err
	}
	go func(id string, record ProcessRecord, exited <-chan error) {
		exits <- childExit{tunnelID: id, record: record, err: waitForExit(context.Background(), exited)}
	}(managed.tunnel.ID, process.Record(), process.Exited())
	return nil
}

func resetManagedTunnel(ctx context.Context, networkManager NetworkManager, statePath string, journal *ownershipJournal, managed *managedTunnel) error {
	entry, err := journal.tunnel(managed.tunnel.ID)
	if err != nil {
		return err
	}
	if err := networkManager.CleanupTunnel(ctx, *entry); err != nil {
		return err
	}
	entry.Process = ProcessRecord{}
	entry.InterfaceIndex = 0
	entry.Phase = "prepared"
	return writeOwnershipJournal(statePath, *journal)
}

func recoverOwnership(ctx context.Context, networkManager NetworkManager, statePath string) error {
	journal, exists, err := loadOwnershipJournal(statePath)
	if err != nil || !exists {
		return err
	}
	return rollbackOwnership(ctx, networkManager, statePath, &journal, nil)
}

func rollbackOwnership(ctx context.Context, networkManager NetworkManager, statePath string, journal *ownershipJournal, managed map[string]*managedTunnel) error {
	if journal == nil {
		return nil
	}
	processErrors := make(chan error, len(journal.Tunnels))
	processCtx, processCancel := context.WithTimeout(ctx, time.Second)
	defer processCancel()
	for index := range journal.Tunnels {
		entry := journal.Tunnels[index]
		go func() {
			if current := managed[entry.ID]; current != nil && current.process != nil {
				processErrors <- current.process.Stop(processCtx)
				return
			}
			processErrors <- terminateRecordedProcess(processCtx, entry.Process)
		}()
	}
	var result error
	for range journal.Tunnels {
		result = errors.Join(result, <-processErrors)
	}
	for index := len(journal.Tunnels) - 1; index >= 0; index-- {
		result = errors.Join(result, networkManager.CleanupTunnel(ctx, journal.Tunnels[index]))
	}
	if result == nil {
		result = removeOwnershipJournal(statePath)
	}
	return result
}

func probeManagedTunnels(parent context.Context, server *health.Server, networkManager NetworkManager, prober Prober, managed map[string]*managedTunnel, failures map[string]int, nextProbe map[string]time.Time, force bool) (bool, []string) {
	now := time.Now()
	serving := true
	type probeResult struct {
		id  string
		err error
	}
	results := make(chan probeResult, len(managed))
	due := make([]string, 0, len(managed))
	for id, current := range managed {
		if current.process == nil {
			serving = false
			continue
		}
		if !force && now.Before(nextProbe[id]) {
			if failures[id] >= current.tunnel.Health.FailureThreshold {
				serving = false
			}
			continue
		}
		due = append(due, id)
		go func(id string, tunnel Tunnel) {
			probeCtx, cancel := context.WithTimeout(parent, tunnel.Health.Timeout())
			defer cancel()
			err := networkManager.VerifyTunnel(probeCtx, tunnel)
			if err == nil && tunnel.Health.Enabled {
				err = prober.Probe(probeCtx, tunnel)
			}
			results <- probeResult{id: id, err: err}
		}(id, current.tunnel)
	}
	unhealthy := make([]string, 0)
	for range due {
		result := <-results
		current := managed[result.id]
		nextProbe[result.id] = now.Add(current.tunnel.Health.Interval())
		if result.err != nil {
			failures[result.id]++
			fmt.Fprintf(os.Stderr, "gost-mesh: tunnel %q health check failed (%d/%d): %v\n", result.id, failures[result.id], current.tunnel.Health.FailureThreshold, result.err)
		} else {
			failures[result.id] = 0
		}
		if force && result.err != nil || failures[result.id] >= current.tunnel.Health.FailureThreshold {
			serving = false
		}
		if failures[result.id] >= current.tunnel.Health.FailureThreshold {
			unhealthy = append(unhealthy, result.id)
		}
	}
	for id, current := range managed {
		if current.process == nil {
			continue
		}
		if failures[id] >= current.tunnel.Health.FailureThreshold {
			serving = false
		}
	}
	status := healthpb.HealthCheckResponse_NOT_SERVING
	if serving {
		status = healthpb.HealthCheckResponse_SERVING
	}
	server.SetServingStatus("", status)
	server.SetServingStatus(ID, status)
	return serving, unhealthy
}

func minimumHealthInterval(config Config) time.Duration {
	minimum := 5 * time.Second
	for index, tunnel := range config.Tunnels {
		if index == 0 || tunnel.Health.Interval() < minimum {
			minimum = tunnel.Health.Interval()
		}
	}
	return minimum
}

func resolveGOSTBinary(configured string) (string, error) {
	path := strings.TrimSpace(configured)
	if path == "" {
		executable, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("resolve gost-mesh plugin executable: %w", err)
		}
		path = filepath.Join(filepath.Dir(executable), "runtime", "gost")
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("GOST runtime path must be absolute")
	}
	if filepath.Clean(path) != path {
		return "", errors.New("GOST runtime path must be clean")
	}
	return path, nil
}

func unexpectedExit(err error) error {
	if err == nil {
		return errors.New("GOST child exited unexpectedly")
	}
	return err
}

func childResultIfExited(process ChildProcess) error {
	if process == nil || process.Exited() == nil {
		return nil
	}
	select {
	case err, ok := <-process.Exited():
		if !ok || err == nil {
			return errors.New("GOST child exited before the TUN interface became ready")
		}
		return fmt.Errorf("GOST child exited before the TUN interface became ready: %w", err)
	default:
		return nil
	}
}

func waitForRuntimeExit(ctx context.Context, server *grpc.Server, healthServer *health.Server, serveResult <-chan error) error {
	select {
	case <-ctx.Done():
		healthServer.Shutdown()
		server.Stop()
		if err := <-serveResult; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return fmt.Errorf("serve gost-mesh health API: %w", err)
		}
		return nil
	case err := <-serveResult:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return fmt.Errorf("serve gost-mesh health API: %w", err)
		}
		return nil
	}
}

func validateSocketPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("--anixops-socket must be an absolute clean path")
	}
	return path, nil
}

func listenUnixSocket(path string) (net.Listener, error) {
	if err := removeUnixSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on gost-mesh Unix socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = removeUnixSocket(path)
		return nil, err
	}
	return listener, nil
}

func removeUnixSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket path %q", path)
	}
	return os.Remove(path)
}
