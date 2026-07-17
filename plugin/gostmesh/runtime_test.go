package gostmesh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const runtimeTestBootID = "01234567-89ab-cdef-0123-456789abcdef"

type runtimeTestNetwork struct {
	mu       sync.Mutex
	calls    []string
	failures map[string]error
}

func (n *runtimeTestNetwork) record(call string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, call)
	return n.failures[call]
}

func (n *runtimeTestNetwork) Preflight(context.Context, Config) error {
	return n.record("preflight")
}

func (n *runtimeTestNetwork) WaitTunnel(_ context.Context, tunnel Tunnel, _ time.Duration) (int, error) {
	err := n.record("wait:" + tunnel.ID)
	return runtimeTestInterfaceIndex(tunnel.ID), err
}

func (n *runtimeTestNetwork) ApplyEntryRouting(_ context.Context, tunnel Tunnel) error {
	return n.record("route:" + tunnel.ID)
}

func (n *runtimeTestNetwork) VerifyTunnel(_ context.Context, tunnel Tunnel) error {
	return n.record("verify:" + tunnel.ID)
}

func (n *runtimeTestNetwork) CleanupTunnel(_ context.Context, tunnel tunnelJournal) error {
	return n.record("cleanup:" + tunnel.ID)
}

func (n *runtimeTestNetwork) Calls() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.calls...)
}

func (n *runtimeTestNetwork) CleanupIDs() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	ids := make([]string, 0)
	for _, call := range n.calls {
		if strings.HasPrefix(call, "cleanup:") {
			ids = append(ids, strings.TrimPrefix(call, "cleanup:"))
		}
	}
	return ids
}

type runtimeTestProber struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (p *runtimeTestProber) Probe(_ context.Context, tunnel Tunnel) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, tunnel.ID)
	return p.err
}

func (p *runtimeTestProber) Calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

type runtimeTestVerifier struct {
	mu      sync.Mutex
	binary  string
	calls   int
	failure error
}

func (v *runtimeTestVerifier) Verify(_ context.Context, binary string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	v.binary = binary
	return v.failure
}

func (v *runtimeTestVerifier) Snapshot() (string, int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.binary, v.calls
}

type runtimeTestChild struct {
	record ProcessRecord
	exited chan error
	once   sync.Once
	mu     sync.Mutex
	stops  int
}

func newRuntimeTestChild(record ProcessRecord) *runtimeTestChild {
	return &runtimeTestChild{record: record, exited: make(chan error, 1)}
}

func (p *runtimeTestChild) Record() ProcessRecord { return p.record }
func (p *runtimeTestChild) Exited() <-chan error  { return p.exited }

func (p *runtimeTestChild) Stop(context.Context) error {
	p.mu.Lock()
	p.stops++
	p.mu.Unlock()
	p.finish(nil)
	return nil
}

func (p *runtimeTestChild) Crash(err error) { p.finish(err) }

func (p *runtimeTestChild) finish(err error) {
	p.once.Do(func() {
		p.exited <- err
		close(p.exited)
	})
}

func (p *runtimeTestChild) StopCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stops
}

type runtimeTestLauncher struct {
	mu       sync.Mutex
	bySpec   map[string]string
	starts   map[string][]*runtimeTestChild
	order    []string
	nextPID  int
	failures map[string]error
}

func newRuntimeTestLauncher(t *testing.T, config Config, binary string) *runtimeTestLauncher {
	t.Helper()
	specs, err := BuildCommandSpecs(config, binary)
	require.NoError(t, err)
	launcher := &runtimeTestLauncher{
		bySpec:  make(map[string]string, len(specs)),
		starts:  make(map[string][]*runtimeTestChild, len(specs)),
		nextPID: 50000,
	}
	for _, spec := range specs {
		launcher.bySpec[runtimeCommandKey(spec.Binary, spec.Args)] = spec.TunnelID
	}
	return launcher
}

func (l *runtimeTestLauncher) Start(_ context.Context, binary string, args []string) (ChildProcess, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	id := l.bySpec[runtimeCommandKey(binary, args)]
	if id == "" {
		return nil, errors.New("unexpected GOST command")
	}
	if err := l.failures[id]; err != nil {
		return nil, err
	}
	l.nextPID++
	child := newRuntimeTestChild(ProcessRecord{PID: l.nextPID, StartTime: uint64(l.nextPID * 10), Executable: binary, BootID: runtimeTestBootID})
	l.starts[id] = append(l.starts[id], child)
	l.order = append(l.order, id)
	return child, nil
}

func (l *runtimeTestLauncher) StartCount(id string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.starts[id])
}

func (l *runtimeTestLauncher) Children(id string) []*runtimeTestChild {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*runtimeTestChild(nil), l.starts[id]...)
}

func (l *runtimeTestLauncher) Order() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.order...)
}

func runtimeCommandKey(binary string, args []string) string {
	return binary + "\x00" + strings.Join(args, "\x00")
}

func TestResolveGOSTBinaryPreservesPathForSymlinkRejection(t *testing.T) {
	directory := runtimeSecureTempDir(t)
	target := filepath.Join(directory, "gost-target")
	link := filepath.Join(directory, "gost")
	require.NoError(t, os.WriteFile(target, []byte("runtime"), 0o750))
	require.NoError(t, os.Symlink(target, link))

	resolved, err := resolveGOSTBinary(link)
	require.NoError(t, err)
	require.Equal(t, link, resolved)
	err = (gostVersionVerifier{}).Verify(context.Background(), resolved)
	require.ErrorContains(t, err, "not a symlink")
}

func TestGOSTVersionVerifierHasBoundedDeadline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable shell fixture is Unix-specific")
	}
	directory := runtimeSecureTempDir(t)
	binary := filepath.Join(directory, "slow-gost")
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\nexec sleep 30\n"), 0o750))

	started := time.Now()
	err := (gostVersionVerifier{timeout: 50 * time.Millisecond}).Verify(context.Background(), binary)
	require.ErrorContains(t, err, "deadline exceeded")
	require.Less(t, time.Since(started), time.Second)
}

func runtimeTestInterfaceIndex(id string) int {
	index := 100
	for _, character := range []byte(id) {
		index += int(character)
	}
	return index
}

func TestRunObservationModeRecoversInterruptedOwnership(t *testing.T) {
	directory, configPath, statePath, socketPath, binary := runtimeTestFiles(t, Config{
		APIVersion: APIVersion, Apply: false, RollbackOnExit: true, Tunnels: []Tunnel{},
	})
	_ = directory
	journal := newOwnershipJournal(validConfig(validEntry()), binary)
	require.NoError(t, writeOwnershipJournal(statePath, journal))

	network := &runtimeTestNetwork{}
	verifier := &runtimeTestVerifier{}
	launcher := newRuntimeTestLauncher(t, Config{APIVersion: APIVersion, Apply: false, RollbackOnExit: true}, binary)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, Options{
			SocketPath: socketPath, ConfigPath: configPath, StatePath: statePath, GOSTBinary: binary,
			Network: network, Launcher: launcher, Prober: &runtimeTestProber{}, RuntimeVerifier: verifier,
		})
	}()

	connection := dialRuntimeHealth(t, socketPath)
	defer connection.Close()
	require.Equal(t, healthpb.HealthCheckResponse_SERVING, runtimeHealthStatus(t, connection, ""))
	require.Equal(t, healthpb.HealthCheckResponse_UNKNOWN, runtimeHealthStatus(t, connection, ID))
	require.Equal(t, []string{"cleanup:" + validEntry().ID}, network.Calls())
	_, err := os.Lstat(statePath)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, verifierCalls := verifier.Snapshot()
	require.Zero(t, verifierCalls)
	require.Empty(t, launcher.Order())

	cancel()
	require.NoError(t, waitRuntimeResult(t, result))
}

func TestRunApplyStartsMultipleTunnelsServesHealthAndRollsBack(t *testing.T) {
	config := validConfig(validEntry(), validExit())
	_, configPath, statePath, socketPath, binary := runtimeTestFiles(t, config)
	network := &runtimeTestNetwork{}
	prober := &runtimeTestProber{}
	verifier := &runtimeTestVerifier{}
	launcher := newRuntimeTestLauncher(t, config, binary)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, Options{
			SocketPath: socketPath, ConfigPath: configPath, StatePath: statePath, GOSTBinary: binary,
			Network: network, Launcher: launcher, Prober: prober, RuntimeVerifier: verifier,
		})
	}()

	connection := dialRuntimeHealth(t, socketPath)
	defer connection.Close()
	require.Eventually(t, func() bool {
		return runtimeHealthStatusNoFail(connection, ID) == healthpb.HealthCheckResponse_SERVING
	}, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, []string{validEntry().ID, validExit().ID}, launcher.Order())
	require.Equal(t, []string{validEntry().ID}, prober.Calls())
	verifiedBinary, verifyCalls := verifier.Snapshot()
	require.Equal(t, binary, verifiedBinary)
	require.Equal(t, 1, verifyCalls)

	journal, exists, err := loadOwnershipJournal(statePath)
	require.NoError(t, err)
	require.True(t, exists)
	require.Len(t, journal.Tunnels, 2)
	for _, tunnel := range journal.Tunnels {
		require.Equal(t, "active", tunnel.Phase)
		require.Positive(t, tunnel.Process.PID)
		require.Equal(t, runtimeTestInterfaceIndex(tunnel.ID), tunnel.InterfaceIndex)
	}

	cancel()
	require.NoError(t, waitRuntimeResult(t, result))
	require.Equal(t, []string{validExit().ID, validEntry().ID}, network.CleanupIDs())
	for _, id := range []string{validEntry().ID, validExit().ID} {
		children := launcher.Children(id)
		require.Len(t, children, 1)
		require.Equal(t, 1, children[0].StopCount())
	}
	_, err = os.Lstat(statePath)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(socketPath)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRunPartialFailureRollsBackTunnelsInReverseOrder(t *testing.T) {
	first, second := validEntry(), secondEntry()
	config := validConfig(first, second)
	_, configPath, statePath, socketPath, binary := runtimeTestFiles(t, config)
	network := &runtimeTestNetwork{failures: map[string]error{"wait:" + second.ID: errors.New("injected wait failure")}}
	launcher := newRuntimeTestLauncher(t, config, binary)

	err := Run(context.Background(), Options{
		SocketPath: socketPath, ConfigPath: configPath, StatePath: statePath, GOSTBinary: binary,
		Network: network, Launcher: launcher, Prober: &runtimeTestProber{}, RuntimeVerifier: &runtimeTestVerifier{},
	})
	require.ErrorContains(t, err, "injected wait failure")
	require.Equal(t, []string{second.ID, first.ID}, network.CleanupIDs())
	for _, id := range []string{first.ID, second.ID} {
		children := launcher.Children(id)
		require.Len(t, children, 1)
		require.Equal(t, 1, children[0].StopCount())
	}
	_, statErr := os.Lstat(statePath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestRunRestartsCrashedChildWithinLimitAndFailsAfterExhaustion(t *testing.T) {
	tunnel := validEntry()
	tunnel.Health.Enabled = false
	tunnel.Health.RestartDelaySeconds = 1
	tunnel.Health.RestartLimit = 1
	config := validConfig(tunnel)
	_, configPath, statePath, socketPath, binary := runtimeTestFiles(t, config)
	network := &runtimeTestNetwork{}
	launcher := newRuntimeTestLauncher(t, config, binary)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, Options{
			SocketPath: socketPath, ConfigPath: configPath, StatePath: statePath, GOSTBinary: binary,
			Network: network, Launcher: launcher, Prober: &runtimeTestProber{}, RuntimeVerifier: &runtimeTestVerifier{},
		})
	}()

	connection := dialRuntimeHealth(t, socketPath)
	connection.Close()
	require.Eventually(t, func() bool { return launcher.StartCount(tunnel.ID) == 1 }, time.Second, 10*time.Millisecond)
	launcher.Children(tunnel.ID)[0].Crash(errors.New("first crash"))
	require.Eventually(t, func() bool { return launcher.StartCount(tunnel.ID) == 2 }, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, []string{tunnel.ID}, network.CleanupIDs())
	launcher.Children(tunnel.ID)[1].Crash(errors.New("second crash"))

	err := waitRuntimeResult(t, result)
	require.ErrorContains(t, err, "exhausted 1 restarts")
	require.ErrorContains(t, err, "second crash")
	require.Equal(t, []string{tunnel.ID, tunnel.ID}, network.CleanupIDs())
	_, statErr := os.Lstat(statePath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestCleanupUsesStableJournalWithoutLoadingConfig(t *testing.T) {
	directory := runtimeSecureTempDir(t)
	statePath := filepath.Join(directory, "ownership.json")
	missingConfig := filepath.Join(directory, "missing-config.json")
	binary := filepath.Join(directory, "runtime", "gost")
	journal := newOwnershipJournal(validConfig(validEntry(), validExit()), binary)
	require.NoError(t, writeOwnershipJournal(statePath, journal))
	network := &runtimeTestNetwork{}

	err := Cleanup(context.Background(), Options{ConfigPath: missingConfig, StatePath: statePath, Network: network})
	require.NoError(t, err)
	require.Equal(t, []string{validExit().ID, validEntry().ID}, network.CleanupIDs())
	_, statErr := os.Lstat(statePath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func runtimeTestFiles(t *testing.T, config Config) (directory, configPath, statePath, socketPath, binary string) {
	t.Helper()
	directory = runtimeSecureTempDir(t)
	configPath = filepath.Join(directory, "config.json")
	statePath = filepath.Join(directory, "ownership.json")
	socketPath = filepath.Join(directory, "plugin.sock")
	runtimeDir := filepath.Join(directory, "runtime")
	require.NoError(t, os.Mkdir(runtimeDir, 0o700))
	binary = filepath.Join(runtimeDir, "gost")
	require.NoError(t, os.WriteFile(binary, []byte("signed gost runtime"), 0o750))
	require.NoError(t, os.WriteFile(configPath, mustJSON(t, config), 0o600))
	return directory, configPath, statePath, socketPath, binary
}

func runtimeSecureTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	return directory
}

func dialRuntimeHealth(t *testing.T, socketPath string) *grpc.ClientConn {
	t.Helper()
	require.Eventually(t, func() bool {
		info, err := os.Stat(socketPath)
		return err == nil && info.Mode()&os.ModeSocket != 0
	}, 2*time.Second, 10*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	connection, err := grpc.DialContext(
		ctx,
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	return connection
}

func runtimeHealthStatus(t *testing.T, connection *grpc.ClientConn, service string) healthpb.HealthCheckResponse_ServingStatus {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := healthpb.NewHealthClient(connection).Check(ctx, &healthpb.HealthCheckRequest{Service: service})
	require.NoError(t, err)
	return response.Status
}

func runtimeHealthStatusNoFail(connection *grpc.ClientConn, service string) healthpb.HealthCheckResponse_ServingStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	response, err := healthpb.NewHealthClient(connection).Check(ctx, &healthpb.HealthCheckRequest{Service: service})
	if err != nil {
		return healthpb.HealthCheckResponse_UNKNOWN
	}
	return response.Status
}

func waitRuntimeResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(4 * time.Second):
		t.Fatal("gost-mesh runtime did not exit")
		return nil
	}
}
