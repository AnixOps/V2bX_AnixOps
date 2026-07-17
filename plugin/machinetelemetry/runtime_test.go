package machinetelemetry

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestLoadConfigEnforcesSignedSchema(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name      string
		contents  string
		want      int
		wantError string
	}{
		{name: "default", contents: `{}`, want: DefaultIntervalSeconds},
		{name: "configured", contents: `{"interval_seconds":5}`, want: 5},
		{name: "maximum", contents: `{"interval_seconds":3600}`, want: MaximumIntervalSeconds},
		{name: "below minimum", contents: `{"interval_seconds":4}`, wantError: "at least 5"},
		{name: "above maximum", contents: `{"interval_seconds":3601}`, wantError: "at most 3600"},
		{name: "null", contents: `{"interval_seconds":null}`, wantError: "must be an integer"},
		{name: "fraction", contents: `{"interval_seconds":5.5}`, wantError: "must be an integer"},
		{name: "unknown field", contents: `{"interval_seconds":5,"command":"id"}`, wantError: "unknown field"},
		{name: "trailing document", contents: `{} {}`, wantError: "exactly one"},
		{name: "not object", contents: `null`, wantError: "JSON object"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name+".json")
			require.NoError(t, os.WriteFile(path, []byte(test.contents), 0o600))
			config, err := LoadConfig(path)
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, config.IntervalSeconds)
		})
	}
}

func TestLoadConfigRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"interval_seconds":5}`), 0o600))
	require.NoError(t, os.Chmod(configPath, 0o622))
	_, err := LoadConfig(configPath)
	require.ErrorContains(t, err, "writable by group or other")

	if runtime.GOOS == "windows" {
		return
	}
	privatePath := filepath.Join(dir, "private.json")
	symlinkPath := filepath.Join(dir, "config-link.json")
	require.NoError(t, os.WriteFile(privatePath, []byte(`{}`), 0o600))
	require.NoError(t, os.Symlink(privatePath, symlinkPath))
	_, err = LoadConfig(symlinkPath)
	require.ErrorContains(t, err, "not a symlink")
}

func TestRunServesHealthAndCleansSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket plugin runtime")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	configPath := filepath.Join(dir, "config.json")
	socketPath := filepath.Join(dir, "plugin.sock")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"interval_seconds":5}`), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, Options{SocketPath: socketPath, ConfigPath: configPath})
	}()

	dialCtx, cancelDial := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDial()
	connection, err := grpc.DialContext(dialCtx, "unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	require.NoError(t, err)
	response, err := healthpb.NewHealthClient(connection).Check(dialCtx, &healthpb.HealthCheckRequest{Service: ID})
	require.NoError(t, err)
	require.Equal(t, healthpb.HealthCheckResponse_SERVING, response.Status)
	require.NoError(t, connection.Close())

	cancel()
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("plugin did not stop after cancellation")
	}
	_, err = os.Lstat(socketPath)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRunServesTelemetrySnapshot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket plugin runtime")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	configPath := filepath.Join(dir, "config.json")
	socketPath := filepath.Join(dir, "plugin.sock")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"interval_seconds":5}`), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- Run(ctx, Options{SocketPath: socketPath, ConfigPath: configPath}) }()

	dialCtx, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDial()
	connection, err := grpc.DialContext(dialCtx, "unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	require.NoError(t, err)
	client := NewTelemetryClient(connection)
	snapshot, err := client.Snapshot(dialCtx)
	require.NoError(t, err)
	require.NoError(t, snapshot.Validate())
	require.Greater(t, snapshot.ObservedAtUnixMs, int64(0))
	require.Contains(t, snapshot.Metrics, "cpu_usage_percent")
	require.Contains(t, snapshot.Metrics, "memory_usage_percent")
	require.Contains(t, snapshot.Metrics, "disk_usage_percent")
	require.Contains(t, snapshot.Metrics, "uptime_seconds")
	require.NoError(t, connection.Close())

	cancel()
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("plugin did not stop after cancellation")
	}
}

func TestSnapshotRejectsUntrustedValues(t *testing.T) {
	base := Snapshot{Metrics: map[string]float64{"cpu_usage_percent": 1}, ObservedAtUnixMs: 1}
	require.NoError(t, base.Validate())
	base.Metrics["Bad Key"] = 1
	require.ErrorContains(t, base.Validate(), "invalid")
	base.Metrics = map[string]float64{"cpu_usage_percent": 1}
	base.Metrics["memory_usage_percent"] = math.Inf(1)
	require.ErrorContains(t, base.Validate(), "not finite")
}
