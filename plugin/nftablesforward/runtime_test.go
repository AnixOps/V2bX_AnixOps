package nftablesforward

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

func TestParseConfigValidatesSignedContract(t *testing.T) {
	tests := []struct {
		name      string
		contents  string
		wantError string
	}{
		{
			name: "minimal tcp udp",
			contents: `{
				"rules": [
					{"id":"tcp-1","protocol":"tcp","listen_address":"198.51.100.10","listen_port":443,"target_address":"203.0.113.10","target_port":8443},
					{"id":"udp-1","protocol":"udp","listen_address":"2001:db8::10","listen_port":443,"target_address":"2001:db8::20","target_port":8443}
				]
			}`,
		},
		{name: "unknown field", contents: `{"rules":[],"command":"id"}`, wantError: "unknown field"},
		{name: "missing rules", contents: `{}`, wantError: "rules must be declared"},
		{name: "apply empty rules", contents: `{"apply":true,"rules":[]}`, wantError: "at least one"},
		{name: "bad protocol", contents: `{"rules":[{"id":"r1","protocol":"icmp","listen_address":"198.51.100.10","listen_port":443,"target_address":"203.0.113.10","target_port":8443}]}`, wantError: "protocol"},
		{name: "bad listen address", contents: `{"rules":[{"id":"r1","protocol":"tcp","listen_address":"0.0.0.0","listen_port":443,"target_address":"203.0.113.10","target_port":8443}]}`, wantError: "unicast"},
		{name: "mixed family", contents: `{"rules":[{"id":"r1","protocol":"tcp","listen_address":"198.51.100.10","listen_port":443,"target_address":"2001:db8::20","target_port":8443}]}`, wantError: "same IP family"},
		{name: "relative plan", contents: `{"plan_path":"plan.nft","rules":[{"id":"r1","protocol":"tcp","listen_address":"198.51.100.10","listen_port":443,"target_address":"203.0.113.10","target_port":8443}]}`, wantError: "plan_path must be absolute"},
		{name: "unsafe table", contents: `{"table":"bad-name","rules":[{"id":"r1","protocol":"tcp","listen_address":"198.51.100.10","listen_port":443,"target_address":"203.0.113.10","target_port":8443}]}`, wantError: "table"},
		{name: "trailing document", contents: `{"rules":[{"id":"r1","protocol":"tcp","listen_address":"198.51.100.10","listen_port":443,"target_address":"203.0.113.10","target_port":8443}]} {}`, wantError: "exactly one"},
		{name: "not object", contents: `null`, wantError: "JSON object"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := ParseConfig([]byte(test.contents))
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, DefaultFamily, config.Family)
			require.Equal(t, DefaultTable, config.Table)
			require.Len(t, config.Rules, 2)
		})
	}
}

func TestLoadConfigRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(validConfigJSON("uuid-1")), 0o600))
	require.NoError(t, os.Chmod(configPath, 0o622))
	_, err := LoadConfig(configPath)
	require.ErrorContains(t, err, "writable by group or other")

	if runtime.GOOS == "windows" {
		return
	}
	privatePath := filepath.Join(dir, "private.json")
	symlinkPath := filepath.Join(dir, "config-link.json")
	require.NoError(t, os.WriteFile(privatePath, []byte(validConfigJSON("uuid-2")), 0o600))
	require.NoError(t, os.Symlink(privatePath, symlinkPath))
	_, err = LoadConfig(symlinkPath)
	require.ErrorContains(t, err, "not a symlink")
}

func TestRenderRulesetCoversTCPUDPAndFamilies(t *testing.T) {
	config, err := ParseConfig([]byte(`{
		"family": "inet",
		"table": "anixops_forward",
		"chain": "prerouting",
		"priority": -90,
		"rules": [
			{"id":"tcp-443","protocol":"tcp","listen_address":"198.51.100.10","listen_port":443,"target_address":"203.0.113.10","target_port":8443,"comment":"dedicated"},
			{"id":"udp-443","protocol":"udp","listen_address":"2001:db8::10","listen_port":443,"target_address":"2001:db8::20","target_port":8443}
		]
	}`))
	require.NoError(t, err)

	ruleset, err := RenderRuleset(config)
	require.NoError(t, err)
	require.Contains(t, ruleset, "add table inet anixops_forward")
	require.Contains(t, ruleset, "flush table inet anixops_forward")
	require.Contains(t, ruleset, "add chain inet anixops_forward prerouting { type nat hook prerouting priority -90; policy accept; }")
	require.Contains(t, ruleset, `add rule inet anixops_forward prerouting ip daddr 198.51.100.10 tcp dport 443 dnat to 203.0.113.10:8443 comment "anixops tcp-443 dedicated"`)
	require.Contains(t, ruleset, `add rule inet anixops_forward prerouting ip6 daddr 2001:db8::10 udp dport 443 dnat to [2001:db8::20]:8443 comment "anixops udp-443"`)

	config.Family = "ip"
	_, err = RenderRuleset(config)
	require.ErrorContains(t, err, "IPv6 rule")
}

func TestRunDryRunServesHealthWritesPlanAndCleansSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket plugin runtime")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	configPath := filepath.Join(dir, "config.json")
	planPath := filepath.Join(dir, "plan.nft")
	socketPath := filepath.Join(dir, "plugin.sock")
	statePath := filepath.Join(dir, "ownership.json")
	require.NoError(t, os.WriteFile(configPath, []byte(strings.Replace(validConfigJSON("dry-run"), `"rules"`, `"plan_path":"`+planPath+`","rules"`, 1)), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, Options{SocketPath: socketPath, ConfigPath: configPath, StatePath: statePath})
	}()

	connection := waitForHealth(t, socketPath)
	require.NoError(t, connection.Close())
	plan, err := os.ReadFile(planPath)
	require.NoError(t, err)
	require.Contains(t, string(plan), "dnat to 203.0.113.10:8443")

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

func TestRunApplyAndRollbackOnExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket plugin runtime")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	configPath := filepath.Join(dir, "config.json")
	socketPath := filepath.Join(dir, "plugin.sock")
	statePath := filepath.Join(dir, "ownership.json")
	config := strings.Replace(validConfigJSON("apply-1"), `"rules"`, `"apply":true,"rollback_on_exit":true,"rules"`, 1)
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))

	applier := &recordingApplier{}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, Options{SocketPath: socketPath, ConfigPath: configPath, StatePath: statePath, Applier: applier})
	}()

	connection := waitForHealth(t, socketPath)
	require.NoError(t, connection.Close())
	cancel()
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("plugin did not stop after cancellation")
	}
	calls := applier.Calls()
	require.Len(t, calls, 2)
	require.Contains(t, calls[0], "dnat to 203.0.113.10:8443")
	require.Contains(t, calls[1], "delete table inet anixops_forward")
	snapshots := applier.Snapshots()
	require.Equal(t, []string{"inet anixops_forward", "inet anixops_forward"}, snapshots)
}

func TestRenderRollbackFromSnapshotRestoresExistingTable(t *testing.T) {
	config, err := ParseConfig([]byte(validConfigJSON("snapshot-1")))
	require.NoError(t, err)
	rollback, err := RenderRollbackFromSnapshot(config, TableSnapshot{
		Exists: true,
		Ruleset: `table inet anixops_forward {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		ip daddr 198.51.100.20 tcp dport 443 dnat ip to 203.0.113.20:8443 comment "pre-existing"
	}
}
`,
	})
	require.NoError(t, err)
	require.Contains(t, rollback, "delete table inet anixops_forward")
	require.Contains(t, rollback, `ip daddr 198.51.100.20 tcp dport 443 dnat ip to 203.0.113.20:8443 comment "pre-existing"`)

	rollback, err = RenderRollbackFromSnapshot(config, TableSnapshot{Exists: false})
	require.NoError(t, err)
	require.Contains(t, rollback, "delete table inet anixops_forward")
}

type recordingApplier struct {
	mu          sync.Mutex
	calls       []string
	snapshots   []string
	exists      bool
	verifyErr   error
	verifyCalls int
}

func (a *recordingApplier) Apply(ctx context.Context, nftBinary, ruleset string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, ruleset)
	if strings.Contains(ruleset, "add rule ") {
		a.exists = true
	} else if strings.Contains(ruleset, "delete table ") {
		a.exists = false
	}
	return nil
}

func (a *recordingApplier) Snapshot(ctx context.Context, nftBinary, family, table string) (TableSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return TableSnapshot{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.snapshots = append(a.snapshots, family+" "+table)
	return TableSnapshot{Exists: a.exists}, nil
}

func (a *recordingApplier) VerifyApplied(ctx context.Context, nftBinary string, config Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.verifyCalls++
	return a.verifyErr
}

func (a *recordingApplier) SetVerifyError(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.verifyErr = err
}

func (a *recordingApplier) VerifyCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.verifyCalls
}

func (a *recordingApplier) Calls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}

func (a *recordingApplier) Snapshots() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.snapshots...)
}

func TestRunApplyMarksHealthUnhealthyWhenKernelVerificationFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket plugin runtime")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	configPath := filepath.Join(dir, "config.json")
	socketPath := filepath.Join(dir, "plugin.sock")
	statePath := filepath.Join(dir, "ownership.json")
	config := strings.Replace(validConfigJSON("verify-health"), `"rules"`, `"apply":true,"rollback_on_exit":true,"rules"`, 1)
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))

	applier := &recordingApplier{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, Options{
			SocketPath: socketPath, ConfigPath: configPath, StatePath: statePath,
			Applier: applier, VerifyInterval: 10 * time.Millisecond,
		})
	}()
	connection := waitForHealth(t, socketPath)
	defer connection.Close()
	require.GreaterOrEqual(t, applier.VerifyCalls(), 1)
	applier.SetVerifyError(errors.New("kernel ruleset changed"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := healthpb.NewHealthClient(connection).Check(context.Background(), &healthpb.HealthCheckRequest{Service: ID})
		if err == nil && response.Status == healthpb.HealthCheckResponse_NOT_SERVING {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	response, err := healthpb.NewHealthClient(connection).Check(context.Background(), &healthpb.HealthCheckRequest{Service: ID})
	require.NoError(t, err)
	require.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, response.Status)

	cancel()
	require.NoError(t, <-result)
	require.Len(t, applier.Calls(), 2)
}

func waitForHealth(t *testing.T, socketPath string) *grpc.ClientConn {
	t.Helper()
	dialCtx, cancelDial := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancelDial)
	connection, err := grpc.DialContext(dialCtx, "unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	require.NoError(t, err)
	response, err := healthpb.NewHealthClient(connection).Check(dialCtx, &healthpb.HealthCheckRequest{Service: ID})
	require.NoError(t, err)
	require.Equal(t, healthpb.HealthCheckResponse_SERVING, response.Status)
	return connection
}

func validConfigJSON(id string) string {
	return `{
		"rules": [
			{"id":"` + id + `","protocol":"tcp","listen_address":"198.51.100.10","listen_port":443,"target_address":"203.0.113.10","target_port":8443}
		]
	}`
}
