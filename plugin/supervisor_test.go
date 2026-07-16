package plugin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v3/api/agent"
	"github.com/stretchr/testify/require"
)

type fakeProcess struct {
	mu      sync.Mutex
	stopped bool
}

type watchableFakeProcess struct {
	fakeProcess
	exitOnce sync.Once
	exited   chan error
}

func newWatchableFakeProcess() *watchableFakeProcess {
	return &watchableFakeProcess{exited: make(chan error, 1)}
}

func (p *watchableFakeProcess) Stop(ctx context.Context) error {
	err := p.fakeProcess.Stop(ctx)
	p.exitOnce.Do(func() {
		p.exited <- nil
		close(p.exited)
	})
	return err
}

func (p *watchableFakeProcess) Exited() <-chan error { return p.exited }

func (p *watchableFakeProcess) Crash(err error) {
	p.exitOnce.Do(func() {
		p.exited <- err
		close(p.exited)
	})
}

type watchableRunner struct {
	mu      sync.Mutex
	starts  int
	process *watchableFakeProcess
}

func (r *watchableRunner) Start(context.Context, string, string, string) (Process, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.starts++
	r.process = newWatchableFakeProcess()
	return r.process, nil
}

func (r *watchableRunner) Starts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.starts
}

func (r *watchableRunner) Process() *watchableFakeProcess {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.process
}

func (p *fakeProcess) Stop(context.Context) error {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	return nil
}
func (p *fakeProcess) PID() int { return 42 }
func (p *fakeProcess) Stopped() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopped
}

type fakeRunner struct {
	mu      sync.Mutex
	starts  int
	process *fakeProcess
}

func (r *fakeRunner) Start(context.Context, string, string, string) (Process, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.starts++
	r.process = &fakeProcess{}
	return r.process, nil
}

func (r *fakeRunner) Starts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.starts
}

func (r *fakeRunner) Process() *fakeProcess {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.process
}

type fakeHealth struct {
	mu    sync.Mutex
	calls int
}

type configRecordingRunner struct {
	mu        sync.Mutex
	configs   [][]byte
	processes []*fakeProcess
}

func (r *configRecordingRunner) Start(_ context.Context, _, _, configPath string) (Process, error) {
	config, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	process := &fakeProcess{}
	r.mu.Lock()
	r.configs = append(r.configs, append([]byte(nil), config...))
	r.processes = append(r.processes, process)
	r.mu.Unlock()
	return process, nil
}

func (r *configRecordingRunner) Configs() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	configs := make([][]byte, 0, len(r.configs))
	for _, config := range r.configs {
		configs = append(configs, append([]byte(nil), config...))
	}
	return configs
}

func (r *configRecordingRunner) Processes() []*fakeProcess {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*fakeProcess(nil), r.processes...)
}

type configRejectingHealth struct {
	runner       *configRecordingRunner
	rejectConfig string
}

func (h *configRejectingHealth) Check(context.Context, string) error {
	configs := h.runner.Configs()
	if len(configs) > 0 && string(configs[len(configs)-1]) == h.rejectConfig {
		return errors.New("injected config health failure")
	}
	return nil
}

func (h *fakeHealth) Check(context.Context, string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	return nil
}

func (h *fakeHealth) Calls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

func signedRequest(t *testing.T, privateKey ed25519.PrivateKey, artifact []byte, id, version string) InstallRequest {
	t.Helper()
	digest := sha256.Sum256(artifact)
	manifest := Manifest{
		ID: id, Name: id, Version: version, APIVersion: "v1", Publisher: manifestPublisher,
		Targets: []string{"agent"}, ArtifactSHA256: hex.EncodeToString(digest[:]),
	}
	canonical, err := CanonicalManifest(manifest)
	require.NoError(t, err)
	return InstallRequest{ManifestJSON: string(canonical), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)), Artifact: artifact}
}

func readAgentManifestGolden(t *testing.T) []byte {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "contracts", "plugin", "v1", "manifest-golden.json"))
	require.NoError(t, err)
	return bytes.TrimSpace(raw)
}

func readAgentManifestNegativeFixtures(t *testing.T) []struct {
	Name      string          `json:"name"`
	WantError string          `json:"want_error"`
	Manifest  json.RawMessage `json:"manifest"`
} {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "contracts", "plugin", "v1", "manifest-negative.json"))
	require.NoError(t, err)
	var suite struct {
		APIVersion string `json:"api_version"`
		Cases      []struct {
			Name      string          `json:"name"`
			WantError string          `json:"want_error"`
			Manifest  json.RawMessage `json:"manifest"`
		} `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	require.NoError(t, decoder.Decode(&suite))
	require.Equal(t, "anixops.plugin.negative/v1", suite.APIVersion)
	require.NotEmpty(t, suite.Cases)
	return suite.Cases
}

func testEnvelope(operationID, pluginID, version string, revision uint64, config []byte) *agent.OperationEnvelope {
	digest := sha256.Sum256(config)
	return &agent.OperationEnvelope{
		Version: agent.OperationEnvelopeVersion, OperationID: operationID, IdempotencyKey: operationID,
		SessionID: "session-1", Revision: revision, PluginID: pluginID, TargetVersion: version,
		ConfigHash: hex.EncodeToString(digest[:]), Config: config,
	}
}

func TestSupervisorInstallLifecycleAndJournal(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	runner, health := &fakeRunner{}, &fakeHealth{}
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: runner, Health: health})
	require.NoError(t, err)

	artifact := []byte("signed executable bytes")
	installed, err := supervisor.Install(context.Background(), signedRequest(t, privateKey, artifact, "wireguard", "1.0.0"))
	require.NoError(t, err)
	require.Equal(t, "1.0.0", installed.DesiredVersion)

	config := []byte(`{"private_key_ref":"secret/wg-entry"}`)
	configured, err := supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("configure-1", "wireguard", "1.0.0", 1, config))
	require.NoError(t, err)
	require.JSONEq(t, `{"id":"wireguard","desired_version":"1.0.0","observed_version":"","previous_version":"","enabled":false,"health":"installed","config_hash":"`+configHash(config)+`","desired_revision":1,"observed_revision":0,"last_error":""}`, string(stripUpdatedAt(t, configured)))

	enable := testEnvelope("enable-1", "wireguard", "1.0.0", 2, []byte(`{}`))
	_, err = supervisor.Handle(context.Background(), "plugin.enable", enable)
	require.NoError(t, err)
	require.Equal(t, 1, runner.Starts())
	require.Equal(t, 1, health.Calls())
	_, err = supervisor.Handle(context.Background(), "plugin.enable", enable)
	require.NoError(t, err)
	require.Equal(t, 1, runner.Starts(), "same journaled operation must not restart the plugin")

	_, err = supervisor.Handle(context.Background(), "plugin.disable", testEnvelope("disable-1", "wireguard", "1.0.0", 3, []byte(`{}`)))
	require.NoError(t, err)
	require.True(t, runner.Process().Stopped())
	state, err := supervisor.inspect("wireguard")
	require.NoError(t, err)
	require.Contains(t, string(state), `"desired_version":"1.0.0"`, "disable preserves installed data")
}

func TestConfigureEnabledPluginRestartsWithNewConfig(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	runner := &configRecordingRunner{}
	socketDir, err := os.MkdirTemp("", "anix-cfg-sock-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), SocketDir: socketDir, PublicKey: publicKey, Runner: runner, Health: &configRejectingHealth{runner: runner}})
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("configure-restart"), "machine-telemetry", "1.0.0"))
	require.NoError(t, err)
	oldConfig := []byte(`{"interval_seconds":60}`)
	_, err = supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("configure-old", "machine-telemetry", "1.0.0", 1, oldConfig))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("enable-configured", "machine-telemetry", "1.0.0", 2, nil))
	require.NoError(t, err)

	newConfig := []byte(`{"interval_seconds":30}`)
	result, err := supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("configure-new", "machine-telemetry", "1.0.0", 3, newConfig))
	require.NoError(t, err)
	require.JSONEq(t, `{"id":"machine-telemetry","desired_version":"1.0.0","observed_version":"1.0.0","previous_version":"","enabled":true,"health":"healthy","config_hash":"`+configHash(newConfig)+`","desired_revision":3,"observed_revision":3,"last_error":""}`, string(stripUpdatedAt(t, result)))
	require.Equal(t, [][]byte{oldConfig, newConfig}, runner.Configs())
	processes := runner.Processes()
	require.Len(t, processes, 2)
	require.True(t, processes[0].Stopped())
	require.False(t, processes[1].Stopped())
	require.NoError(t, supervisor.Close(context.Background()))
}

func TestConfigureEnabledPluginHealthFailureRestoresOldConfigAndProcess(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	runner := &configRecordingRunner{}
	badConfig := []byte(`{"interval_seconds":30}`)
	health := &configRejectingHealth{runner: runner, rejectConfig: string(badConfig)}
	root := t.TempDir()
	socketDir, err := os.MkdirTemp("", "anix-cfg-sock-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	supervisor, err := NewSupervisor(Config{RootDir: root, SocketDir: socketDir, PublicKey: publicKey, Runner: runner, Health: health})
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("configure-rollback"), "machine-telemetry", "1.0.0"))
	require.NoError(t, err)
	oldConfig := []byte(`{"interval_seconds":60}`)
	_, err = supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("configure-good", "machine-telemetry", "1.0.0", 1, oldConfig))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("enable-good", "machine-telemetry", "1.0.0", 2, nil))
	require.NoError(t, err)

	_, err = supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("configure-bad", "machine-telemetry", "1.0.0", 3, badConfig))
	require.ErrorContains(t, err, "injected config health failure")
	storedConfig, readErr := os.ReadFile(filepath.Join(root, "machine-telemetry", "1.0.0", "config.json"))
	require.NoError(t, readErr)
	require.Equal(t, oldConfig, storedConfig)
	require.Equal(t, [][]byte{oldConfig, badConfig, oldConfig}, runner.Configs())
	processes := runner.Processes()
	require.Len(t, processes, 3)
	require.True(t, processes[0].Stopped(), "old process must stop before applying new config")
	require.True(t, processes[1].Stopped(), "unhealthy new process must be stopped")
	require.False(t, processes[2].Stopped(), "restored old process must remain active")
	stateJSON, inspectErr := supervisor.inspect("machine-telemetry")
	require.NoError(t, inspectErr)
	require.Contains(t, string(stateJSON), `"enabled":true`)
	require.Contains(t, string(stateJSON), `"health":"healthy"`)
	require.Contains(t, string(stateJSON), `"config_hash":"`+configHash(oldConfig)+`"`)
	require.Contains(t, string(stateJSON), "injected config health failure")
	require.NoError(t, supervisor.Close(context.Background()))
}

func TestSupervisorRejectsTamperedArtifactAndInlineSecret(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}})
	require.NoError(t, err)

	request := signedRequest(t, privateKey, []byte("expected"), "gost-mesh", "1.0.0")
	request.Artifact = []byte("tampered")
	_, err = supervisor.Install(context.Background(), request)
	require.ErrorContains(t, err, "hash mismatch")

	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("expected"), "gost-mesh", "1.0.0"))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("configure-secret", "gost-mesh", "1.0.0", 1, []byte(`{"apiKey":"inline-secret"}`)))
	require.ErrorContains(t, err, "reference secrets")
}

func configHash(config []byte) string {
	digest := sha256.Sum256(config)
	return hex.EncodeToString(digest[:])
}

func stripUpdatedAt(t *testing.T, raw []byte) []byte {
	t.Helper()
	var value map[string]any
	require.NoError(t, json.Unmarshal(raw, &value))
	delete(value, "updated_at")
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return encoded
}

func TestSupervisorCloseStopsProcesses(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	runner := &fakeRunner{}
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: runner, Health: &fakeHealth{}, Now: func() time.Time { return time.Unix(1, 0) }})
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("artifact"), "nftables-forward", "1.0.0"))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("enable-close", "nftables-forward", "1.0.0", 1, []byte(`{}`)))
	require.NoError(t, err)
	require.NoError(t, supervisor.Close(context.Background()))
	require.True(t, runner.Process().Stopped())
}

func TestSupervisorMarksUnexpectedProcessExitUnhealthyAndDisablesRestore(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	socketDir, err := os.MkdirTemp("", "anix-crash-sock-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	runner := &watchableRunner{}
	supervisor, err := NewSupervisor(Config{RootDir: root, SocketDir: socketDir, PublicKey: publicKey, Runner: runner, Health: &fakeHealth{}})
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("crash-observed"), "machine-telemetry", "1.0.0"))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("enable-crash-test", "machine-telemetry", "1.0.0", 1, nil))
	require.NoError(t, err)
	require.Equal(t, 1, runner.Starts())
	runner.Process().Crash(errors.New("injected plugin crash"))

	require.Eventually(t, func() bool {
		stateJSON, inspectErr := supervisor.inspect("machine-telemetry")
		return inspectErr == nil && strings.Contains(string(stateJSON), `"enabled":false`) &&
			strings.Contains(string(stateJSON), `"health":"unhealthy"`) &&
			strings.Contains(string(stateJSON), "injected plugin crash")
	}, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, supervisor.Close(context.Background()))

	restartRunner := &fakeRunner{}
	restarted, err := NewSupervisor(Config{RootDir: root, SocketDir: socketDir, PublicKey: publicKey, Runner: restartRunner, Health: &fakeHealth{}})
	require.NoError(t, err)
	require.Equal(t, 0, restartRunner.Starts(), "unexpectedly exited plugin must not auto-restore on Agent restart")
	require.NoError(t, restarted.Close(context.Background()))
}

func TestVerifyManifestMatchesControlCanonicalContract(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	manifestJSON := readAgentManifestGolden(t)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestJSON))
	manifest, err := VerifyManifest(string(manifestJSON), signature, publicKey)
	require.NoError(t, err)
	canonical, err := CanonicalManifest(*manifest)
	require.NoError(t, err)
	require.Equal(t, string(manifestJSON), string(canonical))
	require.Equal(t, "machine-telemetry", manifest.ID)
	require.Equal(t, []string{"any"}, manifest.Architectures)
	require.Equal(t, []string{"/api/v3/plugins/machine-telemetry/status"}, manifest.ControlRoutes)
	require.NotNil(t, manifest.WebUI)
	require.Equal(t, "webui/index.mjs", manifest.WebUI.Bundle.Path)

	_, err = VerifyManifest(string(manifestJSON)+` {}`, signature, publicKey)
	require.ErrorContains(t, err, "multiple JSON values")
}

func TestManifestSharedNegativeFixtures(t *testing.T) {
	for _, fixture := range readAgentManifestNegativeFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			var manifest Manifest
			decoder := json.NewDecoder(bytes.NewReader(fixture.Manifest))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&manifest)
			if err == nil {
				err = manifest.validateForRuntime("linux", "amd64")
			}
			require.ErrorContains(t, err, fixture.WantError)
		})
	}
}

func TestManifestContractValidation(t *testing.T) {
	base := Manifest{
		ID: "gost-mesh", Name: "GOST Mesh", Version: "1.0.0", APIVersion: pluginAPIVersion,
		Publisher: manifestPublisher, Targets: []string{"agent"}, Architectures: []string{"linux/amd64"},
		ArtifactSHA256: strings.Repeat("a", sha256.Size*2), Dependencies: []string{"machine-telemetry"},
		Conflicts: []string{"legacy-gost"}, Entrypoints: map[string]string{"health": "bin/health"},
	}
	require.NoError(t, base.validateForRuntime("linux", "amd64"))

	tests := []struct {
		name    string
		mutate  func(*Manifest)
		wantErr string
	}{
		{name: "API version", mutate: func(m *Manifest) { m.APIVersion = "v2" }, wantErr: "API version"},
		{name: "unsafe version", mutate: func(m *Manifest) { m.Version = "../1.0.0" }, wantErr: "safe path"},
		{name: "wrong architecture", mutate: func(m *Manifest) { m.Architectures = []string{"windows/amd64"} }, wantErr: "does not support"},
		{name: "duplicate architecture", mutate: func(m *Manifest) { m.Architectures = []string{"amd64", "amd64"} }, wantErr: "duplicate"},
		{name: "self dependency", mutate: func(m *Manifest) { m.Dependencies = []string{"gost-mesh"} }, wantErr: "depend on itself"},
		{name: "duplicate dependency", mutate: func(m *Manifest) { m.Dependencies = []string{"wireguard", "wireguard"} }, wantErr: "duplicate"},
		{name: "dependency conflict overlap", mutate: func(m *Manifest) { m.Dependencies, m.Conflicts = []string{"wireguard"}, []string{"wireguard"} }, wantErr: "both a dependency"},
		{name: "entrypoint traversal", mutate: func(m *Manifest) { m.Entrypoints = map[string]string{"health": "../bin/health"} }, wantErr: "relative path"},
		{name: "array config schema", mutate: func(m *Manifest) { m.ConfigSchema = json.RawMessage(`[]`) }, wantErr: "config_schema"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := base
			test.mutate(&manifest)
			require.ErrorContains(t, manifest.validateForRuntime("linux", "amd64"), test.wantErr)
		})
	}

	universal := base
	universal.Architectures = nil
	require.NoError(t, universal.validateForRuntime("freebsd", "arm64"), "empty architecture remains legacy-compatible")
}

func TestManifestControlRouteValidation(t *testing.T) {
	base := Manifest{
		ID: "machine-telemetry", Name: "Machine Telemetry", Version: "1.0.0", APIVersion: pluginAPIVersion,
		Publisher: manifestPublisher, Targets: []string{"agent", "control"}, Architectures: []string{"linux/amd64"},
		ArtifactSHA256: strings.Repeat("a", sha256.Size*2),
		Permissions:    []string{"machine-telemetry.api"},
		ControlRoutes:  []string{"/api/v3/plugins/machine-telemetry/status", "/api/v3/plugins/machine-telemetry/admin/*"},
		Entrypoints:    map[string]string{"health": "bin/health"},
	}
	require.NoError(t, base.validateForRuntime("linux", "amd64"))

	tests := []struct {
		name    string
		mutate  func(*Manifest)
		wantErr string
	}{
		{name: "without control target", mutate: func(m *Manifest) { m.Targets = []string{"agent"} }, wantErr: "control target"},
		{name: "missing api permission", mutate: func(m *Manifest) { m.Permissions = []string{"machine-telemetry.view"} }, wantErr: "machine-telemetry.api"},
		{name: "permission outside namespace", mutate: func(m *Manifest) { m.Permissions = append(m.Permissions, "admin.users") }, wantErr: "outside the plugin namespace"},
		{name: "outside plugin namespace", mutate: func(m *Manifest) { m.ControlRoutes = []string{"/api/v3/plugins/wireguard/status"} }, wantErr: "outside"},
		{name: "query string", mutate: func(m *Manifest) { m.ControlRoutes = []string{"/api/v3/plugins/machine-telemetry/status?x=1"} }, wantErr: "unsafe"},
		{name: "middle wildcard", mutate: func(m *Manifest) { m.ControlRoutes = []string{"/api/v3/plugins/machine-telemetry/*/status"} }, wantErr: "wildcard"},
		{name: "duplicate route", mutate: func(m *Manifest) {
			m.ControlRoutes = []string{"/api/v3/plugins/machine-telemetry/status", "/api/v3/plugins/machine-telemetry/status"}
		}, wantErr: "duplicate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := base
			manifest.Permissions = append([]string{}, base.Permissions...)
			manifest.ControlRoutes = append([]string{}, base.ControlRoutes...)
			manifest.Targets = append([]string{}, base.Targets...)
			test.mutate(&manifest)
			require.ErrorContains(t, manifest.validateForRuntime("linux", "amd64"), test.wantErr)
		})
	}
}

func TestManifestWebUIValidation(t *testing.T) {
	var base Manifest
	require.NoError(t, json.Unmarshal(readAgentManifestGolden(t), &base))
	require.NoError(t, base.validateForRuntime("linux", "amd64"))

	tests := []struct {
		name    string
		mutate  func(*Manifest)
		wantErr string
	}{
		{name: "webui without control target", mutate: func(m *Manifest) { m.Targets = []string{"agent"} }, wantErr: "control target"},
		{name: "remote bundle", mutate: func(m *Manifest) { m.WebUI.Bundle.Path = "https://evil.example/plugin.mjs" }, wantErr: "bundle path"},
		{name: "bundle traversal", mutate: func(m *Manifest) { m.WebUI.Bundle.Path = "webui/../plugin.mjs" }, wantErr: "bundle path"},
		{name: "route outside namespace", mutate: func(m *Manifest) { m.WebUI.Routes[0].Path = "/admin/users" }, wantErr: "outside"},
		{name: "undeclared permission", mutate: func(m *Manifest) { m.WebUI.Permissions = []string{"machine-telemetry.other"} }, wantErr: "not declared"},
		{name: "frontend mismatch", mutate: func(m *Manifest) { m.FrontendSHA256 = strings.Repeat("c", 64) }, wantErr: "frontend_sha256"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := base
			manifest.Permissions = append([]string(nil), base.Permissions...)
			manifest.Targets = append([]string(nil), base.Targets...)
			manifest.WebUI = &PluginWebUI{
				Bundle:      base.WebUI.Bundle,
				Permissions: append([]string(nil), base.WebUI.Permissions...),
				Menus:       append([]PluginWebUIMenu(nil), base.WebUI.Menus...),
				Routes:      append([]PluginWebUIRoute(nil), base.WebUI.Routes...),
			}
			test.mutate(&manifest)
			require.ErrorContains(t, manifest.validateForRuntime("linux", "amd64"), test.wantErr)
		})
	}
}

func TestInstallStagesNewVersionUntilUpdate(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	runner := &fakeRunner{}
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: runner, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = supervisor.Close(context.Background()) })

	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("version one"), "wireguard", "1.0.0"))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("enable-v1", "wireguard", "1.0.0", 1, []byte(`{}`)))
	require.NoError(t, err)
	oldProcess := runner.Process()
	staged, err := supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("version two"), "wireguard", "2.0.0"))
	require.NoError(t, err)
	require.Equal(t, "1.0.0", staged.DesiredVersion)
	require.False(t, oldProcess.Stopped())

	result, err := supervisor.Handle(context.Background(), "plugin.update", testEnvelope("update-v2", "wireguard", "2.0.0", 2, []byte(`{}`)))
	require.NoError(t, err)
	require.Contains(t, string(result), `"desired_version":"2.0.0"`)
	require.Contains(t, string(result), `"previous_version":"1.0.0"`)
	require.True(t, oldProcess.Stopped())
	require.Equal(t, 2, runner.Starts())
}

type versionRunner struct {
	mu          sync.Mutex
	failVersion string
	starts      []string
	processes   []*fakeProcess
}

func (r *versionRunner) Start(_ context.Context, binaryPath, _, _ string) (Process, error) {
	version := filepath.Base(filepath.Dir(binaryPath))
	r.mu.Lock()
	defer r.mu.Unlock()
	r.starts = append(r.starts, version)
	if version == r.failVersion {
		return nil, errors.New("injected start failure")
	}
	process := &fakeProcess{}
	r.processes = append(r.processes, process)
	return process, nil
}

func (r *versionRunner) Versions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.starts...)
}

func TestUpdateFailureAutomaticallyRestoresOldVersion(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	runner := &versionRunner{failVersion: "2.0.0"}
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: runner, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = supervisor.Close(context.Background()) })
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("one"), "gost-mesh", "1.0.0"))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("enable-old", "gost-mesh", "1.0.0", 1, []byte(`{}`)))
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("two"), "gost-mesh", "2.0.0"))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.update", testEnvelope("update-fail", "gost-mesh", "2.0.0", 2, []byte(`{}`)))
	require.ErrorContains(t, err, "injected start failure")
	stateJSON, inspectErr := supervisor.inspect("gost-mesh")
	require.NoError(t, inspectErr)
	require.Contains(t, string(stateJSON), `"desired_version":"1.0.0"`)
	require.Contains(t, string(stateJSON), `"enabled":true`)
	require.Contains(t, string(stateJSON), `"health":"healthy"`)
	require.Equal(t, []string{"1.0.0", "2.0.0", "1.0.0"}, runner.Versions())
}

func TestSupervisorRestoresEnabledPluginAfterRestart(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	firstRunner := &fakeRunner{}
	first, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: firstRunner, Health: &fakeHealth{}})
	require.NoError(t, err)
	_, err = first.Install(context.Background(), signedRequest(t, privateKey, []byte("restore"), "nat-egress", "1.0.0"))
	require.NoError(t, err)
	_, err = first.Handle(context.Background(), "plugin.enable", testEnvelope("enable-restore", "nat-egress", "1.0.0", 1, []byte(`{}`)))
	require.NoError(t, err)
	require.NoError(t, first.Close(context.Background()))

	restartRunner := &fakeRunner{}
	restarted, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: restartRunner, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = restarted.Close(context.Background()) })
	require.Equal(t, 1, restartRunner.Starts())
	stateJSON, err := restarted.inspect("nat-egress")
	require.NoError(t, err)
	require.Contains(t, string(stateJSON), `"health":"healthy"`)
}

func TestSupervisorRejectsTamperedInstalledArtifactBeforeStart(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	runner := &fakeRunner{}
	supervisor, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: runner, Health: &fakeHealth{}})
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("trusted"), "protocol-runtime", "1.0.0"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, "protocol-runtime", "1.0.0", pluginBinaryName), []byte("tampered"), 0o750))
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("enable-tampered", "protocol-runtime", "1.0.0", 1, []byte(`{}`)))
	require.ErrorContains(t, err, "artifact hash mismatch")
	require.Equal(t, 0, runner.Starts())
	require.NoError(t, supervisor.Close(context.Background()))
}

type blockingHealth struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (h *blockingHealth) Check(ctx context.Context, _ string) error {
	h.once.Do(func() { close(h.entered) })
	select {
	case <-h.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestConcurrentDuplicateOperationStartsOnce(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	runner := &fakeRunner{}
	health := &blockingHealth{entered: make(chan struct{}), release: make(chan struct{})}
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: runner, Health: health})
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("concurrent"), "wireguard", "1.0.0"))
	require.NoError(t, err)
	envelope := testEnvelope("same-operation", "wireguard", "1.0.0", 1, []byte(`{}`))
	results := make(chan error, 2)
	go func() { _, err := supervisor.Handle(context.Background(), "plugin.enable", envelope); results <- err }()
	<-health.entered
	go func() { _, err := supervisor.Handle(context.Background(), "plugin.enable", envelope); results <- err }()
	close(health.release)
	require.NoError(t, <-results)
	require.NoError(t, <-results)
	require.Equal(t, 1, runner.Starts())
	require.NoError(t, supervisor.Close(context.Background()))
}

func TestJournalBindsOperationKindAndIdempotencyKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("journal"), "wireguard", "1.0.0"))
	require.NoError(t, err)
	envelope := testEnvelope("inspect-one", "wireguard", "1.0.0", 1, []byte(`{}`))
	_, err = supervisor.Handle(context.Background(), "plugin.inspect", envelope)
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.health", envelope)
	require.ErrorContains(t, err, "operation_id is already bound")
	other := testEnvelope("inspect-two", "wireguard", "1.0.0", 2, []byte(`{}`))
	other.IdempotencyKey = envelope.IdempotencyKey
	_, err = supervisor.Handle(context.Background(), "plugin.inspect", other)
	require.ErrorContains(t, err, "idempotency_key is already bound")
	require.NoError(t, supervisor.Close(context.Background()))
}

func TestCompletedJournalReplaysAcrossAgentControlSession(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	runner := &fakeRunner{}
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: runner, Health: &fakeHealth{}})
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("session-replay"), "wireguard", "1.0.0"))
	require.NoError(t, err)

	envelope := testEnvelope("enable-across-session", "wireguard", "1.0.0", 1, []byte(`{}`))
	first, err := supervisor.Handle(context.Background(), "plugin.enable", envelope)
	require.NoError(t, err)
	require.Equal(t, 1, runner.Starts())

	replayed := *envelope
	replayed.SessionID = "session-after-control-restart"
	second, err := supervisor.Handle(context.Background(), "plugin.enable", &replayed)
	require.NoError(t, err)
	require.JSONEq(t, string(first), string(second))
	require.Equal(t, 1, runner.Starts(), "cross-session replay must return the journaled result without restarting")
	require.NoError(t, supervisor.Close(context.Background()))
}
