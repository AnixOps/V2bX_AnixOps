package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRestartDefersRestoreUntilInterruptedDisableReplays(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	socketDir := shortSocketDir(t)
	firstRunner := &fakeRunner{}
	first, err := NewSupervisor(Config{RootDir: root, SocketDir: socketDir, PublicKey: publicKey, Runner: firstRunner, Health: &fakeHealth{}})
	require.NoError(t, err)
	_, err = first.Install(context.Background(), signedRequest(t, privateKey, []byte("disable-crash"), "wireguard", "1.0.0"))
	require.NoError(t, err)
	config := []byte(`{"listen":"127.0.0.1:51820"}`)
	_, err = first.Handle(context.Background(), "plugin.configure", testEnvelope("disable-crash-config", "wireguard", "1.0.0", 1, config))
	require.NoError(t, err)
	_, err = first.Handle(context.Background(), "plugin.enable", testEnvelope("disable-crash-enable", "wireguard", "1.0.0", 2, []byte(`{}`)))
	require.NoError(t, err)

	disable := testEnvelope("disable-crash-operation", "wireguard", "1.0.0", 3, []byte(`{}`))
	first.mu.Lock()
	first.state.Journal[disable.OperationID] = newJournalEntry("plugin.disable", disable, time.Unix(10, 0))
	process := first.processes["wireguard"]
	first.removeProcessLocked("wireguard")
	require.NoError(t, first.persistLocked())
	first.mu.Unlock()
	require.NoError(t, process.Stop(context.Background()))
	require.NoError(t, first.Close(context.Background()))

	restartRunner := &fakeRunner{}
	restarted, err := NewSupervisor(Config{RootDir: root, SocketDir: socketDir, PublicKey: publicKey, Runner: restartRunner, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restarted.Close(context.Background())) })
	require.Zero(t, restartRunner.Starts(), "an interrupted disable must not restore the old data plane")
	stateJSON, err := restarted.inspect("wireguard")
	require.NoError(t, err)
	require.Contains(t, string(stateJSON), `"enabled":true`)
	require.Contains(t, string(stateJSON), `"health":"interrupted"`)

	result, err := restarted.Handle(context.Background(), "plugin.disable", disable)
	require.NoError(t, err)
	require.Contains(t, string(result), `"enabled":false`)
	require.Contains(t, string(result), `"health":"disabled"`)
	require.Contains(t, string(result), `"observed_revision":3`)
	require.Zero(t, restartRunner.Starts())
}

func TestRestartDefersUncommittedConfigUntilExactReplay(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	socketDir := shortSocketDir(t)
	firstRunner := &fakeRunner{}
	first, err := NewSupervisor(Config{RootDir: root, SocketDir: socketDir, PublicKey: publicKey, Runner: firstRunner, Health: &fakeHealth{}})
	require.NoError(t, err)
	_, err = first.Install(context.Background(), signedRequest(t, privateKey, []byte("configure-crash"), "machine-telemetry", "1.0.0"))
	require.NoError(t, err)
	oldConfig := []byte(`{"interval_seconds":30}`)
	newConfig := []byte(`{"interval_seconds":15}`)
	_, err = first.Handle(context.Background(), "plugin.configure", testEnvelope("configure-crash-old", "machine-telemetry", "1.0.0", 1, oldConfig))
	require.NoError(t, err)
	_, err = first.Handle(context.Background(), "plugin.enable", testEnvelope("configure-crash-enable", "machine-telemetry", "1.0.0", 2, []byte(`{}`)))
	require.NoError(t, err)

	configure := testEnvelope("configure-crash-operation", "machine-telemetry", "1.0.0", 3, newConfig)
	first.mu.Lock()
	first.state.Journal[configure.OperationID] = newJournalEntry("plugin.configure", configure, time.Unix(20, 0))
	process := first.processes["machine-telemetry"]
	first.removeProcessLocked("machine-telemetry")
	require.NoError(t, first.persistLocked())
	first.mu.Unlock()
	require.NoError(t, process.Stop(context.Background()))
	require.NoError(t, writePrivateFile(filepath.Join(root, "machine-telemetry", "1.0.0", "config.json"), newConfig, 0o600))
	require.NoError(t, first.Close(context.Background()))

	restartRunner := &configRecordingRunner{}
	restarted, err := NewSupervisor(Config{RootDir: root, SocketDir: socketDir, PublicKey: publicKey, Runner: restartRunner, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restarted.Close(context.Background())) })
	require.Empty(t, restartRunner.Configs(), "uncommitted config must not start before exact replay")
	stateJSON, err := restarted.inspect("machine-telemetry")
	require.NoError(t, err)
	require.Contains(t, string(stateJSON), `"config_hash":"`+configHash(oldConfig)+`"`)
	require.Contains(t, string(stateJSON), `"health":"interrupted"`)

	result, err := restarted.Handle(context.Background(), "plugin.configure", configure)
	require.NoError(t, err)
	require.Contains(t, string(result), `"config_hash":"`+configHash(newConfig)+`"`)
	require.Contains(t, string(result), `"health":"healthy"`)
	require.Equal(t, [][]byte{newConfig}, restartRunner.Configs())
	stored, err := os.ReadFile(filepath.Join(root, "machine-telemetry", "1.0.0", "config.json"))
	require.NoError(t, err)
	require.Equal(t, newConfig, stored)
}

func TestRestartRestoresWhenInterruptedTransitionIsOlderThanDesiredState(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	socketDir := shortSocketDir(t)
	first, err := NewSupervisor(Config{RootDir: root, SocketDir: socketDir, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	_, err = first.Install(context.Background(), signedRequest(t, privateKey, []byte("stale-interrupted"), "nat-egress", "1.0.0"))
	require.NoError(t, err)
	_, err = first.Handle(context.Background(), "plugin.configure", testEnvelope("stale-config", "nat-egress", "1.0.0", 1, []byte(`{}`)))
	require.NoError(t, err)
	_, err = first.Handle(context.Background(), "plugin.enable", testEnvelope("stale-enable", "nat-egress", "1.0.0", 2, []byte(`{}`)))
	require.NoError(t, err)

	obsolete := testEnvelope("obsolete-disable", "nat-egress", "1.0.0", 1, []byte(`{}`))
	first.mu.Lock()
	first.state.Journal[obsolete.OperationID] = newJournalEntry("plugin.disable", obsolete, time.Unix(30, 0))
	require.NoError(t, first.persistLocked())
	first.mu.Unlock()
	require.NoError(t, first.Close(context.Background()))

	restartRunner := &fakeRunner{}
	restarted, err := NewSupervisor(Config{RootDir: root, SocketDir: socketDir, PublicKey: publicKey, Runner: restartRunner, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restarted.Close(context.Background())) })
	require.Equal(t, 1, restartRunner.Starts(), "an older interrupted journal must not suppress newer durable desired state")
	stateJSON, err := restarted.inspect("nat-egress")
	require.NoError(t, err)
	require.Contains(t, string(stateJSON), `"health":"healthy"`)
}

func TestOperationErrorIncludesTerminalPersistenceFailure(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	realPersist := supervisor.persistState
	t.Cleanup(func() {
		supervisor.persistState = realPersist
		require.NoError(t, supervisor.Close(context.Background()))
	})

	operationErr := errors.New("injected install loader failure")
	persistErr := errors.New("injected terminal persistence failure")
	persistCalls := 0
	supervisor.persistState = func(encoded []byte) error {
		persistCalls++
		if persistCalls == 2 {
			return persistErr
		}
		return realPersist(encoded)
	}
	envelope := testEnvelope("persist-failure-install", "wireguard", "1.0.0", 1, []byte(`{}`))
	_, err = supervisor.HandleInstall(context.Background(), envelope, func(context.Context) (InstallRequest, error) {
		return InstallRequest{}, operationErr
	})
	require.ErrorIs(t, err, operationErr)
	require.ErrorIs(t, err, persistErr)
	require.Equal(t, 2, persistCalls)
}
