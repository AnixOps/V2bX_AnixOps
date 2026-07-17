package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTelemetryMetricsDoesNotPollPluginWithoutTelemetryCapability(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	supervisor, err := NewSupervisor(Config{
		RootDir: t.TempDir(), SocketDir: shortSocketDir(t), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{},
	})
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("no-telemetry"), "example", "1.0.0"))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("enable-no-telemetry", "example", "1.0.0", 1, nil))
	require.NoError(t, err)
	metricsCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	metrics, err := supervisor.TelemetryMetrics(metricsCtx)
	require.NoError(t, err)
	require.Empty(t, metrics)
	require.NoError(t, supervisor.Close(context.Background()))
}

func TestTelemetryMetricsReportsMissingSocketForDeclaredCapability(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	supervisor, err := NewSupervisor(Config{
		RootDir: t.TempDir(), SocketDir: shortSocketDir(t), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{},
	})
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequestWithCapabilities(t, privateKey, []byte("telemetry"), "example", "1.0.0", []string{"telemetry.read"}))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("enable-telemetry", "example", "1.0.0", 1, nil))
	require.NoError(t, err)
	metricsCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	metrics, err := supervisor.TelemetryMetrics(metricsCtx)
	require.ErrorContains(t, err, "collect telemetry plugin example")
	require.Empty(t, metrics)
	require.NoError(t, supervisor.Close(context.Background()))
}
