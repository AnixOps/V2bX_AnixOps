package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRemoteInstallerDownloadsAuthenticatedSignedReleaseAndReplaysWithoutFetching(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	supervisor, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })

	request := signedRequest(t, privateKey, []byte("remote signed plugin"), "wireguard", "4.0.0-alpha.1")
	var manifestRequests, artifactRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, requestHTTP *http.Request) {
		require.Equal(t, "node-api-key", requestHTTP.Header.Get("X-API-Key"))
		require.Equal(t, "identity", requestHTTP.Header.Get("Accept-Encoding"))
		switch {
		case strings.HasSuffix(requestHTTP.URL.Path, "/manifest"):
			manifestRequests.Add(1)
			_, _ = response.Write([]byte(request.ManifestJSON))
		case strings.HasSuffix(requestHTTP.URL.Path, "/artifact"):
			artifactRequests.Add(1)
			_, _ = response.Write(request.Artifact)
		default:
			http.NotFound(response, requestHTTP)
		}
	}))
	defer server.Close()

	payload := remoteInstallPayload(t, publicKey, request, "wireguard", "4.0.0-alpha.1")
	envelope := testEnvelope("remote-install-1", "wireguard", "4.0.0-alpha.1", 1, payload)
	installer, err := NewRemoteInstaller(RemoteInstallerConfig{
		Supervisor: supervisor, BaseURL: server.URL + "/ignored/base/path", APIKey: "node-api-key",
	})
	require.NoError(t, err)

	first, err := installer.Handle(context.Background(), envelope)
	require.NoError(t, err)
	require.Contains(t, string(first), `"desired_version":"4.0.0-alpha.1"`)
	require.Contains(t, string(first), `"desired_revision":1`)
	require.Contains(t, string(first), `"observed_revision":1`)
	require.FileExists(t, filepath.Join(root, "wireguard", "4.0.0-alpha.1", pluginBinaryName))

	second, err := installer.Handle(context.Background(), envelope)
	require.NoError(t, err)
	require.JSONEq(t, string(first), string(second))
	require.Equal(t, int32(1), manifestRequests.Load())
	require.Equal(t, int32(1), artifactRequests.Load())
}

func TestRemoteInstallerRejectsRedirectBeforeArtifactDownload(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
	request := signedRequest(t, privateKey, []byte("redirect target"), "wireguard", "4.0.0-alpha.1")
	var redirected, artifactRequests atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer redirectTarget.Close()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, requestHTTP *http.Request) {
		if strings.HasSuffix(requestHTTP.URL.Path, "/manifest") {
			http.Redirect(response, requestHTTP, redirectTarget.URL, http.StatusFound)
			return
		}
		artifactRequests.Add(1)
		_, _ = response.Write(request.Artifact)
	}))
	defer server.Close()
	installer, err := NewRemoteInstaller(RemoteInstallerConfig{Supervisor: supervisor, BaseURL: server.URL, APIKey: "node-api-key"})
	require.NoError(t, err)
	envelope := testEnvelope("redirect-install", "wireguard", "4.0.0-alpha.1", 1, remoteInstallPayload(t, publicKey, request, "wireguard", "4.0.0-alpha.1"))
	_, err = installer.Handle(context.Background(), envelope)
	require.ErrorContains(t, err, "unexpected HTTP status 302")
	require.Zero(t, redirected.Load())
	require.Zero(t, artifactRequests.Load())
}

func TestRemoteInstallerRejectsUnsafeOrMismatchedURLs(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
	installer, err := NewRemoteInstaller(RemoteInstallerConfig{Supervisor: supervisor, BaseURL: "https://control.example.com", APIKey: "node-api-key"})
	require.NoError(t, err)
	request := signedRequest(t, privateKey, []byte("unsafe URL"), "wireguard", "4.0.0-alpha.1")

	tests := []struct {
		name string
		url  string
		err  string
	}{
		{name: "cross origin", url: "https://evil.example/plugin", err: "same-origin absolute path"},
		{name: "network path", url: "//evil.example/plugin", err: "same-origin absolute path"},
		{name: "traversal", url: "/api/v3/agent/plugin-releases/wireguard/4.0.0-alpha.1/../artifact?sha256=x&size=1", err: "does not match"},
		{name: "encoded traversal", url: "/api/v3/agent/plugin-releases/wireguard/%2e%2e/artifact?sha256=x&size=1", err: "encoded path"},
		{name: "wrong release", url: "/api/v3/agent/plugin-releases/other/4.0.0-alpha.1/artifact?sha256=x&size=1", err: "does not match"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var spec remoteInstallSpec
			require.NoError(t, json.Unmarshal(remoteInstallPayload(t, publicKey, request, "wireguard", "4.0.0-alpha.1"), &spec))
			spec.Artifact.URL = test.url
			payload, marshalErr := json.Marshal(spec)
			require.NoError(t, marshalErr)
			envelope := testEnvelope("unsafe-"+strings.ReplaceAll(test.name, " ", "-"), "wireguard", "4.0.0-alpha.1", 1, payload)
			_, handleErr := installer.Handle(context.Background(), envelope)
			require.ErrorContains(t, handleErr, test.err)
		})
	}
}

func TestRemoteInstallerRejectsTamperedManifestWithoutDownloadingArtifact(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
	request := signedRequest(t, privateKey, []byte("signed artifact"), "wireguard", "4.0.0-alpha.1")
	tamperedManifest := strings.Replace(request.ManifestJSON, `"name":"wireguard"`, `"name":"tampered"`, 1)
	var artifactRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, requestHTTP *http.Request) {
		if strings.HasSuffix(requestHTTP.URL.Path, "/manifest") {
			_, _ = response.Write([]byte(tamperedManifest))
			return
		}
		artifactRequests.Add(1)
		_, _ = response.Write(request.Artifact)
	}))
	defer server.Close()
	manifestDigest := sha256.Sum256([]byte(tamperedManifest))
	var spec remoteInstallSpec
	require.NoError(t, json.Unmarshal(remoteInstallPayload(t, publicKey, request, "wireguard", "4.0.0-alpha.1"), &spec))
	spec.Manifest.SHA256 = hex.EncodeToString(manifestDigest[:])
	spec.Manifest.Size = int64(len(tamperedManifest))
	spec.Manifest.URL = releaseAssetURL("wireguard", "4.0.0-alpha.1", "manifest", spec.Manifest.remoteAsset)
	payload, err := json.Marshal(spec)
	require.NoError(t, err)
	installer, err := NewRemoteInstaller(RemoteInstallerConfig{Supervisor: supervisor, BaseURL: server.URL, APIKey: "node-api-key"})
	require.NoError(t, err)
	_, err = installer.Handle(context.Background(), testEnvelope("tampered-install", "wireguard", "4.0.0-alpha.1", 1, payload))
	require.ErrorContains(t, err, "verify downloaded plugin manifest")
	require.Zero(t, artifactRequests.Load())
}

func TestRemoteInstallerRejectsArtifactSizeAndHashMismatch(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	request := signedRequest(t, privateKey, []byte("signed artifact"), "wireguard", "4.0.0-alpha.1")
	for _, test := range []struct {
		name     string
		artifact []byte
		wantErr  string
	}{
		{name: "size", artifact: append(append([]byte(nil), request.Artifact...), '!'), wantErr: "content length does not match"},
		{name: "sha256", artifact: []byte("tamper artifact"), wantErr: "SHA-256 mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			supervisor, createErr := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
			require.NoError(t, createErr)
			t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, requestHTTP *http.Request) {
				if strings.HasSuffix(requestHTTP.URL.Path, "/manifest") {
					_, _ = response.Write([]byte(request.ManifestJSON))
					return
				}
				_, _ = response.Write(test.artifact)
			}))
			defer server.Close()
			installer, createErr := NewRemoteInstaller(RemoteInstallerConfig{Supervisor: supervisor, BaseURL: server.URL, APIKey: "node-api-key"})
			require.NoError(t, createErr)
			payload := remoteInstallPayload(t, publicKey, request, "wireguard", "4.0.0-alpha.1")
			_, handleErr := installer.Handle(context.Background(), testEnvelope("artifact-"+test.name, "wireguard", "4.0.0-alpha.1", 1, payload))
			require.ErrorContains(t, handleErr, test.wantErr)
		})
	}
}

func TestRemoteInstallerRejectsArtifactMetadataAbove64MiB(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
	request := signedRequest(t, privateKey, []byte("bounded artifact"), "wireguard", "4.0.0-alpha.1")
	var spec remoteInstallSpec
	require.NoError(t, json.Unmarshal(remoteInstallPayload(t, publicKey, request, "wireguard", "4.0.0-alpha.1"), &spec))
	spec.Artifact.Size = maxPluginArtifactBytes + 1
	spec.Artifact.URL = releaseAssetURL(spec.PluginID, spec.Version, "artifact", spec.Artifact)
	payload, err := json.Marshal(spec)
	require.NoError(t, err)
	installer, err := NewRemoteInstaller(RemoteInstallerConfig{Supervisor: supervisor, BaseURL: "https://control.example.com", APIKey: "node-api-key"})
	require.NoError(t, err)
	_, err = installer.Handle(context.Background(), testEnvelope("oversized-artifact", "wireguard", "4.0.0-alpha.1", 1, payload))
	require.ErrorContains(t, err, "size must be between 1 and 67108864 bytes")
}

func remoteInstallPayload(t *testing.T, publicKey ed25519.PublicKey, request InstallRequest, pluginID, version string) []byte {
	t.Helper()
	manifestDigest := sha256.Sum256([]byte(request.ManifestJSON))
	artifactDigest := sha256.Sum256(request.Artifact)
	manifestAsset := remoteAsset{SHA256: hex.EncodeToString(manifestDigest[:]), Size: int64(len(request.ManifestJSON))}
	artifactAsset := remoteAsset{SHA256: hex.EncodeToString(artifactDigest[:]), Size: int64(len(request.Artifact))}
	manifestAsset.URL = releaseAssetURL(pluginID, version, "manifest", manifestAsset)
	artifactAsset.URL = releaseAssetURL(pluginID, version, "artifact", artifactAsset)
	payload, err := json.Marshal(remoteInstallSpec{
		APIVersion: PluginInstallAPIVersion, PluginID: pluginID, Version: version, Artifact: artifactAsset,
		Manifest: remoteManifestAsset{
			remoteAsset: manifestAsset, Signature: request.Signature, Publisher: manifestPublisher,
			KeyID: trustRootKeyID(publicKey), APIVersion: pluginAPIVersion,
		},
	})
	require.NoError(t, err)
	return payload
}

func releaseAssetURL(pluginID, version, kind string, asset remoteAsset) string {
	return fmt.Sprintf("/api/v3/agent/plugin-releases/%s/%s/%s?sha256=%s&size=%d", pluginID, version, kind, asset.SHA256, asset.Size)
}

func TestInstallUsesAtomicVersionDirectoryAndCleansStaleStage(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	supervisor, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
	pluginDir := filepath.Join(root, "wireguard")
	require.NoError(t, os.MkdirAll(filepath.Join(pluginDir, ".1.0.0.staging-crashed"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, ".1.0.0.staging-crashed", "partial"), []byte("partial"), 0o600))
	request := signedRequest(t, privateKey, []byte("atomic artifact"), "wireguard", "1.0.0")
	_, err = supervisor.Install(context.Background(), request)
	require.NoError(t, err)
	require.NoDirExists(t, filepath.Join(pluginDir, ".1.0.0.staging-crashed"))
	require.FileExists(t, filepath.Join(pluginDir, "1.0.0", manifestFileName))
	require.FileExists(t, filepath.Join(pluginDir, "1.0.0", signatureFileName))
	require.FileExists(t, filepath.Join(pluginDir, "1.0.0", pluginBinaryName))
	_, err = supervisor.Install(context.Background(), request)
	require.NoError(t, err)
	entries, err := os.ReadDir(pluginDir)
	require.NoError(t, err)
	for _, entry := range entries {
		require.NotContains(t, entry.Name(), ".staging-")
	}
}

func TestInterruptedOperationExactReplayRepairsCurrentRevision(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	first, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	_, err = first.Install(context.Background(), signedRequest(t, privateKey, []byte("repair replay"), "wireguard", "1.0.0"))
	require.NoError(t, err)
	config := []byte(`{"listen":"127.0.0.1:51820"}`)
	_, err = first.Handle(context.Background(), "plugin.configure", testEnvelope("initial-config", "wireguard", "1.0.0", 1, config))
	require.NoError(t, err)
	repairEnvelope := testEnvelope("repair-config", "wireguard", "1.0.0", 1, config)
	first.mu.Lock()
	first.state.Journal[repairEnvelope.OperationID] = newJournalEntry("plugin.configure", repairEnvelope, time.Unix(10, 0))
	require.NoError(t, first.persistLocked())
	first.mu.Unlock()
	require.NoError(t, first.Close(context.Background()))

	restarted, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restarted.Close(context.Background())) })
	result, err := restarted.Handle(context.Background(), "plugin.configure", repairEnvelope)
	require.NoError(t, err)
	require.Contains(t, string(result), `"desired_revision":1`)
	restarted.mu.Lock()
	journal := restarted.state.Journal[repairEnvelope.OperationID]
	restarted.mu.Unlock()
	require.Equal(t, "succeeded", journal.State)
}

func TestUpdateAppliesTargetConfigAndHealthFailureRestoresOldVersion(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	runner := &configRecordingRunner{}
	badConfig := []byte(`{"listen":"bad"}`)
	supervisor, err := NewSupervisor(Config{
		RootDir: root, SocketDir: shortSocketDir(t), PublicKey: publicKey, Runner: runner,
		Health: &configRejectingHealth{runner: runner, rejectConfig: string(badConfig)},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("update-v1"), "wireguard", "1.0.0"))
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("update-v2"), "wireguard", "2.0.0"))
	require.NoError(t, err)
	oldConfig := []byte(`{"listen":"127.0.0.1:51820"}`)
	_, err = supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("update-config-v1", "wireguard", "1.0.0", 1, oldConfig))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("update-enable-v1", "wireguard", "1.0.0", 2, []byte(`{}`)))
	require.NoError(t, err)

	_, err = supervisor.Handle(context.Background(), "plugin.update", testEnvelope("update-bad-v2", "wireguard", "2.0.0", 3, badConfig))
	require.ErrorContains(t, err, "injected config health failure")
	stateJSON, inspectErr := supervisor.inspect("wireguard")
	require.NoError(t, inspectErr)
	require.Contains(t, string(stateJSON), `"desired_version":"1.0.0"`)
	require.Contains(t, string(stateJSON), `"observed_version":"1.0.0"`)
	require.Contains(t, string(stateJSON), `"config_hash":"`+configHash(oldConfig)+`"`)
	_, statErr := os.Stat(filepath.Join(root, "wireguard", "2.0.0", "config.json"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
	configs := runner.Configs()
	require.Equal(t, [][]byte{oldConfig, badConfig, oldConfig}, configs)
}

func TestUpdatePersistsSuccessfulTargetConfigHash(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	runner := &configRecordingRunner{}
	supervisor, err := NewSupervisor(Config{RootDir: root, SocketDir: shortSocketDir(t), PublicKey: publicKey, Runner: runner, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("success-v1"), "wireguard", "1.0.0"))
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("success-v2"), "wireguard", "2.0.0"))
	require.NoError(t, err)
	oldConfig := []byte(`{"listen":"127.0.0.1:51820"}`)
	newConfig := []byte(`{"listen":"127.0.0.1:51821"}`)
	_, err = supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("success-config-v1", "wireguard", "1.0.0", 1, oldConfig))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("success-enable-v1", "wireguard", "1.0.0", 2, []byte(`{}`)))
	require.NoError(t, err)
	result, err := supervisor.Handle(context.Background(), "plugin.update", testEnvelope("success-update-v2", "wireguard", "2.0.0", 3, newConfig))
	require.NoError(t, err)
	require.Contains(t, string(result), `"desired_version":"2.0.0"`)
	require.Contains(t, string(result), `"config_hash":"`+configHash(newConfig)+`"`)
	stored, err := os.ReadFile(filepath.Join(root, "wireguard", "2.0.0", "config.json"))
	require.NoError(t, err)
	require.Equal(t, newConfig, stored)
	require.Equal(t, [][]byte{oldConfig, newConfig}, runner.Configs())
}
