package plugin

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSupervisorInstallsPlatformEntrypointFromSignedPackage(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	supervisor, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)

	entrypoint := "agent/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin"
	binary := []byte("signed platform executable")
	artifact := makeZipArtifact(t, map[string][]byte{entrypoint: binary, "webui/index.mjs": []byte("export default {}")})
	request := signedPackageRequest(t, privateKey, artifact, Manifest{
		ID: "package-test", Name: "Package Test", Version: "1.0.0", APIVersion: pluginAPIVersion,
		Publisher: manifestPublisher, Targets: []string{"agent"}, Architectures: []string{runtime.GOOS + "/" + runtime.GOARCH},
		Entrypoints: map[string]string{"agent-" + runtime.GOOS + "-" + runtime.GOARCH: entrypoint},
	})

	_, err = supervisor.Install(context.Background(), request)
	require.NoError(t, err)
	versionDir := filepath.Join(root, "package-test", "1.0.0")
	installedBinary, err := os.ReadFile(filepath.Join(versionDir, pluginBinaryName))
	require.NoError(t, err)
	require.Equal(t, binary, installedBinary)
	storedPackage, err := os.ReadFile(filepath.Join(versionDir, pluginPackageName))
	require.NoError(t, err)
	require.Equal(t, artifact, storedPackage)
	require.NoError(t, supervisor.verifyInstalledVersion("package-test", "1.0.0"))

	require.NoError(t, os.WriteFile(filepath.Join(versionDir, pluginBinaryName), []byte("tampered"), 0o750))
	require.ErrorContains(t, supervisor.verifyInstalledVersion("package-test", "1.0.0"), "does not match the signed package entrypoint")
}

func TestSupervisorRejectsEntrypointChangeForSameArtifactAndVersion(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	supervisor, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)

	platformKey := "agent-" + runtime.GOOS + "-" + runtime.GOARCH
	firstPath := "agent/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin"
	secondPath := "agent/" + runtime.GOOS + "-" + runtime.GOARCH + "/alternate"
	firstBinary := []byte("first signed executable")
	artifact := makeZipArtifact(t, map[string][]byte{firstPath: firstBinary, secondPath: []byte("alternate signed executable")})
	manifest := Manifest{
		ID: "immutable-package", Name: "Immutable Package", Version: "1.0.0", APIVersion: pluginAPIVersion,
		Publisher: manifestPublisher, Targets: []string{"agent"}, Architectures: []string{runtime.GOOS + "/" + runtime.GOARCH},
		Entrypoints: map[string]string{platformKey: firstPath},
	}
	_, err = supervisor.Install(context.Background(), signedPackageRequest(t, privateKey, artifact, manifest))
	require.NoError(t, err)

	manifest.Entrypoints = map[string]string{platformKey: secondPath}
	_, err = supervisor.Install(context.Background(), signedPackageRequest(t, privateKey, artifact, manifest))
	require.ErrorContains(t, err, "versions are immutable")
	installed, err := os.ReadFile(filepath.Join(root, manifest.ID, manifest.Version, pluginBinaryName))
	require.NoError(t, err)
	require.Equal(t, firstBinary, installed)
}

func TestPackageEntrypointResolutionAndRejection(t *testing.T) {
	entrypoint := "agent/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin"
	manifest := Manifest{Entrypoints: map[string]string{
		"agent-any": "agent/any/plugin",
		"agent-" + runtime.GOOS + "-" + runtime.GOARCH: entrypoint,
	}}
	resolved, declared := resolveAgentEntrypoint(manifest, runtime.GOOS, runtime.GOARCH)
	require.True(t, declared)
	require.Equal(t, entrypoint, resolved)

	archive := makeZipArtifact(t, map[string][]byte{entrypoint: []byte("binary")})
	_, _, err := materializeAgentArtifact(Manifest{WebUI: &PluginWebUI{}}, archive)
	require.ErrorContains(t, err, "must declare an agent entrypoint")
	_, _, err = materializeAgentArtifact(Manifest{Entrypoints: map[string]string{"agent-other-arch": "agent/other/plugin"}}, archive)
	require.ErrorContains(t, err, "no agent entrypoint")
}

func TestPackageEntrypointRejectsDuplicateAndLink(t *testing.T) {
	entrypoint := "agent/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin"
	var duplicate bytes.Buffer
	writer := zip.NewWriter(&duplicate)
	for range 2 {
		file, err := writer.Create(entrypoint)
		require.NoError(t, err)
		_, err = file.Write([]byte("binary"))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	_, err := extractPackageFile(duplicate.Bytes(), entrypoint)
	require.ErrorContains(t, err, "appears more than once")

	var linked bytes.Buffer
	linkWriter := zip.NewWriter(&linked)
	header := &zip.FileHeader{Name: entrypoint}
	header.SetMode(os.ModeSymlink | 0o777)
	file, err := linkWriter.CreateHeader(header)
	require.NoError(t, err)
	_, err = file.Write([]byte("/etc/passwd"))
	require.NoError(t, err)
	require.NoError(t, linkWriter.Close())
	_, err = extractPackageFile(linked.Bytes(), entrypoint)
	require.ErrorContains(t, err, "not a regular file")
}

func signedPackageRequest(t *testing.T, privateKey ed25519.PrivateKey, artifact []byte, manifest Manifest) InstallRequest {
	t.Helper()
	digest := sha256.Sum256(artifact)
	manifest.ArtifactSHA256 = hex.EncodeToString(digest[:])
	canonical, err := CanonicalManifest(manifest)
	require.NoError(t, err)
	return InstallRequest{
		ManifestJSON: string(canonical),
		Signature:    base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)),
		Artifact:     artifact,
	}
}

func makeZipArtifact(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var artifact bytes.Buffer
	writer := zip.NewWriter(&artifact)
	for name, contents := range files {
		file, err := writer.Create(name)
		require.NoError(t, err)
		_, err = file.Write(contents)
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	return artifact.Bytes()
}
