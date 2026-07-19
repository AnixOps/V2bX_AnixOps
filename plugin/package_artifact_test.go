package plugin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
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
	_, err = supervisor.verifyInstalledVersion("package-test", "1.0.0")
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(versionDir, pluginBinaryName), []byte("tampered"), 0o750))
	_, err = supervisor.verifyInstalledVersion("package-test", "1.0.0")
	require.ErrorContains(t, err, "does not match the signed package entrypoint")
}

func TestSupervisorInstallsV2IndexedPlatformEntrypoint(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	supervisor, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)

	platform := runtime.GOOS + "/" + runtime.GOARCH
	otherPlatform := "linux/arm64"
	if platform == otherPlatform {
		otherPlatform = "linux/amd64"
	}
	selectedPath := "agent/" + strings.ReplaceAll(platform, "/", "-") + "/plugin"
	otherPath := "agent/" + strings.ReplaceAll(otherPlatform, "/", "-") + "/plugin"
	selectedBinary := []byte("signed indexed platform executable")
	otherBinary := []byte("signed indexed other executable")
	index := makeV2AgentEntrypointIndex(t, []v2AgentEntrypointIndexEntry{
		{Architecture: platform, Path: selectedPath, SHA256: sha256Hex(selectedBinary)},
		{Architecture: otherPlatform, Path: otherPath, SHA256: sha256Hex(otherBinary)},
	})
	migrations := []byte(`{"format":"anixops.migrations/v1","migrations":[]}`)
	routes := []byte(`{"api_version":"v2","routes":[]}`)
	artifact := makeZipArtifact(t, map[string][]byte{
		"agent/entrypoints.json": index,
		selectedPath:             selectedBinary,
		otherPath:                otherBinary,
		"migrations/index.json":  migrations,
		"compat/v2-routes.json":  routes,
	})
	request := signedPackageRequest(t, privateKey, artifact, Manifest{
		ID: "indexed-package", Name: "Indexed Package", Version: "4.0.0", APIVersion: pluginAPIVersionV2,
		Publisher: manifestPublisher, Targets: []string{"agent"}, Architectures: []string{platform, otherPlatform},
		AgentEntrypoint:     &ManifestEntrypoint{Path: "agent/entrypoints.json", SHA256: sha256Hex(index)},
		Migrations:          &ManifestMigrations{Index: "migrations/index.json", SHA256: sha256Hex(migrations)},
		CompatibilityRoutes: &ManifestCompatibilityRoutes{Path: "compat/v2-routes.json", SHA256: sha256Hex(routes)},
		RouteContractDigest: sha256Hex(routes), RuntimeAPIVersion: agentRuntimeAPIVersionV110,
	})

	_, err = supervisor.Install(context.Background(), request)
	require.NoError(t, err)
	installed, err := os.ReadFile(filepath.Join(root, "indexed-package", "4.0.0", pluginBinaryName))
	require.NoError(t, err)
	require.Equal(t, selectedBinary, installed)
	_, err = supervisor.verifyInstalledVersion("indexed-package", "4.0.0")
	require.NoError(t, err)
}

func TestSupervisorInstallsV2IndexedEntrypointAndRuntimeFromGzipArtifact(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	supervisor, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)

	platform := runtime.GOOS + "/" + runtime.GOARCH
	agentPath := "agent/" + strings.ReplaceAll(platform, "/", "-") + "/plugin"
	runtimePath := "runtime/" + strings.ReplaceAll(platform, "/", "-") + "/gost"
	agentBinary := []byte("signed indexed gzip agent executable")
	runtimeBinary := []byte("signed indexed gzip gost runtime")
	index := makeV2AgentEntrypointIndex(t, []v2AgentEntrypointIndexEntry{{
		Architecture: platform, Path: agentPath, SHA256: sha256Hex(agentBinary),
	}})
	migrations := []byte(`{"format":"anixops.migrations/v1","migrations":[]}`)
	routes := []byte(`{"api_version":"v2","routes":[]}`)
	artifact := makeGzipTarArtifact(t, map[string][]byte{
		"agent/entrypoints.json": index,
		agentPath:                agentBinary,
		runtimePath:              runtimeBinary,
		"migrations/index.json":  migrations,
		"compat/v2-routes.json":  routes,
	})
	request := signedPackageRequest(t, privateKey, artifact, Manifest{
		ID: "indexed-gzip-runtime", Name: "Indexed Gzip Runtime", Version: "4.0.0", APIVersion: pluginAPIVersionV2,
		Publisher: manifestPublisher, Targets: []string{"agent"}, Architectures: []string{platform},
		Entrypoints: map[string]string{
			"runtime-gost-" + runtime.GOOS + "-" + runtime.GOARCH: runtimePath,
		},
		AgentEntrypoint:     &ManifestEntrypoint{Path: "agent/entrypoints.json", SHA256: sha256Hex(index)},
		Migrations:          &ManifestMigrations{Index: "migrations/index.json", SHA256: sha256Hex(migrations)},
		CompatibilityRoutes: &ManifestCompatibilityRoutes{Path: "compat/v2-routes.json", SHA256: sha256Hex(routes)},
		RouteContractDigest: sha256Hex(routes), RuntimeAPIVersion: agentRuntimeAPIVersionV110,
	})

	_, err = supervisor.Install(context.Background(), request)
	require.NoError(t, err)
	versionDir := filepath.Join(root, "indexed-gzip-runtime", "4.0.0")
	installedAgent, err := os.ReadFile(filepath.Join(versionDir, pluginBinaryName))
	require.NoError(t, err)
	require.Equal(t, agentBinary, installedAgent)
	installedRuntime, err := os.ReadFile(filepath.Join(versionDir, pluginRuntimeDirName, "gost"))
	require.NoError(t, err)
	require.Equal(t, runtimeBinary, installedRuntime)
	_, err = supervisor.verifyInstalledVersion("indexed-gzip-runtime", "4.0.0")
	require.NoError(t, err)
}

func TestSupervisorRejectsTamperedV2IndexedPlatformEntrypoint(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	supervisor, err := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)

	platform := runtime.GOOS + "/" + runtime.GOARCH
	selectedPath := "agent/" + strings.ReplaceAll(platform, "/", "-") + "/plugin"
	selectedBinary := []byte("signed indexed platform executable")
	index := makeV2AgentEntrypointIndex(t, []v2AgentEntrypointIndexEntry{{
		Architecture: platform, Path: selectedPath, SHA256: strings.Repeat("0", sha256.Size*2),
	}})
	migrations := []byte(`{"format":"anixops.migrations/v1","migrations":[]}`)
	routes := []byte(`{"api_version":"v2","routes":[]}`)
	artifact := makeZipArtifact(t, map[string][]byte{
		"agent/entrypoints.json": index,
		selectedPath:             selectedBinary,
		"migrations/index.json":  migrations,
		"compat/v2-routes.json":  routes,
	})
	request := signedPackageRequest(t, privateKey, artifact, Manifest{
		ID: "tampered-indexed-package", Name: "Tampered Indexed Package", Version: "4.0.0", APIVersion: pluginAPIVersionV2,
		Publisher: manifestPublisher, Targets: []string{"agent"}, Architectures: []string{platform},
		AgentEntrypoint:     &ManifestEntrypoint{Path: "agent/entrypoints.json", SHA256: sha256Hex(index)},
		Migrations:          &ManifestMigrations{Index: "migrations/index.json", SHA256: sha256Hex(migrations)},
		CompatibilityRoutes: &ManifestCompatibilityRoutes{Path: "compat/v2-routes.json", SHA256: sha256Hex(routes)},
		RouteContractDigest: sha256Hex(routes), RuntimeAPIVersion: agentRuntimeAPIVersionV110,
	})

	_, err = supervisor.Install(context.Background(), request)
	require.ErrorContains(t, err, "agent entrypoint digest")
}

func TestSupervisorRetainsV2DirectPlatformEntrypointCompatibility(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	supervisor, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)

	platform := runtime.GOOS + "/" + runtime.GOARCH
	entrypoint := "agent/" + strings.ReplaceAll(platform, "/", "-") + "/plugin"
	binary := []byte("signed direct v2 executable")
	migrations := []byte(`{"format":"anixops.migrations/v1","migrations":[]}`)
	routes := []byte(`{"api_version":"v2","routes":[]}`)
	artifact := makeZipArtifact(t, map[string][]byte{
		entrypoint:              binary,
		"migrations/index.json": migrations,
		"compat/v2-routes.json": routes,
	})
	request := signedPackageRequest(t, privateKey, artifact, Manifest{
		ID: "direct-v2-package", Name: "Direct V2 Package", Version: "3.4.0", APIVersion: pluginAPIVersionV2,
		Publisher: manifestPublisher, Targets: []string{"agent"}, Architectures: []string{platform},
		AgentEntrypoint:     &ManifestEntrypoint{Path: entrypoint, SHA256: sha256Hex(binary)},
		Migrations:          &ManifestMigrations{Index: "migrations/index.json", SHA256: sha256Hex(migrations)},
		CompatibilityRoutes: &ManifestCompatibilityRoutes{Path: "compat/v2-routes.json", SHA256: sha256Hex(routes)},
		RouteContractDigest: sha256Hex(routes), RuntimeAPIVersion: agentRuntimeAPIVersionV110,
	})

	_, err = supervisor.Install(context.Background(), request)
	require.NoError(t, err)
	installed, err := os.ReadFile(filepath.Join(root, "direct-v2-package", "3.4.0", pluginBinaryName))
	require.NoError(t, err)
	require.Equal(t, binary, installed)
	_, err = supervisor.verifyInstalledVersion("direct-v2-package", "3.4.0")
	require.NoError(t, err)
}

func TestSupervisorMaterializesSignedPlatformRuntimes(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	supervisor, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)

	agentEntrypoint := "agent/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin"
	gostEntrypoint := "runtime/" + runtime.GOOS + "-" + runtime.GOARCH + "/gost"
	gostFallback := "runtime/any/gost"
	helperEntrypoint := "runtime/portable/health-helper"
	artifact := makeZipArtifact(t, map[string][]byte{
		agentEntrypoint:  []byte("signed agent executable"),
		gostEntrypoint:   []byte("signed platform gost"),
		gostFallback:     []byte("portable gost fallback"),
		helperEntrypoint: []byte("signed portable helper"),
	})
	request := signedPackageRequest(t, privateKey, artifact, Manifest{
		ID: "runtime-package", Name: "Runtime Package", Version: "1.0.0", APIVersion: pluginAPIVersion,
		Publisher: manifestPublisher, Targets: []string{"agent"}, Architectures: []string{runtime.GOOS + "/" + runtime.GOARCH},
		Entrypoints: map[string]string{
			"agent-" + runtime.GOOS + "-" + runtime.GOARCH:        agentEntrypoint,
			"runtime-gost-" + runtime.GOOS + "-" + runtime.GOARCH: gostEntrypoint,
			"runtime-gost-any":      gostFallback,
			"runtime-health-helper": helperEntrypoint,
		},
	})

	_, err = supervisor.Install(context.Background(), request)
	require.NoError(t, err)
	versionDir := filepath.Join(root, "runtime-package", "1.0.0")
	for name, expected := range map[string][]byte{
		"gost":          []byte("signed platform gost"),
		"health-helper": []byte("signed portable helper"),
	} {
		installedPath := filepath.Join(versionDir, pluginRuntimeDirName, name)
		installed, readErr := os.ReadFile(installedPath)
		require.NoError(t, readErr)
		require.Equal(t, expected, installed)
		info, statErr := os.Stat(installedPath)
		require.NoError(t, statErr)
		require.Equal(t, os.FileMode(0o750), info.Mode().Perm())
	}
	_, err = supervisor.verifyInstalledVersion("runtime-package", "1.0.0")
	require.NoError(t, err)
}

func TestSupervisorIgnoresRuntimeForAnotherPlatform(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	supervisor, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)

	otherOS, otherArch := otherRuntimePlatform()
	agentEntrypoint := "agent/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin"
	otherEntrypoint := "runtime/" + otherOS + "-" + otherArch + "/gost"
	artifact := makeZipArtifact(t, map[string][]byte{
		agentEntrypoint: []byte("signed agent executable"),
		otherEntrypoint: []byte("runtime for another platform"),
	})
	request := signedPackageRequest(t, privateKey, artifact, Manifest{
		ID: "foreign-runtime", Name: "Foreign Runtime", Version: "1.0.0", APIVersion: pluginAPIVersion,
		Publisher: manifestPublisher, Targets: []string{"agent"}, Architectures: []string{runtime.GOOS + "/" + runtime.GOARCH},
		Entrypoints: map[string]string{
			"agent-" + runtime.GOOS + "-" + runtime.GOARCH: agentEntrypoint,
			"runtime-gost-" + otherOS + "-" + otherArch:    otherEntrypoint,
		},
	})

	_, err = supervisor.Install(context.Background(), request)
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(root, "foreign-runtime", "1.0.0", pluginRuntimeDirName, "gost"))
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = supervisor.verifyInstalledVersion("foreign-runtime", "1.0.0")
	require.NoError(t, err)
}

func TestSupervisorRejectsConflictingRuntimeDeclarations(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	agentEntrypoint := "agent/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin"
	baseManifest := Manifest{
		ID: "runtime-conflict", Name: "Runtime Conflict", Version: "1.0.0", APIVersion: pluginAPIVersion,
		Publisher: manifestPublisher, Targets: []string{"agent"}, Architectures: []string{runtime.GOOS + "/" + runtime.GOARCH},
	}

	t.Run("any and generic fallback", func(t *testing.T) {
		artifact := makeZipArtifact(t, map[string][]byte{
			agentEntrypoint:      []byte("agent"),
			"runtime/any/gost":   []byte("any"),
			"runtime/plain/gost": []byte("plain"),
		})
		manifest := baseManifest
		manifest.Entrypoints = map[string]string{
			"agent-" + runtime.GOOS + "-" + runtime.GOARCH: agentEntrypoint,
			"runtime-gost-any": "runtime/any/gost",
			"runtime-gost":     "runtime/plain/gost",
		}
		supervisor, createErr := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
		require.NoError(t, createErr)
		_, installErr := supervisor.Install(context.Background(), signedPackageRequest(t, privateKey, artifact, manifest))
		require.ErrorContains(t, installErr, "conflicting any and generic fallbacks")
	})

	t.Run("duplicate package path", func(t *testing.T) {
		artifact := makeZipArtifact(t, map[string][]byte{
			agentEntrypoint:    []byte("agent"),
			"runtime/bin/tool": []byte("shared"),
		})
		manifest := baseManifest
		manifest.Entrypoints = map[string]string{
			"agent-" + runtime.GOOS + "-" + runtime.GOARCH: agentEntrypoint,
			"runtime-gost":   "runtime/bin/tool",
			"runtime-helper": "runtime/bin/tool",
		}
		supervisor, createErr := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
		require.NoError(t, createErr)
		_, installErr := supervisor.Install(context.Background(), signedPackageRequest(t, privateKey, artifact, manifest))
		require.ErrorContains(t, installErr, "use the same package path")
	})

	t.Run("runtime reuses agent path", func(t *testing.T) {
		artifact := makeZipArtifact(t, map[string][]byte{agentEntrypoint: []byte("agent")})
		manifest := baseManifest
		manifest.Entrypoints = map[string]string{
			"agent-" + runtime.GOOS + "-" + runtime.GOARCH: agentEntrypoint,
			"runtime-gost": agentEntrypoint,
		}
		supervisor, createErr := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
		require.NoError(t, createErr)
		_, installErr := supervisor.Install(context.Background(), signedPackageRequest(t, privateKey, artifact, manifest))
		require.ErrorContains(t, installErr, "use the same package path")
	})

	t.Run("raw legacy artifact", func(t *testing.T) {
		manifest := baseManifest
		manifest.Entrypoints = map[string]string{"runtime-gost": "runtime/bin/gost"}
		supervisor, createErr := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
		require.NoError(t, createErr)
		_, installErr := supervisor.Install(context.Background(), signedPackageRequest(t, privateKey, []byte("raw executable"), manifest))
		require.ErrorContains(t, installErr, "require a packaged agent entrypoint")
	})
}

func TestSupervisorRejectsUnsafeMissingAndIrregularRuntime(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	agentEntrypoint := "agent/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin"
	runtimeKey := "runtime-gost-" + runtime.GOOS + "-" + runtime.GOARCH
	baseManifest := Manifest{
		ID: "invalid-runtime", Name: "Invalid Runtime", Version: "1.0.0", APIVersion: pluginAPIVersion,
		Publisher: manifestPublisher, Targets: []string{"agent"}, Architectures: []string{runtime.GOOS + "/" + runtime.GOARCH},
	}

	t.Run("traversal", func(t *testing.T) {
		artifact := makeZipArtifact(t, map[string][]byte{agentEntrypoint: []byte("agent")})
		manifest := baseManifest
		manifest.Entrypoints = map[string]string{
			"agent-" + runtime.GOOS + "-" + runtime.GOARCH: agentEntrypoint,
			runtimeKey: "../runtime/gost",
		}
		supervisor, createErr := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
		require.NoError(t, createErr)
		_, installErr := supervisor.Install(context.Background(), signedPackageRequest(t, privateKey, artifact, manifest))
		require.ErrorContains(t, installErr, "canonical relative path")
	})

	t.Run("missing package member", func(t *testing.T) {
		artifact := makeZipArtifact(t, map[string][]byte{agentEntrypoint: []byte("agent")})
		manifest := baseManifest
		manifest.Entrypoints = map[string]string{
			"agent-" + runtime.GOOS + "-" + runtime.GOARCH: agentEntrypoint,
			runtimeKey: "runtime/bin/gost",
		}
		supervisor, createErr := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
		require.NoError(t, createErr)
		_, installErr := supervisor.Install(context.Background(), signedPackageRequest(t, privateKey, artifact, manifest))
		require.ErrorContains(t, installErr, "was not found")
	})

	t.Run("symlink package member", func(t *testing.T) {
		artifact := makeZipArtifactWithSymlink(t, agentEntrypoint, "runtime/bin/gost")
		manifest := baseManifest
		manifest.Entrypoints = map[string]string{
			"agent-" + runtime.GOOS + "-" + runtime.GOARCH: agentEntrypoint,
			runtimeKey: "runtime/bin/gost",
		}
		supervisor, createErr := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
		require.NoError(t, createErr)
		_, installErr := supervisor.Install(context.Background(), signedPackageRequest(t, privateKey, artifact, manifest))
		require.ErrorContains(t, installErr, "not a regular file")
	})

	t.Run("duplicate package member", func(t *testing.T) {
		artifact := makeZipArtifactWithDuplicateRuntime(t, agentEntrypoint, "runtime/bin/gost")
		manifest := baseManifest
		manifest.Entrypoints = map[string]string{
			"agent-" + runtime.GOOS + "-" + runtime.GOARCH: agentEntrypoint,
			runtimeKey: "runtime/bin/gost",
		}
		supervisor, createErr := NewSupervisor(Config{RootDir: t.TempDir(), PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
		require.NoError(t, createErr)
		_, installErr := supervisor.Install(context.Background(), signedPackageRequest(t, privateKey, artifact, manifest))
		require.ErrorContains(t, installErr, "appears more than once")
	})
}

func TestSupervisorReverifiesSignedRuntimeBeforeStart(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(t *testing.T, path string)
		wantErr string
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, path string) {
				require.NoError(t, os.Remove(path))
			},
			wantErr: "inspect installed runtime",
		},
		{
			name: "tampered",
			mutate: func(t *testing.T, path string) {
				require.NoError(t, os.WriteFile(path, []byte("tampered runtime"), 0o750))
			},
			wantErr: "does not match the signed package entrypoint",
		},
		{
			name: "not executable",
			mutate: func(t *testing.T, path string) {
				require.NoError(t, os.Chmod(path, 0o600))
			},
			wantErr: "is not executable",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			root := t.TempDir()
			runner := &fakeRunner{}
			supervisor, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: runner, Health: &fakeHealth{}})
			require.NoError(t, err)
			agentEntrypoint := "agent/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin"
			runtimeEntrypoint := "runtime/" + runtime.GOOS + "-" + runtime.GOARCH + "/gost"
			artifact := makeZipArtifact(t, map[string][]byte{
				agentEntrypoint:   []byte("agent"),
				runtimeEntrypoint: []byte("signed gost runtime"),
			})
			manifest := Manifest{
				ID: "runtime-start", Name: "Runtime Start", Version: "1.0.0", APIVersion: pluginAPIVersion,
				Publisher: manifestPublisher, Targets: []string{"agent"}, Architectures: []string{runtime.GOOS + "/" + runtime.GOARCH},
				Entrypoints: map[string]string{
					"agent-" + runtime.GOOS + "-" + runtime.GOARCH:        agentEntrypoint,
					"runtime-gost-" + runtime.GOOS + "-" + runtime.GOARCH: runtimeEntrypoint,
				},
			}
			_, err = supervisor.Install(context.Background(), signedPackageRequest(t, privateKey, artifact, manifest))
			require.NoError(t, err)
			test.mutate(t, filepath.Join(root, manifest.ID, manifest.Version, pluginRuntimeDirName, "gost"))
			_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("enable-runtime-"+test.name, manifest.ID, manifest.Version, 1, []byte(`{}`)))
			require.ErrorContains(t, err, test.wantErr)
			require.Equal(t, 0, runner.Starts())
		})
	}
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

func TestRuntimeEntrypointRejectsOversizedFile(t *testing.T) {
	entrypoint := "runtime/bin/gost"
	file := &zip.File{FileHeader: zip.FileHeader{
		Name:               entrypoint,
		UncompressedSize64: uint64(maxPluginRuntimeBytes + 1),
	}}
	_, err := extractZipFile(
		&zip.Reader{File: []*zip.File{file}},
		entrypoint,
		"runtime \"gost\" entrypoint",
		maxPluginRuntimeBytes,
	)
	require.ErrorContains(t, err, "exceeds")
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

func sha256Hex(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func makeV2AgentEntrypointIndex(t *testing.T, entries []v2AgentEntrypointIndexEntry) []byte {
	t.Helper()
	ordered := append([]v2AgentEntrypointIndexEntry(nil), entries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Architecture < ordered[j].Architecture })
	index, err := json.Marshal(v2AgentEntrypointIndex{Format: packageEntrypointIndexFormat, Entries: ordered})
	require.NoError(t, err)
	return index
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

func makeGzipTarArtifact(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var artifact bytes.Buffer
	gzipWriter := gzip.NewWriter(&artifact)
	tarWriter := tar.NewWriter(gzipWriter)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		contents := files[name]
		require.NoError(t, tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(contents))}))
		_, err := tarWriter.Write(contents)
		require.NoError(t, err)
	}
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzipWriter.Close())
	return artifact.Bytes()
}

func makeZipArtifactWithSymlink(t *testing.T, agentEntrypoint, runtimeEntrypoint string) []byte {
	t.Helper()
	var artifact bytes.Buffer
	writer := zip.NewWriter(&artifact)
	agentFile, err := writer.Create(agentEntrypoint)
	require.NoError(t, err)
	_, err = agentFile.Write([]byte("agent"))
	require.NoError(t, err)
	header := &zip.FileHeader{Name: runtimeEntrypoint}
	header.SetMode(os.ModeSymlink | 0o777)
	runtimeFile, err := writer.CreateHeader(header)
	require.NoError(t, err)
	_, err = runtimeFile.Write([]byte("/usr/bin/gost"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return artifact.Bytes()
}

func makeZipArtifactWithDuplicateRuntime(t *testing.T, agentEntrypoint, runtimeEntrypoint string) []byte {
	t.Helper()
	var artifact bytes.Buffer
	writer := zip.NewWriter(&artifact)
	agentFile, err := writer.Create(agentEntrypoint)
	require.NoError(t, err)
	_, err = agentFile.Write([]byte("agent"))
	require.NoError(t, err)
	for range 2 {
		runtimeFile, createErr := writer.Create(runtimeEntrypoint)
		require.NoError(t, createErr)
		_, writeErr := runtimeFile.Write([]byte("gost"))
		require.NoError(t, writeErr)
	}
	require.NoError(t, writer.Close())
	return artifact.Bytes()
}

func otherRuntimePlatform() (string, string) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		return "windows", "amd64"
	}
	return "linux", "arm64"
}
