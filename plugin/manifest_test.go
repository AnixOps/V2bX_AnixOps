package plugin

import (
	"crypto/sha256"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManifestAcceptsV2AgentEntrypointForSDKV110(t *testing.T) {
	manifest := Manifest{
		ID:             "v2-agent-package",
		Name:           "V2 Agent Package",
		Version:        "4.0.0",
		APIVersion:     pluginAPIVersionV2,
		Publisher:      manifestPublisher,
		Targets:        []string{"agent"},
		Architectures:  []string{runtime.GOOS + "/" + runtime.GOARCH},
		ArtifactSHA256: strings.Repeat("a", sha256.Size*2),
		AgentEntrypoint: &ManifestEntrypoint{
			Path:   "agent/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin",
			SHA256: strings.Repeat("b", sha256.Size*2),
		},
		Migrations: &ManifestMigrations{
			Index:  "migrations/index.json",
			SHA256: strings.Repeat("c", sha256.Size*2),
		},
		CompatibilityRoutes: &ManifestCompatibilityRoutes{
			Path:   "compat/v2-routes.json",
			SHA256: strings.Repeat("d", sha256.Size*2),
		},
		RouteContractDigest: strings.Repeat("e", sha256.Size*2),
		RuntimeAPIVersion:   agentRuntimeAPIVersionV110,
	}

	require.NoError(t, manifest.Validate())

	manifest.RuntimeAPIVersion = "anixops.agent.sdk/v1.0.0"
	require.ErrorContains(t, manifest.Validate(), "runtime_api_version")

	manifest.RuntimeAPIVersion = agentRuntimeAPIVersionV110
	manifest.AgentEntrypoint.Path = "../agent/plugin"
	require.ErrorContains(t, manifest.Validate(), "agent_entrypoint")
}

func TestManifestAcceptsV2MultiarchAgentEntrypointIndex(t *testing.T) {
	manifest := Manifest{
		ID:             "v2-multiarch-package",
		Name:           "V2 Multiarch Package",
		Version:        "4.0.0",
		APIVersion:     pluginAPIVersionV2,
		Publisher:      manifestPublisher,
		Targets:        []string{"agent"},
		Architectures:  []string{"linux/amd64", "linux/arm64"},
		ArtifactSHA256: strings.Repeat("a", sha256.Size*2),
		AgentEntrypoint: &ManifestEntrypoint{
			Path:   "agent/entrypoints.json",
			SHA256: strings.Repeat("b", sha256.Size*2),
		},
		Migrations: &ManifestMigrations{
			Index:  "migrations/index.json",
			SHA256: strings.Repeat("c", sha256.Size*2),
		},
		CompatibilityRoutes: &ManifestCompatibilityRoutes{
			Path:   "compat/v2-routes.json",
			SHA256: strings.Repeat("d", sha256.Size*2),
		},
		RouteContractDigest: strings.Repeat("e", sha256.Size*2),
		RuntimeAPIVersion:   agentRuntimeAPIVersionV110,
	}

	require.NoError(t, manifest.validateForRuntime("linux", "amd64"))
	require.NoError(t, manifest.validateForRuntime("linux", "arm64"))
}

func TestManifestRetainsV1ValidationDuringV2Migration(t *testing.T) {
	manifest := Manifest{
		ID:             "legacy-agent-package",
		Name:           "Legacy Agent Package",
		Version:        "1.0.0",
		APIVersion:     pluginAPIVersionV1,
		Publisher:      manifestPublisher,
		Targets:        []string{"agent"},
		Architectures:  []string{runtime.GOOS + "/" + runtime.GOARCH},
		ArtifactSHA256: strings.Repeat("a", sha256.Size*2),
		Entrypoints: map[string]string{
			"agent-" + runtime.GOOS + "-" + runtime.GOARCH: "agent/" + runtime.GOOS + "-" + runtime.GOARCH + "/plugin",
		},
	}

	require.NoError(t, manifest.Validate())
}
