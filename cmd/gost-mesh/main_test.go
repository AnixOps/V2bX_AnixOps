package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunValidateConfigOnly(t *testing.T) {
	directory := t.TempDir()
	validPath := filepath.Join(directory, "valid.json")
	invalidPath := filepath.Join(directory, "invalid.json")
	require.NoError(t, os.WriteFile(validPath, []byte(`{
  "api_version":"anixops.gost-mesh/v1",
  "apply":false,
  "rollback_on_exit":true,
  "tunnels":[]
}`), 0o600))
	require.NoError(t, os.WriteFile(invalidPath, []byte(`{"api_version":"invalid"}`), 0o600))

	require.Equal(t, 0, run([]string{"--anixops-validate", "--anixops-config", validPath}))
	require.Equal(t, 1, run([]string{"--anixops-validate", "--anixops-config", invalidPath}))
	require.Equal(t, 1, run([]string{"--anixops-validate"}))
	require.Equal(t, 2, run([]string{"--anixops-validate", "--anixops-cleanup", "--anixops-config", validPath}))
}
