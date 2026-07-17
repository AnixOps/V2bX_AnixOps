package main

import (
	"io"
	"os"
	"testing"

	"github.com/AnixOps/anix-agent/v4/plugin/nftablesforward"
	"github.com/stretchr/testify/require"
)

const officialManifestVersion = "1.0.0"

func TestVersionMatchesOfficialManifest(t *testing.T) {
	require.Equal(t, officialManifestVersion, nftablesforward.Version)
	exitCode, output := runAndCaptureStdout(t, []string{"--version"})
	require.Equal(t, 0, exitCode)
	require.Equal(t, nftablesforward.ID+" "+officialManifestVersion+"\n", output)
}

func runAndCaptureStdout(t *testing.T, args []string) (int, string) {
	t.Helper()

	read, write, err := os.Pipe()
	require.NoError(t, err)
	original := os.Stdout
	os.Stdout = write
	exitCode := run(args)
	os.Stdout = original
	require.NoError(t, write.Close())

	output, err := io.ReadAll(read)
	require.NoError(t, err)
	require.NoError(t, read.Close())
	return exitCode, string(output)
}
