package nategress

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoveOwnershipJournalPropagatesDirectorySyncFailure(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	path := filepath.Join(directory, "ownership.json")
	require.NoError(t, os.WriteFile(path, []byte("journal\n"), 0o600))

	expected := errors.New("injected directory sync failure")
	syncedDirectory := ""
	err := removeOwnershipJournalWithSync(path, func(path string) error {
		syncedDirectory = path
		return expected
	})

	require.ErrorIs(t, err, expected)
	require.Equal(t, directory, syncedDirectory)
	_, statErr := os.Lstat(path)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}
