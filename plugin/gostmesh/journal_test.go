package gostmesh

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOwnershipJournalRoundTripAndRejectsCorruption(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		_, path, journal := runtimeTestJournal(t)
		require.NoError(t, writeOwnershipJournal(path, journal))
		loaded, exists, err := loadOwnershipJournal(path)
		require.NoError(t, err)
		require.True(t, exists)
		require.Equal(t, journal, loaded)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		directory := runtimeSecureTempDir(t)
		path := filepath.Join(directory, "ownership.json")
		require.NoError(t, os.WriteFile(path, []byte("{"), 0o600))
		_, _, err := loadOwnershipJournal(path)
		require.ErrorContains(t, err, "decode gost-mesh ownership journal")
	})

	t.Run("unknown field", func(t *testing.T) {
		_, path, journal := runtimeTestJournal(t)
		contents, err := json.Marshal(journal)
		require.NoError(t, err)
		var document map[string]any
		require.NoError(t, json.Unmarshal(contents, &document))
		document["unexpected"] = true
		contents, err = json.Marshal(document)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, contents, 0o600))
		_, _, err = loadOwnershipJournal(path)
		require.ErrorContains(t, err, "unknown field")
	})

	t.Run("trailing document", func(t *testing.T) {
		_, path, journal := runtimeTestJournal(t)
		contents, err := json.Marshal(journal)
		require.NoError(t, err)
		contents = append(contents, '\n', '{', '}')
		require.NoError(t, os.WriteFile(path, contents, 0o600))
		_, _, err = loadOwnershipJournal(path)
		require.ErrorContains(t, err, "exactly one JSON object")
	})

	t.Run("invalid identity", func(t *testing.T) {
		_, path, journal := runtimeTestJournal(t)
		journal.PluginVersion = "0.0.0"
		contents, err := json.Marshal(journal)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, contents, 0o600))
		_, _, err = loadOwnershipJournal(path)
		require.ErrorContains(t, err, "identity is invalid")
	})
}

func TestOwnershipJournalRejectsUnsafePermissionsAndSymlinks(t *testing.T) {
	t.Run("world-readable journal", func(t *testing.T) {
		_, path, journal := runtimeTestJournal(t)
		require.NoError(t, writeOwnershipJournal(path, journal))
		require.NoError(t, os.Chmod(path, 0o644))
		_, _, err := loadOwnershipJournal(path)
		require.ErrorContains(t, err, "must be private")
	})

	t.Run("journal symlink", func(t *testing.T) {
		directory, path, journal := runtimeTestJournal(t)
		target := filepath.Join(directory, "target.json")
		contents, err := json.Marshal(journal)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(target, contents, 0o600))
		require.NoError(t, os.Symlink(target, path))
		_, _, err = loadOwnershipJournal(path)
		require.ErrorContains(t, err, "not a symlink")
	})

	t.Run("non-private parent", func(t *testing.T) {
		directory, path, journal := runtimeTestJournal(t)
		require.NoError(t, os.Chmod(directory, 0o755))
		err := writeOwnershipJournal(path, journal)
		require.ErrorContains(t, err, "directory must be a private real directory")
	})

	t.Run("refuse replacing symlink", func(t *testing.T) {
		directory, path, journal := runtimeTestJournal(t)
		target := filepath.Join(directory, "target.json")
		require.NoError(t, os.WriteFile(target, []byte("do not replace"), 0o600))
		require.NoError(t, os.Symlink(target, path))
		err := writeOwnershipJournal(path, journal)
		require.ErrorContains(t, err, "refusing to replace an unsafe")
		contents, readErr := os.ReadFile(target)
		require.NoError(t, readErr)
		require.Equal(t, "do not replace", string(contents))
	})
}

func runtimeTestJournal(t *testing.T) (string, string, ownershipJournal) {
	t.Helper()
	directory := runtimeSecureTempDir(t)
	path := filepath.Join(directory, "ownership.json")
	journal := newOwnershipJournal(
		validConfig(validEntry(), validExit()),
		filepath.Join(directory, "runtime", "gost"),
	)
	return directory, path, journal
}
