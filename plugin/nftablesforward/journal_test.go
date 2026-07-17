package nftablesforward

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type journalApplier struct {
	snapshot TableSnapshot
	calls    []string
	applyErr error
	failAt   int
	exists   bool
}

type fixedSnapshotApplier struct {
	current TableSnapshot
}

func (a fixedSnapshotApplier) Apply(context.Context, string, string) error { return nil }

func (a fixedSnapshotApplier) Snapshot(context.Context, string, string, string) (TableSnapshot, error) {
	return a.current, nil
}

func TestRollbackRulesetHandlesExistingAndMissingTables(t *testing.T) {
	config, err := ParseConfig([]byte(validConfigJSON("rollback-shape")))
	require.NoError(t, err)
	original := TableSnapshot{Exists: true, Ruleset: "table inet anixops_forward {\n\tchain baseline { }\n}\n"}

	ruleset, needed, err := rollbackRuleset(context.Background(), fixedSnapshotApplier{}, config, TableSnapshot{})
	require.NoError(t, err)
	require.False(t, needed)
	require.Empty(t, ruleset)

	ruleset, needed, err = rollbackRuleset(context.Background(), fixedSnapshotApplier{current: TableSnapshot{Exists: true, Ruleset: "managed"}}, config, TableSnapshot{})
	require.NoError(t, err)
	require.True(t, needed)
	require.Equal(t, "delete table inet anixops_forward\n", ruleset)

	ruleset, needed, err = rollbackRuleset(context.Background(), fixedSnapshotApplier{}, config, original)
	require.NoError(t, err)
	require.True(t, needed)
	require.Equal(t, original.Ruleset, ruleset)
	require.NotContains(t, ruleset, "delete table")

	ruleset, needed, err = rollbackRuleset(context.Background(), fixedSnapshotApplier{current: TableSnapshot{Exists: true, Ruleset: "managed"}}, config, original)
	require.NoError(t, err)
	require.True(t, needed)
	require.Contains(t, ruleset, "delete table inet anixops_forward")
	require.Contains(t, ruleset, "chain baseline")
	require.NotContains(t, ruleset, "add table inet anixops_forward\ndelete table")
}

func (a *journalApplier) Apply(ctx context.Context, _ string, ruleset string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.calls = append(a.calls, ruleset)
	if strings.Contains(ruleset, "add rule ") {
		a.exists = true
	} else if strings.Contains(ruleset, "delete table ") {
		a.exists = false
	}
	if a.applyErr != nil && (a.failAt == 0 || len(a.calls) == a.failAt) {
		return a.applyErr
	}
	return nil
}

func (a *journalApplier) Snapshot(ctx context.Context, _, _, _ string) (TableSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return TableSnapshot{}, err
	}
	if a.exists {
		return TableSnapshot{Exists: true, Ruleset: a.snapshot.Ruleset}, nil
	}
	return a.snapshot, nil
}

func TestOwnershipJournalRecoversAfterAgentRestart(t *testing.T) {
	directory := t.TempDir()
	_ = os.Chmod(directory, 0o700)
	statePath := filepath.Join(directory, "ownership.json")
	config, err := ParseConfig([]byte(`{
		"apply":true,
		"rollback_on_exit":true,
		"rules":[{"id":"restart","protocol":"tcp","listen_address":"198.51.100.10","listen_port":443,"target_address":"203.0.113.10","target_port":8443}]
	}`))
	require.NoError(t, err)
	ruleset, err := RenderRuleset(config)
	require.NoError(t, err)

	first := &journalApplier{}
	state, err := applyManagedRuleset(context.Background(), first, config, ruleset, statePath)
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Len(t, first.calls, 1)
	require.FileExists(t, statePath)

	// A new Agent process starts with the stable journal still present. The
	// next apply restores the old baseline before installing the fresh plan.
	second := &journalApplier{exists: true}
	state, err = applyManagedRuleset(context.Background(), second, config, ruleset, statePath)
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Len(t, second.calls, 2)
	require.Contains(t, second.calls[0], "delete table inet anixops_forward")
	require.Contains(t, second.calls[1], "add rule inet anixops_forward")
	require.FileExists(t, statePath)

	require.NoError(t, state.rollback(context.Background()))
	_, err = os.Stat(statePath)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestApplyFailureRollsBackAndRemovesJournal(t *testing.T) {
	directory := t.TempDir()
	_ = os.Chmod(directory, 0o700)
	statePath := filepath.Join(directory, "ownership.json")
	config, err := ParseConfig([]byte(validConfigJSON("apply-failure")))
	require.NoError(t, err)
	config.Apply = true
	ruleset, err := RenderRuleset(config)
	require.NoError(t, err)
	applyErr := errors.New("injected nft apply failure")
	applier := &journalApplier{applyErr: applyErr, failAt: 1}
	state, err := applyManagedRuleset(context.Background(), applier, config, ruleset, statePath)
	require.ErrorIs(t, err, applyErr)
	require.Nil(t, state)
	require.Len(t, applier.calls, 2)
	_, statErr := os.Stat(statePath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestCleanupFailureRetainsJournalForRetry(t *testing.T) {
	directory := t.TempDir()
	_ = os.Chmod(directory, 0o700)
	statePath := filepath.Join(directory, "ownership.json")
	config, err := ParseConfig([]byte(validConfigJSON("cleanup-failure")))
	require.NoError(t, err)
	config.Apply = true
	journal := newOwnershipJournal(config, TableSnapshot{})
	require.NoError(t, writeOwnershipJournal(statePath, journal))
	applier := &journalApplier{applyErr: errors.New("rollback unavailable"), exists: true}
	err = cleanupOwnershipJournal(context.Background(), applier, statePath)
	require.ErrorContains(t, err, "rollback unavailable")
	require.FileExists(t, statePath)
}

func TestRunRollsBackWhenSocketSetupFails(t *testing.T) {
	directory := t.TempDir()
	_ = os.Chmod(directory, 0o700)
	configPath := filepath.Join(directory, "config.json")
	statePath := filepath.Join(directory, "ownership.json")
	config := strings.Replace(validConfigJSON("socket-failure"), `"rules"`, `"apply":true,"rollback_on_exit":true,"rules"`, 1)
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))
	applier := &journalApplier{}
	err := Run(context.Background(), Options{
		ConfigPath: configPath,
		StatePath:  statePath,
		SocketPath: filepath.Join(directory, "missing", "plugin.sock"),
		Applier:    applier,
	})
	require.ErrorContains(t, err, "inspect plugin socket directory")
	require.Len(t, applier.calls, 2)
	_, statErr := os.Stat(statePath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}
