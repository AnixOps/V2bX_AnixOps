package nftablesforward

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRuntimeObservationIsPrivateAndContainsOnlyFixedFields(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	statePath := filepath.Join(directory, "ownership.json")
	path, err := observationFilePath(statePath)
	require.NoError(t, err)
	config := observationTestConfig(t)
	at := time.UnixMilli(1_725_000_000_123)
	require.NoError(t, writeHealthyObservation(path, config, NftablesObservation{
		RulesetSHA256: strings.Repeat("a", 64),
		RuleCounters:  []NftablesRuleCounter{{RuleID: "observed", Packets: 12, Bytes: 3456}},
	}, at))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "target_address")
	require.NotContains(t, string(raw), "listen_address")
	require.NotContains(t, string(raw), "error")
	require.NotContains(t, string(raw), "nft_binary")

	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.Equal(t, map[string]bool{
		"version": true, "plugin_id": true, "plugin_version": true, "health": true,
		"observed_at_unix_ms": true, "ruleset_sha256": true, "rule_counters": true,
	}, stringSet(fields))

	observation, err := loadRuntimeObservation(path)
	require.NoError(t, err)
	require.Equal(t, observationHealthy, observation.Health)
	require.Equal(t, at.UTC().UnixMilli(), observation.ObservedAtUnixMS)
	require.Equal(t, []runtimeRuleCounter{{RuleID: "observed", Packets: 12, Bytes: 3456}}, observation.RuleCounters)
	leftovers, err := filepath.Glob(filepath.Join(directory, ".nftables-forward-observation-*"))
	require.NoError(t, err)
	require.Empty(t, leftovers)

	require.NoError(t, writeUnhealthyObservation(path, at.Add(time.Second)))
	observation, err = loadRuntimeObservation(path)
	require.NoError(t, err)
	require.Equal(t, observationUnhealthy, observation.Health)
	require.Empty(t, observation.RulesetSHA256)
	require.Empty(t, observation.RuleCounters)
}

func TestRuntimeObservationRejectsUnsafeAndUnrecognizedDocuments(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	statePath := filepath.Join(directory, "ownership.json")
	path, err := observationFilePath(statePath)
	require.NoError(t, err)
	config := observationTestConfig(t)

	if runtime.GOOS != "windows" {
		other := filepath.Join(directory, "other.json")
		require.NoError(t, os.WriteFile(other, []byte(`{}`), 0o600))
		require.NoError(t, os.Symlink(other, path))
		err = writeHealthyObservation(path, config, NftablesObservation{
			RulesetSHA256: strings.Repeat("b", 64),
			RuleCounters:  []NftablesRuleCounter{{RuleID: "observed"}},
		}, time.Now())
		require.ErrorContains(t, err, "unsafe")
		require.NoError(t, os.Remove(path))
	}

	contents := `{"version":1,"plugin_id":"nftables-forward","plugin_version":"` + Version + `","health":"unhealthy","observed_at_unix_ms":1725000000123,"error":"must-not-be-accepted"}`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	_, err = loadRuntimeObservation(path)
	require.ErrorContains(t, err, "unknown field")
}

func TestCleanupInvalidatesPreviousObservation(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	statePath := filepath.Join(directory, "ownership.json")
	path, err := observationFilePath(statePath)
	require.NoError(t, err)
	config := observationTestConfig(t)
	require.NoError(t, writeHealthyObservation(path, config, NftablesObservation{
		RulesetSHA256: strings.Repeat("c", 64),
		RuleCounters:  []NftablesRuleCounter{{RuleID: "observed", Packets: 1, Bytes: 2}},
	}, time.Now()))

	require.NoError(t, Cleanup(context.Background(), Options{StatePath: statePath, Applier: fixedSnapshotApplier{}}))
	observation, err := loadRuntimeObservation(path)
	require.NoError(t, err)
	require.Equal(t, observationUnhealthy, observation.Health)
}

func observationTestConfig(t *testing.T) Config {
	t.Helper()
	config, err := ParseConfig([]byte(`{
        "apply":true,
        "rollback_on_exit":true,
        "rules":[{"id":"observed","protocol":"tcp","listen_address":"198.51.100.10","listen_port":443,"target_address":"203.0.113.10","target_port":8443}]
    }`))
	require.NoError(t, err)
	return config
}

func stringSet(fields map[string]json.RawMessage) map[string]bool {
	result := make(map[string]bool, len(fields))
	for key := range fields {
		result[key] = true
	}
	return result
}
