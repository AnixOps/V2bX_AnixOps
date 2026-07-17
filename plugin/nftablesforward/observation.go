package nftablesforward

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	observationSchemaVersion = 1
	maxObservationBytes      = 256 << 10
	observationHealthy       = "healthy"
	observationUnhealthy     = "unhealthy"
)

// NftablesRuleCounter is the counter value for one signed forwarding rule.
// It intentionally has no addresses, ports, command output, or configuration
// payload because the Supervisor only needs a bounded liveness proof.
type NftablesRuleCounter struct {
	RuleID  string
	Packets uint64
	Bytes   uint64
}

// NftablesObservation is the counter-safe result of semantic live-kernel
// verification. RulesetSHA256 is derived from normalized semantics only; it
// never includes nft handles or mutable counter values.
type NftablesObservation struct {
	RulesetSHA256 string
	RuleCounters  []NftablesRuleCounter
}

// runtimeObservation is the only data the plugin persists for Agent-side
// collection. Keep this schema fixed and deliberately narrow: raw nft JSON,
// signed config, command errors, and secrets must never enter this file.
type runtimeObservation struct {
	Version          int                  `json:"version"`
	PluginID         string               `json:"plugin_id"`
	PluginVersion    string               `json:"plugin_version"`
	Health           string               `json:"health"`
	ObservedAtUnixMS int64                `json:"observed_at_unix_ms"`
	RulesetSHA256    string               `json:"ruleset_sha256,omitempty"`
	RuleCounters     []runtimeRuleCounter `json:"rule_counters,omitempty"`
}

type runtimeRuleCounter struct {
	RuleID  string `json:"rule_id"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

func observationFilePath(statePath string) (string, error) {
	statePath, err := privateStatePath(statePath)
	if err != nil {
		return "", err
	}
	return statePath + ".observed.json", nil
}

func writeHealthyObservation(path string, config Config, observed NftablesObservation, at time.Time) error {
	if err := validateNftablesObservation(config, observed); err != nil {
		return err
	}
	counters := make([]runtimeRuleCounter, 0, len(observed.RuleCounters))
	for _, counter := range observed.RuleCounters {
		counters = append(counters, runtimeRuleCounter{
			RuleID: counter.RuleID, Packets: counter.Packets, Bytes: counter.Bytes,
		})
	}
	return writeRuntimeObservation(path, runtimeObservation{
		Version:          observationSchemaVersion,
		PluginID:         ID,
		PluginVersion:    Version,
		Health:           observationHealthy,
		ObservedAtUnixMS: at.UTC().UnixMilli(),
		RulesetSHA256:    observed.RulesetSHA256,
		RuleCounters:     counters,
	})
}

func writeUnhealthyObservation(path string, at time.Time) error {
	return writeRuntimeObservation(path, runtimeObservation{
		Version:          observationSchemaVersion,
		PluginID:         ID,
		PluginVersion:    Version,
		Health:           observationUnhealthy,
		ObservedAtUnixMS: at.UTC().UnixMilli(),
	})
}

// invalidateRuntimeObservation replaces live evidence with an unhealthy
// snapshot. If the atomic replacement itself fails, it removes a previously
// healthy private file when that can be done safely. The Supervisor separately
// probes the runtime health on every heartbeat, so an unremovable file can
// never remain trusted merely because its invalidation failed.
func invalidateRuntimeObservation(path string, at time.Time) error {
	writeErr := writeUnhealthyObservation(path, at)
	if writeErr == nil {
		return nil
	}
	if removeErr := removeRuntimeObservation(path); removeErr != nil {
		return errors.Join(writeErr, fmt.Errorf("remove stale nftables-forward observation: %w", removeErr))
	}
	return fmt.Errorf("persist unhealthy nftables-forward observation: %w", writeErr)
}

func removeRuntimeObservation(path string) error {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("inspect nftables-forward observation directory: %w", err)
	}
	if parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return errors.New("nftables-forward observation directory must be a private real directory")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing nftables-forward observation: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("refusing to remove an unsafe nftables-forward observation")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove nftables-forward observation: %w", err)
	}
	return syncOwnershipDirectory(filepath.Dir(path))
}

func validateNftablesObservation(config Config, observed NftablesObservation) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if !config.Apply {
		return errors.New("nftables-forward observation requires apply=true")
	}
	if !validObservationSHA256(observed.RulesetSHA256) {
		return errors.New("nftables-forward observation ruleset hash is invalid")
	}
	if len(observed.RuleCounters) != len(config.Rules) {
		return errors.New("nftables-forward observation counters do not match signed rules")
	}
	for index, expected := range config.Rules {
		counter := observed.RuleCounters[index]
		if counter.RuleID != expected.ID {
			return errors.New("nftables-forward observation counters do not match signed rule order")
		}
	}
	return nil
}

func validObservationSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validateRuntimeObservation(observation runtimeObservation) error {
	if observation.Version != observationSchemaVersion || observation.PluginID != ID || observation.PluginVersion != Version {
		return errors.New("nftables-forward observation identity is invalid")
	}
	if observation.ObservedAtUnixMS <= 0 {
		return errors.New("nftables-forward observation timestamp is invalid")
	}
	switch observation.Health {
	case observationHealthy:
		if !validObservationSHA256(observation.RulesetSHA256) {
			return errors.New("nftables-forward healthy observation ruleset hash is invalid")
		}
		if len(observation.RuleCounters) == 0 || len(observation.RuleCounters) > maxRules {
			return errors.New("nftables-forward healthy observation counters are invalid")
		}
		seen := make(map[string]struct{}, len(observation.RuleCounters))
		for _, counter := range observation.RuleCounters {
			if !safeRuleID(counter.RuleID) {
				return errors.New("nftables-forward healthy observation counter rule id is invalid")
			}
			if _, exists := seen[counter.RuleID]; exists {
				return errors.New("nftables-forward healthy observation counter rule id is duplicated")
			}
			seen[counter.RuleID] = struct{}{}
		}
	case observationUnhealthy:
		if observation.RulesetSHA256 != "" || len(observation.RuleCounters) != 0 {
			return errors.New("nftables-forward unhealthy observation must not retain live state")
		}
	default:
		return errors.New("nftables-forward observation health is invalid")
	}
	return nil
}

func writeRuntimeObservation(path string, observation runtimeObservation) error {
	if err := validateRuntimeObservation(observation); err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("inspect nftables-forward observation directory: %w", err)
	}
	if parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return errors.New("nftables-forward observation directory must be a private real directory")
	}
	if current, err := os.Lstat(path); err == nil {
		if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || current.Mode().Perm()&0o077 != 0 {
			return errors.New("refusing to replace an unsafe nftables-forward observation")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing nftables-forward observation: %w", err)
	}

	contents, err := json.Marshal(observation)
	if err != nil {
		return fmt.Errorf("encode nftables-forward observation: %w", err)
	}
	contents = append(contents, '\n')
	if len(contents) > maxObservationBytes {
		return fmt.Errorf("nftables-forward observation exceeds %d bytes", maxObservationBytes)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".nftables-forward-observation-*")
	if err != nil {
		return fmt.Errorf("create nftables-forward observation: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write nftables-forward observation: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync nftables-forward observation: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close nftables-forward observation: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish nftables-forward observation: %w", err)
	}
	return syncOwnershipDirectory(filepath.Dir(path))
}

func loadRuntimeObservation(path string) (runtimeObservation, error) {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return runtimeObservation{}, fmt.Errorf("inspect nftables-forward observation directory: %w", err)
	}
	if parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return runtimeObservation{}, errors.New("nftables-forward observation directory must be a private real directory")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return runtimeObservation{}, fmt.Errorf("inspect nftables-forward observation: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return runtimeObservation{}, errors.New("nftables-forward observation must be a private regular file")
	}
	if info.Size() > maxObservationBytes {
		return runtimeObservation{}, fmt.Errorf("nftables-forward observation exceeds %d bytes", maxObservationBytes)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return runtimeObservation{}, fmt.Errorf("read nftables-forward observation: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var observation runtimeObservation
	if err := decoder.Decode(&observation); err != nil {
		return runtimeObservation{}, fmt.Errorf("decode nftables-forward observation: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return runtimeObservation{}, errors.New("nftables-forward observation must contain exactly one JSON object")
	}
	if err := validateRuntimeObservation(observation); err != nil {
		return runtimeObservation{}, err
	}
	return observation, nil
}
