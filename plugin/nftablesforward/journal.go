package nftablesforward

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	ownershipJournalVersion = 1
	maxJournalBytes         = 2 << 20
)

type ownershipIdentity struct {
	PluginID      string   `json:"plugin_id"`
	PluginVersion string   `json:"plugin_version"`
	NftBinary     string   `json:"nft_binary,omitempty"`
	Family        string   `json:"family"`
	Table         string   `json:"table"`
	Chain         string   `json:"chain"`
	Priority      int      `json:"priority"`
	RuleIDs       []string `json:"rule_ids"`
}

type ownershipJournal struct {
	Version  int               `json:"version"`
	Identity ownershipIdentity `json:"identity"`
	Snapshot TableSnapshot     `json:"nft_snapshot"`
}

type appliedState struct {
	applier     Applier
	config      Config
	snapshot    TableSnapshot
	journalPath string
}

func rollbackRuleset(ctx context.Context, applier Applier, config Config, original TableSnapshot) (string, bool, error) {
	if applier == nil {
		return "", false, errors.New("nftables-forward applier is required")
	}
	snapshotter, ok := applier.(Snapshotter)
	if !ok {
		return "", false, errors.New("nftables-forward rollback requires table snapshots")
	}
	current, err := snapshotter.Snapshot(ctx, config.NftBinary, config.Family, config.Table)
	if err != nil {
		return "", false, err
	}
	if !current.Exists {
		if !original.Exists {
			return "", false, nil
		}
		return strings.TrimSpace(original.Ruleset) + "\n", true, nil
	}
	if !original.Exists {
		return fmt.Sprintf("delete table %s %s\n", config.Family, config.Table), true, nil
	}
	ruleset := strings.TrimSpace(original.Ruleset)
	if ruleset == "" {
		return "", false, errors.New("snapshot ruleset is empty")
	}
	return fmt.Sprintf("delete table %s %s\n%s\n", config.Family, config.Table, ruleset), true, nil
}

func newOwnershipJournal(config Config, snapshot TableSnapshot) ownershipJournal {
	ruleIDs := make([]string, 0, len(config.Rules))
	for _, rule := range config.Rules {
		ruleIDs = append(ruleIDs, rule.ID)
	}
	return ownershipJournal{
		Version: ownershipJournalVersion,
		Identity: ownershipIdentity{
			PluginID: ID, PluginVersion: Version, NftBinary: config.NftBinary,
			Family: config.Family, Table: config.Table, Chain: config.Chain,
			Priority: config.Priority, RuleIDs: ruleIDs,
		},
		Snapshot: snapshot,
	}
}

func (i ownershipIdentity) config() Config {
	return Config{
		Apply: true, RollbackOnExit: true, NftBinary: i.NftBinary,
		Family: i.Family, Table: i.Table, Chain: i.Chain, Priority: i.Priority,
	}
}

func validateOwnershipJournal(journal ownershipJournal) error {
	if journal.Version != ownershipJournalVersion || journal.Identity.PluginID != ID || journal.Identity.PluginVersion != Version {
		return errors.New("nftables-forward ownership journal identity is invalid")
	}
	config := journal.Identity.config()
	if err := validateRulesetNames(config); err != nil {
		return fmt.Errorf("nftables-forward ownership journal identity is invalid: %w", err)
	}
	if config.Priority < -500 || config.Priority > 500 || strings.ContainsAny(config.NftBinary, "\x00\r\n") {
		return errors.New("nftables-forward ownership journal identity is invalid")
	}
	if len(journal.Identity.RuleIDs) == 0 || len(journal.Identity.RuleIDs) > maxRules {
		return errors.New("nftables-forward ownership journal rule identity is invalid")
	}
	seen := make(map[string]bool, len(journal.Identity.RuleIDs))
	for _, ruleID := range journal.Identity.RuleIDs {
		if !safeRuleID(ruleID) || seen[ruleID] {
			return errors.New("nftables-forward ownership journal rule identity is invalid")
		}
		seen[ruleID] = true
	}
	if journal.Snapshot.Exists && strings.TrimSpace(journal.Snapshot.Ruleset) == "" {
		return errors.New("nftables-forward ownership journal contains an empty nftables snapshot")
	}
	return nil
}

func loadOwnershipJournal(path string) (ownershipJournal, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ownershipJournal{}, false, nil
	}
	if err != nil {
		return ownershipJournal{}, false, fmt.Errorf("inspect nftables-forward ownership journal: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ownershipJournal{}, false, errors.New("nftables-forward ownership journal must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return ownershipJournal{}, false, errors.New("nftables-forward ownership journal must be private")
	}
	if info.Size() > maxJournalBytes {
		return ownershipJournal{}, false, fmt.Errorf("nftables-forward ownership journal exceeds %d bytes", maxJournalBytes)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return ownershipJournal{}, false, fmt.Errorf("read nftables-forward ownership journal: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var journal ownershipJournal
	if err := decoder.Decode(&journal); err != nil {
		return ownershipJournal{}, false, fmt.Errorf("decode nftables-forward ownership journal: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ownershipJournal{}, false, errors.New("nftables-forward ownership journal must contain exactly one JSON object")
	}
	if err := validateOwnershipJournal(journal); err != nil {
		return ownershipJournal{}, false, err
	}
	return journal, true, nil
}

func writeOwnershipJournal(path string, journal ownershipJournal) error {
	if err := validateOwnershipJournal(journal); err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("inspect nftables-forward ownership directory: %w", err)
	}
	if parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return errors.New("nftables-forward ownership directory must be a private real directory")
	}
	if current, err := os.Lstat(path); err == nil {
		if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() {
			return errors.New("refusing to replace an unsafe nftables-forward ownership journal")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing nftables-forward ownership journal: %w", err)
	}
	contents, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return fmt.Errorf("encode nftables-forward ownership journal: %w", err)
	}
	contents = append(contents, '\n')
	if len(contents) > maxJournalBytes {
		return fmt.Errorf("nftables-forward ownership journal exceeds %d bytes", maxJournalBytes)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".nftables-forward-state-*")
	if err != nil {
		return fmt.Errorf("create nftables-forward ownership journal: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write nftables-forward ownership journal: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync nftables-forward ownership journal: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close nftables-forward ownership journal: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish nftables-forward ownership journal: %w", err)
	}
	return syncOwnershipDirectory(filepath.Dir(path))
}

func removeOwnershipJournal(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("refusing to remove an unsafe nftables-forward ownership journal")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncOwnershipDirectory(filepath.Dir(path))
}

func syncOwnershipDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open nftables-forward ownership directory: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func privateStatePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("absolute nftables-forward runtime state path is required")
	}
	return path, nil
}

func applyManagedRuleset(ctx context.Context, applier Applier, config Config, ruleset, journalPath string) (*appliedState, error) {
	if applier == nil {
		return nil, errors.New("nftables-forward applier is required")
	}
	if err := cleanupOwnershipJournal(ctx, applier, journalPath); err != nil {
		return nil, fmt.Errorf("recover interrupted nftables-forward state: %w", err)
	}
	snapshotter, ok := applier.(Snapshotter)
	if !ok {
		return nil, errors.New("nftables-forward applier must support table snapshots")
	}
	snapshot, err := snapshotter.Snapshot(ctx, config.NftBinary, config.Family, config.Table)
	if err != nil {
		return nil, err
	}
	state := &appliedState{applier: applier, config: config, snapshot: snapshot, journalPath: journalPath}
	if err := writeOwnershipJournal(journalPath, newOwnershipJournal(config, snapshot)); err != nil {
		return nil, err
	}
	if err := applier.Apply(ctx, config.NftBinary, ruleset); err != nil {
		return nil, errors.Join(err, state.rollbackWithTimeout())
	}
	return state, nil
}

func cleanupOwnershipJournal(ctx context.Context, applier Applier, journalPath string) error {
	journal, exists, err := loadOwnershipJournal(journalPath)
	if err != nil || !exists {
		return err
	}
	config := journal.Identity.config()
	ruleset, needed, err := rollbackRuleset(ctx, applier, config, journal.Snapshot)
	if err != nil {
		return err
	}
	if needed {
		if err := applier.Apply(ctx, journal.Identity.NftBinary, ruleset); err != nil {
			return err
		}
	}
	if err := removeOwnershipJournal(journalPath); err != nil {
		return err
	}
	return nil
}

func (s *appliedState) rollback(ctx context.Context) error {
	if s == nil || s.applier == nil {
		return nil
	}
	ruleset, needed, err := rollbackRuleset(ctx, s.applier, s.config, s.snapshot)
	if err != nil {
		return err
	}
	if needed {
		if err := s.applier.Apply(ctx, s.config.NftBinary, ruleset); err != nil {
			return err
		}
	}
	return removeOwnershipJournal(s.journalPath)
}

func (s *appliedState) rollbackWithTimeout() error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	return s.rollback(ctx)
}

// Cleanup restores the exact pre-apply nftables snapshot recorded by the
// stable Supervisor-owned state path. The journal is retained on any failure so
// a later Agent restart can retry without guessing ownership.
func Cleanup(ctx context.Context, options Options) error {
	if ctx == nil {
		return errors.New("plugin context is required")
	}
	statePath, err := privateStatePath(options.StatePath)
	if err != nil {
		return err
	}
	applier := options.Applier
	if applier == nil {
		applier = CommandApplier{}
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	return cleanupOwnershipJournal(cleanupCtx, applier, statePath)
}
