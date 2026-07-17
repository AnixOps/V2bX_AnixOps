package nategress

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	ownershipJournalVersion = 1
	maxJournalBytes         = 512 << 10
)

type ownershipIdentity struct {
	TableName       string `json:"table_name"`
	ChainName       string `json:"chain_name"`
	EgressInterface string `json:"egress_interface"`
	DefaultMark     int    `json:"default_mark"`
	PolicyTable     int    `json:"policy_table"`
	RulePriority    int    `json:"rule_priority"`
	IPv4Masquerade  bool   `json:"ipv4_masquerade"`
	IPv6Masquerade  bool   `json:"ipv6_masquerade"`
}

type journalPolicy struct {
	Route      PolicyRoute `json:"route"`
	RuleOwned  bool        `json:"rule_owned"`
	RouteOwned bool        `json:"route_owned"`
}

type ownershipJournal struct {
	Version  int                      `json:"version"`
	Identity ownershipIdentity        `json:"identity"`
	Snapshot TableSnapshot            `json:"nft_snapshot"`
	Policies map[string]journalPolicy `json:"policies"`
}

func ownershipJournalPath(configPath string) string {
	return configPath + ".nat-egress-state.json"
}

func newOwnershipJournal(config Config, snapshot TableSnapshot, policies map[IPFamily]*policyOwnership) ownershipJournal {
	journal := ownershipJournal{
		Version:  ownershipJournalVersion,
		Identity: identityForConfig(config),
		Snapshot: snapshot,
		Policies: make(map[string]journalPolicy, len(policies)),
	}
	for family, policy := range policies {
		journal.Policies[strconv.Itoa(int(family))] = journalPolicy{
			Route:      policy.inspection.Route,
			RuleOwned:  policy.ruleOwned,
			RouteOwned: policy.routeOwned,
		}
	}
	return journal
}

func identityForConfig(config Config) ownershipIdentity {
	return ownershipIdentity{
		TableName:       config.TableName,
		ChainName:       config.ChainName,
		EgressInterface: config.EgressInterface,
		DefaultMark:     config.DefaultMark,
		PolicyTable:     config.PolicyTable,
		RulePriority:    config.RulePriority,
		IPv4Masquerade:  config.IPv4Masquerade,
		IPv6Masquerade:  config.IPv6Masquerade,
	}
}

func loadOwnershipJournal(path string) (ownershipJournal, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ownershipJournal{}, false, nil
	}
	if err != nil {
		return ownershipJournal{}, false, fmt.Errorf("inspect nat-egress ownership journal: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ownershipJournal{}, false, errors.New("nat-egress ownership journal must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return ownershipJournal{}, false, errors.New("nat-egress ownership journal must be private")
	}
	if info.Size() > maxJournalBytes {
		return ownershipJournal{}, false, fmt.Errorf("nat-egress ownership journal exceeds %d bytes", maxJournalBytes)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return ownershipJournal{}, false, fmt.Errorf("read nat-egress ownership journal: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var journal ownershipJournal
	if err := decoder.Decode(&journal); err != nil {
		return ownershipJournal{}, false, fmt.Errorf("decode nat-egress ownership journal: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ownershipJournal{}, false, errors.New("nat-egress ownership journal must contain exactly one JSON object")
	}
	if err := validateOwnershipJournal(journal); err != nil {
		return ownershipJournal{}, false, err
	}
	return journal, true, nil
}

func validateOwnershipJournal(journal ownershipJournal) error {
	if journal.Version != ownershipJournalVersion {
		return fmt.Errorf("unsupported nat-egress ownership journal version %d", journal.Version)
	}
	config := journal.Identity.config()
	if err := config.Validate(); err != nil {
		return fmt.Errorf("nat-egress ownership journal identity is invalid: %w", err)
	}
	if journal.Snapshot.Exists && strings.TrimSpace(journal.Snapshot.Ruleset) == "" {
		return errors.New("nat-egress ownership journal contains an empty nftables snapshot")
	}
	expected := enabledFamilies(config)
	if len(journal.Policies) != len(expected) {
		return errors.New("nat-egress ownership journal policy families do not match configuration")
	}
	for _, family := range expected {
		policy, ok := journal.Policies[strconv.Itoa(int(family))]
		if !ok {
			return fmt.Errorf("nat-egress ownership journal is missing %s policy state", familyName(family))
		}
		if policy.Route.Family != family || policy.Route.Device != config.EgressInterface {
			return fmt.Errorf("nat-egress ownership journal %s route does not match configuration", familyName(family))
		}
	}
	return nil
}

func (identity ownershipIdentity) config() Config {
	return Config{
		RollbackOnExit:             true,
		TableName:                  identity.TableName,
		ChainName:                  identity.ChainName,
		EgressInterface:            identity.EgressInterface,
		DefaultMark:                identity.DefaultMark,
		PolicyTable:                identity.PolicyTable,
		RulePriority:               identity.RulePriority,
		IPv4Masquerade:             identity.IPv4Masquerade,
		IPv6Masquerade:             identity.IPv6Masquerade,
		HealthCheckEnabled:         false,
		HealthCheckIntervalSeconds: DefaultHealthCheckIntervalSeconds,
		HealthCheckTimeoutSeconds:  DefaultHealthCheckTimeoutSeconds,
		HealthCheckTarget:          DefaultHealthCheckTarget,
	}
}

func writeOwnershipJournal(path string, journal ownershipJournal) error {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("inspect nat-egress ownership directory: %w", err)
	}
	if parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return errors.New("nat-egress ownership directory must be a private real directory")
	}
	if current, err := os.Lstat(path); err == nil {
		if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() {
			return errors.New("refusing to replace an unsafe nat-egress ownership journal")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing nat-egress ownership journal: %w", err)
	}
	contents, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return fmt.Errorf("encode nat-egress ownership journal: %w", err)
	}
	contents = append(contents, '\n')
	if len(contents) > maxJournalBytes {
		return fmt.Errorf("nat-egress ownership journal exceeds %d bytes", maxJournalBytes)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".nat-egress-state-*")
	if err != nil {
		return fmt.Errorf("create nat-egress ownership journal: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write nat-egress ownership journal: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync nat-egress ownership journal: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close nat-egress ownership journal: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish nat-egress ownership journal: %w", err)
	}
	return syncOwnershipDirectory(filepath.Dir(path))
}

func syncOwnershipDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open nat-egress ownership directory: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		syncErr = fmt.Errorf("sync nat-egress ownership directory: %w", syncErr)
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("close nat-egress ownership directory: %w", closeErr)
	}
	return errors.Join(syncErr, closeErr)
}

func removeOwnershipJournal(path string) error {
	return removeOwnershipJournalWithSync(path, syncOwnershipDirectory)
}

func removeOwnershipJournalWithSync(path string, syncDirectory func(string) error) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("refusing to remove an unsafe nat-egress ownership journal")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
