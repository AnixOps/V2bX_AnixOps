package gostmesh

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	journalVersion  = 1
	maxJournalBytes = 1 << 20
)

type tunnelJournal struct {
	ID             string        `json:"id"`
	Role           string        `json:"role"`
	TUNName        string        `json:"tun_name"`
	TUNAddress     string        `json:"tun_address"`
	TUNPeer        string        `json:"tun_peer"`
	InterfaceIndex int           `json:"interface_index"`
	RoutingTable   int           `json:"routing_table"`
	RulePriority   int           `json:"rule_priority"`
	SourceCIDRs    []string      `json:"source_cidrs"`
	RouteCIDRs     []string      `json:"route_cidrs"`
	Process        ProcessRecord `json:"process"`
	Phase          string        `json:"phase"`
}

type ownershipJournal struct {
	Version        int             `json:"version"`
	PluginID       string          `json:"plugin_id"`
	PluginVersion  string          `json:"plugin_version"`
	GOSTExecutable string          `json:"gost_executable"`
	Tunnels        []tunnelJournal `json:"tunnels"`
}

func newOwnershipJournal(config Config, gostExecutable string) ownershipJournal {
	journal := ownershipJournal{
		Version:        journalVersion,
		PluginID:       ID,
		PluginVersion:  Version,
		GOSTExecutable: gostExecutable,
		Tunnels:        make([]tunnelJournal, 0, len(config.Tunnels)),
	}
	for _, tunnel := range config.Tunnels {
		journal.Tunnels = append(journal.Tunnels, tunnelJournal{
			ID:           tunnel.ID,
			Role:         tunnel.Role,
			TUNName:      tunnel.TUN.Name,
			TUNAddress:   tunnel.TUN.Address,
			TUNPeer:      tunnel.TUN.Peer,
			RoutingTable: tunnel.Routing.Table,
			RulePriority: tunnel.Routing.Priority,
			SourceCIDRs:  append([]string(nil), tunnel.Routing.SourceCIDRs...),
			RouteCIDRs:   append([]string(nil), tunnel.Routing.RouteCIDRs...),
			Phase:        "prepared",
		})
	}
	return journal
}

func (j *ownershipJournal) tunnel(id string) (*tunnelJournal, error) {
	for index := range j.Tunnels {
		if j.Tunnels[index].ID == id {
			return &j.Tunnels[index], nil
		}
	}
	return nil, fmt.Errorf("ownership journal does not contain tunnel %q", id)
}

func loadOwnershipJournal(path string) (ownershipJournal, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ownershipJournal{}, false, nil
	}
	if err != nil {
		return ownershipJournal{}, false, fmt.Errorf("inspect gost-mesh ownership journal: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ownershipJournal{}, false, errors.New("gost-mesh ownership journal must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return ownershipJournal{}, false, errors.New("gost-mesh ownership journal must be private")
	}
	if info.Size() > maxJournalBytes {
		return ownershipJournal{}, false, fmt.Errorf("gost-mesh ownership journal exceeds %d bytes", maxJournalBytes)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return ownershipJournal{}, false, fmt.Errorf("read gost-mesh ownership journal: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var journal ownershipJournal
	if err := decoder.Decode(&journal); err != nil {
		return ownershipJournal{}, false, fmt.Errorf("decode gost-mesh ownership journal: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ownershipJournal{}, false, errors.New("gost-mesh ownership journal must contain exactly one JSON object")
	}
	if err := validateOwnershipJournal(journal); err != nil {
		return ownershipJournal{}, false, err
	}
	return journal, true, nil
}

func validateOwnershipJournal(journal ownershipJournal) error {
	if journal.Version != journalVersion || journal.PluginID != ID || journal.PluginVersion != Version {
		return errors.New("gost-mesh ownership journal identity is invalid")
	}
	if !filepath.IsAbs(journal.GOSTExecutable) || filepath.Clean(journal.GOSTExecutable) != journal.GOSTExecutable {
		return errors.New("gost-mesh ownership journal executable is invalid")
	}
	if len(journal.Tunnels) == 0 || len(journal.Tunnels) > maxTunnels {
		return errors.New("gost-mesh ownership journal tunnel count is invalid")
	}
	seen := make(map[string]struct{}, len(journal.Tunnels))
	for _, tunnel := range journal.Tunnels {
		if !safeID(tunnel.ID) || (tunnel.Role != "entry" && tunnel.Role != "exit") || !safeInterfaceName(tunnel.TUNName) {
			return fmt.Errorf("gost-mesh ownership journal tunnel %q is invalid", tunnel.ID)
		}
		if _, exists := seen[tunnel.ID]; exists {
			return fmt.Errorf("gost-mesh ownership journal tunnel %q is duplicated", tunnel.ID)
		}
		seen[tunnel.ID] = struct{}{}
		if tunnel.Phase != "prepared" && tunnel.Phase != "started" && tunnel.Phase != "active" {
			return fmt.Errorf("gost-mesh ownership journal tunnel %q has invalid phase", tunnel.ID)
		}
		if tunnel.Role == "entry" {
			if tunnel.RoutingTable < 1 || tunnel.RoutingTable > maxTableID || tunnel.RulePriority < 1 || tunnel.RulePriority > maxPriority {
				return fmt.Errorf("gost-mesh ownership journal tunnel %q has invalid routing identity", tunnel.ID)
			}
			if len(tunnel.SourceCIDRs) == 0 || len(tunnel.RouteCIDRs) != 0 || tunnel.RulePriority+len(tunnel.SourceCIDRs)-1 > maxPriority {
				return fmt.Errorf("gost-mesh ownership journal tunnel %q has invalid entry routing state", tunnel.ID)
			}
		} else if tunnel.RoutingTable != 0 || tunnel.RulePriority != 0 || len(tunnel.SourceCIDRs) != 0 || len(tunnel.RouteCIDRs) == 0 {
			return fmt.Errorf("gost-mesh ownership journal tunnel %q has invalid exit routing state", tunnel.ID)
		}
		if _, err := validateTUN(TUNConfig{Name: tunnel.TUNName, Address: tunnel.TUNAddress, Peer: tunnel.TUNPeer, Port: 1, MTU: 1280}); err != nil {
			return fmt.Errorf("gost-mesh ownership journal tunnel %q has invalid TUN identity: %w", tunnel.ID, err)
		}
		if _, err := validateCIDRs(tunnel.SourceCIDRs, "source_cidrs"); err != nil {
			return fmt.Errorf("gost-mesh ownership journal tunnel %q: %w", tunnel.ID, err)
		}
		if _, err := validateCIDRs(tunnel.RouteCIDRs, "route_cidrs"); err != nil {
			return fmt.Errorf("gost-mesh ownership journal tunnel %q: %w", tunnel.ID, err)
		}
		if tunnel.InterfaceIndex < 0 {
			return fmt.Errorf("gost-mesh ownership journal tunnel %q has invalid interface index", tunnel.ID)
		}
		processEmpty := tunnel.Process.PID == 0 && tunnel.Process.StartTime == 0 && tunnel.Process.Executable == "" && tunnel.Process.BootID == ""
		processValid := tunnel.Process.PID > 0 && tunnel.Process.StartTime > 0 && validBootID(tunnel.Process.BootID) &&
			filepath.IsAbs(tunnel.Process.Executable) && filepath.Clean(tunnel.Process.Executable) == tunnel.Process.Executable &&
			sameExecutable(tunnel.Process.Executable, journal.GOSTExecutable)
		if !processEmpty && !processValid {
			return fmt.Errorf("gost-mesh ownership journal tunnel %q has invalid process identity", tunnel.ID)
		}
		if tunnel.Phase == "prepared" && (!processEmpty || tunnel.InterfaceIndex != 0) {
			return fmt.Errorf("gost-mesh ownership journal tunnel %q has inconsistent prepared state", tunnel.ID)
		}
		if (tunnel.Phase == "started" || tunnel.Phase == "active") && !processValid {
			return fmt.Errorf("gost-mesh ownership journal tunnel %q has inconsistent process state", tunnel.ID)
		}
		if tunnel.Phase == "active" && tunnel.InterfaceIndex <= 0 {
			return fmt.Errorf("gost-mesh ownership journal tunnel %q has inconsistent active state", tunnel.ID)
		}
	}
	return nil
}

func writeOwnershipJournal(path string, journal ownershipJournal) error {
	if err := validateOwnershipJournal(journal); err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("inspect gost-mesh ownership directory: %w", err)
	}
	if parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return errors.New("gost-mesh ownership directory must be a private real directory")
	}
	if current, err := os.Lstat(path); err == nil {
		if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() {
			return errors.New("refusing to replace an unsafe gost-mesh ownership journal")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing gost-mesh ownership journal: %w", err)
	}
	contents, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return fmt.Errorf("encode gost-mesh ownership journal: %w", err)
	}
	contents = append(contents, '\n')
	if len(contents) > maxJournalBytes {
		return fmt.Errorf("gost-mesh ownership journal exceeds %d bytes", maxJournalBytes)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".gost-mesh-state-*")
	if err != nil {
		return fmt.Errorf("create gost-mesh ownership journal: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write gost-mesh ownership journal: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync gost-mesh ownership journal: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close gost-mesh ownership journal: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish gost-mesh ownership journal: %w", err)
	}
	return syncJournalDirectory(filepath.Dir(path))
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
		return errors.New("refusing to remove an unsafe gost-mesh ownership journal")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncJournalDirectory(filepath.Dir(path))
}

func syncJournalDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func privateStatePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("absolute gost-mesh runtime state path is required")
	}
	return path, nil
}
