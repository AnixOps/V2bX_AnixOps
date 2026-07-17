package nftablesforward

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	ID              = "nftables-forward"
	Version         = "1.0.0"
	DefaultFamily   = "inet"
	DefaultTable    = "anixops_forward"
	DefaultChain    = "prerouting"
	maxConfigBytes  = 256 << 10
	maxRules        = 1024
	defaultPriority = -100
)

type Config struct {
	Apply          bool
	NftBinary      string
	PlanPath       string
	Family         string
	Table          string
	Chain          string
	Priority       int
	RollbackOnExit bool
	Rules          []Rule
}

type Rule struct {
	ID            string
	Protocol      string
	ListenAddress string
	ListenPort    uint16
	TargetAddress string
	TargetPort    uint16
	Comment       string
}

type rawConfig struct {
	Apply          bool            `json:"apply"`
	NftBinary      string          `json:"nft_binary"`
	PlanPath       string          `json:"plan_path"`
	Family         string          `json:"family"`
	Table          string          `json:"table"`
	Chain          string          `json:"chain"`
	Priority       *int            `json:"priority"`
	RollbackOnExit bool            `json:"rollback_on_exit"`
	Rules          json.RawMessage `json:"rules"`
}

type rawRule struct {
	ID            string `json:"id"`
	Protocol      string `json:"protocol"`
	ListenAddress string `json:"listen_address"`
	ListenPort    int    `json:"listen_port"`
	TargetAddress string `json:"target_address"`
	TargetPort    int    `json:"target_port"`
	Comment       string `json:"comment"`
}

type Options struct {
	SocketPath string
	ConfigPath string
	Applier    Applier
}

type Applier interface {
	Apply(ctx context.Context, nftBinary, ruleset string) error
}

type TableSnapshot struct {
	Exists  bool
	Ruleset string
}

type Snapshotter interface {
	Snapshot(ctx context.Context, nftBinary, family, table string) (TableSnapshot, error)
}

type CommandApplier struct{}

func (CommandApplier) Apply(ctx context.Context, nftBinary, ruleset string) error {
	if strings.TrimSpace(nftBinary) == "" {
		nftBinary = "nft"
	}
	dir, err := os.MkdirTemp("", "anixops-nftables-forward-*")
	if err != nil {
		return fmt.Errorf("create nftables transaction directory: %w", err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "ruleset.nft")
	if err := os.WriteFile(path, []byte(ruleset), 0o600); err != nil {
		return fmt.Errorf("write nftables transaction: %w", err)
	}
	command := exec.CommandContext(ctx, nftBinary, "-f", path)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply nftables transaction: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (CommandApplier) Snapshot(ctx context.Context, nftBinary, family, table string) (TableSnapshot, error) {
	if strings.TrimSpace(nftBinary) == "" {
		nftBinary = "nft"
	}
	command := exec.CommandContext(ctx, nftBinary, "list", "table", family, table)
	output, err := command.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(output))
		if strings.Contains(text, "No such file or directory") ||
			strings.Contains(text, "does not exist") ||
			strings.Contains(text, "No such file") {
			return TableSnapshot{Exists: false}, nil
		}
		return TableSnapshot{}, fmt.Errorf("snapshot nftables table: %w: %s", err, text)
	}
	ruleset := string(output)
	if strings.TrimSpace(ruleset) == "" {
		return TableSnapshot{}, errors.New("snapshot nftables table returned an empty ruleset")
	}
	if !strings.HasSuffix(ruleset, "\n") {
		ruleset += "\n"
	}
	return TableSnapshot{Exists: true, Ruleset: ruleset}, nil
}

func LoadConfig(path string) (Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Config{}, errors.New("--anixops-config is required")
	}
	if !filepath.IsAbs(path) {
		return Config{}, errors.New("--anixops-config must be an absolute path")
	}

	before, err := os.Lstat(path)
	if err != nil {
		return Config{}, fmt.Errorf("inspect plugin config: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return Config{}, errors.New("plugin config must be a regular file, not a symlink")
	}
	if before.Mode().Perm()&0o022 != 0 {
		return Config{}, errors.New("plugin config must not be writable by group or other users")
	}
	if before.Size() > maxConfigBytes {
		return Config{}, fmt.Errorf("plugin config exceeds %d bytes", maxConfigBytes)
	}

	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open plugin config: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("stat opened plugin config: %w", err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return Config{}, errors.New("plugin config changed while it was being opened")
	}

	contents, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read plugin config: %w", err)
	}
	if len(contents) > maxConfigBytes {
		return Config{}, fmt.Errorf("plugin config exceeds %d bytes", maxConfigBytes)
	}
	return ParseConfig(contents)
}

func ParseConfig(contents []byte) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var raw *rawConfig
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("decode plugin config: %w", err)
	}
	if raw == nil {
		return Config{}, errors.New("plugin config must be a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("plugin config must contain exactly one JSON object")
		}
		return Config{}, fmt.Errorf("decode trailing plugin config data: %w", err)
	}

	config := Config{
		Apply:          raw.Apply,
		NftBinary:      strings.TrimSpace(raw.NftBinary),
		PlanPath:       strings.TrimSpace(raw.PlanPath),
		Family:         strings.TrimSpace(raw.Family),
		Table:          strings.TrimSpace(raw.Table),
		Chain:          strings.TrimSpace(raw.Chain),
		Priority:       defaultPriority,
		RollbackOnExit: raw.RollbackOnExit,
	}
	if config.Family == "" {
		config.Family = DefaultFamily
	}
	if config.Table == "" {
		config.Table = DefaultTable
	}
	if config.Chain == "" {
		config.Chain = DefaultChain
	}
	if raw.Priority != nil {
		config.Priority = *raw.Priority
	}
	if err := validateRulesetNames(config); err != nil {
		return Config{}, err
	}
	if config.PlanPath != "" && !filepath.IsAbs(config.PlanPath) {
		return Config{}, errors.New("plan_path must be absolute")
	}
	if config.NftBinary != "" && strings.ContainsAny(config.NftBinary, "\x00\r\n") {
		return Config{}, errors.New("nft_binary is invalid")
	}
	if config.Priority < -500 || config.Priority > 500 {
		return Config{}, errors.New("priority must be between -500 and 500")
	}
	if len(raw.Rules) == 0 {
		return Config{}, errors.New("rules must be declared")
	}
	var rawRules []rawRule
	ruleDecoder := json.NewDecoder(bytes.NewReader(raw.Rules))
	ruleDecoder.DisallowUnknownFields()
	if err := ruleDecoder.Decode(&rawRules); err != nil {
		return Config{}, fmt.Errorf("decode forwarding rules: %w", err)
	}
	if len(rawRules) == 0 {
		return Config{}, errors.New("at least one forwarding rule is required")
	}
	if len(rawRules) > maxRules {
		return Config{}, fmt.Errorf("forwarding rules exceed %d entries", maxRules)
	}
	seenIDs := make(map[string]bool, len(rawRules))
	for index, rawRule := range rawRules {
		rule, err := normalizeRule(rawRule)
		if err != nil {
			return Config{}, fmt.Errorf("rule %d: %w", index, err)
		}
		if seenIDs[rule.ID] {
			return Config{}, fmt.Errorf("rule %q is duplicated", rule.ID)
		}
		seenIDs[rule.ID] = true
		config.Rules = append(config.Rules, rule)
	}
	return config, nil
}

func validateRulesetNames(config Config) error {
	if config.Family != "inet" && config.Family != "ip" && config.Family != "ip6" {
		return errors.New("family must be inet, ip, or ip6")
	}
	if !safeNftIdentifier(config.Table) {
		return errors.New("table must be a safe nftables identifier")
	}
	if !safeNftIdentifier(config.Chain) {
		return errors.New("chain must be a safe nftables identifier")
	}
	return nil
}

func normalizeRule(raw rawRule) (Rule, error) {
	rule := Rule{
		ID:            strings.TrimSpace(raw.ID),
		Protocol:      strings.ToLower(strings.TrimSpace(raw.Protocol)),
		ListenAddress: strings.TrimSpace(raw.ListenAddress),
		ListenPort:    uint16(raw.ListenPort),
		TargetAddress: strings.TrimSpace(raw.TargetAddress),
		TargetPort:    uint16(raw.TargetPort),
		Comment:       strings.TrimSpace(raw.Comment),
	}
	if !safeRuleID(rule.ID) {
		return Rule{}, errors.New("id is invalid")
	}
	if rule.Protocol != "tcp" && rule.Protocol != "udp" {
		return Rule{}, errors.New("protocol must be tcp or udp")
	}
	if raw.ListenPort < 1 || raw.ListenPort > 65535 {
		return Rule{}, errors.New("listen_port must be between 1 and 65535")
	}
	if raw.TargetPort < 1 || raw.TargetPort > 65535 {
		return Rule{}, errors.New("target_port must be between 1 and 65535")
	}
	listen, err := netip.ParseAddr(rule.ListenAddress)
	if err != nil || listen.IsUnspecified() || listen.IsMulticast() {
		return Rule{}, errors.New("listen_address must be a unicast IP address")
	}
	target, err := netip.ParseAddr(rule.TargetAddress)
	if err != nil || target.IsUnspecified() || target.IsMulticast() {
		return Rule{}, errors.New("target_address must be a unicast IP address")
	}
	if listen.Is4() != target.Is4() {
		return Rule{}, errors.New("listen_address and target_address must use the same IP family")
	}
	if rule.Comment != "" && (!safeComment(rule.Comment) || len(rule.Comment) > 96) {
		return Rule{}, errors.New("comment is invalid")
	}
	return rule, nil
}

func RenderRuleset(config Config) (string, error) {
	if err := validateRulesetNames(config); err != nil {
		return "", err
	}
	if len(config.Rules) == 0 {
		return "", errors.New("at least one forwarding rule is required")
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "add table %s %s\n", config.Family, config.Table)
	fmt.Fprintf(&builder, "flush table %s %s\n", config.Family, config.Table)
	fmt.Fprintf(&builder, "add chain %s %s %s { type nat hook prerouting priority %d; policy accept; }\n",
		config.Family,
		config.Table,
		config.Chain,
		config.Priority,
	)
	for _, rule := range config.Rules {
		if err := validateRuleForFamily(config.Family, rule); err != nil {
			return "", fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		fmt.Fprintf(&builder, "add rule %s %s %s %s daddr %s %s dport %d dnat to %s comment %q\n",
			config.Family,
			config.Table,
			config.Chain,
			nftAddressFamily(rule.ListenAddress),
			formatNftAddress(rule.ListenAddress),
			rule.Protocol,
			rule.ListenPort,
			formatNftDestination(rule.TargetAddress, rule.TargetPort),
			nftComment(rule),
		)
	}
	return builder.String(), nil
}

func validateRuleForFamily(family string, rule Rule) error {
	addr, err := netip.ParseAddr(rule.ListenAddress)
	if err != nil {
		return errors.New("listen_address must be a valid IP address")
	}
	if family == "ip" && !addr.Is4() {
		return errors.New("IPv6 rule cannot be installed in an ip family table")
	}
	if family == "ip6" && !addr.Is6() {
		return errors.New("IPv4 rule cannot be installed in an ip6 family table")
	}
	return nil
}

func Run(ctx context.Context, options Options) error {
	if ctx == nil {
		return errors.New("plugin context is required")
	}
	config, err := LoadConfig(options.ConfigPath)
	if err != nil {
		return err
	}
	ruleset, err := RenderRuleset(config)
	if err != nil {
		return err
	}
	if config.PlanPath != "" {
		if err := writePrivatePlan(config.PlanPath, ruleset); err != nil {
			return err
		}
	}
	applier := options.Applier
	if applier == nil {
		applier = CommandApplier{}
	}
	var rollbackRuleset string
	if config.Apply && config.RollbackOnExit {
		snapshotter, ok := applier.(Snapshotter)
		if ok {
			snapshotCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			snapshot, snapshotErr := snapshotter.Snapshot(snapshotCtx, config.NftBinary, config.Family, config.Table)
			cancel()
			if snapshotErr != nil {
				return snapshotErr
			}
			rollbackRuleset, err = RenderRollbackFromSnapshot(config, snapshot)
		} else {
			rollbackRuleset, err = RenderRollback(config)
		}
		if err != nil {
			return err
		}
	}
	if config.Apply {
		applyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := applier.Apply(applyCtx, config.NftBinary, ruleset)
		cancel()
		if err != nil {
			return err
		}
	}

	listener, err := listenUnixSocket(options.SocketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = removeUnixSocket(options.SocketPath)
	}()

	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(ID, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		healthServer.Shutdown()
		server.Stop()
		err := <-serveResult
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return fmt.Errorf("serve plugin health API: %w", err)
		}
		if config.Apply && config.RollbackOnExit {
			if rollbackRuleset == "" {
				rollbackRuleset, err = RenderRollback(config)
				if err != nil {
					return err
				}
			}
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := applier.Apply(rollbackCtx, config.NftBinary, rollbackRuleset); err != nil {
				return err
			}
		}
		return nil
	case err := <-serveResult:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return fmt.Errorf("serve plugin health API: %w", err)
		}
		return nil
	}
}

func RenderRollback(config Config) (string, error) {
	if err := validateRulesetNames(config); err != nil {
		return "", err
	}
	return fmt.Sprintf("delete table %s %s\n", config.Family, config.Table), nil
}

func RenderRollbackFromSnapshot(config Config, snapshot TableSnapshot) (string, error) {
	if err := validateRulesetNames(config); err != nil {
		return "", err
	}
	if !snapshot.Exists {
		return RenderRollback(config)
	}
	ruleset := strings.TrimSpace(snapshot.Ruleset)
	if ruleset == "" {
		return "", errors.New("snapshot ruleset is empty")
	}
	return fmt.Sprintf("flush table %s %s\n%s\n", config.Family, config.Table, ruleset), nil
}

func writePrivatePlan(path, ruleset string) error {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("inspect plan directory: %w", err)
	}
	if parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() {
		return errors.New("plan directory must be a real directory")
	}
	if parent.Mode().Perm()&0o022 != 0 {
		return errors.New("plan directory must not be writable by group or other users")
	}
	return os.WriteFile(path, []byte(ruleset), 0o600)
}

func listenUnixSocket(path string) (net.Listener, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("--anixops-socket is required")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("--anixops-socket must be an absolute path")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("inspect plugin socket directory: %w", err)
	}
	if parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() {
		return nil, errors.New("plugin socket directory must be a real directory")
	}
	if parent.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("plugin socket directory must not be writable by group or other users")
	}
	if err := removeUnixSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on plugin Unix socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = removeUnixSocket(path)
		return nil, fmt.Errorf("protect plugin Unix socket: %w", err)
	}
	return listener, nil
}

func removeUnixSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket plugin path %q", path)
	}
	return os.Remove(path)
}

func safeNftIdentifier(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for index, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char == '_' || index > 0 && char >= '0' && char <= '9' {
			continue
		}
		return false
	}
	return true
}

func safeRuleID(value string) bool {
	if value == "" || len(value) > 80 {
		return false
	}
	for index, char := range value {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_' || index > 0 && char == '.' {
			continue
		}
		return false
	}
	return true
}

func safeComment(value string) bool {
	return !strings.ContainsAny(value, "\x00\r\n\"\\")
}

func nftAddressFamily(address string) string {
	addr := netip.MustParseAddr(address)
	if addr.Is4() {
		return "ip"
	}
	return "ip6"
}

func formatNftAddress(address string) string {
	addr := netip.MustParseAddr(address)
	if addr.Is6() {
		return addr.String()
	}
	return addr.String()
}

func formatNftDestination(address string, port uint16) string {
	addr := netip.MustParseAddr(address)
	if addr.Is6() {
		return "[" + addr.String() + "]:" + strconv.Itoa(int(port))
	}
	return addr.String() + ":" + strconv.Itoa(int(port))
}

func nftComment(rule Rule) string {
	if rule.Comment != "" {
		return "anixops " + rule.ID + " " + rule.Comment
	}
	return "anixops " + rule.ID
}
