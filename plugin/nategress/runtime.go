package nategress

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
	"runtime"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	ID      = "nat-egress"
	Version = "1.0.0"

	DefaultTableName                  = "anixops_nat_egress"
	DefaultChainName                  = "postrouting"
	DefaultEgressInterface            = "eth0"
	DefaultMark                       = 100
	DefaultPolicyTable                = 100
	DefaultRulePriority               = 10100
	DefaultHealthCheckIntervalSeconds = 15
	DefaultHealthCheckTimeoutSeconds  = 3
	DefaultHealthCheckTarget          = "1.1.1.1:443"

	maxConfigBytes    = 64 << 10
	maxTableID        = 252
	maxRulePriority   = 32765
	maxMark           = 65535
	nftPriority       = 100
	commandTimeout    = 30 * time.Second
	localRouteTable   = 255
	mainRouteTable    = 254
	defaultRouteTable = 253
)

type Config struct {
	Apply                      bool
	RollbackOnExit             bool
	TableName                  string
	ChainName                  string
	EgressInterface            string
	DefaultMark                int
	PolicyTable                int
	RulePriority               int
	IPv4Masquerade             bool
	IPv6Masquerade             bool
	HealthCheckEnabled         bool
	HealthCheckIntervalSeconds int
	HealthCheckTimeoutSeconds  int
	HealthCheckTarget          string
}

func (c Config) HealthCheckInterval() time.Duration {
	return time.Duration(c.HealthCheckIntervalSeconds) * time.Second
}

func (c Config) HealthCheckTimeout() time.Duration {
	return time.Duration(c.HealthCheckTimeoutSeconds) * time.Second
}

type rawConfig struct {
	Apply                      *bool  `json:"apply"`
	RollbackOnExit             *bool  `json:"rollback_on_exit"`
	TableName                  string `json:"table_name"`
	ChainName                  string `json:"chain_name"`
	EgressInterface            string `json:"egress_interface"`
	DefaultMark                *int   `json:"default_mark"`
	PolicyTable                *int   `json:"policy_table"`
	RulePriority               *int   `json:"rule_priority"`
	IPv4Masquerade             *bool  `json:"ipv4_masquerade"`
	IPv6Masquerade             *bool  `json:"ipv6_masquerade"`
	HealthCheckEnabled         *bool  `json:"health_check_enabled"`
	HealthCheckIntervalSeconds *int   `json:"health_check_interval_seconds"`
	HealthCheckTimeoutSeconds  *int   `json:"health_check_timeout_seconds"`
	HealthCheckTarget          string `json:"health_check_target"`
}

type Options struct {
	SocketPath string
	ConfigPath string
	StatePath  string
	Network    NetworkManager
	Prober     Prober
}

func Cleanup(ctx context.Context, options Options) error {
	if ctx == nil {
		return errors.New("plugin context is required")
	}
	if runtime.GOOS != "linux" {
		return errors.New("nat-egress cleanup is supported only on Linux")
	}
	socketPath := strings.TrimSpace(options.SocketPath)
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		return errors.New("--anixops-socket must be an absolute path")
	}
	network := options.Network
	if network == nil {
		network = CommandNetworkManager{}
	}
	statePath := runtimeStatePath(options)
	if strings.TrimSpace(statePath) == "" || !filepath.IsAbs(statePath) {
		return errors.New("absolute nat-egress runtime state path is required")
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	return cleanupOwnershipJournal(cleanupCtx, network, statePath)
}

type IPFamily int

const (
	IPv4 IPFamily = 4
	IPv6 IPFamily = 6
)

func (f IPFamily) flag() string {
	if f == IPv6 {
		return "-6"
	}
	return "-4"
}

type TableSnapshot struct {
	Exists  bool   `json:"exists"`
	Ruleset string `json:"ruleset,omitempty"`
}

type PolicyRoute struct {
	Family          IPFamily `json:"family"`
	Gateway         string   `json:"gateway,omitempty"`
	Device          string   `json:"device"`
	PreferredSource string   `json:"preferred_source,omitempty"`
	Metric          int      `json:"metric,omitempty"`
	MTU             int      `json:"mtu,omitempty"`
	AdvMSS          int      `json:"advmss,omitempty"`
	Onlink          bool     `json:"onlink,omitempty"`
}

type PolicyInspection struct {
	RuleExists  bool
	RouteExists bool
	Route       PolicyRoute
}

type NetworkManager interface {
	ValidateForwarding(context.Context, Config) error
	VerifyApplied(context.Context, Config) error
	SnapshotTable(context.Context, string) (TableSnapshot, error)
	ApplyRuleset(context.Context, string) error
	InspectPolicy(context.Context, IPFamily, Config) (PolicyInspection, error)
	AddPolicyRoute(context.Context, int, PolicyRoute) error
	DeletePolicyRoute(context.Context, int, PolicyRoute) error
	AddPolicyRule(context.Context, IPFamily, int, int, int) error
	DeletePolicyRule(context.Context, IPFamily, int, int, int) error
}

type Prober interface {
	Probe(context.Context, Config) error
}

type CommandNetworkManager struct {
	NftBinary string
	IPBinary  string
	ProcRoot  string
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
		RollbackOnExit:             true,
		TableName:                  DefaultTableName,
		ChainName:                  DefaultChainName,
		EgressInterface:            DefaultEgressInterface,
		DefaultMark:                DefaultMark,
		PolicyTable:                DefaultPolicyTable,
		RulePriority:               DefaultRulePriority,
		IPv4Masquerade:             true,
		HealthCheckEnabled:         true,
		HealthCheckIntervalSeconds: DefaultHealthCheckIntervalSeconds,
		HealthCheckTimeoutSeconds:  DefaultHealthCheckTimeoutSeconds,
		HealthCheckTarget:          DefaultHealthCheckTarget,
	}
	if raw.Apply != nil {
		config.Apply = *raw.Apply
	}
	if raw.RollbackOnExit != nil {
		config.RollbackOnExit = *raw.RollbackOnExit
	}
	if value := strings.TrimSpace(raw.TableName); value != "" {
		config.TableName = value
	}
	if value := strings.TrimSpace(raw.ChainName); value != "" {
		config.ChainName = value
	}
	if value := strings.TrimSpace(raw.EgressInterface); value != "" {
		config.EgressInterface = value
	}
	if raw.DefaultMark != nil {
		config.DefaultMark = *raw.DefaultMark
	}
	if raw.PolicyTable != nil {
		config.PolicyTable = *raw.PolicyTable
	}
	if raw.RulePriority != nil {
		config.RulePriority = *raw.RulePriority
	}
	if raw.IPv4Masquerade != nil {
		config.IPv4Masquerade = *raw.IPv4Masquerade
	}
	if raw.IPv6Masquerade != nil {
		config.IPv6Masquerade = *raw.IPv6Masquerade
	}
	if raw.HealthCheckEnabled != nil {
		config.HealthCheckEnabled = *raw.HealthCheckEnabled
	}
	if raw.HealthCheckIntervalSeconds != nil {
		config.HealthCheckIntervalSeconds = *raw.HealthCheckIntervalSeconds
	}
	if raw.HealthCheckTimeoutSeconds != nil {
		config.HealthCheckTimeoutSeconds = *raw.HealthCheckTimeoutSeconds
	}
	if value := strings.TrimSpace(raw.HealthCheckTarget); value != "" {
		config.HealthCheckTarget = value
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if !c.RollbackOnExit {
		return errors.New("rollback_on_exit must remain enabled for the nat-egress v1 crash-safe lifecycle")
	}
	if !safeNftIdentifier(c.TableName) {
		return errors.New("table_name must be a safe nftables identifier")
	}
	if !safeNftIdentifier(c.ChainName) {
		return errors.New("chain_name must be a safe nftables identifier")
	}
	if !safeInterfaceName(c.EgressInterface) {
		return errors.New("egress_interface is invalid")
	}
	if c.DefaultMark < 1 || c.DefaultMark > maxMark {
		return fmt.Errorf("default_mark must be between 1 and %d", maxMark)
	}
	if c.PolicyTable < 1 || c.PolicyTable > maxTableID {
		return fmt.Errorf("policy_table must be between 1 and %d", maxTableID)
	}
	if c.RulePriority < 1 || c.RulePriority > maxRulePriority {
		return fmt.Errorf("rule_priority must be between 1 and %d", maxRulePriority)
	}
	if !c.IPv4Masquerade && !c.IPv6Masquerade {
		return errors.New("at least one of ipv4_masquerade or ipv6_masquerade must be enabled")
	}
	if c.HealthCheckIntervalSeconds < 5 || c.HealthCheckIntervalSeconds > 300 {
		return errors.New("health_check_interval_seconds must be between 5 and 300")
	}
	if c.HealthCheckTimeoutSeconds < 1 || c.HealthCheckTimeoutSeconds > 30 {
		return errors.New("health_check_timeout_seconds must be between 1 and 30")
	}
	if c.HealthCheckEnabled {
		if err := validateHealthTarget(c.HealthCheckTarget); err != nil {
			return err
		}
		host, _, _ := net.SplitHostPort(c.HealthCheckTarget)
		if address, err := netip.ParseAddr(host); err == nil {
			if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() {
				return errors.New("health_check_target must be an external unicast address")
			}
			if address.Is4() && !c.IPv4Masquerade {
				return errors.New("an IPv4 health_check_target requires ipv4_masquerade")
			}
			if address.Is6() && !c.IPv6Masquerade {
				return errors.New("an IPv6 health_check_target requires ipv6_masquerade")
			}
			if c.IPv4Masquerade && c.IPv6Masquerade {
				return errors.New("a dual-stack health check requires a hostname with IPv4 and IPv6 records")
			}
		}
	}
	return nil
}

func RenderRuleset(config Config) (string, error) {
	if err := config.Validate(); err != nil {
		return "", err
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "add table inet %s\n", config.TableName)
	fmt.Fprintf(&builder, "delete table inet %s\n", config.TableName)
	fmt.Fprintf(&builder, "add table inet %s\n", config.TableName)
	fmt.Fprintf(&builder, "add chain inet %s %s { type nat hook postrouting priority %d; policy accept; }\n",
		config.TableName,
		config.ChainName,
		nftPriority,
	)
	if config.IPv4Masquerade {
		fmt.Fprintf(&builder, "add rule inet %s %s meta nfproto ipv4 oifname %q masquerade comment %q\n",
			config.TableName,
			config.ChainName,
			config.EgressInterface,
			"anixops:nat-egress:ipv4",
		)
	}
	if config.IPv6Masquerade {
		fmt.Fprintf(&builder, "add rule inet %s %s meta nfproto ipv6 oifname %q masquerade comment %q\n",
			config.TableName,
			config.ChainName,
			config.EgressInterface,
			"anixops:nat-egress:ipv6",
		)
	}
	return builder.String(), nil
}

func RenderRollback(config Config, snapshot TableSnapshot) (string, error) {
	if err := config.Validate(); err != nil {
		return "", err
	}
	if !snapshot.Exists {
		return fmt.Sprintf("add table inet %s\ndelete table inet %s\n", config.TableName, config.TableName), nil
	}
	ruleset := strings.TrimSpace(snapshot.Ruleset)
	if ruleset == "" {
		return "", errors.New("snapshot ruleset is empty")
	}
	return fmt.Sprintf("add table inet %s\ndelete table inet %s\n%s\n", config.TableName, config.TableName, ruleset), nil
}

type policyOwnership struct {
	inspection PolicyInspection
	ruleOwned  bool
	routeOwned bool
}

type appliedState struct {
	network     NetworkManager
	config      Config
	snapshot    TableSnapshot
	journalPath string
	nftApplied  bool
	policies    map[IPFamily]*policyOwnership
}

func applyNetwork(ctx context.Context, network NetworkManager, config Config, ruleset, journalPath string) (*appliedState, error) {
	if network == nil {
		return nil, errors.New("network manager is required")
	}
	if strings.TrimSpace(journalPath) == "" || !filepath.IsAbs(journalPath) {
		return nil, errors.New("absolute nat-egress ownership journal path is required")
	}
	if err := cleanupOwnershipJournal(ctx, network, journalPath); err != nil {
		return nil, fmt.Errorf("recover interrupted nat-egress state: %w", err)
	}
	if err := network.ValidateForwarding(ctx, config); err != nil {
		return nil, err
	}
	snapshot, err := network.SnapshotTable(ctx, config.TableName)
	if err != nil {
		return nil, err
	}
	state := &appliedState{
		network:     network,
		config:      config,
		snapshot:    snapshot,
		journalPath: journalPath,
		policies:    make(map[IPFamily]*policyOwnership),
	}
	for _, family := range enabledFamilies(config) {
		inspection, inspectErr := network.InspectPolicy(ctx, family, config)
		if inspectErr != nil {
			return nil, inspectErr
		}
		state.policies[family] = &policyOwnership{
			inspection: inspection,
			ruleOwned:  !inspection.RuleExists,
			routeOwned: !inspection.RouteExists,
		}
	}
	journal := newOwnershipJournal(config, state.snapshot, state.policies)
	if err := writeOwnershipJournal(journalPath, journal); err != nil {
		return nil, err
	}
	state.nftApplied = true
	if err := network.ApplyRuleset(ctx, ruleset); err != nil {
		return nil, errors.Join(err, state.rollbackWithTimeout())
	}

	for _, family := range enabledFamilies(config) {
		ownership := state.policies[family]
		if !ownership.inspection.RouteExists {
			if err := network.AddPolicyRoute(ctx, config.PolicyTable, ownership.inspection.Route); err != nil {
				return nil, errors.Join(err, state.rollbackWithTimeout())
			}
		}
		if !ownership.inspection.RuleExists {
			if err := network.AddPolicyRule(ctx, family, config.DefaultMark, config.PolicyTable, config.RulePriority); err != nil {
				return nil, errors.Join(err, state.rollbackWithTimeout())
			}
		}
	}
	return state, nil
}

func cleanupOwnershipJournal(ctx context.Context, network NetworkManager, journalPath string) error {
	journal, exists, err := loadOwnershipJournal(journalPath)
	if err != nil || !exists {
		return err
	}
	config := journal.Identity.config()
	state := &appliedState{
		network:     network,
		config:      config,
		snapshot:    journal.Snapshot,
		journalPath: journalPath,
		nftApplied:  true,
		policies:    make(map[IPFamily]*policyOwnership, len(journal.Policies)),
	}
	for _, family := range enabledFamilies(config) {
		persisted := journal.Policies[strconv.Itoa(int(family))]
		state.policies[family] = &policyOwnership{
			inspection: PolicyInspection{Route: persisted.Route},
			ruleOwned:  persisted.RuleOwned,
			routeOwned: persisted.RouteOwned,
		}
	}
	return state.rollback(ctx)
}

func (s *appliedState) rollback(ctx context.Context) error {
	if s == nil || s.network == nil {
		return nil
	}
	var rollbackErr error
	families := enabledFamilies(s.config)
	for index := len(families) - 1; index >= 0; index-- {
		family := families[index]
		ownership := s.policies[family]
		if ownership == nil {
			continue
		}
		if ownership.ruleOwned {
			rollbackErr = errors.Join(rollbackErr, s.network.DeletePolicyRule(
				ctx,
				family,
				s.config.DefaultMark,
				s.config.PolicyTable,
				s.config.RulePriority,
			))
		}
		if ownership.routeOwned {
			rollbackErr = errors.Join(rollbackErr, s.network.DeletePolicyRoute(ctx, s.config.PolicyTable, ownership.inspection.Route))
		}
	}
	if s.nftApplied {
		ruleset, err := RenderRollback(s.config, s.snapshot)
		if err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		} else {
			rollbackErr = errors.Join(rollbackErr, s.network.ApplyRuleset(ctx, ruleset))
		}
	}
	if rollbackErr == nil {
		rollbackErr = removeOwnershipJournal(s.journalPath)
	}
	return rollbackErr
}

func (s *appliedState) rollbackWithTimeout() error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	return s.rollback(ctx)
}

func Run(ctx context.Context, options Options) (runErr error) {
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

	network := options.Network
	if network == nil {
		network = CommandNetworkManager{}
	}
	var state *appliedState
	if config.Apply {
		if runtime.GOOS != "linux" {
			return errors.New("nat-egress apply is supported only on Linux")
		}
		applyCtx, cancel := context.WithTimeout(ctx, commandTimeout)
		state, err = applyNetwork(applyCtx, network, config, ruleset, runtimeStatePath(options))
		cancel()
		if err != nil {
			return err
		}
		defer func() {
			if config.RollbackOnExit || runErr != nil {
				runErr = errors.Join(runErr, state.rollbackWithTimeout())
			}
		}()
	} else {
		cleanupCtx, cancel := context.WithTimeout(ctx, commandTimeout)
		err = cleanupOwnershipJournal(cleanupCtx, network, runtimeStatePath(options))
		cancel()
		if err != nil {
			return fmt.Errorf("clean interrupted nat-egress state before observation mode: %w", err)
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
	if config.Apply {
		healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
		healthServer.SetServingStatus(ID, healthpb.HealthCheckResponse_NOT_SERVING)
	} else {
		healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		healthServer.SetServingStatus(ID, healthpb.HealthCheckResponse_UNKNOWN)
	}
	healthpb.RegisterHealthServer(server, healthServer)

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()

	prober := options.Prober
	if prober == nil {
		prober = newSystemProber()
	}
	var ticker *time.Ticker
	var tickerC <-chan time.Time
	if config.Apply {
		probeHealth(ctx, healthServer, prober, network, config)
		ticker = time.NewTicker(config.HealthCheckInterval())
		tickerC = ticker.C
		defer ticker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			healthServer.Shutdown()
			server.Stop()
			err := <-serveResult
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				return fmt.Errorf("serve plugin health API: %w", err)
			}
			return nil
		case err := <-serveResult:
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				return fmt.Errorf("serve plugin health API: %w", err)
			}
			return nil
		case <-tickerC:
			probeHealth(ctx, healthServer, prober, network, config)
		}
	}
}

func runtimeStatePath(options Options) string {
	if value := strings.TrimSpace(options.StatePath); value != "" {
		return value
	}
	return ownershipJournalPath(options.SocketPath)
}

func probeHealth(parent context.Context, server *health.Server, prober Prober, network NetworkManager, config Config) {
	probeCtx, cancel := context.WithTimeout(parent, config.HealthCheckTimeout())
	err := network.VerifyApplied(probeCtx, config)
	if err == nil && config.HealthCheckEnabled {
		err = prober.Probe(probeCtx, config)
	}
	cancel()
	if err != nil {
		server.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
		server.SetServingStatus(ID, healthpb.HealthCheckResponse_NOT_SERVING)
		return
	}
	server.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	server.SetServingStatus(ID, healthpb.HealthCheckResponse_SERVING)
}

func (m CommandNetworkManager) SnapshotTable(ctx context.Context, table string) (TableSnapshot, error) {
	output, err := m.run(ctx, m.nftBinary(), "list", "table", "inet", table)
	if err != nil {
		text := strings.TrimSpace(string(output))
		if strings.Contains(text, "No such file or directory") || strings.Contains(text, "does not exist") || strings.Contains(text, "No such file") {
			return TableSnapshot{}, nil
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

func (m CommandNetworkManager) ValidateForwarding(ctx context.Context, config Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	checks := make([]struct {
		family string
		path   string
	}, 0, 2)
	if config.IPv4Masquerade {
		checks = append(checks, struct {
			family string
			path   string
		}{family: "IPv4", path: "net/ipv4/ip_forward"})
	}
	if config.IPv6Masquerade {
		checks = append(checks, struct {
			family string
			path   string
		}{family: "IPv6", path: "net/ipv6/conf/all/forwarding"})
	}
	for _, check := range checks {
		contents, err := os.ReadFile(filepath.Join(m.procRoot(), check.path))
		if err != nil {
			return fmt.Errorf("read %s forwarding state: %w", check.family, err)
		}
		if strings.TrimSpace(string(contents)) != "1" {
			return fmt.Errorf("%s forwarding is disabled; enable %s before activating nat-egress", check.family, strings.ReplaceAll(check.path, "/", "."))
		}
	}
	return nil
}

func (m CommandNetworkManager) VerifyApplied(ctx context.Context, config Config) error {
	if err := m.ValidateForwarding(ctx, config); err != nil {
		return err
	}
	output, err := m.run(ctx, m.nftBinary(), "-j", "list", "table", "inet", config.TableName)
	if err != nil {
		return fmt.Errorf("inspect nat-egress nftables state: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := verifyNftDocument(output, config); err != nil {
		return err
	}
	for _, family := range enabledFamilies(config) {
		inspection, err := m.InspectPolicy(ctx, family, config)
		if err != nil {
			return err
		}
		if !inspection.RouteExists || !inspection.RuleExists {
			return fmt.Errorf("nat-egress %s policy route or rule is missing", familyName(family))
		}
	}
	return nil
}

func (m CommandNetworkManager) ApplyRuleset(ctx context.Context, ruleset string) error {
	command := exec.CommandContext(ctx, m.nftBinary(), "-f", "-")
	command.Stdin = strings.NewReader(ruleset)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply nftables transaction: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m CommandNetworkManager) InspectPolicy(ctx context.Context, family IPFamily, config Config) (PolicyInspection, error) {
	mainRoutes, err := m.routes(ctx, family, "main", config.EgressInterface, false)
	if err != nil {
		return PolicyInspection{}, err
	}
	if len(mainRoutes) != 1 {
		return PolicyInspection{}, fmt.Errorf("expected exactly one %s default route on %s, found %d", familyName(family), config.EgressInterface, len(mainRoutes))
	}
	desiredRoute := mainRoutes[0]

	policyRoutes, err := m.routes(ctx, family, strconv.Itoa(config.PolicyTable), "", true)
	if err != nil {
		return PolicyInspection{}, err
	}
	inspection := PolicyInspection{Route: desiredRoute}
	switch len(policyRoutes) {
	case 0:
	case 1:
		if !routesEquivalent(policyRoutes[0], desiredRoute) {
			return PolicyInspection{}, fmt.Errorf("%s policy table %d already has a conflicting default route", familyName(family), config.PolicyTable)
		}
		inspection.RouteExists = true
	default:
		return PolicyInspection{}, fmt.Errorf("%s policy table %d has multiple default routes", familyName(family), config.PolicyTable)
	}

	rules, err := m.rules(ctx, family)
	if err != nil {
		return PolicyInspection{}, err
	}
	inspection.RuleExists, err = inspectPolicyRules(rules, family, config)
	if err != nil {
		return PolicyInspection{}, err
	}
	return inspection, nil
}

func inspectPolicyRules(rules []policyRule, family IPFamily, config Config) (bool, error) {
	found := false
	for _, rule := range rules {
		if rule.Priority < config.RulePriority {
			if rule.HasMark {
				if rule.matchesMark(config.DefaultMark) {
					return false, fmt.Errorf("%s policy rule priority %d intercepts mark %d before nat-egress priority %d", familyName(family), rule.Priority, config.DefaultMark, config.RulePriority)
				}
				continue
			}
			if !rule.isCanonicalLocalLookup() {
				return false, fmt.Errorf("%s policy rule priority %d may intercept marked traffic before nat-egress priority %d", familyName(family), rule.Priority, config.RulePriority)
			}
			continue
		}
		if rule.Priority != config.RulePriority {
			continue
		}
		if rule.HasMark && rule.Mark == config.DefaultMark && rule.FullMask && rule.Global && rule.Table == config.PolicyTable && strings.TrimSpace(rule.Action) == "" {
			if found {
				return false, fmt.Errorf("%s policy rule priority %d is duplicated", familyName(family), config.RulePriority)
			}
			found = true
			continue
		}
		return false, fmt.Errorf("%s policy rule priority %d is already occupied", familyName(family), config.RulePriority)
	}
	return found, nil
}

func (m CommandNetworkManager) AddPolicyRoute(ctx context.Context, table int, route PolicyRoute) error {
	return m.runIP(ctx, routeCommandArgs("add", table, route)...)
}

func (m CommandNetworkManager) DeletePolicyRoute(ctx context.Context, table int, route PolicyRoute) error {
	return m.runIPAllowMissing(ctx, routeCommandArgs("del", table, route)...)
}

func (m CommandNetworkManager) AddPolicyRule(ctx context.Context, family IPFamily, mark, table, priority int) error {
	return m.runIP(ctx, ruleCommandArgs("add", family, mark, table, priority)...)
}

func (m CommandNetworkManager) DeletePolicyRule(ctx context.Context, family IPFamily, mark, table, priority int) error {
	return m.runIPAllowMissing(ctx, ruleCommandArgs("del", family, mark, table, priority)...)
}

type routeJSON struct {
	Destination     string                       `json:"dst"`
	Source          string                       `json:"from"`
	Gateway         string                       `json:"gateway"`
	Device          string                       `json:"dev"`
	PreferredSource string                       `json:"prefsrc"`
	Metric          int                          `json:"metric"`
	Flags           []string                     `json:"flags"`
	Metrics         []map[string]json.RawMessage `json:"metrics"`
	Preference      string                       `json:"pref"`
}

func (m CommandNetworkManager) routes(ctx context.Context, family IPFamily, table, device string, wholeTable bool) ([]PolicyRoute, error) {
	args := []string{family.flag(), "-json", "route", "show", "table", table}
	if !wholeTable {
		args = append(args, "default")
	}
	output, err := m.run(ctx, m.ipBinary(), args...)
	if err != nil {
		text := strings.TrimSpace(string(output))
		if table != "main" && strings.Contains(text, "FIB table does not exist") {
			return nil, nil
		}
		return nil, fmt.Errorf("inspect %s routes: %w: %s", familyName(family), err, text)
	}
	return decodeRoutes(output, family, device, wholeTable)
}

func decodeRoutes(output []byte, family IPFamily, device string, rejectNonDefault bool) ([]PolicyRoute, error) {
	var decoded []routeJSON
	if err := json.Unmarshal(output, &decoded); err != nil {
		return nil, fmt.Errorf("decode %s routes: %w", familyName(family), err)
	}
	routes := make([]PolicyRoute, 0, len(decoded))
	for _, value := range decoded {
		source := strings.TrimSpace(value.Source)
		if source != "" && source != "all" && source != "0.0.0.0/0" && source != "::/0" {
			return nil, fmt.Errorf("%s default route has unsupported source selector %q", familyName(family), source)
		}
		if value.Destination != "" && value.Destination != "default" {
			if rejectNonDefault {
				return nil, fmt.Errorf("%s policy table contains unmanaged route %q", familyName(family), value.Destination)
			}
			continue
		}
		if device != "" && strings.TrimSpace(value.Device) != device {
			continue
		}
		route := PolicyRoute{
			Family:          family,
			Gateway:         strings.TrimSpace(value.Gateway),
			Device:          strings.TrimSpace(value.Device),
			PreferredSource: strings.TrimSpace(value.PreferredSource),
			Metric:          value.Metric,
			Onlink:          containsString(value.Flags, "onlink"),
		}
		if len(value.Metrics) > 1 {
			return nil, fmt.Errorf("%s default route has multiple metric sets", familyName(family))
		}
		if len(value.Metrics) == 1 {
			for name, raw := range value.Metrics[0] {
				metric, parseErr := parseNumericJSON(raw)
				if parseErr != nil {
					return nil, fmt.Errorf("decode %s default route metric %s: %w", familyName(family), name, parseErr)
				}
				switch name {
				case "mtu":
					route.MTU = metric
				case "advmss":
					route.AdvMSS = metric
				default:
					return nil, fmt.Errorf("%s default route metric %s is not supported", familyName(family), name)
				}
			}
		}
		if route.Device == "" {
			return nil, fmt.Errorf("%s default route is missing a device", familyName(family))
		}
		if route.Gateway != "" {
			address, parseErr := netip.ParseAddr(route.Gateway)
			if parseErr != nil || (family == IPv4 && !address.Is4()) || (family == IPv6 && !address.Is6()) {
				return nil, fmt.Errorf("%s default route has an invalid gateway", familyName(family))
			}
		}
		routes = append(routes, route)
	}
	return routes, nil
}

type ruleJSON struct {
	Priority    int             `json:"priority"`
	Source      string          `json:"src"`
	Destination string          `json:"dst"`
	FWMark      string          `json:"fwmark"`
	FWMask      string          `json:"fwmask"`
	Table       json.RawMessage `json:"table"`
	Action      string          `json:"action"`
	Flags       []string        `json:"flags"`
}

type policyRule struct {
	Priority int
	Mark     int
	Mask     uint32
	HasMark  bool
	FullMask bool
	Global   bool
	Table    int
	Action   string
}

func (r policyRule) matchesMark(mark int) bool {
	if !r.HasMark {
		return false
	}
	return uint32(mark)&r.Mask == uint32(r.Mark)&r.Mask
}

func (r policyRule) isCanonicalLocalLookup() bool {
	return r.Priority == 0 && !r.HasMark && r.Global && r.Table == localRouteTable && strings.TrimSpace(r.Action) == ""
}

func (m CommandNetworkManager) rules(ctx context.Context, family IPFamily) ([]policyRule, error) {
	output, err := m.run(ctx, m.ipBinary(), family.flag(), "-json", "rule", "show")
	if err != nil {
		return nil, fmt.Errorf("inspect %s policy rules: %w: %s", familyName(family), err, strings.TrimSpace(string(output)))
	}
	return decodePolicyRules(output, family)
}

func decodePolicyRules(output []byte, family IPFamily) ([]policyRule, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(output, &entries); err != nil {
		return nil, fmt.Errorf("decode %s policy rules: %w", familyName(family), err)
	}
	rules := make([]policyRule, 0, len(entries))
	for _, entry := range entries {
		var value ruleJSON
		if err := json.Unmarshal(entry, &value); err != nil {
			return nil, fmt.Errorf("decode %s policy rule: %w", familyName(family), err)
		}
		rule := policyRule{
			Priority: value.Priority,
			Mark:     -1,
			Mask:     ^uint32(0),
			Global:   (value.Source == "" || value.Source == "all") && (value.Destination == "" || value.Destination == "all"),
			Table:    -1,
			Action:   strings.TrimSpace(value.Action),
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(entry, &fields); err != nil {
			return nil, fmt.Errorf("decode %s policy rule fields: %w", familyName(family), err)
		}
		for name := range fields {
			switch name {
			case "priority", "src", "dst", "fwmark", "fwmask", "table", "protocol", "action", "flags":
			default:
				rule.Global = false
			}
		}
		if len(value.Flags) != 0 {
			rule.Global = false
		}
		if markText := strings.TrimSpace(value.FWMark); markText != "" {
			mark, parseErr := strconv.ParseInt(markText, 0, 32)
			if parseErr != nil {
				return nil, fmt.Errorf("decode %s policy rule mark %q: %w", familyName(family), value.FWMark, parseErr)
			}
			rule.Mark = int(mark)
			rule.HasMark = true
		}
		if table, parseErr := parseRoutingTable(value.Table); parseErr == nil {
			rule.Table = table
		}
		maskText := strings.TrimSpace(value.FWMask)
		if maskText == "" {
			rule.FullMask = true
		} else {
			mask, parseErr := strconv.ParseUint(maskText, 0, 32)
			if parseErr != nil {
				return nil, fmt.Errorf("decode %s policy rule mask %q: %w", familyName(family), value.FWMask, parseErr)
			}
			rule.Mask = uint32(mask)
			rule.FullMask = rule.Mask == ^uint32(0)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseRoutingTable(raw json.RawMessage) (int, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return 0, errors.New("routing table is missing")
	}
	var name string
	if err := json.Unmarshal(raw, &name); err == nil {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "local":
			return localRouteTable, nil
		case "main":
			return mainRouteTable, nil
		case "default":
			return defaultRouteTable, nil
		}
	}
	return parseNumericJSON(raw)
}

func (m CommandNetworkManager) runIP(ctx context.Context, args ...string) error {
	output, err := m.run(ctx, m.ipBinary(), args...)
	if err != nil {
		return fmt.Errorf("run ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m CommandNetworkManager) runIPAllowMissing(ctx context.Context, args ...string) error {
	output, err := m.run(ctx, m.ipBinary(), args...)
	if err == nil {
		return nil
	}
	text := strings.TrimSpace(string(output))
	if strings.Contains(text, "No such process") || strings.Contains(text, "No such file or directory") || strings.Contains(text, "Cannot find device") || strings.Contains(text, "FIB table does not exist") {
		return nil
	}
	return fmt.Errorf("run ip %s: %w: %s", strings.Join(args, " "), err, text)
}

func (m CommandNetworkManager) run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, binary, args...).CombinedOutput()
}

func (m CommandNetworkManager) nftBinary() string {
	if value := strings.TrimSpace(m.NftBinary); value != "" {
		return value
	}
	return "nft"
}

func (m CommandNetworkManager) ipBinary() string {
	if value := strings.TrimSpace(m.IPBinary); value != "" {
		return value
	}
	return "ip"
}

func (m CommandNetworkManager) procRoot() string {
	if value := strings.TrimSpace(m.ProcRoot); value != "" {
		return value
	}
	return "/proc/sys"
}

func routeCommandArgs(action string, table int, route PolicyRoute) []string {
	args := []string{route.Family.flag(), "route", action, "table", strconv.Itoa(table), "default"}
	if route.Gateway != "" {
		args = append(args, "via", route.Gateway)
	}
	args = append(args, "dev", route.Device)
	if route.PreferredSource != "" {
		args = append(args, "src", route.PreferredSource)
	}
	if route.Metric > 0 {
		args = append(args, "metric", strconv.Itoa(route.Metric))
	}
	if route.MTU > 0 {
		args = append(args, "mtu", strconv.Itoa(route.MTU))
	}
	if route.AdvMSS > 0 {
		args = append(args, "advmss", strconv.Itoa(route.AdvMSS))
	}
	if route.Onlink {
		args = append(args, "onlink")
	}
	return args
}

func ruleCommandArgs(action string, family IPFamily, mark, table, priority int) []string {
	return []string{
		family.flag(),
		"rule",
		action,
		"priority",
		strconv.Itoa(priority),
		"fwmark",
		strconv.Itoa(mark),
		"lookup",
		strconv.Itoa(table),
	}
}

func enabledFamilies(config Config) []IPFamily {
	families := make([]IPFamily, 0, 2)
	if config.IPv4Masquerade {
		families = append(families, IPv4)
	}
	if config.IPv6Masquerade {
		families = append(families, IPv6)
	}
	return families
}

func routesEquivalent(left, right PolicyRoute) bool {
	return left.Family == right.Family &&
		left.Gateway == right.Gateway &&
		left.Device == right.Device &&
		left.PreferredSource == right.PreferredSource &&
		left.Metric == right.Metric &&
		left.MTU == right.MTU &&
		left.AdvMSS == right.AdvMSS &&
		left.Onlink == right.Onlink
}

func parseNumericJSON(raw json.RawMessage) (int, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return 0, errors.New("numeric value is missing")
	}
	if strings.HasPrefix(trimmed, "\"") {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return 0, err
		}
		return strconv.Atoi(text)
	}
	return strconv.Atoi(trimmed)
}

func familyName(family IPFamily) string {
	if family == IPv6 {
		return "IPv6"
	}
	return "IPv4"
}

func validateHealthTarget(target string) error {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return errors.New("health_check_target must be host:port")
	}
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n\t /?#") {
		return errors.New("health_check_target host is invalid")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("health_check_target port must be between 1 and 65535")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("health_check_target host is invalid")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
				return errors.New("health_check_target host is invalid")
			}
		}
	}
	return nil
}

func safeNftIdentifier(value string) bool {
	if value == "" || len(value) > 48 {
		return false
	}
	for index := range value {
		character := value[index]
		if index == 0 && (character < 'a' || character > 'z') {
			return false
		}
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func safeInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for index := range value {
		character := value[index]
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' && character != '.' && character != ':' && character != '@' {
			return false
		}
	}
	return true
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
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
