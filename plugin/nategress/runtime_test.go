package nategress

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type fakeNetworkManager struct {
	mu          sync.Mutex
	snapshot    TableSnapshot
	inspections map[IPFamily]PolicyInspection
	failCall    string
	failCalls   map[string]bool
	verifyErr   error
	calls       []string
}

func (f *fakeNetworkManager) record(call string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	if call == f.failCall || f.failCalls[call] {
		return errors.New("injected network failure")
	}
	return nil
}

func (f *fakeNetworkManager) ValidateForwarding(context.Context, Config) error {
	return f.record("validate-forwarding")
}

func (f *fakeNetworkManager) VerifyApplied(context.Context, Config) error {
	if err := f.record("verify-applied"); err != nil {
		return err
	}
	return f.verifyErr
}

func (f *fakeNetworkManager) SnapshotTable(context.Context, string) (TableSnapshot, error) {
	if err := f.record("snapshot"); err != nil {
		return TableSnapshot{}, err
	}
	return f.snapshot, nil
}

func (f *fakeNetworkManager) ApplyRuleset(_ context.Context, ruleset string) error {
	call := "nft:rollback"
	if strings.Contains(ruleset, "add chain inet") {
		call = "nft:apply"
	}
	return f.record(call)
}

func (f *fakeNetworkManager) InspectPolicy(_ context.Context, family IPFamily, _ Config) (PolicyInspection, error) {
	if err := f.record("inspect:" + familyName(family)); err != nil {
		return PolicyInspection{}, err
	}
	return f.inspections[family], nil
}

func (f *fakeNetworkManager) AddPolicyRoute(_ context.Context, _ int, route PolicyRoute) error {
	if err := f.record("route:add:" + familyName(route.Family)); err != nil {
		return err
	}
	f.mu.Lock()
	inspection := f.inspections[route.Family]
	inspection.RouteExists = true
	f.inspections[route.Family] = inspection
	f.mu.Unlock()
	return nil
}

func (f *fakeNetworkManager) DeletePolicyRoute(_ context.Context, _ int, route PolicyRoute) error {
	if err := f.record("route:delete:" + familyName(route.Family)); err != nil {
		return err
	}
	f.mu.Lock()
	inspection := f.inspections[route.Family]
	inspection.RouteExists = false
	f.inspections[route.Family] = inspection
	f.mu.Unlock()
	return nil
}

func (f *fakeNetworkManager) AddPolicyRule(_ context.Context, family IPFamily, _, _, _ int) error {
	if err := f.record("rule:add:" + familyName(family)); err != nil {
		return err
	}
	f.mu.Lock()
	inspection := f.inspections[family]
	inspection.RuleExists = true
	f.inspections[family] = inspection
	f.mu.Unlock()
	return nil
}

func (f *fakeNetworkManager) DeletePolicyRule(_ context.Context, family IPFamily, _, _, _ int) error {
	if err := f.record("rule:delete:" + familyName(family)); err != nil {
		return err
	}
	f.mu.Lock()
	inspection := f.inspections[family]
	inspection.RuleExists = false
	f.inspections[family] = inspection
	f.mu.Unlock()
	return nil
}

func (f *fakeNetworkManager) recordedCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeNetworkManager) resetCalls() {
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
}

type fakeProber struct {
	err error
}

func (p fakeProber) Probe(context.Context, Config) error {
	return p.err
}

func TestParseConfigDefaults(t *testing.T) {
	config, err := ParseConfig([]byte(`{}`))
	require.NoError(t, err)
	assert.False(t, config.Apply)
	assert.True(t, config.RollbackOnExit)
	assert.Equal(t, DefaultTableName, config.TableName)
	assert.Equal(t, DefaultChainName, config.ChainName)
	assert.Equal(t, DefaultEgressInterface, config.EgressInterface)
	assert.Equal(t, DefaultMark, config.DefaultMark)
	assert.Equal(t, DefaultPolicyTable, config.PolicyTable)
	assert.Equal(t, DefaultRulePriority, config.RulePriority)
	assert.True(t, config.IPv4Masquerade)
	assert.False(t, config.IPv6Masquerade)
	assert.True(t, config.HealthCheckEnabled)
	assert.Equal(t, DefaultHealthCheckTarget, config.HealthCheckTarget)
}

func TestParseConfigRejectsUnsafeOrIncompleteValues(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		message string
	}{
		{name: "unknown field", config: `{"unknown":true}`, message: "unknown field"},
		{name: "rollback disabled", config: `{"rollback_on_exit":false}`, message: "rollback_on_exit must remain enabled"},
		{name: "unsafe table", config: `{"table_name":"bad-name"}`, message: "table_name"},
		{name: "unsafe interface", config: `{"egress_interface":"eth0;reboot"}`, message: "egress_interface"},
		{name: "reserved policy table", config: `{"policy_table":253}`, message: "policy_table"},
		{name: "no address family", config: `{"ipv4_masquerade":false,"ipv6_masquerade":false}`, message: "at least one"},
		{name: "bad health target", config: `{"health_check_target":"missing-port"}`, message: "host:port"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(test.config))
			require.ErrorContains(t, err, test.message)
		})
	}
}

func TestRenderRulesetIncludesSelectedAddressFamilies(t *testing.T) {
	config := validConfig()
	config.IPv6Masquerade = true
	ruleset, err := RenderRuleset(config)
	require.NoError(t, err)
	assert.Contains(t, ruleset, "add table inet anixops_nat_egress")
	assert.Contains(t, ruleset, "type nat hook postrouting priority 100")
	assert.Contains(t, ruleset, `meta nfproto ipv4 oifname "eth0" masquerade`)
	assert.Contains(t, ruleset, `meta nfproto ipv6 oifname "eth0" masquerade`)
	assert.Contains(t, ruleset, `comment "anixops:nat-egress:ipv4"`)
}

func TestRenderRollbackRestoresSnapshotOrDeletesCreatedTable(t *testing.T) {
	config := validConfig()
	created, err := RenderRollback(config, TableSnapshot{})
	require.NoError(t, err)
	assert.Equal(t, "add table inet anixops_nat_egress\ndelete table inet anixops_nat_egress\n", created)

	restored, err := RenderRollback(config, TableSnapshot{Exists: true, Ruleset: "table inet anixops_nat_egress {\n}\n"})
	require.NoError(t, err)
	assert.Equal(t, "add table inet anixops_nat_egress\ndelete table inet anixops_nat_egress\ntable inet anixops_nat_egress {\n}\n", restored)
}

func TestApplyNetworkRollsBackPartialPolicyFailure(t *testing.T) {
	config := validConfig()
	config.IPv6Masquerade = true
	network := newFakeNetworkManager()
	network.failCall = "rule:add:IPv6"
	ruleset, err := RenderRuleset(config)
	require.NoError(t, err)

	journalPath := filepath.Join(secureTempDir(t), "ownership.json")
	state, err := applyNetwork(context.Background(), network, config, ruleset, journalPath)
	require.ErrorContains(t, err, "injected network failure")
	assert.Nil(t, state)
	_, statErr := os.Stat(journalPath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
	assert.Equal(t, []string{
		"validate-forwarding",
		"snapshot",
		"inspect:IPv4",
		"inspect:IPv6",
		"nft:apply",
		"route:add:IPv4",
		"rule:add:IPv4",
		"route:add:IPv6",
		"rule:add:IPv6",
		"rule:delete:IPv6",
		"route:delete:IPv6",
		"rule:delete:IPv4",
		"route:delete:IPv4",
		"nft:rollback",
	}, network.recordedCalls())
}

func TestApplyNetworkRollsBackAmbiguousNftFailure(t *testing.T) {
	config := validConfig()
	network := newFakeNetworkManager()
	network.failCall = "nft:apply"
	ruleset, err := RenderRuleset(config)
	require.NoError(t, err)
	journalPath := filepath.Join(secureTempDir(t), "ownership.json")

	state, err := applyNetwork(context.Background(), network, config, ruleset, journalPath)
	require.ErrorContains(t, err, "injected network failure")
	assert.Nil(t, state)
	assert.Equal(t, []string{
		"validate-forwarding",
		"snapshot",
		"inspect:IPv4",
		"nft:apply",
		"rule:delete:IPv4",
		"route:delete:IPv4",
		"nft:rollback",
	}, network.recordedCalls())
	_, statErr := os.Stat(journalPath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestApplyNetworkKeepsJournalWhenAmbiguousNftRollbackFails(t *testing.T) {
	config := validConfig()
	network := newFakeNetworkManager()
	network.failCalls = map[string]bool{"nft:apply": true, "nft:rollback": true}
	ruleset, err := RenderRuleset(config)
	require.NoError(t, err)
	journalPath := filepath.Join(secureTempDir(t), "ownership.json")

	state, err := applyNetwork(context.Background(), network, config, ruleset, journalPath)
	require.ErrorContains(t, err, "injected network failure")
	assert.Nil(t, state)
	_, statErr := os.Stat(journalPath)
	require.NoError(t, statErr, "failed rollback must preserve the ownership journal for restart recovery")
}

func TestApplyNetworkRejectsOversizedJournalBeforeMutation(t *testing.T) {
	config := validConfig()
	network := newFakeNetworkManager()
	network.snapshot = TableSnapshot{
		Exists:  true,
		Ruleset: "table inet anixops_nat_egress {\n" + strings.Repeat("#", maxJournalBytes) + "\n}\n",
	}
	ruleset, err := RenderRuleset(config)
	require.NoError(t, err)
	journalPath := filepath.Join(secureTempDir(t), "ownership.json")

	state, err := applyNetwork(context.Background(), network, config, ruleset, journalPath)
	require.ErrorContains(t, err, "ownership journal exceeds")
	assert.Nil(t, state)
	assert.Equal(t, []string{"validate-forwarding", "snapshot", "inspect:IPv4"}, network.recordedCalls())
	_, statErr := os.Stat(journalPath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestOwnershipJournalRecoversAfterCrashAndCleansOriginalBaseline(t *testing.T) {
	config := validConfig()
	network := newFakeNetworkManager()
	network.snapshot = TableSnapshot{
		Exists:  true,
		Ruleset: "table inet anixops_nat_egress {\n\tchain baseline { }\n}\n",
	}
	ruleset, err := RenderRuleset(config)
	require.NoError(t, err)
	journalPath := filepath.Join(secureTempDir(t), "ownership.json")

	first, err := applyNetwork(context.Background(), network, config, ruleset, journalPath)
	require.NoError(t, err)
	require.NotNil(t, first)
	_, err = os.Stat(journalPath)
	require.NoError(t, err)

	// Simulate SIGKILL plus a new main gateway: the restart first restores the
	// original baseline from the stable journal, then applies a fresh plan.
	network.inspections[IPv4] = PolicyInspection{
		RuleExists:  true,
		RouteExists: true,
		Route:       PolicyRoute{Family: IPv4, Gateway: "198.51.100.1", Device: "eth0", MTU: 1400},
	}
	network.resetCalls()
	second, err := applyNetwork(context.Background(), network, config, ruleset, journalPath)
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.Equal(t, []string{
		"rule:delete:IPv4",
		"route:delete:IPv4",
		"nft:rollback",
		"validate-forwarding",
		"snapshot",
		"inspect:IPv4",
		"nft:apply",
		"route:add:IPv4",
		"rule:add:IPv4",
	}, network.recordedCalls())

	require.NoError(t, second.rollback(context.Background()))
	assert.Equal(t, []string{
		"rule:delete:IPv4",
		"route:delete:IPv4",
		"nft:rollback",
		"validate-forwarding",
		"snapshot",
		"inspect:IPv4",
		"nft:apply",
		"route:add:IPv4",
		"rule:add:IPv4",
		"rule:delete:IPv4",
		"route:delete:IPv4",
		"nft:rollback",
	}, network.recordedCalls())
	_, err = os.Stat(journalPath)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestOwnershipJournalCleansOldIdentityBeforeApplyingChangedConfig(t *testing.T) {
	config := validConfig()
	network := newFakeNetworkManager()
	ruleset, err := RenderRuleset(config)
	require.NoError(t, err)
	journalPath := filepath.Join(secureTempDir(t), "ownership.json")
	_, err = applyNetwork(context.Background(), network, config, ruleset, journalPath)
	require.NoError(t, err)

	changed := config
	changed.PolicyTable++
	changedRuleset, err := RenderRuleset(changed)
	require.NoError(t, err)
	network.resetCalls()
	state, err := applyNetwork(context.Background(), network, changed, changedRuleset, journalPath)
	require.NoError(t, err)
	require.NotNil(t, state)
	require.NoError(t, state.rollback(context.Background()))
}

func TestCleanupJournalToleratesMissingPolicyTableBeforeRouteCreation(t *testing.T) {
	directory := secureTempDir(t)
	ipBinary := filepath.Join(directory, "ip")
	require.NoError(t, os.WriteFile(ipBinary, []byte("#!/bin/sh\nprintf '%s\\n' 'Error: FIB table does not exist.' >&2\nexit 2\n"), 0o750))
	config := validConfig()
	route := PolicyRoute{Family: IPv4, Gateway: "192.0.2.1", Device: config.EgressInterface}
	journalPath := filepath.Join(directory, "ownership.json")
	journal := newOwnershipJournal(config, TableSnapshot{}, map[IPFamily]*policyOwnership{
		IPv4: {
			inspection: PolicyInspection{Route: route},
			ruleOwned:  true,
			routeOwned: true,
		},
	})
	require.NoError(t, writeOwnershipJournal(journalPath, journal))
	manager := CommandNetworkManager{IPBinary: ipBinary, NftBinary: "/bin/true"}

	require.NoError(t, cleanupOwnershipJournal(context.Background(), manager, journalPath))
	_, err := os.Stat(journalPath)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestDeletePolicyRouteTreatsMissingFIBTableAsAlreadyAbsent(t *testing.T) {
	directory := secureTempDir(t)
	ipBinary := filepath.Join(directory, "ip")
	require.NoError(t, os.WriteFile(ipBinary, []byte("#!/bin/sh\nprintf '%s\\n' 'Error: FIB table does not exist.' >&2\nexit 2\n"), 0o750))
	manager := CommandNetworkManager{IPBinary: ipBinary}

	require.NoError(t, manager.DeletePolicyRoute(context.Background(), 201, PolicyRoute{
		Family: IPv4, Gateway: "192.0.2.1", Device: "eth0",
	}))
}

func TestCommandNetworkManagerValidatesForwardingPrerequisites(t *testing.T) {
	root := secureTempDir(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "net/ipv4"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "net/ipv6/conf/all"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "net/ipv4/ip_forward"), []byte("1\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "net/ipv6/conf/all/forwarding"), []byte("0\n"), 0o600))
	manager := CommandNetworkManager{ProcRoot: root}
	config := validConfig()
	require.NoError(t, manager.ValidateForwarding(context.Background(), config))
	config.IPv6Masquerade = true
	err := manager.ValidateForwarding(context.Background(), config)
	require.ErrorContains(t, err, "IPv6 forwarding is disabled")
}

func TestRunServesHealthAndRollsBackOwnedState(t *testing.T) {
	directory := secureTempDir(t)
	configPath := filepath.Join(directory, "config.json")
	socketPath := filepath.Join(directory, "plugin.sock")
	writeConfig(t, configPath, `{
		"apply": true,
		"rollback_on_exit": true,
		"health_check_target": "192.0.2.1:443"
	}`)
	network := newFakeNetworkManager()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, Options{
			SocketPath: socketPath,
			ConfigPath: configPath,
			Network:    network,
			Prober:     fakeProber{},
		})
	}()

	connection := dialHealth(t, socketPath)
	defer connection.Close()
	healthClient := healthpb.NewHealthClient(connection)
	checkCtx, checkCancel := context.WithTimeout(context.Background(), time.Second)
	defer checkCancel()
	processHealth, err := healthClient.Check(checkCtx, &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, processHealth.Status)
	require.Eventually(t, func() bool {
		probeCtx, probeCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer probeCancel()
		egressHealth, checkErr := healthClient.Check(probeCtx, &healthpb.HealthCheckRequest{Service: ID})
		return checkErr == nil && egressHealth.Status == healthpb.HealthCheckResponse_SERVING
	}, time.Second, 10*time.Millisecond)

	cancel()
	require.NoError(t, <-result)
	assert.Contains(t, network.recordedCalls(), "rule:delete:IPv4")
	assert.Contains(t, network.recordedCalls(), "route:delete:IPv4")
	assert.Equal(t, "nft:rollback", network.recordedCalls()[len(network.recordedCalls())-1])
}

func TestRunReportsUnhealthyWhenEgressProbeFails(t *testing.T) {
	directory := secureTempDir(t)
	configPath := filepath.Join(directory, "config.json")
	socketPath := filepath.Join(directory, "plugin.sock")
	writeConfig(t, configPath, `{
		"apply":true,
		"rollback_on_exit":true,
		"health_check_target":"192.0.2.1:443"
	}`)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, Options{
			SocketPath: socketPath,
			ConfigPath: configPath,
			Network:    newFakeNetworkManager(),
			Prober:     fakeProber{err: errors.New("egress unavailable")},
		})
	}()

	connection := dialHealth(t, socketPath)
	defer connection.Close()
	healthClient := healthpb.NewHealthClient(connection)
	checkCtx, checkCancel := context.WithTimeout(context.Background(), time.Second)
	defer checkCancel()
	processHealth, err := healthClient.Check(checkCtx, &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, processHealth.Status)
	egressHealth, err := healthClient.Check(checkCtx, &healthpb.HealthCheckRequest{Service: ID})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, egressHealth.Status)

	cancel()
	require.NoError(t, <-result)
}

func TestRunReportsObservationModeWhenApplyIsDisabled(t *testing.T) {
	directory := secureTempDir(t)
	configPath := filepath.Join(directory, "config.json")
	socketPath := filepath.Join(directory, "plugin.sock")
	writeConfig(t, configPath, `{"health_check_enabled":false}`)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, Options{
			SocketPath: socketPath,
			ConfigPath: configPath,
			Network:    newFakeNetworkManager(),
			Prober:     fakeProber{},
		})
	}()
	connection := dialHealth(t, socketPath)
	defer connection.Close()
	checkCtx, checkCancel := context.WithTimeout(context.Background(), time.Second)
	defer checkCancel()
	response, err := healthpb.NewHealthClient(connection).Check(checkCtx, &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, response.Status)
	readiness, err := healthpb.NewHealthClient(connection).Check(checkCtx, &healthpb.HealthCheckRequest{Service: ID})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_UNKNOWN, readiness.Status)
	cancel()
	require.NoError(t, <-result)
}

func TestObservationModeCleansInterruptedAppliedState(t *testing.T) {
	directory := secureTempDir(t)
	configPath := filepath.Join(directory, "config.json")
	socketPath := filepath.Join(directory, "plugin.sock")
	network := newFakeNetworkManager()
	appliedConfig := validConfig()
	ruleset, err := RenderRuleset(appliedConfig)
	require.NoError(t, err)
	_, err = applyNetwork(context.Background(), network, appliedConfig, ruleset, ownershipJournalPath(socketPath))
	require.NoError(t, err)
	network.resetCalls()
	writeConfig(t, configPath, `{"health_check_enabled":false}`)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Run(ctx, Options{
			SocketPath: socketPath,
			ConfigPath: configPath,
			Network:    network,
			Prober:     fakeProber{},
		})
	}()
	connection := dialHealth(t, socketPath)
	connection.Close()
	assert.Equal(t, []string{"rule:delete:IPv4", "route:delete:IPv4", "nft:rollback"}, network.recordedCalls())
	_, err = os.Stat(ownershipJournalPath(socketPath))
	require.ErrorIs(t, err, os.ErrNotExist)
	cancel()
	require.NoError(t, <-result)
}

func TestRouteAndRuleCommandArguments(t *testing.T) {
	route := PolicyRoute{
		Family:          IPv6,
		Gateway:         "2001:db8::1",
		Device:          "eth0",
		PreferredSource: "2001:db8::2",
		Metric:          1024,
		MTU:             1400,
		AdvMSS:          1360,
		Onlink:          true,
	}
	assert.Equal(t, []string{
		"-6", "route", "add", "table", "100", "default", "via", "2001:db8::1", "dev", "eth0",
		"src", "2001:db8::2", "metric", "1024", "mtu", "1400", "advmss", "1360", "onlink",
	}, routeCommandArgs("add", 100, route))
	assert.Equal(t, []string{
		"-4", "rule", "add", "priority", "10100", "fwmark", "100", "lookup", "100",
	}, ruleCommandArgs("add", IPv4, 100, 100, 10100))
}

func TestParseNumericJSON(t *testing.T) {
	value, err := parseNumericJSON([]byte(`"100"`))
	require.NoError(t, err)
	assert.Equal(t, 100, value)
	value, err = parseNumericJSON([]byte(`100`))
	require.NoError(t, err)
	assert.Equal(t, 100, value)
}

func TestDecodePolicyRulesKeepsUnrelatedNamedTablesWithoutFailing(t *testing.T) {
	rules, err := decodePolicyRules([]byte(`[
		{"priority":9000,"src":"all","fwmark":"0x1","table":"main"},
		{"priority":10100,"src":"all","fwmark":"0x64","table":"100"}
	]`), IPv4)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	assert.Equal(t, mainRouteTable, rules[0].Table)
	assert.Equal(t, policyRule{Priority: 10100, Mark: 100, Mask: ^uint32(0), HasMark: true, FullMask: true, Global: true, Table: 100}, rules[1])
}

func TestInspectPolicyRulesRejectsEarlierUnmarkedRules(t *testing.T) {
	config := validConfig()
	tests := []struct {
		name string
		rule string
	}{
		{name: "catch all lookup", rule: `{"priority":1000,"src":"all","table":"200"}`},
		{name: "narrow source lookup", rule: `{"priority":1000,"src":"10.0.0.0","srclen":24,"table":"200"}`},
		{name: "terminal blackhole", rule: `{"priority":1000,"src":"all","action":"blackhole"}`},
		{name: "fake canonical local blackhole", rule: `{"priority":0,"src":"all","table":"local","action":"blackhole"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rules, err := decodePolicyRules([]byte(`[`+test.rule+`]`), IPv4)
			require.NoError(t, err)
			_, err = inspectPolicyRules(rules, IPv4, config)
			require.ErrorContains(t, err, "may intercept marked traffic")
		})
	}
}

func TestInspectPolicyRulesAllowsCanonicalLocalAndNonOverlappingMark(t *testing.T) {
	config := validConfig()
	rules, err := decodePolicyRules([]byte(`[
		{"priority":0,"src":"all","table":"local"},
		{"priority":1000,"src":"all","fwmark":"0x1","table":"200"},
		{"priority":10100,"src":"all","fwmark":"0x64","table":"100"}
	]`), IPv4)
	require.NoError(t, err)
	exists, err := inspectPolicyRules(rules, IPv4, config)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestInspectPolicyRulesRejectsDesiredMarkWithTerminalAction(t *testing.T) {
	config := validConfig()
	rules, err := decodePolicyRules([]byte(`[
		{"priority":10100,"src":"all","fwmark":"0x64","table":"100","action":"blackhole"}
	]`), IPv4)
	require.NoError(t, err)
	_, err = inspectPolicyRules(rules, IPv4, config)
	require.ErrorContains(t, err, "already occupied")
}

func TestDecodePolicyRulesPreservesMaskConflict(t *testing.T) {
	rules, err := decodePolicyRules([]byte(`[
		{"priority":10100,"src":"all","fwmark":"0x64","fwmask":"0xff","table":"100"}
	]`), IPv4)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.False(t, rules[0].FullMask)
}

func TestDecodePolicyRulesRejectsNarrowSelectorsAsGlobal(t *testing.T) {
	rules, err := decodePolicyRules([]byte(`[
		{"priority":10100,"src":"10.0.0.0","srclen":24,"fwmark":"0x64","table":"100"}
	]`), IPv4)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.False(t, rules[0].Global)
}

func TestPolicyRuleMatchesOverlappingMarkMask(t *testing.T) {
	rule := policyRule{Mark: 0x60, Mask: 0xf0, HasMark: true}
	assert.True(t, rule.matchesMark(0x64))
	assert.False(t, rule.matchesMark(0x54))
}

func TestDecodeRoutesFiltersByDeviceWithoutIPJSONDevFilter(t *testing.T) {
	routes, err := decodeRoutes([]byte(`[
		{"dst":"default","gateway":"192.0.2.1","dev":"eth0","flags":[]},
		{"dst":"default","gateway":"198.51.100.1","dev":"eth1","metric":20,"flags":[]}
	]`), IPv4, "eth1", false)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	assert.Equal(t, PolicyRoute{Family: IPv4, Gateway: "198.51.100.1", Device: "eth1", Metric: 20}, routes[0])
}

func TestDecodeRoutesPreservesMTUAndAdvMSS(t *testing.T) {
	routes, err := decodeRoutes([]byte(`[
		{"dst":"default","dev":"eth0","flags":[],"metrics":[{"mtu":1400,"advmss":1360}]}
	]`), IPv4, "eth0", false)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	assert.Equal(t, 1400, routes[0].MTU)
	assert.Equal(t, 1360, routes[0].AdvMSS)
}

func TestDecodeRoutesRejectsUnmanagedPolicyTableRoutes(t *testing.T) {
	_, err := decodeRoutes([]byte(`[
		{"dst":"203.0.113.0/24","dev":"eth9","type":"blackhole","flags":[]}
	]`), IPv4, "", true)
	require.ErrorContains(t, err, "unmanaged route")
}

func TestDecodeRoutesRejectsSourceSpecificDefault(t *testing.T) {
	_, err := decodeRoutes([]byte(`[
		{"dst":"default","from":"2001:db8::/64","dev":"eth0","metric":1024,"pref":"medium","flags":[]}
	]`), IPv6, "eth0", false)
	require.ErrorContains(t, err, "unsupported source selector")
}

func newFakeNetworkManager() *fakeNetworkManager {
	return &fakeNetworkManager{
		inspections: map[IPFamily]PolicyInspection{
			IPv4: {Route: PolicyRoute{Family: IPv4, Gateway: "192.0.2.1", Device: "eth0"}},
			IPv6: {Route: PolicyRoute{Family: IPv6, Gateway: "2001:db8::1", Device: "eth0"}},
		},
	}
}

func validConfig() Config {
	config, err := ParseConfig([]byte(`{"health_check_enabled":false}`))
	if err != nil {
		panic(err)
	}
	return config
}

func secureTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	return directory
}

func writeConfig(t *testing.T, path, contents string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
}

func dialHealth(t *testing.T, socketPath string) *grpc.ClientConn {
	t.Helper()
	require.Eventually(t, func() bool {
		info, err := os.Stat(socketPath)
		return err == nil && info.Mode()&os.ModeSocket != 0
	}, 2*time.Second, 10*time.Millisecond)
	dialCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	connection, err := grpc.DialContext(
		dialCtx,
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	return connection
}

func TestLoadConfigRejectsWorldWritableFile(t *testing.T) {
	directory := secureTempDir(t)
	path := filepath.Join(directory, "config.json")
	require.NoError(t, os.WriteFile(path, []byte(`{}`), 0o666))
	require.NoError(t, os.Chmod(path, 0o666))
	_, err := LoadConfig(path)
	require.ErrorContains(t, err, "must not be writable")
}

func TestHealthTargetValidationAcceptsIPv6(t *testing.T) {
	config, err := ParseConfig([]byte(`{
		"ipv4_masquerade":false,
		"ipv6_masquerade":true,
		"health_check_target":"[2001:db8::1]:443"
	}`))
	require.NoError(t, err)
	assert.Equal(t, "[2001:db8::1]:443", config.HealthCheckTarget)
}

func TestHealthTargetValidationRejectsLiteralFamilyMismatch(t *testing.T) {
	_, err := ParseConfig([]byte(`{"health_check_target":"127.0.0.1:443"}`))
	require.ErrorContains(t, err, "external unicast")
	_, err = ParseConfig([]byte(`{
		"ipv4_masquerade":false,
		"ipv6_masquerade":true,
		"health_check_target":"192.0.2.1:443"
	}`))
	require.ErrorContains(t, err, "IPv4 health_check_target")
	_, err = ParseConfig([]byte(`{
		"ipv4_masquerade":true,
		"ipv6_masquerade":true,
		"health_check_target":"192.0.2.1:443"
	}`))
	require.ErrorContains(t, err, "dual-stack health check")
}

func TestRunRejectsNonSocketCollision(t *testing.T) {
	directory := secureTempDir(t)
	configPath := filepath.Join(directory, "config.json")
	socketPath := filepath.Join(directory, "plugin.sock")
	writeConfig(t, configPath, `{"health_check_enabled":false}`)
	require.NoError(t, os.WriteFile(socketPath, []byte("sentinel"), 0o600))
	err := Run(context.Background(), Options{
		SocketPath: socketPath,
		ConfigPath: configPath,
		Network:    newFakeNetworkManager(),
		Prober:     fakeProber{},
	})
	require.ErrorContains(t, err, "refusing to remove non-socket")
	contents, readErr := os.ReadFile(socketPath)
	require.NoError(t, readErr)
	assert.Equal(t, "sentinel", string(contents))
}

func TestListenUnixSocketRejectsInsecureDirectory(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o777))
	_, err := listenUnixSocket(filepath.Join(directory, "plugin.sock"))
	require.ErrorContains(t, err, "must not be writable")
}
