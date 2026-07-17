//go:build linux

package gostmesh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type CommandNetworkManager struct {
	IPBinary string
	ProcRoot string
}

func (m CommandNetworkManager) Preflight(ctx context.Context, config Config) error {
	if os.Geteuid() != 0 {
		return errors.New("gost-mesh apply requires root network privileges")
	}
	if err := m.validateForwarding(); err != nil {
		return err
	}
	rules, err := m.rules(ctx)
	if err != nil {
		return err
	}
	for _, tunnel := range config.Tunnels {
		exists, err := m.linkExists(ctx, tunnel.TUN.Name)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("tunnel %q TUN interface %q already exists", tunnel.ID, tunnel.TUN.Name)
		}
		if tunnel.Role == "entry" {
			routes, err := m.run(ctx, "-4", "route", "show", "table", strconv.Itoa(tunnel.Routing.Table))
			if err != nil && !missingNetworkObject(routes) {
				return fmt.Errorf("inspect tunnel %q routing table: %w: %s", tunnel.ID, err, strings.TrimSpace(string(routes)))
			}
			if strings.TrimSpace(string(routes)) != "" && !missingNetworkObject(routes) {
				return fmt.Errorf("tunnel %q routing table %d is not empty", tunnel.ID, tunnel.Routing.Table)
			}
			for index := range tunnel.Routing.SourceCIDRs {
				priority := tunnel.Routing.Priority + index
				if owner := ruleAtPriority(rules, priority); owner != "" {
					return fmt.Errorf("tunnel %q routing priority %d is already occupied by %s", tunnel.ID, priority, owner)
				}
			}
		}
		if err := validateTunnelTLSFiles(tunnel); err != nil {
			return fmt.Errorf("tunnel %q: %w", tunnel.ID, err)
		}
		if tunnel.Role == "exit" {
			if err := checkListenerAvailable(tunnel); err != nil {
				return fmt.Errorf("tunnel %q: %w", tunnel.ID, err)
			}
		}
	}
	return nil
}

func (m CommandNetworkManager) WaitTunnel(ctx context.Context, tunnel Tunnel, timeout time.Duration) (int, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready, interfaceIndex, err := m.tunnelReady(waitCtx, tunnel)
		if err == nil && ready {
			return interfaceIndex, nil
		}
		select {
		case <-waitCtx.Done():
			if err != nil {
				return 0, errors.Join(fmt.Errorf("wait for tunnel %q TUN interface: %w", tunnel.ID, err), waitCtx.Err())
			}
			return 0, fmt.Errorf("wait for tunnel %q TUN interface: %w", tunnel.ID, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func (m CommandNetworkManager) ApplyEntryRouting(ctx context.Context, tunnel Tunnel) error {
	if tunnel.Role != "entry" {
		return nil
	}
	if output, err := m.run(ctx, "-4", "route", "add", "table", strconv.Itoa(tunnel.Routing.Table), "default", "dev", tunnel.TUN.Name); err != nil {
		return fmt.Errorf("add tunnel %q policy route: %w: %s", tunnel.ID, err, strings.TrimSpace(string(output)))
	}
	for index, source := range tunnel.Routing.SourceCIDRs {
		priority := strconv.Itoa(tunnel.Routing.Priority + index)
		if output, err := m.run(ctx, "-4", "rule", "add", "priority", priority, "from", source, "table", strconv.Itoa(tunnel.Routing.Table)); err != nil {
			return fmt.Errorf("add tunnel %q source rule: %w: %s", tunnel.ID, err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func (m CommandNetworkManager) VerifyTunnel(ctx context.Context, tunnel Tunnel) error {
	ready, _, err := m.tunnelReady(ctx, tunnel)
	if err != nil {
		return err
	}
	if !ready {
		return fmt.Errorf("tunnel %q TUN interface is not ready", tunnel.ID)
	}
	if tunnel.Role == "entry" {
		output, err := m.run(ctx, "-4", "route", "show", "table", strconv.Itoa(tunnel.Routing.Table), "default", "dev", tunnel.TUN.Name)
		if err != nil || strings.TrimSpace(string(output)) == "" {
			return fmt.Errorf("tunnel %q policy route is missing: %w: %s", tunnel.ID, err, strings.TrimSpace(string(output)))
		}
		rules, err := m.rules(ctx)
		if err != nil {
			return err
		}
		for index, source := range tunnel.Routing.SourceCIDRs {
			priority := tunnel.Routing.Priority + index
			if !hasExactRule(rules, priority, source, tunnel.Routing.Table) {
				return fmt.Errorf("tunnel %q source rule priority %d is missing", tunnel.ID, priority)
			}
		}
		return nil
	}
	for _, route := range tunnel.Routing.RouteCIDRs {
		output, err := m.run(ctx, "-4", "route", "show", route, "dev", tunnel.TUN.Name)
		if err != nil || strings.TrimSpace(string(output)) == "" {
			return fmt.Errorf("tunnel %q return route %s is missing: %w: %s", tunnel.ID, route, err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func (m CommandNetworkManager) CleanupTunnel(ctx context.Context, tunnel tunnelJournal) error {
	exists, interfaceIndex, matches, err := m.journalLinkIdentity(ctx, tunnel)
	if err != nil {
		return err
	}
	if exists && (tunnel.InterfaceIndex <= 0 || interfaceIndex != tunnel.InterfaceIndex || !matches) {
		return fmt.Errorf("refusing to clean tunnel %q because TUN interface ownership no longer matches", tunnel.ID)
	}
	var result error
	if tunnel.Role == "entry" {
		for index := len(tunnel.SourceCIDRs) - 1; index >= 0; index-- {
			priority := strconv.Itoa(tunnel.RulePriority + index)
			output, err := m.run(ctx, "-4", "rule", "del", "priority", priority, "from", tunnel.SourceCIDRs[index], "table", strconv.Itoa(tunnel.RoutingTable))
			if err != nil && !missingNetworkObject(output) {
				result = errors.Join(result, fmt.Errorf("delete tunnel %q source rule: %w: %s", tunnel.ID, err, strings.TrimSpace(string(output))))
			}
		}
		output, err := m.run(ctx, "-4", "route", "del", "table", strconv.Itoa(tunnel.RoutingTable), "default", "dev", tunnel.TUNName)
		if err != nil && !missingNetworkObject(output) {
			result = errors.Join(result, fmt.Errorf("delete tunnel %q policy route: %w: %s", tunnel.ID, err, strings.TrimSpace(string(output))))
		}
	}
	if exists {
		output, deleteErr := m.run(ctx, "link", "delete", "dev", tunnel.TUNName)
		if deleteErr != nil && !missingNetworkObject(output) {
			result = errors.Join(result, fmt.Errorf("delete tunnel %q TUN interface: %w: %s", tunnel.ID, deleteErr, strings.TrimSpace(string(output))))
		}
	}
	return result
}

func (m CommandNetworkManager) validateForwarding() error {
	contents, err := os.ReadFile(filepath.Join(m.procRoot(), "sys/net/ipv4/ip_forward"))
	if err != nil {
		return fmt.Errorf("read IPv4 forwarding state: %w", err)
	}
	if strings.TrimSpace(string(contents)) != "1" {
		return errors.New("IPv4 forwarding is disabled; enable net.ipv4.ip_forward before activating gost-mesh")
	}
	rpFilterPaths, err := filepath.Glob(filepath.Join(m.procRoot(), "sys/net/ipv4/conf/*/rp_filter"))
	if err != nil {
		return fmt.Errorf("inspect IPv4 reverse-path filter state: %w", err)
	}
	if len(rpFilterPaths) == 0 {
		return errors.New("IPv4 reverse-path filter state is unavailable")
	}
	for _, path := range rpFilterPaths {
		value, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read IPv4 reverse-path filter %s: %w", filepath.Base(filepath.Dir(path)), readErr)
		}
		if strings.TrimSpace(string(value)) != "0" {
			return fmt.Errorf("IPv4 reverse-path filtering is enabled on %s; set net.ipv4.conf.%s.rp_filter=0 before activating source-policy gost-mesh", filepath.Base(filepath.Dir(path)), filepath.Base(filepath.Dir(path)))
		}
	}
	return nil
}

type linkAddress struct {
	IfIndex  int      `json:"ifindex"`
	Flags    []string `json:"flags"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

func (m CommandNetworkManager) tunnelReady(ctx context.Context, tunnel Tunnel) (bool, int, error) {
	output, err := m.run(ctx, "-details", "-4", "-json", "addr", "show", "dev", tunnel.TUN.Name)
	if err != nil {
		if missingNetworkObject(output) {
			return false, 0, nil
		}
		return false, 0, fmt.Errorf("inspect tunnel %q TUN interface: %w: %s", tunnel.ID, err, strings.TrimSpace(string(output)))
	}
	var links []linkAddress
	if err := json.Unmarshal(output, &links); err != nil {
		return false, 0, fmt.Errorf("decode tunnel %q TUN interface: %w", tunnel.ID, err)
	}
	prefix, _ := netip.ParsePrefix(tunnel.TUN.Address)
	for _, link := range links {
		up := false
		for _, flag := range link.Flags {
			if flag == "UP" {
				up = true
			}
		}
		if !up || link.IfIndex <= 0 || link.LinkInfo.Kind != "tun" {
			continue
		}
		for _, address := range link.AddrInfo {
			if address.Family == "inet" && address.Local == prefix.Addr().String() && address.PrefixLen == prefix.Bits() {
				return true, link.IfIndex, nil
			}
		}
	}
	return false, 0, nil
}

func (m CommandNetworkManager) journalLinkIdentity(ctx context.Context, tunnel tunnelJournal) (bool, int, bool, error) {
	output, err := m.run(ctx, "-details", "-4", "-json", "addr", "show", "dev", tunnel.TUNName)
	if err != nil {
		if missingNetworkObject(output) {
			return false, 0, false, nil
		}
		return false, 0, false, fmt.Errorf("inspect journal TUN interface %q: %w: %s", tunnel.TUNName, err, strings.TrimSpace(string(output)))
	}
	var links []linkAddress
	if err := json.Unmarshal(output, &links); err != nil {
		return false, 0, false, fmt.Errorf("decode journal TUN interface %q: %w", tunnel.TUNName, err)
	}
	prefix, err := netip.ParsePrefix(tunnel.TUNAddress)
	if err != nil {
		return true, 0, false, err
	}
	for _, link := range links {
		matches := link.LinkInfo.Kind == "tun"
		addressMatches := false
		for _, address := range link.AddrInfo {
			if address.Family == "inet" && address.Local == prefix.Addr().String() && address.PrefixLen == prefix.Bits() {
				addressMatches = true
				break
			}
		}
		return true, link.IfIndex, matches && addressMatches, nil
	}
	return false, 0, false, nil
}

func (m CommandNetworkManager) linkExists(ctx context.Context, name string) (bool, error) {
	output, err := m.run(ctx, "link", "show", "dev", name)
	if err != nil {
		if missingNetworkObject(output) {
			return false, nil
		}
		return false, fmt.Errorf("inspect TUN interface %q: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return true, nil
}

type ruleDocument struct {
	Priority  int             `json:"priority"`
	Source    string          `json:"src"`
	SourceLen int             `json:"srclen"`
	Table     json.RawMessage `json:"table"`
}

type parsedRule struct {
	Priority int
	Source   string
	Table    int
	Raw      string
}

func (m CommandNetworkManager) rules(ctx context.Context) ([]parsedRule, error) {
	output, err := m.run(ctx, "-4", "-json", "rule", "show")
	if err != nil {
		return nil, fmt.Errorf("inspect IPv4 policy rules: %w: %s", err, strings.TrimSpace(string(output)))
	}
	var documents []ruleDocument
	if err := json.Unmarshal(output, &documents); err != nil {
		return nil, fmt.Errorf("decode IPv4 policy rules: %w", err)
	}
	rules := make([]parsedRule, 0, len(documents))
	for _, document := range documents {
		table, err := parseRuleTable(document.Table)
		if err != nil {
			return nil, err
		}
		source := strings.TrimSpace(document.Source)
		if source != "" && source != "all" && document.SourceLen > 0 && !strings.Contains(source, "/") {
			source += "/" + strconv.Itoa(document.SourceLen)
		}
		rules = append(rules, parsedRule{Priority: document.Priority, Source: source, Table: table, Raw: string(document.Table)})
	}
	return rules, nil
}

func parseRuleTable(raw json.RawMessage) (int, error) {
	var numeric int
	if json.Unmarshal(raw, &numeric) == nil {
		return numeric, nil
	}
	var name string
	if err := json.Unmarshal(raw, &name); err != nil {
		return 0, errors.New("IPv4 policy rule table is invalid")
	}
	switch name {
	case "local":
		return 255, nil
	case "main":
		return 254, nil
	case "default":
		return 253, nil
	default:
		value, err := strconv.Atoi(name)
		if err != nil {
			return 0, fmt.Errorf("IPv4 policy rule table %q is not supported", name)
		}
		return value, nil
	}
}

func ruleAtPriority(rules []parsedRule, priority int) string {
	for _, rule := range rules {
		if rule.Priority == priority {
			return fmt.Sprintf("source=%q table=%d", rule.Source, rule.Table)
		}
	}
	return ""
}

func hasExactRule(rules []parsedRule, priority int, source string, table int) bool {
	for _, rule := range rules {
		if rule.Priority == priority && (rule.Source == source || (rule.Source == "all" && source == "0.0.0.0/0")) && rule.Table == table {
			return true
		}
	}
	return false
}

func validateTunnelTLSFiles(tunnel Tunnel) error {
	contents, err := readTLSFile(tunnel.TLS.CAFile, false)
	if err != nil {
		return fmt.Errorf("read tls.ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(contents) {
		return errors.New("tls.ca_file does not contain a PEM certificate")
	}
	certificate, err := readTLSFile(tunnel.TLS.CertFile, false)
	if err != nil {
		return fmt.Errorf("read tls.cert_file: %w", err)
	}
	key, err := readTLSFile(tunnel.TLS.KeyFile, true)
	if err != nil {
		return fmt.Errorf("read tls.key_file: %w", err)
	}
	if _, err := tls.X509KeyPair(certificate, key); err != nil {
		return fmt.Errorf("tls certificate and private key do not match: %w", err)
	}
	return nil
}

func readTLSFile(path string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("TLS path must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("TLS file must not be writable by group or other users")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("TLS private key must not be accessible by group or other users")
	}
	if info.Size() > 2<<20 {
		return nil, errors.New("TLS file exceeds 2 MiB")
	}
	return os.ReadFile(path)
}

func checkListenerAvailable(tunnel Tunnel) error {
	address := net.JoinHostPort(tunnel.Listen.Address, strconv.Itoa(tunnel.Listen.Port))
	if tunnel.Transport == "wss" {
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			return fmt.Errorf("WSS listener %s is unavailable: %w", address, err)
		}
		return listener.Close()
	}
	listener, err := net.ListenPacket("udp4", address)
	if err != nil {
		return fmt.Errorf("QUIC listener %s is unavailable: %w", address, err)
	}
	return listener.Close()
}

func (m CommandNetworkManager) run(ctx context.Context, args ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, networkCommandTimeout)
	defer cancel()
	return exec.CommandContext(commandCtx, m.ipBinary(), args...).CombinedOutput()
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
	return "/proc"
}

func missingNetworkObject(output []byte) bool {
	text := strings.ToLower(strings.TrimSpace(string(output)))
	return strings.Contains(text, "does not exist") || strings.Contains(text, "cannot find device") || strings.Contains(text, "no such process") || strings.Contains(text, "fib table does not exist") || strings.Contains(text, "no such file")
}
