package gostmesh

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	ID         = "gost-mesh"
	Version    = "1.0.0"
	APIVersion = "anixops.gost-mesh/v1"

	maxConfigBytes = 256 << 10
	maxTunnels     = 128
	maxCIDRs       = 128
	maxPathBytes   = 4096
	maxTableID     = 252
	maxPriority    = 32765
)

type Config struct {
	APIVersion     string   `json:"api_version"`
	Apply          bool     `json:"apply"`
	RollbackOnExit bool     `json:"rollback_on_exit"`
	Tunnels        []Tunnel `json:"tunnels"`
}

type Tunnel struct {
	ID        string          `json:"id"`
	Role      string          `json:"role"`
	Transport string          `json:"transport"`
	TUN       TUNConfig       `json:"tun"`
	Routing   RoutingConfig   `json:"routing"`
	Listen    *ListenEndpoint `json:"listen,omitempty"`
	Remote    *RemoteEndpoint `json:"remote,omitempty"`
	TLS       TLSConfig       `json:"tls"`
	WSSPath   string          `json:"wss_path"`
	Health    HealthConfig    `json:"health"`
}

type TUNConfig struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Peer    string `json:"peer_address"`
	Port    int    `json:"port"`
	MTU     int    `json:"mtu"`
}

type RoutingConfig struct {
	SourceCIDRs []string `json:"source_cidrs"`
	RouteCIDRs  []string `json:"route_cidrs"`
	Table       int      `json:"table"`
	Priority    int      `json:"priority"`
}

type ListenEndpoint struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type RemoteEndpoint struct {
	Address string `json:"host"`
	Port    int    `json:"port"`
}

type TLSConfig struct {
	CAFile     string `json:"ca_file"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	ServerName string `json:"server_name"`
}

type HealthConfig struct {
	Enabled             bool   `json:"enabled"`
	Target              string `json:"target"`
	SourceAddress       string `json:"source_address"`
	IntervalSeconds     int    `json:"interval_seconds"`
	TimeoutSeconds      int    `json:"timeout_seconds"`
	FailureThreshold    int    `json:"failure_threshold"`
	RestartDelaySeconds int    `json:"restart_delay_seconds"`
	RestartLimit        int    `json:"restart_limit"`
}

func (h HealthConfig) Interval() time.Duration {
	return time.Duration(h.IntervalSeconds) * time.Second
}

func (h HealthConfig) Timeout() time.Duration {
	return time.Duration(h.TimeoutSeconds) * time.Second
}

func (h HealthConfig) RestartDelay() time.Duration {
	return time.Duration(h.RestartDelaySeconds) * time.Second
}

type rawConfig struct {
	APIVersion     string          `json:"api_version"`
	Apply          *bool           `json:"apply"`
	RollbackOnExit *bool           `json:"rollback_on_exit"`
	Tunnels        json.RawMessage `json:"tunnels"`
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
	if len(contents) > maxConfigBytes {
		return Config{}, fmt.Errorf("plugin config exceeds %d bytes", maxConfigBytes)
	}
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
	if raw.Apply == nil {
		return Config{}, errors.New("apply must be declared")
	}
	if raw.RollbackOnExit == nil {
		return Config{}, errors.New("rollback_on_exit must be declared")
	}
	tunnelJSON := bytes.TrimSpace(raw.Tunnels)
	if len(tunnelJSON) == 0 || tunnelJSON[0] != '[' {
		return Config{}, errors.New("tunnels must be declared as an array")
	}
	var tunnels []Tunnel
	tunnelDecoder := json.NewDecoder(bytes.NewReader(tunnelJSON))
	tunnelDecoder.DisallowUnknownFields()
	if err := tunnelDecoder.Decode(&tunnels); err != nil {
		return Config{}, fmt.Errorf("decode tunnels: %w", err)
	}
	if len(tunnels) > maxTunnels {
		return Config{}, fmt.Errorf("tunnels exceed %d entries", maxTunnels)
	}

	config := Config{
		APIVersion:     raw.APIVersion,
		Apply:          *raw.Apply,
		RollbackOnExit: *raw.RollbackOnExit,
		Tunnels:        tunnels,
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if c.APIVersion != APIVersion {
		return fmt.Errorf("api_version must be %q", APIVersion)
	}
	if !c.RollbackOnExit {
		return errors.New("rollback_on_exit must remain enabled for the gost-mesh v1 crash-safe lifecycle")
	}
	if c.Apply && len(c.Tunnels) == 0 {
		return errors.New("apply=true requires at least one tunnel")
	}
	if len(c.Tunnels) > maxTunnels {
		return fmt.Errorf("tunnels exceed %d entries", maxTunnels)
	}

	seenIDs := make(map[string]struct{}, len(c.Tunnels))
	seenTUNNames := make(map[string]string, len(c.Tunnels))
	seenTables := make(map[int]string, len(c.Tunnels))
	seenPriorities := make(map[int]string, len(c.Tunnels))
	var validated []validatedTunnel
	for index, tunnel := range c.Tunnels {
		checked, err := validateTunnel(tunnel)
		if err != nil {
			return fmt.Errorf("tunnel %d: %w", index, err)
		}
		if _, exists := seenIDs[tunnel.ID]; exists {
			return fmt.Errorf("tunnel id %q is duplicated", tunnel.ID)
		}
		seenIDs[tunnel.ID] = struct{}{}
		if owner, exists := seenTUNNames[tunnel.TUN.Name]; exists {
			return fmt.Errorf("tunnels %q and %q use the same TUN name %q", owner, tunnel.ID, tunnel.TUN.Name)
		}
		seenTUNNames[tunnel.TUN.Name] = tunnel.ID
		if tunnel.Role == "entry" {
			if owner, exists := seenTables[tunnel.Routing.Table]; exists {
				return fmt.Errorf("tunnels %q and %q use the same routing table %d", owner, tunnel.ID, tunnel.Routing.Table)
			}
			seenTables[tunnel.Routing.Table] = tunnel.ID
			for offset := range tunnel.Routing.SourceCIDRs {
				priority := tunnel.Routing.Priority + offset
				if owner, exists := seenPriorities[priority]; exists {
					return fmt.Errorf("tunnels %q and %q use the same routing priority %d", owner, tunnel.ID, priority)
				}
				seenPriorities[priority] = tunnel.ID
			}
		}
		for _, previous := range validated {
			if checked.tunNetwork.Overlaps(previous.tunNetwork) {
				return fmt.Errorf("tunnels %q and %q use overlapping TUN networks", previous.tunnel.ID, tunnel.ID)
			}
			if tunnel.Role == "exit" && previous.tunnel.Role == "exit" && tunnel.TUN.Port == previous.tunnel.TUN.Port {
				return fmt.Errorf("exit tunnels %q and %q use the same TUN port %d", previous.tunnel.ID, tunnel.ID, tunnel.TUN.Port)
			}
			if tunnel.Role == "exit" && previous.tunnel.Role == "exit" &&
				tunnel.Transport == previous.tunnel.Transport && endpointsConflict(*tunnel.Listen, *previous.tunnel.Listen) {
				return fmt.Errorf("exit tunnels %q and %q have conflicting %s listeners", previous.tunnel.ID, tunnel.ID, tunnel.Transport)
			}
			if prefixesOverlap(checked.sourceCIDRs, previous.sourceCIDRs) {
				return fmt.Errorf("tunnels %q and %q use overlapping source CIDRs", previous.tunnel.ID, tunnel.ID)
			}
			if prefixesOverlap(checked.routeCIDRs, previous.routeCIDRs) {
				return fmt.Errorf("tunnels %q and %q use overlapping route CIDRs", previous.tunnel.ID, tunnel.ID)
			}
		}
		validated = append(validated, checked)
	}
	return nil
}

type validatedTunnel struct {
	tunnel      Tunnel
	tunNetwork  netip.Prefix
	sourceCIDRs []netip.Prefix
	routeCIDRs  []netip.Prefix
}

func validateTunnel(tunnel Tunnel) (validatedTunnel, error) {
	if !safeID(tunnel.ID) {
		return validatedTunnel{}, errors.New("id is invalid")
	}
	if tunnel.Role != "entry" && tunnel.Role != "exit" {
		return validatedTunnel{}, errors.New("role must be entry or exit")
	}
	if tunnel.Transport != "quic" && tunnel.Transport != "wss" {
		return validatedTunnel{}, errors.New("transport must be quic or wss")
	}
	tunNetwork, err := validateTUN(tunnel.TUN)
	if err != nil {
		return validatedTunnel{}, err
	}
	sourceCIDRs, err := validateCIDRs(tunnel.Routing.SourceCIDRs, "routing.source_cidrs")
	if err != nil {
		return validatedTunnel{}, err
	}
	routeCIDRs, err := validateCIDRs(tunnel.Routing.RouteCIDRs, "routing.route_cidrs")
	if err != nil {
		return validatedTunnel{}, err
	}
	if err := validateHealth(tunnel.Health); err != nil {
		return validatedTunnel{}, err
	}
	if tunnel.Transport == "wss" {
		if err := validateWSSPath(tunnel.WSSPath); err != nil {
			return validatedTunnel{}, err
		}
	} else if tunnel.WSSPath != "" {
		return validatedTunnel{}, errors.New("wss_path is only valid for the wss transport")
	}

	switch tunnel.Role {
	case "entry":
		if tunnel.Routing.Table < 1 || tunnel.Routing.Table > maxTableID {
			return validatedTunnel{}, fmt.Errorf("routing.table must be between 1 and %d for entry", maxTableID)
		}
		if tunnel.Routing.Priority < 1 || tunnel.Routing.Priority > maxPriority {
			return validatedTunnel{}, fmt.Errorf("routing.priority must be between 1 and %d for entry", maxPriority)
		}
		if len(sourceCIDRs) > 0 && tunnel.Routing.Priority+len(sourceCIDRs)-1 > maxPriority {
			return validatedTunnel{}, fmt.Errorf("routing.priority range must not exceed %d", maxPriority)
		}
		if tunnel.Remote == nil {
			return validatedTunnel{}, errors.New("entry requires remote")
		}
		if tunnel.Listen != nil {
			return validatedTunnel{}, errors.New("entry must not declare listen")
		}
		if err := validateRemote(*tunnel.Remote); err != nil {
			return validatedTunnel{}, err
		}
		if len(sourceCIDRs) == 0 {
			return validatedTunnel{}, errors.New("entry requires routing.source_cidrs")
		}
		if tunnel.Health.Enabled {
			sourceAddress, _ := netip.ParseAddr(tunnel.Health.SourceAddress)
			contained := false
			for _, sourceCIDR := range sourceCIDRs {
				if sourceCIDR.Contains(sourceAddress) {
					contained = true
					break
				}
			}
			if !contained {
				return validatedTunnel{}, errors.New("health.source_address must belong to routing.source_cidrs")
			}
		}
		if len(routeCIDRs) != 0 {
			return validatedTunnel{}, errors.New("entry must not declare routing.route_cidrs")
		}
		if err := validateTLSFile(tunnel.TLS.CAFile, "tls.ca_file", true); err != nil {
			return validatedTunnel{}, err
		}
		if err := validateTLSFile(tunnel.TLS.CertFile, "tls.cert_file", true); err != nil {
			return validatedTunnel{}, err
		}
		if err := validateTLSFile(tunnel.TLS.KeyFile, "tls.key_file", true); err != nil {
			return validatedTunnel{}, err
		}
		if tunnel.TLS.CertFile == tunnel.TLS.KeyFile {
			return validatedTunnel{}, errors.New("tls.cert_file and tls.key_file must be different files")
		}
		if !safeServerName(tunnel.TLS.ServerName) {
			return validatedTunnel{}, errors.New("entry requires a valid tls.server_name")
		}
	case "exit":
		if tunnel.Routing.Table != 0 || tunnel.Routing.Priority != 0 {
			return validatedTunnel{}, errors.New("exit routing.table and routing.priority must be omitted or 0")
		}
		if tunnel.Listen == nil {
			return validatedTunnel{}, errors.New("exit requires listen")
		}
		if tunnel.Remote != nil {
			return validatedTunnel{}, errors.New("exit must not declare remote")
		}
		if err := validateListen(*tunnel.Listen); err != nil {
			return validatedTunnel{}, err
		}
		if len(routeCIDRs) == 0 {
			return validatedTunnel{}, errors.New("exit requires routing.route_cidrs")
		}
		if len(sourceCIDRs) != 0 {
			return validatedTunnel{}, errors.New("exit must not declare routing.source_cidrs")
		}
		if err := validateTLSFile(tunnel.TLS.CertFile, "tls.cert_file", true); err != nil {
			return validatedTunnel{}, err
		}
		if err := validateTLSFile(tunnel.TLS.KeyFile, "tls.key_file", true); err != nil {
			return validatedTunnel{}, err
		}
		if tunnel.TLS.CertFile == tunnel.TLS.KeyFile {
			return validatedTunnel{}, errors.New("tls.cert_file and tls.key_file must be different files")
		}
		if err := validateTLSFile(tunnel.TLS.CAFile, "tls.ca_file", true); err != nil {
			return validatedTunnel{}, err
		}
		if tunnel.TLS.ServerName != "" {
			return validatedTunnel{}, errors.New("exit must not declare tls.server_name")
		}
	}

	return validatedTunnel{
		tunnel:      tunnel,
		tunNetwork:  tunNetwork,
		sourceCIDRs: sourceCIDRs,
		routeCIDRs:  routeCIDRs,
	}, nil
}

func validateTUN(config TUNConfig) (netip.Prefix, error) {
	if !safeInterfaceName(config.Name) {
		return netip.Prefix{}, errors.New("tun.name is invalid")
	}
	prefix, err := netip.ParsePrefix(config.Address)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, errors.New("tun.address must be an IPv4 prefix")
	}
	address := prefix.Addr()
	if !safeIPv4Address(address, false) {
		return netip.Prefix{}, errors.New("tun.address must contain a usable IPv4 host address")
	}
	if prefix.Bits() >= 32 || prefix.Masked().Addr() == address || isIPv4Broadcast(prefix, address) {
		return netip.Prefix{}, errors.New("tun.address must contain a usable host address and peer")
	}
	peer, err := netip.ParseAddr(config.Peer)
	if err != nil || !peer.Is4() || !safeIPv4Address(peer, false) {
		return netip.Prefix{}, errors.New("tun.peer must be a usable IPv4 address")
	}
	if peer == address || !prefix.Contains(peer) || prefix.Masked().Addr() == peer || isIPv4Broadcast(prefix, peer) {
		return netip.Prefix{}, errors.New("tun.peer must be a different usable host in tun.address network")
	}
	if config.Port < 1 || config.Port > 65535 {
		return netip.Prefix{}, errors.New("tun.port must be between 1 and 65535")
	}
	if config.MTU < 576 || config.MTU > 9000 {
		return netip.Prefix{}, errors.New("tun.mtu must be between 576 and 9000")
	}
	return prefix.Masked(), nil
}

func validateCIDRs(values []string, field string) ([]netip.Prefix, error) {
	if len(values) > maxCIDRs {
		return nil, fmt.Errorf("%s exceeds %d entries", field, maxCIDRs)
	}
	result := make([]netip.Prefix, 0, len(values))
	for index, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("%s[%d] must be an IPv4 CIDR", field, index)
		}
		if prefix != prefix.Masked() {
			return nil, fmt.Errorf("%s[%d] must use the canonical network address", field, index)
		}
		for _, previous := range result {
			if prefix.Overlaps(previous) {
				return nil, fmt.Errorf("%s contains overlapping CIDRs", field)
			}
		}
		result = append(result, prefix)
	}
	return result, nil
}

func validateListen(endpoint ListenEndpoint) error {
	address, err := netip.ParseAddr(endpoint.Address)
	if err != nil || !address.Is4() || !safeIPv4Address(address, true) {
		return errors.New("listen.address must be an IPv4 address")
	}
	if endpoint.Port < 1 || endpoint.Port > 65535 {
		return errors.New("listen.port must be between 1 and 65535")
	}
	return nil
}

func validateRemote(endpoint RemoteEndpoint) error {
	if endpoint.Port < 1 || endpoint.Port > 65535 {
		return errors.New("remote.port must be between 1 and 65535")
	}
	if address, err := netip.ParseAddr(endpoint.Address); err == nil {
		if !address.Is4() || !safeIPv4Address(address, false) {
			return errors.New("remote.address must be an IPv4 address or DNS name")
		}
		return nil
	}
	if !safeDNSName(endpoint.Address) {
		return errors.New("remote.address must be an IPv4 address or DNS name")
	}
	return nil
}

func validateTLSFile(value, field string, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
	if len(value) > maxPathBytes || strings.ContainsAny(value, "\x00\r\n") || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) {
		return fmt.Errorf("%s must be a clean absolute local file path", field)
	}
	return nil
}

func validateWSSPath(value string) error {
	if value == "" || len(value) > 1024 || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\x00\r\n?#") {
		return errors.New("wss_path must be an absolute HTTP path without query or fragment")
	}
	return nil
}

func validateHealth(config HealthConfig) error {
	if config.IntervalSeconds < 5 || config.IntervalSeconds > 300 {
		return errors.New("health.interval_seconds must be between 5 and 300")
	}
	if config.TimeoutSeconds < 1 || config.TimeoutSeconds > 30 {
		return errors.New("health.timeout_seconds must be between 1 and 30")
	}
	if config.TimeoutSeconds >= config.IntervalSeconds {
		return errors.New("health.timeout_seconds must be less than health.interval_seconds")
	}
	if config.FailureThreshold < 1 || config.FailureThreshold > 20 {
		return errors.New("health.failure_threshold must be between 1 and 20")
	}
	if config.RestartDelaySeconds < 1 || config.RestartDelaySeconds > 300 {
		return errors.New("health.restart_delay_seconds must be between 1 and 300")
	}
	if config.RestartLimit < 1 || config.RestartLimit > 100 {
		return errors.New("health.restart_limit must be between 1 and 100")
	}
	if config.Enabled && config.Target == "" {
		return errors.New("health.target is required when health.enabled=true")
	}
	if config.Enabled && config.SourceAddress == "" {
		return errors.New("health.source_address is required when health.enabled=true")
	}
	if config.Target != "" {
		if err := validateHealthTarget(config.Target); err != nil {
			return err
		}
	}
	if config.SourceAddress != "" {
		address, err := netip.ParseAddr(config.SourceAddress)
		if err != nil || !address.Is4() || !safeIPv4Address(address, false) {
			return errors.New("health.source_address must be a usable IPv4 address")
		}
	}
	return nil
}

func validateHealthTarget(value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return errors.New("health.target must be an IPv4 or DNS host:port endpoint")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("health.target port must be between 1 and 65535")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if !address.Is4() || address.As4()[0] == 0 || address.IsLoopback() || !safeIPv4Address(address, false) {
			return errors.New("health.target must use IPv4 or a DNS name")
		}
		return nil
	}
	if !safeDNSName(host) {
		return errors.New("health.target must use IPv4 or a DNS name")
	}
	return nil
}

func safeID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index := range value {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			continue
		}
		if index > 0 && (character == '-' || character == '_' || character == '.') {
			continue
		}
		return false
	}
	return true
}

func safeInterfaceName(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 15 {
		return false
	}
	for index := range value {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func safeDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.HasSuffix(value, ".") || strings.ContainsAny(value, "\x00\r\n/: \\") {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range label {
			character := label[index]
			if (character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func safeServerName(value string) bool {
	if net.ParseIP(value) != nil {
		return false
	}
	return safeDNSName(value)
}

func safeIPv4Address(address netip.Addr, allowUnspecified bool) bool {
	if !address.IsValid() || !address.Is4() || address.IsMulticast() || address.IsLinkLocalUnicast() {
		return false
	}
	if address.IsUnspecified() {
		return allowUnspecified
	}
	return address.String() != "255.255.255.255"
}

func isIPv4Broadcast(prefix netip.Prefix, address netip.Addr) bool {
	if !prefix.Addr().Is4() || !address.Is4() || prefix.Bits() >= 31 {
		return false
	}
	network := prefix.Masked().Addr().As4()
	candidate := address.As4()
	hostBits := uint(32 - prefix.Bits())
	networkValue := uint32(network[0])<<24 | uint32(network[1])<<16 | uint32(network[2])<<8 | uint32(network[3])
	broadcast := networkValue | uint32((uint64(1)<<hostBits)-1)
	value := uint32(candidate[0])<<24 | uint32(candidate[1])<<16 | uint32(candidate[2])<<8 | uint32(candidate[3])
	return value == broadcast
}

func prefixesOverlap(left, right []netip.Prefix) bool {
	for _, one := range left {
		for _, two := range right {
			if one.Overlaps(two) {
				return true
			}
		}
	}
	return false
}

func endpointsConflict(left, right ListenEndpoint) bool {
	if left.Port != right.Port {
		return false
	}
	leftAddress, _ := netip.ParseAddr(left.Address)
	rightAddress, _ := netip.ParseAddr(right.Address)
	return leftAddress == rightAddress || leftAddress.IsUnspecified() || rightAddress.IsUnspecified()
}
