package wireguard

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
)

var _ vCore.Core = (*WireGuard)(nil)
var _ vCore.OnlineDeviceProvider = (*WireGuard)(nil)

type commandExecutor interface {
	Run(name string, args ...string) error
	Output(name string, args ...string) ([]byte, error)
	Start(name string, args ...string) (process, error)
}

type process interface {
	Stop() error
}

type osExecutor struct{}

func (osExecutor) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (osExecutor) Output(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.Output()
}

func (osExecutor) Start(name string, args ...string) (process, error) {
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return osProcess{cmd: cmd}, nil
}

type osProcess struct {
	cmd *exec.Cmd
}

func (p osProcess) Stop() error {
	if p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	err := p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
	return err
}

type WireGuard struct {
	cfg      *conf.WireGuardConfig
	executor commandExecutor
	mu       sync.Mutex
	nodes    map[string]*nodeState
	traffic  map[string]map[string]trafficPair
}

type nodeState struct {
	tag                   string
	iface                 string
	info                  *panel.NodeInfo
	users                 map[string]panel.UserInfo
	gost                  process
	gostRuntime           *gostRuntime
	cfgPath               string
	reportMinTrafficBytes int64
}

type trafficPair struct {
	upload   int64
	download int64
}

type gostRuntime struct {
	role            string
	tunName         string
	sourceCIDR      string
	routingTable    int
	routingPriority int
	exitNAT         bool
	outboundIface   string
}

func init() {
	vCore.RegisterCore("wireguard", New)
}

func New(c *conf.CoreConfig) (vCore.Core, error) {
	cfg := conf.NewWireGuardConfig()
	if c != nil && c.WireGuardConfig != nil {
		cfg = c.WireGuardConfig
	}
	return &WireGuard{
		cfg:      cfg,
		executor: osExecutor{},
		nodes:    make(map[string]*nodeState),
		traffic:  make(map[string]map[string]trafficPair),
	}, nil
}

func (w *WireGuard) Start() error { return nil }

func (w *WireGuard) Close() error {
	w.mu.Lock()
	tags := make([]string, 0, len(w.nodes))
	for tag := range w.nodes {
		tags = append(tags, tag)
	}
	w.mu.Unlock()

	var errs []error
	for _, tag := range tags {
		if err := w.DelNode(tag); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (w *WireGuard) AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error {
	if info == nil || info.WireGuard == nil {
		return errors.New("wireguard node config is missing")
	}
	if strings.TrimSpace(info.WireGuard.ServerPrivateKey) == "" {
		return errors.New("wireguard server_private_key is required")
	}
	if strings.TrimSpace(info.WireGuard.ServerAddress) == "" {
		return errors.New("wireguard server_address is required")
	}

	w.mu.Lock()
	state := &nodeState{
		tag:     tag,
		iface:   interfaceName(tag),
		info:    info,
		users:   make(map[string]panel.UserInfo),
		cfgPath: filepath.Join(w.cfg.RuntimeDir, interfaceName(tag)+".conf"),
	}
	if config != nil {
		state.reportMinTrafficBytes = config.ReportMinTraffic * 1024
	}
	w.nodes[tag] = state
	w.mu.Unlock()

	if err := w.apply(state); err != nil {
		w.mu.Lock()
		delete(w.nodes, tag)
		delete(w.traffic, tag)
		w.mu.Unlock()
		return err
	}
	return nil
}

func (w *WireGuard) DelNode(tag string) error {
	w.mu.Lock()
	state, ok := w.nodes[tag]
	if ok {
		delete(w.nodes, tag)
		delete(w.traffic, tag)
	}
	w.mu.Unlock()
	if !ok {
		return errors.New("the node is not have")
	}
	if state.gost != nil {
		w.cleanupGost(state)
	}
	_ = os.Remove(state.cfgPath)
	return w.executor.Run(w.cfg.IPPath, "link", "delete", state.iface)
}

func (w *WireGuard) AddUsers(p *vCore.AddUsersParams) (int, error) {
	if p == nil {
		return 0, errors.New("wireguard add users params is nil")
	}
	w.mu.Lock()
	state, ok := w.nodes[p.Tag]
	if !ok {
		w.mu.Unlock()
		return 0, errors.New("the node is not have")
	}
	for _, user := range p.Users {
		if err := validateWireGuardUser(user); err != nil {
			w.mu.Unlock()
			return 0, err
		}
		state.users[user.Uuid] = user
	}
	w.mu.Unlock()
	if err := w.apply(state); err != nil {
		return 0, err
	}
	return len(p.Users), nil
}

func (w *WireGuard) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	w.mu.Lock()
	state, ok := w.nodes[tag]
	if !ok {
		w.mu.Unlock()
		return errors.New("the node is not have")
	}
	for _, user := range users {
		delete(state.users, user.Uuid)
	}
	w.mu.Unlock()
	return w.apply(state)
}

func (w *WireGuard) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	w.mu.Lock()
	state, ok := w.nodes[tag]
	if !ok {
		w.mu.Unlock()
		return nil, errors.New("the node is not have")
	}
	publicKeyToUID := make(map[string]int, len(state.users))
	for _, user := range state.users {
		publicKeyToUID[user.WireGuardPublicKey] = user.Id
	}
	w.mu.Unlock()

	out, err := w.executor.Output(w.cfg.WGPath, "show", state.iface, "transfer")
	if err != nil {
		return nil, err
	}
	current := parseTransferOutput(out)

	w.mu.Lock()
	defer w.mu.Unlock()
	previous := w.traffic[tag]
	if previous == nil {
		previous = make(map[string]trafficPair)
		w.traffic[tag] = previous
	}

	trafficSlice := make([]panel.UserTraffic, 0, len(current))
	for publicKey, now := range current {
		uid := publicKeyToUID[publicKey]
		if uid == 0 {
			continue
		}
		report := now
		if reset {
			last := previous[publicKey]
			report.upload -= last.upload
			report.download -= last.download
			previous[publicKey] = now
		}
		if report.upload < 0 || report.download < 0 {
			report = now
		}
		if report.upload+report.download <= state.reportMinTrafficBytes {
			continue
		}
		trafficSlice = append(trafficSlice, panel.UserTraffic{
			UID:      uid,
			Upload:   report.upload,
			Download: report.download,
		})
	}
	if len(trafficSlice) == 0 {
		return nil, nil
	}
	return trafficSlice, nil
}

func (w *WireGuard) GetOnlineDevice(tag string) ([]panel.OnlineUser, error) {
	w.mu.Lock()
	state, ok := w.nodes[tag]
	if !ok {
		w.mu.Unlock()
		return nil, errors.New("the node is not have")
	}
	publicKeyToUID := make(map[string]int, len(state.users))
	for _, user := range state.users {
		publicKeyToUID[user.WireGuardPublicKey] = user.Id
	}
	iface := state.iface
	w.mu.Unlock()

	out, err := w.executor.Output(w.cfg.WGPath, "show", iface, "dump")
	if err != nil {
		return nil, err
	}
	return parseDumpOnline(out, publicKeyToUID, time.Now().Unix(), w.cfg.OnlineHandshakeTimeoutSeconds), nil
}

func (w *WireGuard) Protocols() []string {
	return []string{"wireguard"}
}

func (w *WireGuard) Type() string {
	return "wireguard"
}

func (w *WireGuard) apply(state *nodeState) error {
	if err := os.MkdirAll(w.cfg.RuntimeDir, 0700); err != nil {
		return err
	}
	cfg := renderConfig(state)
	if err := os.WriteFile(state.cfgPath, []byte(cfg), 0600); err != nil {
		return err
	}

	if err := w.executor.Run(w.cfg.IPPath, "link", "show", state.iface); err != nil {
		if err := w.executor.Run(w.cfg.IPPath, "link", "add", state.iface, "type", "wireguard"); err != nil {
			return err
		}
	}

	n := state.info.WireGuard
	if err := w.executor.Run(w.cfg.IPPath, "address", "flush", "dev", state.iface); err != nil {
		return err
	}
	if err := w.executor.Run(w.cfg.IPPath, "address", "add", n.ServerAddress, "dev", state.iface); err != nil {
		return err
	}
	if err := w.executor.Run(w.cfg.IPPath, "link", "set", "mtu", strconv.Itoa(wireGuardMTU(n)), "dev", state.iface); err != nil {
		return err
	}
	if err := w.executor.Run(w.cfg.WGPath, "setconf", state.iface, state.cfgPath); err != nil {
		return err
	}
	if err := w.executor.Run(w.cfg.IPPath, "link", "set", "up", "dev", state.iface); err != nil {
		return err
	}
	return w.applyGost(state)
}

func (w *WireGuard) applyGost(state *nodeState) error {
	n := state.info.WireGuard
	if strings.ToLower(n.Relay.Backend) != "gost" {
		return nil
	}

	if err := w.cleanupGost(state); err != nil {
		return err
	}

	role := wireGuardRelayRole(n)
	mode, err := wireGuardGostMode(n)
	if err != nil {
		return err
	}
	tunPort := n.Relay.TunPort
	if tunPort <= 0 {
		tunPort = 8421
	}
	tunName := strings.TrimSpace(n.Relay.TunName)
	if tunName == "" {
		tunName = gostTunName(state.tag)
	}
	sourceCIDR := strings.TrimSpace(n.CIDR)
	if sourceCIDR == "" {
		return errors.New("wireguard cidr is required for gost relay routing")
	}
	runtime := &gostRuntime{
		role:            role,
		tunName:         tunName,
		sourceCIDR:      sourceCIDR,
		routingTable:    relayRoutingTable(state.tag, n.Relay.RoutingTable),
		routingPriority: relayRoutingPriority(state.tag, n.Relay.RoutingPriority),
		exitNAT:         n.Relay.ExitNAT,
		outboundIface:   strings.TrimSpace(n.Relay.OutboundIface),
	}
	if err := w.enableIPv4Forwarding(); err != nil {
		return err
	}

	var proc process
	switch role {
	case "exit":
		proc, err = w.startGostExit(state, mode, tunName, tunPort)
		if err == nil && n.Relay.ExitNAT {
			err = w.applyExitNAT(runtime)
		}
	default:
		proc, err = w.startGostEntry(state, mode, tunName, tunPort)
		if err == nil {
			err = w.applyEntryRouting(runtime)
		}
	}
	if err != nil {
		if proc != nil {
			_ = proc.Stop()
		}
		if runtime.role == "exit" {
			w.cleanupExitNAT(runtime)
		} else {
			w.cleanupEntryRouting(runtime)
		}
		return err
	}
	state.gost = proc
	state.gostRuntime = runtime
	return nil
}

func (w *WireGuard) cleanupGost(state *nodeState) error {
	if state == nil {
		return nil
	}
	if state.gost != nil {
		_ = state.gost.Stop()
		state.gost = nil
	}
	runtime := state.gostRuntime
	state.gostRuntime = nil
	if runtime == nil {
		return nil
	}
	if runtime.role == "exit" && runtime.exitNAT {
		w.cleanupExitNAT(runtime)
		return nil
	}
	w.cleanupEntryRouting(runtime)
	return nil
}

func (w *WireGuard) startGostEntry(state *nodeState, mode, tunName string, tunPort int) (process, error) {
	n := state.info.WireGuard
	if strings.TrimSpace(n.Relay.Server) == "" || n.Relay.ServerPort <= 0 {
		return nil, errors.New("wireguard gost entry requires relay.server and relay.server_port")
	}
	tunAddress := relayTunAddress(n, "entry")
	if tunAddress == "" {
		return nil, errors.New("wireguard gost entry requires relay.entry_tun_address or relay.tun_address")
	}
	listener := fmt.Sprintf(
		"tun://:0/:%d?net=%s&name=%s&mtu=%d",
		tunPort,
		tunAddress,
		tunName,
		wireGuardMTU(n),
	)
	forwarder := fmt.Sprintf("%s://%s:%d", mode, n.Relay.Server, n.Relay.ServerPort)
	return w.executor.Start(w.cfg.GostPath, "-L", listener, "-F", forwarder)
}

func (w *WireGuard) startGostExit(state *nodeState, mode, tunName string, tunPort int) (process, error) {
	n := state.info.WireGuard
	tunAddress := relayTunAddress(n, "exit")
	if tunAddress == "" {
		return nil, errors.New("wireguard gost exit requires relay.exit_tun_address or relay.tun_address")
	}
	entryTunIP := relayTunIP(n.Relay.EntryTunAddress)
	if entryTunIP == "" {
		return nil, errors.New("wireguard gost exit requires relay.entry_tun_address")
	}
	listener := fmt.Sprintf(
		"tun://:%d?net=%s&name=%s&mtu=%d&route=%s&gw=%s",
		tunPort,
		tunAddress,
		tunName,
		wireGuardMTU(n),
		n.CIDR,
		entryTunIP,
	)
	relayListener := fmt.Sprintf("%s://:%d?bind=true", mode, state.info.Common.ServerPort)
	if n.Relay.ServerPort > 0 {
		relayListener = fmt.Sprintf("%s://:%d?bind=true", mode, n.Relay.ServerPort)
	}
	return w.executor.Start(w.cfg.GostPath, "-L", listener, "-L", relayListener)
}

func (w *WireGuard) enableIPv4Forwarding() error {
	if w.cfg.SysctlPath == "" {
		return nil
	}
	return w.executor.Run(w.cfg.SysctlPath, "-w", "net.ipv4.ip_forward=1")
}

func (w *WireGuard) applyEntryRouting(runtime *gostRuntime) error {
	w.cleanupEntryRouting(runtime)
	if err := w.executor.Run(
		w.cfg.IPPath,
		"route", "replace", "default", "dev", runtime.tunName, "table", strconv.Itoa(runtime.routingTable),
	); err != nil {
		return err
	}
	return w.executor.Run(
		w.cfg.IPPath,
		"rule", "add", "from", runtime.sourceCIDR,
		"table", strconv.Itoa(runtime.routingTable),
		"priority", strconv.Itoa(runtime.routingPriority),
	)
}

func (w *WireGuard) cleanupEntryRouting(runtime *gostRuntime) {
	if runtime == nil {
		return
	}
	_ = w.executor.Run(
		w.cfg.IPPath,
		"rule", "delete", "from", runtime.sourceCIDR,
		"table", strconv.Itoa(runtime.routingTable),
		"priority", strconv.Itoa(runtime.routingPriority),
	)
	_ = w.executor.Run(w.cfg.IPPath, "route", "flush", "table", strconv.Itoa(runtime.routingTable))
}

func (w *WireGuard) applyExitNAT(runtime *gostRuntime) error {
	if w.cfg.IPTablesPath == "" {
		return nil
	}
	natArgs := []string{"-t", "nat", "-A", "POSTROUTING", "-s", runtime.sourceCIDR}
	if runtime.outboundIface != "" {
		natArgs = append(natArgs, "-o", runtime.outboundIface)
	}
	natArgs = append(natArgs, "-j", "MASQUERADE")
	if err := ensureIPTablesRule(w.executor, w.cfg.IPTablesPath, natArgs...); err != nil {
		return err
	}
	if runtime.outboundIface == "" {
		return ensureIPTablesRule(w.executor, w.cfg.IPTablesPath, "-A", "FORWARD", "-i", runtime.tunName, "-j", "ACCEPT")
	}
	return ensureIPTablesRule(w.executor, w.cfg.IPTablesPath, "-A", "FORWARD", "-i", runtime.tunName, "-o", runtime.outboundIface, "-j", "ACCEPT")
}

func (w *WireGuard) cleanupExitNAT(runtime *gostRuntime) {
	if runtime == nil || w.cfg.IPTablesPath == "" {
		return
	}
	natArgs := []string{"-t", "nat", "-D", "POSTROUTING", "-s", runtime.sourceCIDR}
	if runtime.outboundIface != "" {
		natArgs = append(natArgs, "-o", runtime.outboundIface)
	}
	natArgs = append(natArgs, "-j", "MASQUERADE")
	_ = w.executor.Run(w.cfg.IPTablesPath, natArgs...)
	if runtime.outboundIface == "" {
		_ = w.executor.Run(w.cfg.IPTablesPath, "-D", "FORWARD", "-i", runtime.tunName, "-j", "ACCEPT")
		return
	}
	_ = w.executor.Run(w.cfg.IPTablesPath, "-D", "FORWARD", "-i", runtime.tunName, "-o", runtime.outboundIface, "-j", "ACCEPT")
}

func ensureIPTablesRule(executor commandExecutor, path string, args ...string) error {
	checkArgs := make([]string, len(args))
	copy(checkArgs, args)
	for i, arg := range checkArgs {
		if arg == "-A" {
			checkArgs[i] = "-C"
			break
		}
	}
	if err := executor.Run(path, checkArgs...); err == nil {
		return nil
	}
	return executor.Run(path, args...)
}

func renderConfig(state *nodeState) string {
	n := state.info.WireGuard
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + n.ServerPrivateKey + "\n")
	b.WriteString("ListenPort = " + strconv.Itoa(state.info.Common.ServerPort) + "\n")

	users := make([]panel.UserInfo, 0, len(state.users))
	for _, user := range state.users {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].WireGuardPeerIP < users[j].WireGuardPeerIP
	})
	for _, user := range users {
		b.WriteString("\n[Peer]\n")
		b.WriteString("PublicKey = " + user.WireGuardPublicKey + "\n")
		if user.WireGuardPresharedKey != "" {
			b.WriteString("PresharedKey = " + user.WireGuardPresharedKey + "\n")
		}
		b.WriteString("AllowedIPs = " + peerAllowedIP(user.WireGuardPeerIP) + "\n")
	}
	return b.String()
}

func validateWireGuardUser(user panel.UserInfo) error {
	if strings.TrimSpace(user.Uuid) == "" {
		return errors.New("wireguard user uuid is required")
	}
	if strings.TrimSpace(user.WireGuardPeerIP) == "" {
		return fmt.Errorf("wireguard peer_ip is required for user %s", user.Uuid)
	}
	if strings.TrimSpace(user.WireGuardPublicKey) == "" {
		return fmt.Errorf("wireguard public_key is required for user %s", user.Uuid)
	}
	return nil
}

func interfaceName(tag string) string {
	sum := sha1.Sum([]byte(tag))
	return "wg" + hex.EncodeToString(sum[:])[:13]
}

func gostTunName(tag string) string {
	sum := sha1.Sum([]byte(tag + ":gost"))
	return "gt" + hex.EncodeToString(sum[:])[:13]
}

func relayRoutingTable(tag string, configured int) int {
	if configured > 0 {
		return configured
	}
	sum := sha1.Sum([]byte(tag + ":table"))
	return 30000 + int(sum[0])<<8 + int(sum[1])
}

func relayRoutingPriority(tag string, configured int) int {
	if configured > 0 {
		return configured
	}
	return relayRoutingTable(tag, 0)
}

func wireGuardMTU(n *panel.WireGuardNode) int {
	if n != nil && n.MTU > 0 {
		return n.MTU
	}
	return 1280
}

func wireGuardRelayRole(n *panel.WireGuardNode) string {
	if n == nil {
		return "entry"
	}
	role := strings.ToLower(strings.TrimSpace(n.Relay.Role))
	if role == "exit" {
		return "exit"
	}
	return "entry"
}

func wireGuardGostMode(n *panel.WireGuardNode) (string, error) {
	if n == nil {
		return "relay+quic", nil
	}
	tunnelType := strings.ToLower(strings.TrimSpace(n.TunnelType))
	mode := strings.ToLower(strings.TrimSpace(n.Relay.Mode))
	if tunnelType == "" && mode != "" {
		if strings.Contains(mode, "wss") {
			tunnelType = "wss"
		} else if strings.Contains(mode, "quic") {
			tunnelType = "quic"
		}
	}
	if n.Relay.WSSCompat {
		tunnelType = "wss"
	}
	switch tunnelType {
	case "", "quic":
		return "relay+quic", nil
	case "wss":
		return "relay+wss", nil
	default:
		return "", fmt.Errorf("wireguard tunnel_type %q is not supported by first relay runtime", n.TunnelType)
	}
}

func relayTunAddress(n *panel.WireGuardNode, role string) string {
	if n == nil {
		return ""
	}
	if role == "exit" {
		if v := strings.TrimSpace(n.Relay.ExitTunAddress); v != "" {
			return v
		}
	} else if v := strings.TrimSpace(n.Relay.EntryTunAddress); v != "" {
		return v
	}
	return strings.TrimSpace(n.Relay.TunAddress)
}

func relayTunIP(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	if strings.Contains(address, "/") {
		ip, _, err := net.ParseCIDR(address)
		if err == nil && ip != nil {
			return ip.String()
		}
	}
	return address
}

func peerAllowedIP(peerIP string) string {
	peerIP = strings.TrimSpace(peerIP)
	if strings.Contains(peerIP, "/") {
		return peerIP
	}
	if strings.Contains(peerIP, ":") {
		return peerIP + "/128"
	}
	return peerIP + "/32"
}

func parseTransferOutput(out []byte) map[string]trafficPair {
	result := make(map[string]trafficPair)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		rx, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		tx, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			continue
		}
		result[fields[0]] = trafficPair{
			upload:   rx,
			download: tx,
		}
	}
	return result
}

func parseDumpOnline(out []byte, publicKeyToUID map[string]int, now, timeoutSeconds int64) []panel.OnlineUser {
	if timeoutSeconds <= 0 {
		return nil
	}
	online := make([]panel.OnlineUser, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		uid := publicKeyToUID[fields[0]]
		if uid == 0 {
			continue
		}
		ip := endpointIP(fields[2])
		if ip == "" {
			continue
		}
		latestHandshake, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil || latestHandshake <= 0 {
			continue
		}
		if now >= latestHandshake && now-latestHandshake > timeoutSeconds {
			continue
		}
		online = append(online, panel.OnlineUser{UID: uid, IP: ip})
	}
	return online
}

func endpointIP(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || endpoint == "(none)" {
		return ""
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	if strings.HasPrefix(endpoint, "[") {
		if end := strings.Index(endpoint, "]"); end > 1 {
			return endpoint[1:end]
		}
	}
	if strings.Count(endpoint, ":") == 1 {
		host, _, _ = strings.Cut(endpoint, ":")
		return host
	}
	return strings.Trim(endpoint, "[]")
}
