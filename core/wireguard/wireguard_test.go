package wireguard

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
)

type fakeExecutor struct {
	commands     []string
	starts       []string
	outputs      map[string][]byte
	failContains []string
}

func (f *fakeExecutor) Run(name string, args ...string) error {
	cmd := name + " " + strings.Join(args, " ")
	f.commands = append(f.commands, cmd)
	if strings.Contains(cmd, " link show ") {
		return errors.New("missing")
	}
	for _, pattern := range f.failContains {
		if strings.Contains(cmd, pattern) {
			return errors.New("forced failure")
		}
	}
	return nil
}

func (f *fakeExecutor) Output(name string, args ...string) ([]byte, error) {
	if f.outputs == nil {
		return nil, nil
	}
	return f.outputs[name+" "+strings.Join(args, " ")], nil
}

func (f *fakeExecutor) Start(name string, args ...string) (process, error) {
	f.starts = append(f.starts, name+" "+strings.Join(args, " "))
	return fakeProcess{}, nil
}

type fakeProcess struct{}

func (fakeProcess) Stop() error { return nil }

func TestWireGuard_AddNodeAndUsersApplyConfig(t *testing.T) {
	exec := &fakeExecutor{}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir: t.TempDir(),
			WGPath:     "wg",
			IPPath:     "ip",
			GostPath:   "gost",
		},
		executor: exec,
		nodes:    make(map[string]*nodeState),
	}
	node := testNodeInfo()

	if err := core.AddNode("test-node", node, &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	added, err := core.AddUsers(&vCore.AddUsersParams{
		Tag:      "test-node",
		NodeInfo: node,
		Users: []panel.UserInfo{{
			Id:                    1,
			Uuid:                  "user-1",
			WireGuardPeerIP:       "10.66.0.2",
			WireGuardPublicKey:    "peer-public",
			WireGuardPresharedKey: "psk",
		}},
	})
	if err != nil {
		t.Fatalf("AddUsers() error = %v", err)
	}
	if added != 1 {
		t.Fatalf("AddUsers() added = %d, want 1", added)
	}

	rendered := renderConfig(core.nodes["test-node"])
	for _, want := range []string{
		"PrivateKey = server-private",
		"ListenPort = 51820",
		"PublicKey = peer-public",
		"PresharedKey = psk",
		"AllowedIPs = 10.66.0.2/32",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered config missing %q:\n%s", want, rendered)
		}
	}
	joined := strings.Join(exec.commands, "\n")
	for _, want := range []string{
		"ip link add",
		"ip address add 10.66.0.1/24",
		"wg setconf",
		"ip link set up",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commands missing %q:\n%s", want, joined)
		}
	}
}

func TestWireGuard_AddUsersRejectsMissingPeer(t *testing.T) {
	core := &WireGuard{
		cfg:      conf.NewWireGuardConfig(),
		executor: &fakeExecutor{},
		nodes: map[string]*nodeState{
			"test-node": {
				tag:   "test-node",
				iface: "wgtest",
				info:  testNodeInfo(),
				users: make(map[string]panel.UserInfo),
			},
		},
	}

	_, err := core.AddUsers(&vCore.AddUsersParams{
		Tag: "test-node",
		Users: []panel.UserInfo{{
			Uuid:               "user-1",
			WireGuardPublicKey: "peer-public",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "peer_ip") {
		t.Fatalf("AddUsers() error = %v, want peer_ip error", err)
	}
}

func TestWireGuard_GetUserTrafficSliceParsesTransferDeltas(t *testing.T) {
	exec := &fakeExecutor{
		outputs: map[string][]byte{
			"wg show wgtest transfer": []byte("peer-public 1000 2000\n"),
		},
	}
	core := &WireGuard{
		cfg:      conf.NewWireGuardConfig(),
		executor: exec,
		nodes: map[string]*nodeState{
			"test-node": {
				tag:     "test-node",
				iface:   "wgtest",
				info:    testNodeInfo(),
				users:   make(map[string]panel.UserInfo),
				cfgPath: "unused",
			},
		},
		traffic: make(map[string]map[string]trafficPair),
	}
	core.nodes["test-node"].users["user-1"] = panel.UserInfo{
		Id:                 7,
		Uuid:               "user-1",
		WireGuardPublicKey: "peer-public",
	}

	first, err := core.GetUserTrafficSlice("test-node", true)
	if err != nil {
		t.Fatalf("GetUserTrafficSlice() error = %v", err)
	}
	if len(first) != 1 || first[0].UID != 7 || first[0].Upload != 1000 || first[0].Download != 2000 {
		t.Fatalf("first traffic = %#v", first)
	}

	exec.outputs["wg show wgtest transfer"] = []byte("peer-public 1700 2600\n")
	second, err := core.GetUserTrafficSlice("test-node", true)
	if err != nil {
		t.Fatalf("GetUserTrafficSlice() second error = %v", err)
	}
	if len(second) != 1 || second[0].Upload != 700 || second[0].Download != 600 {
		t.Fatalf("second traffic = %#v", second)
	}
}

func TestWireGuard_GetOnlineDeviceParsesRecentHandshake(t *testing.T) {
	now := time.Now().Unix()
	exec := &fakeExecutor{
		outputs: map[string][]byte{
			"wg show wgtest dump": []byte(strings.Join([]string{
				"server-private server-public 51820 off",
				"peer-public psk 203.0.113.10:51280 10.66.0.2/32 " + strconv.FormatInt(now-30, 10) + " 1000 2000 0",
				"old-peer psk 203.0.113.11:51280 10.66.0.3/32 " + strconv.FormatInt(now-600, 10) + " 1000 2000 0",
				"none-peer psk (none) 10.66.0.4/32 " + strconv.FormatInt(now-20, 10) + " 1000 2000 0",
				"unknown-peer psk 203.0.113.12:51280 10.66.0.5/32 " + strconv.FormatInt(now-20, 10) + " 1000 2000 0",
			}, "\n")),
		},
	}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			WGPath:                        "wg",
			OnlineHandshakeTimeoutSeconds: 180,
		},
		executor: exec,
		nodes: map[string]*nodeState{
			"test-node": {
				tag:   "test-node",
				iface: "wgtest",
				info:  testNodeInfo(),
				users: map[string]panel.UserInfo{
					"user-1": {Id: 7, Uuid: "user-1", WireGuardPublicKey: "peer-public"},
					"user-2": {Id: 8, Uuid: "user-2", WireGuardPublicKey: "old-peer"},
					"user-3": {Id: 9, Uuid: "user-3", WireGuardPublicKey: "none-peer"},
				},
			},
		},
	}

	online, err := core.GetOnlineDevice("test-node")
	if err != nil {
		t.Fatalf("GetOnlineDevice() error = %v", err)
	}
	if len(online) != 1 || online[0].UID != 7 || online[0].IP != "203.0.113.10" {
		t.Fatalf("online users = %#v", online)
	}
}

func TestParseDumpOnlineSupportsIPv6Endpoint(t *testing.T) {
	now := int64(1700000000)
	out := []byte("peer-public psk [2001:db8::1]:51280 10.66.0.2/32 1699999990 1000 2000 0\n")
	online := parseDumpOnline(out, map[string]int{"peer-public": 7}, now, 180)
	if len(online) != 1 || online[0].UID != 7 || online[0].IP != "2001:db8::1" {
		t.Fatalf("online users = %#v", online)
	}
}

func TestWireGuard_AddNodeStartsGostEntryAndPolicyRoute(t *testing.T) {
	exec := &fakeExecutor{}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir:   t.TempDir(),
			WGPath:       "wg",
			IPPath:       "ip",
			IPTablesPath: "iptables",
			SysctlPath:   "sysctl",
			GostPath:     "gost",
		},
		executor: exec,
		nodes:    make(map[string]*nodeState),
	}
	node := testNodeInfo()
	node.WireGuard.CIDR = "10.66.0.0/24"
	node.WireGuard.Relay = panel.WireGuardRelay{
		Backend:         "gost",
		Role:            "entry",
		Server:          "exit.example.com",
		ServerPort:      8443,
		TunPort:         8421,
		EntryTunAddress: "172.31.66.2/24",
		TunName:         "gtwgtest",
		RoutingTable:    32010,
		RoutingPriority: 12010,
	}

	if err := core.AddNode("test-node", node, &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}

	starts := strings.Join(exec.starts, "\n")
	for _, want := range []string{
		"gost -L tun://:0/:8421?net=172.31.66.2/24&name=gtwgtest&mtu=1280 -F relay+quic://exit.example.com:8443",
	} {
		if !strings.Contains(starts, want) {
			t.Fatalf("starts missing %q:\n%s", want, starts)
		}
	}
	joined := strings.Join(exec.commands, "\n")
	for _, want := range []string{
		"sysctl -w net.ipv4.ip_forward=1",
		"ip route replace default dev gtwgtest table 32010",
		"ip rule add from 10.66.0.0/24 table 32010 priority 12010",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commands missing %q:\n%s", want, joined)
		}
	}
}

func TestWireGuard_AddNodeStartsGostExitAndNAT(t *testing.T) {
	exec := &fakeExecutor{
		failContains: []string{"iptables -t nat -C", "iptables -C FORWARD"},
	}
	core := &WireGuard{
		cfg: &conf.WireGuardConfig{
			RuntimeDir:   t.TempDir(),
			WGPath:       "wg",
			IPPath:       "ip",
			IPTablesPath: "iptables",
			SysctlPath:   "sysctl",
			GostPath:     "gost",
		},
		executor: exec,
		nodes:    make(map[string]*nodeState),
	}
	node := testNodeInfo()
	node.WireGuard.CIDR = "10.66.0.0/24"
	node.WireGuard.Relay = panel.WireGuardRelay{
		Backend:         "gost",
		Role:            "exit",
		ServerPort:      8443,
		TunPort:         8421,
		EntryTunAddress: "172.31.66.2/24",
		ExitTunAddress:  "172.31.66.1/24",
		TunName:         "gtwgexit",
		ExitNAT:         true,
		OutboundIface:   "eth0",
	}

	if err := core.AddNode("exit-node", node, &conf.Options{}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}

	starts := strings.Join(exec.starts, "\n")
	for _, want := range []string{
		"gost -L tun://:8421?net=172.31.66.1/24&name=gtwgexit&mtu=1280&route=10.66.0.0/24&gw=172.31.66.2 -L relay+quic://:8443?bind=true",
	} {
		if !strings.Contains(starts, want) {
			t.Fatalf("starts missing %q:\n%s", want, starts)
		}
	}
	joined := strings.Join(exec.commands, "\n")
	for _, want := range []string{
		"iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE",
		"iptables -A FORWARD -i gtwgexit -o eth0 -j ACCEPT",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commands missing %q:\n%s", want, joined)
		}
	}
}

func testNodeInfo() *panel.NodeInfo {
	common := panel.CommonNode{
		Host:       "entry.example.com",
		ServerPort: 51820,
		ServerName: "entry.example.com",
	}
	wg := &panel.WireGuardNode{
		CommonNode:       common,
		CIDR:             "10.66.0.0/24",
		ServerAddress:    "10.66.0.1/24",
		ServerPrivateKey: "server-private",
		ServerPublicKey:  "server-public",
		MTU:              1280,
		TunnelType:       "quic",
	}
	return &panel.NodeInfo{
		Id:        1,
		Type:      "wireguard",
		Security:  panel.None,
		Common:    &common,
		WireGuard: wg,
	}
}
