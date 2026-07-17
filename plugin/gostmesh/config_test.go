package gostmesh

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseConfigAcceptsV1RolesAndObservationMode(t *testing.T) {
	t.Run("entry and exit", func(t *testing.T) {
		config := validConfig(validEntry(), validExit())
		contents := mustJSON(t, config)
		parsed, err := ParseConfig(contents)
		if err != nil {
			t.Fatalf("ParseConfig() error = %v", err)
		}
		if !parsed.Apply || !parsed.RollbackOnExit || len(parsed.Tunnels) != 2 {
			t.Fatalf("ParseConfig() = %#v", parsed)
		}
		if parsed.Tunnels[0].Role != "entry" || parsed.Tunnels[0].Transport != "wss" {
			t.Fatalf("entry contract changed: %#v", parsed.Tunnels[0])
		}
	})

	t.Run("apply false permits explicit empty array", func(t *testing.T) {
		parsed, err := ParseConfig([]byte(`{
  "api_version":"anixops.gost-mesh/v1",
  "apply":false,
  "rollback_on_exit":true,
  "tunnels":[]
}`))
		if err != nil {
			t.Fatalf("ParseConfig() error = %v", err)
		}
		if parsed.Apply || len(parsed.Tunnels) != 0 {
			t.Fatalf("ParseConfig() = %#v", parsed)
		}
	})
}

func TestParseConfigRejectsNonCanonicalSignedValues(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(*Tunnel)
		message string
	}{
		{name: "role whitespace", mutate: func(tunnel *Tunnel) { tunnel.Role = " entry" }, message: "role must be"},
		{name: "transport case", mutate: func(tunnel *Tunnel) { tunnel.Transport = "WSS" }, message: "transport must be"},
		{name: "CIDR whitespace", mutate: func(tunnel *Tunnel) { tunnel.Routing.SourceCIDRs[0] += " " }, message: "IPv4 CIDR"},
		{name: "health target whitespace", mutate: func(tunnel *Tunnel) { tunnel.Health.Target += " " }, message: "health.target"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tunnel := validEntry()
			test.mutate(&tunnel)
			_, err := ParseConfig(mustJSON(t, validConfig(tunnel)))
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("ParseConfig() error = %v, want substring %q", err, test.message)
			}
		})
	}
}

func TestConfigJSONUsesFrozenEndpointFieldNames(t *testing.T) {
	contents := string(mustJSON(t, validConfig(validEntry())))
	if !strings.Contains(contents, `"peer_address":"172.31.66.1"`) || !strings.Contains(contents, `"host":"exit.example.com"`) {
		t.Fatalf("serialized config does not use the frozen endpoint field names: %s", contents)
	}
	if strings.Contains(contents, `"peer":`) || strings.Contains(contents, `"remote":{"address":`) {
		t.Fatalf("serialized config contains obsolete endpoint field names: %s", contents)
	}
}

func TestParseConfigRejectsInvalidTopLevelContract(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		message string
	}{
		{name: "null", config: `null`, message: "JSON object"},
		{name: "apply missing", config: `{"api_version":"anixops.gost-mesh/v1","rollback_on_exit":true,"tunnels":[]}`, message: "apply must be declared"},
		{name: "rollback missing", config: `{"api_version":"anixops.gost-mesh/v1","apply":false,"tunnels":[]}`, message: "rollback_on_exit must be declared"},
		{name: "wrong API", config: `{"api_version":"v0","apply":false,"rollback_on_exit":true,"tunnels":[]}`, message: "api_version"},
		{name: "rollback disabled", config: `{"api_version":"anixops.gost-mesh/v1","apply":false,"rollback_on_exit":false,"tunnels":[]}`, message: "rollback_on_exit must remain enabled"},
		{name: "apply without tunnel", config: `{"api_version":"anixops.gost-mesh/v1","apply":true,"rollback_on_exit":true,"tunnels":[]}`, message: "requires at least one tunnel"},
		{name: "null tunnels", config: `{"api_version":"anixops.gost-mesh/v1","apply":false,"rollback_on_exit":true,"tunnels":null}`, message: "declared as an array"},
		{name: "unknown field", config: `{"api_version":"anixops.gost-mesh/v1","apply":false,"rollback_on_exit":true,"tunnels":[],"packet_mark":10}`, message: "unknown field"},
		{name: "trailing object", config: `{"api_version":"anixops.gost-mesh/v1","apply":false,"rollback_on_exit":true,"tunnels":[]} {}`, message: "exactly one JSON object"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(test.config))
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("ParseConfig() error = %v, want substring %q", err, test.message)
			}
		})
	}
}

func TestParseConfigRejectsUnknownNestedField(t *testing.T) {
	contents := string(mustJSON(t, validConfig(validEntry())))
	contents = strings.Replace(contents, `"mtu":1280`, `"mtu":1280,"packet_mark":10`, 1)
	_, err := ParseConfig([]byte(contents))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("ParseConfig() error = %v, want unknown field", err)
	}
}

func TestTunnelRoleIsolation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Tunnel)
		message string
	}{
		{name: "entry missing remote", mutate: func(v *Tunnel) { v.Remote = nil }, message: "entry requires remote"},
		{name: "entry leaked listen", mutate: func(v *Tunnel) { v.Listen = &ListenEndpoint{Address: "0.0.0.0", Port: 443} }, message: "must not declare listen"},
		{name: "entry missing source", mutate: func(v *Tunnel) { v.Routing.SourceCIDRs = nil }, message: "requires routing.source_cidrs"},
		{name: "entry leaked routes", mutate: func(v *Tunnel) { v.Routing.RouteCIDRs = []string{"10.67.0.0/24"} }, message: "must not declare routing.route_cidrs"},
		{name: "entry missing CA", mutate: func(v *Tunnel) { v.TLS.CAFile = "" }, message: "tls.ca_file is required"},
		{name: "entry missing SNI", mutate: func(v *Tunnel) { v.TLS.ServerName = "" }, message: "valid tls.server_name"},
		{name: "entry missing client cert", mutate: func(v *Tunnel) { v.TLS.CertFile = "" }, message: "tls.cert_file is required"},
		{name: "entry missing client key", mutate: func(v *Tunnel) { v.TLS.KeyFile = "" }, message: "tls.key_file is required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tunnel := validEntry()
			test.mutate(&tunnel)
			assertInvalidTunnel(t, tunnel, test.message)
		})
	}

	exitTests := []struct {
		name    string
		mutate  func(*Tunnel)
		message string
	}{
		{name: "exit missing listen", mutate: func(v *Tunnel) { v.Listen = nil }, message: "exit requires listen"},
		{name: "exit leaked remote", mutate: func(v *Tunnel) { v.Remote = &RemoteEndpoint{Address: "entry.example.com", Port: 443} }, message: "must not declare remote"},
		{name: "exit missing routes", mutate: func(v *Tunnel) { v.Routing.RouteCIDRs = nil }, message: "requires routing.route_cidrs"},
		{name: "exit leaked sources", mutate: func(v *Tunnel) { v.Routing.SourceCIDRs = []string{"10.66.0.0/24"} }, message: "must not declare routing.source_cidrs"},
		{name: "exit leaked routing table", mutate: func(v *Tunnel) { v.Routing.Table = 203 }, message: "must be omitted or 0"},
		{name: "exit leaked routing priority", mutate: func(v *Tunnel) { v.Routing.Priority = 12012 }, message: "must be omitted or 0"},
		{name: "exit missing cert", mutate: func(v *Tunnel) { v.TLS.CertFile = "" }, message: "tls.cert_file is required"},
		{name: "exit missing key", mutate: func(v *Tunnel) { v.TLS.KeyFile = "" }, message: "tls.key_file is required"},
		{name: "exit missing client CA", mutate: func(v *Tunnel) { v.TLS.CAFile = "" }, message: "tls.ca_file is required"},
		{name: "exit leaked SNI", mutate: func(v *Tunnel) { v.TLS.ServerName = "exit.example.com" }, message: "must not declare tls.server_name"},
	}
	for _, test := range exitTests {
		t.Run(test.name, func(t *testing.T) {
			tunnel := validExit()
			test.mutate(&tunnel)
			assertInvalidTunnel(t, tunnel, test.message)
		})
	}
}

func TestTunnelValidationRejectsUnsafeNetworkTLSAndHealth(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Tunnel)
		message string
	}{
		{name: "TUIC is unsupported", mutate: func(v *Tunnel) { v.Transport = "tuic" }, message: "quic or wss"},
		{name: "IPv6 TUN", mutate: func(v *Tunnel) { v.TUN.Address = "fd00::2/64" }, message: "IPv4 prefix"},
		{name: "peer outside network", mutate: func(v *Tunnel) { v.TUN.Peer = "172.31.67.1" }, message: "in tun.address network"},
		{name: "network address as host", mutate: func(v *Tunnel) { v.TUN.Address = "172.31.66.0/30" }, message: "usable host"},
		{name: "broadcast peer", mutate: func(v *Tunnel) { v.TUN.Peer = "172.31.66.3" }, message: "different usable host"},
		{name: "invalid interface", mutate: func(v *Tunnel) { v.TUN.Name = "../../tun" }, message: "tun.name is invalid"},
		{name: "bad TUN port", mutate: func(v *Tunnel) { v.TUN.Port = 0 }, message: "tun.port"},
		{name: "bad MTU", mutate: func(v *Tunnel) { v.TUN.MTU = 200 }, message: "tun.mtu"},
		{name: "noncanonical source", mutate: func(v *Tunnel) { v.Routing.SourceCIDRs = []string{"10.66.0.1/24"} }, message: "canonical network"},
		{name: "IPv6 source", mutate: func(v *Tunnel) { v.Routing.SourceCIDRs = []string{"fd00::/64"} }, message: "IPv4 CIDR"},
		{name: "priority range overflow", mutate: func(v *Tunnel) {
			v.Routing.Priority = maxPriority
			v.Routing.SourceCIDRs = []string{"10.66.0.0/25", "10.66.0.128/25"}
		}, message: "priority range"},
		{name: "relative CA", mutate: func(v *Tunnel) { v.TLS.CAFile = "ca.pem" }, message: "clean absolute"},
		{name: "unclean CA", mutate: func(v *Tunnel) { v.TLS.CAFile = "/etc/anixops/../ca.pem" }, message: "clean absolute"},
		{name: "invalid WSS path", mutate: func(v *Tunnel) { v.WSSPath = "/mesh?token=leak" }, message: "without query"},
		{name: "QUIC with WSS path", mutate: func(v *Tunnel) { v.Transport = "quic" }, message: "only valid for the wss"},
		{name: "IPv6 remote", mutate: func(v *Tunnel) { v.Remote.Address = "2001:db8::1" }, message: "IPv4 address or DNS"},
		{name: "timeout not below interval", mutate: func(v *Tunnel) { v.Health.TimeoutSeconds = v.Health.IntervalSeconds }, message: "less than"},
		{name: "missing health target", mutate: func(v *Tunnel) { v.Health.Target = "" }, message: "target is required"},
		{name: "missing health source", mutate: func(v *Tunnel) { v.Health.SourceAddress = "" }, message: "source_address is required"},
		{name: "health source outside policy", mutate: func(v *Tunnel) { v.Health.SourceAddress = "10.99.0.1" }, message: "belong to routing.source_cidrs"},
		{name: "IPv6 health target", mutate: func(v *Tunnel) { v.Health.Target = "[2001:db8::1]:443" }, message: "use IPv4"},
		{name: "loopback health target", mutate: func(v *Tunnel) { v.Health.Target = "127.0.0.1:443" }, message: "use IPv4"},
		{name: "link-local health target", mutate: func(v *Tunnel) { v.Health.Target = "169.254.1.1:443" }, message: "use IPv4"},
		{name: "multicast health target", mutate: func(v *Tunnel) { v.Health.Target = "224.0.0.1:443" }, message: "use IPv4"},
		{name: "unspecified health target", mutate: func(v *Tunnel) { v.Health.Target = "0.0.0.0:443" }, message: "use IPv4"},
		{name: "this-network health target", mutate: func(v *Tunnel) { v.Health.Target = "0.1.2.3:443" }, message: "use IPv4"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tunnel := validEntry()
			test.mutate(&tunnel)
			assertInvalidTunnel(t, tunnel, test.message)
		})
	}
}

func TestConfigRejectsCIDRArraysAboveSchemaLimit(t *testing.T) {
	tunnel := validEntry()
	tunnel.Routing.SourceCIDRs = make([]string, maxCIDRs+1)
	for index := range tunnel.Routing.SourceCIDRs {
		tunnel.Routing.SourceCIDRs[index] = "10." + strconv.Itoa(index/256) + "." + strconv.Itoa(index%256) + ".0/32"
	}
	tunnel.Health.SourceAddress = tunnel.Routing.SourceCIDRs[0][:len(tunnel.Routing.SourceCIDRs[0])-3]
	assertInvalidTunnel(t, tunnel, "exceeds 128 entries")
}

func TestConfigRejectsCrossTunnelConflicts(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Tunnel, *Tunnel)
		message string
	}{
		{name: "ID", mutate: func(first, second *Tunnel) { second.ID = first.ID }, message: "id \"wss-entry\" is duplicated"},
		{name: "TUN name", mutate: func(first, second *Tunnel) { second.TUN.Name = first.TUN.Name }, message: "same TUN name"},
		{name: "TUN network", mutate: func(first, second *Tunnel) { second.TUN.Address = "172.31.66.6/29"; second.TUN.Peer = "172.31.66.5" }, message: "overlapping TUN networks"},
		{name: "routing table", mutate: func(first, second *Tunnel) { second.Routing.Table = first.Routing.Table }, message: "same routing table"},
		{name: "routing priority", mutate: func(first, second *Tunnel) { second.Routing.Priority = first.Routing.Priority }, message: "same routing priority"},
		{name: "routing priority range", mutate: func(first, second *Tunnel) {
			first.Routing.SourceCIDRs = []string{"10.66.0.0/25", "10.66.0.128/25"}
			second.Routing.Priority = first.Routing.Priority + 1
		}, message: "same routing priority"},
		{name: "source CIDR", mutate: func(first, second *Tunnel) {
			second.Routing.SourceCIDRs = []string{"10.66.0.128/25"}
			second.Health.SourceAddress = "10.66.0.129"
		}, message: "overlapping source CIDRs"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := validEntry()
			second := secondEntry()
			test.mutate(&first, &second)
			config := validConfig(first, second)
			err := config.Validate()
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.message)
			}
		})
	}

	t.Run("exit TUN port", func(t *testing.T) {
		first, second := validExit(), secondExit()
		second.TUN.Port = first.TUN.Port
		assertInvalidConfig(t, validConfig(first, second), "same TUN port")
	})
	t.Run("wildcard listener", func(t *testing.T) {
		first, second := validExit(), secondExit()
		second.Listen.Port = first.Listen.Port
		assertInvalidConfig(t, validConfig(first, second), "conflicting wss listeners")
	})
	t.Run("same numeric TCP and UDP port is allowed", func(t *testing.T) {
		first, second := validExit(), secondExit()
		second.Transport = "quic"
		second.WSSPath = ""
		second.Listen.Port = first.Listen.Port
		if err := validConfig(first, second).Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})
}

func TestLoadConfigRejectsUnsafeConfigFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "gost-mesh.json")
	if err := os.WriteFile(path, mustJSON(t, validConfig(validEntry())), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "writable by group") {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(path, link); err == nil {
		if _, err := LoadConfig(link); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("LoadConfig(symlink) error = %v", err)
		}
	}
}

func validConfig(tunnels ...Tunnel) Config {
	return Config{
		APIVersion:     APIVersion,
		Apply:          true,
		RollbackOnExit: true,
		Tunnels:        tunnels,
	}
}

func validEntry() Tunnel {
	return Tunnel{
		ID:        "wss-entry",
		Role:      "entry",
		Transport: "wss",
		TUN: TUNConfig{
			Name: "anxwss0", Address: "172.31.66.2/30", Peer: "172.31.66.1", Port: 8421, MTU: 1280,
		},
		Routing: RoutingConfig{
			SourceCIDRs: []string{"10.66.0.0/24"}, RouteCIDRs: []string{}, Table: 201, Priority: 12010,
		},
		Remote: &RemoteEndpoint{Address: "exit.example.com", Port: 443},
		TLS: TLSConfig{
			CAFile: "/etc/anixops/ca bundle.pem", CertFile: "/etc/anixops/client cert.pem",
			KeyFile: "/etc/anixops/client key.pem", ServerName: "exit.example.com",
		},
		WSSPath: "/mesh path",
		Health: HealthConfig{
			Enabled: true, Target: "1.1.1.1:443", SourceAddress: "10.66.0.1", IntervalSeconds: 15, TimeoutSeconds: 3,
			FailureThreshold: 3, RestartDelaySeconds: 2, RestartLimit: 5,
		},
	}
}

func secondEntry() Tunnel {
	tunnel := validEntry()
	tunnel.ID = "quic-entry-two"
	tunnel.Transport = "quic"
	tunnel.TUN = TUNConfig{Name: "anxquic1", Address: "172.31.67.2/30", Peer: "172.31.67.1", Port: 8422, MTU: 1280}
	tunnel.Routing = RoutingConfig{SourceCIDRs: []string{"10.67.0.0/24"}, RouteCIDRs: []string{}, Table: 202, Priority: 12011}
	tunnel.Remote = &RemoteEndpoint{Address: "203.0.113.10", Port: 8443}
	tunnel.Health.SourceAddress = "10.67.0.1"
	tunnel.WSSPath = ""
	return tunnel
}

func validExit() Tunnel {
	return Tunnel{
		ID:        "wss-exit",
		Role:      "exit",
		Transport: "wss",
		TUN: TUNConfig{
			Name: "anxwss1", Address: "172.31.68.1/30", Peer: "172.31.68.2", Port: 8421, MTU: 1280,
		},
		Routing: RoutingConfig{
			SourceCIDRs: []string{}, RouteCIDRs: []string{"10.68.0.0/24", "10.69.0.0/24"}, Table: 0, Priority: 0,
		},
		Listen: &ListenEndpoint{Address: "0.0.0.0", Port: 443},
		TLS: TLSConfig{
			CAFile: "/etc/anixops/ca bundle.pem", CertFile: "/etc/anixops/server cert.pem",
			KeyFile: "/etc/anixops/server key.pem",
		},
		WSSPath: "/mesh path",
		Health: HealthConfig{
			Enabled: false, Target: "", SourceAddress: "", IntervalSeconds: 15, TimeoutSeconds: 3,
			FailureThreshold: 3, RestartDelaySeconds: 2, RestartLimit: 5,
		},
	}
}

func secondExit() Tunnel {
	tunnel := validExit()
	tunnel.ID = "wss-exit-two"
	tunnel.TUN = TUNConfig{Name: "anxwss2", Address: "172.31.69.1/30", Peer: "172.31.69.2", Port: 8422, MTU: 1280}
	tunnel.Routing = RoutingConfig{SourceCIDRs: []string{}, RouteCIDRs: []string{"10.70.0.0/24"}, Table: 0, Priority: 0}
	tunnel.Listen = &ListenEndpoint{Address: "192.0.2.10", Port: 8443}
	return tunnel
}

func assertInvalidTunnel(t *testing.T, tunnel Tunnel, message string) {
	t.Helper()
	assertInvalidConfig(t, validConfig(tunnel), message)
}

func assertInvalidConfig(t *testing.T, config Config, message string) {
	t.Helper()
	err := config.Validate()
	if err == nil || !strings.Contains(err.Error(), message) {
		t.Fatalf("Validate() error = %v, want substring %q", err, message)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	contents, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
