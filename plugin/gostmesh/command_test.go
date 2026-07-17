package gostmesh

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestBuildCommandSpecsBuildsPinnedGostV3WSSAndQUIC(t *testing.T) {
	entry := validEntry()
	exit := validExit()
	exit.Transport = "quic"
	exit.WSSPath = ""
	commands, err := BuildCommandSpecs(validConfig(entry, exit), "/opt/anix ops/gost")
	if err != nil {
		t.Fatalf("BuildCommandSpecs() error = %v", err)
	}
	if len(commands) != 2 {
		t.Fatalf("len(commands) = %d, want 2", len(commands))
	}

	entryCommand := commands[0]
	if entryCommand.TunnelID != entry.ID || entryCommand.Binary != "/opt/anix ops/gost" {
		t.Fatalf("entry command = %#v", entryCommand)
	}
	if len(entryCommand.Args) != 4 || entryCommand.Args[0] != "-L" || entryCommand.Args[2] != "-F" {
		t.Fatalf("entry args = %#v", entryCommand.Args)
	}
	entryTUN := mustParseURL(t, entryCommand.Args[1])
	if entryTUN.Scheme != "tun" || entryTUN.Host != ":0" || entryTUN.Path != "/:8421" {
		t.Fatalf("entry TUN URL = %s", entryTUN.String())
	}
	assertQuery(t, entryTUN, map[string]string{
		"net": "172.31.66.2/30", "peer": "172.31.66.1", "name": "anxwss0", "mtu": "1280",
	})
	entryRelay := mustParseURL(t, entryCommand.Args[3])
	if entryRelay.Scheme != "relay+wss" || entryRelay.Host != "exit.example.com:443" {
		t.Fatalf("entry relay URL = %s", entryRelay.String())
	}
	assertQuery(t, entryRelay, map[string]string{
		"secure": "true", "caFile": "/etc/anixops/ca bundle.pem", "certFile": "/etc/anixops/client cert.pem",
		"keyFile": "/etc/anixops/client key.pem", "serverName": "exit.example.com", "path": "/mesh path",
	})
	if !strings.Contains(entryCommand.Args[3], "caFile=%2Fetc%2Fanixops%2Fca+bundle.pem") ||
		!strings.Contains(entryCommand.Args[3], "path=%2Fmesh+path") {
		t.Fatalf("entry relay query was not safely encoded: %s", entryCommand.Args[3])
	}

	exitCommand := commands[1]
	if exitCommand.TunnelID != exit.ID || len(exitCommand.Args) != 4 || exitCommand.Args[0] != "-L" || exitCommand.Args[2] != "-L" {
		t.Fatalf("exit command = %#v", exitCommand)
	}
	exitTUN := mustParseURL(t, exitCommand.Args[1])
	if exitTUN.Scheme != "tun" || exitTUN.Host != ":8421" || exitTUN.Path != "" {
		t.Fatalf("exit TUN URL = %s", exitTUN.String())
	}
	assertQuery(t, exitTUN, map[string]string{
		"net": "172.31.68.1/30", "peer": "172.31.68.2", "gw": "172.31.68.2", "name": "anxwss1",
		"mtu": "1280", "route": "10.68.0.0/24,10.69.0.0/24",
	})
	exitRelay := mustParseURL(t, exitCommand.Args[3])
	if exitRelay.Scheme != "relay+quic" || exitRelay.Host != "0.0.0.0:443" {
		t.Fatalf("exit relay URL = %s", exitRelay.String())
	}
	assertQuery(t, exitRelay, map[string]string{
		"bind": "true", "caFile": "/etc/anixops/ca bundle.pem",
		"certFile": "/etc/anixops/server cert.pem", "keyFile": "/etc/anixops/server key.pem",
	})
	if entryRelay.User != nil || exitRelay.User != nil {
		t.Fatal("relay credentials must not be embedded in process arguments")
	}
	for _, forbidden := range []string{"masquerade", "iptables", "nft", "secure", "serverName", "path"} {
		if strings.Contains(exitCommand.Args[3], forbidden) {
			t.Fatalf("exit relay URL contains forbidden %q: %s", forbidden, exitCommand.Args[3])
		}
	}
}

func TestBuildCommandSpecsRejectsInvalidInputAndSupportsObservationMode(t *testing.T) {
	observation := Config{APIVersion: APIVersion, Apply: false, RollbackOnExit: true, Tunnels: []Tunnel{}}
	commands, err := BuildCommandSpecs(observation, "gost")
	if err != nil || len(commands) != 0 {
		t.Fatalf("BuildCommandSpecs(observation) = %#v, %v", commands, err)
	}
	for _, binary := range []string{"", "gost\n--api"} {
		if _, err := BuildCommandSpecs(validConfig(validEntry()), binary); err == nil || !strings.Contains(err.Error(), "binary is invalid") {
			t.Fatalf("BuildCommandSpecs(binary=%q) error = %v", binary, err)
		}
	}
	invalid := validConfig(validEntry())
	invalid.Tunnels[0].Transport = "tuic"
	if _, err := BuildCommandSpecs(invalid, "gost"); err == nil || !strings.Contains(err.Error(), "quic or wss") {
		t.Fatalf("BuildCommandSpecs(invalid config) error = %v", err)
	}
}

func mustParseURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", value, err)
	}
	return parsed
}

func assertQuery(t *testing.T, parsed *url.URL, expected map[string]string) {
	t.Helper()
	actual := make(map[string]string)
	for key, values := range parsed.Query() {
		if len(values) != 1 {
			t.Fatalf("query %q = %#v, want one value", key, values)
		}
		actual[key] = values[0]
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("query = %#v, want %#v", actual, expected)
	}
}
