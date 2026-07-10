package conf

import (
	"path/filepath"
	"testing"
)

func TestConf_LoadFromPath(t *testing.T) {
	c := New()
	if err := c.LoadFromPath("../example/config.json"); err != nil {
		t.Fatalf("LoadFromPath() error = %v", err)
	}
	if len(c.NodeConfig) == 0 {
		t.Fatal("LoadFromPath() loaded no nodes")
	}
}

func TestConf_LoadWireGuardConfigPreservesExplicitCore(t *testing.T) {
	c := New()
	if err := c.LoadFromPath("../example/config.wireguard.json"); err != nil {
		t.Fatalf("LoadFromPath() error = %v", err)
	}
	if len(c.NodeConfig) != 1 {
		t.Fatalf("LoadFromPath() nodes = %d, want 1", len(c.NodeConfig))
	}
	node := c.NodeConfig[0]
	if node.Options.Core != "wireguard" {
		t.Fatalf("Options.Core = %q, want wireguard", node.Options.Core)
	}
	if node.ApiConfig.NodeType != "wireguard" {
		t.Fatalf("ApiConfig.NodeType = %q, want wireguard", node.ApiConfig.NodeType)
	}
}

func TestConf_WatchMissingFile(t *testing.T) {
	c := New()
	err := c.Watch(filepath.Join(t.TempDir(), "missing.json"), "", "", func() {})
	if err == nil {
		t.Fatal("Watch() missing file error = nil")
	}
}
