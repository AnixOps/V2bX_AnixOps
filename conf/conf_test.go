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

func TestConf_WatchMissingFile(t *testing.T) {
	c := New()
	err := c.Watch(filepath.Join(t.TempDir(), "missing.json"), "", "", func() {})
	if err == nil {
		t.Fatal("Watch() missing file error = nil")
	}
}
