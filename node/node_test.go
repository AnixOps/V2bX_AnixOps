package node

import "testing"

func TestInitialNodeType(t *testing.T) {
	tests := []struct {
		name     string
		nodeType string
		coreType string
		want     string
	}{
		{name: "explicit node type wins", nodeType: "vless", coreType: "wireguard", want: "vless"},
		{name: "wireguard core infers node type", coreType: "wireguard", want: "wireguard"},
		{name: "wireguard core is case insensitive", coreType: "WireGuard", want: "wireguard"},
		{name: "other core does not infer node type", coreType: "sing", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := initialNodeType(tt.nodeType, tt.coreType); got != tt.want {
				t.Fatalf("initialNodeType(%q, %q) = %q, want %q", tt.nodeType, tt.coreType, got, tt.want)
			}
		})
	}
}
