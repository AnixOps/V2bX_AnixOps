package agentcontrol

import (
	"errors"
	"testing"

	agentv1pb "github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1"
)

func TestProtocolConstants(t *testing.T) {
	if ProtocolV1 != "anix.agent.v1" {
		t.Fatalf("ProtocolV1 = %q, want anix.agent.v1", ProtocolV1)
	}
	if CapabilityVersionV1 != "v1" {
		t.Fatalf("CapabilityVersionV1 = %q, want v1", CapabilityVersionV1)
	}
}

func TestValidateCapabilities(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []*agentv1pb.Capability
		want         error
	}{
		{name: "missing", want: ErrCapabilitiesRequired},
		{name: "empty", capabilities: []*agentv1pb.Capability{}, want: ErrCapabilitiesRequired},
		{name: "nil entry", capabilities: []*agentv1pb.Capability{nil}, want: ErrCapabilityNameRequired},
		{name: "blank name", capabilities: []*agentv1pb.Capability{{Name: "  "}}, want: ErrCapabilityNameRequired},
		{name: "valid", capabilities: []*agentv1pb.Capability{{Name: "agent.ping", Version: "v1"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateCapabilities(test.capabilities)
			if test.want == nil {
				if err != nil {
					t.Fatalf("ValidateCapabilities() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateCapabilities() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCapabilityQueries(t *testing.T) {
	capabilities := []*agentv1pb.Capability{
		nil,
		{Name: "agent.ping", Version: "v1"},
		{Name: "plugin.health", Version: "v2"},
	}

	if !HasCapability(capabilities, "agent.ping") {
		t.Fatal("agent.ping should be present")
	}
	if HasCapability(capabilities, "missing") {
		t.Fatal("missing capability should not be present")
	}
	if !HasCapabilityVersion(capabilities, "plugin.health", "v2") {
		t.Fatal("plugin.health v2 should be present")
	}
	if HasCapabilityVersion(capabilities, "plugin.health", "v1") {
		t.Fatal("plugin.health v1 should not be present")
	}
}
