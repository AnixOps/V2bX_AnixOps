package agentcontrol

import (
	"errors"
	"strings"

	agentv1pb "github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1"
)

const (
	ProtocolV1          = "anix.agent.v1"
	CapabilityVersionV1 = "v1"
)

var (
	ErrCapabilitiesRequired   = errors.New("hello capabilities are required")
	ErrCapabilityNameRequired = errors.New("capability name is required")
)

func ValidateCapabilities(capabilities []*agentv1pb.Capability) error {
	if len(capabilities) == 0 {
		return ErrCapabilitiesRequired
	}

	for _, capability := range capabilities {
		if capability == nil || strings.TrimSpace(capability.Name) == "" {
			return ErrCapabilityNameRequired
		}
	}

	return nil
}

func HasCapability(capabilities []*agentv1pb.Capability, name string) bool {
	for _, capability := range capabilities {
		if capability != nil && capability.Name == name {
			return true
		}
	}

	return false
}

func HasCapabilityVersion(capabilities []*agentv1pb.Capability, name, version string) bool {
	for _, capability := range capabilities {
		if capability != nil && capability.Name == name && capability.Version == version {
			return true
		}
	}

	return false
}
