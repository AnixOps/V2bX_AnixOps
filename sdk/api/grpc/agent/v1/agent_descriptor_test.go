package agentv1pb

import "testing"

func TestAgentControlServiceDescriptor(t *testing.T) {
	if got := string(File_api_grpc_agent_v1_agent_proto.Package()); got != "anix.agent.v1" {
		t.Fatalf("package = %q, want anix.agent.v1", got)
	}

	service := File_api_grpc_agent_v1_agent_proto.Services().ByName("AgentControlService")
	if service == nil || service.Methods().ByName("ControlStream") == nil {
		t.Fatal("AgentControlService.ControlStream descriptor is missing")
	}
}
