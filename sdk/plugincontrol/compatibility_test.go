package plugincontrol

import (
	"testing"

	agentv1pb "github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestV1DesiredOperationDescriptorRemainsStable(t *testing.T) {
	file := agentv1pb.File_api_grpc_agent_v1_agent_proto
	if got := string(file.Package()); got != "anix.agent.v1" {
		t.Fatalf("protobuf package = %q, want anix.agent.v1", got)
	}

	desiredOperation := file.Messages().ByName("DesiredOperation")
	if desiredOperation == nil {
		t.Fatal("DesiredOperation descriptor is missing")
	}

	fields := []struct {
		name   string
		number int
	}{
		{name: "operation_id", number: 1},
		{name: "kind", number: 2},
		{name: "revision", number: 3},
		{name: "payload_json", number: 4},
		{name: "deadline_unix_ms", number: 5},
	}
	for _, field := range fields {
		descriptor := desiredOperation.Fields().ByName(protoreflect.Name(field.name))
		if descriptor == nil || int(descriptor.Number()) != field.number {
			t.Fatalf("DesiredOperation.%s field = %v, want field %d", field.name, descriptor, field.number)
		}
	}

	service := file.Services().ByName("AgentControlService")
	if service == nil || service.Methods().ByName("ControlStream") == nil {
		t.Fatal("AgentControlService.ControlStream descriptor is missing")
	}
}
