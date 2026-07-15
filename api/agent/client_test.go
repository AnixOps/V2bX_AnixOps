package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	mathrand "math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1pb "github.com/AnixOps/anix-agent/v3/api/grpc/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type controlStreamResult struct {
	hello    *agentv1pb.Hello
	ack      *agentv1pb.OperationAck
	applying *agentv1pb.ObservedState
	terminal *agentv1pb.ObservedState
}

type recordingAgentClientStream struct {
	grpc.ClientStream
	mu   sync.Mutex
	sent []*agentv1pb.AgentToControl
}

func (s *recordingAgentClientStream) Send(message *agentv1pb.AgentToControl) error {
	s.mu.Lock()
	s.sent = append(s.sent, message)
	s.mu.Unlock()
	return nil
}

func (s *recordingAgentClientStream) Recv() (*agentv1pb.ControlToAgent, error) {
	return nil, io.EOF
}

type testAgentControlServer struct {
	agentv1pb.UnimplementedAgentControlServiceServer
	nodeID    uint32
	apiKey    string
	operation *agentv1pb.DesiredOperation
	result    chan controlStreamResult
}

func (s *testAgentControlServer) ControlStream(stream agentv1pb.AgentControlService_ControlStreamServer) error {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok || len(md.Get("x-api-key")) == 0 || md.Get("x-api-key")[0] != s.apiKey {
		return status.Error(codes.Unauthenticated, "missing agent API key")
	}
	if len(md.Get("x-node-id")) == 0 || md.Get("x-node-id")[0] != strconv.FormatUint(uint64(s.nodeID), 10) {
		return status.Error(codes.Unauthenticated, "missing agent node ID")
	}

	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil || hello.Protocol != ProtocolVersion {
		return status.Error(codes.FailedPrecondition, "invalid hello")
	}
	if err := stream.Send(&agentv1pb.ControlToAgent{
		RequestId:    first.RequestId,
		NodeId:       s.nodeID,
		SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.ControlToAgent_HelloAck{
			HelloAck: &agentv1pb.HelloAck{
				SessionId:                "test-session",
				ServerTimeUnixMs:         time.Now().UnixMilli(),
				HeartbeatIntervalSeconds: 30,
			},
		},
	}); err != nil {
		return err
	}
	if err := stream.Send(&agentv1pb.ControlToAgent{
		RequestId:    "desired-request",
		NodeId:       s.nodeID,
		Revision:     s.operation.Revision,
		SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.ControlToAgent_DesiredOperation{
			DesiredOperation: s.operation,
		},
	}); err != nil {
		return err
	}

	result := controlStreamResult{hello: hello}
	for result.ack == nil || result.applying == nil || result.terminal == nil {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		if ack := message.GetOperationAck(); ack != nil {
			result.ack = ack
		}
		if observed := message.GetObservedState(); observed != nil {
			switch observed.Phase {
			case agentv1pb.ObservedPhase_OBSERVED_PHASE_APPLYING:
				result.applying = observed
			case agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED,
				agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED:
				result.terminal = observed
			}
		}
	}
	s.result <- result
	<-stream.Context().Done()
	return stream.Context().Err()
}

func TestClientControlStreamOperationLifecycle(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	resultCh := make(chan controlStreamResult, 1)
	operation := &agentv1pb.DesiredOperation{
		OperationId: "operation-1",
		Kind:        "agent.ping",
		Revision:    7,
		PayloadJson: []byte(`{"message":"ping"}`),
	}
	agentv1pb.RegisterAgentControlServiceServer(server, &testAgentControlServer{
		nodeID:    42,
		apiKey:    "node-api-key",
		operation: operation,
		result:    resultCh,
	})
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(listener) }()

	handled := make(chan *agentv1pb.DesiredOperation, 1)
	client, err := NewClient(Config{
		Target:       listener.Addr().String(),
		NodeID:       42,
		APIKey:       "node-api-key",
		AgentVersion: "test-agent",
		InstanceID:   "instance-1",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.ping", Version: "v1"}},
		Handler: OperationHandlerFunc(func(_ context.Context, desired *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			handled <- desired
			return json.RawMessage(`{"applied":true}`), nil
		}),
		ReconnectMin: 100 * time.Millisecond,
		ReconnectMax: time.Second,
	})
	require.NoError(t, err)
	require.NoError(t, client.Start())

	select {
	case <-client.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("agent control client did not become ready")
	}
	assert.True(t, client.IsConnected())
	assert.Equal(t, "test-session", client.SessionID())

	select {
	case desired := <-handled:
		assert.Equal(t, operation.OperationId, desired.OperationId)
		assert.Equal(t, operation.Revision, desired.Revision)
	case <-time.After(5 * time.Second):
		t.Fatal("desired operation was not handled")
	}

	select {
	case result := <-resultCh:
		assert.Equal(t, "test-agent", result.hello.AgentVersion)
		require.NotNil(t, result.ack)
		assert.True(t, result.ack.Accepted)
		assert.Equal(t, "test-session", result.ack.SessionId)
		assert.Equal(t, operation.Revision, result.ack.Revision)
		require.NotNil(t, result.applying)
		assert.Equal(t, operation.Revision, result.applying.Revision)
		assert.Equal(t, "test-session", result.applying.SessionId)
		require.NotNil(t, result.terminal)
		assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED, result.terminal.Phase)
		assert.Equal(t, "test-session", result.terminal.SessionId)
		assert.JSONEq(t, `{"applied":true}`, string(result.terminal.StateJson))
	case <-time.After(5 * time.Second):
		t.Fatal("operation lifecycle was not reported")
	}

	require.NoError(t, client.Close())
	server.GracefulStop()
	err = <-serverErr
	if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		require.NoError(t, err)
	}
}

func TestExecuteOperationSupersedesRevisionThatBecameStaleInQueue(t *testing.T) {
	var handled atomic.Int32
	client, err := NewClient(Config{
		Target:       "unused:1",
		NodeID:       1,
		APIKey:       "key",
		AgentVersion: "test-agent",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.ping"}},
		Handler: OperationHandlerFunc(func(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			handled.Add(1)
			return nil, nil
		}),
	})
	require.NoError(t, err)
	client.observedRevision.Store(10)
	stream := &recordingAgentClientStream{}

	client.executeOperation(context.Background(), stream, "current-session", &agentv1pb.DesiredOperation{
		OperationId: "stale-in-queue",
		Kind:        "agent.ping",
		Revision:    9,
	})

	assert.Zero(t, handled.Load())
	stream.mu.Lock()
	require.Len(t, stream.sent, 1)
	observed := stream.sent[0].GetObservedState()
	stream.mu.Unlock()
	require.NotNil(t, observed)
	assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, observed.Phase)
	assert.Equal(t, "current-session", observed.SessionId)
	assert.Equal(t, uint64(9), observed.Revision)
	completed, ok := client.completedOperation("stale-in-queue")
	require.True(t, ok)
	assert.Equal(t, agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED, completed.Phase)
}

func TestClientRetriesFailedDial(t *testing.T) {
	var attempts atomic.Int32
	client, err := NewClient(Config{
		Target:       "unused:1",
		NodeID:       1,
		APIKey:       "key",
		AgentVersion: "test-agent",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.ping"}},
		ReconnectMin: 5 * time.Millisecond,
		ReconnectMax: 20 * time.Millisecond,
		DialTimeout:  5 * time.Millisecond,
		DialContext: func(context.Context, string, ...grpc.DialOption) (*grpc.ClientConn, error) {
			attempts.Add(1)
			return nil, errors.New("dial failed")
		},
	})
	require.NoError(t, err)
	require.NoError(t, client.Start())
	require.Eventually(t, func() bool { return attempts.Load() >= 3 }, time.Second, 5*time.Millisecond)
	require.NoError(t, client.Close())
}

func TestReconnectDelayUsesExponentialBackoffAndJitter(t *testing.T) {
	client, err := NewClient(Config{
		Target:       "unused:1",
		NodeID:       1,
		APIKey:       "key",
		AgentVersion: "test-agent",
		Capabilities: []*agentv1pb.Capability{{Name: "agent.ping"}},
		ReconnectMin: time.Second,
		ReconnectMax: 5 * time.Second,
		Rand:         mathrand.New(mathrand.NewSource(1)),
	})
	require.NoError(t, err)

	delay0 := client.reconnectDelay(0)
	delay1 := client.reconnectDelay(1)
	delay2 := client.reconnectDelay(2)
	delay9 := client.reconnectDelay(9)
	assert.GreaterOrEqual(t, delay0, 500*time.Millisecond)
	assert.LessOrEqual(t, delay0, time.Second)
	assert.GreaterOrEqual(t, delay1, time.Second)
	assert.LessOrEqual(t, delay1, 2*time.Second)
	assert.GreaterOrEqual(t, delay2, 2*time.Second)
	assert.LessOrEqual(t, delay2, 4*time.Second)
	assert.GreaterOrEqual(t, delay9, 2500*time.Millisecond)
	assert.LessOrEqual(t, delay9, 5*time.Second)
	assert.NotEqual(t, delay0, client.reconnectDelay(0), "jitter should vary retries at the same backoff step")
}
