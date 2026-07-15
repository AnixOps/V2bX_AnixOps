package agent

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	agentv1pb "github.com/AnixOps/anix-agent/v3/api/grpc/agent/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

const (
	ProtocolVersion         = "anix.agent.v1"
	defaultHeartbeat        = 20 * time.Second
	defaultReconnectMin     = time.Second
	defaultReconnectMax     = 30 * time.Second
	defaultDialTimeout      = 10 * time.Second
	defaultHandshakeTimeout = 10 * time.Second
	operationQueueSize      = 32
	completedCacheSize      = 256
)

type OperationHandler interface {
	HandleOperation(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error)
}

type OperationHandlerFunc func(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error)

func (f OperationHandlerFunc) HandleOperation(ctx context.Context, operation *agentv1pb.DesiredOperation) (json.RawMessage, error) {
	return f(ctx, operation)
}

type DialContextFunc func(context.Context, string, ...grpc.DialOption) (*grpc.ClientConn, error)

type Config struct {
	Target           string
	NodeID           int
	APIKey           string
	UseTLS           bool
	ServerName       string
	AgentVersion     string
	InstanceID       string
	Capabilities     []*agentv1pb.Capability
	Labels           map[string]string
	KeepaliveTime    time.Duration
	Heartbeat        time.Duration
	ReconnectMin     time.Duration
	ReconnectMax     time.Duration
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	Handler          OperationHandler
	DialContext      DialContextFunc
	DialOptions      []grpc.DialOption
	Rand             *mathrand.Rand
}

type Client struct {
	config Config

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	sendMu sync.Mutex
	randMu sync.Mutex
	mu     sync.RWMutex

	sessionID        string
	ready            bool
	readyCh          chan struct{}
	readyOnce        sync.Once
	desiredRevision  atomic.Uint64
	observedRevision atomic.Uint64
	completed        map[string]*agentv1pb.ObservedState
	completedOrder   []string
	started          atomic.Bool
	closed           atomic.Bool
}

func NewClient(config Config) (*Client, error) {
	config.Target = strings.TrimSpace(config.Target)
	if config.Target == "" {
		return nil, fmt.Errorf("agent control target is required")
	}
	if config.NodeID <= 0 {
		return nil, fmt.Errorf("agent node ID must be positive")
	}
	if strings.TrimSpace(config.APIKey) == "" {
		return nil, fmt.Errorf("agent API key is required")
	}
	if config.Heartbeat <= 0 {
		config.Heartbeat = defaultHeartbeat
	}
	if config.ReconnectMin <= 0 {
		config.ReconnectMin = defaultReconnectMin
	}
	if config.ReconnectMax <= 0 {
		config.ReconnectMax = defaultReconnectMax
	}
	if config.ReconnectMax < config.ReconnectMin {
		config.ReconnectMax = config.ReconnectMin
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = defaultDialTimeout
	}
	if config.HandshakeTimeout <= 0 {
		config.HandshakeTimeout = defaultHandshakeTimeout
	}
	if config.KeepaliveTime <= 0 {
		config.KeepaliveTime = 30 * time.Second
	}
	if config.InstanceID == "" {
		config.InstanceID = newID("instance")
	}
	if config.Handler == nil {
		config.Handler = OperationHandlerFunc(func(context.Context, *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			return nil, fmt.Errorf("desired operation handler is not configured")
		})
	}
	if config.DialContext == nil {
		config.DialContext = grpc.DialContext
	}
	if config.Rand == nil {
		config.Rand = mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		config:    config,
		ctx:       ctx,
		cancel:    cancel,
		readyCh:   make(chan struct{}),
		completed: make(map[string]*agentv1pb.ObservedState),
	}, nil
}

func (c *Client) Start() error {
	if c.closed.Load() {
		return fmt.Errorf("agent control client is closed")
	}
	if !c.started.CompareAndSwap(false, true) {
		return nil
	}
	c.wg.Add(1)
	go c.run()
	return nil
}

func (c *Client) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	c.cancel()
	c.wg.Wait()
	return nil
}

func (c *Client) Ready() <-chan struct{} {
	return c.readyCh
}

func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ready
}

func (c *Client) SessionID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionID
}

func (c *Client) run() {
	defer c.wg.Done()
	attempt := 0
	for {
		connected, err := c.runSession()
		c.setDisconnected()
		if c.ctx.Err() != nil {
			return
		}
		if err != nil {
			log.WithFields(log.Fields{
				"component": "agent-control",
				"node_id":   c.config.NodeID,
				"error":     err,
			}).Warn("Agent control stream disconnected")
		}
		if connected {
			attempt = 0
		}
		delay := c.reconnectDelay(attempt)
		if attempt < 62 {
			attempt++
		}
		timer := time.NewTimer(delay)
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

type receiveResult struct {
	message *agentv1pb.ControlToAgent
	err     error
}

func (c *Client) runSession() (bool, error) {
	var connectedAt time.Time
	dialCtx, dialCancel := context.WithTimeout(c.ctx, c.config.DialTimeout)
	defer dialCancel()

	conn, err := c.config.DialContext(dialCtx, c.config.Target, c.dialOptions()...)
	if err != nil {
		return false, fmt.Errorf("dial agent control: %w", err)
	}
	defer conn.Close()

	sessionCtx, sessionCancel := context.WithCancel(c.ctx)
	defer sessionCancel()
	authCtx := metadata.AppendToOutgoingContext(
		sessionCtx,
		"x-node-id", strconv.Itoa(c.config.NodeID),
		"x-api-key", c.config.APIKey,
	)
	stream, err := agentv1pb.NewAgentControlServiceClient(conn).ControlStream(authCtx)
	if err != nil {
		return false, fmt.Errorf("open control stream: %w", err)
	}

	receiveCh := make(chan receiveResult, 1)
	go receiveControlMessages(sessionCtx, stream, receiveCh)

	helloRequestID := newID("hello")
	if err := c.send(stream, &agentv1pb.AgentToControl{
		RequestId:    helloRequestID,
		NodeId:       uint32(c.config.NodeID),
		Revision:     c.observedRevision.Load(),
		SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.AgentToControl_Hello{
			Hello: &agentv1pb.Hello{
				Protocol:     ProtocolVersion,
				AgentVersion: c.config.AgentVersion,
				InstanceId:   c.config.InstanceID,
				Capabilities: cloneCapabilities(c.config.Capabilities),
				Labels:       cloneStringMap(c.config.Labels),
			},
		},
	}); err != nil {
		return false, fmt.Errorf("send hello: %w", err)
	}

	handshakeTimer := time.NewTimer(c.config.HandshakeTimeout)
	defer handshakeTimer.Stop()
	var helloAck *agentv1pb.HelloAck
	select {
	case <-c.ctx.Done():
		return false, c.ctx.Err()
	case <-handshakeTimer.C:
		return false, fmt.Errorf("agent control hello timed out")
	case received := <-receiveCh:
		if received.err != nil {
			return false, fmt.Errorf("receive hello ACK: %w", received.err)
		}
		if received.message.RequestId != helloRequestID {
			return false, fmt.Errorf("hello ACK request_id mismatch")
		}
		helloAck = received.message.GetHelloAck()
		if helloAck == nil || helloAck.SessionId == "" {
			return false, fmt.Errorf("invalid hello ACK")
		}
	}

	c.desiredRevision.Store(helloAck.DesiredRevision)
	c.setConnected(helloAck.SessionId)
	connectedAt = time.Now()
	heartbeatInterval := c.config.Heartbeat
	if helloAck.HeartbeatIntervalSeconds > 0 {
		heartbeatInterval = time.Duration(helloAck.HeartbeatIntervalSeconds) * time.Second
	}
	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()

	operationQueue := make(chan *agentv1pb.DesiredOperation, operationQueueSize)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		c.operationWorker(sessionCtx, stream, helloAck.SessionId, operationQueue)
	}()
	defer func() {
		sessionCancel()
		<-workerDone
	}()

	startedAt := connectedAt
	for {
		select {
		case <-c.ctx.Done():
			return c.sessionWasStable(connectedAt), c.ctx.Err()
		case <-heartbeatTicker.C:
			if err := c.sendHeartbeat(stream, helloAck.SessionId, startedAt); err != nil {
				return c.sessionWasStable(connectedAt), err
			}
		case received := <-receiveCh:
			if received.err != nil {
				return c.sessionWasStable(connectedAt), received.err
			}
			if received.message.NodeId != uint32(c.config.NodeID) {
				return c.sessionWasStable(connectedAt), fmt.Errorf("control message node_id mismatch")
			}
			switch payload := received.message.Payload.(type) {
			case *agentv1pb.ControlToAgent_HeartbeatAck:
				if payload.HeartbeatAck.SessionId != helloAck.SessionId {
					return c.sessionWasStable(connectedAt), fmt.Errorf("heartbeat ACK session_id mismatch")
				}
				c.storeDesiredRevision(payload.HeartbeatAck.DesiredRevision)
			case *agentv1pb.ControlToAgent_DesiredOperation:
				c.storeDesiredRevision(payload.DesiredOperation.Revision)
				if err := c.acceptOperation(stream, helloAck.SessionId, operationQueue, payload.DesiredOperation); err != nil {
					return c.sessionWasStable(connectedAt), err
				}
			case *agentv1pb.ControlToAgent_HelloAck:
				return c.sessionWasStable(connectedAt), fmt.Errorf("unexpected duplicate hello ACK")
			default:
				return c.sessionWasStable(connectedAt), fmt.Errorf("control message payload is required")
			}
		}
	}
}

func (c *Client) sessionWasStable(connectedAt time.Time) bool {
	if connectedAt.IsZero() {
		return false
	}
	return time.Since(connectedAt) >= c.config.Heartbeat
}

func (c *Client) dialOptions() []grpc.DialOption {
	if len(c.config.DialOptions) > 0 {
		return append([]grpc.DialOption(nil), c.config.DialOptions...)
	}
	options := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                c.config.KeepaliveTime,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	if c.config.UseTLS {
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			ServerName: c.config.ServerName,
			MinVersion: tls.VersionTLS12,
		})))
	} else {
		options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	return options
}

func receiveControlMessages(ctx context.Context, stream agentv1pb.AgentControlService_ControlStreamClient, output chan<- receiveResult) {
	for {
		message, err := stream.Recv()
		select {
		case output <- receiveResult{message: message, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *Client) acceptOperation(stream agentv1pb.AgentControlService_ControlStreamClient, sessionID string, queue chan<- *agentv1pb.DesiredOperation, operation *agentv1pb.DesiredOperation) error {
	if operation == nil || operation.OperationId == "" || operation.Kind == "" || operation.Revision == 0 {
		return c.sendOperationAck(stream, sessionID, operation, false, "invalid desired operation")
	}
	if completed, ok := c.completedOperation(operation.OperationId); ok {
		if completed.Revision != operation.Revision {
			return c.sendOperationAck(stream, sessionID, operation, false, fmt.Sprintf("operation_id was already completed at revision %d", completed.Revision))
		}
		if err := c.sendOperationAck(stream, sessionID, operation, true, ""); err != nil {
			return err
		}
		return c.sendObserved(stream, sessionID, completed)
	}
	if operation.Revision <= c.observedRevision.Load() {
		if err := c.sendOperationAck(stream, sessionID, operation, true, ""); err != nil {
			return err
		}
		return c.sendObserved(stream, sessionID, &agentv1pb.ObservedState{
			OperationId:      operation.OperationId,
			Revision:         operation.Revision,
			Phase:            agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED,
			Message:          "operation revision is stale",
			ObservedAtUnixMs: time.Now().UnixMilli(),
		})
	}

	cloned := proto.Clone(operation).(*agentv1pb.DesiredOperation)
	select {
	case queue <- cloned:
		return c.sendOperationAck(stream, sessionID, operation, true, "")
	default:
		return c.sendOperationAck(stream, sessionID, operation, false, "operation queue is full")
	}
}

func (c *Client) operationWorker(ctx context.Context, stream agentv1pb.AgentControlService_ControlStreamClient, sessionID string, queue <-chan *agentv1pb.DesiredOperation) {
	for {
		select {
		case <-ctx.Done():
			return
		case operation := <-queue:
			c.executeOperation(ctx, stream, sessionID, operation)
		}
	}
}

func (c *Client) executeOperation(parent context.Context, stream agentv1pb.AgentControlService_ControlStreamClient, sessionID string, operation *agentv1pb.DesiredOperation) {
	if operation == nil {
		return
	}
	if operation.Revision <= c.observedRevision.Load() {
		terminal := &agentv1pb.ObservedState{
			OperationId:      operation.OperationId,
			Revision:         operation.Revision,
			Phase:            agentv1pb.ObservedPhase_OBSERVED_PHASE_SUPERSEDED,
			Message:          "operation revision became stale before execution",
			ObservedAtUnixMs: time.Now().UnixMilli(),
		}
		c.rememberCompleted(terminal)
		_ = c.sendObserved(stream, sessionID, terminal)
		return
	}

	applying := &agentv1pb.ObservedState{
		OperationId:      operation.OperationId,
		Revision:         operation.Revision,
		Phase:            agentv1pb.ObservedPhase_OBSERVED_PHASE_APPLYING,
		ObservedAtUnixMs: time.Now().UnixMilli(),
	}
	if err := c.sendObserved(stream, sessionID, applying); err != nil {
		return
	}

	operationCtx := parent
	cancel := func() {}
	if operation.DeadlineUnixMs > 0 {
		operationCtx, cancel = context.WithDeadline(parent, time.UnixMilli(operation.DeadlineUnixMs))
	}
	defer cancel()
	state, err := c.config.Handler.HandleOperation(operationCtx, proto.Clone(operation).(*agentv1pb.DesiredOperation))

	terminal := &agentv1pb.ObservedState{
		OperationId:      operation.OperationId,
		Revision:         operation.Revision,
		Phase:            agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED,
		StateJson:        append([]byte(nil), state...),
		ObservedAtUnixMs: time.Now().UnixMilli(),
	}
	if err != nil {
		terminal.Phase = agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED
		terminal.Message = err.Error()
	}
	c.storeObservedRevision(operation.Revision)
	c.rememberCompleted(terminal)
	_ = c.sendObserved(stream, sessionID, terminal)
}

func (c *Client) sendHeartbeat(stream agentv1pb.AgentControlService_ControlStreamClient, sessionID string, startedAt time.Time) error {
	return c.send(stream, &agentv1pb.AgentToControl{
		RequestId:    newID("heartbeat"),
		NodeId:       uint32(c.config.NodeID),
		Revision:     c.observedRevision.Load(),
		SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.AgentToControl_Heartbeat{
			Heartbeat: &agentv1pb.Heartbeat{
				SessionId:        sessionID,
				UptimeSeconds:    int64(time.Since(startedAt) / time.Second),
				ObservedRevision: c.observedRevision.Load(),
				Metrics: map[string]float64{
					"go_goroutines": float64(runtime.NumGoroutine()),
				},
			},
		},
	})
}

func (c *Client) sendOperationAck(stream agentv1pb.AgentControlService_ControlStreamClient, sessionID string, operation *agentv1pb.DesiredOperation, accepted bool, reason string) error {
	operationID := ""
	revision := uint64(0)
	if operation != nil {
		operationID = operation.OperationId
		revision = operation.Revision
	}
	return c.send(stream, &agentv1pb.AgentToControl{
		RequestId:    newID("ack"),
		NodeId:       uint32(c.config.NodeID),
		Revision:     revision,
		SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.AgentToControl_OperationAck{
			OperationAck: &agentv1pb.OperationAck{
				OperationId:      operationID,
				Accepted:         accepted,
				Error:            reason,
				AcceptedAtUnixMs: time.Now().UnixMilli(),
				SessionId:        sessionID,
				Revision:         revision,
			},
		},
	})
}

func (c *Client) sendObserved(stream agentv1pb.AgentControlService_ControlStreamClient, sessionID string, observed *agentv1pb.ObservedState) error {
	cloned := proto.Clone(observed).(*agentv1pb.ObservedState)
	cloned.SessionId = sessionID
	return c.send(stream, &agentv1pb.AgentToControl{
		RequestId:    newID("observed"),
		NodeId:       uint32(c.config.NodeID),
		Revision:     observed.Revision,
		SentAtUnixMs: time.Now().UnixMilli(),
		Payload: &agentv1pb.AgentToControl_ObservedState{
			ObservedState: cloned,
		},
	})
}

func (c *Client) send(stream agentv1pb.AgentControlService_ControlStreamClient, message *agentv1pb.AgentToControl) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return stream.Send(message)
}

func (c *Client) setConnected(sessionID string) {
	c.mu.Lock()
	c.sessionID = sessionID
	c.ready = true
	c.mu.Unlock()
	c.readyOnce.Do(func() { close(c.readyCh) })
}

func (c *Client) setDisconnected() {
	c.mu.Lock()
	c.sessionID = ""
	c.ready = false
	c.mu.Unlock()
}

func (c *Client) storeDesiredRevision(revision uint64) {
	storeMax(&c.desiredRevision, revision)
}

func (c *Client) storeObservedRevision(revision uint64) {
	storeMax(&c.observedRevision, revision)
}

func storeMax(target *atomic.Uint64, value uint64) {
	for {
		current := target.Load()
		if value <= current || target.CompareAndSwap(current, value) {
			return
		}
	}
}

func (c *Client) completedOperation(operationID string) (*agentv1pb.ObservedState, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	observed, ok := c.completed[operationID]
	if !ok {
		return nil, false
	}
	return proto.Clone(observed).(*agentv1pb.ObservedState), true
}

func (c *Client) rememberCompleted(observed *agentv1pb.ObservedState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.completed[observed.OperationId]; !exists {
		c.completedOrder = append(c.completedOrder, observed.OperationId)
	}
	c.completed[observed.OperationId] = proto.Clone(observed).(*agentv1pb.ObservedState)
	for len(c.completedOrder) > completedCacheSize {
		oldest := c.completedOrder[0]
		c.completedOrder = c.completedOrder[1:]
		delete(c.completed, oldest)
	}
}

func (c *Client) reconnectDelay(attempt int) time.Duration {
	base := c.config.ReconnectMin
	for i := 0; i < attempt && base < c.config.ReconnectMax; i++ {
		if base > c.config.ReconnectMax/2 {
			base = c.config.ReconnectMax
			break
		}
		base *= 2
	}
	if base > c.config.ReconnectMax {
		base = c.config.ReconnectMax
	}
	c.randMu.Lock()
	jitter := 0.5 + c.config.Rand.Float64()*0.5
	c.randMu.Unlock()
	return time.Duration(float64(base) * jitter)
}

func cloneCapabilities(capabilities []*agentv1pb.Capability) []*agentv1pb.Capability {
	cloned := make([]*agentv1pb.Capability, 0, len(capabilities))
	for _, capability := range capabilities {
		if capability != nil {
			cloned = append(cloned, proto.Clone(capability).(*agentv1pb.Capability))
		}
	}
	return cloned
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func newID(prefix string) string {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(random)
}
