// Command agent-control-fixture is a test-only Agent process used by the
// cross-repository Control KernelOperationBridge E2E harness.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v3/api/agent"
	agentv1pb "github.com/AnixOps/anix-agent/v3/api/grpc/agent/v1"
)

type fixtureResult struct {
	OperationID   string          `json:"operation_id"`
	Kind          string          `json:"kind"`
	SessionID     string          `json:"session_id"`
	Revision      uint64          `json:"revision"`
	PluginID      string          `json:"plugin_id"`
	TargetVersion string          `json:"target_version"`
	ConfigHash    string          `json:"config_hash"`
	Config        json.RawMessage `json:"config"`
}

func main() {
	var (
		target     = flag.String("target", "", "Control gRPC host:port")
		nodeID     = flag.Int("node-id", 0, "Control node ID")
		apiKey     = flag.String("api-key", "", "Control node API key")
		readyFile  = flag.String("ready-file", "", "file written after the Agent stream is ready")
		resultFile = flag.String("result-file", "", "file written after an operation is handled")
		timeout    = flag.Duration("timeout", 30*time.Second, "maximum fixture lifetime")
	)
	flag.Parse()
	if *target == "" || *nodeID <= 0 || *apiKey == "" || *readyFile == "" || *resultFile == "" {
		fatal(errors.New("target, node-id, api-key, ready-file, and result-file are required"))
	}

	client, err := agentapi.NewClient(agentapi.Config{
		Target: *target, NodeID: *nodeID, APIKey: *apiKey,
		AgentVersion: "agent-control-fixture", InstanceID: "agent-control-fixture-" + strconv.Itoa(os.Getpid()),
		Capabilities: []*agentv1pb.Capability{
			{Name: "agent.control", Version: "v1"},
			{Name: "operation.cancel", Version: "v1"},
			{Name: "plugin.health", Version: "v1"},
		},
		ReconnectMin: 20 * time.Millisecond, ReconnectMax: 100 * time.Millisecond,
		Heartbeat: 5 * time.Second, DialTimeout: 3 * time.Second, HandshakeTimeout: 3 * time.Second,
		Handler: agentapi.OperationHandlerFunc(func(ctx context.Context, operation *agentv1pb.DesiredOperation) (json.RawMessage, error) {
			envelope, decodeErr := agentapi.DecodeOperationEnvelopeContext(ctx, operation)
			if decodeErr != nil {
				return nil, decodeErr
			}
			result := fixtureResult{
				OperationID: operation.OperationId, Kind: operation.Kind, SessionID: envelope.SessionID,
				Revision: envelope.Revision, PluginID: envelope.PluginID, TargetVersion: envelope.TargetVersion,
				ConfigHash: envelope.ConfigHash, Config: append(json.RawMessage(nil), envelope.Config...),
			}
			if writeErr := writeJSONAtomically(*resultFile, result); writeErr != nil {
				return nil, writeErr
			}
			return json.RawMessage(`{"fixture":"agent-control","status":"ok"}`), nil
		}),
	})
	if err != nil {
		fatal(err)
	}
	if err := client.Start(); err != nil {
		fatal(err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			fmt.Fprintln(os.Stderr, closeErr)
		}
	}()

	startup := time.NewTimer(*timeout)
	defer startup.Stop()
	select {
	case <-client.Ready():
		if err := writeJSONAtomically(*readyFile, map[string]any{
			"node_id": *nodeID, "session_id": client.SessionID(), "pid": os.Getpid(),
		}); err != nil {
			fatal(err)
		}
	case <-startup.C:
		fatal(errors.New("Agent fixture did not connect before timeout"))
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	lifetime := time.NewTimer(*timeout)
	defer lifetime.Stop()
	select {
	case <-signals:
	case <-lifetime.C:
		fatal(errors.New("Agent fixture timed out waiting for an operation"))
	}
}

func writeJSONAtomically(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary := path + ".tmp-" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "agent-control-fixture:", err)
	os.Exit(1)
}
