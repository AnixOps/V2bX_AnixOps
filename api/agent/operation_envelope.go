package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	agentv1pb "github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1"
)

const OperationEnvelopeVersion = "anixops.operation/v1"

var ErrNotPluginEnvelope = errors.New("desired operation is not an AnixOps plugin envelope")

type operationSessionContextKey struct{}

// OperationEnvelope travels in DesiredOperation.payload_json. Keeping the
// outer protobuf stable lets older Agents retain their compatibility commands
// while plugin-aware Agents can require the full persistent-operation contract.
type OperationEnvelope struct {
	Version        string          `json:"version"`
	OperationID    string          `json:"operation_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	SessionID      string          `json:"session_id"`
	Revision       uint64          `json:"revision"`
	PluginID       string          `json:"plugin_id"`
	TargetVersion  string          `json:"target_version"`
	ConfigHash     string          `json:"config_hash"`
	Config         json.RawMessage `json:"config"`
}

func DecodeOperationEnvelope(operation *agentv1pb.DesiredOperation) (*OperationEnvelope, error) {
	if operation == nil || len(operation.PayloadJson) == 0 {
		return nil, ErrNotPluginEnvelope
	}
	var probe struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(operation.PayloadJson, &probe); err != nil {
		return nil, fmt.Errorf("decode desired operation payload: %w", err)
	}
	if probe.Version == "" {
		return nil, ErrNotPluginEnvelope
	}
	var envelope OperationEnvelope
	decoder := json.NewDecoder(strings.NewReader(string(operation.PayloadJson)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode plugin operation envelope: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("decode plugin operation envelope: multiple JSON values")
	}
	if err := envelope.Validate(operation); err != nil {
		return nil, err
	}
	return &envelope, nil
}

// DecodeOperationEnvelopeContext additionally binds a plugin operation to the
// active Agent Control stream. DecodeOperationEnvelope remains available for
// offline validation and legacy callers that do not own a live session.
func DecodeOperationEnvelopeContext(ctx context.Context, operation *agentv1pb.DesiredOperation) (*OperationEnvelope, error) {
	envelope, err := DecodeOperationEnvelope(operation)
	if err != nil {
		return nil, err
	}
	activeSession, ok := operationSessionFromContext(ctx)
	if !ok {
		return nil, errors.New("active agent control session is unavailable")
	}
	if envelope.SessionID != activeSession {
		return nil, errors.New("plugin operation session_id does not match active agent control session")
	}
	return envelope, nil
}

func withOperationSession(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, operationSessionContextKey{}, sessionID)
}

func operationSessionFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	sessionID, ok := ctx.Value(operationSessionContextKey{}).(string)
	return sessionID, ok && validIdentity(sessionID, 160)
}

func (e OperationEnvelope) Validate(operation *agentv1pb.DesiredOperation) error {
	if e.Version != OperationEnvelopeVersion {
		return fmt.Errorf("unsupported operation envelope version %q", e.Version)
	}
	if operation == nil || !validIdentity(e.OperationID, 160) || e.OperationID != operation.OperationId {
		return errors.New("operation_id does not match desired operation")
	}
	if !validIdentity(e.IdempotencyKey, 160) || !validIdentity(e.SessionID, 160) || !validPathSegment(e.PluginID) || !validPathSegment(e.TargetVersion) {
		return errors.New("plugin operation envelope is missing required fields")
	}
	if e.Revision == 0 || e.Revision != operation.Revision {
		return errors.New("plugin operation revision does not match desired operation")
	}
	if len(e.ConfigHash) != sha256.Size*2 {
		return errors.New("plugin operation config_hash must be a SHA-256 digest")
	}
	if _, err := hex.DecodeString(e.ConfigHash); err != nil {
		return errors.New("plugin operation config_hash must be hexadecimal")
	}
	if len(e.Config) > 0 && !json.Valid(e.Config) {
		return errors.New("plugin operation config must be valid JSON")
	}
	digest := sha256.Sum256(e.Config)
	if !strings.EqualFold(e.ConfigHash, hex.EncodeToString(digest[:])) {
		return errors.New("plugin operation config_hash does not match config")
	}
	return nil
}

func validIdentity(value string, maxLength int) bool {
	return value != "" && len(value) <= maxLength && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func validPathSegment(value string) bool {
	if !validIdentity(value, 120) || value == "." || value == ".." || strings.ContainsAny(value, `\\/`) {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("._+-", char) {
			continue
		}
		return false
	}
	return true
}
