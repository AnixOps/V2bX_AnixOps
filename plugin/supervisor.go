// Package plugin implements the Agent-side lifecycle boundary for official
// plugins. It intentionally owns control work only; data-plane traffic remains
// inside a plugin process or the kernel networking stack.
package plugin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/AnixOps/anix-agent/v3/api/agent"
)

const (
	manifestPublisher = "AnixOps"
	pluginBinaryName  = "plugin"
	manifestFileName  = "manifest.json"
	signatureFileName = "manifest.sig"
	pluginAPIVersion  = "v1"
	maxSocketPathLen  = 100
	cleanupTimeout    = 5 * time.Second
)

type Manifest struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	APIVersion     string            `json:"api_version"`
	Publisher      string            `json:"publisher"`
	Targets        []string          `json:"targets"`
	Architectures  []string          `json:"architectures"`
	ArtifactSHA256 string            `json:"artifact_sha256"`
	Capabilities   []string          `json:"capabilities"`
	Dependencies   []string          `json:"dependencies"`
	Conflicts      []string          `json:"conflicts"`
	Permissions    []string          `json:"permissions"`
	ConfigSchema   json.RawMessage   `json:"config_schema"`
	SecretFields   []string          `json:"secret_fields"`
	Entrypoints    map[string]string `json:"entrypoints"`
	Migration      int64             `json:"migration_version"`
	ControlRoutes  []string          `json:"control_routes"`
	FrontendSHA256 string            `json:"frontend_sha256"`
	WebUI          *PluginWebUI      `json:"webui,omitempty"`
}

type PluginWebUI struct {
	Bundle      PluginWebUIBundle  `json:"bundle"`
	Permissions []string           `json:"permissions"`
	Menus       []PluginWebUIMenu  `json:"menus"`
	Routes      []PluginWebUIRoute `json:"routes"`
}

type PluginWebUIBundle struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type PluginWebUIMenu struct {
	ID         string `json:"id"`
	Parent     string `json:"parent"`
	Label      string `json:"label"`
	Icon       string `json:"icon"`
	Route      string `json:"route"`
	Permission string `json:"permission"`
	Order      int    `json:"order"`
}

type PluginWebUIRoute struct {
	ID         string `json:"id"`
	Path       string `json:"path"`
	Export     string `json:"export"`
	Permission string `json:"permission"`
}

func (m Manifest) Validate() error {
	return m.validateForRuntime(runtime.GOOS, runtime.GOARCH)
}

func (m Manifest) validateForRuntime(goos, goarch string) error {
	if !safeSegment(m.ID) || !safeSegment(m.Version) {
		return errors.New("plugin manifest id and version must be safe path segments")
	}
	if strings.TrimSpace(m.Name) == "" {
		return errors.New("plugin manifest name is required")
	}
	if m.APIVersion != pluginAPIVersion {
		return fmt.Errorf("unsupported plugin API version %q", m.APIVersion)
	}
	if m.Publisher != manifestPublisher {
		return fmt.Errorf("untrusted plugin publisher %q", m.Publisher)
	}
	if len(m.ArtifactSHA256) != sha256.Size*2 {
		return errors.New("plugin artifact_sha256 must be a SHA-256 digest")
	}
	if _, err := hex.DecodeString(m.ArtifactSHA256); err != nil {
		return errors.New("plugin artifact_sha256 must be hexadecimal")
	}
	if !manifestSupportsTarget(m, "agent") {
		return errors.New("plugin manifest does not support the agent target")
	}
	seenTargets := make(map[string]struct{}, len(m.Targets))
	for _, target := range m.Targets {
		if target != "agent" && target != "control" {
			return fmt.Errorf("unsupported plugin target %q", target)
		}
		if _, exists := seenTargets[target]; exists {
			return fmt.Errorf("duplicate plugin target %q", target)
		}
		seenTargets[target] = struct{}{}
	}
	if err := validateArchitectures(m.Architectures, goos, goarch); err != nil {
		return err
	}
	if err := validatePluginRelationships(m.ID, m.Dependencies, m.Conflicts); err != nil {
		return err
	}
	if err := validateManifestPermissions(m.ID, m.Permissions); err != nil {
		return err
	}
	if err := m.validateControlRoutes(); err != nil {
		return err
	}
	for name, entrypoint := range m.Entrypoints {
		if !safeSegment(name) {
			return fmt.Errorf("plugin entrypoint name %q is invalid", name)
		}
		if !safeRelativePath(entrypoint) {
			return fmt.Errorf("plugin entrypoint %q must be a canonical relative path", name)
		}
	}
	if len(m.ConfigSchema) > 0 {
		trimmed := bytes.TrimSpace(m.ConfigSchema)
		if len(trimmed) > 0 && string(trimmed) != "null" && (trimmed[0] != '{' || !json.Valid(trimmed)) {
			return errors.New("plugin config_schema must be a JSON object")
		}
	}
	if m.FrontendSHA256 != "" && !validSHA256(m.FrontendSHA256) {
		return errors.New("plugin frontend_sha256 must be a SHA-256 digest")
	}
	if m.Migration < 0 {
		return errors.New("plugin migration_version must not be negative")
	}
	if m.WebUI != nil {
		if err := m.validateWebUI(); err != nil {
			return err
		}
	}
	return nil
}

func (m Manifest) validateControlRoutes() error {
	if len(m.ControlRoutes) == 0 {
		return nil
	}
	if !manifestSupportsTarget(m, "control") {
		return errors.New("control routes require the control target")
	}
	requiredPermission := m.ID + ".api"
	if !containsString(m.Permissions, requiredPermission) {
		return fmt.Errorf("control routes require permission %q", requiredPermission)
	}
	seen := make(map[string]bool, len(m.ControlRoutes))
	for _, route := range m.ControlRoutes {
		if err := validatePluginControlRoute(route, m.ID); err != nil {
			return err
		}
		if seen[route] {
			return fmt.Errorf("duplicate control route %q", route)
		}
		seen[route] = true
	}
	return nil
}

func (m Manifest) validateWebUI() error {
	if !safePluginExtensionID(m.ID) {
		return errors.New("webui plugin id must be a lowercase package identifier")
	}
	if !manifestSupportsTarget(m, "control") {
		return errors.New("webui requires the control target")
	}
	if err := validatePluginBundlePath(m.WebUI.Bundle.Path); err != nil {
		return err
	}
	if !validSHA256(m.WebUI.Bundle.SHA256) {
		return errors.New("webui bundle sha256 must be a SHA-256 digest")
	}
	if m.FrontendSHA256 != "" && !strings.EqualFold(m.FrontendSHA256, m.WebUI.Bundle.SHA256) {
		return errors.New("frontend_sha256 does not match webui bundle sha256")
	}

	manifestPermissions := make(map[string]bool, len(m.Permissions))
	for _, permission := range m.Permissions {
		manifestPermissions[permission] = true
	}
	webPermissions := make(map[string]bool, len(m.WebUI.Permissions))
	for _, permission := range m.WebUI.Permissions {
		if !safeNamespacedExtensionID(permission, m.ID) {
			return fmt.Errorf("webui permission %q is outside the plugin namespace", permission)
		}
		if !manifestPermissions[permission] {
			return fmt.Errorf("webui permission %q is not declared by the plugin", permission)
		}
		if webPermissions[permission] {
			return fmt.Errorf("duplicate webui permission %q", permission)
		}
		webPermissions[permission] = true
	}
	if len(m.WebUI.Routes) == 0 {
		return errors.New("webui must declare at least one route")
	}

	routeIDs := make(map[string]bool, len(m.WebUI.Routes))
	routePaths := make(map[string]bool, len(m.WebUI.Routes))
	for _, route := range m.WebUI.Routes {
		if !safeNamespacedExtensionID(route.ID, m.ID) {
			return fmt.Errorf("webui route id %q is outside the plugin namespace", route.ID)
		}
		if routeIDs[route.ID] {
			return fmt.Errorf("duplicate webui route id %q", route.ID)
		}
		if err := validatePluginAdminRoute(route.Path, m.ID); err != nil {
			return err
		}
		if routePaths[route.Path] {
			return fmt.Errorf("duplicate webui route path %q", route.Path)
		}
		if !safeJavaScriptExport(route.Export) {
			return fmt.Errorf("webui route %q has an invalid export", route.ID)
		}
		if !webPermissions[route.Permission] {
			return fmt.Errorf("webui route %q references an undeclared permission", route.ID)
		}
		routeIDs[route.ID] = true
		routePaths[route.Path] = true
	}

	menuIDs := make(map[string]bool, len(m.WebUI.Menus))
	for _, menu := range m.WebUI.Menus {
		if !safeNamespacedExtensionID(menu.ID, m.ID) {
			return fmt.Errorf("webui menu id %q is outside the plugin namespace", menu.ID)
		}
		if menuIDs[menu.ID] {
			return fmt.Errorf("duplicate webui menu id %q", menu.ID)
		}
		if !safeExtensionMetadataText(menu.Label, 160) {
			return fmt.Errorf("webui menu %q has an invalid label", menu.ID)
		}
		if menu.Parent != "" && !safeExtensionToken(menu.Parent) {
			return fmt.Errorf("webui menu %q has an invalid parent", menu.ID)
		}
		if menu.Icon != "" && !safeExtensionToken(menu.Icon) {
			return fmt.Errorf("webui menu %q has an invalid icon", menu.ID)
		}
		if !routePaths[menu.Route] {
			return fmt.Errorf("webui menu %q references an undeclared route", menu.ID)
		}
		if !webPermissions[menu.Permission] {
			return fmt.Errorf("webui menu %q references an undeclared permission", menu.ID)
		}
		menuIDs[menu.ID] = true
	}
	return nil
}

func CanonicalManifest(manifest Manifest) ([]byte, error) {
	if len(manifest.ConfigSchema) > 0 {
		var schema any
		if err := json.Unmarshal(manifest.ConfigSchema, &schema); err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(schema)
		if err != nil {
			return nil, err
		}
		manifest.ConfigSchema = encoded
	}
	return json.Marshal(manifest)
}

func VerifyManifest(manifestJSON, signature string, publicKey ed25519.PublicKey) (*Manifest, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid official plugin public key")
	}
	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(manifestJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("invalid plugin manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("invalid plugin manifest: multiple JSON values")
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	canonical, err := CanonicalManifest(manifest)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, errors.New("plugin signature must be base64")
	}
	if !ed25519.Verify(publicKey, canonical, sig) {
		return nil, errors.New("plugin manifest signature verification failed")
	}
	return &manifest, nil
}

func ParseOfficialPublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, errors.New("official plugin public key must be base64")
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("official plugin public key has invalid length")
	}
	return ed25519.PublicKey(decoded), nil
}

type Process interface {
	Stop(context.Context) error
	PID() int
}

// ProcessExitWatcher is optional so test and embedded runners remain small.
// CommandRunner implements it to let the Supervisor fail closed when a plugin
// exits without an explicit lifecycle operation.
type ProcessExitWatcher interface {
	Exited() <-chan error
}

type Runner interface {
	Start(context.Context, string, string, string) (Process, error)
}

type HealthChecker interface {
	Check(context.Context, string) error
}

type Config struct {
	RootDir   string
	SocketDir string
	PublicKey ed25519.PublicKey
	Runner    Runner
	Health    HealthChecker
	Now       func() time.Time
}

type PluginState struct {
	ID               string    `json:"id"`
	DesiredVersion   string    `json:"desired_version"`
	ObservedVersion  string    `json:"observed_version"`
	PreviousVersion  string    `json:"previous_version"`
	Enabled          bool      `json:"enabled"`
	Health           string    `json:"health"`
	ConfigHash       string    `json:"config_hash"`
	DesiredRevision  uint64    `json:"desired_revision"`
	ObservedRevision uint64    `json:"observed_revision"`
	LastError        string    `json:"last_error"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type JournalEntry struct {
	OperationID    string          `json:"operation_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	SessionID      string          `json:"session_id"`
	Kind           string          `json:"kind"`
	PluginID       string          `json:"plugin_id"`
	TargetVersion  string          `json:"target_version"`
	ConfigHash     string          `json:"config_hash"`
	Revision       uint64          `json:"revision"`
	State          string          `json:"state"`
	Result         json.RawMessage `json:"result,omitempty"`
	Error          string          `json:"error,omitempty"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

type persistedState struct {
	Plugins map[string]PluginState  `json:"plugins"`
	Journal map[string]JournalEntry `json:"journal"`
}

type Supervisor struct {
	lifecycle           sync.RWMutex
	mu                  sync.Mutex
	rootDir             string
	socketDir           string
	publicKey           ed25519.PublicKey
	runner              Runner
	health              HealthChecker
	now                 func() time.Time
	state               persistedState
	processes           map[string]Process
	processesGeneration map[string]uint64
	pluginMu            map[string]*sync.Mutex
	running             map[string]chan struct{}
	closed              bool
}

func NewSupervisor(config Config) (*Supervisor, error) {
	if strings.TrimSpace(config.RootDir) == "" {
		return nil, errors.New("plugin supervisor root directory is required")
	}
	if len(config.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid official plugin public key")
	}
	if config.Runner == nil {
		config.Runner = CommandRunner{}
	}
	if config.Health == nil {
		config.Health = GRPCHealthChecker{}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.SocketDir == "" {
		config.SocketDir = filepath.Join(config.RootDir, "sockets")
	}
	rootDir, err := filepath.Abs(config.RootDir)
	if err != nil {
		return nil, fmt.Errorf("resolve plugin supervisor root directory: %w", err)
	}
	socketDir, err := filepath.Abs(config.SocketDir)
	if err != nil {
		return nil, fmt.Errorf("resolve plugin supervisor socket directory: %w", err)
	}
	if err := ensurePrivateDir(rootDir); err != nil {
		return nil, err
	}
	if err := ensurePrivateDir(socketDir); err != nil {
		return nil, err
	}
	supervisor := &Supervisor{
		rootDir: rootDir, socketDir: socketDir, publicKey: append(ed25519.PublicKey(nil), config.PublicKey...),
		runner: config.Runner, health: config.Health, now: config.Now,
		state:     persistedState{Plugins: map[string]PluginState{}, Journal: map[string]JournalEntry{}},
		processes: map[string]Process{}, processesGeneration: map[string]uint64{},
		pluginMu: map[string]*sync.Mutex{}, running: map[string]chan struct{}{},
	}
	if err := supervisor.load(); err != nil {
		return nil, err
	}
	supervisor.restoreEnabled()
	return supervisor, nil
}

type InstallRequest struct {
	ManifestJSON string
	Signature    string
	Artifact     []byte
}

// Install verifies a signed artifact, writes it into an Agent-owned directory,
// and retains existing versions for explicit rollback.
func (s *Supervisor) Install(ctx context.Context, request InstallRequest) (*PluginState, error) {
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	manifest, err := VerifyManifest(request.ManifestJSON, request.Signature, s.publicKey)
	if err != nil {
		return nil, err
	}
	canonicalManifest, err := CanonicalManifest(*manifest)
	if err != nil {
		return nil, fmt.Errorf("canonicalize plugin manifest: %w", err)
	}
	canonicalSignature := strings.TrimSpace(request.Signature)
	digest := sha256.Sum256(request.Artifact)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), manifest.ArtifactSHA256) {
		return nil, errors.New("plugin artifact hash mismatch")
	}
	if len(request.Artifact) == 0 {
		return nil, errors.New("plugin artifact must not be empty")
	}
	if len(request.Artifact) > maxPluginArtifactBytes {
		return nil, fmt.Errorf("plugin artifact exceeds %d bytes", maxPluginArtifactBytes)
	}
	binary, packaged, err := materializeAgentArtifact(*manifest, request.Artifact)
	if err != nil {
		return nil, err
	}
	unlockPlugin := s.lockPlugin(manifest.ID)
	defer unlockPlugin()
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.versionDir(manifest.ID, manifest.Version)
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	currentManifestJSON, manifestReadErr := os.ReadFile(filepath.Join(dir, manifestFileName))
	currentSignature, signatureReadErr := os.ReadFile(filepath.Join(dir, signatureFileName))
	if manifestReadErr != nil && !errors.Is(manifestReadErr, os.ErrNotExist) {
		return nil, fmt.Errorf("read installed plugin manifest: %w", manifestReadErr)
	}
	if signatureReadErr != nil && !errors.Is(signatureReadErr, os.ErrNotExist) {
		return nil, fmt.Errorf("read installed plugin signature: %w", signatureReadErr)
	}
	hasManifest := manifestReadErr == nil
	hasSignature := signatureReadErr == nil
	if hasManifest != hasSignature {
		return nil, errors.New("installed plugin version metadata is incomplete; refusing immutable version overwrite")
	}
	if hasManifest {
		currentManifest, verifyErr := VerifyManifest(string(currentManifestJSON), strings.TrimSpace(string(currentSignature)), s.publicKey)
		if verifyErr != nil {
			return nil, fmt.Errorf("installed plugin version metadata is invalid; refusing immutable version overwrite: %w", verifyErr)
		}
		currentCanonical, canonicalErr := CanonicalManifest(*currentManifest)
		if canonicalErr != nil {
			return nil, fmt.Errorf("canonicalize installed plugin manifest: %w", canonicalErr)
		}
		if currentManifest.ID != manifest.ID || currentManifest.Version != manifest.Version ||
			!bytes.Equal(currentCanonical, canonicalManifest) || strings.TrimSpace(string(currentSignature)) != canonicalSignature {
			return nil, errors.New("installed plugin versions are immutable")
		}
	}
	if packaged {
		if err := writePrivateFile(filepath.Join(dir, pluginPackageName), request.Artifact, 0o600); err != nil {
			return nil, err
		}
	} else if err := os.Remove(filepath.Join(dir, pluginPackageName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := writePrivateFile(filepath.Join(dir, pluginBinaryName), binary, 0o750); err != nil {
		return nil, err
	}
	if err := writePrivateFile(filepath.Join(dir, manifestFileName), canonicalManifest, 0o600); err != nil {
		return nil, err
	}
	if err := writePrivateFile(filepath.Join(dir, signatureFileName), []byte(canonicalSignature), 0o600); err != nil {
		return nil, err
	}
	state, existed := s.state.Plugins[manifest.ID]
	previous := state
	if state.ID == "" {
		state.ID = manifest.ID
		state.DesiredVersion = manifest.Version
		state.Health = "installed"
	}
	state.LastError = ""
	state.UpdatedAt = s.now()
	s.state.Plugins[manifest.ID] = state
	if err := s.persistLocked(); err != nil {
		if existed {
			s.state.Plugins[manifest.ID] = previous
		} else {
			delete(s.state.Plugins, manifest.ID)
		}
		return nil, err
	}
	return copyPluginState(state), nil
}

// Handle executes an already validated plugin operation. It journals every
// result before returning it so stream retries cannot restart a process.
func (s *Supervisor) Handle(ctx context.Context, kind string, envelope *agent.OperationEnvelope) (json.RawMessage, error) {
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	if envelope == nil {
		return nil, errors.New("plugin operation envelope is required")
	}
	if err := validateOperation(kind, envelope); err != nil {
		return nil, err
	}
	envelopeCopy := *envelope
	envelopeCopy.ConfigHash = strings.ToLower(envelopeCopy.ConfigHash)
	envelopeCopy.Config = append(json.RawMessage(nil), envelope.Config...)
	envelope = &envelopeCopy

	for {
		s.mu.Lock()
		if previous, ok := s.state.Journal[envelope.OperationID]; ok {
			if !journalMatches(previous, kind, envelope) {
				s.mu.Unlock()
				return nil, errors.New("operation_id is already bound to a different plugin operation")
			}
			switch previous.State {
			case "succeeded":
				result := append(json.RawMessage(nil), previous.Result...)
				s.mu.Unlock()
				return result, nil
			case "failed":
				err := errors.New(previous.Error)
				if previous.Error == "" {
					err = errors.New("plugin operation previously failed")
				}
				s.mu.Unlock()
				return nil, err
			case "running":
				done := s.running[envelope.OperationID]
				if done == nil {
					previous.State = "failed"
					previous.Error = "plugin operation was interrupted before completion"
					previous.UpdatedAt = s.now()
					s.state.Journal[envelope.OperationID] = previous
					_ = s.persistLocked()
					s.mu.Unlock()
					return nil, errors.New(previous.Error)
				}
				s.mu.Unlock()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-done:
					continue
				}
			default:
				s.mu.Unlock()
				return nil, fmt.Errorf("plugin operation journal has invalid state %q", previous.State)
			}
		}
		for operationID, previous := range s.state.Journal {
			if operationID != envelope.OperationID && previous.IdempotencyKey == envelope.IdempotencyKey {
				s.mu.Unlock()
				return nil, errors.New("idempotency_key is already bound to a different plugin operation")
			}
		}
		done := make(chan struct{})
		s.running[envelope.OperationID] = done
		s.state.Journal[envelope.OperationID] = newJournalEntry(kind, envelope, s.now())
		if err := s.persistLocked(); err != nil {
			delete(s.state.Journal, envelope.OperationID)
			delete(s.running, envelope.OperationID)
			close(done)
			s.mu.Unlock()
			return nil, err
		}
		s.mu.Unlock()
		break
	}

	unlockPlugin := s.lockPlugin(envelope.PluginID)
	var result json.RawMessage
	var err error
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = ctxErr
	} else {
		result, err = s.handleOperation(ctx, kind, envelope)
	}
	unlockPlugin()
	s.mu.Lock()
	entry := s.state.Journal[envelope.OperationID]
	entry.UpdatedAt = s.now()
	if err != nil {
		entry.State, entry.Error = "failed", err.Error()
	} else {
		entry.State, entry.Result, entry.Error = "succeeded", append(json.RawMessage(nil), result...), ""
	}
	s.state.Journal[envelope.OperationID] = entry
	persistErr := s.persistLocked()
	done := s.running[envelope.OperationID]
	delete(s.running, envelope.OperationID)
	if done != nil {
		close(done)
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if persistErr != nil {
		return nil, persistErr
	}
	return result, nil
}

func (s *Supervisor) handleOperation(ctx context.Context, kind string, envelope *agent.OperationEnvelope) (json.RawMessage, error) {
	if operationMutatesState(kind) {
		if err := s.rejectStaleRevision(envelope); err != nil {
			return nil, err
		}
	}
	switch kind {
	case "plugin.inspect":
		return s.inspect(envelope.PluginID)
	case "plugin.configure":
		return s.configure(ctx, envelope)
	case "plugin.enable":
		return s.enable(ctx, envelope)
	case "plugin.disable":
		return s.disable(ctx, envelope)
	case "plugin.update":
		return s.update(ctx, envelope)
	case "plugin.rollback":
		return s.rollback(ctx, envelope)
	case "plugin.health":
		return s.healthCheck(ctx, envelope)
	default:
		return nil, fmt.Errorf("unsupported plugin operation %q", kind)
	}
}

func (s *Supervisor) inspect(pluginID string) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.state.Plugins[pluginID]
	if !ok {
		return nil, errors.New("plugin is not installed")
	}
	return json.Marshal(state)
}

func (s *Supervisor) configure(ctx context.Context, envelope *agent.OperationEnvelope) (json.RawMessage, error) {
	if containsInlineSecret(envelope.Config) {
		return nil, errors.New("plugin config must reference secrets instead of containing secret material")
	}
	s.mu.Lock()
	state, ok := s.state.Plugins[envelope.PluginID]
	if !ok || state.DesiredVersion == "" {
		s.mu.Unlock()
		return nil, errors.New("plugin is not installed")
	}
	if envelope.TargetVersion != state.DesiredVersion {
		s.mu.Unlock()
		return nil, errors.New("plugin operation target version is not installed")
	}
	original := state
	configPath := filepath.Join(s.versionDir(state.ID, state.DesiredVersion), "config.json")
	process := s.processes[state.ID]
	if !state.Enabled {
		if err := writePrivateFile(configPath, envelope.Config, 0o600); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		state.ConfigHash, state.DesiredRevision, state.UpdatedAt, state.LastError = envelope.ConfigHash, envelope.Revision, s.now(), ""
		s.state.Plugins[state.ID] = state
		err := s.persistLocked()
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return json.Marshal(state)
	}
	s.mu.Unlock()

	oldConfig, oldConfigExists, err := readOptionalFile(configPath)
	if err != nil {
		s.recordPluginError(original.ID, "unhealthy", err)
		return nil, err
	}
	s.mu.Lock()
	s.removeProcessLocked(state.ID)
	s.mu.Unlock()
	if process != nil {
		if err := process.Stop(ctx); err != nil {
			s.recordConfigureStopFailure(original, err)
			return nil, fmt.Errorf("stop plugin before configure: %w", err)
		}
	}
	if err := removeSocket(s.socketPath(state.ID)); err != nil {
		return nil, s.rollbackConfiguration(original, envelope, configPath, oldConfig, oldConfigExists, fmt.Errorf("remove old plugin socket: %w", err))
	}
	if err := writePrivateFile(configPath, envelope.Config, 0o600); err != nil {
		return nil, s.rollbackConfiguration(original, envelope, configPath, oldConfig, oldConfigExists, fmt.Errorf("write updated plugin config: %w", err))
	}
	newProcess, err := s.startVersion(ctx, state.ID, state.DesiredVersion)
	if err != nil {
		return nil, s.rollbackConfiguration(original, envelope, configPath, oldConfig, oldConfigExists, fmt.Errorf("restart plugin after configure: %w", err))
	}

	state.ConfigHash, state.DesiredRevision, state.UpdatedAt, state.LastError = envelope.ConfigHash, envelope.Revision, s.now(), ""
	state.ObservedRevision, state.Health, state.Enabled = maxRevision(state.ObservedRevision, envelope.Revision), "healthy", true
	s.mu.Lock()
	s.setProcessLocked(state.ID, newProcess)
	s.state.Plugins[state.ID] = state
	err = s.persistLocked()
	if err != nil {
		s.removeProcessLocked(state.ID)
		s.state.Plugins[state.ID] = original
	}
	s.mu.Unlock()
	if err != nil {
		stopErr := stopProcess(newProcess)
		return nil, s.rollbackConfiguration(original, envelope, configPath, oldConfig, oldConfigExists, errors.Join(fmt.Errorf("persist updated plugin config state: %w", err), stopErr))
	}
	return json.Marshal(state)
}

func readOptionalFile(path string) ([]byte, bool, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read existing plugin config: %w", err)
	}
	return contents, true, nil
}

func restoreOptionalFile(path string, contents []byte, existed bool) error {
	if existed {
		return writePrivateFile(path, contents, 0o600)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Supervisor) recordConfigureStopFailure(original PluginState, operationErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := original
	state.Enabled, state.Health = false, "unhealthy"
	state.LastError, state.UpdatedAt = operationErr.Error(), s.now()
	s.removeProcessLocked(state.ID)
	s.state.Plugins[state.ID] = state
	_ = s.persistLocked()
}

func (s *Supervisor) rollbackConfiguration(original PluginState, envelope *agent.OperationEnvelope, configPath string, oldConfig []byte, oldConfigExists bool, operationErr error) error {
	restoreErr := restoreOptionalFile(configPath, oldConfig, oldConfigExists)
	var rollbackProcess Process
	var rollbackErr error
	if restoreErr == nil {
		rollbackProcess, rollbackErr = s.startVersion(context.Background(), original.ID, original.DesiredVersion)
	}

	s.mu.Lock()
	state := original
	state.DesiredRevision = maxRevision(state.DesiredRevision, envelope.Revision)
	state.UpdatedAt = s.now()
	state.LastError = operationErr.Error()
	if restoreErr == nil && rollbackErr == nil {
		state.Enabled, state.Health, state.ObservedVersion = true, "healthy", original.DesiredVersion
		s.setProcessLocked(state.ID, rollbackProcess)
	} else {
		state.Enabled, state.Health = false, "unhealthy"
		s.removeProcessLocked(state.ID)
		state.LastError = errors.Join(operationErr, restoreErr, rollbackErr).Error()
	}
	s.state.Plugins[state.ID] = state
	persistErr := s.persistLocked()
	s.mu.Unlock()
	return errors.Join(operationErr, restoreErr, rollbackErr, persistErr)
}

func (s *Supervisor) enable(ctx context.Context, envelope *agent.OperationEnvelope) (json.RawMessage, error) {
	s.mu.Lock()
	state, ok := s.state.Plugins[envelope.PluginID]
	if !ok || state.DesiredVersion == "" {
		s.mu.Unlock()
		return nil, errors.New("plugin is not installed")
	}
	if state.DesiredVersion != envelope.TargetVersion {
		s.mu.Unlock()
		return nil, errors.New("plugin operation target version is not installed")
	}
	process := s.processes[state.ID]
	s.mu.Unlock()

	if process != nil && state.Enabled && state.ObservedVersion == state.DesiredVersion {
		if err := s.health.Check(ctx, s.socketPath(state.ID)); err == nil {
			s.mu.Lock()
			current := s.state.Plugins[state.ID]
			current.Health, current.LastError = "healthy", ""
			current.DesiredRevision = maxRevision(current.DesiredRevision, envelope.Revision)
			current.ObservedRevision = maxRevision(current.ObservedRevision, envelope.Revision)
			current.UpdatedAt = s.now()
			s.state.Plugins[state.ID] = current
			persistErr := s.persistLocked()
			s.mu.Unlock()
			if persistErr != nil {
				return nil, persistErr
			}
			return json.Marshal(current)
		}
		s.mu.Lock()
		s.removeProcessLocked(state.ID)
		s.mu.Unlock()
		if err := stopProcess(process); err != nil {
			s.recordConfigureStopFailure(state, err)
			return nil, fmt.Errorf("stop unhealthy plugin process: %w", err)
		}
		if err := removeSocket(s.socketPath(state.ID)); err != nil {
			s.recordConfigureStopFailure(state, err)
			return nil, err
		}
	}

	process, err := s.startVersion(ctx, state.ID, state.DesiredVersion)
	if err != nil {
		s.recordPluginError(state.ID, "unhealthy", err)
		return nil, err
	}
	s.mu.Lock()
	state = s.state.Plugins[state.ID]
	previous := state
	state.Enabled, state.Health, state.ObservedVersion = true, "healthy", state.DesiredVersion
	state.DesiredRevision, state.ObservedRevision = maxRevision(state.DesiredRevision, envelope.Revision), maxRevision(state.ObservedRevision, envelope.Revision)
	state.UpdatedAt, state.LastError = s.now(), ""
	s.setProcessLocked(state.ID, process)
	s.state.Plugins[state.ID] = state
	err = s.persistLocked()
	if err != nil {
		s.removeProcessLocked(state.ID)
		s.state.Plugins[state.ID] = previous
	}
	s.mu.Unlock()
	if err != nil {
		_ = stopProcess(process)
		return nil, err
	}
	return json.Marshal(state)
}

func (s *Supervisor) disable(ctx context.Context, envelope *agent.OperationEnvelope) (json.RawMessage, error) {
	s.mu.Lock()
	state, ok := s.state.Plugins[envelope.PluginID]
	if !ok {
		s.mu.Unlock()
		return nil, errors.New("plugin is not installed")
	}
	if state.DesiredVersion != envelope.TargetVersion {
		s.mu.Unlock()
		return nil, errors.New("plugin operation target version is not installed")
	}
	process := s.processes[state.ID]
	s.removeProcessLocked(state.ID)
	s.mu.Unlock()
	if process != nil {
		if err := process.Stop(ctx); err != nil {
			s.recordConfigureStopFailure(state, err)
			return nil, err
		}
	}
	socketErr := removeSocket(s.socketPath(envelope.PluginID))
	s.mu.Lock()
	state = s.state.Plugins[envelope.PluginID]
	state.Enabled, state.Health = false, "disabled"
	state.DesiredRevision, state.ObservedRevision, state.UpdatedAt = maxRevision(state.DesiredRevision, envelope.Revision), maxRevision(state.ObservedRevision, envelope.Revision), s.now()
	state.LastError = ""
	if socketErr != nil {
		state.LastError = socketErr.Error()
	}
	s.state.Plugins[envelope.PluginID] = state
	err := s.persistLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if socketErr != nil {
		return nil, socketErr
	}
	return json.Marshal(state)
}

func (s *Supervisor) update(ctx context.Context, envelope *agent.OperationEnvelope) (json.RawMessage, error) {
	s.mu.Lock()
	state, ok := s.state.Plugins[envelope.PluginID]
	if !ok {
		s.mu.Unlock()
		return nil, errors.New("plugin is not installed")
	}
	if state.DesiredVersion == envelope.TargetVersion {
		s.mu.Unlock()
		return s.enable(ctx, envelope)
	}
	if err := s.verifyInstalledVersion(state.ID, envelope.TargetVersion); err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("target plugin version is not installed or trusted: %w", err)
	}
	original := state
	oldProcess := s.processes[state.ID]
	s.mu.Unlock()

	if !original.Enabled {
		state = original
		state.PreviousVersion, state.DesiredVersion = original.DesiredVersion, envelope.TargetVersion
		state.Health, state.LastError = "installed", ""
		state.DesiredRevision, state.ObservedRevision = maxRevision(state.DesiredRevision, envelope.Revision), maxRevision(state.ObservedRevision, envelope.Revision)
		state.UpdatedAt = s.now()
		s.mu.Lock()
		s.state.Plugins[state.ID] = state
		err := s.persistLocked()
		if err != nil {
			s.state.Plugins[state.ID] = original
		}
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return json.Marshal(state)
	}

	if oldProcess != nil {
		s.mu.Lock()
		s.removeProcessLocked(original.ID)
		s.mu.Unlock()
		if err := oldProcess.Stop(ctx); err != nil {
			s.recordConfigureStopFailure(original, err)
			return nil, fmt.Errorf("stop current plugin version: %w", err)
		}
	}
	if err := removeSocket(s.socketPath(original.ID)); err != nil {
		s.recordConfigureStopFailure(original, err)
		return nil, err
	}

	newProcess, startErr := s.startVersion(ctx, original.ID, envelope.TargetVersion)
	if startErr != nil {
		rollbackProcess, rollbackErr := s.startVersion(context.Background(), original.ID, original.DesiredVersion)
		s.mu.Lock()
		state = original
		state.DesiredRevision = maxRevision(state.DesiredRevision, envelope.Revision)
		state.UpdatedAt = s.now()
		state.LastError = fmt.Sprintf("update to %s failed: %v", envelope.TargetVersion, startErr)
		if rollbackErr == nil {
			state.Enabled, state.Health, state.ObservedVersion = true, "healthy", original.DesiredVersion
			state.ObservedRevision = maxRevision(state.ObservedRevision, envelope.Revision)
			s.setProcessLocked(state.ID, rollbackProcess)
		} else {
			state.Enabled, state.Health = false, "unhealthy"
			state.LastError += fmt.Sprintf("; automatic rollback failed: %v", rollbackErr)
		}
		s.state.Plugins[state.ID] = state
		persistErr := s.persistLocked()
		s.mu.Unlock()
		if persistErr != nil {
			return nil, errors.Join(startErr, rollbackErr, persistErr)
		}
		return nil, errors.Join(fmt.Errorf("start updated plugin version: %w", startErr), rollbackErr)
	}

	state = original
	state.PreviousVersion, state.DesiredVersion = original.DesiredVersion, envelope.TargetVersion
	state.Enabled, state.Health, state.ObservedVersion = true, "healthy", envelope.TargetVersion
	state.DesiredRevision, state.ObservedRevision = maxRevision(state.DesiredRevision, envelope.Revision), maxRevision(state.ObservedRevision, envelope.Revision)
	state.UpdatedAt, state.LastError = s.now(), ""
	s.mu.Lock()
	s.setProcessLocked(state.ID, newProcess)
	s.state.Plugins[state.ID] = state
	persistErr := s.persistLocked()
	if persistErr != nil {
		s.removeProcessLocked(state.ID)
		s.state.Plugins[state.ID] = original
	}
	s.mu.Unlock()
	if persistErr != nil {
		_ = stopProcess(newProcess)
		rollbackProcess, rollbackErr := s.startVersion(context.Background(), original.ID, original.DesiredVersion)
		if rollbackErr == nil {
			s.mu.Lock()
			s.setProcessLocked(original.ID, rollbackProcess)
			s.mu.Unlock()
		}
		return nil, errors.Join(persistErr, rollbackErr)
	}
	return json.Marshal(state)
}

func (s *Supervisor) rollback(ctx context.Context, envelope *agent.OperationEnvelope) (json.RawMessage, error) {
	s.mu.Lock()
	state, ok := s.state.Plugins[envelope.PluginID]
	if !ok || state.PreviousVersion == "" {
		s.mu.Unlock()
		return nil, errors.New("plugin has no rollback version")
	}
	target := state.PreviousVersion
	s.mu.Unlock()
	if envelope.TargetVersion != target {
		return nil, errors.New("plugin rollback target does not match the installed previous version")
	}
	envelopeCopy := *envelope
	return s.update(ctx, &envelopeCopy)
}

func (s *Supervisor) healthCheck(ctx context.Context, envelope *agent.OperationEnvelope) (json.RawMessage, error) {
	s.mu.Lock()
	state, ok := s.state.Plugins[envelope.PluginID]
	if !ok {
		s.mu.Unlock()
		return nil, errors.New("plugin is not installed")
	}
	socket := s.socketPath(state.ID)
	s.mu.Unlock()
	if !state.Enabled {
		return s.inspect(envelope.PluginID)
	}
	if s.health != nil {
		if err := s.health.Check(ctx, socket); err != nil {
			s.mu.Lock()
			state = s.state.Plugins[envelope.PluginID]
			state.Health, state.LastError, state.UpdatedAt = "unhealthy", err.Error(), s.now()
			s.state.Plugins[envelope.PluginID] = state
			_ = s.persistLocked()
			s.mu.Unlock()
			return nil, err
		}
	}
	s.mu.Lock()
	state = s.state.Plugins[envelope.PluginID]
	state.Health, state.LastError, state.UpdatedAt = "healthy", "", s.now()
	s.state.Plugins[envelope.PluginID] = state
	err := s.persistLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return json.Marshal(state)
}

func (s *Supervisor) Close(ctx context.Context) error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	processes := make(map[string]Process, len(s.processes))
	for id, process := range s.processes {
		processes[id] = process
	}
	for id := range s.processes {
		s.removeProcessLocked(id)
	}
	s.mu.Unlock()
	var result error
	for id, process := range processes {
		err := process.Stop(ctx)
		result = errors.Join(result, err)
		s.mu.Lock()
		state := s.state.Plugins[id]
		state.Health, state.LastError, state.UpdatedAt = "stopped", "", s.now()
		if err != nil {
			state.Health, state.LastError = "unhealthy", err.Error()
		}
		s.state.Plugins[id] = state
		s.mu.Unlock()
	}
	s.mu.Lock()
	result = errors.Join(result, s.persistLocked())
	s.mu.Unlock()
	return result
}

func (s *Supervisor) binaryPath(state PluginState) string {
	return filepath.Join(s.versionDir(state.ID, state.DesiredVersion), pluginBinaryName)
}
func (s *Supervisor) versionDir(id, version string) string {
	return filepath.Join(s.rootDir, id, version)
}
func (s *Supervisor) socketPath(id string) string { return filepath.Join(s.socketDir, id+".sock") }

// setProcessLocked registers one process generation and starts an optional
// exit watcher. s.mu must be held by the caller.
func (s *Supervisor) setProcessLocked(id string, process Process) {
	s.processesGeneration[id]++
	generation := s.processesGeneration[id]
	s.processes[id] = process
	watcher, ok := process.(ProcessExitWatcher)
	if !ok {
		return
	}
	exited := watcher.Exited()
	if exited == nil {
		return
	}
	go s.observeProcessExit(id, generation, exited)
}

// removeProcessLocked invalidates all watchers for the current generation.
// s.mu must be held by the caller.
func (s *Supervisor) removeProcessLocked(id string) {
	s.processesGeneration[id]++
	delete(s.processes, id)
}

func (s *Supervisor) observeProcessExit(id string, generation uint64, exited <-chan error) {
	exitErr, _ := <-exited
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.processesGeneration[id] != generation {
		return
	}
	s.removeProcessLocked(id)
	socketErr := removeSocket(s.socketPath(id))
	state, ok := s.state.Plugins[id]
	if !ok {
		return
	}
	message := "plugin process exited unexpectedly"
	if exitErr != nil {
		message += ": " + exitErr.Error()
	}
	if socketErr != nil {
		message += "; remove socket: " + socketErr.Error()
	}
	state.Enabled, state.Health = false, "unhealthy"
	state.LastError, state.UpdatedAt = message, s.now()
	s.state.Plugins[id] = state
	_ = s.persistLocked()
}

func (s *Supervisor) load() error {
	data, err := os.ReadFile(filepath.Join(s.rootDir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s.state); err != nil {
		return fmt.Errorf("read plugin supervisor state: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("read plugin supervisor state: multiple JSON values")
	}
	if s.state.Plugins == nil {
		s.state.Plugins = map[string]PluginState{}
	}
	if s.state.Journal == nil {
		s.state.Journal = map[string]JournalEntry{}
	}
	changed := false
	for id, state := range s.state.Plugins {
		if !safeSegment(id) || state.ID != id || !safeOptionalSegment(state.DesiredVersion) || !safeOptionalSegment(state.ObservedVersion) || !safeOptionalSegment(state.PreviousVersion) {
			return fmt.Errorf("read plugin supervisor state: invalid plugin state for %q", id)
		}
		if state.ConfigHash != "" && !validSHA256(state.ConfigHash) {
			return fmt.Errorf("read plugin supervisor state: invalid config hash for %q", id)
		}
	}
	for operationID, entry := range s.state.Journal {
		if entry.OperationID != operationID || strings.TrimSpace(operationID) == "" {
			return fmt.Errorf("read plugin supervisor state: invalid journal entry %q", operationID)
		}
		if entry.Result != nil && !json.Valid(entry.Result) {
			return fmt.Errorf("read plugin supervisor state: invalid journal result for %q", operationID)
		}
		if entry.State == "running" {
			entry.State = "failed"
			entry.Error = "plugin operation was interrupted by agent restart"
			entry.UpdatedAt = s.now()
			s.state.Journal[operationID] = entry
			changed = true
		}
	}
	if changed {
		return s.persistLocked()
	}
	return nil
}

func (s *Supervisor) persistLocked() error {
	encoded, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	return writePrivateFile(filepath.Join(s.rootDir, "state.json"), encoded, 0o600)
}

func writePrivateFile(path string, contents []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("plugin path %q must be a real directory", path)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return nil
}

func (s *Supervisor) checkOpen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("plugin supervisor is closed")
	}
	return nil
}

func (s *Supervisor) lockPlugin(id string) func() {
	s.mu.Lock()
	lock := s.pluginMu[id]
	if lock == nil {
		lock = &sync.Mutex{}
		s.pluginMu[id] = lock
	}
	s.mu.Unlock()
	lock.Lock()
	return lock.Unlock
}

func (s *Supervisor) rejectStaleRevision(envelope *agent.OperationEnvelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.state.Plugins[envelope.PluginID]
	if !ok {
		return nil
	}
	if envelope.Revision <= state.DesiredRevision {
		return fmt.Errorf("plugin operation revision %d is not newer than desired revision %d", envelope.Revision, state.DesiredRevision)
	}
	return nil
}

func (s *Supervisor) startVersion(ctx context.Context, id, version string) (Process, error) {
	if err := s.verifyInstalledVersion(id, version); err != nil {
		return nil, err
	}
	socket := s.socketPath(id)
	if len(socket) > maxSocketPathLen {
		return nil, fmt.Errorf("plugin Unix socket path is too long: %d bytes", len(socket))
	}
	binary := filepath.Join(s.versionDir(id, version), pluginBinaryName)
	config := filepath.Join(s.versionDir(id, version), "config.json")
	process, err := s.runner.Start(ctx, binary, socket, config)
	if err != nil {
		return nil, err
	}
	if err := s.health.Check(ctx, socket); err != nil {
		stopErr := stopProcess(process)
		return nil, errors.Join(fmt.Errorf("plugin health check failed: %w", err), stopErr)
	}
	return process, nil
}

func (s *Supervisor) verifyInstalledVersion(id, version string) error {
	if !safeSegment(id) || !safeSegment(version) {
		return errors.New("plugin id and version must be safe path segments")
	}
	dir := s.versionDir(id, version)
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("plugin version path is not a real directory")
	}
	manifestJSON, err := os.ReadFile(filepath.Join(dir, manifestFileName))
	if err != nil {
		return fmt.Errorf("read installed plugin manifest: %w", err)
	}
	signature, err := os.ReadFile(filepath.Join(dir, signatureFileName))
	if err != nil {
		return fmt.Errorf("read installed plugin signature: %w", err)
	}
	manifest, err := VerifyManifest(string(manifestJSON), strings.TrimSpace(string(signature)), s.publicKey)
	if err != nil {
		return fmt.Errorf("verify installed plugin manifest: %w", err)
	}
	if manifest.ID != id || manifest.Version != version {
		return errors.New("installed plugin manifest does not match its path")
	}
	binaryPath := filepath.Join(dir, pluginBinaryName)
	binaryInfo, err := os.Lstat(binaryPath)
	if err != nil {
		return fmt.Errorf("inspect installed plugin artifact: %w", err)
	}
	if binaryInfo.Mode()&os.ModeSymlink != 0 || !binaryInfo.Mode().IsRegular() {
		return errors.New("installed plugin artifact must be a regular file")
	}
	if binaryInfo.Mode().Perm()&0o111 == 0 {
		return errors.New("installed plugin artifact is not executable")
	}
	return verifyInstalledAgentArtifact(*manifest, dir, binaryPath)
}

func stopProcess(process Process) error {
	if process == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	return process.Stop(ctx)
}

func (s *Supervisor) recordPluginError(id, health string, operationErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.state.Plugins[id]
	if !ok {
		return
	}
	state.Health, state.LastError, state.UpdatedAt = health, operationErr.Error(), s.now()
	s.state.Plugins[id] = state
	_ = s.persistLocked()
}

func (s *Supervisor) restoreEnabled() {
	s.mu.Lock()
	plugins := make([]PluginState, 0, len(s.state.Plugins))
	for _, state := range s.state.Plugins {
		if state.Enabled {
			plugins = append(plugins, state)
		}
	}
	s.mu.Unlock()
	for _, persisted := range plugins {
		process, err := s.startVersion(context.Background(), persisted.ID, persisted.DesiredVersion)
		s.mu.Lock()
		state := s.state.Plugins[persisted.ID]
		state.UpdatedAt = s.now()
		if err != nil {
			state.Health, state.LastError = "unhealthy", fmt.Sprintf("restore enabled plugin: %v", err)
		} else {
			state.Health, state.LastError, state.ObservedVersion = "healthy", "", state.DesiredVersion
			s.setProcessLocked(state.ID, process)
		}
		s.state.Plugins[state.ID] = state
		s.mu.Unlock()
	}
	if len(plugins) > 0 {
		s.mu.Lock()
		_ = s.persistLocked()
		s.mu.Unlock()
	}
}

func newJournalEntry(kind string, envelope *agent.OperationEnvelope, now time.Time) JournalEntry {
	return JournalEntry{
		OperationID: envelope.OperationID, IdempotencyKey: envelope.IdempotencyKey,
		SessionID: envelope.SessionID, Kind: kind, PluginID: envelope.PluginID,
		TargetVersion: envelope.TargetVersion, ConfigHash: envelope.ConfigHash,
		Revision: envelope.Revision, State: "running", UpdatedAt: now,
	}
}

func journalMatches(entry JournalEntry, kind string, envelope *agent.OperationEnvelope) bool {
	return entry.OperationID == envelope.OperationID && entry.IdempotencyKey == envelope.IdempotencyKey &&
		entry.Kind == kind && entry.PluginID == envelope.PluginID &&
		entry.TargetVersion == envelope.TargetVersion && strings.EqualFold(entry.ConfigHash, envelope.ConfigHash) &&
		entry.Revision == envelope.Revision
}

func validateOperation(kind string, envelope *agent.OperationEnvelope) error {
	switch kind {
	case "plugin.inspect", "plugin.configure", "plugin.enable", "plugin.disable", "plugin.update", "plugin.rollback", "plugin.health":
	default:
		return fmt.Errorf("unsupported plugin operation %q", kind)
	}
	if envelope.Version != agent.OperationEnvelopeVersion {
		return fmt.Errorf("unsupported plugin operation envelope version %q", envelope.Version)
	}
	if !safeIdentity(envelope.OperationID, 160) || !safeIdentity(envelope.IdempotencyKey, 160) || !safeIdentity(envelope.SessionID, 160) {
		return errors.New("plugin operation identity fields are required")
	}
	if !safeSegment(envelope.PluginID) || !safeSegment(envelope.TargetVersion) {
		return errors.New("plugin operation id and target version must be safe path segments")
	}
	if envelope.Revision == 0 {
		return errors.New("plugin operation revision must be positive")
	}
	if !validSHA256(envelope.ConfigHash) {
		return errors.New("plugin operation config_hash must be a SHA-256 digest")
	}
	if len(envelope.Config) > 0 && !json.Valid(envelope.Config) {
		return errors.New("plugin operation config must be valid JSON")
	}
	digest := sha256.Sum256(envelope.Config)
	if !strings.EqualFold(envelope.ConfigHash, hex.EncodeToString(digest[:])) {
		return errors.New("plugin operation config_hash does not match config")
	}
	return nil
}

func safeIdentity(value string, maxLength int) bool {
	return value != "" && len(value) <= maxLength && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func operationMutatesState(kind string) bool {
	switch kind {
	case "plugin.configure", "plugin.enable", "plugin.disable", "plugin.update", "plugin.rollback":
		return true
	default:
		return false
	}
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func safePluginExtensionID(value string) bool {
	if len(value) == 0 || len(value) > 120 || value != strings.ToLower(value) || !asciiAlphaNumeric(value[0]) || !asciiAlphaNumeric(value[len(value)-1]) || strings.Contains(value, "..") {
		return false
	}
	for i := range value {
		if !asciiAlphaNumeric(value[i]) && value[i] != '.' && value[i] != '_' && value[i] != '-' {
			return false
		}
	}
	return true
}

func safeNamespacedExtensionID(value, pluginID string) bool {
	if !strings.HasPrefix(value, pluginID+".") || len(value) > 180 || !safeExtensionToken(value) {
		return false
	}
	return !strings.Contains(value, "..")
}

func safeExtensionToken(value string) bool {
	if value == "" {
		return false
	}
	for i := range value {
		if !asciiAlphaNumeric(value[i]) && value[i] != '.' && value[i] != '_' && value[i] != '-' {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func safeExtensionMetadataText(value string, maxLength int) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > maxLength {
		return false
	}
	for i := range value {
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func safeJavaScriptExport(value string) bool {
	if value == "" || len(value) > 120 {
		return false
	}
	for i := range value {
		character := value[i]
		if i == 0 {
			if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || character == '_' || character == '$') {
				return false
			}
			continue
		}
		if !asciiAlphaNumeric(character) && character != '_' && character != '$' {
			return false
		}
	}
	return true
}

func validateManifestPermissions(pluginID string, permissions []string) error {
	seen := make(map[string]bool, len(permissions))
	for _, permission := range permissions {
		if !safeNamespacedExtensionID(permission, pluginID) {
			return fmt.Errorf("plugin permission %q is outside the plugin namespace", permission)
		}
		if seen[permission] {
			return fmt.Errorf("duplicate plugin permission %q", permission)
		}
		seen[permission] = true
	}
	return nil
}

func validatePluginBundlePath(value string) error {
	if value == "" || value != strings.TrimSpace(value) || !strings.HasPrefix(value, "webui/") {
		return errors.New("webui bundle path must be relative to the webui directory")
	}
	if strings.ContainsAny(value, "\\%?#\r\n\t ") || strings.HasPrefix(value, "/") || path.Clean(value) != value || strings.Contains(value, "//") {
		return errors.New("webui bundle path is unsafe")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != value {
		return errors.New("webui bundle path is unsafe")
	}
	for i := range value {
		character := value[i]
		if !asciiAlphaNumeric(character) && character != '.' && character != '_' && character != '-' && character != '/' {
			return errors.New("webui bundle path contains unsupported characters")
		}
	}
	extension := strings.ToLower(path.Ext(value))
	if extension != ".js" && extension != ".mjs" {
		return errors.New("webui bundle must be a JavaScript module")
	}
	return nil
}

func validatePluginControlRoute(value, pluginID string) error {
	if value == "" || value != strings.TrimSpace(value) {
		return errors.New("control route is required")
	}
	if strings.Count(value, "*") > 1 || (strings.Contains(value, "*") && !strings.HasSuffix(value, "/*")) {
		return fmt.Errorf("control route %q has an invalid wildcard", value)
	}
	routePath := strings.TrimSuffix(value, "/*")
	if routePath == "" {
		return fmt.Errorf("control route %q is unsafe", value)
	}
	namespace := "/api/v3/plugins/" + pluginID
	if routePath != namespace && !strings.HasPrefix(routePath, namespace+"/") {
		return fmt.Errorf("control route %q is outside %s", value, namespace)
	}
	if strings.ContainsAny(routePath, "\\%?#\r\n\t ") || path.Clean(routePath) != routePath || strings.Contains(routePath, "//") {
		return fmt.Errorf("control route %q is unsafe", value)
	}
	parsed, err := url.Parse(routePath)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != routePath {
		return fmt.Errorf("control route %q is unsafe", value)
	}
	return nil
}

func validatePluginAdminRoute(value, pluginID string) error {
	namespace := "/admin/extensions/" + pluginID
	if value == "" || value != strings.TrimSpace(value) || (value != namespace && !strings.HasPrefix(value, namespace+"/")) {
		return fmt.Errorf("webui route %q is outside %s", value, namespace)
	}
	if strings.ContainsAny(value, "\\%?#\r\n\t ") || path.Clean(value) != value || strings.Contains(value, "//") {
		return fmt.Errorf("webui route %q is unsafe", value)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != value {
		return fmt.Errorf("webui route %q is unsafe", value)
	}
	return nil
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func validateArchitectures(architectures []string, goos, goarch string) error {
	if len(architectures) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(architectures))
	supported := false
	for _, architecture := range architectures {
		if architecture == "" || architecture != strings.ToLower(architecture) || architecture != strings.TrimSpace(architecture) {
			return fmt.Errorf("invalid plugin architecture %q", architecture)
		}
		if _, exists := seen[architecture]; exists {
			return fmt.Errorf("duplicate plugin architecture %q", architecture)
		}
		seen[architecture] = struct{}{}
		if architecture == "any" || architecture == "*" || architecture == goarch || architecture == goos+"/"+goarch || architecture == goos+"-"+goarch {
			supported = true
			continue
		}
		parts := strings.FieldsFunc(architecture, func(char rune) bool { return char == '/' || char == '-' })
		if len(parts) > 2 {
			return fmt.Errorf("invalid plugin architecture %q", architecture)
		}
		for _, part := range parts {
			if !safeSegment(part) {
				return fmt.Errorf("invalid plugin architecture %q", architecture)
			}
		}
	}
	if !supported {
		return fmt.Errorf("plugin manifest does not support agent architecture %s/%s", goos, goarch)
	}
	return nil
}

func validatePluginRelationships(pluginID string, dependencies, conflicts []string) error {
	dependencySet := make(map[string]struct{}, len(dependencies))
	for _, dependency := range dependencies {
		if !safeSegment(dependency) {
			return fmt.Errorf("invalid plugin dependency %q", dependency)
		}
		if dependency == pluginID {
			return errors.New("plugin cannot depend on itself")
		}
		if _, exists := dependencySet[dependency]; exists {
			return fmt.Errorf("duplicate plugin dependency %q", dependency)
		}
		dependencySet[dependency] = struct{}{}
	}
	conflictSet := make(map[string]struct{}, len(conflicts))
	for _, conflict := range conflicts {
		if !safeSegment(conflict) {
			return fmt.Errorf("invalid plugin conflict %q", conflict)
		}
		if conflict == pluginID {
			return errors.New("plugin cannot conflict with itself")
		}
		if _, exists := conflictSet[conflict]; exists {
			return fmt.Errorf("duplicate plugin conflict %q", conflict)
		}
		if _, dependency := dependencySet[conflict]; dependency {
			return fmt.Errorf("plugin %q cannot be both a dependency and a conflict", conflict)
		}
		conflictSet[conflict] = struct{}{}
	}
	return nil
}

func safeRelativePath(value string) bool {
	if value == "" || strings.ContainsAny(value, "\\\x00") || path.IsAbs(value) {
		return false
	}
	cleaned := path.Clean(value)
	if cleaned != value || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return false
	}
	for _, segment := range strings.Split(cleaned, "/") {
		if !safeSegment(segment) {
			return false
		}
	}
	return true
}

func safeSegment(value string) bool {
	if value == "" || len(value) > 120 || value != strings.TrimSpace(value) || value == "." || value == ".." || value != filepath.Base(value) || strings.ContainsAny(value, `\\/`) {
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

func safeOptionalSegment(value string) bool { return value == "" || safeSegment(value) }
func manifestSupportsTarget(manifest Manifest, target string) bool {
	for _, candidate := range manifest.Targets {
		if candidate == target {
			return true
		}
	}
	return false
}
func maxRevision(current, candidate uint64) uint64 {
	if candidate > current {
		return candidate
	}
	return current
}
func copyPluginState(state PluginState) *PluginState { copy := state; return &copy }

func containsInlineSecret(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return true
	}
	return containsSecretValue(value)
}

func containsSecretValue(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), ".", "_"))
			compact := strings.ReplaceAll(normalized, "_", "")
			reference := strings.HasSuffix(normalized, "_id") || strings.HasSuffix(normalized, "_ref") || strings.HasSuffix(compact, "id") || strings.HasSuffix(compact, "ref")
			sensitive := normalized == "secret" || normalized == "password" || normalized == "token" || normalized == "api_key" || normalized == "private_key" || normalized == "preshared_key" || compact == "apikey" || compact == "privatekey" || compact == "presharedkey"
			if sensitive && !reference && child != nil {
				return true
			}
			if containsSecretValue(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsSecretValue(child) {
				return true
			}
		}
	}
	return false
}
