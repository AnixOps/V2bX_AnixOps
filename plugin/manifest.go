package plugin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
)

const (
	manifestPublisher            = "AnixOps"
	pluginAPIVersionV1           = "v1"
	pluginAPIVersionV2           = "v2"
	pluginAPIVersion             = pluginAPIVersionV1
	agentRuntimeAPIVersionV110   = "anixops.agent.sdk/v1.1.0"
	packageEntrypointIndexFormat = "anixops.package-entrypoints/v1"
	agentEntrypointIndexPath     = "agent/entrypoints.json"
)

// Manifest describes the signed package contract accepted by the Agent. V1
// fields remain available while installed legacy packages are supported; v2
// adds immutable host and runtime metadata for package materialization.
type Manifest struct {
	ID                  string                       `json:"id"`
	Name                string                       `json:"name"`
	Version             string                       `json:"version"`
	APIVersion          string                       `json:"api_version"`
	Publisher           string                       `json:"publisher"`
	Targets             []string                     `json:"targets"`
	Architectures       []string                     `json:"architectures"`
	ArtifactSHA256      string                       `json:"artifact_sha256"`
	Capabilities        []string                     `json:"capabilities"`
	Dependencies        []string                     `json:"dependencies"`
	Conflicts           []string                     `json:"conflicts"`
	Permissions         []string                     `json:"permissions"`
	ConfigSchema        json.RawMessage              `json:"config_schema"`
	SecretFields        []string                     `json:"secret_fields"`
	Entrypoints         map[string]string            `json:"entrypoints"`
	Migration           int64                        `json:"migration_version"`
	ControlRoutes       []string                     `json:"control_routes"`
	FrontendSHA256      string                       `json:"frontend_sha256"`
	WebUI               *PluginWebUI                 `json:"webui,omitempty"`
	ControlEntrypoint   *ManifestEntrypoint          `json:"control_entrypoint,omitempty"`
	AgentEntrypoint     *ManifestEntrypoint          `json:"agent_entrypoint,omitempty"`
	Migrations          *ManifestMigrations          `json:"migrations,omitempty"`
	CompatibilityRoutes *ManifestCompatibilityRoutes `json:"compatibility_routes,omitempty"`
	RouteContractDigest string                       `json:"route_contract_digest,omitempty"`
	RuntimeAPIVersion   string                       `json:"runtime_api_version,omitempty"`
}

type ManifestEntrypoint struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type ManifestMigrations struct {
	Index  string `json:"index"`
	SHA256 string `json:"sha256"`
}

type ManifestCompatibilityRoutes struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
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

func isSupportedPluginAPIVersion(value string) bool {
	return value == pluginAPIVersionV1 || value == pluginAPIVersionV2
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
	if !isSupportedPluginAPIVersion(m.APIVersion) {
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
	if containsString(m.Capabilities, "plugin.cleanup") && !containsString(m.Capabilities, "plugin.runtime-state") {
		return errors.New("plugin.cleanup capability requires plugin.runtime-state")
	}
	if containsString(m.Capabilities, observedStateCapability) && !containsString(m.Capabilities, "plugin.runtime-state") {
		return fmt.Errorf("%s capability requires plugin.runtime-state", observedStateCapability)
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
	if m.APIVersion == pluginAPIVersionV2 {
		return m.validateV2Contract(goos, goarch)
	}
	return nil
}

func (m Manifest) validateV2Contract(goos, goarch string) error {
	if manifestSupportsTarget(m, "control") {
		if err := validateManifestEntrypoint(m.ControlEntrypoint, "control_entrypoint"); err != nil {
			return err
		}
	} else if m.ControlEntrypoint != nil {
		return errors.New("control_entrypoint requires the control target")
	}
	if err := validateManifestMigrations(m.Migrations); err != nil {
		return err
	}
	if err := validateManifestCompatibilityRoutes(m.CompatibilityRoutes); err != nil {
		return err
	}
	if !validSHA256(m.RouteContractDigest) {
		return errors.New("route_contract_digest must be a SHA-256 digest")
	}
	if err := validateManifestEntrypoint(m.AgentEntrypoint, "agent_entrypoint"); err != nil {
		return err
	}
	if m.AgentEntrypoint.Path != agentEntrypointIndexPath && m.AgentEntrypoint.Path != "agent/"+goos+"-"+goarch+"/plugin" {
		return fmt.Errorf("agent_entrypoint must match %s/%s or %s", goos, goarch, agentEntrypointIndexPath)
	}
	if m.RuntimeAPIVersion != agentRuntimeAPIVersionV110 {
		return fmt.Errorf("runtime_api_version must match %q", agentRuntimeAPIVersionV110)
	}
	return nil
}

func validateManifestEntrypoint(value *ManifestEntrypoint, field string) error {
	if value == nil || !safeRelativePath(value.Path) || !validSHA256(value.SHA256) {
		return fmt.Errorf("%s must declare a canonical path and SHA-256 digest", field)
	}
	return nil
}

func validateManifestMigrations(value *ManifestMigrations) error {
	if value == nil || !safeRelativePath(value.Index) || !validSHA256(value.SHA256) {
		return errors.New("migrations must declare a canonical index and SHA-256 digest")
	}
	return nil
}

func validateManifestCompatibilityRoutes(value *ManifestCompatibilityRoutes) error {
	if value == nil || !safeRelativePath(value.Path) || !validSHA256(value.SHA256) {
		return errors.New("compatibility_routes must declare a canonical path and SHA-256 digest")
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
