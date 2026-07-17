package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/AnixOps/anix-agent/v3/api/agent"
)

const (
	PluginInstallAPIVersion = "anixops.io/plugin-install/v1alpha1"
	maxRemoteManifestBytes  = 1 << 20
)

type RemoteInstallerConfig struct {
	Supervisor *Supervisor
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

type RemoteInstaller struct {
	supervisor *Supervisor
	baseURL    *url.URL
	apiKey     string
	client     *http.Client
}

type remoteInstallSpec struct {
	APIVersion string              `json:"api_version"`
	PluginID   string              `json:"plugin_id"`
	Version    string              `json:"version"`
	Artifact   remoteAsset         `json:"artifact"`
	Manifest   remoteManifestAsset `json:"manifest"`
}

type remoteAsset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type remoteManifestAsset struct {
	remoteAsset
	Signature  string `json:"signature"`
	Publisher  string `json:"publisher"`
	KeyID      string `json:"key_id"`
	APIVersion string `json:"api_version"`
}

func NewRemoteInstaller(config RemoteInstallerConfig) (*RemoteInstaller, error) {
	if config.Supervisor == nil {
		return nil, errors.New("plugin supervisor is required")
	}
	baseURL, err := url.Parse(strings.TrimSpace(config.BaseURL))
	if err != nil || baseURL == nil || (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.Host == "" {
		return nil, errors.New("plugin download base URL must be an absolute HTTP(S) URL")
	}
	if baseURL.User != nil || baseURL.Fragment != "" {
		return nil, errors.New("plugin download base URL must not contain credentials or a fragment")
	}
	apiKey := strings.TrimSpace(config.APIKey)
	if apiKey == "" || strings.ContainsAny(apiKey, "\x00\r\n") {
		return nil, errors.New("plugin download node API key is required")
	}
	client := &http.Client{}
	if config.HTTPClient != nil {
		copy := *config.HTTPClient
		client = &copy
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &RemoteInstaller{supervisor: config.Supervisor, baseURL: baseURL, apiKey: apiKey, client: client}, nil
}

func (i *RemoteInstaller) Handle(ctx context.Context, envelope *agent.OperationEnvelope) (json.RawMessage, error) {
	if envelope == nil {
		return nil, errors.New("plugin install operation envelope is required")
	}
	spec, err := decodeRemoteInstallSpec(envelope.Config)
	if err != nil {
		return nil, err
	}
	if spec.PluginID != envelope.PluginID || spec.Version != envelope.TargetVersion {
		return nil, errors.New("plugin install payload does not match the operation target")
	}
	if err := i.validateSpec(spec); err != nil {
		return nil, err
	}
	return i.supervisor.HandleInstall(ctx, envelope, func(fetchCtx context.Context) (InstallRequest, error) {
		manifestJSON, err := i.fetch(fetchCtx, spec.PluginID, spec.Version, "manifest", spec.Manifest.remoteAsset, maxRemoteManifestBytes)
		if err != nil {
			return InstallRequest{}, err
		}
		manifest, err := VerifyManifest(string(manifestJSON), spec.Manifest.Signature, i.supervisor.publicKey)
		if err != nil {
			return InstallRequest{}, fmt.Errorf("verify downloaded plugin manifest: %w", err)
		}
		if manifest.ID != spec.PluginID || manifest.Version != spec.Version {
			return InstallRequest{}, errors.New("downloaded plugin manifest identity does not match install payload")
		}
		if manifest.Publisher != spec.Manifest.Publisher || manifest.APIVersion != spec.Manifest.APIVersion {
			return InstallRequest{}, errors.New("downloaded plugin manifest metadata does not match install payload")
		}
		if !strings.EqualFold(manifest.ArtifactSHA256, spec.Artifact.SHA256) {
			return InstallRequest{}, errors.New("downloaded plugin manifest artifact hash does not match install payload")
		}
		artifact, err := i.fetch(fetchCtx, spec.PluginID, spec.Version, "artifact", spec.Artifact, maxPluginArtifactBytes)
		if err != nil {
			return InstallRequest{}, err
		}
		return InstallRequest{ManifestJSON: string(manifestJSON), Signature: spec.Manifest.Signature, Artifact: artifact}, nil
	})
}

func decodeRemoteInstallSpec(raw json.RawMessage) (*remoteInstallSpec, error) {
	var spec remoteInstallSpec
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return nil, fmt.Errorf("decode plugin install payload: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("decode plugin install payload: multiple JSON values")
	}
	return &spec, nil
}

func (i *RemoteInstaller) validateSpec(spec *remoteInstallSpec) error {
	if spec == nil {
		return errors.New("plugin install payload is required")
	}
	if spec.APIVersion != PluginInstallAPIVersion {
		return fmt.Errorf("unsupported plugin install API version %q", spec.APIVersion)
	}
	if !safeSegment(spec.PluginID) || !safeSegment(spec.Version) {
		return errors.New("plugin install identity is invalid")
	}
	if spec.Manifest.Publisher != manifestPublisher || spec.Manifest.APIVersion != pluginAPIVersion {
		return errors.New("plugin install manifest metadata is not official or supported")
	}
	if spec.Manifest.KeyID != trustRootKeyID(i.supervisor.publicKey) {
		return errors.New("plugin install manifest key_id does not match the configured official trust root")
	}
	if strings.TrimSpace(spec.Manifest.Signature) == "" || len(spec.Manifest.Signature) > 4096 {
		return errors.New("plugin install manifest signature is invalid")
	}
	if err := validateRemoteAsset(spec.Manifest.remoteAsset, maxRemoteManifestBytes); err != nil {
		return fmt.Errorf("plugin manifest download: %w", err)
	}
	if err := validateRemoteAsset(spec.Artifact, maxPluginArtifactBytes); err != nil {
		return fmt.Errorf("plugin artifact download: %w", err)
	}
	if _, err := i.resolveAssetURL(spec.PluginID, spec.Version, "manifest", spec.Manifest.remoteAsset); err != nil {
		return err
	}
	if _, err := i.resolveAssetURL(spec.PluginID, spec.Version, "artifact", spec.Artifact); err != nil {
		return err
	}
	return nil
}

func validateRemoteAsset(asset remoteAsset, maximum int64) error {
	if !validSHA256(asset.SHA256) {
		return errors.New("sha256 must be a hexadecimal SHA-256 digest")
	}
	if asset.Size <= 0 || asset.Size > maximum {
		return fmt.Errorf("size must be between 1 and %d bytes", maximum)
	}
	return nil
}

func trustRootKeyID(publicKey []byte) string {
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:])[:16]
}

func (i *RemoteInstaller) resolveAssetURL(pluginID, version, kind string, asset remoteAsset) (*url.URL, error) {
	raw := strings.TrimSpace(asset.URL)
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return nil, fmt.Errorf("plugin %s URL must be a same-origin absolute path", kind)
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("plugin %s URL must be a valid same-origin path", kind)
	}
	if parsed.RawPath != "" || strings.Contains(strings.SplitN(raw, "?", 2)[0], "%") {
		return nil, fmt.Errorf("plugin %s URL must not use encoded path segments", kind)
	}
	expectedPath := path.Join("/api/v3/agent/plugin-releases", pluginID, version, kind)
	if parsed.Path != expectedPath {
		return nil, fmt.Errorf("plugin %s URL path does not match the requested release", kind)
	}
	query := parsed.Query()
	if len(query) != 2 || len(query["sha256"]) != 1 || len(query["size"]) != 1 ||
		!strings.EqualFold(query.Get("sha256"), asset.SHA256) || query.Get("size") != strconv.FormatInt(asset.Size, 10) {
		return nil, fmt.Errorf("plugin %s URL query does not match its signed metadata", kind)
	}
	return &url.URL{Scheme: i.baseURL.Scheme, Host: i.baseURL.Host, Path: parsed.Path, RawQuery: parsed.RawQuery}, nil
}

func (i *RemoteInstaller) fetch(ctx context.Context, pluginID, version, kind string, asset remoteAsset, maximum int64) ([]byte, error) {
	if asset.Size > maximum {
		return nil, fmt.Errorf("plugin %s exceeds the download limit", kind)
	}
	target, err := i.resolveAssetURL(pluginID, version, kind, asset)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-API-Key", i.apiKey)
	request.Header.Set("Accept-Encoding", "identity")
	response, err := i.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download plugin %s: %w", kind, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download plugin %s: unexpected HTTP status %d", kind, response.StatusCode)
	}
	if encoding := strings.TrimSpace(response.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return nil, fmt.Errorf("download plugin %s: content encoding is not allowed", kind)
	}
	if response.ContentLength >= 0 && response.ContentLength != asset.Size {
		return nil, fmt.Errorf("download plugin %s: content length does not match metadata", kind)
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, asset.Size+1))
	if err != nil {
		return nil, fmt.Errorf("download plugin %s body: %w", kind, err)
	}
	if int64(len(contents)) != asset.Size {
		return nil, fmt.Errorf("download plugin %s: body size does not match metadata", kind)
	}
	digest := sha256.Sum256(contents)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), asset.SHA256) {
		return nil, fmt.Errorf("download plugin %s: SHA-256 mismatch", kind)
	}
	return contents, nil
}
