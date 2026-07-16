package machinetelemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	ID                     = "machine-telemetry"
	Version                = "1.0.0"
	DefaultIntervalSeconds = 60
	MinimumIntervalSeconds = 5
	MaximumIntervalSeconds = 3600
	maxConfigBytes         = 64 << 10
)

type Config struct {
	IntervalSeconds int
}

func (c Config) Interval() time.Duration {
	return time.Duration(c.IntervalSeconds) * time.Second
}

type rawConfig struct {
	IntervalSeconds json.RawMessage `json:"interval_seconds"`
}

// LoadConfig reads the Supervisor-owned configuration without following a
// final-path symlink. The manifest schema is enforced again at the process
// boundary so a manually modified file cannot relax the signed contract.
func LoadConfig(path string) (Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Config{}, errors.New("--anixops-config is required")
	}
	if !filepath.IsAbs(path) {
		return Config{}, errors.New("--anixops-config must be an absolute path")
	}

	before, err := os.Lstat(path)
	if err != nil {
		return Config{}, fmt.Errorf("inspect plugin config: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return Config{}, errors.New("plugin config must be a regular file, not a symlink")
	}
	if before.Mode().Perm()&0o022 != 0 {
		return Config{}, errors.New("plugin config must not be writable by group or other users")
	}
	if before.Size() > maxConfigBytes {
		return Config{}, fmt.Errorf("plugin config exceeds %d bytes", maxConfigBytes)
	}

	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open plugin config: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("stat opened plugin config: %w", err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return Config{}, errors.New("plugin config changed while it was being opened")
	}

	contents, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read plugin config: %w", err)
	}
	if len(contents) > maxConfigBytes {
		return Config{}, fmt.Errorf("plugin config exceeds %d bytes", maxConfigBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var raw *rawConfig
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("decode plugin config: %w", err)
	}
	if raw == nil {
		return Config{}, errors.New("plugin config must be a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("plugin config must contain exactly one JSON object")
		}
		return Config{}, fmt.Errorf("decode trailing plugin config data: %w", err)
	}

	config := Config{IntervalSeconds: DefaultIntervalSeconds}
	if len(raw.IntervalSeconds) == 0 {
		return config, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw.IntervalSeconds), []byte("null")) {
		return Config{}, errors.New("interval_seconds must be an integer")
	}
	if err := json.Unmarshal(raw.IntervalSeconds, &config.IntervalSeconds); err != nil {
		return Config{}, fmt.Errorf("interval_seconds must be an integer: %w", err)
	}
	if config.IntervalSeconds < MinimumIntervalSeconds {
		return Config{}, fmt.Errorf("interval_seconds must be at least %d", MinimumIntervalSeconds)
	}
	if config.IntervalSeconds > MaximumIntervalSeconds {
		return Config{}, fmt.Errorf("interval_seconds must be at most %d", MaximumIntervalSeconds)
	}
	return config, nil
}

type Options struct {
	SocketPath string
	ConfigPath string
}

// Run serves the versioned reference plugin until ctx is cancelled. The
// standard health service is the first stable local RPC contract; telemetry
// transport is intentionally left to a later API revision.
func Run(ctx context.Context, options Options) error {
	if ctx == nil {
		return errors.New("plugin context is required")
	}
	config, err := LoadConfig(options.ConfigPath)
	if err != nil {
		return err
	}
	listener, err := listenUnixSocket(options.SocketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = removeUnixSocket(options.SocketPath)
	}()

	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(ID, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()

	ticker := time.NewTicker(config.Interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			healthServer.Shutdown()
			// A health Watch stream can be long lived. Shutdown must not let a
			// disable operation wait indefinitely for an untrusted local client.
			server.Stop()
			err := <-serveResult
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				return fmt.Errorf("serve plugin health API: %w", err)
			}
			return nil
		case err := <-serveResult:
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				return fmt.Errorf("serve plugin health API: %w", err)
			}
			return nil
		case <-ticker.C:
			// The v1 reference package has no telemetry transport yet. Refreshing
			// health proves the signed interval is active without leaking data.
			healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
			healthServer.SetServingStatus(ID, healthpb.HealthCheckResponse_SERVING)
		}
	}
}

func listenUnixSocket(path string) (net.Listener, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("--anixops-socket is required")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("--anixops-socket must be an absolute path")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("inspect plugin socket directory: %w", err)
	}
	if parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() {
		return nil, errors.New("plugin socket directory must be a real directory")
	}
	if parent.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("plugin socket directory must not be writable by group or other users")
	}
	if err := removeUnixSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on plugin Unix socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = removeUnixSocket(path)
		return nil, fmt.Errorf("protect plugin Unix socket: %w", err)
	}
	return listener, nil
}

func removeUnixSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket plugin path %q", path)
	}
	return os.Remove(path)
}
