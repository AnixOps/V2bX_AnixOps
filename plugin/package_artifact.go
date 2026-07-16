package plugin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	pluginPackageName      = "artifact.pkg"
	maxPluginArtifactBytes = 32 << 20
	maxPluginBinaryBytes   = 128 << 20
)

func materializeAgentArtifact(manifest Manifest, artifact []byte) ([]byte, bool, error) {
	entrypoint, declared := resolveAgentEntrypoint(manifest, runtime.GOOS, runtime.GOARCH)
	if entrypoint != "" {
		binary, err := extractPackageFile(artifact, entrypoint)
		if err != nil {
			return nil, false, fmt.Errorf("extract agent entrypoint %q: %w", entrypoint, err)
		}
		if len(binary) == 0 {
			return nil, false, errors.New("agent entrypoint is empty")
		}
		return binary, true, nil
	}
	if declared {
		return nil, false, fmt.Errorf("plugin package has no agent entrypoint for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if manifest.WebUI != nil {
		return nil, false, errors.New("plugin package with webui must declare an agent entrypoint")
	}
	return append([]byte(nil), artifact...), false, nil
}

func resolveAgentEntrypoint(manifest Manifest, goos, goarch string) (string, bool) {
	for _, key := range []string{"agent-" + goos + "-" + goarch, "agent-any", "agent"} {
		if entrypoint := strings.TrimSpace(manifest.Entrypoints[key]); entrypoint != "" {
			return entrypoint, true
		}
	}
	for key := range manifest.Entrypoints {
		if key == "agent" || strings.HasPrefix(key, "agent-") {
			return "", true
		}
	}
	return "", false
}

func verifyInstalledAgentArtifact(manifest Manifest, dir, binaryPath string) error {
	entrypoint, declared := resolveAgentEntrypoint(manifest, runtime.GOOS, runtime.GOARCH)
	if entrypoint == "" {
		if declared {
			return fmt.Errorf("installed plugin package has no agent entrypoint for %s/%s", runtime.GOOS, runtime.GOARCH)
		}
		if manifest.WebUI != nil {
			return errors.New("installed plugin package with webui has no agent entrypoint")
		}
		return verifyFileDigest(binaryPath, manifest.ArtifactSHA256, maxPluginArtifactBytes)
	}

	artifactPath := filepath.Join(dir, pluginPackageName)
	artifact, err := readRegularFile(artifactPath, maxPluginArtifactBytes)
	if err != nil {
		return fmt.Errorf("read installed plugin package: %w", err)
	}
	digest := sha256.Sum256(artifact)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), manifest.ArtifactSHA256) {
		return errors.New("installed plugin package hash mismatch")
	}
	expected, err := extractPackageFile(artifact, entrypoint)
	if err != nil {
		return fmt.Errorf("verify installed agent entrypoint %q: %w", entrypoint, err)
	}
	actual, err := readRegularFile(binaryPath, maxPluginBinaryBytes)
	if err != nil {
		return fmt.Errorf("read installed plugin artifact: %w", err)
	}
	if !bytes.Equal(actual, expected) {
		return errors.New("installed plugin artifact does not match the signed package entrypoint")
	}
	return nil
}

func verifyFileDigest(path, expected string, maximum int64) error {
	contents, err := readRegularFile(path, maximum)
	if err != nil {
		return fmt.Errorf("read installed plugin artifact: %w", err)
	}
	digest := sha256.Sum256(contents)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), expected) {
		return errors.New("installed plugin artifact hash mismatch")
	}
	return nil
}

func readRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("path must be a regular file, not a symlink")
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("file changed while it was being opened")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return contents, nil
}

func extractPackageFile(artifact []byte, entrypoint string) ([]byte, error) {
	if !safeRelativePath(entrypoint) {
		return nil, errors.New("agent entrypoint must be a canonical relative path")
	}
	if reader, err := zip.NewReader(bytes.NewReader(artifact), int64(len(artifact))); err == nil {
		return extractZipFile(reader, entrypoint)
	}
	if gzipReader, err := gzip.NewReader(bytes.NewReader(artifact)); err == nil {
		defer gzipReader.Close()
		binary, recognized, err := extractTarFile(gzipReader, entrypoint)
		if err == nil && !recognized {
			return nil, errors.New("gzip artifact does not contain a tar package")
		}
		return binary, err
	}
	binary, recognized, err := extractTarFile(bytes.NewReader(artifact), entrypoint)
	if err != nil {
		return nil, err
	}
	if !recognized {
		return nil, errors.New("artifact is not a supported zip, tar.gz, or tar package")
	}
	return binary, nil
}

func extractZipFile(reader *zip.Reader, entrypoint string) ([]byte, error) {
	var binary []byte
	found := false
	for _, file := range reader.File {
		name := strings.TrimPrefix(file.Name, "./")
		if name != entrypoint {
			continue
		}
		if found {
			return nil, fmt.Errorf("agent entrypoint %q appears more than once", entrypoint)
		}
		found = true
		if !file.Mode().IsRegular() {
			return nil, fmt.Errorf("agent entrypoint %q is not a regular file", entrypoint)
		}
		if file.UncompressedSize64 > maxPluginBinaryBytes {
			return nil, fmt.Errorf("agent entrypoint exceeds %d bytes", maxPluginBinaryBytes)
		}
		opened, err := file.Open()
		if err != nil {
			return nil, err
		}
		contents, readErr := io.ReadAll(io.LimitReader(opened, maxPluginBinaryBytes+1))
		closeErr := opened.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return nil, err
		}
		if len(contents) > maxPluginBinaryBytes {
			return nil, fmt.Errorf("agent entrypoint exceeds %d bytes", maxPluginBinaryBytes)
		}
		binary = contents
	}
	if !found {
		return nil, fmt.Errorf("agent entrypoint %q was not found", entrypoint)
	}
	return binary, nil
}

func extractTarFile(reader io.Reader, entrypoint string) ([]byte, bool, error) {
	tarReader := tar.NewReader(reader)
	var binary []byte
	found := false
	recognized := false
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if !recognized {
				return nil, false, nil
			}
			return nil, true, fmt.Errorf("read package tar: %w", err)
		}
		recognized = true
		name := strings.TrimPrefix(header.Name, "./")
		if name != entrypoint {
			continue
		}
		if found {
			return nil, true, fmt.Errorf("agent entrypoint %q appears more than once", entrypoint)
		}
		found = true
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return nil, true, fmt.Errorf("agent entrypoint %q is not a regular file", entrypoint)
		}
		if header.Size < 0 || header.Size > maxPluginBinaryBytes {
			return nil, true, fmt.Errorf("agent entrypoint exceeds %d bytes", maxPluginBinaryBytes)
		}
		contents, err := io.ReadAll(io.LimitReader(tarReader, maxPluginBinaryBytes+1))
		if err != nil {
			return nil, true, err
		}
		if len(contents) > maxPluginBinaryBytes {
			return nil, true, fmt.Errorf("agent entrypoint exceeds %d bytes", maxPluginBinaryBytes)
		}
		binary = contents
	}
	if !found {
		if !recognized {
			return nil, false, nil
		}
		return nil, true, fmt.Errorf("agent entrypoint %q was not found", entrypoint)
	}
	return binary, true, nil
}
