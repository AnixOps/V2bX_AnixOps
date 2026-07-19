package plugin

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	pluginPackageName             = "artifact.pkg"
	pluginRuntimeDirName          = "runtime"
	maxPluginArtifactBytes        = 64 << 20
	maxPluginBinaryBytes          = 128 << 20
	maxPluginRuntimeBytes         = 128 << 20
	maxPluginRuntimeTotalBytes    = 256 << 20
	maxPluginRuntimeEntries       = 32
	maxPluginEntrypointIndexBytes = 1 << 20
)

type materializedRuntime struct {
	Name       string
	Entrypoint string
	Contents   []byte
}

type runtimeEntrypointDeclaration struct {
	key        string
	name       string
	entrypoint string
	goos       string
	goarch     string
	fallback   string
}

type v2AgentEntrypointIndex struct {
	Format  string                        `json:"format"`
	Entries []v2AgentEntrypointIndexEntry `json:"entries"`
}

type v2AgentEntrypointIndexEntry struct {
	Architecture string `json:"architecture"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
}

func materializeAgentArtifact(manifest Manifest, artifact []byte) ([]byte, bool, error) {
	if manifest.APIVersion == pluginAPIVersionV2 && manifest.AgentEntrypoint != nil {
		binary, err := extractV2AgentEntrypoint(manifest, artifact, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return nil, false, err
		}
		if len(binary) == 0 {
			return nil, false, errors.New("agent entrypoint is empty")
		}
		return binary, true, nil
	}
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
	if manifest.APIVersion == pluginAPIVersionV2 {
		if manifest.AgentEntrypoint == nil {
			return "", false
		}
		return manifest.AgentEntrypoint.Path, true
	}
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

func extractV2AgentEntrypoint(manifest Manifest, artifact []byte, goos, goarch string) ([]byte, error) {
	if manifest.AgentEntrypoint == nil {
		return nil, errors.New("plugin package does not declare an agent entrypoint")
	}
	entrypoint := manifest.AgentEntrypoint
	if entrypoint.Path != agentEntrypointIndexPath {
		expectedPath := "agent/" + goos + "-" + goarch + "/plugin"
		if entrypoint.Path != expectedPath {
			return nil, fmt.Errorf("agent entrypoint must match %q", expectedPath)
		}
		contents, err := extractPackageFile(artifact, entrypoint.Path)
		if err != nil {
			return nil, fmt.Errorf("extract agent entrypoint %q: %w", entrypoint.Path, err)
		}
		if !packageContentsMatchSHA256(contents, entrypoint.SHA256) {
			return nil, fmt.Errorf("agent entrypoint digest mismatch for %q", entrypoint.Path)
		}
		return contents, nil
	}

	indexContents, err := extractPackageFileWithLimit(
		artifact,
		agentEntrypointIndexPath,
		"agent entrypoint index",
		maxPluginEntrypointIndexBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("extract agent entrypoint index: %w", err)
	}
	if !packageContentsMatchSHA256(indexContents, entrypoint.SHA256) {
		return nil, errors.New("agent entrypoint index digest mismatch")
	}
	index, err := decodeV2AgentEntrypointIndex(indexContents)
	if err != nil {
		return nil, err
	}
	selected, err := resolveV2AgentEntrypointIndex(index, manifest.Architectures, goos, goarch)
	if err != nil {
		return nil, err
	}
	contents, err := extractPackageFile(artifact, selected.Path)
	if err != nil {
		return nil, fmt.Errorf("extract agent entrypoint %q: %w", selected.Path, err)
	}
	if !packageContentsMatchSHA256(contents, selected.SHA256) {
		return nil, fmt.Errorf("agent entrypoint digest mismatch for %q", selected.Path)
	}
	return contents, nil
}

func decodeV2AgentEntrypointIndex(contents []byte) (v2AgentEntrypointIndex, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var index v2AgentEntrypointIndex
	if err := decoder.Decode(&index); err != nil {
		return v2AgentEntrypointIndex{}, fmt.Errorf("decode agent entrypoint index: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return v2AgentEntrypointIndex{}, errors.New("agent entrypoint index must contain one JSON value")
		}
		return v2AgentEntrypointIndex{}, fmt.Errorf("decode agent entrypoint index: %w", err)
	}
	if index.Format != packageEntrypointIndexFormat {
		return v2AgentEntrypointIndex{}, fmt.Errorf("unsupported agent entrypoint index format %q", index.Format)
	}
	if len(index.Entries) == 0 || len(index.Entries) > 2 {
		return v2AgentEntrypointIndex{}, errors.New("agent entrypoint index must declare one or two entries")
	}
	return index, nil
}

func resolveV2AgentEntrypointIndex(index v2AgentEntrypointIndex, architectures []string, goos, goarch string) (v2AgentEntrypointIndexEntry, error) {
	declared := make(map[string]struct{}, len(architectures))
	for _, architecture := range architectures {
		if _, ok := indexedAgentEntrypointPath(architecture); !ok {
			return v2AgentEntrypointIndexEntry{}, fmt.Errorf("agent entrypoint index requires os/arch manifest architecture %q", architecture)
		}
		declared[architecture] = struct{}{}
	}
	if len(declared) == 0 || len(declared) != len(index.Entries) {
		return v2AgentEntrypointIndexEntry{}, errors.New("agent entrypoint index must cover every manifest architecture")
	}

	platform := goos + "/" + goarch
	var selected v2AgentEntrypointIndexEntry
	foundSelected := false
	previous := ""
	for _, entry := range index.Entries {
		if entry.Architecture == "" || entry.Architecture <= previous {
			return v2AgentEntrypointIndexEntry{}, errors.New("agent entrypoint index entries must be ordered by architecture")
		}
		previous = entry.Architecture
		expectedPath, ok := indexedAgentEntrypointPath(entry.Architecture)
		if !ok || entry.Path != expectedPath || !validSHA256(entry.SHA256) {
			return v2AgentEntrypointIndexEntry{}, fmt.Errorf("agent entrypoint index entry for %q is invalid", entry.Architecture)
		}
		if _, ok := declared[entry.Architecture]; !ok {
			return v2AgentEntrypointIndexEntry{}, fmt.Errorf("agent entrypoint index architecture %q is not declared", entry.Architecture)
		}
		if entry.Architecture == platform {
			selected = entry
			foundSelected = true
		}
	}
	if !foundSelected {
		return v2AgentEntrypointIndexEntry{}, fmt.Errorf("agent entrypoint index has no entry for %s", platform)
	}
	return selected, nil
}

func indexedAgentEntrypointPath(architecture string) (string, bool) {
	parts := strings.Split(architecture, "/")
	if len(parts) != 2 || !safeSegment(parts[0]) || !safeSegment(parts[1]) {
		return "", false
	}
	return "agent/" + parts[0] + "-" + parts[1] + "/plugin", true
}

func packageContentsMatchSHA256(contents []byte, expected string) bool {
	if !validSHA256(expected) {
		return false
	}
	digest := sha256.Sum256(contents)
	return strings.EqualFold(hex.EncodeToString(digest[:]), expected)
}

func materializeRuntimeArtifacts(manifest Manifest, artifact []byte, goos, goarch string) ([]materializedRuntime, bool, error) {
	entrypoints, declared, err := resolveRuntimeEntrypoints(manifest, goos, goarch)
	if err != nil || len(entrypoints) == 0 {
		return nil, declared, err
	}
	runtimes := make([]materializedRuntime, 0, len(entrypoints))
	total := int64(0)
	for _, entrypoint := range entrypoints {
		contents, err := extractPackageFileWithLimit(
			artifact,
			entrypoint.Entrypoint,
			fmt.Sprintf("runtime %q entrypoint", entrypoint.Name),
			maxPluginRuntimeBytes,
		)
		if err != nil {
			return nil, true, fmt.Errorf("extract runtime %q entrypoint %q: %w", entrypoint.Name, entrypoint.Entrypoint, err)
		}
		if len(contents) == 0 {
			return nil, true, fmt.Errorf("runtime %q entrypoint is empty", entrypoint.Name)
		}
		total += int64(len(contents))
		if total > maxPluginRuntimeTotalBytes {
			return nil, true, fmt.Errorf("platform runtime entrypoints exceed %d bytes", maxPluginRuntimeTotalBytes)
		}
		runtimes = append(runtimes, materializedRuntime{
			Name:       entrypoint.Name,
			Entrypoint: entrypoint.Entrypoint,
			Contents:   contents,
		})
	}
	return runtimes, true, nil
}

func resolveRuntimeEntrypoints(manifest Manifest, goos, goarch string) ([]materializedRuntime, bool, error) {
	declarations := make([]runtimeEntrypointDeclaration, 0)
	seenPaths := make(map[string]string)
	for key, entrypoint := range manifest.Entrypoints {
		if !strings.HasPrefix(key, "runtime-") {
			if _, exists := seenPaths[entrypoint]; !exists {
				seenPaths[entrypoint] = key
			}
		}
	}
	for key, entrypoint := range manifest.Entrypoints {
		declaration, runtimeEntrypoint, err := parseRuntimeEntrypoint(key, entrypoint)
		if err != nil {
			return nil, true, err
		}
		if !runtimeEntrypoint {
			continue
		}
		if len(declarations) >= maxPluginRuntimeEntries {
			return nil, true, fmt.Errorf("plugin declares more than %d runtime entrypoints", maxPluginRuntimeEntries)
		}
		if previous, exists := seenPaths[declaration.entrypoint]; exists {
			return nil, true, fmt.Errorf("runtime entrypoints %q and %q use the same package path", previous, declaration.key)
		}
		seenPaths[declaration.entrypoint] = declaration.key
		declarations = append(declarations, declaration)
	}
	if len(declarations) == 0 {
		return nil, false, nil
	}

	type runtimeSelection struct {
		exact   *runtimeEntrypointDeclaration
		any     *runtimeEntrypointDeclaration
		generic *runtimeEntrypointDeclaration
	}
	selections := make(map[string]*runtimeSelection)
	for i := range declarations {
		declaration := &declarations[i]
		selection := selections[declaration.name]
		if selection == nil {
			selection = &runtimeSelection{}
			selections[declaration.name] = selection
		}
		switch {
		case declaration.goos == goos && declaration.goarch == goarch:
			if selection.exact != nil {
				return nil, true, fmt.Errorf("runtime %q has duplicate entrypoints for %s/%s", declaration.name, goos, goarch)
			}
			selection.exact = declaration
		case declaration.fallback == "any":
			selection.any = declaration
		case declaration.fallback == "generic":
			selection.generic = declaration
		}
	}

	names := make([]string, 0, len(selections))
	for name, selection := range selections {
		if selection.any != nil && selection.generic != nil {
			return nil, true, fmt.Errorf("runtime %q declares conflicting any and generic fallbacks", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	resolved := make([]materializedRuntime, 0, len(names))
	for _, name := range names {
		selection := selections[name]
		declaration := selection.exact
		if declaration == nil {
			declaration = selection.any
		}
		if declaration == nil {
			declaration = selection.generic
		}
		if declaration == nil {
			continue
		}
		resolved = append(resolved, materializedRuntime{Name: name, Entrypoint: declaration.entrypoint})
	}
	return resolved, true, nil
}

func parseRuntimeEntrypoint(key, entrypoint string) (runtimeEntrypointDeclaration, bool, error) {
	if !strings.HasPrefix(key, "runtime-") {
		return runtimeEntrypointDeclaration{}, false, nil
	}
	remainder := strings.TrimPrefix(key, "runtime-")
	parts := strings.Split(remainder, "-")
	declaration := runtimeEntrypointDeclaration{key: key, entrypoint: entrypoint}
	switch {
	case len(parts) >= 3 && knownRuntimeGOOS(parts[len(parts)-2]) && knownRuntimeGOARCH(parts[len(parts)-1]):
		declaration.name = strings.Join(parts[:len(parts)-2], "-")
		declaration.goos = parts[len(parts)-2]
		declaration.goarch = parts[len(parts)-1]
	case len(parts) >= 2 && parts[len(parts)-1] == "any":
		declaration.name = strings.Join(parts[:len(parts)-1], "-")
		declaration.fallback = "any"
	default:
		declaration.name = remainder
		declaration.fallback = "generic"
	}
	if !safeRuntimeName(declaration.name) {
		return runtimeEntrypointDeclaration{}, true, fmt.Errorf("runtime entrypoint name %q is invalid", declaration.name)
	}
	if !safeRelativePath(entrypoint) {
		return runtimeEntrypointDeclaration{}, true, fmt.Errorf("runtime %q entrypoint must be a canonical relative path", declaration.name)
	}
	return declaration, true, nil
}

func safeRuntimeName(value string) bool {
	if len(value) == 0 || len(value) > 64 || value != strings.ToLower(value) ||
		!asciiAlphaNumeric(value[0]) || !asciiAlphaNumeric(value[len(value)-1]) || strings.Contains(value, "..") {
		return false
	}
	for i := range value {
		if !asciiAlphaNumeric(value[i]) && value[i] != '.' && value[i] != '_' && value[i] != '-' {
			return false
		}
	}
	return true
}

func knownRuntimeGOOS(value string) bool {
	switch value {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios", "js", "linux", "netbsd", "openbsd", "plan9", "solaris", "wasip1", "windows":
		return true
	default:
		return false
	}
}

func knownRuntimeGOARCH(value string) bool {
	switch value {
	case "386", "amd64", "arm", "arm64", "loong64", "mips", "mips64", "mips64le", "mipsle", "ppc64", "ppc64le", "riscv64", "s390x", "wasm":
		return true
	default:
		return false
	}
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
	var expected []byte
	if manifest.APIVersion == pluginAPIVersionV2 {
		expected, err = extractV2AgentEntrypoint(manifest, artifact, runtime.GOOS, runtime.GOARCH)
	} else {
		expected, err = extractPackageFile(artifact, entrypoint)
	}
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

func verifyInstalledRuntimeArtifacts(manifest Manifest, dir string) error {
	entrypoints, declared, err := resolveRuntimeEntrypoints(manifest, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	if !declared || len(entrypoints) == 0 {
		return nil
	}
	if entrypoint, _ := resolveAgentEntrypoint(manifest, runtime.GOOS, runtime.GOARCH); entrypoint == "" {
		return errors.New("signed runtime entrypoints require a packaged agent entrypoint")
	}

	artifactPath := filepath.Join(dir, pluginPackageName)
	artifact, err := readRegularFile(artifactPath, maxPluginArtifactBytes)
	if err != nil {
		return fmt.Errorf("read installed plugin package for runtimes: %w", err)
	}
	digest := sha256.Sum256(artifact)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), manifest.ArtifactSHA256) {
		return errors.New("installed plugin package hash mismatch while verifying runtimes")
	}
	total := int64(0)
	for _, entrypoint := range entrypoints {
		expected, err := extractPackageFileWithLimit(
			artifact,
			entrypoint.Entrypoint,
			fmt.Sprintf("runtime %q entrypoint", entrypoint.Name),
			maxPluginRuntimeBytes,
		)
		if err != nil {
			return fmt.Errorf("verify installed runtime %q entrypoint %q: %w", entrypoint.Name, entrypoint.Entrypoint, err)
		}
		if len(expected) == 0 {
			return fmt.Errorf("installed runtime %q entrypoint is empty", entrypoint.Name)
		}
		total += int64(len(expected))
		if total > maxPluginRuntimeTotalBytes {
			return fmt.Errorf("installed platform runtime entrypoints exceed %d bytes", maxPluginRuntimeTotalBytes)
		}
		installedPath := filepath.Join(dir, pluginRuntimeDirName, entrypoint.Name)
		info, err := os.Lstat(installedPath)
		if err != nil {
			return fmt.Errorf("inspect installed runtime %q: %w", entrypoint.Name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("installed runtime %q must be a regular file", entrypoint.Name)
		}
		if info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("installed runtime %q is not executable", entrypoint.Name)
		}
		actual, err := readRegularFile(installedPath, maxPluginRuntimeBytes)
		if err != nil {
			return fmt.Errorf("read installed runtime %q: %w", entrypoint.Name, err)
		}
		if !bytes.Equal(actual, expected) {
			return fmt.Errorf("installed runtime %q does not match the signed package entrypoint", entrypoint.Name)
		}
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
	return extractPackageFileWithLimit(artifact, entrypoint, "agent entrypoint", maxPluginBinaryBytes)
}

func extractPackageFileWithLimit(artifact []byte, entrypoint, label string, maximum int64) ([]byte, error) {
	if !safeRelativePath(entrypoint) {
		return nil, fmt.Errorf("%s must be a canonical relative path", label)
	}
	if reader, err := zip.NewReader(bytes.NewReader(artifact), int64(len(artifact))); err == nil {
		return extractZipFile(reader, entrypoint, label, maximum)
	}
	if gzipReader, err := gzip.NewReader(bytes.NewReader(artifact)); err == nil {
		defer gzipReader.Close()
		binary, recognized, err := extractTarFile(gzipReader, entrypoint, label, maximum)
		if err == nil && !recognized {
			return nil, errors.New("gzip artifact does not contain a tar package")
		}
		return binary, err
	}
	binary, recognized, err := extractTarFile(bytes.NewReader(artifact), entrypoint, label, maximum)
	if err != nil {
		return nil, err
	}
	if !recognized {
		return nil, errors.New("artifact is not a supported zip, tar.gz, or tar package")
	}
	return binary, nil
}

func extractZipFile(reader *zip.Reader, entrypoint, label string, maximum int64) ([]byte, error) {
	var binary []byte
	found := false
	for _, file := range reader.File {
		name := strings.TrimPrefix(file.Name, "./")
		if name != entrypoint {
			continue
		}
		if found {
			return nil, fmt.Errorf("%s %q appears more than once", label, entrypoint)
		}
		found = true
		if !file.Mode().IsRegular() {
			return nil, fmt.Errorf("%s %q is not a regular file", label, entrypoint)
		}
		if file.UncompressedSize64 > uint64(maximum) {
			return nil, fmt.Errorf("%s exceeds %d bytes", label, maximum)
		}
		opened, err := file.Open()
		if err != nil {
			return nil, err
		}
		contents, readErr := io.ReadAll(io.LimitReader(opened, maximum+1))
		closeErr := opened.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return nil, err
		}
		if int64(len(contents)) > maximum {
			return nil, fmt.Errorf("%s exceeds %d bytes", label, maximum)
		}
		binary = contents
	}
	if !found {
		return nil, fmt.Errorf("%s %q was not found", label, entrypoint)
	}
	return binary, nil
}

func extractTarFile(reader io.Reader, entrypoint, label string, maximum int64) ([]byte, bool, error) {
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
			return nil, true, fmt.Errorf("%s %q appears more than once", label, entrypoint)
		}
		found = true
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return nil, true, fmt.Errorf("%s %q is not a regular file", label, entrypoint)
		}
		if header.Size < 0 || header.Size > maximum {
			return nil, true, fmt.Errorf("%s exceeds %d bytes", label, maximum)
		}
		contents, err := io.ReadAll(io.LimitReader(tarReader, maximum+1))
		if err != nil {
			return nil, true, err
		}
		if int64(len(contents)) > maximum {
			return nil, true, fmt.Errorf("%s exceeds %d bytes", label, maximum)
		}
		binary = contents
	}
	if !found {
		if !recognized {
			return nil, false, nil
		}
		return nil, true, fmt.Errorf("%s %q was not found", label, entrypoint)
	}
	return binary, true, nil
}
