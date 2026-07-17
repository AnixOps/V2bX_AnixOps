//go:build linux

package gostmesh

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadProcessRecordParsesLinuxStatIdentity(t *testing.T) {
	root := runtimeSecureTempDir(t)
	writeRuntimeTestBootID(t, root, runtimeTestBootID)
	executable := filepath.Join(root, "signed runtime", "gost")
	require.NoError(t, os.MkdirAll(filepath.Dir(executable), 0o700))
	require.NoError(t, os.WriteFile(executable, []byte("gost"), 0o750))
	writeRuntimeTestProcess(t, root, 321, "gost worker (mesh)", 987654, executable)

	record, err := readProcessRecord(321, root)
	require.NoError(t, err)
	require.Equal(t, ProcessRecord{PID: 321, StartTime: 987654, Executable: executable, BootID: runtimeTestBootID}, record)
	require.NoError(t, verifyProcessRecord(record, root))
}

func TestVerifyProcessRecordRejectsPIDReuse(t *testing.T) {
	root := runtimeSecureTempDir(t)
	writeRuntimeTestBootID(t, root, runtimeTestBootID)
	firstExecutable := filepath.Join(root, "gost-v1")
	secondExecutable := filepath.Join(root, "gost-v2")
	require.NoError(t, os.WriteFile(firstExecutable, []byte("one"), 0o750))
	require.NoError(t, os.WriteFile(secondExecutable, []byte("two"), 0o750))
	writeRuntimeTestProcess(t, root, 654, "gost", 1111, firstExecutable)
	expected, err := readProcessRecord(654, root)
	require.NoError(t, err)

	t.Run("start time changed", func(t *testing.T) {
		writeRuntimeTestProcess(t, root, 654, "unrelated", 2222, firstExecutable)
		err := verifyProcessRecord(expected, root)
		require.ErrorContains(t, err, "identity no longer matches")
	})

	t.Run("executable changed", func(t *testing.T) {
		writeRuntimeTestBootID(t, root, runtimeTestBootID)
		writeRuntimeTestProcess(t, root, 654, "gost", 1111, secondExecutable)
		err := verifyProcessRecord(expected, root)
		require.ErrorContains(t, err, "identity no longer matches")
	})

	t.Run("boot changed", func(t *testing.T) {
		writeRuntimeTestBootID(t, root, "fedcba98-7654-3210-fedc-ba9876543210")
		writeRuntimeTestProcess(t, root, 654, "gost", 1111, firstExecutable)
		err := verifyProcessRecord(expected, root)
		require.ErrorContains(t, err, "identity no longer matches")
	})
}

func TestReadProcessRecordRejectsMalformedStat(t *testing.T) {
	root := runtimeSecureTempDir(t)
	processDir := filepath.Join(root, "777")
	require.NoError(t, os.MkdirAll(processDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(processDir, "stat"), []byte("777 malformed"), 0o600))
	_, err := readProcessRecord(777, root)
	require.ErrorContains(t, err, "invalid command field")

	require.NoError(t, os.WriteFile(filepath.Join(processDir, "stat"), []byte("777 (gost) S 0 0"), 0o600))
	_, err = readProcessRecord(777, root)
	require.ErrorContains(t, err, "missing start time")

	writeRuntimeTestProcess(t, root, 777, "gost", 0, filepath.Join(root, "missing"))
	_, err = readProcessRecord(777, root)
	require.ErrorContains(t, err, "invalid start time")
}

func writeRuntimeTestProcess(t *testing.T, procRoot string, pid int, command string, startTime uint64, executable string) {
	t.Helper()
	processDir := filepath.Join(procRoot, strconv.Itoa(pid))
	require.NoError(t, os.MkdirAll(processDir, 0o700))
	fields := []string{"S"}
	for len(fields) < 19 {
		fields = append(fields, "0")
	}
	fields = append(fields, strconv.FormatUint(startTime, 10))
	contents := fmt.Sprintf("%d (%s) %s\n", pid, command, strings.Join(fields, " "))
	require.NoError(t, os.WriteFile(filepath.Join(processDir, "stat"), []byte(contents), 0o600))
	exePath := filepath.Join(processDir, "exe")
	if err := os.Remove(exePath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	require.NoError(t, os.Symlink(executable, exePath))
}

func writeRuntimeTestBootID(t *testing.T, procRoot, bootID string) {
	t.Helper()
	path := filepath.Join(procRoot, "sys/kernel/random/boot_id")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(bootID+"\n"), 0o600))
}
