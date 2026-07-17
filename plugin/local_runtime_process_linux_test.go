//go:build linux

package plugin

import (
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigurePluginCommandKillsChildWithAgentParent(t *testing.T) {
	command := exec.Command("true")
	configurePluginCommand(command)
	require.NotNil(t, command.SysProcAttr)
	require.True(t, command.SysProcAttr.Setpgid)
	require.Equal(t, syscall.SIGKILL, command.SysProcAttr.Pdeathsig)
}
