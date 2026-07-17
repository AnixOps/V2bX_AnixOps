//go:build linux

package plugin

import (
	"os/exec"
	"syscall"
)

func configurePluginCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
}
