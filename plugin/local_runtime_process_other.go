//go:build !linux

package plugin

import "os/exec"

func configurePluginCommand(*exec.Cmd) {}
