package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AnixOps/anix-agent/v3/common/exec"
	"github.com/spf13/cobra"
)

var (
	targetVersion string
	purgeConfig   bool
)

var releaseVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+)?)?$`)

var (
	updateCommand = cobra.Command{
		Use:   "update",
		Short: "Update AnixOps Agent",
		Run: func(_ *cobra.Command, _ []string) {
			if targetVersion != "" && !releaseVersionPattern.MatchString(targetVersion) {
				fmt.Println(Err("版本号格式无效: ", targetVersion))
				return
			}
			command := `tmp_file="$(mktemp)" && trap 'rm -f "${tmp_file}"' EXIT && curl -fsSL https://raw.githubusercontent.com/AnixOps/anix-agent/dev_new/scripts/install.sh -o "${tmp_file}" && bash "${tmp_file}"`
			if targetVersion != "" {
				command += " " + targetVersion
			}
			if _, err := exec.RunCommandByShell(command); err != nil {
				fmt.Println(Err("更新失败: ", err))
			}
		},
		Args: cobra.NoArgs,
	}
	uninstallCommand = cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall AnixOps Agent",
		Run:   uninstallHandle,
	}
)

func init() {
	updateCommand.PersistentFlags().StringVar(&targetVersion, "version", "", "update target version")
	uninstallCommand.Flags().BoolVar(&purgeConfig, "purge", false, "remove the AnixOps Agent configuration directory")
	command.AddCommand(&updateCommand)
	command.AddCommand(&uninstallCommand)
}

func uninstallHandle(_ *cobra.Command, _ []string) {
	var yes string
	fmt.Println(Warn("确定要卸载 AnixOps Agent 吗?(Y/n)"))
	fmt.Scan(&yes)
	if strings.ToLower(yes) != "y" {
		fmt.Println("已取消卸载")
		return
	}
	_, _ = exec.RunCommandByShell("systemctl stop anix-agent.service >/dev/null 2>&1 || true; systemctl disable anix-agent.service >/dev/null 2>&1 || true")
	removeCompatibilitySymlink("/etc/systemd/system/V2bX.service", "/etc/systemd/system/anix-agent.service")
	removeCompatibilitySymlink("/usr/bin/v2bx-anixops", "/usr/bin/anix-agent")
	removeCompatibilitySymlink("/usr/local/bin/v2bx-anixops", "/usr/bin/anix-agent")
	removeCompatibilitySymlink("/usr/bin/V2bX", "/usr/bin/anix-agent")
	removeCompatibilitySymlink("/usr/local/bin/V2bX", "/usr/bin/anix-agent")
	_ = os.RemoveAll("/etc/systemd/system/anix-agent.service")
	_ = os.RemoveAll("/usr/local/anixops-agent/")
	_ = os.RemoveAll("/usr/bin/anix-agent")
	_ = os.RemoveAll("/usr/local/bin/anix-agent")
	if purgeConfig {
		_ = os.RemoveAll("/etc/anixops/agent/")
	} else {
		fmt.Println(Ok("已保留配置目录: /etc/anixops/agent"))
	}
	_, err := exec.RunCommandByShell("systemctl daemon-reload && systemctl reset-failed")
	if err != nil {
		fmt.Println(Err("exec cmd error: ", err))
		fmt.Println(Err("卸载失败"))
		return
	}
	fmt.Println(Ok("卸载成功"))
}

func removeCompatibilitySymlink(path, expectedTarget string) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil && resolved == expectedTarget {
		_ = os.Remove(path)
	}
}
