package cmd

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	_ "github.com/InazumaV/V2bX/core/imports"
	"github.com/spf13/cobra"
)

// LocalTimeFormatter 自定义格式化器，使用本地时间
type LocalTimeFormatter struct {
	log.TextFormatter
}

func (f *LocalTimeFormatter) Format(entry *log.Entry) ([]byte, error) {
	entry.Time = entry.Time.Local()
	return f.TextFormatter.Format(entry)
}

var command = &cobra.Command{
	Use:   "V2bX",
	Short: "V2bX - A multi-protocol proxy node client",
	Long: `V2bX is a multi-protocol proxy node client that supports 
VMess, VLESS, Trojan, Shadowsocks, Hysteria, Hysteria2, TUIC, and AnyTLS protocols.

Usage:
  V2bX -c config.json           Run with specified config file  
  V2bX server -c config.json    Run with specified config file
  V2bX server                   Run with default config file
  V2bX version                  Show version information`,
	// 直接运行 V2bX 或 V2bX -c xxx 时执行 server 命令
	Run: serverHandle,
}

func init() {
	// 设置日志使用本地时间
	log.SetFormatter(&LocalTimeFormatter{
		TextFormatter: log.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.DateTime,
		},
	})

	// 添加全局 config 参数到根命令
	command.PersistentFlags().StringVarP(&config, "config", "c", getDefaultConfigPath(), "config file path")
	command.PersistentFlags().BoolVarP(&watch, "watch", "w", true, "watch file path change")
	command.PersistentFlags().BoolVarP(&reRegister, "re-register", "r", false, "force re-register node (delete existing credentials)")
}

func Run() {
	// 检查是否是子命令（server, version 等）
	if len(os.Args) > 1 {
		firstArg := os.Args[1]
		// 如果第一个参数不是以 - 开头，且是已知的子命令，正常执行
		if firstArg != "-c" && firstArg != "--config" &&
			firstArg != "-w" && firstArg != "--watch" &&
			firstArg != "-h" && firstArg != "--help" &&
			!isSubCommand(firstArg) {
			// 未知参数，显示帮助
		}
	}

	err := command.Execute()
	if err != nil {
		log.WithField("err", err).Error("Execute command failed")
	}
}

// isSubCommand 检查是否是已知的子命令
func isSubCommand(arg string) bool {
	for _, cmd := range command.Commands() {
		if cmd.Name() == arg {
			return true
		}
	}
	return false
}
