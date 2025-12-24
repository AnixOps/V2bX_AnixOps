package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ANSI 颜色代码
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
)

var (
	version  = "TempVersion" //use ldflags replace
	codename = "V2bX"
	intro    = "A V2board backend based on multi core"
)

var versionCommand = cobra.Command{
	Use:   "version",
	Short: "Print version info",
	Run: func(_ *cobra.Command, _ []string) {
		showVersion()
	},
}

func init() {
	command.AddCommand(&versionCommand)
}

// rainbowText 将文本渲染成彩虹色
func rainbowText(text string) string {
	colors := []string{colorRed, colorYellow, colorGreen, colorCyan, colorBlue, colorPurple}
	result := ""
	colorIndex := 0
	for _, char := range text {
		if char == ' ' {
			result += string(char)
		} else {
			result += colors[colorIndex%len(colors)] + string(char)
			colorIndex++
		}
	}
	result += colorReset
	return result
}

func showVersion() {
	fmt.Println(` 
  _/      _/    _/_/    _/        _/      _/   
 _/      _/  _/    _/  _/_/_/      _/  _/      
_/      _/      _/    _/    _/      _/         
 _/  _/      _/      _/    _/    _/  _/        
  _/      _/_/_/_/  _/_/_/    _/      _/        `)
	fmt.Println("              " + rainbowText("AnixOps edition") + "                   ")
	fmt.Printf("%s %s (%s) \n", codename, version, intro)
	//fmt.Printf("Supported cores: %s\n", strings.Join(vCore.RegisteredCore(), ", "))
	// Warning
	//fmt.Println(Warn("This version need V2board version >= 1.7.0."))
	//fmt.Println(Warn("The version have many changed for config, please check your config file"))
}
