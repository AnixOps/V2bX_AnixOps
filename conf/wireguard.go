package conf

type WireGuardConfig struct {
	RuntimeDir                    string `json:"RuntimeDir"`
	WGPath                        string `json:"WGPath"`
	IPPath                        string `json:"IPPath"`
	IPTablesPath                  string `json:"IPTablesPath"`
	SysctlPath                    string `json:"SysctlPath"`
	GostPath                      string `json:"GostPath"`
	OnlineHandshakeTimeoutSeconds int64  `json:"OnlineHandshakeTimeoutSeconds"`
}

func NewWireGuardConfig() *WireGuardConfig {
	return &WireGuardConfig{
		RuntimeDir:                    "/etc/V2bX/wireguard",
		WGPath:                        "wg",
		IPPath:                        "ip",
		IPTablesPath:                  "iptables",
		SysctlPath:                    "sysctl",
		GostPath:                      "gost",
		OnlineHandshakeTimeoutSeconds: 180,
	}
}
