package conf

type WireGuardConfig struct {
	RuntimeDir                    string `json:"RuntimeDir"`
	WGPath                        string `json:"WGPath"`
	IPPath                        string `json:"IPPath"`
	TCPath                        string `json:"TCPath"`
	IPTablesPath                  string `json:"IPTablesPath"`
	SysctlPath                    string `json:"SysctlPath"`
	GostPath                      string `json:"GostPath"`
	OnlineHandshakeTimeoutSeconds int64  `json:"OnlineHandshakeTimeoutSeconds"`
	GostRestartDelaySeconds       int64  `json:"GostRestartDelaySeconds"`
}

func NewWireGuardConfig() *WireGuardConfig {
	return &WireGuardConfig{
		RuntimeDir:                    "/etc/anixops/agent/wireguard",
		WGPath:                        "wg",
		IPPath:                        "ip",
		TCPath:                        "tc",
		IPTablesPath:                  "iptables",
		SysctlPath:                    "sysctl",
		GostPath:                      "gost",
		OnlineHandshakeTimeoutSeconds: 180,
		GostRestartDelaySeconds:       3,
	}
}
