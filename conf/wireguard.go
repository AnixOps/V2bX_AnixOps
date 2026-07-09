package conf

type WireGuardConfig struct {
	RuntimeDir                    string `json:"RuntimeDir"`
	WGPath                        string `json:"WGPath"`
	IPPath                        string `json:"IPPath"`
	GostPath                      string `json:"GostPath"`
	OnlineHandshakeTimeoutSeconds int64  `json:"OnlineHandshakeTimeoutSeconds"`
}

func NewWireGuardConfig() *WireGuardConfig {
	return &WireGuardConfig{
		RuntimeDir:                    "/etc/V2bX/wireguard",
		WGPath:                        "wg",
		IPPath:                        "ip",
		GostPath:                      "gost",
		OnlineHandshakeTimeoutSeconds: 180,
	}
}
