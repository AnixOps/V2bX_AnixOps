package conf

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"encoding/json"

	"github.com/InazumaV/V2bX/common/json5"
)

type NodeConfig struct {
	ApiConfig ApiConfig `json:"-"`
	Options   Options   `json:"-"`
}

type rawNodeConfig struct {
	Include string          `json:"Include"`
	ApiRaw  json.RawMessage `json:"ApiConfig"`
	OptRaw  json.RawMessage `json:"Options"`
}

type ApiConfig struct {
	APIHost      string `json:"ApiHost"`
	APISendIP    string `json:"ApiSendIP"`
	NodeID       int    `json:"NodeID"`
	Key          string `json:"ApiKey"`
	Timeout      int    `json:"Timeout"`
	RuleListPath string `json:"RuleListPath"`

	// 自动发现相关配置
	AuthKey           string `json:"AuthKey"`           // 授权密钥 (首次注册使用)
	NodeName          string `json:"NodeName"`          // 节点名称
	NodeHost          string `json:"NodeHost"`          // 节点地址 (可选，默认使用客户端IP)
	NodePort          int    `json:"NodePort"`          // API端口 (默认443)
	CredentialFile    string `json:"CredentialFile"`    // 凭证存储路径
	HeartbeatInterval int    `json:"HeartbeatInterval"` // 心跳间隔 (秒，默认60)
	AutoRegister      bool   `json:"AutoRegister"`      // 是否启用自动注册

	// 安全增强配置
	EnableSign        bool `json:"EnableSign"`        // 是否启用请求签名 (默认true)
	EncryptCredential bool `json:"EncryptCredential"` // 是否加密存储凭证 (默认true)

	// 调试配置
	EnableDebug    bool   `json:"EnableDebug"`    // 是否启用 API 调试
	DebugOutputDir string `json:"DebugOutputDir"` // 调试输出目录 (默认 test_data/api_debug)

	// 运行时参数 (不从配置文件读取)
	ForceReRegister bool `json:"-"` // 强制重新注册 (命令行参数)
}

func (n *NodeConfig) UnmarshalJSON(data []byte) (err error) {
	rn := rawNodeConfig{}
	err = json.Unmarshal(data, &rn)
	if err != nil {
		return err
	}
	if len(rn.Include) != 0 {
		file, _ := strings.CutPrefix(rn.Include, ":")
		switch file {
		case "http", "https":
			rsp, err := http.Get(file)
			if err != nil {
				return err
			}
			defer rsp.Body.Close()
			data, err = io.ReadAll(json5.NewTrimNodeReader(rsp.Body))
			if err != nil {
				return fmt.Errorf("open include file error: %s", err)
			}
		default:
			f, err := os.Open(rn.Include)
			if err != nil {
				return fmt.Errorf("open include file error: %s", err)
			}
			defer f.Close()
			data, err = io.ReadAll(json5.NewTrimNodeReader(f))
			if err != nil {
				return fmt.Errorf("open include file error: %s", err)
			}
		}
		err = json.Unmarshal(data, &rn)
		if err != nil {
			return fmt.Errorf("unmarshal include file error: %s", err)
		}
	}

	n.ApiConfig = ApiConfig{
		APIHost: "http://127.0.0.1",
		Timeout: 30,
	}
	if len(rn.ApiRaw) > 0 {
		err = json.Unmarshal(rn.ApiRaw, &n.ApiConfig)
		if err != nil {
			return
		}
	} else {
		err = json.Unmarshal(data, &n.ApiConfig)
		if err != nil {
			return
		}
	}

	n.Options = Options{
		ListenIP:   "0.0.0.0",
		SendIP:     "0.0.0.0",
		CertConfig: NewCertConfig(),
	}
	if len(rn.OptRaw) > 0 {
		err = json.Unmarshal(rn.OptRaw, &n.Options)
		if err != nil {
			return
		}
	} else {
		err = json.Unmarshal(data, &n.Options)
		if err != nil {
			return
		}
	}
	return
}

type Options struct {
	Name                   string          `json:"Name"`
	Core                   string          `json:"Core"`
	CoreName               string          `json:"CoreName"`
	ListenIP               string          `json:"ListenIP"`
	SendIP                 string          `json:"SendIP"`
	DeviceOnlineMinTraffic int64           `json:"DeviceOnlineMinTraffic"`
	ReportMinTraffic       int64           `json:"ReportMinTraffic"`
	LimitConfig            LimitConfig     `json:"LimitConfig"`
	RawOptions             json.RawMessage `json:"RawOptions"`
	XrayOptions            *XrayOptions    `json:"XrayOptions"`
	SingOptions            *SingOptions    `json:"SingOptions"`
	Hysteria2ConfigPath    string          `json:"Hysteria2ConfigPath"`
	CertConfig             *CertConfig     `json:"CertConfig"`
	SyncConfig             *SyncConfig     `json:"SyncConfig"`
}

// SyncConfig 同步配置
type SyncConfig struct {
	// WebSocket 配置
	EnableWebSocket   bool   `json:"EnableWebSocket"`
	WSEndpoint        string `json:"WSEndpoint"`
	ReconnectInterval int    `json:"ReconnectInterval"` // 秒
	MaxReconnectTries int    `json:"MaxReconnectTries"` // 0 = 无限重试

	// 心跳配置
	PingInterval int `json:"PingInterval"` // 秒
	PongTimeout  int `json:"PongTimeout"`  // 秒

	// 消息配置
	AckTimeout int `json:"AckTimeout"` // 秒
	BufferSize int `json:"BufferSize"`

	// 降级配置
	EnableFallback   bool `json:"EnableFallback"`
	FallbackInterval int  `json:"FallbackInterval"` // 秒
}

// NewSyncConfig 创建默认同步配置
func NewSyncConfig() *SyncConfig {
	return &SyncConfig{
		EnableWebSocket:   false, // 默认不启用，等后端支持后启用
		WSEndpoint:        "/api/v2/node/ws",
		ReconnectInterval: 5,
		MaxReconnectTries: 0,
		PingInterval:      30,
		PongTimeout:       10,
		AckTimeout:        5,
		BufferSize:        100,
		EnableFallback:    true,
		FallbackInterval:  60,
	}
}

func (o *Options) UnmarshalJSON(data []byte) error {
	type opt Options
	err := json.Unmarshal(data, (*opt)(o))
	if err != nil {
		return err
	}
	switch o.Core {
	case "xray":
		o.XrayOptions = NewXrayOptions()
		return json.Unmarshal(data, o.XrayOptions)
	case "sing":
		o.SingOptions = NewSingOptions()
		return json.Unmarshal(data, o.SingOptions)
	case "hysteria2":
		o.RawOptions = data
		return nil
	default:
		o.Core = ""
		o.RawOptions = data
	}
	return nil
}
