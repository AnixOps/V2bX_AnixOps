package panel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

// DebugConfig 调试配置
type DebugConfig struct {
	Enable    bool   `json:"Enable"`
	OutputDir string `json:"OutputDir"`
}

// DefaultDebugConfig 默认调试配置
func DefaultDebugConfig() *DebugConfig {
	return &DebugConfig{
		Enable:    false,
		OutputDir: "test_data/api_debug",
	}
}

// DebugDumper API 响应调试工具
type DebugDumper struct {
	config    *DebugConfig
	sessionID string // 会话ID (基于启动时间)
}

// NewDebugDumper 创建调试工具
func NewDebugDumper(config *DebugConfig) *DebugDumper {
	if config == nil {
		config = DefaultDebugConfig()
	}

	// 生成会话ID
	sessionID := time.Now().Format("20060102_150405")

	return &DebugDumper{
		config:    config,
		sessionID: sessionID,
	}
}

// DumpNodeConfig 保存节点配置响应
func (d *DebugDumper) DumpNodeConfig(rawJSON []byte, nodeID int) error {
	if !d.config.Enable {
		return nil
	}

	return d.dumpJSON("node_config", rawJSON, nodeID)
}

// DumpUserList 保存用户列表响应
func (d *DebugDumper) DumpUserList(rawJSON []byte, nodeID int) error {
	if !d.config.Enable {
		return nil
	}

	return d.dumpJSON("user_list", rawJSON, nodeID)
}

// DumpUserAlive 保存用户在线状态响应
func (d *DebugDumper) DumpUserAlive(rawJSON []byte, nodeID int) error {
	if !d.config.Enable {
		return nil
	}

	return d.dumpJSON("user_alive", rawJSON, nodeID)
}

// DumpParsedNodeInfo 保存解析后的节点信息
func (d *DebugDumper) DumpParsedNodeInfo(nodeInfo *NodeInfo, nodeID int) error {
	if !d.config.Enable {
		return nil
	}

	data, err := json.MarshalIndent(nodeInfo, "", "  ")
	if err != nil {
		return err
	}

	return d.dumpJSON("parsed_node_info", data, nodeID)
}

// DumpGeneratedConfig 保存生成的核心配置
func (d *DebugDumper) DumpGeneratedConfig(configType string, config interface{}, nodeID int) error {
	if !d.config.Enable {
		return nil
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("generated_%s", configType)
	return d.dumpJSON(filename, data, nodeID)
}

// dumpJSON 保存 JSON 数据到文件
func (d *DebugDumper) dumpJSON(name string, data []byte, nodeID int) error {
	// 创建目录结构: test_data/api_debug/{session_id}/node_{id}/
	dir := filepath.Join(d.config.OutputDir, d.sessionID, fmt.Sprintf("node_%d", nodeID))

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create debug dir: %w", err)
	}

	// 文件名带时间戳
	timestamp := time.Now().Format("150405.000")
	filename := fmt.Sprintf("%s_%s.json", timestamp, name)
	filePath := filepath.Join(dir, filename)

	// 美化 JSON
	var prettyJSON []byte
	var temp interface{}
	if err := json.Unmarshal(data, &temp); err == nil {
		prettyJSON, _ = json.MarshalIndent(temp, "", "  ")
	} else {
		prettyJSON = data
	}

	if err := os.WriteFile(filePath, prettyJSON, 0644); err != nil {
		return fmt.Errorf("write debug file: %w", err)
	}

	log.WithFields(log.Fields{
		"file": filePath,
		"size": len(prettyJSON),
	}).Debug("Dumped API response")

	return nil
}

// DumpSummary 保存汇总信息
func (d *DebugDumper) DumpSummary(nodeID int, info map[string]interface{}) error {
	if !d.config.Enable {
		return nil
	}

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}

	return d.dumpJSON("summary", data, nodeID)
}

// GetSessionDir 获取当前会话的目录
func (d *DebugDumper) GetSessionDir() string {
	return filepath.Join(d.config.OutputDir, d.sessionID)
}

// IsEnabled 是否启用调试
func (d *DebugDumper) IsEnabled() bool {
	return d.config.Enable
}
