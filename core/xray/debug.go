package xray

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"encoding/json"

	log "github.com/sirupsen/logrus"
)

// CoreDebugger 提供 Xray 内核调试功能
type CoreDebugger struct {
	enabled   bool
	outputDir string
	sessionID string
	mu        sync.Mutex

	// 配置快照
	inboundConfigs  map[string]interface{}
	outboundConfigs map[string]interface{}
}

// NewCoreDebugger 创建调试器
func NewCoreDebugger(enabled bool, outputDir string) *CoreDebugger {
	if !enabled {
		return &CoreDebugger{enabled: false}
	}

	if outputDir == "" {
		outputDir = "test_data/core_debug"
	}

	sessionID := time.Now().Format("20060102_150405")

	debugger := &CoreDebugger{
		enabled:         true,
		outputDir:       outputDir,
		sessionID:       sessionID,
		inboundConfigs:  make(map[string]interface{}),
		outboundConfigs: make(map[string]interface{}),
	}

	// 创建输出目录
	sessionDir := filepath.Join(outputDir, sessionID)
	if err := os.MkdirAll(sessionDir, 0755); err != nil {
		log.WithError(err).Warn("Failed to create core debug directory")
		return &CoreDebugger{enabled: false}
	}

	log.WithField("dir", sessionDir).Info("Core debugger initialized")
	return debugger
}

// IsEnabled 检查是否启用
func (d *CoreDebugger) IsEnabled() bool {
	return d != nil && d.enabled
}

// LogCoreStart 记录内核启动
func (d *CoreDebugger) LogCoreStart(coreType string, version string) {
	if !d.IsEnabled() {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	info := map[string]interface{}{
		"event":     "core_start",
		"timestamp": time.Now().Format(time.RFC3339),
		"core_type": coreType,
		"version":   version,
	}

	d.writeJSON("core_start.json", info)
	log.WithFields(log.Fields{
		"core": coreType,
		"ver":  version,
	}).Debug("[CoreDebug] Core started")
}

// LogCoreStop 记录内核停止
func (d *CoreDebugger) LogCoreStop(coreType string) {
	if !d.IsEnabled() {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	info := map[string]interface{}{
		"event":     "core_stop",
		"timestamp": time.Now().Format(time.RFC3339),
		"core_type": coreType,
	}

	d.writeJSON("core_stop.json", info)
	log.WithField("core", coreType).Debug("[CoreDebug] Core stopped")
}

// LogInboundAdd 记录添加入站
func (d *CoreDebugger) LogInboundAdd(tag string, protocol string, port int, config interface{}) {
	if !d.IsEnabled() {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	filename := fmt.Sprintf("inbound_%s.json", sanitizeFilename(tag))

	info := map[string]interface{}{
		"event":     "inbound_add",
		"timestamp": time.Now().Format(time.RFC3339),
		"tag":       tag,
		"protocol":  protocol,
		"port":      port,
		"config":    config,
	}

	d.inboundConfigs[tag] = info
	d.writeJSON(filename, info)

	log.WithFields(log.Fields{
		"tag":      tag,
		"protocol": protocol,
		"port":     port,
	}).Debug("[CoreDebug] Inbound added")
}

// LogInboundRemove 记录移除入站
func (d *CoreDebugger) LogInboundRemove(tag string) {
	if !d.IsEnabled() {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.inboundConfigs, tag)

	log.WithField("tag", tag).Debug("[CoreDebug] Inbound removed")
}

// LogUserAdd 记录添加用户
func (d *CoreDebugger) LogUserAdd(tag string, count int, users interface{}) {
	if !d.IsEnabled() {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	filename := fmt.Sprintf("users_%s_%s.json",
		sanitizeFilename(tag),
		time.Now().Format("150405"))

	info := map[string]interface{}{
		"event":     "users_add",
		"timestamp": time.Now().Format(time.RFC3339),
		"tag":       tag,
		"count":     count,
		"users":     users,
	}

	d.writeJSON(filename, info)

	log.WithFields(log.Fields{
		"tag":   tag,
		"count": count,
	}).Debug("[CoreDebug] Users added")
}

// LogUserRemove 记录移除用户
func (d *CoreDebugger) LogUserRemove(tag string, count int) {
	if !d.IsEnabled() {
		return
	}

	log.WithFields(log.Fields{
		"tag":   tag,
		"count": count,
	}).Debug("[CoreDebug] Users removed")
}

// LogError 记录错误
func (d *CoreDebugger) LogError(operation string, tag string, err error) {
	if !d.IsEnabled() {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	filename := fmt.Sprintf("error_%s.json", time.Now().Format("150405.000"))

	info := map[string]interface{}{
		"event":     "error",
		"timestamp": time.Now().Format(time.RFC3339),
		"operation": operation,
		"tag":       tag,
		"error":     err.Error(),
	}

	d.writeJSON(filename, info)

	log.WithFields(log.Fields{
		"op":  operation,
		"tag": tag,
		"err": err,
	}).Error("[CoreDebug] Operation failed")
}

// LogXrayConfig 记录完整的 Xray 配置
func (d *CoreDebugger) LogXrayConfig(tag string, inboundConfig interface{}) {
	if !d.IsEnabled() {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	filename := fmt.Sprintf("xray_config_%s.json", sanitizeFilename(tag))

	info := map[string]interface{}{
		"event":     "xray_inbound_config",
		"timestamp": time.Now().Format(time.RFC3339),
		"tag":       tag,
		"config":    inboundConfig,
	}

	d.writeJSON(filename, info)
}

// DumpCurrentState 输出当前状态
func (d *CoreDebugger) DumpCurrentState() {
	if !d.IsEnabled() {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	state := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"inbounds":  d.inboundConfigs,
		"outbounds": d.outboundConfigs,
	}

	d.writeJSON("current_state.json", state)
	log.Debug("[CoreDebug] State dumped")
}

// writeJSON 写入 JSON 文件
func (d *CoreDebugger) writeJSON(filename string, data interface{}) {
	sessionDir := filepath.Join(d.outputDir, d.sessionID)
	filePath := filepath.Join(sessionDir, filename)

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.WithError(err).Warn("Failed to marshal debug data")
		return
	}

	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		log.WithError(err).Warn("Failed to write debug file")
	}
}

// sanitizeFilename 清理文件名
func sanitizeFilename(s string) string {
	// 移除不安全的字符
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		"[", "",
		"]", "",
	)
	return replacer.Replace(s)
}
