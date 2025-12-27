package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/sign"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// SyncState 同步状态
type SyncState int32

const (
	SyncStateDisconnected SyncState = iota
	SyncStateConnecting
	SyncStateConnected
	SyncStateFallback
	SyncStateClosed
)

func (s SyncState) String() string {
	switch s {
	case SyncStateDisconnected:
		return "disconnected"
	case SyncStateConnecting:
		return "connecting"
	case SyncStateConnected:
		return "connected"
	case SyncStateFallback:
		return "fallback"
	case SyncStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// SyncConfig 同步配置
type SyncConfig struct {
	// WebSocket 配置
	EnableWebSocket   bool          `json:"EnableWebSocket"`
	WSEndpoint        string        `json:"WSEndpoint"`
	ReconnectInterval time.Duration `json:"ReconnectInterval"`
	MaxReconnectTries int           `json:"MaxReconnectTries"` // 0 = 无限重试

	// 心跳配置
	PingInterval time.Duration `json:"PingInterval"`
	PongTimeout  time.Duration `json:"PongTimeout"`

	// 消息配置
	AckTimeout time.Duration `json:"AckTimeout"`
	BufferSize int           `json:"BufferSize"`

	// 降级配置
	EnableFallback   bool          `json:"EnableFallback"`
	FallbackInterval time.Duration `json:"FallbackInterval"`
}

// DefaultSyncConfig 默认同步配置
func DefaultSyncConfig() *SyncConfig {
	return &SyncConfig{
		EnableWebSocket:   true,
		WSEndpoint:        "/api/v2/node/ws",
		ReconnectInterval: 5 * time.Second,
		MaxReconnectTries: 0,
		PingInterval:      30 * time.Second,
		PongTimeout:       10 * time.Second,
		AckTimeout:        5 * time.Second,
		BufferSize:        100,
		EnableFallback:    true,
		FallbackInterval:  60 * time.Second,
	}
}

// SyncManager 同步管理器
type SyncManager struct {
	client     *panel.Client
	controller *Controller
	config     *SyncConfig

	// WebSocket 连接
	conn   *websocket.Conn
	connMu sync.RWMutex

	// 状态
	state        int32 // atomic
	reconnecting int32 // atomic

	// 消息通道
	inbound  chan *panel.SyncMessage
	outbound chan *panel.SyncMessage

	// 待确认消息
	pendingAcks sync.Map // map[msgID]*pendingAck

	// 统计
	stats *SyncStats

	// 生命周期
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// SyncStats 同步统计
type SyncStats struct {
	MessagesReceived int64
	MessagesSent     int64
	ReconnectCount   int64
	LastConnectedAt  time.Time
	LastMessageAt    time.Time
	CurrentLatency   int64 // ms
}

// pendingAck 待确认消息
type pendingAck struct {
	msg     *panel.SyncMessage
	sentAt  time.Time
	ackChan chan *panel.AckPayload
	timeout time.Duration
}

// NewSyncManager 创建同步管理器
func NewSyncManager(client *panel.Client, controller *Controller, config *SyncConfig) *SyncManager {
	if config == nil {
		config = DefaultSyncConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &SyncManager{
		client:     client,
		controller: controller,
		config:     config,
		inbound:    make(chan *panel.SyncMessage, config.BufferSize),
		outbound:   make(chan *panel.SyncMessage, config.BufferSize),
		stats:      &SyncStats{},
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start 启动同步管理器
func (sm *SyncManager) Start() error {
	if !sm.config.EnableWebSocket {
		log.Info("WebSocket sync disabled, using polling mode only")
		return nil
	}

	log.WithField("endpoint", sm.config.WSEndpoint).Info("Starting sync manager")

	// 尝试连接
	if err := sm.connect(); err != nil {
		log.WithError(err).Warn("Initial WebSocket connection failed")

		if sm.config.EnableFallback {
			log.Info("Falling back to polling mode")
			sm.setState(SyncStateFallback)
			sm.wg.Add(1)
			go sm.runFallbackMode()
		}
		return nil
	}

	// 启动工作协程
	sm.startWorkers()

	return nil
}

// connect 建立 WebSocket 连接
func (sm *SyncManager) connect() error {
	if !sm.compareAndSetState(SyncStateDisconnected, SyncStateConnecting) &&
		!sm.compareAndSetState(SyncStateFallback, SyncStateConnecting) {
		return fmt.Errorf("invalid state for connect: %s", sm.getState())
	}

	wsURL := sm.buildWSURL()

	log.WithField("url", wsURL).Debug("Connecting to WebSocket")

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	headers := sm.buildHeaders()

	conn, resp, err := dialer.DialContext(sm.ctx, wsURL, headers)
	if err != nil {
		sm.setState(SyncStateDisconnected)
		if resp != nil {
			log.WithFields(log.Fields{
				"status": resp.StatusCode,
				"error":  err,
			}).Error("WebSocket dial failed")
		}
		return fmt.Errorf("dial: %w", err)
	}

	sm.connMu.Lock()
	sm.conn = conn
	sm.connMu.Unlock()

	sm.setState(SyncStateConnected)
	sm.stats.LastConnectedAt = time.Now()

	log.Info("WebSocket connected successfully")
	return nil
}

// buildWSURL 构建 WebSocket URL
func (sm *SyncManager) buildWSURL() string {
	baseURL := sm.client.APIHost

	// 替换 http -> ws, https -> wss
	baseURL = strings.Replace(baseURL, "https://", "wss://", 1)
	baseURL = strings.Replace(baseURL, "http://", "ws://", 1)

	// 解析并添加查询参数
	u, err := url.Parse(baseURL + sm.config.WSEndpoint)
	if err != nil {
		return baseURL + sm.config.WSEndpoint
	}

	q := u.Query()
	q.Set("node_id", strconv.Itoa(sm.client.NodeId))
	u.RawQuery = q.Encode()

	return u.String()
}

// buildHeaders 构建请求头
func (sm *SyncManager) buildHeaders() http.Header {
	headers := http.Header{}
	headers.Set("X-API-Key", sm.client.Token)
	headers.Set("X-Node-ID", strconv.Itoa(sm.client.NodeId))

	// 添加签名
	if sm.client.EnableSign && sm.client.Secret != "" {
		signer := sign.NewSigner(sm.client.Secret)
		signData := signer.Sign("GET", sm.config.WSEndpoint, nil)
		headers.Set("X-Timestamp", signData.Timestamp)
		headers.Set("X-Nonce", signData.Nonce)
		headers.Set("X-Signature", signData.Signature)
	}

	return headers
}

// startWorkers 启动工作协程
func (sm *SyncManager) startWorkers() {
	sm.wg.Add(4)
	go sm.readLoop()
	go sm.writeLoop()
	go sm.processLoop()
	go sm.heartbeatLoop()
}

// readLoop 读取消息循环
func (sm *SyncManager) readLoop() {
	defer sm.wg.Done()
	defer sm.handleDisconnect()

	for {
		select {
		case <-sm.ctx.Done():
			return
		default:
		}

		sm.connMu.RLock()
		conn := sm.conn
		sm.connMu.RUnlock()

		if conn == nil {
			return
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.WithError(err).Error("WebSocket read error")
			}
			return
		}

		var msg panel.SyncMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			log.WithError(err).Error("Failed to unmarshal message")
			continue
		}

		atomic.AddInt64(&sm.stats.MessagesReceived, 1)
		sm.stats.LastMessageAt = time.Now()

		// 优先处理紧急消息
		if msg.IsUrgent() {
			go sm.handleMessage(&msg)
		} else {
			select {
			case sm.inbound <- &msg:
			default:
				log.Warn("Inbound channel full, dropping message")
			}
		}
	}
}

// writeLoop 发送消息循环
func (sm *SyncManager) writeLoop() {
	defer sm.wg.Done()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case msg := <-sm.outbound:
			if err := sm.send(msg); err != nil {
				log.WithError(err).Error("Failed to send message")
			}
		}
	}
}

// processLoop 处理消息循环
func (sm *SyncManager) processLoop() {
	defer sm.wg.Done()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case msg := <-sm.inbound:
			sm.handleMessage(msg)
		}
	}
}

// heartbeatLoop 心跳循环
func (sm *SyncManager) heartbeatLoop() {
	defer sm.wg.Done()

	ticker := time.NewTicker(sm.config.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			if sm.getState() != SyncStateConnected {
				continue
			}

			// 发送心跳
			if err := sm.sendHeartbeat(); err != nil {
				log.WithError(err).Warn("Failed to send heartbeat")
			}
		}
	}
}

// handleMessage 处理消息
func (sm *SyncManager) handleMessage(msg *panel.SyncMessage) {
	log.WithFields(log.Fields{
		"type": msg.Type,
		"id":   msg.ID,
	}).Debug("Processing sync message")

	var err error

	switch msg.Type {
	case panel.MsgTypeConfigUpdate:
		err = sm.handleConfigUpdate(msg)
	case panel.MsgTypeUserUpdate:
		err = sm.handleUserUpdate(msg)
	case panel.MsgTypeUserBan:
		err = sm.handleUserBan(msg)
	case panel.MsgTypeRuleUpdate:
		err = sm.handleRuleUpdate(msg)
	case panel.MsgTypeCertUpdate:
		err = sm.handleCertUpdate(msg)
	case panel.MsgTypePing:
		err = sm.handlePing(msg)
	case panel.MsgTypeForceReload:
		err = sm.handleForceReload(msg)
	case panel.MsgTypeAck:
		sm.handleAck(msg)
		return // Ack 消息不需要再确认
	default:
		log.WithField("type", msg.Type).Warn("Unknown message type")
		return
	}

	// 发送确认
	if msg.RequireAck {
		sm.sendAck(msg.ID, err)
	}
}

// handleConfigUpdate 处理配置更新
func (sm *SyncManager) handleConfigUpdate(msg *panel.SyncMessage) error {
	var payload panel.ConfigUpdatePayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	log.WithFields(log.Fields{
		"version":    payload.Version,
		"changeType": payload.ChangeType,
	}).Info("Received config update")

	if payload.ChangeType == "full" && payload.NodeInfo != nil {
		// 完整配置更新 - 触发节点重载
		return sm.controller.reloadNode(payload.NodeInfo)
	}

	// TODO: 实现增量配置更新
	// 目前先使用完整重载
	log.Debug("Partial config update, fetching full config")
	return sm.controller.nodeInfoMonitor()
}

// handleUserUpdate 处理用户更新
func (sm *SyncManager) handleUserUpdate(msg *panel.SyncMessage) error {
	var payload panel.UserUpdatePayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	log.WithFields(log.Fields{
		"action": payload.Action,
		"count":  len(payload.Users),
	}).Info("Received user update")

	switch payload.Action {
	case "add":
		_, err := sm.controller.server.AddUsers(&vCore.AddUsersParams{
			Tag:      sm.controller.tag,
			Users:    payload.Users,
			NodeInfo: sm.controller.info,
		})
		if err != nil {
			return fmt.Errorf("add users: %w", err)
		}
		sm.controller.limiter.UpdateUser(sm.controller.tag, payload.Users, nil)

	case "remove":
		if err := sm.controller.server.DelUsers(payload.Users, sm.controller.tag, sm.controller.info); err != nil {
			return fmt.Errorf("del users: %w", err)
		}
		sm.controller.limiter.UpdateUser(sm.controller.tag, nil, payload.Users)

	case "update":
		// 先删除再添加
		_ = sm.controller.server.DelUsers(payload.Users, sm.controller.tag, sm.controller.info)
		_, err := sm.controller.server.AddUsers(&vCore.AddUsersParams{
			Tag:      sm.controller.tag,
			Users:    payload.Users,
			NodeInfo: sm.controller.info,
		})
		if err != nil {
			return fmt.Errorf("update users: %w", err)
		}
		sm.controller.limiter.UpdateUser(sm.controller.tag, payload.Users, payload.Users)
	}

	return nil
}

// handleUserBan 处理用户封禁 (紧急事件)
func (sm *SyncManager) handleUserBan(msg *panel.SyncMessage) error {
	var payload panel.UserBanPayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	log.WithFields(log.Fields{
		"count":  len(payload.UUIDs),
		"reason": payload.Reason,
	}).Warn("Received user ban (URGENT)")

	// 构建 UserInfo 用于删除
	users := make([]panel.UserInfo, 0, len(payload.UUIDs))
	for i, uuid := range payload.UUIDs {
		uid := 0
		if i < len(payload.UserIDs) {
			uid = payload.UserIDs[i]
		}
		users = append(users, panel.UserInfo{
			Id:   uid,
			Uuid: uuid,
		})
	}

	// 立即删除
	if err := sm.controller.server.DelUsers(users, sm.controller.tag, sm.controller.info); err != nil {
		return fmt.Errorf("ban users: %w", err)
	}

	sm.controller.limiter.UpdateUser(sm.controller.tag, nil, users)

	return nil
}

// handleRuleUpdate 处理规则更新
func (sm *SyncManager) handleRuleUpdate(msg *panel.SyncMessage) error {
	var payload panel.RuleUpdatePayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	log.WithField("action", payload.Action).Info("Received rule update")

	return sm.controller.limiter.UpdateRule(&payload.Rules)
}

// handleCertUpdate 处理证书更新
func (sm *SyncManager) handleCertUpdate(msg *panel.SyncMessage) error {
	var payload panel.CertUpdatePayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	log.WithField("domain", payload.Domain).Info("Received cert update")

	// TODO: 实现证书热更新
	// 目前先触发完整重载
	if payload.AutoReload {
		return sm.controller.nodeInfoMonitor()
	}

	return nil
}

// handlePing 处理 Ping
func (sm *SyncManager) handlePing(msg *panel.SyncMessage) error {
	var payload panel.PingPayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	// 回复 Pong
	pong := &panel.PongPayload{
		ServerTime: payload.ServerTime,
		ClientTime: time.Now().Unix(),
		Latency:    time.Now().UnixMilli() - payload.ServerTime*1000,
	}

	pongMsg, _ := panel.NewSyncMessage(panel.MsgTypePong, sm.client.NodeId, pong)
	sm.outbound <- pongMsg

	return nil
}

// handleForceReload 处理强制重载
func (sm *SyncManager) handleForceReload(msg *panel.SyncMessage) error {
	var payload panel.ForceReloadPayload
	if err := msg.ParsePayload(&payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	log.WithField("reason", payload.Reason).Warn("Received force reload command")

	// 重新获取配置并重载节点
	return sm.controller.nodeInfoMonitor()
}

// handleAck 处理确认消息
func (sm *SyncManager) handleAck(msg *panel.SyncMessage) {
	var payload panel.AckPayload
	if err := msg.ParsePayload(&payload); err != nil {
		log.WithError(err).Error("Failed to parse ack payload")
		return
	}

	if pending, ok := sm.pendingAcks.LoadAndDelete(payload.MessageID); ok {
		p := pending.(*pendingAck)
		select {
		case p.ackChan <- &payload:
		default:
		}
	}
}

// sendAck 发送确认消息
func (sm *SyncManager) sendAck(msgID string, err error) {
	payload := &panel.AckPayload{
		MessageID: msgID,
		Success:   err == nil,
		Timestamp: time.Now().Unix(),
	}
	if err != nil {
		payload.Error = err.Error()
	}

	ackMsg, _ := panel.NewSyncMessage(panel.MsgTypeAck, sm.client.NodeId, payload)
	sm.outbound <- ackMsg
}

// sendHeartbeat 发送心跳
func (sm *SyncManager) sendHeartbeat() error {
	payload := &panel.HeartbeatPayload{
		Uptime:  time.Since(sm.stats.LastConnectedAt).Milliseconds() / 1000,
		Version: "1.0.0", // TODO: 使用实际版本
	}

	msg, _ := panel.NewSyncMessage(panel.MsgTypeHeartbeat, sm.client.NodeId, payload)
	sm.outbound <- msg

	return nil
}

// send 发送消息
func (sm *SyncManager) send(msg *panel.SyncMessage) error {
	sm.connMu.RLock()
	conn := sm.conn
	sm.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return err
	}

	atomic.AddInt64(&sm.stats.MessagesSent, 1)
	return nil
}

// handleDisconnect 处理断开连接
func (sm *SyncManager) handleDisconnect() {
	sm.connMu.Lock()
	if sm.conn != nil {
		sm.conn.Close()
		sm.conn = nil
	}
	sm.connMu.Unlock()

	if sm.getState() == SyncStateClosed {
		return
	}

	sm.setState(SyncStateDisconnected)

	// 启动重连
	go sm.reconnectLoop()
}

// reconnectLoop 重连循环
func (sm *SyncManager) reconnectLoop() {
	if !atomic.CompareAndSwapInt32(&sm.reconnecting, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&sm.reconnecting, 0)

	tries := 0

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-time.After(sm.config.ReconnectInterval):
		}

		if sm.getState() == SyncStateClosed {
			return
		}

		tries++
		atomic.AddInt64(&sm.stats.ReconnectCount, 1)

		log.WithField("attempt", tries).Info("Attempting to reconnect...")

		if err := sm.connect(); err != nil {
			log.WithError(err).Warn("Reconnect failed")

			if sm.config.MaxReconnectTries > 0 && tries >= sm.config.MaxReconnectTries {
				log.Error("Max reconnect tries reached")

				if sm.config.EnableFallback {
					log.Info("Switching to fallback mode")
					sm.setState(SyncStateFallback)
					sm.wg.Add(1)
					go sm.runFallbackMode()
				}
				return
			}
			continue
		}

		// 重连成功
		sm.startWorkers()
		return
	}
}

// runFallbackMode 降级到轮询模式
func (sm *SyncManager) runFallbackMode() {
	defer sm.wg.Done()

	log.Info("Running in fallback polling mode")

	ticker := time.NewTicker(sm.config.FallbackInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			// 尝试升级到 WebSocket
			if err := sm.connect(); err == nil {
				log.Info("Upgraded from fallback to WebSocket mode")
				sm.startWorkers()
				return
			}

			// 继续使用轮询
			if err := sm.controller.nodeInfoMonitor(); err != nil {
				log.WithError(err).Warn("Fallback poll failed")
			}
		}
	}
}

// State management

func (sm *SyncManager) getState() SyncState {
	return SyncState(atomic.LoadInt32(&sm.state))
}

func (sm *SyncManager) setState(s SyncState) {
	atomic.StoreInt32(&sm.state, int32(s))
}

func (sm *SyncManager) compareAndSetState(old, new SyncState) bool {
	return atomic.CompareAndSwapInt32(&sm.state, int32(old), int32(new))
}

// Close 关闭同步管理器
func (sm *SyncManager) Close() error {
	sm.setState(SyncStateClosed)
	sm.cancel()

	sm.connMu.Lock()
	if sm.conn != nil {
		sm.conn.Close()
		sm.conn = nil
	}
	sm.connMu.Unlock()

	// 等待所有协程退出
	sm.wg.Wait()

	return nil
}

// Stats 获取统计信息
func (sm *SyncManager) Stats() *SyncStats {
	return &SyncStats{
		MessagesReceived: atomic.LoadInt64(&sm.stats.MessagesReceived),
		MessagesSent:     atomic.LoadInt64(&sm.stats.MessagesSent),
		ReconnectCount:   atomic.LoadInt64(&sm.stats.ReconnectCount),
		LastConnectedAt:  sm.stats.LastConnectedAt,
		LastMessageAt:    sm.stats.LastMessageAt,
		CurrentLatency:   sm.stats.CurrentLatency,
	}
}

// IsConnected 是否已连接
func (sm *SyncManager) IsConnected() bool {
	return sm.getState() == SyncStateConnected
}
