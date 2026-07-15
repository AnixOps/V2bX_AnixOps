# AnixOps Agent 多协议配置与同步机制设计文档

> 状态说明：本文保留早期 WebSocket/轮询设计作为兼容背景。`v3.0.0-alpha.1`
> 已引入 opt-in 的 `anix.agent.v1` 双向 gRPC 控制流，作为 Agent-first
> foundation/preview；REST/UniProxy、旧版 gRPC 和 WebSocket 仍是数据面或回退
> 路径，新控制流尚未接管所有生产任务源。

## 目录

1. [当前多协议配置架构](#1-当前多协议配置架构)
2. [数据流程分析](#2-数据流程分析)
3. [当前同步机制的限制](#3-当前同步机制的限制)
4. [双边通讯同步方案设计](#4-双边通讯同步方案设计)
5. [实现计划](#5-实现计划)

---

## 1. 当前多协议配置架构

### 1.1 配置结构概览

```
配置文件 (config.json)
├── Log: 日志配置
├── Cores[]: 核心引擎配置 (支持多核心)
│   ├── Type: xray | sing | hysteria2 | wireguard
│   └── ... 核心特定配置
└── Nodes[]: 节点配置 (支持多节点)
    ├── Core: 指定使用的核心
    ├── ApiConfig: 后端 API 配置
    └── Options: 节点选项
```

### 1.2 核心组件关系

```
                    ┌─────────────────────────────────────┐
                    │           main.go                   │
                    │         程序入口                     │
                    └─────────────┬───────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────────────┐
                    │         conf.Conf                   │
                    │    配置加载 (conf/conf.go)          │
                    └─────────────┬───────────────────────┘
                                  │
                    ┌─────────────┴───────────────┐
                    │                             │
                    ▼                             ▼
        ┌───────────────────┐        ┌─────────────────────────┐
        │   core.Core       │        │      node.Node          │
        │  核心引擎接口      │        │   节点管理器             │
        │ (core/core.go)    │        │  (node/node.go)         │
        └───────────────────┘        └───────────┬─────────────┘
                    │                             │
    ┌───────────────┼───────────────┐            │
    │               │               │            │
    ▼               ▼               ▼            ▼
┌───────┐     ┌─────────┐    ┌──────────┐  ┌────────────┐  ┌─────────────────┐
│ xray  │     │  sing   │    │ hysteria2│  │ wireguard  │  │  Controller[]   │
│ 核心  │     │  核心   │    │   核心   │  │ 系统运行时  │  │  每个节点一个    │
└───────┘     └─────────┘    └──────────┘  └────────────┘  └───────┬─────────┘
                                                   │
                                                   ▼
                                          ┌─────────────────┐
                                          │  panel.Client   │
                                          │  API 客户端     │
                                          └─────────────────┘
```

### 1.3 多核心选择机制 (Selector)

当配置多个 Core 时，系统使用 `Selector` 模式：

```go
// core/selector.go
type Selector struct {
    cores map[string]Core  // 核心映射表
    nodes sync.Map         // 节点到核心的映射
}
```

**核心选择逻辑**:
1. 如果 `Options.CoreName` 指定，使用名称匹配
2. 否则，根据 `Options.Core` 类型匹配
3. 再否则，根据协议类型自动匹配支持该协议的核心

### 1.4 支持的协议类型

| 协议类型 | 支持的核心 | 安全模式 |
|---------|-----------|---------|
| vmess | xray, sing | None/Tls/Reality |
| vless | xray, sing | None/Tls/Reality |
| trojan | xray, sing | Tls |
| shadowsocks | xray, sing | None |
| tuic | sing | Tls |
| anytls | sing | Tls |
| hysteria | hysteria2 | Tls |
| hysteria2 | hysteria2 | Tls |
| wireguard | wireguard | None |

WireGuard core 通过面板下发的节点配置和用户 peer 扩展字段应用入口机 WireGuard 接口。它依赖系统 `ip`、`wg` 命令；GOST relay+QUIC 是默认双机目标路径，WSS 仅为兼容模式。节点配置显式设置 `Core: "wireguard"` 时，首次配置拉取会自动限定为 `node_type=wireguard`，避免混合协议节点按协议排序取到错误配置；显式 `NodeType` 优先。当前还会从最近的 `wg show <iface> dump` 握手记录合并 peer 在线状态到现有 `/alive` 上报。V2bX 已有首版 GOST TUN relay runtime 切片：entry 角色启动 GOST TUN over `relay+quic`/`relay+wss` 并为 IPv4 WireGuard CIDR 安装策略路由；exit 角色只启动匹配 listener 与 IPv4 iptables NAT，不创建本地 WireGuard interface、不接收任何运行时用户列表或 user peer，也不采集 peer 流量。出口配置不得包含入口机的 `server_address`、`server_private_key`、`server_public_key` 或 `public_key`，面板会拒绝这些字段，V2bX 也不会使用它们。WSS 使用 `wss_path` 匹配两端，入口必须启用 `wss_secure` 并配置 `wss_server_name`，出口必须配置 `wss_cert_file` 与 `wss_key_file`；可选 `wss_ca_file` 支持私有 CA 校验。入口通过 Linux `tc` 应用节点和 peer 限速、收敛动态限速。GOST 进程退出会被监测、清理并自动重启，runtime health 通过 REST 或 gRPC 日志通道回传面板；首版 relay 运行时拒绝 IPv6 peer/relay CIDR 与 IPv6 AllowedIPs；严格 tag/RC 发布会执行 GitHub Actions 网络命名空间 QUIC/WSS 验收，真实 GOST/WSS 跨地域链路仍需要补齐后才能标记生产完成。

---

## 2. 数据流程分析

### 2.1 启动流程

```
1. 加载配置文件 (conf.LoadFromPath)
         │
         ▼
2. 初始化核心引擎 (core.NewCore)
   ├── 单核心: 直接创建
   └── 多核心: 创建 Selector
         │
         ▼
3. 启动核心引擎 (core.Start)
         │
         ▼
4. 创建节点管理器 (node.New)
         │
         ▼
5. 为每个节点创建控制器 (node.Start)
   ├── 创建 panel.Client
   ├── 自动注册 (如果启用)
   └── 获取初始配置
         │
         ▼
6. 启动定时任务
   ├── nodeInfoMonitor (拉取节点配置)
   ├── userReportPeriodic (上报流量)
   ├── renewCertPeriodic (证书续期)
   └── dynamicSpeedLimitPeriodic (动态限速)
```

### 2.2 当前同步机制 (单向拉取)

```
┌─────────────────┐                      ┌─────────────────┐
│    V2bX 节点    │                      │   后端 Panel    │
│                 │                      │                 │
│  定时任务       │                      │                 │
│  (PullInterval) │  ────GET /config───► │  返回节点配置   │
│                 │  ◄─────────────────  │                 │
│                 │                      │                 │
│  定时任务       │  ────GET /user────►  │  返回用户列表   │
│  (PullInterval) │  ◄─────────────────  │                 │
│                 │                      │                 │
│  定时任务       │  ────POST /report──► │  接收流量数据   │
│  (PushInterval) │  ◄─────────────────  │                 │
└─────────────────┘                      └─────────────────┘
```

### 2.3 配置变更检测

当前使用 **ETag + Body Hash** 双重检测机制：

```go
// api/panel/node.go - GetNodeInfo()
r, err := c.client.R().
    SetHeader("If-None-Match", c.nodeEtag).  // ETag 检测
    Get(path)

if r.StatusCode() == 304 {
    return nil, nil  // 无变化
}

hash := sha256.Sum256(r.Body())
newBodyHash := hex.EncodeToString(hash[:])
if c.responseBodyHash == newBodyHash {
    return nil, nil  // 内容相同
}
```

### 2.4 配置变更处理 (node/task.go)

```go
func (c *Controller) nodeInfoMonitor() error {
    newN, _ := c.apiClient.GetNodeInfo()
    newU, _ := c.apiClient.GetUserList()
    newA, _ := c.apiClient.GetUserAlive()
    
    if newN != nil {
        // 节点配置变化 -> 重载整个节点
        c.server.DelNode(c.tag)
        c.server.AddNode(c.tag, newN, c.Options)
        c.server.AddUsers(...)
    } else if len(newU) > 0 {
        // 仅用户列表变化 -> 增量更新
        deleted, added := compareUserList(c.userList, newU)
        c.server.DelUsers(deleted, ...)
        c.server.AddUsers(added, ...)
    }
}
```

---

## 3. 当前同步机制的限制

### 3.1 问题分析

| 问题 | 描述 | 影响 |
|-----|------|-----|
| **延迟性** | 依赖轮询间隔 (默认 60s)，配置变更不能即时生效 | 用户封禁延迟、配置更新滞后 |
| **资源浪费** | 即使无变化也要轮询 | 网络带宽、服务器 CPU |
| **单向通讯** | 节点无法主动通知面板 | 告警、状态上报不及时 |
| **连接状态** | 无法感知连接断开 | 节点离线检测依赖超时 |
| **扩展性** | 每个节点独立轮询 | 面板负载随节点数线性增长 |

### 3.2 场景示例

```
场景: 用户被封禁

当前流程:
1. 管理员在面板封禁用户 (T=0)
2. 节点下次轮询 (T=PullInterval, 最多 60s)
3. 节点删除用户 (T=60s+处理时间)

问题: 用户在封禁后最多还能使用 60 秒
```

---

## 4. 双边通讯同步方案设计

### 4.1 架构设计

```
┌─────────────────┐                      ┌─────────────────┐
│    V2bX 节点    │                      │   后端 Panel    │
│                 │                      │                 │
│  ┌───────────┐  │   WebSocket/SSE      │  ┌───────────┐  │
│  │  SyncMgr  │◄─┼──────────────────────┼──┤ PushSvc   │  │
│  └─────┬─────┘  │  (实时推送)          │  └───────────┘  │
│        │        │                      │                 │
│        ▼        │                      │                 │
│  ┌───────────┐  │   HTTP REST          │  ┌───────────┐  │
│  │Controller │──┼──────────────────────┼──┤   API     │  │
│  └───────────┘  │  (按需拉取/确认)      │  └───────────┘  │
│                 │                      │                 │
└─────────────────┘                      └─────────────────┘
```

### 4.2 通讯协议选择

| 协议 | 优点 | 缺点 | 适用场景 |
|-----|------|-----|---------|
| **WebSocket** | 全双工、低延迟、原生二进制支持 | 需要维护连接、代理兼容性 | 旧版实时同步兼容路径 |
| **SSE** | 简单、HTTP 兼容、自动重连 | 单向、文本模式 | 备选方案 |
| **Long Polling** | 最广泛兼容 | 延迟较高、资源消耗 | 兜底方案 |
| **gRPC Streaming** | 双向、类型安全、原生操作确认与状态观察 | 需要 HTTP/2、TLS 和幂等操作设计 | v3 alpha Agent-first 主控预览（显式 opt-in） |

**v3 alpha 推荐：`anix.agent.v1` gRPC 控制流 + 已验证的 REST/旧 gRPC 数据面回退。**

旧版 WebSocket + HTTP 混合模式继续兼容，但不再代表 Agent-first 的目标架构。
在新控制流覆盖全部任务源并完成持久化/重启验证前，不应删除这些回退路径。

### 4.3 消息类型定义

```go
// api/panel/sync.go

// SyncMessageType 同步消息类型
type SyncMessageType string

const (
    // 服务端 -> 节点
    MsgTypeConfigUpdate    SyncMessageType = "config_update"     // 配置更新
    MsgTypeUserUpdate      SyncMessageType = "user_update"       // 用户变更
    MsgTypeUserBan         SyncMessageType = "user_ban"          // 用户封禁
    MsgTypeRuleUpdate      SyncMessageType = "rule_update"       // 规则更新
    MsgTypeCertUpdate      SyncMessageType = "cert_update"       // 证书更新
    MsgTypePing            SyncMessageType = "ping"              // 心跳
    MsgTypeForceReload     SyncMessageType = "force_reload"      // 强制重载
    
    // 节点 -> 服务端
    MsgTypeHeartbeat       SyncMessageType = "heartbeat"         // 心跳响应
    MsgTypeAck             SyncMessageType = "ack"               // 确认消息
    MsgTypeTrafficReport   SyncMessageType = "traffic_report"    // 流量上报
    MsgTypeAlertReport     SyncMessageType = "alert"             // 告警上报
)

// SyncMessage 同步消息结构
type SyncMessage struct {
    ID        string          `json:"id"`         // 消息唯一ID
    Type      SyncMessageType `json:"type"`       // 消息类型
    Timestamp int64           `json:"timestamp"`  // 时间戳
    NodeID    int             `json:"node_id"`    // 节点ID
    Payload   json.RawMessage `json:"payload"`    // 消息负载
}

// ConfigUpdatePayload 配置更新负载
type ConfigUpdatePayload struct {
    Version     int64           `json:"version"`      // 配置版本号
    ChangeType  string          `json:"change_type"`  // full | partial
    NodeInfo    *NodeInfo       `json:"node_info,omitempty"`
    Changes     []ConfigChange  `json:"changes,omitempty"`
}

// ConfigChange 配置变更项
type ConfigChange struct {
    Field    string      `json:"field"`     // 变更字段
    OldValue interface{} `json:"old_value"` // 旧值
    NewValue interface{} `json:"new_value"` // 新值
}

// UserUpdatePayload 用户更新负载
type UserUpdatePayload struct {
    Action   string     `json:"action"`   // add | remove | update
    Users    []UserInfo `json:"users"`    // 涉及的用户
}
```

### 4.4 SyncManager 设计

```go
// node/sync.go

package node

import (
    "context"
    "sync"
    "time"
    
    "github.com/gorilla/websocket"
)

// SyncManager 同步管理器
type SyncManager struct {
    client      *panel.Client
    conn        *websocket.Conn
    controller  *Controller
    
    // 状态管理
    connected   bool
    reconnecting bool
    mu          sync.RWMutex
    
    // 消息处理
    msgChan     chan *panel.SyncMessage
    ackChan     chan string
    
    // 配置
    config      *SyncConfig
    
    // 生命周期
    ctx         context.Context
    cancel      context.CancelFunc
}

// SyncConfig 同步配置
type SyncConfig struct {
    // WebSocket 配置
    WSEndpoint        string        `json:"ws_endpoint"`
    WSEndpointFallbacks []string      `json:"ws_endpoint_fallbacks"`
    ReconnectInterval time.Duration `json:"reconnect_interval"`
    MaxReconnectTries int           `json:"max_reconnect_tries"`
    
    // 心跳配置  
    PingInterval      time.Duration `json:"ping_interval"`
    PongTimeout       time.Duration `json:"pong_timeout"`
    
    // 消息配置
    AckTimeout        time.Duration `json:"ack_timeout"`
    BufferSize        int           `json:"buffer_size"`
    AckRetries        int           `json:"ack_retries"`
    
    // 降级配置
    EnableFallback    bool          `json:"enable_fallback"`
    FallbackInterval  time.Duration `json:"fallback_interval"`
}

`WSEndpointFallbacks` 列表會在 `/api/v2/agent/ws` 之後順序嘗試，預設包含 `/api/v2/node/ws`，`AckRetries` 決定 `require_ack=true` 消息在每次 `AckTimeout` 後最多重試次數（實際嘗試次數為 `AckRetries + 1`），節點可根據 `id` 去重。

func DefaultSyncConfig() *SyncConfig {
    return &SyncConfig{
        WSEndpoint:        "/api/v2/agent/ws",
        WSEndpointFallbacks: []string{"/api/v2/node/ws"},
        ReconnectInterval: 5 * time.Second,
        MaxReconnectTries: 0, // 0 = 无限重试
        PingInterval:      30 * time.Second,
        PongTimeout:       10 * time.Second,
        AckTimeout:        5 * time.Second,
        AckRetries:        2,
        BufferSize:        100,
        EnableFallback:    true,
        FallbackInterval:  60 * time.Second,
    }
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
        msgChan:    make(chan *panel.SyncMessage, config.BufferSize),
        ackChan:    make(chan string, config.BufferSize),
        ctx:        ctx,
        cancel:     cancel,
    }
}

// Start 启动同步管理器
func (sm *SyncManager) Start() error {
    // 尝试建立 WebSocket 连接
    if err := sm.connect(); err != nil {
        log.WithError(err).Warn("WebSocket connection failed, using fallback mode")
        if sm.config.EnableFallback {
            go sm.runFallbackMode()
        }
        return nil
    }
    
    // 启动工作协程
    go sm.readLoop()
    go sm.writeLoop()
    go sm.heartbeatLoop()
    go sm.processLoop()
    
    return nil
}

// connect 建立 WebSocket 连接
func (sm *SyncManager) connect() error {
    sm.mu.Lock()
    defer sm.mu.Unlock()
    
    // 构建 WebSocket URL
    wsURL := sm.buildWSURL()
    
    // 创建连接
    dialer := websocket.Dialer{
        HandshakeTimeout: 10 * time.Second,
    }
    
    headers := http.Header{}
    headers.Set("X-API-Key", sm.client.APIKey)
    headers.Set("X-Node-ID", strconv.Itoa(sm.client.NodeId))
    
    // 添加签名
    if sm.client.EnableSign && sm.client.Secret != "" {
        sm.addWSSignature(headers)
    }
    
    conn, _, err := dialer.Dial(wsURL, headers)
    if err != nil {
        return fmt.Errorf("dial websocket: %w", err)
    }
    
    sm.conn = conn
    sm.connected = true
    
    log.Info("WebSocket connection established")
    return nil
}

// readLoop 读取消息循环
func (sm *SyncManager) readLoop() {
    defer sm.handleDisconnect()
    
    for {
        select {
        case <-sm.ctx.Done():
            return
        default:
        }
        
        _, message, err := sm.conn.ReadMessage()
        if err != nil {
            log.WithError(err).Error("Read message failed")
            return
        }
        
        var msg panel.SyncMessage
        if err := json.Unmarshal(message, &msg); err != nil {
            log.WithError(err).Error("Unmarshal message failed")
            continue
        }
        
        sm.msgChan <- &msg
    }
}

// processLoop 处理消息循环
func (sm *SyncManager) processLoop() {
    for {
        select {
        case <-sm.ctx.Done():
            return
        case msg := <-sm.msgChan:
            sm.handleMessage(msg)
        }
    }
}

// handleMessage 处理同步消息
func (sm *SyncManager) handleMessage(msg *panel.SyncMessage) {
    log.WithFields(log.Fields{
        "type": msg.Type,
        "id":   msg.ID,
    }).Debug("Received sync message")
    
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
    case panel.MsgTypePing:
        err = sm.handlePing(msg)
    case panel.MsgTypeForceReload:
        err = sm.handleForceReload(msg)
    default:
        log.WithField("type", msg.Type).Warn("Unknown message type")
    }
    
    // 发送确认
    sm.sendAck(msg.ID, err)
}

// handleConfigUpdate 处理配置更新
func (sm *SyncManager) handleConfigUpdate(msg *panel.SyncMessage) error {
    var payload panel.ConfigUpdatePayload
    if err := json.Unmarshal(msg.Payload, &payload); err != nil {
        return err
    }
    
    if payload.ChangeType == "full" {
        // 完整配置更新 - 重载节点
        return sm.controller.reloadNode(payload.NodeInfo)
    }
    
    // 增量更新
    return sm.controller.applyConfigChanges(payload.Changes)
}

// handleUserUpdate 处理用户更新
func (sm *SyncManager) handleUserUpdate(msg *panel.SyncMessage) error {
    var payload panel.UserUpdatePayload
    if err := json.Unmarshal(msg.Payload, &payload); err != nil {
        return err
    }
    
    switch payload.Action {
    case "add":
        _, err := sm.controller.server.AddUsers(&vCore.AddUsersParams{
            Tag:      sm.controller.tag,
            Users:    payload.Users,
            NodeInfo: sm.controller.info,
        })
        return err
    case "remove":
        return sm.controller.server.DelUsers(payload.Users, sm.controller.tag, sm.controller.info)
    case "update":
        // 先删除再添加
        sm.controller.server.DelUsers(payload.Users, sm.controller.tag, sm.controller.info)
        _, err := sm.controller.server.AddUsers(&vCore.AddUsersParams{
            Tag:      sm.controller.tag,
            Users:    payload.Users,
            NodeInfo: sm.controller.info,
        })
        return err
    }
    
    return nil
}

// handleUserBan 处理用户封禁 (紧急事件，立即执行)
func (sm *SyncManager) handleUserBan(msg *panel.SyncMessage) error {
    var payload panel.UserUpdatePayload
    if err := json.Unmarshal(msg.Payload, &payload); err != nil {
        return err
    }
    
    // 立即删除被封禁用户
    return sm.controller.server.DelUsers(payload.Users, sm.controller.tag, sm.controller.info)
}

// sendAck 发送确认消息
func (sm *SyncManager) sendAck(msgID string, err error) {
    ack := &panel.SyncMessage{
        ID:        uuid.New().String(),
        Type:      panel.MsgTypeAck,
        Timestamp: time.Now().Unix(),
        NodeID:    sm.client.NodeId,
        Payload:   json.RawMessage(fmt.Sprintf(`{"msg_id":"%s","success":%v}`, msgID, err == nil)),
    }
    
    sm.send(ack)
}

// handleDisconnect 处理断开连接
func (sm *SyncManager) handleDisconnect() {
    sm.mu.Lock()
    sm.connected = false
    if sm.conn != nil {
        sm.conn.Close()
        sm.conn = nil
    }
    sm.mu.Unlock()
    
    // 启动重连
    go sm.reconnectLoop()
}

// reconnectLoop 重连循环
func (sm *SyncManager) reconnectLoop() {
    sm.mu.Lock()
    if sm.reconnecting {
        sm.mu.Unlock()
        return
    }
    sm.reconnecting = true
    sm.mu.Unlock()
    
    defer func() {
        sm.mu.Lock()
        sm.reconnecting = false
        sm.mu.Unlock()
    }()
    
    tries := 0
    for {
        select {
        case <-sm.ctx.Done():
            return
        case <-time.After(sm.config.ReconnectInterval):
        }
        
        tries++
        log.WithField("attempt", tries).Info("Attempting to reconnect...")
        
        if err := sm.connect(); err != nil {
            log.WithError(err).Warn("Reconnect failed")
            
            if sm.config.MaxReconnectTries > 0 && tries >= sm.config.MaxReconnectTries {
                log.Error("Max reconnect tries reached, falling back to polling")
                if sm.config.EnableFallback {
                    go sm.runFallbackMode()
                }
                return
            }
            continue
        }
        
        // 重连成功
        go sm.readLoop()
        go sm.writeLoop()
        return
    }
}

// runFallbackMode 降级到轮询模式
func (sm *SyncManager) runFallbackMode() {
    log.Info("Running in fallback polling mode")
    
    ticker := time.NewTicker(sm.config.FallbackInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-sm.ctx.Done():
            return
        case <-ticker.C:
            // 检查是否可以升级到 WebSocket
            if err := sm.connect(); err == nil {
                log.Info("Upgraded to WebSocket mode")
                go sm.readLoop()
                go sm.writeLoop()
                return
            }
            
            // 继续轮询
            sm.controller.nodeInfoMonitor()
        }
    }
}

// Close 关闭同步管理器
func (sm *SyncManager) Close() error {
    sm.cancel()
    
    sm.mu.Lock()
    defer sm.mu.Unlock()
    
    if sm.conn != nil {
        return sm.conn.Close()
    }
    return nil
}
```

### 4.5 API 端点设计 (后端需要实现)

```
后端需要实现以下端点:

1. WebSocket 端点
   GET /api/v2/agent/ws
   Headers:
     - X-API-Key: 节点 API Key
     - X-Node-ID: 节点 ID
     - X-Timestamp, X-Nonce, X-Signature: 签名相关
   - 主端点 `/api/v2/agent/ws`，`SyncConfig.WSEndpointFallbacks` 默认含 `/api/v2/node/ws` 作为备援。

2. SSE 端点 (备选)
   GET /api/v2/node/events
   Headers: 同上
   
3. 消息确认端点
   POST /api/v2/node/ack
   Body: { "msg_id": "xxx", "success": true/false }
```

### 4.6 状态机

```
                    ┌──────────────┐
                    │  Connecting  │◄───────────────────┐
                    └──────┬───────┘                    │
                           │ success                    │ reconnect
                           ▼                            │
┌────────────────┐  ┌──────────────┐   disconnect   ┌───┴──────────┐
│    Fallback    │◄─┤   Connected  ├───────────────►│ Disconnected │
│ (Polling Mode) │  └──────────────┘                └──────────────┘
└────────┬───────┘                                          │
         │ upgrade success                                  │
         └─────────────────────────────────────────────────►│
                                                   (try reconnect)
```

---

## 5. 实现计划

以下阶段记录的是早期 WebSocket 方案。当前 v3 alpha 的实现与交付语义以
`api/grpc/agent/v1/PROTOCOL.md` 为准；尚未迁移的任务源继续按本节兼容方案
运行。

### 5.1 Phase 1: 基础设施 (Week 1)

- [ ] 定义消息类型和协议 (`api/panel/sync.go`)
- [ ] 实现 SyncManager 基础框架 (`node/sync.go`)
- [ ] 实现 WebSocket 连接管理
- [ ] 实现心跳机制

### 5.2 Phase 2: 消息处理 (Week 2)

- [ ] 实现各类消息处理器
- [ ] 实现消息确认机制
- [ ] 实现增量配置更新
- [ ] 集成到 Controller

### 5.3 Phase 3: 容错机制 (Week 3)

- [ ] 实现自动重连
- [ ] 实现降级到轮询模式
- [ ] 实现消息缓存和重试
- [ ] 添加监控指标

### 5.4 Phase 4: 优化与测试 (Week 4)

- [ ] 性能优化
- [ ] 压力测试
- [ ] 兼容性测试
- [ ] 文档完善

### 5.5 配置文件更新

```json
{
  "Nodes": [
    {
      "ApiHost": "https://panel.example.com",
      "NodeID": 1,
      "ApiKey": "xxx",
      
      // 新增同步配置
      "SyncConfig": {
        "EnableWebSocket": true,
        "WSEndpoint": "/api/v2/agent/ws",
        "WSEndpointFallbacks": ["/api/v2/node/ws"],
        "ReconnectInterval": 5,
        "MaxReconnectTries": 0,
        "PingInterval": 30,
        "AckTimeout": 5,
        "AckRetries": 2,
        "BufferSize": 100,
        "EnableFallback": true,
        "FallbackInterval": 60
      }
    }
  ]
}
```

---

## 附录

### A. 消息示例

**配置更新消息**:
```json
{
  "id": "msg-001",
  "type": "config_update",
  "timestamp": 1703577600,
  "node_id": 1,
  "payload": {
    "version": 12345,
    "change_type": "partial",
    "changes": [
      {
        "field": "server_port",
        "old_value": 443,
        "new_value": 8443
      }
    ]
  }
}
```

**用户封禁消息**:
```json
{
  "id": "msg-002",
  "type": "user_ban",
  "timestamp": 1703577600,
  "node_id": 1,
  "payload": {
    "action": "remove",
    "users": [
      {"id": 100, "uuid": "xxx"}
    ]
  }
}
```

### B. 参考资料

- [WebSocket RFC 6455](https://tools.ietf.org/html/rfc6455)
- [Server-Sent Events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)
- [gorilla/websocket](https://github.com/gorilla/websocket)
