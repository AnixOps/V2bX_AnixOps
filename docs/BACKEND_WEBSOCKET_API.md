# V2bX 后端 WebSocket API 规范

本文档描述了后端 Panel 需要实现的 WebSocket API 接口，以支持与 V2bX 节点的双边实时通讯。

## 1. WebSocket 连接端点

### 1.1 端点信息

```
GET /api/v2/node/ws
协议: WSS (生产环境) / WS (开发环境)
```

### 1.2 认证参数

**Query 参数:**
| 参数 | 类型 | 必须 | 说明 |
|-----|------|-----|------|
| node_id | int | 是 | 节点 ID |

**Headers:**
| Header | 类型 | 必须 | 说明 |
|--------|------|-----|------|
| X-API-Key | string | 是 | 节点 API Key |
| X-Node-ID | string | 是 | 节点 ID |
| X-Timestamp | string | 条件 | 签名时间戳 (EnableSign=true 时必须) |
| X-Nonce | string | 条件 | 随机数 (EnableSign=true 时必须) |
| X-Signature | string | 条件 | 请求签名 (EnableSign=true 时必须) |

### 1.3 签名算法

```
signature = HMAC-SHA256(secret, method + path + timestamp + nonce + body)
```

**示例:**
```
method = "GET"
path = "/api/v2/node/ws"
timestamp = "1703577600"
nonce = "abc123"
body = ""

signature = HMAC-SHA256(secret, "GET/api/v2/node/ws1703577600abc123")
```

### 1.4 连接响应

**成功:**
```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
```

**失败:**
```json
// 401 Unauthorized
{
  "error": "invalid_api_key",
  "message": "API key is invalid or expired"
}

// 403 Forbidden
{
  "error": "signature_invalid",
  "message": "Request signature verification failed"
}

// 404 Not Found
{
  "error": "node_not_found",
  "message": "Node with ID xxx not found"
}
```

---

## 2. 消息格式

所有消息使用 JSON 格式，结构如下:

```json
{
  "id": "string",           // 消息唯一 ID (UUID 或自定义)
  "type": "string",         // 消息类型
  "timestamp": 1703577600,  // Unix 时间戳 (秒)
  "node_id": 1,             // 节点 ID
  "payload": {},            // 消息负载 (根据 type 不同而不同)
  "priority": 0,            // 优先级: 0=普通, 1=高, 2=紧急
  "require_ack": false      // 是否需要确认
}
```

---

## 3. 消息类型

### 3.1 服务端 -> 节点

#### 3.1.1 config_update - 配置更新

当节点配置发生变化时发送。

```json
{
  "id": "msg-001",
  "type": "config_update",
  "timestamp": 1703577600,
  "node_id": 1,
  "priority": 1,
  "require_ack": true,
  "payload": {
    "version": 12345,
    "change_type": "full",  // "full" 或 "partial"
    "node_info": {
      // 完整的节点配置 (change_type=full 时)
      "type": "vmess",
      "server_port": 443,
      // ... 其他字段
    },
    "changes": [
      // 变更列表 (change_type=partial 时)
      {
        "field": "server_port",
        "old_value": 443,
        "new_value": 8443,
        "action": "set"
      }
    ]
  }
}
```

#### 3.1.2 user_update - 用户更新

当用户列表发生变化时发送。

```json
{
  "id": "msg-002",
  "type": "user_update",
  "timestamp": 1703577600,
  "node_id": 1,
  "priority": 0,
  "require_ack": true,
  "payload": {
    "action": "add",  // "add", "remove", "update"
    "users": [
      {
        "id": 100,
        "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "speed_limit": 0,
        "device_limit": 3
      }
    ]
  }
}
```

#### 3.1.3 user_ban - 用户封禁 (紧急)

当用户被封禁时发送，需要立即处理。

```json
{
  "id": "msg-003",
  "type": "user_ban",
  "timestamp": 1703577600,
  "node_id": 1,
  "priority": 2,
  "require_ack": true,
  "payload": {
    "user_ids": [100, 101, 102],
    "uuids": [
      "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
    ],
    "reason": "abuse",
    "expire_at": 0,
    "immediate": true
  }
}
```

#### 3.1.4 rule_update - 规则更新

当审计规则发生变化时发送。

```json
{
  "id": "msg-004",
  "type": "rule_update",
  "timestamp": 1703577600,
  "node_id": 1,
  "priority": 1,
  "require_ack": true,
  "payload": {
    "action": "replace",  // "replace", "append", "remove"
    "rules": {
      "regexp": ["pattern1", "pattern2"],
      "protocol": ["bittorrent"]
    }
  }
}
```

#### 3.1.5 cert_update - 证书更新

当 TLS 证书更新时发送。

```json
{
  "id": "msg-005",
  "type": "cert_update",
  "timestamp": 1703577600,
  "node_id": 1,
  "priority": 1,
  "require_ack": true,
  "payload": {
    "domain": "example.com",
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
    "key_pem": "-----BEGIN PRIVATE KEY-----\n...",
    "expire_at": 1735689600,
    "auto_reload": true
  }
}
```

#### 3.1.6 ping - 心跳检测

定期发送以检测连接状态。

```json
{
  "id": "msg-006",
  "type": "ping",
  "timestamp": 1703577600,
  "node_id": 1,
  "payload": {
    "server_time": 1703577600
  }
}
```

#### 3.1.7 force_reload - 强制重载

强制节点重新加载配置。

```json
{
  "id": "msg-007",
  "type": "force_reload",
  "timestamp": 1703577600,
  "node_id": 1,
  "priority": 2,
  "require_ack": true,
  "payload": {
    "reason": "configuration_sync",
    "clear_cache": false
  }
}
```

### 3.2 节点 -> 服务端

#### 3.2.1 heartbeat - 心跳

节点定期发送心跳。

```json
{
  "id": "msg-100",
  "type": "heartbeat",
  "timestamp": 1703577600,
  "node_id": 1,
  "payload": {
    "cpu_usage": 15.5,
    "memory_usage": 45.2,
    "disk_usage": 30.0,
    "uptime": 86400,
    "online_users": 50,
    "connections": 200,
    "upload": 1073741824,
    "download": 10737418240,
    "version": "1.0.0",
    "config_version": 12345
  }
}
```

#### 3.2.2 pong - Pong 响应

响应 ping 消息。

```json
{
  "id": "msg-101",
  "type": "pong",
  "timestamp": 1703577600,
  "node_id": 1,
  "payload": {
    "server_time": 1703577600,
    "client_time": 1703577601,
    "latency": 50
  }
}
```

#### 3.2.3 ack - 消息确认

确认收到并处理消息。

```json
{
  "id": "msg-102",
  "type": "ack",
  "timestamp": 1703577600,
  "node_id": 1,
  "payload": {
    "msg_id": "msg-001",
    "success": true,
    "error": "",
    "timestamp": 1703577600
  }
}
```

#### 3.2.4 traffic_report - 流量上报

上报用户流量数据。

```json
{
  "id": "msg-103",
  "type": "traffic_report",
  "timestamp": 1703577600,
  "node_id": 1,
  "payload": {
    "period": 60,
    "traffic": [
      {
        "uid": 100,
        "upload": 1048576,
        "download": 10485760
      }
    ],
    "total_up": 104857600,
    "total_down": 1048576000
  }
}
```

#### 3.2.5 alert - 告警上报

上报节点告警。

```json
{
  "id": "msg-104",
  "type": "alert",
  "timestamp": 1703577600,
  "node_id": 1,
  "payload": {
    "level": "warning",
    "type": "high_memory",
    "message": "Memory usage exceeded 90%",
    "details": {
      "memory_usage": "92%",
      "threshold": "90%"
    },
    "timestamp": 1703577600
  }
}
```

---

## 4. 处理流程

### 4.1 连接建立

```
Client                              Server
   |                                   |
   |------- WebSocket Upgrade -------->|
   |                                   | (验证 API Key, 签名)
   |<-------- 101 Switching ---------- |
   |                                   |
   |<-------- ping ----------------- |
   |------- pong ------------------->|
   |                                   |
   |<-------- config_update ---------|  (发送当前配置)
   |------- ack -------------------->|
   |                                   |
```

### 4.2 配置变更

```
管理员操作                     Server                    Client
    |                            |                          |
    |--- 修改节点配置 ---------->|                          |
    |                            |--- config_update ------->|
    |                            |                          | (应用配置)
    |                            |<-------- ack ------------|
    |<-- 操作成功 --------------|                          |
```

### 4.3 用户封禁

```
管理员操作                     Server                    Client
    |                            |                          |
    |--- 封禁用户 ------------->|                          |
    |                            |--- user_ban (urgent) --->|
    |                            |                          | (立即断开用户)
    |                            |<-------- ack ------------|
    |<-- 操作成功 --------------|                          |
```

### 4.4 断线重连

```
Client                              Server
   |                                   |
   |<------- (connection lost) --------|
   |                                   |
   | (等待 ReconnectInterval)          |
   |                                   |
   |------- WebSocket Upgrade -------->|
   |<-------- 101 Switching ---------- |
   |                                   |
   |<-------- config_update ---------|  (同步最新配置)
   |------- ack -------------------->|
   |                                   |
```

---

## 5. 错误处理

### 5.1 连接级错误

| 错误码 | 说明 | 客户端处理 |
|-------|------|-----------|
| 1000 | 正常关闭 | 不重连 |
| 1001 | Going Away | 延迟重连 |
| 1006 | 异常关闭 | 立即重连 |
| 1008 | Policy Violation | 检查认证 |
| 1011 | Internal Error | 延迟重连 |

### 5.2 消息级错误

在 ack 消息中返回错误信息:

```json
{
  "type": "ack",
  "payload": {
    "msg_id": "msg-001",
    "success": false,
    "error": "invalid_payload: missing required field 'users'"
  }
}
```

---

## 6. 最佳实践

### 6.1 消息优先级

- **紧急 (priority=2)**: user_ban, force_reload
  - 立即处理，绕过队列
- **高 (priority=1)**: config_update, rule_update, cert_update
  - 优先处理
- **普通 (priority=0)**: user_update, heartbeat
  - 按顺序处理

### 6.2 消息确认

- 需要确认的消息 (`require_ack=true`) 应在处理完成后发送 ack
- 建议设置 5 秒超时，超时后服务端可重发
- 节点应记录已处理的消息 ID，避免重复处理

### 6.3 心跳策略

- 服务端每 30 秒发送 ping
- 节点收到后立即回复 pong
- 节点也应每 30 秒发送 heartbeat
- 超过 60 秒无消息则认为连接断开

### 6.4 批量操作

对于大量用户更新，建议:
- 分批发送，每批不超过 100 个用户
- 使用增量更新而非全量替换
- 设置合理的发送间隔 (100ms)

---

## 7. 示例实现 (PHP Laravel)

```php
// routes/channels.php
Broadcast::channel('node.{nodeId}', function ($user, $nodeId) {
    return $user->isAdmin() || $user->node_id === (int) $nodeId;
});

// app/Events/NodeConfigUpdated.php
class NodeConfigUpdated implements ShouldBroadcast
{
    public function __construct(
        public int $nodeId,
        public array $config
    ) {}

    public function broadcastOn(): Channel
    {
        return new PrivateChannel("node.{$this->nodeId}");
    }

    public function broadcastAs(): string
    {
        return 'config_update';
    }

    public function broadcastWith(): array
    {
        return [
            'id' => Str::uuid(),
            'type' => 'config_update',
            'timestamp' => now()->timestamp,
            'node_id' => $this->nodeId,
            'priority' => 1,
            'require_ack' => true,
            'payload' => [
                'version' => $this->config['version'],
                'change_type' => 'full',
                'node_info' => $this->config['info'],
            ],
        ];
    }
}

// 使用
event(new NodeConfigUpdated($node->id, $config));
```

---

## 8. 版本历史

| 版本 | 日期 | 说明 |
|-----|------|-----|
| 1.0.0 | 2024-12-26 | 初始版本 |
