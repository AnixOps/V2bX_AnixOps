# V2bX 面板后端 API 接口文档

## 概述

本文档基于 V2bX 节点端代码分析，提取出面板后端需要实现的 API 接口。V2bX 是一个支持多协议的代理节点管理客户端，支持 VMess、VLESS、Trojan、Shadowsocks、Hysteria、Hysteria2、TUIC、AnyTLS 等协议。

## 基础信息

### 请求基础配置

所有 API 请求都需要携带以下 **Query 参数**：

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| `node_type` | string | 是 | 节点类型：`vmess`, `vless`, `trojan`, `shadowsocks`, `hysteria`, `hysteria2`, `tuic`, `anytls` |
| `node_id` | int | 是 | 节点ID |
| `token` | string | 是 | API 鉴权令牌 |

### 响应通用规范

- 成功状态码: `200`
- 无变更状态码: `304` (用于 ETag 缓存机制)
- 错误状态码: `>=400`
- 支持 `ETag` 缓存机制
- 支持 `msgpack` 响应格式 (通过 `X-Response-Format: msgpack` 请求头)

---

## API 接口列表

### 1. 获取节点配置

获取当前节点的配置信息。

**请求**
```
GET /api/v1/server/UniProxy/config
```

**请求头**
| 头名称 | 说明 |
|--------|------|
| `If-None-Match` | ETag 值，用于缓存判断 |

**响应**

响应内容根据 `node_type` 不同而有所差异：

#### 公共字段 (CommonNode)

```json
{
  "host": "example.com",
  "server_port": 443,
  "server_name": "example.com",
  "routes": [
    {
      "id": 1,
      "match": "regexp:.*\\.cn$",
      "action": "block",
      "action_value": ""
    },
    {
      "id": 2,
      "match": "main,{\"servers\":[{\"address\":\"8.8.8.8\"}]}",
      "action": "dns",
      "action_value": "8.8.8.8"
    }
  ],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

#### VMess/VLESS 节点 (node_type: vmess/vless)

```json
{
  "host": "example.com",
  "server_port": 443,
  "server_name": "example.com",
  "tls": 0,
  "tls_settings": {
    "server_name": "example.com",
    "dest": "example.com:443",
    "server_port": "443",
    "short_id": "abc123",
    "private_key": "private_key_here",
    "mldsa65Seed": "",
    "xver": "0"
  },
  "network": "tcp",
  "network_settings": {},
  "encryption": "",
  "encryption_settings": {
    "mode": "",
    "ticket": "",
    "server_padding": "",
    "private_key": ""
  },
  "flow": "xtls-rprx-vision",
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

**tls 字段说明：**
- `0` = None (无加密)
- `1` = TLS
- `2` = Reality

**network 字段可选值：**
- `tcp`
- `ws` (WebSocket)
- `grpc`
- `http`
- `quic`

**network_settings 示例 (WebSocket):**
```json
{
  "path": "/ws",
  "headers": {
    "Host": "example.com"
  }
}
```

**network_settings 示例 (gRPC):**
```json
{
  "serviceName": "grpc_service"
}
```

#### Shadowsocks 节点 (node_type: shadowsocks)

```json
{
  "host": "example.com",
  "server_port": 443,
  "server_name": "example.com",
  "cipher": "2022-blake3-aes-128-gcm",
  "server_key": "base64_encoded_key",
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

**cipher 可选值：**
- `aes-128-gcm`
- `aes-256-gcm`
- `chacha20-ietf-poly1305`
- `2022-blake3-aes-128-gcm`
- `2022-blake3-aes-256-gcm`
- `2022-blake3-chacha20-poly1305`

#### Trojan 节点 (node_type: trojan)

```json
{
  "host": "example.com",
  "server_port": 443,
  "server_name": "example.com",
  "network": "tcp",
  "networkSettings": {},
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

#### TUIC 节点 (node_type: tuic)

```json
{
  "host": "example.com",
  "server_port": 443,
  "server_name": "example.com",
  "congestion_control": "bbr",
  "zero_rtt_handshake": true,
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

**congestion_control 可选值：**
- `bbr`
- `cubic`
- `new_reno`

#### AnyTLS 节点 (node_type: anytls)

```json
{
  "host": "example.com",
  "server_port": 443,
  "server_name": "example.com",
  "padding_scheme": ["random"],
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

#### Hysteria 节点 (node_type: hysteria)

```json
{
  "host": "example.com",
  "server_port": 443,
  "server_name": "example.com",
  "up_mbps": 100,
  "down_mbps": 100,
  "obfs": "xplus",
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

#### Hysteria2 节点 (node_type: hysteria2)

```json
{
  "host": "example.com",
  "server_port": 443,
  "server_name": "example.com",
  "ignore_client_bandwidth": false,
  "up_mbps": 100,
  "down_mbps": 100,
  "obfs": "salamander",
  "obfs-password": "password_here",
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

---

### 2. 获取用户列表

获取当前节点的用户列表。

**请求**
```
GET /api/v1/server/UniProxy/user
```

**请求头**
| 头名称 | 说明 |
|--------|------|
| `If-None-Match` | ETag 值，用于缓存判断 |
| `X-Response-Format` | 响应格式，可选 `msgpack` |

**响应 (JSON)**
```json
{
  "users": [
    {
      "id": 1,
      "uuid": "550e8400-e29b-41d4-a716-446655440000",
      "speed_limit": 0,
      "device_limit": 3
    },
    {
      "id": 2,
      "uuid": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "speed_limit": 10485760,
      "device_limit": 5
    }
  ]
}
```

**响应 (msgpack)**

当请求头包含 `X-Response-Format: msgpack` 时，响应 `Content-Type` 为 `application/x-msgpack`，数据结构相同但采用 msgpack 编码。

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | int | 用户ID |
| `uuid` | string | 用户UUID，用于协议认证 |
| `speed_limit` | int | 速度限制 (bytes/s)，0表示不限制 |
| `device_limit` | int | 设备数限制，0表示不限制 |

---

### 3. 获取用户在线状态

获取用户的在线 IP 数量（用于设备限制判断）。

**请求**
```
GET /api/v1/server/UniProxy/alivelist
```

**响应**
```json
{
  "alive": {
    "1": 2,
    "2": 1,
    "10": 0
  }
}
```

**字段说明**

`alive` 是一个 map，key 为用户 ID (字符串)，value 为该用户当前在线 IP 数量。

---

### 4. 上报用户流量

节点定期向面板上报用户流量消耗。

**请求**
```
POST /api/v1/server/UniProxy/push
```

**请求体**
```json
{
  "1": [1024000, 2048000],
  "2": [512000, 1024000]
}
```

**格式说明**

```
{
  "<user_id>": [<upload_bytes>, <download_bytes>],
  ...
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| key | string | 用户ID |
| value[0] | int64 | 上传流量 (bytes) |
| value[1] | int64 | 下载流量 (bytes) |

**响应**
```json
{
  "status": "success"
}
```

---

### 5. 上报用户在线状态

节点定期向面板上报当前在线用户及其 IP 列表。

**请求**
```
POST /api/v1/server/UniProxy/alive
```

**请求体**
```json
{
  "1": ["192.168.1.100", "10.0.0.50"],
  "2": ["172.16.0.1"]
}
```

**格式说明**

```
{
  "<user_id>": ["<ip1>", "<ip2>", ...],
  ...
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| key | string | 用户ID |
| value | string[] | 该用户当前在线的 IP 列表 |

**响应**
```json
{
  "status": "success"
}
```

---

## Routes 路由规则说明

节点配置中的 `routes` 字段用于定义路由规则，支持两种 action：

### 1. block - 阻止规则

用于阻止特定协议或域名。

```json
{
  "id": 1,
  "match": "regexp:.*\\.cn$,protocol:bittorrent",
  "action": "block",
  "action_value": ""
}
```

**match 格式：**
- `regexp:<正则表达式>` - 匹配域名的正则
- `protocol:<协议名>` - 匹配特定协议 (如 bittorrent)

### 2. dns - DNS 规则

用于指定特定域名的 DNS 服务器。

```json
{
  "id": 2,
  "match": ["google.com", "youtube.com"],
  "action": "dns",
  "action_value": "8.8.8.8"
}
```

**特殊情况 - 主 DNS 配置：**

当 match 的第一个元素为 `main` 时，后续内容为完整的 DNS 配置 JSON：

```json
{
  "id": 3,
  "match": "main,{\"servers\":[{\"address\":\"8.8.8.8\",\"port\":53}]}",
  "action": "dns",
  "action_value": ""
}
```

---

## 数据库模型参考

基于 API 接口，后端需要以下核心数据模型：

### Node (节点)

```sql
CREATE TABLE nodes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255),
    type ENUM('vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria', 'hysteria2', 'tuic', 'anytls'),
    host VARCHAR(255),
    server_port INT,
    server_name VARCHAR(255),
    config JSON,  -- 存储协议特定配置
    routes JSON,  -- 存储路由规则
    push_interval INT DEFAULT 60,
    pull_interval INT DEFAULT 60,
    api_token VARCHAR(255),
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### User (用户)

```sql
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    uuid VARCHAR(36) UNIQUE,
    email VARCHAR(255),
    speed_limit BIGINT DEFAULT 0,
    device_limit INT DEFAULT 0,
    traffic_used BIGINT DEFAULT 0,
    traffic_limit BIGINT DEFAULT 0,
    expired_at TIMESTAMP,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### UserNodeAccess (用户节点访问权限)

```sql
CREATE TABLE user_node_access (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    node_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (node_id) REFERENCES nodes(id)
);
```

### TrafficLog (流量日志)

```sql
CREATE TABLE traffic_logs (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    node_id INT,
    upload BIGINT,
    download BIGINT,
    created_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (node_id) REFERENCES nodes(id)
);
```

### OnlineLog (在线日志)

```sql
CREATE TABLE online_logs (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    node_id INT,
    ip VARCHAR(45),
    created_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (node_id) REFERENCES nodes(id)
);
```

---

## 完整 API 实现示例 (伪代码)

### 获取节点配置

```python
@app.get("/api/v1/server/UniProxy/config")
def get_config(node_type: str, node_id: int, token: str, if_none_match: str = None):
    # 1. 验证 token
    node = verify_node_token(node_id, token)
    if not node:
        return Response(status=401)
    
    # 2. 检查 ETag
    current_etag = generate_etag(node)
    if if_none_match == current_etag:
        return Response(status=304)
    
    # 3. 根据节点类型构建响应
    config = build_node_config(node, node_type)
    
    return Response(
        body=config,
        headers={"ETag": current_etag}
    )
```

### 获取用户列表

```python
@app.get("/api/v1/server/UniProxy/user")
def get_users(node_type: str, node_id: int, token: str, 
              if_none_match: str = None, x_response_format: str = None):
    # 1. 验证 token
    node = verify_node_token(node_id, token)
    if not node:
        return Response(status=401)
    
    # 2. 获取有权访问该节点的用户
    users = get_node_users(node_id)
    
    # 3. 检查 ETag
    current_etag = generate_etag(users)
    if if_none_match == current_etag:
        return Response(status=304)
    
    # 4. 构建响应
    response_data = {
        "users": [
            {
                "id": u.id,
                "uuid": u.uuid,
                "speed_limit": u.speed_limit,
                "device_limit": u.device_limit
            }
            for u in users
        ]
    }
    
    # 5. 根据请求格式返回
    if x_response_format == "msgpack":
        return Response(
            body=msgpack.encode(response_data),
            content_type="application/x-msgpack",
            headers={"ETag": current_etag}
        )
    
    return Response(
        body=json.dumps(response_data),
        headers={"ETag": current_etag}
    )
```

### 上报流量

```python
@app.post("/api/v1/server/UniProxy/push")
def push_traffic(node_type: str, node_id: int, token: str, body: dict):
    # 1. 验证 token
    node = verify_node_token(node_id, token)
    if not node:
        return Response(status=401)
    
    # 2. 处理流量数据
    for user_id, traffic in body.items():
        upload, download = traffic[0], traffic[1]
        
        # 记录流量日志
        save_traffic_log(user_id, node_id, upload, download)
        
        # 更新用户已用流量
        update_user_traffic(user_id, upload + download)
    
    return {"status": "success"}
```

### 上报在线状态

```python
@app.post("/api/v1/server/UniProxy/alive")
def push_alive(node_type: str, node_id: int, token: str, body: dict):
    # 1. 验证 token
    node = verify_node_token(node_id, token)
    if not node:
        return Response(status=401)
    
    # 2. 更新在线状态
    for user_id, ips in body.items():
        # 清除该节点该用户的旧在线记录
        clear_online_logs(user_id, node_id)
        
        # 记录新的在线 IP
        for ip in ips:
            save_online_log(user_id, node_id, ip)
    
    return {"status": "success"}
```

### 获取在线 IP 数量

```python
@app.get("/api/v1/server/UniProxy/alivelist")
def get_alive_list(node_type: str, node_id: int, token: str):
    # 1. 验证 token
    node = verify_node_token(node_id, token)
    if not node:
        return Response(status=401)
    
    # 2. 获取所有用户的在线 IP 数量（跨所有节点）
    alive_map = get_all_users_online_count()
    
    return {"alive": alive_map}
```

---

## 节点客户端配置示例

节点端 (V2bX) 的配置文件示例：

```json
{
  "Log": {
    "Level": "info",
    "Output": ""
  },
  "Cores": [
    {
      "Type": "sing",
      "Log": {
        "Level": "info"
      }
    }
  ],
  "Nodes": [
    {
      "Core": "sing",
      "ApiHost": "https://your-panel.com",
      "ApiKey": "your-api-token",
      "NodeID": 1,
      "NodeType": "vmess",
      "Timeout": 30,
      "ListenIP": "0.0.0.0",
      "SendIP": "0.0.0.0",
      "DeviceOnlineMinTraffic": 200
    }
  ]
}
```

---

## 注意事项

1. **ETag 缓存**: 建议实现 ETag 机制，减少不必要的数据传输
2. **msgpack 支持**: 用户列表接口支持 msgpack 格式，可显著减少带宽消耗
3. **定时任务**: 
   - `push_interval`: 流量上报间隔 (秒)
   - `pull_interval`: 配置/用户拉取间隔 (秒)
4. **设备限制**: 需要维护全局在线 IP 状态，跨节点计算
5. **流量统计**: 建议使用异步队列处理，避免阻塞节点上报

---

## 协议支持矩阵

| 协议 | TLS | Reality | WebSocket | gRPC | HTTP/2 | QUIC |
|------|-----|---------|-----------|------|--------|------|
| VMess | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| VLESS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Trojan | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| Shadowsocks | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Hysteria | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Hysteria2 | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| TUIC | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| AnyTLS | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
