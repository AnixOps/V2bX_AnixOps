# 后端 API 响应问题分析报告

本文档分析当前后端 API 响应与规范的差异，帮助后端开发者进行修复。

## 📅 分析时间
2024-12-27

## 📊 调试数据来源
文件: `test_data/api_debug/20251227_000936/node_1/000936.159_node_config.json`

---

## 当前后端响应

```json
{
  "base_config": {
    "pull_interval": 60,
    "push_interval": 60
  },
  "host": "127.0.0.1",
  "network": "tcp",
  "node_type": "vless",
  "routes": [],
  "send_through": "0.0.0.0",
  "server_name": "127.0.0.1",
  "server_port": 19999,
  "tls": 0
}
```

---

## 问题清单

### ❌ 问题 1: 字段名不一致

| 后端返回 | 规范要求 | 说明 |
|----------|----------|------|
| `node_type` | `type` | V2bX 同时支持两者，但推荐使用 `type` |

**修复建议**: 返回 `type` 字段，或同时返回两者。

### ❌ 问题 2: 缺少 VLESS 必需字段

当 `type=vless` 时，根据 XTLS 规范，需要以下字段：

| 缺失字段 | 说明 | 默认行为 |
|----------|------|----------|
| `flow` | 流控模式 | V2bX 默认为空字符串 |
| `encryption` | 加密设置 | V2bX 默认为 `"none"` |
| `encryption_settings` | 加密配置 | 可选 |
| `network_settings` | 传输层配置 | 可选 |

**修复建议**:
```json
{
  "type": "vless",
  "flow": "",
  "encryption": "",
  "encryption_settings": {},
  "network_settings": {}
}
```

### ❌ 问题 3: TLS 配置缺失

当前 `tls: 0` 表示不加密。如果节点需要安全连接：

#### 当 `tls: 1` (普通 TLS) 时
不需要额外配置，V2bX 使用本地证书。

#### 当 `tls: 2` (Reality) 时
**必须** 提供 `tls_settings`:

```json
{
  "tls": 2,
  "tls_settings": {
    "server_name": "www.microsoft.com",
    "dest": "www.microsoft.com",
    "server_port": "443",
    "short_id": "abcd1234",
    "private_key": "your-x25519-private-key"
  }
}
```

### ⚠️ 问题 4: 多余字段

| 字段 | 说明 |
|------|------|
| `send_through` | V2bX 未使用此字段 |

这不会导致错误，但可以考虑移除。

---

## 完整修复后的响应示例

### 场景 1: VLESS + 无加密 (测试用)

```json
{
  "type": "vless",
  "host": "127.0.0.1",
  "server_port": 19999,
  "server_name": "127.0.0.1",
  
  "tls": 0,
  
  "network": "tcp",
  "network_settings": {},
  
  "flow": "",
  "encryption": "",
  "encryption_settings": {},
  
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

### 场景 2: VLESS + Reality + XTLS Vision (推荐生产环境)

```json
{
  "type": "vless",
  "host": "your-server.com",
  "server_port": 443,
  "server_name": "www.microsoft.com",
  
  "tls": 2,
  "tls_settings": {
    "server_name": "www.microsoft.com",
    "dest": "www.microsoft.com",
    "server_port": "443",
    "short_id": "6ba85179e30d4fc2",
    "private_key": "your-x25519-private-key-here",
    "mldsa65Seed": "",
    "xver": 0
  },
  
  "network": "tcp",
  "network_settings": {},
  
  "flow": "xtls-rprx-vision",
  "encryption": "",
  "encryption_settings": {},
  
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

### 场景 3: VLESS + TLS + WebSocket

```json
{
  "type": "vless",
  "host": "your-server.com",
  "server_port": 443,
  "server_name": "your-server.com",
  
  "tls": 1,
  "tls_settings": {
    "server_name": "your-server.com"
  },
  
  "network": "ws",
  "network_settings": {
    "path": "/vless-ws",
    "headers": {
      "Host": "your-server.com"
    }
  },
  
  "flow": "",
  "encryption": "",
  "encryption_settings": {},
  
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

---

## 各协议类型模板

### VMess

```json
{
  "type": "vmess",
  "host": "server.example.com",
  "server_port": 443,
  "server_name": "server.example.com",
  
  "tls": 1,
  
  "network": "ws",
  "network_settings": {
    "path": "/vmess-ws",
    "headers": {
      "Host": "server.example.com"
    }
  },
  
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

### Trojan

```json
{
  "type": "trojan",
  "host": "server.example.com",
  "server_port": 443,
  "server_name": "server.example.com",
  
  "network": "tcp",
  "networkSettings": {},
  
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

### Shadowsocks

```json
{
  "type": "shadowsocks",
  "host": "server.example.com",
  "server_port": 8388,
  
  "cipher": "2022-blake3-aes-256-gcm",
  "server_key": "base64-encoded-32-byte-key-here",
  
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

---

## 用户接口检查

当前用户列表响应:
```json
{
  "users": []
}
```

**状态**: ✅ 格式正确，但用户列表为空。

预期用户格式:
```json
{
  "users": [
    {
      "id": 1,
      "uuid": "550e8400-e29b-41d4-a716-446655440000",
      "speed_limit": 0,
      "device_limit": 3
    }
  ]
}
```

---

## 优先级修复建议

### 高优先级 (影响功能)

1. **添加 `type` 字段** (替代或补充 `node_type`)
2. **当 `tls=2` 时提供完整的 `tls_settings`**
3. **确保用户接口返回正确的用户数据**

### 中优先级 (推荐改进)

4. **添加 `flow` 字段** (VLESS 推荐)
5. **添加 `network_settings` 字段**
6. **为 Shadowsocks 提供 `cipher` 和 `server_key`**

### 低优先级 (可选)

7. 移除未使用的字段如 `send_through`
8. 添加详细的错误处理

---

## 快速验证

修改后端后，可以使用以下命令验证:

```bash
# 设置环境变量
set GOEXPERIMENT=jsonv2

# 运行 V2bX (Windows)
.\V2bX_windows_amd64.exe --config config.json

# 或者只运行一次获取配置
.\V2bX_windows_amd64.exe --config config.json server --get-node-info
```

调试输出将保存在 `test_data/api_debug/` 目录下。

---

## 参考文档

- [完整协议配置规范](./PROTOCOL_CONFIG_SPECIFICATION.md)
- [XTLS 官方文档](https://xtls.github.io/config/)
