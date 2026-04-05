# V2bX AnixOps

V2bX AnixOps 是 AnixOps 维护的 V2Board 节点端后端程序（Fork 自 [wyx2685/V2bX](https://github.com/wyx2685/V2bX)）。

- 节点端仓库: [AnixOps/V2bX_AnixOps](https://github.com/AnixOps/V2bX_AnixOps)
- 面板端仓库: [AnixOps/v2board_AnixOps](https://github.com/AnixOps/v2board_AnixOps)
- 上游仓库: [wyx2685/V2bX](https://github.com/wyx2685/V2bX)

## 项目概述

本项目用于对接 V2Board 面板，支持节点配置同步、用户认证、流量统计、在线设备上报、证书管理等能力。

支持多内核：
- Xray-core
- Sing-box
- Hysteria2

## 主要特性

- 多内核统一管理（Xray / Sing-box / Hysteria2）
- 支持多协议（VMess / VLESS / Trojan / Shadowsocks / Hysteria2 等）
- 用户流量与在线 IP 统计上报
- 节点限流、设备数限制、动态限速
- 自动注册、签名鉴权、凭证加密存储
- ACME 证书管理与续期
- 支持 Linux / Windows / macOS

## 目录结构

```text
V2bX_AnixOps/
├── api/                # 面板 API 客户端
├── cmd/                # CLI 入口与子命令
├── conf/               # 配置结构体定义
├── core/               # 各内核实现（xray/sing/hy2）
├── node/               # 节点控制器与定时任务
├── limiter/            # 限流实现
├── common/             # 通用工具
├── docs/               # 项目文档
└── example/            # 配置示例
```

## 环境要求

- Go 1.25+
- 构建时需设置 `GOEXPERIMENT=jsonv2`

## 一键安装（Linux）

快速安装最新版：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/AnixOps/V2bX_AnixOps/dev_new/scripts/install.sh)
```

安装指定版本：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/AnixOps/V2bX_AnixOps/dev_new/scripts/install.sh) v0.1.0
```

安装后管理命令：

```bash
V2bX start|stop|restart|status|log
V2bX update [version]
V2bX uninstall [--purge]
```

## 快速开始

### 1. 准备配置

参考示例配置：`example/config.json`

### 2. 构建

Linux/macOS:

```bash
export GOEXPERIMENT=jsonv2
export CGO_ENABLED=0
go build -v -o V2bX -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor" -trimpath
```

Windows (PowerShell):

```powershell
$env:GOEXPERIMENT="jsonv2"
$env:CGO_ENABLED="0"
go build -v -o V2bX.exe -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor" -trimpath
```

或直接使用仓库脚本：
- Linux/macOS: `./build.sh`
- Windows: `./build.ps1`

### 3. 运行

```bash
V2bX server -c /etc/V2bX/config.json
```

Windows:

```powershell
.\V2bX.exe server -c .\config.json
```

## 与面板对接

默认对接 API（示例）：
- `GET /api/v2/server/UniProxy/config`
- `GET /api/v2/server/UniProxy/user`
- `GET /api/v2/server/UniProxy/alivelist`
- `POST /api/v2/server/UniProxy/push`
- `POST /api/v2/server/UniProxy/alive`

UniProxy 鉴权约定：
- Query: `node_id`（必填）+ `node_type`（可选）
- Header: `X-API-Key: <api_key>`（必填）

请确保面板端版本与本仓库对应，优先使用：
[AnixOps/v2board_AnixOps](https://github.com/AnixOps/v2board_AnixOps)

## 文档

- [API 文档](./docs/API_DOCUMENTATION.md)
- [后端 API 问题分析](./docs/BACKEND_API_ISSUES.md)
- `docs/PROTOCOL_CONFIG_*.md` 协议配置规范

## 贡献

欢迎通过 Issue / PR 提交问题与改进建议。

## 致谢

- [Project X](https://github.com/XTLS/)
- [V2Fly](https://github.com/v2fly)
- [XrayR](https://github.com/XrayR/XrayR)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
