# Anix Agent SDK 同步开发设计

日期：2026-07-18
状态：已确认，待实现计划
归属：`anix-agent` 仓库

## 背景与目标

`anix-control` 和 `anix-agent` 是独立发布的 Go 仓库，但当前都维护
`anix.agent.v1` 的 protobuf、生成代码和协议约定。两份源码只能靠人工和 CI
保持一致，且各自的 `go_package` 指向不同的根 module，不能作为稳定的共享依赖。

本设计将 Agent 中可安全复用的协议能力发布为独立 SDK，使两端可以在本地同步
开发，同时让 CI、发布构建和生产制品只消费固定版本的依赖。

首期目标：

- 创建 `github.com/AnixOps/anix-agent/sdk` 嵌套 Go module。
- 将 `anix.agent.v1` protobuf、生成代码、协议说明和无副作用的能力协商辅助 API
  迁入 SDK，并使其成为唯一事实来源。
- 让 Control 与 Agent 根 module 都显式依赖同一个 SDK tag。
- 提供本地 `go.work` 联调、跨仓库验证和 protobuf 兼容性门禁。

本期不迁移插件清单、配置、节点状态模型或 Agent 运行时；它们可在 SDK 协议边界
稳定后作为独立的小版本增量评估。

## 模块边界

依赖方向固定为：

```text
anix-control/v4 ───┐
                    ├──> anix-agent/sdk
anix-agent/v4 ─────┘
```

Control 不得导入 `github.com/AnixOps/anix-agent/v4` 根 module。SDK 也不得导入
Agent 根 module；这避免把内核、文件系统、插件进程、配置或平台相关依赖带入
Control，并消除循环依赖的可能。

SDK 初始布局如下：

```text
sdk/
  go.mod
  README.md
  api/grpc/agent/v1/
    agent.proto
    agent.pb.go
    agent_grpc.pb.go
    PROTOCOL.md
  agentcontrol/
    protocol.go
    capability.go
```

`agent.proto` 的 Go package 固定为：

```text
github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1;agentv1pb
```

`api/grpc/agent/v1` 公开 protobuf 和 gRPC 生成类型。`agentcontrol` 只公开协议名、
capability 名称/版本比较和输入校验等确定性辅助函数；它不建立连接、不访问磁盘、
不读取配置，也不决定 Agent 实际启用哪些能力。

Control 继续拥有鉴权、持久化、调度和业务决策。Agent 继续拥有运行时、节点能力
清单、插件执行和本地错误处理。两个根仓库均可将自己的领域对象映射到 SDK 的 wire
types，但领域模型不进入首期 SDK。

## 本地开发与依赖解析

开发者在两个仓库的共同父目录使用未提交的 `go.work`：

```text
anixops-workspace/
  go.work
  anix-control/
  anix-agent/
    sdk/
```

该 workspace 同时包含 `anix-control`、`anix-agent` 和 `anix-agent/sdk` 三个
module。Go 在本地联调时因此解析 SDK 工作副本，任何协议或辅助 API 改动都会立即
被两端编译和测试发现。

两个根 module 的 `go.mod` 始终保留一个精确、已发布的 SDK 版本。不会提交
`replace` 指令，也不会让任一仓库跟踪 Agent 开发分支或伪版本。常规 CI 以
`GOWORK=off` 运行，保证合并结果和发行制品可由公开 tag 重现。

## 版本与协议兼容性

首个稳定发布为 `sdk/v1.0.0`，而不是不承诺兼容性的 `v0`。嵌套 module 的 Git
tag 使用目录前缀，例如 `sdk/v1.0.0` 和 `sdk/v1.1.0-rc.1`；消费者在
`go.mod` 中使用 module 版本 `v1.0.0` 或预发布版本。

在 SDK v1 内只允许向后兼容的 protobuf 变更：

- 可以新增字段、消息、RPC、enum 值和 capability。
- 不得删除、重编号、重用或改变既有字段的 wire type；废弃字段保留其编号。
- 不得改变既有服务和消息的 wire 含义。

`Hello.protocol` 保持 `anix.agent.v1`。实际操作的可用性仍由 Agent 在 `Hello`
中声明的 capability 名称和版本确定；Control 只向满足最低 capability 版本的会话
调度操作。

破坏性协议变更必须创建 `github.com/AnixOps/anix-agent/sdk/v2` 和
`anix.agent.v2` 命名空间。Control 在迁移期间以独立适配器同时支持旧、新协议，
不得原地改变 `anix.agent.v1` 的行为。

SDK 的校验函数返回可检查的验证错误，不 panic，不隐藏重试。认证、网络、数据库、
运行时错误以及 gRPC status 映射继续由各自的 Control 或 Agent 层处理和记录。

## 配对开发、CI 与发布流程

常规开发以以下顺序进行：

1. SDK PR 添加兼容的协议或辅助 API，并在 SDK CI 通过后发布预发布 tag。
2. Agent 与 Control 的配对 PR 将依赖固定到该预发布 tag；每个根仓库的普通 CI 在
   `GOWORK=off` 下独立通过。
3. 跨仓库 `sdk-sync` 工作流检出指定的 Agent 与 Control 提交，在临时目录生成
   `go.work`，运行两端相关测试和跨仓库 E2E。
4. 配对 PR 与 SDK 变更均通过后，发布稳定 SDK tag；消费者将依赖升级为稳定 tag，
   然后继续独立发布 Agent 和 Control 制品。

`sdk-sync` 由 Control 承载，因为现有跨仓库控制流 E2E 已位于 Control 测试面。
该工作流接收 Agent 与 Control ref，检出它们以及 SDK 所在的 Agent 工作树，不依赖
可变分支版本。涉及 SDK 的配对 PR 必须把该工作流作为合并前检查。

SDK CI 使用与当前仓库一致的固定 `protoc`、`protoc-gen-go` 和
`protoc-gen-go-grpc` 版本，检查生成产物无差异，并运行 SDK 单元测试。它还运行
固定版本的 protobuf breaking-change 检查，将待测 descriptor 与最新稳定 v1 tag
比较；首次 `sdk/v1.0.0` 发布没有历史 v1 基线，只运行完整协议测试，后续 v1
发布均以上一个稳定 v1 tag 为基线。Agent 和 Control 原有的 `api/grpc/gen.sh`
检查只保留各自私有的 v2board 生成任务；Agent 协议的生成和 freshness 检查移动到
SDK。

验证矩阵包括：

- SDK 的序列化、能力比较和无效输入测试。
- SDK 生成代码 freshness 与 v1 protobuf 兼容性测试。
- Agent 与 Control 在 `GOWORK=off` 下的完整或相关回归测试。
- 指定提交的跨仓库控制流 E2E。
- Control 依赖图检查，拒绝出现以
  `github.com/AnixOps/anix-agent/v4` 开头的任何包路径，只允许导入 SDK module。

## 迁移步骤与验收标准

迁移按以下顺序执行，保持每一步可构建、可回滚：

1. 在 Agent 仓库加入与当前协议 wire 内容一致的 SDK module、生成脚本和测试。
2. 发布 `sdk/v1.0.0`，确认外部 `go get` 可解析该嵌套 module。
3. 更新 Agent 与 Control 的 imports 和 `go.mod`，改为使用固定 SDK tag；删除两端
   重复的 `api/grpc/agent/v1` 副本及其生成目标。
4. 更新两仓库 CI、开发文档和 `sdk-sync` 工作流，确保本地 `go.work` 与
   `GOWORK=off` 两种路径都被覆盖。
5. 以当前 `anix.agent.v1` 行为运行跨仓库 E2E，确认迁移不改变 REST、旧 gRPC 或
   WebSocket 回退路径。

完成条件：

- Control 和 Agent 均从同一个已发布 SDK tag 导入 `agentv1pb`。
- SDK 是唯一的 `anix.agent.v1` proto 与生成代码来源。
- Control 的依赖图不包含任何 Agent 根 module 包路径。
- 本地 workspace 修改 SDK 时可同时验证两端；CI 和发布构建在没有 workspace 时
  仍可完全重现。
- 同一 v1 内的破坏性 protobuf 变更会被自动检查拒绝。

## 非目标与后续扩展

本设计不将 Agent 根 module 变成 Control 的库，不改变现有 Agent-first、REST、
旧 gRPC 或 WebSocket 的运行时启用策略，也不改变生产发布必须由 GitHub Actions
构建的规则。

插件清单、签名、配置和状态模型可在首期稳定后逐项纳入 SDK。每一项必须先定义
无副作用的公开边界、兼容性规则和独立测试，不能借由 SDK 引入 Agent 运行时依赖。
