package client

import "github.com/InazumaV/V2bX/api/panel"

// NodeAPI defines the contract required by node controllers regardless of transport.
// Implementations can be REST (api/panel) or gRPC (api/grpc).
type NodeAPI interface {
	GetNodeInfo() (*panel.NodeInfo, error)
	GetUserList() ([]panel.UserInfo, error)
	GetUserAlive() (map[int]int, error)
	ReportUserTraffic([]panel.UserTraffic) error
	ReportNodeOnlineUsers(*map[int][]string) error

	GetNodeID() int
	GetAPIHost() string
	GetAPIKey() string
	GetSecret() string
	IsSignEnabled() bool
	SetNodeType(string)
	SupportsSync() bool
	Close() error
}
