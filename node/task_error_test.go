package node

import (
	"context"
	"errors"
	"testing"

	apiclient "github.com/AnixOps/anix-agent/v4/api/client"
	agentv1pb "github.com/AnixOps/anix-agent/v4/api/grpc/agent/v1"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/common/monitor"
	"github.com/AnixOps/anix-agent/v4/conf"
	vCore "github.com/AnixOps/anix-agent/v4/core"
)

var _ apiclient.NodeAPI = (*errorTestNodeAPI)(nil)
var _ vCore.Core = (*errorTestCore)(nil)

type errorTestNodeAPI struct {
	node     *panel.NodeInfo
	users    []panel.UserInfo
	alive    map[int]int
	nodeErr  error
	usersErr error
	aliveErr error
	nodeType string
}

func (f *errorTestNodeAPI) GetNodeInfo() (*panel.NodeInfo, error)         { return f.node, f.nodeErr }
func (f *errorTestNodeAPI) GetUserList() ([]panel.UserInfo, error)        { return f.users, f.usersErr }
func (f *errorTestNodeAPI) GetUserAlive() (map[int]int, error)            { return f.alive, f.aliveErr }
func (f *errorTestNodeAPI) ReportUserTraffic([]panel.UserTraffic) error   { return nil }
func (f *errorTestNodeAPI) ReportNodeOnlineUsers(*map[int][]string) error { return nil }
func (f *errorTestNodeAPI) ReportNodeStatus(*monitor.SystemInfo, int, int64, int64) error {
	return nil
}
func (f *errorTestNodeAPI) ReportNodeLogs([]panel.NodeLogEntry) error { return nil }
func (f *errorTestNodeAPI) GetNodeID() int                            { return 1 }
func (f *errorTestNodeAPI) GetAPIHost() string                        { return "http://127.0.0.1" }
func (f *errorTestNodeAPI) GetAPIKey() string                         { return "test-key" }
func (f *errorTestNodeAPI) GetSecret() string                         { return "" }
func (f *errorTestNodeAPI) IsSignEnabled() bool                       { return false }
func (f *errorTestNodeAPI) SetNodeType(nodeType string)               { f.nodeType = nodeType }
func (f *errorTestNodeAPI) SupportsSync() bool                        { return false }
func (f *errorTestNodeAPI) Close() error                              { return nil }

type errorTestCore struct {
	delNodeErr  error
	delUsersErr error
}

func (f *errorTestCore) Start() error                                         { return nil }
func (f *errorTestCore) Close() error                                         { return nil }
func (f *errorTestCore) AddNode(string, *panel.NodeInfo, *conf.Options) error { return nil }
func (f *errorTestCore) DelNode(string) error                                 { return f.delNodeErr }
func (f *errorTestCore) AddUsers(*vCore.AddUsersParams) (int, error)          { return 0, nil }
func (f *errorTestCore) GetUserTrafficSlice(string, bool) ([]panel.UserTraffic, error) {
	return nil, nil
}
func (f *errorTestCore) DelUsers([]panel.UserInfo, string, *panel.NodeInfo) error {
	return f.delUsersErr
}
func (f *errorTestCore) Protocols() []string { return nil }
func (f *errorTestCore) Type() string        { return "test" }

func TestNodeInfoMonitorReturnsFetchErrors(t *testing.T) {
	nodeErr := errors.New("node fetch failed")
	usersErr := errors.New("users fetch failed")
	aliveErr := errors.New("alive fetch failed")

	tests := []struct {
		name string
		api  *errorTestNodeAPI
		want error
	}{
		{name: "node info", api: &errorTestNodeAPI{nodeErr: nodeErr}, want: nodeErr},
		{name: "user list", api: &errorTestNodeAPI{usersErr: usersErr}, want: usersErr},
		{name: "alive list", api: &errorTestNodeAPI{aliveErr: aliveErr}, want: aliveErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := &Controller{
				apiClient: tt.api,
				server:    &errorTestCore{},
				Options:   &conf.Options{},
			}
			if err := controller.nodeInfoMonitor(); !errors.Is(err, tt.want) {
				t.Fatalf("nodeInfoMonitor() error = %v, want wrapping %v", err, tt.want)
			}
		})
	}
}

func TestNodeInfoMonitorReturnsDeleteErrorWithoutPanic(t *testing.T) {
	delErr := errors.New("delete failed")
	controller := &Controller{
		apiClient: &errorTestNodeAPI{
			node:  &panel.NodeInfo{Id: 1, Type: "vless"},
			alive: map[int]int{},
		},
		server:  &errorTestCore{delNodeErr: delErr},
		tag:     "test-node",
		Options: &conf.Options{},
	}

	if err := controller.nodeInfoMonitor(); !errors.Is(err, delErr) {
		t.Fatalf("nodeInfoMonitor() error = %v, want wrapping %v", err, delErr)
	}
}

func TestNodeInfoMonitorReturnsDeleteUsersError(t *testing.T) {
	delErr := errors.New("delete users failed")
	controller := &Controller{
		apiClient: &errorTestNodeAPI{
			users: []panel.UserInfo{},
		},
		server:   &errorTestCore{delUsersErr: delErr},
		tag:      "test-node",
		info:     &panel.NodeInfo{Id: 1, Type: "vless"},
		userList: []panel.UserInfo{{Id: 7, Uuid: "removed-user"}},
		Options:  &conf.Options{},
	}

	if err := controller.nodeInfoMonitor(); !errors.Is(err, delErr) {
		t.Fatalf("nodeInfoMonitor() error = %v, want wrapping %v", err, delErr)
	}
}

func TestAgentReloadOperationReportsReconcileFailure(t *testing.T) {
	fetchErr := errors.New("control reload fetch failed")
	controller := &Controller{
		apiClient: &errorTestNodeAPI{nodeErr: fetchErr},
		server:    &errorTestCore{},
		Options:   &conf.Options{},
	}

	_, err := controller.handleAgentOperation(context.Background(), &agentv1pb.DesiredOperation{
		Kind: "node.reload",
	})
	if !errors.Is(err, fetchErr) {
		t.Fatalf("handleAgentOperation() error = %v, want wrapping %v", err, fetchErr)
	}
}
