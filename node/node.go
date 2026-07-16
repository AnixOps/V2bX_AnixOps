package node

import (
	"context"
	"fmt"
	"strings"

	agentapi "github.com/AnixOps/anix-agent/v3/api/agent"
	apiclient "github.com/AnixOps/anix-agent/v3/api/client"
	grpcapi "github.com/AnixOps/anix-agent/v3/api/grpc"
	"github.com/AnixOps/anix-agent/v3/api/panel"
	"github.com/AnixOps/anix-agent/v3/conf"
	vCore "github.com/AnixOps/anix-agent/v3/core"
	"github.com/AnixOps/anix-agent/v3/plugin"
)

type Node struct {
	controllers      []*Controller
	agentClients     []*agentapi.Client
	pluginSupervisor *plugin.Supervisor
}

func New() *Node {
	return &Node{}
}

func createAPIClient(apiCfg *conf.ApiConfig) (apiclient.NodeAPI, error) {
	var (
		client apiclient.NodeAPI
		err    error
	)
	switch strings.ToLower(strings.TrimSpace(apiCfg.Transport)) {
	case "", "http", "https", "rest":
		client, err = panel.New(apiCfg)
	case "grpc":
		client, err = grpcapi.NewFromAPIConfig(apiCfg)
	default:
		return nil, fmt.Errorf("unsupported api transport %q", apiCfg.Transport)
	}
	if err != nil {
		return nil, err
	}
	if apiCfg.NodeType != "" {
		client.SetNodeType(apiCfg.NodeType)
	}
	return client, nil
}

func initialNodeType(nodeType, coreType string) string {
	if strings.TrimSpace(nodeType) != "" {
		return nodeType
	}
	if strings.EqualFold(strings.TrimSpace(coreType), "wireguard") {
		return "wireguard"
	}
	return ""
}

func (n *Node) Start(nodes []conf.NodeConfig, core vCore.Core) error {
	n.controllers = make([]*Controller, len(nodes))
	n.agentClients = nil
	supervisor, err := newPluginSupervisor(nodes)
	if err != nil {
		return err
	}
	n.pluginSupervisor = supervisor
	startedAgentNodes := make(map[int]struct{})
	for i := range nodes {
		nodes[i].ApiConfig.NodeType = initialNodeType(nodes[i].ApiConfig.NodeType, nodes[i].Options.Core)
		client, err := createAPIClient(&nodes[i].ApiConfig)
		if err != nil {
			return err
		}
		// Register controller service
		n.controllers[i] = NewController(core, client, &nodes[i].Options)
		if n.pluginSupervisor != nil && nodes[i].ApiConfig.PluginSupervisorEnabled {
			n.controllers[i].SetPluginSupervisor(n.pluginSupervisor)
		}
		err = n.controllers[i].Start()
		if err != nil {
			_ = client.Close()
			return fmt.Errorf("start node controller [%s-%d] error: %s",
				nodes[i].ApiConfig.APIHost,
				nodes[i].ApiConfig.NodeID,
				err)
		}
		nodeID := client.GetNodeID()
		if _, started := startedAgentNodes[nodeID]; !started && nodes[i].ApiConfig.AgentControlEnabled {
			if agentClient, agentErr := newAgentControlClient(&nodes[i].ApiConfig, n.controllers[i], core, n.pluginSupervisor != nil && nodes[i].ApiConfig.PluginSupervisorEnabled); agentErr != nil {
				logAgentControlUnavailable(nodeID, agentErr)
			} else {
				if agentErr := agentClient.Start(); agentErr != nil {
					logAgentControlUnavailable(nodeID, agentErr)
				} else {
					n.agentClients = append(n.agentClients, agentClient)
					startedAgentNodes[nodeID] = struct{}{}
				}
			}
		}
	}
	return nil
}

func (n *Node) Close() {
	for _, client := range n.agentClients {
		if err := client.Close(); err != nil {
			panic(err)
		}
	}
	n.agentClients = nil
	if n.pluginSupervisor != nil {
		if err := n.pluginSupervisor.Close(context.Background()); err != nil {
			panic(err)
		}
		n.pluginSupervisor = nil
	}
	for _, c := range n.controllers {
		err := c.Close()
		if err != nil {
			panic(err)
		}
	}
	n.controllers = nil
}

func newPluginSupervisor(nodes []conf.NodeConfig) (*plugin.Supervisor, error) {
	var rootDir, socketDir, key string
	for _, node := range nodes {
		api := node.ApiConfig
		if !api.PluginSupervisorEnabled {
			continue
		}
		if strings.TrimSpace(api.PluginRoot) == "" {
			return nil, fmt.Errorf("PluginRoot is required when PluginSupervisorEnabled is true")
		}
		if rootDir == "" {
			rootDir, socketDir, key = api.PluginRoot, api.PluginSocketDir, api.PluginOfficialPublicKey
			continue
		}
		if rootDir != api.PluginRoot || socketDir != api.PluginSocketDir || key != api.PluginOfficialPublicKey {
			return nil, fmt.Errorf("all plugin-supervisor node configurations must use the same root, socket directory, and trust root")
		}
	}
	if rootDir == "" {
		return nil, nil
	}
	if strings.TrimSpace(key) == "" {
		return nil, fmt.Errorf("PluginOfficialPublicKey is required when PluginSupervisorEnabled is true")
	}
	publicKey, err := plugin.ParseOfficialPublicKey(key)
	if err != nil {
		return nil, err
	}
	return plugin.NewSupervisor(plugin.Config{RootDir: rootDir, SocketDir: socketDir, PublicKey: publicKey})
}
