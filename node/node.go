package node

import (
	"fmt"
	"strings"

	agentapi "github.com/AnixOps/anix-agent/v3/api/agent"
	apiclient "github.com/AnixOps/anix-agent/v3/api/client"
	grpcapi "github.com/AnixOps/anix-agent/v3/api/grpc"
	"github.com/AnixOps/anix-agent/v3/api/panel"
	"github.com/AnixOps/anix-agent/v3/conf"
	vCore "github.com/AnixOps/anix-agent/v3/core"
)

type Node struct {
	controllers  []*Controller
	agentClients []*agentapi.Client
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
	startedAgentNodes := make(map[int]struct{})
	for i := range nodes {
		nodes[i].ApiConfig.NodeType = initialNodeType(nodes[i].ApiConfig.NodeType, nodes[i].Options.Core)
		client, err := createAPIClient(&nodes[i].ApiConfig)
		if err != nil {
			return err
		}
		// Register controller service
		n.controllers[i] = NewController(core, client, &nodes[i].Options)
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
			if agentClient, agentErr := newAgentControlClient(&nodes[i].ApiConfig, n.controllers[i], core); agentErr != nil {
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
	for _, c := range n.controllers {
		err := c.Close()
		if err != nil {
			panic(err)
		}
	}
	n.controllers = nil
}
