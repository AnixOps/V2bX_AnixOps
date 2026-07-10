package node

import (
	"fmt"
	"strings"

	apiclient "github.com/InazumaV/V2bX/api/client"
	grpcapi "github.com/InazumaV/V2bX/api/grpc"
	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
)

type Node struct {
	controllers []*Controller
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
	}
	return nil
}

func (n *Node) Close() {
	for _, c := range n.controllers {
		err := c.Close()
		if err != nil {
			panic(err)
		}
	}
	n.controllers = nil
}
