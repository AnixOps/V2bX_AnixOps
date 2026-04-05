package panel

// Close implements api/client.NodeAPI.
// REST transport has no persistent connection to close.
func (c *Client) Close() error { return nil }

// GetNodeID implements api/client.NodeAPI.
func (c *Client) GetNodeID() int { return c.NodeId }

// GetAPIHost implements api/client.NodeAPI.
func (c *Client) GetAPIHost() string { return c.APIHost }

// GetAPIKey implements api/client.NodeAPI.
func (c *Client) GetAPIKey() string { return c.Token }

// GetSecret implements api/client.NodeAPI.
func (c *Client) GetSecret() string { return c.Secret }

// IsSignEnabled implements api/client.NodeAPI.
func (c *Client) IsSignEnabled() bool { return c.EnableSign }

// SetNodeType implements api/client.NodeAPI.
func (c *Client) SetNodeType(nodeType string) {
	c.NodeType = nodeType
	if c.client != nil && nodeType != "" {
		c.client.SetQueryParam("node_type", nodeType)
	}
}

// SupportsSync implements api/client.NodeAPI.
func (c *Client) SupportsSync() bool { return true }
