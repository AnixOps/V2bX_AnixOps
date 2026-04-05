package node

import (
	"errors"
	"fmt"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/task"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	log "github.com/sirupsen/logrus"
)

type Controller struct {
	server                    vCore.Core
	apiClient                 *panel.Client
	tag                       string
	limiter                   *limiter.Limiter
	traffic                   map[string]int64
	userList                  []panel.UserInfo
	aliveMap                  map[int]int
	info                      *panel.NodeInfo
	nodeInfoMonitorPeriodic   *task.Task
	userReportPeriodic        *task.Task
	renewCertPeriodic         *task.Task
	dynamicSpeedLimitPeriodic *task.Task
	onlineIpReportPeriodic    *task.Task
	syncManager               *SyncManager
	*conf.Options
}

// NewController return a Node controller with default parameters.
func NewController(server vCore.Core, api *panel.Client, config *conf.Options) *Controller {
	controller := &Controller{
		server:    server,
		Options:   config,
		apiClient: api,
	}
	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	// First fetch Node Info
	var err error
	node, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return fmt.Errorf("get node info error: %s", err)
	}
	// Update user
	c.userList, err = c.apiClient.GetUserList()
	if err != nil {
		return fmt.Errorf("get user list error: %s", err)
	}
	if len(c.userList) == 0 {
		log.Warn("No users found for this node, will continue running and check for users periodically")
	}
	c.aliveMap, err = c.apiClient.GetUserAlive()
	if err != nil {
		return fmt.Errorf("failed to get user alive list: %s", err)
	}
	if len(c.Options.Name) == 0 {
		c.tag = c.buildNodeTag(node)
	} else {
		c.tag = c.Options.Name
	}

	// add limiter
	l := limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, c.aliveMap)
	// add rule limiter
	if err = l.UpdateRule(&node.Rules); err != nil {
		return fmt.Errorf("update rule error: %s", err)
	}
	c.limiter = l
	if node.Security == panel.Tls {
		err = c.requestCert()
		if err != nil {
			return fmt.Errorf("request cert error: %s", err)
		}
	}
	// Add new tag
	err = c.server.AddNode(c.tag, node, c.Options)
	if err != nil {
		return fmt.Errorf("add new node error: %s", err)
	}
	added, err := c.server.AddUsers(&vCore.AddUsersParams{
		Tag:      c.tag,
		Users:    c.userList,
		NodeInfo: node,
	})
	if err != nil {
		return fmt.Errorf("add users error: %s", err)
	}
	log.WithField("tag", c.tag).Infof("Added %d new users", added)
	c.info = node
	c.startTasks(node)

	c.syncManager = NewSyncManager(c.apiClient, c, c.buildSyncConfig())
	if err := c.syncManager.Start(); err != nil {
		c.syncManager = nil
		return fmt.Errorf("start sync manager error: %w", err)
	}

	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	var closeErr error
	if c.syncManager != nil {
		if err := c.syncManager.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close sync manager error: %w", err))
		}
		c.syncManager = nil
	}

	limiter.DeleteLimiter(c.tag)
	if c.nodeInfoMonitorPeriodic != nil {
		c.nodeInfoMonitorPeriodic.Close()
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
	}
	if c.dynamicSpeedLimitPeriodic != nil {
		c.dynamicSpeedLimitPeriodic.Close()
	}
	if c.onlineIpReportPeriodic != nil {
		c.onlineIpReportPeriodic.Close()
	}
	if err := c.server.DelNode(c.tag); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("del node error: %w", err))
	}
	return closeErr
}

func (c *Controller) buildNodeTag(node *panel.NodeInfo) string {
	return fmt.Sprintf("[%s]-%s:%d", c.apiClient.APIHost, node.Type, node.Id)
}

func (c *Controller) buildSyncConfig() *SyncConfig {
	if c.Options == nil || c.Options.SyncConfig == nil {
		return DefaultSyncConfig()
	}

	config := DefaultSyncConfig()
	syncConfig := c.Options.SyncConfig

	config.EnableWebSocket = syncConfig.EnableWebSocket
	if syncConfig.WSEndpoint != "" {
		config.WSEndpoint = syncConfig.WSEndpoint
	}
	if len(syncConfig.WSEndpointFallbacks) > 0 {
		config.WSEndpointFallbacks = syncConfig.WSEndpointFallbacks
	}
	if syncConfig.ReconnectInterval > 0 {
		config.ReconnectInterval = time.Duration(syncConfig.ReconnectInterval) * time.Second
	}
	config.MaxReconnectTries = syncConfig.MaxReconnectTries

	if syncConfig.PingInterval > 0 {
		config.PingInterval = time.Duration(syncConfig.PingInterval) * time.Second
	}
	if syncConfig.PongTimeout > 0 {
		config.PongTimeout = time.Duration(syncConfig.PongTimeout) * time.Second
	}
	if syncConfig.AckTimeout > 0 {
		config.AckTimeout = time.Duration(syncConfig.AckTimeout) * time.Second
	}
	if syncConfig.BufferSize > 0 {
		config.BufferSize = syncConfig.BufferSize
	}
	config.AckRetries = syncConfig.AckRetries

	config.EnableFallback = syncConfig.EnableFallback
	if syncConfig.FallbackInterval > 0 {
		config.FallbackInterval = time.Duration(syncConfig.FallbackInterval) * time.Second
	}

	return config
}

// reloadNode 重载节点配置 (用于同步管理器)
func (c *Controller) reloadNode(newNode *panel.NodeInfo) error {
	log.WithField("tag", c.tag).Info("Reloading node configuration")

	// 保存旧的 tag
	oldTag := c.tag

	// 删除旧节点
	if err := c.server.DelNode(oldTag); err != nil {
		log.WithFields(log.Fields{
			"tag": oldTag,
			"err": err,
		}).Error("Failed to delete old node")
		return err
	}

	// 更新 tag
	if len(c.Options.Name) == 0 {
		c.tag = c.buildNodeTag(newNode)
		// 更新 limiter
		limiter.DeleteLimiter(oldTag)
		l := limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, c.aliveMap)
		c.limiter = l
	}

	// 更新规则
	if err := c.limiter.UpdateRule(&newNode.Rules); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Failed to update rules")
		return err
	}

	// 请求证书
	if newNode.Security == panel.Tls {
		if err := c.requestCert(); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Failed to request cert")
			return err
		}
	}

	// 添加新节点
	if err := c.server.AddNode(c.tag, newNode, c.Options); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Failed to add new node")
		return err
	}

	// 添加用户
	added, err := c.server.AddUsers(&vCore.AddUsersParams{
		Tag:      c.tag,
		Users:    c.userList,
		NodeInfo: newNode,
	})
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Failed to add users")
		return err
	}

	c.info = newNode
	c.traffic = make(map[string]int64)

	log.WithFields(log.Fields{
		"tag":   c.tag,
		"users": added,
	}).Info("Node reloaded successfully")

	return nil
}
