package node

import (
	"errors"
	"fmt"
	"sync"
	"time"

	apiclient "github.com/AnixOps/anix-agent/v4/api/client"
	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/common/task"
	"github.com/AnixOps/anix-agent/v4/conf"
	vCore "github.com/AnixOps/anix-agent/v4/core"
	"github.com/AnixOps/anix-agent/v4/limiter"
	"github.com/AnixOps/anix-agent/v4/plugin"
	log "github.com/sirupsen/logrus"
)

type Controller struct {
	server                    vCore.Core
	apiClient                 apiclient.NodeAPI
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
	logHook                   *RemoteLogHook
	reconcileMu               sync.Mutex
	pluginSupervisor          *plugin.Supervisor
	limiterAdded              bool
	nodeAdded                 bool
	*conf.Options
}

func (c *Controller) SetPluginSupervisor(supervisor *plugin.Supervisor) {
	c.pluginSupervisor = supervisor
}

// NewController return a Node controller with default parameters.
func NewController(server vCore.Core, api apiclient.NodeAPI, config *conf.Options) *Controller {
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
	if node != nil && node.Type != "" {
		c.apiClient.SetNodeType(node.Type)
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
	c.logHook = NewRemoteLogHook(c.apiClient, c.tag)
	log.StandardLogger().AddHook(c.logHook)

	// add limiter
	l := limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, c.aliveMap)
	c.limiter = l
	c.limiterAdded = true
	// add rule limiter
	if err = l.UpdateRule(&node.Rules); err != nil {
		return fmt.Errorf("update rule error: %s", err)
	}
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
	c.nodeAdded = true
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

	if c.apiClient.SupportsSync() {
		c.syncManager = NewSyncManager(c.apiClient, c, c.buildSyncConfig())
		if err := c.syncManager.Start(); err != nil {
			c.syncManager = nil
			return fmt.Errorf("start sync manager error: %w", err)
		}
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

	if c.limiterAdded {
		limiter.DeleteLimiter(c.tag)
		c.limiterAdded = false
	}
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
	if c.logHook != nil {
		c.logHook.Close()
		c.logHook = nil
	}
	if c.nodeAdded {
		if err := c.server.DelNode(c.tag); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("del node error: %w", err))
		}
		c.nodeAdded = false
	}
	if err := c.apiClient.Close(); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close api client error: %w", err))
	}
	return closeErr
}

func (c *Controller) buildNodeTag(node *panel.NodeInfo) string {
	return fmt.Sprintf("[%s]-%s:%d", c.apiClient.GetAPIHost(), node.Type, node.Id)
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
	c.nodeAdded = false

	// 更新 tag
	if len(c.Options.Name) == 0 {
		c.tag = c.buildNodeTag(newNode)
		// 更新 limiter
		if c.limiterAdded {
			limiter.DeleteLimiter(oldTag)
			c.limiterAdded = false
		}
		l := limiter.AddLimiter(c.tag, &c.LimitConfig, c.userList, c.aliveMap)
		c.limiter = l
		c.limiterAdded = true
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
	c.nodeAdded = true

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
