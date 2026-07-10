package node

import (
	"strconv"

	"github.com/InazumaV/V2bX/api/panel"
	vCore "github.com/InazumaV/V2bX/core"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) reportUserTrafficTask() (err error) {
	userTraffic, err := c.server.GetUserTrafficSlice(c.tag, true)
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Warn("Get user traffic failed")
		userTraffic = nil
	}
	if c.LimitConfig.EnableDynamicSpeedLimit && c.traffic != nil {
		for _, traffic := range userTraffic {
			for _, user := range c.userList {
				if user.Id == traffic.UID {
					c.traffic[user.Uuid] += traffic.Upload + traffic.Download
					break
				}
			}
		}
	}
	if len(userTraffic) > 0 {
		err = c.apiClient.ReportUserTraffic(userTraffic)
		if err != nil {
			if rollbacker, ok := c.server.(vCore.TrafficRollbacker); ok {
				if rollbackErr := rollbacker.RollbackUserTrafficSlice(c.tag, userTraffic); rollbackErr != nil {
					log.WithFields(log.Fields{
						"tag": c.tag,
						"err": rollbackErr,
					}).Warn("Rollback user traffic cursor failed")
				}
			}
			if c.LimitConfig.EnableDynamicSpeedLimit && c.traffic != nil {
				for _, traffic := range userTraffic {
					for _, user := range c.userList {
						if user.Id != traffic.UID {
							continue
						}
						amount := traffic.Upload + traffic.Download
						c.traffic[user.Uuid] -= amount
						if c.traffic[user.Uuid] < 0 {
							c.traffic[user.Uuid] = 0
						}
						break
					}
				}
			}
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report user traffic failed")
		} else {
			log.WithField("tag", c.tag).Infof("Report %d users traffic", len(userTraffic))
			log.WithField("tag", c.tag).Debugf("User traffic: %+v", userTraffic)
		}
	}

	onlineDevice, err := c.limiter.GetOnlineDevice()
	if err != nil {
		log.Print(err)
		onlineDevice = &[]panel.OnlineUser{}
	}
	coreOnlineDevice, err := c.getCoreOnlineDevice()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Info("Get core online users failed")
	}
	mergedOnlineDevice := mergeOnlineDevices(append(*onlineDevice, coreOnlineDevice...))
	if len(mergedOnlineDevice) > 0 {
		// Only report user has traffic > 100kb to allow ping test
		var result []panel.OnlineUser
		var nocountUID = make(map[int]struct{})
		for _, traffic := range userTraffic {
			total := traffic.Upload + traffic.Download
			if total < int64(c.Options.DeviceOnlineMinTraffic*1000) {
				nocountUID[traffic.UID] = struct{}{}
			}
		}
		for _, online := range mergedOnlineDevice {
			if _, ok := nocountUID[online.UID]; !ok {
				result = append(result, online)
			}
		}
		data := make(map[int][]string)
		for _, onlineuser := range result {
			// json structure: { UID1:["ip1","ip2"],UID2:["ip3","ip4"] }
			data[onlineuser.UID] = append(data[onlineuser.UID], onlineuser.IP)
		}
		if err = c.apiClient.ReportNodeOnlineUsers(&data); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("Report online users failed")
		} else {
			log.WithField("tag", c.tag).Infof("Total %d online users, %d Reported", len(mergedOnlineDevice), len(result))
			log.WithField("tag", c.tag).Debugf("Online users: %+v", data)
		}
	}

	userTraffic = nil
	c.syncCoreUserRateLimits()
	return nil
}

func (c *Controller) syncCoreUserRateLimits() {
	if c.limiter == nil {
		return
	}
	updater, ok := c.server.(vCore.RateLimitUpdater)
	if !ok {
		return
	}
	for _, user := range c.userList {
		if err := updater.UpdateUserRateLimit(c.tag, user.Uuid, c.limiter.GetUserSpeedLimit(c.tag, user.Uuid)); err != nil {
			log.WithFields(log.Fields{"tag": c.tag, "uuid": user.Uuid, "err": err}).Warn("Sync WireGuard rate limit failed")
		}
	}
}

func (c *Controller) getCoreOnlineDevice() ([]panel.OnlineUser, error) {
	provider, ok := c.server.(vCore.OnlineDeviceProvider)
	if !ok {
		return nil, nil
	}
	return provider.GetOnlineDevice(c.tag)
}

func mergeOnlineDevices(users []panel.OnlineUser) []panel.OnlineUser {
	seen := make(map[string]struct{}, len(users))
	merged := make([]panel.OnlineUser, 0, len(users))
	for _, user := range users {
		if user.UID == 0 || user.IP == "" {
			continue
		}
		key := strconv.Itoa(user.UID) + "\x00" + user.IP
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, user)
	}
	return merged
}

func compareUserList(old, new []panel.UserInfo) (deleted, added []panel.UserInfo) {
	oldMap := make(map[string]int)
	for i, user := range old {
		key := userSyncKey(user)
		oldMap[key] = i
	}

	for _, user := range new {
		key := userSyncKey(user)
		if _, exists := oldMap[key]; !exists {
			added = append(added, user)
		} else {
			delete(oldMap, key)
		}
	}

	for _, index := range oldMap {
		deleted = append(deleted, old[index])
	}

	return deleted, added
}

func userSyncKey(user panel.UserInfo) string {
	return user.Uuid + "\x00" + strconv.Itoa(user.SpeedLimit) + "\x00" +
		strconv.Itoa(user.DeviceLimit) + "\x00" + user.WireGuardPeerIP + "\x00" +
		user.WireGuardPublicKey + "\x00" + user.WireGuardPresharedKey
}
