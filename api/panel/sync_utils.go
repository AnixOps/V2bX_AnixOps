package panel

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// generateMessageID 生成消息ID
func generateMessageID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// currentTimestamp 获取当前时间戳
func currentTimestamp() int64 {
	return time.Now().Unix()
}
