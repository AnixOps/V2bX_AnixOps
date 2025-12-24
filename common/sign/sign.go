package sign

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// Signer 请求签名器
type Signer struct {
	secret string
}

// NewSigner 创建签名器
func NewSigner(secret string) *Signer {
	return &Signer{secret: secret}
}

// SignData 签名数据结构
type SignData struct {
	Timestamp string
	Nonce     string
	Signature string
}

// Sign 生成请求签名
// signData = timestamp + method + path + body
func (s *Signer) Sign(method, path string, body []byte) *SignData {
	// 时间戳
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// 生成随机 nonce (防重放)
	nonceBytes := make([]byte, 16)
	rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)

	// 构建签名字符串: timestamp + method + path + body
	signString := timestamp + method + path + string(body)

	// 计算 HMAC-SHA256
	signature := s.ComputeHMAC(signString)

	return &SignData{
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: signature,
	}
}

// ComputeHMAC 计算 HMAC-SHA256
func (s *Signer) ComputeHMAC(data string) string {
	mac := hmac.New(sha256.New, []byte(s.secret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify 验证签名
func (s *Signer) Verify(timestamp, method, path string, body []byte, signature string) bool {
	// 构建签名字符串
	signString := timestamp + method + path + string(body)

	// 重新计算签名
	expected := s.ComputeHMAC(signString)

	// 使用恒定时间比较防止时序攻击
	return hmac.Equal([]byte(expected), []byte(signature))
}

// IsTimestampValid 检查时间戳是否有效（5分钟内）
func IsTimestampValid(timestamp string, maxAge time.Duration) bool {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}

	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}

	return diff <= int64(maxAge.Seconds())
}
