package panel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// EncryptedCredentialStore 加密凭证存储
type EncryptedCredentialStore struct {
	filePath string
	mu       sync.RWMutex
	cred     *Credential
	key      []byte
}

// NewEncryptedCredentialStore 创建加密凭证存储
func NewEncryptedCredentialStore(filePath string) (*EncryptedCredentialStore, error) {
	key, err := deriveKey()
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return &EncryptedCredentialStore{
		filePath: filePath,
		key:      key,
	}, nil
}

// deriveKey 从机器特征派生加密密钥
func deriveKey() ([]byte, error) {
	// 获取机器唯一特征
	id := getMachineID()

	// 加盐并哈希
	salt := "v2bx-node-credential-v1"
	h := sha256.Sum256([]byte(id + salt))
	return h[:], nil
}

// getMachineID 获取机器唯一标识
func getMachineID() string {
	// 尝试多种方式获取机器 ID
	var id string

	// 1. 尝试读取 machine-id (Linux)
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			id = string(data)
		} else if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
			id = string(data)
		}
	}

	// 2. 尝试使用主机名
	if id == "" {
		hostname, err := os.Hostname()
		if err == nil {
			id = hostname
		}
	}

	// 3. 降级：使用固定值（不推荐，但保证程序能运行）
	if id == "" {
		id = "default-v2bx-node"
	}

	return id
}

// Load 解密加载凭证
func (s *EncryptedCredentialStore) Load() (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ciphertext, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // 文件不存在，返回nil表示需要注册
		}
		return nil, err
	}

	// 如果文件太小，可能是损坏的
	if len(ciphertext) < 12 {
		return nil, fmt.Errorf("credential file corrupted")
	}

	// AES-GCM 解密
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	var cred Credential
	if err := json.Unmarshal(plaintext, &cred); err != nil {
		return nil, fmt.Errorf("unmarshal credential: %w", err)
	}

	s.cred = &cred
	return &cred, nil
}

// Save 加密保存凭证
func (s *EncryptedCredentialStore) Save(cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// JSON 序列化
	plaintext, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("marshal credential: %w", err)
	}

	// AES-GCM 加密
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// 确保目录存在
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// 写入文件（安全权限）
	if err := os.WriteFile(s.filePath, ciphertext, 0600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	s.cred = cred
	return nil
}

// Get 获取当前凭证
func (s *EncryptedCredentialStore) Get() *Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cred
}

// Clear 清除凭证
func (s *EncryptedCredentialStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cred = nil
	return os.Remove(s.filePath)
}

// Exists 检查凭证是否存在
func (s *EncryptedCredentialStore) Exists() bool {
	_, err := os.Stat(s.filePath)
	return err == nil
}
