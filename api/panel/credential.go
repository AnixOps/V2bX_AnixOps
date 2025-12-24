package panel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Credential 节点凭证
type Credential struct {
	NodeID int    `json:"node_id"`
	APIKey string `json:"api_key"`
	Secret string `json:"secret"`
}

// CredentialStore 凭证存储
type CredentialStore struct {
	filePath string
	mu       sync.RWMutex
	cred     *Credential
}

// NewCredentialStore 创建凭证存储
func NewCredentialStore(filePath string) *CredentialStore {
	return &CredentialStore{
		filePath: filePath,
	}
}

// Load 加载凭证
func (s *CredentialStore) Load() (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // 文件不存在，返回nil表示需要注册
		}
		return nil, err
	}

	var cred Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, err
	}

	s.cred = &cred
	return &cred, nil
}

// Save 保存凭证
func (s *CredentialStore) Save(cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 确保目录存在
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return err
	}

	// 使用安全的文件权限
	if err := os.WriteFile(s.filePath, data, 0600); err != nil {
		return err
	}

	s.cred = cred
	return nil
}

// Get 获取当前凭证
func (s *CredentialStore) Get() *Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cred
}

// Clear 清除凭证
func (s *CredentialStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cred = nil
	return os.Remove(s.filePath)
}

// Exists 检查凭证是否存在
func (s *CredentialStore) Exists() bool {
	_, err := os.Stat(s.filePath)
	return err == nil
}
