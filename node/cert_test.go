package node

import (
	"os"
	"path/filepath"
	"testing"
)

func Test_generateSelfSslCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "cert.key")

	if err := generateSelfSslCertificate("domain.com", certPath, keyPath); err != nil {
		t.Fatalf("generateSelfSslCertificate() error = %v", err)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert file stat error = %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file stat error = %v", err)
	}
}
