//go:build linux

package gostmesh

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadTLSFileRejectsMutableTrustMaterial(t *testing.T) {
	directory := runtimeSecureTempDir(t)

	for _, test := range []struct {
		name    string
		mode    os.FileMode
		private bool
		wantErr string
	}{
		{name: "group-writable CA", mode: 0o620, wantErr: "must not be writable"},
		{name: "world-writable certificate", mode: 0o606, wantErr: "must not be writable"},
		{name: "group-readable private key", mode: 0o640, private: true, wantErr: "must not be accessible"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(directory, test.name+".pem")
			require.NoError(t, os.WriteFile(path, []byte("test material"), 0o600))
			require.NoError(t, os.Chmod(path, test.mode))

			_, err := readTLSFile(path, test.private)
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}
