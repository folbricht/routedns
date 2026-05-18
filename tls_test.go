package rdns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTLSServerConfigMutualTLSRequiresCA(t *testing.T) {
	// Without a CA, mutual-tls must fail rather than silently fall back to
	// the system root pool for client certificate verification.
	_, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", true)
	require.Error(t, err)

	// With a CA it should succeed.
	_, err = TLSServerConfig("testdata/ca.crt", "testdata/server.crt", "testdata/server.key", true)
	require.NoError(t, err)

	// Without mutual-tls, no CA is required.
	_, err = TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)
}

func TestDTLSServerConfigMutualTLSRequiresCA(t *testing.T) {
	_, err := DTLSServerConfig("", "testdata/server.crt", "testdata/server.key", true)
	require.Error(t, err)

	_, err = DTLSServerConfig("testdata/ca.crt", "testdata/server.crt", "testdata/server.key", true)
	require.NoError(t, err)

	_, err = DTLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)
}
