package rdns

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/pion/dtls/v2"
)

// DTLSServerConfig is a convenience function that builds a dtls.Config instance for DTLS servers
// based on common options and certificate+key files.
func DTLSServerConfig(caFile, crtFile, keyFile string, mutualTLS bool) (*dtls.Config, error) {
	dtlsConfig := &dtls.Config{}
	if mutualTLS {
		dtlsConfig.ClientAuth = dtls.RequireAndVerifyClientCert
	}
	if caFile != "" {
		certPool := x509.NewCertPool()
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if ok := certPool.AppendCertsFromPEM(b); !ok {
			return nil, fmt.Errorf("no CA certificates found in %s", caFile)
		}
		dtlsConfig.ClientCAs = certPool
	}

	if crtFile != "" && keyFile != "" {
		var err error
		dtlsConfig.Certificates = make([]tls.Certificate, 1)
		dtlsConfig.Certificates[0], err = tls.LoadX509KeyPair(crtFile, keyFile)
		if err != nil {
			return nil, err
		}
	}
	return dtlsConfig, nil
}

// DTLSClientConfig is a convenience function that builds a dtls.Config instance for TLS clients
// based on common options and certificate+key files.
func DTLSClientConfig(caFile, crtFile, keyFile string) (*dtls.Config, error) {
	dtlsConfig := &dtls.Config{}

	// Add client key/cert if provided
	if crtFile != "" && keyFile != "" {
		var err error
		dtlsConfig.Certificates = make([]tls.Certificate, 1)
		dtlsConfig.Certificates[0], err = tls.LoadX509KeyPair(crtFile, keyFile)
		if err != nil {
			return nil, err
		}
	}

	// Load custom CA set if provided
	if caFile != "" {
		certPool := x509.NewCertPool()
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if ok := certPool.AppendCertsFromPEM(b); !ok {
			return nil, fmt.Errorf("no CA certificates found in %s", caFile)
		}
		dtlsConfig.RootCAs = certPool
	}
	return dtlsConfig, nil
}
