package rdns

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// TLSServerConfig is a convenience function that builds a tls.Config instance for TLS servers
// based on common options and certificate+key files.
func TLSServerConfig(caFile, crtFile, keyFile string, mutualTLS bool) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if mutualTLS {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
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
		tlsConfig.ClientCAs = certPool
	}

	if crtFile != "" && keyFile != "" {
		var err error
		tlsConfig.Certificates = make([]tls.Certificate, 1)
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(crtFile, keyFile)
		if err != nil {
			return nil, err
		}
	}
	return tlsConfig, nil
}

// TLSClientConfig is a convenience function that builds a tls.Config instance for TLS clients
// based on common options and certificate+key files.
func TLSClientConfig(caFile, crtFile, keyFile, serverName string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}

	// Add client key/cert if provided
	if crtFile != "" && keyFile != "" {
		certificate, err := tls.LoadX509KeyPair(crtFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate from %s", crtFile)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
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
		tlsConfig.RootCAs = certPool
	}
	return tlsConfig, nil
}
