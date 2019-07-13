package rdns

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

type ClientTLSOptions struct {
	// CAs to trust. Defaults to the system's CA store.
	CAFile string

	// Key and Certificate mutual TLS. Only required if the server expects
	// a client certificate.
	ClientKeyFile string
	ClientCrtFile string
}

// Config returns a TLS config for a client based on the options.
func (opt ClientTLSOptions) Config() (*tls.Config, error) {
	tlsConfig := &tls.Config{}

	// Add client key/cert if provided
	if opt.ClientCrtFile != "" && opt.ClientKeyFile != "" {
		certificate, err := tls.LoadX509KeyPair(opt.ClientCrtFile, opt.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate from %s", opt.ClientCrtFile)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	// Load custom CA set if provided
	if opt.CAFile != "" {
		certPool := x509.NewCertPool()
		b, err := ioutil.ReadFile(opt.CAFile)
		if err != nil {
			return nil, err
		}
		if ok := certPool.AppendCertsFromPEM(b); !ok {
			return nil, fmt.Errorf("no CA certficates found in %s", opt.CAFile)
		}
		tlsConfig.RootCAs = certPool
	}
	return tlsConfig, nil
}
