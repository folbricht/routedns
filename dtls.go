package rdns

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/pion/dtls/v3"
)

// PSK is a DTLS pre-shared key and the identity presented alongside it. Used
// as an alternative to certificates, typically with constrained devices that
// can't do a full certificate exchange.
type PSK struct {
	// Key is the shared secret itself.
	Key []byte

	// Identity names the key so the peer can select the right one. Required
	// for clients, which send it during the handshake. Optional for servers,
	// where it is offered as a hint.
	Identity string
}

// pskCipherSuites are the pre-shared key suites pion supports. They have to be
// selected explicitly: pion's default list holds only certificate suites, so a
// config with a PSK and no suites of its own fails the handshake with no
// available cipher suite.
//
// The ECDHE suite comes first even though the rest are AEAD, because it is the
// only one here that provides forward secrecy. The others derive their keys
// from the shared secret alone, so anyone who later obtains the key can decrypt
// traffic captured earlier, and the key sits in a config file for its whole
// lifetime. A server picks the first entry of this list that it also supports,
// so peers that can do ECDHE get forward secrecy while constrained ones still
// negotiate a suite further down.
var pskCipherSuites = []dtls.CipherSuiteID{
	dtls.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
	dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
	dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
	dtls.TLS_PSK_WITH_AES_128_CCM,
	dtls.TLS_PSK_WITH_AES_128_CCM_8,
	dtls.TLS_PSK_WITH_AES_256_CCM_8,
	dtls.TLS_PSK_WITH_AES_128_CBC_SHA256,
}

// recommendedPSKLength is the key size the documentation suggests generating.
// Shorter keys are allowed, since embedded peers sometimes use them, but they
// are the only thing authenticating the connection so a short one is worth
// pointing out.
const recommendedPSKLength = 16

// applyPSK puts a pre-shared key into a DTLS config. Certificates and a PSK
// are mutually exclusive here: pion can offer both, but the mix makes it
// unclear which one a peer actually used, so a config asking for both is
// rejected instead.
func applyPSK(cfg *dtls.Config, psk *PSK, crtFile, keyFile string) error {
	if psk == nil {
		return nil
	}
	if len(psk.Key) == 0 {
		return errors.New("psk must not be empty")
	}
	// Checked against the file names rather than cfg.Certificates, which is
	// only populated when both a certificate and a key were given. Otherwise a
	// half-specified certificate would be dropped without a word.
	if crtFile != "" || keyFile != "" {
		return errors.New("psk cannot be combined with a certificate and key, they are alternatives")
	}
	if len(psk.Key) < recommendedPSKLength {
		Log.Warn("psk is shorter than recommended",
			"bytes", len(psk.Key), "recommended", recommendedPSKLength)
	}
	key := psk.Key
	cfg.PSK = func([]byte) ([]byte, error) { return key, nil }
	if psk.Identity != "" {
		cfg.PSKIdentityHint = []byte(psk.Identity)
	}
	cfg.CipherSuites = pskCipherSuites
	return nil
}

// DTLSServerConfig is a convenience function that builds a dtls.Config instance for DTLS servers
// based on common options and certificate+key files. A non-nil psk configures
// pre-shared key authentication instead of certificates.
func DTLSServerConfig(caFile, crtFile, keyFile string, mutualTLS bool, psk *PSK) (*dtls.Config, error) {
	if mutualTLS && caFile == "" {
		return nil, errors.New("mutual-tls requires a ca to be configured to verify client certificates")
	}
	// A PSK handshake never carries a client certificate, so requiring one
	// leaves a listener that starts up but fails every handshake.
	if mutualTLS && psk != nil {
		return nil, errors.New("psk cannot be combined with mutual-tls, a pre-shared key handshake has no client certificate")
	}
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
	if err := applyPSK(dtlsConfig, psk, crtFile, keyFile); err != nil {
		return nil, err
	}
	return dtlsConfig, nil
}

// DTLSClientConfig is a convenience function that builds a dtls.Config instance for TLS clients
// based on common options and certificate+key files. A non-nil psk configures
// pre-shared key authentication instead of certificates.
func DTLSClientConfig(caFile, crtFile, keyFile string, psk *PSK) (*dtls.Config, error) {
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
	if psk != nil && psk.Identity == "" {
		return nil, errors.New("psk-identity is required when using a psk on a resolver")
	}
	if err := applyPSK(dtlsConfig, psk, crtFile, keyFile); err != nil {
		return nil, err
	}
	return dtlsConfig, nil
}
