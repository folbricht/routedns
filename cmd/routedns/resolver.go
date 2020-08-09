package main

import (
	"fmt"
	"net"

	rdns "github.com/folbricht/routedns"
)

// Instantiates an rdns.Resolver from a resolver config
func resolverFromConfig(id string, r resolver) (rdns.Resolver, error) {
	switch r.Protocol {
	case "doq":
		tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
		if err != nil {
			return nil, err
		}
		opt := rdns.DoQClientOptions{
			BootstrapAddr: r.BootstrapAddr,
			LocalAddr:     net.ParseIP(r.LocalAddr),
			TLSConfig:     tlsConfig,
		}
		return rdns.NewDoQClient(id, r.Address, opt)
	case "dot":
		tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
		if err != nil {
			return nil, err
		}
		opt := rdns.DoTClientOptions{
			BootstrapAddr: r.BootstrapAddr,
			LocalAddr:     net.ParseIP(r.LocalAddr),
			TLSConfig:     tlsConfig,
		}
		return rdns.NewDoTClient(id, r.Address, opt)
	case "dtls":
		dtlsConfig, err := rdns.DTLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
		if err != nil {
			return nil, err
		}
		opt := rdns.DTLSClientOptions{
			BootstrapAddr: r.BootstrapAddr,
			LocalAddr:     net.ParseIP(r.LocalAddr),
			DTLSConfig:    dtlsConfig,
		}
		return rdns.NewDTLSClient(id, r.Address, opt)
	case "doh":
		tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
		if err != nil {
			return nil, err
		}
		opt := rdns.DoHClientOptions{
			Method:        r.DoH.Method,
			TLSConfig:     tlsConfig,
			BootstrapAddr: r.BootstrapAddr,
			Transport:     r.Transport,
			LocalAddr:     net.ParseIP(r.LocalAddr),
		}
		return rdns.NewDoHClient(id, r.Address, opt)
	case "tcp", "udp":
		opt := rdns.DNSClientOptions{
			LocalAddr: net.ParseIP(r.LocalAddr),
		}
		return rdns.NewDNSClient(id, r.Address, r.Protocol, opt)
	default:
		return nil, fmt.Errorf("unsupported protocol '%s' for resolver '%s'", r.Protocol, id)
	}
}
