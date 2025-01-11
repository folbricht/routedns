package main

import (
	"fmt"
	"net"
	"time"

	rdns "github.com/folbricht/routedns"
)

// Instantiates an rdns.Resolver from a resolver config
func instantiateResolver(id string, r resolver, resolvers map[string]rdns.Resolver) error {
	var err error
	switch r.Protocol {

	case "doq":
		r.Address = rdns.AddressWithDefault(r.Address, rdns.DoQPort)

		tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey, r.ServerName)
		if err != nil {
			return err
		}
		opt := rdns.DoQClientOptions{
			BootstrapAddr: r.BootstrapAddr,
			LocalAddr:     net.ParseIP(r.LocalAddr),
			TLSConfig:     tlsConfig,
			QueryTimeout:  time.Duration(r.QueryTimeout) * time.Second,
			Use0RTT:       r.Use0RTT,
		}
		resolvers[id], err = rdns.NewDoQClient(id, r.Address, opt)
		if err != nil {
			return err
		}
	case "dot":
		r.Address = rdns.AddressWithDefault(r.Address, rdns.DoTPort)

		tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey, r.ServerName)
		if err != nil {
			return err
		}
		opt := rdns.DoTClientOptions{
			BootstrapAddr: r.BootstrapAddr,
			LocalAddr:     net.ParseIP(r.LocalAddr),
			TLSConfig:     tlsConfig,
			QueryTimeout:  time.Duration(r.QueryTimeout) * time.Second,
			Dialer:        socks5DialerFromConfig(r),
		}
		resolvers[id], err = rdns.NewDoTClient(id, r.Address, opt)
		if err != nil {
			return err
		}
	case "dtls":
		r.Address = rdns.AddressWithDefault(r.Address, rdns.DTLSPort)

		dtlsConfig, err := rdns.DTLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
		if err != nil {
			return err
		}
		opt := rdns.DTLSClientOptions{
			BootstrapAddr: r.BootstrapAddr,
			LocalAddr:     net.ParseIP(r.LocalAddr),
			DTLSConfig:    dtlsConfig,
			UDPSize:       r.EDNS0UDPSize,
			QueryTimeout:  time.Duration(r.QueryTimeout) * time.Second,
		}
		resolvers[id], err = rdns.NewDTLSClient(id, r.Address, opt)
		if err != nil {
			return err
		}
	case "doh":
		r.Address = rdns.AddressWithDefault(r.Address, rdns.DoHPort)

		tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey, r.ServerName)
		if err != nil {
			return err
		}
		opt := rdns.DoHClientOptions{
			Method:        r.DoH.Method,
			TLSConfig:     tlsConfig,
			BootstrapAddr: r.BootstrapAddr,
			Transport:     r.Transport,
			LocalAddr:     net.ParseIP(r.LocalAddr),
			QueryTimeout:  time.Duration(r.QueryTimeout) * time.Second,
			Dialer:        socks5DialerFromConfig(r),
			Use0RTT:       r.Use0RTT,
		}
		resolvers[id], err = rdns.NewDoHClient(id, r.Address, opt)
		if err != nil {
			return err
		}
	case "tcp", "udp":
		r.Address = rdns.AddressWithDefault(r.Address, rdns.PlainDNSPort)

		opt := rdns.DNSClientOptions{
			LocalAddr:    net.ParseIP(r.LocalAddr),
			UDPSize:      r.EDNS0UDPSize,
			QueryTimeout: time.Duration(r.QueryTimeout) * time.Second,
			Dialer:       socks5DialerFromConfig(r),
		}
		resolvers[id], err = rdns.NewDNSClient(id, r.Address, r.Protocol, opt)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported protocol '%s' for resolver '%s'", r.Protocol, id)
	}
	return nil
}

// Returns a dialer if a socks5 proxy is configured, nil otherwise
func socks5DialerFromConfig(cfg resolver) rdns.Dialer {
	if cfg.Socks5Address == "" {
		return nil
	}
	r := rdns.NewSocks5Dialer(
		cfg.Socks5Address,
		rdns.Socks5DialerOptions{
			Username:     cfg.Socks5Username,
			Password:     cfg.Socks5Password,
			TCPTimeout:   0,
			UDPTimeout:   5 * time.Second,
			ResolveLocal: cfg.Socks5ResolveLocal,
			LocalAddr:    net.ParseIP(cfg.LocalAddr),
		})
	return r
}
