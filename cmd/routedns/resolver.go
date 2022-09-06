package main

import (
	"fmt"
	"net"

	rdns "github.com/folbricht/routedns"
)

// Instantiates an rdns.Resolver from a resolver config
func instantiateResolver(id string, r resolver, resolvers map[string]rdns.Resolver) error {
	var err error
	switch r.Protocol {

	case "doq":
		r.Address = rdns.AddressWithDefault(r.Address, rdns.DoQPort)

		tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
		if err != nil {
			return err
		}
		opt := rdns.DoQClientOptions{
			BootstrapAddr: r.BootstrapAddr,
			LocalAddr:     net.ParseIP(r.LocalAddr),
			TLSConfig:     tlsConfig,
		}
		resolvers[id], err = rdns.NewDoQClient(id, r.Address, opt)
		if err != nil {
			return err
		}
	case "dot":
		r.Address = rdns.AddressWithDefault(r.Address, rdns.DoTPort)

		tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
		if err != nil {
			return err
		}
		opt := rdns.DoTClientOptions{
			BootstrapAddr: r.BootstrapAddr,
			LocalAddr:     net.ParseIP(r.LocalAddr),
			TLSConfig:     tlsConfig,
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
		}
		resolvers[id], err = rdns.NewDTLSClient(id, r.Address, opt)
		if err != nil {
			return err
		}
	case "doh":
		r.Address = rdns.AddressWithDefault(r.Address, rdns.DoHPort)

		tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
		if err != nil {
			return err
		}
		opt := rdns.DoHClientOptions{
			Method:        r.DoH.Method,
			TLSConfig:     tlsConfig,
			BootstrapAddr: r.BootstrapAddr,
			Transport:     r.Transport,
			LocalAddr:     net.ParseIP(r.LocalAddr),
		}
		resolvers[id], err = rdns.NewDoHClient(id, r.Address, opt)
		if err != nil {
			return err
		}
	case "odoh":
		tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
		if err != nil {
			return err
		}
		opt := rdns.DoHClientOptions{
			Method:        r.DoH.Method,
			TLSConfig:     tlsConfig,
			BootstrapAddr: r.BootstrapAddr,
			Transport:     r.Transport,
			LocalAddr:     net.ParseIP(r.LocalAddr),
		}
		resolvers[id], err = rdns.NewODoHClient(id, r.Address, r.Target, opt)
		if err != nil {
			return err
		}
	case "tcp", "udp":
		r.Address = rdns.AddressWithDefault(r.Address, rdns.PlainDNSPort)

		opt := rdns.DNSClientOptions{
			LocalAddr: net.ParseIP(r.LocalAddr),
			UDPSize:   r.EDNS0UDPSize,
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
