package main

import (
	"fmt"
	"net"
	"strings"

	rdns "github.com/folbricht/routedns"
)

// Instantiates an rdns.Resolver from a resolver config
func instantiateResolver(id string, r resolver, resolvers map[string]rdns.Resolver) error {
	var err error
	var portIsSet bool = false
	var portIsSetBootstrapAddress bool = false
	var address string = r.Address
	var bootstrapAddress string = r.BootstrapAddr

	if strings.Contains(address, ":") {
		portIsSet = true
	}
	if strings.Contains(bootstrapAddress, ":") {
		portIsSetBootstrapAddress = true
	}
	switch r.Protocol {

	case "doq":
		tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
		if portIsSet == false {
			r.Address = r.Address + rdns.DoQPort
		}
		if portIsSetBootstrapAddress == false {
			r.BootstrapAddr = r.BootstrapAddr + rdns.DoQPort
		}
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
		tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
		if portIsSet == false {
			r.Address = r.Address + rdns.DoTPort
		}
		if portIsSetBootstrapAddress == false {
			r.BootstrapAddr = r.BootstrapAddr + rdns.DoTPort
		}
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
		dtlsConfig, err := rdns.DTLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
		if portIsSet == false {
			r.Address = r.Address + rdns.DTLSPort
		}
		if portIsSetBootstrapAddress == false {
			r.BootstrapAddr = r.BootstrapAddr + rdns.DTLSPort
		}
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
		if portIsSet == false {
			r.Address = r.Address + rdns.DoHPort
		}
		if portIsSetBootstrapAddress == false {
			r.BootstrapAddr = r.BootstrapAddr + rdns.DoHPort
		}
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
	case "tcp", "udp":
		if portIsSet == false {
			r.Address = r.Address + rdns.PlainDNSPort
		}
		if portIsSetBootstrapAddress == false {
			r.BootstrapAddr = r.BootstrapAddr + rdns.PlainDNSPort
		}
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
