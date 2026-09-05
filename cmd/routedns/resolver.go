package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	rdns "github.com/folbricht/routedns"
)

// idleTimeout returns the idle connection timeout for a resolver, reconciling
// the resolver-level option with the deprecated DoH-specific one. A zero value
// means the protocol applies its own default. Since zero is indistinguishable
// from unset, setting both is an error rather than picking a winner silently.
func idleTimeout(id string, r resolver) (time.Duration, error) {
	if r.IdleTimeout != 0 && r.DoH.IdleTimeout != 0 {
		return 0, fmt.Errorf("resolver '%s': idle-timeout is set both at the resolver level and under doh, use only the resolver-level option", id)
	}
	seconds := r.IdleTimeout
	if r.DoH.IdleTimeout != 0 {
		rdns.Log.Warn("doh = { idle-timeout } is deprecated, use the resolver-level idle-timeout", "id", id)
		seconds = r.DoH.IdleTimeout
	}
	if seconds < 0 {
		return 0, fmt.Errorf("resolver '%s': idle-timeout must not be negative", id)
	}
	return time.Duration(seconds) * time.Second, nil
}

// parsePSK turns the hex-encoded psk options into an rdns.PSK, or nil when no
// key is configured. An identity without a key is a config error rather than a
// silently ignored option.
func parsePSK(key, identity string) (*rdns.PSK, error) {
	if key == "" {
		if identity != "" {
			return nil, errors.New("psk-identity requires psk to be set")
		}
		return nil, nil
	}
	b, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("psk must be hex-encoded: %w", err)
	}
	if len(b) == 0 {
		return nil, errors.New("psk must not be empty")
	}
	return &rdns.PSK{Key: b, Identity: identity}, nil
}

// Instantiates an rdns.Resolver from a resolver config
func instantiateResolver(id string, r resolver, resolvers map[string]rdns.Resolver) error {
	var err error

	netns, err := buildNetNS(r.NetNS, r.XSocket)
	if err != nil {
		return fmt.Errorf("resolver '%s': %w", id, err)
	}

	idle, err := idleTimeout(id, r)
	if err != nil {
		return err
	}

	sockOpts := rdns.SocketOptions{
		FWMark:        r.FWMark,
		BindInterface: r.BindInterface,
	}

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
			LocalAddrV4:   net.ParseIP(r.LocalAddrV4),
			LocalAddrV6:   net.ParseIP(r.LocalAddrV6),
			TLSConfig:     tlsConfig,
			QueryTimeout:  time.Duration(r.QueryTimeout) * time.Second,
			IdleTimeout:   idle,
			Use0RTT:       r.Use0RTT,
			NetNS:         netns,
			SocketOptions: sockOpts,
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
			LocalAddrV4:   net.ParseIP(r.LocalAddrV4),
			LocalAddrV6:   net.ParseIP(r.LocalAddrV6),
			TLSConfig:     tlsConfig,
			QueryTimeout:  time.Duration(r.QueryTimeout) * time.Second,
			IdleTimeout:   idle,
			Dialer:        socks5DialerFromConfig(r, netns, sockOpts),
			NetNS:         netns,
			SocketOptions: sockOpts,
		}
		resolvers[id], err = rdns.NewDoTClient(id, r.Address, opt)
		if err != nil {
			return err
		}
	case "dtls":
		r.Address = rdns.AddressWithDefault(r.Address, rdns.DTLSPort)

		psk, err := parsePSK(r.PSK, r.PSKIdentity)
		if err != nil {
			return fmt.Errorf("resolver '%s': %w", id, err)
		}
		dtlsConfig, err := rdns.DTLSClientConfig(r.CA, r.ClientCrt, r.ClientKey, psk)
		if err != nil {
			return fmt.Errorf("resolver '%s': %w", id, err)
		}
		opt := rdns.DTLSClientOptions{
			BootstrapAddr: r.BootstrapAddr,
			LocalAddr:     net.ParseIP(r.LocalAddr),
			LocalAddrV4:   net.ParseIP(r.LocalAddrV4),
			LocalAddrV6:   net.ParseIP(r.LocalAddrV6),
			DTLSConfig:    dtlsConfig,
			UDPSize:       r.EDNS0UDPSize,
			QueryTimeout:  time.Duration(r.QueryTimeout) * time.Second,
			IdleTimeout:   idle,
			NetNS:         netns,
			SocketOptions: sockOpts,
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
			LocalAddrV4:   net.ParseIP(r.LocalAddrV4),
			LocalAddrV6:   net.ParseIP(r.LocalAddrV6),
			QueryTimeout:  time.Duration(r.QueryTimeout) * time.Second,
			IdleTimeout:   idle,
			Dialer:        socks5DialerFromConfig(r, netns, sockOpts),
			Use0RTT:       r.Use0RTT,
			NetNS:         netns,
			SocketOptions: sockOpts,
		}
		resolvers[id], err = rdns.NewDoHClient(id, r.Address, opt)
		if err != nil {
			return err
		}
	case "odoh":
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
			LocalAddrV4:   net.ParseIP(r.LocalAddrV4),
			LocalAddrV6:   net.ParseIP(r.LocalAddrV6),
			QueryTimeout:  time.Duration(r.QueryTimeout) * time.Second,
			IdleTimeout:   idle,
			NetNS:         netns,
			SocketOptions: sockOpts,
		}
		resolvers[id], err = rdns.NewODoHClient(id, r.Address, r.Target, r.TargetConfig, opt)
		if err != nil {
			return err
		}
	case "tcp", "udp":
		r.Address = rdns.AddressWithDefault(r.Address, rdns.PlainDNSPort)

		opt := rdns.DNSClientOptions{
			LocalAddr:     net.ParseIP(r.LocalAddr),
			LocalAddrV4:   net.ParseIP(r.LocalAddrV4),
			LocalAddrV6:   net.ParseIP(r.LocalAddrV6),
			UDPSize:       r.EDNS0UDPSize,
			QueryTimeout:  time.Duration(r.QueryTimeout) * time.Second,
			IdleTimeout:   idle,
			Dialer:        socks5DialerFromConfig(r, netns, sockOpts),
			NetNS:         netns,
			SocketOptions: sockOpts,
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

// Returns a dialer if a socks5 proxy is configured, nil otherwise. The netns
// and socket options are used for the connection to the proxy itself.
func socks5DialerFromConfig(cfg resolver, netns *rdns.NetNS, sockOpts rdns.SocketOptions) rdns.Dialer {
	if cfg.Socks5Address == "" {
		return nil
	}
	r := rdns.NewSocks5Dialer(
		cfg.Socks5Address,
		rdns.Socks5DialerOptions{
			Username:      cfg.Socks5Username,
			Password:      cfg.Socks5Password,
			TCPTimeout:    0,
			UDPTimeout:    5 * time.Second,
			ResolveLocal:  cfg.Socks5ResolveLocal,
			LocalAddr:     net.ParseIP(cfg.LocalAddr),
			LocalAddrV4:   net.ParseIP(cfg.LocalAddrV4),
			LocalAddrV6:   net.ParseIP(cfg.LocalAddrV6),
			NetNS:         netns,
			SocketOptions: sockOpts,
		})
	return r
}
