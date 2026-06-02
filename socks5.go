package rdns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/txthinking/socks5"
)

type Socks5Dialer struct {
	*socks5.Client
	opt Socks5DialerOptions

	once sync.Once
	addr string
}

type Socks5DialerOptions struct {
	Username    string
	Password    string
	UDPTimeout  time.Duration
	TCPTimeout  time.Duration
	LocalAddr   net.IP
	LocalAddrV4 net.IP
	LocalAddrV6 net.IP

	// When the resolver is configured with a name, not an IP, e.g. one.one.one.one:53
	// this setting will resolve that name locally rather than on the SOCKS proxy. The
	// name will be resolved either on the local system, or via the bootstrap-resolver
	// if one is setup.
	ResolveLocal bool

	// Linux network namespace for the connection to the SOCKS5 proxy. Only the
	// xsocket mechanism is handled here; setns-based namespaces are entered by
	// the caller (which wraps Dial in RunInNetNS). A nil or empty value reaches
	// the proxy from the current namespace.
	NetNS *NetNS

	// Linux socket options (fwmark, interface binding) applied to the socket
	// used to reach the proxy. Only honoured when dialing the proxy via xsocket;
	// other paths apply them around Dial.
	SocketOptions SocketOptions
}

var _ Dialer = (*Socks5Dialer)(nil)

func NewSocks5Dialer(addr string, opt Socks5DialerOptions) *Socks5Dialer {
	client, _ := socks5.NewClient(
		addr,
		opt.Username,
		opt.Password,
		int(opt.TCPTimeout.Seconds()),
		int(opt.UDPTimeout.Seconds()),
	)
	switch {
	case opt.NetNS.usesXSocket():
		// Reach the proxy through an xsocket-server (a network namespace we
		// can't enter with setns) by overriding the client's socket creation.
		// These per-client hooks avoid the process-wide effect of the
		// package-level socks5.DialTCP/DialUDP variables. Socket options are
		// applied to the proxy socket inside dialXSocket.
		path := opt.NetNS.XSocket
		sockOpts := opt.SocketOptions
		client.DialTCP = func(network, laddr, raddr string) (net.Conn, error) {
			return dialXSocket(path, network, raddr, sockOpts, socks5LocalIP(laddr), opt.TCPTimeout)
		}
		client.DialUDP = func(network, laddr, raddr string) (net.Conn, error) {
			return dialXSocket(path, network, raddr, sockOpts, socks5LocalIP(laddr), opt.UDPTimeout)
		}
	case opt.SocketOptions.active():
		// Apply socket options (fwmark, bind-if) when creating the sockets
		// reaching the proxy. They must be set before connect for
		// SO_BINDTODEVICE to affect routing, and post-connect application
		// isn't possible anyway: the socks5 client conn doesn't expose the
		// underlying descriptor.
		client.DialTCP = socks5SockOptsDialer(opt.SocketOptions, opt.TCPTimeout)
		client.DialUDP = socks5SockOptsDialer(opt.SocketOptions, opt.UDPTimeout)
	}
	return &Socks5Dialer{Client: client, opt: opt}
}

// socks5SockOptsDialer returns a dial hook mirroring the socks5 package's
// default dialers, but applying the socket options at socket creation.
func socks5SockOptsDialer(sockOpts SocketOptions, timeout time.Duration) func(network, laddr, raddr string) (net.Conn, error) {
	return func(network, laddr, raddr string) (net.Conn, error) {
		nd := net.Dialer{Timeout: timeout, Control: sockOpts.dialerControl()}
		if laddr != "" {
			var err error
			if strings.HasPrefix(network, "udp") {
				nd.LocalAddr, err = net.ResolveUDPAddr(network, laddr)
			} else {
				nd.LocalAddr, err = net.ResolveTCPAddr(network, laddr)
			}
			if err != nil {
				return nil, err
			}
		}
		return nd.Dial(network, raddr)
	}
}

func (d *Socks5Dialer) Dial(network string, address string) (net.Conn, error) {
	d.once.Do(func() {
		d.addr = address

		// If the address uses a hostname and ResolveLocal is enabled, lookup
		// the IP for it locally and use that when talking to the proxy going
		// forward. This avoids the DNS server's address leaking out from the
		// proxy.
		if d.opt.ResolveLocal {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				Log.Error("failed to parse socks5 address", "error", err)
				return
			}
			Log.With("addr", host).Debug("resolving dns server locally")
			ip := net.ParseIP(host)
			if ip != nil {
				// Already an IP
				return
			}
			timeout := d.opt.UDPTimeout
			if timeout == 0 {
				timeout = 5 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
			if err != nil {
				Log.Warn("failed to lookup host locally", "error", err,
					"host", host)
				return
			}
			if len(ips) == 0 {
				Log.Warn("failed to resolve dns server locally, forwarding to socks5 proxy", "error", err)
				return
			}
			d.addr = net.JoinHostPort(ips[0].String(), port)
		}

	})

	localAddr := selectLocalAddr(d.addr, d.opt.LocalAddr, d.opt.LocalAddrV4, d.opt.LocalAddrV6)
	if localAddr != nil {
		// The socks5 library resolves the source address with
		// net.ResolveTCPAddr, which requires a host:port. Bind the configured
		// local IP with port 0 so the OS picks the source port; a bare IP would
		// fail with "missing port in address".
		src := net.JoinHostPort(localAddr.String(), "0")
		return d.Client.DialWithLocalAddr(network, src, d.addr, nil)
	}
	return d.Client.Dial(network, d.addr)
}

// socks5LocalIP extracts a local bind IP from the address string the socks5
// package passes to its dial hooks. It accepts "ip:port", a bare "ip", or an
// empty string (no binding).
func socks5LocalIP(laddr string) net.IP {
	if laddr == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(laddr); err == nil {
		laddr = host
	}
	return net.ParseIP(laddr)
}
