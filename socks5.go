package rdns

import (
	"context"
	"net"
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
	Username   string
	Password   string
	UDPTimeout time.Duration
	TCPTimeout time.Duration
	LocalAddr  net.IP

	// When the resolver is configured with a name, not an IP, e.g. one.one.one.one:53
	// this setting will resolve that name locally rather than on the SOCKS proxy. The
	// name will be resolved either on the local system, or via the bootstrap-resolver
	// if one is setup.
	ResolveLocal bool
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
	return &Socks5Dialer{Client: client, opt: opt}
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
				Log.Error("failed to lookup host locally", "error", err,
					"host", host)
				return
			}
			if len(ips) == 0 {
				Log.Error("failed to resolve dns server locally, forwarding to socks5 proxy", "error", err)
				return
			}
			d.addr = net.JoinHostPort(ips[0].String(), port)
		}

	})

	if d.opt.LocalAddr != nil {
		return d.Client.DialWithLocalAddr(network, d.opt.LocalAddr.String(), d.addr, nil)
	}
	return d.Client.Dial(network, d.addr)
}
