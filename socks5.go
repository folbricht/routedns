package rdns

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
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

// The underlying socks5 package creates the sockets used to reach the proxy
// itself, via the overridable package-level socks5.DialTCP/DialUDP hooks. To
// reach a proxy through an xsocket-server (a network namespace we can't enter
// with setns), those hooks must be swapped for xsocket-backed dialers for the
// duration of the dial. Since the hooks are process-wide, all socks5 dials are
// serialized through socks5DialMu while any xsocket-backed dialer exists, so a
// swapped-in hook can never leak into an unrelated dial.
var (
	socks5XSocketActive atomic.Bool
	socks5DialMu        sync.Mutex
	socks5DefaultsOnce  sync.Once
	socks5DefaultTCP    func(network, laddr, raddr string) (net.Conn, error)
	socks5DefaultUDP    func(network, laddr, raddr string) (net.Conn, error)
)

func NewSocks5Dialer(addr string, opt Socks5DialerOptions) *Socks5Dialer {
	client, _ := socks5.NewClient(
		addr,
		opt.Username,
		opt.Password,
		int(opt.TCPTimeout.Seconds()),
		int(opt.UDPTimeout.Seconds()),
	)
	if opt.NetNS.usesXSocket() {
		socks5DefaultsOnce.Do(func() {
			socks5DefaultTCP = socks5.DialTCP
			socks5DefaultUDP = socks5.DialUDP
		})
		socks5XSocketActive.Store(true)
	}
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
	dial := func() (net.Conn, error) {
		if localAddr != nil {
			// The socks5 library resolves the source address with
			// net.ResolveTCPAddr, which requires a host:port. Bind the
			// configured local IP with port 0 so the OS picks the source port;
			// a bare IP would fail with "missing port in address".
			src := net.JoinHostPort(localAddr.String(), "0")
			return d.Client.DialWithLocalAddr(network, src, d.addr, nil)
		}
		return d.Client.Dial(network, d.addr)
	}

	// Fast path: no xsocket-backed proxy is configured anywhere, so the global
	// dial hooks are never swapped and don't need to be guarded.
	if !socks5XSocketActive.Load() {
		return dial()
	}

	// Serialize against any concurrent dial that swaps the global hooks.
	socks5DialMu.Lock()
	defer socks5DialMu.Unlock()
	if d.opt.NetNS.usesXSocket() {
		tcp, udp := d.xsocketHooks()
		socks5.DialTCP, socks5.DialUDP = tcp, udp
		defer func() {
			socks5.DialTCP, socks5.DialUDP = socks5DefaultTCP, socks5DefaultUDP
		}()
	}
	return dial()
}

// xsocketHooks returns replacements for socks5.DialTCP/DialUDP that obtain the
// socket reaching the proxy from this dialer's xsocket-server.
func (d *Socks5Dialer) xsocketHooks() (tcp, udp func(network, laddr, raddr string) (net.Conn, error)) {
	path := d.opt.NetNS.XSocket
	opts := d.opt.SocketOptions
	tcp = func(network, laddr, raddr string) (net.Conn, error) {
		return dialXSocket(path, network, raddr, opts, socks5LocalIP(laddr), d.opt.TCPTimeout)
	}
	udp = func(network, laddr, raddr string) (net.Conn, error) {
		return dialXSocket(path, network, raddr, opts, socks5LocalIP(laddr), d.opt.UDPTimeout)
	}
	return tcp, udp
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
