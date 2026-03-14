package rdns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/pion/dtls/v3"
)

// DTLSClient is a DNS-over-DTLS resolver.
type DTLSClient struct {
	id       string
	endpoint string
	pipeline *Pipeline // Pipeline also provides operation metrics.
	opt      DTLSClientOptions
}

// DTLSClientOptions contains options used by the DNS-over-DTLS resolver.
type DTLSClientOptions struct {
	// Bootstrap address - IP to use for the service instead of looking up
	// the service's hostname with potentially plain DNS.
	BootstrapAddr string

	// Local IP to use for outbound connections. If nil, a local address is chosen.
	LocalAddr   net.IP
	LocalAddrV4 net.IP
	LocalAddrV6 net.IP

	// Sets the EDNS0 UDP size for all queries sent upstream. If set to 0, queries
	// are not changed.
	UDPSize uint16

	DTLSConfig *dtls.Config

	QueryTimeout time.Duration

	// Linux network namespace for outbound connections.
	NetNS *NetNS

	// Linux socket options for fwmark and interface binding.
	SocketOptions SocketOptions
}

var _ Resolver = &DTLSClient{}

// NewDTLSClient instantiates a new DNS-over-TLS resolver.
func NewDTLSClient(id, endpoint string, opt DTLSClientOptions) (*DTLSClient, error) {
	if err := validEndpoint(endpoint); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	// If a bootstrap address was provided, we need to use the IP for the connection but the
	// hostname in the TLS handshake.
	var ip net.IP
	if opt.BootstrapAddr != "" {
		opt.DTLSConfig.ServerName = host
		ip = net.ParseIP(opt.BootstrapAddr)
		if ip == nil {
			return nil, fmt.Errorf("failed to parse bootstrap address '%s'", opt.BootstrapAddr)
		}
	} else {
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, err
		}
		if len(ips) < 1 {
			return nil, fmt.Errorf("failed to lookup '%s'", host)
		}
		ip = ips[0]
	}
	addr := &net.UDPAddr{IP: ip, Port: p}

	// Select the local address based on the target's address family
	localAddr := opt.LocalAddr
	if ip.To4() != nil && opt.LocalAddrV4 != nil {
		localAddr = opt.LocalAddrV4
	} else if ip.To4() == nil && opt.LocalAddrV6 != nil {
		localAddr = opt.LocalAddrV6
	}
	var laddr *net.UDPAddr
	if localAddr != nil {
		laddr = &net.UDPAddr{IP: localAddr}
	}

	client := &dtlsDialer{
		raddr:         addr,
		laddr:         laddr,
		dtlsConfig:    opt.DTLSConfig,
		netns:         opt.NetNS,
		socketOptions: opt.SocketOptions,
	}
	return &DTLSClient{
		id:       id,
		endpoint: endpoint,
		pipeline: NewPipeline(id, endpoint, client, opt.QueryTimeout),
		opt:      opt,
	}, nil
}

// Resolve a DNS query.
func (d *DTLSClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	// Packing a message is not always a read-only operation, make a copy
	q = q.Copy()

	log := logger(d.id, q, ci)
	log.Debug("querying upstream resolver",
		"resolver", d.endpoint,
		"protocol", "dtls",
	)

	q = setUDPSize(q, d.opt.UDPSize)

	// Add padding to the query before sending over TLS
	padQuery(q)
	return d.pipeline.Resolve(q)
}

func (d *DTLSClient) String() string {
	return d.id
}

type dtlsDialer struct {
	raddr         *net.UDPAddr
	laddr         *net.UDPAddr
	dtlsConfig    *dtls.Config
	netns         *NetNS
	socketOptions SocketOptions
}

func (d dtlsDialer) Dial(address string) (*dns.Conn, error) {
	var pConn net.PacketConn
	err := RunInNetNS(d.netns, func() error {
		laddr := ":0"
		if d.laddr != nil {
			laddr = d.laddr.String()
		}
		lc := net.ListenConfig{Control: d.socketOptions.dialerControl()}
		var e error
		pConn, e = lc.ListenPacket(context.Background(), "udp", laddr)
		return e
	})
	if err != nil {
		return nil, err
	}
	c, err := dtls.Client(pConn, d.raddr, d.dtlsConfig)
	return &dns.Conn{Conn: &dtlsConn{Conn: c}}, err
}
