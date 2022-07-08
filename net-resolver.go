package rdns

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
)

func NewNetDialer(r Resolver) *net.Dialer {
	return &net.Dialer{
		Resolver: NewNetResolver(r),
	}
}

// NewNetResolver returns a new.Resolver that is backed by a RouteDNS resolver
// instead of the system's.
func NewNetResolver(r Resolver) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return newConn(r, network, address), nil
		},
	}
}

// var _ net.PacketConn = &packetConn{}
var _ net.Conn = &packetConn{}

// packetConn implements net.PacketConn and is used in the Dial() func in a
// net.Resolver to redirect lookups through one of RouteDNS' resolvers instead
// of the system ones.
type packetConn struct {
	network string
	address string
	r       Resolver
	ch      chan *dns.Msg
}

func newConn(r Resolver, network, address string) *packetConn {
	return &packetConn{
		network: network,
		address: address,
		r:       r,
		ch:      make(chan *dns.Msg, 1),
	}
}

func (c *packetConn) Read(p []byte) (n int, err error) {
	a := <-c.ch
	b, err := a.Pack()
	if err != nil {
		return 0, err
	}
	if len(p) < len(b) {
		return 0, errors.New("read buffer too small")
	}
	copy(p, b)
	return len(b), nil
}

// These functions need to exist to implement net.PacketConn as the net.Resolver
// then uses Read/Write in UDP mode. They're not called but need to be present.
func (c *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, nil
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}

func (c *packetConn) Write(p []byte) (n int, err error) {
	// Decode the query
	q := new(dns.Msg)
	if err := q.Unpack(p); err != nil {
		return len(p), err
	}

	a, err := c.r.Resolve(q, ClientInfo{SourceIP: net.IP{127, 0, 0, 1}})
	if err != nil {
		return len(p), err
	}
	c.ch <- a
	return len(p), nil
}

func (c *packetConn) Close() error {
	return nil
}

func (c *packetConn) LocalAddr() net.Addr {
	return nil
}

func (c *packetConn) RemoteAddr() net.Addr {
	return nil
}

func (c *packetConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	return nil
}
