package rdns

import (
	"crypto/tls"
	"net"

	"github.com/miekg/dns"
)

// DNSListener is a standard DNS listener for UDP or TCP.
type DNSListener struct {
	*dns.Server
	id string
}

var _ Listener = &DNSListener{}

type ListenOptions struct {
	// Network allowed to query this listener.
	AllowedNet []*net.IPNet
}

// NewDNSListener returns an instance of either a UDP or TCP DNS listener.
func NewDNSListener(id, addr, net string, opt ListenOptions, resolver Resolver) *DNSListener {
	return &DNSListener{
		id: id,
		Server: &dns.Server{
			Addr:    addr,
			Net:     net,
			Handler: listenHandler(id, net, addr, resolver, opt.AllowedNet),
		},
	}
}

// Start the DNS listener.
func (s DNSListener) Start() error {
	Log.Info("starting listener", "id", s.id, "protocol", s.Net, "addr", s.Addr)
	return s.ListenAndServe()
}

func (s DNSListener) String() string {
	return s.id
}

// DNS handler to forward all incoming requests to a given resolver.
func listenHandler(id, protocol, addr string, r Resolver, allowedNet []*net.IPNet) dns.HandlerFunc {
	metrics := NewListenerMetrics("listener", id)
	return func(w dns.ResponseWriter, req *dns.Msg) {
		var err error

		ci := ClientInfo{
			Listener: id,
		}

		if r, ok := w.(interface{ ConnectionState() *tls.ConnectionState }); ok {
			connState := r.ConnectionState()
			if connState != nil {
				ci.TLSServerName = connState.ServerName
			}
		}

		switch addr := w.RemoteAddr().(type) {
		case *net.TCPAddr:
			ci.SourceIP = addr.IP
		case *net.UDPAddr:
			ci.SourceIP = addr.IP
		}

		log := Log.With(
			"id", id,
			"client", ci.SourceIP,
			"qname", qName(req),
			"protocol", protocol,
			"addr", addr,
		)
		log.Debug("received query")
		metrics.query.Add(1)

		a := new(dns.Msg)
		if isAllowed(allowedNet, ci.SourceIP) {
			log.With("resolver", r.String()).Debug("forwarding query to resolver")
			a, err = r.Resolve(req, ci)
			if err != nil {
				metrics.err.Add("resolve", 1)
				log.Error("failed to resolve", "error", err)
				a = servfail(req)
			}
		} else {
			metrics.err.Add("acl", 1)
			log.Debug("refusing client ip")
			a.SetRcode(req, dns.RcodeRefused)
		}

		// A nil response from the resolvers means "drop", close the connection
		if a == nil {
			w.Close()
			metrics.drop.Add(1)
			return
		}

		// If the client asked via DoT and EDNS0 is enabled, the response should be padded for extra security.
		// See rfc7830 and rfc8467.
		if protocol == "dot" || protocol == "dtls" {
			padAnswer(req, a)
		} else {
			stripPadding(a)
		}

		// Check the response actually fits if the query was sent over UDP. If not, respond with TC flag.
		if protocol == "udp" || protocol == "dtls" {
			maxSize := dns.MinMsgSize
			if edns0 := req.IsEdns0(); edns0 != nil {
				maxSize = int(edns0.UDPSize())
			}
			a.Truncate(maxSize)
		}

		metrics.response.Add(rCode(a), 1)
		_ = w.WriteMsg(a)
	}
}

func isAllowed(allowedNet []*net.IPNet, ip net.IP) bool {
	if len(allowedNet) == 0 {
		return true
	}
	for _, net := range allowedNet {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}
