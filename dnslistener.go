package rdns

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// DNSListener is a standard DNS listener for UDP or TCP.
type DNSListener struct {
	*dns.Server
}

var _ Listener = &DNSListener{}

type ListenOptions struct {
	// Network allowed to query this listener.
	AllowedNet []*net.IPNet
}

// NewDNSListener returns an instance of either a UDP or TCP DNS listener.
func NewDNSListener(addr, net string, opt ListenOptions, resolver Resolver) *DNSListener {
	return &DNSListener{
		Server: &dns.Server{
			Addr:    addr,
			Net:     net,
			Handler: listenHandler(net, addr, resolver, opt.AllowedNet),
		},
	}
}

// Start the DNS listener.
func (s DNSListener) Start() error {
	Log.WithFields(logrus.Fields{"protocol": s.Net, "addr": s.Addr}).Info("starting listener")
	return s.ListenAndServe()
}

func (s DNSListener) String() string {
	return fmt.Sprintf("%s(%s)", s.Net, s.Addr)
}

// DNS handler to forward all incoming requests to a given resolver.
func listenHandler(protocol, addr string, r Resolver, allowedNet []*net.IPNet) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		var (
			ci  ClientInfo
			err error
		)

		switch addr := w.RemoteAddr().(type) {
		case *net.TCPAddr:
			ci.SourceIP = addr.IP
		case *net.UDPAddr:
			ci.SourceIP = addr.IP
		}

		log := Log.WithFields(logrus.Fields{"client": ci.SourceIP, "qname": qName(req), "protocol": protocol, "addr": addr})
		log.Debug("received query")

		a := new(dns.Msg)
		if isAllowed(allowedNet, ci.SourceIP) {
			log.WithField("resolver", r.String()).Trace("forwarding query to resolver")
			a, err = r.Resolve(req, ci)
			if err != nil {
				log.WithError(err).Error("failed to resolve")
				a = new(dns.Msg)
				a.SetRcode(req, dns.RcodeServerFailure)
			}
		} else {
			log.Debug("refusing client ip")
			a.SetRcode(req, dns.RcodeRefused)
		}

		// If the client asked via DoT and EDNS0 is enabled, the response should be padded for extra security.
		// See rfc7830 and rfc8467.
		if protocol == "dot" || protocol == "dtls" {
			padAnswer(req, a)
		} else {
			stripPadding(a)
		}
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
