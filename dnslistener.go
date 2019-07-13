package rdns

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// DNSListener is a standard DNS listener for UDP or TCP.
type DNSListener struct {
	*dns.Server
}

var _ Listener = &DNSListener{}

// NewDNSListener returns an instance of either a UDP or TCP DNS listener.
func NewDNSListener(addr, net string, resolver Resolver) *DNSListener {
	return &DNSListener{
		Server: &dns.Server{
			Addr:    addr,
			Net:     net,
			Handler: listenHandler(resolver),
		},
	}
}

// Start the DNS listener.
func (s DNSListener) Start() error {
	return s.ListenAndServe()
}

func (s DNSListener) String() string {
	return fmt.Sprintf("%s(%s)", s.Net, s.Addr)
}

// DNS handler to forward all incoming requests to a given resolver.
func listenHandler(r Resolver) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		Log.Printf("received query for '%s' forwarded to %s", qName(req), r.String())
		var ci ClientInfo
		switch addr := w.RemoteAddr().(type) {
		case *net.TCPAddr:
			ci.SourceIP = addr.IP
		case *net.UDPAddr:
			ci.SourceIP = addr.IP
		}
		a, err := r.Resolve(req, ci)
		if err != nil {
			Log.Printf("failed to resolve '%s' : %s", qName(req), err)
			a = new(dns.Msg)
			a.SetRcode(req, dns.RcodeServerFailure)
		}
		w.WriteMsg(a)
	}
}
