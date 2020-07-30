package rdns

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// DoQListener is a DNS listener/server for QUIC.
type DoQListener struct {
	id   string
	addr string
	r    Resolver
	opt  DoQListenerOptions
	ln   quic.Listener
	log  *logrus.Entry

	expSession  *varMap // Transport query was received over.
	expStream   *varInt // Number of streams seen in all sessions.
	expError    *varMap // RouteDNS failure reason.
	expResponse *varMap // DNS response code.
	expDrop     *varInt // Number of queries dropped internally.
}

var _ Listener = &DoQListener{}

// DoQListenerOptions contains options used by the QUIC server.
type DoQListenerOptions struct {
	ListenOptions

	TLSConfig *tls.Config
}

// NewQuicListener returns an instance of a QUIC listener.
func NewQUICListener(id, addr string, opt DoQListenerOptions, resolver Resolver) *DoQListener {
	if opt.TLSConfig == nil {
		opt.TLSConfig = new(tls.Config)
	}
	opt.TLSConfig.NextProtos = []string{"dq"}
	l := &DoQListener{
		id:          id,
		addr:        addr,
		r:           resolver,
		opt:         opt,
		log:         Log.WithFields(logrus.Fields{"id": id, "protocol": "doq", "addr": addr}),
		expSession:  getVarMap("listener", id, "session"),
		expStream:   getVarInt("listener", id, "stream"),
		expResponse: getVarMap("listener", id, "response"),
		expError:    getVarMap("listener", id, "error"),
		expDrop:     getVarInt("listener", id, "drop"),
	}
	return l
}

// Start the QUIC server.
func (s DoQListener) Start() error {
	var err error
	s.ln, err = quic.ListenAddr(s.addr, s.opt.TLSConfig, &quic.Config{})
	if err != nil {
		return err
	}
	s.log.Info("starting listener")

	for {
		session, err := s.ln.Accept(context.Background())
		if err != nil {
			s.log.WithError(err).Warn("failed to accept")
			continue
		}
		s.log.Trace("started session")

		go func() {
			s.handleSession(session)
			_ = session.CloseWithError(quic.ErrorCode(DOQNoError), "")
			s.log.Trace("closing session")
		}()
	}
}

// Stop the server.
func (s DoQListener) Stop() error {
	Log.WithFields(logrus.Fields{"protocol": "quic", "addr": s.addr}).Info("stopping listener")
	return s.ln.Close()
}

func (s DoQListener) handleSession(session quic.Session) {
	var ci ClientInfo
	switch addr := session.RemoteAddr().(type) {
	case *net.TCPAddr:
		s.expSession.Add("tcp", 1)
		ci.SourceIP = addr.IP
	case *net.UDPAddr:
		s.expSession.Add("udp", 1)
		ci.SourceIP = addr.IP
	}
	log := s.log.WithField("client", session.RemoteAddr())

	if !isAllowed(s.opt.AllowedNet, ci.SourceIP) {
		log.Debug("rejecting incoming session")
		s.expDrop.Add(1)
		return
	}
	log.Trace("accepting incoming session")

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) // TODO: configurable
		stream, err := session.AcceptStream(ctx)
		if err != nil {
			cancel()
			break
		}
		log.WithField("stream", stream.StreamID()).Trace("opening stream")
		s.expStream.Add(1)
		go func() {
			s.handleStream(stream, log, ci)
			cancel()
			log.WithField("stream", stream.StreamID()).Trace("closing stream")
		}()
	}
}

func (s DoQListener) handleStream(stream quic.Stream, log *logrus.Entry, ci ClientInfo) {
	// DNS over QUIC uses one stream per query/response.
	defer stream.Close()

	// Read the raw query
	_ = stream.SetReadDeadline(time.Now().Add(time.Second)) // TODO: configurable timeout
	b, err := ioutil.ReadAll(stream)
	if err != nil {
		s.expError.Add("read", 1)
		log.WithError(err).Error("failed to read query")
		return
	}

	// Decode the query
	q := new(dns.Msg)
	if err := q.Unpack(b); err != nil {
		s.expError.Add("unpack", 1)
		log.WithError(err).Error("failed to decode query")
		return
	}
	log = log.WithField("qname", qName(q))
	log.Debug("received query")

	// Receiving a edns-tcp-keepalive EDNS(0) option is a fatal error according to the RFC
	edns0 := q.IsEdns0()
	if edns0 != nil {
		for _, opt := range edns0.Option {
			if opt.Option() == dns.EDNS0TCPKEEPALIVE {
				log.Error("received edns-tcp-keepalive, aborting")
				s.expError.Add("keepalive", 1)
				return
			}
		}
	}

	// Resolve the query using the next hop
	a, err := s.r.Resolve(q, ci)
	if err != nil {
		log.WithError(err).Error("failed to resolve")
		a = new(dns.Msg)
		a.SetRcode(q, dns.RcodeServerFailure)
	}
	s.expResponse.Add(dns.RcodeToString[a.Rcode], 1)

	out, err := a.Pack()
	if err != nil {
		log.WithError(err).Error("failed to encode response")
		s.expError.Add("encode", 1)
		return
	}

	// Send the response
	_ = stream.SetWriteDeadline(time.Now().Add(time.Second)) // TODO: configurable timeout
	if _, err = stream.Write(out); err != nil {
		s.expError.Add("send", 1)
		log.WithError(err).Error("failed to send response")
	}
}

func (s DoQListener) String() string {
	return s.id
}
