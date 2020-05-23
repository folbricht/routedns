package rdns

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// DoQListener is a DNS listener/server for QUIC.
type DoQListener struct {
	addr string
	r    Resolver
	opt  DoQListenerOptions
	ln   quic.Listener
	log  *logrus.Entry
}

var _ Listener = &DoQListener{}

// DoQListenerOptions contains options used by the QUIC server.
type DoQListenerOptions struct {
	ListenOptions

	TLSConfig *tls.Config
}

// NewQuicListener returns an instance of a QUIC listener.
func NewQUICListener(addr string, opt DoQListenerOptions, resolver Resolver) *DoQListener {
	if opt.TLSConfig == nil {
		opt.TLSConfig = new(tls.Config)
	}
	opt.TLSConfig.NextProtos = []string{"dq"}
	l := &DoQListener{
		addr: addr,
		r:    resolver,
		opt:  opt,
		log:  Log.WithFields(logrus.Fields{"protocol": "doq", "addr": addr}),
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
			_ = session.CloseWithError(quic.ErrorCode(quicErrorNoError), "")
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
		ci.SourceIP = addr.IP
	case *net.UDPAddr:
		ci.SourceIP = addr.IP
	}
	log := s.log.WithField("client", session.RemoteAddr())

	if !isAllowed(s.opt.AllowedNet, ci.SourceIP) {
		log.Trace("rejecting incoming session")
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
		log.WithError(err).Error("failed to read query")
		return
	}

	// Decode the query
	q := new(dns.Msg)
	if err := q.Unpack(b); err != nil {
		log.WithError(err).Error("failed to decode query")
		return
	}
	log = log.WithField("qname", qName(q))
	log.Debug("received query")

	// Resolve the query using the next hop
	a, err := s.r.Resolve(q, ci)
	if err != nil {
		log.WithError(err).Error("failed to resolve")
		a = new(dns.Msg)
		a.SetRcode(q, dns.RcodeServerFailure)
	}

	// Pad the packet according to rfc8467 and rfc7830
	padAnswer(q, a)

	out, err := a.Pack()
	if err != nil {
		log.WithError(err).Error("failed to encode response")
		return
	}

	// Send the response
	_ = stream.SetWriteDeadline(time.Now().Add(time.Second)) // TODO: configurable timeout
	if _, err = stream.Write(out); err != nil {
		log.WithError(err).Error("failed to send response")
	}
}

func (s DoQListener) String() string {
	return fmt.Sprintf("DoQ(%s)", s.addr)
}
