package rdns

import (
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Log is a package-global logger used throughout the library. Configuration can be
// changed directly on this instance or the instance replaced.
var Log = logrus.New()

func logger(id string, q *dns.Msg, ci ClientInfo) *logrus.Entry {
	return Log.WithFields(logrus.Fields{
		"id":     id,
		"client": ci.SourceIP,
		"qtype":  dns.Type(q.Question[0].Qtype).String(),
		"qname":  qName(q),
	})
}
