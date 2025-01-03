package rdns

import (
	"log/slog"

	"github.com/miekg/dns"
)

// Log is a package-global logger used throughout the library. Configuration can be
// changed directly on this instance or the instance replaced.
var Log = slog.Default()

func logger(id string, q *dns.Msg, ci ClientInfo) *slog.Logger {
	return Log.With(
		slog.String("id", id),
		slog.Any("client", ci.SourceIP),
		slog.String("qtype", dns.Type(q.Question[0].Qtype).String()),
		slog.String("qname", qName(q)),
	)
}
