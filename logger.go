package rdns

import (
	"context"
	"log/slog"
	"runtime"
	"slices"
	"time"

	"github.com/miekg/dns"
)

// Log is a package-global logger used throughout the library. Configuration can be
// changed directly on this instance or the instance replaced.
var Log = slog.Default()

// queryLogger holds the per-query log context and renders it only once a level
// check has passed. Attributes are stored rather than formatted, so a call that
// ends up being suppressed costs nothing beyond the level check. Every record
// carries the full query context regardless of level, so Warn and Error
// identify the query they refer to even when debug logging is off.
//
// The context is whatever the component already has in hand: its own id, the
// query, and the ClientInfo threaded through every Resolve. The listener half
// of it (protocol, listener address, DoH path) comes from ClientInfo, so a
// listener logs through this type exactly as a resolver does.
//
// Attributes with no value are omitted: a nil query drops qtype and qname,
// which is what connection-scoped records logged before a query is read look
// like, and the three listener attributes are absent for queries that no
// listener produced.
type queryLogger struct {
	// Destination, resolved when the logger is created so that a record and
	// the level check that admitted it always go to the same logger. Falls
	// back to Log when unset.
	dst *slog.Logger

	id string
	q  *dns.Msg
	ci ClientInfo

	// Additional attributes from With, in slog's alternating key/value form
	// (slog.Attr values are also accepted, as by slog.Logger.With).
	extra []any
}

func logger(id string, q *dns.Msg, ci ClientInfo) queryLogger {
	return queryLogger{dst: Log, id: id, q: q, ci: ci}
}

// With returns a copy of the logger with additional attributes appended.
func (l queryLogger) With(args ...any) queryLogger {
	if len(args) == 0 {
		return l
	}
	// Clip so the append allocates rather than writing into an array shared
	// with the receiver. Callers keep logging through the value they called
	// With on, which must not see the attributes added to the copy.
	l.extra = append(slices.Clip(l.extra), args...)
	return l
}

func (l queryLogger) Debug(msg string, args ...any) { l.log(slog.LevelDebug, msg, args...) }
func (l queryLogger) Info(msg string, args ...any)  { l.log(slog.LevelInfo, msg, args...) }
func (l queryLogger) Warn(msg string, args ...any)  { l.log(slog.LevelWarn, msg, args...) }
func (l queryLogger) Error(msg string, args ...any) { l.log(slog.LevelError, msg, args...) }

func (l queryLogger) log(level slog.Level, msg string, args ...any) {
	dst := l.dst
	if dst == nil {
		dst = Log
	}
	ctx := context.Background()
	if !dst.Enabled(ctx, level) {
		return
	}

	r := newRecord(level, msg)
	r.Add(slog.String("id", l.id), slog.Any("client", l.ci.SourceIP))
	if l.q != nil {
		r.Add(slog.String("qtype", qTypeName(l.q)), slog.String("qname", qName(l.q)))
	}
	if l.ci.Protocol != "" {
		r.Add(slog.String("protocol", l.ci.Protocol))
	}
	if l.ci.ListenerAddr != "" {
		r.Add(slog.String("addr", l.ci.ListenerAddr))
	}
	if l.ci.DoHPath != "" {
		r.Add(slog.String("path", l.ci.DoHPath))
	}
	r.Add(l.extra...)
	r.Add(args...)
	_ = dst.Handler().Handle(ctx, r)
}

// Builds a record carrying the PC of the code that called the Debug/Info/Warn/
// Error method, for handlers configured with AddSource. Skips runtime.Callers,
// this function, the log method, and that wrapper.
func newRecord(level slog.Level, msg string) slog.Record {
	var pcs [1]uintptr
	runtime.Callers(4, pcs[:])
	return slog.NewRecord(time.Now(), level, msg, pcs[0])
}

// Returns the string representation of the query type, rendering types with no
// registered name as "TYPE<n>". qType returns an empty string for those.
func qTypeName(q *dns.Msg) string {
	if len(q.Question) == 0 {
		return ""
	}
	return dns.Type(q.Question[0].Qtype).String()
}
