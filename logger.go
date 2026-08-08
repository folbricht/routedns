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

// queryLogger holds the per-query log context (resolver id, client, question)
// and renders it only once a level check has passed. Attributes are stored
// rather than formatted, so a call that ends up being suppressed costs nothing
// beyond the level check. Every record carries the full query context
// regardless of level, so Warn and Error identify the query they refer to even
// when debug logging is off.
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
	r.Add(
		slog.String("id", l.id),
		slog.Any("client", l.ci.SourceIP),
		slog.String("qtype", qTypeName(l.q)),
		slog.String("qname", qName(l.q)),
	)
	r.Add(l.extra...)
	r.Add(args...)
	_ = dst.Handler().Handle(ctx, r)
}

// deferredLogger holds an arbitrary set of attributes and applies them only
// once a level check has passed. It serves the listeners, whose attributes vary
// by protocol and so can't be typed fields the way queryLogger's are; a call
// that is suppressed costs the level check and nothing else, and one that is
// emitted costs the same as slog.Logger.With would have.
//
// Prefer queryLogger for the resolver chain: its fixed attribute set is held in
// typed fields, so it does not allocate at all.
type deferredLogger struct {
	dst *slog.Logger

	// Attributes in slog's alternating key/value form (slog.Attr values are
	// also accepted, as by slog.Logger.With).
	attrs []any
}

func deferredLog(dst *slog.Logger) deferredLogger {
	return deferredLogger{dst: dst}
}

// With returns a copy of the logger with additional attributes appended.
func (l deferredLogger) With(args ...any) deferredLogger {
	if len(args) == 0 {
		return l
	}
	// Clip so the append allocates rather than writing into an array shared
	// with the receiver. Callers keep logging through the value they called
	// With on, which must not see the attributes added to the copy.
	l.attrs = append(slices.Clip(l.attrs), args...)
	return l
}

func (l deferredLogger) Debug(msg string, args ...any) { l.log(slog.LevelDebug, msg, args...) }
func (l deferredLogger) Info(msg string, args ...any)  { l.log(slog.LevelInfo, msg, args...) }
func (l deferredLogger) Warn(msg string, args ...any)  { l.log(slog.LevelWarn, msg, args...) }
func (l deferredLogger) Error(msg string, args ...any) { l.log(slog.LevelError, msg, args...) }

func (l deferredLogger) log(level slog.Level, msg string, args ...any) {
	dst := l.dst
	if dst == nil {
		dst = Log
	}
	ctx := context.Background()
	if !dst.Enabled(ctx, level) {
		return
	}

	r := newRecord(level, msg)
	r.Add(l.attrs...)
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
