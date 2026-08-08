package rdns

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func testQuery() *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion("www.example.com.", dns.TypeA)
	return q
}

// Returns a logger writing to a buffer, dropping the timestamp so records can
// be compared directly. The package-global Log is deliberately left alone:
// background refresh goroutines started by other tests read it without
// synchronisation (client-blocklist.go), so writing it here would race.
func captureLog(t *testing.T, level slog.Level, opts ...func(*slog.HandlerOptions)) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	buf := new(bytes.Buffer)
	o := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}
	for _, f := range opts {
		f(o)
	}
	return slog.New(slog.NewTextHandler(buf, o)), buf
}

// A queryLogger as logger() builds it, but pointed at the test's logger.
func testQueryLogger(dst *slog.Logger, id string, q *dns.Msg, ci ClientInfo) queryLogger {
	l := logger(id, q, ci)
	l.dst = dst
	return l
}

// Records must be identical to what slog.Logger.With produces for the same
// query context, covering the attribute set, their values and their order.
// slog is the definition of the output format here, so it is used as the
// oracle rather than a golden string: an attribute added to or reordered in
// queryLogger.log fails this.
func TestQueryLoggerMatchesSlogWith(t *testing.T) {
	q := testQuery()
	ci := ClientInfo{SourceIP: []byte{192, 168, 1, 5}, Listener: "listener1"}

	tests := []struct {
		name   string
		emit   func(l queryLogger)
		oracle func(l *slog.Logger)
	}{
		{
			name:   "plain message",
			emit:   func(l queryLogger) { l.Debug("cache-hit") },
			oracle: func(l *slog.Logger) { l.Debug("cache-hit") },
		},
		{
			name:   "key/value args",
			emit:   func(l queryLogger) { l.Debug("forwarding", "resolver", "upstream") },
			oracle: func(l *slog.Logger) { l.Debug("forwarding", "resolver", "upstream") },
		},
		{
			name:   "slog.Attr args",
			emit:   func(l queryLogger) { l.Warn("failed", slog.String("error", "boom")) },
			oracle: func(l *slog.Logger) { l.Warn("failed", slog.String("error", "boom")) },
		},
		{
			name:   "With then log",
			emit:   func(l queryLogger) { l.With("resolver", "upstream").Debug("forwarding") },
			oracle: func(l *slog.Logger) { l.With("resolver", "upstream").Debug("forwarding") },
		},
		{
			name: "chained With",
			emit: func(l queryLogger) {
				l.With(slog.String("list", "l1")).With(slog.String("rule", "r1")).Debug("blocking")
			},
			oracle: func(l *slog.Logger) {
				l.With(slog.String("list", "l1")).With(slog.String("rule", "r1")).Debug("blocking")
			},
		},
		{
			name:   "With plus call args",
			emit:   func(l queryLogger) { l.With("list", "l1").Debug("blocking", "rule", "r1") },
			oracle: func(l *slog.Logger) { l.With("list", "l1").Debug("blocking", "rule", "r1") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst, buf := captureLog(t, slog.LevelDebug)
			tt.emit(testQueryLogger(dst, "resolver1", q, ci))
			got := buf.String()

			buf.Reset()
			tt.oracle(dst.With(
				slog.String("id", "resolver1"),
				slog.Any("client", ci.SourceIP),
				slog.String("qtype", dns.Type(q.Question[0].Qtype).String()),
				slog.String("qname", qName(q)),
			))
			require.Equal(t, buf.String(), got)
		})
	}
}

// Suppressing debug records must not cost the query context on the records
// that do get emitted: a Warn at info level still identifies its query.
func TestQueryLoggerKeepsContextWhenDebugDisabled(t *testing.T) {
	dst, buf := captureLog(t, slog.LevelInfo)
	q := testQuery()
	ci := ClientInfo{SourceIP: []byte{10, 0, 0, 1}}

	log := testQueryLogger(dst, "resolver1", q, ci)
	log.Debug("suppressed")
	require.Empty(t, buf.String(), "debug record must not be emitted at info level")

	log.Warn("failed to resolve", "error", "boom")
	out := buf.String()
	require.Contains(t, out, "id=resolver1")
	require.Contains(t, out, "client=10.0.0.1")
	require.Contains(t, out, "qtype=A")
	require.Contains(t, out, "qname=www.example.com.")
	require.Contains(t, out, "error=boom")
}

// With returns an independent value; attributes added to the copy must not
// appear on records emitted through the logger it was derived from.
func TestQueryLoggerWithDoesNotMutateReceiver(t *testing.T) {
	dst, buf := captureLog(t, slog.LevelDebug)
	base := testQueryLogger(dst, "resolver1", testQuery(), ClientInfo{})

	withList := base.With("list", "l1")
	branchA := withList.With("rule", "a")
	branchB := withList.With("rule", "b")

	branchA.Debug("first")
	branchB.Debug("second")
	base.Debug("third")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 3)
	require.Contains(t, lines[0], "list=l1")
	require.Contains(t, lines[0], "rule=a")
	require.Contains(t, lines[1], "list=l1")
	require.Contains(t, lines[1], "rule=b")
	require.NotContains(t, lines[1], "rule=a")
	require.NotContains(t, lines[2], "list=l1")
	require.NotContains(t, lines[2], "rule=")
}

// Two loggers derived from the same value must not share the array their
// attributes live in. append only reuses spare capacity, which the sizes the
// natural call sites produce happen not to have, so the condition is set up
// explicitly here.
func TestQueryLoggerWithDoesNotShareSpareCapacity(t *testing.T) {
	dst, buf := captureLog(t, slog.LevelDebug)

	base := testQueryLogger(dst, "resolver1", testQuery(), ClientInfo{})
	base.extra = append(make([]any, 0, 8), "list", "l1")
	require.Greater(t, cap(base.extra), len(base.extra), "test needs spare capacity to be meaningful")

	branchA := base.With("rule", "a")
	branchB := base.With("rule", "b")

	// Emitted after both derivations, so a shared array shows up as branchB
	// having overwritten branchA's attribute.
	branchA.Debug("first")
	branchB.Debug("second")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], "rule=a")
	require.Contains(t, lines[1], "rule=b")
}

// A handler with AddSource must report the caller, not this package's logger.
func TestQueryLoggerReportsCallerSource(t *testing.T) {
	dst, buf := captureLog(t, slog.LevelDebug, func(o *slog.HandlerOptions) { o.AddSource = true })
	testQueryLogger(dst, "resolver1", testQuery(), ClientInfo{}).Debug("here")

	out := buf.String()
	require.Contains(t, out, "logger_test.go", "source should point at the call site")
	require.NotContains(t, out, "logger.go:", "source must not point at the logging helper")
}

// The question section is read when a record is emitted, so a query without
// one must not panic there.
func TestQueryLoggerEmptyQuestion(t *testing.T) {
	dst, buf := captureLog(t, slog.LevelDebug)
	require.NotPanics(t, func() {
		testQueryLogger(dst, "resolver1", new(dns.Msg), ClientInfo{}).Debug("no question")
	})
	require.Contains(t, buf.String(), "qname=")
}

// A listener logs through the same type, with its protocol, bind address and
// DoH path coming from ClientInfo. The attribute order is part of the output,
// so this pins it for each listener shape.
func TestQueryLoggerListenerContext(t *testing.T) {
	q := testQuery()
	clientIP := net.IP{192, 168, 1, 5}

	tests := []struct {
		name string
		ci   ClientInfo
		want []any
	}{
		{
			name: "plain dns listener",
			ci: ClientInfo{
				SourceIP: clientIP, Listener: "listener1",
				Protocol: "udp", ListenerAddr: ":53",
			},
			want: []any{
				slog.String("id", "listener1"), slog.Any("client", clientIP),
				slog.String("qtype", "A"), slog.String("qname", "www.example.com."),
				slog.String("protocol", "udp"), slog.String("addr", ":53"),
			},
		},
		{
			name: "doh listener carries the path",
			ci: ClientInfo{
				SourceIP: clientIP, Listener: "doh1", DoHPath: "/dns-query",
				Protocol: "doh", ListenerAddr: ":443",
			},
			want: []any{
				slog.String("id", "doh1"), slog.Any("client", clientIP),
				slog.String("qtype", "A"), slog.String("qname", "www.example.com."),
				slog.String("protocol", "doh"), slog.String("addr", ":443"),
				slog.String("path", "/dns-query"),
			},
		},
		{
			name: "resolver has no listener context",
			ci:   ClientInfo{SourceIP: clientIP},
			want: []any{
				slog.String("id", "resolver1"), slog.Any("client", clientIP),
				slog.String("qtype", "A"), slog.String("qname", "www.example.com."),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := tt.want[0].(slog.Attr).Value.String()
			dst, buf := captureLog(t, slog.LevelDebug)
			testQueryLogger(dst, id, q, tt.ci).Debug("received query")
			got := buf.String()

			buf.Reset()
			dst.With(tt.want...).Debug("received query")
			require.Equal(t, buf.String(), got)
		})
	}
}

// Connection-scoped records, logged before a query has been read, carry the
// listener context without empty qtype and qname attributes.
func TestQueryLoggerNilQueryOmitsQuestion(t *testing.T) {
	ci := ClientInfo{
		SourceIP: net.IP{192, 168, 1, 5}, Listener: "doq1",
		Protocol: "doq", ListenerAddr: ":853",
	}
	dst, buf := captureLog(t, slog.LevelDebug)
	testQueryLogger(dst, "doq1", nil, ci).Debug("accepting incoming connection")

	out := buf.String()
	require.Contains(t, out, "id=doq1")
	require.Contains(t, out, "protocol=doq")
	require.Contains(t, out, "addr=:853")
	require.NotContains(t, out, "qtype=")
	require.NotContains(t, out, "qname=")
}

// A query that unpacked but carries no question keeps the attributes, empty,
// so the record still shows a query was involved.
func TestQueryLoggerEmptyQuestionKeepsAttributes(t *testing.T) {
	dst, buf := captureLog(t, slog.LevelDebug)
	testQueryLogger(dst, "listener1", new(dns.Msg), ClientInfo{Protocol: "udp"}).
		Warn("dropping query with no Question section")

	out := buf.String()
	require.Contains(t, out, "qtype=")
	require.Contains(t, out, "qname=")
	require.Contains(t, out, "protocol=udp")
}

// The listener path must stay allocation-free too, which is what folding the
// listener attributes into ClientInfo buys over holding them as a slice.
func TestQueryLoggerListenerSuppressedCallDoesNotAllocate(t *testing.T) {
	dst, _ := captureLog(t, slog.LevelInfo)
	q := testQuery()
	ci := ClientInfo{
		SourceIP: net.IP{192, 168, 1, 5}, Listener: "doh1", DoHPath: "/dns-query",
		Protocol: "doh", ListenerAddr: ":443",
	}

	allocs := testing.AllocsPerRun(100, func() {
		log := testQueryLogger(dst, "doh1", q, ci)
		log.Debug("received query")
	})
	require.Zero(t, allocs)
}

// A call whose level is not enabled must do no work beyond the level check.
func TestQueryLoggerSuppressedCallDoesNotAllocate(t *testing.T) {
	dst, _ := captureLog(t, slog.LevelInfo)
	q := testQuery()
	ci := ClientInfo{SourceIP: []byte{10, 0, 0, 1}}

	allocs := testing.AllocsPerRun(100, func() {
		log := testQueryLogger(dst, "resolver1", q, ci)
		log.Debug("cache-hit")
		log.Debug("forwarding", "resolver", "upstream")
	})
	require.Zero(t, allocs)
}
