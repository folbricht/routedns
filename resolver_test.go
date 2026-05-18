package rdns

import (
	"errors"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/miekg/dns"
)

func init() {
	// Silence the logger while running tests
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// TestResolver is a configurable resolver used for testing. It counts the
// number of queries, can be set to fail, and the resolve function can be
// defined externally.
type TestResolver struct {
	ResolveFunc func(*dns.Msg, ClientInfo) (*dns.Msg, error)
	// hitCount is atomic because Fastest (and similar groups) abandon
	// slower resolvers' goroutines, which keep calling Resolve after
	// the group has returned, concurrently with the test reading
	// HitCount().
	hitCount   atomic.Int64
	shouldFail bool
}

func (r *TestResolver) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	r.hitCount.Add(1)
	if r.shouldFail {
		return nil, errors.New("failed")
	}
	if r.ResolveFunc != nil {
		return r.ResolveFunc(q, ci)
	}
	return q, nil
}

func (r *TestResolver) String() string {
	return "TestResolver()"
}

func (r *TestResolver) HitCount() int {
	return int(r.hitCount.Load())
}

func (r *TestResolver) SetFail(f bool) {
	r.shouldFail = f
}
