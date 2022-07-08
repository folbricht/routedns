package rdns

import (
	"errors"

	"github.com/miekg/dns"
)

func init() {
	// Silence the logger while running tests
	Log.SetLevel(0)
}

// TestResolver is a configurable resolver used for testing. It counts the
// number of queries, can be set to fail, and the resolve function can be
// defined externally.
type TestResolver struct {
	ResolveFunc func(*dns.Msg, ClientInfo) (*dns.Msg, error)
	hitCount    int
	shouldFail  bool
}

func (r *TestResolver) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	r.hitCount++
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
	return r.hitCount
}

func (r *TestResolver) SetFail(f bool) {
	r.shouldFail = f
}
