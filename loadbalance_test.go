package rdns

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type namedTestResolver struct {
	TestResolver
	name string
}

func (r *namedTestResolver) String() string {
	return r.name
}

func TestLoadBalancePickPrefersLowerAverageRTT(t *testing.T) {
	slowest := &namedTestResolver{name: "slowest"}
	slower := &namedTestResolver{name: "slower"}
	fastest := &namedTestResolver{name: "fastest"}

	g := NewLoadBalance("test-lb", LoadBalanceOptions{}, slowest, slower, fastest)
	g.updateRTT(0, 500*time.Millisecond)
	g.updateRTT(1, 50*time.Millisecond)
	g.updateRTT(2, 5*time.Millisecond)

	counts := map[int]int{}
	remaining := []int{0, 1, 2}
	for range 1000 {
		counts[remaining[g.pick(remaining)]]++
	}

	require.Greater(t, counts[2], counts[1])
	require.Greater(t, counts[1], counts[0])
}

func TestLoadBalanceRetriesOnError(t *testing.T) {
	var ci ClientInfo
	bad := &namedTestResolver{name: "bad"}
	bad.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
		return nil, errors.New("failed")
	}
	good := &namedTestResolver{name: "good"}

	g := NewLoadBalance("test-lb", LoadBalanceOptions{}, bad, good)
	g.randFloat = func() float64 { return 0 }

	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)
	a, err := g.Resolve(q, ci)

	require.NoError(t, err)
	require.NotNil(t, a)
	require.Equal(t, 1, bad.HitCount())
	require.Equal(t, 1, good.HitCount())
	require.Equal(t, float64(defaultLoadBalanceFailurePenalty.Microseconds()), g.stats[0].rttEMA)
}

func TestLoadBalanceFailurePenaltyOption(t *testing.T) {
	var ci ClientInfo
	bad := &namedTestResolver{name: "bad"}
	bad.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
		return nil, errors.New("failed")
	}
	good := &namedTestResolver{name: "good"}

	penalty := 250 * time.Millisecond
	g := NewLoadBalance("test-lb", LoadBalanceOptions{FailurePenalty: penalty}, bad, good)
	g.randFloat = func() float64 { return 0 }

	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)
	_, err := g.Resolve(q, ci)

	require.NoError(t, err)
	require.Equal(t, float64(penalty.Microseconds()), g.stats[0].rttEMA)
}

func TestLoadBalanceSERVFAILOption(t *testing.T) {
	var ci ClientInfo
	opt := StaticResolverOptions{
		RCode: dns.RcodeServerFailure,
	}
	r1, err := NewStaticResolver("test-static", opt)
	require.NoError(t, err)
	r2 := &namedTestResolver{name: "good"}

	g := NewLoadBalance("test-lb", LoadBalanceOptions{ServfailError: true}, r1, r2)
	g.randFloat = func() float64 { return 0 }

	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)
	a, err := g.Resolve(q, ci)

	require.NoError(t, err)
	require.NotEqual(t, dns.RcodeServerFailure, a.Rcode)
	require.Equal(t, 1, r2.HitCount())
}

func TestLoadBalanceReturnsSERVFAILWhenAllowed(t *testing.T) {
	var ci ClientInfo
	opt := StaticResolverOptions{
		RCode: dns.RcodeServerFailure,
	}
	r1, err := NewStaticResolver("test-static", opt)
	require.NoError(t, err)
	r2 := &namedTestResolver{name: "good"}

	g := NewLoadBalance("test-lb", LoadBalanceOptions{}, r1, r2)
	g.randFloat = func() float64 { return 0 }

	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)
	a, err := g.Resolve(q, ci)

	require.NoError(t, err)
	require.Equal(t, dns.RcodeServerFailure, a.Rcode)
	require.Equal(t, 0, r2.HitCount())
}

func TestLoadBalanceEmptyErrorOption(t *testing.T) {
	var ci ClientInfo
	drop := &namedTestResolver{name: "drop"}
	drop.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
		return nil, nil
	}
	good := &namedTestResolver{name: "good"}

	t.Run("Disabled", func(t *testing.T) {
		g := NewLoadBalance("test-lb-empty-disabled", LoadBalanceOptions{}, drop, good)
		g.randFloat = func() float64 { return 0 }

		q := new(dns.Msg)
		q.SetQuestion("test.com.", dns.TypeA)
		a, err := g.Resolve(q, ci)

		require.NoError(t, err)
		require.Nil(t, a)
		require.Equal(t, 1, drop.HitCount())
		require.Equal(t, 0, good.HitCount())
	})

	t.Run("Enabled", func(t *testing.T) {
		drop := &namedTestResolver{name: "drop"}
		drop.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			return nil, nil
		}
		good := &namedTestResolver{name: "good"}
		g := NewLoadBalance("test-lb-empty-enabled", LoadBalanceOptions{EmptyError: true}, drop, good)
		g.randFloat = func() float64 { return 0 }

		q := new(dns.Msg)
		q.SetQuestion("test.com.", dns.TypeA)
		a, err := g.Resolve(q, ci)

		require.NoError(t, err)
		require.NotNil(t, a)
		require.Equal(t, 1, drop.HitCount())
		require.Equal(t, 1, good.HitCount())
	})
}

func TestLoadBalanceAllResolversFail(t *testing.T) {
	var ci ClientInfo
	err1 := errors.New("failed 1")
	err2 := errors.New("failed 2")
	r1 := &namedTestResolver{name: "bad1"}
	r1.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
		return nil, err1
	}
	r2 := &namedTestResolver{name: "bad2"}
	r2.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
		return nil, err2
	}

	g := NewLoadBalance("test-lb-all-fail", LoadBalanceOptions{}, r1, r2)
	g.randFloat = func() float64 { return 0 }

	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)
	a, err := g.Resolve(q, ci)

	require.Nil(t, a)
	require.ErrorIs(t, err, err2) // randFloat=0 picks r1 first, then r2; last error wins
	require.Equal(t, 1, r1.HitCount())
	require.Equal(t, 1, r2.HitCount())
}
