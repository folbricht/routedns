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

// pickCounts runs g.pick repeatedly and tallies how often each resolver index
// in remaining is selected.
func pickCounts(g *LoadBalance, remaining []int, picks int) map[int]int {
	counts := map[int]int{}
	for range picks {
		counts[remaining[g.pick(remaining)]]++
	}
	return counts
}

func TestLoadBalancePickPrefersLowerAverageRTT(t *testing.T) {
	slowest := &namedTestResolver{name: "slowest"}
	slower := &namedTestResolver{name: "slower"}
	fastest := &namedTestResolver{name: "fastest"}

	g := NewLoadBalance("test-lb", LoadBalanceOptions{}, slowest, slower, fastest)
	g.updateOnSuccess(0, 500*time.Millisecond)
	g.updateOnSuccess(1, 50*time.Millisecond)
	g.updateOnSuccess(2, 5*time.Millisecond)

	counts := pickCounts(g, []int{0, 1, 2}, 1000)

	require.Greater(t, counts[2], counts[1])
	require.Greater(t, counts[1], counts[0])
}

// TestLoadBalanceExplorationFloor verifies that even a heavily penalized
// resolver still receives a non-trivial share of traffic via ε-greedy
// exploration, so it can be re-measured and recover.
func TestLoadBalanceExplorationFloor(t *testing.T) {
	penalized := &namedTestResolver{name: "penalized"}
	fast := &namedTestResolver{name: "fast"}

	g := NewLoadBalance("test-lb-exploration", LoadBalanceOptions{}, penalized, fast)
	// Make the first resolver extremely slow and the second extremely fast so
	// weighting alone would almost never pick the slow one.
	g.updateOnSuccess(0, 10*time.Second)
	g.updateOnSuccess(1, time.Millisecond)

	const picks = 5000
	counts := pickCounts(g, []int{0, 1}, picks)

	// With ~5% exploration split evenly across 2 resolvers, the penalized one
	// should get roughly 2.5% of picks. Assert a conservative lower bound well
	// above zero to confirm it is not starved.
	require.Greater(t, counts[0], picks/100,
		"penalized resolver should still receive a minimum traffic share")
}

// TestLoadBalanceFastRecovery verifies that after a penalty streak inflates the
// EMA, a single subsequent success re-seeds the EMA to the measured RTT rather
// than slowly decaying via the alpha blend.
func TestLoadBalanceFastRecovery(t *testing.T) {
	r := &namedTestResolver{name: "recovering"}
	g := NewLoadBalance("test-lb-recovery", LoadBalanceOptions{}, r)

	// Drive consecFails to/above the penalty threshold and inflate the EMA.
	g.stats[0].rttEMA = float64((5 * time.Second).Microseconds())
	g.stats[0].count = 5
	g.stats[0].consecFails.Store(loadBalancePenaltyThreshold)

	g.updateOnSuccess(0, 3*time.Millisecond)

	require.Equal(t, int32(0), g.stats[0].consecFails.Load())
	require.Equal(t, float64((3 * time.Millisecond).Microseconds()), g.stats[0].rttEMA,
		"a success after a penalty streak should re-seed the EMA to the measured RTT")
}

// TestLoadBalanceWeightClamp verifies that the per-resolver weight is bounded so
// an extremely fast resolver does not completely starve a slower one.
func TestLoadBalanceWeightClamp(t *testing.T) {
	ultraFast := &namedTestResolver{name: "ultrafast"}
	slow := &namedTestResolver{name: "slow"}

	g := NewLoadBalance("test-lb-clamp", LoadBalanceOptions{}, ultraFast, slow)
	// 1µs EMA would, unclamped, give a weight of 100000 vs ~1 for the 100ms one.
	// Clamped to 1ms the weight is capped at 100.
	g.stats[0].rttEMA = 1
	g.stats[0].count = 1
	g.stats[1].rttEMA = float64((100 * time.Millisecond).Microseconds())
	g.stats[1].count = 1

	const picks = 20000
	counts := pickCounts(g, []int{0, 1}, picks)

	// With the clamp the weight ratio is at most ~100:1, so the slow resolver
	// (plus exploration) should still receive a measurable share. Without the
	// clamp the ratio would be ~100000:1 and this would be near zero.
	require.Greater(t, counts[1], picks/1000,
		"weight clamp should keep the slower resolver from being fully starved")
}

// TestLoadBalanceFailoverMetric verifies the failover metric is only incremented
// when there is another resolver to fail over to, while the failure metric
// increments on every failure.
func TestLoadBalanceFailoverMetric(t *testing.T) {
	var ci ClientInfo
	r1 := &namedTestResolver{name: "fail1"}
	r1.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
		return nil, errors.New("failed 1")
	}
	r2 := &namedTestResolver{name: "fail2"}
	r2.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
		return nil, errors.New("failed 2")
	}

	g := NewLoadBalance("test-lb-failover-metric", LoadBalanceOptions{}, r1, r2)
	g.randFloat = func() float64 { return 0 }

	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)
	_, err := g.Resolve(q, ci) //nolint:errcheck
	require.Error(t, err)

	// Two resolvers, both fail: the first failure is a real failover, the second
	// (last remaining) is not. So failover == 1 but two failures were recorded.
	require.Equal(t, int64(1), g.metrics.failover.Value(),
		"only the non-final failure should count as a failover")
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
}

// TestLoadBalanceTransientFailure verifies that a single failure does not
// trigger the penalty — only consecutive failures at or above the threshold do.
func TestLoadBalanceTransientFailure(t *testing.T) {
	var ci ClientInfo
	calls := 0
	flaky := &namedTestResolver{name: "flaky"}
	flaky.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("transient")
		}
		return new(dns.Msg), nil
	}

	penalty := 5 * time.Second
	g := NewLoadBalance("test-lb", LoadBalanceOptions{FailurePenalty: penalty}, flaky)
	g.randFloat = func() float64 { return 0 }

	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// First call: fails once (below threshold), no penalty applied.
	g.Resolve(q, ci) //nolint:errcheck
	require.Less(t, g.stats[0].rttEMA, float64(penalty.Microseconds()),
		"single transient failure should not apply the full penalty")

	// Second call: succeeds, consecFails resets.
	g.Resolve(q, ci) //nolint:errcheck
	require.Equal(t, int32(0), g.stats[0].consecFails.Load())
}

func TestLoadBalanceFailurePenaltyOption(t *testing.T) {
	var ci ClientInfo
	bad := &namedTestResolver{name: "bad"}
	bad.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
		return nil, errors.New("failed")
	}
	good := &namedTestResolver{name: "good"}

	penalty := 5 * time.Second
	g := NewLoadBalance("test-lb", LoadBalanceOptions{FailurePenalty: penalty}, bad, good)
	g.randFloat = func() float64 { return 0 }

	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// First query: bad fails once (below threshold), good succeeds.
	_, err := g.Resolve(q, ci)
	require.NoError(t, err)
	require.Less(t, g.stats[0].rttEMA, float64(penalty.Microseconds()),
		"first failure should not apply penalty")

	// Seed bad as the only resolver so it fails twice consecutively.
	bad2 := &namedTestResolver{name: "bad2"}
	bad2.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
		return nil, errors.New("failed")
	}
	g2 := NewLoadBalance("test-lb2", LoadBalanceOptions{FailurePenalty: penalty}, bad2)
	g2.randFloat = func() float64 { return 0 }

	g2.Resolve(q, ci) //nolint:errcheck // fail 1 — below threshold, elapsed recorded
	require.Less(t, g2.stats[0].consecFails.Load(), int32(loadBalancePenaltyThreshold))
	g2.Resolve(q, ci) //nolint:errcheck // fail 2 — threshold reached, penalty applied
	require.GreaterOrEqual(t, g2.stats[0].consecFails.Load(), int32(loadBalancePenaltyThreshold))
	require.Greater(t, g2.stats[0].rttEMA, float64(penalty.Microseconds())*defaultLoadBalanceEMAAlpha,
		"penalty should influence EMA after threshold is reached")
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

	// A nil response is a deliberate signal (e.g. DropResolver) and is always
	// treated as success regardless of EmptyError; it is not retried.
	t.Run("Enabled_NilIsSuccess", func(t *testing.T) {
		drop := &namedTestResolver{name: "drop"}
		drop.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			return nil, nil
		}
		good := &namedTestResolver{name: "good"}
		g := NewLoadBalance("test-lb-empty-enabled-nil", LoadBalanceOptions{EmptyError: true}, drop, good)
		g.randFloat = func() float64 { return 0 }

		q := new(dns.Msg)
		q.SetQuestion("test.com.", dns.TypeA)
		a, err := g.Resolve(q, ci)

		require.NoError(t, err)
		require.Nil(t, a)
		require.Equal(t, 1, drop.HitCount())
		require.Equal(t, 0, good.HitCount())
	})

	t.Run("Enabled_EmptyMsgIsRetried", func(t *testing.T) {
		empty := &namedTestResolver{name: "empty"}
		empty.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			return new(dns.Msg), nil
		}
		good := &namedTestResolver{name: "good"}
		g := NewLoadBalance("test-lb-empty-enabled-msg", LoadBalanceOptions{EmptyError: true}, empty, good)
		g.randFloat = func() float64 { return 0 }

		q := new(dns.Msg)
		q.SetQuestion("test.com.", dns.TypeA)
		a, err := g.Resolve(q, ci)

		require.NoError(t, err)
		require.NotNil(t, a)
		require.Equal(t, 1, empty.HitCount())
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
