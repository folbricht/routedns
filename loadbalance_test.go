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

// TestLoadBalanceFastRecovery verifies that after failures inflate the EMA (via
// the failure penalty), a single subsequent success re-seeds the EMA to the
// measured RTT rather than slowly decaying via the alpha blend.
func TestLoadBalanceFastRecovery(t *testing.T) {
	r := &namedTestResolver{name: "recovering"}
	penalty := 5 * time.Second
	g := NewLoadBalance("test-lb-recovery", LoadBalanceOptions{FailurePenalty: penalty}, r)

	// Establish an honest average, then drive consecutive failures so the penalty
	// inflates the EMA and sets the inflation flag.
	g.updateOnSuccess(0, 3*time.Millisecond)
	g.updateOnFailure(0, time.Millisecond)                  // fail 1 — below threshold
	require.True(t, g.updateOnFailure(0, time.Millisecond)) // fail 2 — penalty applied
	require.Greater(t, g.stats[0].rttEMA, float64((100 * time.Millisecond).Microseconds()),
		"penalty should have inflated the EMA")

	g.updateOnSuccess(0, 3*time.Millisecond)

	require.Equal(t, int32(0), g.stats[0].consecFails.Load())
	require.Equal(t, float64((3 * time.Millisecond).Microseconds()), g.stats[0].rttEMA,
		"a success after a penalty streak should re-seed the EMA to the measured RTT")
}

// TestLoadBalanceFirstFailureRecovery verifies that when a resolver's first-ever
// event is a fast failure — which seeds the EMA up to the baseline rather than
// the (faster) measured time — the next success re-seeds to the measured RTT
// instead of slowly blending down from the inflated baseline.
func TestLoadBalanceFirstFailureRecovery(t *testing.T) {
	r := &namedTestResolver{name: "firstfail"}
	g := NewLoadBalance("test-lb-first-fail", LoadBalanceOptions{}, r) // no penalty

	// First-ever event: a fast failure (e.g. connection refused in ~1ms). The
	// seed is floored to the baseline, which is inflated above the real 1ms.
	g.updateOnFailure(0, time.Millisecond)
	require.Equal(t, float64(defaultLoadBalanceInitialRTT.Microseconds()), g.stats[0].rttEMA,
		"a fast first failure should seed the EMA to the baseline")
	require.True(t, g.stats[0].emaInflated,
		"a baseline-floored first-failure seed should be marked inflated")

	// A genuine fast success must re-seed to the measured RTT, not blend down
	// from the baseline (which would leave the resolver artificially slow).
	g.updateOnSuccess(0, 3*time.Millisecond)
	require.Equal(t, float64((3 * time.Millisecond).Microseconds()), g.stats[0].rttEMA,
		"a success after an inflated first-failure seed should re-seed to the measured RTT")
}

// TestLoadBalanceSlowFirstFailureRecovery verifies that when a resolver's
// first-ever event is a slow failure — e.g. a timeout above the baseline, so
// the EMA is seeded to the timeout value itself — the next success re-seeds to
// the measured RTT instead of slowly blending down from the failure-derived
// seed.
func TestLoadBalanceSlowFirstFailureRecovery(t *testing.T) {
	r := &namedTestResolver{name: "slowfirstfail"}
	g := NewLoadBalance("test-lb-slow-first-fail", LoadBalanceOptions{}, r) // no penalty

	// First-ever event: a slow failure (e.g. a 2s timeout). The seed is the
	// timeout value, which says nothing about the resolver's real speed.
	timeout := 2 * time.Second
	g.updateOnFailure(0, timeout)
	require.Equal(t, float64(timeout.Microseconds()), g.stats[0].rttEMA,
		"a slow first failure should seed the EMA to the measured elapsed time")
	require.True(t, g.stats[0].emaInflated,
		"a failure-derived first seed should be marked inflated")

	// A genuine fast success must re-seed to the measured RTT, not blend down
	// from the timeout (which would take ~20+ successes to decay).
	g.updateOnSuccess(0, 3*time.Millisecond)
	require.Equal(t, float64((3 * time.Millisecond).Microseconds()), g.stats[0].rttEMA,
		"a success after a slow first failure should re-seed to the measured RTT")
}

// TestLoadBalanceNoReseedWithoutInflation verifies that a failure streak alone
// (with no failure penalty configured, so updateOnFailure never inflated the
// EMA) does not wipe an established average on the next success — it blends
// normally instead of re-seeding.
func TestLoadBalanceNoReseedWithoutInflation(t *testing.T) {
	r := &namedTestResolver{name: "steady"}
	g := NewLoadBalance("test-lb-no-reseed", LoadBalanceOptions{}, r) // no FailurePenalty

	// Establish an honest 400ms average.
	honest := 400 * time.Millisecond
	g.updateOnSuccess(0, honest)

	// Two fast transient failures: with the upward-only update and no penalty,
	// these leave the EMA unchanged but push consecFails past the threshold.
	g.updateOnFailure(0, time.Millisecond)
	g.updateOnFailure(0, time.Millisecond)
	require.GreaterOrEqual(t, g.stats[0].consecFails.Load(), int32(loadBalancePenaltyThreshold))
	require.Equal(t, float64(honest.Microseconds()), g.stats[0].rttEMA,
		"fast failures with no penalty should not have inflated the EMA")

	// A fast success must blend toward the measured RTT, not hard-reset to it.
	g.updateOnSuccess(0, time.Millisecond)
	expected := defaultLoadBalanceEMAAlpha*float64(time.Millisecond.Microseconds()) +
		(1-defaultLoadBalanceEMAAlpha)*float64(honest.Microseconds())
	require.Equal(t, expected, g.stats[0].rttEMA,
		"a success after a non-inflated streak should blend, not re-seed")
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

// TestLoadBalanceFailoverMetric verifies the failover metric increments on every
// failure, consistent with FailRotate, so the counter stays comparable across
// groups (including a completely broken single-resolver group).
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

	// Two resolvers, both fail: every failure counts as a failover, matching
	// FailRotate's semantics.
	require.Equal(t, int64(2), g.metrics.failover.Value(),
		"every failure should count as a failover, consistent with fail-rotate")
}

// TestLoadBalanceSingleResolverFailoverMetric verifies that a completely broken
// single-resolver group still reports a failover, so alerts keyed on the
// failover counter are not silenced.
func TestLoadBalanceSingleResolverFailoverMetric(t *testing.T) {
	var ci ClientInfo
	dead := &namedTestResolver{name: "dead"}
	dead.ResolveFunc = func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
		return nil, errors.New("dead")
	}

	g := NewLoadBalance("test-lb-single-failover", LoadBalanceOptions{}, dead)
	g.randFloat = func() float64 { return 0 }

	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)
	_, err := g.Resolve(q, ci) //nolint:errcheck
	require.Error(t, err)

	require.Equal(t, int64(1), g.metrics.failover.Value(),
		"a broken single-resolver group should still report a failover")
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
