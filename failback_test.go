package rdns

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestFailBack(t *testing.T) {
	// Build 2 resolvers that count the number of invocations
	var (
		c1, c2       int
		fail1, fail2 bool
	)

	r1 := TestResolver(func(q *dns.Msg) (*dns.Msg, error) {
		c1++
		if fail1 {
			return nil, errors.New("failed")
		}
		return q, nil
	})
	r2 := TestResolver(func(q *dns.Msg) (*dns.Msg, error) {
		c2++
		if fail2 {
			return nil, errors.New("failed")
		}
		return q, nil
	})

	g := NewFailBack(FailBackOptions{ResetAfter: time.Second}, r1, r2)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// Send the first couple of queries. The first resolver should be active and be used for both
	_, err := g.Resolve(q)
	require.NoError(t, err)
	_, err = g.Resolve(q)
	require.NoError(t, err)
	require.Equal(t, 2, c1)
	require.Equal(t, 0, c2)

	// Set the 1st to failure
	fail1 = true

	// The next one should hit both stores (1st will fail, 2nd succeed)
	_, err = g.Resolve(q)
	require.NoError(t, err)
	require.Equal(t, 3, c1)
	require.Equal(t, 1, c2)

	// Fix the 1st resolver and wait a second
	fail1 = false
	time.Sleep(time.Second + 100*time.Millisecond)

	// It should have been reset and the first should be active again now
	_, err = g.Resolve(q)
	require.NoError(t, err)
	_, err = g.Resolve(q)
	require.NoError(t, err)
	require.Equal(t, 5, c1)
	require.Equal(t, 1, c2)
}
