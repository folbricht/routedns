package rdns

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type testDialer func(address string) (*dns.Conn, error)

func (d testDialer) Dial(address string) (*dns.Conn, error) {
	return d(address)
}

func TestPipelineQueryTimeout(t *testing.T) {
	df := func(address string) (*dns.Conn, error) {
		time.Sleep(2 * time.Second)
		return nil, errors.New("failed")
	}
	p := NewPipeline("test", "localhost:53", testDialer(df))

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	// Send some queries to start the pipeline
	_, _ = p.Resolve(q)
	_, _ = p.Resolve(q)

	// Record when we sent the query in order to tell how long it took
	start := time.Now()
	_, err := p.Resolve(q)

	// Make sure we get a timeout error and it took the right amount to come back
	require.ErrorAs(t, err, &QueryTimeoutError{})
	require.WithinDuration(t, start.Add(queryTimeout), time.Now(), 10*time.Millisecond)
}
