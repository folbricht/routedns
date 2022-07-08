package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestAnswerPadding(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)

	a := new(dns.Msg)
	a.SetReply(q)

	// No EDNS0 in the query, there should be none in the answer either
	padAnswer(q, a)
	edns0 := a.IsEdns0()
	require.Nil(t, edns0, "unexpected EDNS0 option in response")

	// With EDNS0 in the query now, should see padding in the response
	q.SetEdns0(4096, false)
	a.SetReply(q)
	padAnswer(q, a)
	edns0 = a.IsEdns0()
	require.NotNil(t, edns0, "missing EDNS0 in response")
	require.Zero(t, a.Len()%ResponsePaddingBlockSize, "response not padded to the correct length")

	// Use padding on packet that needs to be smaller than the usual padded size
	maxSize := ResponsePaddingBlockSize - 10
	q.SetEdns0(uint16(maxSize), false)
	a.SetReply(q)
	padAnswer(q, a)
	edns0 = a.IsEdns0()
	require.NotNil(t, edns0, "missing EDNS0 in response")
	require.Equal(t, maxSize, a.Len(), "not padded to the correct length")
}

func TestQueryPadding(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)

	// No padding should be added when there's no EDNS0 in the query
	padQuery(q)
	edns0 := q.IsEdns0()
	require.Nil(t, edns0, "unexpected EDNS0 option in query")

	// Now with EDNS0, the query should be padded to the right size
	q.SetEdns0(4096, false)
	padQuery(q)
	edns0 = q.IsEdns0()
	require.NotNil(t, edns0, "missing EDNS0 in query")
	require.Zero(t, q.Len()%QueryPaddingBlockSize, "query not padded to the correct length")
}

func TestStripPadding(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	q.SetEdns0(4096, false)
	len1 := q.Len()
	padQuery(q)
	stripPadding(q)
	len2 := q.Len()
	require.Equal(t, len1, len2, "padding not stripped off correctly")
}

func TestStripPaddingMulti(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	q.SetEdns0(4096, false)
	edns0 := q.IsEdns0()

	tests := []struct {
		opts          []dns.EDNS0
		lenAfterStrip int
	}{
		{
			opts:          nil,
			lenAfterStrip: 0,
		},
		{
			opts:          []dns.EDNS0{},
			lenAfterStrip: 0,
		},
		{
			opts: []dns.EDNS0{
				&dns.EDNS0_PADDING{},
			},
			lenAfterStrip: 0,
		},
		{
			opts: []dns.EDNS0{
				&dns.EDNS0_PADDING{},
				&dns.EDNS0_PADDING{},
			},
			lenAfterStrip: 0,
		},
		{
			opts: []dns.EDNS0{
				&dns.EDNS0_PADDING{},
				&dns.EDNS0_PADDING{},
				&dns.EDNS0_NSID{},
			},
			lenAfterStrip: 1,
		},
		{
			opts: []dns.EDNS0{
				&dns.EDNS0_NSID{},
				&dns.EDNS0_PADDING{},
				&dns.EDNS0_PADDING{},
			},
			lenAfterStrip: 1,
		},
	}

	for _, test := range tests {
		edns0.Option = test.opts
		stripPadding(q)
		require.Len(t, edns0.Option, test.lenAfterStrip)
	}
}
