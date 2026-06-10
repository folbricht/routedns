package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// When the syslog connection fails at startup, queries must still be
// passed through rather than panic on the nil writer.
func TestSyslogUnreachableServer(t *testing.T) {
	opt := SyslogOptions{
		Network:     "tcp",
		Address:     "127.0.0.1:1", // nothing listens here, Dial fails
		LogRequest:  true,
		LogResponse: true,
	}
	r := NewSyslog("test-syslog", &TestResolver{}, opt)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a, err := r.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotNil(t, a)
}
