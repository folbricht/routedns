package rdns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestSynthesizeIPv6_96(t *testing.T) {
	prefixes, err := parseDNS64Prefixes([]string{"64:ff9b::/96"})
	require.NoError(t, err)
	result := synthesizeIPv6(prefixes[0], net.IP{192, 0, 2, 33})
	expected := net.ParseIP("64:ff9b::c000:221")
	require.Equal(t, expected.To16(), result)
}

func TestSynthesizeIPv6_64(t *testing.T) {
	prefixes, err := parseDNS64Prefixes([]string{"2001:db8:122:344::/64"})
	require.NoError(t, err)
	result := synthesizeIPv6(prefixes[0], net.IP{192, 0, 2, 33})
	expected := net.ParseIP("2001:db8:122:344:00c0:0002:2100:0000")
	require.Equal(t, expected.To16(), result)
}

func TestSynthesizeIPv6_56(t *testing.T) {
	prefixes, err := parseDNS64Prefixes([]string{"2001:db8:122:300::/56"})
	require.NoError(t, err)
	result := synthesizeIPv6(prefixes[0], net.IP{192, 0, 2, 33})
	expected := net.ParseIP("2001:db8:122:3c0:0:0221:0:0")
	require.Equal(t, expected.To16(), result)
}

func TestSynthesizeIPv6_48(t *testing.T) {
	prefixes, err := parseDNS64Prefixes([]string{"2001:db8:122::/48"})
	require.NoError(t, err)
	result := synthesizeIPv6(prefixes[0], net.IP{192, 0, 2, 33})
	expected := net.ParseIP("2001:db8:122:c000:0002:2100::")
	require.Equal(t, expected.To16(), result)
}

func TestSynthesizeIPv6_40(t *testing.T) {
	prefixes, err := parseDNS64Prefixes([]string{"2001:db8:100::/40"})
	require.NoError(t, err)
	result := synthesizeIPv6(prefixes[0], net.IP{192, 0, 2, 33})
	expected := net.ParseIP("2001:db8:1c0:0002:0021::")
	require.Equal(t, expected.To16(), result)
}

func TestSynthesizeIPv6_32(t *testing.T) {
	prefixes, err := parseDNS64Prefixes([]string{"2001:db8::/32"})
	require.NoError(t, err)
	result := synthesizeIPv6(prefixes[0], net.IP{192, 0, 2, 33})
	expected := net.ParseIP("2001:db8:c000:0221::")
	require.Equal(t, expected.To16(), result)
}

func TestParseDNS64Prefixes(t *testing.T) {
	// Valid prefixes
	for _, cidr := range []string{
		"64:ff9b::/96",
		"2001:db8::/32",
		"2001:db8:100::/40",
		"2001:db8:122::/48",
		"2001:db8:122:300::/56",
		"2001:db8:122:344::/64",
	} {
		_, err := parseDNS64Prefixes([]string{cidr})
		require.NoError(t, err, "should accept %s", cidr)
	}

	// Invalid: bad CIDR
	_, err := parseDNS64Prefixes([]string{"not-a-cidr"})
	require.Error(t, err)

	// Invalid: IPv4 CIDR
	_, err = parseDNS64Prefixes([]string{"192.168.0.0/24"})
	require.Error(t, err)

	// Invalid: unsupported prefix length
	_, err = parseDNS64Prefixes([]string{"2001:db8::/80"})
	require.Error(t, err)
}

func TestDNS64PassthroughNonAAAA(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			a.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IP{1, 2, 3, 4},
				},
			}
			return a, nil
		},
	}
	d, err := NewDNS64("test", upstream, DNS64Options{})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Len(t, a.Answer, 1)
	require.Equal(t, dns.TypeA, a.Answer[0].Header().Rrtype)
}

func TestDNS64NativeAAAA(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			a.Answer = []dns.RR{
				&dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
					AAAA: net.ParseIP("2001:db8::1"),
				},
			}
			return a, nil
		},
	}
	d, err := NewDNS64("test", upstream, DNS64Options{})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
	a, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Len(t, a.Answer, 1)
	require.Equal(t, dns.TypeAAAA, a.Answer[0].Header().Rrtype)
	require.Equal(t, net.ParseIP("2001:db8::1").To16(), a.Answer[0].(*dns.AAAA).AAAA.To16())
}

func TestDNS64Synthesize(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			if q.Question[0].Qtype == dns.TypeAAAA {
				// No AAAA records
				return a, nil
			}
			if q.Question[0].Qtype == dns.TypeA {
				a.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.IP{192, 0, 2, 1},
					},
				}
			}
			return a, nil
		},
	}
	d, err := NewDNS64("test", upstream, DNS64Options{
		Prefixes: []string{"64:ff9b::/96"},
	})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
	a, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Len(t, a.Answer, 1)
	require.Equal(t, dns.TypeAAAA, a.Answer[0].Header().Rrtype)
	require.Equal(t, uint32(300), a.Answer[0].Header().Ttl)
	require.Equal(t, net.ParseIP("64:ff9b::c000:201").To16(), a.Answer[0].(*dns.AAAA).AAAA.To16())
}

func TestDNS64SynthesizeMultipleARecords(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			if q.Question[0].Qtype == dns.TypeA {
				a.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.IP{192, 0, 2, 1},
					},
					&dns.A{
						Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600},
						A:   net.IP{192, 0, 2, 2},
					},
				}
			}
			return a, nil
		},
	}
	d, err := NewDNS64("test", upstream, DNS64Options{})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
	a, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Len(t, a.Answer, 2)
	require.Equal(t, net.ParseIP("64:ff9b::c000:201").To16(), a.Answer[0].(*dns.AAAA).AAAA.To16())
	require.Equal(t, net.ParseIP("64:ff9b::c000:202").To16(), a.Answer[1].(*dns.AAAA).AAAA.To16())
}

func TestDNS64SynthesizeMultiplePrefixes(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			if q.Question[0].Qtype == dns.TypeA {
				a.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.IP{192, 0, 2, 1},
					},
				}
			}
			return a, nil
		},
	}
	d, err := NewDNS64("test", upstream, DNS64Options{
		Prefixes: []string{"64:ff9b::/96", "2001:db8::/32"},
	})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
	a, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Len(t, a.Answer, 2)
	require.Equal(t, net.ParseIP("64:ff9b::c000:201").To16(), a.Answer[0].(*dns.AAAA).AAAA.To16())
	require.Equal(t, net.ParseIP("2001:db8:c000:0201::").To16(), a.Answer[1].(*dns.AAAA).AAAA.To16())
}

func TestDNS64NXDOMAIN(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetRcode(q, dns.RcodeNameError)
			return a, nil
		},
	}
	d, err := NewDNS64("test", upstream, DNS64Options{})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("nonexistent.example.com.", dns.TypeAAAA)
	a, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Equal(t, dns.RcodeNameError, a.Rcode)
}

func TestDNS64DefaultPrefix(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			if q.Question[0].Qtype == dns.TypeA {
				a.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.IP{10, 0, 0, 1},
					},
				}
			}
			return a, nil
		},
	}
	// Empty options should use default 64:ff9b::/96
	d, err := NewDNS64("test", upstream, DNS64Options{})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
	a, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Len(t, a.Answer, 1)
	require.Equal(t, net.ParseIP("64:ff9b::a00:1").To16(), a.Answer[0].(*dns.AAAA).AAAA.To16())
}

func TestDNS64UpstreamError(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetRcode(q, dns.RcodeServerFailure)
			return a, nil
		},
	}
	d, err := NewDNS64("test", upstream, DNS64Options{})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
	a, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Equal(t, dns.RcodeServerFailure, a.Rcode)
}

func TestDNS64NoARecordsEither(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			// Empty answer for both AAAA and A
			return a, nil
		},
	}
	d, err := NewDNS64("test", upstream, DNS64Options{})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
	a, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Empty(t, a.Answer)
}
