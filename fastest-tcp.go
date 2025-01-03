package rdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

// FastestTCP first resolves the query with the upstream resolver, then
// performs TCP connection tests with the response IPs to determine which
// IP responds the fastest. This IP is then returned in the response as first
// A/AAAA record. This should be used in combination with a Cache to avoid
// the TCP connection overhead on every query.
type FastestTCP struct {
	id       string
	resolver Resolver
	opt      FastestTCPOptions
	port     string
}

var _ Resolver = &FastestTCP{}

// FastestTCPOptions contain settings for a resolver that filters responses
// based on TCP connection probes.
type FastestTCPOptions struct {
	// Port number to use for TCP probes, default 443
	Port int

	// Wait for all connection probes and sort the responses based on time
	// (fastest first). This is generally slower than just waiting for the
	// fastest, since the response time is determined by the slowest probe.
	WaitAll bool

	// TTL set on all RRs when TCP probing was successful. Can be used to
	// ensure these are kept for longer in a cache and improve performance.
	SuccessTTLMin uint32
}

// NewFastestTCP returns a new instance of a TCP probe resolver.
func NewFastestTCP(id string, resolver Resolver, opt FastestTCPOptions) *FastestTCP {
	port := strconv.Itoa(opt.Port)
	if port == "0" {
		port = "443"
	}
	return &FastestTCP{
		id:       id,
		resolver: resolver,
		opt:      opt,
		port:     port,
	}
}

// Resolve a DNS query and order the response based on which IP was able to establish
// a TCP connection the fastest.
func (r *FastestTCP) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	log := logger(r.id, q, ci)
	a, err := r.resolver.Resolve(q, ci)
	if err != nil {
		return a, err
	}
	question := q.Question[0]

	// Don't need to do anything if the query wasn't for an IP
	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return a, nil
	}
	fmt.Println("Responses")
	fmt.Println(a)

	// Extract the IP responses
	var ipRRs []dns.RR
	for _, rr := range a.Answer {
		if rr.Header().Rrtype == question.Qtype {
			ipRRs = append(ipRRs, rr)
		}
	}

	// If there's only one IP in the response, nothing to probe
	if len(ipRRs) < 2 {
		return a, nil
	}

	// Send TCP probes to all, if anything returns an error, just return
	// the original response rather than trying to be clever and pick one.
	log = log.With("port", r.port)
	var sorted []dns.RR
	if r.opt.WaitAll {
		sorted, err = r.probeAll(log, ipRRs)
	} else {
		sorted, err = r.probeFastest(log, ipRRs)
	}
	if err != nil {
		log.Debug("tcp probe failed",
			"error", err)
		return a, nil
	}
	r.setTTL(sorted...)

	// Merge the sorted list of RRs back into the original answer in the same
	// positions. The original answer could have CNAMEs and other types in it.
	for i, rr := range a.Answer {
		if rr.Header().Rrtype == question.Qtype {
			a.Answer[i] = sorted[0]
			sorted = sorted[1:]
		}
	}
	return a, nil
}

// Sets the TTL of the given RRs if the option was provided
func (r *FastestTCP) setTTL(rrs ...dns.RR) {
	for _, rr := range rrs {
		h := rr.Header()
		if h.Ttl < r.opt.SuccessTTLMin {
			h.Ttl = r.opt.SuccessTTLMin
		}
	}
}

func (r *FastestTCP) String() string {
	return r.id
}

// Probes all IPs and returns only the RR with the fastest responding IP.
// Waits for the first one that comes back. Returns an error if the fastest response
// is an error.
func (r *FastestTCP) probeFastest(log *slog.Logger, rrs []dns.RR) ([]dns.RR, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resultCh := r.probe(ctx, log, rrs)
	select {
	case res := <-resultCh:
		// Re-order the list in-place to put the fastest at the top
		rr := res.rr
		err := res.err
		for i := 0; i < len(rrs); i++ {
			if rrs[i] == rr {
				return rrs, err
			}
			rrs[i], rr = rr, rrs[i]
		}
		return rrs, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Probes all IPs and returns them in the order of response time, fastest first. Returns
// an error if any of the probes fail or if the probe times out.
func (r *FastestTCP) probeAll(log *slog.Logger, rrs []dns.RR) ([]dns.RR, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resultCh := r.probe(ctx, log, rrs)
	results := make([]dns.RR, 0, len(rrs))
	for i := 0; i < len(rrs); i++ {
		select {
		case res := <-resultCh:
			if res.err != nil {
				return nil, res.err
			}
			results = append(results, res.rr)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return results, nil
}

type tcpProbeResult struct {
	rr  dns.RR
	err error
}

// Probes all IPs and returns a channel with responses in the order they succeed or fail.
func (r *FastestTCP) probe(ctx context.Context, log *slog.Logger, rrs []dns.RR) <-chan tcpProbeResult {
	resultCh := make(chan tcpProbeResult)
	for _, rr := range rrs {
		var d net.Dialer
		go func(rr dns.RR) {
			var network, ip string
			switch record := rr.(type) {
			case *dns.A:
				network, ip = "tcp4", record.A.String()
			case *dns.AAAA:
				network, ip = "tcp6", record.AAAA.String()
			default:
				resultCh <- tcpProbeResult{err: errors.New("unexpected resource type")}
				return
			}
			start := time.Now()
			log.Debug("sending tcp probe",
				"ip", ip)
			c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, r.port))
			if err != nil {
				resultCh <- tcpProbeResult{err: err}
				return
			}
			log.With("ip", ip).With("response-time", time.Since(start)).Debug("tcp probe finished")
			defer c.Close()
			resultCh <- tcpProbeResult{rr: rr}
		}(rr)
	}
	return resultCh
}
