package rdns

import (
	"encoding/binary"
	"sync"

	"github.com/miekg/dns"
)

type dedupKey struct {
	name        string
	qtype       uint16
	ecs_ipv4    uint32
	ecs_ipv6_hi uint64
	ecs_ipv6_lo uint64
	ecs_mask    uint8
}

type inflightRequest struct {
	answer *dns.Msg
	err    error
	done   chan struct{}
}

// requestDedup passes individual requests normally. Subsequent
// queries for the same name are being held until the first query
// returns. In that case, all waiting requests are answered with
// the same response. This element is used to smooth out spikes
// of queries for the same name.
type requestDedup struct {
	id       string
	resolver Resolver
	mu       sync.Mutex
	inflight map[dedupKey]*inflightRequest
}

var _ Resolver = &requestDedup{}

func NewRequestDedup(id string, resolver Resolver) *requestDedup {
	return &requestDedup{
		id:       id,
		resolver: resolver,
		inflight: make(map[dedupKey]*inflightRequest),
	}
}

func (r *requestDedup) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	var (
		ecsIPv4              uint32
		ecsIPv6Lo, ecsIPv6Hi uint64
		ecsMask              uint8
	)

	edns0 := q.IsEdns0()
	if edns0 != nil {
		// Find the ECS option
		for _, opt := range edns0.Option {
			ecs, ok := opt.(*dns.EDNS0_SUBNET)
			if !ok {
				continue
			}
			switch ecs.Family {
			case 1: // ip4
				ecsIPv4 = byteToUint32(ecs.Address.To4())
				ecsMask = ecs.SourceNetmask
			case 2: // ip6
				ecsIPv6Hi, ecsIPv6Lo = byteToUint128(ecs.Address.To16())
				ecsMask = ecs.SourceNetmask
			}
			break
		}
	}
	k := dedupKey{
		name:        q.Question[0].Name,
		qtype:       q.Question[0].Qtype,
		ecs_ipv4:    ecsIPv4,
		ecs_ipv6_hi: ecsIPv6Hi,
		ecs_ipv6_lo: ecsIPv6Lo,
		ecs_mask:    ecsMask,
	}

	r.mu.Lock()
	req, ok := r.inflight[k]
	if !ok {
		req = &inflightRequest{
			done: make(chan struct{}),
		}
		r.inflight[k] = req
	}
	r.mu.Unlock()

	log := logger(r.id, q, ci)
	// If the request is already in flight, wait for that to complete and
	// return the same answer.
	if ok {
		log.Debug("duplicated request, waiting for first answer")
		<-req.done
		a, err := req.answer, req.err
		// Return a copy of the answer as other elements might be modifying it
		if a != nil {
			a = a.Copy()
		}
		return a, err
	}
	log.With("resolver", r.resolver).Debug("forwarding query to resolver")

	// Not already in flight, make the request
	a, err := r.resolver.Resolve(q, ci)
	req.answer = a
	req.err = err
	close(req.done) // release other goroutines waiting for the response

	// No longer in flight
	r.mu.Lock()
	delete(r.inflight, k)
	r.mu.Unlock()

	// Return a copy since it could be modified in the chain (i.e. in the listener)
	// but it's also stored for other goroutines which need to copy it.
	if a != nil {
		return a.Copy(), err
	}
	return a, err
}

func (r *requestDedup) String() string {
	return r.id
}

func byteToUint128(b []byte) (uint64, uint64) {
	if len(b) != 16 {
		return 0, 0
	}
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	return hi, lo
}

func byteToUint32(b []byte) uint32 {
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b[0:4])
}
