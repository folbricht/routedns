package rdns

import (
	"encoding/binary"
	"github.com/miekg/dns"
	"sync"
	"sync/atomic"
	"time"
)

type key struct {
	name        string
	qtype       uint16
	ecs_ipv4    uint32
	ecs_ipv6_hi uint64
	ecs_ipv6_lo uint64
	ecs_mask    uint8
}

type value struct {
	//If expiredTimeStamp is negative number , it means it will return SERVFAIL.
	expiredTimeStamp int64
	mu               *newMutex
}

type lockDuplicateRequest struct {
	id       string
	resolver Resolver
	m        sync.Map
}

var _ Resolver = &lockDuplicateRequest{}

func NewlockDuplicateRequest(id string, resolver Resolver) *lockDuplicateRequest {
	ret := &lockDuplicateRequest{id: id, resolver: resolver}
	return ret
}

func (r *lockDuplicateRequest) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {

	var ecsipv4 uint32 = 0
	var ecsipv6hi uint64 = 0
	var ecsipv6lo uint64 = 0
	var ecsmask uint8 = 0

	if len(q.Question) != 1 {
		return r.resolver.Resolve(q, ci)
	}

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
				ecsipv4 = ldrByteToUint32(ecs.Address.To4())
				ecsmask = ecs.SourceNetmask
				break
			case 2: // ip6
				ecsipv6hi, ecsipv6lo = ldrByteToUint128(ecs.Address.To16())
				ecsmask = ecs.SourceNetmask
				break
			}
		}
	}

	k := key{
		name:        q.Question[0].Name,
		qtype:       q.Question[0].Qtype,
		ecs_ipv4:    ecsipv4,
		ecs_ipv6_hi: ecsipv6hi,
		ecs_ipv6_lo: ecsipv6lo,
		ecs_mask:    ecsmask,
	}

	var newValue value
	parse, _ := time.ParseDuration("+5s")
	expired := time.Now().Add(parse)
	newValue.expiredTimeStamp = expired.Unix()
	newValue.mu = &newMutex{}
	loaded, _ := r.m.LoadOrStore(k, newValue)
	v := loaded.(value)


	var returnAnswer *dns.Msg
	var returnError error

	v.mu.Lock()
	if v.expiredTimeStamp >= 0 {
		a, err := r.resolver.Resolve(q, ci)
		returnAnswer = a
		returnError = err
	} else {
		returnAnswer = nil
		returnError = QueryTimeoutError{q}
	}
	v.mu.UnLock()

	currentTimeStamp := time.Now().Unix()
	expiredTimeStamp := v.expiredTimeStamp
	if v.mu.Count() == 0 {
		r.m.Delete(k)
	} else if expiredTimeStamp >= 0 && expiredTimeStamp < currentTimeStamp {
		r.m.Delete(k)
		v.expiredTimeStamp = ^expiredTimeStamp
		v.mu.UnLockAll()
	}

	return returnAnswer, returnError
}

func (r *lockDuplicateRequest) String() string {
	return r.id
}

func ldrByteToUint128(b []byte) (uint64, uint64) {
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	return hi, lo
}

func ldrByteToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b[0:4])
}

type newMutex struct {
	count uint32
	sync  sync.Mutex
}

func (r *newMutex) Count() uint32 {
	return r.count
}

func (r *newMutex) Lock() {
	r.sync.Lock()
	atomic.AddUint32(&(r.count), +1)
}

func (r *newMutex) UnLock() {
	for {
		count := atomic.LoadUint32(&(r.count))
		if count > 0 {
			ok := atomic.CompareAndSwapUint32(&(r.count), count, count-1)
			if ok {
				break
			}
		} else {
			return
		}
	}
	r.sync.Unlock()
}

func (r *newMutex) UnLockAll() {
	for {
		count := atomic.LoadUint32(&(r.count))
		if count > 0 {
			ok := atomic.CompareAndSwapUint32(&(r.count), count, 0)
			if ok {
				for count > 0 {
					count--
					r.sync.Unlock()
				}
			}
		} else {
			break
		}
	}
}
