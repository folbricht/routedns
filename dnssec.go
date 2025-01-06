package rdns

import (
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// The DNSSEC enforcer will upgrade DNS queries to also request DNSSEC and only forwards DNSSEC validated responses
type DNSSECenforcer struct {
	id       string
	resolver Resolver
}

var _ Resolver = &DNSSECenforcer{}

func NewDNSSECenforcer(id string, resolver Resolver) *DNSSECenforcer {
	return &DNSSECenforcer{id: id, resolver: resolver}
}

func (d *DNSSECenforcer) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	var answer *RRSet
	var response *dns.Msg
	var authChain *AuthenticationChain
	var g errgroup.Group

	// Resolve the A query with RRSIG option
	g.Go(func() error {
		var err error
		res, err := d.resolver.Resolve(setDNSSECdo(q), ci)
		if err != nil {
			return err
		}
		response = res.Copy()
		answer, err = extractRRset(res)
		if err != nil {
			return err
		}
		if answer.IsEmpty() {
			return ErrNoResult
		}
		if !answer.IsSigned() {
			return ErrResourceNotSigned
		}
		return nil
	})

	// Resolve the entire DNSSEC authentication chain
	g.Go(func() error {
		authChain = NewAuthenticationChain()
		if populateErr := authChain.Populate(qName(q), d.resolver); populateErr != nil {
			return populateErr
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}
	if err := authChain.Verify(answer); err != nil {
		return nil, err
	}

	Log.Debug("Valid DNS Record Answer for ", qName(q))
	return removeRRSIGs(response), nil
}

func (d *DNSSECenforcer) String() string {
	return d.id
}
