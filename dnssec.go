package rdns

import (
	"errors"
	"log/slog"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// The DNSSEC validator will upgrade DNS queries to also request DNSSEC and only forwards DNSSEC validated responses
type DNSSECvalidator struct {
	id          string
	resolver    Resolver
	rootKeys    *RRSet
	fwdUnsigned bool
}

type DNSSECvalidatorOptions struct {
	Mode            string
	TrustAnchorFile string
}

var _ Resolver = &DNSSECvalidator{}

func NewDNSSECvalidator(id string, resolver Resolver, opt DNSSECvalidatorOptions) *DNSSECvalidator {
	mode := true
	if opt.Mode == "strict" {
		Log.Debug("Forwarding unsigned responses disabled")
		mode = false
	}

	var rk *RRSet
	if len(opt.TrustAnchorFile) != 0 {
		rk, err := loadRootKeysFromXML(opt.TrustAnchorFile)
		if err != nil || len(rk.RrSet) == 0 {
			Log.Error("Error loading root keys", slog.String("error", err.Error()))
			return nil
		}

		Log.Debug("Succesfully Loaded Root Keys")
	}

	return &DNSSECvalidator{id: id, resolver: resolver, fwdUnsigned: mode, rootKeys: rk}
}

func (d *DNSSECvalidator) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	var g errgroup.Group

	var rrSet *RRSet
	var response *dns.Msg
	var nsecs []dns.RR

	doIsSet := q.IsEdns0().Do()

	// Resolve the A query with RRSIG option
	g.Go(func() error {
		res, err := d.resolver.Resolve(setDNSSECdo(q), ci)
		if err != nil {
			return err
		}
		response = res.Copy()
		rrSet = extractRRset(response)
		if rrSet.checkHeaderIntegrity(qName(q)) {
			return ErrForgedRRsig
		}
		if rrSet.isEmpty() || !rrSet.isSigned() {
			nsecs = extractNSEC(res)
		}
		return nil
	})

	// Resolve the entire DNSSEC authentication chain
	authChain := &AuthenticationChain{}
	g.Go(func() error {
		return authChain.Populate(qName(q), d.resolver, ci)
	})

	if err := g.Wait(); err != nil {
		if rrSet == nil {
			return nil, err
		}

		if !rrSet.isEmpty() {
			if errors.Is(err, ErrResourceNotSigned) || errors.Is(err, ErrDnskeyNotAvailable) {
				if d.fwdUnsigned {
					Log.Debug("Forwarding unsigned DNS Record Answer", slog.String("domain", qName(q)))
					return forwardResponse(response, doIsSet), nil
				}
				Log.Debug("Dropping unsigned DNS Record Answer")
				return nil, ErrResourceNotSigned
			}
			return nil, err
		}
	}

	if len(nsecs) > 0 && rrSet.isEmpty() { // NSEC Validate non-existance of record
		validNsecSet, err := authChain.ValidateNSEC(nsecs)
		if err != nil {
			Log.Debug("have some error validating the NSEC records")
			return nil, err
		}

		var nsecErr error
		qname := qName(response)
		qtype := response.Question[0].Qtype
		rcode := rCode(response)
		if validNsecSet[0].Header().Rrtype == dns.TypeNSEC {
			nsecErr = denialNSEC(validNsecSet, qname, qtype)
		} else {
			nsecErr = denialNSEC3(validNsecSet, qname, qtype, rcode)
		}

		if nsecErr != nil {
			return nil, ErrResourceNotSigned
		}
		return nil, ErrNoResult
	}

	if err := authChain.Verify(rrSet, d.rootKeys); err != nil {
		return nil, err
	}

	Log.Debug("Valid DNS Record Answer", slog.String("domain", qName(q)))
	return forwardResponse(response, doIsSet), nil
}

func (d *DNSSECvalidator) String() string {
	return d.id
}
