package rdns

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// QueryLogResolver logs requests to STDOUT or file.
type QueryLogResolver struct {
	id       string
	resolver Resolver
	opt      QueryLogResolverOptions
	w        io.Writer
	mu       sync.Mutex
}

var _ Resolver = &QueryLogResolver{}

type QueryLogResolverOptions struct {
	OutputFile string // Output filename, leave blank for STDOUT
}

// NewQueryLogResolver returns a new instance of a QueryLogResolver.
func NewQueryLogResolver(id string, resolver Resolver, opt QueryLogResolverOptions) (*QueryLogResolver, error) {
	w := os.Stdout
	if opt.OutputFile != "" {
		f, err := os.OpenFile(opt.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		w = f
	}
	return &QueryLogResolver{
		resolver: resolver,
		w:        w,
	}, nil
}

// Resolve logs the query details and passes the query to the next resolver.
func (r *QueryLogResolver) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	log := logger(r.id, q, ci)
	question := q.Question[0]
	now := time.Now().Format(time.RFC3339Nano)
	r.mu.Lock()
	_, err := fmt.Fprintf(r.w, "%s %s %s %s %s\n", now, ci.SourceIP, question.Name, dns.Class(question.Qclass).String(), dns.Type(question.Qtype).String())
	r.mu.Unlock()
	if err != nil {
		log.WithError(err).Error("failed to write query to log")
	}
	return r.resolver.Resolve(q, ci)
}

func (r *QueryLogResolver) String() string {
	return r.id
}
