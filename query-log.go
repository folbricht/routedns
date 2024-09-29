package rdns

import (
	"context"
	"log/slog"
	"os"

	"github.com/miekg/dns"
)

// QueryLogResolver logs requests to STDOUT or file.
type QueryLogResolver struct {
	id       string
	resolver Resolver
	opt      QueryLogResolverOptions
	logger   *slog.Logger
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
	logger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == "msg" || a.Key == "level" {
				return slog.Attr{}
			}
			return a
		},
	}))
	return &QueryLogResolver{
		resolver: resolver,
		logger:   logger,
	}, nil
}

// Resolve logs the query details and passes the query to the next resolver.
func (r *QueryLogResolver) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	question := q.Question[0]
	attrs := []slog.Attr{
		slog.String("source-ip", ci.SourceIP.String()),
		slog.String("question-name", question.Name),
		slog.String("question-class", dns.Class(question.Qclass).String()),
		slog.String("question-type", dns.Type(question.Qtype).String()),
	}

	// Add ECS attributes if present
	edns0 := q.IsEdns0()
	if edns0 != nil {
		// Find the ECS option
		for _, opt := range edns0.Option {
			ecs, ok := opt.(*dns.EDNS0_SUBNET)
			if ok {
				attrs = append(attrs, slog.String("ecs-addr", ecs.Address.String()))
			}
		}
	}

	r.logger.LogAttrs(context.Background(), slog.LevelInfo, "", attrs...)
	return r.resolver.Resolve(q, ci)
}

func (r *QueryLogResolver) String() string {
	return r.id
}
