package rdns_test

import (
	"fmt"

	rdns "github.com/folbricht/routedns"
	"github.com/miekg/dns"
)

func Example_resolver() {
	// Define resolver
	r, _ := rdns.NewDoTClient("test-dot", "dns.google:853", rdns.DoTClientOptions{})

	// Build a query
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)

	// Resolve the query
	a, _ := r.Resolve(q, rdns.ClientInfo{})
	fmt.Println(a)
}

func Example_group() {
	// Define resolvers
	r1, _ := rdns.NewDNSClient("google1", "8.8.8.8:53", "udp", rdns.DNSClientOptions{})
	r2, _ := rdns.NewDNSClient("google2", "8.8.4.4:53", "udp", rdns.DNSClientOptions{})

	// Combine them int a group that does round-robin over the two resolvers
	g := rdns.NewRoundRobin("test-rr", r1, r2)

	// Build a query
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)

	// Resolve the query
	a, _ := g.Resolve(q, rdns.ClientInfo{})
	fmt.Println(a)
}

func Example_router() {
	// Define resolvers
	google, _ := rdns.NewDNSClient("g-dns", "8.8.8.8:53", "udp", rdns.DNSClientOptions{})
	cloudflare, _ := rdns.NewDNSClient("cf-dns", "1.1.1.1:53", "udp", rdns.DNSClientOptions{})

	// Build a router that will send all "*.cloudflare.com" to the cloudflare
	// resolvber while everything else goes to the google resolver (default)
	r := rdns.NewRouter("my-router")
	_ = r.Add(`\.cloudflare\.com\.$`, "", "", "", cloudflare)
	_ = r.Add("", "", "", "", google)

	// Build a query
	q := new(dns.Msg)
	q.SetQuestion("www.cloudflare.com.", dns.TypeA)

	// Resolve the query
	a, _ := r.Resolve(q, rdns.ClientInfo{})
	fmt.Println(a)
}
