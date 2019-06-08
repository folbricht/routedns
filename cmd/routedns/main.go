package main

import (
	"fmt"
	"log"
	"os"
	"time"

	rdns "github.com/folbricht/routedns"
	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:   "routedns",
		Short: "DNS router and proxy resolver",
		Long: `DNS router and proxy resolver.

It listens for incoming DNS requests and forwards
them to upstream resolvers. Supports plain DNS over
UDP and TCP as well as DNS-over-TLS as input and
forwarding protocol.

Routes can be defined to send requests for certain
queries (record type or query name) to different
upstream resolvers.
`,
		Example: `  routedns config.toml`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return start(args)
		},
		SilenceUsage: true,
	}
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}

}

func start(args []string) error {
	configFile := args[0]
	config, err := loadConfig(configFile)
	if err != nil {
		return err
	}

	// Set the logger
	rdns.Log = log.New(os.Stderr, "", log.LstdFlags)

	// Map to hold all the resolvers extracted from the config, key'ed by resolver ID. It
	// holds configured resolvers, groups, as well as routers (since they all implement
	// rdns.Resolver)
	resolvers := make(map[string]rdns.Resolver)

	// Parse resolver config from the config first since groups and routers reference them
	for id, r := range config.Resolvers {
		switch r.Protocol {
		case "dot":
			resolvers[id] = rdns.NewDoTClient(r.Address)
		case "doh":
			resolvers[id], err = rdns.NewDoHClient(r.Address, rdns.DoHClientOptions{Method: r.DOHMethod})
			if err != nil {
				return fmt.Errorf("failed to parse resolver config for '%s' : %s", id, err)
			}
		case "tcp":
			resolvers[id] = rdns.NewDNSClient(r.Address, "tcp")
		case "udp":
			resolvers[id] = rdns.NewDNSClient(r.Address, "udp")
		default:
			return fmt.Errorf("unsupported protocol '%s' for resolver '%s'", r.Protocol, id)
		}
	}

	// Now the resolver groups. They reference the resolvers above and are used by routers
	// later.
	for id, g := range config.Groups {
		if _, ok := resolvers[id]; ok {
			return fmt.Errorf("group defined with duplicate id '%s", id)
		}
		switch g.Type {
		case "round-robin":
			var gr []rdns.Resolver
			for _, rid := range g.Resolvers {
				resolver, ok := resolvers[rid]
				if !ok {
					return fmt.Errorf("group '%s' references non-existant resolver or group '%s", id, rid)
				}
				gr = append(gr, resolver)
			}
			resolvers[id] = rdns.NewRoundRobin(gr...)
		default:
			return fmt.Errorf("unsupported group type '%s' for group '%s", g.Type, id)
		}
	}

	// Parse the routers next. These can be referenced by listeners.
	for id, r := range config.Routers {
		if _, ok := resolvers[id]; ok {
			return fmt.Errorf("router defined with duplicate id '%s", id)
		}
		router := rdns.NewRouter()
		for _, route := range r.Routes {
			resolver, ok := resolvers[route.Resolver]
			if !ok {
				return fmt.Errorf("router '%s' references non-existant resolver or group '%s", id, route.Resolver)
			}
			router.Add(route.Name, route.Type, resolver)
		}
		resolvers[id] = router
	}

	// Build the Listeners last as they can point to routers, groups or resolvers directly.
	var listeners []rdns.Listener
	for id, l := range config.Listeners {
		resolver, ok := resolvers[l.Resolver]
		if !ok {
			return fmt.Errorf("listener '%s' references non-existant resolver, group or router '%s", id, l.Resolver)
		}
		switch l.Protocol {
		case "tcp":
			listeners = append(listeners, rdns.NewDNSListener(l.Address, "tcp", resolver))
		case "udp":
			listeners = append(listeners, rdns.NewDNSListener(l.Address, "udp", resolver))
		default:
			return fmt.Errorf("unsupported protocol '%s' for listener '%s'", l.Protocol, id)
		}
	}

	// Start the listeners
	for _, l := range listeners {
		go func(l rdns.Listener) {
			for {
				log.Println("starting listener", l)
				err := l.Start()
				log.Println("listener", l, "failed:", err)
				time.Sleep(time.Second)
			}
		}(l)
	}

	select {}
}
