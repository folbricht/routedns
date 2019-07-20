package main

import (
	"fmt"
	"os"
	"time"

	rdns "github.com/folbricht/routedns"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type options struct {
	logLevel uint32
}

func main() {
	var opt options
	cmd := &cobra.Command{
		Use:   "routedns",
		Short: "DNS stub resolver, proxy and router",
		Long: `DNS stub resolver, proxy and router.

Listens for incoming DNS requests, routes, modifies and 
forwards to upstream resolvers. Supports plain DNS over 
UDP and TCP as well as DNS-over-TLS and DNS-over-HTTPS
as listener and client protocols.

Routes can be defined to send requests for certain queries;
by record type, query name or client-IP to different modifiers
or upstream resolvers.
`,
		Example: `  routedns config.toml`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return start(opt, args)
		},
		SilenceUsage: true,
	}
	cmd.Flags().Uint32VarP(&opt.logLevel, "log-level", "l", 4, "log level; 0=None .. 6=Trace")
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}

}

func start(opt options, args []string) error {
	// Set the log level in the library package
	if opt.logLevel > 6 {
		return fmt.Errorf("invalid log level: %d", opt.logLevel)
	}
	rdns.Log.SetLevel(logrus.Level(opt.logLevel))

	configFile := args[0]
	config, err := loadConfig(configFile)
	if err != nil {
		return err
	}

	// Map to hold all the resolvers extracted from the config, key'ed by resolver ID. It
	// holds configured resolvers, groups, as well as routers (since they all implement
	// rdns.Resolver)
	resolvers := make(map[string]rdns.Resolver)

	// Parse resolver config from the config first since groups and routers reference them
	for id, r := range config.Resolvers {
		switch r.Protocol {
		case "dot":
			tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
			if err != nil {
				return err
			}
			resolvers[id] = rdns.NewDoTClient(r.Address, rdns.DoTClientOptions{TLSConfig: tlsConfig})
		case "doh":
			tlsConfig, err := rdns.TLSClientConfig(r.CA, r.ClientCrt, r.ClientKey)
			if err != nil {
				return err
			}
			opt := rdns.DoHClientOptions{
				Method:    r.DoH.Method,
				TLSConfig: tlsConfig,
			}
			resolvers[id], err = rdns.NewDoHClient(r.Address, opt)
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
	// later. Since groups can reference other groups, we need to figure out which ones to
	// process first. That's done by analysing the dependencies between them.
	for _, id := range groupKeyOrder(config.Groups) {
		g := config.Groups[id]
		if _, ok := resolvers[id]; ok {
			return fmt.Errorf("group defined with duplicate id '%s", id)
		}
		var gr []rdns.Resolver
		for _, rid := range g.Resolvers {
			resolver, ok := resolvers[rid]
			if !ok {
				return fmt.Errorf("group '%s' references non-existant resolver or group '%s", id, rid)
			}
			gr = append(gr, resolver)
		}
		switch g.Type {
		case "round-robin":
			resolvers[id] = rdns.NewRoundRobin(gr...)
		case "fail-rotate":
			resolvers[id] = rdns.NewFailRotate(gr...)
		case "fail-back":
			resolvers[id] = rdns.NewFailBack(rdns.FailBackOptions{ResetAfter: time.Minute}, gr...)
		case "blocklist":
			if len(gr) != 1 {
				return fmt.Errorf("type blocklist only supports one resolver in '%s'", id)
			}
			resolvers[id], err = rdns.NewBlocklist(gr[0], g.Blocklist...)
			if err != nil {
				return err
			}
		case "replace":
			if len(gr) != 1 {
				return fmt.Errorf("type replace only supports one resolver in '%s'", id)
			}
			resolvers[id], err = rdns.NewReplace(gr[0], g.Replace...)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported group type '%s' for group '%s", g.Type, id)
		}
	}

	// Parse the routers next. These can be referenced by listeners and by other routers.
	for _, id := range routerKeyOrder(config.Routers) {
		r := config.Routers[id]
		if _, ok := resolvers[id]; ok {
			return fmt.Errorf("router defined with duplicate id '%s", id)
		}
		router := rdns.NewRouter()
		for _, route := range r.Routes {
			resolver, ok := resolvers[route.Resolver]
			if !ok {
				return fmt.Errorf("router '%s' references non-existant resolver or group '%s", id, route.Resolver)
			}
			if err := router.Add(route.Name, route.Type, route.Source, resolver); err != nil {
				return fmt.Errorf("failure parsing routes for router '%s' : %s", id, err.Error())
			}
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
		case "dot":
			tlsConfig, err := rdns.TLSServerConfig(l.CA, l.ServerCrt, l.ServerKey, l.MutualTLS)
			if err != nil {
				return err
			}
			ln := rdns.NewDoTListener(l.Address, rdns.DoTListenerOptions{TLSConfig: tlsConfig}, resolver)
			listeners = append(listeners, ln)
		case "doh":
			tlsConfig, err := rdns.TLSServerConfig(l.CA, l.ServerCrt, l.ServerKey, l.MutualTLS)
			if err != nil {
				return err
			}
			ln := rdns.NewDoHListener(l.Address, rdns.DoHListenerOptions{TLSConfig: tlsConfig}, resolver)
			listeners = append(listeners, ln)
		default:
			return fmt.Errorf("unsupported protocol '%s' for listener '%s'", l.Protocol, id)
		}
	}

	// Start the listeners
	for _, l := range listeners {
		go func(l rdns.Listener) {
			for {
				err := l.Start()
				rdns.Log.WithError(err).Error("listener failed")
				time.Sleep(time.Second)
			}
		}(l)
	}

	select {}
}
