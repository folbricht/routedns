package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	rdns "github.com/folbricht/routedns"
	"github.com/heimdalr/dag"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type options struct {
	logLevel uint32
	version  bool
}

func main() {
	var opt options
	cmd := &cobra.Command{
		Use:   "routedns <config> [<config>..]",
		Short: "DNS stub resolver, proxy and router",
		Long: `DNS stub resolver, proxy and router.

Listens for incoming DNS requests, routes, modifies and
forwards to upstream resolvers. Supports plain DNS over
UDP and TCP as well as DNS-over-TLS and DNS-over-HTTPS
as listener and client protocols.

Routes can be defined to send requests for certain queries;
by record type, query name or client-IP to different modifiers
or upstream resolvers.

Configuration can be split over multiple files with listeners,
groups and routers defined in different files and provided as
arguments.
`,
		Example: `  routedns config.toml`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return start(opt, args)
		},
		SilenceUsage: true,
	}

	cmd.Flags().Uint32VarP(&opt.logLevel, "log-level", "l", 4, "log level; 0=None .. 6=Trace")
	cmd.Flags().BoolVarP(&opt.version, "version", "v", false, "Prints code version string")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}

}

type Node struct {
	id    string
	value interface{}
}

var _ dag.IDInterface = Node{}

func (n Node) ID() string {
	return n.id
}

func start(opt options, args []string) error {
	// Set the log level in the library package
	if opt.logLevel > 6 {
		return fmt.Errorf("invalid log level: %d", opt.logLevel)
	}
	if opt.version {
		printVersion()
		os.Exit(0)
	} else {
		if len(args) < 1 {
			return errors.New("not enough arguments")
		}

	}
	rdns.Log.SetLevel(logrus.Level(opt.logLevel))

	config, err := loadConfig(args...)
	if err != nil {
		return err
	}

	// Map to hold all the resolvers extracted from the config, key'ed by resolver ID. It
	// holds configured resolvers, groups, as well as routers (since they all implement
	// rdns.Resolver)
	resolvers := make(map[string]rdns.Resolver)

	// See if a bootstrap-resolver was defined in the config. If so, instantiate it,
	// wrap it in a net.Resolver wrapper and replace the net.DefaultResolver with it
	// for all other entities to use.
	if config.BootstrapResolver.Address != "" {
		if err := instantiateResolver("bootstrap-resolver", config.BootstrapResolver, resolvers); err != nil {
			return fmt.Errorf("failed to instantiate bootstrap-resolver: %w", err)
		}
		net.DefaultResolver = rdns.NewNetResolver(resolvers["bootstrap-resolver"])
	}
	// Add all types of nodes to a DAG, this is to find duplicates. Then populate the edges (dependencies).
	graph := dag.NewDAG()
	edges := make(map[string][]string)
	for id, v := range config.Resolvers {
		node := &Node{id, v}
		_, err := graph.AddVertex(node)
		if err != nil {
			return err
		}
	}
	for id, v := range config.Groups {
		node := &Node{id, v}
		_, err := graph.AddVertex(node)
		if err != nil {
			return err
		}
		edges[id] = append(v.Resolvers, v.AllowListResolver, v.BlockListResolver, v.LimitResolver, v.RetryResolver)
	}
	for id, v := range config.Routers {
		node := &Node{id, v}
		_, err := graph.AddVertex(node)
		if err != nil {
			return err
		}
		// One router can have multiple edges to the same resolver.
		// Dedup them before adding to the list of edges.
		dep := make(map[string]struct{})
		for _, route := range v.Routes {
			dep[route.Resolver] = struct{}{}
		}
		for r := range dep {
			edges[id] = append(edges[id], r)
		}
	}
	// Add the edges to the DAG. This will fail if there are duplicate edges, recursion or missing nodes
	for id, es := range edges {
		for _, e := range es {
			if e == "" {
				continue
			}
			if err := graph.AddEdge(id, e); err != nil {
				return err
			}
		}
	}

	// Instantiate the elements from leaves to the root nodes
	for graph.GetOrder() > 0 {
		leaves := graph.GetLeaves()
		for id, v := range leaves {
			node := v.(*Node)
			if r, ok := node.value.(resolver); ok {
				if err := instantiateResolver(id, r, resolvers); err != nil {
					return err
				}
			}
			if g, ok := node.value.(group); ok {
				if err := instantiateGroup(id, g, resolvers); err != nil {
					return err
				}
			}
			if r, ok := node.value.(router); ok {
				if err := instantiateRouter(id, r, resolvers); err != nil {
					return err
				}
			}
			if err := graph.DeleteVertex(id); err != nil {
				return err
			}
		}
	}

	// Build the Listeners last as they can point to routers, groups or resolvers directly.
	var listeners []rdns.Listener
	for id, l := range config.Listeners {
		resolver, ok := resolvers[l.Resolver]
		// All Listeners should route queries (except the admin service).
		if !ok && l.Protocol != "admin" {
			return fmt.Errorf("listener '%s' references non-existant resolver, group or router '%s'", id, l.Resolver)
		}

		allowedNet, err := parseCIDRList(l.AllowedNet)
		if err != nil {
			return err
		}

		opt := rdns.ListenOptions{AllowedNet: allowedNet}

		switch l.Protocol {
		case "tcp":
			listeners = append(listeners, rdns.NewDNSListener(id, l.Address, "tcp", opt, resolver))
		case "udp":
			listeners = append(listeners, rdns.NewDNSListener(id, l.Address, "udp", opt, resolver))
		case "admin":
			tlsConfig, err := rdns.TLSServerConfig(l.CA, l.ServerCrt, l.ServerKey, l.MutualTLS)
			if err != nil {
				return err
			}
			opt := rdns.AdminListenerOptions{
				TLSConfig:     tlsConfig,
				ListenOptions: opt,
				Transport:     l.Transport,
			}
			ln, err := rdns.NewAdminListener(id, l.Address, opt)
			if err != nil {
				return err
			}
			listeners = append(listeners, ln)
		case "dot":
			tlsConfig, err := rdns.TLSServerConfig(l.CA, l.ServerCrt, l.ServerKey, l.MutualTLS)
			if err != nil {
				return err
			}
			ln := rdns.NewDoTListener(id, l.Address, rdns.DoTListenerOptions{TLSConfig: tlsConfig, ListenOptions: opt}, resolver)
			listeners = append(listeners, ln)
		case "dtls":
			dtlsConfig, err := rdns.DTLSServerConfig(l.CA, l.ServerCrt, l.ServerKey, l.MutualTLS)
			if err != nil {
				return err
			}
			ln := rdns.NewDTLSListener(id, l.Address, rdns.DTLSListenerOptions{DTLSConfig: dtlsConfig, ListenOptions: opt}, resolver)
			listeners = append(listeners, ln)
		case "doh":
			tlsConfig, err := rdns.TLSServerConfig(l.CA, l.ServerCrt, l.ServerKey, l.MutualTLS)
			if err != nil {
				return err
			}
			var httpProxyNet *net.IPNet
			if l.Frontend.HTTPProxyNet != "" {
				_, httpProxyNet, err = net.ParseCIDR(l.Frontend.HTTPProxyNet)
				if err != nil {
					return fmt.Errorf("listener '%s' trusted-proxy '%s': %v", id, l.Frontend.HTTPProxyNet, err)
				}
			}
			opt := rdns.DoHListenerOptions{
				TLSConfig:     tlsConfig,
				ListenOptions: opt,
				Transport:     l.Transport,
				HTTPProxyNet:  httpProxyNet,
			}
			ln, err := rdns.NewDoHListener(id, l.Address, opt, resolver)
			if err != nil {
				return err
			}
			listeners = append(listeners, ln)
		case "doq":
			tlsConfig, err := rdns.TLSServerConfig(l.CA, l.ServerCrt, l.ServerKey, l.MutualTLS)
			if err != nil {
				return err
			}
			ln := rdns.NewQUICListener(id, l.Address, rdns.DoQListenerOptions{TLSConfig: tlsConfig, ListenOptions: opt}, resolver)
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

// Instantiate a group object based on configuration and add to the map of resolvers by ID.
func instantiateGroup(id string, g group, resolvers map[string]rdns.Resolver) error {
	var gr []rdns.Resolver
	var err error
	for _, rid := range g.Resolvers {
		resolver, ok := resolvers[rid]
		if !ok {
			return fmt.Errorf("group '%s' references non-existant resolver or group '%s'", id, rid)
		}
		gr = append(gr, resolver)
	}
	switch g.Type {
	case "round-robin":
		resolvers[id] = rdns.NewRoundRobin(id, gr...)
	case "fail-rotate":
		opt := rdns.FailRotateOptions{
			ServfailError: g.ServfailError,
		}
		resolvers[id] = rdns.NewFailRotate(id, opt, gr...)
	case "fail-back":
		opt := rdns.FailBackOptions{
			ResetAfter:    time.Duration(g.ResetAfter),
			ServfailError: g.ServfailError,
		}
		resolvers[id] = rdns.NewFailBack(id, opt, gr...)
	case "fastest":
		resolvers[id] = rdns.NewFastest(id, gr...)
	case "random":
		opt := rdns.RandomOptions{
			ResetAfter:    time.Duration(g.ResetAfter),
			ServfailError: g.ServfailError,
		}
		resolvers[id] = rdns.NewRandom(id, opt, gr...)
	case "blocklist":
		if len(gr) != 1 {
			return fmt.Errorf("type blocklist only supports one resolver in '%s'", id)
		}
		if len(g.Blocklist) > 0 && g.Source != "" {
			return fmt.Errorf("static blocklist can't be used with 'source' in '%s'", id)
		}
		blocklistDB, err := newBlocklistDB(list{Format: g.Format, Source: g.Source}, g.Blocklist)
		if err != nil {
			return err
		}
		opt := rdns.BlocklistOptions{
			BlocklistDB:      blocklistDB,
			BlocklistRefresh: time.Duration(g.Refresh) * time.Second,
		}
		resolvers[id], err = rdns.NewBlocklist(id, gr[0], opt)
		if err != nil {
			return err
		}
	case "blocklist-v2":
		if len(gr) != 1 {
			return fmt.Errorf("type blocklist-v2 only supports one resolver in '%s'", id)
		}
		if len(g.Blocklist) > 0 && len(g.BlocklistSource) > 0 {
			return fmt.Errorf("static blocklist can't be used with 'source' in '%s'", id)
		}
		if len(g.Allowlist) > 0 && len(g.AllowlistSource) > 0 {
			return fmt.Errorf("static allowlist can't be used with 'source' in '%s'", id)
		}
		var blocklistDB rdns.BlocklistDB
		if len(g.Blocklist) > 0 {
			blocklistDB, err = newBlocklistDB(list{Format: g.BlocklistFormat}, g.Blocklist)
			if err != nil {
				return err
			}
		} else {
			var dbs []rdns.BlocklistDB
			for _, s := range g.BlocklistSource {
				db, err := newBlocklistDB(s, nil)
				if err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				dbs = append(dbs, db)
			}
			blocklistDB, err = rdns.NewMultiDB(dbs...)
			if err != nil {
				return err
			}
		}
		var allowlistDB rdns.BlocklistDB
		if len(g.Allowlist) > 0 {
			allowlistDB, err = newBlocklistDB(list{Format: g.BlocklistFormat}, g.Allowlist)
			if err != nil {
				return err
			}
		} else {
			var dbs []rdns.BlocklistDB
			for _, s := range g.AllowlistSource {
				db, err := newBlocklistDB(s, nil)
				if err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				dbs = append(dbs, db)
			}
			allowlistDB, err = rdns.NewMultiDB(dbs...)
			if err != nil {
				return err
			}
		}
		opt := rdns.BlocklistOptions{
			BlocklistResolver: resolvers[g.BlockListResolver],
			BlocklistDB:       blocklistDB,
			BlocklistRefresh:  time.Duration(g.BlocklistRefresh) * time.Second,
			AllowListResolver: resolvers[g.AllowListResolver],
			AllowlistDB:       allowlistDB,
			AllowlistRefresh:  time.Duration(g.AllowlistRefresh) * time.Second,
		}
		resolvers[id], err = rdns.NewBlocklist(id, gr[0], opt)
		if err != nil {
			return err
		}
	case "replace":
		if len(gr) != 1 {
			return fmt.Errorf("type replace only supports one resolver in '%s'", id)
		}
		resolvers[id], err = rdns.NewReplace(id, gr[0], g.Replace...)
		if err != nil {
			return err
		}
	case "ttl-modifier":
		if len(gr) != 1 {
			return fmt.Errorf("type ttl-modifier only supports one resolver in '%s'", id)
		}
		opt := rdns.TTLModifierOptions{
			MinTTL: g.TTLMin,
			MaxTTL: g.TTLMax,
		}
		resolvers[id] = rdns.NewTTLModifier(id, gr[0], opt)
	case "truncate-retry":
		if len(gr) != 1 {
			return fmt.Errorf("type truncate-retry only supports one resolver in '%s'", id)
		}
		retryResolver := resolvers[g.RetryResolver]
		if retryResolver == nil {
			return errors.New("type truncate-retry requires 'retry-resolver' option")
		}
		opt := rdns.TruncateRetryOptions{}
		resolvers[id] = rdns.NewTruncateRetry(id, gr[0], retryResolver, opt)
	case "request-dedup":
		if len(gr) != 1 {
			return fmt.Errorf("type request-dedup only supports one resolver in '%s'", id)
		}
		resolvers[id] = rdns.NewRequestDedup(id, gr[0])
	case "fastest-tcp":
		if len(gr) != 1 {
			return fmt.Errorf("type fastest-tcp only supports one resolver in '%s'", id)
		}
		opt := rdns.FastestTCPOptions{
			Port:          g.Port,
			WaitAll:       g.WaitAll,
			SuccessTTLMin: g.SuccessTTLMin,
		}
		resolvers[id] = rdns.NewFastestTCP(id, gr[0], opt)
	case "ecs-modifier":
		if len(gr) != 1 {
			return fmt.Errorf("type ecs-modifier only supports one resolver in '%s'", id)
		}
		var f rdns.ECSModifierFunc
		switch g.ECSOp {
		case "add":
			f = rdns.ECSModifierAdd(g.ECSAddress, g.ECSPrefix4, g.ECSPrefix6)
		case "delete":
			f = rdns.ECSModifierDelete
		case "privacy":
			f = rdns.ECSModifierPrivacy(g.ECSPrefix4, g.ECSPrefix6)
		case "":
		default:
			return fmt.Errorf("unsupported ecs-modifier operation '%s'", g.ECSOp)
		}
		resolvers[id], err = rdns.NewECSModifier(id, gr[0], f)
		if err != nil {
			return err
		}
	case "edns0-modifier":
		if len(gr) != 1 {
			return fmt.Errorf("type edns0-modifier only supports one resolver in '%s'", id)
		}
		var f rdns.EDNS0ModifierFunc
		switch g.EDNS0Op {
		case "add":
			f = rdns.EDNS0ModifierAdd(g.EDNS0Code, g.EDNS0Data)
		case "delete":
			f = rdns.EDNS0ModifierDelete(g.EDNS0Code)
		case "":
		default:
			return fmt.Errorf("unsupported edns0-modifier operation '%s'", g.EDNS0Op)
		}
		resolvers[id], err = rdns.NewEDNS0Modifier(id, gr[0], f)
		if err != nil {
			return err
		}
	case "cache":
		var shuffleFunc rdns.AnswerShuffleFunc
		switch g.CacheAnswerShuffle {
		case "": // default
		case "random":
			shuffleFunc = rdns.AnswerShuffleRandon
		case "round-robin":
			shuffleFunc = rdns.AnswerShuffleRoundRobin
		default:
			return fmt.Errorf("unsupported shuffle function %q", g.CacheAnswerShuffle)
		}
		opt := rdns.CacheOptions{
			GCPeriod:            time.Duration(g.GCPeriod) * time.Second,
			Capacity:            g.CacheSize,
			NegativeTTL:         g.CacheNegativeTTL,
			ShuffleAnswerFunc:   shuffleFunc,
			HardenBelowNXDOMAIN: g.CacheHardenBelowNXDOMAIN,
			FlushQuery:          g.CacheFlushQuery,
		}
		resolvers[id] = rdns.NewCache(id, gr[0], opt)
	case "response-blocklist-ip", "response-blocklist-cidr": // "response-blocklist-cidr" has been retired/renamed to "response-blocklist-ip"
		if len(gr) != 1 {
			return fmt.Errorf("type response-blocklist-ip only supports one resolver in '%s'", id)
		}
		if len(g.Blocklist) > 0 && len(g.BlocklistSource) > 0 {
			return fmt.Errorf("static blocklist can't be used with 'blocklist-source' in '%s'", id)
		}
		var blocklistDB rdns.IPBlocklistDB
		if len(g.Blocklist) > 0 {
			blocklistDB, err = newIPBlocklistDB(list{Format: g.BlocklistFormat}, g.LocationDB, g.Blocklist)
			if err != nil {
				return err
			}
		} else {
			var dbs []rdns.IPBlocklistDB
			for _, s := range g.BlocklistSource {
				db, err := newIPBlocklistDB(s, g.LocationDB, nil)
				if err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				dbs = append(dbs, db)
			}
			blocklistDB, err = rdns.NewMultiIPDB(dbs...)
			if err != nil {
				return err
			}
		}
		opt := rdns.ResponseBlocklistIPOptions{
			BlocklistResolver: resolvers[g.BlockListResolver],
			BlocklistDB:       blocklistDB,
			BlocklistRefresh:  time.Duration(g.BlocklistRefresh) * time.Second,
			Filter:            g.Filter,
		}
		resolvers[id], err = rdns.NewResponseBlocklistIP(id, gr[0], opt)
		if err != nil {
			return err
		}
	case "response-blocklist-name":
		if len(gr) != 1 {
			return fmt.Errorf("type response-blocklist-name only supports one resolver in '%s'", id)
		}
		if len(g.Blocklist) > 0 && len(g.BlocklistSource) > 0 {
			return fmt.Errorf("static blocklist can't be used with 'blocklist-source' in '%s'", id)
		}
		var blocklistDB rdns.BlocklistDB
		if len(g.Blocklist) > 0 {
			blocklistDB, err = newBlocklistDB(list{Format: g.BlocklistFormat}, g.Blocklist)
			if err != nil {
				return err
			}
		} else {
			var dbs []rdns.BlocklistDB
			for _, s := range g.BlocklistSource {
				db, err := newBlocklistDB(s, nil)
				if err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				dbs = append(dbs, db)
			}
			blocklistDB, err = rdns.NewMultiDB(dbs...)
			if err != nil {
				return err
			}
		}
		opt := rdns.ResponseBlocklistNameOptions{
			BlocklistResolver: resolvers[g.BlockListResolver],
			BlocklistDB:       blocklistDB,
			BlocklistRefresh:  time.Duration(g.BlocklistRefresh) * time.Second,
		}
		resolvers[id], err = rdns.NewResponseBlocklistName(id, gr[0], opt)
		if err != nil {
			return err
		}
	case "client-blocklist":
		if len(gr) != 1 {
			return fmt.Errorf("type client-blocklist only supports one resolver in '%s'", id)
		}
		if len(g.Blocklist) > 0 && len(g.BlocklistSource) > 0 {
			return fmt.Errorf("static blocklist can't be used with 'blocklist-source' in '%s'", id)
		}
		var blocklistDB rdns.IPBlocklistDB
		if len(g.Blocklist) > 0 {
			blocklistDB, err = newIPBlocklistDB(list{Format: g.BlocklistFormat}, g.LocationDB, g.Blocklist)
			if err != nil {
				return err
			}
		} else {
			var dbs []rdns.IPBlocklistDB
			for _, s := range g.BlocklistSource {
				db, err := newIPBlocklistDB(s, g.LocationDB, nil)
				if err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				dbs = append(dbs, db)
			}
			blocklistDB, err = rdns.NewMultiIPDB(dbs...)
			if err != nil {
				return err
			}
		}
		opt := rdns.ClientBlocklistOptions{
			BlocklistResolver: resolvers[g.BlockListResolver],
			BlocklistDB:       blocklistDB,
			BlocklistRefresh:  time.Duration(g.BlocklistRefresh) * time.Second,
		}
		resolvers[id], err = rdns.NewClientBlocklist(id, gr[0], opt)
		if err != nil {
			return err
		}

	case "static-responder":
		opt := rdns.StaticResolverOptions{
			Answer: g.Answer,
			NS:     g.NS,
			Extra:  g.Extra,
			RCode:  g.RCode,
		}
		resolvers[id], err = rdns.NewStaticResolver(id, opt)
		if err != nil {
			return err
		}
	case "response-minimize":
		if len(gr) != 1 {
			return fmt.Errorf("type response-minimize only supports one resolver in '%s'", id)
		}
		resolvers[id] = rdns.NewResponseMinimize(id, gr[0])
	case "response-collapse":
		if len(gr) != 1 {
			return fmt.Errorf("type response-collapse only supports one resolver in '%s'", id)
		}
		opt := rdns.ResponseCollapsOptions{
			NullRCode: g.NullRCode,
		}
		resolvers[id] = rdns.NewResponseCollapse(id, gr[0], opt)
	case "drop":
		resolvers[id] = rdns.NewDropResolver(id)
	case "rate-limiter":
		if len(gr) != 1 {
			return fmt.Errorf("type rate-limiter only supports one resolver in '%s'", id)
		}
		opt := rdns.RateLimiterOptions{
			Requests:      g.Requests,
			Window:        g.Window,
			Prefix4:       g.Prefix4,
			Prefix6:       g.Prefix6,
			LimitResolver: resolvers[g.LimitResolver],
		}
		resolvers[id] = rdns.NewRateLimiter(id, gr[0], opt)

	default:
		return fmt.Errorf("unsupported group type '%s' for group '%s'", g.Type, id)
	}
	return nil
}

// Instantiate a router object based on configuration and add to the map of resolvers by ID.
func instantiateRouter(id string, r router, resolvers map[string]rdns.Resolver) error {
	router := rdns.NewRouter(id)
	for _, route := range r.Routes {
		resolver, ok := resolvers[route.Resolver]
		if !ok {
			return fmt.Errorf("router '%s' references non-existant resolver or group '%s'", id, route.Resolver)
		}
		types := route.Types
		if route.Type != "" { // Support the deprecated "Type" by just adding it to "Types" if defined
			types = append(types, route.Type)
		}
		r, err := rdns.NewRoute(route.Name, route.Class, types, route.Weekdays, route.Before, route.After, route.Source, resolver)
		if err != nil {
			return fmt.Errorf("failure parsing routes for router '%s' : %s", id, err.Error())
		}
		r.Invert(route.Invert)
		router.Add(r)
	}
	resolvers[id] = router
	return nil
}

func newBlocklistDB(l list, rules []string) (rdns.BlocklistDB, error) {
	loc, err := url.Parse(l.Source)
	if err != nil {
		return nil, err
	}
	var loader rdns.BlocklistLoader
	if len(rules) > 0 {
		loader = rdns.NewStaticLoader(rules)
	} else {
		switch loc.Scheme {
		case "http", "https":
			opt := rdns.HTTPLoaderOptions{
				CacheDir: l.CacheDir,
			}
			loader = rdns.NewHTTPLoader(l.Source, opt)
		case "":
			loader = rdns.NewFileLoader(l.Source)
		default:
			return nil, fmt.Errorf("unsupported scheme '%s' in '%s'", loc.Scheme, l.Source)
		}
	}
	switch l.Format {
	case "regexp", "":
		return rdns.NewRegexpDB(loader)
	case "domain":
		return rdns.NewDomainDB(loader)
	case "hosts":
		return rdns.NewHostsDB(loader)
	default:
		return nil, fmt.Errorf("unsupported format '%s'", l.Format)
	}
}

func newIPBlocklistDB(l list, locationDB string, rules []string) (rdns.IPBlocklistDB, error) {
	loc, err := url.Parse(l.Source)
	if err != nil {
		return nil, err
	}
	var loader rdns.BlocklistLoader
	if len(rules) > 0 {
		loader = rdns.NewStaticLoader(rules)
	} else {
		switch loc.Scheme {
		case "http", "https":
			opt := rdns.HTTPLoaderOptions{
				CacheDir: l.CacheDir,
			}
			loader = rdns.NewHTTPLoader(l.Source, opt)
		case "":
			loader = rdns.NewFileLoader(l.Source)
		default:
			return nil, fmt.Errorf("unsupported scheme '%s' in '%s'", loc.Scheme, l.Source)
		}
	}

	switch l.Format {
	case "cidr", "":
		return rdns.NewCidrDB(loader)
	case "location":
		return rdns.NewGeoIPDB(loader, locationDB)
	default:
		return nil, fmt.Errorf("unsupported format '%s'", l.Format)
	}
}

func printVersion() {
	fmt.Println("Build: ", rdns.BuildNumber)
	fmt.Println("Build Time: ", rdns.BuildTime)
	fmt.Println("Version: ", rdns.BuildVersion)
}
