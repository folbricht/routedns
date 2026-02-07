/*
Package rdns implements a variety of functionality to make DNS resolution configurable
and extensible. It offers DNS resolvers as well as listeners with a number of protocols
such as DNS-over-TLS, DNS-over-HTTP, and plain wire format DNS. In addition it is
possible to route queries based on the query name or type. There are 4 fundamental types
of objects available in this library.

Resolvers

Resolvers implement name resolution with upstream resolvers. All of them implement connection
reuse as well as pipelining (sending multiple queries and receiving them out-of-order).

Groups

Groups typically wrap multiple resolvers and implement failover or load-balancing algorithms
across all resolvers in the group. Groups too are resolvers and can therefore be nested
into other groups for more complex query routing.

Routers

Routers are used to send DNS queries to resolvers, groups, or even other routers based on
the query content. As with groups, routers too are resolvers that can be combined to form
more advanced configurations.

Listeners

While resolvers handle outgoing queries to upstream servers, listeners are the receivers
of queries. Multiple listeners can be started for different protocols and on different ports.
Each listener forwards received queries to one resolver, group, or router.

This example starts a stub resolver on the local machine which will forward all queries
via DNS-over-TLS to provide privacy.

	r := rdns.NewDoTClient("1.1.1.1:853")
	l := rdns.NewDNSListener("127.0.0.1:53", "udp", r)
	panic(l.Start())

*/
package rdns
