# Lua Scripting

[Guide index](configuration.md) | [Overview](overview.md) | [Listeners](listeners.md) | [Routing](routing.md) | [Blocklists](blocklists.md) | [Caching and Performance](caching.md) | [Failover and Load Balancing](groups.md) | [Modifiers](modifiers.md) | [Responders](responders.md) | **Lua Scripting** | [DNSSEC and Rate Limiting](security.md) | [Logging](observability.md) | [Resolvers](resolvers.md) | [Templates](templates.md)

## Lua

`type = "lua"`

Lua groups allow writing custom query handling logic using Lua 5.4 scripts. The script must define a `Resolve(msg, ci)` function that receives the DNS message and client info, and returns a response message and error. The `msg` it receives is the script's own copy of the query, so it can be changed freely and passed to a resolver, and what the script does to it is not seen by the components it came through. Scripts run in a sandboxed environment by default with access to DNS types, message construction, and upstream resolvers. They are not available in binaries built with the `nolua` tag, such as the `routedns-minimal-*` release artifacts.

### Configuration

To enable a Lua group, add an element with `type = "lua"` in the groups section of the configuration. Either `lua-script` or `lua-script-source` must be provided.

Options:

- `resolvers` - Array of upstream resolvers accessible in the script as `Resolvers[1]`, `Resolvers[2]`, etc.
- `lua-script` - Inline Lua script (multi-line string in TOML using `"""`).
- `lua-script-source` - Path to an external `.lua` file. Alternative to `lua-script`.
- `lua-no-sandbox` - Disable the sandbox to allow `io`, `os` and loading code at run time. Default `false`.
- `lua-timeout` - Seconds a script may run before it is cut off, both for a query and for the top level of the script when it is loaded. Default `30`. A negative value removes the limit. See [Run time](#run-time).

### Sandbox

By default, scripts run in a sandbox with the `base`, `string`, `table`, `math`, `utf8` and `coroutine` libraries. There is no access to files, the operating system or the network, other than through the resolvers the group is given, and code cannot be loaded at run time: `dofile`, `loadfile` and `load` are not available, and `require` has nothing to load.

Set `lua-no-sandbox = true` to add the `io` library, the `os` library (`clock`, `time`, `date` and `difftime` only) and `load`. Only use this for trusted scripts. The `debug` library is not available either way.

### State between queries

Scripts cannot share or keep state between executions. The top level of the script runs once, when it is loaded, and what it sets up there, its globals, tables and local variables, is frozen afterwards and shared by every query. A query that tries to change any of it fails with `attempt to modify a frozen table`. This includes assigning a global inside `Resolve`, so variables used within a query must be declared `local`:

```lua
function Resolve(msg, ci)
    local answer, err = Resolvers[1]:resolve(msg, ci)  -- not: answer, err = ...
    return answer, err
end
```

Messages, questions, records and EDNS0 options can be changed by scripts, so they can't be built when the script loads, and a script that keeps one from its top level fails to start. Build them in `Resolve` instead. Strings, numbers and tables of them can be set up at the top level, for example a list of names to match.

Since every query sees the same frozen state, nothing needs to be guarded against other queries running at the same time, and a single group serves any number of queries at once.

The query a script receives is a copy, so what the script does to it is not seen by the components the query came through.

### Run time

A query fails with an error if its script runs longer than `lua-timeout` seconds, or does more work than the interpreter allows for one call (10 million steps, roughly loop iterations and function calls, and 64 MiB allocated). The same limits apply to the top level of the script when it is loaded, so a script that does not return there fails to start rather than hanging startup. A loop with no exit is cut off by the step limit within a fraction of a second.

Time spent waiting on an upstream resolver counts towards the timeout. A query the script sent is not interrupted, but the script is cut off as soon as it returns past the limit. Otherwise the limit is checked as the script runs, every thousand steps or so, so a single read that blocks, from a file opened with `lua-no-sandbox` for instance, is not interrupted either. A negative `lua-timeout` removes the time limit; the step and allocation limits stay.

### Performance

A script adds a few microseconds to a query. Measured on a 2017 laptop CPU (Intel i7-7600U), on top of the upstream lookup itself:

| Script | Added per query |
| --- | --- |
| Forward the query unchanged | about 2µs |
| Choose an upstream by matching the query name | about 3µs |
| Cap the TTL of each record in a three-record answer | about 5µs |

An upstream lookup over the internet typically takes 10 to 50 milliseconds, thousands of times longer, so a script makes no noticeable difference to how quickly a client gets its answer. One group runs its script for any number of queries at the same time, so queries don't wait for each other either. To run a script only for some queries, put it behind a [router](routing.md); behind a [cache](caching.md), it only runs for queries the cache can't answer.

The numbers come from `go test -bench Lua`, which runs these scripts against an in-process upstream, less the time that upstream takes on its own.

### Lua version

Scripts are Lua 5.4. Scripts written for Lua 5.1, which RouteDNS used up to v1.0.1, may need changes:

- `unpack` is `table.unpack`.
- `setfenv`, `getfenv` and `module` are gone.
- Integers and floats are separate types. The constants such as `TypeA` are integers, `/` always gives a float, and `//` is integer division. A field that takes a number, such as `ttl`, rejects a float that is not a whole number.
- Globals can't be assigned while handling a query, see [State between queries](#state-between-queries).

### Lua API

Scripts have access to the following types and globals:

- **Message** - DNS message. Create with `Message.new()`. Fields: `id`, `response`, `rcode`, `authoritative`, `recursion_desired`, `recursion_available`, `authenticated_data`, `questions`, `answer`, `ns`, `extra`. Methods: `:set_reply(request)`, `:set_question(name, type)`, `:is_edns0()`, `:set_edns0(udpsize, do)`. Note: methods use Lua colon syntax (e.g. `msg:set_reply(request)`).
- **Question** - DNS question. Create with `Question.new(name, qtype, qclass)`. Fields: `name`, `qtype`, `qclass`.
- **RR** - Resource record. Create with `RR.new({rtype = TypeA, name = "example.com.", class = ClassIN, ttl = 300, a = "1.2.3.4"})`. Header fields: `name`, `rtype`, `class`, `ttl`, `rdlength`. Data fields are type-specific and use lowercase names (e.g., `a`, `aaaa`, `ns`, `cname`, `mx`, `preference`, `target`, etc.).
- **OPT** - EDNS0 OPT pseudo-record. Create with `OPT.new(udp_size, do_bit)`. Fields: `udp_size`, `do_bit`, `version`, `extended_rcode`, `option` (array of EDNS0 options), `name`, `rtype`. Also returned by `Message:is_edns0()` and created implicitly by `Message:set_edns0(udp_size, do_bit)`.
- **ClientInfo** - Client information passed as the second argument (`ci`) to `Resolve(msg, ci)`. Read-only fields: `source_ip` (string or nil), `doh_path` (string), `tls_server_name` (string), `listener` (string), `protocol` (string, the transport the query arrived on, one of `udp`, `tcp`, `dot`, `doh`, `doq`, `dtls` or `odoh`), `listener_addr` (string, the address the receiving listener is bound to). The last two are empty for queries that were not produced by a listener, such as those from the `prefetch` component.
- **Error** - Error value. Create with `Error.new("message")`. Methods: `error()`.
- **Resolvers** - Table of upstream resolvers. Each resolver has a `:resolve(msg, ci)` method that returns `(response, error)` (e.g. `Resolvers[1]:resolve(msg, ci)`).
- **DNS constants** - Type constants (`TypeA`, `TypeAAAA`, `TypeMX`, ...), class constants (`ClassIN`, `ClassCH`, ...), rcode constants (`RcodeNOERROR`, `RcodeNXDOMAIN`, ...).
- **BuildVersion** - String constant containing the RouteDNS build version (e.g. `"v0.1.138"`).
- **EDNS0 option constants** - `EDNS0SUBNET`, `EDNS0COOKIE`, `EDNS0EDE`, `EDNS0PADDING`, etc.
- **EDNS0 types** - `EDNS0_SUBNET`, `EDNS0_COOKIE`, `EDNS0_EDE`, `EDNS0_PADDING`, `EDNS0_NSID`, `EDNS0_LOCAL`, and others. Each has a `new(...)` constructor and field accessors.

### Examples

Simple passthrough to an upstream resolver:

```toml
[groups.lua-proxy]
type = "lua"
resolvers = ["cloudflare-dot"]
lua-script = """
function Resolve(msg, ci)
    local answer, err = Resolvers[1]:resolve(msg, ci)
    if err ~= nil then
        return nil, err
    end
    return answer, nil
end
"""
```

Return a static A record for a specific domain, forwarding everything else upstream:

```toml
[groups.lua-static]
type = "lua"
resolvers = ["cloudflare-dot"]
lua-script = """
function Resolve(msg, ci)
    local q = msg.questions[1]

    -- Return a static A record for "example.com"
    if q.name == "example.com." and q.qtype == TypeA then
        local answer = Message.new()
        answer:set_reply(msg)
        local rr = RR.new({rtype = TypeA, name = q.name, class = ClassIN, ttl = 300, a = "192.168.1.1"})
        answer.answer = { rr }
        return answer, nil
    end

    -- Forward everything else upstream
    return Resolvers[1]:resolve(msg, ci)
end
"""
```

Route queries to different resolvers based on name patterns:

```toml
[groups.lua-router]
type = "lua"
resolvers = ["cloudflare-dot", "google-dot"]
lua-script = """
function Resolve(msg, ci)
    local q = msg.questions[1]
    local name = q.name

    -- Route .google.com queries to Google DNS
    if string.find(name, "google%.com%.$") then
        return Resolvers[2]:resolve(msg, ci)
    end

    -- Everything else goes to Cloudflare
    return Resolvers[1]:resolve(msg, ci)
end
"""
```

Route queries based on client information (source IP, listener, TLS server name):

```toml
[groups.lua-client-routing]
type = "lua"
resolvers = ["internal-resolver", "external-resolver"]
lua-script = """
function Resolve(msg, ci)
    -- Route queries from internal network to internal resolver
    if ci.source_ip ~= nil and string.find(ci.source_ip, "^192%.168%.") then
        return Resolvers[1]:resolve(msg, ci)
    end

    -- Route based on TLS server name
    if ci.tls_server_name == "private.dns.example.com" then
        return Resolvers[1]:resolve(msg, ci)
    end

    -- Treat anything that arrived over an encrypted transport as trusted
    if ci.protocol == "dot" or ci.protocol == "doh" or ci.protocol == "doq" then
        return Resolvers[1]:resolve(msg, ci)
    end

    -- Everything else goes to the external resolver
    return Resolvers[2]:resolve(msg, ci)
end
"""
```

Load the script from an external file:

```toml
[groups.lua-custom]
type = "lua"
resolvers = ["cloudflare-dot"]
lua-script-source = "/etc/routedns/custom.lua"
```

Block a domain with NXDOMAIN and attach an EDNS0 Extended DNS Error (EDE):

```toml
[groups.lua-ede-block]
type = "lua"
lua-script = """
function Resolve(msg, ci)
    local q = msg.questions[1]

    if q.name == "blocked.example.com." then
        local answer = Message.new()
        answer:set_reply(msg)
        answer.rcode = RcodeNXDOMAIN

        -- Add EDNS0 OPT with an EDE option (info code 15 = Blocked)
        answer:set_edns0(4096, false)
        local opt = answer:is_edns0()
        local ede = EDNS0_EDE.new(15, "domain blocked by policy")
        opt.option = { ede }

        return answer, nil
    end

    return Resolvers[1]:resolve(msg, ci)
end
"""
resolvers = ["cloudflare-dot"]
```

Example config files: [lua-passthrough.toml](../cmd/routedns/example-config/lua-passthrough.toml), [lua-static-answer.toml](../cmd/routedns/example-config/lua-static-answer.toml), [lua-routing.toml](../cmd/routedns/example-config/lua-routing.toml), [lua-opt.toml](../cmd/routedns/example-config/lua-opt.toml)
