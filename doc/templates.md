# Templates

[Guide index](configuration.md) | [Overview](overview.md) | [Listeners](listeners.md) | [Routing](routing.md) | [Blocklists](blocklists.md) | [Caching and Performance](caching.md) | [Failover and Load Balancing](groups.md) | [Modifiers](modifiers.md) | [Responders](responders.md) | [Lua Scripting](scripting.md) | [DNSSEC and Rate Limiting](security.md) | [Logging](observability.md) | [Resolvers](resolvers.md) | **Templates**

Some options hold templates, i.e. text with placeholders that are populated at runtime with data from the query. Placeholders between `{{` and `}}` are replaced when the response is built. The template syntax is explained in more detail [here](https://pkg.go.dev/text/template).

Templates are supported in the following places:

| Option | Where |
| --- | --- |
| `edns0-ede` `text` | [Query Blocklist](blocklists.md#query-blocklist), [Response Blocklist](blocklists.md#response-blocklist) (`response-blocklist-ip` only), [Static Responder](responders.md#static-responder), [Static Template Responder](responders.md#static-template-responder) |
| `answer`, `ns`, `extra` | [Static Template Responder](responders.md#static-template-responder) |

An extended error text on a blocklist, for example, would be configured as `"Blocked {{ .Question }} with ID {{ .ID }} because reasons"` and filled in when a query is blocked.

**Data available to templates**

The following pieces of information from the query are available in the template:

- `ID` - The query ID.
- `Question` - The question string.
- `QuestionType` - The question type, `A`, `AAAA`, `CNAME` etc.
- `QuestionClass` - The query class, `IN`, `ANY`, etc.
- `Blocklist` - The name of the blocklist (only present if this request was blocked).
- `BlocklistRule` - The rule on the blocklist that matched (only present if this was blocked).

In addition to the [built-in template functions](https://pkg.go.dev/text/template#hdr-Functions), the following functions are available.

- `replaceAll` - Replace all instances of a substring with another. Equivalent to [strings.ReplaceAll](https://pkg.go.dev/strings#ReplaceAll)
- `trimPrefix` - Removes a prefix from string. Equivalent to [strings.TrimPrefix](https://pkg.go.dev/strings#TrimPrefix).
- `trimSuffix` - Removes a suffix from a string. Equivalent to [strings.TrimSuffix](https://pkg.go.dev/strings#TrimPrefix).
- `split` - Split strings into substrings using the given separator. Equivalent to [strings.Split](https://pkg.go.dev/strings#Split).
- `join` - Concatenates strings with a given separator. Equivalent to [strings.Join](https://pkg.go.dev/strings#Join).

Functions can be combined with conditionals to make more complex template such as this example.

```template
'{{ .Question }} 18000 IN NS {{ if (eq .QuestionType "AAAA") }}ns6{{ else }}ns4{{ end }}.example.com.'
```

Support for additional string-manipulation functions can be added as needed.
