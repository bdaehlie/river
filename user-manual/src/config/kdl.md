# Configuration File (KDL)

The primary configuration file format used by River uses the
[KDL Configuration Language](https://kdl.dev/).

KDL is a language for describing structured data.

There are currently two major sections used by River:

## The `system` section

Here is an example `system` configuration block:

```kdl
system {
    threads-per-service 8
    daemonize false
    pid-file "/tmp/river.pidfile"

    // Path to upgrade socket
    //
    // NOTE: `upgrade` is NOT exposed in the config file, it MUST be set on the CLI
    // NOTE: This has issues if you use relative paths. See issue https://github.com/memorysafety/river/issues/50
    // NOTE: The upgrade command is only supported on Linux
    upgrade-socket "/tmp/river-upgrade.sock"
}
```

### `system.threads-per-service INT`

This field configures the number of threads spawned by each service. This configuration
applies to all services.

A positive, non-zero integer is provided as `INT`.

This field is optional, and defaults to `8`.

### `system.daemonize BOOL`

This field configures whether River should daemonize.

The values `true` or `false` is provided as `BOOL`.

This field is optional, and defaults to `false`.

If this field is set as `true`, then `system.pid-file` must also be set.

### `system.pid-file PATH`

This field configured the path to the created pidfile when River is configured
to daemonize.

A UTF-8 absolute path is provided as `PATH`.

This field is optional if `system.daemonize` is `false`, and required if
`system.daemonize` is `true`.

### `system.upgrade-socket`

This field configured the path to the upgrade socket when River is configured
to take over an existing instance.

A UTF-8 absolute path is provided as `PATH`.

This field is optional if the `--upgrade` flag is provided via CLI, and required if
`--upgrade` is not set.

## The `services` section

Here is an example `services` block:

```kdl
services {
    Example1 {
        listeners {
            "0.0.0.0:8080"
            "0.0.0.0:4443" cert-path="./assets/test.crt" key-path="./assets/test.key" offer-h2=true
        }
        connectors {
            load-balance {
                selection "Ketama" key="UriPath"
                health-check "TCP" frequency-ms=5000 timeout-ms=1000 \
                    consecutive-failure=2 consecutive-success=1
                refresh-bounds min-seconds=5 max-seconds=300
            }
            "91.107.223.4:443" tls-sni="onevariable.com" proto="h2-or-h1" \
                connection-timeout-ms=1000 read-timeout-ms=30000
            dns "backends.example.com" port=8080
            srv "_https._tcp.example.com" tls=true proto="h2-or-h1"
        }
        path-control {
            request-filters {
                filter kind="block-cidr-range" \
                    addrs="192.168.0.0/16, 10.0.0.0/8, 2001:0db8::0/32, 127.0.0.1" \
                    status=403
            }
            upstream-request {
                filter kind="remove-header-key-regex" pattern=".*(secret|SECRET).*"
                filter kind="upsert-header" key="x-proxy-friend" value="river"
            }
            upstream-response {
                filter kind="remove-header-key-regex" pattern=".*ETag.*"
                filter kind="upsert-header" key="x-with-love-from" value="river"
            }
        }
        rate-limiting {
            rule kind="source-ip" \
                max-buckets=4000 tokens-per-bucket=10 refill-qty=1 refill-rate-ms=10

            rule kind="specific-uri" pattern="static/.*" \
                max-buckets=2000 tokens-per-bucket=20 refill-qty=5 refill-rate-ms=1

            rule kind="any-matching-uri" pattern=r".*\.mp4" \
                tokens-per-bucket=50 refill-qty=2 refill-rate-ms=3
        }
    }
    Example3 {
        listeners {
            "0.0.0.0:9000"
            "0.0.0.0:9443" cert-path="./assets/test.crt" key-path="./assets/test.key" offer-h2=true
        }
        file-server {
            // The base path is what will be used as the "root" of the file server
            //
            // All files within the root will be available
            base-path "."
        }
    }
}
```

Each block represents a single service, with the name of the service serving as
the name of the block.

### `services.$NAME`

The `$NAME` field is a UTF-8 string, used as the name of the service. If the name
does not contain spaces, it is not necessary to surround the name in quotes.

Examples:

* `Example1` - Valid, "Example1"
* `"Example2"` - Valid, "Example2"
* `"Server One"` - Valid, "Server One"
* `Server Two` - Invalid (missing quotation marks)

### `services.$NAME.listeners`

This section contains one or more Listeners.
This section is required.
Listeners are specified in the form:

`"SOCKETADDR" [cert-path="PATH" key-path="PATH"] [acme-domains="DOMAINS"] [offer-h2=BOOL]`

`SOCKETADDR` is a UTF-8 string that is parsed into an IPv4 or IPv6 address and port.

If the listener should accept TLS connections, the certificate and key paths are
specified in the form `cert-path="PATH" key-path="PATH"`, where `PATH` is a UTF-8
path to the relevant files. If these are not provided, connections will be accepted
without TLS.

Alternatively, River can obtain and renew the certificate for you. This is
specified in the form `acme-domains="DOMAINS"`, where `DOMAINS` is a comma
separated list of domain names. This requires a top level `acme` section - see
[Automatic Certificates (ACME)](./acme.md) for the full description. `acme-domains`
may be combined with `cert-path` and `key-path`, in which case the certificate on
disk is served to clients whose requested name matches none of the managed domains.

If the listener should offer HTTP2.0 connections, this is specified in the form
`offer-h2=BOOL`, where `BOOL` is either `true` or `false`. `offer-h2` may only
be specified if the listener has TLS, either through `cert-path`/`key-path` or
through `acme-domains`. This configuration is
optional, and defaults to `true` if TLS is configured. If this field is `true`,
HTTP2.0 will be offered (but not required). If this field is `false` then only
HTTP1.x will be offered.

### `services.$NAME.routes`

This section splits a service's upstream servers into routes, so that different
request paths and methods reach different sets of servers. Each `route` has a
`connectors` block of its own, described below.

A service has either a `routes` block or a `connectors` block, not both. See
[Routing](./routing.md) for the full description.

This section is optional.

### `services.$NAME.connectors`

This section contains one or more Connectors.
It is required unless the service has a `routes` block, in which case each
route carries one instead.

A Connector says where upstream servers come from. There are three kinds, and a
service may use any mix of them:

* `"SOCKETADDR"` - one server, written out in the configuration file.
  `SOCKETADDR` is a UTF-8 string that is parsed into an IPv4 or IPv6 address and
  port.
* `dns "HOSTNAME" port=PORT` - every address behind a hostname's A and AAAA
  records
* `srv "_service._proto.domain"` - every target named by a set of SRV records,
  with the port and relative weight taken from the records

The `dns` and `srv` kinds are re-resolved while River runs, so upstream servers
can be added and retired without restarting or reloading River. See
[Service Discovery](./discovery.md) for how often they are looked up again, and
for what happens when a lookup fails.

All three kinds accept the same settings for how to connect to whatever they
find:

`[tls-sni="DOMAIN"] [tls=BOOL] [proto="PROTO"] [TIMEOUTS]`

If the connector should use TLS for connections to the upstream server, the TLS-SNI
is specified in the form `tls-sni="DOMAIN"`, where DOMAIN is a domain name. If this
is not provided, connections to upstream servers will be made without TLS.

For `dns` and `srv` connectors, `tls=true` may be given instead of `tls-sni`. This
uses the name the server was discovered under - the queried hostname for `dns`, or
each record's own target for `srv` - which is what a set of servers behind one
name normally expects. Setting both `tls` and `tls-sni` is an error. `tls=true` is
not available on a `"SOCKETADDR"` connector, because an address was not discovered
under any name.

The protocol used to connect with the upstream server us specified in the form
`proto="PROTO"`, where `PROTO` is a string with one of the following values:

* `h1-only`: Only HTTP1.0 will be used to connect
* `h2-only`: Only HTTP2.0 will be used to connect
* `h2-or-h1`: HTTP2.0 will be preferred, with fallback to HTTP1.0

The `proto` field is optional. If it is not specified and TLS is configured, the default
will be `h2-or-h1`. If TLS is not configured, the default will be `h1-only`, and any
other option will result in an error.

Timeouts are optional, and are given in milliseconds:

* `connection-timeout-ms=N` - establishing the TCP connection
* `total-connection-timeout-ms=N` - establishing the connection including the TLS
  handshake
* `read-timeout-ms=N` - waiting for data from the upstream server, which is what
  bounds how long a proxied request may take
* `write-timeout-ms=N` - writing data to the upstream server
* `idle-timeout-ms=N` - how long an unused pooled connection is kept

A timeout that is not set keeps Pingora's own default, rather than being
disabled.

Unknown settings on a connector are an error, so a misspelled key is reported
against the line it appears on rather than silently doing nothing.

### `services.$NAME.connectors.load-balance`

This section defines how load balancing properties are configured for the
connectors in this set.

This section is optional. It may appear anywhere among the connectors: the
settings in it apply to all of them, whatever the order in the file.

### `services.$NAME.connectors.load-balance.selection`

This defines how the upstream server is selected.

Options are:

* `selection "RoundRobin"`
    * Servers are selected in a Round Robin fashion, giving equal distribution
* `selection "Random"`
    * Servers are selected on a random basis, giving a statistically equal distribution
* `selection "FNV" key="KEYKIND"`
    * FNV hashing is used based on the provided KEYKIND
* `selection "Ketama" key="KEYKIND"`
    * Stable Ketama hashing is used based on the provided KEYKIND

Where `KEYKIND` is one of the following:

* `UriPath` - The URI path is hashed
* `SourceAddrAndUriPath` - The Source address and URI path is hashed

### `services.$NAME.connectors.load-balance.health-check`

This defines how River decides whether an upstream server is fit to receive
traffic. A server that fails its check is taken out of rotation, and put back
when it passes again.

This setting is optional, and defaults to `health-check "None"`.

Options are:

* `health-check "None"`
    * Every server is assumed healthy. Requests to a server that has gone away
      fail as they are made.
* `health-check "TCP" [tls-sni="DOMAIN"]`
    * A connection is opened and closed again. With `tls-sni`, a TLS handshake
      is completed as well.
* `health-check "HTTP" host="DOMAIN" [path="/PATH"] [tls=BOOL] [expect-status=CODE] [port=PORT] [reuse-connection=BOOL]`
    * A request is made and its response status is checked. `host` is required,
      and is sent as the `Host` header. `path` defaults to `/`, `expect-status`
      to `200`, and `tls` and `reuse-connection` to `false`. `port` checks a
      different port than traffic is sent to, for a health endpoint that lives
      beside the service rather than on it.

All kinds except `"None"` also accept:

* `frequency-ms=N` - how often every server is checked. Defaults to `5000`.
* `timeout-ms=N` - how long one check may take before it counts as a failure.
  Defaults to `1000`.
* `consecutive-failure=N` - failures in a row before a healthy server is taken
  out. Defaults to `1`.
* `consecutive-success=N` - successes in a row before an unhealthy server is used
  again. Defaults to `1`.
* `parallel=BOOL` - check every server at once rather than one after another.
  Defaults to `false`.

Note that a check has to speak the same protocol as the traffic it stands in
for: an `"HTTP"` check without `tls=true` against a TLS-only server will report
every server as unhealthy.

### `services.$NAME.connectors.load-balance.refresh-bounds`

This bounds how often the `dns` and `srv` connectors in this set are looked up
again. See [Service Discovery](./discovery.md).

`refresh-bounds [min-seconds=N] [max-seconds=N]`

Defaults to `min-seconds=5 max-seconds=300`. Individual connectors may override
these with `min-refresh-seconds` and `max-refresh-seconds`.

### `services.$NAME.connectors.load-balance.discovery`

**Deprecated.** This setting no longer does anything: what a service discovers
is now said by which connectors it has. `discovery "Static"` is still accepted,
with a warning, so that configuration files written for v0.5.0 keep loading, and
will be removed in a future release. Any other value is an error.

### `services.$NAME.overload`

This section limits how much work a service will take on at once, and bounds
how long a slow client may hold a connection.

This section is optional, and nothing here is set by default. What a service
can take depends on the upstream servers behind it, and River has no way to
guess it.

```kdl
overload {
    max-concurrent-requests 1000
    max-headers 64
    max-header-bytes 16384
    read-timeout-ms 30000
    write-timeout-ms 30000
    drain-timeout-ms 5000
    min-send-rate-bytes 1024
    status 503
    body "Server is busy, please retry\n"
}
```

* `max-concurrent-requests N` - requests this service will handle at once.
  Beyond that, requests are shed until one finishes.

  This is a different question from rate limiting. Rate limiting asks how fast
  one client may ask; this asks how much River is willing to have in flight at
  all, whoever is asking. A sudden surge of legitimate traffic passes every
  rate limit and can still knock over an upstream server.

  Shedding runs after the ACME challenge handler, so a certificate authority's
  validation is never turned away by a service that is merely busy - a shed
  challenge costs a renewal, not a request. It runs before everything else,
  because it is the cheapest way to say no.

* `max-headers N` and `max-header-bytes N` - a tighter bound than the parser's
  own, which allows 256 headers and about 1 MiB of header on HTTP/1.1. The
  bytes have already been read by the time these are checked; the point is to
  refuse to spend anything further on the request.

* `read-timeout-ms N` / `write-timeout-ms N` - how long a single read from, or
  write to, the client may stall.
* `drain-timeout-ms N` - how long draining an unread request body may take in
  total.
* `min-send-rate-bytes N` - bytes per second the client must accept the
  response at.

  Those four are the answer to a slow loris, in both directions: without them a
  client can hold a connection open indefinitely by sending a request body one
  byte at a time, or reading a response equally slowly.

* `status CODE` / `body "TEXT"` - how a shed request is answered. Defaults to
  `503` with no body: the client did nothing wrong, the server is simply full,
  and that distinction is what tells a caller whether backing off will help.

### `services.$NAME.normalization`

This section controls the checks and rewrites River applies to every request
before anything else looks at it - resolving `..`, collapsing duplicate
slashes, rejecting encoded path separators and control characters, and
requiring a single coherent `Host`.

**Normalization is on by default**, with no configuration. This section exists
to change or disable it. See
[Request Normalization](./normalization.md) for the full description of each
check and for what to do if one of them turns away traffic you need.

```kdl
normalization {
    encoded-separators false
    status 422
}
```

This section is optional.

### `services.$NAME.client-ip`

This section tells River how to work out which address a request came from.

This section is optional. Without it, the address River is connected to is the
address it uses.

```kdl
client-ip {
    trusted-proxies "10.0.0.0/8, 192.168.0.0/16"
    header "x-forwarded-for"
}
```

When River runs behind a load balancer, a CDN, or any other proxy, the address
of the TCP connection is that intermediary's, not the client's. Filtering and
rate limiting on it is worse than useless: every request looks like it came
from one machine, so `block-cidr-range` matches nothing and every client in the
world shares a single rate limiting bucket.

* `trusted-proxies "CIDRS"` - required. A comma separated list of addresses or
  CIDR ranges whose forwarding header River is willing to believe.
* `header "NAME"` - optional, defaults to `x-forwarded-for`. Set this to
  `cf-connecting-ip`, `true-client-ip`, or whatever your provider sends.

The header is only consulted when the connecting peer is inside
`trusted-proxies`. Anyone can send an `X-Forwarded-For`; it is evidence only
when it came from something known to rewrite it. When the peer is not trusted,
its own address is used and whatever it claimed is ignored.

Within a trusted connection, River reads the header right to left and takes the
first address that is not itself a trusted proxy. That is the last address
something we trust vouched for. Taking the leftmost entry instead - the common
mistake - would take whatever the original client sent, letting anyone walk
straight past a deny list by adding a header to their own request.

Every filter, every rate limiting rule, and every log line uses the address this
section produces, so they all agree on who the client is.

**Note:** requirement 6 of "2.1 - Downstream" in the design document also names
v1 and v2 of the PROXY protocol and Cloudflare Spectrum. Those are not
implemented; see the roadmap for why.

### `services.$NAME.path-control`

This section contains the configuration for path control filters

Each path control filter allows for modification or rejection at different stages of request
and response handling.

This section is optional.

Example:

```kdl
path-control {
    request-filters {
        filter kind="block-cidr-range" addrs="192.168.0.0/16, 10.0.0.0/8, 2001:0db8::0/32, 127.0.0.1"
    }
    upstream-request {
        filter kind="remove-header-key-regex" pattern=".*(secret|SECRET).*"
        filter kind="upsert-header" key="x-proxy-friend" value="river"
    }
    upstream-response {
        filter kind="remove-header-key-regex" pattern=".*ETag.*"
        filter kind="upsert-header" key="x-with-love-from" value="river"
    }
}
```

Every entry in a stage is a `filter`, and what it does is chosen by its `kind`.
Settings that a filter does not use are an error, so a misspelled key is
reported against the line it appears on rather than silently doing nothing.
This is checked when the configuration file is read, which means
`--validate-configs` catches a bad regular expression, an unparseable address
range, or an invalid header name without River having to start.

#### Rejecting a request

Filters that can reject a request all accept the same two optional settings,
which say how the rejection is answered:

* `status=CODE` - the HTTP status sent downstream. Each filter has its own
  default, given below.
* `body="TEXT"` - sent as the response body. If this is not set, the response
  has no body.

Choosing the status is worth a moment's thought. Answering `404` rather than
`403` tells someone probing the server nothing about *why* they were turned
away, which may be what you want; answering `403` is more truthful to an
operator reading their own logs.

#### `services.$NAME.path-control.request-filters`

Filters at this stage are the earliest, running before an upstream server has
been selected. Currently supported filters:

* `kind="block-cidr-range" addrs="ADDRS" [status=CODE] [body="TEXT"]`
    * `ADDRS` is a comma separated list of IPv4 or IPv6 addresses or CIDR
      address ranges.
    * A request whose client address matches any entry is rejected. Defaults to
      `status=403`: a blocked address is forbidden, not unauthenticated, and
      there is no credential the client could present that would change the
      answer.
* `kind="allow-cidr-range" addrs="ADDRS" [status=CODE] [body="TEXT"]`
    * The complement: a request whose client address matches **none** of the
      entries is rejected. Also defaults to `status=403`.

These are two independent filters rather than one combined allow/deny list,
which means there is no precedence rule to remember - they run in the order you
write them, and the first one to reject wins:

| Written                                | `10.0.0.5`     | `10.6.6.5`     | `203.0.113.5`  |
| -------------------------------------- | -------------- | -------------- | -------------- |
| `block 10.6.6.0/24`                    | allowed        | **rejected**   | allowed        |
| `allow 10.0.0.0/8`                     | allowed        | allowed        | **rejected**   |
| `block 10.6.6.0/24` then `allow 10/8`  | allowed        | **rejected**   | **rejected**   |
| `allow 10/8` then `block 10.6.6.0/24`  | allowed        | **rejected**   | **rejected**   |

Both filters use the *client* address, which is not the address River is
connected to when it sits behind a load balancer - see
`services.$NAME.client-ip` below. Connections over a unix domain socket have no
address at all: a deny list never matches one, and an allow list always rejects
one, since it satisfies none of the ranges that were listed.

#### `services.$NAME.path-control.upstream-request`

All three header stages - `upstream-request`, `upstream-response`, and
`response-filters` - accept the same five filters:

* `kind="remove-header-key-regex" pattern="PATTERN"`
    * `PATTERN` is a regular expression matched against the header name
    * Every matching header is removed
* `kind="remove-header-key-glob" pattern="PATTERN"`
    * `PATTERN` is a glob matched against the header name, where `*` matches any
      run of characters and `?` matches exactly one. Matching is
      case-insensitive, because header names are.
    * Every matching header is removed. `x-internal-*` is easier to get right
      than the equivalent regular expression, and cannot accidentally match in
      the middle of a name the way an unanchored regex does.
* `kind="remove-header" key="KEY"`
    * Removes just that header, with no pattern matching at all
* `kind="upsert-header" key="KEY" value="VALUE"`
    * Adds the header, **replacing** any existing value
* `kind="append-header" key="KEY" value="VALUE"`
    * Adds the header, **keeping** any existing value alongside it. Some headers
      are defined as lists - `Vary`, `Set-Cookie` - and replacing rather than
      appending silently discards what an upstream server or an earlier filter
      had to say.

`KEY` must be a valid HTTP header name and `VALUE` a valid HTTP header value;
both are checked when the configuration file is read.

#### `services.$NAME.path-control.upstream-response`

The header filters above, applied to the response as it arrived from the
upstream server.

#### `services.$NAME.path-control.response-filters`

The header filters above, applied at the last point before the response goes
downstream.

The difference between the two stages is which responses they see.
`upstream-response` sees a response that was fetched from an upstream server.
`response-filters` sees every response on its way out, including one served
from cache. A header you want on every response - `x-served-by`, a security
header - belongs here; a header that is about what the upstream server said
belongs in `upstream-response`.

#### `services.$NAME.path-control.request-body` and `.response-body`

These stages bound how large a body River is willing to move. They count and
reject; they do not modify. Rewriting a body means holding all of it in memory
at once, which is the denial of service vector these limits exist to prevent,
so it is not available. See the roadmap for where body rewriting is expected to
land.

* `kind="max-size" max-bytes=N [status=CODE]`
    * `N` is the number of bytes allowed, and must be at least 1
    * At most one `max-size` may appear per stage

On `request-body`, `status` defaults to `413`. A request whose `Content-Length`
already exceeds the limit is rejected before any of its body is read; a request
that declares no length - a chunked upload - is counted as it arrives and cut
off once it goes over.

On `response-body`, `status` defaults to `502`, because a response that is too
large is the upstream server misbehaving rather than anything the client did.

What a client sees when a `response-body` limit is exceeded depends on how far
the response had already got, and it is worth knowing which:

* If the response header has not yet been sent downstream - which is the case
  for a response still small enough to be buffered - the client gets `status`.
* If it has already been sent, HTTP gives no way to retract it. The response is
  cut short instead, and the client sees a truncated body under whatever status
  the upstream server sent.

What holds either way is that the oversize body does not arrive in full, and
that River logs the reason. A client that needs to detect truncation should
compare what it received against the `Content-Length` it was given.

### `services.$NAME.rate-limiting`

This section contains the configuration for rate limiting rules.

Rate limiting rules are used to limit the total number of requests made by downstream clients,
based on various criteria.

Note that Rate limiting is on a **per service** basis, services do not share rate limiting
information.

This section is optional.

Example:

```
rate-limiting {
    rule kind="source-ip" \
        max-buckets=4000 tokens-per-bucket=10 refill-qty=1 refill-rate-ms=10

    rule kind="specific-uri" pattern="static/.*" \
        max-buckets=2000 tokens-per-bucket=20 refill-qty=5 refill-rate-ms=1

    rule kind="any-matching-uri" pattern=r".*\.mp4" \
        tokens-per-bucket=50 refill-qty=2 refill-rate-ms=3
}
```

#### `services.$NAME.rate-limiting.rule`

Rules are used to specify rate limiting parameters, and applicability of rules to a given request.

##### Leaky Buckets

Rate limiting in River uses a [Leaky Bucket] model for determining whether a request can be served
immediately, or if it should be rejected. For a given rule, a "bucket" of "tokens" is created, where
one "token" is required for each request.

The bucket for a rule starts with a configurable `tokens-per-bucket` number. When a request arrives,
it attempts to take one token from the bucket. If one is available, it is served immediately. Otherwise,
the request is rejected immediately.

The bucket is refilled at a configurable rate, specified by `refill-rate-ms`, and adds a configurable
number of tokens specified by `refill-qty`. The number of tokens in the bucket will never exceed the
initial `tokens-per-bucket` number.

Once a refill occurs, additional requests may be served.

[Leaky Bucket]: https://en.wikipedia.org/wiki/Leaky_bucket

##### How many buckets?

Some rules require many buckets. For example, rules based on the source IP address will create a bucket
for each unique source IP address observed in a request. We refer to these as "multi" rules.

However, each of these buckets require space to contain the metadata, and to avoid unbounded growth,
we allow for a configurable `max-buckets` number, which serves to influence the total memory required
for storing buckets. This uses an [Adaptive Replacement Cache]
to allow for concurrent access to these buckets, as well as the ability to automatically evict buckets that
are not actively being used (somewhat similar to an LRU or "Least Recently Used" cache).

[Adaptive Replacement Cache]: https://docs.rs/concread/latest/concread/arcache/index.html

There is a trade off here: The larger `max-buckets` is, the longer that River can "remember" a bucket
for a given factor, such as specific IP addresses. However, it also requires more resident memory to
retain this information.

If `max-buckets` is set too low, then buckets will be "evicted" from the cache, meaning that subsequent
requests matching that bucket will require the creation of a new bucket (with a full set of tokens),
potentially defeating the objective of accurate rate limiting.

For "single" rules, or rules that do not have multiple buckets, a single bucket will be shared by all
requests matching the rule.

##### Gotta claim 'em all

When multiple rules apply to a single request, for example rules based on both source IP address,
and the URI path, then a request must claim ALL applicable tokens before proceeding. If a given IP
address is making it's first request, but to a URI that that has an empty bucket, it will immediately
obtain the IP address token, but the request will be rejected as the URI bucket claim failed.

##### Kinds of Rules

Currently three kinds of rules are supported:

* `kind="source-ip"` - this tracks the IP address of the requestor.
    * This rule is a "multi" rule: A unique bucket will be created for
      the IPv4 or IPv6 address of the requestor.
    * The `max-buckets` parameter controls how many IP addresses will be remembered.
* `kind="specific-uri" pattern="REGEX"` - This tracks the URI path of the request, such as `static/images/example.jpg`
    * This rule is a "multi" rule: if the request's URI path matches the provided `REGEX`,
      the full URI path will be assigned to a given bucket
    * For example, if the regex `static/.*` was provided:
        * `index.html` would not match this rule, and would not require obtaining a token
        * `static/images/example.jpg` would match this rule, and would require obtaining a token
        * `static/styles/example.css` would also match this rule, and would require obtaining a token
        * Note that `static/images/example.jpg` and `static/styles/example.css` would each have a UNIQUE
          bucket.
* `kind="any-matching-uri" pattern="REGEX"` - This tracks the URI path of the request, such as `static/videos/example.mp4`
    * This is a "single" rule: ANY path matching `REGEX` will share a single bucket
    * For example, if the regex `.*\.mp4` was provided:
        * `index.html` would not match this rule, and would not require obtaining a token
        * `static/videos/example1.mp4` would match this rule, and would require obtaining a token
        * `static/videos/example2.mp4` would also match this rule, and would require obtaining a token
        * Note that `static/videos/example1.mp4` and `static/videos/example2.mp4` would share a SINGLE bucket
          (also shared with any other path containing an MP4 file)

### `services.$NAME.file-server`

This section is only allowed when `connectors` and `path-control` are not present.

This is used when serving static files, rather than proxying connections.

### `services.$NAME.file-server.base-path`

This is the base path used for serving files. ALL files within this directory
(and any children) will be available for serving.

This is specified in the form `base-path "PATH"`, where `PATH` is a valid UTF-8 path.

This section is required.
