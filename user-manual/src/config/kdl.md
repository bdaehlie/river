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

### `services.$NAME.connectors`

This section contains one or more Connectors.
This section is required.

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

#### `services.$NAME.path-control.request-filters`

Filters at this stage are the earliest. Currently supported filters:

* `kind = "block-cidr-range"`
    * Arguments: `addrs = "ADDRS"`, where `ADDRS` is a comma separated list of IPv4 or IPv6 addresses or CIDR address ranges.
    * Any matching source IP addresses will be rejected with a 400 error code.

#### `services.$NAME.path-control.upstream-request`

* `kind = "remove-header-key-regex"`
    * Arguments: `pattern = "PATTERN"`, where `PATTERN` is a regular expression matching the key of an HTTP header
    * Any matching header entry will be removed from the request before forwarding
* `kind = "upsert-header"`
    * Arguments: `key="KEY" value="VALUE"`, where `KEY` is a valid HTTP header key, and `VALUE` is a valid HTTP header value
    * The given header will be added or replaced to `VALUE`

#### `services.$NAME.path-control.upstream-response`

* `kind = "remove-header-key-regex"`
    * Arguments: `pattern = "PATTERN"`, where `PATTERN` is a regular expression matching the key of an HTTP header
    * Any matching header entry will be removed from the response before forwarding
* `kind = "upsert-header"`
    * Arguments: `key="KEY" value="VALUE"`, where `KEY` is a valid HTTP header key, and `VALUE` is a valid HTTP header value
    * The given header will be added or replaced to `VALUE`

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
