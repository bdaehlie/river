# Service Discovery

River can find its upstream servers at runtime, instead of being told about all
of them in the configuration file. This matters when back-end servers are
deployed more often than the proxy in front of them: servers can be added and
retired without restarting or reloading River.

Discovery is configured in a service's `connectors` block. Every entry there is
a source of upstream servers:

```kdl
connectors {
    // One server, known when River starts and never changing
    "10.0.0.1:8000"

    // Every address behind a hostname
    dns "app.internal.example.com" port=8000

    // Every target named by a set of SRV records
    srv "_https._tcp.api.example.com" tls=true
}
```

A service may mix the three freely. If two sources produce the same address, the
duplicate is dropped, and the connection settings of whichever entry appears
first in the file are the ones used.

The syntax of the entries themselves - TLS, protocol, and timeouts - is described
in the [KDL configuration reference](./kdl.md#servicesnameconnectors). This page
covers the behaviour.

## `dns` - addresses behind a hostname

```kdl
dns "app.internal.example.com" port=8000
```

Every address in the hostname's A and AAAA records becomes an upstream server. If
both an A and an AAAA record exist, both become servers - which is a good reason
to turn on health checks, since a server that answers on IPv4 but not on IPv6
will otherwise receive half the traffic and fail it.

`port` is required. DNS address records do not carry a port, so River has no way
to guess one.

This is the shape offered by most container orchestrators: a Kubernetes headless
service, a Docker Compose service name, or a Consul DNS lookup all resolve one
name to every instance behind it.

## `srv` - targets named by SRV records

```kdl
srv "_https._tcp.api.example.com" tls=true
```

Each SRV record names a target host, a port, a priority, and a weight. River
resolves each target's addresses and uses the record's port, so no `port` setting
is needed.

`tls=true` uses each record's own target as the SNI, which is normally what SRV
based deployments expect.

Two details of RFC 2782 are worth knowing:

* **Only the most preferred priority is used.** SRV priorities describe a
  fallback order - contact the lowest-numbered priority you can reach, and only
  fall back when none of those work. River's load balancing has no notion of
  fallback tiers, so it uses the records at the lowest priority number and
  ignores the rest. Servers meant as backups are therefore never used. If you
  need them in the rotation, give them the same priority as the others.
* **Weights are scaled, not used directly.** SRV weights run from 0 to 65535,
  and River's selection expands weights into a table, so the raw values are
  reduced to a small range that preserves the ratios where it can. A weight of 0,
  which RFC 2782 defines as "eligible but least preferred", becomes the smallest
  share rather than "never selected".

A single SRV record whose target is `.` means the service is deliberately not
offered. River reads that as "no upstream servers", not as an error.

## How often names are looked up again

Each source keeps its own schedule, so a source with a five second interval does
not drag one with a five minute TTL along with it.

By default, the TTL of the answer decides:

```kdl
dns "app.example.com" port=8000                    // refresh="ttl" is the default
dns "app.example.com" port=8000 refresh="ttl"      // the same thing, said out loud
```

A fixed interval may be used instead, for a zone whose TTLs are not meaningful:

```kdl
dns "app.example.com" port=8000 refresh-seconds=30
```

Either way the interval is clamped into a band, because neither extreme is
useful: a TTL of zero would mean querying in a tight loop, and a day-long TTL
would mean never noticing a deployment. The band defaults to 5 to 300 seconds
and can be set for a whole service, or per source:

```kdl
connectors {
    load-balance {
        refresh-bounds min-seconds=10 max-seconds=60
    }

    dns "steady.example.com" port=8000
    dns "churny.example.com" port=8000 min-refresh-seconds=2
}
```

For an `srv` source, the interval comes from the shortest-lived part of the
answer: the SRV records and the address records of their targets.

## When a lookup fails

A source that has resolved successfully before keeps serving its last known set
of servers. This is deliberate: a nameserver having a bad minute says nothing
about whether the servers behind it are healthy, and dropping them would turn a
DNS blip into an outage. Failures are logged, and retried with an interval that
doubles from `min-seconds` up to `max-seconds`.

A source that has *never* resolved successfully contributes nothing. If no source
in a service has ever succeeded, the service has no upstream servers and requests
to it fail while River keeps retrying.

The same applies at startup. A service with a re-resolving source does not begin
accepting connections until its first resolution attempt has finished, so River
does not answer requests before it knows where to send them. The attempt reports
in whether or not it succeeded, so DNS being down when River starts delays
startup rather than preventing it - River comes up, logs the problem, and keeps
trying.

## Health checks

Discovery says which servers exist; health checks say which of them are working.
They are worth turning on together: a server that crashes will usually still be
in DNS, and without a health check River will keep sending requests to it.

```kdl
load-balance {
    health-check "TCP" frequency-ms=5000 timeout-ms=1000 \
        consecutive-failure=2 consecutive-success=1
}
```

A server that fails its check is taken out of rotation and put back when it
passes again. See
[`health-check`](./kdl.md#servicesnameconnectorsload-balancehealth-check) for the
full set of options.

A newly discovered server is assumed healthy until its first check. River runs a
check immediately after the set of servers changes, so that window is short, but
it is not zero.

## What discovery does not do

* **Connections are not closed when a server is removed.** In-flight requests to
  a retired server finish, and its pooled connections age out rather than being
  dropped. A server being removed from DNS is not a signal that it has stopped
  working.
* **Configuration is not re-read.** Only the list of servers is discovered at
  runtime. Changing anything else, including which names are looked up, needs a
  [reload](../reloading.md).
* **`PTR` based DNS-SD browsing is not supported.** River looks up the names it
  is configured with; it does not enumerate service instances from a `PTR`
  record.

## Logging

Changes to a service's set of servers are logged at `INFO`, with what was added
and what was removed:

```text
INFO Upstream servers changed service="Example" total=3 added="10.0.0.4:8000" removed="-"
```

Failed lookups are logged at `WARN`, and say whether the last known servers are
still being used.
