# Core Concepts

River is a Reverse Proxy application.

It is intended to handle connections from **Downstream** clients, forward
**Requests** to **Upstream** servers, and then forward **Responses** from
the **Upstream** servers back to the **Downstream** clients.

```text
┌────────────┐          ┌─────────────┐         ┌────────────┐
│ Downstream │       ┌ ─│─   Proxy  ┌ ┼ ─       │  Upstream  │
│   Client   │─────────▶│ │           │──┼─────▶│   Server   │
└────────────┘       │  └───────────┼─┘         └────────────┘
                      ─ ─ ┘          ─ ─ ┘
                        ▲              ▲
                     ┌──┘              └──┐
                     │                    │
                ┌ ─ ─ ─ ─ ┐         ┌ ─ ─ ─ ─ ─
                 Listeners           Connectors│
                └ ─ ─ ─ ─ ┘         └ ─ ─ ─ ─ ─
```

For the purpose of this guide, we define **Requests** as messages sent
from the downstream client to the upstream server, and define **Responses**
as messages sent from the upstream server to the downstream client.

River is capable of handling connections, requests, and responses from
numerous downstream clients and upstream servers simultaneously.

When proxying between a downstream client and upstream server, River
may modify or block requests or responses. Examples of modification
include the removal or addition of HTTP headers of requests or responses,
to add internal metadata, or to remove sensitive information. Examples
of blocking include the rejection of requests for authentication or
rate limiting purposes.

## Services

River is oriented around the concept of **Services**. **Services** are
composed of three major elements:

* **Listeners** - the sockets used to accept incoming connections from
  downstream clients
* **Connectors** - the listing of potential upstream servers that requests
  may be forwarded to
* **Path Control Options** - the modification or filtering settings used
  when processing requests or responses.

A service may also split its connectors across several **Routes**, so that
different request paths reach different sets of upstream servers. A service
that does not is simply one that has a single route claiming everything. See
[Routing](../config/routing.md).

Services are configured independently from each other. This allows a single
instance of the River application to handle the proxying of multiple different
kinds of traffic, and to apply different rules when proxying these different
kinds of traffic.

Each service also creates its own pool of worker threads, in order to allow for
the operating system to provide equal time and resources to each Service,
preventing one highly loaded Service from starving other Services of resources
such as memory and CPU time.

## Listeners

Listeners are responsible for accepting incoming connections and requests
from downstream clients. Each listener is a single listening socket, for
example listening to IPv4 traffic on address `192.168.10.2:443`.

Listeners may optionally support the establishment and termination of TLS.
They may be configured with a TLS certificate and [SNI], allowing them
to securely accept traffic sent to a certain domain name, such as
`https://example.com`.

[SNI]: https://www.cloudflare.com/en-gb/learning/ssl/what-is-sni/

Unlike some other reverse proxy applications, in River, a given listener
is "owned" by a single service. This means that multiple services may not
be listening to the same address and port. Traffic received by a given
Listener will always be processed by the same Service for the duration
of time that the River application is running.

Listeners are configured "statically": they are set in the configuration
file loaded at the start of the River application, and are constant for
the time that the River application is running.

## Connectors

Connectors are responsible for the communication between the Service and
the upstream server(s).

Connectors manage a few important tasks:

* Allowing for Service Discovery, changing the set up potential upstream servers over time
* Allowing for Health Checks, selectively enabling and disabling which upstream servers
  are eligible for proxying
* Load balancing of proxied requests across multiple upstream servers
* Optionally establishing secure TLS connections to upstream servers
* Maintaining reusable connections to upstream servers, to reduce the cost of connection
  and proxying

Similar to Listeners, each Service maintains its own unique set of Connectors. However,
Services may have overlapping sets of upstream servers, each of them considering an
upstream server in the list of proxy-able servers in their own connectors. This allows
multiple services to proxy to the same upstream servers, but pooled connections and
other aspects managed by Connectors are not shared across Services.

Unlike Listeners, Connectors are not necessarily static. An upstream server may be
written out in the configuration file, or it may be discovered at runtime from DNS
address records or SRV records, in which case the set of servers changes as they are
deployed and retired - without restarting or reloading River. See
[Service Discovery](../config/discovery.md).

## Path Control

Path Control allows for configurable filtering and modification of requests and
responses at multiple stages of the proxying process.

A request passes through a sequence of stages on its way to an upstream server,
and the response passes back through a second sequence on its way out. Each
stage is a place where River may inspect what is passing through, change it, or
stop it. Which stages exist is fixed; what happens at each of them is
configuration.

Before any of it runs, River normalizes the request: resolving `..` in the
path, collapsing duplicate slashes, and turning away requests that are
malformed in ways that tend to mean an attack. This happens first precisely so
that the stages below cannot be fooled by an unusual spelling of a path -
`/static/../admin` reaches them as `/admin`. See
[Request Normalization](../config/normalization.md).

The stages River currently exposes, in the order a request meets them:

* **Request arrival** (`request-filters`) - the earliest point, before an
  upstream server has been chosen. Rejecting here is the cheapest thing River
  can do, because no upstream connection has been spent on the request.
* **Request body** (`request-body`) - the body arriving from the client, in
  fragments.
* **Upstream request forwarding** (`upstream-request`) - the request as it will
  be sent to the upstream server. This is where headers are added or removed on
  the way out.
* **Upstream response arrival** (`upstream-response`) - the response as it
  arrived from the upstream server.
* **Downstream response forwarding** (`response-filters`) - every response on
  its way out, including one served from cache rather than fetched upstream.
  This is the last point at which the response header can be changed.
* **Response body** (`response-body`) - the body on its way to the client, in
  fragments.

Each stage runs its filters in the order they appear in the configuration file.
A filter that rejects a request answers the client itself, and no later stage
runs.

The two body stages are different in kind from the others. A body arrives in
fragments, and River sees one fragment at a time rather than the whole thing.
It could hold on to the fragments until it had all of them, but that would mean
storing an arbitrary amount of somebody else's data in memory, which is exactly
the problem these stages exist to prevent. So the body stages count what goes
by and stop it if there is too much; they do not rewrite it.

There is also an ordering consequence worth knowing about. Once a response
header has gone downstream, HTTP gives no way to take it back and send a
different status. A limit exceeded in the `response-body` stage therefore has
two possible endings: if the header has not gone out yet, the client gets an
error status; if it has, the response is simply cut short under the status the
client was already given.

Rate limiting is closely related, but is configured separately, in its own
`rate-limiting` section. It runs before any of the stages above.

Load shedding is separate again. Rate limiting asks how fast a single client
may ask; shedding asks how much work River is willing to have in flight at all,
whoever is asking - because a surge of entirely legitimate traffic passes every
rate limit and can still overwhelm an upstream server. It is configured in the
`overload` section, along with the timeouts that bound how long a slow client
may hold a connection open.
