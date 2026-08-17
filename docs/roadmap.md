# `river` roadmap - End of June, 2024

## Completed Milestones

### "Kickstart Spike 1" / v0.2.0

This work took place over the course of April 2024. The goals of this milestone were:

1. Getting the river application up and running as a Linux binary
2. Getting enough configuration options working to allow for basic operation
3. Integrating the pingora library and getting basic reverse proxy operation working
4. Start setting up build and release infrastructure
5. Start working on observability, including structured logging

For more information: https://github.com/memorysafety/river/blob/main/docs/release-notes/2024-04-29-v0.2.0.md

### "Kickstart Spike 2" / v0.5.0

This work took place over the course of June-August 2024.

For more information: https://github.com/memorysafety/river/blob/main/docs/release-notes/2024-08-30-v0.5.0.md

#### "Spike 2.1"

This work was focused on "load balancing" use cases, including:

1. Supporting Load Balancing of upstream servers
2. Supporting Health Checks of upstream servers
3. Supporting Service Discovery of upstream servers

#### "Spike 2.2"

This work was focused on "Developer and Operator Quality of Life" features, including:

1. Supporting basic static HTML file serving
2. ~~Supporting semi-dynamic observability endpoints, e.g. for Prometheus polling~~
    * This work was de-scheduled and not included in v0.5.0
3. Support for hot-reloading of configuration
4. CI for build and test checks on pull requests

#### "Spike 2.3"

This work was focused on "initial Robustness" features, including:

1. Rate limiting of connections and/or requests
2. CIDR/API range-based filtering for rejecting connections

#### "Spike 2 - Bonus"

This work was not planned but occurred as part of the v0.5.0, but happened.

1. Adoption of the KDL language for configuration
2. Development of the [River User Manual]
3. Support for HTTP2 connection to downstream clients and upstream servers

[River User Manual]: https://onevariable.com/river-user-manual/

## Implemented, Pending Release

### "ACME features" / v0.6.x

#### Summary

This work implements [ACME] protocol support, to enable automatically obtaining and/or renewing TLS
certificates from providers such as Lets Encrypt. This feature works without active human
interaction.

[ACME]: https://datatracker.ietf.org/doc/html/rfc8555/

#### Reasons for Prioritization

Support for automated ACME protocol support allows users to deploy with full TLS support, an expected
feature for modern deployments. Older standards in this space to not support this feature, requiring
the installation of third party plugins or additional deployment setup to provision Reverse Proxy
servers.

This feature has been highly requested, and has been prioritized as an example of "user and operator
friendly" feature support.

#### Status

The implementation has landed on `main`. It has not yet been released, and no automated test has
exercised an order against a real ACME server - see "Remaining before release" below.

Certificates are selected per-connection by SNI rather than being bound to a listener at startup,
which is what allows a certificate to be replaced without a reload, and a listener to start before
its certificate exists. Configuration is a new top level `acme` section plus an `acme-domains`
argument on listeners; see the [River User Manual] for the operator-facing description.

#### Requirements/Features to Implement:

1. ~~The application MUST support the use of the Automatic Certificate Management Environment (ACME)
   protocol to obtain new TLS certificates.~~ Done.
2. ~~The application MUST support the use of ACME protocol to renew TLS certificates.~~ Done, on a
   periodic check that swaps the certificate in place, with no reload and no dropped connections.
3. ~~The application MUST support the configuration of domain names to be managed (including obtaining
   and renewal steps) automatically~~ Done, via `acme-domains` on each listener.
4. ~~The application MUST support both fully qualified and wildcard domains.~~ Done. Note that a
   certificate authority will only issue a wildcard against a `dns-01` challenge, so wildcards
   require an operator-supplied DNS hook. River deliberately does not integrate with DNS provider
   APIs directly.
5. ~~The application MUST support configuration of certificate renewal interval, from either:~~ Done,
   as `renew-after-issue-days` and `renew-before-expiry-days` respectively.
    1. ~~The number of days since the certificate was acquired~~
    2. ~~The number of days until the certificate will expired~~
6. ~~The application MUST support RFC 8555, e.g. "Let's Encrypt ACMEv2"~~ Done, using the
   `instant-acme` crate.

#### Remaining before release

* Integration tests against [Pebble] and `pebble-challtestsrv`. Until these exist, no code path has
  actually completed an order against an ACME server.
* Confirmation that the `x86_64-unknown-linux-musl` release build still succeeds. The ACME client's
  crypto backend compiles C, which is a new build requirement for River.
* Release notes, and a v0.6.0 tag.

[Pebble]: https://github.com/letsencrypt/pebble

#### Known constraints

River's dynamic certificate selection relies on Pingora's TLS certificate callback, which upstream
implements only for its OpenSSL and BoringSSL backends. Under Pingora's `rustls` backend the
callback is stubbed out and returns an error, so this feature currently depends on River selecting
the `openssl` feature. See https://github.com/cloudflare/pingora/pull/599 for the upstream work that
would lift that restriction.

### "Full Service-Discovery Features" / v0.7.x

#### Summary

The work in "Spike 2.1" introduced basic scaffolding for service discovery, but did not
support any "active" service discovery features outside of a static list provided on
start-up.

#### Reasons for Prioritization

For production users with automated and/or continuous deployment environments, it is common that
back-end or API component servers are likely to be deployed more often than the Reverse Proxy server
would be. In order to support seamless hand-off between "old" and "new" deployments, the ability to
discover new back-end servers, and retire old back-end servers is necessary.

Additionally, support for Service Discovery features also allows for simplified Reverse Proxy
configuration: It is not necessary to configure River with all potential servers at starting time,
eliding this to be detected at runtime.

#### Status

The implementation has landed on `main`. It has not yet been released.

A service's `connectors` block now lists *sources* of upstream servers rather than servers:
a literal address as before, or a `dns` or `srv` entry that is re-resolved while River runs.
Each source keeps its own schedule and its own last known set of servers, so one source
refreshing quickly does not drag another along, and a failing nameserver does not drain
traffic off servers that are fine. See the [River User Manual] for the operator-facing
description.

Two things listed as complete in "Spike 2.1" turned out not to exist in the shipped code,
and requirement 5 could not be met without them, so they were implemented here:
health checks (`HealthCheckKind` had a single `None` variant and `set_health_check` was
never called) and upstream timeouts (no field of `PeerOptions` was reachable from a
configuration file).

#### Requirements/Features to Implement:

1. ~~River MUST support the use of DNS-Service Discovery to provide a list of upstream servers for a
   given service~~ Done, as a `dns` connector entry: every address behind a hostname's A and
   AAAA records, on a configured port. See "Known constraints" for what this deliberately
   does not include.
2. ~~River MUST support the use of SRV records to provide a list of upstream servers for a given
   service~~ Done, as a `srv` connector entry, taking the port and relative weight from each
   record.
3. ~~River MUST have a configurable timeout for re-polling poll-based service discovery mechanisms~~
   Done, as `refresh-seconds` per source, with `refresh-bounds` for a whole service.
4. ~~River MUST support the use of DNS TTL as timeout value for re-polling poll-based service
   discovery mechanisms~~ Done, and it is the default. The interval is clamped into a
   configurable band, because a TTL of zero would otherwise mean querying in a tight loop and
   a day-long TTL would mean never noticing a deployment.
5. ~~Ensure that we support the following for discovered upstreams:~~ Done, for discovered and
   statically configured upstreams alike.
    * ~~Timeouts on connections~~ `connection-timeout-ms` and `total-connection-timeout-ms`
    * ~~Timeouts on Requests~~ `read-timeout-ms`, plus `write-timeout-ms` and `idle-timeout-ms`
    * ~~Timeouts on health checks~~ `timeout-ms` on the `health-check` node

#### Known constraints

* **SRV priority tiers are not used for fallback.** RFC 2782 describes priorities as a
  fallback order, but Pingora's selection has no notion of preference tiers. River uses the
  records at the lowest priority number and ignores the rest, rather than mixing backup
  servers into the rotation and silently defeating the point of setting priorities.
* **`PTR` based DNS-SD browsing (RFC 6763) is not supported.** Requirement 1 is read as plain
  DNS-based discovery rather than RFC 6763, since requirement 2 lists SRV separately and
  RFC 6763 is built on SRV. Instance enumeration from a `PTR` record would be one more source
  type on the same machinery if it is ever wanted.
* **SRV weights are scaled rather than used directly.** Pingora's weighted selection expands a
  backend into `weight` entries in a lookup table, so passing SRV's 0..65535 range through
  unchanged would turn a handful of servers into a multi-megabyte allocation, rebuilt on every
  change. Weights are reduced by their greatest common divisor and capped, which preserves the
  ratios in the cases that matter.
* **Removing a server does not close its connections.** In-flight requests finish and pooled
  connections age out. A server leaving DNS is not a signal that it has stopped working.

#### Remaining before release

* Release notes, and a v0.7.0 tag. Note that v0.6.0 (ACME) is also implemented and unreleased;
  whether the two ship together is an open question.

### "Full Path Control Features" / v0.8.x

#### Summary

Spike 1 introduced initial Path Control features, allowing for filtering or modification of
requests and responses.

As these filters are "fixed" working towards the 1.0 release, it is likely we will want to
build these out to cover common security and reliability use cases, including resistance to
Denial of Service attacks, or general overload.

Additionally, there is intent to implement default-enabled normalization modifications and
checks, intended to prevent against common attack vectors or programmer errors.

#### Reasons for Prioritization

Many features of a reverse proxy are regarding what kind of connections the proxy facilitates.
However in many cases, it is also just as important to be able to determine what kind of
connections should be **rejected**, both for security reasons, as well as prevention of
overload of upstream servers, which can result in Denial Of Service conditions.

The ability to quickly and efficiently deny unwanted traffic is an important feature to
enable real-world production usage of River.

#### Status

The implementation has landed on `main`. It has not yet been released.

The list below is the enumeration that this section previously said had not been done. It
was written before any of the work, and every item on it is now implemented.

Path control filters are now typed and validated while the configuration file is read, so a
bad regular expression or address range is a diagnostic pointing at the line that has it
rather than a panic at startup, and `--validate-configs` covers them. A service may split its
upstreams across routes; it may work out the client address from a forwarding header when it
sits behind a trusted proxy; and it normalizes every request before anything else looks at
it. See the [River User Manual] for the operator-facing description.

Three scope decisions were made while enumerating, and are recorded here because the
requirement text does not settle them:

1. **Path routing is in scope.** Requirement 7 of "2.2 - Upstream" - selecting a subset of
   upstream servers by URI path - was not covered by the v0.7 milestone and belongs to no
   other. It is the only thing that makes the "Peer Selection" control point of requirement 1
   below meaningful, so it is implemented here.
2. **Client address resolution is limited to `X-Forwarded-For`.** CIDR filtering and rate
   limiting are useless behind a load balancer if they key on the TCP peer address, so River
   needs to know the real client. The other pre-proxying protocols named in "2.1 - Downstream"
   are not implemented - see "Known constraints".
3. **Normalization is enabled by default**, per the summary above, with each check individually
   disableable. This rejects requests that v0.7 accepted, which is a breaking change.

#### Requirements/Features to Implement:

Requirements 1-8 are from "2.4 - Request Path Control". Requirements 9 and 10 are drawn from
elsewhere for the reasons given above, and requirement 11 comes from the summary of this
section rather than from a numbered requirement anywhere.

1. ~~River MUST support modifying or rejecting a connection at each of the seven stages named in
   "2.4 - Request Path Control".~~ Done. The four that were missing are peer selection (which
   needed routing to have anything to decide), downstream response forwarding, request body,
   and response body.
2. ~~River MUST support rejecting a connection by returning an error response.~~ Done, as a
   `Rejection` carried by every filter that can reject, with `status` and `body` arguments.
3. ~~River MUST support CIDR range-based filtering allow **and** deny lists.~~ Done, as two
   independent filters rather than one list with a precedence rule: they run in the order they
   are written, which is the only rule an operator has to remember.
4. ~~River MUST support rate limiting on a fixed rate per second and on a burst rate.~~ Met as
   of v0.5 by the leaky bucket implementation, whose `refill-rate-ms` is the fixed rate and
   whose `tokens-per-bucket` is the burst. An integration test now demonstrates it.
5. ~~River MUST support rate limiting on a per-endpoint basis.~~ Met as of v0.5 by the
   `specific-uri` and `any-matching-uri` rule kinds.
6. ~~River MUST support removal of HTTP headers on a glob **or** regex matching basis.~~ Done,
   as `remove-header-key-glob`. The matcher is written in River rather than taken from a crate,
   because the glob crates carry path semantics that are wrong for header names.
7. ~~River MUST support addition of fixed HTTP headers to a request.~~ Met as of v0.5 by
   `upsert-header`, and rounded out here with `append-header` and `remove-header`.
8. ~~River MUST support normalization of request and response headers and bodies, covering URI
   normalization and text encoding.~~ Done, and enabled by default. Reading Pingora and httparse
   first removed several checks from the design that would have been dead code - see "Known
   constraints".
9. ~~River MUST support the configurable selection of a subset of upstream servers based on HTTP
   URI paths.~~ Done, as a `routes` block. This is requirement 7 of "2.2 - Upstream".
10. ~~River MUST support deriving the client address from the `X-Forwarded-For` header when the
    connecting peer is a configured trusted proxy.~~ Done, as a `client-ip` block. This is a
    partial answer to requirement 6 of "2.1 - Downstream".
11. ~~River MUST support limiting concurrent load and defending against slow clients.~~ Done, as
    an `overload` block. This comes from the summary of this section; "2.4 - Request Path
    Control" has no numbered requirement for it. See "Open questions".

#### Known constraints

* **The PROXY protocol and Cloudflare Spectrum are not supported.** Requirement 6 of
  "2.1 - Downstream" names v1 and v2 of the PROXY protocol, Cloudflare Spectrum, and the
  `X-Forwarded-For` header. Pingora 0.8.1 has no PROXY protocol support anywhere in its tree,
  so supporting it means either upstream work or a stream wrapper beneath Pingora's listener
  layer. Only `X-Forwarded-For` is implemented here, and requirement 6 remains open.
* **Body stages count and reject; they do not rewrite.** Pingora delivers bodies in fragments.
  Rewriting one means buffering it, and buffering an arbitrary request body is the denial of
  service vector this milestone exists to defend against. Arbitrary body transformation is
  deferred to the scripting milestone.
* **A response status cannot be changed once headers have been sent downstream.** This bounds
  what a response body filter can do about a response that turns out to be too large. Whether
  the client gets the configured status or a truncated body depends on whether the response
  header had already been flushed, which in turn depends on the size of the response. The
  guarantee is only that the oversize body does not arrive in full.
* **Text encoding normalization covers header field octets, not body transcoding.** Requirement
  8 names "text encoding" without saying what it means. It is read here as validating header
  field values against the octets RFC 9110 permits. Transcoding a body between character sets
  is not implemented, and would belong with the other body rewriting work.
* **Route matching is prefix-based.** Evaluating regular expressions against every request is a
  performance cliff. Longest-prefix matching is the default path; a regex form exists for cases
  that need it.
* **Normalization rejects requests that earlier versions accepted.** This is the intent of the
  feature, but it means a configuration that worked under v0.7 may reject traffic under v0.8.
  Each check can be disabled individually.
* **Two checks that were planned turned out to be unimplementable, and were dropped rather
  than written as code that could never fire.** Pingora removes a `Content-Length` when a
  `Transfer-Encoding` is also present, so River never sees that pairing and cannot reject it.
  httparse admits only HTAB, space, `0x21..=0x7E` and `0x80..` into header values, so a
  control character check would have had nothing to catch. Both are recorded in the module
  documentation so that the next person does not rediscover them.

#### Open questions

* Requirement 11 has no basis in `what-is-it.md`, only in the summary of this roadmap section.
  Either "2.4 - Request Path Control" should gain a numbered requirement for overload
  resistance, or this roadmap should be understood as its specification. Editing the
  requirements document is the heavier of the two choices.
* v0.6 (ACME) and v0.7 (service discovery) are both implemented and unreleased. Shipping the
  breaking normalization change on top of two unreleased milestones makes for a single large
  release carrying a lot of unrelated risk. Cutting v0.6 and v0.7 first is worth considering -
  the integration test harness this milestone builds also serves the Pebble tests that v0.6 is
  waiting on.

#### Remaining before release

* A v0.8.0 tag. Release notes are written, at
  `docs/release-notes/2026-08-17-v0.8.0.md`.
* Note that v0.6.0 (ACME) and v0.7.0 (service discovery) are also implemented and unreleased.
  See "Open questions" for whether they should ship first.

## Future Milestones - towards 1.0

The following milestones are working towards the requirements specified in the design document
for `river`: https://github.com/memorysafety/river/blob/main/docs/what-is-it.md

These milestones are the currently planned way of structuring major features in the approach
towards a stable 1.0 release.

### Polish, packaging, and pre-release / v0.9.x+

At this stage, `river` is considered nearly feature complete for a 1.0 release. This milestone
is intended to prepare release candidates, which can be used for widespread test releases.

Particularly, this stage is also when we will want to ensure that development and operational
documentation for River is complete, and suitable for end-users who are not already familiar
with River during the early preview stages.

It is expected to potentially make any remaining breaking changes, work to ensure that River
can be packaged in a variety of expected ways, and to get user feedback with respect to
performance and usability.

### Non-Milestone Items that need to be scheduled

The following items are not necessarily "milestone" targets, but should be scheduled across
the other existing milestones:

* Building out more extensive unit, functional, user interface, and end-to-end testing
    * This also may include augmenting existing pingora tests
    * ~~This also will include developing an integration test suite specific to river~~ Started
      in v0.8.x, as `source/river/tests/`: it runs a real River process against a real socket,
      because the normalization and request framing checks are about what arrives on the wire.
      It covers path control; the ACME work in v0.6.x still needs its own tests against Pebble,
      and this harness is the place to put them.
* Building out benchmarking and regression test suites
    * These will be used to ensure addition of new features does not regress overall performance
    * The intent of these benchmarks are largely to be used relative to river itself, not
      necessarily against other existing proxying tools
* Extending and enhancing structured logging and metrics
    * We will want to instrument aspects of the proxying lifecycle, to be able to make
      meaningful measurements of river's performance over time
    * We will want to take feedback from real-world and benchmarking use cases in
      order to make it possible to debug and reason about the internal workings of
      river from an operational perspective
* Review of "UX Consistency"
    * Ensure choices regarding configuration, to ensure that options are reasonable
    * Ensure Configuration Files, Command Line, and Environment Variable interfaces
      are consistent with each other
    * Ensure emitted logs, metrics, and tracing data is consistent and readable
      for operators
* Review of log customization and filtering
    * See https://github.com/memorysafety/river/issues/58 for more details

### Release / v1.x.x

At this stage, `river` will make a 1.0 release.

## Far Future Milestones - Beyond 1.0

### Scripting Language

The largest open milestone which is likely to be deferred until AFTER 1.0 is the
introduction of a scripting interface and integrated scripting language. This
language is intended to allow for:

* Dynamic Path Control - allowing for modification or filtering of requests and
  responses
* Dynamic Service Discovery - allowing for discovery of new upstream servers based
  on scripted logic
* Dynamic Health Checks - allowing for more expressive or in-depth checks of upstream
  server health
* Dynamic Load Balancing - allowing for more control over delegation of requests to
  upstream servers

This work will be informed by the "baked in" choices we make towards 1.0 for all of
the above items, and will entail:

* Development of a stable API and/or language interface for performing these actions
  externally and dynamically
* Selection of a scripting language (such as WASM), as well as the execution environment
  or runtime (such as WasmTime)
* Management and loading of dynamic components as part of the application configuration
