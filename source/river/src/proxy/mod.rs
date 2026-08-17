//! Proxy handling
//!
//! This module contains the primary proxying logic for River. At the moment,
//! this includes creation of HTTP proxy services, as well as Path Control
//! modifiers.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::FutureExt;

use pingora::{server::Server, Error, ErrorType};
use pingora_core::{
    services::{background::background_service, ServiceWithDependents},
    upstreams::peer::HttpPeer,
    Result,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_load_balancing::{
    selection::{consistent::KetamaHashing, FVNHash, Random, RoundRobin},
    Backends, LoadBalancer,
};
use pingora_proxy::{ProxyHttp, Session};

use crate::acme::http01::ChallengeStore;
use crate::{
    acme,
    config::internal::{
        BodySizeLimit, ClientIpConfig, HealthCheckSettings, Normalization, PathControl,
        ProxyConfig, Rejection, RequestFilterConfig, ResponseModifierConfig, RouteConfig,
        SelectionKind,
    },
    populate_listners,
    proxy::{
        discovery::{
            resolver::Resolver,
            service::{PoolState, UpstreamService},
            RiverDiscovery, SharedDiscovery,
        },
        overload::Overload,
        pool::BackendPool,
        request_filters::CidrSense,
        request_modifiers::RequestModifyMod,
        response_modifiers::ResponseModifyMod,
        routing::{Route, Routes},
    },
    tls::store::CertStore,
};

use self::{
    rate_limiting::{multi::MultiRaterInstance, single::SingleInstance, Outcome},
    request_filters::RequestFilterMod,
};

pub mod client_ip;
pub mod discovery;
pub mod glob;
pub mod headers;
pub mod health_check;
pub mod normalize;
pub mod overload;
pub mod pool;
pub mod rate_limiting;
pub mod request_filters;
pub mod request_modifiers;
pub mod request_selector;
pub mod response_modifiers;
pub mod routing;

pub struct RateLimiters {
    request_filter_stage_multi: Vec<MultiRaterInstance>,
    request_filter_stage_single: Vec<SingleInstance>,
}

/// The [RiverProxyService] is intended to capture the behaviors used to extend
/// the [HttpProxy] functionality by providing a [ProxyHttp] trait implementation.
///
/// The [ProxyHttp] trait allows us to provide callback-like control of various stages
/// of the [request/response lifecycle].
///
/// [request/response lifecycle]: https://github.com/cloudflare/pingora/blob/7ce6f4ac1c440756a63b0766f72dbeca25c6fc94/docs/user_guide/phase_chart.md
pub struct RiverProxyService {
    /// All modifiers used when implementing the [ProxyHttp] trait.
    pub modifiers: Modifiers,
    /// Where a request goes, decided by matching it against the service's routes
    ///
    /// Each route's pool is shared with the service's [`UpstreamService`],
    /// which replaces its backend set as servers are discovered and retired.
    pub routes: Routes,
    /// The answer when no route claims the request
    pub no_route: Rejection,
    /// How the client address is worked out, when River is behind a proxy
    pub client_ip: Option<ClientIpConfig>,
    /// Checks and rewrites applied before anything else looks at the request
    ///
    /// `None` when every check is turned off, so the common path does not pay
    /// for a walk over a request nothing is going to look at.
    pub normalization: Option<Normalization>,
    /// Limits on how much work this service will take on at once
    ///
    /// `None` when nothing is configured, so the common path does not pay for
    /// an atomic on every request.
    pub overload: Option<Overload>,
    pub rate_limiters: RateLimiters,
    /// Set when ACME is configured, so that this service answers challenges
    ///
    /// `None` when it is not, in which case requests under the challenge
    /// prefix are proxied like any other.
    pub acme_challenges: Option<Arc<ChallengeStore>>,
}

/// A proxy service, and the background service that keeps its upstreams current
///
/// The second is `None` for a service whose upstreams are all literal
/// addresses and which does not health check - there is nothing for it to do.
pub type ProxyServices = (
    Box<dyn ServiceWithDependents>,
    Option<Box<dyn ServiceWithDependents>>,
);

/// Build one route's pool, and the discovery and health settings that drive it
///
/// The selection algorithm is chosen here and then erased, which is what lets
/// one service hold routes that are balanced in different ways.
fn build_pool(
    route: &RouteConfig,
    resolver: &Arc<dyn Resolver>,
) -> (
    Arc<dyn BackendPool>,
    Arc<RiverDiscovery>,
    Option<HealthCheckSettings>,
) {
    let discovery = Arc::new(RiverDiscovery::from_config(&route.upstreams, resolver));
    let mut backends = Backends::new(Box::new(SharedDiscovery(discovery.clone())));

    let health = route.upstream_options.health_checks.settings().copied();
    if let Some(check) = health_check::build(&route.upstream_options.health_checks) {
        backends.set_health_check(check);
    }

    // The one place the selection algorithm is still a type, before it is
    // erased into `Arc<dyn BackendPool>`.
    let pool: Arc<dyn BackendPool> = match route.upstream_options.selection {
        SelectionKind::RoundRobin => Arc::new(LoadBalancer::<RoundRobin>::from_backends(backends)),
        SelectionKind::Random => Arc::new(LoadBalancer::<Random>::from_backends(backends)),
        SelectionKind::Fnv => Arc::new(LoadBalancer::<FVNHash>::from_backends(backends)),
        SelectionKind::Ketama => Arc::new(LoadBalancer::<KetamaHashing>::from_backends(backends)),
    };

    (pool, discovery, health)
}

/// Create a proxy service from the given [ProxyConfig]
pub fn river_proxy_service(
    conf: ProxyConfig,
    server: &Server,
    cert_store: &Arc<CertStore>,
    acme_challenges: Option<&Arc<ChallengeStore>>,
    resolver: &Arc<dyn Resolver>,
) -> ProxyServices {
    let modifiers = Modifiers::from_conf(&conf.path_control);

    let mut routes = Vec::with_capacity(conf.routes.len());
    let mut pools = Vec::with_capacity(conf.routes.len());

    for route in &conf.routes {
        let (pool, discovery, health) = build_pool(route, resolver);

        // A pool with nothing to refresh and nothing to check resolves its
        // backends once, right here, and never needs to be visited again.
        // Every source is a literal address in that case, so this cannot block.
        if !discovery.is_dynamic() && health.is_none() {
            pool.update()
                .now_or_never()
                .expect("static discovery should not block")
                .expect("static discovery should not error");
        } else {
            pools.push(PoolState::new(pool.clone(), discovery, health));
        }

        routes.push(Route::new(route, pool, route.upstream_options.selector));
    }

    // One background service per proxy service, driving every pool that needs
    // it. Keeping it to one means the readiness and dependency wiring in
    // `main.rs` does not have to change shape as routes are added.
    let background = (!pools.is_empty()).then(|| {
        Box::new(background_service(
            &format!("Upstreams for {}", conf.name),
            UpstreamService::new(conf.name.clone(), pools),
        )) as Box<dyn ServiceWithDependents>
    });

    let mut request_filter_stage_multi = vec![];
    let mut request_filter_stage_single = vec![];

    for rule in conf.rate_limiting.rules {
        match rule {
            rate_limiting::AllRateConfig::Single { kind, config } => {
                let rater = SingleInstance::new(config, kind);
                request_filter_stage_single.push(rater);
            }
            rate_limiting::AllRateConfig::Multi { kind, config } => {
                let rater = MultiRaterInstance::new(config, kind);
                request_filter_stage_multi.push(rater);
            }
        }
    }

    let mut my_proxy = pingora_proxy::http_proxy_service_with_name(
        &server.configuration,
        RiverProxyService {
            modifiers,
            routes: Routes::new(routes),
            no_route: conf.no_route,
            client_ip: conf.client_ip,
            normalization: (!conf.normalization.is_noop()).then_some(conf.normalization),
            overload: (!conf.overload.is_noop()).then(|| Overload::new(conf.overload)),
            rate_limiters: RateLimiters {
                request_filter_stage_multi,
                request_filter_stage_single,
            },
            acme_challenges: acme_challenges.cloned(),
        },
        &conf.name,
    );

    populate_listners(conf.listeners, &mut my_proxy, cert_store);

    (Box::new(my_proxy), background)
}

//
// MODIFIERS
//
// This section implements "Path Control Modifiers". As an overview of the initially
// planned control points:
//
//             ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐  ┌ ─ ─ ─ ─ ─ ─ ┐
//                  ┌───────────┐    ┌───────────┐    ┌───────────┐
//             │    │  Request  │    │           │    │  Request  │    │  │             │
// Request  ═══════▶│  Arrival  │═══▶│Which Peer?│═══▶│ Forwarded │═══════▶
//             │    │           │    │           │    │           │    │  │             │
//                  └───────────┘    └───────────┘    └───────────┘
//             │          │                │                │          │  │             │
//                        │                │                │
//             │          ├───On Error─────┼────────────────┤          │  │  Upstream   │
//                        │                │                │
//             │          │          ┌───────────┐    ┌───────────┐    │  │             │
//                        ▼          │ Response  │    │ Response  │
//             │                     │Forwarding │    │  Arrival  │    │  │             │
// Response ◀════════════════════════│           │◀═══│           │◀═══════
//             │                     └───────────┘    └───────────┘    │  │             │
//               ┌────────────────────────┐
//             └ ┤ Simplified Phase Chart │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘  └ ─ ─ ─ ─ ─ ─ ┘
//               └────────────────────────┘
//
// At the moment, "Request Forwarded" corresponds with "upstream_request_filters".
//

/// All modifiers used when implementing the [ProxyHttp] trait.
pub struct Modifiers {
    /// Filters used during the handling of [ProxyHttp::request_filter]
    pub request_filters: Vec<Box<dyn RequestFilterMod>>,
    /// Filters used during the handling of [ProxyHttp::upstream_request_filter]
    pub upstream_request_filters: Vec<Box<dyn RequestModifyMod>>,
    /// Filters used during the handling of [ProxyHttp::upstream_response_filter]
    pub upstream_response_filters: Vec<Box<dyn ResponseModifyMod>>,
    /// Filters used during the handling of [ProxyHttp::response_filter]
    pub response_filters: Vec<Box<dyn ResponseModifyMod>>,
    /// Bound on the request body, enforced in [ProxyHttp::request_body_filter]
    pub request_body_limit: Option<BodySizeLimit>,
    /// Bound on the response body, enforced in [ProxyHttp::response_body_filter]
    pub response_body_limit: Option<BodySizeLimit>,
}

impl Modifiers {
    /// Build all modifiers from the provided [PathControl]
    ///
    /// This cannot fail. Every regular expression, header name, and address
    /// range was parsed and validated when the configuration file was read, so
    /// there is nothing left here that can be wrong - which is what allows
    /// `--validate-configs` to be meaningful for path control.
    pub fn from_conf(conf: &PathControl) -> Self {
        let request_filters = conf
            .request_filters
            .iter()
            .map(|filter| -> Box<dyn RequestFilterMod> {
                let (blocks, sense, rejection) = match filter {
                    RequestFilterConfig::BlockCidr { blocks, rejection } => {
                        (blocks, CidrSense::Deny, rejection)
                    }
                    RequestFilterConfig::AllowCidr { blocks, rejection } => {
                        (blocks, CidrSense::Allow, rejection)
                    }
                };
                Box::new(request_filters::CidrRangeFilter::new(
                    blocks.clone(),
                    sense,
                    rejection.clone(),
                ))
            })
            .collect();

        let upstream_request_filters = conf
            .upstream_request_filters
            .iter()
            .map(|filter| -> Box<dyn RequestModifyMod> {
                Box::new(request_modifiers::HeaderMod::new(filter.clone()))
            })
            .collect();

        let response_modifiers = |configs: &[ResponseModifierConfig]| {
            configs
                .iter()
                .map(|filter| -> Box<dyn ResponseModifyMod> {
                    Box::new(response_modifiers::HeaderMod::new(filter.clone()))
                })
                .collect()
        };

        Self {
            request_filters,
            upstream_request_filters,
            upstream_response_filters: response_modifiers(&conf.upstream_response_filters),
            response_filters: response_modifiers(&conf.response_filters),
            request_body_limit: conf.request_body_limit,
            response_body_limit: conf.response_body_limit,
        }
    }
}

impl Rejection {
    /// Answer the request with this rejection
    ///
    /// Returns `true`, which is how a `request_filter` says it has handled the
    /// request itself and no upstream should be contacted.
    pub async fn apply(&self, session: &mut Session) -> Result<bool> {
        match self.body.as_ref() {
            Some(body) => {
                session
                    .downstream_session
                    .respond_error_with_body(self.status, body.clone())
                    .await?
            }
            None => {
                session
                    .downstream_session
                    .respond_error(self.status)
                    .await?
            }
        }
        Ok(true)
    }
}

/// Per-request state
pub struct RiverContext {
    selector_buf: Vec<u8>,

    /// Request body bytes seen so far, for [`Modifiers::request_body_limit`]
    ///
    /// Counted rather than buffered: the point of the limit is to avoid
    /// holding an arbitrary amount of a client's data in memory.
    request_body_bytes: usize,

    /// Response body bytes seen so far, for [`Modifiers::response_body_limit`]
    response_body_bytes: usize,

    /// The route that claimed this request, for logging
    route: Option<String>,

    /// Whether this request is counted against the concurrency limit
    ///
    /// Set when a slot was taken, so that `logging` gives back exactly the
    /// slots that were taken and no others.
    holds_slot: bool,

    /// The address this request is attributed to
    ///
    /// The peer address, unless the peer is a configured trusted proxy and
    /// sent a forwarding header. Every filter and rate limiter reads this
    /// rather than the socket, so that they all agree on who the client is.
    pub(crate) client_addr: Option<std::net::IpAddr>,
}

#[async_trait]
impl ProxyHttp for RiverProxyService {
    type CTX = RiverContext;

    fn new_ctx(&self) -> Self::CTX {
        RiverContext {
            selector_buf: Vec::new(),
            request_body_bytes: 0,
            response_body_bytes: 0,
            route: None,
            holds_slot: false,
            client_addr: None,
        }
    }

    /// Handle the "Request filter" stage
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        // Before anything else reads the request, including the challenge
        // path below: every later stage - the CIDR filters, the rate limiting
        // rules that match on URI, the route table - decides using the path,
        // and they must all be looking at the same canonical spelling of it.
        // Otherwise `/static/../admin` reaches a rule written for `/static`
        // and a server that serves `/admin`.
        if let Some(config) = self.normalization.as_ref() {
            if let Err(reason) =
                normalize::apply(session.downstream_session.req_header_mut(), config)
            {
                tracing::debug!(reason = reason.as_str(), "Rejecting a malformed request");
                return config.rejection.apply(session).await;
            }
        }

        // ACME challenges are answered next. A certificate
        // authority's validation request must not be rate limited or blocked
        // by a CIDR filter - if it is, the certificate silently fails to renew
        // and the failure only shows up weeks later, as an expired
        // certificate.
        if let Some(challenges) = self.acme_challenges.as_ref() {
            if acme::http01::try_serve(challenges, session).await? {
                return Ok(true);
            }
        }

        // Load shedding comes after the ACME challenge, so that a certificate
        // authority's validation is never turned away by a service that is
        // merely busy - a shed challenge costs a renewal, not a request. It
        // comes before everything below it because it is the cheapest way to
        // say no, and under overload that is the whole point.
        if let Some(overload) = self.overload.as_ref() {
            overload.apply_timeouts(session);

            if !overload.header_within_limits(session) {
                return overload.config().rejection.apply(session).await;
            }

            if !overload.acquire() {
                tracing::debug!(
                    in_flight = overload.in_flight(),
                    "Shedding a request: the service is at its concurrency limit"
                );
                return overload.config().rejection.apply(session).await;
            }
            ctx.holds_slot = true;
        }

        // Worked out before anything looks at an address, so that the CIDR
        // filters, the rate limiters, and the logs all agree on who the client
        // is. Behind a load balancer the peer address is the balancer's, which
        // would collapse every client into one bucket.
        ctx.client_addr = client_ip::resolve(session, self.client_ip.as_ref());

        let multis = self
            .rate_limiters
            .request_filter_stage_multi
            .iter()
            .filter_map(|l| l.get_ticket(session, ctx.client_addr));

        let singles = self
            .rate_limiters
            .request_filter_stage_single
            .iter()
            .filter_map(|l| l.get_ticket(session));

        // Attempt to get all tokens
        //
        // TODO: If https://github.com/udoprog/leaky-bucket/issues/17 is resolved we could
        // remember the buckets that we did get approved for, and "return" the unused tokens.
        //
        // For now, if some tickets succeed but subsequent tickets fail, the preceeding
        // approved tokens are just "burned".
        //
        // TODO: If https://github.com/udoprog/leaky-bucket/issues/34 is resolved we could
        // support a "max debt" number, allowing us to delay if acquisition of the token
        // would happen soon-ish, instead of immediately 429-ing if the token we need is
        // about to become available.
        if singles
            .chain(multis)
            .any(|t| t.now_or_never() == Outcome::Declined)
        {
            tracing::trace!("Rejecting due to rate limiting failure");
            session.downstream_session.respond_error(429).await?;
            return Ok(true);
        }

        for filter in &self.modifiers.request_filters {
            match filter.request_filter(session, ctx).await {
                // If Ok true: we're done handling this request
                o @ Ok(true) => return o,
                // If Err: we return that
                e @ Err(_) => return e,
                // If Ok(false), we move on to the next filter
                Ok(false) => {}
            }
        }

        // A request that declares an oversize body is turned away here, before
        // a byte of it has been read. `request_body_filter` still counts what
        // actually arrives - a `Content-Length` is a claim, and a chunked body
        // makes no claim at all - but catching the honest case costs one header
        // lookup and saves reading the whole body first.
        if let Some(limit) = self.modifiers.request_body_limit.as_ref() {
            if let Some(declared) = declared_body_len(session) {
                if declared > limit.max_bytes {
                    tracing::debug!(
                        declared,
                        max_bytes = limit.max_bytes,
                        "Rejecting a request that declares an oversize body"
                    );
                    session
                        .downstream_session
                        .respond_error(limit.status)
                        .await?;
                    return Ok(true);
                }
            }
        }

        // Which servers may serve this request. Matching here rather than in
        // `upstream_peer` means a request that matches nothing is answered
        // directly, which that phase has no way to do - it must return a peer
        // or an error, and "no route" is neither a proxy failure nor a peer.
        match self.routes.find(session) {
            Some(route) => {
                tracing::trace!(route = %route.name, "Route matched");
                ctx.route = Some(route.name.clone());
            }
            None => {
                tracing::debug!(
                    path = %session.downstream_session.req_header().uri.path(),
                    "No route matched"
                );
                return self.no_route.apply(session).await;
            }
        }

        Ok(false)
    }

    /// Handle the "upstream peer" phase, where we pick which upstream to proxy to
    ///
    /// The route was chosen in `request_filter`; this picks one server from
    /// that route's pool.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Matched again rather than carried across as a reference, because the
        // context cannot hold one that borrows from the service. This is a walk
        // over a handful of routes, and it keeps `upstream_peer` correct even
        // if it is ever reached without `request_filter` having run.
        let route = self
            .routes
            .find(session)
            .ok_or_else(|| pingora::Error::new_str("No route for request"))?;

        let key = (route.selector)(ctx, session);

        let backend = route.pool.select(key);

        // Manually clear the selector buf to avoid accidental leaks
        ctx.selector_buf.clear();

        let backend = backend.ok_or_else(|| {
            tracing::warn!(
                route = %route.name,
                "No healthy upstream server available for this route"
            );
            pingora::Error::new_str("Unable to determine backend")
        })?;

        // Retrieve the HttpPeer from the associated backend metadata
        backend
            .ext
            .get::<HttpPeer>()
            .map(|p| Box::new(p.clone()))
            .ok_or_else(|| pingora::Error::new_str("Fatal: Missing selected backend metadata"))
    }

    /// Handle the "upstream request filter" phase, where we can choose to make
    /// modifications to the request, prior to it being passed along to the
    /// upstream.
    ///
    /// We can also *reject* requests here, though in the future we might do that
    /// via the `request_filter` stage, as that rejection can be done prior to
    /// paying any potential cost `upstream_peer` may incur.
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        header: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        for filter in &self.modifiers.upstream_request_filters {
            filter.upstream_request_filter(session, header, ctx).await?;
        }
        Ok(())
    }

    /// Handle the "upstream response filter" phase, where we can choose to make
    /// modifications to the response, prior to it being passed along downstream
    ///
    /// We may want to also support `upstream_response` stage, as that may interact
    /// with cache differently.
    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        for filter in &self.modifiers.upstream_response_filters {
            filter.upstream_response_filter(session, upstream_response, ctx);
        }
        Ok(())
    }

    /// Handle the "downstream response forwarding" phase
    ///
    /// Unlike [`ProxyHttp::upstream_response_filter`], this runs for every
    /// response on its way out, including one served from cache rather than
    /// fetched from an upstream server. It is the last point at which the
    /// response header can be changed.
    async fn response_filter(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        for filter in &self.modifiers.response_filters {
            filter.upstream_response_filter(session, response, ctx);
        }
        Ok(())
    }

    /// Handle the "request body" phase, one fragment at a time
    ///
    /// This counts what goes by and rejects once the limit is passed. It does
    /// not rewrite: rewriting a body means buffering it, and buffering an
    /// arbitrary body is the thing the limit exists to prevent.
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let Some(limit) = self.modifiers.request_body_limit.as_ref() else {
            return Ok(());
        };
        let Some(chunk) = body.as_ref() else {
            return Ok(());
        };

        ctx.request_body_bytes = ctx.request_body_bytes.saturating_add(chunk.len());

        if ctx.request_body_bytes > limit.max_bytes {
            tracing::debug!(
                seen = ctx.request_body_bytes,
                max_bytes = limit.max_bytes,
                "Rejecting an oversize request body"
            );
            // Pingora's `fail_to_proxy` turns this into the status we name,
            // which is how a rejection at this stage reaches the client.
            return Err(Error::new(ErrorType::HTTPStatus(limit.status)));
        }

        Ok(())
    }

    /// Called once at the end of every request, however it ended
    ///
    /// This is the one callback Pingora runs for every request whatever
    /// happened to it, which is what makes it the right place to give back a
    /// concurrency slot: one that is not given back is one the service never
    /// gets to use again.
    async fn logging(&self, _session: &mut Session, _e: Option<&Error>, ctx: &mut Self::CTX) {
        if ctx.holds_slot {
            ctx.holds_slot = false;
            if let Some(overload) = self.overload.as_ref() {
                overload.release();
            }
        }
    }

    /// Handle the "response body" phase, one fragment at a time
    ///
    /// Note that by the time this runs the response header has already gone
    /// downstream, so an oversize response cannot be turned into an error
    /// response - the exchange can only be cut short.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>>
    where
        Self::CTX: Send + Sync,
    {
        let Some(limit) = self.modifiers.response_body_limit.as_ref() else {
            return Ok(None);
        };
        let Some(chunk) = body.as_ref() else {
            return Ok(None);
        };

        ctx.response_body_bytes = ctx.response_body_bytes.saturating_add(chunk.len());

        if ctx.response_body_bytes > limit.max_bytes {
            tracing::warn!(
                seen = ctx.response_body_bytes,
                max_bytes = limit.max_bytes,
                "Cutting off an oversize response body"
            );
            return Err(Error::new(ErrorType::HTTPStatus(limit.status)));
        }

        Ok(None)
    }
}

/// The request's declared body length, if it declared one
///
/// A `Content-Length` that is not a number is not treated as a length here.
/// Pingora has already checked the framing by this point, and inventing an
/// interpretation of a malformed header is how proxies and their upstream
/// servers come to disagree about where a request ends.
fn declared_body_len(session: &Session) -> Option<usize> {
    session
        .downstream_session
        .req_header()
        .headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse::<usize>()
        .ok()
}
