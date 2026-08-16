//! Runtime discovery of upstream servers
//!
//! Pingora's [`Backends`][pingora_load_balancing::Backends] holds exactly one
//! [`ServiceDiscovery`], so [`RiverDiscovery`] is that one, and it fans out to
//! the sources named in a service's `connectors` block. A literal address is a
//! source that yields one server and never changes; a `dns` or `srv` entry is
//! re-resolved while River runs.
//!
//! Each source keeps its own clock and its own last good answer, which is what
//! lets one source refresh every five seconds while another sits on a five
//! minute TTL, and what stops a single failing nameserver from emptying the
//! whole pool.

pub mod dns;
pub mod resolver;
pub mod service;
pub mod srv;

#[cfg(test)]
mod live_test;

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use pingora_core::protocols::l4::socket::SocketAddr as PingoraSocketAddr;
use pingora_core::{Error, ErrorType, Result};
use pingora_load_balancing::{discovery::ServiceDiscovery, Backend, Extensions};

use crate::config::internal::{RefreshPolicy, UpstreamConfig, UpstreamKind};

use self::{dns::DnsJob, resolver::ResolveError, resolver::Resolver, srv::SrvJob};

/// The most backends River will hand to a selection algorithm
///
/// Pingora's weighted selection indexes backends with a `u16` and asserts on
/// anything larger, so a resolution that returns more than this is truncated
/// here rather than panicking there.
const MAX_BACKENDS: usize = u16::MAX as usize;

/// Something that can produce a set of upstream servers
#[async_trait]
pub trait UpstreamSource: Send + Sync {
    /// When this source would like to be polled again
    ///
    /// `None` for a source that never changes.
    fn next_due(&self) -> Option<Instant>;

    /// Whether this source has ever produced an answer
    ///
    /// A source that has never succeeded contributes nothing, and is the
    /// difference between "this service has no backends right now" and "this
    /// service has never known any backends".
    fn has_result(&self) -> bool;

    /// How this source is named in logs
    fn describe(&self) -> &str;

    /// The current set of servers, re-resolving if due
    async fn poll(&self, now: Instant) -> Vec<Backend>;
}

/// The union of every source configured for one service
pub struct RiverDiscovery {
    sources: Vec<Box<dyn UpstreamSource>>,
}

impl RiverDiscovery {
    pub fn new(sources: Vec<Box<dyn UpstreamSource>>) -> Self {
        Self { sources }
    }

    /// Build the sources named by a service's `connectors` block
    pub fn from_config(upstreams: &[UpstreamConfig], resolver: &Arc<dyn Resolver>) -> Self {
        let sources = upstreams
            .iter()
            .map(|upstream| -> Box<dyn UpstreamSource> {
                match &upstream.kind {
                    UpstreamKind::Static { addr } => {
                        Box::new(StaticSource::new(*addr, &upstream.peer))
                    }
                    UpstreamKind::Dns {
                        host,
                        port,
                        refresh,
                    } => Box::new(PollingSource::new(
                        DnsJob::new(resolver.clone(), host, *port, upstream.peer.clone()),
                        *refresh,
                    )),
                    UpstreamKind::Srv { name, refresh } => Box::new(PollingSource::new(
                        SrvJob::new(resolver.clone(), name, upstream.peer.clone()),
                        *refresh,
                    )),
                }
            })
            .collect();

        Self::new(sources)
    }

    /// Does anything here need re-resolving while River runs?
    ///
    /// When nothing does, the service needs no background service at all and
    /// can resolve its backends once, at startup.
    pub fn is_dynamic(&self) -> bool {
        self.sources.iter().any(|s| s.next_due().is_some())
    }

    /// The soonest any source wants to be polled
    pub fn next_due(&self) -> Option<Instant> {
        self.sources.iter().filter_map(|s| s.next_due()).min()
    }

    async fn collect(&self, now: Instant) -> Result<BTreeSet<Backend>> {
        let mut backends = BTreeSet::new();
        let mut known = false;

        for source in &self.sources {
            let found = source.poll(now).await;
            known |= source.has_result();

            for backend in found {
                // `Backend`'s ordering ignores `ext`, so two sources that
                // resolve to the same address collapse into one entry, and
                // `insert` keeps the one already there. Source order in the
                // configuration file therefore decides which connection
                // settings win.
                backends.insert(backend);
            }
        }

        // Returning an error leaves Pingora holding the previous backend set,
        // which is what we want when nothing is known: a service whose only
        // nameserver is unreachable at startup should serve errors rather than
        // pretend it has no upstreams configured.
        if !known {
            let sources = self
                .sources
                .iter()
                .map(|s| s.describe())
                .collect::<Vec<&str>>()
                .join(", ");

            return Error::e_explain(
                ErrorType::InternalError,
                format!("no upstream source has produced a result yet: {sources}"),
            );
        }

        if backends.len() > MAX_BACKENDS {
            tracing::warn!(
                found = backends.len(),
                limit = MAX_BACKENDS,
                "Discovered more upstream servers than the load balancer supports, dropping the excess"
            );
            backends = backends.into_iter().take(MAX_BACKENDS).collect();
        }

        Ok(backends)
    }
}

/// Lets the background service keep a handle on the discovery `Backends` owns
///
/// [`pingora_load_balancing::Backends`] takes ownership of its
/// [`ServiceDiscovery`] and offers no way to borrow it back, but the background
/// loop needs to ask when the next poll is due.
pub struct SharedDiscovery(pub Arc<RiverDiscovery>);

#[async_trait]
impl ServiceDiscovery for SharedDiscovery {
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let backends = self.0.collect(Instant::now()).await?;

        // River expresses "do not send traffic here" through health checks
        // rather than through discovery enablement, so this is always empty.
        Ok((backends, HashMap::new()))
    }
}

/// A single address from the configuration file
struct StaticSource {
    backend: Backend,
    description: String,
}

impl StaticSource {
    fn new(addr: std::net::SocketAddr, template: &crate::config::internal::PeerTemplate) -> Self {
        // A literal address has no name to derive an SNI from, which the
        // configuration parser has already checked.
        let peer = template.peer(addr, "");

        Self {
            backend: backend_for(addr, 1, peer),
            description: addr.to_string(),
        }
    }
}

#[async_trait]
impl UpstreamSource for StaticSource {
    fn next_due(&self) -> Option<Instant> {
        None
    }

    fn has_result(&self) -> bool {
        true
    }

    fn describe(&self) -> &str {
        &self.description
    }

    async fn poll(&self, _now: Instant) -> Vec<Backend> {
        vec![self.backend.clone()]
    }
}

/// One resolution attempt, without any of the scheduling around it
///
/// [`PollingSource`] owns the clock, the cache and the backoff; an
/// implementation of this only has to turn a name into backends.
#[async_trait]
pub(crate) trait ResolveJob: Send + Sync {
    /// Resolve, returning the servers found and how long the answer is good for
    async fn resolve(&self) -> std::result::Result<(Vec<Backend>, Duration), ResolveError>;

    /// How this job is named in logs
    fn describe(&self) -> &str;
}

/// What a polling source remembers between resolutions
struct RefreshState {
    /// When to resolve again
    next_due: Instant,

    /// The last successful answer, served until a new one replaces it
    backends: Vec<Backend>,

    /// Whether there has ever been a successful answer
    have_result: bool,

    /// Consecutive failures, which set the backoff
    failures: u32,
}

/// A source that re-resolves on a schedule
///
/// The schedule comes from [`RefreshPolicy`]: either the TTL of the last
/// answer or a fixed interval, clamped either way. A failed resolution keeps
/// the previous answer and backs off, so a nameserver having a bad minute does
/// not drain traffic off servers that are fine.
pub struct PollingSource<J: ResolveJob> {
    job: J,
    policy: RefreshPolicy,
    state: Mutex<RefreshState>,
}

impl<J: ResolveJob> PollingSource<J> {
    pub(crate) fn new(job: J, policy: RefreshPolicy) -> Self {
        Self {
            job,
            policy,
            // Due immediately: the first poll is what populates the service.
            state: Mutex::new(RefreshState {
                next_due: Instant::now(),
                backends: Vec::new(),
                have_result: false,
                failures: 0,
            }),
        }
    }
}

#[async_trait]
impl<J: ResolveJob> UpstreamSource for PollingSource<J> {
    fn next_due(&self) -> Option<Instant> {
        Some(self.state.lock().unwrap().next_due)
    }

    fn has_result(&self) -> bool {
        self.state.lock().unwrap().have_result
    }

    fn describe(&self) -> &str {
        self.job.describe()
    }

    async fn poll(&self, now: Instant) -> Vec<Backend> {
        // Check the clock and let go of the lock before doing any I/O - it is
        // a std mutex and must not be held across an await.
        {
            let state = self.state.lock().unwrap();
            if now < state.next_due {
                return state.backends.clone();
            }
        }

        let outcome = self.job.resolve().await;
        let mut state = self.state.lock().unwrap();

        match outcome {
            Ok((backends, ttl)) => {
                let interval = self.policy.interval(ttl);
                state.next_due = Instant::now() + interval;
                state.failures = 0;
                state.have_result = true;
                state.backends = backends;
            }
            Err(e) => {
                state.failures = state.failures.saturating_add(1);
                let backoff = self.policy.backoff(state.failures);
                state.next_due = Instant::now() + backoff;

                if state.have_result {
                    tracing::warn!(
                        source = self.job.describe(),
                        error = %e,
                        failures = state.failures,
                        retry_in_secs = backoff.as_secs(),
                        "Could not refresh upstream servers, keeping the last known set"
                    );
                } else {
                    tracing::warn!(
                        source = self.job.describe(),
                        error = %e,
                        failures = state.failures,
                        retry_in_secs = backoff.as_secs(),
                        "Could not discover any upstream servers"
                    );
                }
            }
        }

        state.backends.clone()
    }
}

/// Build a Pingora backend for one discovered address
pub(crate) fn backend_for(
    addr: std::net::SocketAddr,
    weight: usize,
    peer: pingora_core::upstreams::peer::HttpPeer,
) -> Backend {
    let mut ext = Extensions::new();
    ext.insert(peer);

    Backend {
        addr: PingoraSocketAddr::Inet(addr),
        weight,
        ext,
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;
    use crate::config::internal::{PeerTemplate, RefreshKind};

    #[test]
    fn ttl_is_clamped_into_the_configured_band() {
        let policy = RefreshPolicy {
            kind: RefreshKind::Ttl,
            min: Duration::from_secs(5),
            max: Duration::from_secs(300),
        };

        // A zero TTL is common in service meshes, and honouring it literally
        // would mean querying in a loop.
        assert_eq!(policy.interval(Duration::ZERO), Duration::from_secs(5));
        assert_eq!(
            policy.interval(Duration::from_secs(30)),
            Duration::from_secs(30)
        );
        // A day-long TTL should not mean never noticing a deployment.
        assert_eq!(
            policy.interval(Duration::from_secs(86400)),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn a_fixed_interval_ignores_the_ttl() {
        let policy = RefreshPolicy {
            kind: RefreshKind::Fixed(Duration::from_secs(30)),
            min: Duration::from_secs(5),
            max: Duration::from_secs(300),
        };

        assert_eq!(policy.interval(Duration::ZERO), Duration::from_secs(30));
        assert_eq!(
            policy.interval(Duration::from_secs(86400)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn backoff_doubles_up_to_the_ceiling() {
        let policy = RefreshPolicy {
            kind: RefreshKind::Ttl,
            min: Duration::from_secs(5),
            max: Duration::from_secs(300),
        };

        assert_eq!(policy.backoff(1), Duration::from_secs(5));
        assert_eq!(policy.backoff(2), Duration::from_secs(10));
        assert_eq!(policy.backoff(3), Duration::from_secs(20));
        assert_eq!(policy.backoff(7), Duration::from_secs(300));
        // Enough failures to overflow a naive shift.
        assert_eq!(policy.backoff(1000), Duration::from_secs(300));
    }

    #[tokio::test]
    async fn a_static_only_service_never_asks_to_be_polled() {
        let template = PeerTemplate::default();
        let upstreams = vec![UpstreamConfig {
            kind: UpstreamKind::Static {
                addr: "10.0.0.1:80".parse().unwrap(),
            },
            peer: template,
        }];

        let resolver: Arc<dyn Resolver> = resolver::test::FakeResolver::new();
        let disco = RiverDiscovery::from_config(&upstreams, &resolver);

        assert!(!disco.is_dynamic());
        assert_eq!(disco.next_due(), None);

        let backends = disco.collect(Instant::now()).await.unwrap();
        assert_eq!(backends.len(), 1);
    }

    #[tokio::test]
    async fn sources_sharing_an_address_collapse_to_one_backend() {
        let resolver = resolver::test::FakeResolver::new();
        resolver.set_addresses("dupe.example.com", &["10.0.0.1"], Duration::from_secs(30));
        let resolver: Arc<dyn Resolver> = resolver;

        let upstreams = vec![
            UpstreamConfig {
                kind: UpstreamKind::Static {
                    addr: "10.0.0.1:80".parse().unwrap(),
                },
                peer: PeerTemplate::default(),
            },
            UpstreamConfig {
                kind: UpstreamKind::Dns {
                    host: "dupe.example.com".into(),
                    port: 80,
                    refresh: RefreshPolicy::default(),
                },
                peer: PeerTemplate::default(),
            },
        ];

        let disco = RiverDiscovery::from_config(&upstreams, &resolver);
        let backends = disco.collect(Instant::now()).await.unwrap();
        assert_eq!(backends.len(), 1);
    }

    #[tokio::test]
    async fn a_service_that_has_never_resolved_reports_an_error() {
        let resolver: Arc<dyn Resolver> = resolver::test::FakeResolver::new();
        let upstreams = vec![UpstreamConfig {
            kind: UpstreamKind::Dns {
                host: "missing.example.com".into(),
                port: 80,
                refresh: RefreshPolicy::default(),
            },
            peer: PeerTemplate::default(),
        }];

        let disco = RiverDiscovery::from_config(&upstreams, &resolver);
        // An error, rather than an empty set, so that Pingora keeps whatever
        // it had before.
        assert!(disco.collect(Instant::now()).await.is_err());
    }

    #[tokio::test]
    async fn one_failing_source_does_not_remove_a_working_one() {
        let resolver = resolver::test::FakeResolver::new();
        resolver.set_addresses("good.example.com", &["10.0.0.1"], Duration::from_secs(30));
        let resolver: Arc<dyn Resolver> = resolver;

        let upstreams = vec![
            UpstreamConfig {
                kind: UpstreamKind::Dns {
                    host: "good.example.com".into(),
                    port: 80,
                    refresh: RefreshPolicy::default(),
                },
                peer: PeerTemplate::default(),
            },
            UpstreamConfig {
                kind: UpstreamKind::Dns {
                    host: "bad.example.com".into(),
                    port: 80,
                    refresh: RefreshPolicy::default(),
                },
                peer: PeerTemplate::default(),
            },
        ];

        let disco = RiverDiscovery::from_config(&upstreams, &resolver);
        let backends = disco.collect(Instant::now()).await.unwrap();
        assert_eq!(backends.len(), 1);
    }
}
