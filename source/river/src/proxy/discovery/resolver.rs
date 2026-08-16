//! Name resolution, behind a trait
//!
//! Discovery sources talk to DNS through [`Resolver`] rather than through
//! `hickory-resolver` directly. That keeps the interesting logic - priority
//! tiers, weight scaling, TTL clamping, backoff - testable against scripted
//! answers, without a nameserver and without constructing `hickory` types by
//! hand.
//!
//! Every answer carries the instant it stops being valid, because that is what
//! "River MUST support the use of DNS TTL as timeout value for re-polling" in
//! `docs/what-is-it.md` section 2.3 needs.

use std::{
    net::IpAddr,
    sync::{Arc, OnceLock},
    time::Instant,
};

use async_trait::async_trait;
use hickory_resolver::{
    config::ResolverConfig, net::runtime::TokioRuntimeProvider, proto::rr::RData, TokioResolver,
};

/// A lookup that did not produce an answer
///
/// The underlying error types differ between the resolver setup step and the
/// lookup itself, and nothing in River does anything with them beyond logging,
/// so they are flattened into a message here.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ResolveError(String);

impl ResolveError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// The addresses behind a hostname, and how long they may be used
pub struct Addresses {
    pub addrs: Vec<IpAddr>,

    /// The instant the answer stops being valid, from its TTL
    pub valid_until: Instant,
}

/// The SRV records for a service, and how long they may be used
pub struct SrvRecords {
    pub records: Vec<SrvRecord>,
    pub valid_until: Instant,
}

/// One SRV record
///
/// Field meanings are RFC 2782's: lower `priority` is preferred, `weight` is a
/// relative share within one priority, and `target` is a hostname that still
/// needs resolving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,

    /// The target hostname, in the form the nameserver gave it - which for a
    /// fully qualified name includes the trailing dot.
    pub target: String,
}

impl SrvRecord {
    /// A target of `.` means the service is deliberately not offered here
    pub fn is_unavailable(&self) -> bool {
        self.target == "."
    }

    /// The target as a name suitable for TLS SNI
    ///
    /// SNI must not carry the trailing dot that a fully qualified DNS name
    /// has, so it is trimmed here.
    pub fn sni(&self) -> &str {
        self.target.trim_end_matches('.')
    }
}

/// Somewhere to look up names
#[async_trait]
pub trait Resolver: Send + Sync + 'static {
    /// The A and AAAA records for `host`
    async fn addresses(&self, host: &str) -> Result<Addresses, ResolveError>;

    /// The SRV records for `name`, which is a full `_service._proto.domain`
    async fn srv(&self, name: &str) -> Result<SrvRecords, ResolveError>;
}

/// The system resolver, as configured in `/etc/resolv.conf`
///
/// The `hickory` resolver is built on first use rather than at construction.
/// River builds its services before Pingora sets up any runtime, and the first
/// use of this always happens inside a background service, where a runtime is
/// definitely present.
#[derive(Default)]
pub struct SystemResolver {
    /// Which nameservers to ask. `None` means whatever the system says.
    config: Option<ResolverConfig>,

    inner: OnceLock<Result<TokioResolver, String>>,
}

impl SystemResolver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A resolver that asks one specific nameserver over UDP
    ///
    /// Only used by tests, which need to point at a nameserver they control
    /// rather than the machine's.
    #[cfg(test)]
    pub fn for_nameserver(addr: std::net::SocketAddr) -> Arc<Self> {
        use hickory_resolver::config::{ConnectionConfig, NameServerConfig};

        let mut connection = ConnectionConfig::udp();
        connection.port = addr.port();

        Arc::new(Self {
            config: Some(ResolverConfig::from_parts(
                None,
                vec![],
                vec![NameServerConfig::new(addr.ip(), true, vec![connection])],
            )),
            inner: OnceLock::new(),
        })
    }

    fn get(&self) -> Result<&TokioResolver, ResolveError> {
        let built = self.inner.get_or_init(|| {
            let builder = match self.config.as_ref() {
                Some(config) => TokioResolver::builder_with_config(
                    config.clone(),
                    TokioRuntimeProvider::default(),
                ),
                None => match TokioResolver::builder_tokio() {
                    Ok(builder) => builder,
                    Err(e) => return Err(e.to_string()),
                },
            };

            builder.build().map_err(|e| e.to_string())
        });

        built.as_ref().map_err(|e| {
            ResolveError::new(format!("could not set up the system DNS resolver: {e}"))
        })
    }
}

#[async_trait]
impl Resolver for SystemResolver {
    async fn addresses(&self, host: &str) -> Result<Addresses, ResolveError> {
        let lookup = self
            .get()?
            .lookup_ip(host)
            .await
            .map_err(|e| ResolveError::new(format!("looking up '{host}': {e}")))?;

        Ok(Addresses {
            valid_until: lookup.valid_until(),
            addrs: lookup.iter().collect(),
        })
    }

    async fn srv(&self, name: &str) -> Result<SrvRecords, ResolveError> {
        let lookup = self
            .get()?
            .srv_lookup(name)
            .await
            .map_err(|e| ResolveError::new(format!("looking up SRV '{name}': {e}")))?;

        // The answer section can hold records of other types - a CNAME chain,
        // for instance - so this filters rather than assuming.
        let records = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::SRV(srv) => Some(SrvRecord {
                    priority: srv.priority,
                    weight: srv.weight,
                    port: srv.port,
                    target: srv.target.to_utf8(),
                }),
                _ => None,
            })
            .collect();

        Ok(SrvRecords {
            records,
            valid_until: lookup.valid_until(),
        })
    }
}

#[cfg(test)]
pub mod test {
    use std::{
        collections::HashMap,
        sync::Mutex,
        time::{Duration, Instant},
    };

    use super::*;

    /// A resolver that answers from a script, for tests
    ///
    /// Answers are keyed by name. A name with no entry fails the lookup, which
    /// is how the failure paths are exercised.
    #[derive(Default)]
    pub struct FakeResolver {
        inner: Mutex<Fake>,
    }

    #[derive(Default)]
    struct Fake {
        addresses: HashMap<String, (Vec<IpAddr>, Duration)>,
        srv: HashMap<String, (Vec<SrvRecord>, Duration)>,
        address_lookups: usize,
        srv_lookups: usize,
    }

    impl FakeResolver {
        pub fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        /// Answer `host` with `addrs`, valid for `ttl`
        pub fn set_addresses(&self, host: &str, addrs: &[&str], ttl: Duration) {
            let addrs = addrs.iter().map(|a| a.parse().unwrap()).collect();
            self.inner
                .lock()
                .unwrap()
                .addresses
                .insert(host.to_string(), (addrs, ttl));
        }

        /// Stop answering for `host`, so lookups fail
        pub fn clear_addresses(&self, host: &str) {
            self.inner.lock().unwrap().addresses.remove(host);
        }

        pub fn set_srv(&self, name: &str, records: &[SrvRecord], ttl: Duration) {
            self.inner
                .lock()
                .unwrap()
                .srv
                .insert(name.to_string(), (records.to_vec(), ttl));
        }

        /// How many address lookups have been made, to check polling intervals
        pub fn address_lookups(&self) -> usize {
            self.inner.lock().unwrap().address_lookups
        }

        pub fn srv_lookups(&self) -> usize {
            self.inner.lock().unwrap().srv_lookups
        }
    }

    #[async_trait]
    impl Resolver for FakeResolver {
        async fn addresses(&self, host: &str) -> Result<Addresses, ResolveError> {
            let mut inner = self.inner.lock().unwrap();
            inner.address_lookups += 1;
            match inner.addresses.get(host) {
                Some((addrs, ttl)) => Ok(Addresses {
                    addrs: addrs.clone(),
                    valid_until: Instant::now() + *ttl,
                }),
                None => Err(ResolveError::new(format!("no such name '{host}'"))),
            }
        }

        async fn srv(&self, name: &str) -> Result<SrvRecords, ResolveError> {
            let mut inner = self.inner.lock().unwrap();
            inner.srv_lookups += 1;
            match inner.srv.get(name) {
                Some((records, ttl)) => Ok(SrvRecords {
                    records: records.clone(),
                    valid_until: Instant::now() + *ttl,
                }),
                None => Err(ResolveError::new(format!("no such service '{name}'"))),
            }
        }
    }
}
