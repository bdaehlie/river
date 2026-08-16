//! Discovery from SRV records
//!
//! An SRV record set names targets together with their ports, a preference
//! order, and a relative share of traffic. River uses the port and the weight;
//! see [`lowest_tier`] for what happens to the preference order and
//! [`normalize_weights`] for why the weights cannot be used as they arrive.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use pingora_load_balancing::Backend;

use crate::config::internal::PeerTemplate;

use super::{
    backend_for,
    resolver::{ResolveError, Resolver, SrvRecord},
    ResolveJob,
};

/// The largest weight River gives a backend
///
/// Pingora's `Weighted::build` expands a backend into `weight` entries in a
/// lookup table, and rebuilds that table whenever the backend set changes. SRV
/// weights run to 65535, so passing them through unscaled turns a handful of
/// servers into a multi-megabyte allocation. Sixteen steps is more resolution
/// than any real weighting needs.
pub const MAX_WEIGHT: u16 = 16;

/// Resolves one SRV name into a set of servers
pub struct SrvJob {
    resolver: Arc<dyn Resolver>,
    name: String,
    template: PeerTemplate,
    description: String,
}

impl SrvJob {
    pub fn new(resolver: Arc<dyn Resolver>, name: &str, template: PeerTemplate) -> Self {
        Self {
            resolver,
            name: name.to_string(),
            template,
            description: format!("srv {name}"),
        }
    }
}

#[async_trait]
impl ResolveJob for SrvJob {
    async fn resolve(&self) -> Result<(Vec<Backend>, Duration), ResolveError> {
        let answer = self.resolver.srv(&self.name).await?;
        let mut valid_until = answer.valid_until;

        // RFC 2782: a single record with a target of "." says the service is
        // deliberately not offered here. That is an answer, not a failure -
        // the correct behaviour is to have no backends.
        if answer.records.iter().any(SrvRecord::is_unavailable) {
            tracing::info!(
                source = %self.description,
                "SRV record says this service is not offered, no upstream servers"
            );
            return Ok((
                Vec::new(),
                valid_until.saturating_duration_since(Instant::now()),
            ));
        }

        let tier = lowest_tier(&answer.records);
        if tier.is_empty() {
            return Err(ResolveError::new(format!(
                "'{}' returned no SRV records",
                self.name
            )));
        }

        let weights = normalize_weights(&tier.iter().map(|r| r.weight).collect::<Vec<_>>());

        let mut backends = Vec::new();
        let mut failures = 0usize;

        for (record, weight) in tier.iter().zip(weights) {
            let addresses = match self.resolver.addresses(&record.target).await {
                Ok(addresses) => addresses,
                Err(e) => {
                    // One target being unresolvable is normal during a rolling
                    // deploy; the others are still good.
                    tracing::debug!(
                        source = %self.description,
                        target = %record.target,
                        error = %e,
                        "Could not resolve an SRV target"
                    );
                    failures += 1;
                    continue;
                }
            };

            // The answer is only good until its shortest-lived part expires.
            valid_until = valid_until.min(addresses.valid_until);

            for ip in addresses.addrs {
                let addr = SocketAddr::new(ip, record.port);
                backends.push(backend_for(
                    addr,
                    weight,
                    self.template.peer(addr, record.sni()),
                ));
            }
        }

        // Every target failing looks the same as the SRV lookup failing, and
        // should be treated the same way: keep the previous answer.
        if backends.is_empty() && failures > 0 {
            return Err(ResolveError::new(format!(
                "none of the {failures} target(s) of '{}' could be resolved",
                self.name
            )));
        }

        Ok((
            backends,
            valid_until.saturating_duration_since(Instant::now()),
        ))
    }

    fn describe(&self) -> &str {
        &self.description
    }
}

/// The records at the most preferred priority
///
/// RFC 2782 says a client contacts the lowest-numbered priority it can reach,
/// and only falls back to the next when none of those work. Pingora's
/// selection has no notion of preference tiers, so River uses the preferred
/// tier and ignores the rest rather than mixing backup servers into the
/// rotation - which would silently defeat the point of setting priorities.
fn lowest_tier(records: &[SrvRecord]) -> Vec<&SrvRecord> {
    let Some(best) = records.iter().map(|r| r.priority).min() else {
        return Vec::new();
    };

    let tier: Vec<&SrvRecord> = records.iter().filter(|r| r.priority == best).collect();

    if tier.len() < records.len() {
        tracing::debug!(
            using = tier.len(),
            ignored = records.len() - tier.len(),
            priority = best,
            "Using only the most preferred SRV priority; River does not fall back between tiers"
        );
    }

    tier
}

/// Scale SRV weights into the small range the selection algorithm can afford
///
/// Reducing by the greatest common divisor keeps the ratios exact whenever it
/// can - `[100, 200]` becomes `[1, 2]` rather than `[8, 16]` - and scaling
/// handles whatever is left.
///
/// RFC 2782 gives weight 0 the meaning "eligible, but least preferred", which a
/// weighted table cannot express and Pingora would read as "never select".
/// Zero therefore becomes the smallest non-zero share.
fn normalize_weights(weights: &[u16]) -> Vec<usize> {
    if weights.is_empty() {
        return Vec::new();
    }

    // gcd(0, x) == x, so an all-zero set reduces to a divisor of 1 and every
    // record ends up with the same share.
    let divisor = weights
        .iter()
        .fold(0u32, |acc, w| gcd(acc, u32::from(*w)))
        .max(1);

    let reduced: Vec<u32> = weights.iter().map(|w| u32::from(*w) / divisor).collect();
    let largest = reduced.iter().copied().max().unwrap_or(0);

    // A mix of zero and non-zero weights is the one case where reducing by the
    // divisor is not enough: "very small chance" is not a ratio, so there is
    // nothing to preserve. Spreading the non-zero weights across the whole
    // budget leaves the zero-weight records - which land on 1 below - with the
    // smallest share the budget can express.
    let mixed = largest > 0 && reduced.contains(&0);

    let scaled: Vec<u32> = if largest > u32::from(MAX_WEIGHT) || mixed {
        reduced
            .iter()
            .map(|w| (w * u32::from(MAX_WEIGHT)).div_ceil(largest))
            .collect()
    } else {
        reduced
    };

    scaled.into_iter().map(|w| w.max(1) as usize).collect()
}

fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        config::internal::{RefreshKind, RefreshPolicy, TlsName},
        proxy::discovery::{resolver::test::FakeResolver, PollingSource, UpstreamSource},
    };
    use pingora_core::upstreams::peer::HttpPeer;

    fn record(priority: u16, weight: u16, port: u16, target: &str) -> SrvRecord {
        SrvRecord {
            priority,
            weight,
            port,
            target: target.to_string(),
        }
    }

    fn policy() -> RefreshPolicy {
        RefreshPolicy {
            kind: RefreshKind::Ttl,
            min: Duration::from_secs(5),
            max: Duration::from_secs(300),
        }
    }

    #[test]
    fn weights_keep_their_ratio_when_they_can() {
        assert_eq!(normalize_weights(&[100, 200]), vec![1, 2]);
        assert_eq!(normalize_weights(&[3, 6, 9]), vec![1, 2, 3]);
    }

    #[test]
    fn large_weights_are_scaled_down() {
        // Unscaled, this pair would allocate 65536 table entries per rebuild.
        let scaled = normalize_weights(&[65535, 1]);
        assert_eq!(scaled[0], MAX_WEIGHT as usize);
        assert_eq!(scaled[1], 1);
        assert!(scaled.iter().sum::<usize>() <= 2 * MAX_WEIGHT as usize);
    }

    #[test]
    fn zero_weight_still_receives_traffic() {
        // Pingora would never select a backend with weight 0, but RFC 2782
        // says a zero-weight record is eligible.
        assert_eq!(normalize_weights(&[0, 100]), vec![1, 16]);
        // The "no selection to do" case: every record weight 0.
        assert_eq!(normalize_weights(&[0, 0, 0]), vec![1, 1, 1]);
    }

    #[test]
    fn only_the_most_preferred_priority_is_used() {
        let records = vec![
            record(10, 1, 80, "backup.example.com."),
            record(0, 1, 80, "primary.example.com."),
            record(0, 1, 81, "primary2.example.com."),
        ];

        let tier = lowest_tier(&records);
        assert_eq!(tier.len(), 2);
        assert!(tier.iter().all(|r| r.priority == 0));
    }

    #[tokio::test]
    async fn ports_and_weights_come_from_the_records() {
        let fake = FakeResolver::new();
        fake.set_srv(
            "_https._tcp.example.com",
            &[
                record(0, 100, 8443, "a.example.com."),
                record(0, 200, 9443, "b.example.com."),
            ],
            Duration::from_secs(60),
        );
        fake.set_addresses("a.example.com.", &["10.0.0.1"], Duration::from_secs(60));
        fake.set_addresses("b.example.com.", &["10.0.0.2"], Duration::from_secs(60));

        let source = PollingSource::new(
            SrvJob::new(fake, "_https._tcp.example.com", PeerTemplate::default()),
            policy(),
        );

        let mut backends = source.poll(Instant::now()).await;
        backends.sort_by_key(|b| b.addr.to_string());

        assert_eq!(backends.len(), 2);
        assert_eq!(backends[0].addr.to_string(), "10.0.0.1:8443");
        assert_eq!(backends[0].weight, 1);
        assert_eq!(backends[1].addr.to_string(), "10.0.0.2:9443");
        assert_eq!(backends[1].weight, 2);
    }

    #[tokio::test]
    async fn each_target_supplies_its_own_sni() {
        let fake = FakeResolver::new();
        fake.set_srv(
            "_https._tcp.example.com",
            &[record(0, 1, 443, "a.example.com.")],
            Duration::from_secs(60),
        );
        fake.set_addresses("a.example.com.", &["10.0.0.1"], Duration::from_secs(60));

        let template = PeerTemplate {
            tls: TlsName::Discovered,
            ..PeerTemplate::default()
        };
        let source = PollingSource::new(
            SrvJob::new(fake, "_https._tcp.example.com", template),
            policy(),
        );

        let backends = source.poll(Instant::now()).await;
        let peer = backends[0].ext.get::<HttpPeer>().unwrap();
        // Note the trailing dot of the DNS name is gone: SNI must not have one.
        assert_eq!(peer.sni, "a.example.com");
    }

    #[tokio::test]
    async fn a_dot_target_means_no_servers() {
        let fake = FakeResolver::new();
        fake.set_srv(
            "_https._tcp.example.com",
            &[record(0, 0, 0, ".")],
            Duration::from_secs(60),
        );

        let source = PollingSource::new(
            SrvJob::new(fake, "_https._tcp.example.com", PeerTemplate::default()),
            policy(),
        );

        assert!(source.poll(Instant::now()).await.is_empty());
        // An answer, not a failure - so this counts as having a result.
        assert!(source.has_result());
    }

    #[tokio::test]
    async fn an_unresolvable_target_is_skipped() {
        let fake = FakeResolver::new();
        fake.set_srv(
            "_https._tcp.example.com",
            &[
                record(0, 1, 443, "here.example.com."),
                record(0, 1, 443, "gone.example.com."),
            ],
            Duration::from_secs(60),
        );
        fake.set_addresses("here.example.com.", &["10.0.0.1"], Duration::from_secs(60));

        let source = PollingSource::new(
            SrvJob::new(fake, "_https._tcp.example.com", PeerTemplate::default()),
            policy(),
        );

        assert_eq!(source.poll(Instant::now()).await.len(), 1);
    }

    #[tokio::test]
    async fn the_shortest_ttl_in_the_chain_sets_the_next_poll() {
        let fake = FakeResolver::new();
        fake.set_srv(
            "_https._tcp.example.com",
            &[record(0, 1, 443, "a.example.com.")],
            Duration::from_secs(300),
        );
        // The address record expires long before the SRV record does.
        fake.set_addresses("a.example.com.", &["10.0.0.1"], Duration::from_secs(10));
        let counter = fake.clone();

        let source = PollingSource::new(
            SrvJob::new(fake, "_https._tcp.example.com", PeerTemplate::default()),
            policy(),
        );

        let now = Instant::now();
        source.poll(now).await;
        assert_eq!(counter.srv_lookups(), 1);

        source.poll(now + Duration::from_secs(11)).await;
        assert_eq!(counter.srv_lookups(), 2);
    }
}
