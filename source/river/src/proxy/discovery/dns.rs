//! Discovery from a hostname's A and AAAA records
//!
//! This covers the pattern every container orchestrator offers: one name that
//! resolves to every instance of a service, on a port the operator already
//! knows. Kubernetes headless services, Docker Compose service names, and
//! Consul's DNS interface all work this way.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use pingora_load_balancing::Backend;

use crate::config::internal::PeerTemplate;

use super::{
    backend_for,
    resolver::{ResolveError, Resolver},
    ResolveJob,
};

/// Resolves one hostname into a set of servers on a fixed port
pub struct DnsJob {
    resolver: Arc<dyn Resolver>,
    host: String,
    port: u16,
    template: PeerTemplate,
    description: String,
}

impl DnsJob {
    pub fn new(resolver: Arc<dyn Resolver>, host: &str, port: u16, template: PeerTemplate) -> Self {
        Self {
            resolver,
            host: host.to_string(),
            port,
            template,
            description: format!("dns {host}:{port}"),
        }
    }
}

#[async_trait]
impl ResolveJob for DnsJob {
    async fn resolve(&self) -> Result<(Vec<Backend>, Duration), ResolveError> {
        let answer = self.resolver.addresses(&self.host).await?;

        // Address records carry no name, so every server discovered this way
        // is served under the name that was queried - which is also the right
        // SNI when the template asks for the discovered name.
        let backends = answer
            .addrs
            .iter()
            .map(|ip| {
                let addr = SocketAddr::new(*ip, self.port);
                backend_for(addr, 1, self.template.peer(addr, &self.host))
            })
            .collect::<Vec<_>>();

        if backends.is_empty() {
            return Err(ResolveError::new(format!(
                "'{}' resolved to no addresses",
                self.host
            )));
        }

        Ok((
            backends,
            answer
                .valid_until
                .saturating_duration_since(std::time::Instant::now()),
        ))
    }

    fn describe(&self) -> &str {
        &self.description
    }
}

#[cfg(test)]
mod test {
    use std::time::Instant;

    use super::*;
    use crate::{
        config::internal::{RefreshKind, RefreshPolicy, TlsName},
        proxy::discovery::{resolver::test::FakeResolver, PollingSource, UpstreamSource},
    };
    use pingora_core::upstreams::peer::HttpPeer;

    fn policy() -> RefreshPolicy {
        RefreshPolicy {
            kind: RefreshKind::Ttl,
            min: Duration::from_secs(5),
            max: Duration::from_secs(300),
        }
    }

    #[tokio::test]
    async fn every_address_behind_a_name_becomes_a_backend() {
        let fake = FakeResolver::new();
        fake.set_addresses(
            "app.example.com",
            &["10.0.0.1", "10.0.0.2", "fd00::1"],
            Duration::from_secs(30),
        );

        let source = PollingSource::new(
            DnsJob::new(fake, "app.example.com", 8080, PeerTemplate::default()),
            policy(),
        );

        let backends = source.poll(Instant::now()).await;
        assert_eq!(backends.len(), 3);
        assert!(backends
            .iter()
            .all(|b| b.addr.to_string().ends_with(":8080")));
    }

    #[tokio::test]
    async fn the_queried_name_becomes_the_sni() {
        let fake = FakeResolver::new();
        fake.set_addresses("app.example.com", &["10.0.0.1"], Duration::from_secs(30));

        let template = PeerTemplate {
            tls: TlsName::Discovered,
            ..PeerTemplate::default()
        };
        let source = PollingSource::new(
            DnsJob::new(fake, "app.example.com", 443, template),
            policy(),
        );

        let backends = source.poll(Instant::now()).await;
        let peer = backends[0].ext.get::<HttpPeer>().unwrap();
        assert_eq!(peer.sni, "app.example.com");
    }

    #[tokio::test]
    async fn a_name_is_not_re_resolved_until_its_ttl_expires() {
        let fake = FakeResolver::new();
        fake.set_addresses("app.example.com", &["10.0.0.1"], Duration::from_secs(30));
        let counter = fake.clone();

        let source = PollingSource::new(
            DnsJob::new(fake, "app.example.com", 80, PeerTemplate::default()),
            policy(),
        );

        let now = Instant::now();
        source.poll(now).await;
        assert_eq!(counter.address_lookups(), 1);

        // Well inside the 30 second TTL, so this is answered from the cache.
        source.poll(now + Duration::from_secs(10)).await;
        assert_eq!(counter.address_lookups(), 1);

        source.poll(now + Duration::from_secs(31)).await;
        assert_eq!(counter.address_lookups(), 2);
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_last_known_servers() {
        let fake = FakeResolver::new();
        fake.set_addresses("app.example.com", &["10.0.0.1"], Duration::from_secs(30));
        let control = fake.clone();

        let source = PollingSource::new(
            DnsJob::new(fake, "app.example.com", 80, PeerTemplate::default()),
            policy(),
        );

        let now = Instant::now();
        assert_eq!(source.poll(now).await.len(), 1);

        control.clear_addresses("app.example.com");
        let backends = source.poll(now + Duration::from_secs(31)).await;

        // The nameserver is unreachable, but the server behind it is probably
        // still fine - draining traffic off it would turn a DNS blip into an
        // outage.
        assert_eq!(backends.len(), 1);
        assert!(source.has_result());
    }
}
