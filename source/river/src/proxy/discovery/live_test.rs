//! Discovery against a real nameserver, running in this process
//!
//! Everything else in this module is tested against a scripted fake, which is
//! the right tool for the scheduling and weighting logic. What a fake cannot
//! tell us is whether River reads real DNS records correctly: whether the SRV
//! fields land in the right places, and whether the TTL of an answer is what
//! ends up driving the next poll.
//!
//! So these tests serve a zone from `hickory-server` on a loopback port and
//! point River's own resolver at it. Nothing here touches the network, and no
//! name used here resolves on the public internet.

use std::{
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use hickory_server::{
    proto::rr::{
        rdata::{A, SOA, SRV},
        Name, RData, Record, RecordType,
    },
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{AxfrPolicy, Catalog, ZoneHandler, ZoneType},
    Server,
};

use crate::{
    config::internal::{
        PeerTemplate, RefreshKind, RefreshPolicy, TlsName, UpstreamConfig, UpstreamKind,
    },
    proxy::discovery::{
        dns::DnsJob,
        resolver::{Resolver, SystemResolver},
        srv::SrvJob,
        PollingSource, RiverDiscovery, SharedDiscovery, UpstreamSource,
    },
};

const ZONE: &str = "example.com.";

/// A nameserver serving one editable zone
///
/// The `Server` is kept alive by holding it: dropping it stops answering.
struct TestNameserver {
    addr: SocketAddr,
    zone: Arc<InMemoryZoneHandler>,
    serial: u32,
    _server: Server<Catalog>,
}

impl TestNameserver {
    /// Start a nameserver with an empty zone, on a port the OS picks
    async fn start() -> Self {
        let origin = Name::from_str(ZONE).unwrap();

        let mut zone =
            InMemoryZoneHandler::empty(origin.clone(), ZoneType::Primary, AxfrPolicy::Deny);

        // A zone is not a zone without an SOA, and the handler refuses to
        // answer anything until one is present.
        let serial = 1;
        zone.upsert_mut(
            Record::from_rdata(
                origin.clone(),
                60,
                RData::SOA(SOA::new(
                    Name::from_str("ns.example.com.").unwrap(),
                    Name::from_str("hostmaster.example.com.").unwrap(),
                    serial,
                    60,
                    60,
                    60,
                    60,
                )),
            ),
            serial,
        );

        let zone = Arc::new(zone);
        let mut catalog = Catalog::new();
        catalog.upsert(origin.into(), vec![zone.clone() as Arc<dyn ZoneHandler>]);

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        let mut server = Server::new(catalog);
        server.register_socket(socket);

        Self {
            addr,
            zone,
            serial,
            _server: server,
        }
    }

    /// A resolver that asks this nameserver and nothing else
    fn resolver(&self) -> Arc<dyn Resolver> {
        SystemResolver::for_nameserver(self.addr)
    }

    async fn add_a(&mut self, name: &str, ip: &str, ttl: u32) {
        self.serial += 1;
        let record = Record::from_rdata(
            Name::from_str(name).unwrap(),
            ttl,
            RData::A(A(ip.parse().unwrap())),
        );
        self.zone.upsert(record, self.serial).await;
    }

    async fn add_srv(
        &mut self,
        name: &str,
        priority: u16,
        weight: u16,
        port: u16,
        target: &str,
        ttl: u32,
    ) {
        self.serial += 1;
        let record = Record::from_rdata(
            Name::from_str(name).unwrap(),
            ttl,
            RData::SRV(SRV::new(
                priority,
                weight,
                port,
                Name::from_str(target).unwrap(),
            )),
        );
        self.zone.upsert(record, self.serial).await;
    }

    /// Remove every record of a type at a name
    async fn remove(&mut self, name: &str, record_type: RecordType) {
        self.serial += 1;
        self.zone
            .records_mut()
            .await
            .remove(&hickory_server::proto::rr::RrKey::new(
                Name::from_str(name).unwrap().into(),
                record_type,
            ));
    }
}

fn policy(min: Duration, max: Duration) -> RefreshPolicy {
    RefreshPolicy {
        kind: RefreshKind::Ttl,
        min,
        max,
    }
}

#[tokio::test]
async fn reads_real_address_records() {
    let mut ns = TestNameserver::start().await;
    ns.add_a("app.example.com.", "10.0.0.1", 60).await;
    ns.add_a("app.example.com.", "10.0.0.2", 60).await;

    let source = PollingSource::new(
        DnsJob::new(
            ns.resolver(),
            "app.example.com.",
            8080,
            PeerTemplate::default(),
        ),
        policy(Duration::from_secs(1), Duration::from_secs(300)),
    );

    let mut found: Vec<String> = source
        .poll(Instant::now())
        .await
        .iter()
        .map(|b| b.addr.to_string())
        .collect();
    found.sort();

    assert_eq!(found, vec!["10.0.0.1:8080", "10.0.0.2:8080"]);
}

#[tokio::test]
async fn reads_real_srv_records() {
    let mut ns = TestNameserver::start().await;
    ns.add_srv(
        "_https._tcp.example.com.",
        0,
        100,
        8443,
        "a.example.com.",
        60,
    )
    .await;
    ns.add_srv(
        "_https._tcp.example.com.",
        0,
        200,
        9443,
        "b.example.com.",
        60,
    )
    .await;
    // A backup tier, which River deliberately ignores.
    ns.add_srv(
        "_https._tcp.example.com.",
        10,
        100,
        8443,
        "backup.example.com.",
        60,
    )
    .await;
    ns.add_a("a.example.com.", "10.0.0.1", 60).await;
    ns.add_a("b.example.com.", "10.0.0.2", 60).await;
    ns.add_a("backup.example.com.", "10.0.0.3", 60).await;

    let template = PeerTemplate {
        tls: TlsName::Discovered,
        ..PeerTemplate::default()
    };
    let source = PollingSource::new(
        SrvJob::new(ns.resolver(), "_https._tcp.example.com.", template),
        policy(Duration::from_secs(1), Duration::from_secs(300)),
    );

    let mut found = source.poll(Instant::now()).await;
    found.sort_by_key(|b| b.addr.to_string());

    // The port comes from each record, the weights keep their 1:2 ratio, and
    // the priority 10 record is not in the rotation at all.
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].addr.to_string(), "10.0.0.1:8443");
    assert_eq!(found[0].weight, 1);
    assert_eq!(found[1].addr.to_string(), "10.0.0.2:9443");
    assert_eq!(found[1].weight, 2);

    let peer = found[0]
        .ext
        .get::<pingora_core::upstreams::peer::HttpPeer>()
        .unwrap();
    assert_eq!(peer.sni, "a.example.com");
}

/// The whole point of the milestone: a server added to DNS starts receiving
/// traffic, and one removed from DNS stops, without restarting River.
#[tokio::test]
async fn follows_a_zone_change_when_the_ttl_expires() {
    let mut ns = TestNameserver::start().await;
    // A one second TTL, so the test does not have to wait long. `min` is set
    // to match, since it would otherwise be the binding constraint.
    ns.add_a("app.example.com.", "10.0.0.1", 1).await;

    let source = PollingSource::new(
        DnsJob::new(
            ns.resolver(),
            "app.example.com.",
            80,
            PeerTemplate::default(),
        ),
        policy(Duration::from_secs(1), Duration::from_secs(300)),
    );

    assert_eq!(source.poll(Instant::now()).await.len(), 1);

    // A second instance is deployed and appears in DNS.
    ns.add_a("app.example.com.", "10.0.0.2", 1).await;

    // Still inside the TTL, so nothing has changed yet: River is not supposed
    // to query more often than the zone says it may.
    assert_eq!(source.poll(Instant::now()).await.len(), 1);

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let mut found: Vec<String> = source
        .poll(Instant::now())
        .await
        .iter()
        .map(|b| b.addr.to_string())
        .collect();
    found.sort();
    assert_eq!(found, vec!["10.0.0.1:80", "10.0.0.2:80"]);
}

/// A nameserver that stops answering must not drain traffic off servers that
/// are, as far as anyone knows, still healthy.
#[tokio::test]
async fn a_vanishing_record_set_keeps_the_last_known_servers() {
    let mut ns = TestNameserver::start().await;
    ns.add_a("app.example.com.", "10.0.0.1", 1).await;

    let source = PollingSource::new(
        DnsJob::new(
            ns.resolver(),
            "app.example.com.",
            80,
            PeerTemplate::default(),
        ),
        policy(Duration::from_secs(1), Duration::from_secs(300)),
    );

    assert_eq!(source.poll(Instant::now()).await.len(), 1);

    ns.remove("app.example.com.", RecordType::A).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Confirm the name really has stopped resolving, through a resolver with
    // no cache of its own to answer from. Without this the assertion below
    // would pass whether or not the record had gone.
    assert!(ns.resolver().addresses("app.example.com.").await.is_err());

    assert_eq!(source.poll(Instant::now()).await.len(), 1);
    assert!(source.has_result());
}

/// The pieces as Pingora sees them: discovery feeding a `LoadBalancer`, and
/// `select` returning what was discovered along with the peer it should be
/// reached on.
#[tokio::test]
async fn a_load_balancer_selects_discovered_servers() {
    use pingora_load_balancing::{selection::RoundRobin, Backends, LoadBalancer};

    let mut ns = TestNameserver::start().await;
    ns.add_a("app.example.com.", "10.0.0.1", 1).await;

    let discovery = Arc::new(RiverDiscovery::from_config(
        &[UpstreamConfig {
            kind: UpstreamKind::Dns {
                host: "app.example.com.".into(),
                port: 8080,
                refresh: policy(Duration::from_secs(1), Duration::from_secs(300)),
            },
            peer: PeerTemplate::default(),
        }],
        &ns.resolver(),
    ));

    let load_balancer = LoadBalancer::<RoundRobin>::from_backends(Backends::new(Box::new(
        SharedDiscovery(discovery.clone()),
    )));

    load_balancer.update().await.unwrap();

    let backend = load_balancer.select(b"", 256).expect("a discovered server");
    assert_eq!(backend.addr.to_string(), "10.0.0.1:8080");

    // The peer is what `upstream_peer` hands back to Pingora, so it has to
    // survive the trip through discovery.
    let peer = backend
        .ext
        .get::<pingora_core::upstreams::peer::HttpPeer>()
        .expect("every backend carries its peer");
    assert_eq!(peer._address.to_string(), "10.0.0.1:8080");

    // A second server is deployed.
    ns.add_a("app.example.com.", "10.0.0.2", 1).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    load_balancer.update().await.unwrap();

    assert_eq!(load_balancer.backends().get_backend().len(), 2);
}

/// A server that stops listening is taken out of rotation, and comes back when
/// it starts listening again.
#[tokio::test]
async fn health_checks_take_a_dead_server_out_of_rotation() {
    use pingora_load_balancing::{selection::RoundRobin, Backends, LoadBalancer};

    use crate::{
        config::internal::{HealthCheckKind, HealthCheckSettings},
        proxy::health_check,
    };

    // Two real listeners, so that one can be closed.
    let alive = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let doomed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let alive_addr = alive.local_addr().unwrap();
    let doomed_addr = doomed.local_addr().unwrap();

    let upstreams = [alive_addr, doomed_addr].map(|addr| UpstreamConfig {
        kind: UpstreamKind::Static { addr },
        peer: PeerTemplate::default(),
    });

    let discovery = Arc::new(RiverDiscovery::from_config(&upstreams, &ns_free_resolver()));
    let mut backends = Backends::new(Box::new(SharedDiscovery(discovery)));

    let settings = HealthCheckSettings {
        timeout: Duration::from_millis(250),
        ..HealthCheckSettings::default()
    };
    backends.set_health_check(
        health_check::build(&HealthCheckKind::Tcp {
            settings,
            sni: None,
        })
        .expect("a TCP check"),
    );

    let load_balancer = LoadBalancer::<RoundRobin>::from_backends(backends);
    load_balancer.update().await.unwrap();
    load_balancer.backends().run_health_check(false).await;

    // Both are listening, so both are usable.
    assert_eq!(reachable(&load_balancer), 2);

    drop(doomed);
    load_balancer.backends().run_health_check(false).await;

    let selected = load_balancer
        .select(b"", 256)
        .expect("the surviving server");
    assert_eq!(selected.addr.to_string(), alive_addr.to_string());
    assert_eq!(reachable(&load_balancer), 1);

    // And it returns once something is listening there again.
    let _revived = tokio::net::TcpListener::bind(doomed_addr).await.unwrap();
    load_balancer.backends().run_health_check(false).await;
    assert_eq!(reachable(&load_balancer), 2);
}

/// How many backends the load balancer would currently send traffic to
fn reachable(
    load_balancer: &pingora_load_balancing::LoadBalancer<
        pingora_load_balancing::selection::RoundRobin,
    >,
) -> usize {
    load_balancer
        .backends()
        .get_backend()
        .iter()
        .filter(|b| load_balancer.backends().ready(b))
        .count()
}

/// A resolver for tests that only use static sources and never look anything up
fn ns_free_resolver() -> Arc<dyn Resolver> {
    SystemResolver::new()
}
