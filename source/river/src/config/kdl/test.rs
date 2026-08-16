use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, time::Duration};

use crate::{
    config::internal::{
        AcmeDirectory, ChallengeKind, FileServerConfig, HealthCheckKind, HealthCheckSettings,
        ListenerConfig, ListenerKind, PeerTemplate, PeerTimeouts, ProxyConfig, RefreshKind,
        RefreshPolicy, RenewalPolicy, TlsName, UpstreamConfig, UpstreamKind, UpstreamOptions,
    },
    proxy::{
        rate_limiting::{multi::MultiRaterConfig, AllRateConfig, RegexShim},
        request_selector::uri_path_selector,
    },
};

#[test]
fn load_test() {
    let kdl_contents = std::fs::read_to_string("./assets/test-config.kdl").unwrap();

    let doc: ::kdl::KdlDocument = kdl_contents.parse().unwrap_or_else(|e| {
        panic!("Error parsing KDL file: {e:?}");
    });
    let val: crate::config::internal::Config = doc.try_into().unwrap_or_else(|e| {
        panic!("Error rendering config from KDL file: {e:?}");
    });

    let expected = crate::config::internal::Config {
        validate_configs: false,
        threads_per_service: 8,
        basic_proxies: vec![
            ProxyConfig {
                name: "Example1".into(),
                listeners: vec![
                    ListenerConfig {
                        source: crate::config::internal::ListenerKind::Tcp {
                            addr: "0.0.0.0:8080".into(),
                            tls: None,
                            offer_h2: false,
                        },
                    },
                    ListenerConfig {
                        source: crate::config::internal::ListenerKind::Tcp {
                            addr: "0.0.0.0:4443".into(),
                            tls: Some(crate::config::internal::TlsConfig {
                                cert: Some(crate::config::internal::CertKeyPaths {
                                    cert_path: "./assets/test.crt".into(),
                                    key_path: "./assets/test.key".into(),
                                }),
                                acme_domains: vec![],
                            }),
                            offer_h2: true,
                        },
                    },
                ],
                upstreams: vec![UpstreamConfig {
                    kind: UpstreamKind::Static {
                        addr: "91.107.223.4:443".parse().unwrap(),
                    },
                    peer: PeerTemplate {
                        tls: TlsName::Fixed("onevariable.com".into()),
                        alpn: pingora::protocols::ALPN::H2H1,
                        timeouts: PeerTimeouts {
                            connection: Some(Duration::from_millis(1000)),
                            read: Some(Duration::from_millis(30000)),
                            ..PeerTimeouts::default()
                        },
                    },
                }],
                path_control: crate::config::internal::PathControl {
                    upstream_request_filters: vec![
                        BTreeMap::from([
                            ("kind".to_string(), "remove-header-key-regex".to_string()),
                            ("pattern".to_string(), ".*(secret|SECRET).*".to_string()),
                        ]),
                        BTreeMap::from([
                            ("key".to_string(), "x-proxy-friend".to_string()),
                            ("kind".to_string(), "upsert-header".to_string()),
                            ("value".to_string(), "river".to_string()),
                        ]),
                    ],
                    upstream_response_filters: vec![
                        BTreeMap::from([
                            ("kind".to_string(), "remove-header-key-regex".to_string()),
                            ("pattern".to_string(), ".*ETag.*".to_string()),
                        ]),
                        BTreeMap::from([
                            ("key".to_string(), "x-with-love-from".to_string()),
                            ("kind".to_string(), "upsert-header".to_string()),
                            ("value".to_string(), "river".to_string()),
                        ]),
                    ],
                    request_filters: vec![BTreeMap::from([
                        ("kind".to_string(), "block-cidr-range".to_string()),
                        (
                            "addrs".to_string(),
                            "192.168.0.0/16, 10.0.0.0/8, 2001:0db8::0/32".to_string(),
                        ),
                    ])],
                },
                upstream_options: UpstreamOptions {
                    selection: crate::config::internal::SelectionKind::Ketama,
                    selector: uri_path_selector,
                    health_checks: HealthCheckKind::Tcp {
                        settings: HealthCheckSettings {
                            frequency: Duration::from_millis(5000),
                            timeout: Duration::from_millis(1000),
                            consecutive_success: 1,
                            consecutive_failure: 2,
                            parallel: false,
                        },
                        sni: None,
                    },
                },
                rate_limiting: crate::config::internal::RateLimitingConfig {
                    rules: vec![
                        AllRateConfig::Multi {
                            config: MultiRaterConfig {
                                threads: 8,
                                max_buckets: 4000,
                                max_tokens_per_bucket: 10,
                                refill_interval_millis: 10,
                                refill_qty: 1,
                            },
                            kind: crate::proxy::rate_limiting::multi::MultiRequestKeyKind::SourceIp,
                        },
                        AllRateConfig::Multi {
                            config: MultiRaterConfig {
                                threads: 8,
                                max_buckets: 2000,
                                max_tokens_per_bucket: 20,
                                refill_interval_millis: 1,
                                refill_qty: 5,
                            },
                            kind: crate::proxy::rate_limiting::multi::MultiRequestKeyKind::Uri {
                                pattern: RegexShim::new("static/.*").unwrap(),
                            },
                        },
                        AllRateConfig::Single {
                            config: crate::proxy::rate_limiting::single::SingleInstanceConfig {
                                max_tokens_per_bucket: 50,
                                refill_interval_millis: 3,
                                refill_qty: 2,
                            },
                            kind: crate::proxy::rate_limiting::single::SingleRequestKeyKind::UriGroup {
                                pattern: RegexShim::new(r".*\.mp4").unwrap(),
                            },
                        },
                    ],
                },
            },
            ProxyConfig {
                name: "Example2".into(),
                listeners: vec![ListenerConfig {
                    source: crate::config::internal::ListenerKind::Tcp {
                        addr: "0.0.0.0:8000".into(),
                        tls: None,
                        offer_h2: false,
                    },
                }],
                upstreams: vec![UpstreamConfig {
                    kind: UpstreamKind::Static {
                        addr: "91.107.223.4:80".parse().unwrap(),
                    },
                    peer: PeerTemplate::default(),
                }],
                path_control: crate::config::internal::PathControl {
                    upstream_request_filters: vec![],
                    upstream_response_filters: vec![],
                    request_filters: vec![],
                },
                upstream_options: UpstreamOptions::default(),
                rate_limiting: crate::config::internal::RateLimitingConfig { rules: vec![] },
            },
        ],
        file_servers: vec![FileServerConfig {
            name: "Example3".into(),
            listeners: vec![
                ListenerConfig {
                    source: crate::config::internal::ListenerKind::Tcp {
                        addr: "0.0.0.0:9000".into(),
                        tls: None,
                        offer_h2: false,
                    },
                },
                ListenerConfig {
                    source: crate::config::internal::ListenerKind::Tcp {
                        addr: "0.0.0.0:9443".into(),
                        tls: Some(crate::config::internal::TlsConfig {
                            cert: Some(crate::config::internal::CertKeyPaths {
                                cert_path: "./assets/test.crt".into(),
                                key_path: "./assets/test.key".into(),
                            }),
                            acme_domains: vec![],
                        }),
                        offer_h2: true,
                    },
                },
            ],
            base_path: Some(".".into()),
        }],
        daemonize: false,
        pid_file: Some("/tmp/river.pidfile".into()),
        upgrade_socket: Some("/tmp/river-upgrade.sock".into()),
        upgrade: false,
        acme: None,
    };

    assert_eq!(val.validate_configs, expected.validate_configs);
    assert_eq!(val.threads_per_service, expected.threads_per_service);
    assert_eq!(val.basic_proxies.len(), expected.basic_proxies.len());
    assert_eq!(val.file_servers.len(), expected.file_servers.len());

    for (abp, ebp) in val.basic_proxies.iter().zip(expected.basic_proxies.iter()) {
        let ProxyConfig {
            name,
            listeners,
            upstream_options,
            upstreams,
            path_control,
            rate_limiting,
        } = abp;
        assert_eq!(*name, ebp.name);
        assert_eq!(*listeners, ebp.listeners);
        assert_eq!(*upstream_options, ebp.upstream_options);
        assert_eq!(*upstreams, ebp.upstreams);
        assert_eq!(*path_control, ebp.path_control);
        assert_eq!(*rate_limiting, ebp.rate_limiting);
    }

    for (afs, efs) in val.file_servers.iter().zip(expected.file_servers.iter()) {
        let FileServerConfig {
            name,
            listeners,
            base_path,
        } = afs;
        assert_eq!(*name, efs.name);
        assert_eq!(*listeners, efs.listeners);
        assert_eq!(*base_path, efs.base_path);
    }
}

/// Empty: not allowed
const EMPTY_TEST: &str = "
";

#[test]
fn empty() {
    let doc: ::kdl::KdlDocument = EMPTY_TEST.parse().unwrap_or_else(|e| {
        panic!("Error parsing KDL file: {e:?}");
    });
    let val: Result<crate::config::internal::Config, _> = doc.try_into();
    assert!(val.is_err());
}

/// Empty services: not allowed
const SERVICES_EMPTY_TEST: &str = "
    services {

    }
";

#[test]
fn services_empty() {
    let doc: ::kdl::KdlDocument = SERVICES_EMPTY_TEST.parse().unwrap_or_else(|e| {
        panic!("Error parsing KDL file: {e:?}");
    });
    let val: Result<crate::config::internal::Config, _> = doc.try_into();
    assert!(val.is_err());
}

/// The most minimal config is single services block
const ONE_SERVICE_TEST: &str = r#"
services {
    Example {
        listeners {
            "127.0.0.1:80"
        }
        connectors {
            "127.0.0.1:8000"
        }
    }
}
"#;

#[test]
fn one_service() {
    let doc: ::kdl::KdlDocument = ONE_SERVICE_TEST.parse().unwrap_or_else(|e| {
        panic!("Error parsing KDL file: {e:?}");
    });
    let val: crate::config::internal::Config = doc.try_into().unwrap_or_else(|e| {
        panic!("Error rendering config from KDL file: {e:?}");
    });
    assert_eq!(val.basic_proxies.len(), 1);
    assert_eq!(val.basic_proxies[0].listeners.len(), 1);
    assert_eq!(
        val.basic_proxies[0].listeners[0].source,
        ListenerKind::Tcp {
            addr: "127.0.0.1:80".into(),
            tls: None,
            offer_h2: false,
        }
    );
    assert_eq!(
        val.basic_proxies[0].upstreams[0].kind,
        UpstreamKind::Static {
            addr: "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
        }
    );
}

//
// ACME configuration
//

/// Build a config document around an `acme` section and a listener's
/// `acme-domains`, so the tests below only have to state what differs.
fn acme_doc(acme: &str, listener_args: &str) -> String {
    format!(
        r#"
services {{
    Example {{
        listeners {{
            "0.0.0.0:443" {listener_args}
        }}
        connectors {{
            "127.0.0.1:8000"
        }}
    }}
}}
{acme}
"#
    )
}

fn parse(doc: &str) -> miette::Result<crate::config::internal::Config> {
    let doc: ::kdl::KdlDocument = doc.parse().expect("test KDL should parse");
    doc.try_into()
}

const FULL_ACME: &str = r#"
acme {
    provider "letsencrypt-staging"
    accept-terms-of-service true
    contact "mailto:ops@example.com"
    contact "mailto:oncall@example.com"
    store-dir "/var/lib/river/acme"
    renew-before-expiry-days 21
    challenge "http-01"
    challenge-listener "0.0.0.0:80"
    domain "*.example.com" challenge="dns-01" hook="/usr/local/bin/river-dns-hook"
}
"#;

#[test]
fn parses_a_full_acme_section() {
    let cfg = parse(&acme_doc(
        FULL_ACME,
        r#"acme-domains="example.com, www.example.com""#,
    ))
    .unwrap();

    let acme = cfg.acme.as_ref().expect("acme section should be parsed");
    assert_eq!(acme.directory, AcmeDirectory::LetsEncryptStaging);
    assert_eq!(
        acme.directory.url(),
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    );
    assert_eq!(
        acme.contacts,
        vec![
            "mailto:ops@example.com".to_string(),
            "mailto:oncall@example.com".to_string()
        ]
    );
    assert!(acme.accept_terms_of_service);
    assert_eq!(acme.store_dir, PathBuf::from("/var/lib/river/acme"));
    assert_eq!(acme.renewal, RenewalPolicy::BeforeExpiry { days: 21 });
    assert_eq!(acme.default_challenge, ChallengeKind::Http01);
    assert_eq!(acme.challenge_listener.as_deref(), Some("0.0.0.0:80"));

    // The listener's domains come through in order
    assert_eq!(cfg.acme_domains(), vec!["example.com", "www.example.com"]);

    // The per-domain override applies only to the domain it names
    assert_eq!(
        acme.challenge_for("www.example.com"),
        (ChallengeKind::Http01, None)
    );
    let (kind, hook) = acme.challenge_for("*.example.com");
    assert_eq!(kind, ChallengeKind::Dns01);
    assert_eq!(hook, Some(&PathBuf::from("/usr/local/bin/river-dns-hook")));
}

#[test]
fn acme_defaults_are_conservative() {
    let minimal = r#"
acme {
    accept-terms-of-service true
    store-dir "/var/lib/river/acme"
}
"#;
    let cfg = parse(&acme_doc(minimal, r#"acme-domains="example.com""#)).unwrap();
    let acme = cfg.acme.unwrap();

    assert_eq!(acme.directory, AcmeDirectory::LetsEncrypt);
    assert_eq!(acme.default_challenge, ChallengeKind::Http01);
    assert_eq!(acme.renewal, RenewalPolicy::BeforeExpiry { days: 30 });
    assert!(acme.challenge_listener.is_none());
}

#[test]
fn acme_listener_keeps_a_static_fallback_certificate() {
    let cfg = parse(&acme_doc(
        FULL_ACME,
        r#"acme-domains="example.com" cert-path="./assets/test.crt" key-path="./assets/test.key" offer-h2=true"#,
    ))
    .unwrap();

    let ListenerKind::Tcp {
        tls: Some(tls),
        offer_h2,
        ..
    } = &cfg.basic_proxies[0].listeners[0].source
    else {
        panic!("expected a TLS listener");
    };

    assert_eq!(tls.acme_domains, vec!["example.com".to_string()]);
    assert_eq!(
        tls.cert,
        Some(crate::config::internal::CertKeyPaths {
            cert_path: "./assets/test.crt".into(),
            key_path: "./assets/test.key".into(),
        })
    );
    assert!(offer_h2);
}

#[test]
fn acme_domains_alone_make_a_tls_listener() {
    let cfg = parse(&acme_doc(FULL_ACME, r#"acme-domains="example.com""#)).unwrap();

    let ListenerKind::Tcp {
        tls: Some(tls),
        offer_h2,
        ..
    } = &cfg.basic_proxies[0].listeners[0].source
    else {
        panic!("expected a TLS listener");
    };

    assert!(tls.cert.is_none());
    // H2 defaults on for a TLS listener, same as a statically configured one
    assert!(offer_h2);
}

/// The mistakes an operator is most likely to make, and the message they get
#[test]
fn rejects_bad_acme_configurations() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "wildcard without dns-01",
            r#"
acme {
    accept-terms-of-service true
    store-dir "/var/lib/river/acme"
}
"#,
            r#"acme-domains="*.example.com""#,
        ),
        (
            "dns-01 without a hook",
            r#"
acme {
    accept-terms-of-service true
    store-dir "/var/lib/river/acme"
    domain "*.example.com" challenge="dns-01"
}
"#,
            r#"acme-domains="*.example.com""#,
        ),
        (
            "terms of service not accepted",
            r#"
acme {
    store-dir "/var/lib/river/acme"
}
"#,
            r#"acme-domains="example.com""#,
        ),
        (
            "relative store-dir",
            r#"
acme {
    accept-terms-of-service true
    store-dir "./acme"
}
"#,
            r#"acme-domains="example.com""#,
        ),
        (
            "acme-domains with no acme section",
            "",
            r#"acme-domains="example.com""#,
        ),
        (
            "both renewal policies",
            r#"
acme {
    accept-terms-of-service true
    store-dir "/var/lib/river/acme"
    renew-before-expiry-days 30
    renew-after-issue-days 60
}
"#,
            r#"acme-domains="example.com""#,
        ),
        (
            "unknown provider",
            r#"
acme {
    provider "cheapcerts"
    accept-terms-of-service true
    store-dir "/var/lib/river/acme"
}
"#,
            r#"acme-domains="example.com""#,
        ),
        (
            "malformed domain",
            FULL_ACME,
            r#"acme-domains="https://example.com""#,
        ),
        (
            "empty entry in the domain list",
            FULL_ACME,
            r#"acme-domains="example.com,,www.example.com""#,
        ),
        (
            "unknown acme setting",
            r#"
acme {
    accept-terms-of-service true
    store-dir "/var/lib/river/acme"
    renew-every-fortnight true
}
"#,
            r#"acme-domains="example.com""#,
        ),
    ];

    for (why, acme, listener_args) in cases {
        assert!(
            parse(&acme_doc(acme, listener_args)).is_err(),
            "expected '{why}' to be rejected"
        );
    }
}

/// A service that could answer an HTTP-01 challenge must never be made to wait
/// for the ACME service, or first issuance deadlocks: the certificate authority
/// cannot reach the listener, because the listener is waiting on the
/// certificate the authority would issue.
#[test]
fn only_tls_only_services_may_wait_for_acme() {
    use crate::config::internal::serves_plaintext;

    let cfg = parse(&acme_doc(FULL_ACME, r#"acme-domains="example.com""#)).unwrap();
    // The generated document has a single TLS-only listener
    assert!(!serves_plaintext(&cfg.basic_proxies[0].listeners));

    // The common shape - a plaintext listener beside the TLS one - must not wait
    let with_plaintext = r#"
services {
    Example {
        listeners {
            "0.0.0.0:80"
            "0.0.0.0:443" acme-domains="example.com"
        }
        connectors {
            "127.0.0.1:8000"
        }
    }
}
"#
    .to_string()
        + FULL_ACME;

    let cfg = parse(&with_plaintext).unwrap();
    assert!(serves_plaintext(&cfg.basic_proxies[0].listeners));
}

#[test]
fn configs_without_acme_are_unaffected() {
    // The whole feature is opt-in: a document that says nothing about ACME
    // parses exactly as it did before.
    let cfg = parse(&acme_doc("", "")).unwrap();
    assert!(cfg.acme.is_none());
    assert!(cfg.acme_domains().is_empty());
}

//
// Upstream service discovery
//

/// Build a config document around one `connectors` block, so the tests below
/// only have to state the entries they care about.
fn connectors_doc(connectors: &str) -> String {
    format!(
        r#"
services {{
    Example {{
        listeners {{
            "0.0.0.0:80"
        }}
        connectors {{
{connectors}
        }}
    }}
}}
"#
    )
}

fn upstreams(doc: &str) -> Vec<UpstreamConfig> {
    parse(&connectors_doc(doc))
        .unwrap_or_else(|e| panic!("expected this to parse: {e:?}"))
        .basic_proxies
        .remove(0)
        .upstreams
}

#[test]
fn parses_a_dns_source() {
    let parsed = upstreams(
        r#"
            dns "app.example.com" port=8080 refresh-seconds=30 \
                min-refresh-seconds=2 max-refresh-seconds=60
        "#,
    );

    assert_eq!(
        parsed,
        vec![UpstreamConfig {
            kind: UpstreamKind::Dns {
                host: "app.example.com".into(),
                port: 8080,
                refresh: RefreshPolicy {
                    kind: RefreshKind::Fixed(Duration::from_secs(30)),
                    min: Duration::from_secs(2),
                    max: Duration::from_secs(60),
                },
            },
            peer: PeerTemplate::default(),
        }]
    );
}

#[test]
fn parses_an_srv_source() {
    let parsed = upstreams(
        r#"
            srv "_https._tcp.example.com" tls=true proto="h2-or-h1"
        "#,
    );

    assert_eq!(
        parsed,
        vec![UpstreamConfig {
            kind: UpstreamKind::Srv {
                name: "_https._tcp.example.com".into(),
                // Nothing was said about refreshing, so the record's own TTL
                // decides - which is the behaviour an operator expects.
                refresh: RefreshPolicy::default(),
            },
            peer: PeerTemplate {
                tls: TlsName::Discovered,
                alpn: pingora::protocols::ALPN::H2H1,
                timeouts: PeerTimeouts::default(),
            },
        }]
    );
}

#[test]
fn refresh_bounds_are_inherited_from_load_balance() {
    let parsed = upstreams(
        r#"
            load-balance {
                refresh-bounds min-seconds=10 max-seconds=60
            }
            dns "a.example.com" port=80
            dns "b.example.com" port=80 min-refresh-seconds=1
        "#,
    );

    let bounds = |u: &UpstreamConfig| match &u.kind {
        UpstreamKind::Dns { refresh, .. } => (refresh.min, refresh.max),
        _ => unreachable!(),
    };

    assert_eq!(
        bounds(&parsed[0]),
        (Duration::from_secs(10), Duration::from_secs(60))
    );
    // A source may override what it inherited.
    assert_eq!(
        bounds(&parsed[1]),
        (Duration::from_secs(1), Duration::from_secs(60))
    );
}

#[test]
fn the_load_balance_block_may_come_after_the_sources_it_configures() {
    // The block holds defaults the entries read, so it cannot be parsed in
    // document order.
    let parsed = upstreams(
        r#"
            dns "a.example.com" port=80
            load-balance {
                refresh-bounds min-seconds=10 max-seconds=60
            }
        "#,
    );

    let UpstreamKind::Dns { refresh, .. } = &parsed[0].kind else {
        unreachable!()
    };
    assert_eq!(refresh.min, Duration::from_secs(10));
}

#[test]
fn connector_timeouts_are_parsed() {
    let parsed = upstreams(
        r#"
            "10.0.0.1:80" connection-timeout-ms=1000 total-connection-timeout-ms=2000 \
                read-timeout-ms=30000 write-timeout-ms=5000 idle-timeout-ms=60000
        "#,
    );

    assert_eq!(
        parsed[0].peer.timeouts,
        PeerTimeouts {
            connection: Some(Duration::from_millis(1000)),
            total_connection: Some(Duration::from_millis(2000)),
            read: Some(Duration::from_millis(30000)),
            write: Some(Duration::from_millis(5000)),
            idle: Some(Duration::from_millis(60000)),
        }
    );
}

#[test]
fn an_unset_timeout_stays_at_pingoras_default() {
    // Writing `None` over Pingora's defaults would be a change, not a no-op,
    // so an unset key has to stay unset all the way through.
    let parsed = upstreams(r#""10.0.0.1:80""#);
    assert_eq!(parsed[0].peer.timeouts, PeerTimeouts::default());
}

#[test]
fn parses_health_checks() {
    let tcp = parse(&connectors_doc(
        r#"
            load-balance {
                health-check "TCP" frequency-ms=2000 timeout-ms=500 \
                    consecutive-success=2 consecutive-failure=3 parallel=true
            }
            "10.0.0.1:80"
        "#,
    ))
    .unwrap();

    assert_eq!(
        tcp.basic_proxies[0].upstream_options.health_checks,
        HealthCheckKind::Tcp {
            settings: HealthCheckSettings {
                frequency: Duration::from_millis(2000),
                timeout: Duration::from_millis(500),
                consecutive_success: 2,
                consecutive_failure: 3,
                parallel: true,
            },
            sni: None,
        }
    );

    let http = parse(&connectors_doc(
        r#"
            load-balance {
                health-check "HTTP" host="app.example.com" path="/healthz" \
                    expect-status=204 port=9000 tls=true reuse-connection=true
            }
            "10.0.0.1:80"
        "#,
    ))
    .unwrap();

    assert_eq!(
        http.basic_proxies[0].upstream_options.health_checks,
        HealthCheckKind::Http {
            settings: HealthCheckSettings::default(),
            host: "app.example.com".into(),
            path: "/healthz".into(),
            tls: true,
            expect_status: 204,
            port: Some(9000),
            reuse_connection: true,
        }
    );
}

#[test]
fn health_checks_are_off_unless_asked_for() {
    let cfg = parse(&connectors_doc(r#""10.0.0.1:80""#)).unwrap();
    assert_eq!(
        cfg.basic_proxies[0].upstream_options.health_checks,
        HealthCheckKind::None
    );
}

/// `discovery "Static"` said nothing once sources became explicit, but it
/// shipped in v0.5.0, so a document that still has it keeps loading.
#[test]
fn the_old_discovery_setting_still_loads() {
    let cfg = parse(&connectors_doc(
        r#"
            load-balance {
                discovery "Static"
            }
            "10.0.0.1:80"
        "#,
    ))
    .unwrap();

    assert_eq!(cfg.basic_proxies[0].upstreams.len(), 1);
}

/// The mistakes an operator is most likely to make, and whether they are caught
#[test]
fn rejects_bad_connector_configurations() {
    let cases: &[(&str, &str)] = &[
        ("a dns source without a port", r#"dns "app.example.com""#),
        (
            "an address written as a dns source",
            r#"dns "10.0.0.1" port=80"#,
        ),
        (
            "a hostname written as an srv source",
            r#"srv "app.example.com""#,
        ),
        (
            "a hostname written as a plain connector",
            r#""app.example.com:80""#,
        ),
        (
            "a misspelled setting",
            r#""10.0.0.1:80" read-timeout-mms=1000"#,
        ),
        (
            "a timeout that is not a number",
            r#""10.0.0.1:80" read-timeout-ms="30s""#,
        ),
        (
            "both ways of naming the upstream for TLS",
            r#"dns "app.example.com" port=443 tls=true tls-sni="app.example.com""#,
        ),
        (
            "tls=true on an address, which has no name to use",
            r#""10.0.0.1:443" tls=true"#,
        ),
        ("HTTP2 without TLS", r#""10.0.0.1:80" proto="h2-only""#),
        (
            "both ways of setting the refresh interval",
            r#"dns "app.example.com" port=80 refresh="ttl" refresh-seconds=30"#,
        ),
        (
            "an unknown refresh setting",
            r#"dns "app.example.com" port=80 refresh="hourly""#,
        ),
        (
            "a zero refresh interval",
            r#"dns "app.example.com" port=80 refresh-seconds=0"#,
        ),
        (
            "refresh bounds that cross over",
            r#"dns "app.example.com" port=80 min-refresh-seconds=60 max-refresh-seconds=10"#,
        ),
        (
            "an unknown health check kind",
            r#"
            load-balance {
                health-check "Ping"
            }
            "10.0.0.1:80"
            "#,
        ),
        (
            "an HTTP health check without a host",
            r#"
            load-balance {
                health-check "HTTP" path="/healthz"
            }
            "10.0.0.1:80"
            "#,
        ),
        (
            "a health check path that is not a path",
            r#"
            load-balance {
                health-check "HTTP" host="app.example.com" path="healthz"
            }
            "10.0.0.1:80"
            "#,
        ),
        (
            "a zero health check frequency",
            r#"
            load-balance {
                health-check "TCP" frequency-ms=0
            }
            "10.0.0.1:80"
            "#,
        ),
        (
            "a health check threshold of zero",
            r#"
            load-balance {
                health-check "TCP" consecutive-failure=0
            }
            "10.0.0.1:80"
            "#,
        ),
        (
            "two load-balance sections",
            r#"
            load-balance {
                selection "Random"
            }
            load-balance {
                selection "RoundRobin"
            }
            "10.0.0.1:80"
            "#,
        ),
        (
            "a discovery setting that no longer exists",
            r#"
            load-balance {
                discovery "DNS"
            }
            "10.0.0.1:80"
            "#,
        ),
    ];

    for (why, connectors) in cases {
        assert!(
            parse(&connectors_doc(connectors)).is_err(),
            "expected '{why}' to be rejected"
        );
    }
}
