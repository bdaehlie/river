//! Configuration sourced from a TOML file

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::internal::{
    PeerTemplate, PeerTimeouts, RateLimitingConfig, RequestModifierConfig, ResponseModifierConfig,
    TlsName, UpstreamConfig, UpstreamKind, UpstreamOptions,
};
use crate::proxy::rate_limiting::RegexShim;
use http::{HeaderName, HeaderValue};
use pingora::protocols::ALPN;

/// Configuration used for TOML formatted files
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Toml {
    /// System-wide configuration valies
    #[serde(default)]
    pub system: System,

    /// Configuration for each Basic Proxy instance
    #[serde(default = "Vec::new")]
    pub basic_proxy: Vec<ProxyConfig>,
}

impl Toml {
    pub fn from_path<P>(path: &P) -> Self
    where
        P: AsRef<Path> + core::fmt::Debug + ?Sized,
    {
        tracing::info!("Loading TOML from {path:?}");
        let f = std::fs::read_to_string(path)
            .unwrap_or_else(|_| panic!("Failed to load file at {path:?}"));
        let t = ::toml::from_str(&f).expect("failed to deserialize");
        tracing::info!("TOML file contents: {t:?}");
        t
    }
}

//
// System Config
//

/// System level configuration options
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct System {
    #[serde(default = "System::default_threads_per_service")]
    pub threads_per_service: usize,
}

impl Default for System {
    fn default() -> Self {
        System {
            threads_per_service: Self::default_threads_per_service(),
        }
    }
}

impl System {
    fn default_threads_per_service() -> usize {
        8
    }
}

/// Add Path Control Modifiers
///
/// Note that we use `BTreeMap` and NOT `HashMap`, as we want to maintain the
/// ordering from the configuration file.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct PathControl {
    #[serde(default = "Vec::new")]
    pub upstream_request_filters: Vec<BTreeMap<String, String>>,
    #[serde(default = "Vec::new")]
    pub upstream_response_filters: Vec<BTreeMap<String, String>>,
}

//
// Basic Proxy Configuration
//

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ProxyConfig {
    /// Name of the Service. Used for logging.
    pub name: String,

    /// Listeners - or "downstream" interfaces we listen to
    #[serde(default = "Vec::new")]
    pub listeners: Vec<ListenerConfig>,

    /// Connector - our (currently single) "upstream" server
    pub connector: ConnectorConfig,
    #[serde(default = "Default::default")]

    /// Path Control, for modifying and filtering requests
    pub path_control: PathControl,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ConnectorConfig {
    /// Proxy Address, e.g. `IP:port`
    pub proxy_addr: String,
    /// TLS SNI, if TLS should be used
    pub tls_sni: Option<String>,
}

impl From<ConnectorConfig> for UpstreamConfig {
    fn from(val: ConnectorConfig) -> Self {
        // The TOML format predates service discovery and is not being extended
        // to cover it - the KDL format is where new configuration goes - so a
        // connector here is always a single literal address.
        let addr = val.proxy_addr.parse().unwrap_or_else(|_| {
            panic!(
                "'{}' is not an 'IP:port' socket address. To name upstream servers by hostname, \
                 use the KDL configuration format.",
                val.proxy_addr
            )
        });

        let (tls, alpn) = match val.tls_sni {
            Some(sni) => (TlsName::Fixed(sni), ALPN::H2H1),
            None => (TlsName::None, ALPN::H1),
        };

        Self {
            kind: UpstreamKind::Static { addr },
            peer: PeerTemplate {
                tls,
                alpn,
                timeouts: PeerTimeouts::default(),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ListenerTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ListenerConfig {
    pub source: ListenerKind,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "kind", content = "value")]
pub enum ListenerKind {
    Tcp {
        addr: String,
        tls: Option<ListenerTlsConfig>,
    },
    Uds(PathBuf),
}

impl From<ProxyConfig> for super::internal::ProxyConfig {
    fn from(other: ProxyConfig) -> Self {
        Self {
            name: other.name,
            listeners: other.listeners.into_iter().map(Into::into).collect(),
            upstreams: vec![other.connector.into()],
            path_control: other.path_control.into(),
            upstream_options: UpstreamOptions::default(),
            rate_limiting: RateLimitingConfig::default(),
        }
    }
}

impl From<PathControl> for super::internal::PathControl {
    fn from(value: PathControl) -> Self {
        Self {
            // The TOML format has no `request-filters` stage and is not being
            // extended to gain one - the KDL format is where new configuration
            // goes.
            request_filters: vec![],
            upstream_request_filters: value
                .upstream_request_filters
                .into_iter()
                .map(request_modifier_from_map)
                .collect(),
            upstream_response_filters: value
                .upstream_response_filters
                .into_iter()
                .map(response_modifier_from_map)
                .collect(),
        }
    }
}

/// Read one `[[basic-proxy.path-control.upstream-request-filters]]` table
///
/// The KDL format reports a bad filter as a diagnostic pointing at the line
/// that has it. TOML carries no spans here, so the best this can do is panic
/// with a message naming the problem - which is what the rest of this module
/// already does for a malformed connector address.
fn request_modifier_from_map(mut map: BTreeMap<String, String>) -> RequestModifierConfig {
    match take_kind(&mut map).as_str() {
        "remove-header-key-regex" => RequestModifierConfig::RemoveHeaderKeyRegex {
            pattern: take_pattern(&mut map),
        },
        "upsert-header" => {
            let (key, value) = take_header_pair(&mut map);
            RequestModifierConfig::UpsertHeader { key, value }
        }
        other => panic!(
            "'{other}' is not an upstream request filter. Use 'remove-header-key-regex' or \
             'upsert-header'."
        ),
    }
}

/// As [`request_modifier_from_map`], for the response side
fn response_modifier_from_map(mut map: BTreeMap<String, String>) -> ResponseModifierConfig {
    match take_kind(&mut map).as_str() {
        "remove-header-key-regex" => ResponseModifierConfig::RemoveHeaderKeyRegex {
            pattern: take_pattern(&mut map),
        },
        "upsert-header" => {
            let (key, value) = take_header_pair(&mut map);
            ResponseModifierConfig::UpsertHeader { key, value }
        }
        other => panic!(
            "'{other}' is not an upstream response filter. Use 'remove-header-key-regex' or \
             'upsert-header'."
        ),
    }
}

fn take_kind(map: &mut BTreeMap<String, String>) -> String {
    map.remove("kind")
        .expect("a path control filter must have a 'kind'")
}

fn take_pattern(map: &mut BTreeMap<String, String>) -> RegexShim {
    let pattern = map
        .remove("pattern")
        .expect("'remove-header-key-regex' needs a 'pattern'");
    let shim = RegexShim::new(&pattern)
        .unwrap_or_else(|e| panic!("'{pattern}' is not a valid regular expression: {e}"));
    ensure_empty(map);
    shim
}

fn take_header_pair(map: &mut BTreeMap<String, String>) -> (HeaderName, HeaderValue) {
    let key = map.remove("key").expect("'upsert-header' needs a 'key'");
    let value = map
        .remove("value")
        .expect("'upsert-header' needs a 'value'");

    let name = HeaderName::try_from(&key)
        .unwrap_or_else(|_| panic!("'{key}' is not a valid HTTP header name"));
    let value = HeaderValue::try_from(&value)
        .unwrap_or_else(|_| panic!("'{value}' is not a valid HTTP header value"));

    ensure_empty(map);
    (name, value)
}

/// Reject leftover keys, so a misspelling is not silently ignored
fn ensure_empty(map: &BTreeMap<String, String>) {
    if !map.is_empty() {
        let keys = map.keys().map(String::as_str).collect::<Vec<&str>>();
        panic!(
            "Unknown path control filter setting(s): {}",
            keys.join(", ")
        );
    }
}

impl From<ListenerTlsConfig> for super::internal::TlsConfig {
    fn from(other: ListenerTlsConfig) -> Self {
        Self {
            cert: Some(super::internal::CertKeyPaths {
                cert_path: other.cert_path,
                key_path: other.key_path,
            }),
            // The TOML format predates ACME support and is not being extended
            // to cover it - the KDL format is where new configuration goes.
            acme_domains: vec![],
        }
    }
}

impl From<ListenerConfig> for super::internal::ListenerConfig {
    fn from(other: ListenerConfig) -> Self {
        Self {
            source: other.source.into(),
        }
    }
}

impl From<ListenerKind> for super::internal::ListenerKind {
    fn from(other: ListenerKind) -> Self {
        match other {
            ListenerKind::Tcp { addr, tls } => super::internal::ListenerKind::Tcp {
                addr,
                tls: tls.map(Into::into),
                offer_h2: false,
            },
            ListenerKind::Uds(a) => super::internal::ListenerKind::Uds(a),
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::collections::BTreeMap;

    use crate::config::{
        apply_toml,
        internal::{
            self, PeerTemplate, RateLimitingConfig, RequestModifierConfig, ResponseModifierConfig,
            TlsName, UpstreamConfig, UpstreamKind, UpstreamOptions,
        },
        toml::{ConnectorConfig, ListenerConfig, ProxyConfig, System},
    };
    use crate::proxy::rate_limiting::RegexShim;
    use http::{HeaderName, HeaderValue};
    use pingora::protocols::ALPN;

    use super::Toml;

    #[test]
    fn load_example() {
        let snapshot: Toml = Toml {
            system: System {
                threads_per_service: 8,
            },
            basic_proxy: vec![],
        };
        let loaded = Toml::from_path("./assets/example-config.toml");
        assert_eq!(snapshot, loaded);

        let def = internal::Config::default();
        let mut cfg = internal::Config::default();
        apply_toml(&mut cfg, &loaded);

        // These don't impl PartialEq, largely due to `BasicPeer` and `Tracer` not
        // implementing the trait. Since we only need this for testing, this is...
        // sort of acceptable
        assert_eq!(format!("{def:?}"), format!("{cfg:?}"));
    }

    #[test]
    fn load_test() {
        let toml_snapshot: Toml = Toml {
            system: System {
                threads_per_service: 8,
            },
            basic_proxy: vec![
                ProxyConfig {
                    name: "Example1".into(),
                    listeners: vec![
                        ListenerConfig {
                            source: crate::config::toml::ListenerKind::Tcp {
                                addr: "0.0.0.0:8080".into(),
                                tls: None,
                            },
                        },
                        ListenerConfig {
                            source: crate::config::toml::ListenerKind::Tcp {
                                addr: "0.0.0.0:4443".into(),
                                tls: Some(crate::config::toml::ListenerTlsConfig {
                                    cert_path: "./assets/test.crt".into(),
                                    key_path: "./assets/test.key".into(),
                                }),
                            },
                        },
                    ],
                    connector: ConnectorConfig {
                        proxy_addr: "91.107.223.4:443".into(),
                        tls_sni: Some(String::from("onevariable.com")),
                    },
                    path_control: crate::config::toml::PathControl {
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
                    },
                },
                ProxyConfig {
                    name: "Example2".into(),
                    listeners: vec![ListenerConfig {
                        source: crate::config::toml::ListenerKind::Tcp {
                            addr: "0.0.0.0:8000".into(),
                            tls: None,
                        },
                    }],
                    connector: ConnectorConfig {
                        proxy_addr: "91.107.223.4:80".into(),
                        tls_sni: None,
                    },
                    path_control: crate::config::toml::PathControl {
                        upstream_request_filters: vec![],
                        upstream_response_filters: vec![],
                    },
                },
            ],
        };
        let loaded = Toml::from_path("./assets/test-config.toml");
        assert_eq!(toml_snapshot, loaded);

        let sys_snapshot = internal::Config {
            validate_configs: false,
            threads_per_service: 8,
            acme: None,
            basic_proxies: vec![
                internal::ProxyConfig {
                    name: "Example1".into(),
                    listeners: vec![
                        internal::ListenerConfig {
                            source: internal::ListenerKind::Tcp {
                                addr: "0.0.0.0:8080".into(),
                                tls: None,
                                offer_h2: false,
                            },
                        },
                        internal::ListenerConfig {
                            source: internal::ListenerKind::Tcp {
                                addr: "0.0.0.0:4443".into(),
                                tls: Some(internal::TlsConfig {
                                    cert: Some(internal::CertKeyPaths {
                                        cert_path: "./assets/test.crt".into(),
                                        key_path: "./assets/test.key".into(),
                                    }),
                                    acme_domains: vec![],
                                }),
                                offer_h2: false,
                            },
                        },
                    ],
                    upstreams: vec![UpstreamConfig {
                        kind: UpstreamKind::Static {
                            addr: "91.107.223.4:443".parse().unwrap(),
                        },
                        peer: PeerTemplate {
                            tls: TlsName::Fixed("onevariable.com".into()),
                            alpn: ALPN::H2H1,
                            ..PeerTemplate::default()
                        },
                    }],
                    path_control: internal::PathControl {
                        upstream_request_filters: vec![
                            RequestModifierConfig::RemoveHeaderKeyRegex {
                                pattern: RegexShim::new(".*(secret|SECRET).*").unwrap(),
                            },
                            RequestModifierConfig::UpsertHeader {
                                key: HeaderName::from_static("x-proxy-friend"),
                                value: HeaderValue::from_static("river"),
                            },
                        ],
                        upstream_response_filters: vec![
                            ResponseModifierConfig::RemoveHeaderKeyRegex {
                                pattern: RegexShim::new(".*ETag.*").unwrap(),
                            },
                            ResponseModifierConfig::UpsertHeader {
                                key: HeaderName::from_static("x-with-love-from"),
                                value: HeaderValue::from_static("river"),
                            },
                        ],
                        request_filters: vec![],
                    },
                    upstream_options: UpstreamOptions::default(),
                    rate_limiting: RateLimitingConfig::default(),
                },
                internal::ProxyConfig {
                    name: "Example2".into(),
                    listeners: vec![internal::ListenerConfig {
                        source: internal::ListenerKind::Tcp {
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
                    path_control: internal::PathControl {
                        upstream_request_filters: vec![],
                        upstream_response_filters: vec![],
                        request_filters: vec![],
                    },
                    upstream_options: UpstreamOptions::default(),
                    rate_limiting: RateLimitingConfig::default(),
                },
            ],
            file_servers: Vec::new(),
            daemonize: false,
            pid_file: None,
            upgrade_socket: None,
            upgrade: false,
        };

        let mut cfg = internal::Config::default();
        apply_toml(&mut cfg, &loaded);

        // These don't impl PartialEq, largely due to `BasicPeer` and `Tracer` not
        // implementing the trait. Since we only need this for testing, this is...
        // sort of acceptable
        assert_eq!(format!("{sys_snapshot:?}"), format!("{cfg:?}"));
    }
}
