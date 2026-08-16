//! This is the *actual* internal configuration structure.
//!
//! It is ONLY used for the internal configuration, and should not ever
//! be exposed as the public API for CLI, Env vars, or via Serde.
//!
//! This is used as the buffer between any external stable UI, and internal
//! impl details which may change at any time.

use std::{collections::BTreeMap, path::PathBuf};

use pingora::{
    server::configuration::{Opt as PingoraOpt, ServerConf as PingoraServerConf},
    upstreams::peer::HttpPeer,
};
use tracing::warn;

use crate::proxy::{
    rate_limiting::AllRateConfig,
    request_selector::{null_selector, RequestSelector},
};

/// River's internal configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub validate_configs: bool,
    pub threads_per_service: usize,
    pub daemonize: bool,
    pub pid_file: Option<PathBuf>,
    pub upgrade_socket: Option<PathBuf>,
    pub upgrade: bool,
    pub basic_proxies: Vec<ProxyConfig>,
    pub file_servers: Vec<FileServerConfig>,
    /// Account-level ACME settings, when any listener manages domains
    pub acme: Option<AcmeConfig>,
}

impl Config {
    /// Every domain named by any listener's `acme-domains`
    ///
    /// Duplicates are preserved: the same domain appearing on two listeners is
    /// unusual but not wrong, and the caller decides what to make of it.
    pub fn acme_domains(&self) -> Vec<&str> {
        let proxy_listeners = self.basic_proxies.iter().flat_map(|p| p.listeners.iter());
        let file_listeners = self.file_servers.iter().flat_map(|f| f.listeners.iter());

        proxy_listeners
            .chain(file_listeners)
            .filter_map(|l| match &l.source {
                ListenerKind::Tcp { tls: Some(tls), .. } => Some(tls),
                _ => None,
            })
            .flat_map(|tls| tls.acme_domains.iter().map(String::as_str))
            .collect()
    }
}

/// Can this set of listeners answer an HTTP-01 challenge?
///
/// A certificate authority validates `http-01` over plain HTTP, so only a
/// listener without TLS can serve one. This decides whether a service is
/// allowed to wait for the ACME service before it starts: a service that might
/// be needed to answer a challenge must not wait for the thing that is waiting
/// on the challenge.
pub fn serves_plaintext(listeners: &[ListenerConfig]) -> bool {
    listeners.iter().any(|l| {
        matches!(
            &l.source,
            ListenerKind::Tcp { tls: None, .. } | ListenerKind::Uds(_)
        )
    })
}

impl Config {
    /// Get the [`Opt`][PingoraOpt] field for Pingora
    pub fn pingora_opt(&self) -> PingoraOpt {
        // TODO
        PingoraOpt {
            upgrade: self.upgrade,
            daemon: self.daemonize,
            nocapture: false,
            test: self.validate_configs,
            conf: None,
        }
    }

    /// Get the [`ServerConf`][PingoraServerConf] field for Pingora
    pub fn pingora_server_conf(&self) -> PingoraServerConf {
        PingoraServerConf {
            daemon: self.daemonize,
            error_log: None,
            // TODO: These are bad assumptions - non-developers will not have "target"
            // files, and we shouldn't necessarily use utf-8 strings with fixed separators
            // here.
            pid_file: self
                .pid_file
                .as_ref()
                .cloned()
                .unwrap_or_else(|| PathBuf::from("/tmp/river.pidfile"))
                .to_string_lossy()
                .into(),
            upgrade_sock: self
                .upgrade_socket
                .as_ref()
                .cloned()
                .unwrap_or_else(|| PathBuf::from("/tmp/river-upgrade.sock"))
                .to_string_lossy()
                .into(),
            user: None,
            group: None,
            threads: self.threads_per_service,
            work_stealing: true,
            ca_file: None,
            ..PingoraServerConf::default()
        }
    }

    pub fn validate(&self) {
        // This is currently mostly ad-hoc checks, we should potentially be a bit
        // more systematic about this.
        if self.daemonize {
            if let Some(pf) = self.pid_file.as_ref() {
                // NOTE: currently due to https://github.com/cloudflare/pingora/issues/331,
                // we are not able to use relative paths.
                assert!(pf.is_absolute(), "pid file path must be absolute, see https://github.com/cloudflare/pingora/issues/331");
            } else {
                panic!("Daemonize commanded but no pid file set!");
            }
        } else if let Some(pf) = self.pid_file.as_ref() {
            if !pf.is_absolute() {
                warn!("pid file path must be absolute. Currently: {:?}, see https://github.com/cloudflare/pingora/issues/331", pf);
            }
        }
        if self.upgrade {
            assert!(
                cfg!(target_os = "linux"),
                "Upgrade is only supported on linux!"
            );
            if let Some(us) = self.upgrade_socket.as_ref() {
                // NOTE: currently due to https://github.com/cloudflare/pingora/issues/331,
                // we are not able to use relative paths.
                assert!(us.is_absolute(), "upgrade socket path must be absolute, see https://github.com/cloudflare/pingora/issues/331");
            } else {
                panic!("Upgrade commanded but upgrade socket path not set!");
            }
        } else if let Some(us) = self.upgrade_socket.as_ref() {
            if !us.is_absolute() {
                warn!("upgrade socket path must be absolute. Currently: {:?}, see https://github.com/cloudflare/pingora/issues/331", us);
            }
        }

        if let Some(acme) = self.acme.as_ref() {
            // Same reasoning as the pid file: a relative path is resolved
            // against a working directory that changes when River daemonizes.
            assert!(
                acme.store_dir.is_absolute(),
                "acme store-dir must be an absolute path, got {:?}",
                acme.store_dir
            );

            // The domains are the reason the block exists, so an ACME block
            // with nothing to manage is almost certainly a mistake.
            if self.acme_domains().is_empty() {
                warn!(
                    "An 'acme' section is configured, but no listener sets 'acme-domains'. \
                     No certificates will be requested."
                );
            }
        }
    }
}

///
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RateLimitingConfig {
    pub(crate) rules: Vec<AllRateConfig>,
}

//
// ACME Configuration
//

/// Account-level settings for automatic certificate management
///
/// Which domains are managed is set per-listener, via
/// [`TlsConfig::acme_domains`] - this holds the settings that apply to all of
/// them.
#[derive(Debug, Clone, PartialEq)]
pub struct AcmeConfig {
    /// The ACME server to obtain certificates from
    pub(crate) directory: AcmeDirectory,

    /// Contact URIs registered with the account, such as `mailto:ops@example.com`
    pub(crate) contacts: Vec<String>,

    /// Set when the operator has agreed to the CA's terms of service
    ///
    /// Most CAs, Let's Encrypt included, refuse to create an account without
    /// this. There is no sensible default: agreeing to a legal document is the
    /// operator's to do, so it must be written down explicitly.
    pub(crate) accept_terms_of_service: bool,

    /// Where the account key and issued certificates are kept
    ///
    /// This must be writable by the user River runs as *after* dropping
    /// privileges, not the user that launched it.
    pub(crate) store_dir: PathBuf,

    /// When certificates should be renewed
    pub(crate) renewal: RenewalPolicy,

    /// The challenge used for domains without a more specific setting
    pub(crate) default_challenge: ChallengeKind,

    /// An optional listener dedicated to answering HTTP-01 challenges
    ///
    /// Not needed when a service already has a plaintext listener that the CA
    /// can reach on port 80.
    pub(crate) challenge_listener: Option<String>,

    /// How long to wait after a DNS-01 hook returns, before asking the CA to check
    ///
    /// A hook that returns before its record is visible to the CA's resolvers
    /// causes a failed validation, which costs a retry against the CA's rate
    /// limits.
    pub(crate) dns_propagation_seconds: u32,

    /// Per-domain overrides of the default challenge
    pub(crate) domains: Vec<AcmeDomainConfig>,
}

/// The ACME server to talk to
#[derive(Debug, Clone, PartialEq)]
pub enum AcmeDirectory {
    LetsEncrypt,
    LetsEncryptStaging,
    /// A directory URL, for any other CA or for a test server such as Pebble
    Custom(String),
}

impl AcmeDirectory {
    pub fn url(&self) -> &str {
        match self {
            AcmeDirectory::LetsEncrypt => "https://acme-v02.api.letsencrypt.org/directory",
            AcmeDirectory::LetsEncryptStaging => {
                "https://acme-staging-v02.api.letsencrypt.org/directory"
            }
            AcmeDirectory::Custom(url) => url,
        }
    }
}

/// When a certificate should be replaced
///
/// These are the two forms called for by the requirements: counting forward
/// from when the certificate was obtained, or backward from when it expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalPolicy {
    /// Renew once fewer than this many days remain before expiry
    BeforeExpiry { days: u32 },
    /// Renew once this many days have passed since the certificate was issued
    AfterIssue { days: u32 },
}

impl Default for RenewalPolicy {
    fn default() -> Self {
        // Let's Encrypt certificates last 90 days and the recommended renewal
        // point is with a third of the lifetime left.
        RenewalPolicy::BeforeExpiry { days: 30 }
    }
}

/// How River proves control of a domain
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    /// Serve a token over plain HTTP on port 80
    Http01,
    /// Publish a TXT record, via an operator-supplied hook
    ///
    /// Required for wildcard domains - no CA will issue a wildcard against any
    /// other challenge type.
    Dns01,
}

impl ChallengeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChallengeKind::Http01 => "http-01",
            ChallengeKind::Dns01 => "dns-01",
        }
    }
}

/// Settings that apply to one managed domain rather than to all of them
#[derive(Debug, Clone, PartialEq)]
pub struct AcmeDomainConfig {
    /// The domain this applies to, exactly as it appears in `acme-domains`
    pub(crate) domain: String,

    /// The challenge to use for this domain
    pub(crate) challenge: ChallengeKind,

    /// The program run to publish and remove DNS-01 TXT records
    ///
    /// Required when `challenge` is [`ChallengeKind::Dns01`].
    pub(crate) dns_hook: Option<PathBuf>,
}

impl AcmeConfig {
    /// The challenge to use for `domain`, and the hook to run if it is DNS-01
    pub fn challenge_for(&self, domain: &str) -> (ChallengeKind, Option<&PathBuf>) {
        let normalized = crate::tls::store::normalize(domain);

        match self
            .domains
            .iter()
            .find(|d| crate::tls::store::normalize(&d.domain) == normalized)
        {
            Some(over) => (over.challenge, over.dns_hook.as_ref()),
            None => (self.default_challenge, None),
        }
    }
}

/// Add Path Control Modifiers
///
/// Note that we use `BTreeMap` and NOT `HashMap`, as we want to maintain the
/// ordering from the configuration file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PathControl {
    pub(crate) request_filters: Vec<BTreeMap<String, String>>,
    pub(crate) upstream_request_filters: Vec<BTreeMap<String, String>>,
    pub(crate) upstream_response_filters: Vec<BTreeMap<String, String>>,
}

//
// File Server Configuration
//
#[derive(Debug, Clone)]
pub struct FileServerConfig {
    pub(crate) name: String,
    pub(crate) listeners: Vec<ListenerConfig>,
    pub(crate) base_path: Option<PathBuf>,
}

//
// Basic Proxy Configuration
//

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub(crate) name: String,
    pub(crate) listeners: Vec<ListenerConfig>,
    pub(crate) upstream_options: UpstreamOptions,
    pub(crate) upstreams: Vec<HttpPeer>,
    pub(crate) path_control: PathControl,
    pub(crate) rate_limiting: RateLimitingConfig,
}

#[derive(Debug, PartialEq, Clone)]
pub struct TlsConfig {
    /// A certificate and key loaded from disk
    ///
    /// When `acme_domains` is also set, this is the certificate served to
    /// clients whose SNI matches none of the managed domains.
    pub(crate) cert: Option<CertKeyPaths>,

    /// Domains that River obtains and renews certificates for over ACME
    ///
    /// A non-empty list here requires an [`AcmeConfig`] to be present.
    pub(crate) acme_domains: Vec<String>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct CertKeyPaths {
    pub(crate) cert_path: PathBuf,
    pub(crate) key_path: PathBuf,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ListenerConfig {
    pub(crate) source: ListenerKind,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ListenerKind {
    Tcp {
        addr: String,
        tls: Option<TlsConfig>,
        offer_h2: bool,
    },
    Uds(PathBuf),
}

#[derive(Debug, Clone)]
pub struct UpstreamOptions {
    pub(crate) selection: SelectionKind,
    pub(crate) selector: RequestSelector,
    pub(crate) health_checks: HealthCheckKind,
    pub(crate) discovery: DiscoveryKind,
}

impl PartialEq for UpstreamOptions {
    fn eq(&self, other: &Self) -> bool {
        // [`RequestSelector`] is a function pointer, so the only way to compare
        // two of them is by address. That is not reliable in general - the same
        // function can end up at different addresses in different codegen units,
        // and distinct functions can be merged into a single address - but the
        // selectors are a small, fixed set of functions, and this comparison is
        // only used to check parsed configuration against expected values.
        self.selection == other.selection
            && std::ptr::fn_addr_eq(self.selector, other.selector)
            && self.health_checks == other.health_checks
            && self.discovery == other.discovery
    }
}

impl Default for UpstreamOptions {
    fn default() -> Self {
        Self {
            selection: SelectionKind::RoundRobin,
            selector: null_selector,
            health_checks: HealthCheckKind::None,
            discovery: DiscoveryKind::Static,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum SelectionKind {
    RoundRobin,
    Random,
    Fnv,
    Ketama,
}

#[derive(Debug, PartialEq, Clone)]
pub enum HealthCheckKind {
    None,
}

#[derive(Debug, PartialEq, Clone)]
pub enum DiscoveryKind {
    Static,
}

//
// Boilerplate trait impls
//

impl Default for Config {
    fn default() -> Self {
        Self {
            validate_configs: false,
            threads_per_service: 8,
            basic_proxies: vec![],
            file_servers: vec![],
            acme: None,
            daemonize: false,
            pid_file: None,
            upgrade: false,
            upgrade_socket: None,
        }
    }
}
