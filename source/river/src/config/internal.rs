//! This is the *actual* internal configuration structure.
//!
//! It is ONLY used for the internal configuration, and should not ever
//! be exposed as the public API for CLI, Env vars, or via Serde.
//!
//! This is used as the buffer between any external stable UI, and internal
//! impl details which may change at any time.

use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, time::Duration};

use pingora::{
    protocols::ALPN,
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
    pub(crate) upstreams: Vec<UpstreamConfig>,
    pub(crate) path_control: PathControl,
    pub(crate) rate_limiting: RateLimitingConfig,
}

//
// Upstream Service Discovery
//

/// One source of upstream servers
///
/// Every entry in a service's `connectors` block becomes one of these. A
/// literal socket address is a source that yields exactly one server and never
/// changes; the others are re-resolved while River runs.
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamConfig {
    pub(crate) kind: UpstreamKind,

    /// How to connect to whatever this source discovers
    pub(crate) peer: PeerTemplate,
}

/// Where a source's list of servers comes from
#[derive(Debug, Clone, PartialEq)]
pub enum UpstreamKind {
    /// A single address, written out in the configuration file
    Static { addr: SocketAddr },

    /// Every address behind a hostname's A and AAAA records
    ///
    /// DNS address records carry no port, so one is given in the
    /// configuration and applies to every discovered address.
    Dns {
        host: String,
        port: u16,
        refresh: RefreshPolicy,
    },

    /// Every target named by a `_service._proto.name` SRV record set
    ///
    /// Unlike [`UpstreamKind::Dns`], the port comes from each record, as does
    /// a relative weight.
    Srv {
        name: String,
        refresh: RefreshPolicy,
    },
}

/// How often a source is re-resolved
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshPolicy {
    pub(crate) kind: RefreshKind,

    /// Never re-resolve more often than this
    ///
    /// A TTL of zero is common in service meshes, and honouring it literally
    /// would mean querying in a tight loop. This is also the first delay used
    /// when backing off after a failed lookup.
    pub(crate) min: Duration,

    /// Always re-resolve at least this often
    ///
    /// A long TTL should not mean River never notices a deployment.
    pub(crate) max: Duration,
}

/// Where the interval between re-resolutions comes from
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshKind {
    /// From the TTL of the records that were returned
    Ttl,
    /// From the configuration file, ignoring the TTL
    Fixed(Duration),
}

impl Default for RefreshPolicy {
    fn default() -> Self {
        Self {
            kind: RefreshKind::Ttl,
            min: Duration::from_secs(5),
            max: Duration::from_secs(300),
        }
    }
}

impl RefreshPolicy {
    /// The delay before the next resolution, given the TTL of the last answer
    ///
    /// `ttl` is ignored when the policy names a fixed interval, and the result
    /// is always inside `min..=max` either way.
    pub fn interval(&self, ttl: Duration) -> Duration {
        let raw = match self.kind {
            RefreshKind::Ttl => ttl,
            RefreshKind::Fixed(fixed) => fixed,
        };
        raw.clamp(self.min, self.max)
    }

    /// The delay before retrying, after `failures` consecutive failed lookups
    ///
    /// Doubles from `min` up to `max`, so a nameserver that is down is asked
    /// about it less and less often.
    pub fn backoff(&self, failures: u32) -> Duration {
        let shift = failures.saturating_sub(1).min(16);
        self.min
            .saturating_mul(1u32 << shift)
            .clamp(self.min, self.max)
    }
}

/// How to connect to a server, once one has been discovered
///
/// This is everything an [`HttpPeer`] needs except the address, which is what
/// discovery supplies.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerTemplate {
    /// Whether to connect over TLS, and if so how the name is chosen
    pub(crate) tls: TlsName,

    pub(crate) alpn: ALPN,

    pub(crate) timeouts: PeerTimeouts,
}

/// The SNI used when connecting to an upstream server
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsName {
    /// Connect without TLS
    None,

    /// Connect over TLS, sending this name
    Fixed(String),

    /// Connect over TLS, sending the name the server was discovered under
    ///
    /// For a `dns` source that is the queried hostname; for a `srv` source it
    /// is each record's target. Only available to sources that have a name -
    /// a literal address does not.
    Discovered,
}

impl PeerTemplate {
    /// Build the peer for one discovered address
    ///
    /// `name` is the hostname the address was discovered under, and is used
    /// only when the template asks for [`TlsName::Discovered`].
    pub fn peer(&self, addr: SocketAddr, name: &str) -> HttpPeer {
        let (tls, sni) = match &self.tls {
            TlsName::None => (false, String::new()),
            TlsName::Fixed(sni) => (true, sni.clone()),
            TlsName::Discovered => (true, name.to_string()),
        };

        let mut peer = HttpPeer::new(addr, tls, sni);
        peer.options.alpn = self.alpn.clone();
        self.timeouts.apply(&mut peer);
        peer
    }
}

impl Default for PeerTemplate {
    fn default() -> Self {
        Self {
            tls: TlsName::None,
            alpn: ALPN::H1,
            timeouts: PeerTimeouts::default(),
        }
    }
}

/// Timeouts applied to connections to an upstream server
///
/// Each is left at Pingora's own default when unset, rather than River
/// inventing a value that would silently override it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerTimeouts {
    /// Establishing the TCP connection
    pub(crate) connection: Option<Duration>,

    /// Establishing the connection including the TLS handshake
    pub(crate) total_connection: Option<Duration>,

    /// Waiting for data from the upstream, which bounds a request
    pub(crate) read: Option<Duration>,

    /// Writing data to the upstream
    pub(crate) write: Option<Duration>,

    /// How long an unused pooled connection is kept
    pub(crate) idle: Option<Duration>,
}

impl PeerTimeouts {
    pub fn apply(&self, peer: &mut HttpPeer) {
        // Only assign what was configured: `PeerOptions` starts from Pingora's
        // defaults, and writing `None` over them would be a change, not a
        // no-op.
        if let Some(t) = self.connection {
            peer.options.connection_timeout = Some(t);
        }
        if let Some(t) = self.total_connection {
            peer.options.total_connection_timeout = Some(t);
        }
        if let Some(t) = self.read {
            peer.options.read_timeout = Some(t);
        }
        if let Some(t) = self.write {
            peer.options.write_timeout = Some(t);
        }
        if let Some(t) = self.idle {
            peer.options.idle_timeout = Some(t);
        }
    }
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
    }
}

impl Default for UpstreamOptions {
    fn default() -> Self {
        Self {
            selection: SelectionKind::RoundRobin,
            selector: null_selector,
            health_checks: HealthCheckKind::None,
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

//
// Health Checks
//

/// How River decides whether an upstream server is fit to receive traffic
#[derive(Debug, PartialEq, Clone)]
pub enum HealthCheckKind {
    /// Every discovered server is assumed healthy
    None,

    /// Open a connection and close it again
    Tcp {
        settings: HealthCheckSettings,

        /// When set, complete a TLS handshake with this name as well
        sni: Option<String>,
    },

    /// Make a request and check the response status
    Http {
        settings: HealthCheckSettings,

        /// Value of the `Host` header, and the SNI when `tls` is set
        host: String,

        /// Request path, e.g. `/healthz`
        path: String,

        tls: bool,

        /// The status that counts as healthy
        expect_status: u16,

        /// Check a different port than the one traffic is sent to
        port: Option<u16>,

        /// Reuse the connection between checks
        ///
        /// Faster, but an established connection can hide a firewall or L4
        /// load balancer problem, so this defaults to off.
        reuse_connection: bool,
    },
}

impl HealthCheckKind {
    pub fn settings(&self) -> Option<&HealthCheckSettings> {
        match self {
            HealthCheckKind::None => None,
            HealthCheckKind::Tcp { settings, .. } | HealthCheckKind::Http { settings, .. } => {
                Some(settings)
            }
        }
    }
}

/// The parts of health checking that do not depend on the kind of check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthCheckSettings {
    /// How often every server is checked
    pub(crate) frequency: Duration,

    /// How long one check may take before it counts as a failure
    pub(crate) timeout: Duration,

    /// Checks that must pass in a row before an unhealthy server is used again
    pub(crate) consecutive_success: usize,

    /// Checks that must fail in a row before a healthy server is taken out
    pub(crate) consecutive_failure: usize,

    /// Check every server at once, rather than one after another
    pub(crate) parallel: bool,
}

impl Default for HealthCheckSettings {
    fn default() -> Self {
        Self {
            frequency: Duration::from_secs(5),
            timeout: Duration::from_secs(1),
            consecutive_success: 1,
            consecutive_failure: 1,
            parallel: false,
        }
    }
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
