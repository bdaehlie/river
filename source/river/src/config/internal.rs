//! This is the *actual* internal configuration structure.
//!
//! It is ONLY used for the internal configuration, and should not ever
//! be exposed as the public API for CLI, Env vars, or via Serde.
//!
//! This is used as the buffer between any external stable UI, and internal
//! impl details which may change at any time.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use bytes::Bytes;
use cidr::IpCidr;
use http::{HeaderName, HeaderValue, Method};
use pingora::{
    protocols::ALPN,
    server::configuration::{Opt as PingoraOpt, ServerConf as PingoraServerConf},
    upstreams::peer::HttpPeer,
};
use tracing::warn;

use crate::proxy::{
    glob::Glob,
    rate_limiting::{AllRateConfig, RegexShim},
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

//
// Path Control
//

/// How a filter answers a request it has decided to reject
///
/// Every filter that can reject a request carries one of these, so that the
/// status is an operator's choice rather than a constant compiled into each
/// filter. Requirement 2 of the v0.8.x milestone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// The HTTP status sent downstream
    pub(crate) status: u16,

    /// Sent as the response body, when set
    ///
    /// Left unset, the response has no body at all, which is what Pingora's
    /// own error responses do.
    ///
    /// Held as [`Bytes`] rather than a `String` because rejecting is the hot
    /// path exactly when it matters - under the flood of traffic the filter
    /// exists to turn away - and cloning `Bytes` does not copy the body.
    pub(crate) body: Option<Bytes>,
}

impl Rejection {
    pub fn status(&self) -> u16 {
        self.status
    }
}

/// The modifiers applied at each stage of the request lifecycle
///
/// Each list runs in the order it was written in the configuration file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PathControl {
    pub(crate) request_filters: Vec<RequestFilterConfig>,
    pub(crate) upstream_request_filters: Vec<RequestModifierConfig>,
    pub(crate) upstream_response_filters: Vec<ResponseModifierConfig>,

    /// Applied to the response on its way downstream
    ///
    /// Unlike [`Self::upstream_response_filters`], these run for every
    /// response, including one Pingora served from its cache rather than
    /// fetching from an upstream server.
    pub(crate) response_filters: Vec<ResponseModifierConfig>,

    /// Bounds the size of a request body
    pub(crate) request_body_limit: Option<BodySizeLimit>,

    /// Bounds the size of a response body
    pub(crate) response_body_limit: Option<BodySizeLimit>,
}

/// A bound on how large a body may be
///
/// The body stages count and reject; they do not rewrite. Rewriting a body
/// means buffering it, and buffering an arbitrary body is the denial of service
/// vector these filters exist to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodySizeLimit {
    /// Bytes allowed before the request is rejected
    pub(crate) max_bytes: usize,

    /// The status sent downstream once the limit is passed
    ///
    /// Only a status, not a whole [`Rejection`]: by the time a body filter
    /// runs, writing the response is Pingora's job rather than River's, and
    /// the path it takes carries a status but no body.
    pub(crate) status: u16,
}

/// A filter at the "downstream request arrival" stage
///
/// These may reject a request outright, which is why each carries a
/// [`Rejection`].
#[derive(Debug, Clone, PartialEq)]
pub enum RequestFilterConfig {
    /// Reject a request whose client address falls inside any of these ranges
    BlockCidr {
        blocks: Vec<IpCidr>,
        rejection: Rejection,
    },

    /// Reject a request whose client address falls outside all of these ranges
    ///
    /// The complement of [`Self::BlockCidr`], and the other half of
    /// requirement 3. The two are separate filters rather than one combined
    /// allow/deny list so that there is no implicit precedence to remember:
    /// they run in the order they are written.
    AllowCidr {
        blocks: Vec<IpCidr>,
        rejection: Rejection,
    },
}

/// A change made to a request's headers or a response's headers
///
/// The request and response sides support the same set, so they share a type.
#[derive(Debug, Clone, PartialEq)]
pub enum HeaderModifier {
    /// Remove every header whose name matches the regular expression
    RemoveHeaderKeyRegex { pattern: RegexShim },

    /// Remove every header whose name matches the glob
    RemoveHeaderKeyGlob { pattern: Glob },

    /// Remove this one header
    RemoveHeader { key: HeaderName },

    /// Add the header, replacing any existing value
    UpsertHeader { key: HeaderName, value: HeaderValue },

    /// Add the header, keeping any existing value alongside it
    ///
    /// Distinct from [`Self::UpsertHeader`] because some headers are defined
    /// as lists, and replacing rather than appending silently discards what an
    /// upstream server or an earlier filter had to say.
    AppendHeader { key: HeaderName, value: HeaderValue },
}

pub type RequestModifierConfig = HeaderModifier;
pub type ResponseModifierConfig = HeaderModifier;

/// How River works out which address a request came from
///
/// Absent when River is deployed at the edge, where the peer address is the
/// client's and there is nothing to work out.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientIpConfig {
    /// Peers whose forwarding header River is willing to believe
    pub(crate) trusted_proxies: Vec<IpCidr>,

    /// The header the client address is read from
    pub(crate) header: HeaderName,
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

    /// Which requests go to which set of upstream servers
    ///
    /// A service written with a plain `connectors` block and no `routes` block
    /// gets exactly one route here, matching everything, which is what every
    /// configuration file written before routing existed means.
    pub(crate) routes: Vec<RouteConfig>,

    /// The answer when no route matches the request
    pub(crate) no_route: Rejection,

    /// How the client address is worked out, when River is behind a proxy
    pub(crate) client_ip: Option<ClientIpConfig>,

    pub(crate) path_control: PathControl,
    pub(crate) rate_limiting: RateLimitingConfig,
}

/// One route: the requests it claims, and the servers it sends them to
///
/// Each route owns its upstreams, its selection algorithm, and its health
/// checking, so two routes in one service may be balanced and checked in
/// entirely different ways.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteConfig {
    pub(crate) matcher: RouteMatch,

    /// Only requests using one of these methods match this route
    ///
    /// Empty means any method, which is the default.
    pub(crate) methods: Vec<Method>,

    pub(crate) upstream_options: UpstreamOptions,
    pub(crate) upstreams: Vec<UpstreamConfig>,
}

/// How a route decides whether it claims a request
#[derive(Debug, Clone, PartialEq)]
pub enum RouteMatch {
    /// Claims every request
    ///
    /// This is what a service with no `routes` block gets.
    Any,

    /// The URI path is exactly this
    Exact { path: String },

    /// The URI path is this, or continues after it at a segment boundary
    ///
    /// `/api` claims `/api` and `/api/users`, but not `/apiary` - a prefix
    /// that stops in the middle of a path segment is nearly always a
    /// coincidence rather than an intent.
    Prefix { path: String },

    /// The URI path matches this expression
    Regex { pattern: RegexShim },
}

impl RouteMatch {
    /// Does this route claim the given path?
    pub fn matches(&self, path: &str) -> bool {
        match self {
            RouteMatch::Any => true,
            RouteMatch::Exact { path: want } => path == want,
            RouteMatch::Prefix { path: want } => {
                if !path.starts_with(want.as_str()) {
                    return false;
                }
                // Equal, or the prefix already ends at a boundary, or the
                // next character starts a new segment.
                path.len() == want.len()
                    || want.ends_with('/')
                    || path.as_bytes().get(want.len()) == Some(&b'/')
            }
            RouteMatch::Regex { pattern } => pattern.is_match(path),
        }
    }

    /// Sort key deciding which route wins when several could match
    ///
    /// Exact before prefix, longer prefix before shorter, then regular
    /// expressions in the order they were written, and finally the catch-all.
    /// This is a total order computed once at startup, so which route claims a
    /// request never depends on how the file happened to be laid out - except
    /// among regular expressions, where the file order is the only sensible
    /// answer.
    pub fn precedence(&self) -> (u8, usize) {
        match self {
            RouteMatch::Exact { .. } => (0, 0),
            RouteMatch::Prefix { path } => (1, usize::MAX - path.len()),
            RouteMatch::Regex { .. } => (2, 0),
            RouteMatch::Any => (3, 0),
        }
    }
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
