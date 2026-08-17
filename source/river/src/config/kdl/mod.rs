use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};

use crate::{
    config::internal::{
        AcmeConfig, AcmeDirectory, AcmeDomainConfig, BodySizeLimit, CertKeyPaths, ChallengeKind,
        Config, FileServerConfig, HealthCheckKind, HealthCheckSettings, ListenerConfig,
        ListenerKind, PathControl, PeerTemplate, PeerTimeouts, ProxyConfig, RefreshKind,
        RefreshPolicy, Rejection, RenewalPolicy, RequestFilterConfig, RequestModifierConfig,
        ResponseModifierConfig, SelectionKind, TlsConfig, TlsName, UpstreamConfig, UpstreamKind,
        UpstreamOptions,
    },
    proxy::{
        rate_limiting::{
            multi::{MultiRaterConfig, MultiRequestKeyKind},
            single::{SingleInstanceConfig, SingleRequestKeyKind},
            AllRateConfig, RegexShim,
        },
        request_selector::{
            null_selector, source_addr_and_uri_path_selector, uri_path_selector, RequestSelector,
        },
    },
    tls::store::ServedName,
};
use bytes::Bytes;
use cidr::IpCidr;
use http::{HeaderName, HeaderValue};
use kdl::{KdlDocument, KdlEntry, KdlNode, KdlValue};
use miette::{Diagnostic, SourceSpan};
use pingora::protocols::ALPN;

use super::internal::RateLimitingConfig;

#[cfg(test)]
mod test;
mod utils;

/// This is the primary interface for parsing the document.
impl TryFrom<KdlDocument> for Config {
    type Error = miette::Error;

    fn try_from(value: KdlDocument) -> Result<Self, Self::Error> {
        let SystemData {
            threads_per_service,
            daemonize,
            upgrade_socket,
            pid_file,
        } = extract_system_data(&value)?;
        let (basic_proxies, file_servers) = extract_services(threads_per_service, &value)?;
        let acme = extract_acme(&value)?;

        let config = Config {
            threads_per_service,
            daemonize,
            upgrade_socket,
            pid_file,
            basic_proxies,
            file_servers,
            acme,
            ..Config::default()
        };

        // Checks that need both the `acme` section and the listeners that
        // refer to it. These are reported against the `acme` section, or the
        // document as a whole when there isn't one.
        let acme_span = value
            .get("acme")
            .map(|n| *n.span())
            .unwrap_or(*value.span());
        validate_acme(&config, &value, &acme_span)?;

        Ok(config)
    }
}

/// Cross-check the `acme` section against the domains listeners ask it to manage
fn validate_acme(config: &Config, doc: &KdlDocument, acme_span: &SourceSpan) -> miette::Result<()> {
    let domains = config.acme_domains();

    let Some(acme) = config.acme.as_ref() else {
        if let Some(domain) = domains.first() {
            return Err(Bad::docspan(
                format!(
                    "A listener manages '{domain}' over ACME, but there is no top level \
                     'acme' section to say which CA to use"
                ),
                doc,
                acme_span,
            )
            .into());
        }
        return Ok(());
    };

    if !acme.accept_terms_of_service {
        return Err(Bad::docspan(
            "'accept-terms-of-service' must be set to 'true' - certificate authorities \
             require agreement to their terms of service before issuing certificates",
            doc,
            acme_span,
        )
        .into());
    }

    if !acme.store_dir.is_absolute() {
        return Err(Bad::docspan(
            format!(
                "'store-dir' must be an absolute path, got '{}'. River may change its working \
                 directory when it daemonizes, so a relative path is not stable.",
                acme.store_dir.display()
            ),
            doc,
            acme_span,
        )
        .into());
    }

    for domain in &domains {
        // Already parsed once when the listener was read, so this cannot fail.
        let name =
            ServedName::parse(domain).map_err(|e| Bad::docspan(e.to_string(), doc, acme_span))?;
        let (challenge, hook) = acme.challenge_for(domain);

        // This is the mistake every operator makes once: wildcards can only be
        // validated by DNS-01, no matter which CA is in use.
        if name.is_wildcard() && challenge != ChallengeKind::Dns01 {
            return Err(Bad::docspan(
                format!(
                    "'{domain}' is a wildcard, which can only be issued against a 'dns-01' \
                     challenge, but it is configured to use '{}'. Add a \
                     'domain \"{domain}\" challenge=\"dns-01\" hook=\"...\"' entry to the \
                     'acme' section.",
                    challenge.as_str()
                ),
                doc,
                acme_span,
            )
            .into());
        }

        if challenge == ChallengeKind::Dns01 && hook.is_none() {
            return Err(Bad::docspan(
                format!(
                    "'{domain}' uses the 'dns-01' challenge, which needs a 'hook' to publish \
                     the TXT record. River does not talk to DNS providers itself."
                ),
                doc,
                acme_span,
            )
            .into());
        }
    }

    Ok(())
}

/// Extract the optional top level `acme` section
fn extract_acme(doc: &KdlDocument) -> miette::Result<Option<AcmeConfig>> {
    let Some(node) = doc.get("acme") else {
        return Ok(None);
    };
    let acme_doc = node
        .children()
        .or_bail("'acme' should be a nested block", doc, node.span())?;

    let mut directory: Option<AcmeDirectory> = None;
    let mut contacts = vec![];
    let mut accept_terms_of_service = false;
    let mut store_dir: Option<PathBuf> = None;
    let mut before_expiry: Option<u32> = None;
    let mut after_issue: Option<u32> = None;
    let mut default_challenge: Option<ChallengeKind> = None;
    let mut challenge_listener: Option<String> = None;
    let mut dns_propagation_seconds: Option<u32> = None;
    let mut domains: Vec<AcmeDomainConfig> = vec![];

    for (node, name, args) in utils::data_nodes(doc, acme_doc)? {
        match name {
            "provider" => {
                let val =
                    utils::extract_one_str_arg(doc, node, name, args, |s| Some(s.to_string()))?;
                directory = Some(match val.as_str() {
                    "letsencrypt" => AcmeDirectory::LetsEncrypt,
                    "letsencrypt-staging" => AcmeDirectory::LetsEncryptStaging,
                    url if url.starts_with("https://") => AcmeDirectory::Custom(url.to_string()),
                    other => {
                        return Err(Bad::docspan(
                            format!(
                                "'{other}' is not a known ACME provider. Use 'letsencrypt', \
                                 'letsencrypt-staging', or an https:// directory URL."
                            ),
                            doc,
                            node.span(),
                        )
                        .into());
                    }
                });
            }
            "contact" => {
                contacts.push(utils::extract_one_str_arg(doc, node, name, args, |s| {
                    Some(s.to_string())
                })?);
            }
            "accept-terms-of-service" => {
                accept_terms_of_service = utils::extract_one_bool_arg(doc, node, name, args)?;
            }
            "store-dir" => {
                store_dir = Some(utils::extract_one_str_arg(doc, node, name, args, |s| {
                    Some(PathBuf::from(s))
                })?);
            }
            "renew-before-expiry-days" => {
                before_expiry = Some(extract_one_u32_arg(doc, node, name, args)?);
            }
            "renew-after-issue-days" => {
                after_issue = Some(extract_one_u32_arg(doc, node, name, args)?);
            }
            "challenge" => {
                default_challenge = Some(extract_challenge_kind(doc, node, name, args)?);
            }
            "challenge-listener" => {
                let val =
                    utils::extract_one_str_arg(doc, node, name, args, |s| Some(s.to_string()))?;
                if val.parse::<SocketAddr>().is_err() {
                    return Err(Bad::docspan(
                        format!("'{val}' is not a valid socket address"),
                        doc,
                        node.span(),
                    )
                    .into());
                }
                challenge_listener = Some(val);
            }
            "dns-propagation-seconds" => {
                dns_propagation_seconds = Some(extract_one_u32_arg(doc, node, name, args)?);
            }
            "domain" => {
                domains.push(extract_acme_domain(doc, node, args)?);
            }
            other => {
                return Err(Bad::docspan(
                    format!("Unknown setting in 'acme': '{other}'"),
                    doc,
                    node.span(),
                )
                .into());
            }
        }
    }

    let renewal = match (before_expiry, after_issue) {
        (Some(_), Some(_)) => {
            return Err(Bad::docspan(
                "Set only one of 'renew-before-expiry-days' and 'renew-after-issue-days'",
                doc,
                node.span(),
            )
            .into());
        }
        (Some(days), None) => RenewalPolicy::BeforeExpiry { days },
        (None, Some(days)) => RenewalPolicy::AfterIssue { days },
        (None, None) => RenewalPolicy::default(),
    };

    let store_dir = store_dir.or_bail(
        "'store-dir' is required: River needs somewhere to keep the ACME account key \
         and the certificates it obtains",
        doc,
        node.span(),
    )?;

    Ok(Some(AcmeConfig {
        directory: directory.unwrap_or(AcmeDirectory::LetsEncrypt),
        contacts,
        accept_terms_of_service,
        store_dir,
        renewal,
        default_challenge: default_challenge.unwrap_or(ChallengeKind::Http01),
        challenge_listener,
        // A minute is enough for most providers, and waiting is far cheaper
        // than a failed validation.
        dns_propagation_seconds: dns_propagation_seconds.unwrap_or(60),
        domains,
    }))
}

/// `domain "*.example.com" challenge="dns-01" hook="/usr/local/bin/hook"`
fn extract_acme_domain(
    doc: &KdlDocument,
    node: &KdlNode,
    args: &[KdlEntry],
) -> miette::Result<AcmeDomainConfig> {
    let (domain, kvs) = utils::extract_one_str_arg_with_kv_args(doc, node, "domain", args, |s| {
        Some(s.to_string())
    })?;

    // Fail here rather than when the order is placed against the CA.
    if let Err(e) = ServedName::parse(&domain) {
        return Err(Bad::docspan(e.to_string(), doc, node.span()).into());
    }

    let challenge = match kvs.get("challenge").map(String::as_str) {
        Some("http-01") => ChallengeKind::Http01,
        Some("dns-01") => ChallengeKind::Dns01,
        Some(other) => {
            return Err(Bad::docspan(
                format!("'{other}' is not a known challenge type, use 'http-01' or 'dns-01'"),
                doc,
                node.span(),
            )
            .into());
        }
        None => {
            return Err(Bad::docspan(
                "a 'domain' entry must set 'challenge', otherwise it says nothing that the \
                 section defaults do not",
                doc,
                node.span(),
            )
            .into());
        }
    };

    let dns_hook = kvs.get("hook").map(PathBuf::from);

    if challenge == ChallengeKind::Http01 && dns_hook.is_some() {
        return Err(Bad::docspan(
            "'hook' only applies to the 'dns-01' challenge",
            doc,
            node.span(),
        )
        .into());
    }

    Ok(AcmeDomainConfig {
        domain,
        challenge,
        dns_hook,
    })
}

fn extract_challenge_kind(
    doc: &KdlDocument,
    node: &KdlNode,
    name: &str,
    args: &[KdlEntry],
) -> miette::Result<ChallengeKind> {
    let val = utils::extract_one_str_arg(doc, node, name, args, |s| Some(s.to_string()))?;
    match val.as_str() {
        "http-01" => Ok(ChallengeKind::Http01),
        "dns-01" => Ok(ChallengeKind::Dns01),
        other => Err(Bad::docspan(
            format!("'{other}' is not a known challenge type, use 'http-01' or 'dns-01'"),
            doc,
            node.span(),
        )
        .into()),
    }
}

fn extract_one_u32_arg(
    doc: &KdlDocument,
    node: &KdlNode,
    name: &str,
    args: &[KdlEntry],
) -> miette::Result<u32> {
    let val = match args {
        [one] => one.value().as_i64(),
        _ => None,
    }
    .or_bail(
        format!("'{name}' should have exactly one integer argument"),
        doc,
        node.span(),
    )?;

    u32::try_from(val).ok().or_bail(
        format!("'{name}' should be a positive number of days, got '{val}'"),
        doc,
        node.span(),
    )
}

struct SystemData {
    threads_per_service: usize,
    daemonize: bool,
    upgrade_socket: Option<PathBuf>,
    pid_file: Option<PathBuf>,
}

impl Default for SystemData {
    fn default() -> Self {
        Self {
            threads_per_service: 8,
            daemonize: false,
            upgrade_socket: None,
            pid_file: None,
        }
    }
}

/// Extract all services from the top level document
fn extract_services(
    threads_per_service: usize,
    doc: &KdlDocument,
) -> miette::Result<(Vec<ProxyConfig>, Vec<FileServerConfig>)> {
    let service_node = utils::required_child_doc(doc, doc, "services")?;
    let services = utils::wildcard_argless_child_docs(doc, service_node)?;

    let proxy_node_set =
        HashSet::from(["listeners", "connectors", "path-control", "rate-limiting"]);
    let file_server_node_set = HashSet::from(["listeners", "file-server"]);

    let mut proxies = vec![];
    let mut file_servers = vec![];

    for (name, service) in services {
        // First, visit all of the children nodes, and make sure each child
        // node only appears once. This is used to detect duplicate sections
        let mut fingerprint_set: HashSet<&str> = HashSet::new();
        for ch in service.nodes() {
            let name = ch.name().value();
            let dupe = !fingerprint_set.insert(name);
            if dupe {
                return Err(
                    Bad::docspan(format!("Duplicate section: '{name}'!"), doc, ch.span()).into(),
                );
            }
        }

        // Now: what do we do with this node?
        if fingerprint_set.is_subset(&proxy_node_set) {
            // If the contained nodes are a strict subset of proxy node config fields,
            // then treat this section as a proxy node
            proxies.push(extract_service(threads_per_service, doc, name, service)?);
        } else if fingerprint_set.is_subset(&file_server_node_set) {
            // If the contained nodes are a strict subset of the file server config
            // fields, then treat this section as a file server node
            file_servers.push(extract_file_server(doc, name, service)?);
        } else {
            // Otherwise, we're not sure what this node is supposed to be!
            //
            // Obtain the superset of ALL potential nodes, which is essentially
            // our configuration grammar.
            let superset: HashSet<&str> = proxy_node_set
                .union(&file_server_node_set)
                .cloned()
                .collect();

            // Then figure out what fields our fingerprint set contains that
            // is "novel", or basically fields we don't know about
            let what = fingerprint_set
                .difference(&superset)
                .copied()
                .collect::<Vec<&str>>()
                .join(", ");

            // Then inform the user about the reason for our discontent
            return Err(Bad::docspan(
                format!("Unknown configuration section(s): {what}"),
                doc,
                service.span(),
            )
            .into());
        }
    }

    if proxies.is_empty() && file_servers.is_empty() {
        return Err(Bad::docspan("No services defined", doc, service_node.span()).into());
    }

    Ok((proxies, file_servers))
}

/// The `filter kind="..."` nodes of one path control stage
///
/// Reading `kind` here leaves the rest of the arguments for the per-kind
/// parser, which then calls [`Args::finish`]. That is what turns a misspelled
/// key into an error pointing at the line that has it, rather than a setting
/// that silently does nothing.
///
/// ```kdl
/// upstream-request {
///     filter kind="remove-header-key-regex" pattern=".*SECRET.*"
///     filter kind="upsert-header" key="x-proxy-friend" value="river"
/// }
/// ```
fn filter_kinds<'a>(
    doc: &'a KdlDocument,
    stage: &'a KdlDocument,
) -> miette::Result<Vec<(&'a KdlNode, &'a str, Args<'a>)>> {
    let mut out = vec![];

    for (node, name, entries) in utils::data_nodes(doc, stage)? {
        if name != "filter" {
            return Err(Bad::docspan(
                format!(
                    "'{name}' is not a path control entry - every line in this block is a \
                     'filter', and what it does is chosen by its 'kind'"
                ),
                doc,
                node.span(),
            )
            .into());
        }

        let mut args = Args::named(doc, node, entries)?;
        let kind = args.take_str("kind")?.or_bail(
            "a 'filter' must say which 'kind' it is",
            doc,
            node.span(),
        )?;

        out.push((node, kind, args));
    }

    Ok(out)
}

/// The `status` and `body` arguments that every rejecting filter accepts
///
/// `default_status` is what the filter answers when the operator does not say.
fn extract_rejection(
    doc: &KdlDocument,
    node: &KdlNode,
    args: &mut Args<'_>,
    default_status: u16,
) -> miette::Result<Rejection> {
    let status = args.take_u16("status")?.unwrap_or(default_status);

    if !(100..=599).contains(&status) {
        return Err(Bad::docspan(
            format!("'{status}' is not an HTTP status code"),
            doc,
            node.span(),
        )
        .into());
    }

    Ok(Rejection {
        status,
        body: args
            .take_str("body")?
            .map(|s| Bytes::copy_from_slice(s.as_bytes())),
    })
}

/// `addrs="192.168.0.0/16, 10.0.0.0/8, 127.0.0.1"`
fn extract_cidr_list(
    doc: &KdlDocument,
    node: &KdlNode,
    args: &mut Args<'_>,
) -> miette::Result<Vec<IpCidr>> {
    let list = args.take_str("addrs")?.or_bail(
        "'block-cidr-range' needs 'addrs', a comma separated list of addresses or ranges",
        doc,
        node.span(),
    )?;

    let mut blocks = vec![];

    for entry in list.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(Bad::docspan(
                format!("'{list}' has an empty entry - check for a stray comma"),
                doc,
                node.span(),
            )
            .into());
        }

        // Parsed here so that a typo is reported against the line that has it,
        // rather than panicking when the service is built.
        match entry.parse::<IpCidr>() {
            Ok(cidr) => blocks.push(cidr),
            Err(e) => {
                return Err(Bad::docspan(
                    format!("'{entry}' is not an address or CIDR range: {e}"),
                    doc,
                    node.span(),
                )
                .into());
            }
        }
    }

    if blocks.is_empty() {
        return Err(Bad::docspan("'addrs' lists no addresses", doc, node.span()).into());
    }

    Ok(blocks)
}

/// `pattern="..."`, compiled here rather than when the service is built
fn extract_pattern(
    doc: &KdlDocument,
    node: &KdlNode,
    args: &mut Args<'_>,
) -> miette::Result<RegexShim> {
    let pattern = args.take_str("pattern")?.or_bail(
        "'remove-header-key-regex' needs a 'pattern'",
        doc,
        node.span(),
    )?;

    RegexShim::new(pattern).ok().or_bail(
        format!("'{pattern}' is not a valid regular expression"),
        doc,
        node.span(),
    )
}

/// `key="..." value="..."`, validated as an HTTP header here
fn extract_header_pair(
    doc: &KdlDocument,
    node: &KdlNode,
    args: &mut Args<'_>,
) -> miette::Result<(HeaderName, HeaderValue)> {
    let key = args
        .take_str("key")?
        .or_bail("'upsert-header' needs a 'key'", doc, node.span())?;
    let value =
        args.take_str("value")?
            .or_bail("'upsert-header' needs a 'value'", doc, node.span())?;

    let name = HeaderName::try_from(key).ok().or_bail(
        format!("'{key}' is not a valid HTTP header name"),
        doc,
        node.span(),
    )?;
    let value = HeaderValue::try_from(value).ok().or_bail(
        format!("'{value}' is not a valid HTTP header value"),
        doc,
        node.span(),
    )?;

    Ok((name, value))
}

/// The `request-filters` stage
fn extract_request_filters(
    doc: &KdlDocument,
    stage: &KdlDocument,
) -> miette::Result<Vec<RequestFilterConfig>> {
    let mut out = vec![];

    for (node, kind, mut args) in filter_kinds(doc, stage)? {
        let filter = match kind {
            "block-cidr-range" => RequestFilterConfig::BlockCidr {
                blocks: extract_cidr_list(doc, node, &mut args)?,
                // A blocked source address is forbidden, not unauthenticated -
                // there is no credential the client could present that would
                // change the answer.
                rejection: extract_rejection(doc, node, &mut args, 403)?,
            },
            other => {
                return Err(Bad::docspan(
                    format!(
                        "'{other}' is not a request filter. The only kind here is \
                         'block-cidr-range'."
                    ),
                    doc,
                    node.span(),
                )
                .into());
            }
        };

        args.finish()?;
        out.push(filter);
    }

    Ok(out)
}

/// The `upstream-request` stage
fn extract_request_modifiers(
    doc: &KdlDocument,
    stage: &KdlDocument,
) -> miette::Result<Vec<RequestModifierConfig>> {
    let mut out = vec![];

    for (node, kind, mut args) in filter_kinds(doc, stage)? {
        let modifier = match kind {
            "remove-header-key-regex" => RequestModifierConfig::RemoveHeaderKeyRegex {
                pattern: extract_pattern(doc, node, &mut args)?,
            },
            "upsert-header" => {
                let (key, value) = extract_header_pair(doc, node, &mut args)?;
                RequestModifierConfig::UpsertHeader { key, value }
            }
            other => {
                return Err(Bad::docspan(
                    format!(
                        "'{other}' is not an upstream request filter. The kinds here are \
                         'remove-header-key-regex' and 'upsert-header'."
                    ),
                    doc,
                    node.span(),
                )
                .into());
            }
        };

        args.finish()?;
        out.push(modifier);
    }

    Ok(out)
}

/// The `upstream-response` stage
fn extract_response_modifiers(
    doc: &KdlDocument,
    stage: &KdlDocument,
) -> miette::Result<Vec<ResponseModifierConfig>> {
    let mut out = vec![];

    for (node, kind, mut args) in filter_kinds(doc, stage)? {
        let modifier = match kind {
            "remove-header-key-regex" => ResponseModifierConfig::RemoveHeaderKeyRegex {
                pattern: extract_pattern(doc, node, &mut args)?,
            },
            "upsert-header" => {
                let (key, value) = extract_header_pair(doc, node, &mut args)?;
                ResponseModifierConfig::UpsertHeader { key, value }
            }
            other => {
                return Err(Bad::docspan(
                    format!(
                        "'{other}' is not an upstream response filter. The kinds here are \
                         'remove-header-key-regex' and 'upsert-header'."
                    ),
                    doc,
                    node.span(),
                )
                .into());
            }
        };

        args.finish()?;
        out.push(modifier);
    }

    Ok(out)
}

/// A body stage, which currently holds at most one `max-size` filter
///
/// `default_status` differs between the request and response sides, because
/// "your request was too large" and "the server sent too much" are different
/// answers.
fn extract_body_limit(
    doc: &KdlDocument,
    stage: &KdlDocument,
    default_status: u16,
) -> miette::Result<Option<BodySizeLimit>> {
    let mut limit: Option<BodySizeLimit> = None;

    for (node, kind, mut args) in filter_kinds(doc, stage)? {
        match kind {
            "max-size" => {
                if limit.is_some() {
                    return Err(Bad::docspan(
                        "only one 'max-size' filter is allowed per body stage - two limits \
                         would just mean the smaller one",
                        doc,
                        node.span(),
                    )
                    .into());
                }

                let max_bytes = args.take_usize("max-bytes")?.or_bail(
                    "'max-size' needs 'max-bytes'",
                    doc,
                    node.span(),
                )?;

                // A limit of zero would reject every request that has a body
                // at all, which is a thing an operator might mean, but far
                // more often means they left the value unfilled.
                if max_bytes == 0 {
                    return Err(Bad::docspan(
                        "'max-bytes' must be at least 1. To refuse bodies entirely, block the \
                         methods that carry them instead.",
                        doc,
                        node.span(),
                    )
                    .into());
                }

                let status = args.take_u16("status")?.unwrap_or(default_status);
                if !(100..=599).contains(&status) {
                    return Err(Bad::docspan(
                        format!("'{status}' is not an HTTP status code"),
                        doc,
                        node.span(),
                    )
                    .into());
                }

                limit = Some(BodySizeLimit { max_bytes, status });
            }
            other => {
                return Err(Bad::docspan(
                    format!("'{other}' is not a body filter. The only kind here is 'max-size'."),
                    doc,
                    node.span(),
                )
                .into());
            }
        }

        args.finish()?;
    }

    Ok(limit)
}

/// The whole `path-control` block
fn extract_path_control(doc: &KdlDocument, stages: &KdlDocument) -> miette::Result<PathControl> {
    let mut pc = PathControl::default();
    let mut seen: HashSet<&str> = HashSet::new();

    for (node, name, _args) in utils::data_nodes(doc, stages)? {
        if !seen.insert(name) {
            return Err(Bad::docspan(
                format!("Duplicate path control stage: '{name}'"),
                doc,
                node.span(),
            )
            .into());
        }

        let stage = node.children().or_bail(
            format!("'{name}' should be a nested block"),
            doc,
            node.span(),
        )?;

        match name {
            "request-filters" => pc.request_filters = extract_request_filters(doc, stage)?,
            "upstream-request" => {
                pc.upstream_request_filters = extract_request_modifiers(doc, stage)?
            }
            "upstream-response" => {
                pc.upstream_response_filters = extract_response_modifiers(doc, stage)?
            }
            "response-filters" => pc.response_filters = extract_response_modifiers(doc, stage)?,
            // 413 Payload Too Large is the answer to a request body that is
            // more than the server is willing to take.
            "request-body" => pc.request_body_limit = extract_body_limit(doc, stage, 413)?,
            // 502 rather than 413: an oversize response is the upstream
            // server misbehaving, not the client.
            "response-body" => pc.response_body_limit = extract_body_limit(doc, stage, 502)?,
            other => {
                return Err(Bad::docspan(
                    format!(
                        "'{other}' is not a path control stage. The stages are \
                         'request-filters', 'request-body', 'upstream-request', \
                         'upstream-response', 'response-filters', and 'response-body'."
                    ),
                    doc,
                    node.span(),
                )
                .into());
            }
        }
    }

    Ok(pc)
}

/// Extracts a single file server from the `services` block
fn extract_file_server(
    doc: &KdlDocument,
    name: &str,
    node: &KdlDocument,
) -> miette::Result<FileServerConfig> {
    // Listeners
    //
    let listener_node = utils::required_child_doc(doc, node, "listeners")?;
    let listeners = utils::data_nodes(doc, listener_node)?;
    if listeners.is_empty() {
        return Err(Bad::docspan("nonzero listeners required", doc, listener_node.span()).into());
    }
    let mut list_cfgs = vec![];
    for (node, name, args) in listeners {
        let listener = extract_listener(doc, node, name, args)?;
        list_cfgs.push(listener);
    }

    // Base Path
    //
    let fs_node = utils::required_child_doc(doc, node, "file-server")?;
    let data_nodes = utils::data_nodes(doc, fs_node)?;
    let mut map = HashMap::new();
    for (node, name, args) in data_nodes {
        map.insert(name, (node, args));
    }

    let base_path = if let Some((bpnode, bpargs)) = map.get("base-path") {
        let val =
            utils::extract_one_str_arg(doc, bpnode, "base-path", bpargs, |a| Some(a.to_string()))?;
        Some(val.into())
    } else {
        None
    };

    Ok(FileServerConfig {
        name: name.to_string(),
        listeners: list_cfgs,
        base_path,
    })
}

/// Extracts a single service from the `services` block
fn extract_service(
    threads_per_service: usize,
    doc: &KdlDocument,
    name: &str,
    node: &KdlDocument,
) -> miette::Result<ProxyConfig> {
    // Listeners
    //
    let listener_node = utils::required_child_doc(doc, node, "listeners")?;
    let listeners = utils::data_nodes(doc, listener_node)?;
    if listeners.is_empty() {
        return Err(Bad::docspan("nonzero listeners required", doc, listener_node.span()).into());
    }
    let mut list_cfgs = vec![];
    for (node, name, args) in listeners {
        let listener = extract_listener(doc, node, name, args)?;
        list_cfgs.push(listener);
    }

    // Connectors
    //
    let conn_node = utils::required_child_doc(doc, node, "connectors")?;
    let conns = utils::data_nodes(doc, conn_node)?;

    // The `load-balance` block holds settings that the source entries read,
    // such as the refresh bounds, so it is parsed first no matter where in the
    // block it was written.
    let mut load_balance: Option<UpstreamOptions> = None;
    let mut refresh_defaults = RefreshPolicy::default();
    for (node, name, _args) in &conns {
        if *name != "load-balance" {
            continue;
        }
        if load_balance.is_some() {
            return Err(Bad::docspan(
                "Only one 'load-balance' section is allowed",
                doc,
                node.span(),
            )
            .into());
        }
        let (options, defaults) = extract_load_balance(doc, node)?;
        load_balance = Some(options);
        refresh_defaults = defaults;
    }

    let mut conn_cfgs = vec![];
    for (node, name, args) in &conns {
        let upstream = match *name {
            "load-balance" => continue,
            "dns" => extract_dns_source(doc, node, args, refresh_defaults)?,
            "srv" => extract_srv_source(doc, node, args, refresh_defaults)?,
            address => extract_connector(doc, node, address, args)?,
        };
        conn_cfgs.push(upstream);
    }
    if conn_cfgs.is_empty() {
        return Err(
            Bad::docspan("We require at least one connector", doc, conn_node.span()).into(),
        );
    }

    // Path Control (optional)
    //
    let pc = match utils::optional_child_doc(doc, node, "path-control") {
        Some(pc_node) => extract_path_control(doc, pc_node)?,
        None => PathControl::default(),
    };

    // Rate limiting
    let mut rl = RateLimitingConfig::default();
    if let Some(rl_node) = utils::optional_child_doc(doc, node, "rate-limiting") {
        let nodes = utils::data_nodes(doc, rl_node)?;
        for (node, name, args) in nodes.iter() {
            if *name == "rule" {
                let vals = utils::str_value_args(doc, args)?;
                let valslice = vals
                    .iter()
                    .map(|(k, v)| (*k, v.value()))
                    .collect::<BTreeMap<&str, &KdlValue>>();
                rl.rules
                    .push(make_rate_limiter(threads_per_service, doc, node, valslice)?);
            } else {
                return Err(
                    Bad::docspan(format!("Unknown name: '{name}'"), doc, node.span()).into(),
                );
            }
        }
    }

    Ok(ProxyConfig {
        name: name.to_string(),
        listeners: list_cfgs,
        upstreams: conn_cfgs,
        path_control: pc,
        upstream_options: load_balance.unwrap_or_default(),
        rate_limiting: rl,
    })
}

fn make_rate_limiter(
    threads_per_service: usize,
    doc: &KdlDocument,
    node: &KdlNode,
    args: BTreeMap<&str, &KdlValue>,
) -> miette::Result<AllRateConfig> {
    let take_num = |key: &str| -> miette::Result<usize> {
        let Some(val) = args.get(key) else {
            return Err(Bad::docspan(format!("Missing key: '{key}'"), doc, node.span()).into());
        };
        let Some(val) = val.as_i64().and_then(|v| usize::try_from(v).ok()) else {
            return Err(Bad::docspan(
                format!(
                    "'{key} should have a positive integer value, got '{:?}' instead",
                    val
                ),
                doc,
                node.span(),
            )
            .into());
        };
        Ok(val)
    };
    let take_str = |key: &str| -> miette::Result<&str> {
        let Some(val) = args.get(key) else {
            return Err(Bad::docspan(format!("Missing key: '{key}'"), doc, node.span()).into());
        };
        let Some(val) = val.as_string() else {
            return Err(Bad::docspan(
                format!("'{key} should have a string value, got '{:?}' instead", val),
                doc,
                node.span(),
            )
            .into());
        };
        Ok(val)
    };

    // mandatory/common fields
    let kind = take_str("kind")?;
    let tokens_per_bucket = take_num("tokens-per-bucket")?;
    let refill_qty = take_num("refill-qty")?;
    let refill_rate_ms = take_num("refill-rate-ms")?;

    let multi_cfg = || -> miette::Result<MultiRaterConfig> {
        let max_buckets = take_num("max-buckets")?;
        Ok(MultiRaterConfig {
            threads: threads_per_service,
            max_buckets,
            max_tokens_per_bucket: tokens_per_bucket,
            refill_interval_millis: refill_rate_ms,
            refill_qty,
        })
    };

    let single_cfg = || SingleInstanceConfig {
        max_tokens_per_bucket: tokens_per_bucket,
        refill_interval_millis: refill_rate_ms,
        refill_qty,
    };

    let regex_pattern = || -> miette::Result<RegexShim> {
        let pattern = take_str("pattern")?;
        let Ok(pattern) = RegexShim::new(pattern) else {
            return Err(Bad::docspan(
                format!("'{pattern} should be a valid regular expression"),
                doc,
                node.span(),
            )
            .into());
        };
        Ok(pattern)
    };

    match kind {
        "source-ip" => Ok(AllRateConfig::Multi {
            kind: MultiRequestKeyKind::SourceIp,
            config: multi_cfg()?,
        }),
        "specific-uri" => Ok(AllRateConfig::Multi {
            kind: MultiRequestKeyKind::Uri {
                pattern: regex_pattern()?,
            },
            config: multi_cfg()?,
        }),
        "any-matching-uri" => Ok(AllRateConfig::Single {
            kind: SingleRequestKeyKind::UriGroup {
                pattern: regex_pattern()?,
            },
            config: single_cfg(),
        }),
        other => Err(Bad::docspan(
            format!("'{other} is not a known kind of rate limiting"),
            doc,
            node.span(),
        )
        .into()),
    }
}

/// Extracts the `load-balance` structure from the `connectors` section
///
/// Also returns the refresh bounds that the `dns` and `srv` entries in the
/// same block inherit.
fn extract_load_balance(
    doc: &KdlDocument,
    node: &KdlNode,
) -> miette::Result<(UpstreamOptions, RefreshPolicy)> {
    let items = utils::data_nodes(
        doc,
        node.children()
            .or_bail("'load-balance' should have children", doc, node.span())?,
    )?;

    let mut selection: Option<SelectionKind> = None;
    let mut health: Option<HealthCheckKind> = None;
    let mut selector: RequestSelector = null_selector;
    let mut refresh = RefreshPolicy::default();

    for (node, name, args) in items {
        match name {
            "selection" => {
                let (sel, args) = utils::extract_one_str_arg_with_kv_args(
                    doc,
                    node,
                    name,
                    args,
                    |val| match val {
                        "RoundRobin" => Some(SelectionKind::RoundRobin),
                        "Random" => Some(SelectionKind::Random),
                        "FNV" => Some(SelectionKind::Fnv),
                        "Ketama" => Some(SelectionKind::Ketama),
                        _ => None,
                    },
                )?;
                match sel {
                    SelectionKind::RoundRobin | SelectionKind::Random => {
                        // No key required, selection is random
                    }
                    SelectionKind::Fnv | SelectionKind::Ketama => {
                        let sel_ty = args.get("key").or_bail(
                            format!("selection {sel:?} requires a 'key' argument"),
                            doc,
                            node.span(),
                        )?;

                        selector = match sel_ty.as_str() {
                            "UriPath" => uri_path_selector,
                            "SourceAddrAndUriPath" => source_addr_and_uri_path_selector,
                            other => {
                                return Err(Bad::docspan(
                                    format!("Unknown key: '{other}'"),
                                    doc,
                                    node.span(),
                                )
                                .into())
                            }
                        };
                    }
                }

                selection = Some(sel);
            }
            "health-check" => {
                health = Some(extract_health_check(doc, node, name, args)?);
            }
            "refresh-bounds" => {
                refresh = extract_refresh_bounds(doc, node, args)?;
            }
            "discovery" => {
                // Kept so that configuration files written for v0.5.0 keep
                // loading. What a service discovers is now said by which
                // entries its `connectors` block has.
                let val =
                    utils::extract_one_str_arg(doc, node, name, args, |s| Some(s.to_string()))?;
                if val != "Static" {
                    return Err(Bad::docspan(
                        format!(
                            "'{val}' is not a discovery setting. Discovery is declared by the \
                             'dns' and 'srv' entries of the 'connectors' block instead."
                        ),
                        doc,
                        node.span(),
                    )
                    .into());
                }
                tracing::warn!(
                    "'discovery \"Static\"' is deprecated and has no effect. Sources are now \
                     declared by the entries of the 'connectors' block; this setting will be \
                     removed in a future release."
                );
            }
            other => {
                return Err(
                    Bad::docspan(format!("Unknown setting: '{other}'"), doc, node.span()).into(),
                );
            }
        }
    }

    Ok((
        UpstreamOptions {
            selection: selection.unwrap_or(SelectionKind::RoundRobin),
            selector,
            health_checks: health.unwrap_or(HealthCheckKind::None),
        },
        refresh,
    ))
}

/// `refresh-bounds min-seconds=5 max-seconds=300`
fn extract_refresh_bounds(
    doc: &KdlDocument,
    node: &KdlNode,
    args: &[KdlEntry],
) -> miette::Result<RefreshPolicy> {
    let mut args = Args::named(doc, node, args)?;
    let defaults = RefreshPolicy::default();

    let policy = RefreshPolicy {
        kind: defaults.kind,
        min: args.take_seconds("min-seconds")?.unwrap_or(defaults.min),
        max: args.take_seconds("max-seconds")?.unwrap_or(defaults.max),
    };
    args.finish()?;
    check_bounds(doc, node, &policy)?;

    Ok(policy)
}

fn check_bounds(doc: &KdlDocument, node: &KdlNode, policy: &RefreshPolicy) -> miette::Result<()> {
    if policy.min > policy.max {
        return Err(Bad::docspan(
            format!(
                "the minimum refresh interval ({}s) is longer than the maximum ({}s)",
                policy.min.as_secs(),
                policy.max.as_secs()
            ),
            doc,
            node.span(),
        )
        .into());
    }
    Ok(())
}

/// `health-check "TCP" frequency-ms=5000 timeout-ms=1000`
fn extract_health_check(
    doc: &KdlDocument,
    node: &KdlNode,
    name: &str,
    args: &[KdlEntry],
) -> miette::Result<HealthCheckKind> {
    let (kind, mut args) = Args::first_and_named(doc, node, name, args)?;

    let check = match kind {
        "None" => HealthCheckKind::None,
        "TCP" => HealthCheckKind::Tcp {
            sni: args.take_str("tls-sni")?.map(str::to_string),
            settings: extract_health_settings(doc, node, &mut args)?,
        },
        "HTTP" => {
            let host = args.take_str("host")?.or_bail(
                "an HTTP health check needs 'host', which is sent as the Host header",
                doc,
                node.span(),
            )?;

            let path = args.take_str("path")?.unwrap_or("/");
            if !path.starts_with('/') {
                return Err(Bad::docspan(
                    format!("'path' must start with '/', got '{path}'"),
                    doc,
                    node.span(),
                )
                .into());
            }

            let expect_status = args.take_u16("expect-status")?.unwrap_or(200);
            if !(100..=599).contains(&expect_status) {
                return Err(Bad::docspan(
                    format!("'{expect_status}' is not an HTTP status code"),
                    doc,
                    node.span(),
                )
                .into());
            }

            HealthCheckKind::Http {
                tls: args.take_bool("tls")?.unwrap_or(false),
                port: args.take_u16("port")?,
                reuse_connection: args.take_bool("reuse-connection")?.unwrap_or(false),
                host: host.to_string(),
                path: path.to_string(),
                expect_status,
                settings: extract_health_settings(doc, node, &mut args)?,
            }
        }
        other => {
            return Err(Bad::docspan(
                format!("'{other}' is not a kind of health check, use 'None', 'TCP', or 'HTTP'"),
                doc,
                node.span(),
            )
            .into());
        }
    };

    args.finish()?;
    Ok(check)
}

fn extract_health_settings(
    doc: &KdlDocument,
    node: &KdlNode,
    args: &mut Args<'_>,
) -> miette::Result<HealthCheckSettings> {
    let defaults = HealthCheckSettings::default();

    let settings = HealthCheckSettings {
        frequency: args
            .take_millis("frequency-ms")?
            .unwrap_or(defaults.frequency),
        timeout: args.take_millis("timeout-ms")?.unwrap_or(defaults.timeout),
        consecutive_success: args
            .take_usize("consecutive-success")?
            .unwrap_or(defaults.consecutive_success),
        consecutive_failure: args
            .take_usize("consecutive-failure")?
            .unwrap_or(defaults.consecutive_failure),
        parallel: args.take_bool("parallel")?.unwrap_or(defaults.parallel),
    };

    // A zero frequency would make the background loop spin, and a zero
    // threshold would mean a server never changes state.
    if settings.frequency.is_zero() {
        return Err(Bad::docspan("'frequency-ms' must be at least 1", doc, node.span()).into());
    }
    if settings.timeout.is_zero() {
        return Err(Bad::docspan("'timeout-ms' must be at least 1", doc, node.span()).into());
    }
    if settings.consecutive_success == 0 || settings.consecutive_failure == 0 {
        return Err(Bad::docspan(
            "'consecutive-success' and 'consecutive-failure' must be at least 1",
            doc,
            node.span(),
        )
        .into());
    }

    Ok(settings)
}

/// Extracts a single literal-address connector from the `connectors` section
fn extract_connector(
    doc: &KdlDocument,
    node: &KdlNode,
    name: &str,
    args: &[KdlEntry],
) -> miette::Result<UpstreamConfig> {
    let Ok(addr) = name.parse::<SocketAddr>() else {
        return Err(Bad::docspan(
            format!(
                "'{name}' is not a socket address. A connector is either an 'IP:port', or a \
                 'dns' or 'srv' entry."
            ),
            doc,
            node.span(),
        )
        .into());
    };

    let mut args = Args::named(doc, node, args)?;
    // A literal address was not discovered under any name, so there is nothing
    // for `tls=true` to take an SNI from.
    let peer = extract_peer_template(doc, node, &mut args, false)?;
    args.finish()?;

    Ok(UpstreamConfig {
        kind: UpstreamKind::Static { addr },
        peer,
    })
}

/// `dns "backends.example.com" port=8080`
fn extract_dns_source(
    doc: &KdlDocument,
    node: &KdlNode,
    args: &[KdlEntry],
    defaults: RefreshPolicy,
) -> miette::Result<UpstreamConfig> {
    let (host, mut args) = Args::first_and_named(doc, node, "dns", args)?;

    if host.parse::<SocketAddr>().is_ok() || host.parse::<std::net::IpAddr>().is_ok() {
        return Err(Bad::docspan(
            format!("'{host}' is an address, not a name. Write it as a plain connector entry."),
            doc,
            node.span(),
        )
        .into());
    }

    // Address records carry no port, so one has to be configured.
    let port = args.take_u16("port")?.or_bail(
        "'port' is required: DNS address records do not carry one",
        doc,
        node.span(),
    )?;

    let peer = extract_peer_template(doc, node, &mut args, true)?;
    let refresh = extract_refresh(doc, node, &mut args, defaults)?;
    args.finish()?;

    Ok(UpstreamConfig {
        kind: UpstreamKind::Dns {
            host: host.to_string(),
            port,
            refresh,
        },
        peer,
    })
}

/// `srv "_https._tcp.example.com" tls=true`
fn extract_srv_source(
    doc: &KdlDocument,
    node: &KdlNode,
    args: &[KdlEntry],
    defaults: RefreshPolicy,
) -> miette::Result<UpstreamConfig> {
    let (name, mut args) = Args::first_and_named(doc, node, "srv", args)?;

    // Not a hard requirement of the protocol, but a name without the leading
    // underscore labels is nearly always a `dns` entry written by mistake.
    if !name.starts_with('_') {
        return Err(Bad::docspan(
            format!(
                "'{name}' does not look like an SRV name, which has the form \
                 '_service._proto.domain'. For a plain hostname, use a 'dns' entry."
            ),
            doc,
            node.span(),
        )
        .into());
    }

    let peer = extract_peer_template(doc, node, &mut args, true)?;
    let refresh = extract_refresh(doc, node, &mut args, defaults)?;
    args.finish()?;

    Ok(UpstreamConfig {
        kind: UpstreamKind::Srv {
            name: name.to_string(),
            refresh,
        },
        peer,
    })
}

/// The connection settings shared by every kind of connector entry
///
/// `discovered_name` says whether this entry has a name that `tls=true` could
/// take an SNI from.
fn extract_peer_template(
    doc: &KdlDocument,
    node: &KdlNode,
    args: &mut Args<'_>,
    discovered_name: bool,
) -> miette::Result<PeerTemplate> {
    let tls_sni = args.take_str("tls-sni")?;
    let tls_flag = args.take_bool("tls")?;

    let tls = match (tls_sni, tls_flag) {
        (Some(_), Some(_)) => {
            return Err(Bad::docspan(
                "set either 'tls-sni' or 'tls', not both: 'tls-sni' names the server explicitly, \
                 'tls' takes the name it was discovered under",
                doc,
                node.span(),
            )
            .into());
        }
        (Some(sni), None) => TlsName::Fixed(sni.to_string()),
        (None, Some(true)) if discovered_name => TlsName::Discovered,
        (None, Some(true)) => {
            return Err(Bad::docspan(
                "'tls' has no name to use here - this connector is a literal address. Use \
                 'tls-sni' to name the server.",
                doc,
                node.span(),
            )
            .into());
        }
        (None, Some(false)) | (None, None) => TlsName::None,
    };

    let proto = args.take_str("proto")?;
    let secure = tls != TlsName::None;

    let alpn = match proto {
        None if secure => ALPN::H2H1,
        None => ALPN::H1,
        Some("h1-only") => ALPN::H1,
        Some("h1-or-h2") => {
            tracing::warn!("accepting 'h1-or-h2' as meaning 'h2-or-h1'");
            require_tls(doc, node, secure)?;
            ALPN::H2H1
        }
        Some("h2-or-h1") => {
            require_tls(doc, node, secure)?;
            ALPN::H2H1
        }
        Some("h2-only") => {
            require_tls(doc, node, secure)?;
            ALPN::H2
        }
        Some(other) => {
            return Err(Bad::docspan(
                format!(
                    "'proto' should be one of 'h1-only', 'h2-only', or 'h2-or-h1', found '{other}'"
                ),
                doc,
                node.span(),
            )
            .into());
        }
    };

    let timeouts = PeerTimeouts {
        connection: args.take_millis("connection-timeout-ms")?,
        total_connection: args.take_millis("total-connection-timeout-ms")?,
        read: args.take_millis("read-timeout-ms")?,
        write: args.take_millis("write-timeout-ms")?,
        idle: args.take_millis("idle-timeout-ms")?,
    };

    Ok(PeerTemplate {
        tls,
        alpn,
        timeouts,
    })
}

fn require_tls(doc: &KdlDocument, node: &KdlNode, secure: bool) -> miette::Result<()> {
    if secure {
        Ok(())
    } else {
        Err(Bad::docspan(
            "HTTP2 to an upstream server requires TLS: set 'tls-sni' or 'tls'",
            doc,
            node.span(),
        )
        .into())
    }
}

/// How often one source re-resolves
fn extract_refresh(
    doc: &KdlDocument,
    node: &KdlNode,
    args: &mut Args<'_>,
    defaults: RefreshPolicy,
) -> miette::Result<RefreshPolicy> {
    let refresh = args.take_str("refresh")?;
    let seconds = args.take_seconds("refresh-seconds")?;

    let kind = match (refresh, seconds) {
        (Some("ttl"), None) => RefreshKind::Ttl,
        (Some("ttl"), Some(_)) => {
            return Err(Bad::docspan(
                "set either 'refresh=\"ttl\"' or 'refresh-seconds', not both",
                doc,
                node.span(),
            )
            .into());
        }
        (Some(other), _) => {
            return Err(Bad::docspan(
                format!(
                    "'{other}' is not a refresh setting. Use 'refresh=\"ttl\"' to follow the \
                     record's TTL, or 'refresh-seconds' for a fixed interval."
                ),
                doc,
                node.span(),
            )
            .into());
        }
        (None, Some(fixed)) => {
            if fixed.is_zero() {
                return Err(
                    Bad::docspan("'refresh-seconds' must be at least 1", doc, node.span()).into(),
                );
            }
            RefreshKind::Fixed(fixed)
        }
        (None, None) => defaults.kind,
    };

    let policy = RefreshPolicy {
        kind,
        min: args
            .take_seconds("min-refresh-seconds")?
            .unwrap_or(defaults.min),
        max: args
            .take_seconds("max-refresh-seconds")?
            .unwrap_or(defaults.max),
    };

    if policy.min.is_zero() {
        return Err(
            Bad::docspan("'min-refresh-seconds' must be at least 1", doc, node.span()).into(),
        );
    }
    check_bounds(doc, node, &policy)?;

    Ok(policy)
}

/// Parse a comma separated list of domain names
///
/// This matches how the `block-cidr-range` filter takes its list of addresses.
fn parse_domain_list(doc: &KdlDocument, node: &KdlNode, list: &str) -> miette::Result<Vec<String>> {
    let mut out = vec![];

    for entry in list.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(Bad::docspan(
                format!("'{list}' has an empty entry - check for a stray comma"),
                doc,
                node.span(),
            )
            .into());
        }

        // Validate now, so a typo is reported against the line that has it
        // rather than as a failed order days later.
        if let Err(e) = ServedName::parse(entry) {
            return Err(Bad::docspan(e.to_string(), doc, node.span()).into());
        }

        out.push(entry.to_string());
    }

    if out.is_empty() {
        return Err(Bad::docspan(
            "'acme-domains' was set but lists no domains",
            doc,
            node.span(),
        )
        .into());
    }

    Ok(out)
}

// services { Service { listeners { ... } } }
fn extract_listener(
    doc: &KdlDocument,
    node: &KdlNode,
    name: &str,
    args: &[KdlEntry],
) -> miette::Result<ListenerConfig> {
    let args = utils::str_value_args(doc, args)?
        .into_iter()
        .collect::<HashMap<&str, &KdlEntry>>();

    // Is this a bindable name?
    if name.parse::<SocketAddr>().is_ok() {
        // Cool: do we have reasonable args for this?
        let cert_path = utils::map_ensure_str(doc, args.get("cert-path").copied())?;
        let key_path = utils::map_ensure_str(doc, args.get("key-path").copied())?;
        let offer_h2 = utils::map_ensure_bool(doc, args.get("offer-h2").copied())?;
        let acme_domains = utils::map_ensure_str(doc, args.get("acme-domains").copied())?;

        // A certificate can come from disk, from ACME, or both - in which case
        // the one on disk is the fallback for names ACME doesn't cover.
        let cert = match (cert_path, key_path) {
            (None, None) => None,
            (Some(cert_path), Some(key_path)) => Some(CertKeyPaths {
                cert_path: cert_path.into(),
                key_path: key_path.into(),
            }),
            (None, Some(_)) | (Some(_), None) => {
                return Err(Bad::docspan(
                    "'cert-path' and 'key-path' must either BOTH be present, or NEITHER should be present",
                    doc,
                    node.span(),
                )
                .into());
            }
        };

        let acme_domains = match acme_domains {
            Some(list) => parse_domain_list(doc, node, list)?,
            None => vec![],
        };

        // Without a certificate from either source, this is a plaintext listener
        if cert.is_none() && acme_domains.is_empty() {
            // We can't offer H2 if we don't have TLS (at least for now, unless we
            // expose H2C settings in pingora)
            if offer_h2.is_some() {
                return Err(Bad::docspan(
                    "'offer-h2' requires TLS, specify 'cert-path' and 'key-path', or 'acme-domains'",
                    doc,
                    node.span(),
                )
                .into());
            }

            return Ok(ListenerConfig {
                source: ListenerKind::Tcp {
                    addr: name.to_string(),
                    tls: None,
                    offer_h2: false,
                },
            });
        }

        Ok(ListenerConfig {
            source: ListenerKind::Tcp {
                addr: name.to_string(),
                tls: Some(TlsConfig { cert, acme_domains }),
                // Default to enabling H2 if unspecified
                offer_h2: offer_h2.unwrap_or(true),
            },
        })
    } else {
        // Anything that isn't a socket address is treated as a path to a unix
        // domain socket. Every string is a valid path, so there is no further
        // parsing to fail here.
        //
        // TODO: Should we check that this path exists? Otherwise it seems to always match
        Ok(ListenerConfig {
            source: ListenerKind::Uds(PathBuf::from(name)),
        })
    }
}

// system { threads-per-service N }
fn extract_system_data(doc: &KdlDocument) -> miette::Result<SystemData> {
    // Get the top level system doc
    let Some(sys) = utils::optional_child_doc(doc, doc, "system") else {
        return Ok(SystemData::default());
    };
    let tps = extract_threads_per_service(doc, sys)?;

    let daemonize = if let Some(n) = sys.get("daemonize") {
        utils::extract_one_bool_arg(doc, n, "daemonize", n.entries())?
    } else {
        false
    };

    let upgrade_socket = if let Some(n) = sys.get("upgrade-socket") {
        let x = utils::extract_one_str_arg(doc, n, "upgrade-socket", n.entries(), |s| {
            Some(PathBuf::from(s))
        })?;
        Some(x)
    } else {
        None
    };

    let pid_file = if let Some(n) = sys.get("pid-file") {
        let x = utils::extract_one_str_arg(doc, n, "pid-file", n.entries(), |s| {
            Some(PathBuf::from(s))
        })?;
        Some(x)
    } else {
        None
    };

    Ok(SystemData {
        threads_per_service: tps,
        daemonize,
        upgrade_socket,
        pid_file,
    })
}

fn extract_threads_per_service(doc: &KdlDocument, sys: &KdlDocument) -> miette::Result<usize> {
    let Some(tps) = sys.get("threads-per-service") else {
        return Ok(8);
    };

    let [tps_node] = tps.entries() else {
        return Err(Bad::docspan(
            "system > threads-per-service should have exactly one entry",
            doc,
            tps.span(),
        )
        .into());
    };

    let val = tps_node.value().as_i64().or_bail(
        "system > threads-per-service should be an integer",
        doc,
        tps_node.span(),
    )?;
    val.try_into().ok().or_bail(
        "system > threads-per-service should fit in a usize",
        doc,
        tps_node.span(),
    )
}

/// The named arguments of one node, read by name
///
/// Reading an argument removes it, so [`Args::finish`] can report whatever is
/// left over. That turns a misspelled key into an error against the line that
/// has it, rather than a setting that silently does nothing.
struct Args<'a> {
    doc: &'a KdlDocument,
    node: &'a KdlNode,
    entries: BTreeMap<&'a str, &'a KdlEntry>,
}

impl<'a> Args<'a> {
    /// For a node whose arguments are all named, like a connector entry
    fn named(
        doc: &'a KdlDocument,
        node: &'a KdlNode,
        args: &'a [KdlEntry],
    ) -> miette::Result<Self> {
        Ok(Self {
            doc,
            node,
            entries: utils::str_value_args(doc, args)?.into_iter().collect(),
        })
    }

    /// For a node that leads with one unnamed string, like `dns "host" port=80`
    fn first_and_named(
        doc: &'a KdlDocument,
        node: &'a KdlNode,
        name: &str,
        args: &'a [KdlEntry],
    ) -> miette::Result<(&'a str, Self)> {
        let (first, rest) = args.split_first().or_bail(
            format!("'{name}' should have an argument"),
            doc,
            node.span(),
        )?;

        // A named first argument means the unnamed one is missing entirely.
        if first.name().is_some() {
            return Err(Bad::docspan(
                format!("'{name}' should start with an unnamed string argument"),
                doc,
                node.span(),
            )
            .into());
        }

        let first = first.value().as_string().or_bail(
            format!("the argument to '{name}' should be a string"),
            doc,
            first.span(),
        )?;

        Ok((first, Self::named(doc, node, rest)?))
    }

    fn take_str(&mut self, key: &str) -> miette::Result<Option<&'a str>> {
        let Some(entry) = self.entries.remove(key) else {
            return Ok(None);
        };
        entry
            .value()
            .as_string()
            .or_bail(
                format!("'{key}' should be a string"),
                self.doc,
                entry.span(),
            )
            .map(Some)
    }

    fn take_bool(&mut self, key: &str) -> miette::Result<Option<bool>> {
        let Some(entry) = self.entries.remove(key) else {
            return Ok(None);
        };
        entry
            .value()
            .as_bool()
            .or_bail(
                format!("'{key}' should be 'true' or 'false'"),
                self.doc,
                entry.span(),
            )
            .map(Some)
    }

    /// A non-negative integer
    fn take_u64(&mut self, key: &str) -> miette::Result<Option<u64>> {
        let Some(entry) = self.entries.remove(key) else {
            return Ok(None);
        };
        entry
            .value()
            .as_i64()
            .and_then(|v| u64::try_from(v).ok())
            .or_bail(
                format!("'{key}' should be a positive whole number"),
                self.doc,
                entry.span(),
            )
            .map(Some)
    }

    fn take_u16(&mut self, key: &str) -> miette::Result<Option<u16>> {
        let Some(value) = self.take_u64(key)? else {
            return Ok(None);
        };
        u16::try_from(value)
            .ok()
            .or_bail(
                format!("'{key}' should be between 0 and {}", u16::MAX),
                self.doc,
                self.node.span(),
            )
            .map(Some)
    }

    fn take_usize(&mut self, key: &str) -> miette::Result<Option<usize>> {
        let Some(value) = self.take_u64(key)? else {
            return Ok(None);
        };
        usize::try_from(value)
            .ok()
            .or_bail(format!("'{key}' is too large"), self.doc, self.node.span())
            .map(Some)
    }

    fn take_millis(&mut self, key: &str) -> miette::Result<Option<Duration>> {
        Ok(self.take_u64(key)?.map(Duration::from_millis))
    }

    fn take_seconds(&mut self, key: &str) -> miette::Result<Option<Duration>> {
        Ok(self.take_u64(key)?.map(Duration::from_secs))
    }

    /// Reject anything that was not read
    fn finish(self) -> miette::Result<()> {
        if self.entries.is_empty() {
            return Ok(());
        }

        let unknown = self
            .entries
            .keys()
            .copied()
            .collect::<Vec<&str>>()
            .join(", ");

        Err(Bad::docspan(
            format!("Unknown setting(s) here: {unknown}"),
            self.doc,
            self.node.span(),
        )
        .into())
    }
}

#[derive(thiserror::Error, Debug, Diagnostic)]
#[error("Incorrect configuration contents")]
struct Bad {
    #[help]
    error: String,

    #[source_code]
    src: String,

    #[label("incorrect")]
    err_span: SourceSpan,
}

trait OptExtParse {
    type Good;

    fn or_bail(
        self,
        msg: impl Into<String>,
        doc: &KdlDocument,
        span: &SourceSpan,
    ) -> miette::Result<Self::Good>;
}

impl<T> OptExtParse for Option<T> {
    type Good = T;

    fn or_bail(
        self,
        msg: impl Into<String>,
        doc: &KdlDocument,
        span: &SourceSpan,
    ) -> miette::Result<Self::Good> {
        match self {
            Some(t) => Ok(t),
            None => Err(Bad::docspan(msg, doc, span).into()),
        }
    }
}

impl Bad {
    /// Helper function for creating a miette span from a given error
    fn docspan(msg: impl Into<String>, doc: &KdlDocument, span: &SourceSpan) -> Self {
        Self {
            error: msg.into(),
            src: doc.to_string(),
            err_span: span.to_owned(),
        }
    }
}
