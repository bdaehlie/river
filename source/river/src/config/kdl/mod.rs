use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
};

use crate::{
    config::internal::{
        AcmeConfig, AcmeDirectory, AcmeDomainConfig, CertKeyPaths, ChallengeKind, Config,
        DiscoveryKind, FileServerConfig, HealthCheckKind, ListenerConfig, ListenerKind,
        PathControl, ProxyConfig, RenewalPolicy, SelectionKind, TlsConfig, UpstreamOptions,
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
use kdl::{KdlDocument, KdlEntry, KdlNode, KdlValue};
use miette::{bail, Diagnostic, SourceSpan};
use pingora::{protocols::ALPN, upstreams::peer::HttpPeer};

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

/// Collects all the filters, where the node name must be "filter", and the rest of the args
/// are collected as a BTreeMap of String:String values
///
/// ```kdl
/// upstream-request {
///     filter kind="remove-header-key-regex" pattern=".*SECRET.*"
///     filter kind="remove-header-key-regex" pattern=".*secret.*"
///     filter kind="upsert-header" key="x-proxy-friend" value="river"
/// }
/// ```
///
/// creates something like:
///
/// ```json
/// [
///     { kind: "remove-header-key-regex", pattern: ".*SECRET.*" },
///     { kind: "remove-header-key-regex", pattern: ".*secret.*" },
///     { kind: "upsert-header", key: "x-proxy-friend", value: "river" }
/// ]
/// ```
fn collect_filters(
    doc: &KdlDocument,
    node: &KdlDocument,
) -> miette::Result<Vec<BTreeMap<String, String>>> {
    let filters = utils::data_nodes(doc, node)?;
    let mut fout = vec![];
    for (_node, name, args) in filters {
        if name != "filter" {
            bail!("Invalid Filter Rule");
        }
        let args = utils::str_str_args(doc, args)?;
        fout.push(
            args.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
    }
    Ok(fout)
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
    let mut conn_cfgs = vec![];
    let mut load_balance: Option<UpstreamOptions> = None;
    for (node, name, args) in conns {
        if name == "load-balance" {
            if load_balance.is_some() {
                panic!("Don't have two 'load-balance' sections");
            }
            load_balance = Some(extract_load_balance(doc, node)?);
            continue;
        }
        let conn = extract_connector(doc, node, name, args)?;
        conn_cfgs.push(conn);
    }
    if conn_cfgs.is_empty() {
        return Err(
            Bad::docspan("We require at least one connector", doc, conn_node.span()).into(),
        );
    }

    // Path Control (optional)
    //
    let mut pc = PathControl::default();
    if let Some(pc_node) = utils::optional_child_doc(doc, node, "path-control") {
        // request-filters (optional)
        if let Some(ureq_node) = utils::optional_child_doc(doc, pc_node, "request-filters") {
            pc.request_filters = collect_filters(doc, ureq_node)?;
        }

        // upstream-request (optional)
        if let Some(ureq_node) = utils::optional_child_doc(doc, pc_node, "upstream-request") {
            pc.upstream_request_filters = collect_filters(doc, ureq_node)?;
        }

        // upstream-response (optional)
        if let Some(uresp_node) = utils::optional_child_doc(doc, pc_node, "upstream-response") {
            pc.upstream_response_filters = collect_filters(doc, uresp_node)?
        }
    }

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
fn extract_load_balance(doc: &KdlDocument, node: &KdlNode) -> miette::Result<UpstreamOptions> {
    let items = utils::data_nodes(
        doc,
        node.children()
            .or_bail("'load-balance' should have children", doc, node.span())?,
    )?;

    let mut selection: Option<SelectionKind> = None;
    let mut health: Option<HealthCheckKind> = None;
    let mut discover: Option<DiscoveryKind> = None;
    let mut selector: RequestSelector = null_selector;

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
                health = Some(utils::extract_one_str_arg(
                    doc,
                    node,
                    name,
                    args,
                    |val| match val {
                        "None" => Some(HealthCheckKind::None),
                        _ => None,
                    },
                )?);
            }
            "discovery" => {
                discover = Some(utils::extract_one_str_arg(
                    doc,
                    node,
                    name,
                    args,
                    |val| match val {
                        "Static" => Some(DiscoveryKind::Static),
                        _ => None,
                    },
                )?);
            }
            other => {
                return Err(
                    Bad::docspan(format!("Unknown setting: '{other}'"), doc, node.span()).into(),
                );
            }
        }
    }
    Ok(UpstreamOptions {
        selection: selection.unwrap_or(SelectionKind::RoundRobin),
        selector,
        health_checks: health.unwrap_or(HealthCheckKind::None),
        discovery: discover.unwrap_or(DiscoveryKind::Static),
    })
}

/// Extracts a single connector from the `connectors` section
fn extract_connector(
    doc: &KdlDocument,
    node: &KdlNode,
    name: &str,
    args: &[KdlEntry],
) -> miette::Result<HttpPeer> {
    let Ok(sadd) = name.parse::<SocketAddr>() else {
        return Err(Bad::docspan("Not a valid socket address", doc, node.span()).into());
    };

    // TODO: consistent enforcement of only-known args?
    let args = utils::str_str_args(doc, args)?
        .into_iter()
        .collect::<HashMap<&str, &str>>();

    let proto = match args.get("proto").copied() {
        None => None,
        Some("h1-only") => Some(ALPN::H1),
        Some("h2-only") => Some(ALPN::H2),
        Some("h1-or-h2") => {
            tracing::warn!("accepting 'h1-or-h2' as meaning 'h2-or-h1'");
            Some(ALPN::H2H1)
        }
        Some("h2-or-h1") => Some(ALPN::H2H1),
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
    let tls_sni = args.get("tls-sni");

    let (tls, sni, alpn) = match (proto, tls_sni) {
        (None, None) | (Some(ALPN::H1), None) => (false, String::new(), ALPN::H1),
        (None, Some(sni)) => (true, sni.to_string(), ALPN::H2H1),
        (Some(_), None) => {
            return Err(
                Bad::docspan("'tls-sni' is required for HTTP2 support", doc, node.span()).into(),
            );
        }
        (Some(p), Some(sni)) => (true, sni.to_string(), p),
    };

    let mut peer = HttpPeer::new(sadd, tls, sni);
    peer.options.alpn = alpn;

    Ok(peer)
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
