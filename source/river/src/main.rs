mod acme;
mod config;
mod files;
mod proxy;
mod tls;

use std::sync::Arc;

use crate::{
    acme::{http01::ChallengeStore, service::AcmeService},
    config::internal::Config,
    files::river_file_server,
    proxy::{
        discovery::resolver::{Resolver, SystemResolver},
        river_proxy_service,
    },
    tls::{resolver::CertResolver, store::CertStore, store::ServedName},
};
use config::internal::{self, ListenerConfig, ListenerKind};
use openssl::ssl::SslFiletype;
use pingora::{server::Server, services::ServiceWithDependents};
use pingora_core::{listeners::tls::TlsSettings, services::background::background_service};

fn main() {
    // Set up tracing, including catching `log` crate logs from pingora crates
    tracing_subscriber::fmt::init();

    // Read from the various configuration files
    let conf = config::render_config();

    // Start the Server, which we will add services to.
    let mut my_server =
        Server::new_with_opt_and_conf(conf.pingora_opt(), conf.pingora_server_conf());

    // Certificates that are chosen per-connection, by SNI. Listeners read from
    // this during the TLS handshake; the ACME service writes to it as it
    // obtains and renews certificates.
    let cert_store = Arc::new(CertStore::new());

    // Only stood up when ACME is configured, so that services which don't need
    // it don't intercept requests under the challenge path.
    let acme_challenges = conf.acme.as_ref().map(|_| Arc::new(ChallengeStore::new()));

    // Where upstream service discovery looks names up. One resolver is shared
    // by every service, so they also share its cache. It is built lazily, on
    // first use inside a background service, because that is the first point
    // at which a runtime is guaranteed to exist.
    let resolver: Arc<dyn Resolver> = SystemResolver::new();

    tracing::info!("Applying Basic Proxies...");

    // Each service is paired with whether it may wait for the ACME service,
    // and with the background service that keeps its upstreams current, if it
    // has one.
    //
    // A service that can answer an HTTP-01 challenge must NOT wait: the ACME
    // service does not report itself ready until it has obtained the first
    // certificates, and it cannot obtain them if the listener the certificate
    // authority needs to reach is waiting on it. That would deadlock.
    struct Pending {
        service: Box<dyn ServiceWithDependents>,
        may_wait_for_acme: bool,
        upstreams: Option<Box<dyn ServiceWithDependents>>,
    }

    let mut services: Vec<Pending> = vec![];

    for beep in conf.basic_proxies.iter().cloned() {
        tracing::info!("Configuring Basic Proxy: {}", beep.name);
        let may_wait_for_acme = !internal::serves_plaintext(&beep.listeners);
        let (service, upstreams) = river_proxy_service(
            beep,
            &my_server,
            &cert_store,
            acme_challenges.as_ref(),
            &resolver,
        );
        services.push(Pending {
            service,
            may_wait_for_acme,
            upstreams,
        });
    }

    for fs in conf.file_servers.iter().cloned() {
        tracing::info!("Configuring File Server: {}", fs.name);
        let may_wait_for_acme = !internal::serves_plaintext(&fs.listeners);
        let service = river_file_server(fs, &my_server, &cert_store, acme_challenges.as_ref());
        services.push(Pending {
            service,
            may_wait_for_acme,
            upstreams: None,
        });
    }

    // The dedicated challenge listener, if one was configured. This one exists
    // to answer challenges, so it can never wait for them.
    if let (Some(acme_conf), Some(challenges)) = (conf.acme.as_ref(), acme_challenges.as_ref()) {
        if let Some(addr) = acme_conf.challenge_listener.as_deref() {
            tracing::info!("Configuring ACME challenge listener on {addr}");
            let service =
                acme::http01::challenge_service(addr, challenges.clone(), &my_server, &cert_store);
            services.push(Pending {
                service,
                may_wait_for_acme: false,
                upstreams: None,
            });
        }
    }

    // Now we hand it over to pingora to run forever.
    tracing::info!("Bootstrapping...");
    my_server.bootstrap();
    tracing::info!("Bootstrapped. Adding Services...");

    let mut may_wait = Vec::with_capacity(services.len());
    let mut upstream_services = Vec::with_capacity(services.len());
    let mut listening_services: Vec<Box<dyn ServiceWithDependents>> =
        Vec::with_capacity(services.len());

    for pending in services {
        may_wait.push(pending.may_wait_for_acme);
        upstream_services.push(pending.upstreams);
        listening_services.push(pending.service);
    }

    // `add_services` returns handles in the order the services were given.
    let service_handles = my_server.add_services(listening_services);

    // A service that discovers its upstreams at runtime does not start
    // accepting connections until the first resolution attempt has finished,
    // so that River does not answer requests before it knows where to send
    // them. The attempt reports ready whether or not it succeeded, so broken
    // DNS delays startup rather than preventing it.
    for (handle, upstreams) in service_handles.iter().zip(upstream_services) {
        let Some(upstreams) = upstreams else {
            continue;
        };
        let upstream_handle = my_server.add_boxed_service(upstreams);
        handle.add_dependency(upstream_handle);
    }

    // The ACME service goes on last, so that the services above can be made to
    // wait for it.
    if let (Some(acme_conf), Some(challenges)) = (conf.acme.as_ref(), acme_challenges.as_ref()) {
        match build_acme_service(&conf, acme_conf.clone(), &cert_store, challenges) {
            Ok(Some(acme_service)) => {
                let acme_handle = my_server.add_service(background_service("ACME", acme_service));

                // Services that serve only TLS wait for the first certificates
                // to be in hand, so that River does not answer a handshake it
                // has no certificate for.
                let mut waiting = 0;
                for (handle, may_wait) in service_handles.iter().zip(&may_wait) {
                    if *may_wait {
                        handle.add_dependency(acme_handle.clone());
                        waiting += 1;
                    }
                }

                tracing::info!(
                    waiting,
                    "Services that will wait for the first ACME certificates"
                );
            }
            Ok(None) => {}
            Err(e) => {
                // A store directory River cannot use is a configuration
                // problem, and starting up to serve nothing but handshake
                // failures would hide it.
                panic!("Could not set up ACME: {e}");
            }
        }
    }

    tracing::info!("Starting Server...");
    my_server.run_forever();
}

/// Build the ACME background service, if any domains are actually managed
fn build_acme_service(
    conf: &Config,
    acme_conf: config::internal::AcmeConfig,
    cert_store: &Arc<CertStore>,
    challenges: &Arc<ChallengeStore>,
) -> Result<Option<AcmeService>, acme::AcmeError> {
    // One certificate per listener that names domains, so that a listener gets
    // exactly the names it asked for.
    let mut domain_sets: Vec<Vec<ServedName>> = vec![];

    let proxy_listeners = conf.basic_proxies.iter().flat_map(|p| p.listeners.iter());
    let file_listeners = conf.file_servers.iter().flat_map(|f| f.listeners.iter());

    for listener in proxy_listeners.chain(file_listeners) {
        let ListenerKind::Tcp { tls: Some(tls), .. } = &listener.source else {
            continue;
        };
        if tls.acme_domains.is_empty() {
            continue;
        }

        // The config parser has already checked these parse.
        let names: Vec<ServedName> = tls
            .acme_domains
            .iter()
            .filter_map(|d| ServedName::parse(d).ok())
            .collect();
        domain_sets.push(names);
    }

    if domain_sets.is_empty() {
        return Ok(None);
    }

    AcmeService::new(
        acme_conf,
        domain_sets,
        cert_store.clone(),
        challenges.clone(),
    )
    .map(Some)
}

pub fn populate_listners<T>(
    listeners: Vec<ListenerConfig>,
    service: &mut pingora_core::services::listening::Service<T>,
    cert_store: &Arc<CertStore>,
) {
    for list_cfg in listeners {
        // NOTE: See https://github.com/cloudflare/pingora/issues/182 for tracking "paths aren't
        // always UTF-8 strings".
        //
        // See also https://github.com/cloudflare/pingora/issues/183 for tracking "ip addrs shouldn't
        // be strings"
        match list_cfg.source {
            ListenerKind::Tcp {
                addr,
                tls: Some(tls_cfg),
                offer_h2,
            } => {
                let cert_paths = tls_cfg.cert.as_ref().map(|cert| {
                    let cert_path = cert.cert_path.to_str().expect("cert path should be utf8");
                    let key_path = cert.key_path.to_str().expect("key path should be utf8");
                    (cert_path, key_path)
                });

                let mut settings = if tls_cfg.acme_domains.is_empty() {
                    // No managed domains, so there is one certificate and it is
                    // known up front. The config parser guarantees it is here.
                    let (cert_path, key_path) =
                        cert_paths.expect("a TLS listener has a certificate or ACME domains");

                    TlsSettings::intermediate(cert_path, key_path)
                        .expect("adding TLS listener shouldn't fail")
                } else {
                    // Certificates are chosen during the handshake instead, so
                    // this listener can start before any of them exist.
                    let mut settings =
                        TlsSettings::with_callbacks(CertResolver::callbacks(cert_store.clone()))
                            .expect("adding TLS listener shouldn't fail");

                    // A statically configured certificate becomes the fallback
                    // for clients whose SNI matches no managed domain. This
                    // works through `TlsSettings`' `DerefMut` to the underlying
                    // acceptor builder, and is overridden per-connection by
                    // anything the resolver installs.
                    if let Some((cert_path, key_path)) = cert_paths {
                        settings
                            .set_certificate_chain_file(cert_path)
                            .expect("fallback cert should load");
                        settings
                            .set_private_key_file(key_path, SslFiletype::PEM)
                            .expect("fallback key should load");
                    }

                    settings
                };

                if offer_h2 {
                    settings.enable_h2();
                }

                service.add_tls_with_settings(&addr, None, settings);
            }
            ListenerKind::Tcp {
                addr,
                tls: None,
                offer_h2,
            } => {
                if offer_h2 {
                    panic!("Unsupported configuration: {addr:?} configured without TLS, but H2 enabled which requires TLS");
                }
                service.add_tcp(&addr);
            }
            ListenerKind::Uds(path) => {
                let path = path.to_str().unwrap();
                service.add_uds(path, None); // todo
            }
        }
    }
}
