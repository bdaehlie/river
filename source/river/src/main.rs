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
    proxy::river_proxy_service,
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

    tracing::info!("Applying Basic Proxies...");

    // Each service is paired with whether it may wait for the ACME service.
    //
    // A service that can answer an HTTP-01 challenge must NOT wait: the ACME
    // service does not report itself ready until it has obtained the first
    // certificates, and it cannot obtain them if the listener the certificate
    // authority needs to reach is waiting on it. That would deadlock.
    let mut services: Vec<(Box<dyn ServiceWithDependents>, bool)> = vec![];

    // At the moment, we only support basic proxy services. These have some path
    // control, but don't support things like load balancing, health checks, etc.
    for beep in conf.basic_proxies.iter().cloned() {
        tracing::info!("Configuring Basic Proxy: {}", beep.name);
        let may_wait = !internal::serves_plaintext(&beep.listeners);
        let service = river_proxy_service(beep, &my_server, &cert_store, acme_challenges.as_ref());
        services.push((service, may_wait));
    }

    for fs in conf.file_servers.iter().cloned() {
        tracing::info!("Configuring File Server: {}", fs.name);
        let may_wait = !internal::serves_plaintext(&fs.listeners);
        let service = river_file_server(fs, &my_server, &cert_store, acme_challenges.as_ref());
        services.push((service, may_wait));
    }

    // The dedicated challenge listener, if one was configured. This one exists
    // to answer challenges, so it can never wait for them.
    if let (Some(acme_conf), Some(challenges)) = (conf.acme.as_ref(), acme_challenges.as_ref()) {
        if let Some(addr) = acme_conf.challenge_listener.as_deref() {
            tracing::info!("Configuring ACME challenge listener on {addr}");
            let service =
                acme::http01::challenge_service(addr, challenges.clone(), &my_server, &cert_store);
            services.push((service, false));
        }
    }

    // Now we hand it over to pingora to run forever.
    tracing::info!("Bootstrapping...");
    my_server.bootstrap();
    tracing::info!("Bootstrapped. Adding Services...");

    let (services, may_wait): (Vec<_>, Vec<_>) = services.into_iter().unzip();
    // `add_services` returns handles in the order the services were given.
    let service_handles = my_server.add_services(services);

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
