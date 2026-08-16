//! The background service that keeps certificates current
//!
//! This runs alongside the proxy and file services. It has two jobs:
//!
//! 1. Before River starts serving, make sure every managed domain has a
//!    certificate. Listeners that depend on this service do not accept traffic
//!    until it reports ready, which answers the question left open in
//!    `docs/what-to-build.md` section 4.9: a certificate is obtained *before*
//!    traffic is served.
//! 2. Afterwards, check periodically whether anything is due for renewal, and
//!    replace it in place. Because certificates are chosen per-handshake, a
//!    renewal needs no reload and no dropped connections.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use instant_acme::Account;
use pingora_core::{
    server::ShutdownWatch,
    services::{background::BackgroundService, ServiceReadyNotifier},
};

use super::{
    dns01::Dns01Solver,
    http01::{ChallengeStore, Http01Solver},
    order,
    solver::ChallengeSolver,
    store::{AcmeStore, CertificateId},
    AcmeError,
};
use crate::{
    config::internal::{AcmeConfig, ChallengeKind, RenewalPolicy},
    tls::store::{CertStore, Certificate, ServedName},
};

/// How often to check whether anything is due for renewal
///
/// Renewal windows are measured in days, so there is nothing to gain from
/// checking more often than this.
const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How long to wait before retrying after a failed order
///
/// Certificate authorities rate limit failures, so this backs off rather than
/// retrying on the next tick.
const RETRY_BACKOFF: Duration = Duration::from_secs(15 * 60);

/// One certificate River is responsible for
struct ManagedCertificate {
    id: CertificateId,
    domains: Vec<ServedName>,
}

/// Keeps every managed certificate obtained and current
pub struct AcmeService {
    config: AcmeConfig,
    store: AcmeStore,
    certificates: Vec<ManagedCertificate>,
    cert_store: Arc<CertStore>,
    challenges: Arc<ChallengeStore>,
}

impl AcmeService {
    /// Build the service from the configuration
    ///
    /// Groups the domains named across all listeners into certificates - one
    /// per distinct set of domains, so two listeners asking for the same names
    /// share a single certificate and a single order.
    pub fn new(
        config: AcmeConfig,
        domain_sets: Vec<Vec<ServedName>>,
        cert_store: Arc<CertStore>,
        challenges: Arc<ChallengeStore>,
    ) -> Result<Self, AcmeError> {
        let store = AcmeStore::open(&config.store_dir)?;

        let mut by_id: BTreeMap<CertificateId, Vec<ServedName>> = BTreeMap::new();
        for domains in domain_sets {
            if domains.is_empty() {
                continue;
            }
            by_id
                .entry(CertificateId::for_domains(&domains))
                .or_insert(domains);
        }

        let certificates = by_id
            .into_iter()
            .map(|(id, domains)| ManagedCertificate { id, domains })
            .collect();

        Ok(Self {
            config,
            store,
            certificates,
            cert_store,
            challenges,
        })
    }

    /// Load anything already on disk into the certificate store
    ///
    /// Called before the first order, so that a restart serves the certificates
    /// it already has rather than asking the CA for more.
    fn load_cached(&self) -> usize {
        let mut loaded = 0;

        for managed in &self.certificates {
            let stored = match self.store.load_certificate(&managed.id) {
                Ok(Some(stored)) => stored,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(
                        certificate = %managed.id,
                        error = %e,
                        "Could not read a stored certificate, will obtain a new one"
                    );
                    continue;
                }
            };

            match Certificate::new(stored.bundle) {
                Ok(cert) => {
                    self.cert_store.insert(&managed.domains, Arc::new(cert));
                    loaded += 1;
                    tracing::info!(
                        certificate = %managed.id,
                        "Loaded a stored certificate"
                    );
                }
                Err(e) => tracing::warn!(
                    certificate = %managed.id,
                    error = %e,
                    "A stored certificate is not usable, will obtain a new one"
                ),
            }
        }

        loaded
    }

    /// Is this certificate missing, or close enough to expiry to replace?
    fn needs_renewal(&self, managed: &ManagedCertificate) -> bool {
        let Ok(Some(stored)) = self.store.load_certificate(&managed.id) else {
            // Missing or unreadable - either way, obtain one.
            return true;
        };

        let Ok(cert) = Certificate::new(stored.bundle) else {
            return true;
        };

        match self.config.renewal {
            RenewalPolicy::BeforeExpiry { days } => match cert.parsed().days_until_expiry() {
                Ok(remaining) => remaining <= days as i32,
                Err(e) => {
                    tracing::warn!(
                        certificate = %managed.id,
                        error = %e,
                        "Could not read the expiry date, treating as due for renewal"
                    );
                    true
                }
            },
            RenewalPolicy::AfterIssue { days } => stored.meta.days_since_issue() >= days as u64,
        }
    }

    /// The solvers this certificate's domains call for
    ///
    /// An order can mix the two: `example.com` over HTTP-01 alongside
    /// `*.example.com` over DNS-01 is a common arrangement, and each
    /// authorization picks whichever solver its challenge list offers.
    fn solvers(&self, domains: &[ServedName]) -> Result<Vec<Box<dyn ChallengeSolver>>, AcmeError> {
        let mut solvers: Vec<Box<dyn ChallengeSolver>> = Vec::new();

        // DNS-01 first: a wildcard has no other option, and where both are
        // available for a name either will do.
        if let Some(dns) = Dns01Solver::from_config(&self.config, domains) {
            solvers.push(Box::new(dns));
        }

        let any_http01 = domains
            .iter()
            .any(|d| self.config.challenge_for(&d.to_string()).0 == ChallengeKind::Http01);
        if any_http01 {
            solvers.push(Box::new(Http01Solver::new(self.challenges.clone())));
        }

        if solvers.is_empty() {
            return Err(AcmeError::Solver {
                domain: domains
                    .iter()
                    .map(|d| d.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                reason: "no challenge solver is configured for these domains".into(),
            });
        }

        Ok(solvers)
    }

    /// Obtain or renew one certificate and put it into the certificate store
    async fn refresh(
        &self,
        account: &Account,
        managed: &ManagedCertificate,
    ) -> Result<(), AcmeError> {
        let solvers = self.solvers(&managed.domains)?;

        let bundle = order::obtain(account, &self.store, &managed.domains, &solvers).await?;
        let cert = Certificate::new(bundle)?;

        // Swapping the certificate in the store is all it takes. Connections
        // already established keep the certificate they handshook with; the
        // next handshake picks up this one.
        self.cert_store.insert(&managed.domains, Arc::new(cert));

        Ok(())
    }

    /// Bring every certificate up to date, returning how many failed
    async fn refresh_all(&self, account: &Account, force: bool) -> usize {
        let mut failures = 0;

        for managed in &self.certificates {
            if !force && !self.needs_renewal(managed) {
                continue;
            }

            tracing::info!(
                certificate = %managed.id,
                domains = ?managed.domains.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
                "Obtaining a certificate"
            );

            if let Err(e) = self.refresh(account, managed).await {
                tracing::error!(
                    certificate = %managed.id,
                    error = %e,
                    "Could not obtain a certificate"
                );
                failures += 1;
            }
        }

        failures
    }
}

#[async_trait]
impl BackgroundService for AcmeService {
    async fn start_with_ready_notifier(
        &self,
        mut shutdown: ShutdownWatch,
        ready_notifier: ServiceReadyNotifier,
    ) {
        if self.certificates.is_empty() {
            ready_notifier.notify_ready();
            return;
        }

        // Serve whatever we already have, so a restart is not an outage even
        // if the CA is unreachable right now.
        let cached = self.load_cached();
        tracing::info!(
            cached,
            managed = self.certificates.len(),
            "Starting ACME service"
        );

        let account = match order::load_or_create_account(&self.config, &self.store).await {
            Ok(account) => account,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Could not set up the ACME account. Listeners with managed domains will \
                     serve only the certificates already on disk, if any."
                );
                // Release the listeners regardless: refusing to start would
                // turn a CA outage into a River outage, and any cached
                // certificates are still perfectly good.
                ready_notifier.notify_ready();
                return;
            }
        };

        // First pass, before listeners start accepting traffic.
        let failures = self.refresh_all(&account, false).await;
        if failures > 0 {
            tracing::error!(
                failures,
                "Some certificates could not be obtained. Listeners will start anyway; \
                 River will keep retrying."
            );
        }

        ready_notifier.notify_ready();

        // Steady state: check periodically for anything due.
        loop {
            let wait = match failures {
                0 => RENEWAL_CHECK_INTERVAL,
                _ => RETRY_BACKOFF,
            };

            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = shutdown.changed() => {
                    tracing::info!("ACME service shutting down");
                    return;
                }
            }

            self.refresh_all(&account, false).await;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::internal::AcmeDirectory;

    fn names(names: &[&str]) -> Vec<ServedName> {
        names
            .iter()
            .map(|n| ServedName::parse(n).unwrap())
            .collect()
    }

    fn config(dir: &std::path::Path, renewal: RenewalPolicy) -> AcmeConfig {
        AcmeConfig {
            directory: AcmeDirectory::LetsEncryptStaging,
            contacts: vec![],
            accept_terms_of_service: true,
            store_dir: dir.to_path_buf(),
            renewal,
            default_challenge: ChallengeKind::Http01,
            challenge_listener: None,
            dns_propagation_seconds: 0,
            domains: vec![],
        }
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("river-acme-svc-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn service(
        dir: &std::path::Path,
        renewal: RenewalPolicy,
        domains: Vec<Vec<ServedName>>,
    ) -> AcmeService {
        AcmeService::new(
            config(dir, renewal),
            domains,
            Arc::new(CertStore::new()),
            Arc::new(ChallengeStore::new()),
        )
        .unwrap()
    }

    #[test]
    fn groups_identical_domain_sets_into_one_certificate() {
        let dir = temp_dir("group");

        // Three listeners: two asking for the same pair, one for something else
        let svc = service(
            &dir,
            RenewalPolicy::default(),
            vec![
                names(&["example.com", "www.example.com"]),
                names(&["www.example.com", "example.com"]),
                names(&["other.test"]),
            ],
        );

        assert_eq!(
            svc.certificates.len(),
            2,
            "identical domain sets should share one certificate"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_certificate_needs_renewal() {
        let dir = temp_dir("missing");
        let svc = service(
            &dir,
            RenewalPolicy::default(),
            vec![names(&["example.com"])],
        );

        assert!(svc.needs_renewal(&svc.certificates[0]));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn renewal_respects_the_configured_window() {
        use crate::acme::store::CertificateMeta;
        use crate::tls::backend::test::self_signed;

        let dir = temp_dir("window");
        let domains = names(&["example.com"]);

        // A certificate with 60 days left
        let svc = service(
            &dir,
            RenewalPolicy::BeforeExpiry { days: 30 },
            vec![domains.clone()],
        );
        let id = &svc.certificates[0].id;
        svc.store
            .save_certificate(
                id,
                &self_signed(&["example.com"], 60),
                &CertificateMeta::now(&domains, None),
            )
            .unwrap();

        assert!(
            !svc.needs_renewal(&svc.certificates[0]),
            "60 days left is outside a 30 day window"
        );

        // The same certificate, with a wider window
        let svc = service(
            &dir,
            RenewalPolicy::BeforeExpiry { days: 75 },
            vec![domains.clone()],
        );
        assert!(
            svc.needs_renewal(&svc.certificates[0]),
            "60 days left is inside a 75 day window"
        );

        // Counting forward from issue instead: it was issued just now
        let svc = service(
            &dir,
            RenewalPolicy::AfterIssue { days: 30 },
            vec![domains.clone()],
        );
        assert!(
            !svc.needs_renewal(&svc.certificates[0]),
            "just issued, so not yet due under an after-issue policy"
        );

        let svc = service(&dir, RenewalPolicy::AfterIssue { days: 0 }, vec![domains]);
        assert!(
            svc.needs_renewal(&svc.certificates[0]),
            "a zero day after-issue window is always due"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cached_certificates_are_served_on_startup() {
        use crate::acme::store::CertificateMeta;
        use crate::tls::backend::test::self_signed;

        let dir = temp_dir("cached");
        let domains = names(&["example.com", "*.example.com"]);
        let svc = service(&dir, RenewalPolicy::default(), vec![domains.clone()]);

        svc.store
            .save_certificate(
                &svc.certificates[0].id,
                &self_signed(&["example.com", "*.example.com"], 90),
                &CertificateMeta::now(&domains, None),
            )
            .unwrap();

        assert_eq!(svc.load_cached(), 1);

        // Both the exact name and the wildcard resolve
        assert!(svc.cert_store.get("example.com").is_some());
        assert!(svc.cert_store.get("anything.example.com").is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn picks_solvers_from_the_configured_challenges() {
        use crate::config::internal::AcmeDomainConfig;

        let dir = temp_dir("solvers");

        // Only HTTP-01 is configured
        let svc = service(
            &dir,
            RenewalPolicy::default(),
            vec![names(&["example.com"])],
        );
        let solvers = svc.solvers(&names(&["example.com"])).unwrap();
        assert_eq!(solvers.len(), 1);
        assert_eq!(
            solvers[0].challenge_type(),
            instant_acme::ChallengeType::Http01
        );

        // A wildcard over DNS-01 alongside a plain name over HTTP-01 needs both
        let mut cfg = config(&dir, RenewalPolicy::default());
        cfg.domains = vec![AcmeDomainConfig {
            domain: "*.example.com".into(),
            challenge: ChallengeKind::Dns01,
            dns_hook: Some("/usr/local/bin/hook".into()),
        }];

        let svc = AcmeService::new(
            cfg,
            vec![names(&["example.com", "*.example.com"])],
            Arc::new(CertStore::new()),
            Arc::new(ChallengeStore::new()),
        )
        .unwrap();

        let solvers = svc
            .solvers(&names(&["example.com", "*.example.com"]))
            .unwrap();
        let kinds: Vec<_> = solvers.iter().map(|s| s.challenge_type()).collect();
        assert!(kinds.contains(&instant_acme::ChallengeType::Dns01));
        assert!(kinds.contains(&instant_acme::ChallengeType::Http01));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
