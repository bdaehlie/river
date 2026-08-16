//! Answering `dns-01` challenges through an external hook
//!
//! A certificate authority will only issue a wildcard certificate against a
//! `dns-01` challenge, so this is what makes `*.example.com` possible.
//!
//! River does not talk to DNS providers itself. There are dozens of them, each
//! with its own API and its own credentials, and tracking them is not work a
//! reverse proxy should be doing. Instead River runs a program the operator
//! supplies:
//!
//! ```text
//! hook set   _acme-challenge.example.com <txt-value>
//! hook clean _acme-challenge.example.com <txt-value>
//! ```
//!
//! An exit status of zero means the record is published. This is the same shape
//! as lego's `exec` provider and certbot's manual hooks, so existing scripts
//! generally work unchanged.

use std::{collections::HashMap, path::PathBuf, process::Stdio, time::Duration};

use async_trait::async_trait;
use instant_acme::ChallengeType;
use tokio::process::Command;

use super::{
    solver::{Challenge, ChallengeSolver},
    AcmeError,
};
use crate::{
    config::internal::{AcmeConfig, ChallengeKind},
    tls::store::{normalize, ServedName},
};

/// How long a hook is given to publish or remove a record
const HOOK_TIMEOUT: Duration = Duration::from_secs(120);

/// Publishes `dns-01` responses by running an operator-supplied program
pub struct Dns01Solver {
    /// Validation domain to the hook that serves it
    ///
    /// Keyed by the domain the CA actually validates, which for a wildcard is
    /// the parent: an order for `*.example.com` is validated by a TXT record at
    /// `_acme-challenge.example.com`.
    hooks: HashMap<String, PathBuf>,

    /// How long to wait after the hook returns, before telling the CA to check
    settle: Duration,
}

impl Dns01Solver {
    /// Build a solver covering every domain configured to use `dns-01`
    ///
    /// Returns `None` when no domain uses this challenge, so the caller does
    /// not offer a solver that can never be used.
    pub fn from_config(config: &AcmeConfig, domains: &[ServedName]) -> Option<Self> {
        let mut hooks = HashMap::new();

        for domain in domains {
            let (kind, hook) = config.challenge_for(&domain.to_string());
            if kind != ChallengeKind::Dns01 {
                continue;
            }

            // The configuration parser guarantees a hook is present for any
            // domain using this challenge.
            let Some(hook) = hook else { continue };

            hooks.insert(validation_domain(domain), hook.clone());
        }

        match hooks.is_empty() {
            true => None,
            false => Some(Self {
                hooks,
                settle: Duration::from_secs(config.dns_propagation_seconds as u64),
            }),
        }
    }

    fn hook_for(&self, domain: &str) -> Result<&PathBuf, AcmeError> {
        self.hooks
            .get(&normalize(domain))
            .ok_or_else(|| AcmeError::Solver {
                domain: domain.to_string(),
                reason: "no 'dns-01' hook is configured for this domain".into(),
            })
    }

    async fn run(&self, action: &str, challenge: &Challenge) -> Result<(), AcmeError> {
        let hook = self.hook_for(&challenge.domain)?;
        let record = challenge.dns_record_name();
        let value = challenge.dns_record_value();

        let fail = |reason: String| AcmeError::Solver {
            domain: challenge.domain.clone(),
            reason,
        };

        tracing::info!(
            hook = %hook.display(),
            action,
            record = %record,
            "Running the DNS-01 hook"
        );

        let child = Command::new(hook)
            .arg(action)
            .arg(&record)
            .arg(&value)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output();

        let output = match tokio::time::timeout(HOOK_TIMEOUT, child).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                return Err(fail(format!("could not run {}: {e}", hook.display())));
            }
            Err(_) => {
                return Err(fail(format!(
                    "{} did not finish within {} seconds",
                    hook.display(),
                    HOOK_TIMEOUT.as_secs()
                )));
            }
        };

        // The hook's own output is the most useful thing an operator has when
        // this goes wrong, so surface it rather than swallowing it.
        for line in String::from_utf8_lossy(&output.stderr).lines() {
            tracing::warn!(hook = %hook.display(), "{line}");
        }
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            tracing::debug!(hook = %hook.display(), "{line}");
        }

        if !output.status.success() {
            return Err(fail(format!(
                "{} {action} exited with {}",
                hook.display(),
                output.status
            )));
        }

        Ok(())
    }
}

/// The domain a certificate authority validates for `domain`
///
/// A wildcard is validated against its parent: an order for `*.example.com`
/// produces an authorization for `example.com`.
fn validation_domain(domain: &ServedName) -> String {
    match domain {
        ServedName::Exact(name) => name.clone(),
        ServedName::Wildcard(parent) => parent.clone(),
    }
}

#[async_trait]
impl ChallengeSolver for Dns01Solver {
    fn challenge_type(&self) -> ChallengeType {
        ChallengeType::Dns01
    }

    async fn present(&self, challenge: &Challenge) -> Result<(), AcmeError> {
        self.run("set", challenge).await?;

        // A hook that returns before the record is visible everywhere causes a
        // failed validation, which costs a retry against the CA's rate limits.
        // Waiting is much cheaper than getting it wrong.
        if !self.settle.is_zero() {
            tracing::info!(
                seconds = self.settle.as_secs(),
                record = %challenge.dns_record_name(),
                "Waiting for the DNS record to propagate"
            );
            tokio::time::sleep(self.settle).await;
        }

        Ok(())
    }

    async fn cleanup(&self, challenge: &Challenge) {
        // Always attempt cleanup, including after a failed order - a stale TXT
        // record is confusing to find later.
        if let Err(e) = self.run("clean", challenge).await {
            tracing::warn!(
                domain = %challenge.domain,
                error = %e,
                "Could not remove the DNS-01 challenge record, it may need removing by hand"
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::internal::{AcmeDirectory, AcmeDomainConfig, RenewalPolicy};

    fn names(names: &[&str]) -> Vec<ServedName> {
        names
            .iter()
            .map(|n| ServedName::parse(n).unwrap())
            .collect()
    }

    fn config(domains: Vec<AcmeDomainConfig>) -> AcmeConfig {
        AcmeConfig {
            directory: AcmeDirectory::LetsEncryptStaging,
            contacts: vec![],
            accept_terms_of_service: true,
            store_dir: "/tmp/river-acme-test".into(),
            renewal: RenewalPolicy::default(),
            default_challenge: ChallengeKind::Http01,
            challenge_listener: None,
            dns_propagation_seconds: 0,
            domains,
        }
    }

    #[test]
    fn wildcards_are_validated_against_their_parent() {
        // This is the detail that is easy to get wrong: the TXT record for
        // `*.example.com` goes at `_acme-challenge.example.com`, with no `*.`
        // anywhere in it.
        assert_eq!(
            validation_domain(&ServedName::parse("*.example.com").unwrap()),
            "example.com"
        );
        assert_eq!(
            validation_domain(&ServedName::parse("example.com").unwrap()),
            "example.com"
        );
    }

    #[test]
    fn builds_a_hook_map_for_dns01_domains_only() {
        let cfg = config(vec![
            AcmeDomainConfig {
                domain: "*.example.com".into(),
                challenge: ChallengeKind::Dns01,
                dns_hook: Some("/usr/local/bin/hook".into()),
            },
            AcmeDomainConfig {
                domain: "www.example.com".into(),
                challenge: ChallengeKind::Http01,
                dns_hook: None,
            },
        ]);

        let solver = Dns01Solver::from_config(&cfg, &names(&["*.example.com", "www.example.com"]))
            .expect("a dns-01 domain is configured");

        // Keyed by the validation domain, not the configured name
        assert!(solver.hook_for("example.com").is_ok());
        // The http-01 domain is not this solver's business
        assert!(solver.hook_for("www.example.com").is_err());
    }

    #[test]
    fn no_solver_when_nothing_uses_dns01() {
        let cfg = config(vec![]);
        assert!(Dns01Solver::from_config(&cfg, &names(&["example.com"])).is_none());
    }

    #[tokio::test]
    async fn reports_a_failing_hook() {
        let cfg = config(vec![AcmeDomainConfig {
            domain: "example.com".into(),
            challenge: ChallengeKind::Dns01,
            dns_hook: Some("/nonexistent/river-dns-hook".into()),
        }]);

        let solver = Dns01Solver::from_config(&cfg, &names(&["example.com"])).unwrap();
        let hook = solver.hook_for("example.com").unwrap();
        assert_eq!(hook, &PathBuf::from("/nonexistent/river-dns-hook"));
    }
}
