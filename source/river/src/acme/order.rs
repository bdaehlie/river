//! Obtaining one certificate, start to finish
//!
//! This is the part that talks to the certificate authority. Everything it
//! needs - where to store the result, how to answer challenges - is handed in,
//! so the flow itself stays readable.

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};

use super::{
    csr,
    solver::{Challenge, ChallengeSolver},
    store::{AcmeStore, CertificateId, CertificateMeta},
    AcmeError,
};
use crate::{
    config::internal::AcmeConfig,
    tls::store::{CertificateBundle, ServedName},
};

/// Load the stored ACME account, or register a new one
///
/// The credentials are written back out when an account is created, so this
/// only ever registers once for a given store directory.
pub async fn load_or_create_account(
    config: &AcmeConfig,
    store: &AcmeStore,
) -> Result<Account, AcmeError> {
    if let Some(credentials) = store.load_account()? {
        tracing::info!("Using the existing ACME account");
        return Ok(Account::builder()?.from_credentials(credentials).await?);
    }

    tracing::info!(
        directory = config.directory.url(),
        "Registering a new ACME account"
    );

    let contacts: Vec<&str> = config.contacts.iter().map(String::as_str).collect();
    let (account, credentials): (Account, AccountCredentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &contacts,
                // The configuration parser refuses to build an `AcmeConfig`
                // without this set, so agreeing here is the operator's choice,
                // not ours.
                terms_of_service_agreed: config.accept_terms_of_service,
                only_return_existing: false,
            },
            config.directory.url().to_string(),
            None,
        )
        .await?;

    store.save_account(&credentials)?;
    tracing::info!("Registered a new ACME account and saved its credentials");

    Ok(account)
}

/// Obtain a certificate covering `domains`
///
/// Returns the new certificate. The caller is responsible for putting it into
/// the certificate store; this function only writes it to disk.
pub async fn obtain(
    account: &Account,
    store: &AcmeStore,
    domains: &[ServedName],
    solvers: &[Box<dyn ChallengeSolver>],
) -> Result<CertificateBundle, AcmeError> {
    // Hold the store lock for the whole order, so that a second River process
    // - during a graceful upgrade, say - waits rather than placing a duplicate
    // order against the CA's rate limits.
    let _lock = store.lock()?;

    let id = CertificateId::for_domains(domains);

    // Another process may have obtained this while we waited for the lock.
    if let Some(existing) = store.load_certificate(&id)? {
        tracing::info!(
            certificate = %id,
            "Another process obtained this certificate while we waited"
        );
        return Ok(existing.bundle);
    }

    let identifiers: Vec<Identifier> = domains
        .iter()
        .map(|d| Identifier::Dns(d.to_string()))
        .collect();

    tracing::info!(
        certificate = %id,
        domains = ?identifiers,
        "Placing an ACME order"
    );

    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

    // Answer every authorization the order came back with. Track what we
    // published so it can be withdrawn afterwards, whether or not the order
    // succeeds.
    let mut presented: Vec<(usize, Challenge)> = Vec::new();
    let result = solve_authorizations(&mut order, solvers, &mut presented).await;

    for (solver_idx, challenge) in &presented {
        solvers[*solver_idx].cleanup(challenge).await;
    }

    result?;

    // The CA validates asynchronously, so wait for it to make up its mind.
    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        return Err(AcmeError::OrderNotReady(status));
    }

    // River generates its own key and CSR so that the key it will serve with
    // is produced by the same OpenSSL that terminates TLS.
    let csr::KeyAndCsr { key_pem, csr_der } = csr::generate(domains)?;
    order.finalize_csr(&csr_der).await?;

    let chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;
    let bundle = CertificateBundle {
        chain_pem: chain_pem.into_bytes(),
        key_pem,
    };

    // Check the CA gave us something we can actually serve before recording it
    // as the current certificate.
    crate::tls::store::Certificate::new(bundle.clone())?;

    let meta = CertificateMeta::now(domains, Some(order.url().to_string()));
    store.save_certificate(&id, &bundle, &meta)?;

    tracing::info!(certificate = %id, "Obtained and stored a new certificate");

    Ok(bundle)
}

/// Answer each pending authorization on the order
async fn solve_authorizations(
    order: &mut instant_acme::Order,
    solvers: &[Box<dyn ChallengeSolver>],
    presented: &mut Vec<(usize, Challenge)>,
) -> Result<(), AcmeError> {
    let mut authorizations = order.authorizations();

    while let Some(result) = authorizations.next().await {
        let mut authz = result?;

        match authz.status {
            // Already validated, often because a previous order for the same
            // domain succeeded and the authorization has not expired.
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            other => {
                return Err(AcmeError::ValidationFailed {
                    domain: authz.identifier().to_string(),
                    reason: Some(format!("authorization is {other:?}")),
                });
            }
        }

        // The identifier here never carries a `*.` prefix - a wildcard order is
        // validated against its parent domain - which is exactly what both
        // solvers want.
        let domain = match authz.identifier().identifier {
            Identifier::Dns(dns) => dns.clone(),
            other => {
                return Err(AcmeError::ValidationFailed {
                    domain: format!("{other:?}"),
                    reason: Some("River only manages DNS identifiers".into()),
                });
            }
        };

        // Pick the first solver whose challenge this authorization offers, so
        // that an order mixing wildcard and plain names can use a different
        // challenge for each. Read the challenge list rather than probing with
        // `challenge()`, which borrows the authorization mutably.
        let offered: Vec<&ChallengeType> = authz.challenges.iter().map(|c| &c.r#type).collect();
        let chosen = solvers
            .iter()
            .position(|s| offered.contains(&&s.challenge_type()));

        let Some(chosen) = chosen else {
            return Err(AcmeError::NoSuchChallenge {
                challenge: solvers
                    .iter()
                    .map(|s| format!("{:?}", s.challenge_type()))
                    .collect::<Vec<_>>()
                    .join(" or "),
                domain,
            });
        };

        let challenge_type = solvers[chosen].challenge_type();
        let mut handle = authz
            .challenge(challenge_type.clone())
            .expect("challenge was present a moment ago");

        let challenge = Challenge {
            domain: domain.clone(),
            token: handle.token.clone(),
            key_authorization: handle.key_authorization(),
        };

        tracing::info!(
            domain = %domain,
            challenge = ?challenge_type,
            "Answering an ACME challenge"
        );

        solvers[chosen].present(&challenge).await?;
        presented.push((chosen, challenge));

        // Only now tell the CA to go and check.
        handle.set_ready().await?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    fn names(names: &[&str]) -> Vec<ServedName> {
        names
            .iter()
            .map(|n| ServedName::parse(n).unwrap())
            .collect()
    }

    #[test]
    fn wildcards_are_ordered_with_their_prefix() {
        // RFC 8555 asks for the `*.` prefix on the order's identifier, and
        // hands back an authorization for the parent domain. Getting this
        // backwards produces a certificate for the wrong name.
        let identifiers: Vec<Identifier> = names(&["*.example.com", "example.com"])
            .iter()
            .map(|d| Identifier::Dns(d.to_string()))
            .collect();

        assert_eq!(
            identifiers,
            vec![
                Identifier::Dns("*.example.com".into()),
                Identifier::Dns("example.com".into()),
            ]
        );
    }
}
