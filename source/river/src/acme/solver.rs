//! Proving control of a domain
//!
//! A certificate authority will not issue a certificate until River has shown
//! it controls the domain. RFC 8555 defines several ways to do that; River
//! implements the two that matter for a reverse proxy:
//!
//! * `http-01` serves a token over plain HTTP on port 80. This is the default,
//!   and needs no configuration beyond a reachable listener.
//! * `dns-01` publishes a TXT record. It is more work to set up, but it is the
//!   only challenge a CA will accept for a wildcard domain.

use async_trait::async_trait;
use instant_acme::{ChallengeType, KeyAuthorization};

use super::AcmeError;

/// What a solver needs to know to answer one challenge
pub struct Challenge {
    /// The domain being validated
    ///
    /// This never carries a `*.` prefix, even for a wildcard order: the ACME
    /// server validates the parent domain. For `*.example.com`, this is
    /// `example.com`, and the TXT record goes at `_acme-challenge.example.com`.
    pub domain: String,

    /// The challenge token
    ///
    /// For `http-01` this is the last path segment of the URL the CA fetches.
    pub token: String,

    /// The value proving River holds the account key
    pub key_authorization: KeyAuthorization,
}

impl Challenge {
    /// The path an `http-01` challenge is served at
    pub fn http_path(&self) -> String {
        format!("{HTTP01_PREFIX}{}", self.token)
    }

    /// The name of the TXT record a `dns-01` challenge is published at
    pub fn dns_record_name(&self) -> String {
        format!("_acme-challenge.{}", self.domain)
    }

    /// The value of that TXT record
    pub fn dns_record_value(&self) -> String {
        self.key_authorization.dns_value()
    }
}

/// The URL prefix a certificate authority fetches `http-01` challenges from
pub const HTTP01_PREFIX: &str = "/.well-known/acme-challenge/";

/// Publishes and retracts challenge responses
#[async_trait]
pub trait ChallengeSolver: Send + Sync {
    /// Which challenge this solver answers
    fn challenge_type(&self) -> ChallengeType;

    /// Make the response available to the certificate authority
    ///
    /// This must not return until the response is actually retrievable - the CA
    /// may check immediately, and a failed validation costs a retry against the
    /// CA's rate limits.
    async fn present(&self, challenge: &Challenge) -> Result<(), AcmeError>;

    /// Withdraw the response
    ///
    /// Called whether or not validation succeeded, so it must tolerate being
    /// asked to remove something that was never published.
    async fn cleanup(&self, challenge: &Challenge);
}

#[cfg(test)]
mod test {
    use super::*;

    /// A fake key authorization, so tests can build a `Challenge`
    ///
    /// `KeyAuthorization` has no public constructor, so this reaches for the
    /// one place that does hand one out.
    #[test]
    fn builds_challenge_locations() {
        // Only the parts that do not need a `KeyAuthorization`
        let prefix = HTTP01_PREFIX;
        assert_eq!(prefix, "/.well-known/acme-challenge/");
        assert!(prefix.ends_with('/'));
    }
}
