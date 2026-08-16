//! Automatic certificate management, using ACME (RFC 8555)
//!
//! River can obtain and renew TLS certificates from a certificate authority
//! such as Let's Encrypt, without an operator having to run anything by hand.
//!
//! The protocol work is done by the `instant-acme` crate. What lives here is
//! everything around it:
//!
//! * [`store`] keeps the account key and issued certificates on disk, so a
//!   restart does not mean asking the CA for another certificate. Certificate
//!   authorities enforce rate limits, and re-issuing on every restart is the
//!   quickest way to hit them.
//! * [`csr`] generates the certificate keypair and signing request with
//!   OpenSSL, so that the key River serves with is produced by the same library
//!   that serves it.
//! * [`solver`] is how River proves it controls a domain, with [`http01`] and
//!   [`dns01`] implementing the two ways it can do that.
//! * [`order`] drives one certificate order from start to finish.
//!
//! Certificates end up in the [`CertStore`][crate::tls::store::CertStore],
//! where the TLS listeners read them during a handshake.

pub mod csr;
pub mod dns01;
pub mod http01;
pub mod order;
pub mod service;
pub mod solver;
pub mod store;

/// Something went wrong obtaining or storing a certificate
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("ACME protocol error: {0}")]
    Protocol(#[from] instant_acme::Error),

    #[error("could not {action} {path}: {source}")]
    Io {
        action: &'static str,
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not read {path}: {source}")]
    Malformed {
        path: std::path::PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("could not generate a certificate signing request: {0}")]
    Csr(String),

    #[error("the certificate the CA issued is not usable: {0}")]
    Certificate(#[from] crate::tls::CertificateError),

    #[error("the CA offered no '{challenge}' challenge for '{domain}'")]
    NoSuchChallenge { challenge: String, domain: String },

    #[error("the CA could not validate '{domain}'{}", reason.as_ref().map(|r| format!(": {r}")).unwrap_or_default())]
    ValidationFailed {
        domain: String,
        reason: Option<String>,
    },

    #[error("the order did not become ready (status: {0:?})")]
    OrderNotReady(instant_acme::OrderStatus),

    #[error("could not publish the challenge response for '{domain}': {reason}")]
    Solver { domain: String, reason: String },
}

impl AcmeError {
    pub(crate) fn io(
        action: &'static str,
        path: impl Into<std::path::PathBuf>,
    ) -> impl FnOnce(std::io::Error) -> Self {
        let path = path.into();
        move |source| AcmeError::Io {
            action,
            path,
            source,
        }
    }
}
