//! Downstream TLS certificate handling
//!
//! River picks the certificate to serve per-connection, based on the Server
//! Name Indication (SNI) the client sends. That indirection is what makes
//! automatic certificate management possible: a certificate can be replaced
//! while the server is running, and a listener can start up before any
//! certificate for it exists.
//!
//! The pieces are split so that only one of them knows which TLS library is in
//! use:
//!
//! * [`store`] holds certificates and does the name matching. It only ever
//!   handles PEM bytes, which is also how certificates are kept on disk.
//! * [`backend`] is the only module that talks to OpenSSL. It parses PEM into
//!   the types the TLS library wants, and installs them into a handshake.
//! * [`resolver`] joins the two behind Pingora's `TlsAccept` trait.
//!
//! NOTE: Pingora only implements its certificate callback for the OpenSSL and
//! BoringSSL backends. Under the `rustls` backend, `TlsSettings::with_callbacks`
//! returns an error, and the handshake path ignores callbacks entirely. So this
//! design depends on River selecting the `openssl` feature for as long as that
//! remains true upstream. See <https://github.com/cloudflare/pingora/pull/599>
//! for the upstream work that would lift that restriction.

pub mod backend;
pub mod resolver;
pub mod store;

/// Something went wrong loading or serving a certificate
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    #[error("could not parse the certificate chain: {0}")]
    BadChain(String),

    #[error("the certificate chain contained no certificates")]
    EmptyChain,

    #[error("could not parse the private key: {0}")]
    BadKey(String),

    #[error("the private key does not match the leaf certificate")]
    KeyMismatch,

    #[error("could not install the certificate into the TLS handshake: {0}")]
    Install(String),

    #[error("'{0}' is not a valid DNS name")]
    BadName(String),
}
