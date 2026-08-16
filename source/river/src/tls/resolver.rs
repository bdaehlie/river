//! Choosing a certificate during the TLS handshake

use std::sync::Arc;

use async_trait::async_trait;
use pingora_core::{
    listeners::{TlsAccept, TlsAcceptCallbacks},
    protocols::tls::TlsRef,
    tls::ssl::NameType,
};

use super::store::CertStore;

/// Serves certificates out of a [`CertStore`], picked by SNI
///
/// Pingora pauses the handshake after the ClientHello and calls
/// [`TlsAccept::certificate_callback`], which is where a certificate can be
/// chosen for the name the client asked for.
pub struct CertResolver {
    store: Arc<CertStore>,
}

impl CertResolver {
    pub fn new(store: Arc<CertStore>) -> Self {
        Self { store }
    }

    /// Build this resolver in the form `TlsSettings::with_callbacks` wants
    pub fn callbacks(store: Arc<CertStore>) -> TlsAcceptCallbacks {
        Box::new(Self::new(store))
    }
}

#[async_trait]
impl TlsAccept for CertResolver {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        // `servername` borrows from `ssl`, which we need mutably below.
        let sni = ssl.servername(NameType::HOST_NAME).map(str::to_owned);

        let Some(sni) = sni else {
            // Not an error on its own: the listener may have a certificate
            // configured statically, which OpenSSL will fall back to.
            tracing::debug!(
                "TLS handshake sent no SNI, using the listener's default certificate if it has one"
            );
            return;
        };

        let Some(cert) = self.store.get(&sni) else {
            tracing::warn!(
                sni = %sni,
                "No certificate available for this name, using the listener's default \
                 certificate if it has one"
            );
            return;
        };

        // There is no way to signal failure from this callback - it returns
        // `()`. If installing the certificate fails, the handshake carries on
        // with whatever the listener was built with, which is either the
        // static fallback certificate or nothing at all. Log loudly, because
        // from the client's side this looks like a generic TLS failure.
        if let Err(e) = cert.parsed().install(ssl) {
            tracing::error!(
                sni = %sni,
                error = %e,
                "Failed to install the certificate for this name"
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tls::{
        backend::test::self_signed,
        store::{Certificate, ServedName},
    };

    fn store_with(names: &[&str]) -> Arc<CertStore> {
        let store = Arc::new(CertStore::new());
        let cert = Arc::new(Certificate::new(self_signed(names, 30)).unwrap());
        let served: Vec<ServedName> = names
            .iter()
            .map(|n| ServedName::parse(n).unwrap())
            .collect();
        store.insert(&served, cert);
        store
    }

    #[test]
    fn resolves_exact_names() {
        let store = store_with(&["example.com", "www.example.com"]);

        assert!(store.get("example.com").is_some());
        assert!(store.get("www.example.com").is_some());
        // SNI comparison is case insensitive
        assert!(store.get("WWW.Example.com").is_some());
        assert!(store.get("other.example.com").is_none());
    }

    #[test]
    fn resolves_wildcards() {
        let store = store_with(&["*.example.com"]);

        assert!(store.get("www.example.com").is_some());
        // A wildcard does not cover its own parent
        assert!(store.get("example.com").is_none());
        // Nor a deeper name
        assert!(store.get("a.b.example.com").is_none());
    }

    #[test]
    fn exact_names_win_over_wildcards() {
        let store = Arc::new(CertStore::new());

        let wild = Arc::new(Certificate::new(self_signed(&["*.example.com"], 30)).unwrap());
        store.insert(&[ServedName::parse("*.example.com").unwrap()], wild);

        let exact = Arc::new(Certificate::new(self_signed(&["www.example.com"], 90)).unwrap());
        store.insert(&[ServedName::parse("www.example.com").unwrap()], exact);

        // Both could serve `www.example.com`; the exact match is the one with
        // the 90 day lifetime.
        let resolved = store.get("www.example.com").unwrap();
        assert_eq!(resolved.parsed().dns_names(), vec!["www.example.com"]);

        // The wildcard still covers everything else
        assert!(store.get("other.example.com").is_some());
    }

    #[test]
    fn replacing_a_certificate_takes_effect() {
        let store = store_with(&["example.com"]);
        let before = store.get("example.com").unwrap();
        assert!(before.parsed().days_until_expiry().unwrap() <= 30);

        // A renewal is just an insert over the same name
        let renewed = Arc::new(Certificate::new(self_signed(&["example.com"], 90)).unwrap());
        store.insert(&[ServedName::parse("example.com").unwrap()], renewed);

        let after = store.get("example.com").unwrap();
        assert!(after.parsed().days_until_expiry().unwrap() > 30);
    }

    #[test]
    fn reports_coverage() {
        let store = store_with(&["example.com", "*.example.com"]);

        let names = |ns: &[&str]| -> Vec<ServedName> {
            ns.iter().map(|n| ServedName::parse(n).unwrap()).collect()
        };

        assert!(store.covers_all(&names(&["example.com", "*.example.com"])));
        assert!(!store.covers_all(&names(&["example.com", "other.test"])));
    }
}
