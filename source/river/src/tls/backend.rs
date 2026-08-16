//! The OpenSSL specific half of certificate handling
//!
//! This is deliberately the only module in River that names OpenSSL types. If
//! Pingora's `rustls` backend grows a way to resolve certificates during a
//! handshake, replacing this module and [`super::resolver`] is the whole of the
//! work - the certificate store, the ACME client, and the configuration are all
//! backend neutral.

use openssl::{
    asn1::Asn1Time,
    error::ErrorStack,
    pkey::{PKey, Private},
    x509::X509,
};
use pingora_core::{
    protocols::tls::TlsRef,
    tls::ext::{ssl_add_chain_cert, ssl_use_certificate, ssl_use_private_key},
};

use super::{store::CertificateBundle, CertificateError};

/// A certificate chain and key, parsed into the types OpenSSL wants
///
/// Parsing happens once, when the certificate is loaded, rather than on every
/// handshake.
pub struct ParsedCertificate {
    leaf: X509,
    /// Intermediates, in the order they appeared in the chain
    intermediates: Vec<X509>,
    key: PKey<Private>,
}

impl ParsedCertificate {
    /// Parse and validate a PEM certificate bundle
    pub fn from_bundle(bundle: &CertificateBundle) -> Result<Self, CertificateError> {
        let mut chain = X509::stack_from_pem(&bundle.chain_pem)
            .map_err(|e| CertificateError::BadChain(e.to_string()))?;

        if chain.is_empty() {
            return Err(CertificateError::EmptyChain);
        }
        let leaf = chain.remove(0);

        let key = PKey::private_key_from_pem(&bundle.key_pem)
            .map_err(|e| CertificateError::BadKey(e.to_string()))?;

        // Catch a mismatched pair now. During a handshake there is no way to
        // tell the client what went wrong, and the failure looks like a
        // generic TLS error from the outside.
        let leaf_public = leaf
            .public_key()
            .map_err(|e| CertificateError::BadChain(e.to_string()))?;
        if !leaf_public.public_eq(&key) {
            return Err(CertificateError::KeyMismatch);
        }

        Ok(Self {
            leaf,
            intermediates: chain,
            key,
        })
    }

    /// Install this certificate into an in-progress handshake
    pub fn install(&self, ssl: &mut TlsRef) -> Result<(), CertificateError> {
        let err = |e: ErrorStack| CertificateError::Install(e.to_string());

        ssl_use_certificate(ssl, &self.leaf).map_err(err)?;
        ssl_use_private_key(ssl, &self.key).map_err(err)?;
        for intermediate in &self.intermediates {
            ssl_add_chain_cert(ssl, intermediate).map_err(err)?;
        }

        Ok(())
    }

    /// The DNS names in the leaf certificate's Subject Alternative Names
    ///
    /// This is what the certificate is actually valid for, as opposed to what
    /// River asked for, which makes it the right thing to key the store on
    /// after loading a certificate back from disk.
    pub fn dns_names(&self) -> Vec<String> {
        let Some(alt_names) = self.leaf.subject_alt_names() else {
            return Vec::new();
        };

        alt_names
            .iter()
            .filter_map(|name| name.dnsname())
            .map(super::store::normalize)
            .collect()
    }

    /// How many days until the leaf certificate expires
    ///
    /// Negative once the certificate has expired. OpenSSL can compare ASN.1
    /// times directly, which avoids pulling in a date library just for this.
    pub fn days_until_expiry(&self) -> Result<i32, CertificateError> {
        let now =
            Asn1Time::days_from_now(0).map_err(|e| CertificateError::BadChain(e.to_string()))?;

        let diff = now
            .diff(self.leaf.not_after())
            .map_err(|e| CertificateError::BadChain(e.to_string()))?;

        Ok(diff.days)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    /// Build a self signed certificate covering `names`, valid for `days`
    ///
    /// Shared with the tests for the certificate store and resolver.
    pub(crate) fn self_signed(names: &[&str], days: u32) -> CertificateBundle {
        use openssl::{
            bn::{BigNum, MsbOption},
            ec::{EcGroup, EcKey},
            hash::MessageDigest,
            nid::Nid,
            x509::{extension::SubjectAlternativeName, X509NameBuilder},
        };

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", names[0]).unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();

        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();

        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(days).unwrap())
            .unwrap();

        let mut san = SubjectAlternativeName::new();
        for n in names {
            san.dns(n);
        }
        let san = san.build(&builder.x509v3_context(None, None)).unwrap();
        builder.append_extension(san).unwrap();

        builder.sign(&key, MessageDigest::sha256()).unwrap();

        CertificateBundle {
            chain_pem: builder.build().to_pem().unwrap(),
            key_pem: key.private_key_to_pem_pkcs8().unwrap(),
        }
    }

    #[test]
    fn parses_a_valid_bundle() {
        let bundle = self_signed(&["example.com", "www.example.com"], 30);
        let parsed = ParsedCertificate::from_bundle(&bundle).unwrap();

        assert_eq!(
            parsed.dns_names(),
            vec!["example.com".to_string(), "www.example.com".to_string()]
        );
    }

    #[test]
    fn reports_days_until_expiry() {
        let parsed = ParsedCertificate::from_bundle(&self_signed(&["example.com"], 30)).unwrap();

        // Allow a day of slack, since the comparison is against the wall clock.
        let days = parsed.days_until_expiry().unwrap();
        assert!((29..=30).contains(&days), "unexpected days: {days}");
    }

    #[test]
    fn rejects_a_mismatched_key() {
        let mixed = CertificateBundle {
            chain_pem: self_signed(&["example.com"], 30).chain_pem,
            key_pem: self_signed(&["other.example.com"], 30).key_pem,
        };

        assert!(matches!(
            ParsedCertificate::from_bundle(&mixed),
            Err(CertificateError::KeyMismatch)
        ));
    }

    #[test]
    fn rejects_an_empty_chain() {
        let empty = CertificateBundle {
            chain_pem: Vec::new(),
            key_pem: self_signed(&["example.com"], 30).key_pem,
        };

        assert!(matches!(
            ParsedCertificate::from_bundle(&empty),
            Err(CertificateError::EmptyChain)
        ));
    }
}
