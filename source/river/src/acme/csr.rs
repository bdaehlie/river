//! Generating the certificate keypair and signing request
//!
//! `instant-acme` can build a CSR itself, using `rcgen`, but River generates its
//! own so that the private key it ends up serving is produced and handled by
//! the same OpenSSL that Pingora terminates TLS with.

use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    stack::Stack,
    x509::{extension::SubjectAlternativeName, X509Extension, X509NameBuilder, X509ReqBuilder},
};

use super::AcmeError;
use crate::tls::store::ServedName;

/// A freshly generated keypair and the CSR that goes with it
pub struct KeyAndCsr {
    /// PEM encoded private key, to be stored alongside the issued certificate
    pub key_pem: Vec<u8>,
    /// DER encoded certificate signing request, to be sent to the CA
    pub csr_der: Vec<u8>,
}

/// Generate a P-256 keypair and a CSR covering `domains`
///
/// The subject is left empty. Certificate authorities derive the certificate's
/// names from the Subject Alternative Name extension, and Let's Encrypt ignores
/// the subject entirely.
pub fn generate(domains: &[ServedName]) -> Result<KeyAndCsr, AcmeError> {
    let err = |what: &str| {
        let what = what.to_string();
        move |e: openssl::error::ErrorStack| AcmeError::Csr(format!("{what}: {e}"))
    };

    if domains.is_empty() {
        return Err(AcmeError::Csr("no domains to request".into()));
    }

    // P-256 keys are what CAs and clients handle best today, and are what
    // `rcgen` would have produced.
    let group =
        EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(err("selecting a curve"))?;
    let key = PKey::from_ec_key(EcKey::generate(&group).map_err(err("generating a key"))?)
        .map_err(err("generating a key"))?;

    let mut builder = X509ReqBuilder::new().map_err(err("starting a request"))?;
    builder.set_version(0).map_err(err("setting the version"))?;

    let subject = X509NameBuilder::new()
        .map_err(err("building the subject"))?
        .build();
    builder
        .set_subject_name(&subject)
        .map_err(err("setting the subject"))?;
    builder
        .set_pubkey(&key)
        .map_err(err("setting the public key"))?;

    let mut san = SubjectAlternativeName::new();
    for domain in domains {
        san.dns(&domain.to_string());
    }
    let san: X509Extension = san
        .build(&builder.x509v3_context(None))
        .map_err(err("building the SAN extension"))?;

    let mut extensions = Stack::new().map_err(err("building the extension list"))?;
    extensions
        .push(san)
        .map_err(err("building the extension list"))?;
    builder
        .add_extensions(&extensions)
        .map_err(err("adding extensions"))?;

    builder
        .sign(&key, MessageDigest::sha256())
        .map_err(err("signing the request"))?;

    Ok(KeyAndCsr {
        key_pem: key
            .private_key_to_pem_pkcs8()
            .map_err(err("serializing the key"))?,
        csr_der: builder
            .build()
            .to_der()
            .map_err(err("serializing the request"))?,
    })
}

/// The private key type, exposed for tests
#[allow(dead_code)]
pub(crate) type CsrKey = PKey<Private>;

#[cfg(test)]
mod test {
    use super::*;
    use openssl::x509::X509Req;

    fn names(names: &[&str]) -> Vec<ServedName> {
        names
            .iter()
            .map(|n| ServedName::parse(n).unwrap())
            .collect()
    }

    #[test]
    fn produces_a_verifiable_request() {
        let KeyAndCsr { key_pem, csr_der } = generate(&names(&["example.com"])).unwrap();

        let req = X509Req::from_der(&csr_der).unwrap();

        // The CA checks this signature, so a CSR that does not verify against
        // its own public key would be rejected with a confusing error.
        let public = req.public_key().unwrap();
        assert!(req.verify(&public).unwrap());

        // The key we keep is the one the CSR commits to
        let key = PKey::private_key_from_pem(&key_pem).unwrap();
        assert!(public.public_eq(&key));
    }

    #[test]
    fn requests_every_domain_as_a_san() {
        let domains = ["example.com", "www.example.com", "*.api.example.com"];
        let KeyAndCsr { csr_der, .. } = generate(&names(&domains)).unwrap();

        let req = X509Req::from_der(&csr_der).unwrap();
        assert_eq!(
            req.extensions().unwrap().len(),
            1,
            "expected exactly one extension, the SAN list"
        );

        // DNS names are carried as plain ASCII inside the SAN extension, so
        // this is enough to show each one made it into the request the CA
        // will see.
        for domain in domains {
            assert!(
                csr_der
                    .windows(domain.len())
                    .any(|w| w == domain.as_bytes()),
                "'{domain}' is missing from the request"
            );
        }
    }

    #[test]
    fn rejects_an_empty_domain_list() {
        assert!(generate(&[]).is_err());
    }
}
