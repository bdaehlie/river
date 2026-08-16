//! Storage and SNI lookup of certificates
//!
//! Nothing in this module knows which TLS library River uses - certificates are
//! held as PEM bytes, in the same form they are written to disk, alongside a
//! parsed representation that [`super::backend`] produces.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use super::{backend::ParsedCertificate, CertificateError};

/// A certificate chain and its private key, as stored on disk
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateBundle {
    /// PEM encoded certificate chain, leaf certificate first
    pub chain_pem: Vec<u8>,
    /// PEM encoded private key
    pub key_pem: Vec<u8>,
}

/// A certificate that has been parsed and is ready to serve
pub struct Certificate {
    bundle: CertificateBundle,
    parsed: ParsedCertificate,
}

impl Certificate {
    /// Parse and validate a certificate bundle
    ///
    /// This checks that the chain and key can be read, and that they belong
    /// together - a mismatched pair is much better caught here than during a
    /// handshake, where there is no way to report it to the client.
    pub fn new(bundle: CertificateBundle) -> Result<Self, CertificateError> {
        let parsed = ParsedCertificate::from_bundle(&bundle)?;
        Ok(Self { bundle, parsed })
    }

    /// The PEM form of this certificate
    pub fn bundle(&self) -> &CertificateBundle {
        &self.bundle
    }

    /// The parsed form of this certificate
    pub fn parsed(&self) -> &ParsedCertificate {
        &self.parsed
    }
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the bundle - it contains a private key.
        f.debug_struct("Certificate")
            .field("dns_names", &self.parsed.dns_names())
            .finish_non_exhaustive()
    }
}

/// A DNS name that a certificate can be served for
///
/// Names are held lowercased and without any trailing dot, so that comparison
/// against the SNI a client sends is a plain string comparison.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServedName {
    /// An exact name, such as `example.com`
    Exact(String),
    /// A wildcard name, such as `*.example.com`
    ///
    /// The contained string is the parent domain, without the leading `*.`.
    Wildcard(String),
}

impl ServedName {
    /// Parse a name as it was written in the configuration file
    pub fn parse(name: &str) -> Result<Self, CertificateError> {
        let bad = || CertificateError::BadName(name.to_string());
        let normalized = normalize(name);

        let (parent, wildcard) = match normalized.strip_prefix("*.") {
            Some(parent) => (parent, true),
            None => (normalized.as_str(), false),
        };

        if !is_plausible_dns_name(parent) {
            return Err(bad());
        }

        // A wildcard needs something to be a wildcard *of*. `*.com` is
        // technically well formed but no CA will issue it, and it is far more
        // likely to be a typo than an intent.
        if wildcard && !parent.contains('.') {
            return Err(bad());
        }

        Ok(match wildcard {
            true => ServedName::Wildcard(parent.to_string()),
            false => ServedName::Exact(parent.to_string()),
        })
    }

    /// Does this name cover `sni`?
    ///
    /// `sni` is expected to already be normalized by [`normalize`].
    pub fn matches(&self, sni: &str) -> bool {
        match self {
            ServedName::Exact(name) => name == sni,
            ServedName::Wildcard(parent) => is_wildcard_child(parent, sni),
        }
    }

    /// Is this a wildcard name?
    ///
    /// Wildcards can only be issued against a `dns-01` challenge, so callers
    /// need to be able to ask.
    pub fn is_wildcard(&self) -> bool {
        matches!(self, ServedName::Wildcard(_))
    }
}

impl std::fmt::Display for ServedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServedName::Exact(name) => write!(f, "{name}"),
            ServedName::Wildcard(parent) => write!(f, "*.{parent}"),
        }
    }
}

/// Put a name into the form used for comparisons
///
/// DNS names are case insensitive, and may be written with a trailing dot to
/// mark them as fully qualified.
pub fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Does `sni` sit exactly one label below `parent`?
///
/// A wildcard matches a single label only: `*.example.com` covers
/// `www.example.com`, but neither `example.com` itself nor
/// `a.b.example.com`.
fn is_wildcard_child(parent: &str, sni: &str) -> bool {
    let Some(label) = sni.strip_suffix(parent) else {
        return false;
    };
    let Some(label) = label.strip_suffix('.') else {
        return false;
    };
    !label.is_empty() && !label.contains('.')
}

/// A cheap sanity check, not a full RFC 1035 validation
///
/// The certificate authority is the real authority on whether a name can be
/// issued for. This exists to catch obvious configuration mistakes - a URL
/// pasted in place of a hostname, an empty entry from a stray comma - while
/// the operator is still looking at the config file.
fn is_plausible_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }

    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// The certificates River is currently able to serve
///
/// This is shared between the listeners that read from it during a handshake
/// and the ACME service that writes to it as certificates are issued and
/// renewed. Replacing a certificate is just an insert - connections that are
/// already established keep the certificate they handshook with, and the next
/// handshake picks up the new one.
#[derive(Default)]
pub struct CertStore {
    inner: RwLock<StoreInner>,
}

#[derive(Default)]
struct StoreInner {
    exact: HashMap<String, Arc<Certificate>>,
    /// Keyed by the parent domain, so `*.example.com` is stored as `example.com`
    wildcard: HashMap<String, Arc<Certificate>>,
}

impl CertStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `cert` under each of `names`
    ///
    /// Any certificate already registered under one of those names is replaced.
    pub fn insert(&self, names: &[ServedName], cert: Arc<Certificate>) {
        let mut inner = self.write();
        for name in names {
            match name {
                ServedName::Exact(name) => {
                    inner.exact.insert(name.clone(), cert.clone());
                }
                ServedName::Wildcard(parent) => {
                    inner.wildcard.insert(parent.clone(), cert.clone());
                }
            }
        }
    }

    /// Find the certificate to serve for a given SNI
    ///
    /// An exact match always wins over a wildcard, which matches how clients
    /// and CAs treat the two.
    pub fn get(&self, sni: &str) -> Option<Arc<Certificate>> {
        let sni = normalize(sni);
        let inner = self.read();

        if let Some(cert) = inner.exact.get(&sni) {
            return Some(cert.clone());
        }

        // Only the immediate parent can match, since a wildcard covers exactly
        // one label.
        let (_label, parent) = sni.split_once('.')?;
        inner.wildcard.get(parent).cloned()
    }

    /// Is a certificate registered for every one of `names`?
    ///
    /// Used to decide whether the ACME service still has work to do before it
    /// can report itself ready.
    pub fn covers_all(&self, names: &[ServedName]) -> bool {
        let inner = self.read();
        names.iter().all(|name| match name {
            ServedName::Exact(name) => inner.exact.contains_key(name),
            ServedName::Wildcard(parent) => inner.wildcard.contains_key(parent),
        })
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, StoreInner> {
        // The only code that runs under this lock is `HashMap` access, which
        // cannot panic, so a poisoned lock would have to come from somewhere
        // else entirely. Recover rather than cascade a failure into every
        // subsequent handshake.
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, StoreInner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses_names() {
        assert_eq!(
            ServedName::parse("example.com").unwrap(),
            ServedName::Exact("example.com".into())
        );
        // Case and trailing dots are normalized away
        assert_eq!(
            ServedName::parse("  WWW.Example.COM. ").unwrap(),
            ServedName::Exact("www.example.com".into())
        );
        assert_eq!(
            ServedName::parse("*.example.com").unwrap(),
            ServedName::Wildcard("example.com".into())
        );
    }

    #[test]
    fn rejects_implausible_names() {
        for bad in [
            "",
            " ",
            "example..com",
            "https://example.com",
            "example.com/path",
            "exa mple.com",
            "-example.com",
            "example-.com",
            // A wildcard needs a parent domain to be a wildcard of
            "*.com",
            "*",
            // Only a leading `*.` is a wildcard
            "www.*.example.com",
        ] {
            assert!(
                ServedName::parse(bad).is_err(),
                "expected '{bad}' to be rejected"
            );
        }
    }

    #[test]
    fn wildcards_match_exactly_one_label() {
        let wild = ServedName::parse("*.example.com").unwrap();

        assert!(wild.matches("www.example.com"));
        assert!(wild.matches("anything.example.com"));

        // The parent itself is not covered by its own wildcard
        assert!(!wild.matches("example.com"));
        // Neither is a deeper name
        assert!(!wild.matches("a.b.example.com"));
        // Nor a name that merely ends with the same text
        assert!(!wild.matches("notexample.com"));
        assert!(!wild.matches("www.notexample.com"));
    }

    #[test]
    fn exact_names_match_only_themselves() {
        let exact = ServedName::parse("example.com").unwrap();

        assert!(exact.matches("example.com"));
        assert!(!exact.matches("www.example.com"));
        assert!(!exact.matches("example.com.evil.test"));
    }
}
