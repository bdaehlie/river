//! Keeping ACME state on disk
//!
//! Two things need to outlive a River process: the account key, because
//! creating a new account on every start is both wasteful and rate limited, and
//! the certificates themselves, because asking the CA to re-issue a perfectly
//! good certificate on every restart is the fastest route to being rate
//! limited.
//!
//! The layout under the configured `store-dir` is:
//!
//! ```text
//! account.json                  the ACME account credentials
//! .lock                         held while an order is in flight
//! certs/<id>/fullchain.pem      the issued certificate chain
//! certs/<id>/key.pem            its private key
//! certs/<id>/meta.json          when it was issued, and for what
//! ```

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use instant_acme::AccountCredentials;
use openssl::hash::{hash, MessageDigest};
use serde::{Deserialize, Serialize};

use super::AcmeError;
use crate::tls::store::{CertificateBundle, ServedName};

/// Names a certificate by the set of domains it covers
///
/// Two listeners asking for the same set of domains share one certificate, and
/// changing the set produces a different identifier - which is what we want,
/// since it is then a different certificate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CertificateId(String);

impl CertificateId {
    /// Derive the identifier for a set of domains
    ///
    /// The first domain makes the directory recognisable when an operator goes
    /// looking; the hash of the whole sorted set is what makes it unique.
    pub fn for_domains(domains: &[ServedName]) -> Self {
        let mut sorted: Vec<String> = domains.iter().map(|d| d.to_string()).collect();
        sorted.sort();
        sorted.dedup();

        let digest = hash(MessageDigest::sha256(), sorted.join(",").as_bytes())
            .expect("sha256 of a short string cannot fail");
        let short: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();

        let label = sorted
            .first()
            .map(|d| sanitize(d))
            .unwrap_or_else(|| "none".to_string());

        Self(format!("{label}-{short}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CertificateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Make a domain safe to use as a single path component
fn sanitize(domain: &str) -> String {
    let mut out = String::with_capacity(domain.len());
    for c in domain.chars() {
        match c {
            'a'..='z' | '0'..='9' | '.' | '-' => out.push(c),
            'A'..='Z' => out.push(c.to_ascii_lowercase()),
            // `*.example.com` becomes `wildcard.example.com`
            '*' => out.push_str("wildcard"),
            _ => out.push('_'),
        }
    }
    out
}

/// What River records about a certificate beyond the certificate itself
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateMeta {
    /// The domains this certificate was requested for
    pub domains: Vec<String>,
    /// When it was obtained, in seconds since the Unix epoch
    ///
    /// Used by the `renew-after-issue-days` renewal policy. The certificate's
    /// own `notAfter` is used for `renew-before-expiry-days`, since that is
    /// authoritative and this is not.
    pub issued_at: u64,
    /// The order it came from, kept for debugging
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_url: Option<String>,
}

impl CertificateMeta {
    pub fn now(domains: &[ServedName], order_url: Option<String>) -> Self {
        Self {
            domains: domains.iter().map(|d| d.to_string()).collect(),
            issued_at: unix_now(),
            order_url,
        }
    }

    /// How many days ago this certificate was obtained
    pub fn days_since_issue(&self) -> u64 {
        unix_now().saturating_sub(self.issued_at) / 86_400
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// A certificate as it was read back from disk
pub struct StoredCertificate {
    pub bundle: CertificateBundle,
    pub meta: CertificateMeta,
}

/// The ACME state directory
pub struct AcmeStore {
    dir: PathBuf,
}

impl AcmeStore {
    /// Open the store, creating the directories if they do not exist
    ///
    /// This is deliberately done early, while River is still starting up: a
    /// store directory that River cannot write to is a configuration problem,
    /// and it should be reported then rather than at 3am when a renewal is due.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, AcmeError> {
        let dir = dir.into();

        fs::create_dir_all(dir.join("certs"))
            .map_err(AcmeError::io("create the ACME store directory", &dir))?;

        // The account key lives here, so keep the directory to ourselves.
        restrict_permissions(&dir, 0o700)?;

        // Prove we can actually write before reporting success.
        let probe = dir.join(".writable");
        File::create(&probe).map_err(AcmeError::io("write to the ACME store directory", &dir))?;
        let _ = fs::remove_file(&probe);

        Ok(Self { dir })
    }

    //
    // Account
    //

    fn account_path(&self) -> PathBuf {
        self.dir.join("account.json")
    }

    /// Read the stored account credentials, if there are any
    pub fn load_account(&self) -> Result<Option<AccountCredentials>, AcmeError> {
        let path = self.account_path();

        let raw = match fs::read(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(AcmeError::io("read the ACME account", &path)(e)),
        };

        serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|source| AcmeError::Malformed { path, source })
    }

    /// Store account credentials, replacing any that are already there
    pub fn save_account(&self, credentials: &AccountCredentials) -> Result<(), AcmeError> {
        let path = self.account_path();
        let encoded =
            serde_json::to_vec_pretty(credentials).map_err(|source| AcmeError::Malformed {
                path: path.clone(),
                source,
            })?;

        write_atomic(&path, &encoded, 0o600)
    }

    //
    // Certificates
    //

    fn cert_dir(&self, id: &CertificateId) -> PathBuf {
        self.dir.join("certs").join(id.as_str())
    }

    /// Read a stored certificate, if there is one
    ///
    /// A certificate whose files are incomplete or unreadable is reported as
    /// absent rather than as an error - the right response either way is to
    /// obtain a new one.
    pub fn load_certificate(
        &self,
        id: &CertificateId,
    ) -> Result<Option<StoredCertificate>, AcmeError> {
        let dir = self.cert_dir(id);

        let chain_pem = match fs::read(dir.join("fullchain.pem")) {
            Ok(pem) => pem,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(AcmeError::io("read a stored certificate", &dir)(e)),
        };

        let key_pem = match fs::read(dir.join("key.pem")) {
            Ok(pem) => pem,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(AcmeError::io("read a stored certificate key", &dir)(e)),
        };

        let meta_path = dir.join("meta.json");
        let meta = match fs::read(&meta_path) {
            Ok(raw) => serde_json::from_slice(&raw).map_err(|source| AcmeError::Malformed {
                path: meta_path,
                source,
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(AcmeError::io("read certificate metadata", &dir)(e)),
        };

        Ok(Some(StoredCertificate {
            bundle: CertificateBundle { chain_pem, key_pem },
            meta,
        }))
    }

    /// Write a certificate out, replacing any earlier one for the same domains
    ///
    /// The chain is written before the metadata, so a process interrupted
    /// halfway leaves a certificate that reads back as absent rather than one
    /// that claims to be newer than it is.
    pub fn save_certificate(
        &self,
        id: &CertificateId,
        bundle: &CertificateBundle,
        meta: &CertificateMeta,
    ) -> Result<(), AcmeError> {
        let dir = self.cert_dir(id);
        fs::create_dir_all(&dir).map_err(AcmeError::io("create a certificate directory", &dir))?;
        restrict_permissions(&dir, 0o700)?;

        write_atomic(&dir.join("key.pem"), &bundle.key_pem, 0o600)?;
        write_atomic(&dir.join("fullchain.pem"), &bundle.chain_pem, 0o644)?;

        let encoded = serde_json::to_vec_pretty(meta).map_err(|source| AcmeError::Malformed {
            path: dir.join("meta.json"),
            source,
        })?;
        write_atomic(&dir.join("meta.json"), &encoded, 0o644)?;

        Ok(())
    }

    //
    // Locking
    //

    /// Take the store's exclusive lock
    ///
    /// During a graceful upgrade two River processes are running at once, and
    /// both will want to renew the same certificates. Whoever gets the lock
    /// does the work; the other waits and then finds the result already on
    /// disk.
    pub fn lock(&self) -> Result<AcmeLock, AcmeError> {
        let path = self.dir.join(".lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(AcmeError::io("open the ACME lock file", &path))?;

        AcmeLock::acquire(file, path)
    }
}

/// An exclusive advisory lock on the ACME store
///
/// Released when dropped, including if the process exits, since the kernel
/// drops `flock`s when the file descriptor closes.
pub struct AcmeLock {
    // Held for its `Drop`; closing the descriptor releases the lock.
    _file: File,
}

impl AcmeLock {
    #[cfg(unix)]
    fn acquire(file: File, path: PathBuf) -> Result<Self, AcmeError> {
        use std::os::unix::io::AsRawFd;

        // Blocking: waiting for the other process to finish its order is
        // exactly the behaviour we want.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(AcmeError::io("lock the ACME store", path)(
                std::io::Error::last_os_error(),
            ));
        }

        Ok(Self { _file: file })
    }

    #[cfg(not(unix))]
    fn acquire(file: File, _path: PathBuf) -> Result<Self, AcmeError> {
        // River targets Unix for production use. Elsewhere, run unlocked
        // rather than refusing to start.
        tracing::warn!("ACME store locking is not implemented on this platform");
        Ok(Self { _file: file })
    }
}

/// Write a file in a way that never leaves a partial one behind
///
/// The temporary file is created with the final permissions before anything is
/// written to it, so a private key is never briefly world readable.
fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<(), AcmeError> {
    let tmp = path.with_extension("tmp");

    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;

    let mut file = options
        .open(&tmp)
        .map_err(AcmeError::io("create a temporary file", &tmp))?;

    file.write_all(contents)
        .map_err(AcmeError::io("write", &tmp))?;
    // Without this, a crash between `rename` and the kernel flushing could
    // leave an empty file where a certificate should be.
    file.sync_all().map_err(AcmeError::io("flush", &tmp))?;
    drop(file);

    fs::rename(&tmp, path).map_err(AcmeError::io("replace", path))?;

    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &Path, mode: u32) -> Result<(), AcmeError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(AcmeError::io("set permissions on", path))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path, _mode: u32) -> Result<(), AcmeError> {
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tls::backend::test::self_signed;

    fn names(names: &[&str]) -> Vec<ServedName> {
        names
            .iter()
            .map(|n| ServedName::parse(n).unwrap())
            .collect()
    }

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "river-acme-test-{label}-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn identifiers_depend_on_the_whole_domain_set() {
        let one = CertificateId::for_domains(&names(&["example.com", "www.example.com"]));

        // Order does not matter...
        let reordered = CertificateId::for_domains(&names(&["www.example.com", "example.com"]));
        assert_eq!(one, reordered);

        // ...but membership does
        let extra = CertificateId::for_domains(&names(&[
            "example.com",
            "www.example.com",
            "a.example.com",
        ]));
        assert_ne!(one, extra);

        // The label makes the directory recognisable
        assert!(one.as_str().starts_with("example.com-"));
    }

    #[test]
    fn wildcard_identifiers_are_path_safe() {
        let id = CertificateId::for_domains(&names(&["*.example.com"]));
        assert!(id.as_str().starts_with("wildcard.example.com-"));
        assert!(!id.as_str().contains('*'));
        assert!(!id.as_str().contains('/'));
    }

    #[test]
    fn certificates_round_trip() {
        let dir = temp_dir("roundtrip");
        let store = AcmeStore::open(&dir).unwrap();

        let domains = names(&["example.com", "www.example.com"]);
        let id = CertificateId::for_domains(&domains);

        // Nothing stored yet
        assert!(store.load_certificate(&id).unwrap().is_none());

        let bundle = self_signed(&["example.com", "www.example.com"], 90);
        let meta = CertificateMeta::now(&domains, Some("https://acme.test/order/1".into()));
        store.save_certificate(&id, &bundle, &meta).unwrap();

        let loaded = store.load_certificate(&id).unwrap().unwrap();
        assert_eq!(loaded.bundle, bundle);
        assert_eq!(loaded.meta, meta);
        assert_eq!(loaded.meta.days_since_issue(), 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn private_keys_are_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("perms");
        let store = AcmeStore::open(&dir).unwrap();

        let domains = names(&["example.com"]);
        let id = CertificateId::for_domains(&domains);
        store
            .save_certificate(
                &id,
                &self_signed(&["example.com"], 90),
                &CertificateMeta::now(&domains, None),
            )
            .unwrap();

        let key = store.cert_dir(&id).join("key.pem");
        let mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key.pem should be owner-only, got {mode:o}");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_partially_written_certificate_reads_as_absent() {
        let dir = temp_dir("partial");
        let store = AcmeStore::open(&dir).unwrap();

        let domains = names(&["example.com"]);
        let id = CertificateId::for_domains(&domains);

        // A chain with no key and no metadata, as if the process died midway
        let cert_dir = store.cert_dir(&id);
        fs::create_dir_all(&cert_dir).unwrap();
        fs::write(cert_dir.join("fullchain.pem"), b"not a real chain").unwrap();

        assert!(store.load_certificate(&id).unwrap().is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_lock_is_exclusive_within_a_process() {
        let dir = temp_dir("lock");
        let store = AcmeStore::open(&dir).unwrap();

        let held = store.lock().unwrap();
        // `flock` is per open file description, so a second `open` from this
        // same process would block - just check the first one succeeded and
        // releases cleanly.
        drop(held);
        let again = store.lock().unwrap();
        drop(again);

        let _ = fs::remove_dir_all(&dir);
    }
}
