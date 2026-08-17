//! Changes made to a request's or a response's headers
//!
//! Both directions support the same set of changes, so they share one
//! implementation. The request and response header types are distinct in
//! Pingora but expose the same operations, which is what [`Headers`] abstracts
//! over.

use http::{HeaderName, HeaderValue};
use pingora_http::{RequestHeader, ResponseHeader};

use crate::config::internal::HeaderModifier;

/// The header operations a modifier needs, on either kind of message
pub trait Headers {
    fn names(&self) -> Vec<HeaderName>;
    fn remove(&mut self, key: &HeaderName);
    fn upsert(&mut self, key: &HeaderName, value: &HeaderValue);
    fn append(&mut self, key: &HeaderName, value: &HeaderValue);
}

impl Headers for RequestHeader {
    fn names(&self) -> Vec<HeaderName> {
        self.headers.keys().cloned().collect()
    }
    fn remove(&mut self, key: &HeaderName) {
        self.remove_header(key);
    }
    fn upsert(&mut self, key: &HeaderName, value: &HeaderValue) {
        self.remove_header(key);
        // Both were validated when the configuration was parsed.
        let _ = self.append_header(key.clone(), value.clone());
    }
    fn append(&mut self, key: &HeaderName, value: &HeaderValue) {
        let _ = self.append_header(key.clone(), value.clone());
    }
}

impl Headers for ResponseHeader {
    fn names(&self) -> Vec<HeaderName> {
        self.headers.keys().cloned().collect()
    }
    fn remove(&mut self, key: &HeaderName) {
        self.remove_header(key);
    }
    fn upsert(&mut self, key: &HeaderName, value: &HeaderValue) {
        self.remove_header(key);
        let _ = self.append_header(key.clone(), value.clone());
    }
    fn append(&mut self, key: &HeaderName, value: &HeaderValue) {
        let _ = self.append_header(key.clone(), value.clone());
    }
}

/// Apply one configured change
pub fn apply(modifier: &HeaderModifier, headers: &mut impl Headers) {
    match modifier {
        HeaderModifier::RemoveHeaderKeyRegex { pattern } => {
            remove_matching(headers, |name| pattern.is_match(name));
        }
        HeaderModifier::RemoveHeaderKeyGlob { pattern } => {
            remove_matching(headers, |name| pattern.is_match(name));
        }
        HeaderModifier::RemoveHeader { key } => {
            headers.remove(key);
        }
        HeaderModifier::UpsertHeader { key, value } => {
            headers.upsert(key, value);
        }
        HeaderModifier::AppendHeader { key, value } => {
            headers.append(key, value);
        }
    }
}

/// Collect the names to remove before removing any of them
///
/// Removing while iterating the map is not possible, and a header may appear
/// more than once.
fn remove_matching(headers: &mut impl Headers, matches: impl Fn(&str) -> bool) {
    let doomed: Vec<HeaderName> = headers
        .names()
        .into_iter()
        .filter(|name| matches(name.as_str()))
        .collect();

    for name in doomed {
        tracing::debug!(header = %name, "Removing header");
        headers.remove(&name);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::proxy::{glob::Glob, rate_limiting::RegexShim};

    fn request() -> RequestHeader {
        let mut h = RequestHeader::build("GET", b"/", None).unwrap();
        h.append_header("x-internal-trace", "abc").unwrap();
        h.append_header("x-internal-span", "def").unwrap();
        h.append_header("x-keep", "yes").unwrap();
        h.append_header("accept-encoding", "gzip").unwrap();
        h
    }

    fn names(h: &RequestHeader) -> Vec<String> {
        let mut n: Vec<String> = h.headers.keys().map(|k| k.as_str().to_string()).collect();
        n.sort();
        n
    }

    #[test]
    fn a_glob_removes_the_headers_it_matches() {
        let mut h = request();
        apply(
            &HeaderModifier::RemoveHeaderKeyGlob {
                pattern: Glob::new("x-internal-*"),
            },
            &mut h,
        );
        assert_eq!(names(&h), vec!["accept-encoding", "x-keep"]);
    }

    #[test]
    fn a_regex_removes_the_headers_it_matches() {
        let mut h = request();
        apply(
            &HeaderModifier::RemoveHeaderKeyRegex {
                pattern: RegexShim::new("^x-internal-").unwrap(),
            },
            &mut h,
        );
        assert_eq!(names(&h), vec!["accept-encoding", "x-keep"]);
    }

    #[test]
    fn an_exact_removal_takes_only_that_header() {
        let mut h = request();
        apply(
            &HeaderModifier::RemoveHeader {
                key: HeaderName::from_static("x-internal-trace"),
            },
            &mut h,
        );
        assert_eq!(
            names(&h),
            vec!["accept-encoding", "x-internal-span", "x-keep"]
        );
    }

    #[test]
    fn upsert_replaces_and_append_does_not() {
        let mut h = request();
        let key = HeaderName::from_static("accept-encoding");

        apply(
            &HeaderModifier::AppendHeader {
                key: key.clone(),
                value: HeaderValue::from_static("br"),
            },
            &mut h,
        );
        assert_eq!(h.headers.get_all(&key).iter().count(), 2);

        apply(
            &HeaderModifier::UpsertHeader {
                key: key.clone(),
                value: HeaderValue::from_static("identity"),
            },
            &mut h,
        );
        let values: Vec<&str> = h
            .headers
            .get_all(&key)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(values, vec!["identity"]);
    }

    /// Removing a header that appears more than once should take every copy,
    /// not just the first.
    #[test]
    fn removal_takes_every_copy_of_a_repeated_header() {
        let mut h = request();
        h.append_header("x-internal-trace", "second").unwrap();
        assert_eq!(h.headers.get_all("x-internal-trace").iter().count(), 2);

        apply(
            &HeaderModifier::RemoveHeaderKeyGlob {
                pattern: Glob::new("x-internal-trace"),
            },
            &mut h,
        );
        assert_eq!(h.headers.get_all("x-internal-trace").iter().count(), 0);
    }
}
