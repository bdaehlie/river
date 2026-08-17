//! Normalizing and checking requests before anything else looks at them
//!
//! Requirement 8 of the milestone. Two jobs, really: putting a request into a
//! canonical form so that later filters cannot be fooled by an unusual
//! spelling of the same thing, and rejecting requests that are malformed in
//! ways that tend to mean an attack.
//!
//! ## What is deliberately not here
//!
//! The requirement says the implementation must not duplicate what Pingora
//! already does. Checked against pingora-core 0.8.1 and httparse 1.8:
//!
//! * **Duplicate `Content-Length`** is rejected by Pingora
//!   (`check_dup_content_length`).
//! * **`Transfer-Encoding` with `Content-Length`** is handled by Pingora: it
//!   removes the `Content-Length` and disables keepalive, per RFC 9112 §6.1.
//!   River cannot even see this case - by the time a filter runs, the
//!   `Content-Length` is gone - so a check here could never fire.
//! * **A non-chunked final `Transfer-Encoding`**, and `Transfer-Encoding` on an
//!   HTTP/1.0 request, are both rejected by Pingora.
//! * **Control characters in header values** are rejected by httparse, which
//!   permits only HTAB, space, `0x21..=0x7E`, and `0x80..`. So a control
//!   character check would be dead code; obs-text is the only thing that gets
//!   through, and that is [`Normalization::header_non_ascii`].
//! * **Header count and size limits** are enforced by Pingora (256 headers,
//!   ~1 MiB of header on H1; a 64 KiB header list on H2).
//!
//! What is left is the URI, the `Host` header, and obs-text - which is what
//! this module does.

use http::uri::{PathAndQuery, Uri};
use pingora_http::RequestHeader;

use crate::config::internal::Normalization;

/// Why a request was turned away
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// A control character or NUL appeared in the path
    ControlCharacter,
    /// A `%` that was not followed by two hex digits
    BadPercentEncoding,
    /// An encoded `/` or `\`, which hides a path segment boundary
    EncodedSeparator,
    /// `..` climbed above the root of the path
    PathEscapesRoot,
    /// More than one `Host` header
    DuplicateHost,
    /// `Host` disagreed with the authority in the request line
    HostMismatch,
    /// Neither a `Host` header nor an authority in the URI
    MissingHost,
    /// A header value contained bytes outside US-ASCII
    NonAsciiHeader,
}

impl Rejected {
    pub fn as_str(&self) -> &'static str {
        match self {
            Rejected::ControlCharacter => "a control character in the request path",
            Rejected::BadPercentEncoding => "a malformed percent-encoding in the request path",
            Rejected::EncodedSeparator => "an encoded path separator in the request path",
            Rejected::PathEscapesRoot => "a request path that climbs above the root",
            Rejected::DuplicateHost => "more than one Host header",
            Rejected::HostMismatch => "a Host header that disagrees with the request line",
            Rejected::MissingHost => "no Host header",
            Rejected::NonAsciiHeader => "a non-ASCII header value",
        }
    }
}

/// Check and normalize a request in place
///
/// Returns `Err` if the request should be rejected. On `Ok`, the request may
/// have been rewritten into canonical form.
pub fn apply(header: &mut RequestHeader, config: &Normalization) -> Result<(), Rejected> {
    check_headers(header, config)?;
    check_host(header, config)?;
    normalize_uri(header, config)
}

fn check_headers(header: &RequestHeader, config: &Normalization) -> Result<(), Rejected> {
    if !config.header_non_ascii {
        return Ok(());
    }

    // httparse admits obs-text (`0x80..`) into header values, and Pingora
    // builds the value without re-checking. Everything below `0x20` was
    // already refused, so this is the only band left.
    if header
        .headers
        .values()
        .any(|v| v.as_bytes().iter().any(|b| !b.is_ascii()))
    {
        return Err(Rejected::NonAsciiHeader);
    }

    Ok(())
}

fn check_host(header: &RequestHeader, config: &Normalization) -> Result<(), Rejected> {
    if !config.host {
        return Ok(());
    }

    let mut hosts = header.headers.get_all(http::header::HOST).into_iter();
    let host = hosts.next();

    // Two `Host` headers let a proxy and its upstream server disagree about
    // which site a request was for, which is the whole shape of a request
    // smuggling attack.
    if hosts.next().is_some() {
        return Err(Rejected::DuplicateHost);
    }

    let authority = header.uri.authority().map(|a| a.as_str());

    match (host.and_then(|h| h.to_str().ok()), authority) {
        // An HTTP/2 request carries `:authority`, which Pingora puts in the
        // URI. Both present means they have to agree.
        (Some(host), Some(authority)) if !same_host(host, authority) => Err(Rejected::HostMismatch),
        (None, None) => Err(Rejected::MissingHost),
        _ => Ok(()),
    }
}

/// Compare two authorities, ignoring case and a trailing dot
fn same_host(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim_end_matches('.').to_ascii_lowercase();
    norm(a) == norm(b)
}

/// Rewrite the path into canonical form, rejecting what cannot be canonicalized
fn normalize_uri(header: &mut RequestHeader, config: &Normalization) -> Result<(), Rejected> {
    let Some(pq) = header.uri.path_and_query() else {
        return Ok(());
    };
    let path = pq.path();
    let query = pq.query().map(str::to_string);

    let normalized = normalize_path(path, config)?;

    // Only rebuild the URI when something actually changed. Rebuilding is not
    // free, and most requests are already canonical.
    if normalized == path {
        return Ok(());
    }

    tracing::debug!(from = %path, to = %normalized, "Normalized request path");

    let pq = match &query {
        Some(q) => format!("{normalized}?{q}"),
        None => normalized,
    };

    let mut parts = header.uri.clone().into_parts();
    parts.path_and_query = Some(match PathAndQuery::try_from(pq.as_str()) {
        Ok(pq) => pq,
        // Everything in the rewritten path came out of a path that already
        // parsed, so this should not happen; refusing is still better than
        // proceeding with an unnormalized path.
        Err(_) => return Err(Rejected::BadPercentEncoding),
    });

    match Uri::from_parts(parts) {
        Ok(uri) => {
            header.set_uri(uri);
            Ok(())
        }
        Err(_) => Err(Rejected::BadPercentEncoding),
    }
}

/// The canonical form of one path
pub fn normalize_path(path: &str, config: &Normalization) -> Result<String, Rejected> {
    let decoded = decode(path, config)?;

    let collapsed = if config.duplicate_slashes {
        collapse_slashes(&decoded)
    } else {
        decoded
    };

    if config.dot_segments {
        resolve_dot_segments(&collapsed)
    } else {
        Ok(collapsed)
    }
}

/// Percent-decode the characters that are safe to decode, and check the rest
///
/// Only unreserved characters are decoded. Decoding anything else would change
/// what the path means: `%2F` is precisely *not* a segment separator, and
/// turning it into one is the classic way past a path-prefix check.
fn decode(path: &str, config: &Normalization) -> Result<String, Rejected> {
    let bytes = path.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];

        if b != b'%' {
            if config.control_characters && (b < 0x20 || b == 0x7F) {
                return Err(Rejected::ControlCharacter);
            }
            out.push(b as char);
            i += 1;
            continue;
        }

        let (hi, lo) = match (bytes.get(i + 1), bytes.get(i + 2)) {
            (Some(&hi), Some(&lo)) => (hi, lo),
            _ => {
                if config.percent_encoding {
                    return Err(Rejected::BadPercentEncoding);
                }
                out.push('%');
                i += 1;
                continue;
            }
        };

        let value = match (hex(hi), hex(lo)) {
            (Some(hi), Some(lo)) => hi * 16 + lo,
            _ => {
                if config.percent_encoding {
                    return Err(Rejected::BadPercentEncoding);
                }
                out.push('%');
                i += 1;
                continue;
            }
        };

        if config.control_characters && (value < 0x20 || value == 0x7F) {
            return Err(Rejected::ControlCharacter);
        }

        // An encoded separator is ambiguous between River and the upstream
        // server: whichever of them decodes it sees a different set of path
        // segments than the other. Refusing is the only answer that keeps them
        // agreeing.
        if config.encoded_separators && (value == b'/' || value == b'\\') {
            return Err(Rejected::EncodedSeparator);
        }

        if config.percent_encoding && is_unreserved(value) {
            // Safe to decode: an unreserved character means the same thing
            // encoded or not, so the encoded spelling is just a different way
            // of writing the same path. Note this turns `%2E` into `.`, which
            // is what lets dot-segment resolution below see through it.
            out.push(value as char);
        } else {
            // Left encoded, but with the hex digits in a canonical case.
            out.push('%');
            out.push(hi.to_ascii_uppercase() as char);
            out.push(lo.to_ascii_uppercase() as char);
        }

        i += 3;
    }

    Ok(out)
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// RFC 3986 unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn collapse_slashes(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut last_was_slash = false;

    for c in path.chars() {
        if c == '/' {
            if !last_was_slash {
                out.push(c);
            }
            last_was_slash = true;
        } else {
            out.push(c);
            last_was_slash = false;
        }
    }

    out
}

/// Resolve `.` and `..`, per RFC 3986 §5.2.4
///
/// A `..` that would climb above the root is rejected rather than silently
/// clamped. Clamping is what most implementations do, and it means
/// `/../../etc/passwd` and `/etc/passwd` are the same request - so a filter
/// written against one does not cover the other.
fn resolve_dot_segments(path: &str) -> Result<String, Rejected> {
    let absolute = path.starts_with('/');
    let trailing_slash = path.ends_with('/') && path.len() > 1;

    let mut out: Vec<&str> = vec![];

    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if out.pop().is_none() && absolute {
                    return Err(Rejected::PathEscapesRoot);
                }
            }
            other => out.push(other),
        }
    }

    let mut result = String::new();
    if absolute {
        result.push('/');
    }
    result.push_str(&out.join("/"));

    // `/a/b/` and `/a/b` are different requests to many servers, so a trailing
    // slash that was there before is kept.
    if trailing_slash && !result.ends_with('/') {
        result.push('/');
    }

    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;

    fn on() -> Normalization {
        Normalization::default()
    }

    fn norm(path: &str) -> Result<String, Rejected> {
        normalize_path(path, &on())
    }

    #[test]
    fn a_canonical_path_is_left_alone() {
        assert_eq!(norm("/api/users").unwrap(), "/api/users");
        assert_eq!(norm("/").unwrap(), "/");
    }

    #[test]
    fn dot_segments_are_resolved() {
        assert_eq!(norm("/static/../admin").unwrap(), "/admin");
        assert_eq!(norm("/a/./b").unwrap(), "/a/b");
        assert_eq!(norm("/a/b/..").unwrap(), "/a");
    }

    /// The reason normalization has to run before the filters: without it,
    /// these three spellings reach different filters but the same file.
    #[test]
    fn every_spelling_of_a_traversal_lands_in_one_place() {
        assert_eq!(norm("/static/../admin").unwrap(), "/admin");
        assert_eq!(norm("/static/%2E%2E/admin").unwrap(), "/admin");
        assert_eq!(norm("/static//..///admin").unwrap(), "/admin");
    }

    #[test]
    fn climbing_above_the_root_is_rejected_not_clamped() {
        // Clamping would make this identical to /etc/passwd, so a rule written
        // against one would not cover the other.
        assert_eq!(norm("/../etc/passwd"), Err(Rejected::PathEscapesRoot));
        assert_eq!(norm("/a/../../b"), Err(Rejected::PathEscapesRoot));
    }

    #[test]
    fn duplicate_slashes_are_collapsed() {
        assert_eq!(norm("/a//b///c").unwrap(), "/a/b/c");
    }

    #[test]
    fn a_trailing_slash_is_preserved() {
        assert_eq!(norm("/a/b/").unwrap(), "/a/b/");
        assert_eq!(norm("/a/b").unwrap(), "/a/b");
    }

    #[test]
    fn unreserved_characters_are_decoded() {
        assert_eq!(norm("/%61%62%63").unwrap(), "/abc");
        assert_eq!(norm("/a%2Db").unwrap(), "/a-b");
    }

    #[test]
    fn reserved_characters_stay_encoded_in_canonical_case() {
        // A literal space must stay encoded, but `%20` and `%20` should not be
        // two different paths just because of the hex case.
        assert_eq!(norm("/a%20b").unwrap(), "/a%20b");
        assert_eq!(norm("/a%3fb").unwrap(), "/a%3Fb");
    }

    #[test]
    fn an_encoded_separator_is_rejected() {
        // `%2F` means "not a separator". If River treats it as one and the
        // upstream server does not - or the other way round - they disagree
        // about what was requested.
        assert_eq!(norm("/a%2Fb"), Err(Rejected::EncodedSeparator));
        assert_eq!(norm("/a%2fb"), Err(Rejected::EncodedSeparator));
        assert_eq!(norm("/a%5Cb"), Err(Rejected::EncodedSeparator));
    }

    #[test]
    fn control_characters_are_rejected_encoded_or_not() {
        assert_eq!(norm("/a%00b"), Err(Rejected::ControlCharacter));
        assert_eq!(norm("/a%0Ab"), Err(Rejected::ControlCharacter));
        assert_eq!(norm("/a\u{1}b"), Err(Rejected::ControlCharacter));
    }

    #[test]
    fn a_malformed_percent_encoding_is_rejected() {
        assert_eq!(norm("/a%zzb"), Err(Rejected::BadPercentEncoding));
        assert_eq!(norm("/a%2"), Err(Rejected::BadPercentEncoding));
        assert_eq!(norm("/a%"), Err(Rejected::BadPercentEncoding));
    }

    #[test]
    fn each_check_can_be_turned_off_on_its_own() {
        let mut config = on();
        config.encoded_separators = false;
        config.percent_encoding = false;
        // With decoding off, the encoded separator is passed through as-is.
        assert_eq!(normalize_path("/a%2Fb", &config).unwrap(), "/a%2Fb");

        let mut config = on();
        config.dot_segments = false;
        assert_eq!(normalize_path("/a/../b", &config).unwrap(), "/a/../b");

        let mut config = on();
        config.duplicate_slashes = false;
        config.dot_segments = false;
        assert_eq!(normalize_path("/a//b", &config).unwrap(), "/a//b");
    }

    //
    // Header and Host checks
    //

    fn request(path: &str) -> RequestHeader {
        let mut h = RequestHeader::build("GET", path.as_bytes(), None).unwrap();
        h.append_header("host", "example.com").unwrap();
        h
    }

    #[test]
    fn a_normal_request_passes() {
        let mut h = request("/api/users");
        assert!(apply(&mut h, &on()).is_ok());
        assert_eq!(h.uri.path(), "/api/users");
    }

    #[test]
    fn the_uri_is_rewritten_in_place() {
        let mut h = request("/static/../admin?a=1");
        assert!(apply(&mut h, &on()).is_ok());
        assert_eq!(h.uri.path(), "/admin");
        // The query is not the path, and is left exactly as it arrived.
        assert_eq!(h.uri.query(), Some("a=1"));
    }

    #[test]
    fn two_host_headers_are_rejected() {
        let mut h = request("/");
        h.append_header("host", "evil.example").unwrap();
        assert_eq!(apply(&mut h, &on()), Err(Rejected::DuplicateHost));
    }

    #[test]
    fn a_missing_host_is_rejected() {
        let mut h = RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(apply(&mut h, &on()), Err(Rejected::MissingHost));
    }

    /// An HTTP/2 request carries `:authority`, which reaches River as the
    /// authority of the URI. `RequestHeader::build` only ever sets a path, so
    /// this builds the header the way the H2 path does.
    fn h2_request(uri: &str, host: Option<&str>) -> RequestHeader {
        let mut builder = http::Request::builder().method("GET").uri(uri);
        if let Some(host) = host {
            builder = builder.header("host", host);
        }
        let parts = builder.body(()).unwrap().into_parts().0;
        RequestHeader::from(parts)
    }

    #[test]
    fn an_authority_without_a_host_header_is_fine() {
        let mut h = h2_request("http://a.example/", None);
        assert!(h.uri.authority().is_some(), "test needs an authority");
        assert!(apply(&mut h, &on()).is_ok());
    }

    #[test]
    fn a_host_disagreeing_with_the_authority_is_rejected() {
        // The shape of a request smuggling attack: River routes on one name
        // while the upstream server sees the other.
        let mut h = h2_request("http://a.example/", Some("b.example"));
        assert_eq!(apply(&mut h, &on()), Err(Rejected::HostMismatch));
    }

    #[test]
    fn a_host_matching_the_authority_is_fine() {
        // Case and a trailing dot are not a disagreement.
        let mut h = h2_request("http://a.example/", Some("A.Example."));
        assert!(apply(&mut h, &on()).is_ok());
    }

    #[test]
    fn the_host_check_can_be_turned_off() {
        let mut config = on();
        config.host = false;
        let mut h = h2_request("http://a.example/", Some("b.example"));
        assert!(apply(&mut h, &config).is_ok());
    }

    #[test]
    fn obs_text_is_allowed_unless_asked_about() {
        let mut h = request("/");
        h.append_header(
            "x-note",
            http::HeaderValue::from_bytes(b"caf\xC3\xA9").unwrap(),
        )
        .unwrap();

        // Off by default: real traffic carries UTF-8 in headers, and rejecting
        // it would break more than it protects.
        assert!(apply(&mut h, &on()).is_ok());

        let mut strict = on();
        strict.header_non_ascii = true;
        assert_eq!(apply(&mut h, &strict), Err(Rejected::NonAsciiHeader));
    }
}
