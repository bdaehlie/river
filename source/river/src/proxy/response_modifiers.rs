use http::{HeaderName, HeaderValue};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use regex::Regex;

use super::RiverContext;

/// This is a single-serving trait for modifiers that provide actions for
/// [ProxyHttp::upstream_response_filter] methods
pub trait ResponseModifyMod: Send + Sync {
    /// See [ProxyHttp::upstream_response_filter] for more details
    fn upstream_response_filter(
        &self,
        session: &mut Session,
        header: &mut ResponseHeader,
        ctx: &mut RiverContext,
    );
}

// Remove header by key
//
//

/// Removes a header if the key matches a given regex
pub struct RemoveHeaderKeyRegex {
    regex: Regex,
}

impl RemoveHeaderKeyRegex {
    pub fn new(regex: Regex) -> Self {
        Self { regex }
    }
}

impl ResponseModifyMod for RemoveHeaderKeyRegex {
    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        header: &mut ResponseHeader,
        _ctx: &mut RiverContext,
    ) {
        // Find all the headers that have keys that match the regex...
        let headers = header
            .headers
            .keys()
            .filter_map(|k| {
                if self.regex.is_match(k.as_str()) {
                    tracing::debug!("Removing header: {k:?}");
                    Some(k.to_owned())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // ... and remove them
        for h in headers {
            assert!(header.remove_header(&h).is_some());
        }
    }
}

// Upsert Header
//
//

/// Adds or replaces a given header key and value
pub struct UpsertHeader {
    key: HeaderName,
    value: HeaderValue,
}

impl UpsertHeader {
    pub fn new(key: HeaderName, value: HeaderValue) -> Self {
        Self { key, value }
    }
}

impl ResponseModifyMod for UpsertHeader {
    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        header: &mut ResponseHeader,
        _ctx: &mut RiverContext,
    ) {
        if let Some(h) = header.remove_header(&self.key) {
            tracing::debug!("Removed header: {h:?}");
        }
        // The name and value were validated when the configuration was parsed,
        // so this cannot fail on their account.
        let _ = header.append_header(self.key.clone(), self.value.clone());
        tracing::debug!("Inserted header: {:?}: {:?}", self.key, self.value);
    }
}
