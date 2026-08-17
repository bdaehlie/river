use pingora_http::ResponseHeader;
use pingora_proxy::Session;

use crate::config::internal::HeaderModifier;

use super::{headers, RiverContext};

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

/// Applies one configured header change to the response
pub struct HeaderMod {
    modifier: HeaderModifier,
}

impl HeaderMod {
    pub fn new(modifier: HeaderModifier) -> Self {
        Self { modifier }
    }
}

impl ResponseModifyMod for HeaderMod {
    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        header: &mut ResponseHeader,
        _ctx: &mut RiverContext,
    ) {
        headers::apply(&self.modifier, header);
    }
}
