use async_trait::async_trait;
use pingora_core::Result;
use pingora_http::RequestHeader;
use pingora_proxy::Session;

use crate::config::internal::HeaderModifier;

use super::{headers, RiverContext};

/// This is a single-serving trait for modifiers that provide actions for
/// [ProxyHttp::upstream_request_filter] methods
#[async_trait]
pub trait RequestModifyMod: Send + Sync {
    /// See [ProxyHttp::upstream_request_filter] for more details
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        header: &mut RequestHeader,
        ctx: &mut RiverContext,
    ) -> Result<()>;
}

/// Applies one configured header change to the outgoing request
pub struct HeaderMod {
    modifier: HeaderModifier,
}

impl HeaderMod {
    pub fn new(modifier: HeaderModifier) -> Self {
        Self { modifier }
    }
}

#[async_trait]
impl RequestModifyMod for HeaderMod {
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        header: &mut RequestHeader,
        _ctx: &mut RiverContext,
    ) -> Result<()> {
        headers::apply(&self.modifier, header);
        Ok(())
    }
}
