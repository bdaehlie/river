use async_trait::async_trait;
use cidr::IpCidr;
use pingora_core::{protocols::l4::socket::SocketAddr, Result};
use pingora_proxy::Session;

use crate::{config::internal::Rejection, proxy::RiverContext};

/// This is a single-serving trait for modifiers that provide actions for
/// [ProxyHttp::request_filter] methods
#[async_trait]
pub trait RequestFilterMod: Send + Sync {
    /// See [ProxyHttp::request_filter] for more details
    async fn request_filter(&self, session: &mut Session, ctx: &mut RiverContext) -> Result<bool>;
}

/// Rejects a request whose client address falls inside any of the given ranges
pub struct CidrRangeFilter {
    blocks: Vec<IpCidr>,
    rejection: Rejection,
}

impl CidrRangeFilter {
    pub fn new(blocks: Vec<IpCidr>, rejection: Rejection) -> Self {
        Self { blocks, rejection }
    }
}

#[async_trait]
impl RequestFilterMod for CidrRangeFilter {
    async fn request_filter(&self, session: &mut Session, _ctx: &mut RiverContext) -> Result<bool> {
        let Some(addr) = session.downstream_session.client_addr() else {
            // With no source address there is nothing to compare against, so
            // the safe answer is the same one a matching range would get.
            return self.rejection.apply(session).await;
        };
        let SocketAddr::Inet(addr) = addr else {
            // A unix socket has no IP address for a range to contain.
            return Ok(false);
        };
        let ip_addr = addr.ip();

        if self.blocks.iter().any(|b| b.contains(&ip_addr)) {
            self.rejection.apply(session).await
        } else {
            Ok(false)
        }
    }
}
