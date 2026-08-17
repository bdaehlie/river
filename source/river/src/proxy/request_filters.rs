use std::net::IpAddr;

use async_trait::async_trait;
use cidr::IpCidr;
use pingora_core::Result;
use pingora_proxy::Session;

use crate::{config::internal::Rejection, proxy::RiverContext};

/// This is a single-serving trait for modifiers that provide actions for
/// [ProxyHttp::request_filter] methods
#[async_trait]
pub trait RequestFilterMod: Send + Sync {
    /// See [ProxyHttp::request_filter] for more details
    async fn request_filter(&self, session: &mut Session, ctx: &mut RiverContext) -> Result<bool>;
}

/// What a [`CidrRangeFilter`] does with an address that falls in its ranges
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidrSense {
    /// Reject an address that is inside any range
    Deny,
    /// Reject an address that is outside every range
    Allow,
}

/// Accepts or rejects a request based on the address it came from
pub struct CidrRangeFilter {
    blocks: Vec<IpCidr>,
    sense: CidrSense,
    rejection: Rejection,
}

impl CidrRangeFilter {
    pub fn new(blocks: Vec<IpCidr>, sense: CidrSense, rejection: Rejection) -> Self {
        Self {
            blocks,
            sense,
            rejection,
        }
    }

    fn rejects(&self, addr: &IpAddr) -> bool {
        let inside = self.blocks.iter().any(|b| b.contains(addr));
        match self.sense {
            CidrSense::Deny => inside,
            CidrSense::Allow => !inside,
        }
    }
}

#[async_trait]
impl RequestFilterMod for CidrRangeFilter {
    async fn request_filter(&self, session: &mut Session, ctx: &mut RiverContext) -> Result<bool> {
        // The address the request is attributed to, which is not the peer
        // address when River is behind a trusted proxy.
        let Some(addr) = ctx.client_addr else {
            // A unix socket has no address for a range to contain. An allow
            // list is a statement about which addresses may connect, and a
            // connection with no address satisfies none of them; a deny list
            // is a statement about which may not, and it satisfies none of
            // those either.
            return match self.sense {
                CidrSense::Deny => Ok(false),
                CidrSense::Allow => self.rejection.apply(session).await,
            };
        };

        if self.rejects(&addr) {
            tracing::debug!(
                client = %addr,
                sense = ?self.sense,
                status = self.rejection.status(),
                "Rejecting a request by address"
            );
            self.rejection.apply(session).await
        } else {
            Ok(false)
        }
    }
}
