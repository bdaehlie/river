//! A pool of upstream servers, with its selection algorithm erased
//!
//! [`LoadBalancer`] is generic over the algorithm it uses to pick a server.
//! Before routing existed, a service had exactly one pool, so the whole proxy
//! service could be generic over that algorithm and monomorphized once per
//! configured value.
//!
//! With routing, one service has several pools, and there is no reason two
//! routes should have to agree on how their servers are chosen - a route to a
//! stateless API wants round robin, while one to a cache wants consistent
//! hashing. That cannot be expressed with a single type parameter, so the
//! algorithm is erased behind this trait instead, and the proxy service stops
//! being generic at all.

use async_trait::async_trait;
use pingora_core::Result;
use pingora_load_balancing::{
    selection::{BackendIter, BackendSelection},
    Backend, Backends, LoadBalancer,
};

/// How many backends the selection is willing to walk past before giving up
///
/// Selection skips servers that are currently unhealthy; this bounds that
/// search so a pool where everything is failing cannot spin.
const MAX_SELECTION_ITERATIONS: usize = 256;

/// The parts of a [`LoadBalancer`] that River uses
#[async_trait]
pub trait BackendPool: Send + Sync {
    /// Pick a server for a request with the given selection key
    ///
    /// `None` when every server is unhealthy, or there are none at all.
    fn select(&self, key: &[u8]) -> Option<Backend>;

    /// Re-resolve the set of servers
    async fn update(&self) -> Result<()>;

    /// The current server set, used for health checking and for logging
    fn backends(&self) -> &Backends;
}

#[async_trait]
impl<BS> BackendPool for LoadBalancer<BS>
where
    BS: BackendSelection + Send + Sync + 'static,
    BS::Iter: BackendIter,
{
    fn select(&self, key: &[u8]) -> Option<Backend> {
        LoadBalancer::select(self, key, MAX_SELECTION_ITERATIONS)
    }

    async fn update(&self) -> Result<()> {
        LoadBalancer::update(self).await
    }

    fn backends(&self) -> &Backends {
        LoadBalancer::backends(self)
    }
}
