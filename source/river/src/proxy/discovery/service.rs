//! The background service that keeps a service's upstream list current
//!
//! Pingora's [`LoadBalancer`] already implements
//! [`BackgroundService`][pingora_core::services::background::BackgroundService],
//! but its loop sleeps for a fixed `update_frequency`. River needs the interval
//! to come from the answer that was just received, so that a DNS TTL can drive
//! re-polling, and it needs per-source scheduling so that a five second source
//! does not drag a five minute one along with it. So River runs its own loop.
//!
//! It also owns health checking, for the same reason: the checks have to run on
//! their own clock, and a newly discovered server should be probed promptly
//! rather than at the next scheduled tick.

use std::{collections::BTreeSet, sync::Arc, time::Instant};

use async_trait::async_trait;
use pingora_core::{
    server::ShutdownWatch,
    services::{background::BackgroundService, ServiceReadyNotifier},
};
use pingora_load_balancing::{
    selection::{BackendIter, BackendSelection},
    Backend, LoadBalancer,
};

use crate::config::internal::HealthCheckSettings;

use super::RiverDiscovery;

/// Keeps one service's backend set up to date
pub struct UpstreamService<BS: BackendSelection> {
    /// The service these upstreams belong to, for logs
    name: String,

    load_balancer: Arc<LoadBalancer<BS>>,

    /// The same discovery the load balancer's `Backends` owns, kept here so
    /// the loop can ask when the next poll is due.
    discovery: Arc<RiverDiscovery>,

    /// `None` when the service does not health check
    health: Option<HealthCheckSettings>,
}

impl<BS: BackendSelection> UpstreamService<BS> {
    pub fn new(
        name: String,
        load_balancer: Arc<LoadBalancer<BS>>,
        discovery: Arc<RiverDiscovery>,
        health: Option<HealthCheckSettings>,
    ) -> Self {
        Self {
            name,
            load_balancer,
            discovery,
            health,
        }
    }
}

#[async_trait]
impl<BS> BackgroundService for UpstreamService<BS>
where
    BS: BackendSelection + Send + Sync + 'static,
    BS::Iter: BackendIter,
{
    async fn start_with_ready_notifier(
        &self,
        mut shutdown: ShutdownWatch,
        ready: ServiceReadyNotifier,
    ) {
        let mut ready = Some(ready);
        let mut next_health_check = Instant::now();

        loop {
            if *shutdown.borrow() {
                return;
            }

            let before = self.load_balancer.backends().get_backend();

            if let Err(e) = self.load_balancer.update().await {
                tracing::warn!(
                    service = %self.name,
                    error = %e,
                    "Could not update the upstream servers"
                );
            }

            let after = self.load_balancer.backends().get_backend();
            let changed = before != after;
            if changed {
                self.log_change(&before, &after);
            }

            // Readiness is signalled after the first pass whether or not it
            // found anything. If DNS is down when River starts, it should come
            // up, complain, and keep trying - not hold its listeners closed
            // and look like a crash.
            if let Some(notifier) = ready.take() {
                notifier.notify_ready();
            }

            if let Some(health) = self.health.as_ref() {
                // A server that has just appeared is assumed healthy until
                // proven otherwise, so checking straight away shortens the
                // window where traffic goes somewhere unverified.
                if changed || Instant::now() >= next_health_check {
                    self.load_balancer
                        .backends()
                        .run_health_check(health.parallel)
                        .await;
                    next_health_check = Instant::now() + health.frequency;
                }
            }

            let Some(wake_at) = self.next_wakeup(next_health_check) else {
                // Nothing refreshes and nothing is checked, so there is no
                // reason to run again.
                return;
            };

            let delay = wake_at.saturating_duration_since(Instant::now());
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = shutdown.changed() => return,
            }
        }
    }
}

impl<BS: BackendSelection> UpstreamService<BS> {
    /// The earlier of the next discovery poll and the next health check
    fn next_wakeup(&self, next_health_check: Instant) -> Option<Instant> {
        let next_discovery = self.discovery.next_due();

        match (next_discovery, self.health.is_some()) {
            (Some(discovery), true) => Some(discovery.min(next_health_check)),
            (Some(discovery), false) => Some(discovery),
            (None, true) => Some(next_health_check),
            (None, false) => None,
        }
    }

    /// Report what came and went, because an operator debugging a bad deploy
    /// needs to see it
    fn log_change(&self, before: &BTreeSet<Backend>, after: &BTreeSet<Backend>) {
        let added = addresses(after.difference(before));
        let removed = addresses(before.difference(after));

        tracing::info!(
            service = %self.name,
            total = after.len(),
            added = %render(&added),
            removed = %render(&removed),
            "Upstream servers changed"
        );
    }
}

fn addresses<'a>(backends: impl Iterator<Item = &'a Backend>) -> Vec<String> {
    backends.map(|b| b.addr.to_string()).collect()
}

fn render(addrs: &[String]) -> String {
    if addrs.is_empty() {
        "-".to_string()
    } else {
        addrs.join(", ")
    }
}
