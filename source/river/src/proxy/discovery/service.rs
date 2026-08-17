//! The background service that keeps a service's upstream lists current
//!
//! Pingora's [`LoadBalancer`][pingora_load_balancing::LoadBalancer] already
//! implements
//! [`BackgroundService`][pingora_core::services::background::BackgroundService],
//! but its loop sleeps for a fixed `update_frequency`. River needs the interval
//! to come from the answer that was just received, so that a DNS TTL can drive
//! re-polling, and it needs per-source scheduling so that a five second source
//! does not drag a five minute one along with it. So River runs its own loop.
//!
//! It also owns health checking, for the same reason: the checks have to run on
//! their own clock, and a newly discovered server should be probed promptly
//! rather than at the next scheduled tick.
//!
//! Since routing arrived, one proxy service has one pool of servers per route.
//! They are all driven from this single background service, so that the
//! readiness and dependency wiring around it does not change shape as routes
//! are added - but each pool keeps its own schedule, for the same reason each
//! source does.

use std::{collections::BTreeSet, sync::Arc, time::Instant};

use async_trait::async_trait;
use pingora_core::{
    server::ShutdownWatch,
    services::{background::BackgroundService, ServiceReadyNotifier},
};
use pingora_load_balancing::Backend;

use crate::{config::internal::HealthCheckSettings, proxy::pool::BackendPool};

use super::RiverDiscovery;

/// One pool of upstream servers, and what it needs to stay current
pub struct PoolState {
    pool: Arc<dyn BackendPool>,

    /// The same discovery the pool's `Backends` owns, kept here so the loop
    /// can ask when the next poll is due.
    discovery: Arc<RiverDiscovery>,

    /// `None` when this pool does not health check
    health: Option<HealthCheckSettings>,
}

impl PoolState {
    pub fn new(
        pool: Arc<dyn BackendPool>,
        discovery: Arc<RiverDiscovery>,
        health: Option<HealthCheckSettings>,
    ) -> Self {
        Self {
            pool,
            discovery,
            health,
        }
    }
}

/// Keeps every pool of one proxy service up to date
pub struct UpstreamService {
    /// The service these upstreams belong to, for logs
    name: String,

    pools: Vec<PoolState>,
}

impl UpstreamService {
    pub fn new(name: String, pools: Vec<PoolState>) -> Self {
        Self { name, pools }
    }
}

/// When each pool next wants attention
struct Schedule {
    /// Set once a pool has been polled at least once
    polled: Vec<bool>,
    next_health_check: Vec<Instant>,
}

#[async_trait]
impl BackgroundService for UpstreamService {
    async fn start_with_ready_notifier(
        &self,
        mut shutdown: ShutdownWatch,
        ready: ServiceReadyNotifier,
    ) {
        let mut ready = Some(ready);
        let now = Instant::now();
        let mut schedule = Schedule {
            polled: vec![false; self.pools.len()],
            next_health_check: vec![now; self.pools.len()],
        };

        loop {
            if *shutdown.borrow() {
                return;
            }

            let now = Instant::now();

            for (index, state) in self.pools.iter().enumerate() {
                // Only visit a pool that is actually due. Rebuilding a
                // selection table costs real work, and one pool following a
                // five second TTL should not drag the rest along with it.
                let due = !schedule.polled[index]
                    || state.discovery.next_due().is_some_and(|due| now >= due)
                    || state
                        .health
                        .is_some_and(|_| now >= schedule.next_health_check[index]);

                if !due {
                    continue;
                }
                schedule.polled[index] = true;

                self.refresh(state, index, &mut schedule).await;
            }

            // Readiness is signalled after the first pass whether or not it
            // found anything. If DNS is down when River starts, it should come
            // up, complain, and keep trying - not hold its listeners closed
            // and look like a crash.
            if let Some(notifier) = ready.take() {
                notifier.notify_ready();
            }

            let Some(wake_at) = self.next_wakeup(&schedule) else {
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

impl UpstreamService {
    /// Re-resolve one pool, and health check it if it is time
    async fn refresh(&self, state: &PoolState, index: usize, schedule: &mut Schedule) {
        let before = state.pool.backends().get_backend();

        if let Err(e) = state.pool.update().await {
            tracing::warn!(
                service = %self.name,
                error = %e,
                "Could not update the upstream servers"
            );
        }

        let after = state.pool.backends().get_backend();
        let changed = before != after;
        if changed {
            self.log_change(&before, &after);
        }

        if let Some(health) = state.health.as_ref() {
            // A server that has just appeared is assumed healthy until proven
            // otherwise, so checking straight away shortens the window where
            // traffic goes somewhere unverified.
            if changed || Instant::now() >= schedule.next_health_check[index] {
                state
                    .pool
                    .backends()
                    .run_health_check(health.parallel)
                    .await;
                schedule.next_health_check[index] = Instant::now() + health.frequency;
            }
        }
    }

    /// The soonest any pool wants attention
    fn next_wakeup(&self, schedule: &Schedule) -> Option<Instant> {
        self.pools
            .iter()
            .enumerate()
            .filter_map(|(index, state)| {
                let discovery = state.discovery.next_due();
                let health = state.health.map(|_| schedule.next_health_check[index]);

                match (discovery, health) {
                    (Some(d), Some(h)) => Some(d.min(h)),
                    (Some(d), None) => Some(d),
                    (None, Some(h)) => Some(h),
                    (None, None) => None,
                }
            })
            .min()
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
