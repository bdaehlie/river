//! Limiting how much work a service will take on at once
//!
//! Requirement 11 of the milestone, which comes from the roadmap's stated goal
//! of "resistance to Denial of Service attacks, or general overload" rather
//! than from a numbered requirement in the design document.
//!
//! Rate limiting answers "how fast may this client ask". This answers the
//! different question of "how much is River willing to have in flight at
//! once", which is what protects an upstream server from being knocked over by
//! a legitimate but sudden surge, and River itself from a client that opens
//! connections and then sends nothing.

use std::sync::atomic::{AtomicUsize, Ordering};

use pingora_proxy::Session;

use crate::config::internal::OverloadConfig;

/// A service's share of the work it is willing to do at once
pub struct Overload {
    config: OverloadConfig,

    /// Requests currently being handled by this service
    in_flight: AtomicUsize,
}

impl Overload {
    pub fn new(config: OverloadConfig) -> Self {
        Self {
            config,
            in_flight: AtomicUsize::new(0),
        }
    }

    pub fn config(&self) -> &OverloadConfig {
        &self.config
    }

    /// Take a slot, if there is one
    ///
    /// The caller must call [`Self::release`] for every `true` returned. The
    /// count is incremented before it is checked and given back when the check
    /// fails, so two threads racing at the limit may both back off - which
    /// errs towards shedding one request too many rather than admitting one
    /// too many.
    pub fn acquire(&self) -> bool {
        let Some(max) = self.config.max_concurrent_requests else {
            return true;
        };

        let previous = self.in_flight.fetch_add(1, Ordering::Relaxed);
        if previous >= max {
            self.in_flight.fetch_sub(1, Ordering::Relaxed);
            false
        } else {
            true
        }
    }

    pub fn release(&self) {
        if self.config.max_concurrent_requests.is_some() {
            self.in_flight.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// How many requests are in flight, for logging
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Is the request's header within the configured bounds?
    ///
    /// Pingora already caps these far higher - 256 headers and about 1 MiB on
    /// HTTP/1.1 - so this exists for an operator who wants a tighter policy
    /// than "whatever the parser will take". The bytes have already been read
    /// by the time this runs; the point is to refuse to spend anything further
    /// on the request, not to avoid reading it.
    pub fn header_within_limits(&self, session: &Session) -> bool {
        let headers = &session.downstream_session.req_header().headers;

        if let Some(max) = self.config.max_headers {
            if headers.len() > max {
                tracing::debug!(count = headers.len(), max, "Too many request headers");
                return false;
            }
        }

        if let Some(max) = self.config.max_header_bytes {
            let total: usize = headers
                .iter()
                .map(|(name, value)| name.as_str().len() + value.len())
                .sum();

            if total > max {
                tracing::debug!(bytes = total, max, "Request header too large");
                return false;
            }
        }

        true
    }

    /// Apply the connection settings that bound a slow client
    ///
    /// These are Pingora's own knobs; River's part is exposing them. Without
    /// them a client can hold a connection open indefinitely by sending a
    /// request body one byte at a time, or by reading a response equally
    /// slowly - the classic slow loris, in both directions.
    pub fn apply_timeouts(&self, session: &mut Session) {
        let downstream = &mut session.downstream_session;

        if let Some(t) = self.config.read_timeout {
            downstream.set_read_timeout(Some(t));
        }
        if let Some(t) = self.config.write_timeout {
            downstream.set_write_timeout(Some(t));
        }
        if let Some(t) = self.config.drain_timeout {
            downstream.set_total_drain_timeout(Some(t));
        }
        if let Some(rate) = self.config.min_send_rate {
            downstream.set_min_send_rate(Some(rate));
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::internal::Rejection;

    fn limited(max: Option<usize>) -> Overload {
        Overload::new(OverloadConfig {
            max_concurrent_requests: max,
            rejection: Rejection {
                status: 503,
                body: None,
            },
            ..Default::default()
        })
    }

    #[test]
    fn without_a_limit_everything_is_admitted() {
        let o = limited(None);
        for _ in 0..1000 {
            assert!(o.acquire());
        }
        // Nothing is counted, so there is nothing to give back
        assert_eq!(o.in_flight(), 0);
    }

    #[test]
    fn requests_past_the_limit_are_shed() {
        let o = limited(Some(2));

        assert!(o.acquire());
        assert!(o.acquire());
        assert!(!o.acquire());
        assert_eq!(o.in_flight(), 2);
    }

    #[test]
    fn a_shed_request_does_not_leak_a_slot() {
        let o = limited(Some(1));

        assert!(o.acquire());
        // Several rejections in a row must not push the count up, or the
        // service would never recover.
        for _ in 0..10 {
            assert!(!o.acquire());
        }
        assert_eq!(o.in_flight(), 1);

        o.release();
        assert_eq!(o.in_flight(), 0);
        assert!(o.acquire());
    }

    #[test]
    fn releasing_makes_room_again() {
        let o = limited(Some(1));

        assert!(o.acquire());
        assert!(!o.acquire());
        o.release();
        assert!(o.acquire());
    }
}
