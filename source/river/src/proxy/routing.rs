//! Matching a request to the set of upstream servers that should serve it
//!
//! This is the "peer selection" control point: requirement 9 of the v0.8.x
//! milestone, and requirement 7 of "2.2 - Upstream" in the design document.

use std::sync::Arc;

use http::Method;
use pingora_proxy::Session;

use crate::{
    config::internal::{RouteConfig, RouteMatch},
    proxy::{pool::BackendPool, request_selector::RequestSelector},
};

/// One route, built and ready to serve
pub struct Route {
    /// For logs, so an operator can tell which route claimed a request
    pub name: String,

    matcher: RouteMatch,

    /// Empty means any method
    methods: Vec<Method>,

    pub pool: Arc<dyn BackendPool>,

    /// How the selection key is computed for this route's pool
    pub selector: RequestSelector,
}

impl Route {
    pub fn new(
        config: &RouteConfig,
        pool: Arc<dyn BackendPool>,
        selector: RequestSelector,
    ) -> Self {
        Self {
            name: route_name(config),
            matcher: config.matcher.clone(),
            methods: config.methods.clone(),
            pool,
            selector,
        }
    }

    fn claims(&self, path: &str, method: &Method) -> bool {
        if !self.methods.is_empty() && !self.methods.iter().any(|m| m == method) {
            return false;
        }
        self.matcher.matches(path)
    }
}

/// A service's routes, in the order they should be tried
///
/// The order is decided once, at startup, by [`RouteMatch::precedence`]. A
/// linear walk is the right shape here: services have a handful of routes, not
/// thousands, and a scan of a few entries beats the bookkeeping of anything
/// cleverer while being obviously correct.
pub struct Routes {
    routes: Vec<Route>,
}

impl Routes {
    /// Sort the routes into matching order
    pub fn new(mut routes: Vec<Route>) -> Self {
        // `sort_by_key` is stable, so regular expressions - which all share a
        // precedence - keep the order they were written in.
        routes.sort_by_key(|r| r.matcher.precedence());
        Self { routes }
    }

    /// The route that claims this request, if any
    pub fn find(&self, session: &Session) -> Option<&Route> {
        let header = session.downstream_session.req_header();
        let path = header.uri.path();
        let method = &header.method;

        self.routes.iter().find(|r| r.claims(path, method))
    }
}

/// The name used for a route in logs
pub fn route_name(config: &RouteConfig) -> String {
    match &config.matcher {
        RouteMatch::Any => "*".to_string(),
        RouteMatch::Exact { path } => format!("={path}"),
        RouteMatch::Prefix { path } => path.clone(),
        RouteMatch::Regex { pattern } => format!("~{}", pattern.as_str()),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::proxy::rate_limiting::RegexShim;

    fn prefix(path: &str) -> RouteMatch {
        RouteMatch::Prefix {
            path: path.to_string(),
        }
    }

    #[test]
    fn a_prefix_stops_at_a_segment_boundary() {
        let m = prefix("/api");

        assert!(m.matches("/api"));
        assert!(m.matches("/api/"));
        assert!(m.matches("/api/users"));

        // The mistake this rules out: `/apiary` is not part of `/api`.
        assert!(!m.matches("/apiary"));
        assert!(!m.matches("/ap"));
        assert!(!m.matches("/"));
    }

    #[test]
    fn a_prefix_that_already_ends_in_a_slash_still_matches() {
        let m = prefix("/api/");

        assert!(m.matches("/api/"));
        assert!(m.matches("/api/users"));
        assert!(!m.matches("/api"));
    }

    #[test]
    fn an_exact_match_is_exact() {
        let m = RouteMatch::Exact {
            path: "/health".to_string(),
        };

        assert!(m.matches("/health"));
        assert!(!m.matches("/health/"));
        assert!(!m.matches("/health/live"));
    }

    #[test]
    fn any_claims_everything() {
        assert!(RouteMatch::Any.matches("/"));
        assert!(RouteMatch::Any.matches("/anything/at/all"));
    }

    #[test]
    fn a_regex_is_matched_against_the_path() {
        let m = RouteMatch::Regex {
            pattern: RegexShim::new(r"^/v\d+/").unwrap(),
        };

        assert!(m.matches("/v1/users"));
        assert!(m.matches("/v22/users"));
        assert!(!m.matches("/api/v1/users"));
    }

    /// The precedence order is the whole reason routing is predictable, so it
    /// is worth pinning down rather than trusting the enum's declaration order.
    #[test]
    fn more_specific_routes_are_tried_first() {
        let mut matchers = vec![
            RouteMatch::Any,
            prefix("/api"),
            RouteMatch::Regex {
                pattern: RegexShim::new("^/r1").unwrap(),
            },
            RouteMatch::Exact {
                path: "/health".to_string(),
            },
            prefix("/api/v2"),
        ];

        matchers.sort_by_key(|m| m.precedence());

        assert_eq!(
            matchers,
            vec![
                RouteMatch::Exact {
                    path: "/health".to_string()
                },
                // Longer prefix beats shorter
                prefix("/api/v2"),
                prefix("/api"),
                RouteMatch::Regex {
                    pattern: RegexShim::new("^/r1").unwrap()
                },
                // The catch-all is always last
                RouteMatch::Any,
            ]
        );
    }
}
