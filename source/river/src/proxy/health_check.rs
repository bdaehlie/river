//! Building Pingora health checks from River's configuration
//!
//! A health check is what lets a discovered upstream list shrink for the right
//! reason: a server that has gone away stops receiving traffic without waiting
//! for anyone to remove it from DNS. It is also what
//! `docs/what-is-it.md` section 2.2 asks for - "River MUST support the
//! disabling of use of an upstream server based on failed health checks".
//!
//! Pingora's [`Backends`][pingora_load_balancing::Backends] excludes a server
//! that fails its check from selection, and puts it back when it recovers, so
//! all River supplies is the check itself.

use pingora_core::{Error, ErrorType::CustomCode};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_load_balancing::health_check::{HealthCheck, HttpHealthCheck, TcpHealthCheck};

use crate::config::internal::{HealthCheckKind, HealthCheckSettings};

/// Build the check a service is configured to use, if any
pub fn build(kind: &HealthCheckKind) -> Option<Box<dyn HealthCheck + Send + Sync + 'static>> {
    match kind {
        HealthCheckKind::None => None,
        HealthCheckKind::Tcp { settings, sni } => Some(tcp(settings, sni.as_deref())),
        HealthCheckKind::Http {
            settings,
            host,
            path,
            tls,
            expect_status,
            port,
            reuse_connection,
        } => Some(http(
            settings,
            host,
            path,
            *tls,
            *expect_status,
            *port,
            *reuse_connection,
        )),
    }
}

/// Connect, and close again
fn tcp(
    settings: &HealthCheckSettings,
    sni: Option<&str>,
) -> Box<dyn HealthCheck + Send + Sync + 'static> {
    let mut check = match sni {
        Some(sni) => *TcpHealthCheck::new_tls(sni),
        None => TcpHealthCheck::default(),
    };

    check.consecutive_success = settings.consecutive_success;
    check.consecutive_failure = settings.consecutive_failure;

    // The address on the template is a placeholder that Pingora replaces with
    // each backend's, so only the timeouts are worth setting here. Both are
    // set because a check that gets stuck in a TLS handshake is just as stuck
    // as one that never connects.
    check.peer_template.options.connection_timeout = Some(settings.timeout);
    check.peer_template.options.total_connection_timeout = Some(settings.timeout);

    Box::new(check)
}

/// Make a request, and check the status it comes back with
fn http(
    settings: &HealthCheckSettings,
    host: &str,
    path: &str,
    tls: bool,
    expect_status: u16,
    port: Option<u16>,
    reuse_connection: bool,
) -> Box<dyn HealthCheck + Send + Sync + 'static> {
    let mut check = HttpHealthCheck::new(host, tls);

    check.consecutive_success = settings.consecutive_success;
    check.consecutive_failure = settings.consecutive_failure;
    check.reuse_connection = reuse_connection;
    check.port_override = port;

    check.peer_template.options.connection_timeout = Some(settings.timeout);
    check.peer_template.options.total_connection_timeout = Some(settings.timeout);
    check.peer_template.options.read_timeout = Some(settings.timeout);

    // `HttpHealthCheck::new` builds a request for `/`; the configured path
    // replaces it. The parser has already checked that the path is a valid
    // request target.
    let mut req = RequestHeader::build("GET", path.as_bytes(), None)
        .expect("a validated path should build a request");
    req.append_header("Host", host)
        .expect("a validated host should be a header value");
    check.req = req;

    // Pingora's default accepts any 200 and nothing else, which is already
    // what an unset `expect-status` means, so this only takes over when the
    // operator asked for something different.
    if expect_status != 200 {
        check.validator = Some(Box::new(move |resp: &ResponseHeader| {
            if resp.status.as_u16() == expect_status {
                Ok(())
            } else {
                Error::e_explain(
                    CustomCode("unexpected health check status", resp.status.as_u16()),
                    format!("expected {expect_status}"),
                )
            }
        }));
    }

    Box::new(check)
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;

    fn settings() -> HealthCheckSettings {
        HealthCheckSettings {
            frequency: Duration::from_secs(5),
            timeout: Duration::from_millis(250),
            consecutive_success: 2,
            consecutive_failure: 3,
            parallel: false,
        }
    }

    #[test]
    fn no_health_check_builds_nothing() {
        assert!(build(&HealthCheckKind::None).is_none());
    }

    #[test]
    fn thresholds_reach_the_check() {
        let check = build(&HealthCheckKind::Tcp {
            settings: settings(),
            sni: None,
        })
        .unwrap();

        assert_eq!(check.health_threshold(true), 2);
        assert_eq!(check.health_threshold(false), 3);
    }

    #[test]
    fn an_http_check_builds_without_panicking() {
        // `build` unwraps the request construction, on the strength of the
        // parser having validated the path and host. This is the test that
        // says those `expect`s are safe for the values the parser lets past.
        let check = build(&HealthCheckKind::Http {
            settings: settings(),
            host: "app.example.com".into(),
            path: "/healthz?full=1".into(),
            tls: true,
            expect_status: 204,
            port: Some(9000),
            reuse_connection: true,
        });

        assert!(check.is_some());
    }
}
