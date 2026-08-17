//! End-to-end tests for the v0.8.x path control features
//!
//! These run a real River process against a real socket. That is the point:
//! normalization and the checks around request framing are about what arrives
//! on the wire, and no unit test can produce a request that an HTTP client
//! would refuse to construct.

mod harness;

use harness::{free_port, River, Upstream};

/// A service with one upstream and whatever extra configuration a test needs
fn config(port: u16, upstream: u16, extra: &str) -> String {
    format!(
        r#"
system {{
    threads-per-service 2
}}

services {{
    Test {{
        listeners {{
            "127.0.0.1:{port}"
        }}
        connectors {{
            "127.0.0.1:{upstream}"
        }}
{extra}
    }}
}}
"#
    )
}

fn start(extra: &str) -> (River, Upstream) {
    let upstream = Upstream::start();
    let port = free_port();
    let river = River::start(port, &config(port, upstream.port, extra));
    (river, upstream)
}

//
// Proxying at all
//

#[test]
fn a_request_reaches_the_upstream_unchanged() {
    let (river, upstream) = start("");

    let response = river.get("/api/users");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, "upstream\n");
    assert_eq!(upstream.only_request().target, "/api/users");
}

//
// Normalization
//

#[test]
fn a_traversal_is_resolved_before_the_upstream_sees_it() {
    let (river, upstream) = start("");

    let response = river.get("/static/../admin");

    assert_eq!(response.status, 200);
    // The whole reason normalization exists: the upstream server is asked for
    // the path River decided on, not the one the client wrote.
    assert_eq!(upstream.only_request().target, "/admin");
}

#[test]
fn an_encoded_traversal_is_resolved_too() {
    let (river, upstream) = start("");

    assert_eq!(river.get("/static/%2E%2E/admin").status, 200);
    assert_eq!(upstream.only_request().target, "/admin");
}

#[test]
fn duplicate_slashes_are_collapsed() {
    let (river, upstream) = start("");

    assert_eq!(river.get("/a//b///c").status, 200);
    assert_eq!(upstream.only_request().target, "/a/b/c");
}

#[test]
fn an_encoded_separator_is_refused() {
    let (river, upstream) = start("");

    assert_eq!(river.get("/a%2Fb").status, 400);
    assert!(
        upstream.requests().is_empty(),
        "a refused request must not reach the upstream"
    );
}

#[test]
fn climbing_above_the_root_is_refused() {
    let (river, upstream) = start("");

    assert_eq!(river.get("/../etc/passwd").status, 400);
    assert!(upstream.requests().is_empty());
}

#[test]
fn a_request_without_a_host_is_refused() {
    let (river, upstream) = start("");

    let response = river.raw("GET / HTTP/1.1\r\nConnection: close\r\n\r\n");

    assert_eq!(response.status, 400);
    assert!(upstream.requests().is_empty());
}

#[test]
fn two_host_headers_are_refused() {
    let (river, upstream) = start("");

    // The shape of a request smuggling attack: River and the upstream server
    // could otherwise disagree about which site was asked for.
    let response = river.raw(
        "GET / HTTP/1.1\r\nHost: example.com\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(response.status, 400);
    assert!(upstream.requests().is_empty());
}

#[test]
fn a_check_that_is_turned_off_stops_refusing() {
    let (river, upstream) = start(
        r#"
        normalization {
            encoded-separators false
            percent-encoding false
        }
        "#,
    );

    assert_eq!(river.get("/a%2Fb").status, 200);
    assert_eq!(upstream.only_request().target, "/a%2Fb");
}

#[test]
fn the_normalization_answer_can_be_chosen() {
    let (river, _upstream) = start(
        r#"
        normalization {
            status 422
            body "nope\n"
        }
        "#,
    );

    let response = river.get("/a%2Fb");
    assert_eq!(response.status, 422);
    assert_eq!(response.body, "nope\n");
}

//
// Access control
//

#[test]
fn a_blocked_range_is_refused_with_the_configured_answer() {
    let (river, upstream) = start(
        r#"
        path-control {
            request-filters {
                filter kind="block-cidr-range" addrs="127.0.0.0/8" status=403 body="denied\n"
            }
        }
        "#,
    );

    let response = river.get("/");

    assert_eq!(response.status, 403);
    assert_eq!(response.body, "denied\n");
    assert!(upstream.requests().is_empty());
}

#[test]
fn an_allow_list_refuses_what_it_does_not_name() {
    let (river, upstream) = start(
        r#"
        path-control {
            request-filters {
                filter kind="allow-cidr-range" addrs="10.0.0.0/8"
            }
        }
        "#,
    );

    // The test client is on loopback, which the allow list does not include.
    assert_eq!(river.get("/").status, 403);
    assert!(upstream.requests().is_empty());
}

#[test]
fn an_allow_list_admits_what_it_names() {
    let (river, upstream) = start(
        r#"
        path-control {
            request-filters {
                filter kind="allow-cidr-range" addrs="127.0.0.0/8"
            }
        }
        "#,
    );

    assert_eq!(river.get("/").status, 200);
    assert_eq!(upstream.requests().len(), 1);
}

#[test]
fn an_untrusted_peer_cannot_forge_its_address() {
    let (river, upstream) = start(
        r#"
        client-ip {
            // Loopback is deliberately NOT trusted here, so the header below
            // must be ignored.
            trusted-proxies "10.0.0.0/8"
        }
        path-control {
            request-filters {
                filter kind="block-cidr-range" addrs="127.0.0.0/8"
            }
        }
        "#,
    );

    // A client claiming to be somewhere else must not escape the deny list.
    let response = river.raw(
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 10.1.2.3\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(response.status, 403);
    assert!(upstream.requests().is_empty());
}

#[test]
fn a_trusted_peer_hands_over_the_forwarded_address() {
    let (river, upstream) = start(
        r#"
        client-ip {
            trusted-proxies "127.0.0.0/8"
        }
        path-control {
            request-filters {
                // The connection is from loopback, but the forwarded address
                // is what the filter must judge.
                filter kind="block-cidr-range" addrs="203.0.113.0/24"
            }
        }
        "#,
    );

    let blocked = river.raw(
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 203.0.113.9\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(blocked.status, 403);

    let allowed = river.raw(
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 198.51.100.4\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(allowed.status, 200);
    assert_eq!(upstream.requests().len(), 1);
}

//
// Header modifiers
//

#[test]
fn headers_are_added_and_removed_on_the_way_out() {
    let (river, upstream) = start(
        r#"
        path-control {
            upstream-request {
                filter kind="remove-header-key-glob" pattern="x-internal-*"
                filter kind="remove-header" key="x-drop-me"
                filter kind="upsert-header" key="x-proxy-friend" value="river"
            }
        }
        "#,
    );

    let response = river.raw(
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Internal-Trace: abc\r\n\
         X-Drop-Me: yes\r\nX-Keep: yes\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(response.status, 200);

    let seen = upstream.only_request();
    assert!(
        !seen.has_header("x-internal-trace"),
        "glob should have removed it"
    );
    assert!(
        !seen.has_header("x-drop-me"),
        "exact removal should have taken it"
    );
    assert_eq!(seen.header("x-keep"), Some("yes"));
    assert_eq!(seen.header("x-proxy-friend"), Some("river"));
}

#[test]
fn response_headers_are_changed_on_the_way_back() {
    let (river, _upstream) = start(
        r#"
        path-control {
            upstream-response {
                filter kind="remove-header-key-regex" pattern="(?i)^etag$"
            }
            response-filters {
                filter kind="upsert-header" key="x-served-by" value="river"
            }
        }
        "#,
    );

    let response = river.get("/");

    assert_eq!(response.status, 200);
    assert!(
        !response.has_header("etag"),
        "the upstream sent an ETag and it should have been removed"
    );
    assert_eq!(response.header("x-served-by"), Some("river"));
}

//
// Body limits
//

#[test]
fn a_declared_oversize_body_is_refused_before_it_is_read() {
    let (river, upstream) = start(
        r#"
        path-control {
            request-body {
                filter kind="max-size" max-bytes=16
            }
        }
        "#,
    );

    let response = river.raw(
        "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(response.status, 413);
    assert!(upstream.requests().is_empty());
}

#[test]
fn a_body_within_the_limit_is_proxied() {
    let (river, upstream) = start(
        r#"
        path-control {
            request-body {
                filter kind="max-size" max-bytes=16
            }
        }
        "#,
    );

    let response = river.raw(
        "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    );

    assert_eq!(response.status, 200);
    assert_eq!(upstream.only_request().method, "POST");
}

//
// Routing
//

fn routed_config(port: u16, api: u16, rest: u16) -> String {
    format!(
        r#"
system {{
    threads-per-service 2
}}

services {{
    Test {{
        listeners {{
            "127.0.0.1:{port}"
        }}
        routes {{
            no-route status=404 body="no route\n"

            route "/healthz" match="exact" {{
                connectors {{
                    "127.0.0.1:{api}"
                }}
            }}
            route "/api" {{
                connectors {{
                    "127.0.0.1:{api}"
                }}
            }}
            route "/upload" methods="POST" {{
                connectors {{
                    "127.0.0.1:{rest}"
                }}
            }}
        }}
    }}
}}
"#
    )
}

#[test]
fn routes_send_requests_to_different_upstreams() {
    let api = Upstream::start();
    let rest = Upstream::start();
    let port = free_port();
    let river = River::start(port, &routed_config(port, api.port, rest.port));

    assert_eq!(river.get("/api/users").status, 200);
    assert_eq!(api.only_request().target, "/api/users");
    assert!(rest.requests().is_empty());

    let posted = river.raw(
        "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(posted.status, 200);
    assert_eq!(rest.only_request().target, "/upload");
}

#[test]
fn a_request_matching_no_route_gets_the_configured_answer() {
    let api = Upstream::start();
    let rest = Upstream::start();
    let port = free_port();
    let river = River::start(port, &routed_config(port, api.port, rest.port));

    let response = river.get("/nothing/here");

    assert_eq!(response.status, 404);
    assert_eq!(response.body, "no route\n");
    assert!(api.requests().is_empty());
    assert!(rest.requests().is_empty());
}

#[test]
fn a_method_that_a_route_does_not_take_falls_through() {
    let api = Upstream::start();
    let rest = Upstream::start();
    let port = free_port();
    let river = River::start(port, &routed_config(port, api.port, rest.port));

    // /upload is POST-only, and no other route claims it, so a GET is a
    // no-route rather than a request sent to the wrong server.
    assert_eq!(river.get("/upload").status, 404);
    assert!(rest.requests().is_empty());
}

#[test]
fn an_exact_route_wins_over_a_prefix() {
    let api = Upstream::start();
    let rest = Upstream::start();
    let port = free_port();
    let river = River::start(port, &routed_config(port, api.port, rest.port));

    assert_eq!(river.get("/healthz").status, 200);
    assert_eq!(api.only_request().target, "/healthz");
}

//
// Overload
//

#[test]
fn a_request_header_over_the_limit_is_shed() {
    let (river, upstream) = start(
        r#"
        overload {
            max-headers 3
        }
        "#,
    );

    let response = river.raw(
        "GET / HTTP/1.1\r\nHost: example.com\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\n\
         Connection: close\r\n\r\n",
    );

    assert_eq!(response.status, 503);
    assert!(upstream.requests().is_empty());
}

#[test]
fn a_request_within_the_header_limit_is_proxied() {
    let (river, upstream) = start(
        r#"
        overload {
            max-headers 32
        }
        "#,
    );

    assert_eq!(river.get("/").status, 200);
    assert_eq!(upstream.requests().len(), 1);
}

//
// Rate limiting, which predates this milestone but is worth pinning down
//

#[test]
fn a_source_ip_rate_limit_eventually_says_no() {
    let (river, _upstream) = start(
        r#"
        rate-limiting {
            rule kind="source-ip" \
                max-buckets=10 tokens-per-bucket=3 refill-qty=1 refill-rate-ms=60000
        }
        "#,
    );

    // Three tokens, and a refill an hour away, so the fourth request has
    // nothing to take.
    for i in 0..3 {
        assert_eq!(river.get("/").status, 200, "request {i} should be allowed");
    }
    assert_eq!(river.get("/").status, 429);
}

/// What the client ends up seeing depends on how far the response had got.
///
/// The one thing that always holds is that the full body does not arrive. If
/// Pingora has not yet flushed the response header - which is the case for a
/// response small enough to still be buffered - the configured status is sent
/// instead. If it has, HTTP gives no way to retract the status that already
/// went out, and the body is simply cut short. This test pins down the part
/// that is guaranteed, and tolerates both endings.
#[test]
fn an_oversize_response_body_does_not_arrive_in_full() {
    let upstream = Upstream::start_with_body(vec![b'x'; 8192]);
    let port = free_port();
    let river = River::start(
        port,
        &config(
            port,
            upstream.port,
            r#"
        path-control {
            response-body {
                filter kind="max-size" max-bytes=64
            }
        }
        "#,
        ),
    );

    let response = river.get("/");

    assert!(
        response.body.len() < upstream.body_len(),
        "expected the body not to arrive in full, got {} of {} bytes",
        response.body.len(),
        upstream.body_len()
    );
    assert!(
        response.status == 502 || response.status == 200,
        "expected either the configured status or a truncated success, got {}",
        response.status
    );
}
