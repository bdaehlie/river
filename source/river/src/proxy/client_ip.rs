//! Working out which address a request actually came from
//!
//! Requirement 10 of the milestone. When River sits behind a load balancer or
//! a CDN, the address of the TCP peer is the intermediary's, not the client's.
//! Filtering and rate limiting on that address is worse than useless: every
//! request looks like it came from one machine, so deny lists match nothing and
//! every client shares a single rate limit bucket.
//!
//! The fix is to believe a forwarding header, but only from a peer that was
//! configured as a trusted proxy. Anyone may set `X-Forwarded-For`; the header
//! is only evidence when the connection came from something that is known to
//! rewrite it.

use std::net::IpAddr;

use cidr::IpCidr;
use http::HeaderName;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_proxy::Session;

use crate::config::internal::ClientIpConfig;

/// The address a request should be attributed to
///
/// `None` for a connection over a unix domain socket, which has no address at
/// all.
pub fn resolve(session: &Session, config: Option<&ClientIpConfig>) -> Option<IpAddr> {
    let peer = match session.downstream_session.client_addr()? {
        SocketAddr::Inet(addr) => addr.ip(),
        SocketAddr::Unix(_) => return None,
    };

    let Some(config) = config else {
        return Some(peer);
    };

    // An untrusted peer's claim about who it is forwarding for is just a
    // header it chose to send. Ignore it.
    if !is_trusted(&peer, &config.trusted_proxies) {
        return Some(peer);
    }

    Some(from_header(session, config).unwrap_or(peer))
}

/// Walk the forwarding header for the furthest address we are willing to believe
///
/// The header reads left to right as oldest to newest, so the rightmost entry
/// was added by the nearest proxy. Walking right to left and stopping at the
/// first address that is not itself a trusted proxy gives the last address that
/// something we trust vouched for.
///
/// Taking the *leftmost* entry instead is the classic mistake here: that one is
/// whatever the original client sent, so anyone could walk straight through a
/// deny list by adding a header to their own request.
fn from_header(session: &Session, config: &ClientIpConfig) -> Option<IpAddr> {
    let raw = session
        .downstream_session
        .req_header()
        .headers
        .get(&config.header)?
        .to_str()
        .ok()?;

    let addresses: Vec<IpAddr> = raw
        .split(',')
        .filter_map(|entry| parse_entry(entry.trim()))
        .collect();

    // Every entry was a proxy we trust, so the leftmost is as far back as the
    // chain goes.
    addresses
        .iter()
        .rev()
        .find(|addr| !is_trusted(addr, &config.trusted_proxies))
        .or(addresses.first())
        .copied()
}

/// One entry of a forwarding header
///
/// Entries are bare addresses in practice, but a port is common enough - and
/// an IPv6 address may be bracketed - that both are worth handling rather than
/// silently dropping the entry.
fn parse_entry(entry: &str) -> Option<IpAddr> {
    if let Ok(addr) = entry.parse::<IpAddr>() {
        return Some(addr);
    }
    if let Ok(addr) = entry.parse::<std::net::SocketAddr>() {
        return Some(addr.ip());
    }
    // `[::1]` with no port
    let trimmed = entry.strip_prefix('[')?.strip_suffix(']')?;
    trimmed.parse::<IpAddr>().ok()
}

fn is_trusted(addr: &IpAddr, trusted: &[IpCidr]) -> bool {
    trusted.iter().any(|cidr| cidr.contains(addr))
}

/// The header River reads when none is configured
pub fn default_header() -> HeaderName {
    HeaderName::from_static("x-forwarded-for")
}

#[cfg(test)]
mod test {
    use super::*;

    fn config(trusted: &[&str]) -> ClientIpConfig {
        ClientIpConfig {
            trusted_proxies: trusted.iter().map(|c| c.parse().unwrap()).collect(),
            header: default_header(),
        }
    }

    /// The header-walking half, exercised directly - building a `Session`
    /// requires a live connection, so the socket half is covered by the
    /// integration tests instead.
    fn pick(peer: &str, forwarded: &[&str], trusted: &[&str]) -> IpAddr {
        let config = config(trusted);
        let peer: IpAddr = peer.parse().unwrap();

        if !is_trusted(&peer, &config.trusted_proxies) {
            return peer;
        }

        let addresses: Vec<IpAddr> = forwarded.iter().map(|a| a.parse().unwrap()).collect();
        addresses
            .iter()
            .rev()
            .find(|addr| !is_trusted(addr, &config.trusted_proxies))
            .or(addresses.first())
            .copied()
            .unwrap_or(peer)
    }

    #[test]
    fn an_untrusted_peer_is_the_client_whatever_it_claims() {
        // The attack this prevents: a client sends its own X-Forwarded-For
        // hoping to be attributed to some other address.
        assert_eq!(
            pick("203.0.113.9", &["10.1.1.1"], &["10.0.0.0/8"]),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_trusted_peer_hands_over_the_forwarded_address() {
        assert_eq!(
            pick("10.0.0.1", &["203.0.113.9"], &["10.0.0.0/8"]),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_hops_are_walked_past_from_the_right() {
        // client, then two proxies of our own. The rightmost untrusted entry
        // is the client.
        assert_eq!(
            pick(
                "10.0.0.1",
                &["203.0.113.9", "10.0.0.5", "10.0.0.6"],
                &["10.0.0.0/8"]
            ),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_spoofed_prefix_does_not_win() {
        // The client put a fake entry at the front. The real one is the
        // rightmost untrusted address, which is what it actually connected as.
        assert_eq!(
            pick(
                "10.0.0.1",
                &["192.0.2.1", "203.0.113.9", "10.0.0.5"],
                &["10.0.0.0/8"]
            ),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_chain_of_only_trusted_proxies_falls_back_to_the_leftmost() {
        assert_eq!(
            pick("10.0.0.1", &["10.0.0.4", "10.0.0.5"], &["10.0.0.0/8"]),
            "10.0.0.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn entries_may_carry_a_port_or_brackets() {
        assert_eq!(
            parse_entry("203.0.113.9:4321"),
            Some("203.0.113.9".parse().unwrap())
        );
        assert_eq!(
            parse_entry("[2001:db8::1]"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            parse_entry("[2001:db8::1]:443"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(parse_entry("not-an-address"), None);
    }
}
