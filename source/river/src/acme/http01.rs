//! Answering `http-01` challenges
//!
//! The certificate authority fetches
//! `http://<domain>/.well-known/acme-challenge/<token>` over plain HTTP and
//! expects the key authorization back. River answers those requests from any
//! listener it already has, rather than requiring a dedicated one - so a
//! service that already listens on port 80 needs no extra configuration.
//!
//! A dedicated listener is available too, via `acme.challenge-listener`, for
//! deployments that serve only HTTPS and have nothing on port 80 otherwise.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use bytes::Bytes;
use instant_acme::ChallengeType;
use pingora::server::Server;
use pingora_core::{upstreams::peer::HttpPeer, Error, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

use super::{
    solver::{Challenge, ChallengeSolver, HTTP01_PREFIX},
    AcmeError,
};
use crate::{config::internal::ListenerConfig, populate_listners, tls::store::CertStore};

/// The challenge responses River is currently prepared to serve
///
/// Written by the ACME service while an order is in flight, read by whichever
/// listener the certificate authority happens to connect to.
#[derive(Default)]
pub struct ChallengeStore {
    /// Token to key authorization
    ///
    /// Tokens are unique per authorization, so this does not need to be keyed
    /// by domain as well.
    tokens: RwLock<HashMap<String, String>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, token: String, key_authorization: String) {
        self.write().insert(token, key_authorization);
    }

    pub fn remove(&self, token: &str) {
        self.write().remove(token);
    }

    /// The response for `token`, if River is serving one
    pub fn get(&self, token: &str) -> Option<String> {
        self.read().get(token).cloned()
    }

    /// Is River waiting on any challenge right now?
    ///
    /// Lets the request path skip the lookup entirely in the common case, when
    /// no order is in flight.
    pub fn is_idle(&self) -> bool {
        self.read().is_empty()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, String>> {
        self.tokens.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, String>> {
        self.tokens.write().unwrap_or_else(|e| e.into_inner())
    }
}

/// Publishes `http-01` responses into a [`ChallengeStore`]
pub struct Http01Solver {
    store: Arc<ChallengeStore>,
}

impl Http01Solver {
    pub fn new(store: Arc<ChallengeStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl ChallengeSolver for Http01Solver {
    fn challenge_type(&self) -> ChallengeType {
        ChallengeType::Http01
    }

    async fn present(&self, challenge: &Challenge) -> Result<(), AcmeError> {
        // Nothing to wait for: the listeners are already running and read from
        // this store, so the response is retrievable the moment it is stored.
        self.store.insert(
            challenge.token.clone(),
            challenge.key_authorization.as_str().to_string(),
        );

        tracing::debug!(
            domain = %challenge.domain,
            path = %challenge.http_path(),
            "Serving an http-01 challenge response"
        );

        Ok(())
    }

    async fn cleanup(&self, challenge: &Challenge) {
        self.store.remove(&challenge.token);
    }
}

/// Answer this request if it is an ACME challenge River is serving
///
/// Returns `true` when the request was handled and no further processing
/// should happen.
///
/// River only claims tokens it actually issued. A request under the challenge
/// prefix for some other token is passed through untouched, so an upstream
/// running its own ACME client keeps working.
pub async fn try_serve(store: &ChallengeStore, session: &mut Session) -> Result<bool> {
    if store.is_idle() {
        return Ok(false);
    }

    let header = session.req_header();
    if header.method != http::Method::GET {
        return Ok(false);
    }

    let Some(token) = header.uri.path().strip_prefix(HTTP01_PREFIX) else {
        return Ok(false);
    };

    // Path traversal is not a concern here - the token is used as a map key,
    // never as a path - but an empty or nested token is never one of ours.
    let Some(key_authorization) = store.get(token) else {
        return Ok(false);
    };

    tracing::info!(token = %token, "Answering an ACME http-01 challenge");

    let body = Bytes::from(key_authorization);

    // RFC 8555 section 8.3 asks for `application/octet-stream`.
    let mut response = ResponseHeader::build(http::StatusCode::OK, Some(2))?;
    response.insert_header(http::header::CONTENT_TYPE, "application/octet-stream")?;
    response.insert_header(http::header::CONTENT_LENGTH, body.len().to_string())?;

    session
        .write_response_header(Box::new(response), false)
        .await?;
    session.write_response_body(Some(body), true).await?;

    Ok(true)
}

/// A listener that exists only to answer ACME challenges
///
/// Anything that is not a challenge is redirected to HTTPS, which is what an
/// operator running HTTPS-only wants from port 80 anyway.
pub struct AcmeChallengeService {
    store: Arc<ChallengeStore>,
}

/// Build the dedicated challenge listener described by `acme.challenge-listener`
pub fn challenge_service(
    addr: &str,
    store: Arc<ChallengeStore>,
    server: &Server,
    cert_store: &Arc<CertStore>,
) -> Box<dyn pingora::services::ServiceWithDependents> {
    let mut service = pingora_proxy::http_proxy_service_with_name(
        &server.configuration,
        AcmeChallengeService { store },
        "ACME Challenge",
    );

    populate_listners(
        vec![ListenerConfig {
            source: crate::config::internal::ListenerKind::Tcp {
                addr: addr.to_string(),
                tls: None,
                offer_h2: false,
            },
        }],
        &mut service,
        cert_store,
    );

    Box::new(service)
}

#[async_trait]
impl ProxyHttp for AcmeChallengeService {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Every request is answered in `request_filter`, so nothing should
        // reach this stage.
        Err(Error::new_str("Request Failed"))
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        if try_serve(&self.store, session).await? {
            return Ok(true);
        }

        let header = session.req_header();
        let host = header
            .uri
            .authority()
            .map(|a| a.as_str().to_string())
            .or_else(|| {
                header
                    .headers
                    .get(http::header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .map(str::to_string)
            });

        let mut response = match host {
            Some(host) => {
                let path = header
                    .uri
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/");

                let mut response =
                    ResponseHeader::build(http::StatusCode::MOVED_PERMANENTLY, Some(2))?;
                response.insert_header(http::header::LOCATION, format!("https://{host}{path}"))?;
                response
            }
            None => {
                // No host to redirect to, so there is nothing useful to say.
                ResponseHeader::build(http::StatusCode::BAD_REQUEST, Some(1))?
            }
        };
        response.insert_header(http::header::CONTENT_LENGTH, "0")?;

        session
            .write_response_header(Box::new(response), true)
            .await?;

        Ok(true)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn stores_and_retrieves_responses() {
        let store = ChallengeStore::new();
        assert!(store.is_idle());

        store.insert("token-a".into(), "token-a.thumbprint".into());
        assert!(!store.is_idle());
        assert_eq!(store.get("token-a").as_deref(), Some("token-a.thumbprint"));
        assert!(store.get("token-b").is_none());

        store.remove("token-a");
        assert!(store.is_idle());
        assert!(store.get("token-a").is_none());
    }

    #[test]
    fn the_challenge_prefix_matches_the_rfc() {
        // The CA builds this URL itself, so getting it wrong means every
        // validation fails with a 404 that is awkward to trace back.
        assert_eq!(HTTP01_PREFIX, "/.well-known/acme-challenge/");

        let path = format!("{HTTP01_PREFIX}sometoken");
        assert_eq!(path.strip_prefix(HTTP01_PREFIX), Some("sometoken"));
    }
}
