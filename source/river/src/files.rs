//! File Serving
//!
//! River's file server is built on [`ServeDir`] from the `tower-http` crate,
//! which handles the fiddly parts of serving files over HTTP: rejecting paths
//! that try to escape the root directory, guessing content types, and
//! answering conditional and range requests.
//!
//! [`ServeDir`] is a `tower` service rather than a Pingora one, so this module
//! adapts between the two. The adaptation is straightforward because both sides
//! speak the types from the `http` crate: we build an [`http::Request`] from the
//! downstream session, hand it to [`ServeDir`], and copy the resulting
//! [`http::Response`] back into the session.

use std::path::PathBuf;

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty};
use pingora::{server::Server, upstreams::peer::HttpPeer};
use pingora_core::{Error, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use tower_http::services::ServeDir;

use crate::{config::internal::FileServerConfig, populate_listners};

/// Create a new file serving service
pub fn river_file_server(
    conf: FileServerConfig,
    server: &Server,
) -> Box<dyn pingora::services::ServiceWithDependents> {
    let file_server = FileServer::new(&conf.name, conf.base_path);

    let mut my_proxy =
        pingora_proxy::http_proxy_service_with_name(&server.configuration, file_server, &conf.name);

    populate_listners(conf.listeners, &mut my_proxy);

    Box::new(my_proxy)
}

pub struct FileServer {
    /// The handler used to serve files.
    ///
    /// This is `None` when the file server was configured without a
    /// `base-path`, in which case there is no directory to serve from and
    /// every request is rejected.
    serve_dir: Option<ServeDir>,
}

impl FileServer {
    fn new(name: &str, base_path: Option<PathBuf>) -> Self {
        let serve_dir = match base_path {
            Some(path) => Some(ServeDir::new(path)),
            None => {
                tracing::warn!(
                    "File server '{name}' has no 'base-path' configured, \
                     it will reject all requests"
                );
                None
            }
        };

        Self { serve_dir }
    }
}

/// A small wrapper for delegating requests to a file server
#[async_trait::async_trait]
impl ProxyHttp for FileServer {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // This should never happen - we fully handle the request at the
        // `request_filter` stage, so no requests should make it to the
        // later `upstream_peer` stage.
        Err(Error::new_str("Request Failed"))
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let Some(serve_dir) = self.serve_dir.as_ref() else {
            return Err(Error::new_str("File server is not configured"));
        };

        // `ServeDir` only inspects the method, URI and headers of the request,
        // so we can hand it an empty body.
        let downstream = session.req_header();
        let mut request = Request::builder()
            .method(downstream.method.clone())
            .uri(downstream.uri.clone());

        if let Some(headers) = request.headers_mut() {
            headers.clone_from(&downstream.headers);
        }

        let request = request.body(Empty::<Bytes>::new()).map_err(|e| {
            tracing::error!("Failed to build file server request: {e}");
            Error::new_str("Request Failed")
        })?;

        // `try_call` takes `&mut self`, so serve from a clone. `ServeDir` is
        // cheap to clone - it holds the root path and a handful of flags.
        let response = serve_dir.clone().try_call(request).await.map_err(|e| {
            tracing::error!("File server failed to handle request: {e}");
            Error::new_str("Request Failed")
        })?;

        let (parts, mut body) = response.into_parts();

        let mut header = ResponseHeader::build(parts.status, Some(parts.headers.len()))?;
        for (key, value) in parts.headers.iter() {
            header.append_header(key.clone(), value.clone())?;
        }
        session
            .write_response_header(Box::new(header), false)
            .await?;

        // Stream the file to the downstream session one frame at a time, rather
        // than reading it all into memory first.
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| {
                tracing::error!("File server failed to read response body: {e}");
                Error::new_str("Request Failed")
            })?;

            // Trailers are not expected here, and Pingora has no way to send
            // them on this path, so only data frames are forwarded.
            if let Ok(data) = frame.into_data() {
                session.write_response_body(Some(data), false).await?;
            }
        }

        // Mark the end of the response body.
        session.write_response_body(None, true).await?;

        Ok(true)
    }
}
