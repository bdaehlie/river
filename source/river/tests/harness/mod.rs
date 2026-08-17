//! A running River, a test upstream server, and a way to speak to both
//!
//! The roadmap lists "an integration test suite specific to river" as work
//! that needs scheduling. This is the minimal version of it, built because
//! several of the v0.8.x path control features cannot be tested any other way:
//! normalization and request smuggling checks are about what arrives on a
//! socket, and a hand-written malformed request is the only way to produce it.
//!
//! Everything here uses `std` rather than an async runtime. The tests are
//! sequential, blocking, and short; a runtime would add moving parts without
//! making anything clearer.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

/// How long to wait for River to start listening before giving up
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);

/// A port that nothing is listening on
///
/// Racy in principle - something else could take the port between the probe
/// and the bind - but it is what a test suite can do without a port broker,
/// and the window is small.
pub fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("should be able to bind a port");
    listener.local_addr().unwrap().port()
}

/// What one request looked like by the time it reached the upstream server
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenRequest {
    pub method: String,
    /// The request target exactly as it arrived, before any parsing
    pub target: String,
    pub headers: Vec<(String, String)>,
}

impl SeenRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn has_header(&self, name: &str) -> bool {
        self.header(name).is_some()
    }
}

/// A minimal HTTP server that records what it was asked for
///
/// It answers every request the same way. The point is not to be a web server
/// but to be a witness: the tests assert on what River forwarded, which is the
/// only way to tell that a path was normalized or a header removed.
pub struct Upstream {
    pub port: u16,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
    stop: Arc<AtomicBool>,
    /// The body every response carries, so tests can size it
    body: Vec<u8>,
}

impl Upstream {
    pub fn start() -> Self {
        Self::start_with_body(b"upstream\n".to_vec())
    }

    pub fn start_with_body(body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("upstream should bind");
        let port = listener.local_addr().unwrap().port();

        let seen: Arc<Mutex<Vec<SeenRequest>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));

        let thread_seen = seen.clone();
        let thread_stop = stop.clone();
        let thread_body = body.clone();

        thread::spawn(move || {
            for stream in listener.incoming() {
                if thread_stop.load(Ordering::Relaxed) {
                    return;
                }
                let Ok(stream) = stream else { continue };

                let seen = thread_seen.clone();
                let body = thread_body.clone();
                thread::spawn(move || {
                    let _ = serve(stream, seen, body);
                });
            }
        });

        Self {
            port,
            seen,
            stop,
            body,
        }
    }

    /// Every request this server has been sent, in order
    pub fn requests(&self) -> Vec<SeenRequest> {
        self.seen.lock().unwrap().clone()
    }

    /// The one request this server was sent
    ///
    /// Panics when there was not exactly one, since a test that expected a
    /// request to be proxied and finds none has failed in a way worth naming.
    pub fn only_request(&self) -> SeenRequest {
        let requests = self.requests();
        assert_eq!(
            requests.len(),
            1,
            "expected exactly one request to reach the upstream, saw {}: {:#?}",
            requests.len(),
            requests
        );
        requests.into_iter().next().unwrap()
    }

    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Unblock the accept loop so the thread can notice and exit.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn serve(
    mut stream: TcpStream,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
    body: Vec<u8>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }

    let mut parts = request_line.trim_end().split(' ');
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    let mut headers = vec![];
    let mut content_length = 0usize;

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }

    // Read whatever body was announced, so the client is not left writing into
    // a socket nobody is reading.
    if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        let _ = reader.read_exact(&mut buf);
    }

    seen.lock().unwrap().push(SeenRequest {
        method,
        target,
        headers,
    });

    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nETag: \"abc\"\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Write);

    Ok(())
}

/// A River process running against a configuration file written for the test
pub struct River {
    child: Child,
    pub port: u16,
    /// Kept alive so the file is not removed while River is reading it
    _config: tempfile::NamedTempFile,
}

impl River {
    /// Start River with the given KDL, which must listen on `port`
    pub fn start(port: u16, config: &str) -> Self {
        use std::io::Write as _;

        let mut file = tempfile::Builder::new()
            .suffix(".kdl")
            .tempfile()
            .expect("should be able to write a config file");
        file.write_all(config.as_bytes()).unwrap();
        file.flush().unwrap();

        let child = Command::new(env!("CARGO_BIN_EXE_river"))
            .arg("--config-kdl")
            .arg(file.path())
            .stdout(Stdio::null())
            // Left inherited: when a test fails because River refused its
            // configuration, the diagnostic is the most useful thing on screen.
            .stderr(Stdio::inherit())
            .spawn()
            .expect("river binary should start");

        let river = Self {
            child,
            port,
            _config: file,
        };
        river.wait_until_listening();
        river
    }

    fn wait_until_listening(&self) {
        let addr: SocketAddr = ([127, 0, 0, 1], self.port).into();
        let deadline = Instant::now() + STARTUP_TIMEOUT;

        while Instant::now() < deadline {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }

        panic!(
            "river did not start listening on port {} in time",
            self.port
        );
    }

    /// Send raw bytes and read everything that comes back
    ///
    /// Raw, rather than through an HTTP client, because several of these tests
    /// send requests no client would agree to construct.
    pub fn raw(&self, request: &str) -> Response {
        let addr: SocketAddr = ([127, 0, 0, 1], self.port).into();
        let mut stream =
            TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("should connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        stream.write_all(request.as_bytes()).expect("should write");
        stream.flush().unwrap();

        let mut raw = Vec::new();
        let _ = stream.read_to_end(&mut raw);

        Response::parse(&raw)
    }

    /// A well-formed GET, for the cases that are not about malformed requests
    pub fn get(&self, path: &str) -> Response {
        self.raw(&format!(
            "GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        ))
    }
}

impl Drop for River {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What River answered
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    fn parse(raw: &[u8]) -> Self {
        let text = String::from_utf8_lossy(raw);
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_ref(), ""));

        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let status = status_line
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                panic!("could not read a status from response: {status_line:?}");
            });

        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect();

        Self {
            status,
            headers,
            body: body.to_string(),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn has_header(&self, name: &str) -> bool {
        self.header(name).is_some()
    }
}
