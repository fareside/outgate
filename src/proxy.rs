//! HTTP/TLS MITM proxy domain.
//!
//! The proxy has four runtime concepts:
//!
//! - `ProxyServer`: owns the listening socket and accepts client TCP sessions.
//! - `ClientSession`: owns one HTTP/1.1 conversation with a single client.
//! - `MitmProxy`: routes requests to local admin handling, CONNECT interception,
//!   or upstream forwarding.
//! - `StreamingRequest`: adapts Hyper's incoming request body to reqwest without
//!   collecting it first.
//!
//! Outgate's job is egress policy, not traffic dumping. Request bodies stay
//! untouched until either JavaScript reads the native `Request` stream or the
//! Rust-only proxy path streams them upstream with `reqwest`.

use crate::body::{BodyError, ResBody, empty_response, full_body, stream_body, text_response};
use crate::ca::{CaError, CertificateAuthority};
use crate::cli::Cli;
use crate::interceptor::{
    InterceptContext, InterceptRequest, InterceptResponse, InterceptorError, JsInterceptors,
    is_interceptor_module,
};
use crate::kv::SharedKv;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures_util::TryStreamExt;
use http_body_util::BodyDataStream;
use hyper::body::Incoming;
use hyper::header::{
    CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue,
    PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TRANSFER_ENCODING,
};
use hyper::http::HeaderMap as HttpHeaderMap;
use hyper::http::uri::InvalidUri;
use hyper::http::{Error as HttpError, uri::Authority};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_util::future::FutureExt;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub type ProxyResult<T> = Result<T, ProxyError>;

/// Errors produced by the proxy runtime.
///
/// Request handling converts these into `502 Bad Gateway` responses so one bad
/// client request does not kill the process. Server startup and listener errors
/// are returned to `main` and printed as process-level failures.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("CONNECT request missing host:port authority")]
    MissingConnectAuthority,

    #[error("HTTP request missing Host header")]
    MissingHostHeader,

    #[error("proxy authorization must use Basic credentials")]
    UnsupportedProxyAuthorization,

    #[error("proxy authorization is not valid Basic credentials")]
    InvalidProxyAuthorization,

    #[error(transparent)]
    Ca(#[from] CaError),

    #[error(transparent)]
    HeaderToStr(#[from] hyper::header::ToStrError),

    #[error(transparent)]
    Http(#[from] HttpError),

    #[error(transparent)]
    Hyper(#[from] hyper::Error),

    #[error(transparent)]
    InvalidUri(#[from] InvalidUri),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    Interceptor(#[from] InterceptorError),
}

/// Start the proxy listener and accept sessions forever.
pub async fn serve(command: Cli, cancellation_token: CancellationToken) -> ProxyResult<()> {
    let server = ProxyServer::bind(command).await?;
    server
        .with_cancellation_token(cancellation_token)
        .run()
        .await
}

/// Long-running proxy server.
///
/// This object is intentionally small: bind once, print the local endpoints,
/// then turn each accepted TCP stream into a `ClientSession`.
pub struct ProxyServer {
    listener: TcpListener,
    bound_addr: SocketAddr,
    proxy: Arc<MitmProxy>,
    interceptor_watch_path: Option<Arc<PathBuf>>,
    cancellation_token: CancellationToken,
}

impl ProxyServer {
    /// Bind the configured listener and build all process-wide collaborators.
    pub async fn bind(command: Cli) -> ProxyResult<Self> {
        let ca = CertificateAuthority::load_or_create(command.certificate())?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let interceptor = command
            .intercept()
            .map(JsInterceptors::from_path)
            .transpose()?;
        let interceptor_watch_path = interceptor.as_ref().and_then(|i| i.watch_path());
        let interceptor = interceptor.map(|i| Arc::new(RwLock::new(i)));
        let listener = TcpListener::bind(command.addr()).await?;
        let bound_addr = listener.local_addr()?;
        let kv = SharedKv::new();
        let proxy = Arc::new(MitmProxy::new(client, ca, interceptor, kv));

        let cancellation_token = CancellationToken::new();

        Ok(Self {
            listener,
            bound_addr,
            proxy,
            interceptor_watch_path,
            cancellation_token,
        })
    }

    pub fn with_cancellation_token(mut self, cancellation_token: CancellationToken) -> Self {
        self.cancellation_token = cancellation_token;
        self
    }

    /// Accept client connections forever.
    pub async fn run(self) -> ProxyResult<()> {
        self.print_startup().await;

        let listener = self.listener;
        let proxy = self.proxy;
        let interceptor_watch_path = self.interceptor_watch_path;

        if let Some(dir_path) = interceptor_watch_path
            && let Some(interceptor_lock) = proxy.interceptor.clone()
        {
            info!("watching {} for interceptor changes", dir_path.display());
            let cancellation_token = self.cancellation_token.clone();
            tokio::spawn(watch_directory_interceptors(
                interceptor_lock,
                dir_path,
                cancellation_token,
            ));
        }

        while let Some(accepted) = listener
            .accept()
            .with_cancellation_token(&self.cancellation_token)
            .await
        {
            let (stream, peer) = accepted?;
            ClientSession::plain(peer, Arc::clone(&proxy)).spawn(stream);
        }

        Ok(())
    }

    /// Print the handful of URLs/paths humans need after startup.
    async fn print_startup(&self) {
        eprintln!("outgate listening on http://{}", self.bound_addr);
        eprintln!(
            "private CA bundle: {}",
            self.proxy.ca.bundle_path().display()
        );
        eprintln!(
            "public CA certificate: {}",
            self.proxy.ca.public_cert_path().display()
        );
        eprintln!(
            "public CA endpoint: http://{}/_outgate/ca.pem",
            self.bound_addr
        );
        eprintln!(
            "configure a client with HTTP proxy {}; trust the CA only for local development",
            self.bound_addr
        );
        if let Some(interceptor_lock) = self.proxy.interceptor.as_ref() {
            eprintln!(
                "JavaScript intercept enabled: {}",
                interceptor_lock.read().await.display()
            );
        }
    }
}

/// One HTTP/1.1 conversation with one client.
///
/// There are two kinds of sessions:
///
/// - a plain outer proxy session accepted from the TCP listener;
/// - an inner decrypted HTTPS session created after a successful `CONNECT`.
#[derive(Clone)]
struct ClientSession {
    peer: SocketAddr,
    proxy: Arc<MitmProxy>,
    target: RequestTarget,
    interceptor_selector: Option<String>,
}

impl ClientSession {
    /// Build the outer session accepted directly from the listener.
    fn plain(peer: SocketAddr, proxy: Arc<MitmProxy>) -> Self {
        Self {
            peer,
            proxy,
            target: RequestTarget::PlainHttpProxy,
            interceptor_selector: None,
        }
    }

    /// Build the inner session that receives decrypted HTTPS requests.
    fn intercepted(
        peer: SocketAddr,
        proxy: Arc<MitmProxy>,
        authority: InterceptedAuthority,
        interceptor_selector: Option<String>,
    ) -> Self {
        Self {
            peer,
            proxy,
            target: RequestTarget::InterceptedHttps(authority),
            interceptor_selector,
        }
    }

    /// Spawn this session on Tokio and log protocol-level failures.
    fn spawn<I>(self, io: I)
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            self.serve(io).await;
        });
    }

    /// Serve this session over any async IO stream.
    async fn serve<I>(self, io: I)
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let peer = self.peer;
        let io = TokioIo::new(io);
        let connection = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(
                io,
                service_fn(move |req| {
                    let session = self.clone();
                    async move { Arc::clone(&session.proxy).handle(req, session).await }
                }),
            )
            .with_upgrades();

        if let Err(e) = connection.await {
            warn!(peer = %peer, "connection error: {e}");
        }
    }
}

/// Request target implied by the current client session.
///
/// Hyper gives origin-form request targets inside CONNECT tunnels. `reqwest`
/// needs absolute URLs, so this value object owns the conversion rule.
#[derive(Clone)]
enum RequestTarget {
    /// Plain HTTP proxy traffic, ideally already in absolute-form.
    PlainHttpProxy,

    /// HTTPS traffic decrypted from a CONNECT tunnel for this authority.
    InterceptedHttps(InterceptedAuthority),
}

impl RequestTarget {
    /// Normalize the request URI into the absolute form required upstream.
    fn normalize(&self, req: Request<Incoming>) -> ProxyResult<Request<Incoming>> {
        match self {
            Self::PlainHttpProxy => normalize_plain_http_request(req),
            Self::InterceptedHttps(authority) => {
                absolutize_intercepted_request(req, authority.as_str())
            }
        }
    }
}

/// Authority captured from `CONNECT host:port`.
#[derive(Clone, Debug)]
struct InterceptedAuthority(String);

impl InterceptedAuthority {
    fn new(authority: impl Into<String>) -> Self {
        Self(authority.into())
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InterceptedAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parsed target of a CONNECT request.
///
/// `authority` keeps the original `host:port` for URI reconstruction, while
/// `server_name` is just the host part used in the generated leaf certificate.
struct ConnectTarget {
    authority: InterceptedAuthority,
    server_name: String,
}

impl ConnectTarget {
    fn from_request(req: &Request<Incoming>) -> ProxyResult<Self> {
        let authority = req
            .uri()
            .authority()
            .ok_or(ProxyError::MissingConnectAuthority)?;

        Ok(Self::from_authority(authority))
    }

    fn from_authority(authority: &Authority) -> Self {
        Self {
            authority: InterceptedAuthority::new(authority.to_string()),
            server_name: authority.host().to_owned(),
        }
    }
}

/// Request router and upstream client.
#[derive(Clone)]
struct MitmProxy {
    /// Shared upstream client. It is cheap to clone internally and keeps
    /// connection pooling in one place.
    client: reqwest::Client,

    /// Local CA used to mint leaf certificates for intercepted HTTPS hosts.
    ca: CertificateAuthority,

    /// Optional JavaScript request policy hook.
    ///
    /// Wrapped in `Arc<RwLock<...>>` so the directory-watch task can swap in a
    /// fresh set of interceptors without restarting the proxy.
    interceptor: Option<Arc<RwLock<JsInterceptors>>>,

    /// Shared KV store passed into every Deno worker.
    kv: Arc<SharedKv>,
}

impl MitmProxy {
    /// Construct a proxy from its two stateful collaborators.
    fn new(
        client: reqwest::Client,
        ca: CertificateAuthority,
        interceptor: Option<Arc<RwLock<JsInterceptors>>>,
        kv: Arc<SharedKv>,
    ) -> Self {
        Self {
            client,
            ca,
            interceptor,
            kv,
        }
    }

    /// Handle one HTTP request from a client session.
    ///
    /// The session carries the client address and the request-target semantics:
    /// plain HTTP proxy traffic or decrypted HTTPS traffic from a CONNECT
    /// tunnel.
    async fn handle(
        self: Arc<Self>,
        req: Request<Incoming>,
        session: ClientSession,
    ) -> Result<Response<ResBody>, Infallible> {
        let peer = session.peer;
        let result = self.route(req, session).await;

        Ok(result.unwrap_or_else(|e| {
            warn!(peer = %peer, "proxy error: {e}");
            error_response(e)
        }))
    }

    /// Route one request according to proxy semantics.
    async fn route(
        self: Arc<Self>,
        req: Request<Incoming>,
        session: ClientSession,
    ) -> ProxyResult<Response<ResBody>> {
        if req.method() == Method::CONNECT {
            let interceptor_selector = proxy_auth_username(req.headers())?;
            if let Some(interceptor_lock) = self.interceptor.as_ref() {
                interceptor_lock
                    .read()
                    .await
                    .select(interceptor_selector.as_deref())?;
            }
            return self.handle_connect(req, session.peer, interceptor_selector);
        }

        if let Some(endpoint) = AdminEndpoint::from_request(&req) {
            return endpoint.respond(&self.ca);
        }

        let interceptor_selector = match &session.target {
            RequestTarget::PlainHttpProxy => proxy_auth_username(req.headers())?,
            RequestTarget::InterceptedHttps(_) => session.interceptor_selector.clone(),
        };
        let req = session.target.normalize(req)?;
        self.forward(req, session.peer, interceptor_selector.as_deref())
            .await
    }

    /// Convert an HTTP `CONNECT host:port` request into a TLS MITM session.
    ///
    /// The client expects a `200 OK` response before it starts TLS. Hyper's
    /// upgrade API gives us the underlying socket after that response. We then
    /// accept a client-side TLS handshake using a generated leaf certificate and
    /// run another HTTP/1.1 server over the decrypted stream.
    fn handle_connect(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer: SocketAddr,
        interceptor_selector: Option<String>,
    ) -> ProxyResult<Response<ResBody>> {
        let target = ConnectTarget::from_request(&req)?;
        let acceptor = self.ca.tls_acceptor(&target.server_name)?;
        let on_upgrade = hyper::upgrade::on(req);
        let proxy = Arc::clone(&self);
        let authority = target.authority;
        let server_name = target.server_name;

        info!(peer = %peer, "CONNECT {authority}");
        tokio::spawn(async move {
            match on_upgrade.await {
                Ok(upgraded) => match acceptor.accept(TokioIo::new(upgraded)).await {
                    Ok(tls_stream) => {
                        info!(peer = %peer, "TLS intercepted for {authority}");
                        ClientSession::intercepted(peer, proxy, authority, interceptor_selector)
                            .serve(tls_stream)
                            .await;
                    }
                    Err(e) => warn!(peer = %peer, "TLS handshake failed for {server_name}: {e}"),
                },
                Err(e) => warn!(peer = %peer, "CONNECT upgrade failed for {server_name}: {e}"),
            }
        });

        Ok(empty_response(StatusCode::OK))
    }

    /// Apply policy to one normalized request and return the selected response
    /// to the client.
    ///
    /// If a JavaScript interceptor is configured, it receives the still-
    /// unconsumed incoming body as a native `Request` stream. JavaScript must
    /// return a `Response`; the bundled examples use `fetch` with manual
    /// redirect handling so proxy-style redirects stay visible to clients.
    async fn forward(
        &self,
        req: Request<Incoming>,
        peer: SocketAddr,
        interceptor_selector: Option<&str>,
    ) -> ProxyResult<Response<ResBody>> {
        if self.interceptor.is_some() {
            return self
                .forward_with_interceptor(req, peer, interceptor_selector)
                .await;
        }

        let request = StreamingRequest::from_hyper(req);
        let upstream_response = request.send(&self.client).await?;
        upstream_response_into_hyper(upstream_response)
    }

    async fn forward_with_interceptor(
        &self,
        req: Request<Incoming>,
        peer: SocketAddr,
        interceptor_selector: Option<&str>,
    ) -> ProxyResult<Response<ResBody>> {
        let (parts, body) = req.into_parts();

        let request = InterceptRequest::new(
            parts.method.as_str(),
            parts.uri.to_string(),
            header_pairs(&parts.headers),
            method_allows_body(&parts.method),
            InterceptContext::new(peer.to_string()),
        );
        let interceptor = self
            .interceptor
            .as_ref()
            .expect("checked by forward before calling forward_with_interceptor")
            .read()
            .await
            .select(interceptor_selector)?
            .clone();
        let response = interceptor
            .intercept(request, body, Arc::clone(&self.kv))
            .await?;
        intercept_response_into_hyper(response)
    }
}

/// Local admin endpoints handled before proxy forwarding.
///
/// These are intentionally tiny: health, and a way to fetch the generated
/// public CA certificate through the already-running local server.
enum AdminEndpoint {
    Health,
    PublicCaCertificate,
}

impl AdminEndpoint {
    fn from_request(req: &Request<Incoming>) -> Option<Self> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/_outgate/healthz") => Some(Self::Health),
            (&Method::GET, "/_outgate/ca.pem") => Some(Self::PublicCaCertificate),
            _ => None,
        }
    }

    fn respond(self, ca: &CertificateAuthority) -> ProxyResult<Response<ResBody>> {
        match self {
            Self::Health => Ok(text_response(StatusCode::OK, "ok\n")),
            Self::PublicCaCertificate => Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/x-pem-file")
                .header(
                    CONTENT_DISPOSITION,
                    "attachment; filename=\"outgate-root-ca-public.pem\"",
                )
                .body(full_body(fs::read(ca.public_cert_path())?))?),
        }
    }
}

/// Outbound request prepared for `reqwest`.
struct StreamingRequest {
    method: Method,
    uri: Uri,
    headers: HeaderMap<HeaderValue>,
    body: Incoming,
    should_send_body: bool,
}

impl StreamingRequest {
    fn from_hyper(req: Request<Incoming>) -> Self {
        let (parts, body) = req.into_parts();
        let should_send_body = should_send_body(&parts.method, &parts.headers);
        Self {
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
            body,
            should_send_body,
        }
    }

    async fn send(self, client: &reqwest::Client) -> ProxyResult<reqwest::Response> {
        let mut upstream = client.request(self.method, self.uri.to_string());
        for (name, value) in self.headers.iter() {
            if is_end_to_end_header(name) {
                upstream = upstream.header(name, value);
            }
        }

        if self.should_send_body {
            upstream = upstream.body(reqwest::Body::wrap_stream(BodyDataStream::new(self.body)));
        }

        Ok(upstream.send().await?)
    }
}

fn upstream_response_into_hyper(response: reqwest::Response) -> ProxyResult<Response<ResBody>> {
    let mut builder = Response::builder().status(response.status());
    for (name, value) in response.headers().iter() {
        if is_end_to_end_header(name) {
            builder = builder.header(name, value);
        }
    }

    let body = response
        .bytes_stream()
        .map_err(|err| -> BodyError { Box::new(err) });
    Ok(builder.body(stream_body(body))?)
}

fn intercept_response_into_hyper(response: InterceptResponse) -> ProxyResult<Response<ResBody>> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(response.status).unwrap_or(StatusCode::FORBIDDEN));
    for (name, value) in response.headers {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(&value) else {
            continue;
        };
        if is_end_to_end_header(&name) {
            builder = builder.header(name, value);
        }
    }

    Ok(builder.body(response.body)?)
}

fn error_response(error: ProxyError) -> Response<ResBody> {
    let status = error.status_code();
    let mut response = text_response(status, format!("outgate proxy error: {error}\n"));
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response.headers_mut().insert(
            PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"outgate\""),
        );
    }
    response
}

impl ProxyError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::UnsupportedProxyAuthorization
            | Self::InvalidProxyAuthorization
            | Self::Interceptor(InterceptorError::MissingSelector)
            | Self::Interceptor(InterceptorError::UnknownSelector { .. }) => {
                StatusCode::PROXY_AUTHENTICATION_REQUIRED
            }
            _ => StatusCode::BAD_GATEWAY,
        }
    }
}

fn proxy_auth_username(headers: &HeaderMap<HeaderValue>) -> ProxyResult<Option<String>> {
    let Some(value) = headers.get(PROXY_AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str()?;
    let Some((scheme, encoded)) = value.split_once(char::is_whitespace) else {
        return Err(ProxyError::InvalidProxyAuthorization);
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(ProxyError::UnsupportedProxyAuthorization);
    }

    let credentials = BASE64
        .decode(encoded.trim())
        .map_err(|_| ProxyError::InvalidProxyAuthorization)?;
    let credentials =
        String::from_utf8(credentials).map_err(|_| ProxyError::InvalidProxyAuthorization)?;
    let username = credentials
        .split_once(':')
        .map(|(username, _)| username)
        .unwrap_or(credentials.as_str())
        .trim();

    if username.is_empty() {
        return Ok(None);
    }

    Ok(Some(username.to_owned()))
}

/// Convert an origin-form HTTPS request from the decrypted tunnel into an
/// absolute URI for upstream forwarding.
///
/// Browsers send requests like `GET /path HTTP/1.1` inside CONNECT tunnels.
/// `reqwest` needs a full URL, so the CONNECT authority supplies the scheme and
/// authority: `https://example.com/path`.
fn absolutize_intercepted_request(
    mut req: Request<Incoming>,
    authority: &str,
) -> ProxyResult<Request<Incoming>> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/");
    let uri = format!("https://{authority}{path_and_query}").parse::<Uri>()?;
    *req.uri_mut() = uri;
    Ok(req)
}

/// Ensure plain HTTP proxy requests have an absolute URI.
///
/// Correct proxy clients usually send absolute-form requests such as
/// `GET http://example.com/path HTTP/1.1`. This fallback also accepts
/// origin-form requests when a `Host` header is present.
fn normalize_plain_http_request(mut req: Request<Incoming>) -> ProxyResult<Request<Incoming>> {
    if req.uri().scheme().is_some() && req.uri().authority().is_some() {
        return Ok(req);
    }

    let host = req
        .headers()
        .get(HOST)
        .ok_or(ProxyError::MissingHostHeader)?
        .to_str()?;
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/");
    let uri = format!("http://{host}{path_and_query}").parse::<Uri>()?;
    *req.uri_mut() = uri;
    Ok(req)
}

/// Whether a header is end-to-end and may be forwarded upstream.
///
/// This covers the fixed hop-by-hop set. It does not yet parse additional
/// header names listed by the `Connection` header.
fn is_end_to_end_header(name: &HeaderName) -> bool {
    !HOP_BY_HOP
        .iter()
        .any(|hop| name.as_str().eq_ignore_ascii_case(hop))
}

fn header_pairs(headers: &HeaderMap<HeaderValue>) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| is_end_to_end_header(name))
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Heuristic for whether an empty body should still be attached upstream.
///
/// `reqwest` can send body-bearing methods without a body, but keeping the
/// check explicit makes GET/HEAD/OPTIONS/TRACE behavior unsurprising.
fn method_allows_body(method: &Method) -> bool {
    !matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

fn should_send_body(method: &Method, headers: &HttpHeaderMap<HeaderValue>) -> bool {
    method_allows_body(method)
        || headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|len| len > 0)
        || headers.contains_key(TRANSFER_ENCODING)
}

/// Poll a directory every 500 ms and reload interceptors when the file set changes.
async fn watch_directory_interceptors(
    interceptor_lock: Arc<RwLock<JsInterceptors>>,
    dir_path: Arc<PathBuf>,
    cancellation_token: CancellationToken,
) {
    let mut last_files = collect_interceptor_files(&dir_path);
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await; // consume the immediate first tick

    while ticker
        .tick()
        .with_cancellation_token(&cancellation_token)
        .await
        .is_some()
    {
        let current_files = collect_interceptor_files(&dir_path);
        if current_files == last_files {
            continue;
        }
        last_files = current_files;
        match JsInterceptors::from_path(&dir_path) {
            Ok(new_interceptors) => {
                *interceptor_lock.write().await = new_interceptors;
                info!("interceptors reloaded from {}", dir_path.display());
            }
            Err(err) => {
                warn!(
                    "failed to reload interceptors from {}: {err}",
                    dir_path.display()
                );
            }
        }
    }
}

fn collect_interceptor_files(dir: &Path) -> BTreeSet<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return BTreeSet::new();
    };
    entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if !path.is_file() {
                return None;
            }
            let name = path.file_name()?.to_str()?;
            if is_interceptor_module(&path) || name == "agents.json" || name == "agents.yaml" {
                Some(name.to_owned())
            } else {
                None
            }
        })
        .collect()
}
