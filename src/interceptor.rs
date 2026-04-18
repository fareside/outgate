//! JavaScript request interception.
//!
//! This module embeds Deno's runtime worker for one purpose: evaluate an egress
//! policy module that exports `default async function intercept(request, env,
//! ctx)`. From JavaScript, the environment is Deno's normal runtime surface:
//! `Deno`, Web APIs, `fetch`, `Request`, `Response`, timers, and the other
//! globals installed by `deno_runtime`. The request body is exposed as the native
//! `Request.body` stream; Rust does not pre-buffer it just to make the
//! interception call.
//!
//! The return value is normalized into a Rust response:
//!
//! - `Response` returns that response to the client.
//! - Anything else returns a default `403`.
//!
//! The response body is streamed: JavaScript reads the Web `Response.body`
//! stream and pushes chunks into the Hyper body channel as the client consumes
//! them.
//!
//! The first version intentionally creates a fresh Deno worker per request.
//! That is not fast, but it keeps request state isolated while the contract is
//! still small and evolving.

use crate::body::{ResBody, ResBodySender, channel_body};
use crate::kv::SharedKv;
use bytes::Bytes;
use deno_core::OpState;
use deno_core::error::CoreError;
use deno_core::error::JsError;
use deno_core::url::Url;
use deno_core::{FsModuleLoader, PollEventLoopOptions, op2};
use deno_error::JsErrorBox;
use deno_resolver::npm::{DenoInNpmPackageChecker, NpmResolver};
use deno_runtime::BootstrapOptions;
use deno_runtime::deno_fs::RealFs;
use deno_runtime::deno_permissions::{PermissionsContainer, RuntimePermissionDescriptorParser};
use deno_runtime::worker::{MainWorker, WorkerOptions, WorkerServiceOptions};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde::Deserialize;
use serde::Serialize;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use thiserror::Error;
use tokio::sync::{Mutex, oneshot};
use tracing::warn;

/// V8 startup snapshot built by `build.rs` from the deno_runtime extensions.
///
/// Without this, V8 would try to parse the TypeScript sources of built-in
/// Deno extensions (e.g. `deno_telemetry`) as JavaScript and fail on type
/// annotation syntax.
static DENO_SNAPSHOT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/DENO_SNAPSHOT.bin"));

pub type InterceptorResult<T> = Result<T, InterceptorError>;

/// Errors produced while running the JavaScript interceptor.
#[derive(Debug, Error)]
pub enum InterceptorError {
    #[error("interceptor path is not a file: {path}")]
    NotAFile { path: PathBuf },

    #[error("intercept path is neither a file nor a directory: {path}")]
    NotAFileOrDirectory { path: PathBuf },

    #[error("intercept directory has no JavaScript or TypeScript modules: {path}")]
    EmptyDirectory { path: PathBuf },

    #[error("intercept directory has both agents.json and agents.yaml; remove one: {path}")]
    AmbiguousAgentManifest { path: PathBuf },

    #[error("failed to parse agents manifest at {path}: {reason}")]
    ManifestParse { path: PathBuf, reason: String },

    #[error(
        "agents manifest entry `{agent_id}` refers to `{filename}` which is not a JavaScript or TypeScript module"
    )]
    ManifestEntryNotAModule { agent_id: String, filename: String },

    #[error("intercept directory requires a proxy username to select a policy")]
    MissingSelector,

    #[error("unknown interceptor `{selector}`")]
    UnknownSelector { selector: String },

    #[error("interceptor returned invalid HTTP status: {status}")]
    InvalidStatus { status: u16 },

    #[error("failed to serialize interceptor request")]
    RequestSerialize(#[source] serde_json::Error),

    #[error("failed to parse interceptor response metadata")]
    ResponseParse(#[source] serde_json::Error),

    #[error("interceptor response ended before metadata was emitted")]
    ResponseMissingMetadata,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Hyper(#[from] hyper::Error),

    #[error(transparent)]
    JavaScript(#[from] CoreError),

    #[error(transparent)]
    JavaScriptException(#[from] Box<JsError>),
}

/// JavaScript interceptors configured for the proxy.
///
/// A single file keeps the original behavior: every proxied request runs that
/// module. A directory is a small registry where each supported module file is
/// selected by the proxy-auth username on the request that created the proxy
/// session.
#[derive(Clone)]
pub struct JsInterceptors {
    source: InterceptorSource,
}

#[derive(Clone)]
enum InterceptorSource {
    Single(JsInterceptor),
    Directory {
        path: Arc<PathBuf>,
        interceptors: Arc<BTreeMap<String, JsInterceptor>>,
    },
}

impl JsInterceptors {
    /// Build interceptors from either one module file or a directory of modules.
    pub fn from_path(path: &Path) -> InterceptorResult<Self> {
        if path.is_file() {
            return Ok(Self {
                source: InterceptorSource::Single(JsInterceptor::from_path(path)?),
            });
        }

        if path.is_dir() {
            return Self::from_directory(path);
        }

        Err(InterceptorError::NotAFileOrDirectory {
            path: path.to_path_buf(),
        })
    }

    /// Select the interceptor for one request or CONNECT-created tunnel.
    pub fn select(&self, selector: Option<&str>) -> InterceptorResult<&JsInterceptor> {
        match &self.source {
            InterceptorSource::Single(interceptor) => Ok(interceptor),
            InterceptorSource::Directory { interceptors, .. } => {
                let selector = selector.ok_or(InterceptorError::MissingSelector)?;
                interceptors
                    .get(selector)
                    .ok_or_else(|| InterceptorError::UnknownSelector {
                        selector: selector.to_owned(),
                    })
            }
        }
    }

    /// Return the directory path when configured from a directory, for watching.
    pub fn watch_path(&self) -> Option<Arc<PathBuf>> {
        match &self.source {
            InterceptorSource::Directory { path, .. } => Some(Arc::clone(path)),
            InterceptorSource::Single(_) => None,
        }
    }

    /// Human-readable startup description.
    pub fn display(&self) -> String {
        match &self.source {
            InterceptorSource::Single(interceptor) => interceptor.display().to_string(),
            InterceptorSource::Directory { path, interceptors } => {
                format!("{} ({})", path.display(), Self::available(interceptors))
            }
        }
    }

    fn from_directory(path: &Path) -> InterceptorResult<Self> {
        let canonical = path.canonicalize()?;
        let interceptors = if let Some(manifest) = load_agent_manifest(&canonical)? {
            interceptors_from_manifest(&canonical, manifest)?
        } else {
            interceptors_from_filenames(&canonical)?
        };

        if interceptors.is_empty() {
            return Err(InterceptorError::EmptyDirectory { path: canonical });
        }

        Ok(Self {
            source: InterceptorSource::Directory {
                path: Arc::new(canonical),
                interceptors: Arc::new(interceptors),
            },
        })
    }

    fn available(interceptors: &BTreeMap<String, JsInterceptor>) -> String {
        interceptors
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Load and parse `agents.json` or `agents.yaml` from a directory.
///
/// Returns `None` when neither manifest file is present (filename-based mode).
/// Returns an error when both files exist simultaneously.
fn load_agent_manifest(dir: &Path) -> InterceptorResult<Option<HashMap<String, String>>> {
    let json_path = dir.join("agents.json");
    let yaml_path = dir.join("agents.yaml");
    let json_exists = json_path.is_file();
    let yaml_exists = yaml_path.is_file();

    if json_exists && yaml_exists {
        return Err(InterceptorError::AmbiguousAgentManifest {
            path: dir.to_path_buf(),
        });
    }

    if json_exists {
        let content = fs::read_to_string(&json_path)?;
        let map: HashMap<String, String> =
            serde_json::from_str(&content).map_err(|e| InterceptorError::ManifestParse {
                path: json_path,
                reason: e.to_string(),
            })?;
        return Ok(Some(map));
    }

    if yaml_exists {
        let content = fs::read_to_string(&yaml_path)?;
        let map: HashMap<String, String> =
            serde_yaml::from_str(&content).map_err(|e| InterceptorError::ManifestParse {
                path: yaml_path,
                reason: e.to_string(),
            })?;
        return Ok(Some(map));
    }

    Ok(None)
}

/// Build an interceptor map from a manifest: `agent-id → filename`.
fn interceptors_from_manifest(
    dir: &Path,
    manifest: HashMap<String, String>,
) -> InterceptorResult<BTreeMap<String, JsInterceptor>> {
    let mut interceptors = BTreeMap::new();
    for (agent_id, filename) in manifest {
        if !is_interceptor_module(Path::new(&filename)) {
            return Err(InterceptorError::ManifestEntryNotAModule { agent_id, filename });
        }
        let module_path = dir.join(&filename);
        interceptors.insert(agent_id, JsInterceptor::from_path(&module_path)?);
    }
    Ok(interceptors)
}

/// Build an interceptor map from the JS/TS filenames in a directory.
fn interceptors_from_filenames(dir: &Path) -> InterceptorResult<BTreeMap<String, JsInterceptor>> {
    let mut interceptors = BTreeMap::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || !is_interceptor_module(&path) {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        interceptors.insert(file_name.to_owned(), JsInterceptor::from_path(&path)?);
    }
    Ok(interceptors)
}

/// JavaScript interceptor module configured for the proxy.
#[derive(Clone)]
pub struct JsInterceptor {
    module_specifier: Arc<Url>,
    display_path: Arc<PathBuf>,
}

impl JsInterceptor {
    /// Build an interceptor from a local JavaScript module path.
    pub fn from_path(path: &Path) -> InterceptorResult<Self> {
        if !path.is_file() {
            return Err(InterceptorError::NotAFile {
                path: path.to_path_buf(),
            });
        }

        let canonical = path.canonicalize()?;
        let module_specifier = Url::from_file_path(&canonical).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("could not convert {} to file URL", canonical.display()),
            )
        })?;

        Ok(Self {
            module_specifier: Arc::new(module_specifier),
            display_path: Arc::new(canonical),
        })
    }

    /// Human-readable path for startup logs.
    pub fn display(&self) -> std::path::Display<'_> {
        self.display_path.display()
    }

    /// Run the configured JavaScript module for one request.
    ///
    /// The Deno runtime is isolated to a blocking task so the Hyper connection
    /// future stays `Send`, even though V8 and deno_core use local handles
    /// internally.
    pub async fn intercept(
        &self,
        request: InterceptRequest,
        body: Incoming,
        kv: Arc<SharedKv>,
    ) -> InterceptorResult<InterceptResponse> {
        let module_specifier = Arc::clone(&self.module_specifier);
        let (response_tx, response_rx) = oneshot::channel();
        let response_ready = Arc::new(StdMutex::new(Some(response_tx)));
        let worker_response_ready = Arc::clone(&response_ready);

        tokio::task::spawn_blocking(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();

            let result = match runtime {
                Ok(runtime) => runtime.block_on(async move {
                    run_interceptor(
                        module_specifier.as_ref(),
                        request,
                        body,
                        worker_response_ready,
                        kv,
                    )
                    .await
                }),
                Err(err) => Err(InterceptorError::Io(err)),
            };

            match result {
                Ok(()) => {
                    let _ = send_response_error(
                        &response_ready,
                        InterceptorError::ResponseMissingMetadata,
                    );
                }
                Err(err) => {
                    if !send_response_error(&response_ready, err) {
                        warn!("JavaScript interceptor body stream failed after response started");
                    }
                }
            }
        });

        response_rx
            .await
            .map_err(|err| std::io::Error::other(format!("interceptor task failed: {err}")))?
    }
}

pub fn is_interceptor_module(path: &Path) -> bool {
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return false;
    };

    matches!(
        extension.to_ascii_lowercase().as_str(),
        "js" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "jsx" | "tsx"
    )
}

/// Request metadata passed to JavaScript before the native `Request` is built.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InterceptRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    has_body: bool,
    context: InterceptContext,
}

impl InterceptRequest {
    pub fn new(
        method: impl Into<String>,
        url: impl Into<String>,
        headers: Vec<(String, String)>,
        has_body: bool,
        context: InterceptContext,
    ) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            headers,
            has_body,
            context,
        }
    }
}

/// Request context passed to JavaScript as `ctx`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InterceptContext {
    client_addr: String,
}

impl InterceptContext {
    pub fn new(client_addr: impl Into<String>) -> Self {
        Self {
            client_addr: client_addr.into(),
        }
    }
}

/// Local response produced by the JavaScript interceptor.
pub struct InterceptResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: ResBody,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResponseMetadata {
    status: u16,
    headers: Vec<(String, String)>,
}

type ResponseReadySender = oneshot::Sender<InterceptorResult<InterceptResponse>>;
type SharedResponseReady = Arc<StdMutex<Option<ResponseReadySender>>>;
type SharedResponseBodySender = Arc<Mutex<Option<ResBodySender>>>;

struct ResponseStart {
    ready: SharedResponseReady,
    body: Option<ResBody>,
}

async fn run_interceptor(
    module_specifier: &Url,
    request: InterceptRequest,
    body: Incoming,
    response_ready: SharedResponseReady,
    kv: Arc<SharedKv>,
) -> InterceptorResult<()> {
    let (response_body_sender, response_body) = channel_body(8);
    let response_body_sender = Arc::new(Mutex::new(Some(response_body_sender)));
    let response_start = ResponseStart {
        ready: response_ready,
        body: Some(response_body),
    };
    let mut worker = create_worker(
        module_specifier,
        RequestBodyStream::new(body),
        response_start,
        response_body_sender,
        kv,
    );

    let source = invocation_source(module_specifier, &request)?;
    let promise = worker.execute_script("<outgate-interceptor>", source.into())?;
    let resolve = worker.js_runtime.resolve(promise);
    worker
        .js_runtime
        .with_event_loop_promise(resolve, PollEventLoopOptions::default())
        .await?;
    Ok(())
}

fn create_worker(
    main_module: &Url,
    request_body: SharedRequestBody,
    response_start: ResponseStart,
    response_body_sender: SharedResponseBodySender,
    kv: Arc<SharedKv>,
) -> MainWorker {
    let permission_desc_parser = Arc::new(RuntimePermissionDescriptorParser::new(
        sys_traits::impls::RealSys,
    ));
    let fs = Arc::new(RealFs);

    MainWorker::bootstrap_from_options::<
        DenoInNpmPackageChecker,
        NpmResolver<sys_traits::impls::RealSys>,
        sys_traits::impls::RealSys,
    >(
        main_module,
        WorkerServiceOptions {
            blob_store: Default::default(),
            broadcast_channel: Default::default(),
            deno_rt_native_addon_loader: None,
            feature_checker: Default::default(),
            fs,
            module_loader: Rc::new(FsModuleLoader),
            node_services: None,
            npm_process_state_provider: None,
            permissions: PermissionsContainer::allow_all(permission_desc_parser),
            root_cert_store_provider: None,
            fetch_dns_resolver: Default::default(),
            shared_array_buffer_store: None,
            compiled_wasm_module_store: None,
            v8_code_cache: None,
            bundle_provider: None,
        },
        WorkerOptions {
            bootstrap: BootstrapOptions {
                location: Some(main_module.clone()),
                user_agent: "Outgate".to_string(),
                ..Default::default()
            },
            extensions: vec![outgate_interceptor::init(
                request_body,
                response_start,
                response_body_sender,
                kv,
            )],
            startup_snapshot: Some(DENO_SNAPSHOT),
            ..Default::default()
        },
    )
}

fn invocation_source(
    module_specifier: &Url,
    request: &InterceptRequest,
) -> InterceptorResult<String> {
    let module_json = serde_json::to_string(module_specifier.as_str())
        .map_err(InterceptorError::RequestSerialize)?;
    let request_json =
        serde_json::to_string(request).map_err(InterceptorError::RequestSerialize)?;

    Ok(format!(
        r#"
(async () => {{
  const module = await import({module_json});

  const input = {request_json};
  installOutgateFetch();
  const createBodyStream = globalThis[Symbol.for("outgate.createBodyStream")];
  const startResponse = globalThis[Symbol.for("outgate.startResponse")];
  const sendResponseChunk = globalThis[Symbol.for("outgate.sendResponseChunk")];
  if (
    typeof createBodyStream !== "function" ||
    typeof startResponse !== "function" ||
    typeof sendResponseChunk !== "function"
  ) {{
    throw new TypeError("outgate body stream bridge was not installed");
  }}

  const init = {{
    method: input.method,
    headers: input.headers,
  }};
  if (input.hasBody) {{
    init.body = createBodyStream();
    init.duplex = "half";
  }}
  const request = new Request(input.url, init);
  const url = new URL(input.url);
  const outgateKv = globalThis[Symbol.for("outgate.kv")];
  const env = Object.freeze({{
    ...Deno.env.toObject(),
    KV: outgateKv,
  }});
  const ctx = Object.freeze({{
    ...input.context,
    requestId: crypto.randomUUID(),
    host: url.host,
    hostname: url.hostname,
    containerId: Deno.env.get("OUTGATE_CONTAINER_ID") ?? null,
  }});

  if (typeof module.default !== "function") {{
    throw new TypeError("interceptor module must export default async function intercept(request, env, ctx)");
  }}

  const response = normalizeResponse(await module.default(request, env, ctx));
  await startResponse(JSON.stringify({{
    status: response.status,
    headers: Array.from(response.headers.entries()),
  }}));
  await streamResponseBody(response, sendResponseChunk);
}})()

function installOutgateFetch() {{
  const nativeFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (input, init) => {{
    if (
      input instanceof Request &&
      init !== undefined &&
      init.body === undefined &&
      input.body !== null &&
      !input.bodyUsed
    ) {{
      return nativeFetch(input.url, {{
        ...init,
        method: init.method ?? input.method,
        body: input.body,
        duplex: init.duplex ?? "half",
      }});
    }}

    return nativeFetch(input, init);
  }};
}}

function normalizeResponse(response) {{
  if (response instanceof Response) {{
    return response;
  }}

  return new Response("denied by outgate interceptor\n", {{
    status: 403,
    headers: {{ "content-type": "text/plain; charset=utf-8" }},
  }});
}}

async function streamResponseBody(response, sendResponseChunk) {{
  if (response.body === null) {{
    return;
  }}

  const reader = response.body.getReader();
  try {{
    while (true) {{
      const {{ done, value }} = await reader.read();
      if (done) {{
        return;
      }}
      if (value.byteLength > 0) {{
        await sendResponseChunk(value);
      }}
    }}
  }} finally {{
    reader.releaseLock();
  }}
}}
"#
    ))
}

fn parse_response_metadata(json: &str) -> InterceptorResult<ResponseMetadata> {
    let metadata: ResponseMetadata =
        serde_json::from_str(json).map_err(InterceptorError::ResponseParse)?;

    if !(100..=599).contains(&metadata.status) {
        return Err(InterceptorError::InvalidStatus {
            status: metadata.status,
        });
    }

    Ok(metadata)
}

fn send_response_error(response_ready: &SharedResponseReady, error: InterceptorError) -> bool {
    let Some(sender) = response_ready.lock().expect("response sender lock").take() else {
        return false;
    };

    sender.send(Err(error)).is_ok()
}

type SharedRequestBody = Arc<Mutex<RequestBodyStream>>;

struct RequestBodyStream {
    body: Option<Incoming>,
    done: bool,
}

impl RequestBodyStream {
    fn new(body: Incoming) -> SharedRequestBody {
        Arc::new(Mutex::new(Self {
            body: Some(body),
            done: false,
        }))
    }

    async fn next_chunk(&mut self) -> Result<Option<Bytes>, hyper::Error> {
        if self.done {
            return Ok(None);
        }

        let Some(body) = self.body.as_mut() else {
            self.done = true;
            return Ok(None);
        };

        while let Some(frame) = body.frame().await {
            let frame = frame?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            if data.is_empty() {
                continue;
            }

            return Ok(Some(data));
        }

        self.done = true;
        self.body = None;
        Ok(None)
    }
}

#[op2]
#[buffer]
async fn op_outgate_body_next(state: Rc<RefCell<OpState>>) -> Result<Option<Vec<u8>>, JsErrorBox> {
    let request_body = {
        let state = state.borrow();
        Arc::clone(state.borrow::<SharedRequestBody>())
    };
    let next = request_body
        .lock()
        .await
        .next_chunk()
        .await
        .map_err(|err| JsErrorBox::generic(err.to_string()))?;
    Ok(next.map(|chunk| chunk.to_vec()))
}

#[op2(fast)]
fn op_outgate_response_start(
    state: &mut OpState,
    #[string] metadata: String,
) -> Result<(), JsErrorBox> {
    let metadata =
        parse_response_metadata(&metadata).map_err(|err| JsErrorBox::generic(err.to_string()))?;
    let mut response_start = state
        .try_take::<ResponseStart>()
        .ok_or_else(|| JsErrorBox::generic("outgate response already started"))?;
    let body = response_start
        .body
        .take()
        .ok_or_else(|| JsErrorBox::generic("outgate response body already taken"))?;
    let response = InterceptResponse {
        status: metadata.status,
        headers: metadata.headers,
        body,
    };

    let Some(sender) = response_start
        .ready
        .lock()
        .expect("response sender lock")
        .take()
    else {
        return Err(JsErrorBox::generic("outgate response receiver was closed"));
    };

    sender
        .send(Ok(response))
        .map_err(|_| JsErrorBox::generic("outgate response receiver was closed"))?;
    Ok(())
}

#[op2]
async fn op_outgate_response_send(
    state: Rc<RefCell<OpState>>,
    #[buffer(copy)] chunk: Vec<u8>,
) -> Result<(), JsErrorBox> {
    let response_body_sender = {
        let state = state.borrow();
        Arc::clone(state.borrow::<SharedResponseBodySender>())
    };
    let mut sender = response_body_sender.lock().await;
    let Some(sender) = sender.as_mut() else {
        return Err(JsErrorBox::generic("outgate response body is closed"));
    };

    sender
        .send_data(Bytes::from(chunk))
        .await
        .map_err(|err| JsErrorBox::generic(err.to_string()))
}

deno_core::extension!(
    outgate_interceptor,
    ops = [
        op_outgate_body_next,
        op_outgate_response_start,
        op_outgate_response_send,
        crate::kv::op_outgate_kv_get,
        crate::kv::op_outgate_kv_put,
        crate::kv::op_outgate_kv_update,
    ],
    esm_entry_point = "ext:outgate_interceptor/outgate_interceptor.js",
    esm = [dir "src", "outgate_interceptor.js"],
    options = {
        request_body: SharedRequestBody,
        response_start: ResponseStart,
        response_body_sender: SharedResponseBodySender,
        kv: Arc<SharedKv>,
    },
    state = |state, options| {
        state.put::<SharedRequestBody>(options.request_body);
        state.put::<ResponseStart>(options.response_start);
        state.put::<SharedResponseBodySender>(options.response_body_sender);
        state.put::<Arc<SharedKv>>(options.kv);
    },
);
