use axum::extract::Request;
use axum::middleware::Next;
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use fact_canonical::encode as canonicalize;
use fact_commitment::decode_bundle;
use fact_store::Store;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as ConnectionBuilder,
    service::TowerToHyperService,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::Read as IoRead,
    str::FromStr,
    sync::{Arc, Mutex},
};
use time::OffsetDateTime;
use tower::ServiceExt;
use tower_http::trace::TraceLayer;

const VERSION: &str = "0";
const JSON_MEDIA: &str = "application/fact+json";
const COSE_MEDIA: &str = "application/fact+cose";
const BUNDLE_MEDIA: &str = "application/fact-bundle";
const SNAPSHOT_MEDIA: &str = "application/fact-snapshot";
const QUERY_MEDIA: &str = "application/fact-query+json";
const MAX_REQUEST_BODY_BYTES: usize = 72 * 1024 * 1024;
const MAX_QUEUED_WRITES: usize = 256;
const REQUEST_HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const REQUEST_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const MAX_OBJECT_LIST_PAGE_SIZE: usize = 1_000;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<Store>>,
    pub api_root: String,
    coordinator_key: Arc<fact_crypto::SigningKey>,
    coordinator_actor_id: fact_core::ObjectId,
    write_queue: Arc<tokio::sync::Semaphore>,
    write_gate: Arc<tokio::sync::Semaphore>,
    caller_auth: CallerAuthPolicy,
    ledger_visibility: Arc<Mutex<HashMap<[u8; 16], LedgerVisibility>>>,
    nonces: Arc<Mutex<HashMap<String, OffsetDateTime>>>,
}

/// Coordinator-local visibility policy for a hosted ledger.
///
/// This is deliberately not stored in the ledger or synchronized with its
/// protocol objects. It controls network reachability only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerVisibility {
    Public,
    Private,
}

impl LedgerVisibility {
    const fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallerAuthPolicy {
    pub require_push: bool,
    pub require_restricted_reads: bool,
}

impl CallerAuthPolicy {
    pub const fn permissive() -> Self {
        Self {
            require_push: false,
            require_restricted_reads: false,
        }
    }

    pub const fn reference() -> Self {
        Self {
            require_push: true,
            require_restricted_reads: true,
        }
    }
}

impl Default for CallerAuthPolicy {
    fn default() -> Self {
        Self::permissive()
    }
}

impl AppState {
    pub fn new(store: Store, api_root: impl Into<String>) -> Self {
        Self::new_with_reference_policy(
            store,
            api_root,
            fact_crypto::SigningKey::from_seed(&rand::random::<[u8; 32]>())
                .expect("random reference key has the required length"),
            fact_core::ObjectId::new_v7(),
        )
    }
    pub fn new_with_coordinator(
        store: Store,
        api_root: impl Into<String>,
        coordinator_key: fact_crypto::SigningKey,
        coordinator_actor_id: fact_core::ObjectId,
    ) -> Self {
        Self::new_with_reference_policy(store, api_root, coordinator_key, coordinator_actor_id)
    }

    pub fn new_without_caller_auth(
        store: Store,
        api_root: impl Into<String>,
        coordinator_key: fact_crypto::SigningKey,
        coordinator_actor_id: fact_core::ObjectId,
    ) -> Self {
        Self::new_with_policy(
            store,
            api_root,
            coordinator_key,
            coordinator_actor_id,
            CallerAuthPolicy::permissive(),
        )
    }

    pub fn new_with_reference_policy(
        store: Store,
        api_root: impl Into<String>,
        coordinator_key: fact_crypto::SigningKey,
        coordinator_actor_id: fact_core::ObjectId,
    ) -> Self {
        Self::new_with_policy(
            store,
            api_root,
            coordinator_key,
            coordinator_actor_id,
            CallerAuthPolicy::reference(),
        )
    }

    pub fn new_with_policy(
        store: Store,
        api_root: impl Into<String>,
        coordinator_key: fact_crypto::SigningKey,
        coordinator_actor_id: fact_core::ObjectId,
        caller_auth: CallerAuthPolicy,
    ) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            api_root: api_root.into(),
            coordinator_key: Arc::new(coordinator_key),
            coordinator_actor_id,
            write_queue: Arc::new(tokio::sync::Semaphore::new(MAX_QUEUED_WRITES)),
            write_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            caller_auth,
            ledger_visibility: Arc::new(Mutex::new(HashMap::new())),
            nonces: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set coordinator-local visibility for a hosted ledger.
    pub fn set_ledger_visibility(&self, ledger: fact_core::ObjectId, visibility: LedgerVisibility) {
        self.ledger_visibility
            .lock()
            .unwrap()
            .insert(*ledger.uuid().as_bytes(), visibility);
    }

    /// Configure visibility while constructing a router state value.
    pub fn with_ledger_visibility(
        self,
        ledger: fact_core::ObjectId,
        visibility: LedgerVisibility,
    ) -> Self {
        self.set_ledger_visibility(ledger, visibility);
        self
    }

    fn ledger_visibility(&self, ledger: &[u8; 16]) -> LedgerVisibility {
        self.ledger_visibility
            .lock()
            .unwrap()
            .get(ledger)
            .copied()
            .unwrap_or(LedgerVisibility::Public)
    }
}
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/facts", get(discovery))
        .route("/facts/ledgers", get(ledgers))
        .route("/facts/ledgers/{ledger_id}", get(ledger))
        .route(
            "/facts/ledgers/{ledger_id}/objects/{object_id}",
            get(object_by_id),
        )
        .route(
            "/facts/ledgers/{ledger_id}/dispositions/{object_id}",
            get(disposition),
        )
        .route("/facts/ledgers/{ledger_id}/objects", get(objects))
        .route("/facts/ledgers/{ledger_id}/commitment", get(commitment))
        .route(
            "/facts/ledgers/{ledger_id}/commitments/latest",
            get(latest_commitment),
        )
        .route("/facts/ledgers/{ledger_id}/proofs/{hash}", get(proof))
        .route(
            "/facts/ledgers/{ledger_id}/objects/by-hash/{hash}",
            get(object_by_hash),
        )
        .route(
            "/facts/ledgers/{ledger_id}/objects:fetch",
            post(fetch_objects),
        )
        .route(
            "/facts/ledgers/{ledger_id}/objects:pull",
            post(pull_objects),
        )
        .route("/facts/ledgers/{ledger_id}/query", post(query))
        .route(
            "/facts/ledgers/{ledger_id}/merkle:compare",
            post(merkle_compare),
        )
        .route("/facts/namespaces/{normalized_namespace}", get(namespace))
        .route("/facts/ledgers/{ledger_id}/objects:push", post(push))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(negotiate_accept))
        .layer(middleware::from_fn(normalize_method_not_allowed))
        .layer(middleware::from_fn(require_supported_version))
        .layer(middleware::from_fn(reject_unexpected_body))
        .layer(middleware::from_fn(validate_idempotency_key))
        .layer(middleware::from_fn(request_timeout))
        .layer(middleware::from_fn(content_encoding))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            caller_authentication,
        ))
        .layer(middleware::from_fn(attach_problem_instance))
        .with_state(state)
}

/// Serve the reference router with the documented transport boundary.
///
/// The router middleware enforces request-body limits and the 60-second body
/// deadline. This listener boundary additionally configures Hyper's actual
/// HTTP/1 header-read timeout; keeping it here avoids mistaking an application
/// middleware timer for protection against a slow client that has not sent a
/// complete request yet.
pub async fn serve_reference(
    listener: tokio::net::TcpListener,
    state: AppState,
) -> Result<(), std::io::Error> {
    serve_with_header_timeout(listener, state, REQUEST_HEADER_TIMEOUT).await
}

async fn serve_with_header_timeout(
    listener: tokio::net::TcpListener,
    state: AppState,
    header_timeout: std::time::Duration,
) -> Result<(), std::io::Error> {
    let service = router(state).into_service();
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let service = service.clone();
        tokio::spawn(async move {
            let tower_service =
                service.map_request(|request: hyper::Request<hyper::body::Incoming>| {
                    request.map(Body::new)
                });
            let hyper_service = TowerToHyperService::new(tower_service);
            let mut builder = ConnectionBuilder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout);
            let _ = builder
                .serve_connection_with_upgrades(io, hyper_service)
                .await;
        });
    }
}

async fn not_found() -> Response {
    problem(
        StatusCode::NOT_FOUND,
        "unknown-resource",
        "the requested resource is not visible",
    )
}

async fn normalize_method_not_allowed(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload-too-large",
            "request body exceeds the coordinator limit",
        );
    }
    if response.status() == StatusCode::METHOD_NOT_ALLOWED {
        let allow = response.headers().get(header::ALLOW).cloned();
        let mut normalized = problem(
            StatusCode::METHOD_NOT_ALLOWED,
            "method-not-allowed",
            "the requested method is not defined for this resource",
        );
        if let Some(allow) = allow {
            normalized.headers_mut().insert(header::ALLOW, allow);
        }
        return normalized;
    }
    response
}

async fn negotiate_accept(request: Request, next: Next) -> Response {
    let Some(accept) = request.headers().get(header::ACCEPT) else {
        return next.run(request).await;
    };
    let Ok(accept) = accept.to_str() else {
        return problem(
            StatusCode::NOT_ACCEPTABLE,
            "not-acceptable",
            "Accept is not valid UTF-8",
        );
    };
    let path = request.uri().path();
    let supported: &[&str] = if path.ends_with("/objects:pull") {
        &[JSON_MEDIA, SNAPSHOT_MEDIA]
    } else if path.contains("/objects/") && !path.contains(":") {
        &[COSE_MEDIA]
    } else {
        &[JSON_MEDIA]
    };
    let acceptable = accept.split(',').any(|item| {
        let mut parts = item.split(';');
        let media = parts.next().map(str::trim).unwrap_or_default();
        let quality = parts
            .find_map(|part| {
                let (name, value) = part.trim().split_once('=')?;
                (name == "q").then(|| value.parse::<f32>().ok())
            })
            .flatten()
            .unwrap_or(1.0);
        if quality <= 0.0 {
            return false;
        }
        media == "*/*"
            || supported.iter().any(|candidate| {
                media == *candidate
                    || (media.ends_with("/*") && candidate.starts_with(media.trim_end_matches('*')))
            })
    });
    if acceptable {
        next.run(request).await
    } else {
        problem(
            StatusCode::NOT_ACCEPTABLE,
            "not-acceptable",
            "no requested response media type is supported",
        )
    }
}

async fn require_supported_version(request: Request, next: Next) -> Response {
    if let Some(value) = request.headers().get("facts-protocol-version") {
        if value != HeaderValue::from_static(VERSION) {
            return problem(
                StatusCode::BAD_REQUEST,
                "unsupported-version",
                "only Facts-Protocol-Version: 0 is supported",
            );
        }
    }
    if request.uri().query().is_some_and(|query| !query.is_empty()) {
        return problem(
            StatusCode::BAD_REQUEST,
            "malformed-request",
            "query parameters are not part of the v0 endpoint contract",
        );
    }
    next.run(request).await
}

async fn attach_problem_instance(request: Request, next: Next) -> Response {
    let instance = request.uri().path().to_owned();
    let response = next.run(request).await;
    let is_problem = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "application/problem+json");
    if !is_problem {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, MAX_REQUEST_BODY_BYTES).await else {
        return Response::from_parts(parts, Body::empty());
    };
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    let Some(object) = value.as_object_mut() else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    object.insert("instance".to_owned(), serde_json::Value::String(instance));
    let Ok(body) = canonicalize(&serde_json::to_vec(&value).unwrap()) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    parts.headers.insert("content-digest", digest(&body));
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(body))
}

async fn request_timeout(request: Request, next: Next) -> Response {
    match tokio::time::timeout(REQUEST_BODY_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily-unavailable",
            "the coordinator request exceeded its time limit",
        ),
    }
}

async fn content_encoding(request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();
    let encoded = match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload-too-large",
                "request body exceeds the encoded protocol limit",
            )
        }
    };
    let encoding = parts
        .headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("identity");
    if encoding != "identity" && encoding != "gzip" {
        return problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-encoding",
            "only identity and gzip content encodings are supported",
        );
    }
    if encoding == "gzip" {
        if parts.headers.get("content-digest") != Some(&digest(&encoded)) {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-content-digest",
                "Content-Digest must match the encoded request body",
            );
        }
        let mut decoder = flate2::read::GzDecoder::new(encoded.as_ref());
        let mut decoded = Vec::new();
        if decoder.read_to_end(&mut decoded).is_err() {
            return problem(
                StatusCode::BAD_REQUEST,
                "malformed-content-encoding",
                "gzip request body could not be decoded",
            );
        }
        if decoded.len() > MAX_REQUEST_BODY_BYTES {
            return problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload-too-large",
                "decoded request body exceeds the protocol limit",
            );
        }
        parts.headers.remove(header::CONTENT_ENCODING);
        parts.headers.remove(header::CONTENT_LENGTH);
        parts.headers.insert("content-digest", digest(&decoded));
        return next
            .run(Request::from_parts(parts, Body::from(decoded)))
            .await;
    }
    next.run(Request::from_parts(parts, Body::from(encoded)))
        .await
}

async fn caller_authentication(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let push = request.method() == http::Method::POST && path.ends_with("/objects:push");
    let restricted_read = (request.method() == http::Method::POST
        && (path.ends_with("/objects:pull")
            || path.ends_with("/query")
            || path.ends_with("/merkle:compare")))
        || (request.method() == http::Method::GET && path.contains("/dispositions/"));
    let private_ledger = ledger_from_path(path)
        .is_some_and(|ledger| state.ledger_visibility(&ledger) == LedgerVisibility::Private);
    let requires_auth = (state.caller_auth.require_push && push)
        || (state.caller_auth.require_restricted_reads && restricted_read)
        || private_ledger;
    if !requires_auth {
        return next.run(request).await;
    }
    match verify_http_signature(&state, &request) {
        Ok(()) => next.run(request).await,
        Err(AuthFailure::Challenge) => authentication_challenge(&state, "authentication-required"),
        Err(AuthFailure::Failed) => authentication_challenge(&state, "authentication-failed"),
    }
}

fn ledger_from_path(path: &str) -> Option<[u8; 16]> {
    let mut segments = path.split('/');
    while let Some(segment) = segments.next() {
        if segment == "ledgers" {
            return segments.next().and_then(|ledger| uuid_bytes(ledger).ok());
        }
    }
    None
}

enum AuthFailure {
    Challenge,
    Failed,
}

fn authentication_challenge(state: &AppState, code: &str) -> Response {
    let nonce = base64url_encode(&rand::random::<[u8; 32]>());
    state.nonces.lock().unwrap().insert(
        nonce.clone(),
        OffsetDateTime::now_utc() + time::Duration::seconds(300),
    );
    let mut response = problem(
        StatusCode::UNAUTHORIZED,
        code,
        "caller authentication is required",
    );
    response.headers_mut().insert(
        "www-authenticate",
        HeaderValue::try_from(format!(
            "Signature realm=\"facts\", nonce=\"{nonce}\", algs=\"ed25519\""
        ))
        .unwrap(),
    );
    response
}

fn verify_http_signature(state: &AppState, request: &Request) -> Result<(), AuthFailure> {
    let input = request
        .headers()
        .get("signature-input")
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthFailure::Challenge)?;
    let signature = request
        .headers()
        .get("signature")
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthFailure::Challenge)?;
    let (components, created, key_id, nonce, params) = parse_signature_input(input)?;
    let required = [
        "@method",
        "@target-uri",
        "content-digest",
        "facts-ledger",
        "facts-protocol-version",
    ];
    if required
        .iter()
        .any(|name| !components.iter().any(|item| item == name))
    {
        return Err(AuthFailure::Failed);
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if (now - created).unsigned_abs() > 300 {
        return Err(AuthFailure::Failed);
    }
    let public_key = state
        .store
        .lock()
        .unwrap()
        .public_key_by_fingerprint(&key_id.parse().map_err(|_| AuthFailure::Failed)?)
        .map_err(|_| AuthFailure::Failed)?
        .ok_or(AuthFailure::Failed)?;
    let signature = parse_signature_value(signature)?;
    let signing_base = signature_base(state, request, &components, &params);
    fact_crypto::verify(public_key, signing_base.as_bytes(), signature)
        .map_err(|_| AuthFailure::Failed)?;
    let mut nonces = state.nonces.lock().unwrap();
    let expires = nonces.get(&nonce).copied().ok_or(AuthFailure::Failed)?;
    if expires <= OffsetDateTime::now_utc() {
        nonces.remove(&nonce);
        return Err(AuthFailure::Failed);
    }
    nonces.remove(&nonce);
    Ok(())
}

fn parse_signature_input(
    input: &str,
) -> Result<(Vec<String>, i64, String, String, String), AuthFailure> {
    let (_, value) = input.split_once('=').ok_or(AuthFailure::Failed)?;
    let start = value.find('(').ok_or(AuthFailure::Failed)?;
    let end = value[start + 1..]
        .find(')')
        .map(|index| start + 1 + index)
        .ok_or(AuthFailure::Failed)?;
    let components = value[start + 1..end]
        .split('"')
        .enumerate()
        .filter_map(|(index, value)| (index % 2 == 1).then_some(value.to_owned()))
        .collect::<Vec<_>>();
    let params = value[end + 1..].trim_start_matches(';').to_owned();
    let mut created = None;
    let mut key_id = None;
    let mut nonce = None;
    for parameter in params.split(';') {
        let (name, value) = parameter.split_once('=').ok_or(AuthFailure::Failed)?;
        match name.trim() {
            "created" => {
                created = Some(
                    value
                        .trim()
                        .parse::<i64>()
                        .map_err(|_| AuthFailure::Failed)?,
                )
            }
            "keyid" => key_id = Some(value.trim().trim_matches('"').to_owned()),
            "nonce" => nonce = Some(value.trim().trim_matches('"').to_owned()),
            _ => {}
        }
    }
    Ok((
        components,
        created.ok_or(AuthFailure::Failed)?,
        key_id.ok_or(AuthFailure::Failed)?,
        nonce.ok_or(AuthFailure::Failed)?,
        params,
    ))
}

fn signature_base(
    state: &AppState,
    request: &Request,
    components: &[String],
    params: &str,
) -> String {
    let origin = state
        .api_root
        .split("/facts")
        .next()
        .unwrap_or(&state.api_root);
    components
        .iter()
        .map(|component| {
            let value = match component.as_str() {
                "@method" => request.method().as_str().to_owned(),
                "@target-uri" => format!("{}{}", origin, request.uri()),
                name => request
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("")
                    .to_owned(),
            };
            format!("\"{component}\": {value}")
        })
        .chain(std::iter::once(
            format!(
                "\"@signature-params\": ({})",
                components
                    .iter()
                    .map(|component| format!("\"{component}\""))
                    .collect::<Vec<_>>()
                    .join(" ")
            ) + ";"
                + params,
        ))
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_signature_value(value: &str) -> Result<[u8; 64], AuthFailure> {
    let encoded = value
        .split_once("=:")
        .and_then(|(_, value)| value.strip_suffix(':'))
        .ok_or(AuthFailure::Failed)?;
    let bytes = base64_decode(encoded).ok_or(AuthFailure::Failed)?;
    bytes.try_into().map_err(|_| AuthFailure::Failed)
}

fn base64_decode(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in value.bytes().filter(|byte| *byte != b'=') {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | digit;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(output)
}

async fn reject_unexpected_body(request: Request, next: Next) -> Response {
    if matches!(request.method(), &http::Method::GET | &http::Method::HEAD) {
        let has_body = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > 0)
            || request.headers().contains_key(header::CONTENT_TYPE)
            || request.headers().contains_key("content-digest")
            || request.headers().contains_key(header::TRANSFER_ENCODING)
            || request.headers().contains_key(header::CONTENT_ENCODING);
        if has_body {
            return problem(
                StatusCode::BAD_REQUEST,
                "malformed-request",
                "this endpoint does not accept a request body",
            );
        }
    }
    next.run(request).await
}

async fn validate_idempotency_key(request: Request, next: Next) -> Response {
    if let Some(value) = request.headers().get("idempotency-key") {
        let valid = value.as_bytes().len() <= 255
            && !value.as_bytes().is_empty()
            && value.as_bytes().iter().all(|byte| *byte < 0x80);
        if !valid {
            return problem(
                StatusCode::BAD_REQUEST,
                "malformed-request",
                "Idempotency-Key must be 1-255 ASCII bytes",
            );
        }
    }
    next.run(request).await
}

async fn ledger(State(state): State<AppState>, Path(ledger): Path<String>) -> Response {
    match tokio::task::spawn_blocking(move || ledger_sync(state, ledger)).await {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn ledger_sync(state: AppState, ledger: String) -> Response {
    let ledger_bytes = match uuid_bytes(&ledger) {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "ledger_id must be UUIDv7",
            )
        }
    };
    let ledger_text = uuid::Uuid::from_bytes(ledger_bytes).to_string();
    let guard = state.store.lock().unwrap();
    match guard.get_ledger_metadata(&ledger_bytes) {
        Ok(Some((_namespace, _genesis_hash))) => {
            let genesis_hash = match _genesis_hash {
                Some(hash) => hash,
                None => {
                    return problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "coordinator-error",
                        "ledger metadata has no genesis hash",
                    )
                }
            };
            let genesis = match guard.get_cose_by_hash(&ledger_bytes, &genesis_hash) {
                Ok(Some(bytes)) => wire_object(&bytes).ok(),
                Ok(None) => None,
                Err(error) => {
                    return problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "coordinator-error",
                        &error.to_string(),
                    )
                }
            };
            let namespace_assertion_rows =
                match guard.list_object_payloads_by_type(&ledger_bytes, "namespace_assertion") {
                    Ok(rows) => rows,
                    Err(error) => {
                        return problem(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "coordinator-error",
                            &error.to_string(),
                        )
                    }
                };
            let namespace_assertions = namespace_assertion_rows
                .into_iter()
                .filter_map(|row| {
                    guard
                        .get_cose_by_id(&ledger_bytes, row.object_id.as_bytes())
                        .ok()
                        .flatten()
                        .and_then(|bytes| wire_object(&bytes).ok())
                })
                .collect::<Vec<_>>();
            let hashes = match guard.list_object_hashes(&ledger_bytes) {
                Ok(hashes) => hashes,
                Err(error) => {
                    return problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "coordinator-error",
                        &error.to_string(),
                    )
                }
            };
            let tree = match fact_commitment::MerkleTree::new(hashes) {
                Ok(tree) => tree,
                Err(error) => {
                    return problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "commitment-error",
                        &error.to_string(),
                    )
                }
            };
            let created_at = match guard.latest_object_created_at(&ledger_bytes) {
                Ok(Some(value)) => value,
                Ok(None) => timestamp_now(),
                Err(error) => {
                    return problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "commitment-error",
                        &error.to_string(),
                    )
                }
            };
            let ledger_id = match ledger_text.parse::<fact_core::ObjectId>() {
                Ok(value) => value,
                Err(_) => {
                    return problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "commitment-error",
                        "invalid ledger ID",
                    )
                }
            };
            let latest_commitment =
                match signed_commitment_ref(&state, &ledger_id, ledger_bytes, &tree, &created_at) {
                    Ok(value) => value,
                    Err(detail) => {
                        return problem(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "commitment-error",
                            detail,
                        )
                    }
                };
            let (signed_assertion, assertion_hash) = coordinator_assertion_artifact(&state);
            json_response(serde_json::json!({
                "schema":"facts-protocol-ledger-metadata-v0",
                "ledger_id":ledger_text,
                "genesis_hash":genesis_hash.hex(),
                "genesis":genesis,
                "namespace_assertions":namespace_assertions,
                "latest_commitment":latest_commitment,
                "coordinator_assertion":{
                    "object_id":null,
                    "content_hash":assertion_hash.hex(),
                    "cose_sign1":base64url_encode(&signed_assertion)
                }
            }))
        }
        Ok(None) => problem(
            StatusCode::NOT_FOUND,
            "ledger-not-found",
            "ledger is not visible",
        ),
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &error.to_string(),
        ),
    }
}

fn version_headers(mut headers: HeaderMap, media: &'static str, body: &[u8]) -> HeaderMap {
    headers.insert("facts-protocol-version", HeaderValue::from_static(VERSION));
    let request_id = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("request_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
    headers.insert(
        "facts-request-id",
        HeaderValue::try_from(request_id).expect("UUIDv7 request ID is a valid header value"),
    );
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(media));
    headers.insert("content-digest", digest(body));
    headers
}
fn digest(body: &[u8]) -> HeaderValue {
    let mut h = Sha256::new();
    h.update(body);
    let value = format!("sha-256=:{}:", base64_encode(&h.finalize()));
    HeaderValue::try_from(value).unwrap()
}
fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[(n >> 6 & 63) as usize] as char)
        }
        if chunk.len() > 2 {
            out.push(T[(n & 63) as usize] as char)
        }
    }
    out
}
fn json_response(value: serde_json::Value) -> Response {
    let body = json_body(value);
    (
        StatusCode::OK,
        version_headers(HeaderMap::new(), JSON_MEDIA, &body),
        body,
    )
        .into_response()
}
fn json_body(value: serde_json::Value) -> Vec<u8> {
    let envelope = serde_json::json!({
        "schema":"facts-protocol-response-v0",
        "request_id":uuid::Uuid::now_v7().to_string(),
        "protocol_version":0,
        "body":value
    });
    canonicalize(&serde_json::to_vec(&envelope).unwrap()).unwrap()
}
fn problem(status: StatusCode, code: &str, detail: &str) -> Response {
    problem_with_object_errors(status, code, detail, Vec::new())
}

fn problem_with_object_errors(
    status: StatusCode,
    code: &str,
    detail: &str,
    object_errors: Vec<serde_json::Value>,
) -> Response {
    let negotiation_failed = code == "unsupported-version";
    let v = serde_json::json!({"type":format!("https://facts.example/errors/{code}"),"title":problem_title(code),"status":status.as_u16(),"code":code,"first_error_code":code,"detail":detail,"instance":"/facts","request_id":uuid::Uuid::now_v7().to_string(),"protocol_version":if negotiation_failed { serde_json::Value::Null } else { serde_json::json!(0) },"ledger_id":null,"object_errors":object_errors,"missing_dependencies":[],"supported_versions":if negotiation_failed { serde_json::json!([0]) } else { serde_json::json!([]) },"retry":null});
    let body = canonicalize(&serde_json::to_vec(&v).unwrap()).unwrap();
    (
        status,
        version_headers(HeaderMap::new(), "application/problem+json", &body),
        body,
    )
        .into_response()
}

fn problem_title(code: &str) -> String {
    code.split('-')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
fn require_protocol_version(headers: &HeaderMap) -> Option<Response> {
    match headers.get("facts-protocol-version") {
        None => None,
        Some(value) if value == HeaderValue::from_static(VERSION) => None,
        Some(_) => Some(problem(
            StatusCode::BAD_REQUEST,
            "unsupported-version",
            "only Facts-Protocol-Version: 0 is supported",
        )),
    }
}

fn require_matching_ledger_header(headers: &HeaderMap, ledger: &[u8; 16]) -> Option<Response> {
    let value = headers.get("facts-ledger")?;
    let matches = value
        .to_str()
        .ok()
        .and_then(|value| uuid_bytes(value).ok())
        .is_some_and(|value| value == *ledger);
    if matches {
        None
    } else {
        Some(problem(
            StatusCode::BAD_REQUEST,
            "ledger-mismatch",
            "Facts-Ledger does not match the request path",
        ))
    }
}

async fn discovery(State(state): State<AppState>) -> Response {
    let (signed_assertion, _) = coordinator_assertion_artifact(&state);
    json_response(serde_json::json!({
        "schema":"facts-protocol-coordinator-discovery-v0",
        "coordinator_assertion":base64url_encode(&signed_assertion),
        "api_root":state.api_root,
        "supported_versions":[0],
        "supported_media_types":[JSON_MEDIA],
        "deployment_profile":{
            "request_header_timeout_seconds":REQUEST_HEADER_TIMEOUT.as_secs(),
            "request_body_timeout_seconds":REQUEST_BODY_TIMEOUT.as_secs(),
            "maximum_protocol_body_bytes":MAX_REQUEST_BODY_BYTES,
            "maximum_writer_queue":MAX_QUEUED_WRITES,
            "maximum_read_connections":8,
            "maximum_fetch_ids":1000,
            "maximum_fetch_hashes":1000,
            "maximum_query_page_size":1000,
            "content_encoding":"identity",
            "accepted_content_encodings":["identity","gzip"],
            "caller_authentication":"deployment-policy",
            "per_ledger_visibility":"coordinator-policy",
            "header_timeout_enforced_by":"serve_reference"
        }
    }))
}

fn coordinator_assertion_artifact(state: &AppState) -> (Vec<u8>, fact_core::Hash) {
    let assertion = serde_json::json!({
        "schema":"facts-protocol-coordinator-assertion-v0",
        "coordinator_actor_id":state.coordinator_actor_id.to_string(),
        "active_key_fingerprint":state.coordinator_key.fingerprint().hex(),
        "endpoint_uri":state.api_root,
        "supported_protocol_versions":[0],
        "supported_operations":["fetch","pull","push","query"],
        "features":["bundles","commitments","snapshots"],
        "validity":{"valid_from":null,"expires_at":null},
        "predecessor_assertion_hash":null,
        "identity_attestation_refs":[]
    });
    let payload =
        canonicalize(&serde_json::to_vec(&assertion).expect("JSON encoding is infallible"))
            .expect("coordinator assertion is canonicalizable");
    let protected = fact_crypto::coordinator_protected(
        state.coordinator_key.public_key(),
        "coordinator-assertion",
        "0",
        None,
    );
    let signed = fact_crypto::encode_sign1(&fact_crypto::sign1(
        &protected,
        &payload,
        &state.coordinator_key,
    ));
    (signed, fact_core::Hash::digest(&payload))
}
async fn ledgers(State(state): State<AppState>) -> Response {
    match tokio::task::spawn_blocking(move || ledgers_sync(state)).await {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn ledgers_sync(state: AppState) -> Response {
    let guard = state.store.lock().unwrap();
    match guard.list_ledger_metadata() {
        Ok(items) => {
            let ledgers = items
                .into_iter()
                .filter(|(id, _, _)| {
                    uuid_bytes(id)
                        .ok()
                        .is_none_or(|ledger| state.ledger_visibility(&ledger).is_public())
                })
                .map(|(id, namespace, genesis_hash)| {
                    let latest_commitment_hash = uuid_bytes(&id)
                        .ok()
                        .and_then(|ledger| guard.list_object_hashes(&ledger).ok())
                        .and_then(|hashes| {
                            let tree = fact_commitment::MerkleTree::new(hashes).ok()?;
                            let created_at = guard
                                .latest_object_created_at(&uuid_bytes(&id).ok()?)
                                .ok()??;
                            let body = normative_commitment_body_at(
                                &state,
                                &ledger_from_id(&id)?,
                                &tree,
                                &created_at,
                            );
                            let payload = canonicalize(&serde_json::to_vec(&body).ok()?).ok()?;
                            Some(fact_core::Hash::digest(&payload).hex())
                        });
                    let visibility = uuid_bytes(&id)
                        .map(|ledger| state.ledger_visibility(&ledger).as_str())
                        .unwrap_or("public");
                    serde_json::json!({"ledger_id":id,"genesis_hash":genesis_hash.map(|hash|hash.hex()),"namespace":namespace,"latest_commitment_hash":latest_commitment_hash,"visibility":visibility})
                })
                .collect::<Vec<_>>();
            json_response(
                serde_json::json!({"schema":"facts-protocol-ledger-list-v0","ledgers":ledgers,"next_cursor":null}),
            )
        }
        Err(e) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &e.to_string(),
        ),
    }
}

fn ledger_from_id(id: &str) -> Option<fact_core::ObjectId> {
    id.parse().ok()
}

fn commitment_body(
    state: &AppState,
    ledger: &fact_core::ObjectId,
    tree: &fact_commitment::MerkleTree,
) -> serde_json::Value {
    serde_json::json!({
        "schema":"facts-protocol-merkle-v0",
        "coordinator_actor_id":state.coordinator_actor_id.to_string(),
        "ledger_id":ledger.to_string(),
        "scope":{"ledger_id":ledger.to_string()},
        "tree_profile":"facts-protocol-merkle-v0",
        "root":tree.root.hex(),
        "object_count":tree.leaves.len(),
        "previous_commitment_hash":null
    })
}

fn full_ledger_scope(ledger: &impl std::fmt::Display) -> serde_json::Value {
    serde_json::json!({
        "ledger_id": ledger.to_string(),
        "snapshot_boundary": null,
        "query_digest": null,
        "object_types": [],
        "actor_ids": [],
        "proposition_ids": [],
        "revision_ids": [],
        "deliberation_ids": [],
        "filters": {}
    })
}

fn pull_query_digest(scope: &serde_json::Value, limit: usize) -> fact_core::Hash {
    let value = serde_json::json!({"limit":limit,"scope":scope});
    let bytes = canonicalize(&serde_json::to_vec(&value).expect("JSON encoding is infallible"))
        .expect("pull cursor input is canonicalizable");
    fact_core::Hash::digest(&bytes)
}

fn normative_commitment_body_at(
    state: &AppState,
    ledger: &fact_core::ObjectId,
    tree: &fact_commitment::MerkleTree,
    created_at: &str,
) -> serde_json::Value {
    normative_commitment_body_for_scope(state, ledger, &full_ledger_scope(ledger), tree, created_at)
}

fn normative_commitment_body_for_scope(
    state: &AppState,
    ledger: &fact_core::ObjectId,
    scope: &serde_json::Value,
    tree: &fact_commitment::MerkleTree,
    created_at: &str,
) -> serde_json::Value {
    let scope_hash =
        canonicalize(&serde_json::to_vec(&scope).expect("JSON encoding is infallible"))
            .map(|bytes| fact_core::Hash::digest(&bytes).hex())
            .expect("canonical scope is valid");
    let mut body = serde_json::json!({
        "schema":"facts-protocol-commitment-v0",
        "coordinator_actor_id":state.coordinator_actor_id.to_string(),
        "ledger_id":ledger.to_string(),
        "scope":scope,
        "scope_hash":scope_hash,
        "snapshot_id":null,
        "tree_profile":"facts-protocol-merkle-v0",
        "root_hash":tree.root.hex(),
        "object_count":tree.leaves.len(),
        "created_at":created_at,
        "previous_commitment_hash":null,
        "signing_key_fingerprint":state.coordinator_key.fingerprint().hex()
    });
    let preimage = canonicalize(&serde_json::to_vec(&body).expect("JSON encoding is infallible"))
        .expect("commitment preimage is canonicalizable");
    let snapshot_id = fact_core::Hash::digest(&preimage).hex();
    body["snapshot_id"] = serde_json::Value::String(snapshot_id);
    body
}

fn signed_commitment_ref(
    state: &AppState,
    ledger: &fact_core::ObjectId,
    ledger_bytes: [u8; 16],
    tree: &fact_commitment::MerkleTree,
    created_at: &str,
) -> Result<serde_json::Value, &'static str> {
    let body = normative_commitment_body_at(state, ledger, tree, created_at);
    let payload =
        canonicalize(&serde_json::to_vec(&body).map_err(|_| "could not serialize commitment")?)
            .map_err(|_| "could not canonicalize commitment")?;
    let protected = fact_crypto::coordinator_protected(
        state.coordinator_key.public_key(),
        "commitment",
        "0",
        Some(ledger_bytes),
    );
    let signed = fact_crypto::encode_sign1(&fact_crypto::sign1(
        &protected,
        &payload,
        &state.coordinator_key,
    ));
    Ok(serde_json::json!({
        "commitment":base64url_encode(&signed),
        "commitment_hash":fact_core::Hash::digest(&payload).hex()
    }))
}

async fn namespace(
    State(state): State<AppState>,
    Path(normalized_namespace): Path<String>,
) -> Response {
    match tokio::task::spawn_blocking(move || namespace_sync(state, normalized_namespace)).await {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn namespace_sync(state: AppState, normalized_namespace: String) -> Response {
    let guard = state.store.lock().unwrap();
    match guard.list_ledger_metadata() {
        Ok(items) => {
            let matching = items
                .into_iter()
                .filter(|(id, namespace, _)| {
                    namespace == &normalized_namespace
                        && uuid_bytes(id)
                            .ok()
                            .is_none_or(|ledger| state.ledger_visibility(&ledger).is_public())
                })
                .collect::<Vec<_>>();
            if matching.is_empty() {
                problem(
                    StatusCode::NOT_FOUND,
                    "namespace-not-found",
                    "namespace is not visible",
                )
            } else {
                let mut assertions = Vec::new();
                let mut authorities = Vec::new();
                let mut targets = HashSet::new();
                for (ledger_id, _, _) in matching {
                    let Ok(ledger_bytes) = uuid_bytes(&ledger_id) else {
                        continue;
                    };
                    let Ok(rows) =
                        guard.list_object_payloads_by_type(&ledger_bytes, "namespace_assertion")
                    else {
                        continue;
                    };
                    for row in rows {
                        let Ok(Some(bytes)) =
                            guard.get_cose_by_id(&ledger_bytes, row.object_id.as_bytes())
                        else {
                            continue;
                        };
                        if let Ok(value) = fact_crypto::decode_sign1(&bytes)
                            .ok()
                            .and_then(|cose| {
                                serde_json::from_slice::<serde_json::Value>(&cose.payload).ok()
                            })
                            .ok_or(())
                        {
                            if let Some(body) = value.get("body") {
                                if let Some(actor) = body
                                    .get("naming_authority_actor_id")
                                    .and_then(serde_json::Value::as_str)
                                {
                                    authorities.push(actor.to_owned());
                                }
                                if let Some(target) =
                                    body.get("target_id").and_then(serde_json::Value::as_str)
                                {
                                    targets.insert(target.to_owned());
                                }
                            }
                        }
                        if let Ok(wire) = wire_object(&bytes) {
                            assertions.push(wire);
                        }
                    }
                }
                assertions.sort_by(|a, b| {
                    a.get("content_hash")
                        .and_then(serde_json::Value::as_str)
                        .cmp(&b.get("content_hash").and_then(serde_json::Value::as_str))
                });
                authorities.sort();
                let resolution = if assertions.is_empty() {
                    "unresolved"
                } else if targets.len() <= 1 {
                    "unique"
                } else {
                    "ambiguous"
                };
                json_response(serde_json::json!({
                    "schema":"facts-protocol-namespace-response-v0",
                    "namespace":normalized_namespace,
                    "naming_authority_actor_id":authorities.first()
                        .cloned()
                        .unwrap_or_else(|| state.coordinator_actor_id.to_string()),
                    "assertions":assertions,
                    "resolution":resolution
                }))
            }
        }
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &error.to_string(),
        ),
    }
}
async fn object_by_id(
    State(state): State<AppState>,
    Path((ledger, id)): Path<(String, String)>,
) -> Response {
    match tokio::task::spawn_blocking(move || object_by_id_sync(state, ledger, id)).await {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn object_by_id_sync(state: AppState, ledger: String, id: String) -> Response {
    let ledger = match uuid_bytes(&ledger) {
        Ok(x) => x,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "ledger_id must be UUIDv7",
            )
        }
    };
    let ledger_text = uuid::Uuid::from_bytes(ledger).to_string();
    let id = match uuid_bytes(&id) {
        Ok(x) => x,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "object_id must be UUIDv7",
            )
        }
    };
    let guard = state.store.lock().unwrap();
    match guard.get_cose_by_id(&ledger, &id) {
        Ok(Some(bytes)) => {
            let mut headers = version_headers(HeaderMap::new(), COSE_MEDIA, &bytes);
            headers.insert("facts-ledger", HeaderValue::from_str(&ledger_text).unwrap());
            (StatusCode::OK, headers, bytes).into_response()
        }
        Ok(None) => problem(
            StatusCode::NOT_FOUND,
            "object-not-found",
            "object is not visible",
        ),
        Err(e) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &e.to_string(),
        ),
    }
}

async fn disposition(
    State(state): State<AppState>,
    Path((ledger, object_id)): Path<(String, String)>,
) -> Response {
    match tokio::task::spawn_blocking(move || disposition_sync(state, ledger, object_id)).await {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn disposition_sync(state: AppState, ledger: String, object_id: String) -> Response {
    let ledger = match uuid_bytes(&ledger) {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "ledger_id must be UUIDv7",
            )
        }
    };
    let object_id = match uuid_bytes(&object_id) {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "object_id must be UUIDv7",
            )
        }
    };
    let guard = state.store.lock().unwrap();
    let bytes = match guard.get_cose_by_id(&ledger, &object_id) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return problem(
                StatusCode::NOT_FOUND,
                "object-not-found",
                "object is not visible",
            )
        }
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "coordinator-error",
                &error.to_string(),
            )
        }
    };
    let cose = match fact_crypto::decode_sign1(&bytes) {
        Ok(cose) => cose,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "coordinator-error",
                &error.to_string(),
            )
        }
    };
    let object_hash = fact_core::Hash::digest(&cose.payload);
    let body = serde_json::json!({
        "schema":"facts-protocol-disposition-v0",
        "coordinator_actor_id":state.coordinator_actor_id.to_string(),
        "object_id":uuid::Uuid::from_bytes(object_id).to_string(),
        "object_hash":object_hash.hex(),
        "disposition_code":"accepted",
        "disposition_at":timestamp_now(),
        "trusted_validation_time":timestamp_now(),
        "clock_status":"trusted",
        "evaluated_bounds":null,
        "policy_id":null,
        "explanation":null,
        "missing_dependencies":[],
        "signing_key_fingerprint":state.coordinator_key.fingerprint().hex()
    });
    let payload = match canonicalize(&serde_json::to_vec(&body).unwrap()) {
        Ok(payload) => payload,
        Err(_) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "disposition-error",
                "could not canonicalize disposition",
            )
        }
    };
    let protected = fact_crypto::coordinator_protected(
        state.coordinator_key.public_key(),
        "disposition",
        "0",
        Some(ledger),
    );
    let signed = fact_crypto::encode_sign1(&fact_crypto::sign1(
        &protected,
        &payload,
        &state.coordinator_key,
    ));
    let response = serde_json::json!({
        "schema":"facts-protocol-disposition-response-v0",
        "disposition":base64url_encode(&signed)
    });
    let response_body = json_body(response);
    let mut response_headers = version_headers(HeaderMap::new(), JSON_MEDIA, &response_body);
    response_headers.insert(
        "facts-ledger",
        HeaderValue::from_str(&uuid::Uuid::from_bytes(ledger).to_string()).unwrap(),
    );
    (StatusCode::OK, response_headers, response_body).into_response()
}
async fn objects(State(state): State<AppState>, Path(ledger): Path<String>) -> Response {
    match tokio::task::spawn_blocking(move || objects_sync(state, ledger)).await {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn objects_sync(state: AppState, ledger: String) -> Response {
    let ledger = match uuid_bytes(&ledger) {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "ledger_id must be UUIDv7",
            )
        }
    };
    let ledger_text = uuid::Uuid::from_bytes(ledger).to_string();
    let guard = state.store.lock().unwrap();
    match guard.list_object_summaries_page(&ledger, None, MAX_OBJECT_LIST_PAGE_SIZE + 1) {
        Ok(mut objects) => {
            let complete = objects.len() <= MAX_OBJECT_LIST_PAGE_SIZE;
            if !complete {
                objects.truncate(MAX_OBJECT_LIST_PAGE_SIZE);
            }
            let next_cursor = if complete {
                serde_json::Value::Null
            } else {
                objects
                    .last()
                    .map(|object| serde_json::Value::String(object.content_hash.hex()))
                    .unwrap_or(serde_json::Value::Null)
            };
            let value = serde_json::json!({
                "schema": "facts-protocol-object-list-v0",
                "objects": objects.into_iter().map(|object| serde_json::json!({
                    "object_id": object.object_id,
                    "content_hash": object.content_hash.hex(),
                    "object_type": object.object_type,
                })).collect::<Vec<_>>(),
                "next_cursor": next_cursor,
            });
            json_with_ledger_headers(StatusCode::OK, &ledger_text, value)
        }
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &error.to_string(),
        ),
    }
}

async fn latest_commitment(State(state): State<AppState>, Path(ledger): Path<String>) -> Response {
    match tokio::task::spawn_blocking(move || latest_commitment_sync(state, ledger)).await {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn latest_commitment_sync(state: AppState, ledger: String) -> Response {
    let ledger_bytes = match uuid_bytes(&ledger) {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "ledger_id must be UUIDv7",
            )
        }
    };
    let guard = state.store.lock().unwrap();
    let hashes = match guard.list_object_hashes(&ledger_bytes) {
        Ok(hashes) => hashes,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "coordinator-error",
                &error.to_string(),
            )
        }
    };
    let tree = match fact_commitment::MerkleTree::new(hashes) {
        Ok(tree) => tree,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                &error.to_string(),
            )
        }
    };
    let ledger_id = match ledger.parse::<fact_core::ObjectId>() {
        Ok(id) => id,
        Err(_) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                "invalid ledger ID",
            )
        }
    };
    let created_at = match guard.latest_object_created_at(&ledger_bytes) {
        Ok(Some(value)) => value,
        Ok(None) => timestamp_now(),
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                &error.to_string(),
            )
        }
    };
    let unsigned = normative_commitment_body_at(&state, &ledger_id, &tree, &created_at);
    let payload = match canonicalize(&serde_json::to_vec(&unsigned).unwrap()) {
        Ok(payload) => payload,
        Err(_) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                "could not canonicalize commitment",
            )
        }
    };
    let protected = fact_crypto::coordinator_protected(
        state.coordinator_key.public_key(),
        "commitment",
        "0",
        Some(ledger_bytes),
    );
    let signed = fact_crypto::encode_sign1(&fact_crypto::sign1(
        &protected,
        &payload,
        &state.coordinator_key,
    ));
    json_response(serde_json::json!({
        "schema":"facts-protocol-commitment-response-v0",
        "commitment":base64url_encode(&signed),
        "commitment_hash":fact_core::Hash::digest(&payload).hex()
    }))
}

async fn commitment(State(state): State<AppState>, Path(ledger): Path<String>) -> Response {
    match tokio::task::spawn_blocking(move || commitment_sync(state, ledger)).await {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn commitment_sync(state: AppState, ledger: String) -> Response {
    let ledger = match uuid_bytes(&ledger) {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "ledger_id must be UUIDv7",
            )
        }
    };
    let ledger_text = uuid::Uuid::from_bytes(ledger).to_string();
    let guard = state.store.lock().unwrap();
    let hashes = match guard.list_object_hashes(&ledger) {
        Ok(hashes) => hashes,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "coordinator-error",
                &error.to_string(),
            )
        }
    };
    let tree = match fact_commitment::MerkleTree::new(hashes) {
        Ok(tree) => tree,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                &error.to_string(),
            )
        }
    };
    let commitment_statement = commitment_body(&state, &ledger_text.parse().unwrap(), &tree);
    let commitment_payload = match canonicalize(&serde_json::to_vec(&commitment_statement).unwrap())
    {
        Ok(payload) => payload,
        Err(_) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                "could not canonicalize commitment",
            )
        }
    };
    let protected = fact_crypto::coordinator_protected(
        state.coordinator_key.public_key(),
        "commitment",
        "0",
        Some(ledger),
    );
    let signed_commitment = fact_crypto::encode_sign1(&fact_crypto::sign1(
        &protected,
        &commitment_payload,
        &state.coordinator_key,
    ));
    let value = serde_json::json!({
        "schema": "facts-protocol-commitment-v0",
        "ledger_id": ledger_text,
        "tree_profile": "facts-protocol-merkle-v0",
        "root": tree.root.hex(),
        "object_count": tree.leaves.len(),
        "signed_commitment": base64url_encode(&signed_commitment),
    });
    json_with_ledger_headers(StatusCode::OK, &ledger_text, value)
}

async fn proof(
    State(state): State<AppState>,
    Path((ledger, hash)): Path<(String, String)>,
) -> Response {
    match tokio::task::spawn_blocking(move || proof_sync(state, ledger, hash)).await {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn proof_sync(state: AppState, ledger: String, hash: String) -> Response {
    let ledger = match uuid_bytes(&ledger) {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "ledger_id must be UUIDv7",
            )
        }
    };
    let hash = match fact_core::Hash::from_str(&hash) {
        Ok(hash) => hash,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "hash must be SHA-256",
            )
        }
    };
    let ledger_text = uuid::Uuid::from_bytes(ledger).to_string();
    let guard = state.store.lock().unwrap();
    let hashes = match guard.list_object_hashes(&ledger) {
        Ok(hashes) => hashes,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "coordinator-error",
                &error.to_string(),
            )
        }
    };
    let tree = match fact_commitment::MerkleTree::new(hashes) {
        Ok(tree) => tree,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                &error.to_string(),
            )
        }
    };
    let step_json = |step: &fact_commitment::ProofStep| serde_json::json!({"sibling":step.sibling.hex(),"sibling_left":step.sibling_left});
    let value = if let Some(index) = tree.leaves.iter().position(|candidate| *candidate == hash) {
        let steps = tree
            .proof(index)
            .unwrap()
            .iter()
            .map(step_json)
            .collect::<Vec<_>>();
        serde_json::json!({"schema":"facts-protocol-proof-v0","ledger_id":ledger_text,"content_hash":hash.hex(),"proof_type":"inclusion","root":tree.root.hex(),"index":index,"steps":steps})
    } else {
        let proof = tree.non_inclusion_proof(hash).unwrap();
        let neighbor = |entry: &Option<(fact_core::Hash, Vec<fact_commitment::ProofStep>)>| {
            entry.as_ref().map(|(hash, steps)| {
                serde_json::json!({
                    "content_hash":hash.hex(),
                    "steps":steps.iter().map(step_json).collect::<Vec<_>>()
                })
            })
        };
        serde_json::json!({"schema":"facts-protocol-proof-v0","ledger_id":ledger_text,"content_hash":hash.hex(),"proof_type":"non-inclusion","root":tree.root.hex(),"left":neighbor(&proof.left),"right":neighbor(&proof.right)})
    };
    json_with_ledger_headers(StatusCode::OK, &ledger_text, value)
}

async fn merkle_compare(
    State(state): State<AppState>,
    Path(ledger): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match tokio::task::spawn_blocking(move || merkle_compare_sync(state, ledger, headers, body))
        .await
    {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn merkle_compare_sync(
    state: AppState,
    ledger: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(JSON_MEDIA)
    {
        return problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-media-type",
            "merkle comparison requires application/fact+json",
        );
    }
    if headers.get("content-digest") != Some(&digest(&body)) {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid-content-digest",
            "Content-Digest does not match the request body",
        );
    }
    let ledger = match uuid_bytes(&ledger) {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "ledger_id must be UUIDv7",
            )
        }
    };
    if let Some(response) = require_matching_ledger_header(&headers, &ledger) {
        return response;
    }
    let canonical = match canonicalize(&body) {
        Ok(value) if value == body => value,
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "noncanonical-request",
                "comparison body must be canonical JSON",
            )
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(&canonical) {
        Ok(value) => value,
        Err(error) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "malformed-request",
                &error.to_string(),
            )
        }
    };
    let object = match value.as_object() {
        Some(object)
            if object.len() == 5
                && object.get("schema").and_then(serde_json::Value::as_str)
                    == Some("facts-protocol-merkle-compare-v0")
                && object.contains_key("operation")
                && object.contains_key("commitment_hash")
                && object.contains_key("object_hashes")
                && object.contains_key("other_commitment_hash") =>
        {
            object
        }
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-request",
                "comparison requires operation, commitment_hash, object_hashes, and other_commitment_hash",
            )
        }
    };
    let operation = match object.get("operation").and_then(serde_json::Value::as_str) {
        Some(operation @ ("include" | "exclude" | "difference")) => operation,
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-request",
                "operation must be include, exclude, or difference",
            )
        }
    };
    let other_commitment = match object.get("other_commitment_hash") {
        Some(value) if value.is_null() => None,
        Some(value) => match value
            .as_str()
            .and_then(|value| value.parse::<fact_core::Hash>().ok())
        {
            Some(hash) => Some(hash),
            None => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "invalid-identifier",
                    "other_commitment_hash must be lowercase SHA-256 or null",
                )
            }
        },
        None => unreachable!("request shape requires other_commitment_hash"),
    };
    if (operation == "difference") != other_commitment.is_some()
        || (operation != "difference" && other_commitment.is_some())
    {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid-request",
            "other_commitment_hash is required only for difference",
        );
    }
    let expected_root = match object
        .get("commitment_hash")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse::<fact_core::Hash>().ok())
    {
        Some(hash) => hash,
        None => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "commitment_hash must be lowercase SHA-256",
            )
        }
    };
    let requested = match parse_sorted_text_array(object.get("object_hashes"), false) {
        Ok(values) => values
            .into_iter()
            .map(|value| value.parse::<fact_core::Hash>().unwrap())
            .collect::<Vec<_>>(),
        Err(detail) => return problem(StatusCode::BAD_REQUEST, "invalid-request", &detail),
    };
    if operation == "difference" && !requested.is_empty() {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid-request",
            "object_hashes must be empty for difference",
        );
    }
    let guard = state.store.lock().unwrap();
    let hashes = match guard.list_object_hashes(&ledger) {
        Ok(hashes) => hashes,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "coordinator-error",
                &error.to_string(),
            )
        }
    };
    let tree = match fact_commitment::MerkleTree::new(hashes) {
        Ok(tree) => tree,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                &error.to_string(),
            )
        }
    };
    let ledger_id = match uuid::Uuid::from_bytes(ledger).to_string().parse() {
        Ok(ledger_id) => ledger_id,
        Err(_) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                "invalid ledger ID",
            )
        }
    };
    let created_at = match guard.latest_object_created_at(&ledger) {
        Ok(Some(value)) => value,
        Ok(None) => timestamp_now(),
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                &error.to_string(),
            )
        }
    };
    let commitment_body = normative_commitment_body_at(&state, &ledger_id, &tree, &created_at);
    let commitment_payload = match canonicalize(&serde_json::to_vec(&commitment_body).unwrap()) {
        Ok(payload) => payload,
        Err(_) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                "could not canonicalize commitment",
            )
        }
    };
    let current_commitment_hash = fact_core::Hash::digest(&commitment_payload);
    if current_commitment_hash != expected_root {
        return problem(
            StatusCode::CONFLICT,
            "commitment-mismatch",
            "commitment_hash is not the current ledger commitment",
        );
    }
    let inclusion_json =
        |hash: fact_core::Hash, index: usize, steps: &[fact_commitment::ProofStep]| {
            serde_json::json!({
                "schema":"facts-protocol-merkle-inclusion-proof-v0",
                "object_hash":hash.hex(),
                "leaf_index":index,
                "tree_size":tree.leaves.len(),
                "siblings":steps.iter().map(|step|step.sibling.hex()).collect::<Vec<_>>()
            })
        };
    let evidence = match operation {
        "include" => requested
            .iter()
            .map(|hash| {
                let index = tree.leaves.binary_search(hash).map_err(|_| ())?;
                Ok(inclusion_json(
                    *hash,
                    index,
                    &tree.proof(index).map_err(|_| ())?,
                ))
            })
            .collect::<Result<Vec<_>, ()>>(),
        "exclude" => requested
            .iter()
            .map(|hash| {
                let proof = tree.non_inclusion_proof(*hash).map_err(|_| ())?;
                let neighbor =
                    |entry: &Option<(fact_core::Hash, Vec<fact_commitment::ProofStep>)>| {
                        entry.as_ref().and_then(|(neighbor_hash, steps)| {
                            let index = tree.leaves.binary_search(neighbor_hash).ok()?;
                            Some(serde_json::json!({
                                "proof":inclusion_json(*neighbor_hash, index, steps),
                                "index":index
                            }))
                        })
                    };
                Ok(serde_json::json!({
                    "schema":"facts-protocol-merkle-non-inclusion-proof-v0",
                    "queried_hash":hash.hex(),
                    "tree_size":tree.leaves.len(),
                    "root_hash":tree.root.hex(),
                    "predecessor":neighbor(&proof.left),
                    "successor":neighbor(&proof.right)
                }))
            })
            .collect::<Result<Vec<_>, ()>>(),
        "difference" => Ok(vec![]),
        _ => unreachable!(),
    };
    let evidence = match evidence {
        Ok(evidence) => evidence,
        Err(_) => {
            return problem(
                StatusCode::CONFLICT,
                "proof-unavailable",
                "requested inclusion proof is not present in the commitment",
            )
        }
    };
    let response = serde_json::json!({
        "schema":"facts-protocol-merkle-compare-response-v0",
        "operation":operation,
        "commitment_hash":expected_root.hex(),
        "proofs":evidence,
        "difference":if operation == "difference" {
            Some(serde_json::json!({
                "added_hashes":[],
                "removed_hashes":[],
                "complete":other_commitment == Some(expected_root)
            }))
        } else {
            None
        }
    });
    json_with_ledger_headers(
        StatusCode::OK,
        &uuid::Uuid::from_bytes(ledger).to_string(),
        response,
    )
}

async fn object_by_hash(
    State(state): State<AppState>,
    Path((ledger, hash)): Path<(String, String)>,
) -> Response {
    match tokio::task::spawn_blocking(move || object_by_hash_sync(state, ledger, hash)).await {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn object_by_hash_sync(state: AppState, ledger: String, hash: String) -> Response {
    let ledger = match uuid_bytes(&ledger) {
        Ok(x) => x,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "ledger_id must be UUIDv7",
            )
        }
    };
    let hash = match fact_core::Hash::from_str(&hash) {
        Ok(x) => x,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "hash must be SHA-256",
            )
        }
    };
    let ledger_text = uuid::Uuid::from_bytes(ledger).to_string();
    let guard = state.store.lock().unwrap();
    match guard.get_cose_by_hash(&ledger, &hash) {
        Ok(Some(bytes)) => {
            let mut headers = version_headers(HeaderMap::new(), COSE_MEDIA, &bytes);
            headers.insert("facts-ledger", HeaderValue::from_str(&ledger_text).unwrap());
            (StatusCode::OK, headers, bytes).into_response()
        }
        Ok(None) => problem(
            StatusCode::NOT_FOUND,
            "object-not-found",
            "object is not visible",
        ),
        Err(e) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &e.to_string(),
        ),
    }
}

async fn fetch_objects(
    State(state): State<AppState>,
    Path(ledger): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match tokio::task::spawn_blocking(move || fetch_objects_sync(state, ledger, headers, body))
        .await
    {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn fetch_objects_sync(
    state: AppState,
    ledger: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = require_protocol_version(&headers) {
        return response;
    }
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(JSON_MEDIA)
    {
        return problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-media-type",
            "objects:fetch requires application/fact+json",
        );
    }
    if headers.get("content-digest") != Some(&digest(&body)) {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid-content-digest",
            "Content-Digest does not match the request body",
        );
    }
    let ledger = match uuid_bytes(&ledger) {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "ledger_id must be UUIDv7",
            )
        }
    };
    if let Some(response) = require_matching_ledger_header(&headers, &ledger) {
        return response;
    }
    let canonical = match canonicalize(&body) {
        Ok(value) if value == body => value,
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "noncanonical-request",
                "batch fetch body must be canonical JSON",
            )
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(&canonical) {
        Ok(value) => value,
        Err(error) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "malformed-request",
                &error.to_string(),
            )
        }
    };
    let object = match value.as_object() {
        Some(value)
            if value.len() == 4
                && value.get("schema").and_then(serde_json::Value::as_str)
                    == Some("facts-protocol-fetch-v0")
                && value.contains_key("ids")
                && value.contains_key("hashes")
                && value
                    .get("include_missing")
                    .is_some_and(serde_json::Value::is_boolean) =>
        {
            value
        }
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-request",
                "batch fetch requires ids and hashes arrays",
            )
        }
    };
    let ids = match parse_sorted_text_array(object.get("ids"), true) {
        Ok(values) => values,
        Err(detail) => return problem(StatusCode::BAD_REQUEST, "invalid-request", &detail),
    };
    let hashes = match parse_sorted_text_array(object.get("hashes"), false) {
        Ok(values) => values,
        Err(detail) => return problem(StatusCode::BAD_REQUEST, "invalid-request", &detail),
    };
    let single_id = ids.first().cloned();
    let single_hash = hashes
        .first()
        .and_then(|value| value.parse::<fact_core::Hash>().ok());
    if ids.len() > 1000 || hashes.len() > 1000 {
        return problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload-too-large",
            "objects:fetch supports at most 1000 IDs and 1000 hashes",
        );
    }
    let include_missing = object["include_missing"].as_bool().unwrap();
    let guard = state.store.lock().unwrap();
    let mut found = Vec::new();
    let mut found_by_id = HashMap::<String, Vec<u8>>::new();
    let mut found_by_hash = HashMap::<fact_core::Hash, Vec<u8>>::new();
    let mut missing_ids = Vec::new();
    let mut missing_hashes = Vec::new();
    for id in ids {
        let id_bytes = match uuid_bytes(&id) {
            Ok(value) => value,
            Err(_) => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "invalid-identifier",
                    "ids must be UUIDv7",
                )
            }
        };
        let object = match guard.get_cose_by_id(&ledger, &id_bytes) {
            Ok(Some(bytes)) => Some(bytes),
            Ok(None) => match guard.get_cose_by_id_any(&id_bytes) {
                Ok(object) => object,
                Err(error) => {
                    return problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "coordinator-error",
                        &error.to_string(),
                    )
                }
            },
            Err(error) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "coordinator-error",
                    &error.to_string(),
                )
            }
        };
        match object {
            Some(bytes) => {
                found_by_id.insert(id, bytes.clone());
                if !found.iter().any(|candidate| candidate == &bytes) {
                    found.push(bytes);
                }
            }
            None if include_missing => missing_ids.push(id),
            None => {}
        }
    }
    for hash in hashes {
        let hash = match hash.parse::<fact_core::Hash>() {
            Ok(value) => value,
            Err(_) => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "invalid-identifier",
                    "hashes must be lowercase SHA-256 values",
                )
            }
        };
        let object = match guard.get_cose_by_hash(&ledger, &hash) {
            Ok(Some(bytes)) => Some(bytes),
            Ok(None) => match guard.get_cose_by_hash_any(&hash) {
                Ok(object) => object,
                Err(error) => {
                    return problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "coordinator-error",
                        &error.to_string(),
                    )
                }
            },
            Err(error) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "coordinator-error",
                    &error.to_string(),
                )
            }
        };
        match object {
            Some(bytes) => {
                found_by_hash.insert(hash, bytes.clone());
                if !found.iter().any(|candidate| candidate == &bytes) {
                    found.push(bytes);
                }
            }
            None if include_missing => missing_hashes.push(hash),
            None => {}
        }
    }
    if let (Some(single_id), Some(single_hash)) = (single_id, single_hash) {
        if let (Some(by_id), Some(by_hash)) =
            (found_by_id.get(&single_id), found_by_hash.get(&single_hash))
        {
            let id_hash = fact_crypto::decode_sign1(by_id)
                .map(|cose| fact_core::Hash::digest(&cose.payload))
                .ok();
            let hash_hash = fact_crypto::decode_sign1(by_hash)
                .map(|cose| fact_core::Hash::digest(&cose.payload))
                .ok();
            if id_hash != hash_hash {
                return problem_with_object_errors(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "hash-mismatch",
                    "the requested ID and hash identify different objects",
                    vec![serde_json::json!({
                        "code":"hash-mismatch",
                        "object_id":single_id,
                        "object_hash":single_hash.hex()
                    })],
                );
            }
        }
    }
    found.sort_by_key(|bytes| {
        fact_crypto::decode_sign1(bytes)
            .map(|cose| fact_core::Hash::digest(&cose.payload))
            .unwrap_or_else(|_| fact_core::Hash::digest(bytes))
    });
    let objects = found
        .iter()
        .filter_map(|bytes| wire_object(bytes).ok())
        .collect::<Vec<_>>();
    missing_ids.sort_by_key(|id| uuid_bytes(id).unwrap());
    missing_hashes.sort();
    json_with_headers(
        StatusCode::OK,
        serde_json::json!({
            "schema":"facts-protocol-fetch-response-v0",
            "objects":objects,
            "missing_ids": if include_missing { missing_ids } else { Vec::new() },
            "missing_hashes": if include_missing { missing_hashes } else { Vec::new() },
            "not_modified":[]
        }),
    )
}

async fn pull_objects(
    State(state): State<AppState>,
    Path(ledger): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match tokio::task::spawn_blocking(move || pull_objects_sync(state, ledger, headers, body)).await
    {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn pull_objects_sync(state: AppState, ledger: String, headers: HeaderMap, body: Bytes) -> Response {
    if let Some(response) = require_protocol_version(&headers) {
        return response;
    }
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(JSON_MEDIA)
    {
        return problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-media-type",
            "objects:pull requires application/fact+json",
        );
    }
    if headers.get("content-digest") != Some(&digest(&body)) {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid-content-digest",
            "Content-Digest does not match the request body",
        );
    }
    let ledger = match uuid_bytes(&ledger) {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "ledger_id must be UUIDv7",
            )
        }
    };
    if let Some(response) = require_matching_ledger_header(&headers, &ledger) {
        return response;
    }
    let canonical = match canonicalize(&body) {
        Ok(value) if value == body => value,
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "noncanonical-request",
                "pull body must be canonical JSON",
            )
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(&canonical) {
        Ok(value) => value,
        Err(error) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "malformed-request",
                &error.to_string(),
            )
        }
    };
    let object = match value.as_object() {
        Some(value)
            if value.len() == 7
                && value.get("schema").and_then(serde_json::Value::as_str)
                    == Some("facts-protocol-pull-v0")
                && value.contains_key("scope")
                && value.contains_key("known_commitment_hash")
                && value.contains_key("known_object_hashes")
                && value.contains_key("limit")
                && value.contains_key("cursor")
                && value
                    .get("prefer_snapshot")
                    .is_some_and(serde_json::Value::is_boolean) =>
        {
            value
        }
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-request",
                "pull requires scope, known_commitment_hash, and known_object_hashes",
            )
        }
    };
    if !object
        .get("scope")
        .is_some_and(serde_json::Value::is_object)
    {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid-request",
            "scope must be an object",
        );
    }
    let expected_scope = full_ledger_scope(&uuid::Uuid::from_bytes(ledger));
    if object.get("scope") != Some(&expected_scope) {
        return problem(
            StatusCode::BAD_REQUEST,
            "unsupported-scope",
            "reference implementation supports only the exact ledger scope",
        );
    }
    let known_commitment = match object.get("known_commitment_hash") {
        Some(value) if value.is_null() => None,
        Some(value) => match value
            .as_str()
            .and_then(|value| value.parse::<fact_core::Hash>().ok())
        {
            Some(hash) => Some(hash),
            None => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "invalid-identifier",
                    "known_commitment_hash must be a lowercase SHA-256 value or null",
                )
            }
        },
        None => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-request",
                "known_commitment_hash is required",
            )
        }
    };
    let known = match parse_sorted_text_array(object.get("known_object_hashes"), false) {
        Ok(values) => values
            .into_iter()
            .map(|value| value.parse::<fact_core::Hash>().unwrap())
            .collect::<Vec<_>>(),
        Err(detail) => return problem(StatusCode::BAD_REQUEST, "invalid-request", &detail),
    };
    let limit = match object.get("limit").and_then(serde_json::Value::as_u64) {
        Some(limit) if (1..=1_000).contains(&limit) => limit as usize,
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-request",
                "limit is out of range",
            )
        }
    };
    let prefer_snapshot = object["prefer_snapshot"].as_bool().unwrap();
    if prefer_snapshot && (known_commitment.is_some() || !known.is_empty()) {
        return problem(
            StatusCode::BAD_REQUEST,
            "snapshot-requires-full-set",
            "snapshot pull requires an empty known commitment and object set",
        );
    }
    if !object["cursor"].is_null() && object["cursor"].as_str().is_none() {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid-request",
            "cursor must be a string or null",
        );
    }
    let guard = state.store.lock().unwrap();
    let hashes = match guard.list_object_hashes(&ledger) {
        Ok(hashes) => hashes,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "coordinator-error",
                &error.to_string(),
            )
        }
    };
    let current_tree = match fact_commitment::MerkleTree::new(hashes) {
        Ok(tree) => tree,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                &error.to_string(),
            )
        }
    };
    let ledger_id: fact_core::ObjectId = uuid::Uuid::from_bytes(ledger)
        .to_string()
        .parse()
        .expect("validated ledger UUIDv7");
    let created_at = match guard.latest_object_created_at(&ledger) {
        Ok(Some(value)) => value,
        Ok(None) => timestamp_now(),
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                &error.to_string(),
            )
        }
    };
    let unsigned = normative_commitment_body_at(&state, &ledger_id, &current_tree, &created_at);
    let payload = match canonicalize(&serde_json::to_vec(&unsigned).unwrap()) {
        Ok(payload) => payload,
        Err(_) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                "could not canonicalize commitment",
            )
        }
    };
    let current_commitment_hash = fact_core::Hash::digest(&payload);
    if known_commitment.is_some_and(|known| known != current_commitment_hash) {
        return problem(
            StatusCode::CONFLICT,
            "stale-commitment",
            "known_commitment_hash does not match the current commitment",
        );
    }
    if object["prefer_snapshot"].as_bool() == Some(true) && !object["cursor"].is_null() {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid-request",
            "snapshot pull cannot be combined with a continuation cursor",
        );
    }
    let cursor_offset = if let Some(encoded) = object["cursor"].as_str() {
        let search_profile = fact_search::ProfileDescriptor {
            id: "hash-asc-v0".into(),
            version: "0".into(),
        };
        let extraction_profile = fact_search::ProfileDescriptor {
            id: "facts-pull-v0".into(),
            version: "0".into(),
        };
        let expected = fact_search::CursorExpectation {
            query_digest: pull_query_digest(object.get("scope").unwrap(), limit),
            coordinator_actor_id: state.coordinator_actor_id,
            input_commitment_hash: current_commitment_hash,
            ordering_profile: "hash-asc-v0",
            search_profile: &search_profile,
            extraction_profile: &extraction_profile,
            ledger: Some(ledger),
        };
        match fact_search::decode_cursor(
            encoded,
            state.coordinator_key.public_key(),
            &expected,
            Some(&timestamp_now()),
        ) {
            Ok(cursor) => cursor.next_offset as usize,
            Err(_) => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "invalid-cursor",
                    "cursor is not valid for this pull view",
                )
            }
        }
    } else {
        0
    };
    let mut missing = Vec::new();
    for hash in &current_tree.leaves {
        if known.binary_search(hash).is_err() {
            match guard.get_cose_by_hash(&ledger, hash) {
                Ok(Some(bytes)) => missing.push(bytes),
                Ok(None) => {}
                Err(error) => {
                    return problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "coordinator-error",
                        &error.to_string(),
                    )
                }
            }
        }
    }
    missing.sort_by_key(|bytes| {
        fact_crypto::decode_sign1(bytes)
            .map(|cose| fact_core::Hash::digest(&cose.payload))
            .unwrap_or_else(|_| fact_core::Hash::digest(bytes))
    });
    if cursor_offset > missing.len() {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid-cursor",
            "cursor offset is outside the pull view",
        );
    }
    let page_objects = missing
        .iter()
        .skip(cursor_offset)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let complete = cursor_offset + page_objects.len() >= missing.len();
    let objects = page_objects
        .iter()
        .filter_map(|bytes| wire_object(bytes).ok())
        .collect::<Vec<_>>();
    let inclusion_proofs = page_objects
        .iter()
        .filter_map(|bytes| {
            let cose = fact_crypto::decode_sign1(bytes).ok()?;
            let hash = fact_core::Hash::digest(&cose.payload);
            let index = current_tree.leaves.binary_search(&hash).ok()?;
            let steps = current_tree.proof(index).ok()?;
            Some(serde_json::json!({
                "schema":"facts-protocol-merkle-inclusion-proof-v0",
                "object_hash":hash.hex(),
                "leaf_index":index,
                "tree_size":current_tree.leaves.len(),
                "siblings":steps.iter().map(|step|step.sibling.hex()).collect::<Vec<_>>()
            }))
        })
        .collect::<Vec<_>>();
    if prefer_snapshot && complete {
        let frame_objects = missing
            .iter()
            .filter_map(|bytes| {
                let cose = fact_crypto::decode_sign1(bytes).ok()?;
                Some((fact_core::Hash::digest(&cose.payload), bytes.clone()))
            })
            .collect::<Vec<_>>();
        let snapshot_tree = match fact_commitment::MerkleTree::new(
            frame_objects.iter().map(|(hash, _)| *hash).collect(),
        ) {
            Ok(tree) => tree,
            Err(error) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "commitment-error",
                    &error.to_string(),
                )
            }
        };
        let commitment =
            normative_commitment_body_at(&state, &ledger_id, &snapshot_tree, &created_at);
        let commitment_payload = match canonicalize(&serde_json::to_vec(&commitment).unwrap()) {
            Ok(payload) => payload,
            Err(_) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "commitment-error",
                    "could not canonicalize commitment",
                )
            }
        };
        let protected = fact_crypto::coordinator_protected(
            state.coordinator_key.public_key(),
            "commitment",
            "0",
            Some(ledger),
        );
        let signed_commitment = fact_crypto::encode_sign1(&fact_crypto::sign1(
            &protected,
            &commitment_payload,
            &state.coordinator_key,
        ));
        let snapshot_manifest = match canonicalize(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-snapshot-v0",
                "protocol_version":0,
                "ledger_id":uuid::Uuid::from_bytes(ledger),
                "scope":object["scope"].clone(),
                "filters":{},
                "commitment":base64url_encode(&signed_commitment),
                "object_count":frame_objects.len(),
                "profile":"facts-protocol-snapshot-v0"
            }))
            .unwrap(),
        ) {
            Ok(manifest) => manifest,
            Err(_) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "snapshot-error",
                    "could not canonicalize snapshot manifest",
                )
            }
        };
        let snapshot = match fact_commitment::encode_snapshot(&snapshot_manifest, &frame_objects) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "snapshot-error",
                    &error.to_string(),
                )
            }
        };
        let mut headers = version_headers(HeaderMap::new(), SNAPSHOT_MEDIA, &snapshot);
        headers.insert(
            "facts-ledger",
            HeaderValue::from_str(&uuid::Uuid::from_bytes(ledger).to_string()).unwrap(),
        );
        return (StatusCode::OK, headers, snapshot).into_response();
    }
    let protected = fact_crypto::coordinator_protected(
        state.coordinator_key.public_key(),
        "commitment",
        "0",
        Some(ledger),
    );
    let signed = fact_crypto::encode_sign1(&fact_crypto::sign1(
        &protected,
        &payload,
        &state.coordinator_key,
    ));
    let commitment = serde_json::json!({
        "commitment":base64url_encode(&signed),
        "commitment_hash":fact_core::Hash::digest(&payload).hex()
    });
    let next_cursor = if complete {
        serde_json::Value::Null
    } else {
        let last_hash = page_objects
            .last()
            .and_then(|bytes| fact_crypto::decode_sign1(bytes).ok())
            .map(|cose| fact_core::Hash::digest(&cose.payload));
        let search_profile = fact_search::ProfileDescriptor {
            id: "hash-asc-v0".into(),
            version: "0".into(),
        };
        let extraction_profile = fact_search::ProfileDescriptor {
            id: "facts-pull-v0".into(),
            version: "0".into(),
        };
        let cursor = fact_search::Cursor {
            query_digest: pull_query_digest(object.get("scope").unwrap(), limit),
            coordinator_actor_id: state.coordinator_actor_id,
            input_commitment_hash: current_commitment_hash,
            ordering_profile: "hash-asc-v0".into(),
            search_profile,
            extraction_profile,
            next_offset: (cursor_offset + page_objects.len()) as u64,
            preceding_score: Some("0".into()),
            preceding_object_hash: last_hash,
            expires_at: None,
        };
        match fact_search::encode_cursor(&cursor, &state.coordinator_key, Some(ledger)) {
            Ok(cursor) => serde_json::Value::String(cursor),
            Err(_) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "cursor-error",
                    "could not sign pull cursor",
                )
            }
        }
    };
    json_with_headers(
        StatusCode::OK,
        serde_json::json!({
            "schema":"facts-protocol-pull-response-v0",
            "ledger_id":uuid::Uuid::from_bytes(ledger),
            "objects":objects,
            "object_count":objects.len(),
            "commitment":commitment,
            "inclusion_proofs":inclusion_proofs,
            "next_cursor":next_cursor,
            "complete":complete
        }),
    )
}

async fn query(
    State(state): State<AppState>,
    Path(ledger): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match tokio::task::spawn_blocking(move || query_sync(state, ledger, headers, body)).await {
        Ok(response) => response,
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "coordinator-error",
            &format!("read task failed: {error}"),
        ),
    }
}

fn query_sync(state: AppState, ledger: String, headers: HeaderMap, body: Bytes) -> Response {
    if let Some(response) = require_protocol_version(&headers) {
        return response;
    }
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(QUERY_MEDIA)
    {
        return problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-media-type",
            "query requires application/fact-query+json",
        );
    }
    if headers.get("content-digest") != Some(&digest(&body)) {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid-content-digest",
            "Content-Digest does not match the request body",
        );
    }
    let ledger = match uuid_bytes(&ledger) {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "ledger_id must be UUIDv7",
            )
        }
    };
    if let Some(response) = require_matching_ledger_header(&headers, &ledger) {
        return response;
    }
    let canonical = match fact_search::canonical_query(&body) {
        Ok(query) => query,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-query",
                "query must be an exact canonical facts-protocol-query-v0 object",
            )
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(&canonical.bytes) {
        Ok(value) => value,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-query",
                "query is not valid JSON",
            )
        }
    };
    let query_type = value
        .get("query_type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if let Some(ledger_ids) = value
        .get("ledger_ids")
        .and_then(serde_json::Value::as_array)
    {
        if !ledger_ids.is_empty()
            && !ledger_ids
                .iter()
                .any(|id| id.as_str() == Some(&uuid::Uuid::from_bytes(ledger).to_string()))
        {
            return problem(
                StatusCode::BAD_REQUEST,
                "ledger-mismatch",
                "query does not include the request ledger",
            );
        }
    }
    let requested_types = value
        .get("object_types")
        .and_then(serde_json::Value::as_array)
        .map(|types| {
            types
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let guard = state.store.lock().unwrap();
    let search_scores =
        if let Some(search_text) = value.get("search_text").and_then(serde_json::Value::as_str) {
            let results = match guard.search_markdown_index(&ledger, search_text, usize::MAX) {
                Ok(results) => results,
                Err(error) => {
                    return problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "search-error",
                        &error.to_string(),
                    )
                }
            };
            Some(
                results
                    .into_iter()
                    .map(|result| (result.content_hash, result.score))
                    .collect::<HashMap<_, _>>(),
            )
        } else {
            None
        };
    let search_profile = match profile_descriptor(&value, "search_profile") {
        Some(profile) => profile,
        None => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-query",
                "invalid search profile",
            )
        }
    };
    let extraction_profile = match profile_descriptor(&value, "extraction_profile") {
        Some(profile) => profile,
        None => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-query",
                "invalid extraction profile",
            )
        }
    };
    let page_size = value["page_size"].as_u64().unwrap() as usize;
    let all = match if query_type == "pending" {
        guard.list_pending_objects(&ledger)
    } else if let Some(scores) = search_scores.as_ref() {
        let hashes = scores.keys().copied().collect::<Vec<_>>();
        guard.list_objects_by_hashes(&ledger, &hashes)
    } else if !requested_types.is_empty() {
        let mut objects = Vec::new();
        for object_type in &requested_types {
            match guard.list_object_summaries_by_type(&ledger, object_type) {
                Ok(rows) => objects.extend(
                    rows.into_iter()
                        .map(|row| (row.object_id, row.content_hash, row.object_type)),
                ),
                Err(error) => {
                    return problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "coordinator-error",
                        &error.to_string(),
                    )
                }
            }
        }
        objects.sort_by_key(|(_, hash, _)| *hash);
        Ok(objects)
    } else {
        let mut objects = Vec::new();
        let mut after = None;
        loop {
            let page = match guard.list_object_summaries_page(&ledger, after.as_ref(), 512) {
                Ok(page) => page,
                Err(error) => {
                    return problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "coordinator-error",
                        &error.to_string(),
                    )
                }
            };
            if page.is_empty() {
                break;
            }
            after = page.last().map(|row| row.content_hash);
            objects.extend(
                page.into_iter()
                    .map(|row| (row.object_id, row.content_hash, row.object_type)),
            );
        }
        Ok(objects)
    } {
        Ok(objects) => objects,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "coordinator-error",
                &error.to_string(),
            )
        }
    };
    let query_scope_filter = value["scope"].clone();
    let query_status_filter = value["status"].clone();
    let query_relationship_filter = value["relationships"].clone();
    let mut candidate_proposition_ids = HashSet::new();
    let mut candidates = Vec::new();
    for (id, hash, object_type) in all {
        if !requested_types.is_empty() && !requested_types.contains(&object_type.as_str()) {
            continue;
        }
        if query_type == "relationship"
            && !matches!(
                object_type.as_str(),
                "protocol_relationship" | "application_relationship"
            )
        {
            continue;
        }
        if !search_scores
            .as_ref()
            .is_none_or(|scores| scores.contains_key(&hash))
        {
            continue;
        }
        let payload = match guard.get_payload(id.as_bytes()) {
            Ok(Some(payload)) => payload,
            Ok(None) => continue,
            Err(error) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "coordinator-error",
                    &error.to_string(),
                )
            }
        };
        let payload_value = match serde_json::from_slice::<serde_json::Value>(&payload) {
            Ok(value) => value,
            Err(_) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "coordinator-error",
                    "stored canonical payload is not valid JSON",
                )
            }
        };
        if let Some(proposition_id) = payload_value
            .get("body")
            .and_then(|body| body.get("proposition_id"))
            .and_then(serde_json::Value::as_str)
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
        {
            candidate_proposition_ids.insert(proposition_id);
        }
        candidates.push((id, hash, object_type, payload_value));
    }
    let candidate_proposition_ids = candidate_proposition_ids.into_iter().collect::<Vec<_>>();
    let knowledge_propositions = if query_type == "fact" {
        let proposition_ids = match if search_scores.is_some() {
            guard.knowledge_proposition_ids_for_propositions(&ledger, &candidate_proposition_ids)
        } else {
            guard.knowledge_proposition_ids(&ledger)
        } {
            Ok(ids) => ids,
            Err(error) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "coordinator-error",
                    &error.to_string(),
                )
            }
        };
        let mut ids = HashSet::with_capacity(proposition_ids.len());
        for id in proposition_ids {
            ids.insert(id.to_string());
        }
        ids
    } else {
        HashSet::new()
    };
    let effective_projecteds = if search_scores.is_some() {
        guard.effective_state_for_propositions(&ledger, &candidate_proposition_ids)
    } else {
        guard.list_effective_state(&ledger)
    };
    let effective = match effective_projecteds {
        Ok(projecteds) => projecteds
            .into_iter()
            .map(|projected| (projected.proposition_id.to_string(), projected))
            .collect::<HashMap<_, _>>(),
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "coordinator-error",
                &error.to_string(),
            )
        }
    };
    let mut fact_details = HashMap::new();
    let mut filtered = Vec::new();
    for (id, hash, object_type, payload_value) in candidates {
        if query_type == "fact"
            && !fact_object_is_effective(
                &payload_value,
                &query_status_filter,
                &knowledge_propositions,
                &effective,
            )
        {
            continue;
        }
        if query_type == "fact" {
            if let Some(proposition_id) = payload_value
                .get("body")
                .and_then(|body| body.get("proposition_id"))
                .and_then(serde_json::Value::as_str)
            {
                if let Some(projected) = effective.get(proposition_id) {
                    fact_details.insert(
                        hash,
                        serde_json::json!({
                            "proposition_id":proposition_id,
                            "revision_id":projected.revision_id,
                            "deliberation_id":projected.deliberation_id,
                            "settlement_id":projected.settlement_id,
                            "status":projected.status,
                            "withdrawal_status":projected.withdrawal_status,
                            "archival_status":projected.archival_status
                        }),
                    );
                }
            }
        }
        if query_object_matches(
            &payload_value,
            &id.to_string(),
            &query_scope_filter,
            &query_status_filter,
            &query_relationship_filter,
            &effective,
        ) {
            filtered.push((id, hash, object_type));
        }
    }
    if query_type == "fact" {
        filtered.sort_by(|(_, left_hash, _), (_, right_hash, _)| {
            let left_score = search_scores
                .as_ref()
                .and_then(|scores| scores.get(left_hash))
                .and_then(|score| fact_search::parse_score(score).ok());
            let right_score = search_scores
                .as_ref()
                .and_then(|scores| scores.get(right_hash))
                .and_then(|score| fact_search::parse_score(score).ok());
            right_score
                .zip(left_score)
                .map_or(std::cmp::Ordering::Equal, |(right, left)| {
                    right.cmp_numeric(&left)
                })
                .then_with(|| left_hash.cmp(right_hash))
        });
    }
    let tree =
        match fact_commitment::MerkleTree::new(filtered.iter().map(|(_, hash, _)| *hash).collect())
        {
            Ok(tree) => tree,
            Err(error) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "commitment-error",
                    &error.to_string(),
                )
            }
        };
    let ledger_id = fact_core::ObjectId::from_str(&uuid::Uuid::from_bytes(ledger).to_string())
        .expect("validated ledger UUIDv7");
    let query_scope = serde_json::json!({
        "ledger_id":ledger_id.to_string(),
        "snapshot_boundary":null,
        "query_digest":canonical.digest.hex(),
        "object_types":requested_types,
        "actor_ids":value["scope"]["actor_ids"].clone(),
        "proposition_ids":value["scope"]["proposition_ids"].clone(),
        "revision_ids":value["scope"]["revision_ids"].clone(),
        "deliberation_ids":value["scope"]["deliberation_ids"].clone(),
        "filters":{"status":value["status"].clone(),"relationships":value["relationships"].clone()}
    });
    let created_at = match guard.latest_object_created_at(&ledger) {
        Ok(Some(value)) => value,
        Ok(None) => timestamp_now(),
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                &error.to_string(),
            )
        }
    };
    let commitment_body =
        normative_commitment_body_for_scope(&state, &ledger_id, &query_scope, &tree, &created_at);
    let commitment_payload = match canonicalize(&serde_json::to_vec(&commitment_body).unwrap()) {
        Ok(payload) => payload,
        Err(_) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "commitment-error",
                "could not canonicalize query commitment",
            )
        }
    };
    let commitment_hash = fact_core::Hash::digest(&commitment_payload);
    let commitment_protected = fact_crypto::coordinator_protected(
        state.coordinator_key.public_key(),
        "commitment",
        "0",
        Some(ledger),
    );
    let signed_commitment = fact_crypto::encode_sign1(&fact_crypto::sign1(
        &commitment_protected,
        &commitment_payload,
        &state.coordinator_key,
    ));
    let prior_cursor = value
        .get("prior_cursor")
        .and_then(serde_json::Value::as_str);
    let ordering_profile = value["ordering_profile"].as_str().unwrap();
    let offset = if let Some(encoded) = prior_cursor {
        let expected = fact_search::CursorExpectation {
            query_digest: canonical.digest,
            coordinator_actor_id: state.coordinator_actor_id,
            input_commitment_hash: commitment_hash,
            ordering_profile,
            search_profile: &search_profile,
            extraction_profile: &extraction_profile,
            ledger: Some(ledger),
        };
        match fact_search::decode_cursor(
            encoded,
            state.coordinator_key.public_key(),
            &expected,
            None,
        ) {
            Ok(cursor) => cursor.next_offset as usize,
            Err(_) => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "invalid-cursor",
                    "cursor is not valid for this query view",
                )
            }
        }
    } else {
        0
    };
    if offset > filtered.len() {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid-cursor",
            "cursor offset is outside the query view",
        );
    }
    let end = offset.saturating_add(page_size).min(filtered.len());
    let page = &filtered[offset..end];
    let next_cursor = if end < filtered.len() {
        let last_hash = page.last().map(|(_, hash, _)| *hash);
        let cursor = fact_search::Cursor {
            query_digest: canonical.digest,
            coordinator_actor_id: state.coordinator_actor_id,
            input_commitment_hash: commitment_hash,
            ordering_profile: ordering_profile.into(),
            search_profile: search_profile.clone(),
            extraction_profile: extraction_profile.clone(),
            next_offset: end as u64,
            preceding_score: Some(
                page.last()
                    .and_then(|(_, hash, _)| search_scores.as_ref()?.get(hash))
                    .cloned()
                    .unwrap_or_else(|| "0".into()),
            ),
            preceding_object_hash: last_hash,
            expires_at: None,
        };
        match fact_search::encode_cursor(&cursor, &state.coordinator_key, Some(ledger)) {
            Ok(cursor) => Some(cursor),
            Err(_) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "cursor-error",
                    "could not sign result cursor",
                )
            }
        }
    } else {
        None
    };
    let results = page
        .iter()
        .filter_map(|(id, hash, object_type)| {
            let index = tree.leaves.binary_search(hash).ok()?;
            let steps = tree.proof(index).ok()?;
            Some(serde_json::json!({
                "object":{"object_id":id,"content_hash":hash.hex()},
                "score":search_scores.as_ref().and_then(|scores| scores.get(hash)).cloned().unwrap_or_else(|| "0".into()),
                "score_context":null,
                "fact":fact_details.get(hash).cloned().unwrap_or(serde_json::Value::Null),
                "inclusion_proof":{
                    "schema":"facts-protocol-merkle-inclusion-proof-v0",
                    "object_hash":hash.hex(),
                    "leaf_index":index,
                    "tree_size":tree.leaves.len(),
                    "siblings":steps.iter().map(|step|step.sibling.hex()).collect::<Vec<_>>()
                },
                "match":{"excerpt":null,"fields":[object_type],"extraction_profile":{"id":extraction_profile.id,"version":extraction_profile.version}}
            }))
        })
        .collect::<Vec<_>>();
    let statement = serde_json::json!({
        "schema":"facts-protocol-result-set-v0",
        "coordinator_actor_id":state.coordinator_actor_id.to_string(),
        "scope":query_scope,
        "query_digest":canonical.digest.hex(),
        "ledger_id":uuid::Uuid::from_bytes(ledger).to_string(),
        "input_commitment_hash":commitment_hash.hex(),
        "search_profile":{"id":search_profile.id,"version":search_profile.version},
        "extraction_profile":{"id":extraction_profile.id,"version":extraction_profile.version},
        "provider":null,
        "ordered_results":results.iter().map(|result|serde_json::json!({"object_hash":result["object"]["content_hash"],"score":result["score"]})).collect::<Vec<_>>(),
        "page":{"offset":offset,"limit":page_size,"next_cursor":next_cursor},
        "completeness":{"class":"complete-deterministic-profile","reason":null},
        "signing_key_fingerprint":state.coordinator_key.fingerprint().hex()
    });
    let statement_payload = match canonicalize(&serde_json::to_vec(&statement).unwrap()) {
        Ok(payload) => payload,
        Err(_) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "result-set-error",
                "could not canonicalize result set",
            )
        }
    };
    let protected = fact_crypto::coordinator_protected(
        state.coordinator_key.public_key(),
        "result-set",
        "0",
        Some(ledger),
    );
    let signed = fact_crypto::encode_sign1(&fact_crypto::sign1(
        &protected,
        &statement_payload,
        &state.coordinator_key,
    ));
    let response = serde_json::json!({
        "schema":"facts-protocol-query-response-v0",
        "query_digest":canonical.digest.hex(),
        "ledger_id":uuid::Uuid::from_bytes(ledger).to_string(),
        "input_commitment":{"commitment":base64url_encode(&signed_commitment),"commitment_hash":commitment_hash.hex()},
        "results":results,
        "next_cursor":next_cursor,
        "completeness":{"class":"complete-deterministic-profile","reason":null},
        "result_set_statement":base64url_encode(&signed)
    });
    let response_body = json_body(response);
    let mut response_headers = version_headers(HeaderMap::new(), JSON_MEDIA, &response_body);
    response_headers.insert(
        "facts-ledger",
        HeaderValue::from_str(&uuid::Uuid::from_bytes(ledger).to_string()).unwrap(),
    );
    (StatusCode::OK, response_headers, response_body).into_response()
}

fn profile_descriptor(
    value: &serde_json::Value,
    field: &str,
) -> Option<fact_search::ProfileDescriptor> {
    let object = value.get(field)?.as_object()?;
    Some(fact_search::ProfileDescriptor {
        id: object.get("id")?.as_str()?.to_owned(),
        version: object.get("version")?.as_str()?.to_owned(),
    })
}

fn fact_object_is_effective(
    object: &serde_json::Value,
    status: &serde_json::Value,
    knowledge_propositions: &HashSet<String>,
    effective: &HashMap<String, fact_store::EffectiveProjected>,
) -> bool {
    let Some(proposition_id) = object
        .get("body")
        .and_then(|body| body.get("proposition_id"))
        .and_then(serde_json::Value::as_str)
    else {
        return false;
    };
    let Some(projected) = effective.get(proposition_id) else {
        return false;
    };
    if !knowledge_propositions.contains(proposition_id) {
        return false;
    }
    let actual = |name: &str| match name {
        "accepted" => projected.status == "accepted",
        "rejected" => projected.status == "rejected",
        "settled" => projected.status == "settled" || projected.settlement_id.is_some(),
        "archived" => projected.archival_status == "archived",
        "withdrawn" => projected.withdrawal_status == "withdrawn",
        "divergent" => projected.status == "divergent",
        _ => false,
    };
    let names = [
        "accepted",
        "rejected",
        "settled",
        "archived",
        "withdrawn",
        "divergent",
    ];
    if names.iter().any(|name| {
        status
            .get(*name)
            .and_then(serde_json::Value::as_bool)
            .is_some_and(|value| value)
    }) {
        names.iter().any(|name| {
            status
                .get(*name)
                .and_then(serde_json::Value::as_bool)
                .is_some_and(|value| value && actual(name))
        })
    } else {
        projected.status == "accepted"
            && projected.withdrawal_status == "active"
            && projected.archival_status == "visible"
    }
}

fn query_object_matches(
    object: &serde_json::Value,
    object_id: &str,
    scope: &serde_json::Value,
    status: &serde_json::Value,
    relationships: &serde_json::Value,
    effective: &HashMap<String, fact_store::EffectiveProjected>,
) -> bool {
    let body = object.get("body").and_then(serde_json::Value::as_object);
    let id_candidates = |field: &str| -> Vec<String> {
        let mut candidates = Vec::new();
        if field == "actor_ids" {
            if let Some(actor) = object.get("actor_id").and_then(serde_json::Value::as_str) {
                candidates.push(actor.to_owned());
            }
        }
        let body_fields = match field {
            "actor_ids" => [
                "actor_id",
                "participant_actor_id",
                "changed_by_actor_id",
                "inviter_actor_id",
                "invited_actor_id",
            ]
            .as_slice(),
            "proposition_ids" => ["proposition_id", "affected_proposition_id"].as_slice(),
            "revision_ids" => [
                "revision_id",
                "parent_revision_id",
                "source_revision_id",
                "common_ancestor_revision_id",
            ]
            .as_slice(),
            "deliberation_ids" => ["deliberation_id"].as_slice(),
            _ => [].as_slice(),
        };
        if let Some(body) = body {
            for field in body_fields {
                if let Some(id) = body.get(*field).and_then(serde_json::Value::as_str) {
                    candidates.push(id.to_owned());
                }
            }
        }
        candidates
    };
    for field in [
        "actor_ids",
        "proposition_ids",
        "revision_ids",
        "deliberation_ids",
    ] {
        let Some(requested) = scope.get(field).and_then(serde_json::Value::as_array) else {
            return false;
        };
        if requested.is_empty() {
            continue;
        }
        let requested = requested
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<HashSet<_>>();
        if !id_candidates(field)
            .iter()
            .any(|candidate| requested.contains(candidate.as_str()))
        {
            return false;
        }
    }

    if let Some(status) = status.as_object() {
        let proposition_id = body
            .and_then(|body| body.get("proposition_id"))
            .and_then(serde_json::Value::as_str);
        let projected = proposition_id.and_then(|id| effective.get(id));
        let actual = |name: &str| -> bool {
            match (name, projected) {
                ("accepted", Some(projected)) => projected.status == "accepted",
                ("rejected", Some(projected)) => projected.status == "rejected",
                ("settled", Some(projected)) => {
                    projected.status == "settled" || projected.settlement_id.is_some()
                }
                ("archived", Some(projected)) => projected.archival_status == "archived",
                ("withdrawn", Some(projected)) => projected.withdrawal_status == "withdrawn",
                ("divergent", Some(projected)) => projected.status == "divergent",
                _ => false,
            }
        };
        for name in [
            "accepted",
            "rejected",
            "settled",
            "archived",
            "withdrawn",
            "divergent",
        ] {
            if let Some(wanted) = status.get(name).and_then(serde_json::Value::as_bool) {
                if actual(name) != wanted {
                    return false;
                }
            }
        }
    }

    let Some(requested_relationships) = relationships.as_array() else {
        return false;
    };
    requested_relationships.iter().all(|requested| {
        let Some(requested) = requested.as_object() else {
            return false;
        };
        let relationship_type = requested
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let direction = requested
            .get("direction")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let other = requested
            .get("other_object_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        object_relationships(object, body, object_id)
            .into_iter()
            .any(|(kind, source, targets)| {
                if kind != relationship_type {
                    return false;
                }
                match direction {
                    "out" => source == object_id && targets.iter().any(|target| target == other),
                    "in" => source == other && targets.iter().any(|target| target == object_id),
                    "either" => {
                        (source == object_id && targets.iter().any(|target| target == other))
                            || (source == other && targets.iter().any(|target| target == object_id))
                    }
                    _ => false,
                }
            })
    })
}

fn object_relationships(
    object: &serde_json::Value,
    body: Option<&serde_json::Map<String, serde_json::Value>>,
    object_id: &str,
) -> Vec<(String, String, Vec<String>)> {
    let mut output = Vec::new();
    if let Some(relationships) = body
        .and_then(|body| body.get("relationships"))
        .and_then(serde_json::Value::as_array)
    {
        for relationship in relationships {
            let Some(relationship) = relationship.as_object() else {
                continue;
            };
            let Some(kind) = relationship
                .get("relationship")
                .or_else(|| relationship.get("type"))
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            let targets = relationship
                .get("target_object_ids")
                .and_then(serde_json::Value::as_array)
                .map(|targets| {
                    targets
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            output.push((kind.to_owned(), object_id.to_owned(), targets));
        }
    }
    if object_type_is_relationship(object) {
        if let Some(body) = body {
            let source = body
                .get("source_object_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(object_id);
            let targets = body
                .get("target_object_ids")
                .and_then(serde_json::Value::as_array)
                .map(|targets| {
                    targets
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if let Some(kind) = body.get("relationship").and_then(serde_json::Value::as_str) {
                output.push((kind.to_owned(), source.to_owned(), targets));
            }
        }
    }
    output
}

fn object_type_is_relationship(object: &serde_json::Value) -> bool {
    matches!(
        object
            .get("object_type")
            .and_then(serde_json::Value::as_str),
        Some("protocol_relationship") | Some("application_relationship")
    )
}

fn base64url_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((value >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(TABLE[(value & 63) as usize] as char);
        }
    }
    output
}

fn wire_object(bytes: &[u8]) -> Result<serde_json::Value, &'static str> {
    let cose = fact_crypto::decode_sign1(bytes).map_err(|_| "invalid COSE object")?;
    let value: serde_json::Value =
        serde_json::from_slice(&cose.payload).map_err(|_| "invalid object payload")?;
    let object_id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or("object has no ID")?;
    Ok(serde_json::json!({
        "object_id":object_id,
        "content_hash":fact_core::Hash::digest(&cose.payload).hex(),
        "cose_sign1":base64url_encode(bytes)
    }))
}

#[allow(dead_code)]
fn bundle_response(ledger: [u8; 16], bytes: Vec<Vec<u8>>) -> Response {
    let mut objects = match bytes
        .into_iter()
        .map(|bytes| {
            let cose = fact_crypto::decode_sign1(&bytes).map_err(|_| ());
            cose.map(|cose| (fact_core::Hash::digest(&cose.payload), bytes))
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(objects) => objects,
        Err(_) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "bundle-error",
                "stored object is not valid COSE",
            )
        }
    };
    objects.sort_by_key(|(hash, _)| *hash);
    let manifest = match canonicalize(
        &serde_json::to_vec(&serde_json::json!({
            "schema":"facts-protocol-bundle-v0",
            "protocol_version":0,
            "bundle_id":fact_commitment::deterministic_bundle_id(&objects),
            "object_count":objects.len(),
            "ledger_id":uuid::Uuid::from_bytes(ledger).to_string(),
            "objects":objects.iter().map(|(hash, bytes)| {
                let id = fact_crypto::decode_sign1(bytes).ok()
                    .and_then(|cose| serde_json::from_slice::<serde_json::Value>(&cose.payload).ok())
                    .and_then(|value| value.get("id").and_then(serde_json::Value::as_str).map(str::to_owned));
                serde_json::json!({"object_id":id,"content_hash":hash.hex()})
            }).collect::<Vec<_>>(),
            "dependency_refs":[],
            "sender_signature":null,
            "expected_commitment_hash":null,
            "base_commitment_hash":null
        }))
        .unwrap(),
    ) {
        Ok(manifest) => manifest,
        Err(_) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "bundle-error",
                "could not canonicalize bundle manifest",
            )
        }
    };
    let bundle = match fact_commitment::encode_bundle(&manifest, &objects) {
        Ok(bundle) => bundle,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "bundle-error",
                &error.to_string(),
            )
        }
    };
    let mut response_headers = version_headers(HeaderMap::new(), BUNDLE_MEDIA, &bundle);
    response_headers.insert(
        "facts-ledger",
        HeaderValue::from_str(&uuid::Uuid::from_bytes(ledger).to_string()).unwrap(),
    );
    (StatusCode::OK, response_headers, bundle).into_response()
}

fn parse_sorted_text_array(
    value: Option<&serde_json::Value>,
    uuid_values: bool,
) -> Result<Vec<String>, String> {
    let values = value
        .and_then(serde_json::Value::as_array)
        .ok_or("field must be an array")?;
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let value = value.as_str().ok_or("array values must be strings")?;
        if uuid_values {
            uuid_bytes(value).map_err(|_| "array contains an invalid UUIDv7".to_owned())?;
        } else {
            value
                .parse::<fact_core::Hash>()
                .map_err(|_| "array contains an invalid hash".to_owned())?;
        }
        result.push(value.to_owned());
    }
    if result.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("array values must be sorted and deduplicated".into());
    }
    Ok(result)
}
async fn push(
    State(state): State<AppState>,
    Path(ledger): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let queue_permit = match state.write_queue.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily-unavailable",
                "the coordinator write queue is full",
            )
        }
    };
    let gate_permit = match state.write_gate.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            drop(queue_permit);
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily-unavailable",
                "the coordinator write queue is unavailable",
            );
        }
    };
    match tokio::task::spawn_blocking(move || push_sync(state, ledger, headers, body)).await {
        Ok(response) => {
            drop(gate_permit);
            drop(queue_permit);
            response
        }
        Err(error) => {
            drop(gate_permit);
            drop(queue_permit);
            problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "coordinator-error",
                &format!("write task failed: {error}"),
            )
        }
    }
}

fn push_sync(state: AppState, ledger: String, headers: HeaderMap, body: Bytes) -> Response {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some(BUNDLE_MEDIA)
    {
        return problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-media-type",
            "objects:push requires application/fact-bundle",
        );
    }
    if let Some(response) = require_protocol_version(&headers) {
        return response;
    }
    if headers.get("content-digest") != Some(&digest(&body)) {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid-content-digest",
            "Content-Digest does not match the request body",
        );
    }
    let ledger = match uuid_bytes(&ledger) {
        Ok(x) => x,
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid-identifier",
                "ledger_id must be UUIDv7",
            )
        }
    };
    if let Some(response) = require_matching_ledger_header(&headers, &ledger) {
        return response;
    }
    let framed = match decode_bundle(&body) {
        Ok(x) => x,
        Err(e) => return problem(StatusCode::BAD_REQUEST, "malformed-request", &e.to_string()),
    };
    let bundle_id = serde_json::from_slice::<serde_json::Value>(&framed.manifest)
        .ok()
        .and_then(|manifest| manifest.get("bundle_id").cloned())
        .unwrap_or(serde_json::Value::Null);
    let guard = state.store.lock().unwrap();
    for object in &framed.objects {
        if let Err(error) = verify_ledger(&ledger, object) {
            return problem(StatusCode::UNPROCESSABLE_ENTITY, "ledger-mismatch", &error);
        }
    }
    let mut hashes = vec![None; framed.objects.len()];
    let mut new_objects: Vec<(usize, Vec<u8>)> = Vec::new();
    for (index, object) in framed.objects.iter().enumerate() {
        let cose = match fact_crypto::decode_sign1(object) {
            Ok(cose) => cose,
            Err(error) => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "malformed-request",
                    &error.to_string(),
                )
            }
        };
        let hash = fact_core::Hash::digest(&cose.payload);
        match guard.get_cose_by_hash(&ledger, &hash) {
            Ok(Some(existing)) if existing == *object => hashes[index] = Some(hash),
            Ok(Some(_)) => {
                return problem(
                    StatusCode::CONFLICT,
                    "object-equivocation",
                    "content hash is already bound to different signed bytes",
                )
            }
            Ok(None) => {
                new_objects.push((index, object.clone()));
            }
            Err(error) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "coordinator-error",
                    &error.to_string(),
                )
            }
        }
    }
    let mut item_errors: Vec<Option<(String, String)>> = vec![None; framed.objects.len()];
    let has_new_objects = !new_objects.is_empty();
    if !new_objects.is_empty() {
        let bundle_objects = new_objects
            .iter()
            .map(|(_, object)| object.clone())
            .collect::<Vec<_>>();
        let inserted = match guard.insert_authorized_bundle(&bundle_objects) {
            Ok(hashes) => hashes,
            Err(error) => {
                let (code, disposition) = push_error_codes(&error);
                for (index, _) in &new_objects {
                    item_errors[*index] = Some((code.to_owned(), disposition.to_owned()));
                }
                Vec::new()
            }
        };
        if !inserted.is_empty() {
            for ((index, _), hash) in new_objects.iter().zip(inserted) {
                hashes[*index] = Some(hash);
            }
        } else {
            // A complete bundle is the normal path. If it cannot be committed,
            // retry frames individually in causal passes so a valid frame is
            // not hidden by an unrelated invalid or blocked frame.
            let mut pending = new_objects
                .iter()
                .map(|(index, object)| (*index, object.clone()))
                .collect::<Vec<_>>();
            loop {
                let mut progress = false;
                let mut next = Vec::new();
                for (index, object) in pending {
                    match guard.insert_authorized_object(&object) {
                        Ok(hash) => {
                            hashes[index] = Some(hash);
                            item_errors[index] = None;
                            progress = true;
                        }
                        Err(error) => {
                            let (code, disposition) = push_error_codes(&error);
                            item_errors[index] = Some((code.to_owned(), disposition.to_owned()));
                            next.push((index, object));
                        }
                    }
                }
                if next.is_empty() || !progress {
                    break;
                }
                pending = next;
            }
        }
    }
    let evaluated_at = timestamp_now();
    let missing_by_index = framed
        .objects
        .iter()
        .map(|object| missing_dependency_refs(&guard, object))
        .collect::<Vec<_>>();
    let results = hashes
        .into_iter()
        .enumerate()
        .map(|(index, hash)| {
            let object_id = fact_crypto::decode_sign1(&framed.objects[index])
                .ok()
                .and_then(|cose| serde_json::from_slice::<serde_json::Value>(&cose.payload).ok())
                .and_then(|value| {
                    value
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                });
            let (disposition_code, error_code) = match (&hash, &item_errors[index]) {
                (Some(_), _) => ("accepted".to_owned(), None),
                (None, Some((code, disposition))) => (disposition.clone(), Some(code.clone())),
                (None, None) => (
                    "rejected-protocol-invalid".to_owned(),
                    Some("malformed-object".to_owned()),
                ),
            };
            let content_hash = hash.map(|hash| hash.hex()).or_else(|| {
                fact_crypto::decode_sign1(&framed.objects[index])
                    .ok()
                    .map(|cose| fact_core::Hash::digest(&cose.payload).hex())
            });
            let missing_dependencies = if hash.is_none() {
                missing_by_index[index].clone()
            } else {
                Vec::new()
            };
            let disposition = serde_json::json!({
                "schema":"facts-protocol-disposition-v0",
                "coordinator_actor_id":state.coordinator_actor_id.to_string(),
                "object_id":object_id,
                "object_hash":content_hash,
                "disposition_code":disposition_code,
                "disposition_at":evaluated_at,
                "trusted_validation_time":evaluated_at,
                "clock_status":"trusted",
                "evaluated_bounds":null,
                "policy_id":null,
                "explanation":null,
                "missing_dependencies":missing_dependencies,
                "signing_key_fingerprint":state.coordinator_key.fingerprint().hex()
            });
            let payload = canonicalize(&serde_json::to_vec(&disposition).unwrap()).unwrap();
            let protected = fact_crypto::coordinator_protected(
                state.coordinator_key.public_key(),
                "disposition",
                "0",
                Some(ledger),
            );
            let signed = fact_crypto::encode_sign1(&fact_crypto::sign1(
                &protected,
                &payload,
                &state.coordinator_key,
            ));
            serde_json::json!({
                "index":index,
                "object_id":object_id,
                "content_hash":content_hash,
                "disposition":disposition_code,
                "error_code":error_code,
                "missing_dependencies":missing_dependencies,
                "coordinator_disposition":base64url_encode(&signed)
            })
        })
        .collect::<Vec<_>>();
    let accepted_count = results
        .iter()
        .filter(|result| result["disposition"] == "accepted")
        .count();
    let rejected_count = results.len() - accepted_count;
    json_with_headers(
        if rejected_count > 0 {
            StatusCode::MULTI_STATUS
        } else if accepted_count > 0 && has_new_objects {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        serde_json::json!({
            "schema":"facts-protocol-push-response-v0",
            "ledger_id":uuid::Uuid::from_bytes(ledger),
            "bundle_id":bundle_id,
            "results":results,
            "accepted_count":accepted_count,
            "rejected_count":rejected_count,
            "deferred_count":0,
            "commitment":null
        }),
    )
}

fn push_error_codes(error: &fact_store::Error) -> (&'static str, &'static str) {
    match error {
        fact_store::Error::Canonical(_) => ("noncanonical-object", "rejected-protocol-invalid"),
        fact_store::Error::Cose(_) | fact_store::Error::Schema(_) => {
            ("malformed-object", "rejected-protocol-invalid")
        }
        fact_store::Error::PayloadMismatch => ("noncanonical-object", "rejected-protocol-invalid"),
        fact_store::Error::HashMismatch | fact_store::Error::DependencyHashMismatch => {
            ("hash-mismatch", "rejected-protocol-invalid")
        }
        fact_store::Error::InvalidSignature => ("invalid-signature", "rejected-protocol-invalid"),
        fact_store::Error::MissingKey | fact_store::Error::MissingDependency => {
            ("missing-dependency", "rejected-missing-dependency")
        }
        fact_store::Error::InvalidLineage => ("invalid-lineage", "rejected-protocol-invalid"),
        fact_store::Error::Unauthorized => ("unauthorized-object", "rejected-unauthorized"),
        fact_store::Error::TimeUncertain => ("time-uncertain", "rejected-protocol-invalid"),
        fact_store::Error::PolicyRejected => ("policy-rejected", "rejected-policy"),
        _ => ("malformed-object", "rejected-protocol-invalid"),
    }
}

fn missing_dependency_refs(store: &Store, bytes: &[u8]) -> Vec<serde_json::Value> {
    let Ok(cose) = fact_crypto::decode_sign1(bytes) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&cose.payload) else {
        return Vec::new();
    };
    let Some(dependencies) = value
        .get("dependencies")
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    let mut missing = dependencies
        .iter()
        .filter_map(|dependency| {
            let dependency = dependency.as_object()?;
            let object_id = dependency.get("object_id")?.as_str()?;
            let content_hash = dependency.get("content_hash")?.as_str()?;
            let id_bytes = uuid_bytes(object_id).ok()?;
            let hash = content_hash.parse::<fact_core::Hash>().ok()?;
            let payload = store.get_payload(&id_bytes).ok().flatten();
            if payload
                .as_deref()
                .is_some_and(|payload| fact_core::Hash::digest(payload) == hash)
            {
                None
            } else {
                Some(serde_json::json!({
                    "object_id":object_id,
                    "content_hash":content_hash
                }))
            }
        })
        .collect::<Vec<_>>();
    missing.sort_by(|a, b| {
        a.get("object_id")
            .and_then(serde_json::Value::as_str)
            .cmp(&b.get("object_id").and_then(serde_json::Value::as_str))
    });
    missing.dedup();
    missing
}

fn timestamp_now() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond()
    )
}
fn verify_ledger(ledger: &[u8; 16], object: &[u8]) -> Result<(), String> {
    let cose = fact_crypto::decode_sign1(object).map_err(|error| error.to_string())?;
    let value: serde_json::Value =
        serde_json::from_slice(&cose.payload).map_err(|error| error.to_string())?;
    if value
        .get("ledger_id")
        .and_then(|v| v.as_str())
        .map(|s| uuid_bytes(s))
        .transpose()
        .map_err(|error| error.to_string())?
        .as_ref()
        != Some(ledger)
    {
        return Err("ledger mismatch".into());
    }
    Ok(())
}
fn json_with_headers(status: StatusCode, value: serde_json::Value) -> Response {
    let body = json_body(value);
    (
        status,
        version_headers(HeaderMap::new(), JSON_MEDIA, &body),
        body,
    )
        .into_response()
}
fn json_with_ledger_headers(
    status: StatusCode,
    ledger: &str,
    value: serde_json::Value,
) -> Response {
    let body = json_body(value);
    let mut headers = version_headers(HeaderMap::new(), JSON_MEDIA, &body);
    headers.insert("facts-ledger", HeaderValue::from_str(ledger).unwrap());
    (status, headers, body).into_response()
}
fn uuid_bytes(s: &str) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    let u = uuid::Uuid::parse_str(s)?;
    if u.get_version_num() != 7 || u.get_variant() != uuid::Variant::RFC4122 {
        return Err("UUID is not v7".into());
    }
    if u.to_string() != s {
        return Err("UUID must use lowercase hyphenated form".into());
    }
    Ok(*u.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use fact_crypto::{encode_sign1, sign1, SigningKey};
    use http::Request;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    #[tokio::test]
    async fn reference_policy_challenges_unauthenticated_push_before_body_evaluation() {
        let store = Store::open_memory().unwrap();
        let bootstrap = store
            .bootstrap_ledger(
                "auth.example",
                "2026-07-27T12:00:00.000Z",
                [6u8; 32],
                [7u8; 16],
            )
            .unwrap();
        let state = AppState::new_with_reference_policy(
            store,
            "https://example.test/facts",
            SigningKey::from_seed(&[8u8; 32]).unwrap(),
            fact_core::ObjectId::new_v7(),
        );
        let app = router(state.clone());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/facts/ledgers/{}/objects:push",
                        bootstrap.ledger_id
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("nonce=\"")));
        let challenge_nonce = response
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split("nonce=\"").nth(1))
            .and_then(|value| value.split('"').next())
            .unwrap()
            .to_owned();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["code"], "authentication-required");

        let restricted = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/facts/ledgers/{}/dispositions/{}",
                        bootstrap.ledger_id, bootstrap.genesis_id
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(restricted.status(), StatusCode::UNAUTHORIZED);

        let nonce = challenge_nonce;
        let key = SigningKey::from_seed(&[6u8; 32]).unwrap();
        let components = vec![
            "@method".to_owned(),
            "@target-uri".to_owned(),
            "content-digest".to_owned(),
            "facts-ledger".to_owned(),
            "facts-protocol-version".to_owned(),
        ];
        let created = OffsetDateTime::now_utc().unix_timestamp();
        let params = format!(
            "created={created};keyid=\"{}\";nonce=\"{nonce}\"",
            key.fingerprint().hex()
        );
        let input = format!(
            "sig1=({});{}",
            components
                .iter()
                .map(|component| format!("\"{component}\""))
                .collect::<Vec<_>>()
                .join(" "),
            params
        );
        let mut signed_request = Request::builder()
            .method("POST")
            .uri(format!(
                "/facts/ledgers/{}/objects:push",
                bootstrap.ledger_id
            ))
            .header("content-type", JSON_MEDIA)
            .header("content-digest", digest(&[]))
            .header("facts-ledger", bootstrap.ledger_id.to_string())
            .header("facts-protocol-version", "0")
            .header("signature-input", input)
            .body(Body::empty())
            .unwrap();
        let base = signature_base(&state, &signed_request, &components, &params);
        let encoded = base64_encode(&key.sign(base.as_bytes()));
        signed_request.headers_mut().insert(
            "signature",
            HeaderValue::from_str(&format!("sig1=:{encoded}:")).unwrap(),
        );
        let response = app.oneshot(signed_request).await.unwrap();
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn hosted_ledgers_keep_objects_and_commitments_isolated() {
        let store = Store::open_memory().unwrap();
        let first = store
            .bootstrap_ledger(
                "first.example",
                "2026-07-27T12:00:00.000Z",
                [21u8; 32],
                [22u8; 16],
            )
            .unwrap();
        let second = store
            .bootstrap_ledger(
                "second.example",
                "2026-07-27T12:00:00.000Z",
                [23u8; 32],
                [24u8; 16],
            )
            .unwrap();
        let app = router(AppState::new_without_caller_auth(
            store,
            "https://example.test/facts",
            SigningKey::from_seed(&[25u8; 32]).unwrap(),
            fact_core::ObjectId::new_v7(),
        ));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/facts/ledgers/{}/objects/{}",
                        first.ledger_id, second.genesis_id
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/facts/ledgers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ledgers = value["body"]["ledgers"].as_array().unwrap();
        assert_eq!(ledgers.len(), 2);
        assert!(ledgers
            .iter()
            .all(|ledger| ledger["ledger_id"] != serde_json::Value::Null));
    }

    #[tokio::test]
    async fn discovery_and_exact_object_get() {
        let store = Store::open_memory().unwrap();
        let bootstrap = store
            .bootstrap_ledger(
                "example.test",
                "2026-07-27T12:00:00.000Z",
                [4u8; 32],
                [5u8; 16],
            )
            .unwrap();
        let ledger = bootstrap.ledger_id;
        let cose = bootstrap
            .cose_objects
            .iter()
            .find(|bytes| {
                fact_crypto::decode_sign1(bytes)
                    .ok()
                    .and_then(|cose| {
                        serde_json::from_slice::<serde_json::Value>(&cose.payload).ok()
                    })
                    .and_then(|value| value.get("object_type").cloned())
                    == Some(serde_json::json!("genesis"))
            })
            .cloned()
            .unwrap();
        let genesis = fact_crypto::decode_sign1(&cose).unwrap();
        let canonical = genesis.payload;
        let id = serde_json::from_slice::<serde_json::Value>(&canonical).unwrap()["id"]
            .as_str()
            .unwrap()
            .parse::<uuid::Uuid>()
            .unwrap();
        let expected_pull_count = bootstrap
            .cose_objects
            .iter()
            .filter(|bytes| {
                fact_crypto::decode_sign1(bytes)
                    .ok()
                    .and_then(|cose| {
                        serde_json::from_slice::<serde_json::Value>(&cose.payload).ok()
                    })
                    .and_then(|value| value.get("ledger_id").cloned())
                    .is_some()
            })
            .count();
        let actor_bytes = bootstrap
            .cose_objects
            .iter()
            .find(|bytes| {
                fact_crypto::decode_sign1(bytes)
                    .ok()
                    .and_then(|cose| {
                        serde_json::from_slice::<serde_json::Value>(&cose.payload).ok()
                    })
                    .and_then(|value| value.get("object_type").cloned())
                    == Some(serde_json::json!("actor"))
            })
            .cloned()
            .unwrap();
        let actor_hash =
            fact_core::Hash::digest(&fact_crypto::decode_sign1(&actor_bytes).unwrap().payload);
        let app = router(AppState::new_without_caller_auth(
            store,
            "https://example.test/facts",
            SigningKey::from_seed(&[9u8; 32]).unwrap(),
            fact_core::ObjectId::new_v7(),
        ));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/facts")
                    .header("facts-protocol-version", "9")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["code"], "unsupported-version");
        assert_eq!(value["instance"], "/.well-known/facts");
        assert!(value["protocol_version"].is_null());
        assert_eq!(value["supported_versions"], serde_json::json!([0]));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/facts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["schema"], "facts-protocol-response-v0");
        assert!(
            value["body"]["coordinator_assertion"]
                .as_str()
                .unwrap()
                .len()
                > 10
        );
        assert_eq!(
            value["body"]["supported_media_types"],
            serde_json::json!([JSON_MEDIA])
        );
        assert_eq!(
            value["body"]["deployment_profile"]["per_ledger_visibility"],
            "coordinator-policy"
        );
        assert_eq!(
            value["body"]["deployment_profile"]["header_timeout_enforced_by"],
            "serve_reference"
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/facts")
                    .header("content-type", JSON_MEDIA)
                    .body(Body::from("unexpected"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["code"], "malformed-request");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/facts")
                    .header("accept-encoding", "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
        assert!(response.headers().contains_key("content-digest"));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/facts")
                    .header("idempotency-key", "x".repeat(256))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["code"], "malformed-request");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/facts/not-a-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["code"], "unknown-resource");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.well-known/facts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(response.headers().contains_key(header::ALLOW));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["code"], "method-not-allowed");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/facts")
                    .header(header::ACCEPT, "text/plain")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["code"], "not-acceptable");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/facts/namespaces/example.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/facts/ledgers/{ledger}/commitments/latest"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let latest_body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let latest: serde_json::Value = serde_json::from_slice(&latest_body).unwrap();
        assert_eq!(
            latest["body"]["schema"],
            "facts-protocol-commitment-response-v0"
        );
        assert!(latest["body"]["commitment"].as_str().unwrap().len() > 10);
        assert_eq!(
            latest["body"]["commitment_hash"].as_str().unwrap().len(),
            64
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/facts/ledgers/{ledger}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["schema"], "facts-protocol-response-v0");
        assert_eq!(value["body"]["schema"], "facts-protocol-ledger-metadata-v0");
        assert_eq!(value["body"]["genesis_hash"].as_str().unwrap().len(), 64);
        assert!(
            value["body"]["coordinator_assertion"]["cose_sign1"]
                .as_str()
                .unwrap()
                .len()
                > 10
        );
        assert!(value["body"]["namespace_assertions"].is_array());
        assert!(value["body"].get("coordinator_assertion").is_some());
        assert_eq!(
            value["body"]["latest_commitment"]["commitment_hash"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/facts/ledgers/{}/commitment", ledger))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["schema"], "facts-protocol-response-v0");
        assert_eq!(value["body"]["schema"], "facts-protocol-commitment-v0");
        assert!(value["body"]["signed_commitment"].as_str().unwrap().len() > 10);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/facts/ledgers/{}/commitments/latest", ledger))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let latest_value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            latest_value["body"]["schema"],
            "facts-protocol-commitment-response-v0"
        );
        let compare_body = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-merkle-compare-v0",
                "commitment_hash":latest_value["body"]["commitment_hash"],
                "object_hashes":[fact_core::Hash::digest(&canonical).hex()],
                "operation":"include",
                "other_commitment_hash":null
            }))
            .unwrap(),
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/merkle:compare"))
                    .header("content-type", JSON_MEDIA)
                    .header("facts-protocol-version", VERSION)
                    .header("content-digest", digest(&compare_body))
                    .body(Body::from(compare_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let compare_response = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let compare_value: serde_json::Value = serde_json::from_slice(&compare_response).unwrap();
        assert_eq!(compare_value["schema"], "facts-protocol-response-v0");
        assert_eq!(
            compare_value["body"]["schema"],
            "facts-protocol-merkle-compare-response-v0"
        );
        assert!(compare_value["body"]["proofs"].is_array());
        assert_eq!(
            compare_value["body"]["commitment_hash"],
            latest_value["body"]["commitment_hash"]
        );
        assert!(compare_value["body"]["proofs"][0]
            .get("commitment_hash")
            .is_none());
        assert!(compare_value["body"]["difference"].is_null());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/facts/ledgers/{}/proofs/{}",
                        ledger,
                        fact_core::Hash::digest(&canonical)
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let proof_response = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let proof_value: serde_json::Value = serde_json::from_slice(&proof_response).unwrap();
        assert_eq!(proof_value["schema"], "facts-protocol-response-v0");
        assert_eq!(proof_value["body"]["schema"], "facts-protocol-proof-v0");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/facts/ledgers/{}/objects/{}", ledger, id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], COSE_MEDIA);
        assert_eq!(response.headers()["facts-ledger"], ledger.to_string());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/facts/ledgers/{ledger}/dispositions/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let request_id_header = response.headers()["facts-request-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["schema"], "facts-protocol-response-v0");
        assert!(value["request_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()));
        assert_eq!(request_id_header, value["request_id"].as_str().unwrap());
        assert_eq!(value["protocol_version"], 0);
        assert!(value["body"]["disposition"].as_str().unwrap().len() > 10);
        assert!(value["body"].get("signed_disposition").is_none());
        let fetch_body = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-fetch-v0",
                "ids":[id.to_string()],
                "hashes":[],
                "include_missing":true
            }))
            .unwrap(),
        )
        .unwrap();
        let mismatched_fetch = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:fetch"))
                    .header("content-type", JSON_MEDIA)
                    .header("facts-ledger", uuid::Uuid::now_v7().to_string())
                    .header("content-digest", digest(&fetch_body))
                    .body(Body::from(fetch_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mismatched_fetch.status(), StatusCode::BAD_REQUEST);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:fetch"))
                    .header("content-type", JSON_MEDIA)
                    .header("content-digest", digest(&fetch_body))
                    .body(Body::from(fetch_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], JSON_MEDIA);
        let fetch_response = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let fetch_value: serde_json::Value = serde_json::from_slice(&fetch_response).unwrap();
        assert_eq!(
            fetch_value["body"]["schema"],
            "facts-protocol-fetch-response-v0"
        );
        assert_eq!(fetch_value["body"]["objects"].as_array().unwrap().len(), 1);
        let identity_fetch_body = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-fetch-v0",
                "ids":[],
                "hashes":[actor_hash.hex()],
                "include_missing":true
            }))
            .unwrap(),
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:fetch"))
                    .header("content-type", JSON_MEDIA)
                    .header("content-digest", digest(&identity_fetch_body))
                    .body(Body::from(identity_fetch_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let identity_fetch_response = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let identity_fetch_value: serde_json::Value =
            serde_json::from_slice(&identity_fetch_response).unwrap();
        assert_eq!(
            identity_fetch_value["body"]["objects"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            identity_fetch_value["body"]["objects"][0]["content_hash"],
            actor_hash.hex()
        );
        let missing_id = uuid::Uuid::now_v7();
        let missing_hash = fact_core::Hash::digest(b"missing-fetch-object");
        let missing_fetch_body = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-fetch-v0",
                "ids":[missing_id.to_string()],
                "hashes":[missing_hash.hex()],
                "include_missing":true
            }))
            .unwrap(),
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:fetch"))
                    .header("content-type", JSON_MEDIA)
                    .header("content-digest", digest(&missing_fetch_body))
                    .body(Body::from(missing_fetch_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            value["body"]["missing_ids"],
            serde_json::json!([missing_id])
        );
        assert_eq!(
            value["body"]["missing_hashes"],
            serde_json::json!([missing_hash.as_bytes()])
        );
        assert!(value["body"].get("missing").is_none());
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &missing_fetch_body).unwrap();
        let compressed_fetch_body = encoder.finish().unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:fetch"))
                    .header("content-type", JSON_MEDIA)
                    .header("content-encoding", "gzip")
                    .header("content-digest", digest(&compressed_fetch_body))
                    .body(Body::from(compressed_fetch_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mismatch_fetch_body = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-fetch-v0",
                "ids":[id.to_string()],
                "hashes":[actor_hash.hex()],
                "include_missing":true
            }))
            .unwrap(),
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:fetch"))
                    .header("content-type", JSON_MEDIA)
                    .header("content-digest", digest(&mismatch_fetch_body))
                    .body(Body::from(mismatch_fetch_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let value: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(value["code"], "hash-mismatch");
        assert_eq!(value["first_error_code"], "hash-mismatch");
        assert_eq!(value["object_errors"][0]["object_id"], id.to_string());
        assert_eq!(value["object_errors"][0]["object_hash"], actor_hash.hex());
        let mut oversized_ids = (0..1001)
            .map(|_| uuid::Uuid::now_v7().to_string())
            .collect::<Vec<_>>();
        oversized_ids.sort();
        let oversized_fetch_body = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-fetch-v0",
                "ids":oversized_ids,
                "hashes":[],
                "include_missing":true
            }))
            .unwrap(),
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:fetch"))
                    .header("content-type", JSON_MEDIA)
                    .header("content-digest", digest(&oversized_fetch_body))
                    .body(Body::from(oversized_fetch_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let oversized_response = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let oversized_value: serde_json::Value =
            serde_json::from_slice(&oversized_response).unwrap();
        assert_eq!(oversized_value["code"], "payload-too-large");
        let pull_body = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-pull-v0",
                "scope":full_ledger_scope(&ledger),
                "known_commitment_hash":null,
                "known_object_hashes":[],
                "limit":1000,
                "cursor":null,
                "prefer_snapshot":false
            }))
            .unwrap(),
        )
        .unwrap();
        fact_store::Store::reset_debug_metrics();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:pull"))
                    .header("content-type", JSON_MEDIA)
                    .header("facts-protocol-version", VERSION)
                    .header("content-digest", digest(&pull_body))
                    .body(Body::from(pull_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects, 0);
        let pull_response = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let pull_value: serde_json::Value = serde_json::from_slice(&pull_response).unwrap();
        assert_eq!(
            pull_value["body"]["schema"],
            "facts-protocol-pull-response-v0"
        );
        assert_eq!(
            pull_value["body"]["objects"].as_array().unwrap().len(),
            expected_pull_count
        );
        assert_eq!(
            pull_value["body"]["inclusion_proofs"]
                .as_array()
                .unwrap()
                .len(),
            expected_pull_count
        );
        let paged_pull_body = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-pull-v0",
                "scope":full_ledger_scope(&ledger),
                "known_commitment_hash":null,
                "known_object_hashes":[],
                "limit":1,
                "cursor":null,
                "prefer_snapshot":false
            }))
            .unwrap(),
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:pull"))
                    .header("content-type", JSON_MEDIA)
                    .header("facts-protocol-version", VERSION)
                    .header("content-digest", digest(&paged_pull_body))
                    .body(Body::from(paged_pull_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let paged = serde_json::from_slice::<serde_json::Value>(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(paged["body"]["object_count"], 1);
        assert_eq!(
            paged["body"]["inclusion_proofs"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            paged["body"]["inclusion_proofs"][0]["schema"],
            "facts-protocol-merkle-inclusion-proof-v0"
        );
        assert!(!paged["body"]["complete"].as_bool().unwrap());
        let cursor = paged["body"]["next_cursor"].as_str().unwrap();
        let continuation_body = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-pull-v0",
                "scope":full_ledger_scope(&ledger),
                "known_commitment_hash":null,
                "known_object_hashes":[],
                "limit":1,
                "cursor":cursor,
                "prefer_snapshot":false
            }))
            .unwrap(),
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:pull"))
                    .header("content-type", JSON_MEDIA)
                    .header("facts-protocol-version", VERSION)
                    .header("content-digest", digest(&continuation_body))
                    .body(Body::from(continuation_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let continuation = serde_json::from_slice::<serde_json::Value>(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(continuation["body"]["object_count"], 1);
        let stale_pull = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-pull-v0",
                "scope":full_ledger_scope(&ledger),
                "known_commitment_hash":"00".repeat(32),
                "known_object_hashes":[],
                "limit":1000,
                "cursor":null,
                "prefer_snapshot":false
            }))
            .unwrap(),
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:pull"))
                    .header("content-type", JSON_MEDIA)
                    .header("facts-protocol-version", VERSION)
                    .header("content-digest", digest(&stale_pull))
                    .body(Body::from(stale_pull))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let snapshot_pull = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-pull-v0",
                "scope":full_ledger_scope(&ledger),
                "known_commitment_hash":null,
                "known_object_hashes":[],
                "limit":1000,
                "cursor":null,
                "prefer_snapshot":true
            }))
            .unwrap(),
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:pull"))
                    .header("content-type", JSON_MEDIA)
                    .header("facts-protocol-version", VERSION)
                    .header("content-digest", digest(&snapshot_pull))
                    .body(Body::from(snapshot_pull))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], SNAPSHOT_MEDIA);
        let snapshot = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            fact_commitment::decode_snapshot(&snapshot)
                .unwrap()
                .objects
                .len(),
            expected_pull_count
        );
        assert!(fact_commitment::decode_snapshot(&[snapshot.as_ref(), &[0]].concat()).is_err());
        let bundle_manifest = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-bundle-v0",
                "protocol_version":0,
                "bundle_id":uuid::Uuid::now_v7(),
                "ledger_id":ledger,
                "object_count":1,
                "objects":[{"object_id":id,"content_hash":fact_core::Hash::digest(&canonical).hex()}],
                "dependency_refs":[],
                "sender_signature":null,
                "expected_commitment_hash":null,
                "base_commitment_hash":null
            }))
            .unwrap(),
        )
        .unwrap();
        let bundle = fact_commitment::encode_bundle(
            &bundle_manifest,
            &[(fact_core::Hash::digest(&canonical), cose.clone())],
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:push"))
                    .header("content-type", BUNDLE_MEDIA)
                    .header("facts-protocol-version", VERSION)
                    .header("content-digest", digest(&bundle))
                    .body(Body::from(bundle.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let push_body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let push_value: serde_json::Value = serde_json::from_slice(&push_body).unwrap();
        assert_eq!(push_value["schema"], "facts-protocol-response-v0");
        assert_eq!(
            push_value["body"]["schema"],
            "facts-protocol-push-response-v0"
        );
        assert_eq!(push_value["body"]["accepted_count"], 1);
        let query_body = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-query-v0",
                "query_type":"object",
                "search_text":null,
                "ledger_ids":[ledger.to_string()],
                "object_types":["genesis"],
                "scope":{"actor_ids":[],"deliberation_ids":[],"proposition_ids":[],"revision_ids":[]},
                "status":{"accepted":null,"archived":null,"divergent":null,"rejected":null,"settled":null,"withdrawn":null},
                "relationships":[],
                "search_profile":{"id":"hash-asc-v0","version":"0"},
                "extraction_profile":{"id":"facts-markdown-extraction-v0","version":"0"},
                "embedding_model":null,
                "ordering_profile":"hash-asc-v0",
                "page_size":1,
                "prior_cursor":null
            }))
            .unwrap(),
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/query"))
                    .header("content-type", QUERY_MEDIA)
                    .header("facts-protocol-version", VERSION)
                    .header("content-digest", digest(&query_body))
                    .body(Body::from(query_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["schema"], "facts-protocol-response-v0");
        assert_eq!(value["body"]["results"].as_array().unwrap().len(), 1);
        assert_eq!(
            value["body"]["results"][0]["object"]["content_hash"],
            fact_core::Hash::digest(&canonical).hex()
        );
        assert_eq!(value["body"]["schema"], "facts-protocol-query-response-v0");
        assert!(
            value["body"]["result_set_statement"]
                .as_str()
                .unwrap()
                .len()
                > 10
        );
        fact_store::Store::reset_debug_metrics();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/facts/ledgers/{}/objects", ledger))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(fact_store::Store::debug_metrics().list_objects, 0);
        let first_page: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            first_page["body"]["schema"],
            "facts-protocol-object-list-v0"
        );
        assert!(first_page["body"]["objects"].as_array().unwrap().len() >= 3);
        assert!(first_page["body"]["next_cursor"].is_null());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{}/objects:push", ledger))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn commitment_handlers_use_hash_only_store_queries() {
        let store = Store::open_memory().unwrap();
        let bootstrap = store
            .bootstrap_ledger(
                "commitment-query.example",
                "2026-07-27T12:00:00.000Z",
                [19u8; 32],
                [20u8; 16],
            )
            .unwrap();
        let ledger = bootstrap.ledger_id.to_string();
        let state = AppState::new_without_caller_auth(
            store,
            "https://example.test/facts",
            SigningKey::from_seed(&[21u8; 32]).unwrap(),
            fact_core::ObjectId::new_v7(),
        );

        fact_store::Store::reset_debug_metrics();
        let response = ledger_sync(state.clone(), ledger.clone());
        assert_eq!(response.status(), StatusCode::OK);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects, 0);
        assert!(metrics.list_object_hashes > 0);
        assert!(metrics.list_object_payloads_by_type > 0);

        fact_store::Store::reset_debug_metrics();
        let response = namespace_sync(state.clone(), "commitment-query.example".into());
        assert_eq!(response.status(), StatusCode::OK);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects, 0);
        assert!(metrics.list_object_payloads_by_type > 0);

        fact_store::Store::reset_debug_metrics();
        let response = latest_commitment_sync(state.clone(), ledger.clone());
        assert_eq!(response.status(), StatusCode::OK);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects, 0);
        assert!(metrics.list_object_hashes > 0);

        fact_store::Store::reset_debug_metrics();
        let response = commitment_sync(state.clone(), ledger.clone());
        assert_eq!(response.status(), StatusCode::OK);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects, 0);
        assert!(metrics.list_object_hashes > 0);

        let query_body = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-query-v0",
                "query_type":"object",
                "search_text":null,
                "ledger_ids":[ledger.clone()],
                "object_types":["genesis"],
                "scope":{"actor_ids":[],"deliberation_ids":[],"proposition_ids":[],"revision_ids":[]},
                "status":{"accepted":null,"archived":null,"divergent":null,"rejected":null,"settled":null,"withdrawn":null},
                "relationships":[],
                "search_profile":{"id":"hash-asc-v0","version":"0"},
                "extraction_profile":{"id":"facts-markdown-extraction-v0","version":"0"},
                "embedding_model":null,
                "ordering_profile":"hash-asc-v0",
                "page_size":10,
                "prior_cursor":null
            }))
            .unwrap(),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(QUERY_MEDIA));
        headers.insert("facts-protocol-version", HeaderValue::from_static(VERSION));
        headers.insert("content-digest", digest(&query_body));
        fact_store::Store::reset_debug_metrics();
        let response = query_sync(state.clone(), ledger.clone(), headers, query_body.into());
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(fact_store::Store::debug_metrics().list_objects, 0);

        let unscoped_query_body = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-query-v0",
                "query_type":"object",
                "search_text":null,
                "ledger_ids":[ledger.clone()],
                "object_types":[],
                "scope":{"actor_ids":[],"deliberation_ids":[],"proposition_ids":[],"revision_ids":[]},
                "status":{"accepted":null,"archived":null,"divergent":null,"rejected":null,"settled":null,"withdrawn":null},
                "relationships":[],
                "search_profile":{"id":"hash-asc-v0","version":"0"},
                "extraction_profile":{"id":"facts-markdown-extraction-v0","version":"0"},
                "embedding_model":null,
                "ordering_profile":"hash-asc-v0",
                "page_size":10,
                "prior_cursor":null
            }))
            .unwrap(),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(QUERY_MEDIA));
        headers.insert("facts-protocol-version", HeaderValue::from_static(VERSION));
        headers.insert("content-digest", digest(&unscoped_query_body));
        fact_store::Store::reset_debug_metrics();
        let response = query_sync(
            state.clone(),
            ledger.clone(),
            headers,
            unscoped_query_body.into(),
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(fact_store::Store::debug_metrics().list_objects, 0);

        let hash = fact_core::Hash::digest(
            &fact_crypto::decode_sign1(&bootstrap.cose_objects[0])
                .unwrap()
                .payload,
        )
        .hex();
        fact_store::Store::reset_debug_metrics();
        let response = proof_sync(state, ledger, hash);
        assert_eq!(response.status(), StatusCode::OK);
        let metrics = fact_store::Store::debug_metrics();
        assert_eq!(metrics.list_objects, 0);
        assert!(metrics.list_object_hashes > 0);
    }

    #[tokio::test]
    async fn query_text_search_uses_persistent_store_index() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("query.sqlite");
        let seed = [21; 32];
        let store = Store::open(&database).unwrap();
        let bootstrap = fact_sdk::workflow::create_ledger(
            &store,
            fact_sdk::workflow::BootstrapLedgerInput {
                namespace: "query.example".into(),
                created_at: "2026-07-30T12:00:00.000Z".into(),
                seed,
                nonce: [22; 16],
            },
        )
        .unwrap();
        let entry = fact_sdk::environment::LedgerEntry {
            name: "query".into(),
            ledger_id: bootstrap.ledger_id.clone(),
            database: database.clone(),
            actor_id: bootstrap.actor_id,
            key_id: bootstrap.key_id,
            seed_file: temp.path().join("seed"),
            read_only: false,
        };
        let created = fact_sdk::workflow::create_proposition(
            &entry,
            &seed,
            b"# Queryable\n\nNeedle content.\n",
            Some(fact_sdk::workflow::DecisionOutcome::Accepted),
        )
        .unwrap();
        drop(store);

        let store = Store::open(&database).unwrap();
        let app = router(AppState::new_without_caller_auth(
            store,
            "https://example.test/facts",
            SigningKey::from_seed(&[23u8; 32]).unwrap(),
            fact_core::ObjectId::new_v7(),
        ));
        let ledger = uuid::Uuid::parse_str(&entry.ledger_id).unwrap();
        let query_body = fact_canonical::encode(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-query-v0",
                "query_type":"fact",
                "search_text":"needle",
                "ledger_ids":[entry.ledger_id],
                "object_types":["revision"],
                "scope":{"actor_ids":[],"deliberation_ids":[],"proposition_ids":[],"revision_ids":[]},
                "status":{"accepted":null,"archived":null,"divergent":null,"rejected":null,"settled":null,"withdrawn":null},
                "relationships":[],
                "search_profile":{"id":"lexical-bm25-v0","version":"0"},
                "extraction_profile":{"id":"facts-markdown-extraction-v0","version":"0"},
                "embedding_model":null,
                "ordering_profile":"score-desc-hash-asc-v0",
                "page_size":10,
                "prior_cursor":null
            }))
            .unwrap(),
        )
        .unwrap();

        Store::reset_debug_metrics();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/query"))
                    .header("content-type", QUERY_MEDIA)
                    .header("facts-protocol-version", VERSION)
                    .header("content-digest", digest(&query_body))
                    .body(Body::from(query_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let expected_revision_id = created.revision_id.to_string();
        assert_eq!(
            value["body"]["results"][0]["object"]["object_id"].as_str(),
            Some(expected_revision_id.as_str())
        );
        let metrics = Store::debug_metrics();
        assert_eq!(metrics.list_objects, 0);
        assert_eq!(metrics.list_effective_state, 0);
        assert_eq!(metrics.list_knowledge_proposition_ids, 0);
        assert_eq!(metrics.list_markdown_documents, 0);
        assert_eq!(metrics.search_index_rebuilds, 0);
    }

    #[tokio::test]
    async fn ledger_discovery_includes_bootstrap_genesis_hash() {
        let store = Store::open_memory().unwrap();
        let bootstrap = store
            .bootstrap_ledger(
                "example.test",
                "2026-07-27T12:00:00.000Z",
                [9u8; 32],
                [7u8; 16],
            )
            .unwrap();
        let expected = store
            .list_ledger_metadata()
            .unwrap()
            .into_iter()
            .find(|(id, _, _)| id == &bootstrap.ledger_id.to_string())
            .and_then(|(_, _, hash)| hash)
            .unwrap()
            .hex();
        let app = router(AppState::new_without_caller_auth(
            store,
            "https://example.test/facts",
            SigningKey::from_seed(&[9u8; 32]).unwrap(),
            fact_core::ObjectId::new_v7(),
        ));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/facts/ledgers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["schema"], "facts-protocol-response-v0");
        assert_eq!(
            value["body"]["ledgers"][0]["ledger_id"],
            bootstrap.ledger_id.to_string()
        );
        assert_eq!(value["body"]["ledgers"][0]["genesis_hash"], expected);
        assert!(value["body"]["ledgers"][0]["latest_commitment_hash"]
            .as_str()
            .is_some());
    }

    #[tokio::test]
    async fn private_ledger_visibility_is_coordinator_policy() {
        let store = Store::open_memory().unwrap();
        let public = store
            .bootstrap_ledger(
                "public.example",
                "2026-07-27T12:00:00.000Z",
                [10u8; 32],
                [11u8; 16],
            )
            .unwrap();
        let private = store
            .bootstrap_ledger(
                "private.example",
                "2026-07-27T12:00:00.000Z",
                [12u8; 32],
                [13u8; 16],
            )
            .unwrap();
        let state = AppState::new_without_caller_auth(
            store,
            "https://example.test/facts",
            SigningKey::from_seed(&[14u8; 32]).unwrap(),
            fact_core::ObjectId::new_v7(),
        )
        .with_ledger_visibility(
            private.ledger_id.to_string().parse().unwrap(),
            LedgerVisibility::Private,
        );
        let app = router(state);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/facts/ledgers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let visible = value["body"]["ledgers"].as_array().unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0]["ledger_id"], public.ledger_id.to_string());

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/facts/ledgers/{}", private.ledger_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get("www-authenticate").is_some());
    }

    #[tokio::test]
    async fn reference_listener_closes_slow_http_headers() {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind reference listener: {error}"),
        };
        let address = listener.local_addr().unwrap();
        let state = AppState::new_without_caller_auth(
            Store::open_memory().unwrap(),
            "https://example.test/facts",
            SigningKey::from_seed(&[15u8; 32]).unwrap(),
            fact_core::ObjectId::new_v7(),
        );
        let server = tokio::spawn(serve_with_header_timeout(
            listener,
            state,
            std::time::Duration::from_millis(20),
        ));
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.test")
            .await
            .unwrap();
        let mut response = [0u8; 1];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.read(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(read, 0);
        server.abort();
    }

    #[tokio::test]
    async fn push_rejects_action_without_causal_authority() {
        let store = Store::open_memory().unwrap();
        let ledger = uuid::Uuid::now_v7();
        let actor = uuid::Uuid::now_v7();
        let key_id = uuid::Uuid::now_v7();
        let key = SigningKey::from_seed(&[31u8; 32]).unwrap();
        store
            .register_key(key_id.as_bytes(), &key.public_key())
            .unwrap();
        store
            .create_ledger(ledger.as_bytes(), "example.test")
            .unwrap();
        let id = uuid::Uuid::now_v7();
        let value = serde_json::json!({
            "id":id,"ledger_id":ledger,"object_type":"proposition","schema_version":"0",
            "actor_id":actor,"signing_key_id":key_id,"created_at":"2026-07-27T12:00:00.000Z","dependencies":[],
            "body":{"proposition_id":id,"purpose":"knowledge","initial_revision_id":uuid::Uuid::now_v7(),"initial_deliberation_id":uuid::Uuid::now_v7()}
        });
        let payload = canonicalize(&serde_json::to_vec(&value).unwrap()).unwrap();
        let protected = fact_crypto::protocol_protected(
            key.public_key(),
            "proposition",
            "0",
            Some(*ledger.as_bytes()),
        );
        let cose = encode_sign1(&sign1(&protected, &payload, &key));
        let hash = fact_core::Hash::digest(&payload);
        let manifest = canonicalize(
            &serde_json::to_vec(&serde_json::json!({
                "schema":"facts-protocol-bundle-v0",
                "protocol_version":0,
                "bundle_id":uuid::Uuid::now_v7(),
                "object_count":1,
                "ledger_id":ledger,
                "objects":[{"object_id":id,"content_hash":hash.hex()}],
                "dependency_refs":[],
                "sender_signature":null,
                "expected_commitment_hash":null,
                "base_commitment_hash":null
            }))
            .unwrap(),
        )
        .unwrap();
        let bundle = fact_commitment::encode_bundle(&manifest, &[(hash, cose)]).unwrap();
        let app = router(AppState::new_without_caller_auth(
            store,
            "https://example.test/facts",
            SigningKey::from_seed(&[9u8; 32]).unwrap(),
            fact_core::ObjectId::new_v7(),
        ));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/objects:push"))
                    .header("content-type", BUNDLE_MEDIA)
                    .header("facts-protocol-version", VERSION)
                    .header("facts-ledger", ledger.to_string())
                    .header("content-digest", digest(&bundle))
                    .body(Body::from(bundle))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["body"]["accepted_count"], 0);
        assert_eq!(value["body"]["rejected_count"], 1);
        assert_eq!(
            value["body"]["results"][0]["error_code"],
            "missing-dependency"
        );
    }

    #[tokio::test]
    async fn query_cursor_round_trip_is_bound_to_snapshot() {
        let store = Store::open_memory().unwrap();
        let bootstrap = store
            .bootstrap_ledger(
                "example.test",
                "2026-07-27T12:00:00.000Z",
                [6u8; 32],
                [5u8; 16],
            )
            .unwrap();
        let ledger = bootstrap.ledger_id;
        let app = router(AppState::new_without_caller_auth(
            store,
            "https://example.test/facts",
            SigningKey::from_seed(&[9u8; 32]).unwrap(),
            fact_core::ObjectId::new_v7(),
        ));
        let mut query = serde_json::json!({
            "schema":"facts-protocol-query-v0",
            "query_type":"object",
            "search_text":null,
            "ledger_ids":[ledger.to_string()],
            "object_types":[],
            "scope":{"actor_ids":[],"deliberation_ids":[],"proposition_ids":[],"revision_ids":[]},
            "status":{"accepted":null,"archived":null,"divergent":null,"rejected":null,"settled":null,"withdrawn":null},
            "relationships":[],
            "search_profile":{"id":"hash-asc-v0","version":"0"},
            "extraction_profile":{"id":"facts-markdown-extraction-v0","version":"0"},
            "embedding_model":null,
            "ordering_profile":"hash-asc-v0",
            "page_size":1,
            "prior_cursor":null
        });
        let canonical_query = |query: &serde_json::Value| {
            fact_canonical::encode(&serde_json::to_vec(query).unwrap()).unwrap()
        };
        let first_body = canonical_query(&query);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/query"))
                    .header("content-type", QUERY_MEDIA)
                    .header("facts-protocol-version", VERSION)
                    .header("content-digest", digest(&first_body))
                    .body(Body::from(first_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let first: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let cursor = first["body"]["next_cursor"].as_str().unwrap().to_owned();
        assert_eq!(first["body"]["results"].as_array().unwrap().len(), 1);
        assert_eq!(
            first["body"]["results"][0]["inclusion_proof"]["schema"],
            "facts-protocol-merkle-inclusion-proof-v0"
        );
        assert!(first["body"]["results"][0]["inclusion_proof"]["siblings"].is_array());
        query["prior_cursor"] = serde_json::Value::String(cursor);
        let second_body = canonical_query(&query);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/query"))
                    .header("content-type", QUERY_MEDIA)
                    .header("facts-protocol-version", VERSION)
                    .header("content-digest", digest(&second_body))
                    .body(Body::from(second_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let second: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            second["body"]["query_digest"],
            first["body"]["query_digest"]
        );
        assert_eq!(second["body"]["results"].as_array().unwrap().len(), 1);

        let mut fact_query = query;
        fact_query["query_type"] = serde_json::Value::String("fact".into());
        fact_query["search_text"] = serde_json::Value::String("signed".into());
        fact_query["search_profile"] = serde_json::json!({"id":"lexical-bm25-v0","version":"0"});
        fact_query["ordering_profile"] = serde_json::Value::String("score-desc-hash-asc-v0".into());
        fact_query["prior_cursor"] = serde_json::Value::Null;
        let fact_body = canonical_query(&fact_query);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/facts/ledgers/{ledger}/query"))
                    .header("content-type", QUERY_MEDIA)
                    .header("facts-protocol-version", VERSION)
                    .header("content-digest", digest(&fact_body))
                    .body(Body::from(fact_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let fact_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            fact_response["body"]["schema"],
            "facts-protocol-query-response-v0"
        );
    }

    #[test]
    fn query_filters_scope_and_relationships_against_canonical_payload() {
        let object_id = uuid::Uuid::now_v7();
        let actor_id = uuid::Uuid::now_v7();
        let other_id = uuid::Uuid::now_v7();
        let object = serde_json::json!({
            "id":object_id,
            "actor_id":actor_id,
            "object_type":"revision",
            "body":{
                "relationships":[{
                    "relationship":"protocol:parent-revision",
                    "target_object_ids":[other_id]
                }]
            }
        });
        let scope = serde_json::json!({
            "actor_ids":[actor_id],
            "proposition_ids":[],
            "revision_ids":[],
            "deliberation_ids":[]
        });
        let status = serde_json::json!({
            "accepted":null,"rejected":null,"settled":null,
            "archived":null,"withdrawn":null,"divergent":null
        });
        let relationships = serde_json::json!([{
            "type":"protocol:parent-revision",
            "direction":"out",
            "other_object_id":other_id
        }]);
        assert!(query_object_matches(
            &object,
            &object_id.to_string(),
            &scope,
            &status,
            &relationships,
            &HashMap::new()
        ));
        let wrong_scope = serde_json::json!({
            "actor_ids":[other_id],
            "proposition_ids":[],
            "revision_ids":[],
            "deliberation_ids":[]
        });
        assert!(!query_object_matches(
            &object,
            &object_id.to_string(),
            &wrong_scope,
            &status,
            &relationships,
            &HashMap::new()
        ));
    }

    #[test]
    fn fact_query_requires_knowledge_and_active_effective_state() {
        let proposition_id = uuid::Uuid::now_v7();
        let revision_id = uuid::Uuid::now_v7();
        let object = serde_json::json!({
            "id":uuid::Uuid::now_v7(),
            "actor_id":uuid::Uuid::now_v7(),
            "object_type":"revision",
            "body":{"proposition_id":proposition_id,"revision_id":revision_id}
        });
        let projected = fact_store::EffectiveProjected {
            proposition_id: proposition_id.to_string().parse().unwrap(),
            status: "accepted".into(),
            revision_id: Some(revision_id.to_string().parse().unwrap()),
            deliberation_id: None,
            settlement_id: None,
            withdrawal_status: "active".into(),
            archival_status: "visible".into(),
            reason: "valid-settlement".into(),
        };
        let effective = HashMap::from([(proposition_id.to_string(), projected)]);
        let knowledge = HashSet::from([proposition_id.to_string()]);
        let status = serde_json::json!({
            "accepted":null,"rejected":null,"settled":null,
            "archived":null,"withdrawn":null,"divergent":null
        });
        assert!(fact_object_is_effective(
            &object, &status, &knowledge, &effective
        ));

        let archived_status = serde_json::json!({
            "accepted":null,"rejected":null,"settled":null,
            "archived":true,"withdrawn":null,"divergent":null
        });
        assert!(!fact_object_is_effective(
            &object,
            &archived_status,
            &knowledge,
            &effective
        ));
    }
}
