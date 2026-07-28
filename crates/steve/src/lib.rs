pub mod attestation;
#[cfg(feature = "eval-attestation")]
pub mod eval_attestation;
pub mod protocol;
pub mod sessions;

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use attestation::{AttestationProvider, NitroAttestationProvider};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use protocol::{
    AttestedBinding, CONTEXT_HASH_LEN, Envelope, KeyExchangeSuite, NONCE_LEN, ProtocolError,
    SESSION_ID_LEN, SessionRequest, SessionResponse, VERSION, X25519_KEY_MATERIAL_LEN,
    build_transcript, decode_cbor, derive_secrets, encode_cbor, fixed, transcript_hash,
};
use rand::{RngCore, rngs::OsRng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sessions::{CLEANUP_INTERVAL, PENDING_TTL, Session, SessionError, SessionStore};
use tokio::{sync::Semaphore, task};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{debug, error, warn};
use x_wing::{Encapsulate, EncapsulationKey};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_APP_UPSTREAM: &str = "http://127.0.0.1:8083";
const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:49500";
const MAX_ENVELOPE_BYTES: usize = 32 * 1024 * 1024;
const MAX_PROTECTED_RESPONSE_BODY_BYTES: usize = MAX_ENVELOPE_BYTES;
const MAX_UNENCRYPTED_BODY_BYTES: usize = 1024 * 1024;
const MAX_SESSION_BODY_BYTES: usize = 4_096;
const MAX_CONCURRENT_ATTESTATIONS: usize = 8;
const MAX_CONCURRENT_KEY_EXCHANGES: usize = 8;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub upstream_url: url::Url,
    pub cors_origins: Option<String>,
    pub key_exchange: KeyExchangeSuite,
}

/// Enclave metadata surfaced by bootproofd as attestation `user_data`.
///
/// E2P v2 binds attestation to sessions directly, so there is no persistent
/// `verifying_key` anymore; the protocol version tells consumers the v1 key
/// channel is intentionally gone.
#[derive(Debug, Serialize)]
struct StaticMetadataOutput {
    e2p_protocol_version: u32,
    e2p_key_exchange: KeyExchangeSuite,
}

impl StaticMetadataOutput {
    fn new(key_exchange: KeyExchangeSuite) -> Self {
        Self {
            e2p_protocol_version: VERSION.into(),
            e2p_key_exchange: key_exchange,
        }
    }
}

/// Write enclave metadata to `E2P_METADATA_FILE` (default `/metadata.json`)
/// for bootproofd to embed as attestation `user_data`.
pub fn write_metadata() -> Result<(), BoxError> {
    let metadata_path =
        std::env::var("E2P_METADATA_FILE").unwrap_or_else(|_| String::from("/metadata.json"));
    write_metadata_to(&metadata_path, configured_key_exchange()?)
}

fn write_metadata_to(metadata_path: &str, key_exchange: KeyExchangeSuite) -> Result<(), BoxError> {
    let metadata = StaticMetadataOutput::new(key_exchange);
    debug!(?metadata, %metadata_path, "writing enclave metadata");
    let metadata_file = std::fs::File::create_new(metadata_path)?;
    serde_json::to_writer(metadata_file, &metadata)?;
    Ok(())
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, BoxError> {
        let upstream = std::env::var("STEVE_APP_UPSTREAM")
            .unwrap_or_else(|_| DEFAULT_APP_UPSTREAM.to_string());
        Ok(Self {
            listen_addr: std::env::var("STEVE_LISTEN_ADDR")
                .unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string()),
            upstream_url: url::Url::parse(&upstream)?,
            cors_origins: std::env::var("STEVE_CORS_ORIGINS").ok(),
            key_exchange: configured_key_exchange()?,
        })
    }
}

fn configured_key_exchange() -> Result<KeyExchangeSuite, BoxError> {
    parse_configured_key_exchange(std::env::var("STEVE_KEY_EXCHANGE"))
}

fn parse_configured_key_exchange(
    configured: Result<String, std::env::VarError>,
) -> Result<KeyExchangeSuite, BoxError> {
    match configured {
        Ok(value) => value.parse().map_err(|_| {
            format!("invalid STEVE_KEY_EXCHANGE value {value:?}; expected X25519 or XWING-DRAFT10")
                .into()
        }),
        Err(std::env::VarError::NotPresent) => Ok(KeyExchangeSuite::X25519),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("STEVE_KEY_EXCHANGE must be valid Unicode".into())
        }
    }
}

struct AppState {
    attestation: Arc<dyn AttestationProvider>,
    attestation_slots: Arc<Semaphore>,
    kem_slots: Arc<Semaphore>,
    sessions: Arc<SessionStore>,
    key_exchange: KeyExchangeSuite,
    http_client: Client,
    upstream_url: url::Url,
    protected_upstream: Arc<dyn ProtectedUpstream>,
}

type ProtectedFuture<'a> = Pin<Box<dyn Future<Output = ApplicationResponse> + Send + 'a>>;

trait ProtectedUpstream: Send + Sync {
    fn forward(&self, request: ApplicationRequest) -> ProtectedFuture<'_>;
}

struct HttpProtectedUpstream {
    client: Client,
    upstream_url: url::Url,
}

impl ProtectedUpstream for HttpProtectedUpstream {
    fn forward(&self, request: ApplicationRequest) -> ProtectedFuture<'_> {
        Box::pin(forward_protected_http(
            &self.client,
            &self.upstream_url,
            request,
        ))
    }
}

pub fn build_router(config: ServerConfig) -> Result<Router, BoxError> {
    build_router_with_provider(config, Arc::new(NitroAttestationProvider))
}

pub fn build_router_with_provider(
    config: ServerConfig,
    attestation: Arc<dyn AttestationProvider>,
) -> Result<Router, BoxError> {
    let protected_upstream = Arc::new(HttpProtectedUpstream {
        client: enclave_http_client()?,
        upstream_url: config.upstream_url.clone(),
    });
    build_router_with_components(config, attestation, protected_upstream)
}

fn build_router_with_components(
    config: ServerConfig,
    attestation: Arc<dyn AttestationProvider>,
    protected_upstream: Arc<dyn ProtectedUpstream>,
) -> Result<Router, BoxError> {
    build_router_with_components_and_store(
        config,
        attestation,
        protected_upstream,
        Arc::new(SessionStore::default()),
    )
}

fn build_router_with_components_and_store(
    config: ServerConfig,
    attestation: Arc<dyn AttestationProvider>,
    protected_upstream: Arc<dyn ProtectedUpstream>,
    sessions: Arc<SessionStore>,
) -> Result<Router, BoxError> {
    let cors = config.cors_origins.as_deref().map(cors_layer).transpose()?;

    let cleanup_sessions = Arc::clone(&sessions);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            cleanup_sessions.prune();
        }
    });

    let state = Arc::new(AppState {
        attestation,
        attestation_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_ATTESTATIONS)),
        kem_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_KEY_EXCHANGES)),
        sessions,
        key_exchange: config.key_exchange,
        http_client: enclave_http_client()?,
        upstream_url: config.upstream_url,
        protected_upstream,
    });

    let mut e2p = Router::new()
        .route("/v2/session", post(create_session))
        .route("/v2/confirm", post(confirm_session))
        .route("/v2/request", post(protected_request))
        .fallback(e2p_not_found);
    if let Some(cors) = cors {
        e2p = e2p.layer(cors);
    }

    Ok(Router::new()
        .nest("/e2p", e2p)
        .fallback(fallback)
        .layer(DefaultBodyLimit::max(MAX_ENVELOPE_BYTES))
        .with_state(state))
}

fn cors_layer(origins: &str) -> Result<CorsLayer, BoxError> {
    let configured = origins.split(',').map(str::trim).collect::<Vec<_>>();
    if configured.iter().any(|origin| origin.is_empty()) {
        return Err("STEVE_CORS_ORIGINS contains an empty origin entry".into());
    }

    if configured.contains(&"*") {
        return Err("STEVE_CORS_ORIGINS requires explicit origins; '*' is not allowed".into());
    }

    let mut values = Vec::with_capacity(configured.len());
    for configured_origin in configured {
        let origin = url::Url::parse(configured_origin)
            .map_err(|_| format!("invalid CORS origin: {configured_origin}"))?;
        if !matches!(origin.scheme(), "http" | "https")
            || origin.host().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(format!("invalid CORS origin: {configured_origin}").into());
        }
        let value = HeaderValue::from_str(&origin.origin().ascii_serialization())
            .map_err(|_| format!("invalid CORS origin: {configured_origin}"))?;
        if !values.contains(&value) {
            values.push(value);
        }
    }

    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(values))
        .allow_methods([Method::POST])
        .allow_headers([header::CONTENT_TYPE]))
}

fn enclave_http_client() -> Result<Client, reqwest::Error> {
    // The enclave must never inherit host proxy configuration for its local upstream hop.
    // Keep plaintext responses byte-preserving; protected requests explicitly require identity.
    Client::builder()
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response, ApiError> {
    let body = to_bytes(request.into_body(), MAX_SESSION_BODY_BYTES)
        .await
        .map_err(|_| ApiError::Malformed)?;
    let request: SessionRequest = decode_cbor(&body).map_err(ApiError::from)?;
    if request.version != VERSION || request.key_exchange != state.key_exchange {
        return Err(ApiError::Malformed);
    }
    let client_nonce = fixed::<NONCE_LEN>(&request.client_nonce).map_err(ApiError::from)?;
    let context_hash = fixed::<CONTEXT_HASH_LEN>(&request.context_hash).map_err(ApiError::from)?;
    if request.client_key_material.len() != state.key_exchange.client_key_material_len() {
        return Err(ApiError::Malformed);
    }

    // Reserve bounded session capacity before entering either potentially
    // expensive KEM. A failed handshake drops the reservation automatically.
    let reservation = state.sessions.reserve().map_err(ApiError::from)?;
    let kem_slot = Arc::clone(&state.kem_slots)
        .try_acquire_owned()
        .map_err(|_| ApiError::Capacity)?;
    let key_exchange = state.key_exchange;
    let client_key_material = request.client_key_material;
    let kem_client_key_material = client_key_material.clone();
    let (server_key_material, shared_secret) = task::spawn_blocking(move || {
        let _kem_slot = kem_slot;
        perform_key_exchange(key_exchange, &kem_client_key_material)
    })
    .await
    .map_err(|_| ApiError::Internal)?
    .map_err(ApiError::from)?;

    let mut session_id = [0u8; SESSION_ID_LEN];
    OsRng.fill_bytes(&mut session_id);

    let transcript = build_transcript(
        key_exchange,
        &client_nonce,
        &client_key_material,
        &server_key_material,
        &session_id,
        &context_hash,
    )
    .map_err(ApiError::from)?;
    let transcript_hash = transcript_hash(&transcript);
    let secrets = derive_secrets(&shared_secret, &transcript_hash).map_err(ApiError::from)?;
    let user_data = serde_json::to_vec(&AttestedBinding::new(
        key_exchange,
        &session_id,
        &transcript_hash,
        secrets.binder(),
    ))
    .map_err(|_| ApiError::Internal)?;

    let attestation_slot = Arc::clone(&state.attestation_slots)
        .try_acquire_owned()
        .map_err(|_| ApiError::Capacity)?;
    let provider = Arc::clone(&state.attestation);
    let attestation_document = task::spawn_blocking(move || {
        let _attestation_slot = attestation_slot;
        provider.attest(&client_nonce, &user_data)
    })
    .await
    .map_err(|_| ApiError::Attestation)?
    .map_err(|_| ApiError::Attestation)?;

    state
        .sessions
        .insert(
            Session::new(session_id, transcript_hash, secrets),
            reservation,
        )
        .map_err(ApiError::from)?;

    cbor_response(&SessionResponse {
        version: VERSION,
        key_exchange,
        session_id: session_id.to_vec(),
        server_key_material,
        attestation_document,
        expires_in_seconds: PENDING_TTL.as_secs() as u32,
    })
}

fn perform_key_exchange(
    key_exchange: KeyExchangeSuite,
    client_key_material: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), ProtocolError> {
    match key_exchange {
        KeyExchangeSuite::X25519 => {
            let client_public_key =
                PublicKey::from(fixed::<X25519_KEY_MATERIAL_LEN>(client_key_material)?);
            let server_secret = EphemeralSecret::random_from_rng(OsRng);
            let server_public_key = PublicKey::from(&server_secret).to_bytes();
            let shared_secret = server_secret.diffie_hellman(&client_public_key);
            if !shared_secret.was_contributory() {
                return Err(ProtocolError::Authentication);
            }
            Ok((
                server_public_key.to_vec(),
                Zeroizing::new(shared_secret.to_bytes()),
            ))
        }
        KeyExchangeSuite::XWingDraft10 => {
            let client_public_key = EncapsulationKey::try_from(client_key_material)
                .map_err(|_| ProtocolError::InvalidLength)?;
            let (ciphertext, mut shared_secret) = client_public_key.encapsulate();
            let shared_secret_bytes = Zeroizing::new(
                <[u8; 32]>::try_from(shared_secret.as_slice())
                    .map_err(|_| ProtocolError::KeyDerivation)?,
            );
            shared_secret.zeroize();
            Ok((ciphertext.to_vec(), shared_secret_bytes))
        }
    }
}

async fn confirm_session(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let envelope = decode_envelope(&body)?;
    let (session_id, sequence) = envelope.validate().map_err(ApiError::from)?;
    let session = state.sessions.get(&session_id).map_err(ApiError::from)?;
    let ciphertext = session
        .confirm(sequence, &envelope.ciphertext)
        .map_err(ApiError::from)?;
    cbor_response(&Envelope {
        version: VERSION,
        session_id: session_id.to_vec(),
        sequence: sequence.to_be_bytes().to_vec(),
        ciphertext,
    })
}

async fn protected_request(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let envelope = decode_envelope(&body)?;
    let (session_id, sequence) = envelope.validate().map_err(ApiError::from)?;
    let session = state.sessions.get(&session_id).map_err(ApiError::from)?;
    let plaintext = session
        .open_request(sequence, &envelope.ciphertext)
        .map_err(ApiError::from)?;
    let application_request: ApplicationRequest =
        decode_cbor(&plaintext).map_err(ApiError::from)?;

    let application_response = state.protected_upstream.forward(application_request).await;
    let response_plaintext = encode_cbor(&application_response).map_err(ApiError::from)?;
    let ciphertext = session
        .seal_response(sequence, &response_plaintext)
        .map_err(ApiError::from)?;

    cbor_response(&Envelope {
        version: VERSION,
        session_id: session_id.to_vec(),
        sequence: sequence.to_be_bytes().to_vec(),
        ciphertext,
    })
}

fn decode_envelope(body: &[u8]) -> Result<Envelope, ApiError> {
    if body.len() > MAX_ENVELOPE_BYTES {
        return Err(ApiError::Malformed);
    }
    decode_cbor(body).map_err(ApiError::from)
}

#[derive(Debug, Serialize, Deserialize)]
struct ApplicationRequest {
    method: String,
    path: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(with = "serde_bytes", default)]
    body: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ApplicationResponse {
    status: u16,
    headers: HashMap<String, String>,
    #[serde(with = "serde_bytes")]
    body: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug)]
enum ProtectedResponseBodyError {
    TooLarge,
    Read(reqwest::Error),
}

fn append_protected_response_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
) -> Result<(), ProtectedResponseBodyError> {
    if chunk.len() > limit.saturating_sub(body.len()) {
        return Err(ProtectedResponseBodyError::TooLarge);
    }
    body.extend_from_slice(chunk);
    Ok(())
}

async fn read_protected_response_body(
    response: &mut reqwest::Response,
    limit: usize,
) -> Result<Option<Vec<u8>>, ProtectedResponseBodyError> {
    let content_length = response.content_length();
    if content_length.is_some_and(|length| length > limit as u64) {
        return Err(ProtectedResponseBodyError::TooLarge);
    }

    let mut body = Vec::with_capacity(content_length.unwrap_or(0) as usize);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(ProtectedResponseBodyError::Read)?
    {
        append_protected_response_chunk(&mut body, &chunk, limit)?;
    }

    Ok((!body.is_empty()).then_some(body))
}

async fn forward_protected_http(
    client: &Client,
    upstream_url: &url::Url,
    request: ApplicationRequest,
) -> ApplicationResponse {
    let failure = |message: &str| ApplicationResponse {
        status: StatusCode::BAD_GATEWAY.as_u16(),
        headers: HashMap::new(),
        body: None,
        error: Some(message.to_string()),
    };

    let method = match request.method.parse::<Method>() {
        Ok(method) => method,
        Err(_) => return failure("invalid upstream request"),
    };
    let url = match crate::upstream_url(upstream_url, &request.path) {
        Ok(url) => url,
        Err(_) => return failure("invalid upstream request"),
    };

    let mut builder = client
        .request(method, url)
        .header(header::ACCEPT_ENCODING, "identity");
    for (name, value) in request.headers {
        if forwardable_protected_request_header(&name) {
            builder = builder.header(name, value);
        }
    }
    if let Some(body) = request.body {
        builder = builder.body(body);
    }

    let mut response = match builder.send().await {
        Ok(response) => response,
        Err(error) => {
            warn!(%error, "protected upstream request failed");
            return failure("upstream unavailable");
        }
    };
    let status = response.status().as_u16();
    if has_unsupported_content_encoding(response.headers()) {
        warn!("protected upstream returned unsupported content encoding");
        return failure("unsupported upstream content encoding");
    }
    let headers = response_headers(response.headers());
    let body = match read_protected_response_body(&mut response, MAX_PROTECTED_RESPONSE_BODY_BYTES)
        .await
    {
        Ok(body) => body,
        Err(ProtectedResponseBodyError::TooLarge) => {
            warn!(
                limit = MAX_PROTECTED_RESPONSE_BODY_BYTES,
                "protected upstream response exceeded size limit"
            );
            return failure("upstream response too large");
        }
        Err(ProtectedResponseBodyError::Read(error)) => {
            warn!(%error, "failed reading protected upstream response");
            return failure("upstream response unavailable");
        }
    };
    ApplicationResponse {
        status,
        headers,
        body,
        error: None,
    }
}

async fn fallback(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if request.uri().path().starts_with("/e2p/") {
        return (StatusCode::NOT_FOUND, "E2P endpoint unavailable").into_response();
    }
    forward_unencrypted(&state, request).await
}

async fn e2p_not_found() -> Response {
    (StatusCode::NOT_FOUND, "E2P endpoint unavailable").into_response()
}

// Item 3 (fail-closed enforcement) is intentionally deferred. Until then, requests that are not
// handled by the v2 service worker retain STEVE's existing plaintext forwarding behavior.
async fn forward_unencrypted(state: &AppState, request: Request) -> Response {
    let method = request.method().clone();
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| request.uri().path());
    let url = match upstream_url(&state.upstream_url, path) {
        Ok(url) => url,
        Err(_) => return ApiError::Malformed.into_response(),
    };

    let headers = request.headers().clone();
    let body = match axum::body::to_bytes(request.into_body(), MAX_UNENCRYPTED_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return ApiError::Malformed.into_response(),
    };
    let mut builder = state.http_client.request(method, url);
    for (name, value) in &headers {
        if forwardable_header(name.as_str()) {
            builder = builder.header(name.clone(), value.clone());
        }
    }
    let upstream = match builder.body(body).send().await {
        Ok(response) => response,
        Err(error) => {
            error!(%error, "unencrypted upstream request failed");
            return (StatusCode::BAD_GATEWAY, "upstream unavailable").into_response();
        }
    };
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let body = match upstream.bytes().await {
        Ok(body) => body,
        Err(_) => return (StatusCode::BAD_GATEWAY, "upstream unavailable").into_response(),
    };
    let mut response = match Response::builder().status(status).body(Body::from(body)) {
        Ok(response) => response,
        Err(_) => return ApiError::Internal.into_response(),
    };
    for (name, value) in &headers {
        if forwardable_header(name.as_str()) {
            response.headers_mut().append(name.clone(), value.clone());
        }
    }
    response
}

fn upstream_url(base: &url::Url, path: &str) -> Result<url::Url, ()> {
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['\r', '\n'])
        || path.contains("\\")
    {
        return Err(());
    }
    base.join(path).map_err(|_| ())
}

fn forwardable_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "content-length"
            | "connection"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "te"
            | "trailer"
            | "keep-alive"
            | "x-e2p-key"
            | "x-e2p-original-method"
    )
}

fn forwardable_protected_request_header(name: &str) -> bool {
    forwardable_header(name) && !name.eq_ignore_ascii_case("accept-encoding")
}

fn has_unsupported_content_encoding(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .any(|value| {
            value.to_str().map_or(true, |value| {
                let mut encodings = value.split(',').map(str::trim).peekable();
                encodings.peek().is_none()
                    || encodings.any(|encoding| !encoding.eq_ignore_ascii_case("identity"))
            })
        })
}

fn response_headers(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(name, _)| forwardable_header(name.as_str()))
        .filter(|(name, _)| *name != header::CONTENT_ENCODING)
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect()
}

fn cbor_response<T: Serialize>(value: &T) -> Result<Response, ApiError> {
    let body = encode_cbor(value).map_err(ApiError::from)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/cbor")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .map_err(|_| ApiError::Internal)
}

#[derive(Debug)]
enum ApiError {
    Malformed,
    InvalidSession,
    Unconfirmed,
    Replay,
    Capacity,
    Attestation,
    Internal,
}

impl From<ProtocolError> for ApiError {
    fn from(_: ProtocolError) -> Self {
        Self::Malformed
    }
}

impl From<SessionError> for ApiError {
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::InvalidSession => Self::InvalidSession,
            SessionError::Unconfirmed => Self::Unconfirmed,
            SessionError::AlreadyConfirmed | SessionError::Replay => Self::Replay,
            SessionError::Capacity => Self::Capacity,
            SessionError::Collision => Self::Internal,
            SessionError::Authentication | SessionError::ConfirmationMismatch => Self::Malformed,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Malformed => (StatusCode::BAD_REQUEST, "protocol_error"),
            Self::InvalidSession => (StatusCode::UNAUTHORIZED, "invalid_session"),
            Self::Unconfirmed => (StatusCode::TOO_EARLY, "unconfirmed_session"),
            Self::Replay => (StatusCode::CONFLICT, "replayed_sequence"),
            Self::Capacity => (StatusCode::TOO_MANY_REQUESTS, "session_capacity"),
            Self::Attestation => (StatusCode::SERVICE_UNAVAILABLE, "attestation_unavailable"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        let body = serde_json::json!({ "error": code }).to_string();
        (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        attestation::test_support::FakeAttestationProvider,
        protocol::{Direction, MessageType, decode_cbor, derive_secrets, encode_cbor},
    };
    use axum::body::to_bytes;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;
    use x_wing::{Ciphertext, Decapsulate, Kem, KeyExport, XWingKem};
    use x25519_dalek::{EphemeralSecret, PublicKey};

    struct CountingUpstream {
        executions: Arc<AtomicUsize>,
    }

    async fn spawn_test_upstream(router: Router) -> url::Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        url::Url::parse(&format!("http://{address}")).unwrap()
    }

    impl ProtectedUpstream for CountingUpstream {
        fn forward(&self, request: ApplicationRequest) -> ProtectedFuture<'_> {
            self.executions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                ApplicationResponse {
                    status: StatusCode::CREATED.as_u16(),
                    headers: HashMap::new(),
                    body: request.body,
                    error: None,
                }
            })
        }
    }

    #[test]
    fn upstream_urls_remain_origin_relative() {
        let base = url::Url::parse("http://127.0.0.1:8083").unwrap();
        assert!(upstream_url(&base, "/ok?q=1").is_ok());
        assert!(upstream_url(&base, "//attacker.example/x").is_err());
        assert!(upstream_url(&base, "https://attacker.example").is_err());
    }

    #[tokio::test]
    async fn protected_response_body_is_bounded() {
        let mut accepted = reqwest::Response::from(
            axum::http::Response::builder()
                .body(reqwest::Body::from(vec![1, 2, 3, 4]))
                .unwrap(),
        );
        assert_eq!(
            read_protected_response_body(&mut accepted, 4)
                .await
                .unwrap(),
            Some(vec![1, 2, 3, 4])
        );

        let mut rejected = reqwest::Response::from(
            axum::http::Response::builder()
                .body(reqwest::Body::from(vec![1, 2, 3, 4, 5]))
                .unwrap(),
        );
        assert!(matches!(
            read_protected_response_body(&mut rejected, 4).await,
            Err(ProtectedResponseBodyError::TooLarge)
        ));

        let mut streamed = Vec::new();
        append_protected_response_chunk(&mut streamed, &[1, 2], 4).unwrap();
        append_protected_response_chunk(&mut streamed, &[3, 4], 4).unwrap();
        assert!(matches!(
            append_protected_response_chunk(&mut streamed, &[5], 4),
            Err(ProtectedResponseBodyError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn protected_upstream_requests_identity_and_accepts_identity_responses() {
        let upstream = Router::new()
            .route(
                "/accepted",
                axum::routing::get(|headers: HeaderMap| async move {
                    headers
                        .get(header::ACCEPT_ENCODING)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("missing")
                        .to_string()
                }),
            )
            .route(
                "/identity",
                axum::routing::get(|| async {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_ENCODING, "identity")
                        .header(header::CONTENT_LENGTH, 8)
                        .body(Body::from("identity"))
                        .unwrap()
                }),
            );
        let upstream_url = spawn_test_upstream(upstream).await;
        let client = enclave_http_client().unwrap();

        let accepted = forward_protected_http(
            &client,
            &upstream_url,
            ApplicationRequest {
                method: "GET".to_string(),
                path: "/accepted".to_string(),
                headers: HashMap::from([(
                    "accept-encoding".to_string(),
                    "attacker-controlled".to_string(),
                )]),
                body: None,
            },
        )
        .await;
        assert_eq!(accepted.status, StatusCode::OK.as_u16());
        assert_eq!(accepted.body.as_deref(), Some(b"identity".as_slice()));

        let identity = forward_protected_http(
            &client,
            &upstream_url,
            ApplicationRequest {
                method: "GET".to_string(),
                path: "/identity".to_string(),
                headers: HashMap::new(),
                body: None,
            },
        )
        .await;
        assert_eq!(identity.status, StatusCode::OK.as_u16());
        assert_eq!(identity.body.as_deref(), Some(b"identity".as_slice()));
        assert!(!identity.headers.contains_key("content-encoding"));
        assert!(!identity.headers.contains_key("content-length"));
    }

    #[tokio::test]
    async fn protected_upstream_rejects_non_identity_content_encodings() {
        let upstream = Router::new().route(
            "/{encoding}",
            axum::routing::get(
                |axum::extract::Path(encoding): axum::extract::Path<String>| async move {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_ENCODING, encoding)
                        .body(Body::from("encoded"))
                        .unwrap()
                },
            ),
        );
        let upstream_url = spawn_test_upstream(upstream).await;
        let client = enclave_http_client().unwrap();
        for encoding in ["gzip", "br", "deflate", "zstd", "compress%2C%20identity"] {
            let response = forward_protected_http(
                &client,
                &upstream_url,
                ApplicationRequest {
                    method: "GET".to_string(),
                    path: format!("/{encoding}"),
                    headers: HashMap::new(),
                    body: None,
                },
            )
            .await;

            assert_eq!(response.status, StatusCode::BAD_GATEWAY.as_u16());
            assert_eq!(
                response.error.as_deref(),
                Some("unsupported upstream content encoding")
            );
            assert!(response.body.is_none());
        }
    }

    #[tokio::test]
    async fn attested_session_confirms_proxies_and_rejects_replay() {
        let executions = Arc::new(AtomicUsize::new(0));
        let fake = Arc::new(FakeAttestationProvider::default());
        let provider: Arc<dyn AttestationProvider> = fake.clone();
        let protected_upstream: Arc<dyn ProtectedUpstream> = Arc::new(CountingUpstream {
            executions: Arc::clone(&executions),
        });
        let app = build_router_with_components(
            ServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                upstream_url: url::Url::parse("http://127.0.0.1:8083").unwrap(),
                cors_origins: None,
                key_exchange: KeyExchangeSuite::X25519,
            },
            provider,
            protected_upstream,
        )
        .unwrap();

        let v1 = send_cbor(&app, "/e2p/v1/create_shared_key", &serde_json::json!({})).await;
        assert_eq!(v1.status(), StatusCode::NOT_FOUND);

        let non_contributory = send_cbor(
            &app,
            "/e2p/v2/session",
            &SessionRequest {
                version: VERSION,
                key_exchange: KeyExchangeSuite::X25519,
                client_nonce: vec![7; 32],
                client_key_material: vec![0; 32],
                context_hash: vec![8; 32],
            },
        )
        .await;
        assert_eq!(non_contributory.status(), StatusCode::BAD_REQUEST);
        assert!(fake.last_call().is_none());

        let client_nonce = [7u8; 32];
        let context_hash = [8u8; 32];
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret).to_bytes();
        let response = send_cbor(
            &app,
            "/e2p/v2/session",
            &SessionRequest {
                version: VERSION,
                key_exchange: KeyExchangeSuite::X25519,
                client_nonce: client_nonce.to_vec(),
                client_key_material: client_public.to_vec(),
                context_hash: context_hash.to_vec(),
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let session_response: SessionResponse = decode_response(response).await;
        assert_eq!(
            session_response.attestation_document,
            b"fake-nitro-attestation-document"
        );
        assert_eq!(session_response.key_exchange, KeyExchangeSuite::X25519);

        let session_id = fixed::<16>(&session_response.session_id).unwrap();
        let server_public = fixed::<32>(&session_response.server_key_material).unwrap();
        let transcript = build_transcript(
            KeyExchangeSuite::X25519,
            &client_nonce,
            &client_public,
            &server_public,
            &session_id,
            &context_hash,
        )
        .unwrap();
        let transcript_hash = transcript_hash(&transcript);
        let shared = client_secret
            .diffie_hellman(&PublicKey::from(server_public))
            .to_bytes();
        let secrets = derive_secrets(&shared, &transcript_hash).unwrap();

        let (attested_nonce, user_data) = fake.last_call().unwrap();
        assert_eq!(attested_nonce, client_nonce);
        let binding: AttestedBinding = serde_json::from_slice(&user_data).unwrap();
        let expected_binding = AttestedBinding::new(
            KeyExchangeSuite::X25519,
            &session_id,
            &transcript_hash,
            secrets.binder(),
        );
        assert_eq!(binding.protocol, expected_binding.protocol);
        assert_eq!(binding.key_exchange, expected_binding.key_exchange);
        assert_eq!(binding.session_id, expected_binding.session_id);
        assert_eq!(binding.transcript_hash, expected_binding.transcript_hash);
        assert_eq!(binding.binder, expected_binding.binder);

        let unconfirmed_plaintext = encode_cbor(&ApplicationRequest {
            method: "POST".to_string(),
            path: "/once".to_string(),
            headers: HashMap::new(),
            body: Some(b"one".to_vec()),
        })
        .unwrap();
        let unconfirmed_ciphertext = secrets
            .seal(
                Direction::ClientToServer,
                MessageType::Application,
                &session_id,
                1,
                &unconfirmed_plaintext,
            )
            .unwrap();
        let unconfirmed = send_cbor(
            &app,
            "/e2p/v2/request",
            &Envelope {
                version: VERSION,
                session_id: session_id.to_vec(),
                sequence: 1u64.to_be_bytes().to_vec(),
                ciphertext: unconfirmed_ciphertext,
            },
        )
        .await;
        assert_eq!(unconfirmed.status(), StatusCode::TOO_EARLY);

        let confirmation = secrets
            .seal(
                Direction::ClientToServer,
                MessageType::Confirmation,
                &session_id,
                0,
                &transcript_hash,
            )
            .unwrap();
        let response = send_cbor(
            &app,
            "/e2p/v2/confirm",
            &Envelope {
                version: VERSION,
                session_id: session_id.to_vec(),
                sequence: 0u64.to_be_bytes().to_vec(),
                ciphertext: confirmation,
            },
        )
        .await;
        let confirmation_response: Envelope = decode_response(response).await;
        let confirmed_hash = secrets
            .open(
                Direction::ServerToClient,
                MessageType::Confirmation,
                &session_id,
                0,
                &confirmation_response.ciphertext,
            )
            .unwrap();
        assert_eq!(confirmed_hash, transcript_hash);

        let application_ciphertext = secrets
            .seal(
                Direction::ClientToServer,
                MessageType::Application,
                &session_id,
                1,
                &unconfirmed_plaintext,
            )
            .unwrap();
        let application_envelope = Envelope {
            version: VERSION,
            session_id: session_id.to_vec(),
            sequence: 1u64.to_be_bytes().to_vec(),
            ciphertext: application_ciphertext,
        };
        let response = send_cbor(&app, "/e2p/v2/request", &application_envelope).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response_envelope: Envelope = decode_response(response).await;
        let response_plaintext = secrets
            .open(
                Direction::ServerToClient,
                MessageType::Application,
                &session_id,
                1,
                &response_envelope.ciphertext,
            )
            .unwrap();
        let application_response: ApplicationResponse = decode_cbor(&response_plaintext).unwrap();
        assert_eq!(application_response.status, StatusCode::CREATED.as_u16());
        assert_eq!(
            application_response.body.as_deref(),
            Some(b"one".as_slice())
        );

        let replay = send_cbor(&app, "/e2p/v2/request", &application_envelope).await;
        assert_eq!(replay.status(), StatusCode::CONFLICT);
        assert_eq!(executions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn full_session_store_rejects_before_key_exchange_or_attestation() {
        let fake = Arc::new(FakeAttestationProvider::default());
        let provider: Arc<dyn AttestationProvider> = fake.clone();
        let app = build_router_with_components_and_store(
            ServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                upstream_url: url::Url::parse("http://127.0.0.1:8083").unwrap(),
                cors_origins: None,
                key_exchange: KeyExchangeSuite::X25519,
            },
            provider,
            Arc::new(CountingUpstream {
                executions: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(SessionStore::new(0)),
        )
        .unwrap();

        let response = send_cbor(
            &app,
            "/e2p/v2/session",
            &SessionRequest {
                version: VERSION,
                key_exchange: KeyExchangeSuite::X25519,
                client_nonce: vec![7; NONCE_LEN],
                // Non-contributory, so BAD_REQUEST would prove the KEM ran
                // before the zero-capacity SessionStore rejected admission.
                client_key_material: vec![0; X25519_KEY_MATERIAL_LEN],
                context_hash: vec![8; CONTEXT_HASH_LEN],
            },
        )
        .await;

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(fake.last_call().is_none());
    }

    #[tokio::test]
    async fn ninth_concurrent_key_exchange_gets_capacity_without_losing_reservations() {
        let fake = Arc::new(FakeAttestationProvider::default());
        let sessions = Arc::new(SessionStore::new(9));
        let existing_reservations = (0..MAX_CONCURRENT_KEY_EXCHANGES)
            .map(|_| sessions.reserve().unwrap())
            .collect::<Vec<_>>();
        let kem_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_KEY_EXCHANGES));
        let _active_kems = (0..MAX_CONCURRENT_KEY_EXCHANGES)
            .map(|_| Arc::clone(&kem_slots).try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        let state = Arc::new(AppState {
            attestation: fake.clone(),
            attestation_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_ATTESTATIONS)),
            kem_slots,
            sessions: Arc::clone(&sessions),
            key_exchange: KeyExchangeSuite::X25519,
            http_client: enclave_http_client().unwrap(),
            upstream_url: url::Url::parse("http://127.0.0.1:8083").unwrap(),
            protected_upstream: Arc::new(CountingUpstream {
                executions: Arc::new(AtomicUsize::new(0)),
            }),
        });
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let request_body = encode_cbor(&SessionRequest {
            version: VERSION,
            key_exchange: KeyExchangeSuite::X25519,
            client_nonce: vec![7; NONCE_LEN],
            client_key_material: PublicKey::from(&client_secret).to_bytes().to_vec(),
            context_hash: vec![8; CONTEXT_HASH_LEN],
        })
        .unwrap();
        let request = Request::builder().body(Body::from(request_body)).unwrap();

        assert!(matches!(
            create_session(State(state), request).await,
            Err(ApiError::Capacity)
        ));
        assert!(fake.last_call().is_none());

        // The failed ninth request released only its own store reservation.
        let replacement_ninth = sessions.reserve().unwrap();
        assert!(matches!(sessions.reserve(), Err(SessionError::Capacity)));
        drop(replacement_ninth);
        drop(existing_reservations);
    }

    #[tokio::test]
    async fn xwing_session_interoperates_and_binds_the_selected_suite() {
        let fake = Arc::new(FakeAttestationProvider::default());
        let provider: Arc<dyn AttestationProvider> = fake.clone();
        let app = build_router_with_components(
            ServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                upstream_url: url::Url::parse("http://127.0.0.1:8083").unwrap(),
                cors_origins: None,
                key_exchange: KeyExchangeSuite::XWingDraft10,
            },
            provider,
            Arc::new(CountingUpstream {
                executions: Arc::new(AtomicUsize::new(0)),
            }),
        )
        .unwrap();
        let (client_secret, client_public) = XWingKem::generate_keypair();
        let client_key_material = client_public.to_bytes();
        let client_nonce = [7u8; NONCE_LEN];
        let context_hash = [8u8; CONTEXT_HASH_LEN];

        let response = send_cbor(
            &app,
            "/e2p/v2/session",
            &SessionRequest {
                version: VERSION,
                key_exchange: KeyExchangeSuite::XWingDraft10,
                client_nonce: client_nonce.to_vec(),
                client_key_material: client_key_material.to_vec(),
                context_hash: context_hash.to_vec(),
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let session_response: SessionResponse = decode_response(response).await;
        assert_eq!(
            session_response.key_exchange,
            KeyExchangeSuite::XWingDraft10
        );
        assert_eq!(
            client_key_material.len(),
            KeyExchangeSuite::XWingDraft10.client_key_material_len()
        );
        assert_eq!(
            session_response.server_key_material.len(),
            KeyExchangeSuite::XWingDraft10.server_key_material_len()
        );

        let ciphertext: Ciphertext = session_response
            .server_key_material
            .as_slice()
            .try_into()
            .unwrap();
        let mut shared_secret = client_secret.decapsulate(&ciphertext);
        let session_id = fixed::<SESSION_ID_LEN>(&session_response.session_id).unwrap();
        let transcript = build_transcript(
            KeyExchangeSuite::XWingDraft10,
            &client_nonce,
            &client_key_material,
            &session_response.server_key_material,
            &session_id,
            &context_hash,
        )
        .unwrap();
        let transcript_hash = transcript_hash(&transcript);
        let secrets = derive_secrets(shared_secret.as_ref(), &transcript_hash).unwrap();
        shared_secret.zeroize();

        let (attested_nonce, user_data) = fake.last_call().unwrap();
        assert_eq!(attested_nonce, client_nonce);
        let binding: AttestedBinding = serde_json::from_slice(&user_data).unwrap();
        assert_eq!(binding.key_exchange, KeyExchangeSuite::XWingDraft10);
        assert_eq!(
            binding.transcript_hash,
            AttestedBinding::new(
                KeyExchangeSuite::XWingDraft10,
                &session_id,
                &transcript_hash,
                secrets.binder(),
            )
            .transcript_hash
        );

        let confirmation = secrets
            .seal(
                Direction::ClientToServer,
                MessageType::Confirmation,
                &session_id,
                0,
                &transcript_hash,
            )
            .unwrap();
        let response = send_cbor(
            &app,
            "/e2p/v2/confirm",
            &Envelope {
                version: VERSION,
                session_id: session_id.to_vec(),
                sequence: 0u64.to_be_bytes().to_vec(),
                ciphertext: confirmation,
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[derive(Serialize)]
    struct RequestWithStringSuite {
        version: u8,
        key_exchange: String,
        #[serde(with = "serde_bytes")]
        client_nonce: Vec<u8>,
        #[serde(with = "serde_bytes")]
        client_key_material: Vec<u8>,
        #[serde(with = "serde_bytes")]
        context_hash: Vec<u8>,
    }

    #[tokio::test]
    async fn session_rejects_downgrades_malformed_inputs_and_oversized_bodies_uniformly() {
        let fake = Arc::new(FakeAttestationProvider::default());
        let app = build_router_with_components(
            ServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                upstream_url: url::Url::parse("http://127.0.0.1:8083").unwrap(),
                cors_origins: None,
                key_exchange: KeyExchangeSuite::XWingDraft10,
            },
            fake.clone(),
            Arc::new(CountingUpstream {
                executions: Arc::new(AtomicUsize::new(0)),
            }),
        )
        .unwrap();

        let downgrade = send_cbor(
            &app,
            "/e2p/v2/session",
            &SessionRequest {
                version: VERSION,
                key_exchange: KeyExchangeSuite::X25519,
                client_nonce: vec![1; NONCE_LEN],
                client_key_material: vec![2; X25519_KEY_MATERIAL_LEN],
                context_hash: vec![3; CONTEXT_HASH_LEN],
            },
        )
        .await;
        let unknown_suite = send_cbor(
            &app,
            "/e2p/v2/session",
            &RequestWithStringSuite {
                version: VERSION,
                key_exchange: "XWING-DRAFT11".to_string(),
                client_nonce: vec![1; NONCE_LEN],
                client_key_material: vec![
                    2;
                    KeyExchangeSuite::XWingDraft10.client_key_material_len()
                ],
                context_hash: vec![3; CONTEXT_HASH_LEN],
            },
        )
        .await;
        let wrong_size = send_cbor(
            &app,
            "/e2p/v2/session",
            &SessionRequest {
                version: VERSION,
                key_exchange: KeyExchangeSuite::XWingDraft10,
                client_nonce: vec![1; NONCE_LEN],
                client_key_material: vec![
                    2;
                    KeyExchangeSuite::XWingDraft10.client_key_material_len()
                        - 1
                ],
                context_hash: vec![3; CONTEXT_HASH_LEN],
            },
        )
        .await;
        let invalid_ml_kem_key = send_cbor(
            &app,
            "/e2p/v2/session",
            &SessionRequest {
                version: VERSION,
                key_exchange: KeyExchangeSuite::XWingDraft10,
                client_nonce: vec![1; NONCE_LEN],
                // 12-bit ML-KEM coefficients of 0xfff are non-canonical.
                client_key_material: vec![
                    0xff;
                    KeyExchangeSuite::XWingDraft10.client_key_material_len()
                ],
                context_hash: vec![3; CONTEXT_HASH_LEN],
            },
        )
        .await;
        let oversized = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/e2p/v2/session")
                    .header(header::CONTENT_TYPE, "application/cbor")
                    .body(Body::from(vec![0u8; MAX_SESSION_BODY_BYTES + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();

        for response in [
            downgrade,
            unknown_suite,
            wrong_size,
            invalid_ml_kem_key,
            oversized,
        ] {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = to_bytes(response.into_body(), MAX_SESSION_BODY_BYTES)
                .await
                .unwrap();
            assert_eq!(body, r#"{"error":"protocol_error"}"#);
        }
        assert!(fake.last_call().is_none());
    }

    fn try_test_router(cors_origins: Option<String>) -> Result<Router, BoxError> {
        build_router_with_components(
            ServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                upstream_url: url::Url::parse("http://127.0.0.1:8083").unwrap(),
                cors_origins,
                key_exchange: KeyExchangeSuite::X25519,
            },
            Arc::new(FakeAttestationProvider::default()),
            Arc::new(CountingUpstream {
                executions: Arc::new(AtomicUsize::new(0)),
            }),
        )
    }

    fn test_router(cors_origins: Option<String>) -> Router {
        try_test_router(cors_origins).unwrap()
    }

    #[test]
    fn key_exchange_configuration_defaults_to_x25519_and_rejects_unknown_values() {
        assert_eq!(
            parse_configured_key_exchange(Err(std::env::VarError::NotPresent)).unwrap(),
            KeyExchangeSuite::X25519
        );
        assert_eq!(
            parse_configured_key_exchange(Ok("XWING-DRAFT10".to_string())).unwrap(),
            KeyExchangeSuite::XWingDraft10
        );
        assert!(parse_configured_key_exchange(Ok("x25519".to_string())).is_err());
        assert!(parse_configured_key_exchange(Ok(String::new())).is_err());
    }

    #[tokio::test]
    async fn cors_is_scoped_to_v2_endpoints() {
        let app = test_router(Some("https://app.example".to_string()));
        for endpoint in ["/e2p/v2/session", "/e2p/v2/confirm", "/e2p/v2/request"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::OPTIONS)
                        .uri(endpoint)
                        .header(header::ORIGIN, "https://app.example")
                        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
                Some(&HeaderValue::from_static("https://app.example"))
            );
            assert_eq!(
                response.headers().get(header::ACCESS_CONTROL_ALLOW_METHODS),
                Some(&HeaderValue::from_static("POST"))
            );
            assert_eq!(
                response.headers().get(header::ACCESS_CONTROL_ALLOW_HEADERS),
                Some(&HeaderValue::from_static("content-type"))
            );

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(endpoint)
                        .header(header::ORIGIN, "https://app.example")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
                Some(&HeaderValue::from_static("https://app.example"))
            );
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/data")
                    .header(header::ORIGIN, "https://app.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/e2p/v2/session")
                    .header(header::ORIGIN, "https://other.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }

    #[tokio::test]
    async fn plaintext_upstream_cors_headers_are_preserved() {
        let upstream = Router::new().route(
            "/data",
            axum::routing::get(|| async {
                (
                    [(
                        header::ACCESS_CONTROL_ALLOW_ORIGIN,
                        "https://upstream.example",
                    )],
                    "ok",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });

        let app = build_router_with_components(
            ServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                upstream_url: url::Url::parse(&format!("http://{address}")).unwrap(),
                cors_origins: Some("https://app.example".to_string()),
                key_exchange: KeyExchangeSuite::X25519,
            },
            Arc::new(FakeAttestationProvider::default()),
            Arc::new(CountingUpstream {
                executions: Arc::new(AtomicUsize::new(0)),
            }),
        )
        .unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/data")
                    .header(header::ORIGIN, "https://app.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&HeaderValue::from_static("https://upstream.example"))
        );
    }

    #[tokio::test]
    async fn plaintext_forwarding_preserves_content_encoding() {
        let encoded_body = vec![0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03];
        let upstream = Router::new().route(
            "/compressed",
            axum::routing::get({
                let encoded_body = encoded_body.clone();
                move |headers: HeaderMap| {
                    let encoded_body = encoded_body.clone();
                    async move {
                        assert_eq!(
                            headers.get(header::ACCEPT_ENCODING),
                            Some(&HeaderValue::from_static("gzip"))
                        );
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_ENCODING, "gzip")
                            .body(Body::from(encoded_body))
                            .unwrap()
                    }
                }
            }),
        );
        let upstream_url = spawn_test_upstream(upstream).await;
        let app = build_router_with_components(
            ServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                upstream_url,
                cors_origins: None,
                key_exchange: KeyExchangeSuite::X25519,
            },
            Arc::new(FakeAttestationProvider::default()),
            Arc::new(CountingUpstream {
                executions: Arc::new(AtomicUsize::new(0)),
            }),
        )
        .unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/compressed")
                    .header(header::ACCEPT_ENCODING, "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_ENCODING),
            Some(&HeaderValue::from_static("gzip"))
        );
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            encoded_body
        );
    }

    #[tokio::test]
    async fn plaintext_forwarding_preserves_repeated_headers_and_filters_framing() {
        let upstream = Router::new().route(
            "/headers",
            axum::routing::get(|headers: HeaderMap| async move {
                let request_values = headers
                    .get_all("x-repeat")
                    .iter()
                    .map(|value| value.to_str().unwrap())
                    .collect::<Vec<_>>()
                    .join(",");
                let mut response = Response::new(Body::from(request_values));
                response
                    .headers_mut()
                    .append("x-repeat-response", HeaderValue::from_static("one"));
                response
                    .headers_mut()
                    .append("x-repeat-response", HeaderValue::from_static("two"));
                response
                    .headers_mut()
                    .append(header::SET_COOKIE, HeaderValue::from_static("a=1"));
                response
                    .headers_mut()
                    .append(header::SET_COOKIE, HeaderValue::from_static("b=2"));
                response
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("close"));
                response
            }),
        );
        let upstream_url = spawn_test_upstream(upstream).await;
        let app = build_router_with_components(
            ServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                upstream_url,
                cors_origins: None,
                key_exchange: KeyExchangeSuite::X25519,
            },
            Arc::new(FakeAttestationProvider::default()),
            Arc::new(CountingUpstream {
                executions: Arc::new(AtomicUsize::new(0)),
            }),
        )
        .unwrap();
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/headers")
            .body(Body::empty())
            .unwrap();
        request
            .headers_mut()
            .append("x-repeat", HeaderValue::from_static("first"));
        request
            .headers_mut()
            .append("x-repeat", HeaderValue::from_static("second"));

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get_all("x-repeat-response")
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["a=1", "b=2"]
        );
        assert!(!response.headers().contains_key(header::CONNECTION));
        assert!(!response.headers().contains_key(header::TRANSFER_ENCODING));
        assert!(!forwardable_header("content-length"));
        if let Some(content_length) = response.headers().get(header::CONTENT_LENGTH) {
            assert_eq!(content_length, HeaderValue::from_static("12"));
        }
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            "first,second"
        );
    }

    #[tokio::test]
    async fn cors_origin_configuration_is_strict() {
        let trailing_comma_error =
            try_test_router(Some("https://app.example,".to_string())).unwrap_err();
        assert_eq!(
            trailing_comma_error.to_string(),
            "STEVE_CORS_ORIGINS contains an empty origin entry"
        );

        let wildcard_error = try_test_router(Some("*".to_string())).unwrap_err();
        assert_eq!(
            wildcard_error.to_string(),
            "STEVE_CORS_ORIGINS requires explicit origins; '*' is not allowed"
        );

        for invalid in [
            "",
            " ",
            "*,https://app.example",
            "https://app.example/path",
            "https://user@app.example",
            "ftp://app.example",
            "null",
        ] {
            assert!(
                try_test_router(Some(invalid.to_string())).is_err(),
                "{invalid:?} should be rejected"
            );
        }

        assert!(
            try_test_router(Some(
                "https://app.example/, http://localhost:3000, https://app.example".to_string()
            ))
            .is_ok()
        );
    }

    #[tokio::test]
    async fn passthrough_rejects_oversized_body() {
        let app = test_router(None);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/upload")
                    .body(Body::from(vec![0u8; MAX_UNENCRYPTED_BODY_BYTES + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn metadata_reports_protocol_version_without_verifying_key() {
        let path = std::env::temp_dir().join(format!(
            "steve-metadata-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path_str = path.to_str().unwrap();
        write_metadata_to(path_str, KeyExchangeSuite::XWingDraft10).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["e2p_protocol_version"], 2);
        assert_eq!(value["e2p_key_exchange"], "XWING-DRAFT10");
        assert_eq!(value.as_object().unwrap().len(), 2);
        assert!(value.get("verifying_key").is_none());
        // create_new must refuse to clobber an existing file
        assert!(write_metadata_to(path_str, KeyExchangeSuite::XWingDraft10).is_err());
        std::fs::remove_file(&path).unwrap();
    }

    async fn send_cbor<T: Serialize>(app: &Router, path: &str, value: &T) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/cbor")
                    .body(Body::from(encode_cbor(value).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn decode_response<T: serde::de::DeserializeOwned>(response: Response) -> T {
        let body = to_bytes(response.into_body(), MAX_ENVELOPE_BYTES)
            .await
            .unwrap();
        decode_cbor(&body).unwrap()
    }
}
