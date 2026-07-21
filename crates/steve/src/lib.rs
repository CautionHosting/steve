pub mod attestation;
pub mod protocol;
pub mod sessions;

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use attestation::{AttestationProvider, NitroAttestationProvider};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use protocol::{
    AttestedBinding, CONTEXT_HASH_LEN, Envelope, KEY_LEN, NONCE_LEN, ProtocolError, SESSION_ID_LEN,
    SessionRequest, SessionResponse, VERSION, build_transcript, decode_cbor, derive_secrets,
    encode_cbor, fixed, transcript_hash,
};
use rand::{RngCore, rngs::OsRng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sessions::{CLEANUP_INTERVAL, PENDING_TTL, Session, SessionError, SessionStore};
use tokio::{sync::Semaphore, task};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{debug, error, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

const DEFAULT_APP_UPSTREAM: &str = "http://127.0.0.1:8083";
const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:49500";
const MAX_ENVELOPE_BYTES: usize = 32 * 1024 * 1024;
const MAX_UNENCRYPTED_BODY_BYTES: usize = 1024 * 1024;
const MAX_CONCURRENT_ATTESTATIONS: usize = 8;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub upstream_url: url::Url,
    pub cors_origins: Option<String>,
}

/// Enclave metadata surfaced by bootproofd as attestation `user_data`.
///
/// E2P v2 binds attestation to sessions directly, so there is no persistent
/// `verifying_key` anymore; the protocol version tells consumers the v1 key
/// channel is intentionally gone.
#[derive(Debug, Serialize)]
struct MetadataOutput {
    e2p_protocol_version: u32,
}

/// Write enclave metadata to `E2P_METADATA_FILE` (default `/metadata.json`)
/// for bootproofd to embed as attestation `user_data`.
pub fn write_metadata() -> Result<(), BoxError> {
    let metadata_path =
        std::env::var("E2P_METADATA_FILE").unwrap_or_else(|_| String::from("/metadata.json"));
    write_metadata_to(&metadata_path)
}

fn write_metadata_to(metadata_path: &str) -> Result<(), BoxError> {
    let metadata = MetadataOutput {
        e2p_protocol_version: 2,
    };
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
        })
    }
}

struct AppState {
    attestation: Arc<dyn AttestationProvider>,
    attestation_slots: Arc<Semaphore>,
    sessions: Arc<SessionStore>,
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
        sessions,
        http_client: enclave_http_client()?,
        upstream_url: config.upstream_url,
        protected_upstream,
    });

    let app = Router::new()
        .route("/e2p/v2/session", post(create_session))
        .route("/e2p/v2/confirm", post(confirm_session))
        .route("/e2p/v2/request", post(protected_request))
        .fallback(fallback)
        .layer(DefaultBodyLimit::max(MAX_ENVELOPE_BYTES))
        .with_state(state);

    if let Some(origins) = config.cors_origins {
        let allow_origin = if origins.trim() == "*" {
            AllowOrigin::any()
        } else {
            let values = origins
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .map(str::parse)
                .collect::<Result<Vec<_>, _>>()?;
            if values.is_empty() {
                return Err("STEVE_CORS_ORIGINS contains no origins".into());
            }
            AllowOrigin::list(values)
        };
        Ok(app.layer(
            CorsLayer::new()
                .allow_origin(allow_origin)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE]),
        ))
    } else {
        Ok(app)
    }
}

fn enclave_http_client() -> Result<Client, reqwest::Error> {
    // The enclave must never inherit host proxy configuration for its local upstream hop.
    Client::builder().no_proxy().build()
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    if body.len() > MAX_ENVELOPE_BYTES {
        return Err(ApiError::Malformed);
    }
    let request: SessionRequest = decode_cbor(&body).map_err(ApiError::from)?;
    if request.version != VERSION {
        return Err(ApiError::Malformed);
    }
    let client_nonce = fixed::<NONCE_LEN>(&request.client_nonce).map_err(ApiError::from)?;
    let client_public_key = fixed::<KEY_LEN>(&request.client_public_key).map_err(ApiError::from)?;
    let context_hash = fixed::<CONTEXT_HASH_LEN>(&request.context_hash).map_err(ApiError::from)?;

    let client_public_key = PublicKey::from(client_public_key);
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_public_key = PublicKey::from(&server_secret).to_bytes();
    let shared_secret = server_secret.diffie_hellman(&client_public_key);
    if !shared_secret.was_contributory() {
        return Err(ApiError::Malformed);
    }
    let shared_secret = Zeroizing::new(shared_secret.to_bytes());
    let mut session_id = [0u8; SESSION_ID_LEN];
    OsRng.fill_bytes(&mut session_id);

    let transcript = build_transcript(
        &client_nonce,
        client_public_key.as_bytes(),
        &server_public_key,
        &session_id,
        &context_hash,
    );
    let transcript_hash = transcript_hash(&transcript);
    let secrets = derive_secrets(&shared_secret, &transcript_hash).map_err(ApiError::from)?;
    let user_data = serde_json::to_vec(&AttestedBinding::new(
        &session_id,
        &transcript_hash,
        secrets.binder(),
    ))
    .map_err(|_| ApiError::Internal)?;

    let reservation = state.sessions.reserve().map_err(ApiError::from)?;
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
        session_id: session_id.to_vec(),
        server_public_key: server_public_key.to_vec(),
        attestation_document,
        expires_in_seconds: PENDING_TTL.as_secs() as u32,
    })
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

    let mut builder = client.request(method, url);
    for (name, value) in request.headers {
        if forwardable_header(&name) {
            builder = builder.header(name, value);
        }
    }
    if let Some(body) = request.body {
        builder = builder.body(body);
    }

    let response = match builder.send().await {
        Ok(response) => response,
        Err(error) => {
            warn!(%error, "protected upstream request failed");
            return failure("upstream unavailable");
        }
    };
    let status = response.status().as_u16();
    let headers = response_headers(response.headers());
    let body = match response.bytes().await {
        Ok(body) if body.is_empty() => None,
        Ok(body) => Some(body.to_vec()),
        Err(error) => {
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
    for (name, value) in headers {
        if let Some(name) = name
            && forwardable_header(name.as_str())
        {
            builder = builder.header(name, value);
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
    let mut response = Response::builder().status(status);
    for (name, value) in headers {
        if let Some(name) = name {
            response = response.header(name, value);
        }
    }
    response
        .body(Body::from(body))
        .unwrap_or_else(|_| ApiError::Internal.into_response())
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

fn response_headers(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(name, _)| forwardable_header(name.as_str()))
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
    use x25519_dalek::{EphemeralSecret, PublicKey};

    struct CountingUpstream {
        executions: Arc<AtomicUsize>,
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
                client_nonce: vec![7; 32],
                client_public_key: vec![0; 32],
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
                client_nonce: client_nonce.to_vec(),
                client_public_key: client_public.to_vec(),
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

        let session_id = fixed::<16>(&session_response.session_id).unwrap();
        let server_public = fixed::<32>(&session_response.server_public_key).unwrap();
        let transcript = build_transcript(
            &client_nonce,
            &client_public,
            &server_public,
            &session_id,
            &context_hash,
        );
        let transcript_hash = transcript_hash(&transcript);
        let shared = client_secret
            .diffie_hellman(&PublicKey::from(server_public))
            .to_bytes();
        let secrets = derive_secrets(&shared, &transcript_hash).unwrap();

        let (attested_nonce, user_data) = fake.last_call().unwrap();
        assert_eq!(attested_nonce, client_nonce);
        let binding: AttestedBinding = serde_json::from_slice(&user_data).unwrap();
        let expected_binding =
            AttestedBinding::new(&session_id, &transcript_hash, secrets.binder());
        assert_eq!(binding.protocol, expected_binding.protocol);
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
    async fn full_session_store_rejects_before_attestation() {
        let fake = Arc::new(FakeAttestationProvider::default());
        let provider: Arc<dyn AttestationProvider> = fake.clone();
        let app = build_router_with_components_and_store(
            ServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                upstream_url: url::Url::parse("http://127.0.0.1:8083").unwrap(),
                cors_origins: None,
            },
            provider,
            Arc::new(CountingUpstream {
                executions: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(SessionStore::new(0)),
        )
        .unwrap();
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret).to_bytes();

        let response = send_cbor(
            &app,
            "/e2p/v2/session",
            &SessionRequest {
                version: VERSION,
                client_nonce: vec![7; NONCE_LEN],
                client_public_key: client_public.to_vec(),
                context_hash: vec![8; CONTEXT_HASH_LEN],
            },
        )
        .await;

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(fake.last_call().is_none());
    }

    fn test_router(cors_origins: Option<String>) -> Router {
        build_router_with_components(
            ServerConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                upstream_url: url::Url::parse("http://127.0.0.1:8083").unwrap(),
                cors_origins,
            },
            Arc::new(FakeAttestationProvider::default()),
            Arc::new(CountingUpstream {
                executions: Arc::new(AtomicUsize::new(0)),
            }),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn cors_preflight_allows_get() {
        let app = test_router(Some("https://app.example".to_string()));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/data")
                    .header(header::ORIGIN, "https://app.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let allow_methods = response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .expect("preflight should include allow-methods")
            .to_str()
            .unwrap();
        assert!(allow_methods.contains("GET"), "got {allow_methods}");
        assert!(allow_methods.contains("POST"), "got {allow_methods}");
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
        write_metadata_to(path_str).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["e2p_protocol_version"], 2);
        assert!(value.get("verifying_key").is_none());
        // create_new must refuse to clobber an existing file
        assert!(write_metadata_to(path_str).is_err());
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
