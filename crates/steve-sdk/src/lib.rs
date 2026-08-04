//! Native client for STEVE's attestation-bound E2P v2 transport.

mod protocol;

use std::{
    collections::{BTreeSet, HashMap},
    fmt::Debug,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bootproof_sdk::{
    VerifiableSignedAttestationFormat,
    format::nitro::{Nitro, NitroPcrs},
};
use protocol::{
    Direction, Envelope, MessageType, PROTOCOL_ID, ProtocolError, SessionRequest, SessionResponse,
    SessionSecrets, VERSION, build_transcript, decode_cbor, derive_secrets, encode_cbor, fixed,
    transcript_hash,
};
use rand::{RngCore, rngs::OsRng};
use reqwest::{
    Client as HttpClient, Method, StatusCode, Url,
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    sync::{Mutex, oneshot},
    time::timeout,
};
use x_wing::{Ciphertext, Decapsulate, DecapsulationKey, Kem, KeyExport, XWingKem};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, Zeroizing};

pub use bootproof_sdk::format::nitro::NitroPcrs as ExpectedPcrs;

const SESSION_ENDPOINT: &str = "/e2p/v2/session";
const CONFIRM_ENDPOINT: &str = "/e2p/v2/confirm";
const REQUEST_ENDPOINT: &str = "/e2p/v2/request";
const MAX_SESSION_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CONFIRMATION_RESPONSE_BYTES: usize = 4 * 1024;
const MAX_APPLICATION_RESPONSE_BYTES: usize = 32 * 1024 * 1024 + 64 * 1024;
const DEFAULT_SESSION_ROTATION_INTERVAL: Duration = Duration::from_secs(25 * 60);
const DEFAULT_SESSION_ESTABLISHMENT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const REPLAY_WINDOW_SIZE: u128 = 64;
const PCR_SIZE: usize = 48;
const NATIVE_CONTEXT_MAGIC: &[u8] = b"STEVE-E2P-V2-NATIVE\0";

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum KeyExchangeSuite {
    #[serde(rename = "X25519")]
    X25519,
    #[serde(rename = "XWING-DRAFT10")]
    XWingDraft10,
}

impl KeyExchangeSuite {
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::XWingDraft10 => "XWING-DRAFT10",
        }
    }

    pub const fn client_key_material_len(self) -> usize {
        match self {
            Self::X25519 => 32,
            Self::XWingDraft10 => 1_216,
        }
    }

    pub const fn server_key_material_len(self) -> usize {
        match self {
            Self::X25519 => 32,
            Self::XWingDraft10 => 1_120,
        }
    }
}

impl std::fmt::Display for KeyExchangeSuite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_wire())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(#[from] url::ParseError),

    #[error("base URL must have an HTTP(S) origin without credentials")]
    InvalidBaseOrigin,

    #[error("expected PCR {index} is invalid: {reason}")]
    InvalidExpectedPcr { index: u8, reason: &'static str },

    #[error("request path escapes the configured base origin")]
    UrlEscapesBase,

    #[error("invalid HTTP header name: {0}")]
    InvalidHeaderName(#[from] reqwest::header::InvalidHeaderName),

    #[error("invalid HTTP header value: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    #[error("request header value is not valid UTF-8: {0}")]
    RequestHeaderUtf8(String),

    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("{operation} timed out")]
    Timeout { operation: &'static str },

    #[error("{operation} failed with {status}: {body}")]
    ProtocolStatus {
        operation: &'static str,
        status: StatusCode,
        body: String,
    },

    #[error("attestation verification failed: {0}")]
    AttestationVerification(#[from] bootproof_sdk::format::Error),

    #[error("attestation payload is malformed: {0}")]
    MalformedAttestation(&'static str),

    #[error("attestation binding mismatch: {0}")]
    AttestationBinding(&'static str),

    #[error("invalid base64url attestation binding: {0}")]
    AttestationBindingBase64(#[from] base64::DecodeError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("protocol error: {0}")]
    Protocol(&'static str),

    #[error("session is not initialized")]
    SessionNotInitialized,

    #[error("session closed while waiting for a sequence")]
    SessionClosed,

    #[error("session sequence exhausted")]
    SequenceExhausted,

    #[error("unexpected response sequence")]
    UnexpectedSequence,

    #[error("invalid response status from enclave application: {0}")]
    InvalidResponseStatus(u16),
}

impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        let message = match error {
            ProtocolError::InvalidLength => "invalid field length",
            ProtocolError::UnsupportedVersion => "unsupported protocol version",
            ProtocolError::InvalidCbor => "invalid CBOR",
            ProtocolError::KeyDerivation => "key derivation failed",
            ProtocolError::Authentication => "message authentication failed",
        };
        Self::Protocol(message)
    }
}

impl Error {
    fn is_request_local(&self) -> bool {
        match self {
            Self::Http(_) | Self::Timeout { .. } => true,
            Self::ProtocolStatus { status, .. } => {
                matches!(
                    *status,
                    StatusCode::FORBIDDEN
                        | StatusCode::NOT_FOUND
                        | StatusCode::REQUEST_TIMEOUT
                        | StatusCode::TOO_MANY_REQUESTS
                ) || status.is_server_error()
            }
            _ => false,
        }
    }
}

#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    http: HttpClient,
    base_url: Url,
    context_hash: [u8; 32],
    expected_pcrs: NitroPcrs,
    expected_key_exchange: KeyExchangeSuite,
    session_rotation_interval: Duration,
    session_establishment_timeout: Duration,
    request_timeout: Duration,
    attestation_verifier: Arc<dyn AttestationVerifier>,
    bootstrap: Mutex<()>,
    next_generation: AtomicU64,
    state: Mutex<Option<Arc<SessionState>>>,
}

trait AttestationVerifier: Debug + Send + Sync {
    fn verify(
        &self,
        document: &[u8],
        expected_pcrs: &NitroPcrs,
        now: Duration,
        nonce: &[u8; 32],
    ) -> std::result::Result<serde_cbor::Value, bootproof_sdk::format::Error>;
}

#[derive(Debug)]
struct NitroAttestationVerifier;

impl AttestationVerifier for NitroAttestationVerifier {
    fn verify(
        &self,
        document: &[u8],
        expected_pcrs: &NitroPcrs,
        now: Duration,
        nonce: &[u8; 32],
    ) -> std::result::Result<serde_cbor::Value, bootproof_sdk::format::Error> {
        Nitro::new(document, expected_pcrs.clone())?.verify(now, nonce)
    }
}

impl Debug for Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Client")
            .field("base_url", &self.inner.base_url)
            .field(
                "session_rotation_interval",
                &self.inner.session_rotation_interval,
            )
            .field(
                "session_establishment_timeout",
                &self.inner.session_establishment_timeout,
            )
            .field("request_timeout", &self.inner.request_timeout)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationInfo {
    pub session_id: [u8; 16],
    pub module_id: String,
    pub pcrs: NitroPcrs,
}

struct SessionState {
    generation: u64,
    id: [u8; 16],
    secrets: SessionSecrets,
    attestation: AttestationInfo,
    activated_at: Instant,
    sequences: SequenceTracker,
}

#[derive(Default)]
struct SequenceTracker {
    state: StdMutex<SequenceState>,
}

struct SequenceState {
    next: u128,
    pending: BTreeSet<u64>,
    waiters: Vec<oneshot::Sender<()>>,
    closed: bool,
}

impl Default for SequenceState {
    fn default() -> Self {
        Self {
            next: 1,
            pending: BTreeSet::new(),
            waiters: Vec::new(),
            closed: false,
        }
    }
}

impl SequenceTracker {
    async fn allocate(&self) -> Result<u64> {
        loop {
            let receiver = {
                let mut state = self.state.lock().unwrap();
                if state.closed {
                    return Err(Error::SessionClosed);
                }
                let can_allocate = state
                    .pending
                    .first()
                    .is_none_or(|oldest| state.next - u128::from(*oldest) < REPLAY_WINDOW_SIZE);
                if can_allocate {
                    let sequence =
                        u64::try_from(state.next).map_err(|_| Error::SequenceExhausted)?;
                    state.next += 1;
                    state.pending.insert(sequence);
                    return Ok(sequence);
                }

                let (sender, receiver) = oneshot::channel();
                state.waiters.push(sender);
                receiver
            };
            let _ = receiver.await;
        }
    }

    fn accept(&self, expected: u64, received: u64) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(Error::SessionClosed);
        }
        if expected != received || !state.pending.remove(&expected) {
            return Err(Error::UnexpectedSequence);
        }
        wake_waiters(&mut state.waiters);
        Ok(())
    }

    fn retire(&self, sequence: u64) {
        let mut state = self.state.lock().unwrap();
        if !state.closed && state.pending.remove(&sequence) {
            wake_waiters(&mut state.waiters);
        }
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return;
        }
        state.closed = true;
        state.pending.clear();
        wake_waiters(&mut state.waiters);
    }
}

fn wake_waiters(waiters: &mut Vec<oneshot::Sender<()>>) {
    for sender in waiters.drain(..) {
        let _ = sender.send(());
    }
}

pub struct ClientBuilder {
    transport_builder: reqwest::ClientBuilder,
    base_url: Url,
    application_context: Option<Vec<u8>>,
    expected_pcrs: NitroPcrs,
    expected_key_exchange: KeyExchangeSuite,
    session_rotation_interval: Duration,
    session_establishment_timeout: Duration,
    request_timeout: Duration,
    attestation_verifier: Arc<dyn AttestationVerifier>,
}

impl Debug for ClientBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientBuilder")
            .field("base_url", &self.base_url)
            .field("application_context", &self.application_context.is_some())
            .field("expected_pcrs", &self.expected_pcrs)
            .field("expected_key_exchange", &self.expected_key_exchange)
            .field("session_rotation_interval", &self.session_rotation_interval)
            .field(
                "session_establishment_timeout",
                &self.session_establishment_timeout,
            )
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

impl ClientBuilder {
    /// Supply a custom Reqwest builder. Redirects are disabled when the client is built.
    pub fn transport_builder(mut self, builder: reqwest::ClientBuilder) -> Self {
        self.transport_builder = builder;
        self
    }

    /// Add application-specific bytes to the origin-bound native client context.
    pub fn application_context(mut self, context: impl AsRef<[u8]>) -> Self {
        self.application_context = Some(context.as_ref().to_vec());
        self
    }

    /// Pin the process-fixed key exchange suite expected from STEVE.
    ///
    /// X25519 is the default. X-Wing must be selected explicitly; the client
    /// never negotiates or falls back between suites.
    pub fn expected_key_exchange(mut self, suite: KeyExchangeSuite) -> Self {
        self.expected_key_exchange = suite;
        self
    }

    pub fn session_rotation_interval(mut self, interval: Duration) -> Self {
        self.session_rotation_interval = interval;
        self
    }

    pub fn session_establishment_timeout(mut self, duration: Duration) -> Self {
        self.session_establishment_timeout = duration;
        self
    }

    pub fn request_timeout(mut self, duration: Duration) -> Self {
        self.request_timeout = duration;
        self
    }

    pub fn build(self) -> Result<Client> {
        let context_hash = native_context_hash(&self.base_url, self.application_context.as_deref());
        let http = self
            .transport_builder
            .redirect(Policy::none())
            .build()
            .map_err(Error::Http)?;
        Ok(Client {
            inner: Arc::new(Inner {
                http,
                base_url: self.base_url,
                context_hash,
                expected_pcrs: self.expected_pcrs,
                expected_key_exchange: self.expected_key_exchange,
                session_rotation_interval: self.session_rotation_interval,
                session_establishment_timeout: self.session_establishment_timeout,
                request_timeout: self.request_timeout,
                attestation_verifier: self.attestation_verifier,
                bootstrap: Mutex::new(()),
                next_generation: AtomicU64::new(1),
                state: Mutex::new(None),
            }),
        })
    }

    pub async fn connect(self) -> Result<Client> {
        let client = self.build()?;
        client.initialize().await?;
        Ok(client)
    }
}

impl Client {
    pub fn builder(base_url: impl AsRef<str>, expected_pcrs: NitroPcrs) -> Result<ClientBuilder> {
        validate_expected_pcrs(&expected_pcrs)?;
        let base_url = normalize_base_url(base_url.as_ref())?;
        Ok(ClientBuilder {
            transport_builder: HttpClient::builder(),
            base_url,
            application_context: None,
            expected_pcrs,
            expected_key_exchange: KeyExchangeSuite::X25519,
            session_rotation_interval: DEFAULT_SESSION_ROTATION_INTERVAL,
            session_establishment_timeout: DEFAULT_SESSION_ESTABLISHMENT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            attestation_verifier: Arc::new(NitroAttestationVerifier),
        })
    }

    pub async fn new(base_url: impl AsRef<str>, expected_pcrs: NitroPcrs) -> Result<Self> {
        Self::builder(base_url, expected_pcrs)?.connect().await
    }

    pub async fn initialize(&self) -> Result<AttestationInfo> {
        Ok(self.current_session().await?.attestation.clone())
    }

    /// Return the evidence already verified for the current session, initializing it if needed.
    pub async fn verify_attestation(&self) -> Result<AttestationInfo> {
        self.initialize().await
    }

    /// Establish a new attested session and atomically replace the current session.
    ///
    /// A failed reconnect leaves the previous session untouched. Application requests are
    /// never retried by this method.
    pub async fn reconnect(&self) -> Result<AttestationInfo> {
        self.rotate_session().await
    }

    pub async fn rotate_session(&self) -> Result<AttestationInfo> {
        let _bootstrap = self.inner.bootstrap.lock().await;
        let replacement = self.establish_session().await?;
        let attestation = replacement.attestation.clone();
        *self.inner.state.lock().await = Some(replacement);
        Ok(attestation)
    }

    pub fn request(&self, method: Method, path: impl Into<String>) -> RequestBuilder {
        RequestBuilder {
            client: self.clone(),
            method,
            path: path.into(),
            headers: HeaderMap::new(),
            body: None,
        }
    }

    pub fn get(&self, path: impl Into<String>) -> RequestBuilder {
        self.request(Method::GET, path)
    }

    pub fn post(&self, path: impl Into<String>) -> RequestBuilder {
        self.request(Method::POST, path)
    }

    pub fn put(&self, path: impl Into<String>) -> RequestBuilder {
        self.request(Method::PUT, path)
    }

    pub fn delete(&self, path: impl Into<String>) -> RequestBuilder {
        self.request(Method::DELETE, path)
    }

    async fn current_session(&self) -> Result<Arc<SessionState>> {
        if let Some(state) = self.inner.state.lock().await.as_ref()
            && !self.rotation_due(state)
        {
            return Ok(Arc::clone(state));
        }

        let _bootstrap = self.inner.bootstrap.lock().await;
        let current = self.inner.state.lock().await.as_ref().cloned();
        if let Some(current) = &current
            && !self.rotation_due(current)
        {
            return Ok(Arc::clone(current));
        }

        let replacement = self.establish_session().await?;
        let mut state = self.inner.state.lock().await;
        if let (Some(current), Some(latest)) = (&current, state.as_ref())
            && current.generation != latest.generation
        {
            return Ok(Arc::clone(latest));
        }
        *state = Some(Arc::clone(&replacement));
        Ok(replacement)
    }

    fn rotation_due(&self, state: &SessionState) -> bool {
        state.activated_at.elapsed() >= self.inner.session_rotation_interval
    }

    async fn establish_session(&self) -> Result<Arc<SessionState>> {
        timeout(
            self.inner.session_establishment_timeout,
            self.establish_session_within_deadline(),
        )
        .await
        .map_err(|_| Error::Timeout {
            operation: "session establishment",
        })?
    }

    async fn establish_session_within_deadline(&self) -> Result<Arc<SessionState>> {
        let client_nonce = random_array::<32>();
        let key_exchange = self.inner.expected_key_exchange;
        let client_kem = ClientKem::generate(key_exchange);
        let client_key_material = client_kem.key_material().to_vec();
        let request = encode_cbor(&SessionRequest {
            version: VERSION,
            key_exchange,
            client_nonce: client_nonce.to_vec(),
            client_key_material: client_key_material.clone(),
            context_hash: self.inner.context_hash.to_vec(),
        })?;

        let (status, body) = self
            .send_protocol(SESSION_ENDPOINT, request, MAX_SESSION_RESPONSE_BYTES)
            .await?;
        ensure_success("session creation", status, &body)?;
        let response: SessionResponse = decode_cbor(&body)?;
        if response.version != VERSION {
            return Err(Error::Protocol("unsupported session response version"));
        }
        ensure_session_response_suite(key_exchange, response.key_exchange)?;
        if response.expires_in_seconds == 0 {
            return Err(Error::Protocol("invalid pending session expiry"));
        }
        if response.attestation_document.is_empty() {
            return Err(Error::Protocol("empty attestation document"));
        }
        let session_id = fixed::<16>(&response.session_id)?;
        let shared_secret = client_kem.decapsulate(&response.server_key_material)?;
        let transcript = build_transcript(
            key_exchange,
            &client_nonce,
            &client_key_material,
            &response.server_key_material,
            &session_id,
            &self.inner.context_hash,
        );
        let transcript_hash = transcript_hash(&transcript);
        let secrets = derive_secrets(&shared_secret, &transcript_hash)?;
        let attestation = self.verify_session_attestation(
            &response.attestation_document,
            &client_nonce,
            key_exchange,
            &session_id,
            &transcript_hash,
            secrets.binder(),
        )?;

        let confirmation_ciphertext = secrets.seal(
            Direction::ClientToServer,
            MessageType::Confirmation,
            &session_id,
            0,
            &transcript_hash,
        )?;
        let confirmation = encode_cbor(&Envelope {
            version: VERSION,
            session_id: session_id.to_vec(),
            sequence: 0u64.to_be_bytes().to_vec(),
            ciphertext: confirmation_ciphertext,
        })?;
        let (status, body) = self
            .send_protocol(
                CONFIRM_ENDPOINT,
                confirmation,
                MAX_CONFIRMATION_RESPONSE_BYTES,
            )
            .await?;
        ensure_success("session confirmation", status, &body)?;
        let envelope: Envelope = decode_cbor(&body)?;
        let (confirmed_session_id, sequence) = envelope.validate()?;
        if confirmed_session_id != session_id || sequence != 0 {
            return Err(Error::UnexpectedSequence);
        }
        let confirmed_hash = secrets.open(
            Direction::ServerToClient,
            MessageType::Confirmation,
            &session_id,
            0,
            &envelope.ciphertext,
        )?;
        if !constant_time_eq(&confirmed_hash, &transcript_hash) {
            return Err(Error::Protocol("session confirmation mismatch"));
        }

        Ok(Arc::new(SessionState {
            generation: self.inner.next_generation.fetch_add(1, Ordering::Relaxed),
            id: session_id,
            secrets,
            attestation,
            activated_at: Instant::now(),
            sequences: SequenceTracker::default(),
        }))
    }

    fn verify_session_attestation(
        &self,
        document: &[u8],
        client_nonce: &[u8; 32],
        key_exchange: KeyExchangeSuite,
        session_id: &[u8; 16],
        transcript_hash: &[u8; 32],
        binder: &[u8; 32],
    ) -> Result<AttestationInfo> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let payload = self.inner.attestation_verifier.verify(
            document,
            &self.inner.expected_pcrs,
            now,
            client_nonce,
        )?;
        let user_data = extract_bytes(&payload, "user_data")?;
        let binding: AttestedBinding = serde_json::from_slice(user_data)?;
        verify_attested_binding(&binding, key_exchange, session_id, transcript_hash, binder)?;
        Ok(AttestationInfo {
            session_id: *session_id,
            module_id: extract_text(&payload, "module_id")?.to_owned(),
            pcrs: extract_pcrs(&payload)?,
        })
    }

    async fn send_protocol(
        &self,
        endpoint: &'static str,
        body: Vec<u8>,
        max_response_bytes: usize,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let url = self.resolve_url(endpoint)?;
        let mut response = self
            .inner
            .http
            .post(url)
            .header("content-type", "application/cbor")
            .header("cache-control", "no-store")
            .body(body)
            .send()
            .await?;
        ensure_same_origin(&self.inner.base_url, response.url())?;
        let status = response.status();
        let body = read_response_body(&mut response, max_response_bytes).await?;
        Ok((status, body))
    }

    fn resolve_url(&self, path: &str) -> Result<Url> {
        let url = self.inner.base_url.join(path)?;
        ensure_same_origin(&self.inner.base_url, &url)?;
        Ok(url)
    }

    async fn invalidate_generation(&self, generation: u64) {
        let removed = {
            let mut state = self.inner.state.lock().await;
            if state
                .as_ref()
                .is_some_and(|state| state.generation == generation)
            {
                state.take()
            } else {
                None
            }
        };
        if let Some(state) = removed {
            state.sequences.close();
        }
    }
}

async fn read_response_body(response: &mut reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(Error::Protocol("protocol response too large"));
    }

    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or_default();
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(Error::Protocol("protocol response too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub struct RequestBuilder {
    client: Client,
    method: Method,
    path: String,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
}

impl RequestBuilder {
    pub fn header(
        mut self,
        key: impl TryInto<HeaderName, Error = reqwest::header::InvalidHeaderName>,
        value: impl TryInto<HeaderValue, Error = reqwest::header::InvalidHeaderValue>,
    ) -> Result<Self> {
        self.headers.insert(key.try_into()?, value.try_into()?);
        Ok(self)
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn json<T: Serialize>(mut self, value: &T) -> Result<Self> {
        self.body = Some(serde_json::to_vec(value)?);
        self.headers
            .insert("content-type", HeaderValue::from_static("application/json"));
        Ok(self)
    }

    pub async fn send(self) -> Result<Response> {
        let application_url = self.client.resolve_url(&self.path)?;
        let path = match application_url.query() {
            Some(query) => format!("{}?{query}", application_url.path()),
            None => application_url.path().to_owned(),
        };
        let plaintext = encode_cbor(&ApplicationRequest {
            method: self.method.as_str().to_owned(),
            path,
            headers: headers_to_strings(&self.headers)?,
            body: self.body.filter(|body| !body.is_empty()),
        })?;
        let session = self.client.current_session().await?;
        let sequence = session.sequences.allocate().await?;
        let operation = timeout(
            self.client.inner.request_timeout,
            send_application_request(&self.client, &session, sequence, &plaintext),
        )
        .await
        .map_err(|_| Error::Timeout {
            operation: "protected request",
        })
        .and_then(|result| result);

        match operation {
            Ok((response, received_sequence)) => {
                if let Err(error) = session.sequences.accept(sequence, received_sequence) {
                    session.sequences.close();
                    self.client.invalidate_generation(session.generation).await;
                    return Err(error);
                }
                Ok(response)
            }
            Err(error) => {
                if error.is_request_local() {
                    session.sequences.retire(sequence);
                } else {
                    session.sequences.close();
                    self.client.invalidate_generation(session.generation).await;
                }
                Err(error)
            }
        }
    }
}

async fn send_application_request(
    client: &Client,
    session: &SessionState,
    sequence: u64,
    plaintext: &[u8],
) -> Result<(Response, u64)> {
    let ciphertext = session.secrets.seal(
        Direction::ClientToServer,
        MessageType::Application,
        &session.id,
        sequence,
        plaintext,
    )?;
    let envelope = encode_cbor(&Envelope {
        version: VERSION,
        session_id: session.id.to_vec(),
        sequence: sequence.to_be_bytes().to_vec(),
        ciphertext,
    })?;
    let (status, body) = client
        .send_protocol(REQUEST_ENDPOINT, envelope, MAX_APPLICATION_RESPONSE_BYTES)
        .await?;
    ensure_success("protected request", status, &body)?;
    let envelope: Envelope = decode_cbor(&body)?;
    let (response_session_id, response_sequence) = envelope.validate()?;
    if response_session_id != session.id || response_sequence != sequence {
        return Err(Error::UnexpectedSequence);
    }
    let plaintext = session.secrets.open(
        Direction::ServerToClient,
        MessageType::Application,
        &session.id,
        sequence,
        &envelope.ciphertext,
    )?;
    let response: ApplicationResponse = decode_cbor(&plaintext)?;
    Ok((response.try_into()?, response_sequence))
}

#[derive(Debug)]
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Response {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.body
    }

    pub fn text(&self) -> std::result::Result<String, std::str::Utf8Error> {
        std::str::from_utf8(&self.body).map(str::to_owned)
    }

    pub fn json<T: serde::de::DeserializeOwned>(
        &self,
    ) -> std::result::Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

#[derive(Debug, Deserialize)]
struct AttestedBinding {
    protocol: String,
    key_exchange: KeyExchangeSuite,
    session_id: String,
    transcript_hash: String,
    binder: String,
}

#[derive(Debug, Serialize)]
struct ApplicationRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    #[serde(with = "serde_bytes")]
    body: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
struct ApplicationResponse {
    status: u16,
    headers: Vec<(String, String)>,
    #[serde(with = "serde_bytes")]
    body: Option<Vec<u8>>,
    error: Option<String>,
}

impl TryFrom<ApplicationResponse> for Response {
    type Error = Error;

    fn try_from(response: ApplicationResponse) -> Result<Self> {
        if !(200..=599).contains(&response.status) {
            return Err(Error::InvalidResponseStatus(response.status));
        }
        let status = StatusCode::from_u16(response.status)
            .map_err(|_| Error::InvalidResponseStatus(response.status))?;
        let mut headers = HeaderMap::new();
        for (key, value) in response.headers {
            headers.append(HeaderName::try_from(key)?, HeaderValue::try_from(value)?);
        }
        let body = match (response.body, response.error) {
            (Some(body), _) => body,
            (None, Some(error)) => {
                headers
                    .entry("content-type")
                    .or_insert(HeaderValue::from_static("application/json"));
                serde_json::to_vec(&serde_json::json!({ "error": error }))?
            }
            (None, None) => Vec::new(),
        };
        Ok(Self {
            status,
            headers,
            body,
        })
    }
}

fn normalize_base_url(value: &str) -> Result<Url> {
    let url = Url::parse(value)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::InvalidBaseOrigin);
    }
    let origin = url.origin().ascii_serialization();
    if origin == "null" {
        return Err(Error::InvalidBaseOrigin);
    }
    Ok(Url::parse(&format!("{origin}/"))?)
}

fn ensure_same_origin(base: &Url, url: &Url) -> Result<()> {
    if base.scheme() != url.scheme()
        || base.host_str() != url.host_str()
        || base.port_or_known_default() != url.port_or_known_default()
    {
        return Err(Error::UrlEscapesBase);
    }
    Ok(())
}

fn native_context_hash(base_url: &Url, application_context: Option<&[u8]>) -> [u8; 32] {
    let origin = base_url.as_str().trim_end_matches('/').as_bytes();
    let mut hash = Sha256::new();
    if let Some(context) = application_context {
        hash.update(NATIVE_CONTEXT_MAGIC);
        hash.update(origin);
        hash.update([0]);
        hash.update(context);
    } else {
        hash.update(origin);
    }
    hash.finalize().into()
}

fn validate_expected_pcrs(pcrs: &NitroPcrs) -> Result<()> {
    for index in [0, 1, 2] {
        if !pcrs.contains_key(&index) {
            return Err(Error::InvalidExpectedPcr {
                index,
                reason: "missing",
            });
        }
    }
    for (index, value) in pcrs {
        if value.len() != PCR_SIZE {
            return Err(Error::InvalidExpectedPcr {
                index: *index,
                reason: "must be 48 bytes",
            });
        }
        if value.iter().all(|byte| *byte == 0) {
            return Err(Error::InvalidExpectedPcr {
                index: *index,
                reason: "all-zero debug PCRs are not accepted",
            });
        }
    }
    Ok(())
}

fn verify_attested_binding(
    binding: &AttestedBinding,
    key_exchange: KeyExchangeSuite,
    session_id: &[u8; 16],
    transcript_hash: &[u8; 32],
    binder: &[u8; 32],
) -> Result<()> {
    if binding.protocol != PROTOCOL_ID {
        return Err(Error::AttestationBinding("protocol"));
    }
    if binding.key_exchange != key_exchange {
        return Err(Error::AttestationBinding("key_exchange"));
    }
    verify_binding_field("session_id", &binding.session_id, session_id)?;
    verify_binding_field("transcript_hash", &binding.transcript_hash, transcript_hash)?;
    verify_binding_field("binder", &binding.binder, binder)?;
    Ok(())
}

fn ensure_session_response_suite(
    expected: KeyExchangeSuite,
    actual: KeyExchangeSuite,
) -> Result<()> {
    if actual != expected {
        return Err(Error::Protocol("session response key exchange mismatch"));
    }
    Ok(())
}

enum ClientKem {
    X25519 {
        secret: EphemeralSecret,
        key_material: [u8; 32],
    },
    XWing {
        decapsulation_key: Box<DecapsulationKey>,
        key_material: Vec<u8>,
    },
}

impl ClientKem {
    fn generate(key_exchange: KeyExchangeSuite) -> Self {
        match key_exchange {
            KeyExchangeSuite::X25519 => {
                let secret = EphemeralSecret::random_from_rng(OsRng);
                let key_material = PublicKey::from(&secret).to_bytes();
                Self::X25519 {
                    secret,
                    key_material,
                }
            }
            KeyExchangeSuite::XWingDraft10 => {
                let (decapsulation_key, encapsulation_key) = XWingKem::generate_keypair();
                Self::XWing {
                    decapsulation_key: Box::new(decapsulation_key),
                    key_material: encapsulation_key.to_bytes().to_vec(),
                }
            }
        }
    }

    fn key_material(&self) -> &[u8] {
        match self {
            Self::X25519 { key_material, .. } => key_material,
            Self::XWing { key_material, .. } => key_material,
        }
    }

    fn decapsulate(self, server_key_material: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        match self {
            Self::X25519 { secret, .. } => {
                let server_public_key = PublicKey::from(fixed::<32>(server_key_material)?);
                let shared_secret = secret.diffie_hellman(&server_public_key);
                if !shared_secret.was_contributory() {
                    return Err(Error::Protocol("non-contributory server public key"));
                }
                Ok(Zeroizing::new(shared_secret.to_bytes()))
            }
            Self::XWing {
                decapsulation_key, ..
            } => {
                let ciphertext = Ciphertext::try_from(server_key_material)
                    .map_err(|_| Error::Protocol("invalid X-Wing ciphertext"))?;
                let mut shared_secret = decapsulation_key.decapsulate(&ciphertext);
                let mut output = [0u8; 32];
                output.copy_from_slice(shared_secret.as_slice());
                shared_secret.zeroize();
                Ok(Zeroizing::new(output))
            }
        }
    }
}

fn verify_binding_field(name: &'static str, encoded: &str, expected: &[u8]) -> Result<()> {
    let actual = URL_SAFE_NO_PAD.decode(encoded)?;
    if !constant_time_eq(&actual, expected) {
        return Err(Error::AttestationBinding(name));
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn extract_bytes<'a>(payload: &'a serde_cbor::Value, key: &'static str) -> Result<&'a [u8]> {
    let serde_cbor::Value::Map(map) = payload else {
        return Err(Error::MalformedAttestation("payload is not a map"));
    };
    let Some(serde_cbor::Value::Bytes(bytes)) = map.get(&serde_cbor::Value::Text(key.to_owned()))
    else {
        return Err(Error::MalformedAttestation(key));
    };
    Ok(bytes)
}

fn extract_text<'a>(payload: &'a serde_cbor::Value, key: &'static str) -> Result<&'a str> {
    let serde_cbor::Value::Map(map) = payload else {
        return Err(Error::MalformedAttestation("payload is not a map"));
    };
    let Some(serde_cbor::Value::Text(text)) = map.get(&serde_cbor::Value::Text(key.to_owned()))
    else {
        return Err(Error::MalformedAttestation(key));
    };
    Ok(text)
}

fn extract_pcrs(payload: &serde_cbor::Value) -> Result<NitroPcrs> {
    let serde_cbor::Value::Map(map) = payload else {
        return Err(Error::MalformedAttestation("payload is not a map"));
    };
    let Some(serde_cbor::Value::Map(pcrs)) = map.get(&serde_cbor::Value::Text("pcrs".to_owned()))
    else {
        return Err(Error::MalformedAttestation("pcrs"));
    };
    pcrs.iter()
        .map(|(index, value)| {
            let serde_cbor::Value::Integer(index) = index else {
                return Err(Error::MalformedAttestation("pcr index"));
            };
            let index =
                u8::try_from(*index).map_err(|_| Error::MalformedAttestation("pcr index"))?;
            let serde_cbor::Value::Bytes(value) = value else {
                return Err(Error::MalformedAttestation("pcr value"));
            };
            Ok((index, value.clone()))
        })
        .collect()
}

fn headers_to_strings(headers: &HeaderMap) -> Result<HashMap<String, String>> {
    let mut output = HashMap::with_capacity(headers.len());
    for (key, value) in headers {
        let value = value
            .to_str()
            .map_err(|_| Error::RequestHeaderUtf8(key.to_string()))?;
        output.insert(key.to_string(), value.to_owned());
    }
    Ok(output)
}

fn ensure_success(operation: &'static str, status: StatusCode, body: &[u8]) -> Result<()> {
    if status.is_success() {
        return Ok(());
    }
    Err(Error::ProtocolStatus {
        operation,
        status,
        body: String::from_utf8_lossy(body).chars().take(512).collect(),
    })
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut value = [0; N];
    OsRng.fill_bytes(&mut value);
    value
}

#[cfg(test)]
mod tests;
