use super::*;

use rand_core::{TryCryptoRng, TryRng};
use std::{
    convert::Infallible,
    sync::{
        RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering},
    },
};
use x_wing::{Decapsulate, Encapsulate, Kem, KeyExport, XWingKem};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{StatusCode as AxumStatus, Uri, header::CONTENT_LENGTH},
    response::{IntoResponse, Response as AxumResponse},
    routing::any,
};
use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use p384::{
    ecdsa::{Signature, SigningKey, signature::Signer as SignatureSigner},
    pkcs8::DecodePrivateKey,
};
use serde_cbor::Value;
use steve::{
    ServerConfig,
    attestation::{AttestationError, AttestationProvider},
    build_router_with_provider,
    eval_attestation::EvalAttestationProvider,
};
use tokio::{net::TcpListener, time::sleep};
const EVAL_LEAF_KEY_PEM: &str = include_str!("../../../tests/e2e/fixtures/eval-leaf-key.pem");

fn expected_pcrs() -> NitroPcrs {
    HashMap::from([
        (0, vec![0x10; 48]),
        (1, vec![0x11; 48]),
        (2, vec![0x12; 48]),
        (3, vec![0x13; 48]),
    ])
}

#[derive(Default)]
struct ControlledProvider {
    calls: AtomicUsize,
    fail: AtomicBool,
    corrupt_signature: AtomicBool,
    corrupt_binding: AtomicBool,
    evidence_mutation: StdMutex<Option<EvidenceMutation>>,
}

#[derive(Clone, Copy)]
enum EvidenceMutation {
    Certificate,
    Nonce,
    MissingPcr(u8),
    ZeroPcr(u8),
    ShortPcr(u8),
}

impl AttestationProvider for ControlledProvider {
    fn attest(
        &self,
        nonce: &[u8],
        user_data: &[u8],
    ) -> std::result::Result<Vec<u8>, AttestationError> {
        self.calls.fetch_add(1, AtomicOrdering::Relaxed);
        if self.fail.load(AtomicOrdering::Relaxed) {
            return Err(AttestationError::Eval("forced attestation failure".into()));
        }
        let user_data = if self.corrupt_binding.load(AtomicOrdering::Relaxed) {
            b"{}".as_slice()
        } else {
            user_data
        };
        let mut document = EvalAttestationProvider.attest(nonce, user_data)?;
        if let Some(mutation) = *self.evidence_mutation.lock().unwrap() {
            document = mutate_eval_evidence(&document, mutation)?;
        }
        if !self.corrupt_signature.load(AtomicOrdering::Relaxed) {
            return Ok(document);
        }
        let mut cose = CoseSign1::from_tagged_slice(&document)
            .map_err(|error| AttestationError::Eval(error.to_string()))?;
        cose.signature[0] ^= 1;
        cose.to_tagged_vec()
            .map_err(|error| AttestationError::Eval(error.to_string()))
    }
}

fn mutate_eval_evidence(
    document: &[u8],
    mutation: EvidenceMutation,
) -> std::result::Result<Vec<u8>, AttestationError> {
    let mut cose = CoseSign1::from_tagged_slice(document)
        .map_err(|error| AttestationError::Eval(error.to_string()))?;
    let mut payload: Value = serde_cbor::from_slice(
        cose.payload
            .as_deref()
            .ok_or_else(|| AttestationError::Eval("missing payload".into()))?,
    )
    .map_err(|error| AttestationError::Eval(error.to_string()))?;
    let Value::Map(payload) = &mut payload else {
        return Err(AttestationError::Eval("payload is not a map".into()));
    };

    match mutation {
        EvidenceMutation::Certificate | EvidenceMutation::Nonce => {
            let name = match mutation {
                EvidenceMutation::Certificate => "certificate",
                EvidenceMutation::Nonce => "nonce",
                _ => unreachable!(),
            };
            let Some(Value::Bytes(value)) = payload.get_mut(&Value::Text(name.into())) else {
                return Err(AttestationError::Eval(format!("missing {name}")));
            };
            value[0] ^= 1;
        }
        EvidenceMutation::MissingPcr(index)
        | EvidenceMutation::ZeroPcr(index)
        | EvidenceMutation::ShortPcr(index) => {
            let Some(Value::Map(pcrs)) = payload.get_mut(&Value::Text("pcrs".into())) else {
                return Err(AttestationError::Eval("missing PCRs".into()));
            };
            let index = Value::Integer(index.into());
            match mutation {
                EvidenceMutation::MissingPcr(_) => {
                    pcrs.remove(&index);
                }
                EvidenceMutation::ZeroPcr(_) => {
                    pcrs.insert(index, Value::Bytes(vec![0; 48]));
                }
                EvidenceMutation::ShortPcr(_) => {
                    pcrs.insert(index, Value::Bytes(vec![1; 47]));
                }
                _ => unreachable!(),
            }
        }
    }

    cose.payload = Some(
        serde_cbor::to_vec(&payload).map_err(|error| AttestationError::Eval(error.to_string()))?,
    );
    let signing_key = SigningKey::from_pkcs8_pem(EVAL_LEAF_KEY_PEM)
        .map_err(|error| AttestationError::Eval(error.to_string()))?;
    let signature: Signature = signing_key.sign(&cose.tbs_data(&[]));
    cose.signature = signature.to_bytes().to_vec();
    cose.to_tagged_vec()
        .map_err(|error| AttestationError::Eval(error.to_string()))
}

#[derive(Debug, Default)]
struct MemoryPcrTrustStore {
    records: StdMutex<HashMap<PcrTrustKey, ExpectedPcrs>>,
    calls: AtomicUsize,
    fail: AtomicBool,
}

impl MemoryPcrTrustStore {
    fn replace_records(&self, pcrs: ExpectedPcrs) {
        for record in self.records.lock().unwrap().values_mut() {
            *record = pcrs.clone();
        }
    }
}

#[async_trait]
impl PcrTrustStore for MemoryPcrTrustStore {
    async fn load_or_insert(
        &self,
        key: PcrTrustKey,
        observed: ExpectedPcrs,
    ) -> std::result::Result<PcrTrustRecord, PcrTrustStoreError> {
        self.calls.fetch_add(1, AtomicOrdering::Relaxed);
        if self.fail.load(AtomicOrdering::Relaxed) {
            return Err(std::io::Error::other("forced trust store failure").into());
        }
        let mut records = self.records.lock().unwrap();
        if let Some(existing) = records.get(&key) {
            return Ok(PcrTrustRecord::Existing(existing.clone()));
        }
        records.insert(key, observed);
        Ok(PcrTrustRecord::Inserted)
    }
}

#[derive(Clone, Default)]
struct UpstreamState {
    executions: Arc<AtomicUsize>,
    last_request: Arc<RwLock<Option<ObservedRequest>>>,
}

type ObservedRequest = (HeaderMap, Vec<u8>);

async fn hello(
    State(state): State<UpstreamState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    state.executions.fetch_add(1, AtomicOrdering::Relaxed);
    *state.last_request.write().unwrap() = Some((headers, body.to_vec()));
    (AxumStatus::CREATED, [("x-upstream", "yes")], body.to_vec())
}

async fn slow(State(state): State<UpstreamState>, body: Bytes) -> impl IntoResponse {
    state.executions.fetch_add(1, AtomicOrdering::Relaxed);
    sleep(Duration::from_millis(150)).await;
    (AxumStatus::OK, body.to_vec())
}

async fn spawn_router(router: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{address}")
}

async fn spawn_raw_response(response: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut written = 0;
        while written < response.len() {
            socket.writable().await.unwrap();
            match socket.try_write(&response[written..]) {
                Ok(0) => break,
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("raw response write failed: {error}"),
            }
        }
    });
    format!("http://{address}")
}

async fn test_environment(
    provider: Arc<ControlledProvider>,
    request_timeout: Duration,
) -> (Client, UpstreamState) {
    test_environment_for_suite(provider, request_timeout, KeyExchangeSuite::X25519).await
}

async fn test_environment_for_suite(
    provider: Arc<ControlledProvider>,
    request_timeout: Duration,
    key_exchange: KeyExchangeSuite,
) -> (Client, UpstreamState) {
    test_environment_with_suites(provider, request_timeout, key_exchange, key_exchange).await
}

async fn test_environment_with_suites(
    provider: Arc<ControlledProvider>,
    request_timeout: Duration,
    server_key_exchange: KeyExchangeSuite,
    expected_key_exchange: KeyExchangeSuite,
) -> (Client, UpstreamState) {
    let (steve_url, upstream_state) = test_server(provider, server_key_exchange).await;
    let mut builder = Client::builder(&steve_url, expected_pcrs())
        .unwrap()
        .expected_key_exchange(expected_key_exchange)
        .request_timeout(request_timeout);
    builder.attestation_verifier = Arc::new(EvalAttestationVerifier);
    (builder.build().unwrap(), upstream_state)
}

async fn test_server(
    provider: Arc<ControlledProvider>,
    key_exchange: KeyExchangeSuite,
) -> (String, UpstreamState) {
    let upstream_state = UpstreamState::default();
    let upstream = Router::new()
        .route("/hello", any(hello))
        .route("/slow", any(slow))
        .with_state(upstream_state.clone());
    let upstream_url = spawn_router(upstream).await;
    let steve = build_router_with_provider(
        ServerConfig {
            listen_addr: "127.0.0.1:0".into(),
            upstream_url: Url::parse(&upstream_url).unwrap(),
            cors_origins: None,
            key_exchange: match key_exchange {
                KeyExchangeSuite::X25519 => steve::protocol::KeyExchangeSuite::X25519,
                KeyExchangeSuite::XWingDraft10 => steve::protocol::KeyExchangeSuite::XWingDraft10,
            },
            allow_plaintext_fallback: false,
        },
        provider,
    )
    .unwrap();
    let steve_url = spawn_router(steve).await;
    (steve_url, upstream_state)
}

fn test_client_with_policy(
    steve_url: &str,
    policy: PcrPolicy,
    key_exchange: KeyExchangeSuite,
) -> Client {
    let mut builder = Client::builder_with_policy(steve_url, policy)
        .unwrap()
        .expected_key_exchange(key_exchange)
        .request_timeout(Duration::from_secs(2));
    builder.attestation_verifier = Arc::new(EvalAttestationVerifier);
    builder.build().unwrap()
}

#[derive(Clone)]
struct OversizedOnceProxy {
    target: String,
    http: HttpClient,
    protected_requests: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct RejectConfirmationProxy {
    target: String,
    http: HttpClient,
}

async fn proxy_reject_confirmation(
    State(state): State<RejectConfirmationProxy>,
    uri: Uri,
    body: Bytes,
) -> AxumResponse {
    if uri.path() == CONFIRM_ENDPOINT {
        return (AxumStatus::BAD_GATEWAY, "confirmation rejected").into_response();
    }
    let target = format!("{}{}", state.target, uri.path());
    let response = state
        .http
        .post(target)
        .header("content-type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.bytes().await.unwrap();
    AxumResponse::builder()
        .status(status)
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .unwrap()
}

async fn proxy_with_oversized_first_request(
    State(state): State<OversizedOnceProxy>,
    uri: Uri,
    body: Bytes,
) -> AxumResponse {
    if uri.path() == REQUEST_ENDPOINT
        && state
            .protected_requests
            .fetch_add(1, AtomicOrdering::Relaxed)
            == 0
    {
        return AxumResponse::builder()
            .status(AxumStatus::OK)
            .header("content-type", "application/cbor")
            .header(CONTENT_LENGTH, MAX_APPLICATION_RESPONSE_BYTES + 1)
            .body(Body::from(vec![0; MAX_APPLICATION_RESPONSE_BYTES + 1]))
            .unwrap();
    }

    let target = format!("{}{}", state.target, uri.path());
    let response = state
        .http
        .post(target)
        .header("content-type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.bytes().await.unwrap();
    AxumResponse::builder()
        .status(status)
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .unwrap()
}

fn binding(session_id: &[u8; 16], hash: &[u8; 32], binder: &[u8; 32]) -> AttestedBinding {
    AttestedBinding {
        protocol: PROTOCOL_ID.into(),
        key_exchange: KeyExchangeSuite::X25519,
        session_id: URL_SAFE_NO_PAD.encode(session_id),
        transcript_hash: URL_SAFE_NO_PAD.encode(hash),
        binder: URL_SAFE_NO_PAD.encode(binder),
    }
}

fn dummy_session(generation: u64, id: [u8; 16]) -> Arc<SessionState> {
    Arc::new(SessionState {
        generation,
        id,
        secrets: derive_secrets(&[3; 32], &[4; 32]).unwrap(),
        attestation: AttestationInfo {
            session_id: id,
            module_id: "dummy".into(),
            pcrs: expected_pcrs(),
            pcr_trust: PcrTrustStatus::Pinned,
        },
        activated_at: Instant::now(),
        sequences: SequenceTracker::default(),
    })
}

#[tokio::test]
async fn response_body_reader_accepts_the_exact_limit() {
    let body = vec![0x5a; MAX_SESSION_RESPONSE_BYTES];
    let mut raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(&body);
    let url = spawn_raw_response(raw).await;
    let mut response = HttpClient::new().get(url).send().await.unwrap();

    assert_eq!(
        read_response_body(&mut response, MAX_SESSION_RESPONSE_BYTES)
            .await
            .unwrap(),
        body
    );
}

#[tokio::test]
async fn response_body_reader_rejects_oversized_content_length() {
    let raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_CONFIRMATION_RESPONSE_BYTES + 1
    )
    .into_bytes();
    let url = spawn_raw_response(raw).await;
    let mut response = HttpClient::new().get(url).send().await.unwrap();

    assert!(matches!(
        read_response_body(&mut response, MAX_CONFIRMATION_RESPONSE_BYTES).await,
        Err(Error::Protocol("protocol response too large"))
    ));
}

#[tokio::test]
async fn response_body_reader_rejects_chunked_overflow() {
    let first = vec![0x41; MAX_CONFIRMATION_RESPONSE_BYTES];
    let mut raw =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    raw.extend_from_slice(format!("{:x}\r\n", first.len()).as_bytes());
    raw.extend_from_slice(&first);
    raw.extend_from_slice(b"\r\n1\r\nB\r\n0\r\n\r\n");
    let url = spawn_raw_response(raw).await;
    let mut response = HttpClient::new().get(url).send().await.unwrap();

    assert!(matches!(
        read_response_body(&mut response, MAX_CONFIRMATION_RESPONSE_BYTES).await,
        Err(Error::Protocol("protocol response too large"))
    ));
}

#[test]
fn expected_pcrs_require_nonzero_pcr_zero_one_and_two() {
    assert!(matches!(
        PcrPolicy::pinned(Vec::<ExpectedPcrs>::new()),
        Err(Error::EmptyPcrPolicy)
    ));

    let mut missing = expected_pcrs();
    missing.remove(&2);
    assert!(matches!(
        Client::builder("https://example.com", missing),
        Err(Error::InvalidExpectedPcr {
            index: 2,
            reason: "missing"
        })
    ));

    let mut zero = expected_pcrs();
    zero.insert(1, vec![0; 48]);
    assert!(matches!(
        Client::builder("https://example.com", zero),
        Err(Error::InvalidExpectedPcr { index: 1, .. })
    ));

    let mut short = expected_pcrs();
    short.insert(0, vec![1; 47]);
    assert!(matches!(
        Client::builder("https://example.com", short),
        Err(Error::InvalidExpectedPcr { index: 0, .. })
    ));
}

#[test]
fn attested_pcrs_require_nonzero_pcr_zero_one_and_two() {
    let mut missing = expected_pcrs();
    missing.remove(&2);
    assert!(matches!(
        extract_attested_pcrs(&missing, [0, 1, 2]),
        Err(Error::InvalidAttestedPcr {
            index: 2,
            reason: "missing"
        })
    ));

    let mut zero = expected_pcrs();
    zero.insert(1, vec![0; 48]);
    assert!(matches!(
        extract_attested_pcrs(&zero, [0, 1, 2]),
        Err(Error::InvalidAttestedPcr { index: 1, .. })
    ));

    let mut short = expected_pcrs();
    short.insert(0, vec![1; 47]);
    assert!(matches!(
        extract_attested_pcrs(&short, [0, 1, 2]),
        Err(Error::InvalidAttestedPcr { index: 0, .. })
    ));
}

#[test]
fn x25519_is_the_builder_default_and_xwing_requires_an_explicit_pin() {
    let default = Client::builder("https://example.com", expected_pcrs()).unwrap();
    assert_eq!(default.expected_key_exchange, KeyExchangeSuite::X25519);
    let xwing = default.expected_key_exchange(KeyExchangeSuite::XWingDraft10);
    assert_eq!(xwing.expected_key_exchange, KeyExchangeSuite::XWingDraft10);
}

#[tokio::test]
async fn session_response_suite_mismatch_aborts_before_attestation() {
    let requests = Arc::new(AtomicUsize::new(0));
    let app = Router::new().route(
        "/e2p/v2/session",
        axum::routing::post({
            let requests = Arc::clone(&requests);
            move || {
                let requests = Arc::clone(&requests);
                async move {
                    requests.fetch_add(1, AtomicOrdering::Relaxed);
                    (
                        [("content-type", "application/cbor")],
                        encode_cbor(&SessionResponse {
                            version: VERSION,
                            key_exchange: KeyExchangeSuite::XWingDraft10,
                            session_id: vec![1; 16],
                            server_key_material: vec![2; 1_120],
                            attestation_document: Vec::new(),
                            expires_in_seconds: 30,
                        })
                        .unwrap(),
                    )
                }
            }
        }),
    );
    let url = spawn_router(app).await;
    let client = Client::builder(&url, expected_pcrs())
        .unwrap()
        .build()
        .unwrap();

    assert!(matches!(
        client.initialize().await,
        Err(Error::Protocol("session response key exchange mismatch"))
    ));
    assert_eq!(requests.load(AtomicOrdering::Relaxed), 1);
}

#[tokio::test]
async fn session_response_noncanonical_expiry_aborts_before_attestation() {
    let app = Router::new().route(
        "/e2p/v2/session",
        axum::routing::post(|| async {
            (
                [("content-type", "application/cbor")],
                encode_cbor(&SessionResponse {
                    version: VERSION,
                    key_exchange: KeyExchangeSuite::X25519,
                    session_id: vec![1; 16],
                    server_key_material: vec![2; 32],
                    attestation_document: vec![1],
                    expires_in_seconds: 31,
                })
                .unwrap(),
            )
        }),
    );
    let url = spawn_router(app).await;
    let client = Client::builder(&url, expected_pcrs())
        .unwrap()
        .build()
        .unwrap();

    assert!(matches!(
        client.initialize().await,
        Err(Error::Protocol("invalid pending session expiry"))
    ));
}

#[test]
fn corrupted_xwing_ciphertext_uses_implicit_rejection_without_a_kem_error() {
    let client = ClientKem::generate(KeyExchangeSuite::XWingDraft10);
    let client_key_material = client.key_material().to_vec();
    let encapsulation_key =
        x_wing::EncapsulationKey::try_from(client_key_material.as_slice()).unwrap();
    let (mut ciphertext, mut expected_secret) = encapsulation_key.encapsulate();
    let client_nonce = [1u8; 32];
    let session_id = [2u8; 16];
    let context_hash = [3u8; 32];
    let original_transcript = build_transcript(
        KeyExchangeSuite::XWingDraft10,
        &client_nonce,
        &client_key_material,
        &ciphertext,
        &session_id,
        &context_hash,
    );
    let original_hash = transcript_hash(&original_transcript);
    let expected_secrets = derive_secrets(
        expected_secret.as_slice().try_into().unwrap(),
        &original_hash,
    )
    .unwrap();
    let attested = AttestedBinding {
        protocol: PROTOCOL_ID.into(),
        key_exchange: KeyExchangeSuite::XWingDraft10,
        session_id: URL_SAFE_NO_PAD.encode(session_id),
        transcript_hash: URL_SAFE_NO_PAD.encode(original_hash),
        binder: URL_SAFE_NO_PAD.encode(expected_secrets.binder()),
    };
    ciphertext[0] ^= 1;

    let rejected_secret = client.decapsulate(&ciphertext).unwrap();
    assert_ne!(rejected_secret.as_slice(), expected_secret.as_slice());
    let rejected_transcript = build_transcript(
        KeyExchangeSuite::XWingDraft10,
        &client_nonce,
        &client_key_material,
        &ciphertext,
        &session_id,
        &context_hash,
    );
    let rejected_hash = transcript_hash(&rejected_transcript);
    let rejected_secrets = derive_secrets(&rejected_secret, &rejected_hash).unwrap();
    assert!(matches!(
        verify_attested_binding(
            &attested,
            KeyExchangeSuite::XWingDraft10,
            &session_id,
            &rejected_hash,
            rejected_secrets.binder(),
        ),
        Err(Error::AttestationBinding("transcript_hash"))
    ));
    expected_secret.zeroize();
}

#[test]
fn normalizes_origin_and_binds_optional_application_context() {
    let base = normalize_base_url("https://example.com:443/path?q=1").unwrap();
    assert_eq!(base.as_str(), "https://example.com/");
    let default = native_context_hash(&base, None);
    assert_eq!(
        default,
        <[u8; 32]>::from(Sha256::digest(b"https://example.com"))
    );
    assert_ne!(default, native_context_hash(&base, Some(b"application-a")));
    assert_ne!(
        native_context_hash(&base, Some(b"application-a")),
        native_context_hash(&base, Some(b"application-b"))
    );

    let context = native_context_hash(&base, Some(b"application-a"));
    assert_eq!(
        pcr_trust_key(&context, KeyExchangeSuite::X25519),
        pcr_trust_key(&context, KeyExchangeSuite::X25519)
    );
    assert_ne!(
        pcr_trust_key(&context, KeyExchangeSuite::X25519),
        pcr_trust_key(&context, KeyExchangeSuite::XWingDraft10)
    );
}

#[test]
fn rejects_non_http_and_credentialed_origins() {
    assert!(matches!(
        Client::builder("file:///tmp/steve", expected_pcrs()),
        Err(Error::InvalidBaseOrigin)
    ));
    assert!(matches!(
        Client::builder("https://user@example.com", expected_pcrs()),
        Err(Error::InvalidBaseOrigin)
    ));
}

#[test]
fn rejects_paths_that_escape_base_origin() {
    let base = Url::parse("https://enclave.example.com/").unwrap();
    let escaped = base.join("https://evil.example.com/api").unwrap();
    assert!(matches!(
        ensure_same_origin(&base, &escaped),
        Err(Error::UrlEscapesBase)
    ));
}

#[test]
fn validates_every_attested_binding_field() {
    let session_id = [1; 16];
    let hash = [2; 32];
    let binder_bytes = [3; 32];
    assert!(
        verify_attested_binding(
            &binding(&session_id, &hash, &binder_bytes),
            KeyExchangeSuite::X25519,
            &session_id,
            &hash,
            &binder_bytes
        )
        .is_ok()
    );

    let mut wrong = binding(&session_id, &hash, &binder_bytes);
    wrong.protocol = "STEVE-E2P-V1".into();
    assert!(matches!(
        verify_attested_binding(
            &wrong,
            KeyExchangeSuite::X25519,
            &session_id,
            &hash,
            &binder_bytes
        ),
        Err(Error::AttestationBinding("protocol"))
    ));
    for field in ["session_id", "transcript_hash", "binder"] {
        let mut wrong = binding(&session_id, &hash, &binder_bytes);
        match field {
            "session_id" => wrong.session_id = URL_SAFE_NO_PAD.encode([9; 16]),
            "transcript_hash" => wrong.transcript_hash = URL_SAFE_NO_PAD.encode([9; 32]),
            "binder" => wrong.binder = URL_SAFE_NO_PAD.encode([9; 32]),
            _ => unreachable!(),
        }
        assert!(matches!(
            verify_attested_binding(
                &wrong,
                KeyExchangeSuite::X25519,
                &session_id,
                &hash,
                &binder_bytes
            ),
            Err(Error::AttestationBinding(name)) if name == field
        ));
    }

    let mut malformed = binding(&session_id, &hash, &binder_bytes);
    malformed.binder = "***".into();
    assert!(matches!(
        verify_attested_binding(
            &malformed,
            KeyExchangeSuite::X25519,
            &session_id,
            &hash,
            &binder_bytes
        ),
        Err(Error::AttestationBindingBase64(_))
    ));

    let mut wrong_suite = binding(&session_id, &hash, &binder_bytes);
    wrong_suite.key_exchange = KeyExchangeSuite::XWingDraft10;
    assert!(matches!(
        verify_attested_binding(
            &wrong_suite,
            KeyExchangeSuite::X25519,
            &session_id,
            &hash,
            &binder_bytes
        ),
        Err(Error::AttestationBinding("key_exchange"))
    ));
}

#[test]
fn signed_eval_verifier_requires_tag_and_rejects_bad_certificate_signature_pcr_and_nonce() {
    let nonce = [7; 32];
    let document = EvalAttestationProvider
        .attest(&nonce, br#"{"protocol":"test"}"#)
        .unwrap();
    let verifier = EvalAttestationVerifier;
    assert!(
        verifier
            .verify(&document, &expected_pcrs(), Duration::ZERO, &nonce)
            .is_ok()
    );

    let untagged = CoseSign1::from_tagged_slice(&document)
        .unwrap()
        .to_vec()
        .unwrap();
    assert!(matches!(
        verifier.verify(&untagged, &expected_pcrs(), Duration::ZERO, &nonce),
        Err(bootproof_sdk::format::Error::MalformedData(_))
    ));

    let mut wrong_pcrs = expected_pcrs();
    wrong_pcrs.insert(2, vec![0x99; 48]);
    assert!(matches!(
        verifier.verify(&document, &wrong_pcrs, Duration::ZERO, &nonce),
        Err(bootproof_sdk::format::Error::InvalidAAD(_))
    ));
    assert!(matches!(
        verifier.verify(&document, &expected_pcrs(), Duration::ZERO, &[8; 32]),
        Err(bootproof_sdk::format::Error::InvalidNonce)
    ));

    let mut bad_signature = CoseSign1::from_tagged_slice(&document).unwrap();
    bad_signature.signature[0] ^= 1;
    assert!(matches!(
        verifier.verify(
            &bad_signature.to_tagged_vec().unwrap(),
            &expected_pcrs(),
            Duration::ZERO,
            &nonce
        ),
        Err(bootproof_sdk::format::Error::BadSignature)
    ));

    let mut bad_certificate = CoseSign1::from_tagged_slice(&document).unwrap();
    let mut payload: Value =
        serde_cbor::from_slice(bad_certificate.payload.as_ref().unwrap()).unwrap();
    let Value::Map(map) = &mut payload else {
        unreachable!()
    };
    let Some(Value::Bytes(certificate)) = map.get_mut(&Value::Text("certificate".to_owned()))
    else {
        unreachable!()
    };
    certificate[0] ^= 1;
    bad_certificate.payload = Some(serde_cbor::to_vec(&payload).unwrap());
    assert!(matches!(
        verifier.verify(
            &bad_certificate.to_tagged_vec().unwrap(),
            &expected_pcrs(),
            Duration::ZERO,
            &nonce
        ),
        Err(bootproof_sdk::format::Error::InvalidCABundle)
    ));
}

#[tokio::test]
async fn sequence_tracker_backpressures_on_the_64_entry_span() {
    let tracker = Arc::new(SequenceTracker::default());
    for expected in 1..=64 {
        assert_eq!(tracker.allocate().await.unwrap(), expected);
    }
    let waiting = {
        let tracker = Arc::clone(&tracker);
        tokio::spawn(async move { tracker.allocate().await })
    };
    sleep(Duration::from_millis(20)).await;
    assert!(!waiting.is_finished());
    tracker.accept(1, 1).unwrap();
    assert_eq!(waiting.await.unwrap().unwrap(), 65);
}

#[tokio::test]
async fn closing_sequence_tracker_rejects_waiters() {
    let tracker = Arc::new(SequenceTracker::default());
    for _ in 0..64 {
        tracker.allocate().await.unwrap();
    }
    let waiting = {
        let tracker = Arc::clone(&tracker);
        tokio::spawn(async move { tracker.allocate().await })
    };
    sleep(Duration::from_millis(20)).await;
    tracker.close();
    assert!(matches!(waiting.await.unwrap(), Err(Error::SessionClosed)));
}

#[tokio::test]
async fn sequence_tracker_accepts_out_of_order_responses() {
    let first = SequenceTracker::default();
    let sequence_one = first.allocate().await.unwrap();
    let sequence_two = first.allocate().await.unwrap();
    first.accept(sequence_two, sequence_two).unwrap();
    first.accept(sequence_one, sequence_one).unwrap();
    assert_eq!(first.allocate().await.unwrap(), 3);
}

#[tokio::test]
async fn signed_eval_server_round_trip_and_rotation() {
    let provider = Arc::new(ControlledProvider::default());
    let (client, upstream) = test_environment(provider.clone(), Duration::from_secs(2)).await;
    let first = client.initialize().await.unwrap();
    assert_eq!(first.module_id, "steve-local-eval");
    assert_eq!(first.pcrs, expected_pcrs());
    assert_eq!(first.pcr_trust, PcrTrustStatus::Pinned);

    let response = client
        .post("/hello?query=1")
        .header("x-client", "yes")
        .unwrap()
        .body(b"secret request".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["x-upstream"], "yes");
    assert_eq!(response.bytes(), b"secret request");
    let observed = upstream.last_request.read().unwrap().clone().unwrap();
    assert_eq!(observed.0["x-client"], "yes");
    assert_eq!(observed.1, b"secret request");

    let second = client.rotate_session().await.unwrap();
    assert_ne!(first.session_id, second.session_id);
    assert_eq!(provider.calls.load(AtomicOrdering::Relaxed), 2);
}

#[tokio::test]
async fn pinned_policy_accepts_one_complete_profile_and_rejects_mixed_profiles() {
    let provider = Arc::new(ControlledProvider::default());
    let (steve_url, _) = test_server(provider.clone(), KeyExchangeSuite::X25519).await;
    let mut obsolete = expected_pcrs();
    obsolete.insert(2, vec![0x44; 48]);
    for profiles in [
        [expected_pcrs(), obsolete.clone()],
        [obsolete, expected_pcrs()],
    ] {
        let policy = PcrPolicy::pinned(profiles).unwrap();
        let client = test_client_with_policy(&steve_url, policy, KeyExchangeSuite::X25519);
        assert_eq!(
            client.initialize().await.unwrap().pcr_trust,
            PcrTrustStatus::Pinned
        );
    }

    let mut first_mixed = expected_pcrs();
    first_mixed.insert(1, vec![0x55; 48]);
    let mut second_mixed = expected_pcrs();
    second_mixed.insert(0, vec![0x66; 48]);
    let policy = PcrPolicy::pinned([first_mixed, second_mixed]).unwrap();
    let client = test_client_with_policy(&steve_url, policy, KeyExchangeSuite::X25519);
    assert!(matches!(
        client.initialize().await,
        Err(Error::UnapprovedPcrProfile)
    ));
}

#[tokio::test]
async fn tofu_enrolls_after_confirmation_and_matches_on_rotation() {
    let provider = Arc::new(ControlledProvider::default());
    let (steve_url, _) = test_server(provider.clone(), KeyExchangeSuite::X25519).await;
    let store = Arc::new(MemoryPcrTrustStore::default());
    let policy = PcrPolicy::trust_on_first_use(store.clone());
    let client = test_client_with_policy(&steve_url, policy, KeyExchangeSuite::X25519);

    let first = client.initialize().await.unwrap();
    assert_eq!(first.pcr_trust, PcrTrustStatus::TofuEnrolled);
    assert_eq!(first.pcrs, expected_pcrs());
    assert_eq!(store.calls.load(AtomicOrdering::Relaxed), 1);
    let records = store.records.lock().unwrap();
    assert_eq!(records.len(), 1);
    let mut required = expected_pcrs();
    required.remove(&3);
    assert_eq!(records.values().next(), Some(&required));
    drop(records);

    let second = client.rotate_session().await.unwrap();
    assert_eq!(second.pcr_trust, PcrTrustStatus::TofuMatched);
    assert_ne!(first.session_id, second.session_id);
    assert_eq!(store.calls.load(AtomicOrdering::Relaxed), 2);
}

#[tokio::test]
async fn tofu_additional_pcrs_are_canonical_and_enforced() {
    let provider = Arc::new(ControlledProvider::default());
    let (steve_url, _) = test_server(provider, KeyExchangeSuite::X25519).await;
    let store = Arc::new(MemoryPcrTrustStore::default());
    let policy = PcrPolicy::trust_on_first_use_with_additional_pcrs(store.clone(), [3, 1, 3]);
    let client = test_client_with_policy(&steve_url, policy, KeyExchangeSuite::X25519);

    let first = client.initialize().await.unwrap();
    assert_eq!(first.pcr_trust, PcrTrustStatus::TofuEnrolled);
    assert_eq!(first.pcrs, expected_pcrs());
    let enrolled = store.records.lock().unwrap().values().next().cloned();
    assert_eq!(enrolled, Some(expected_pcrs()));
    let second = client.rotate_session().await.unwrap();
    assert_eq!(second.pcr_trust, PcrTrustStatus::TofuMatched);

    let mut wrong = expected_pcrs();
    wrong.insert(3, vec![0x77; 48]);
    store.replace_records(wrong);
    assert!(matches!(
        client.rotate_session().await,
        Err(Error::PcrTrustMismatch)
    ));
    assert_eq!(
        client.verify_attestation().await.unwrap().session_id,
        second.session_id
    );
}

#[tokio::test]
async fn changing_tofu_pcr_selection_conflicts_with_the_existing_record() {
    let provider = Arc::new(ControlledProvider::default());
    let (steve_url, _) = test_server(provider, KeyExchangeSuite::X25519).await;

    let default_store = Arc::new(MemoryPcrTrustStore::default());
    test_client_with_policy(
        &steve_url,
        PcrPolicy::trust_on_first_use(default_store.clone()),
        KeyExchangeSuite::X25519,
    )
    .initialize()
    .await
    .unwrap();
    let stronger = test_client_with_policy(
        &steve_url,
        PcrPolicy::trust_on_first_use_with_additional_pcrs(default_store, [3]),
        KeyExchangeSuite::X25519,
    );
    assert!(matches!(
        stronger.initialize().await,
        Err(Error::PcrTrustMismatch)
    ));

    let stronger_store = Arc::new(MemoryPcrTrustStore::default());
    test_client_with_policy(
        &steve_url,
        PcrPolicy::trust_on_first_use_with_additional_pcrs(stronger_store.clone(), [3]),
        KeyExchangeSuite::X25519,
    )
    .initialize()
    .await
    .unwrap();
    let default = test_client_with_policy(
        &steve_url,
        PcrPolicy::trust_on_first_use(stronger_store),
        KeyExchangeSuite::X25519,
    );
    assert!(matches!(
        default.initialize().await,
        Err(Error::PcrTrustMismatch)
    ));
}

#[tokio::test]
async fn tofu_mismatch_fails_rotation_and_preserves_the_previous_session() {
    let provider = Arc::new(ControlledProvider::default());
    let (steve_url, _) = test_server(provider, KeyExchangeSuite::X25519).await;
    let store = Arc::new(MemoryPcrTrustStore::default());
    let policy = PcrPolicy::trust_on_first_use(store.clone());
    let client = test_client_with_policy(&steve_url, policy, KeyExchangeSuite::X25519);
    let first = client.initialize().await.unwrap();

    let mut wrong = expected_pcrs();
    wrong.insert(2, vec![0x77; 48]);
    store.replace_records(wrong);
    assert!(matches!(
        client.rotate_session().await,
        Err(Error::PcrTrustMismatch)
    ));
    assert_eq!(
        client.verify_attestation().await.unwrap().session_id,
        first.session_id
    );
}

#[tokio::test]
async fn concurrent_tofu_initialization_has_one_atomic_enrollment() {
    let provider = Arc::new(ControlledProvider::default());
    let (steve_url, _) = test_server(provider.clone(), KeyExchangeSuite::X25519).await;
    let store = Arc::new(MemoryPcrTrustStore::default());
    let first = test_client_with_policy(
        &steve_url,
        PcrPolicy::trust_on_first_use(store.clone()),
        KeyExchangeSuite::X25519,
    );
    let second = test_client_with_policy(
        &steve_url,
        PcrPolicy::trust_on_first_use(store.clone()),
        KeyExchangeSuite::X25519,
    );

    let (first, second) = tokio::join!(first.initialize(), second.initialize());
    let statuses = [first.unwrap().pcr_trust, second.unwrap().pcr_trust];
    assert!(statuses.contains(&PcrTrustStatus::TofuEnrolled));
    assert!(statuses.contains(&PcrTrustStatus::TofuMatched));
    assert_eq!(store.records.lock().unwrap().len(), 1);
    assert_eq!(store.calls.load(AtomicOrdering::Relaxed), 2);
    assert_eq!(provider.calls.load(AtomicOrdering::Relaxed), 2);
}

#[tokio::test]
async fn tofu_store_failure_prevents_application_traffic() {
    let provider = Arc::new(ControlledProvider::default());
    let (steve_url, upstream) = test_server(provider, KeyExchangeSuite::X25519).await;
    let store = Arc::new(MemoryPcrTrustStore::default());
    store.fail.store(true, AtomicOrdering::Relaxed);
    let client = test_client_with_policy(
        &steve_url,
        PcrPolicy::trust_on_first_use(store.clone()),
        KeyExchangeSuite::X25519,
    );

    assert!(matches!(
        client.initialize().await,
        Err(Error::PcrTrustStore(_))
    ));
    assert_eq!(store.calls.load(AtomicOrdering::Relaxed), 1);
    assert_eq!(upstream.executions.load(AtomicOrdering::Relaxed), 0);
}

#[tokio::test]
async fn invalid_attestation_and_binding_do_not_write_tofu() {
    let cases = [
        (true, false, None),
        (false, true, None),
        (false, false, Some(EvidenceMutation::Certificate)),
        (false, false, Some(EvidenceMutation::Nonce)),
        (false, false, Some(EvidenceMutation::MissingPcr(2))),
        (false, false, Some(EvidenceMutation::ZeroPcr(2))),
        (false, false, Some(EvidenceMutation::ShortPcr(2))),
    ];
    for (corrupt_signature, corrupt_binding, mutation) in cases {
        let provider = Arc::new(ControlledProvider::default());
        provider
            .corrupt_signature
            .store(corrupt_signature, AtomicOrdering::Relaxed);
        provider
            .corrupt_binding
            .store(corrupt_binding, AtomicOrdering::Relaxed);
        if mutation.is_some() {
            *provider.evidence_mutation.lock().unwrap() = mutation;
        }
        let (steve_url, _) = test_server(provider, KeyExchangeSuite::X25519).await;
        let store = Arc::new(MemoryPcrTrustStore::default());
        let client = test_client_with_policy(
            &steve_url,
            PcrPolicy::trust_on_first_use(store.clone()),
            KeyExchangeSuite::X25519,
        );

        assert!(client.initialize().await.is_err());
        assert_eq!(store.calls.load(AtomicOrdering::Relaxed), 0);
        assert!(store.records.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn invalid_additional_attested_pcrs_do_not_write_tofu() {
    for mutation in [
        EvidenceMutation::MissingPcr(3),
        EvidenceMutation::ZeroPcr(3),
        EvidenceMutation::ShortPcr(3),
    ] {
        let provider = Arc::new(ControlledProvider::default());
        *provider.evidence_mutation.lock().unwrap() = Some(mutation);
        let (steve_url, _) = test_server(provider, KeyExchangeSuite::X25519).await;
        let store = Arc::new(MemoryPcrTrustStore::default());
        let client = test_client_with_policy(
            &steve_url,
            PcrPolicy::trust_on_first_use_with_additional_pcrs(store.clone(), [3]),
            KeyExchangeSuite::X25519,
        );

        assert!(matches!(
            client.initialize().await,
            Err(Error::InvalidAttestedPcr { index: 3, .. })
        ));
        assert_eq!(store.calls.load(AtomicOrdering::Relaxed), 0);
        assert!(store.records.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn failed_confirmation_does_not_write_tofu() {
    let provider = Arc::new(ControlledProvider::default());
    let (steve_url, upstream) = test_server(provider, KeyExchangeSuite::X25519).await;
    let proxy = Router::new()
        .fallback(any(proxy_reject_confirmation))
        .with_state(RejectConfirmationProxy {
            target: steve_url,
            http: HttpClient::new(),
        });
    let proxy_url = spawn_router(proxy).await;
    let store = Arc::new(MemoryPcrTrustStore::default());
    let client = test_client_with_policy(
        &proxy_url,
        PcrPolicy::trust_on_first_use(store.clone()),
        KeyExchangeSuite::X25519,
    );

    assert!(matches!(
        client.initialize().await,
        Err(Error::ProtocolStatus {
            operation: "session confirmation",
            status: StatusCode::BAD_GATEWAY,
            ..
        })
    ));
    assert_eq!(store.calls.load(AtomicOrdering::Relaxed), 0);
    assert_eq!(upstream.executions.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn application_response_preserves_repeated_headers() {
    let exchange = ProtectedExchange {
        session_id: [9; 16],
        sequence: 7,
        key_exchange: KeyExchangeSuite::X25519,
        pcr_trust: PcrTrustStatus::Pinned,
        outer_status: StatusCode::OK,
        request_plaintext_bytes: 10,
        request_ciphertext_bytes: 26,
        request_envelope_bytes: 64,
        response_envelope_bytes: 65,
        response_ciphertext_bytes: 27,
        response_plaintext_bytes: 11,
    };
    let response = ApplicationResponse {
        status: StatusCode::OK.as_u16(),
        headers: vec![
            ("set-cookie".to_string(), "a=1".to_string()),
            ("set-cookie".to_string(), "b=2".to_string()),
        ],
        body: None,
        error: None,
    }
    .into_response(exchange.clone())
    .unwrap();

    assert_eq!(response.exchange(), &exchange);
    assert_eq!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["a=1", "b=2"]
    );
}

#[test]
fn application_response_error_requires_text_when_present() {
    let decode = |value: serde_json::Value| {
        let encoded = encode_cbor(&value).unwrap();
        decode_cbor::<ApplicationResponse>(&encoded)
    };

    assert!(decode(serde_json::json!({
        "status": 200,
        "headers": [],
        "body": null
    }))
    .unwrap()
    .error
    .is_none());
    assert_eq!(
        decode(serde_json::json!({
            "status": 200,
            "headers": [],
            "body": null,
            "error": ""
        }))
        .unwrap()
        .error
        .as_deref(),
        Some("")
    );
    for error in [serde_json::Value::Null, serde_json::json!(7)] {
        assert!(decode(serde_json::json!({
            "status": 200,
            "headers": [],
            "body": null,
            "error": error
        }))
        .is_err());
    }
}

#[tokio::test]
async fn xwing_signed_eval_server_round_trip_and_rotation() {
    let provider = Arc::new(ControlledProvider::default());
    let (client, upstream) = test_environment_for_suite(
        provider.clone(),
        Duration::from_secs(5),
        KeyExchangeSuite::XWingDraft10,
    )
    .await;
    let first = client.initialize().await.unwrap();
    let response = client
        .post("/hello")
        .body(b"xwing secret request".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.bytes(), b"xwing secret request");
    let exchange = response.exchange();
    assert_eq!(exchange.protocol(), "STEVE-E2P-V2");
    assert_eq!(exchange.protection(), "AES-256-GCM");
    assert_eq!(exchange.session_id(), &first.session_id);
    assert_eq!(exchange.sequence(), 1);
    assert_eq!(exchange.key_exchange(), KeyExchangeSuite::XWingDraft10);
    assert_eq!(exchange.pcr_trust(), PcrTrustStatus::Pinned);
    assert_eq!(exchange.outer_status(), StatusCode::OK);
    assert_eq!(
        exchange.request_ciphertext_bytes(),
        exchange.request_plaintext_bytes() + 16
    );
    assert!(exchange.request_envelope_bytes() > exchange.request_ciphertext_bytes());
    assert_eq!(
        exchange.response_ciphertext_bytes(),
        exchange.response_plaintext_bytes() + 16
    );
    assert!(exchange.response_envelope_bytes() > exchange.response_ciphertext_bytes());
    assert_eq!(
        upstream.last_request.read().unwrap().as_ref().unwrap().1,
        b"xwing secret request"
    );
    let second = client.rotate_session().await.unwrap();
    assert_ne!(first.session_id, second.session_id);
    assert_eq!(provider.calls.load(AtomicOrdering::Relaxed), 2);
}

#[tokio::test]
#[ignore = "requires the signed-eval services started by scripts/test-e2e.sh"]
async fn external_eval_e2e() {
    let base_url =
        std::env::var("STEVE_E2E_URL").expect("STEVE_E2E_URL must identify the E2E STEVE origin");
    let suite_name =
        std::env::var("STEVE_KEY_EXCHANGE").expect("STEVE_KEY_EXCHANGE must select the E2E suite");
    let suite = match suite_name.as_str() {
        "X25519" => KeyExchangeSuite::X25519,
        "XWING-DRAFT10" => KeyExchangeSuite::XWingDraft10,
        _ => panic!("STEVE_KEY_EXCHANGE must be exactly X25519 or XWING-DRAFT10"),
    };
    let wrong_suite = match suite {
        KeyExchangeSuite::X25519 => KeyExchangeSuite::XWingDraft10,
        KeyExchangeSuite::XWingDraft10 => KeyExchangeSuite::X25519,
    };

    let mut wrong_builder = Client::builder(&base_url, expected_pcrs())
        .unwrap()
        .expected_key_exchange(wrong_suite);
    wrong_builder.attestation_verifier = Arc::new(EvalAttestationVerifier);
    assert!(matches!(
        wrong_builder.connect().await,
        Err(Error::ProtocolStatus {
            operation: "session creation",
            status: StatusCode::BAD_REQUEST,
            ..
        })
    ));

    let mut builder = Client::builder(&base_url, expected_pcrs())
        .unwrap()
        .expected_key_exchange(suite)
        .request_timeout(Duration::from_secs(5));
    builder.attestation_verifier = Arc::new(EvalAttestationVerifier);
    let client = builder.connect().await.unwrap();
    let first = client.verify_attestation().await.unwrap();
    assert_eq!(first.module_id, "steve-local-eval");
    assert_eq!(first.pcrs, expected_pcrs());

    let body = b"native sdk through steve".to_vec();
    let response = client
        .post("/echo?client=rust")
        .header("content-type", "application/octet-stream")
        .unwrap()
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "application/octet-stream"
    );
    assert_eq!(response.bytes(), body);

    let (slow, fast, medium) = tokio::join!(
        client.get("/delay?ms=120").send(),
        client.get("/delay?ms=20").send(),
        client.get("/delay?ms=60").send(),
    );
    assert_eq!(slow.unwrap().bytes(), b"delayed:120");
    assert_eq!(fast.unwrap().bytes(), b"delayed:20");
    assert_eq!(medium.unwrap().bytes(), b"delayed:60");

    let second = client.rotate_session().await.unwrap();
    assert_ne!(first.session_id, second.session_id);
    let response = client
        .post("/echo?client=rust-after-rotation")
        .body(b"rotated".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes(), b"rotated");
}

#[tokio::test]
async fn request_suite_mismatch_aborts_before_attestation_without_fallback() {
    let provider = Arc::new(ControlledProvider::default());
    let (client, _) = test_environment_with_suites(
        provider.clone(),
        Duration::from_secs(2),
        KeyExchangeSuite::XWingDraft10,
        KeyExchangeSuite::X25519,
    )
    .await;
    assert!(matches!(
        client.initialize().await,
        Err(Error::ProtocolStatus {
            operation: "session creation",
            status: StatusCode::BAD_REQUEST,
            ..
        })
    ));
    assert_eq!(provider.calls.load(AtomicOrdering::Relaxed), 0);
}

#[tokio::test]
async fn concurrent_initialization_performs_one_attested_handshake() {
    let provider = Arc::new(ControlledProvider::default());
    let (client, _) = test_environment(provider.clone(), Duration::from_secs(2)).await;
    let tasks = (0..8)
        .map(|_| {
            let client = client.clone();
            tokio::spawn(async move { client.initialize().await })
        })
        .collect::<Vec<_>>();
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(provider.calls.load(AtomicOrdering::Relaxed), 1);
}

#[tokio::test]
async fn timed_out_request_is_not_replayed_and_session_survives() {
    let provider = Arc::new(ControlledProvider::default());
    let (client, upstream) = test_environment(provider.clone(), Duration::from_millis(40)).await;
    client.initialize().await.unwrap();
    let session_id = client.verify_attestation().await.unwrap().session_id;

    assert!(matches!(
        client.post("/slow").body(b"once".to_vec()).send().await,
        Err(Error::Timeout {
            operation: "protected request"
        })
    ));
    sleep(Duration::from_millis(180)).await;
    assert_eq!(upstream.executions.load(AtomicOrdering::Relaxed), 1);

    let response = client.get("/hello").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        client.verify_attestation().await.unwrap().session_id,
        session_id
    );
    assert_eq!(provider.calls.load(AtomicOrdering::Relaxed), 1);
}

#[tokio::test]
async fn oversized_protected_response_is_not_retried_and_recovers_with_a_new_session() {
    let provider = Arc::new(ControlledProvider::default());
    let (steve_url, upstream) = test_server(provider.clone(), KeyExchangeSuite::X25519).await;
    let protected_requests = Arc::new(AtomicUsize::new(0));
    let proxy = Router::new()
        .fallback(any(proxy_with_oversized_first_request))
        .with_state(OversizedOnceProxy {
            target: steve_url,
            http: HttpClient::new(),
            protected_requests: Arc::clone(&protected_requests),
        });
    let proxy_url = spawn_router(proxy).await;
    let mut builder = Client::builder(&proxy_url, expected_pcrs())
        .unwrap()
        .request_timeout(Duration::from_secs(2));
    builder.attestation_verifier = Arc::new(EvalAttestationVerifier);
    let client = builder.build().unwrap();
    let original = client.initialize().await.unwrap();

    let result = client.get("/hello").send().await;
    assert!(
        matches!(result, Err(Error::Protocol("protocol response too large"))),
        "{result:?}"
    );
    assert_eq!(protected_requests.load(AtomicOrdering::Relaxed), 1);
    assert!(client.inner.state.lock().await.is_none());
    assert_eq!(upstream.executions.load(AtomicOrdering::Relaxed), 0);

    let response = client.get("/hello").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(protected_requests.load(AtomicOrdering::Relaxed), 2);
    assert_eq!(upstream.executions.load(AtomicOrdering::Relaxed), 1);
    assert_ne!(
        client.verify_attestation().await.unwrap().session_id,
        original.session_id
    );
    assert_eq!(provider.calls.load(AtomicOrdering::Relaxed), 2);
}

#[tokio::test]
async fn failed_rotation_preserves_the_previous_session() {
    let provider = Arc::new(ControlledProvider::default());
    let (client, _) = test_environment(provider.clone(), Duration::from_secs(2)).await;
    let original = client.initialize().await.unwrap();
    provider.fail.store(true, AtomicOrdering::Relaxed);
    assert!(matches!(
        client.rotate_session().await,
        Err(Error::ProtocolStatus {
            status: StatusCode::SERVICE_UNAVAILABLE,
            ..
        })
    ));
    assert_eq!(
        client.verify_attestation().await.unwrap().session_id,
        original.session_id
    );
    assert_eq!(
        client.get("/hello").send().await.unwrap().status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn server_session_loss_recovers_without_replaying_the_failed_request() {
    let provider = Arc::new(ControlledProvider::default());
    let (client, upstream) = test_environment(provider.clone(), Duration::from_secs(2)).await;
    client.initialize().await.unwrap();
    let generation = client.inner.next_generation.fetch_add(1, Ordering::Relaxed);
    *client.inner.state.lock().await = Some(dummy_session(generation, [0xee; 16]));

    assert!(matches!(
        client.get("/hello").send().await,
        Err(Error::ProtocolStatus {
            status: StatusCode::UNAUTHORIZED,
            ..
        })
    ));
    assert!(client.inner.state.lock().await.is_none());
    assert_eq!(upstream.executions.load(AtomicOrdering::Relaxed), 0);

    assert_eq!(
        client.get("/hello").send().await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(upstream.executions.load(AtomicOrdering::Relaxed), 1);
    assert_eq!(provider.calls.load(AtomicOrdering::Relaxed), 2);
}

#[tokio::test]
async fn late_failure_cannot_invalidate_a_newer_generation() {
    let client = Client::builder("http://127.0.0.1:9", expected_pcrs())
        .unwrap()
        .build()
        .unwrap();
    let older = dummy_session(1, [1; 16]);
    let newer = dummy_session(2, [2; 16]);
    *client.inner.state.lock().await = Some(older);
    *client.inner.state.lock().await = Some(Arc::clone(&newer));
    client.invalidate_generation(1).await;
    assert_eq!(
        client.inner.state.lock().await.as_ref().unwrap().generation,
        2
    );
}

#[test]
fn request_failure_classification_matches_browser_recovery() {
    for status in [
        StatusCode::FORBIDDEN,
        StatusCode::NOT_FOUND,
        StatusCode::REQUEST_TIMEOUT,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        assert!(
            Error::ProtocolStatus {
                operation: "request",
                status,
                body: String::new(),
            }
            .is_request_local()
        );
    }
    for status in [
        StatusCode::BAD_REQUEST,
        StatusCode::UNAUTHORIZED,
        StatusCode::CONFLICT,
        StatusCode::TOO_EARLY,
    ] {
        assert!(
            !Error::ProtocolStatus {
                operation: "request",
                status,
                body: String::new(),
            }
            .is_request_local()
        );
    }
}

#[derive(Deserialize)]
struct XWingKat {
    seed: String,
    eseed: String,
    ss: String,
    sk: String,
    pk: String,
    ct: String,
}

#[derive(Deserialize)]
struct PcrPolicyVectors {
    version: u8,
    observed: HashMap<String, String>,
    pinned: Vec<PinnedPolicyVector>,
    tofu: TofuPolicyVectors,
}

#[derive(Deserialize)]
struct PinnedPolicyVector {
    name: String,
    profiles: Vec<HashMap<String, String>>,
    accepted: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TofuPolicyVectors {
    additional_pcr_indices: Vec<u8>,
    selected: HashMap<String, String>,
    records: Vec<TofuRecordVector>,
}

#[derive(Deserialize)]
struct TofuRecordVector {
    name: String,
    pcrs: HashMap<String, String>,
    matches: bool,
}

struct KatRng {
    bytes: Vec<u8>,
    offset: usize,
}

impl KatRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> [u8; N] {
        let end = self.offset + N;
        let output = self.bytes[self.offset..end].try_into().unwrap();
        self.offset = end;
        output
    }
}

impl TryRng for KatRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        Ok(u32::from_le_bytes(self.take()))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        Ok(u64::from_le_bytes(self.take()))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> std::result::Result<(), Self::Error> {
        let end = self.offset + destination.len();
        destination.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(())
    }
}

impl TryCryptoRng for KatRng {}

#[test]
fn shared_pcr_policy_vectors_match_native_semantics() {
    let vectors: PcrPolicyVectors = serde_json::from_slice(include_bytes!(
        "../../../test-vectors/pcr-policy-v1.json"
    ))
    .unwrap();
    assert_eq!(vectors.version, 1);
    let observed = vector_pcrs(vectors.observed);

    for vector in vectors.pinned {
        let profiles = vector
            .profiles
            .into_iter()
            .map(vector_pcrs)
            .collect::<Vec<_>>();
        for profile in &profiles {
            validate_expected_pcrs(profile).unwrap();
        }
        assert_eq!(
            profiles
                .iter()
                .any(|profile| pcr_profile_matches(profile, &observed)),
            vector.accepted,
            "{}",
            vector.name
        );
    }

    let indices = BTreeSet::from([0, 1, 2])
        .into_iter()
        .chain(vectors.tofu.additional_pcr_indices)
        .collect::<BTreeSet<_>>();
    let selected = extract_attested_pcrs(&observed, indices).unwrap();
    assert_eq!(selected, vector_pcrs(vectors.tofu.selected));
    for record in vectors.tofu.records {
        assert_eq!(
            vector_pcrs(record.pcrs) == selected,
            record.matches,
            "{}",
            record.name
        );
    }
}

#[test]
fn rustcrypto_matches_all_draft10_kats_and_snapshot_digest() {
    let snapshot = include_bytes!("../../../test-vectors/xwing-draft10.json");
    assert_eq!(
        Sha256::digest(snapshot).as_slice(),
        hex_bytes("eefc9b36f781168a80808ddb2e911c5490ab353342b9f47c52d4d2dc12dc1192")
    );
    let vectors: Vec<XWingKat> = serde_json::from_slice(snapshot).unwrap();
    assert_eq!(vectors.len(), 3);

    for vector in vectors {
        let mut seed = KatRng::new(hex_bytes(&vector.seed));
        let (decapsulation_key, encapsulation_key) = XWingKem::generate_keypair_from_rng(&mut seed);
        assert_eq!(
            decapsulation_key.as_bytes(),
            hex_bytes(&vector.sk).as_slice()
        );
        assert_eq!(
            encapsulation_key.to_bytes().as_slice(),
            hex_bytes(&vector.pk)
        );

        let mut encapsulation_seed = KatRng::new(hex_bytes(&vector.eseed));
        let (ciphertext, sender_secret) =
            encapsulation_key.encapsulate_with_rng(&mut encapsulation_seed);
        assert_eq!(ciphertext.as_slice(), hex_bytes(&vector.ct));
        assert_eq!(sender_secret.as_slice(), hex_bytes(&vector.ss));
        assert_eq!(
            decapsulation_key.decapsulate(&ciphertext).as_slice(),
            hex_bytes(&vector.ss)
        );
    }
}

fn vector_pcrs(values: HashMap<String, String>) -> NitroPcrs {
    values
        .into_iter()
        .map(|(name, value)| {
            let index = name.strip_prefix("PCR").unwrap().parse::<u8>().unwrap();
            (index, hex_bytes(&value))
        })
        .collect()
}

fn hex_bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}
