use super::*;

use rand_core::{TryCryptoRng, TryRng};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{
        RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering},
    },
};
use x_wing::{Decapsulate, Encapsulate, Kem, KeyExport, XWingKem};

use axum::{
    Router, body::Bytes, extract::State, http::StatusCode as AxumStatus, response::IntoResponse,
    routing::any,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use coset::{CborSerializable, CoseSign1};
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier as SignatureVerifier};
use serde_cbor::Value;
use steve::{
    ServerConfig,
    attestation::{AttestationError, AttestationProvider},
    build_router_with_provider,
    eval_attestation::EvalAttestationProvider,
};
use tokio::{net::TcpListener, time::sleep};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

const EVAL_LEAF_CERT_PEM: &str = include_str!("../../../tests/e2e/fixtures/eval-leaf-cert.pem");

fn expected_pcrs() -> NitroPcrs {
    HashMap::from([
        (0, vec![0x10; 48]),
        (1, vec![0x11; 48]),
        (2, vec![0x12; 48]),
    ])
}

#[derive(Debug)]
struct EvalAttestationVerifier;

impl AttestationVerifier for EvalAttestationVerifier {
    fn verify(
        &self,
        document: &[u8],
        expected_pcrs: &NitroPcrs,
        _now: Duration,
        nonce: &[u8; 32],
    ) -> std::result::Result<Value, bootproof_sdk::format::Error> {
        let cose = CoseSign1::from_slice(document)
            .map_err(|_| malformed_attestation("eval cose sign1"))?;
        let payload_bytes = cose
            .payload
            .as_ref()
            .ok_or_else(|| missing_attestation("eval payload"))?;
        let payload: Value = serde_cbor::from_slice(payload_bytes)
            .map_err(|_| malformed_attestation("eval payload"))?;

        let leaf_der = decode_pem(EVAL_LEAF_CERT_PEM)?;
        let certificate = value_bytes(&payload, "certificate")?;
        if certificate != leaf_der {
            return Err(bootproof_sdk::format::Error::InvalidCABundle);
        }
        let (_, certificate) = X509Certificate::from_der(&leaf_der)
            .map_err(|_| malformed_attestation("eval certificate"))?;
        let verifying_key = VerifyingKey::from_sec1_bytes(
            certificate.public_key().subject_public_key.data.as_ref(),
        )
        .map_err(|_| malformed_attestation("eval public key"))?;
        cose.verify_signature(&[], |signature, data| {
            let signature = Signature::from_slice(signature)
                .map_err(|_| bootproof_sdk::format::Error::BadSignature)?;
            verifying_key
                .verify(data, &signature)
                .map_err(|_| bootproof_sdk::format::Error::BadSignature)
        })?;

        let actual_nonce = value_bytes(&payload, "nonce")?;
        if actual_nonce != nonce {
            return Err(bootproof_sdk::format::Error::InvalidNonce);
        }
        let actual_pcrs = value_pcrs(&payload)?;
        for (index, expected) in expected_pcrs {
            if actual_pcrs.get(index) != Some(expected) {
                return Err(bootproof_sdk::format::Error::InvalidAAD(
                    format!("pcr {index}").into(),
                ));
            }
        }
        Ok(payload)
    }
}

fn decode_pem(pem: &str) -> std::result::Result<Vec<u8>, bootproof_sdk::format::Error> {
    let encoded = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    BASE64
        .decode(encoded)
        .map_err(|_| malformed_attestation("eval certificate pem"))
}

fn value_map(
    value: &Value,
) -> std::result::Result<&BTreeMap<Value, Value>, bootproof_sdk::format::Error> {
    let Value::Map(map) = value else {
        return Err(malformed_attestation("eval payload map"));
    };
    Ok(map)
}

fn value_bytes<'a>(
    value: &'a Value,
    name: &'static str,
) -> std::result::Result<&'a [u8], bootproof_sdk::format::Error> {
    let Some(Value::Bytes(bytes)) = value_map(value)?.get(&Value::Text(name.to_owned())) else {
        return Err(missing_attestation(name));
    };
    Ok(bytes)
}

fn value_pcrs(value: &Value) -> std::result::Result<NitroPcrs, bootproof_sdk::format::Error> {
    let Some(Value::Map(pcrs)) = value_map(value)?.get(&Value::Text("pcrs".to_owned())) else {
        return Err(missing_attestation("pcrs"));
    };
    pcrs.iter()
        .map(|(index, value)| {
            let Value::Integer(index) = index else {
                return Err(malformed_attestation("pcr index"));
            };
            let index = u8::try_from(*index).map_err(|_| malformed_attestation("pcr index"))?;
            let Value::Bytes(value) = value else {
                return Err(malformed_attestation("pcr value"));
            };
            Ok((index, value.clone()))
        })
        .collect()
}

fn malformed_attestation(message: &'static str) -> bootproof_sdk::format::Error {
    bootproof_sdk::format::Error::MalformedData(message.into())
}

fn missing_attestation(message: &'static str) -> bootproof_sdk::format::Error {
    bootproof_sdk::format::Error::MissingData(message.into())
}

#[derive(Default)]
struct ControlledProvider {
    calls: AtomicUsize,
    fail: AtomicBool,
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
        EvalAttestationProvider.attest(nonce, user_data)
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
            key_exchange: match server_key_exchange {
                KeyExchangeSuite::X25519 => steve::protocol::KeyExchangeSuite::X25519,
                KeyExchangeSuite::XWingDraft10 => steve::protocol::KeyExchangeSuite::XWingDraft10,
            },
        },
        provider,
    )
    .unwrap();
    let steve_url = spawn_router(steve).await;
    let mut builder = Client::builder(&steve_url, expected_pcrs())
        .unwrap()
        .expected_key_exchange(expected_key_exchange)
        .request_timeout(request_timeout);
    builder.attestation_verifier = Arc::new(EvalAttestationVerifier);
    (builder.build().unwrap(), upstream_state)
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
        },
        activated_at: Instant::now(),
        sequences: SequenceTracker::default(),
    })
}

#[test]
fn expected_pcrs_require_nonzero_pcr_zero_one_and_two() {
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
fn signed_eval_verifier_rejects_bad_certificate_signature_pcr_and_nonce() {
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

    let mut bad_signature = CoseSign1::from_slice(&document).unwrap();
    bad_signature.signature[0] ^= 1;
    assert!(matches!(
        verifier.verify(
            &bad_signature.to_vec().unwrap(),
            &expected_pcrs(),
            Duration::ZERO,
            &nonce
        ),
        Err(bootproof_sdk::format::Error::BadSignature)
    ));

    let mut bad_certificate = CoseSign1::from_slice(&document).unwrap();
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
            &bad_certificate.to_vec().unwrap(),
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
    assert_eq!(
        upstream.last_request.read().unwrap().as_ref().unwrap().1,
        b"xwing secret request"
    );
    let second = client.rotate_session().await.unwrap();
    assert_ne!(first.session_id, second.session_id);
    assert_eq!(provider.calls.load(AtomicOrdering::Relaxed), 2);
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
