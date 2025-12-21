//! Secure Transport Encryption Via Enclave

use std::sync::Arc;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing, Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{SigningKey, Signer};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use tokio::net::TcpListener;
use tracing::{debug, error};
use x25519_dalek::{EphemeralSecret, PublicKey};

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

const APP_UPSTREAM: &str = "http://127.0.0.1:8083";

#[derive(Debug, Clone, serde::Serialize)]
struct MetadataOutput {
    verifying_key: [u8; 32],
}

// NOTE: Be wary when impl the following traits:
// * Clone
// * Debug
// * Display
//
// Use an Arc instead of .clone()

struct AppState {
    persistent_decryption_key: Key<Aes256Gcm>,
    signing_key: SigningKey,
    http_client: Client,
    upstream_url: url::Url,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("persistent_decryption_key", &"<secret_key>")
            .field("signing_key", &"<secret_key>")
            .finish()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    debug!("generating signing key");
    let signing_key = SigningKey::generate(&mut OsRng);
    let metadata_output = MetadataOutput {
        verifying_key: signing_key.verifying_key().to_bytes(),
    };

    debug!("setting up app state");

    // TODO: Use Keyfork reconstitution to get the E2 decryption key
    // We don't have access to that now, so instead generate an ephemeral one.
    //
    let app_state = AppState {
        persistent_decryption_key: Aes256Gcm::generate_key(OsRng),
        signing_key,
        http_client: Client::new(),
        upstream_url: url::Url::parse(APP_UPSTREAM)?,
    };

    let metadata_path = std::env::var("E2P_METADATA_FILE").unwrap_or_else(|e| {
        debug!("could not use E2P_METADATA_FILE: {e}");
        String::from("/metadata.json")
    });
    debug!(
        ?metadata_output,
        ?metadata_path,
        "writing public key to file"
    );

    let metadata_file = std::fs::File::create_new(&metadata_path)?;
    serde_json::to_writer(metadata_file, &metadata_output)?;

    debug!("launching proxy");
    run_proxy(app_state).await?;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct CreateSharedKeyRequest {
    public_key_bytes: [u8; 32],
    nonce: [u8; 16],
}

async fn create_shared_key(
    State(app_state): State<Arc<AppState>>,
    Json(data): Json<CreateSharedKeyRequest>,
) -> Json<serde_json::Value> {
    debug!(?data, "performing ECDH against their key"); 
    let their_pubkey = PublicKey::from(data.public_key_bytes);
    let our_privkey = EphemeralSecret::random_from_rng(OsRng);
    let our_pubkey = PublicKey::from(&our_privkey);
    let shared_secret = our_privkey.diffie_hellman(&their_pubkey);

    debug!("performing ECDH against the shared secret"); 

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut shared_key_bytes = [0u8; 256 / 8];
    hkdf.expand(b"key", &mut shared_key_bytes).unwrap();

    debug!("encrypting shared key with persistent key");
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let cipher = Aes256Gcm::new(&app_state.persistent_decryption_key);
    let ciphertext = cipher.encrypt(&nonce, &shared_key_bytes[..]).unwrap();

    // Prepend nonce to ciphertext so we can decrypt later
    let mut encrypted_shared_key = Vec::with_capacity(12 + ciphertext.len());
    encrypted_shared_key.extend_from_slice(&nonce);
    encrypted_shared_key.extend_from_slice(&ciphertext);

    debug!("signing our public key");
    let to_sign: Vec<u8> = data
        .nonce
        .iter()
        .chain(our_pubkey.as_bytes())
        .copied()
        .collect();
    let signature = app_state.signing_key.sign(&to_sign);

    // NOTE: signature.to_bytes() returns [u8; 64], which serde didn't impl Serialize for
    Json(json!({
        "public_key": our_pubkey.to_bytes(),
        "signature": &signature.to_bytes()[..],
        "enclave_encrypted_shared_key": encrypted_shared_key,
    }))
}

#[derive(Debug, Deserialize)]
struct DecryptedRequest {
    method: String,
    path: String,
    headers: std::collections::HashMap<String, String>,
    #[serde(with = "serde_bytes", default)]
    body: Option<Vec<u8>>,
}

#[derive(Debug, Serialize)]
struct EncryptedResponse {
    status: u16,
    headers: std::collections::HashMap<String, String>,
    #[serde(with = "serde_bytes")]
    body: Option<Vec<u8>>,
}


#[tracing::instrument(skip(app_state, encrypted_body))]
async fn handle_encrypted_request(
    app_state: &AppState,
    headers: &HeaderMap,
    encrypted_body: &[u8],
) -> Result<Response, String> { // TODO fixup using String as Err
    // Get and decode the encrypted shared key from header
    let e2p_key_header = headers
        .get("x-e2p-key")
        .ok_or("Missing X-E2P-Key header")?
        .to_str()
        .map_err(|_| "Invalid X-E2P-Key header")?;

    let encrypted_shared_key = BASE64
        .decode(e2p_key_header)
        .map_err(|_| "Invalid base64 in X-E2P-Key")?;

    if encrypted_shared_key.len() < 12 {
        return Err("Encrypted shared key too short".into());
    }

    // Decrypt the shared key
    let (nonce_bytes, ciphertext) = encrypted_shared_key.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(&app_state.persistent_decryption_key);
    let shared_key_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Failed to decrypt shared key")?;

    let shared_key = Key::<Aes256Gcm>::from_slice(&shared_key_bytes);
    let shared_cipher = Aes256Gcm::new(shared_key);

    // Decrypt the request body
    if encrypted_body.len() < 12 {
        return Err("Encrypted body too short".into());
    }

    let (iv_bytes, body_ciphertext) = encrypted_body.split_at(12);
    let iv = Nonce::from_slice(iv_bytes);
    let plaintext = shared_cipher
        .decrypt(iv, body_ciphertext)
        .map_err(|_| "Failed to decrypt request body")?;

    let request: DecryptedRequest =
        ciborium::from_reader(&plaintext[..]).map_err(|e| format!("Invalid request CBOR: {e}"))?;

    debug!(method = %request.method, path = %request.path, "forwarding decrypted request");

    // Build and send request to upstream app
    let method: Method = request
        .method
        .parse()
        .map_err(|_| "Invalid HTTP method")?;

    let url = app_state.upstream_url.join(&request.path)
        .map_err(|e| format!("Invalid path: {e}"))?;

    let mut req_builder = app_state.http_client.request(method, url);

    for (key, value) in &request.headers {
        if !key.eq_ignore_ascii_case("host")
            && !key.eq_ignore_ascii_case("content-length")
            && !key.eq_ignore_ascii_case("x-e2p-key")
            && !key.eq_ignore_ascii_case("x-e2p-original-method")
        {
            req_builder = req_builder.header(key, value);
        }
    }

    if let Some(ref body_bytes) = request.body {
        req_builder = req_builder.body(body_bytes.clone());
    }

    let upstream_response = req_builder
        .send()
        .await
        .map_err(|e| format!("Upstream request failed: {e}"))?;

    let status = upstream_response.status().as_u16();
    let mut response_headers = std::collections::HashMap::new();
    for (key, value) in upstream_response.headers() {
        if let Ok(v) = value.to_str() {
            response_headers.insert(key.to_string(), v.to_string());
        }
    }

    let response_body = upstream_response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read upstream response: {e}"))?;

    let body_bytes = if response_body.is_empty() {
        None
    } else {
        Some(response_body.to_vec())
    };

    let response_cbor = EncryptedResponse {
        status,
        headers: response_headers,
        body: body_bytes,
    };

    let mut response_plaintext = Vec::new();
    ciborium::into_writer(&response_cbor, &mut response_plaintext)
        .map_err(|e| format!("Failed to serialize response: {e}"))?;

    // Encrypt the response
    let response_iv = Aes256Gcm::generate_nonce(OsRng);
    let response_ciphertext = shared_cipher
        .encrypt(&response_iv, response_plaintext.as_slice())
        .map_err(|_| "Failed to encrypt response")?;

    let mut encrypted_response = Vec::with_capacity(12 + response_ciphertext.len());
    encrypted_response.extend_from_slice(&response_iv);
    encrypted_response.extend_from_slice(&response_ciphertext);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(Body::from(encrypted_response))
        .unwrap())
}

/// Paths that should be passed through without encryption (bootstrap files)
const PASSTHROUGH_PATHS: &[&str] = &["/", "/enclave-sw.js", "/register.js"];

async fn passthrough_request(
    State(app_state): State<Arc<AppState>>,
    request: axum::extract::Request,
) -> Response {
    let path = request.uri().path();
    debug!(%path, "incoming request");

    // Check if this is a passthrough path
    if PASSTHROUGH_PATHS.contains(&path) {
        debug!(%path, "passthrough request (no encryption)");
        return forward_unencrypted(&app_state, request).await;
    }

    // Check if client is using E2E encryption
    let has_e2p_header = request.headers().contains_key("x-e2p-key");
    if !has_e2p_header {
        debug!(%path, "no X-E2P-Key header, forwarding unencrypted");
        return forward_unencrypted(&app_state, request).await;
    }

    // Handle encrypted request
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            error!("failed to read body: {e}");
            return (StatusCode::BAD_REQUEST, "Failed to read body").into_response();
        }
    };

    let result = handle_encrypted_request(&app_state, &parts.headers, &body_bytes).await;
    match result {
        Ok(response) => response,
        Err(e) => {
            error!("proxy error: {e}");
            (StatusCode::BAD_GATEWAY, format!("Proxy error: {e}")).into_response()
        }
    }
}

async fn forward_unencrypted(app_state: &AppState, request: axum::extract::Request) -> Response {
    let method = request.method().clone();
    let path = request.uri().path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(request.uri().path());
    let url = format!("{}{}", APP_UPSTREAM, path);

    let body_bytes = match axum::body::to_bytes(request.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            error!("failed to read request body: {e}");
            return (StatusCode::BAD_REQUEST, "Failed to read body").into_response();
        }
    };

    let upstream_response = match app_state.http_client
        .request(method, &url)
        .body(body_bytes.to_vec())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("upstream request failed: {e}");
            return (StatusCode::BAD_GATEWAY, format!("Upstream error: {e}")).into_response();
        }
    };

    let status = upstream_response.status();
    let headers = upstream_response.headers().clone();
    let body = match upstream_response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            error!("failed to read upstream response: {e}");
            return (StatusCode::BAD_GATEWAY, "Failed to read upstream").into_response();
        }
    };

    let mut response = Response::builder().status(status);
    for (key, value) in headers.iter() {
        response = response.header(key, value);
    }
    response.body(Body::from(body)).unwrap_or_else(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build response").into_response()
    })
}

async fn run_proxy(app_state: AppState) -> Result<()> {
    let state = Arc::new(app_state);

    let app = Router::new()
        .route("/e2p/v1/create_shared_key", routing::post(create_shared_key))
        .fallback(passthrough_request)
        .with_state(state);

    let listen_addr = std::env::var("STEVE_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    debug!(%listen_addr, "binding listener");
    let listener = TcpListener::bind(&listen_addr).await?;

    debug!("serving proxy");
    axum::serve(listener, app).await?;

    Ok(())
}

/*
 * client: start session
 * enclave-sdk: -- POST /attestation_bundle with ephemeral public key & nonce --> gateway
 * gateway -- /attestation_bundle --> enclave
 * enclave: generate shared key using ECDH+KDF? Use WebCrypto standard
 * enclave: generate attestation bundle
 * - enclave attestation (TDX/SEV/Nitro (deprecated))
 *   - PCRs
 *   - public verifying key (see above; end-goal: TPM backed)
 *   - ephemeral public encryption key
 *   - enclave encrypted bundle:
 *     - shared key
 *     - signed-by: enclave signing key
 * enclave -- first step attestation bundle --> gateway
 * gateway: generate attestation bundle & append
 * - gateway attestation (TDX/SEV)
 *   - PCRs
 *   - TPM-backed TLS with nginx
 *   - TLS certfp
 * - full-machine attestation (TPM 2.0)
 * gateway -- send bundle --> enclave-sdk
 * enclave-sdk: validate bundle & TLS certfp, ECDH the public key into the secret key, store
 */

/*
 * Client <-> Enclave Service Worker
 *
 * Assume the service worker has already established a connection with the enclave and ECDH'd a
 * shared secret.
 *
 * Client requests /whatever, Service Worker MITM's and encrypts all traffic. On the server side,
 * the body of every request is decrypted before being passed to the internal application.
 *
 * client -- "hello world" --> application
 * | service worker intercepts, attaches enclave-encrypted shared key |
 * shared_key.aes256gcm.encrypt(body) --> E2KS + encrypted body
 * service worker -- E2KS + encrypted body --> application
 * | enclave decrypter intercepts, decrypts enclave-encrypted shared key |
 * shared_key.aes256gcm.decrypt(body) --> "hello world"
 * enclave decryptor -- "hello world" --> application
 *
 * \:D/
 */
