//! Secure Transport Encryption Via Enclave

use std::sync::Arc;

use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use aes_gcm::{Aes256Gcm, Key, aead::{KeyInit, Aead, AeadCore}};
use axum::{
    Json, Router,
    extract::{self, State},
    routing,
};
use ed25519_dalek::{SigningKey, Signer};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};
use serde_json::json;

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

// NOTE: The ephemeral key should be generated and signed with the persistent key, which the client
// can then use to derive their own shared secret. We should have a long term persistence key which
// we encrypt the shared secret to, and have the client send the encrypted shared secret back to us
// for each request, so it can be shared to multiple enclaves that share the decryption secret.

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
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("persistent_decryption_key", &"<secret key>")
            .field("signing_key", &"<secret key>")
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
    let app_state = AppState {
        persistent_decryption_key: Aes256Gcm::generate_key(OsRng),
        signing_key,
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
    let metadata_file = std::fs::File::create_new(metadata_path)?;
    serde_json::to_writer(metadata_file, &metadata_output)?;

    debug!("launching web app");
    run_proxy(app_state).await?;

    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct CreateE2PSharedKey {
    public_key_bytes: [u8; 32],
    nonce: [u8; 16],
}

// TODO: Error handling.

#[tracing::instrument(skip(app_state, data))]
#[axum::debug_handler]
async fn create_e2p_shared_key(
    State(app_state): State<Arc<AppState>>,
    Json(data): Json<CreateE2PSharedKey>,
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

    debug!("encrypting shared key bytes to persistent key");
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let cipher = Aes256Gcm::new(&app_state.persistent_decryption_key);
    let e2_encrypted_shared_key = cipher.encrypt(&nonce, &shared_key_bytes[..]).unwrap();

    debug!("signing our public key with the provided nonce");
    let bytes = data.nonce.iter().chain(our_pubkey.as_bytes()).copied().collect::<Vec<u8>>();
    let signature = app_state.signing_key.sign(&bytes);

    // NOTE: signature.to_bytes() returns [u8; 64], which serde didn't impl Serialize for
    Json(json!({
        "public_key": our_pubkey.to_bytes(),
        "signature": &signature.to_bytes()[..],
        "enclave_encrypted_shared_key": e2_encrypted_shared_key,
    }))
}

#[tracing::instrument]
async fn proxy_request(path: extract::MatchedPath) -> String {
    todo!()
}

async fn run_proxy(app_state: AppState) -> Result<()> {
    debug!("initializing router");
    let app = Router::new()
        .route(
            "/e2p/v1/create_shared_key",
            routing::post(create_e2p_shared_key),
        )
        .route("/{path}", routing::any(proxy_request))
        .with_state(std::sync::Arc::new(app_state));

    debug!("binding listener");
    let listener = TcpListener::bind("0.0.0.0:8080").await?;

    debug!("serving application");
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
