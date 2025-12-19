use x25519_dalek::EphemeralSecret;
use ed25519_dalek::SigningKey;

// NOTE: The ephemeral key should be generated and signed with the persistent key, which the client
// can then use to derive their own shared secret. We should have a long term persistence key which
// we encrypt the shared secret to, and have the client send the encrypted shared secret back to us
// for each request, so it can be shared to multiple enclaves that share the decryption secret.

#[derive(Debug, Clone, serde::Serialize)]
struct MetadataOutput {
    public_verifying_key: [u8; 32],
}

fn main() {
    let mut csprng = rand::rngs::OsRng;
    let private_key = SigningKey::generate(&mut csprng);
    let metadata_output = MetadataOutput {
        public_verifying_key: private_key.verifying_key().to_bytes(),
    };
    let metadata_file = std::fs::File::create_new("/metadata.json").unwrap();
    serde_json::to_writer(metadata_file, &metadata_output).unwrap();

    loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
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
