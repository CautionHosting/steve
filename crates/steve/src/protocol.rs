use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const VERSION: u8 = 2;
pub const PROTOCOL_ID: &str = "STEVE-E2P-V2";
pub const PROTOCOL_MAGIC: &[u8] = b"STEVE-E2P-V2\0";
pub const SESSION_ID_LEN: usize = 16;
pub const NONCE_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const CONTEXT_HASH_LEN: usize = 32;
pub const SEQUENCE_LEN: usize = 8;

const LABEL_C2S_KEY: &[u8] = b"steve-e2p-v2/c2s-key";
const LABEL_S2C_KEY: &[u8] = b"steve-e2p-v2/s2c-key";
const LABEL_C2S_IV: &[u8] = b"steve-e2p-v2/c2s-iv";
const LABEL_S2C_IV: &[u8] = b"steve-e2p-v2/s2c-iv";
const LABEL_BINDER: &[u8] = b"steve-e2p-v2/attestation-binder";

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid field length")]
    InvalidLength,
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("invalid CBOR")]
    InvalidCbor,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("message authentication failed")]
    Authentication,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionRequest {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub client_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub client_public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub context_hash: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub session_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub server_public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub attestation_document: Vec<u8>,
    pub expires_in_seconds: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub session_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sequence: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    pub fn validate(&self) -> Result<([u8; SESSION_ID_LEN], u64), ProtocolError> {
        if self.version != VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        let session_id = fixed::<SESSION_ID_LEN>(&self.session_id)?;
        let sequence = u64::from_be_bytes(fixed::<SEQUENCE_LEN>(&self.sequence)?);
        Ok((session_id, sequence))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestedBinding {
    pub protocol: String,
    pub session_id: String,
    pub transcript_hash: String,
    pub binder: String,
}

impl AttestedBinding {
    pub fn new(
        session_id: &[u8; SESSION_ID_LEN],
        transcript_hash: &[u8; 32],
        binder: &[u8; 32],
    ) -> Self {
        Self {
            protocol: PROTOCOL_ID.to_string(),
            session_id: URL_SAFE_NO_PAD.encode(session_id),
            transcript_hash: URL_SAFE_NO_PAD.encode(transcript_hash),
            binder: URL_SAFE_NO_PAD.encode(binder),
        }
    }
}

pub struct SessionSecrets {
    c2s_key: Zeroizing<[u8; 32]>,
    s2c_key: Zeroizing<[u8; 32]>,
    c2s_iv_prefix: Zeroizing<[u8; 4]>,
    s2c_iv_prefix: Zeroizing<[u8; 4]>,
    binder: Zeroizing<[u8; 32]>,
}

impl SessionSecrets {
    pub fn binder(&self) -> &[u8; 32] {
        &self.binder
    }

    pub fn seal(
        &self,
        direction: Direction,
        message_type: MessageType,
        session_id: &[u8; SESSION_ID_LEN],
        sequence: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let (key, prefix) = self.material(direction);
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ProtocolError::KeyDerivation)?;
        let nonce_bytes = message_nonce(prefix, sequence);
        let aad = associated_data(message_type, direction, session_id, sequence);
        cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| ProtocolError::Authentication)
    }

    pub fn open(
        &self,
        direction: Direction,
        message_type: MessageType,
        session_id: &[u8; SESSION_ID_LEN],
        sequence: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let (key, prefix) = self.material(direction);
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ProtocolError::KeyDerivation)?;
        let nonce_bytes = message_nonce(prefix, sequence);
        let aad = associated_data(message_type, direction, session_id, sequence);
        cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| ProtocolError::Authentication)
    }

    fn material(&self, direction: Direction) -> (&[u8; 32], &[u8; 4]) {
        match direction {
            Direction::ClientToServer => (&self.c2s_key, &self.c2s_iv_prefix),
            Direction::ServerToClient => (&self.s2c_key, &self.s2c_iv_prefix),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Direction {
    ClientToServer = 0,
    ServerToClient = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageType {
    Confirmation = 0,
    Application = 1,
}

pub fn build_transcript(
    client_nonce: &[u8; NONCE_LEN],
    client_public_key: &[u8; KEY_LEN],
    server_public_key: &[u8; KEY_LEN],
    session_id: &[u8; SESSION_ID_LEN],
    context_hash: &[u8; CONTEXT_HASH_LEN],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(
        PROTOCOL_MAGIC.len() + NONCE_LEN + KEY_LEN + KEY_LEN + SESSION_ID_LEN + CONTEXT_HASH_LEN,
    );
    transcript.extend_from_slice(PROTOCOL_MAGIC);
    transcript.extend_from_slice(client_nonce);
    transcript.extend_from_slice(client_public_key);
    transcript.extend_from_slice(server_public_key);
    transcript.extend_from_slice(session_id);
    transcript.extend_from_slice(context_hash);
    transcript
}

pub fn transcript_hash(transcript: &[u8]) -> [u8; 32] {
    Sha256::digest(transcript).into()
}

pub fn derive_secrets(
    shared_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<SessionSecrets, ProtocolError> {
    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret);
    Ok(SessionSecrets {
        c2s_key: Zeroizing::new(expand::<32>(&hkdf, LABEL_C2S_KEY)?),
        s2c_key: Zeroizing::new(expand::<32>(&hkdf, LABEL_S2C_KEY)?),
        c2s_iv_prefix: Zeroizing::new(expand::<4>(&hkdf, LABEL_C2S_IV)?),
        s2c_iv_prefix: Zeroizing::new(expand::<4>(&hkdf, LABEL_S2C_IV)?),
        binder: Zeroizing::new(expand::<32>(&hkdf, LABEL_BINDER)?),
    })
}

fn expand<const N: usize>(hkdf: &Hkdf<Sha256>, label: &[u8]) -> Result<[u8; N], ProtocolError> {
    let mut output = [0u8; N];
    hkdf.expand(label, &mut output)
        .map_err(|_| ProtocolError::KeyDerivation)?;
    Ok(output)
}

pub fn message_nonce(prefix: &[u8; 4], sequence: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(prefix);
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

pub fn associated_data(
    message_type: MessageType,
    direction: Direction,
    session_id: &[u8; SESSION_ID_LEN],
    sequence: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PROTOCOL_MAGIC.len() + 2 + SESSION_ID_LEN + SEQUENCE_LEN);
    aad.extend_from_slice(PROTOCOL_MAGIC);
    aad.push(message_type as u8);
    aad.push(direction as u8);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

pub fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let mut output = Vec::new();
    ciborium::into_writer(value, &mut output).map_err(|_| ProtocolError::InvalidCbor)?;
    Ok(output)
}

pub fn decode_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    ciborium::from_reader(bytes).map_err(|_| ProtocolError::InvalidCbor)
}

pub fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProtocolError> {
    bytes.try_into().map_err(|_| ProtocolError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_and_aad_are_direction_and_sequence_bound() {
        let session_id = [7u8; SESSION_ID_LEN];
        let prefix = [1, 2, 3, 4];
        assert_ne!(message_nonce(&prefix, 1), message_nonce(&prefix, 2));
        assert_ne!(
            associated_data(
                MessageType::Application,
                Direction::ClientToServer,
                &session_id,
                1,
            ),
            associated_data(
                MessageType::Application,
                Direction::ServerToClient,
                &session_id,
                1,
            )
        );
    }

    #[test]
    fn traffic_keys_cannot_cross_directions() {
        let session_id = [9u8; SESSION_ID_LEN];
        let secrets = derive_secrets(&[3u8; 32], &[4u8; 32]).unwrap();
        let ciphertext = secrets
            .seal(
                Direction::ClientToServer,
                MessageType::Application,
                &session_id,
                1,
                b"hello",
            )
            .unwrap();
        assert!(
            secrets
                .open(
                    Direction::ServerToClient,
                    MessageType::Application,
                    &session_id,
                    1,
                    &ciphertext,
                )
                .is_err()
        );
    }

    #[derive(Deserialize)]
    struct TestVector {
        client_nonce: String,
        client_public_key: String,
        server_public_key: String,
        session_id: String,
        context_hash: String,
        shared_secret: String,
        transcript_hash: String,
        c2s_key: String,
        s2c_key: String,
        c2s_iv_prefix: String,
        s2c_iv_prefix: String,
        binder: String,
        sequence: String,
        c2s_application_iv: String,
        c2s_application_aad: String,
    }

    #[test]
    fn shared_v2_vector_matches_browser_implementation() {
        let vector: TestVector =
            serde_json::from_str(include_str!("../../../test-vectors/e2p-v2.json")).unwrap();
        let client_nonce = hex_fixed(&vector.client_nonce);
        let client_public_key = hex_fixed(&vector.client_public_key);
        let server_public_key = hex_fixed(&vector.server_public_key);
        let session_id = hex_fixed(&vector.session_id);
        let context_hash = hex_fixed(&vector.context_hash);
        let shared_secret = hex_fixed(&vector.shared_secret);
        let expected_hash = hex_fixed(&vector.transcript_hash);
        let transcript = build_transcript(
            &client_nonce,
            &client_public_key,
            &server_public_key,
            &session_id,
            &context_hash,
        );
        assert_eq!(transcript_hash(&transcript), expected_hash);

        let secrets = derive_secrets(&shared_secret, &expected_hash).unwrap();
        assert_eq!(secrets.c2s_key.as_ref(), hex_bytes(&vector.c2s_key));
        assert_eq!(secrets.s2c_key.as_ref(), hex_bytes(&vector.s2c_key));
        assert_eq!(
            secrets.c2s_iv_prefix.as_ref(),
            hex_bytes(&vector.c2s_iv_prefix)
        );
        assert_eq!(
            secrets.s2c_iv_prefix.as_ref(),
            hex_bytes(&vector.s2c_iv_prefix)
        );
        assert_eq!(secrets.binder.as_ref(), hex_bytes(&vector.binder));

        let sequence = vector.sequence.parse().unwrap();
        assert_eq!(
            message_nonce(&secrets.c2s_iv_prefix, sequence).as_slice(),
            hex_bytes(&vector.c2s_application_iv)
        );
        assert_eq!(
            associated_data(
                MessageType::Application,
                Direction::ClientToServer,
                &session_id,
                sequence,
            ),
            hex_bytes(&vector.c2s_application_aad)
        );
    }

    fn hex_fixed<const N: usize>(value: &str) -> [u8; N] {
        hex_bytes(value).try_into().unwrap()
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
}
