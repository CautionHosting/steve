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
pub const X25519_KEY_MATERIAL_LEN: usize = 32;
pub const XWING_CLIENT_KEY_MATERIAL_LEN: usize = 1_216;
pub const XWING_SERVER_KEY_MATERIAL_LEN: usize = 1_120;

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
    #[error("unsupported key exchange suite")]
    UnsupportedKeyExchange,
    #[error("invalid CBOR")]
    InvalidCbor,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("message authentication failed")]
    Authentication,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum KeyExchangeSuite {
    #[serde(rename = "X25519")]
    X25519,
    #[serde(rename = "XWING-DRAFT10")]
    XWingDraft10,
}

impl KeyExchangeSuite {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::XWingDraft10 => "XWING-DRAFT10",
        }
    }

    pub const fn client_key_material_len(self) -> usize {
        match self {
            Self::X25519 => X25519_KEY_MATERIAL_LEN,
            Self::XWingDraft10 => XWING_CLIENT_KEY_MATERIAL_LEN,
        }
    }

    pub const fn server_key_material_len(self) -> usize {
        match self {
            Self::X25519 => X25519_KEY_MATERIAL_LEN,
            Self::XWingDraft10 => XWING_SERVER_KEY_MATERIAL_LEN,
        }
    }

    pub fn validate_key_material(
        self,
        client_key_material: &[u8],
        server_key_material: &[u8],
    ) -> Result<(), ProtocolError> {
        if client_key_material.len() != self.client_key_material_len()
            || server_key_material.len() != self.server_key_material_len()
        {
            return Err(ProtocolError::InvalidLength);
        }
        Ok(())
    }
}

impl std::fmt::Display for KeyExchangeSuite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for KeyExchangeSuite {
    type Err = ProtocolError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X25519" => Ok(Self::X25519),
            "XWING-DRAFT10" => Ok(Self::XWingDraft10),
            _ => Err(ProtocolError::UnsupportedKeyExchange),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionRequest {
    pub version: u8,
    pub key_exchange: KeyExchangeSuite,
    #[serde(with = "serde_bytes")]
    pub client_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub client_key_material: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub context_hash: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    pub version: u8,
    pub key_exchange: KeyExchangeSuite,
    #[serde(with = "serde_bytes")]
    pub session_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub server_key_material: Vec<u8>,
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
    pub key_exchange: KeyExchangeSuite,
    pub session_id: String,
    pub transcript_hash: String,
    pub binder: String,
}

impl AttestedBinding {
    pub fn new(
        key_exchange: KeyExchangeSuite,
        session_id: &[u8; SESSION_ID_LEN],
        transcript_hash: &[u8; 32],
        binder: &[u8; 32],
    ) -> Self {
        Self {
            protocol: PROTOCOL_ID.to_string(),
            key_exchange,
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
    key_exchange: KeyExchangeSuite,
    client_nonce: &[u8; NONCE_LEN],
    client_key_material: &[u8],
    server_key_material: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
    context_hash: &[u8; CONTEXT_HASH_LEN],
) -> Result<Vec<u8>, ProtocolError> {
    key_exchange.validate_key_material(client_key_material, server_key_material)?;
    let suite = key_exchange.as_str().as_bytes();
    let mut transcript = Vec::with_capacity(
        PROTOCOL_MAGIC.len()
            + suite.len()
            + 1
            + NONCE_LEN
            + client_key_material.len()
            + server_key_material.len()
            + SESSION_ID_LEN
            + CONTEXT_HASH_LEN,
    );
    transcript.extend_from_slice(PROTOCOL_MAGIC);
    transcript.extend_from_slice(suite);
    transcript.push(0);
    transcript.extend_from_slice(client_nonce);
    transcript.extend_from_slice(client_key_material);
    transcript.extend_from_slice(server_key_material);
    transcript.extend_from_slice(session_id);
    transcript.extend_from_slice(context_hash);
    Ok(transcript)
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
    fn key_exchange_suite_has_exact_wire_names_and_lengths() {
        assert_eq!(
            serde_json::to_string(&KeyExchangeSuite::X25519).unwrap(),
            "\"X25519\""
        );
        assert_eq!(
            serde_json::to_string(&KeyExchangeSuite::XWingDraft10).unwrap(),
            "\"XWING-DRAFT10\""
        );
        assert_eq!(
            "X25519".parse::<KeyExchangeSuite>().unwrap(),
            KeyExchangeSuite::X25519
        );
        assert_eq!(
            "XWING-DRAFT10".parse::<KeyExchangeSuite>().unwrap(),
            KeyExchangeSuite::XWingDraft10
        );
        assert!("x25519".parse::<KeyExchangeSuite>().is_err());
        assert_eq!(
            KeyExchangeSuite::X25519.client_key_material_len(),
            X25519_KEY_MATERIAL_LEN
        );
        assert_eq!(
            KeyExchangeSuite::XWingDraft10.client_key_material_len(),
            XWING_CLIENT_KEY_MATERIAL_LEN
        );
        assert_eq!(
            KeyExchangeSuite::XWingDraft10.server_key_material_len(),
            XWING_SERVER_KEY_MATERIAL_LEN
        );
    }

    #[test]
    fn transcript_binds_suite_and_rejects_wrong_material_lengths() {
        let client_nonce = [1u8; NONCE_LEN];
        let client_key_material = [2u8; X25519_KEY_MATERIAL_LEN];
        let server_key_material = [3u8; X25519_KEY_MATERIAL_LEN];
        let session_id = [4u8; SESSION_ID_LEN];
        let context_hash = [5u8; CONTEXT_HASH_LEN];
        let transcript = build_transcript(
            KeyExchangeSuite::X25519,
            &client_nonce,
            &client_key_material,
            &server_key_material,
            &session_id,
            &context_hash,
        )
        .unwrap();
        let suite_offset = PROTOCOL_MAGIC.len();
        assert_eq!(
            &transcript[suite_offset..suite_offset + "X25519\0".len()],
            b"X25519\0"
        );
        assert!(
            build_transcript(
                KeyExchangeSuite::XWingDraft10,
                &client_nonce,
                &client_key_material,
                &server_key_material,
                &session_id,
                &context_hash,
            )
            .is_err()
        );
    }

    #[test]
    fn session_cbor_uses_suite_agnostic_key_material_field_names() {
        let request = SessionRequest {
            version: VERSION,
            key_exchange: KeyExchangeSuite::X25519,
            client_nonce: vec![1; NONCE_LEN],
            client_key_material: vec![2; X25519_KEY_MATERIAL_LEN],
            context_hash: vec![3; CONTEXT_HASH_LEN],
        };
        let response = SessionResponse {
            version: VERSION,
            key_exchange: KeyExchangeSuite::X25519,
            session_id: vec![4; SESSION_ID_LEN],
            server_key_material: vec![5; X25519_KEY_MATERIAL_LEN],
            attestation_document: vec![6],
            expires_in_seconds: 30,
        };
        let request_fields = cbor_map_keys(&encode_cbor(&request).unwrap());
        let response_fields = cbor_map_keys(&encode_cbor(&response).unwrap());

        assert!(request_fields.contains("key_exchange"));
        assert!(request_fields.contains("client_key_material"));
        assert!(!request_fields.contains("client_public_key"));
        assert!(response_fields.contains("key_exchange"));
        assert!(response_fields.contains("server_key_material"));
        assert!(!response_fields.contains("server_public_key"));
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
        key_exchange: KeyExchangeSuite,
        client_nonce: String,
        client_key_material: String,
        server_key_material: String,
        session_id: String,
        context_hash: String,
        shared_secret: String,
        session_request_cbor: String,
        session_response_cbor: String,
        transcript: String,
        transcript_hash: String,
        c2s_key: String,
        s2c_key: String,
        c2s_iv_prefix: String,
        s2c_iv_prefix: String,
        binder: String,
        confirmation_plaintext: String,
        confirmation_ciphertext: String,
        confirmation_record_cbor: String,
        sequence: Option<String>,
        c2s_application_iv: Option<String>,
        c2s_application_aad: Option<String>,
    }

    #[test]
    fn shared_v2_vectors_cover_both_suites_and_full_handshake_records() {
        assert_shared_vector(
            include_str!("../../../test-vectors/e2p-v2.json"),
            KeyExchangeSuite::X25519,
        );
        assert_shared_vector(
            include_str!("../../../test-vectors/e2p-v2-xwing.json"),
            KeyExchangeSuite::XWingDraft10,
        );
    }

    fn assert_shared_vector(json: &str, expected_suite: KeyExchangeSuite) {
        let vector: TestVector = serde_json::from_str(json).unwrap();
        assert_eq!(vector.key_exchange, expected_suite);
        let client_nonce = hex_fixed(&vector.client_nonce);
        let client_key_material = hex_bytes(&vector.client_key_material);
        let server_key_material = hex_bytes(&vector.server_key_material);
        vector
            .key_exchange
            .validate_key_material(&client_key_material, &server_key_material)
            .unwrap();
        let session_id = hex_fixed(&vector.session_id);
        let context_hash = hex_fixed(&vector.context_hash);
        let shared_secret = hex_fixed(&vector.shared_secret);
        let expected_hash = hex_fixed(&vector.transcript_hash);
        let request = SessionRequest {
            version: VERSION,
            key_exchange: vector.key_exchange,
            client_nonce: client_nonce.to_vec(),
            client_key_material: client_key_material.clone(),
            context_hash: context_hash.to_vec(),
        };
        assert_eq!(
            encode_cbor(&request).unwrap(),
            hex_bytes(&vector.session_request_cbor)
        );
        let response = SessionResponse {
            version: VERSION,
            key_exchange: vector.key_exchange,
            session_id: session_id.to_vec(),
            server_key_material: server_key_material.clone(),
            attestation_document: vec![0xaa, 0xbb, 0xcc],
            expires_in_seconds: 30,
        };
        assert_eq!(
            encode_cbor(&response).unwrap(),
            hex_bytes(&vector.session_response_cbor)
        );
        let transcript = build_transcript(
            vector.key_exchange,
            &client_nonce,
            &client_key_material,
            &server_key_material,
            &session_id,
            &context_hash,
        )
        .unwrap();
        assert_eq!(transcript, hex_bytes(&vector.transcript));
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
        assert_eq!(
            expected_hash.as_slice(),
            hex_bytes(&vector.confirmation_plaintext)
        );
        let confirmation_ciphertext = secrets
            .seal(
                Direction::ClientToServer,
                MessageType::Confirmation,
                &session_id,
                0,
                &expected_hash,
            )
            .unwrap();
        assert_eq!(
            confirmation_ciphertext,
            hex_bytes(&vector.confirmation_ciphertext)
        );
        assert_eq!(
            encode_cbor(&Envelope {
                version: VERSION,
                session_id: session_id.to_vec(),
                sequence: 0u64.to_be_bytes().to_vec(),
                ciphertext: confirmation_ciphertext,
            })
            .unwrap(),
            hex_bytes(&vector.confirmation_record_cbor)
        );

        if let Some(sequence) = vector.sequence {
            let sequence = sequence.parse().unwrap();
            assert_eq!(
                message_nonce(&secrets.c2s_iv_prefix, sequence).as_slice(),
                hex_bytes(vector.c2s_application_iv.as_deref().unwrap())
            );
            assert_eq!(
                associated_data(
                    MessageType::Application,
                    Direction::ClientToServer,
                    &session_id,
                    sequence,
                ),
                hex_bytes(vector.c2s_application_aad.as_deref().unwrap())
            );
        }
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

    fn cbor_map_keys(bytes: &[u8]) -> std::collections::BTreeSet<String> {
        let value: ciborium::Value = ciborium::from_reader(bytes).unwrap();
        let ciborium::Value::Map(fields) = value else {
            panic!("expected a CBOR map");
        };
        fields
            .into_iter()
            .filter_map(|(key, _)| match key {
                ciborium::Value::Text(key) => Some(key),
                _ => None,
            })
            .collect()
    }
}
