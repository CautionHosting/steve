//! Signed synthetic Nitro-shaped evidence for Docker E2E tests.
//!
//! This provider is compiled only with the non-default `eval-attestation`
//! feature. Its private key is public test material and provides no hardware
//! security or production trust.

use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use p384::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::DecodePrivateKey,
};
use serde::Serialize;
use serde_bytes::ByteBuf;

use crate::attestation::{AttestationError, AttestationProvider};

const MODULE_ID: &str = "steve-local-eval";
const COSE_SIGN1_TAG: u64 = 18;
const LEAF_KEY_PEM: &str = include_str!("../../../tests/e2e/fixtures/eval-leaf-key.pem");
const LEAF_CERT_PEM: &str = include_str!("../../../tests/e2e/fixtures/eval-leaf-cert.pem");

#[derive(Debug, Default)]
pub struct EvalAttestationProvider;

#[derive(Serialize)]
struct EvalPayload {
    module_id: &'static str,
    digest: &'static str,
    timestamp: u64,
    pcrs: BTreeMap<u8, ByteBuf>,
    certificate: ByteBuf,
    cabundle: Vec<ByteBuf>,
    user_data: ByteBuf,
    nonce: ByteBuf,
}

impl AttestationProvider for EvalAttestationProvider {
    fn attest(&self, nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>, AttestationError> {
        let leaf_key = SigningKey::from_pkcs8_pem(LEAF_KEY_PEM)
            .map_err(|error| AttestationError::Eval(error.to_string()))?;
        let leaf_cert = decode_pem(LEAF_CERT_PEM)?;
        let payload = encode(&EvalPayload {
            module_id: MODULE_ID,
            digest: "SHA384",
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| AttestationError::Eval(error.to_string()))?
                .as_millis() as u64,
            pcrs: [
                (0, ByteBuf::from(vec![0x10; 48])),
                (1, ByteBuf::from(vec![0x11; 48])),
                (2, ByteBuf::from(vec![0x12; 48])),
            ]
            .into_iter()
            .collect(),
            certificate: ByteBuf::from(leaf_cert),
            cabundle: Vec::new(),
            user_data: ByteBuf::from(user_data.to_vec()),
            nonce: ByteBuf::from(nonce.to_vec()),
        })?;

        // COSE protected header: { 1: -35 } (alg = ES384).
        let protected = encode(&BTreeMap::from([(1i32, -35i32)]))?;
        let sig_structure = encode(&(
            "Signature1",
            ByteBuf::from(protected.clone()),
            ByteBuf::new(),
            ByteBuf::from(payload.clone()),
        ))?;
        let signature: Signature = leaf_key.sign(&sig_structure);

        encode(&ciborium::tag::Required::<_, COSE_SIGN1_TAG>((
            ByteBuf::from(protected),
            BTreeMap::<i32, i32>::new(),
            ByteBuf::from(payload),
            ByteBuf::from(signature.to_bytes().to_vec()),
        )))
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, AttestationError> {
    let mut output = Vec::new();
    ciborium::into_writer(value, &mut output)
        .map_err(|error| AttestationError::Eval(error.to_string()))?;
    Ok(output)
}

fn decode_pem(pem: &str) -> Result<Vec<u8>, AttestationError> {
    let encoded = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    STANDARD
        .decode(encoded)
        .map_err(|error| AttestationError::Eval(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_is_cose_sign1_and_bound_to_inputs() {
        let provider = EvalAttestationProvider;
        let first = provider.attest(&[1; 32], b"first").unwrap();
        let second = provider.attest(&[2; 32], b"second").unwrap();

        assert_ne!(first, second);
        let decoded: ciborium::Value = ciborium::from_reader(first.as_slice()).unwrap();
        assert!(matches!(
            decoded,
            ciborium::Value::Tag(
                COSE_SIGN1_TAG,
                value
            ) if matches!(&*value, ciborium::Value::Array(values) if values.len() == 4)
        ));
    }
}
