use std::{collections::BTreeMap, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use coset::{CoseSign1, TaggedCborSerializable};
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier as SignatureVerifier};
use serde_cbor::Value;
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use super::{AttestationVerifier, NitroPcrs};

const EVAL_LEAF_CERT_PEM: &str = include_str!("../../../tests/e2e/fixtures/eval-leaf-cert.pem");

#[derive(Debug)]
pub(crate) struct EvalAttestationVerifier;

impl AttestationVerifier for EvalAttestationVerifier {
    fn verify(
        &self,
        document: &[u8],
        expected_pcrs: &NitroPcrs,
        _now: Duration,
        nonce: &[u8; 32],
    ) -> std::result::Result<Value, bootproof_sdk::format::Error> {
        let cose = CoseSign1::from_tagged_slice(document)
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
                let detail = ["pcr ", &index.to_string()].concat();
                return Err(bootproof_sdk::format::Error::InvalidAAD(detail.into()));
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
