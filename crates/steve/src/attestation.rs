use bootproof::format::{Format, nitro::Nitro};

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("Nitro attestation failed: {0}")]
    Failed(#[from] bootproof::format::BoxError),
    #[cfg(feature = "eval-attestation")]
    #[error("local eval attestation failed: {0}")]
    Eval(String),
}

pub trait AttestationProvider: Send + Sync {
    fn attest(&self, nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>, AttestationError>;
}

#[derive(Debug, Default)]
pub struct NitroAttestationProvider;

impl AttestationProvider for NitroAttestationProvider {
    fn attest(&self, nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>, AttestationError> {
        Nitro
            .generate(Some(user_data), Some(nonce))
            .map_err(AttestationError::Failed)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct FakeAttestationProvider {
        calls: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    }

    impl FakeAttestationProvider {
        pub fn last_call(&self) -> Option<(Vec<u8>, Vec<u8>)> {
            self.calls.lock().unwrap().last().cloned()
        }
    }

    impl AttestationProvider for FakeAttestationProvider {
        fn attest(&self, nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>, AttestationError> {
            self.calls
                .lock()
                .unwrap()
                .push((nonce.to_vec(), user_data.to_vec()));
            Ok(b"fake-nitro-attestation-document".to_vec())
        }
    }
}
