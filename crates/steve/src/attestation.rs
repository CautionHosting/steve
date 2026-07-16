use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use serde_bytes::ByteBuf;

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("Nitro Security Module is unavailable")]
    Unavailable,
    #[error("Nitro attestation failed")]
    Failed,
}

pub trait AttestationProvider: Send + Sync {
    fn attest(&self, nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>, AttestationError>;
}

#[derive(Debug, Default)]
pub struct NitroAttestationProvider;

impl AttestationProvider for NitroAttestationProvider {
    fn attest(&self, nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>, AttestationError> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(AttestationError::Unavailable);
        }

        let response = nsm_process_request(
            fd,
            Request::Attestation {
                user_data: Some(ByteBuf::from(user_data.to_vec())),
                nonce: Some(ByteBuf::from(nonce.to_vec())),
                public_key: None,
            },
        );
        nsm_exit(fd);

        match response {
            Response::Attestation { document } => Ok(document),
            _ => Err(AttestationError::Failed),
        }
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
