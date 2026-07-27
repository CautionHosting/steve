//! Minimal browser boundary for STEVE's one-shot X-Wing client key exchange.

use wasm_bindgen::prelude::*;
use x_wing::{
    CIPHERTEXT_SIZE, DECAPSULATION_KEY_SIZE, Decapsulate, DecapsulationKey, Decapsulator,
    KeyExport, SharedKey,
};
use zeroize::Zeroize;

/// Opaque one-shot X-Wing decapsulator.
///
/// The decapsulation key is generated inside WASM and is never exported. A
/// decapsulation attempt consumes it, including attempts with malformed input.
#[wasm_bindgen]
pub struct XWingClient {
    decapsulation_key: Option<DecapsulationKey>,
}

#[wasm_bindgen]
impl XWingClient {
    /// Generate a fresh X-Wing key pair using the browser's CSPRNG.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<XWingClient, JsError> {
        let mut seed = [0_u8; DECAPSULATION_KEY_SIZE];
        getrandom::fill(&mut seed).map_err(|_| JsError::new("browser randomness unavailable"))?;
        let decapsulation_key = DecapsulationKey::from(seed);
        seed.zeroize();

        Ok(Self {
            decapsulation_key: Some(decapsulation_key),
        })
    }

    /// Return only the public encapsulation key.
    pub fn public_key(&self) -> Result<Vec<u8>, JsError> {
        self.public_key_bytes().map_err(JsError::new)
    }

    /// Decapsulate once, destroy the private key, and return the shared secret.
    pub fn decapsulate_and_destroy(
        &mut self,
        ciphertext: &[u8],
    ) -> Result<js_sys::Uint8Array, JsError> {
        let mut shared_secret = self.decapsulate_once(ciphertext).map_err(JsError::new)?;
        let output = js_sys::Uint8Array::from(shared_secret.as_slice());
        shared_secret.zeroize();
        Ok(output)
    }
}

impl XWingClient {
    fn public_key_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let decapsulation_key = self
            .decapsulation_key
            .as_ref()
            .ok_or("X-Wing client already consumed")?;
        Ok(decapsulation_key.encapsulation_key().to_bytes().to_vec())
    }

    fn decapsulate_once(&mut self, ciphertext: &[u8]) -> Result<SharedKey, &'static str> {
        let decapsulation_key = self
            .decapsulation_key
            .take()
            .ok_or("X-Wing client already consumed")?;

        if ciphertext.len() != CIPHERTEXT_SIZE {
            return Err("invalid X-Wing ciphertext");
        }
        let ciphertext = ciphertext
            .try_into()
            .map_err(|_| "invalid X-Wing ciphertext")?;
        Ok(decapsulation_key.decapsulate(&ciphertext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x_wing::{ENCAPSULATION_KEY_SIZE, Encapsulate, EncapsulationKey};

    #[test]
    fn public_key_interoperates_and_decapsulation_is_one_shot() {
        let mut client = XWingClient::new().unwrap();
        let public_key = client.public_key_bytes().unwrap();
        let public_key = EncapsulationKey::try_from(public_key.as_slice()).unwrap();
        let (ciphertext, expected_secret) = public_key.encapsulate();

        let mut shared_secret = client.decapsulate_once(ciphertext.as_slice()).unwrap();
        assert_eq!(shared_secret.as_slice(), expected_secret.as_slice());
        shared_secret.zeroize();
        assert!(client.public_key_bytes().is_err());
        assert!(client.decapsulate_once(ciphertext.as_slice()).is_err());
    }

    #[test]
    fn malformed_ciphertext_still_consumes_private_key() {
        let mut client = XWingClient::new().unwrap();

        assert!(client.decapsulate_once(&[0_u8; 1]).is_err());
        assert!(client.public_key_bytes().is_err());
    }

    #[test]
    fn corrupted_full_length_ciphertext_uses_implicit_rejection_and_consumes_key() {
        let mut client = XWingClient::new().unwrap();
        let public_key = client.public_key_bytes().unwrap();
        let public_key = EncapsulationKey::try_from(public_key.as_slice()).unwrap();
        let (mut ciphertext, expected_secret) = public_key.encapsulate();
        ciphertext[0] ^= 1;

        let mut rejected_secret = client.decapsulate_once(&ciphertext).unwrap();
        assert_eq!(rejected_secret.as_slice().len(), 32);
        assert_ne!(rejected_secret.as_slice(), expected_secret.as_slice());
        rejected_secret.zeroize();
        assert!(client.decapsulate_once(&ciphertext).is_err());
    }

    #[test]
    fn exported_surface_has_protocol_sizes() {
        let client = XWingClient::new().unwrap();

        assert_eq!(
            client.public_key_bytes().unwrap().len(),
            ENCAPSULATION_KEY_SIZE
        );
        assert_eq!(CIPHERTEXT_SIZE, 1120);
    }
}
