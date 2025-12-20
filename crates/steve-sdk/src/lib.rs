//! Steve SDK, the Enclave Encrypt Client

use reqwest::{Client, Method, Url};

pub type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

pub struct RequestBuilder {
    session: Session,
    url: Url,
}

#[derive(Clone, Debug)]
pub struct Session {
    reqwest: Client,
    prefix_url: Url,
}

impl Session {
    // TODO: pass in verifying key, use the client to perform attestation and set up a shared key.
    // NOTE: verifying key should be acquired from attestation.
    pub async fn new(client: Client, base_url: impl AsRef<str>) -> Result<Self> {
        let prefix_url = Url::parse(base_url.as_ref())?;

        Ok(Self {
            reqwest: client,
            prefix_url,
        })
    }

    pub fn request(&self, method: Method, path: impl AsRef<str>) -> Result<RequestBuilder> {
        Ok(RequestBuilder {
            session: self.clone(),
            url: Url::options()
                .base_url(Some(&self.prefix_url))
                .parse(path.as_ref())?,
        })
    }
}
