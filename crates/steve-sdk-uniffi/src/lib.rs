//! UniFFI facade for the native STEVE SDK.

use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, OnceLock},
    time::Duration,
};

use async_trait::async_trait;
use http::Method;
use steve_sdk::{
    Client, ClientBuilder, ExpectedPcrs, PcrPolicy, PcrTrustKey as CorePcrTrustKey,
    PcrTrustRecord as CorePcrTrustRecord, PcrTrustStore as CorePcrTrustStore, PcrTrustStoreError,
};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};

uniffi::setup_scaffolding!();

#[derive(Clone, Debug, uniffi::Record)]
pub struct SteveClientConfig {
    pub base_url: String,
    pub application_context: Option<Vec<u8>>,
    pub key_exchange: Option<KeyExchangeSuite>,
    pub session_rotation_interval_ms: Option<u64>,
    pub session_establishment_timeout_ms: Option<u64>,
    pub request_timeout_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum KeyExchangeSuite {
    X25519,
    XwingDraft10,
}

impl From<KeyExchangeSuite> for steve_sdk::KeyExchangeSuite {
    fn from(value: KeyExchangeSuite) -> Self {
        match value {
            KeyExchangeSuite::X25519 => Self::X25519,
            KeyExchangeSuite::XwingDraft10 => Self::XWingDraft10,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct Pcr {
    pub index: u8,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct PcrProfile {
    pub pcrs: Vec<Pcr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum PcrTrustStatus {
    Pinned,
    TofuEnrolled,
    TofuMatched,
}

impl From<steve_sdk::PcrTrustStatus> for PcrTrustStatus {
    fn from(value: steve_sdk::PcrTrustStatus) -> Self {
        match value {
            steve_sdk::PcrTrustStatus::Pinned => Self::Pinned,
            steve_sdk::PcrTrustStatus::TofuEnrolled => Self::TofuEnrolled,
            steve_sdk::PcrTrustStatus::TofuMatched => Self::TofuMatched,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct AttestationInfo {
    pub session_id: Vec<u8>,
    pub module_id: String,
    pub pcrs: PcrProfile,
    pub pcr_trust: PcrTrustStatus,
}

impl From<steve_sdk::AttestationInfo> for AttestationInfo {
    fn from(value: steve_sdk::AttestationInfo) -> Self {
        Self {
            session_id: value.session_id.to_vec(),
            module_id: value.module_id,
            pcrs: profile_from_core(&value.pcrs),
            pcr_trust: value.pcr_trust.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct HttpHeader {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<HttpHeader>,
    pub body: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum PcrTrustRecord {
    Inserted,
    Existing { profile: PcrProfile },
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PcrTrustStoreCallbackError {
    #[error("PCR trust store callback failed: {message}")]
    Failed { message: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for PcrTrustStoreCallbackError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed {
            message: value.to_string(),
        }
    }
}

#[uniffi::export(foreign)]
pub trait PcrTrustStore: Send + Sync {
    fn load_or_insert(
        &self,
        key: Vec<u8>,
        observed: PcrProfile,
    ) -> Result<PcrTrustRecord, PcrTrustStoreCallbackError>;
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum SteveError {
    #[error("{0}")]
    InvalidBaseUrl(String),
    #[error("{0}")]
    InvalidBaseOrigin(String),
    #[error("{0}")]
    InvalidExpectedPcr(String),
    #[error("{0}")]
    EmptyPcrPolicy(String),
    #[error("{0}")]
    InvalidAttestedPcr(String),
    #[error("{0}")]
    UnapprovedPcrProfile(String),
    #[error("{0}")]
    PcrTrustMismatch(String),
    #[error("{0}")]
    PcrTrustStore(String),
    #[error("{0}")]
    UrlEscapesBase(String),
    #[error("{0}")]
    InvalidHeaderName(String),
    #[error("{0}")]
    InvalidHeaderValue(String),
    #[error("{0}")]
    RequestHeaderUtf8(String),
    #[error("{0}")]
    Http(String),
    #[error("{0}")]
    Timeout(String),
    #[error("{0}")]
    ProtocolStatus(String),
    #[error("{0}")]
    AttestationVerification(String),
    #[error("{0}")]
    MalformedAttestation(String),
    #[error("{0}")]
    AttestationBinding(String),
    #[error("{0}")]
    AttestationBindingBase64(String),
    #[error("{0}")]
    Json(String),
    #[error("{0}")]
    Protocol(String),
    #[error("{0}")]
    SessionNotInitialized(String),
    #[error("{0}")]
    SessionClosed(String),
    #[error("{0}")]
    SequenceExhausted(String),
    #[error("{0}")]
    UnexpectedSequence(String),
    #[error("{0}")]
    InvalidResponseStatus(String),
    #[error("{0}")]
    DuplicatePcrIndex(String),
    #[error("{0}")]
    InvalidHttpMethod(String),
    #[error("{0}")]
    Runtime(String),
}

impl From<steve_sdk::Error> for SteveError {
    fn from(value: steve_sdk::Error) -> Self {
        let message = value.to_string();
        match value {
            steve_sdk::Error::InvalidBaseUrl(_) => Self::InvalidBaseUrl(message),
            steve_sdk::Error::InvalidBaseOrigin => Self::InvalidBaseOrigin(message),
            steve_sdk::Error::InvalidExpectedPcr { .. } => Self::InvalidExpectedPcr(message),
            steve_sdk::Error::EmptyPcrPolicy => Self::EmptyPcrPolicy(message),
            steve_sdk::Error::InvalidAttestedPcr { .. } => Self::InvalidAttestedPcr(message),
            steve_sdk::Error::UnapprovedPcrProfile => Self::UnapprovedPcrProfile(message),
            steve_sdk::Error::PcrTrustMismatch => Self::PcrTrustMismatch(message),
            steve_sdk::Error::PcrTrustStore(_) => Self::PcrTrustStore(message),
            steve_sdk::Error::UrlEscapesBase => Self::UrlEscapesBase(message),
            steve_sdk::Error::InvalidHeaderName(_) => Self::InvalidHeaderName(message),
            steve_sdk::Error::InvalidHeaderValue(_) => Self::InvalidHeaderValue(message),
            steve_sdk::Error::RequestHeaderUtf8(_) => Self::RequestHeaderUtf8(message),
            steve_sdk::Error::Http(_) => Self::Http(message),
            steve_sdk::Error::Timeout { .. } => Self::Timeout(message),
            steve_sdk::Error::ProtocolStatus { .. } => Self::ProtocolStatus(message),
            steve_sdk::Error::AttestationVerification(_) => Self::AttestationVerification(message),
            steve_sdk::Error::MalformedAttestation(_) => Self::MalformedAttestation(message),
            steve_sdk::Error::AttestationBinding(_) => Self::AttestationBinding(message),
            steve_sdk::Error::AttestationBindingBase64(_) => {
                Self::AttestationBindingBase64(message)
            }
            steve_sdk::Error::Json(_) => Self::Json(message),
            steve_sdk::Error::Protocol(_) => Self::Protocol(message),
            steve_sdk::Error::SessionNotInitialized => Self::SessionNotInitialized(message),
            steve_sdk::Error::SessionClosed => Self::SessionClosed(message),
            steve_sdk::Error::SequenceExhausted => Self::SequenceExhausted(message),
            steve_sdk::Error::UnexpectedSequence => Self::UnexpectedSequence(message),
            steve_sdk::Error::InvalidResponseStatus(_) => Self::InvalidResponseStatus(message),
        }
    }
}

#[derive(uniffi::Object)]
pub struct SteveClient {
    inner: Client,
}

#[uniffi::export]
pub fn create_pinned(
    config: SteveClientConfig,
    profiles: Vec<PcrProfile>,
) -> Result<Arc<SteveClient>, SteveError> {
    create_pinned_with_mode(config, profiles, AttestationMode::Nitro)
}

#[uniffi::export]
pub fn create_tofu(
    config: SteveClientConfig,
    trust_store: Arc<dyn PcrTrustStore>,
) -> Result<Arc<SteveClient>, SteveError> {
    create_tofu_with_mode(config, trust_store, AttestationMode::Nitro)
}

#[cfg(feature = "synthetic-testing")]
#[uniffi::export]
pub fn create_pinned_for_synthetic_testing(
    config: SteveClientConfig,
    profiles: Vec<PcrProfile>,
) -> Result<Arc<SteveClient>, SteveError> {
    create_pinned_with_mode(config, profiles, AttestationMode::Synthetic)
}

#[cfg(feature = "synthetic-testing")]
#[uniffi::export]
pub fn create_tofu_for_synthetic_testing(
    config: SteveClientConfig,
    trust_store: Arc<dyn PcrTrustStore>,
) -> Result<Arc<SteveClient>, SteveError> {
    create_tofu_with_mode(config, trust_store, AttestationMode::Synthetic)
}

#[uniffi::export]
impl SteveClient {
    pub async fn verify_attestation(&self) -> Result<AttestationInfo, SteveError> {
        let client = self.inner.clone();
        run_on_runtime(async move { client.verify_attestation().await })
            .await
            .map(Into::into)
    }

    pub async fn rotate_session(&self) -> Result<AttestationInfo, SteveError> {
        let client = self.inner.clone();
        run_on_runtime(async move { client.rotate_session().await })
            .await
            .map(Into::into)
    }

    pub async fn send(&self, request: HttpRequest) -> Result<HttpResponse, SteveError> {
        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|error| SteveError::InvalidHttpMethod(error.to_string()))?;
        let mut builder = self.inner.request(method, request.path);
        for header in request.headers {
            builder = builder
                .header(header.name, header.value)
                .map_err(SteveError::from)?;
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        run_on_runtime(async move { builder.send().await })
            .await
            .map(response_from_core)
    }
}

#[derive(Clone, Copy)]
enum AttestationMode {
    Nitro,
    #[cfg(feature = "synthetic-testing")]
    Synthetic,
}

fn create_pinned_with_mode(
    config: SteveClientConfig,
    profiles: Vec<PcrProfile>,
    mode: AttestationMode,
) -> Result<Arc<SteveClient>, SteveError> {
    let profiles = profiles
        .into_iter()
        .map(profile_into_core)
        .collect::<Result<Vec<_>, _>>()?;
    let policy = PcrPolicy::pinned(profiles).map_err(SteveError::from)?;
    create_client(config, policy, mode)
}

fn create_tofu_with_mode(
    config: SteveClientConfig,
    trust_store: Arc<dyn PcrTrustStore>,
    mode: AttestationMode,
) -> Result<Arc<SteveClient>, SteveError> {
    let policy = PcrPolicy::trust_on_first_use(Arc::new(ForeignPcrTrustStore { trust_store }));
    create_client(config, policy, mode)
}

fn create_client(
    config: SteveClientConfig,
    policy: PcrPolicy,
    mode: AttestationMode,
) -> Result<Arc<SteveClient>, SteveError> {
    let mut builder =
        Client::builder_with_policy(&config.base_url, policy).map_err(SteveError::from)?;
    if let Some(context) = config.application_context {
        builder = builder.application_context(context);
    }
    if let Some(suite) = config.key_exchange {
        builder = builder.expected_key_exchange(suite.into());
    }
    if let Some(milliseconds) = config.session_rotation_interval_ms {
        builder = builder.session_rotation_interval(Duration::from_millis(milliseconds));
    }
    if let Some(milliseconds) = config.session_establishment_timeout_ms {
        builder = builder.session_establishment_timeout(Duration::from_millis(milliseconds));
    }
    if let Some(milliseconds) = config.request_timeout_ms {
        builder = builder.request_timeout(Duration::from_millis(milliseconds));
    }
    builder = configure_attestation(builder, mode);
    let inner = builder.build().map_err(SteveError::from)?;
    Ok(Arc::new(SteveClient { inner }))
}

fn configure_attestation(builder: ClientBuilder, mode: AttestationMode) -> ClientBuilder {
    match mode {
        AttestationMode::Nitro => builder,
        #[cfg(feature = "synthetic-testing")]
        AttestationMode::Synthetic => builder.use_synthetic_attestation_for_testing(),
    }
}

fn profile_into_core(profile: PcrProfile) -> Result<ExpectedPcrs, SteveError> {
    let mut output = HashMap::with_capacity(profile.pcrs.len());
    for pcr in profile.pcrs {
        if output.insert(pcr.index, pcr.value).is_some() {
            return Err(SteveError::DuplicatePcrIndex(
                ["duplicate PCR index ", &pcr.index.to_string()].concat(),
            ));
        }
    }
    Ok(output)
}

fn profile_from_core(profile: &ExpectedPcrs) -> PcrProfile {
    let mut pcrs = profile
        .iter()
        .map(|(index, value)| Pcr {
            index: *index,
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    pcrs.sort_unstable_by_key(|pcr| pcr.index);
    PcrProfile { pcrs }
}

fn response_from_core(response: steve_sdk::Response) -> HttpResponse {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| HttpHeader {
            name: name.as_str().to_owned(),
            value: value.as_bytes().to_vec(),
        })
        .collect();
    HttpResponse {
        status,
        headers,
        body: response.into_bytes(),
    }
}

fn runtime() -> Result<&'static Runtime, SteveError> {
    static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();
    match RUNTIME.get_or_init(|| {
        RuntimeBuilder::new_multi_thread()
            .enable_all()
            .thread_name("steve-sdk-uniffi")
            .build()
            .map_err(|error| error.to_string())
    }) {
        Ok(runtime) => Ok(runtime),
        Err(message) => Err(SteveError::Runtime(message.clone())),
    }
}

async fn run_on_runtime<F, T>(future: F) -> Result<T, SteveError>
where
    F: Future<Output = steve_sdk::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    runtime()?
        .spawn(future)
        .await
        .map_err(|error| SteveError::Runtime(error.to_string()))?
        .map_err(SteveError::from)
}

struct ForeignPcrTrustStore {
    trust_store: Arc<dyn PcrTrustStore>,
}

#[derive(Debug, thiserror::Error)]
enum TrustStoreAdapterError {
    #[error("PCR trust store callback failed: {0}")]
    Callback(String),
    #[error("PCR trust store task failed: {0}")]
    Task(String),
    #[error("PCR trust store returned duplicate PCR index {0}")]
    DuplicatePcrIndex(u8),
}

#[async_trait]
impl CorePcrTrustStore for ForeignPcrTrustStore {
    async fn load_or_insert(
        &self,
        key: CorePcrTrustKey,
        observed: ExpectedPcrs,
    ) -> Result<CorePcrTrustRecord, PcrTrustStoreError> {
        call_foreign_trust_store(
            Arc::clone(&self.trust_store),
            key.as_bytes().to_vec(),
            observed,
        )
        .await
    }
}

async fn call_foreign_trust_store(
    trust_store: Arc<dyn PcrTrustStore>,
    key: Vec<u8>,
    observed: ExpectedPcrs,
) -> Result<CorePcrTrustRecord, PcrTrustStoreError> {
    let observed = profile_from_core(&observed);
    let record = tokio::task::spawn_blocking(move || trust_store.load_or_insert(key, observed))
        .await
        .map_err(|error| -> PcrTrustStoreError {
            Box::new(TrustStoreAdapterError::Task(error.to_string()))
        })?
        .map_err(|error| -> PcrTrustStoreError {
            Box::new(TrustStoreAdapterError::Callback(error.to_string()))
        })?;
    match record {
        PcrTrustRecord::Inserted => Ok(CorePcrTrustRecord::Inserted),
        PcrTrustRecord::Existing { profile } => {
            let existing = profile_into_core_for_store(profile)?;
            Ok(CorePcrTrustRecord::Existing(existing))
        }
    }
}

fn profile_into_core_for_store(profile: PcrProfile) -> Result<ExpectedPcrs, PcrTrustStoreError> {
    let mut output = HashMap::with_capacity(profile.pcrs.len());
    for pcr in profile.pcrs {
        if output.insert(pcr.index, pcr.value).is_some() {
            return Err(Box::new(TrustStoreAdapterError::DuplicatePcrIndex(
                pcr.index,
            )));
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn profile(indices: &[u8]) -> PcrProfile {
        PcrProfile {
            pcrs: indices
                .iter()
                .map(|index| Pcr {
                    index: *index,
                    value: vec![index.saturating_add(1); 48],
                })
                .collect(),
        }
    }

    #[test]
    fn pcr_conversion_rejects_duplicates_and_sorts_output() {
        let duplicate = PcrProfile {
            pcrs: vec![
                Pcr {
                    index: 1,
                    value: vec![1; 48],
                },
                Pcr {
                    index: 1,
                    value: vec![2; 48],
                },
            ],
        };
        assert!(matches!(
            profile_into_core(duplicate),
            Err(SteveError::DuplicatePcrIndex(_))
        ));

        let converted = profile_into_core(profile(&[7, 2, 0, 1])).unwrap();
        assert_eq!(
            profile_from_core(&converted)
                .pcrs
                .iter()
                .map(|pcr| pcr.index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 7]
        );
    }

    #[test]
    fn config_preserves_defaults_and_supports_xwing() {
        let config = SteveClientConfig {
            base_url: "https://example.com".to_owned(),
            application_context: None,
            key_exchange: None,
            session_rotation_interval_ms: None,
            session_establishment_timeout_ms: None,
            request_timeout_ms: None,
        };
        assert!(create_pinned(config.clone(), vec![profile(&[0, 1, 2])]).is_ok());

        let xwing = SteveClientConfig {
            key_exchange: Some(KeyExchangeSuite::XwingDraft10),
            ..config
        };
        assert!(create_pinned(xwing, vec![profile(&[0, 1, 2])]).is_ok());
    }

    #[test]
    fn attestation_conversion_preserves_and_sorts_the_complete_pcr_map() {
        let pcrs = profile_into_core(profile(&[7, 2, 0, 1])).unwrap();
        let converted = AttestationInfo::from(steve_sdk::AttestationInfo {
            session_id: [9; 16],
            module_id: "module".to_owned(),
            pcrs,
            pcr_trust: steve_sdk::PcrTrustStatus::Pinned,
        });
        assert_eq!(converted.session_id, vec![9; 16]);
        assert_eq!(
            converted
                .pcrs
                .pcrs
                .iter()
                .map(|pcr| pcr.index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 7]
        );
    }

    #[tokio::test]
    async fn request_validation_returns_stable_boundary_errors_without_network_io() {
        let client = create_pinned(
            SteveClientConfig {
                base_url: "https://example.com".to_owned(),
                application_context: None,
                key_exchange: None,
                session_rotation_interval_ms: None,
                session_establishment_timeout_ms: None,
                request_timeout_ms: None,
            },
            vec![profile(&[0, 1, 2])],
        )
        .unwrap();
        let error = client
            .send(HttpRequest {
                method: "not a method".to_owned(),
                path: "/".to_owned(),
                headers: Vec::new(),
                body: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(error, SteveError::InvalidHttpMethod(_)));

        let error = client
            .send(HttpRequest {
                method: "GET".to_owned(),
                path: "/".to_owned(),
                headers: vec![HttpHeader {
                    name: "x-invalid".to_owned(),
                    value: vec![0],
                }],
                body: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(error, SteveError::InvalidHeaderValue(_)));
    }

    enum StoreResult {
        Inserted,
        Existing(PcrProfile),
        Failed,
    }

    struct TestStore {
        result: Mutex<Option<StoreResult>>,
    }

    impl PcrTrustStore for TestStore {
        fn load_or_insert(
            &self,
            _key: Vec<u8>,
            _observed: PcrProfile,
        ) -> Result<PcrTrustRecord, PcrTrustStoreCallbackError> {
            match self.result.lock().unwrap().take().unwrap() {
                StoreResult::Inserted => Ok(PcrTrustRecord::Inserted),
                StoreResult::Existing(profile) => Ok(PcrTrustRecord::Existing { profile }),
                StoreResult::Failed => Err(PcrTrustStoreCallbackError::Failed {
                    message: "callback sentinel".to_owned(),
                }),
            }
        }
    }

    async fn call_test_store(
        result: StoreResult,
    ) -> Result<CorePcrTrustRecord, PcrTrustStoreError> {
        call_foreign_trust_store(
            Arc::new(TestStore {
                result: Mutex::new(Some(result)),
            }),
            vec![3; 32],
            profile_into_core(profile(&[0, 1, 2])).unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn tofu_adapter_propagates_records_duplicates_and_callback_messages() {
        assert!(matches!(
            call_test_store(StoreResult::Inserted).await.unwrap(),
            CorePcrTrustRecord::Inserted
        ));
        assert!(matches!(
            call_test_store(StoreResult::Existing(profile(&[0, 1, 2])))
                .await
                .unwrap(),
            CorePcrTrustRecord::Existing(_)
        ));

        let duplicate = PcrProfile {
            pcrs: vec![
                Pcr {
                    index: 0,
                    value: vec![1; 48],
                },
                Pcr {
                    index: 0,
                    value: vec![2; 48],
                },
            ],
        };
        assert!(
            call_test_store(StoreResult::Existing(duplicate))
                .await
                .unwrap_err()
                .to_string()
                .contains("duplicate PCR index 0")
        );
        assert!(
            call_test_store(StoreResult::Failed)
                .await
                .unwrap_err()
                .to_string()
                .contains("callback sentinel")
        );
    }

    #[test]
    fn core_error_mapping_is_exhaustive_and_preserves_the_case() {
        let error = SteveError::from(steve_sdk::Error::UnexpectedSequence);
        assert!(matches!(error, SteveError::UnexpectedSequence(_)));
        let error = SteveError::from(steve_sdk::Error::InvalidResponseStatus(199));
        assert!(matches!(error, SteveError::InvalidResponseStatus(_)));
    }
}
