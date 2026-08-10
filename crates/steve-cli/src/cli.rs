//! Command-line interface for steve-cli.
//!
//! This module provides the CLI argument parsing using Clap.

use async_trait::async_trait;
use clap::Parser;
use fs2::FileExt;
use http::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};
use steve_sdk::{ExpectedPcrs, PcrTrustKey, PcrTrustRecord, PcrTrustStore, PcrTrustStoreError};
use thiserror::Error;

pub const DEFAULT_PCRS_FILE: &str = ".caution/trusted_hashes.json";
const TRUST_STORE_VERSION: u32 = 1;

/// Make one attested, end-to-end encrypted HTTP request
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct App {
    /// The URL to request
    pub url: String,

    /// Approved Caution trusted-hashes file; repeat for a pinned allowlist
    #[arg(
        long = "pcrs",
        visible_alias = "trusted-hashes-file",
        value_name = "PATH",
        action = clap::ArgAction::Append,
        conflicts_with = "tofu_store"
    )]
    pub pcrs_files: Vec<PathBuf>,

    /// Durable JSON trust store for trust on first use
    #[arg(long, value_name = "PATH", conflicts_with = "pcrs_files")]
    pub tofu_store: Option<PathBuf>,

    /// Key exchange suite (X25519 or XWING-DRAFT10)
    #[arg(long, value_name = "SUITE", default_value = "X25519")]
    pub key_exchange: String,

    /// Validate configuration without making a request
    #[arg(long)]
    pub dry_run: bool,

    /// Request body data (conflicts with --json)
    #[arg(long, value_name = "PAYLOAD", conflicts_with = "json")]
    pub data: Option<String>,

    /// Request body as JSON (sets Content-Type: application/json automatically)
    #[arg(long, value_name = "PAYLOAD")]
    pub json: Option<String>,

    /// HTTP headers in the format 'Key: Value' (can be specified multiple times)
    #[arg(long = "header", short = 'H', value_name = "Key: Value", num_args = 1)]
    pub headers: Vec<String>,
}

/// Error from parsing a single header string.
#[derive(Error, Debug)]
pub enum ParseHeaderError {
    /// The header string does not contain a colon separator.
    #[error("Invalid header format: {0}. Expected format: 'Key: Value'")]
    InvalidFormat(String),

    /// The header name is empty after trimming.
    #[error("Header name cannot be empty")]
    EmptyName,

    /// The header value is empty after trimming.
    #[error("Header value cannot be empty")]
    EmptyValue,
}

/// Error from appending a header to the `HeaderMap`.
#[derive(Error, Debug)]
pub enum AppendHeaderError {
    /// The header name is invalid.
    #[error("Invalid header name")]
    ParseName(#[source] http::header::InvalidHeaderName),

    /// The header value is invalid.
    #[error("Invalid header value")]
    ParseValue(#[source] http::header::InvalidHeaderValue),

    // NOTE: https://github.com/hyperium/http/pull/859
    // This should eventually be removed.
    /// The header value contains non-ASCII characters.
    #[error("Header value contains non-ASCII characters")]
    NonAsciiValue,
}

/// Error from parsing the collection of headers.
#[derive(Error, Debug)]
pub enum ParseHeadersError {
    /// Error parsing a specific header string.
    #[error("Failed to parse header")]
    ParseHeader(#[from] ParseHeaderError),

    /// Error appending a header to the map.
    #[error("Failed to append header")]
    AppendHeader(#[from] AppendHeaderError),

    /// A duplicate header name cannot be represented by E2P v2.
    #[error("Duplicate header name is not supported: {0}")]
    DuplicateName(String),
}

/// Error from parsing the key exchange suite string.
#[derive(Error, Debug)]
pub enum ParseKeyExchangeError {
    /// Invalid key exchange suite.
    #[error("Key exchange must be X25519 or XWING-DRAFT10")]
    InvalidKeyExchangeSuite { value: String },
}

/// Error from parsing a single PCR value.
#[derive(Error, Debug)]
pub enum ParsePcrError {
    /// The PCR value is missing.
    #[error("missing")]
    Missing,

    /// The PCR value is not valid hex.
    #[error("not valid hex")]
    InvalidHex(#[source] hex::FromHexError),

    /// The PCR value has invalid length.
    #[error("invalid length: expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    /// Debug PCRs cannot establish workload identity.
    #[error("all-zero debug PCRs are not accepted")]
    AllZero,
}

/// Error from loading the trusted hashes file.
#[derive(Error, Debug)]
pub enum TrustedHashesError {
    /// The file could not be read.
    #[error("Failed to read file")]
    Io(#[from] std::io::Error),

    /// The file contains invalid JSON.
    #[error("Invalid JSON")]
    Json(#[from] serde_json::Error),

    /// A PCR value is invalid.
    #[error("PCR{index} is invalid")]
    InvalidPcr {
        index: u8,
        #[source]
        source: Box<ParsePcrError>,
    },
}

/// Trusted hashes file format from Caution.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustedHashes {
    #[serde(rename = "pcr0")]
    pub pcr0: String,
    #[serde(rename = "pcr1")]
    pub pcr1: String,
    #[serde(rename = "pcr2")]
    pub pcr2: String,
    #[allow(dead_code)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
}

impl TrustedHashes {
    /// Load trusted hashes from a file path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, TrustedHashesError> {
        let content = fs::read_to_string(path.as_ref())?;
        let hashes: Self = serde_json::from_str(&content)?;
        Ok(hashes)
    }

    /// Convert to steve-sdk's `NitroPcrs` format.
    pub fn to_nitro_pcrs(&self) -> Result<ExpectedPcrs, TrustedHashesError> {
        const PCR_LENGTH: usize = 48;
        let mut pcrs = ExpectedPcrs::new();

        pcrs.insert(0, parse_pcr(0, &self.pcr0, PCR_LENGTH)?);
        pcrs.insert(1, parse_pcr(1, &self.pcr1, PCR_LENGTH)?);
        pcrs.insert(2, parse_pcr(2, &self.pcr2, PCR_LENGTH)?);

        Ok(pcrs)
    }

    fn from_pcrs(pcrs: &ExpectedPcrs) -> Result<Self, TrustedHashesError> {
        let read = |index| {
            pcrs.get(&index)
                .map(hex::encode)
                .ok_or_else(|| invalid_pcr(index, ParsePcrError::Missing))
        };
        Ok(Self {
            pcr0: read(0)?,
            pcr1: read(1)?,
            pcr2: read(2)?,
            verified_at: None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyInput {
    Pinned(Vec<PathBuf>),
    Tofu(PathBuf),
}

pub fn load_profiles(paths: &[PathBuf]) -> Result<Vec<ExpectedPcrs>, TrustedHashesError> {
    paths
        .iter()
        .map(|path| TrustedHashes::load(path)?.to_nitro_pcrs())
        .collect()
}

#[derive(Debug, Error)]
pub enum TrustStoreError {
    #[error("TOFU store I/O failed")]
    Io(#[from] io::Error),

    #[error("TOFU store contains invalid JSON")]
    Json(#[from] serde_json::Error),

    #[error("TOFU store contains invalid PCRs")]
    Pcr(#[from] TrustedHashesError),

    #[error("unsupported TOFU store version {actual}; expected {expected}")]
    UnsupportedVersion { actual: u32, expected: u32 },

    #[error("TOFU store contains an invalid trust key")]
    InvalidKey,

    #[error("TOFU store path has no file name")]
    MissingFileName,
}

#[derive(Debug, Deserialize, Serialize)]
struct TrustDatabase {
    version: u32,
    records: BTreeMap<String, TrustedHashes>,
}

impl Default for TrustDatabase {
    fn default() -> Self {
        Self {
            version: TRUST_STORE_VERSION,
            records: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct FilePcrTrustStore {
    path: PathBuf,
}

impl FilePcrTrustStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Validate existing state without creating or modifying the store.
    pub fn validate(&self) -> Result<(), TrustStoreError> {
        if self.path.file_name().is_none() {
            return Err(TrustStoreError::MissingFileName);
        }
        let Some(database) = read_database_if_present(&self.path)? else {
            return Ok(());
        };
        validate_database(&database)
    }
}

#[async_trait]
impl PcrTrustStore for FilePcrTrustStore {
    async fn load_or_insert(
        &self,
        key: PcrTrustKey,
        observed: ExpectedPcrs,
    ) -> std::result::Result<PcrTrustRecord, PcrTrustStoreError> {
        let path = self.path.clone();
        match tokio::task::spawn_blocking(move || load_or_insert(&path, key, observed)).await {
            Ok(result) => result.map_err(|error| Box::new(error) as PcrTrustStoreError),
            Err(error) => Err(Box::new(error)),
        }
    }
}

fn load_or_insert(
    path: &Path,
    key: PcrTrustKey,
    observed: ExpectedPcrs,
) -> Result<PcrTrustRecord, TrustStoreError> {
    load_or_insert_key(path, hex::encode(key.as_bytes()), observed)
}

fn load_or_insert_key(
    path: &Path,
    key: String,
    observed: ExpectedPcrs,
) -> Result<PcrTrustRecord, TrustStoreError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let file_name = path.file_name().ok_or(TrustStoreError::MissingFileName)?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(parent.join(lock_name))?;
    lock.lock_exclusive()?;

    let mut database = read_database_if_present(path)?.unwrap_or_default();
    validate_database(&database)?;
    if let Some(existing) = database.records.get(&key) {
        return Ok(PcrTrustRecord::Existing(existing.to_nitro_pcrs()?));
    }

    database
        .records
        .insert(key, TrustedHashes::from_pcrs(&observed)?);
    persist_database(path, parent, &database)?;
    Ok(PcrTrustRecord::Inserted)
}

fn read_database_if_present(path: &Path) -> Result<Option<TrustDatabase>, TrustStoreError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn validate_database(database: &TrustDatabase) -> Result<(), TrustStoreError> {
    if database.version != TRUST_STORE_VERSION {
        return Err(TrustStoreError::UnsupportedVersion {
            actual: database.version,
            expected: TRUST_STORE_VERSION,
        });
    }
    for (key, record) in &database.records {
        if key.len() != 64
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(TrustStoreError::InvalidKey);
        }
        record.to_nitro_pcrs()?;
    }
    Ok(())
}

fn persist_database(
    path: &Path,
    parent: &Path,
    database: &TrustDatabase,
) -> Result<(), TrustStoreError> {
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut temporary, database)?;
    temporary.write_all(b"\n")?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Parse a single PCR value from a hex string.
///
/// # Arguments
/// * `index` - The PCR index (0, 1, 2, etc.)
/// * `value` - The hex-encoded PCR value
/// * `expected_len` - The expected byte length of the decoded PCR
///
/// # Returns
/// The decoded PCR bytes if valid.
///
/// # Errors
/// Returns [`ParsePcrError`] if the hex is invalid or the length is incorrect.
fn parse_pcr(index: u8, value: &str, expected_len: usize) -> Result<Vec<u8>, TrustedHashesError> {
    let bytes =
        hex::decode(value).map_err(|error| invalid_pcr(index, ParsePcrError::InvalidHex(error)))?;

    if bytes.len() != expected_len {
        return Err(invalid_pcr(
            index,
            ParsePcrError::InvalidLength {
                expected: expected_len,
                actual: bytes.len(),
            },
        ));
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(invalid_pcr(index, ParsePcrError::AllZero));
    }

    Ok(bytes)
}

fn invalid_pcr(index: u8, source: ParsePcrError) -> TrustedHashesError {
    TrustedHashesError::InvalidPcr {
        index,
        source: Box::new(source),
    }
}

impl App {
    /// Resolve the explicit policy flags or the default Caution PCR file.
    #[must_use]
    pub fn policy_input(&self) -> PolicyInput {
        match &self.tofu_store {
            Some(path) => PolicyInput::Tofu(path.clone()),
            None if self.pcrs_files.is_empty() => {
                PolicyInput::Pinned(vec![PathBuf::from(DEFAULT_PCRS_FILE)])
            }
            None => PolicyInput::Pinned(self.pcrs_files.clone()),
        }
    }

    /// Parse the headers from the raw string vector into a [`HeaderMap`].
    ///
    /// # Errors
    /// Returns [`ParseHeadersError`] if any header has an invalid format.
    pub fn parse_headers(&self) -> Result<HeaderMap, ParseHeadersError> {
        let mut headers = HeaderMap::with_capacity(self.headers.len());

        for header in &self.headers {
            let (name, value) = parse_header(header)?;
            let header_name: http::header::HeaderName =
                name.parse().map_err(AppendHeaderError::ParseName)?;
            if headers.contains_key(&header_name) {
                return Err(ParseHeadersError::DuplicateName(name.to_owned()));
            }
            append_header(&mut headers, header_name, value)?;
        }

        Ok(headers)
    }

    /// Get the request body, if any.
    #[must_use]
    pub fn body(&self) -> Option<&str> {
        self.data.as_deref().or(self.json.as_deref())
    }

    /// Check if the request should have JSON content type.
    #[must_use]
    pub fn is_json(&self) -> bool {
        self.json.is_some()
    }

    /// Parse the key exchange suite from the CLI string.
    pub fn parse_key_exchange(&self) -> Result<steve_sdk::KeyExchangeSuite, ParseKeyExchangeError> {
        match self.key_exchange.to_uppercase().as_str() {
            "X25519" => Ok(steve_sdk::KeyExchangeSuite::X25519),
            "XWING-DRAFT10" | "XWING" => Ok(steve_sdk::KeyExchangeSuite::XWingDraft10),
            other => Err(ParseKeyExchangeError::InvalidKeyExchangeSuite {
                value: other.to_string(),
            }),
        }
    }
}

/// Parse a header string into name and value.
///
/// # Arguments
/// * `header` - The header string in format "Key: Value"
///
/// # Returns
/// A tuple of (name, value) with trimmed whitespace.
///
/// # Errors
/// Returns [`ParseHeaderError`] if the header format is invalid.
fn parse_header(header: &str) -> Result<(&str, &str), ParseHeaderError> {
    let parts: Vec<&str> = header.splitn(2, ':').collect();

    if parts.len() != 2 {
        return Err(ParseHeaderError::InvalidFormat(header.to_string()));
    }

    let name = parts[0].trim();
    let value = parts[1].trim();

    if name.is_empty() {
        return Err(ParseHeaderError::EmptyName);
    }

    if value.is_empty() {
        return Err(ParseHeaderError::EmptyValue);
    }

    Ok((name, value))
}

/// Append a header into the `HeaderMap`, validating the name and value.
///
/// # Arguments
/// * `headers` - The `HeaderMap` to append to
/// * `name` - The header name
/// * `value` - The header value
///
/// # Errors
/// Returns [`AppendHeaderError`] if the header name or value is invalid.
fn append_header(
    headers: &mut HeaderMap,
    name: http::header::HeaderName,
    value: &str,
) -> Result<(), AppendHeaderError> {
    // HTTP headers must be ASCII-only; reject non-ASCII characters
    if !value.is_ascii() {
        return Err(AppendHeaderError::NonAsciiValue);
    }

    let header_value =
        http::header::HeaderValue::from_str(value).map_err(AppendHeaderError::ParseValue)?;
    headers.insert(name, header_value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn expected_pcrs(seed: u8) -> ExpectedPcrs {
        ExpectedPcrs::from([
            (0, vec![seed; 48]),
            (1, vec![seed.wrapping_add(1); 48]),
            (2, vec![seed.wrapping_add(2); 48]),
        ])
    }

    fn make_app(url: &str, data: Option<&str>, json: Option<&str>, headers: Vec<&str>) -> App {
        App {
            url: url.to_string(),
            pcrs_files: Vec::new(),
            tofu_store: None,
            key_exchange: "X25519".to_string(),
            dry_run: false,
            data: data.map(String::from),
            json: json.map(String::from),
            headers: headers.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn test_parse_headers_valid() {
        let app = make_app(
            "http://example.com",
            None,
            None,
            vec![
                "Content-Type: application/json",
                "Authorization: Bearer token",
                "X-Custom: value",
            ],
        );

        let headers = app.parse_headers().unwrap();
        assert_eq!(
            headers.get(http::header::CONTENT_TYPE),
            Some(&"application/json".parse().unwrap())
        );
        assert_eq!(
            headers.get("authorization"),
            Some(&"Bearer token".parse().unwrap())
        );
        assert_eq!(headers.get("x-custom"), Some(&"value".parse().unwrap()));
    }

    #[test]
    fn test_parse_headers_empty() {
        let app = make_app("http://example.com", None, None, vec![]);

        let headers = app.parse_headers().unwrap();
        assert!(headers.is_empty());
    }

    #[test]
    fn test_parse_headers_invalid_format() {
        let app = make_app("http://example.com", None, None, vec!["InvalidHeader"]);

        assert!(app.parse_headers().is_err());
    }

    #[test]
    fn test_parse_headers_empty_name() {
        let app = make_app("http://example.com", None, None, vec![": value"]);

        assert!(app.parse_headers().is_err());
    }

    #[test]
    fn test_parse_headers_empty_value() {
        let app = make_app("http://example.com", None, None, vec!["Key:"]);

        assert!(app.parse_headers().is_err());
    }

    #[test]
    fn test_body_with_data() {
        let app = make_app("http://example.com", Some("hello world"), None, vec![]);

        assert_eq!(app.body(), Some("hello world"));
        assert!(!app.is_json());
    }

    #[test]
    fn test_body_with_json() {
        let app = make_app(
            "http://example.com",
            None,
            Some(r#"{"key": "value"}"#),
            vec![],
        );

        assert_eq!(app.body(), Some(r#"{"key": "value"}"#));
        assert!(app.is_json());
    }

    #[test]
    fn test_body_without_any() {
        let app = make_app("http://example.com", None, None, vec![]);

        assert_eq!(app.body(), None);
        assert!(!app.is_json());
    }

    #[test]
    fn test_conflicts_with_data_and_json() {
        // This test verifies that clap rejects both --data and --json
        let cmd = App::try_parse_from([
            "steve",
            "--data",
            "foo",
            "--json",
            "bar",
            "http://example.com",
        ]);
        assert!(cmd.is_err());
    }

    #[test]
    fn policy_flags_support_allowlists_aliases_and_tofu_exclusivity() {
        let pinned = App::try_parse_from([
            "steve",
            "--pcrs",
            "current.json",
            "--pcrs",
            "next.json",
            "http://example.com",
        ])
        .unwrap();
        assert_eq!(
            pinned.policy_input(),
            PolicyInput::Pinned(vec!["current.json".into(), "next.json".into()])
        );

        let alias = App::try_parse_from([
            "steve",
            "--trusted-hashes-file",
            "trusted.json",
            "http://example.com",
        ])
        .unwrap();
        assert_eq!(
            alias.policy_input(),
            PolicyInput::Pinned(vec!["trusted.json".into()])
        );

        assert!(
            App::try_parse_from([
                "steve",
                "--pcrs",
                "trusted.json",
                "--tofu-store",
                "trust.json",
                "http://example.com",
            ])
            .is_err()
        );
    }

    #[test]
    fn default_policy_uses_the_caution_trusted_hashes_path() {
        let app = make_app("http://example.com", None, None, vec![]);
        assert_eq!(
            app.policy_input(),
            PolicyInput::Pinned(vec![PathBuf::from(DEFAULT_PCRS_FILE)])
        );
    }

    #[test]
    fn test_parse_header_with_multiple_colons() {
        let app = make_app("http://example.com", None, None, vec!["X-Time: 12:30:45"]);

        let headers = app.parse_headers().unwrap();
        assert_eq!(headers.get("x-time"), Some(&"12:30:45".parse().unwrap()));
    }

    #[test]
    fn test_parse_headers_rejects_duplicate_names() {
        let app = make_app(
            "http://example.com",
            None,
            None,
            vec!["X-Custom: value1", "X-Custom: value2"],
        );

        assert!(matches!(
            app.parse_headers(),
            Err(ParseHeadersError::DuplicateName(name)) if name == "X-Custom"
        ));
    }

    #[test]
    fn test_parse_header_error_invalid_format() {
        let result = parse_header("InvalidHeader");
        assert!(matches!(result, Err(ParseHeaderError::InvalidFormat(_))));
    }

    #[test]
    fn test_parse_header_error_empty_name() {
        let result = parse_header(": value");
        assert!(matches!(result, Err(ParseHeaderError::EmptyName)));
    }

    #[test]
    fn test_parse_header_error_empty_value() {
        let result = parse_header("Key:");
        assert!(matches!(result, Err(ParseHeaderError::EmptyValue)));
    }

    #[test]
    fn test_append_header_error_invalid_name() {
        let app = make_app("http://example.com", None, None, vec!["\0invalid: value"]);
        assert!(matches!(
            app.parse_headers(),
            Err(ParseHeadersError::AppendHeader(
                AppendHeaderError::ParseName(_)
            ))
        ));
    }

    #[test]
    fn test_append_header_error_invalid_value() {
        let mut headers = HeaderMap::new();
        let result = append_header(&mut headers, "X-Custom".parse().unwrap(), "\0invalid");
        assert!(matches!(result, Err(AppendHeaderError::ParseValue(_))));
    }

    #[test]
    fn test_parse_headers_non_ascii_utf8_rejected() {
        let app = make_app(
            "http://example.com",
            None,
            None,
            vec!["X-Custom: café 中文 😀"],
        );

        let result = app.parse_headers();
        assert!(matches!(
            result,
            Err(ParseHeadersError::AppendHeader(
                AppendHeaderError::NonAsciiValue
            ))
        ));
    }

    #[test]
    fn test_append_header_valid_ascii_utf8_to_str() {
        let mut headers = HeaderMap::new();
        // ASCII header values work with to_str()
        let result = append_header(&mut headers, "X-Custom".parse().unwrap(), "hello world");
        assert!(result.is_ok());
        let value = headers.get("x-custom").unwrap();
        assert_eq!(value.to_str().unwrap(), "hello world");
    }

    #[test]
    fn test_parse_headers_error_wrapping() {
        let app = make_app("http://example.com", None, None, vec!["InvalidHeader"]);

        let result = app.parse_headers();
        assert!(matches!(
            result,
            Err(ParseHeadersError::ParseHeader(
                ParseHeaderError::InvalidFormat(_)
            ))
        ));
    }

    #[test]
    fn test_trusted_hashes_valid() {
        let json = r#"{
            "pcr0": "101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010",
            "pcr1": "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "pcr2": "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
        }"#;
        let hashes: TrustedHashes = serde_json::from_str(json).unwrap();
        assert_eq!(hashes.pcr0.len(), 96); // 48 bytes = 96 hex chars
    }

    #[test]
    fn test_trusted_hashes_invalid_hex() {
        let json = r#"{
            "pcr0": "invalid_hex",
            "pcr1": "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "pcr2": "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
        }"#;
        let result: Result<TrustedHashes, _> = serde_json::from_str(json);
        assert!(result.is_ok()); // JSON is valid, but hex decode will fail later
    }

    #[test]
    fn test_trusted_hashes_to_nitro_pcrs() {
        let json = r#"{
            "pcr0": "101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010",
            "pcr1": "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "pcr2": "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
        }"#;
        let hashes: TrustedHashes = serde_json::from_str(json).unwrap();
        let pcrs = hashes.to_nitro_pcrs().unwrap();
        assert_eq!(pcrs.len(), 3);
    }

    #[test]
    fn test_trusted_hashes_to_nitro_pcrs_invalid_length() {
        let json = r#"{
            "pcr0": "101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010",
            "pcr1": "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "pcr2": "2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
        }"#;
        let hashes: TrustedHashes = serde_json::from_str(json).unwrap();
        let result = hashes.to_nitro_pcrs();
        assert!(matches!(
            result,
            Err(TrustedHashesError::InvalidPcr { index: 2, .. })
        ));
    }

    #[test]
    fn test_parse_pcr_valid() {
        let valid_hex = "101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010";
        let result = parse_pcr(0, valid_hex, 48);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_pcr_invalid_hex() {
        let invalid_hex = "zzzz000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let result = parse_pcr(1, invalid_hex, 48);
        match result {
            Err(TrustedHashesError::InvalidPcr { index: 1, source }) => {
                assert!(matches!(*source, ParsePcrError::InvalidHex(_)));
            }
            _ => panic!("Expected InvalidPcr with index 1 and InvalidHex source"),
        }
    }

    #[test]
    fn test_parse_pcr_invalid_length() {
        // 94 hex chars = 47 bytes (one byte short)
        let short_hex = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let result = parse_pcr(2, short_hex, 48);
        match result {
            Err(TrustedHashesError::InvalidPcr { index: 2, source }) => {
                assert!(matches!(
                    *source,
                    ParsePcrError::InvalidLength {
                        expected: 48,
                        actual: 47
                    }
                ));
            }
            _ => panic!("Expected InvalidPcr with index 2 and InvalidLength source"),
        }
    }

    #[test]
    fn test_parse_pcr_rejects_all_zero_debug_values() {
        let result = parse_pcr(0, &"00".repeat(48), 48);
        assert!(matches!(
            result,
            Err(TrustedHashesError::InvalidPcr { source, .. })
                if matches!(*source, ParsePcrError::AllZero)
        ));
    }

    #[test]
    fn loads_multiple_complete_pcr_profiles() {
        let directory = tempfile::tempdir().unwrap();
        let first_path = directory.path().join("first.json");
        let second_path = directory.path().join("second.json");
        let first = expected_pcrs(0x10);
        let second = expected_pcrs(0x20);
        fs::write(
            &first_path,
            serde_json::to_vec(&TrustedHashes::from_pcrs(&first).unwrap()).unwrap(),
        )
        .unwrap();
        fs::write(
            &second_path,
            serde_json::to_vec(&TrustedHashes::from_pcrs(&second).unwrap()).unwrap(),
        )
        .unwrap();

        assert_eq!(
            load_profiles(&[first_path, second_path]).unwrap(),
            [first, second]
        );
    }

    #[test]
    fn tofu_store_is_atomic_persistent_and_never_replaces() {
        let directory = tempfile::tempdir().unwrap();
        let path = Arc::new(directory.path().join("trust.json"));
        let pcrs = expected_pcrs(0x10);
        let key = "11".repeat(32);
        let threads = (0..2)
            .map(|_| {
                let path = Arc::clone(&path);
                let pcrs = pcrs.clone();
                let key = key.clone();
                std::thread::spawn(move || load_or_insert_key(&path, key, pcrs).unwrap())
            })
            .collect::<Vec<_>>();
        let outcomes = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == PcrTrustRecord::Inserted)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PcrTrustRecord::Existing(_)))
                .count(),
            1
        );

        let before = fs::read(path.as_ref()).unwrap();
        assert_eq!(
            load_or_insert_key(path.as_ref(), key, expected_pcrs(0x30)).unwrap(),
            PcrTrustRecord::Existing(pcrs)
        );
        assert_eq!(fs::read(path.as_ref()).unwrap(), before);
        FilePcrTrustStore::new(path.as_ref().clone())
            .validate()
            .unwrap();
    }

    #[test]
    fn tofu_store_validation_is_read_only_and_rejects_bad_state() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.json");
        FilePcrTrustStore::new(missing.clone()).validate().unwrap();
        assert!(!missing.exists());

        assert!(matches!(
            FilePcrTrustStore::new(PathBuf::new()).validate(),
            Err(TrustStoreError::MissingFileName)
        ));

        let corrupt = directory.path().join("corrupt.json");
        fs::write(&corrupt, b"not json").unwrap();
        assert!(matches!(
            FilePcrTrustStore::new(corrupt).validate(),
            Err(TrustStoreError::Json(_))
        ));

        let unsupported = directory.path().join("unsupported.json");
        fs::write(&unsupported, br#"{"version":2,"records":{}}"#).unwrap();
        assert!(matches!(
            FilePcrTrustStore::new(unsupported).validate(),
            Err(TrustStoreError::UnsupportedVersion { actual: 2, .. })
        ));

        let invalid_key = directory.path().join("invalid-key.json");
        fs::write(
            &invalid_key,
            serde_json::to_vec(&TrustDatabase {
                version: TRUST_STORE_VERSION,
                records: BTreeMap::from([(
                    "not-a-key".into(),
                    TrustedHashes::from_pcrs(&expected_pcrs(0x10)).unwrap(),
                )]),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            FilePcrTrustStore::new(invalid_key).validate(),
            Err(TrustStoreError::InvalidKey)
        ));
    }

    #[test]
    fn test_parse_key_exchange_x25519() {
        let app = make_app("http://example.com", None, None, vec![]);
        assert!(matches!(
            app.parse_key_exchange(),
            Ok(steve_sdk::KeyExchangeSuite::X25519)
        ));
    }

    #[test]
    fn test_parse_key_exchange_xwing() {
        let mut app = make_app("http://example.com", None, None, vec![]);
        app.key_exchange = "XWING-DRAFT10".to_string();
        assert!(matches!(
            app.parse_key_exchange(),
            Ok(steve_sdk::KeyExchangeSuite::XWingDraft10)
        ));
    }

    #[test]
    fn test_parse_key_exchange_xwing_short() {
        let mut app = make_app("http://example.com", None, None, vec![]);
        app.key_exchange = "XWING".to_string();
        assert!(matches!(
            app.parse_key_exchange(),
            Ok(steve_sdk::KeyExchangeSuite::XWingDraft10)
        ));
    }

    #[test]
    fn test_parse_key_exchange_invalid() {
        let mut app = make_app("http://example.com", None, None, vec![]);
        app.key_exchange = "INVALID".to_string();
        assert!(matches!(
            app.parse_key_exchange(),
            Err(ParseKeyExchangeError::InvalidKeyExchangeSuite { .. })
        ));
    }

    #[test]
    fn test_dry_run_flag() {
        let app = App::try_parse_from(["steve", "--dry-run", "http://example.com"]).unwrap();
        assert!(app.dry_run);
    }
}
