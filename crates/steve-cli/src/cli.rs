//! Command-line interface for steve-cli.
//!
//! This module provides the CLI argument parsing using Clap.

use clap::Parser;
use http::header::HeaderMap;
use std::fs;
use std::path::Path;
use thiserror::Error;

/// Steve CLI - A curl-like HTTP client
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct App {
    /// The URL to request
    pub url: String,

    /// Path to the Caution trusted-hashes file
    #[arg(
        long,
        value_name = "PATH",
        default_value = ".caution/trusted-hashes.json"
    )]
    pub trusted_hashes_file: String,

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
    /// The PCR value is not valid hex.
    #[error("not valid hex")]
    InvalidHex(#[source] hex::FromHexError),

    /// The PCR value has invalid length.
    #[error("invalid length: expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
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
#[derive(Debug, serde::Deserialize)]
pub struct TrustedHashes {
    #[serde(rename = "pcr0")]
    pub pcr0: String,
    #[serde(rename = "pcr1")]
    pub pcr1: String,
    #[serde(rename = "pcr2")]
    pub pcr2: String,
    #[allow(dead_code)]
    #[serde(default)]
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
    pub fn to_nitro_pcrs(
        &self,
    ) -> Result<bootproof_sdk::format::nitro::NitroPcrs, TrustedHashesError> {
        const PCR_LENGTH: usize = 48;
        let mut pcrs = bootproof_sdk::format::nitro::NitroPcrs::new();

        pcrs.insert(0, parse_pcr(0, &self.pcr0, PCR_LENGTH)?);
        pcrs.insert(1, parse_pcr(1, &self.pcr1, PCR_LENGTH)?);
        pcrs.insert(2, parse_pcr(2, &self.pcr2, PCR_LENGTH)?);

        Ok(pcrs)
    }
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
    let bytes = hex::decode(value).map_err(|e| TrustedHashesError::InvalidPcr {
        index,
        source: Box::new(ParsePcrError::InvalidHex(e)),
    })?;

    if bytes.len() != expected_len {
        return Err(TrustedHashesError::InvalidPcr {
            index,
            source: Box::new(ParsePcrError::InvalidLength {
                expected: expected_len,
                actual: bytes.len(),
            }),
        });
    }

    Ok(bytes)
}

impl App {
    /// Parse the headers from the raw string vector into a [`HeaderMap`].
    ///
    /// # Errors
    /// Returns [`ParseHeadersError`] if any header has an invalid format.
    pub fn parse_headers(&self) -> Result<HeaderMap, ParseHeadersError> {
        let mut headers = HeaderMap::with_capacity(self.headers.len());

        for header in &self.headers {
            let (name, value) = parse_header(header)?;
            append_header(&mut headers, name, value)?;
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
    name: &str,
    value: &str,
) -> Result<(), AppendHeaderError> {
    let header_name: http::header::HeaderName =
        name.parse().map_err(AppendHeaderError::ParseName)?;

    // HTTP headers must be ASCII-only; reject non-ASCII characters
    if !value.is_ascii() {
        return Err(AppendHeaderError::NonAsciiValue);
    }

    let header_value =
        http::header::HeaderValue::from_str(value).map_err(AppendHeaderError::ParseValue)?;
    headers.append(header_name, header_value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_app(url: &str, data: Option<&str>, json: Option<&str>, headers: Vec<&str>) -> App {
        App {
            url: url.to_string(),
            trusted_hashes_file: ".caution/trusted-hashes.json".to_string(),
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
    fn test_parse_header_with_multiple_colons() {
        let app = make_app("http://example.com", None, None, vec!["X-Time: 12:30:45"]);

        let headers = app.parse_headers().unwrap();
        assert_eq!(headers.get("x-time"), Some(&"12:30:45".parse().unwrap()));
    }

    #[test]
    fn test_parse_headers_duplicate_names() {
        let app = make_app(
            "http://example.com",
            None,
            None,
            vec!["X-Custom: value1", "X-Custom: value2"],
        );

        let headers = app.parse_headers().unwrap();
        // Verify we have 2 entries for X-Custom
        let count = headers
            .iter()
            .filter(|(name, _)| name.as_str() == "x-custom")
            .count();
        assert_eq!(count, 2);
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
        let mut headers = HeaderMap::new();
        let result = append_header(&mut headers, "\0invalid", "value");
        assert!(matches!(result, Err(AppendHeaderError::ParseName(_))));
    }

    #[test]
    fn test_append_header_error_invalid_value() {
        let mut headers = HeaderMap::new();
        let result = append_header(&mut headers, "X-Custom", "\0invalid");
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
        let result = append_header(&mut headers, "X-Custom", "hello world");
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
            "pcr0": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
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
            "pcr0": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
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
            "pcr0": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
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
        let valid_hex = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
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
