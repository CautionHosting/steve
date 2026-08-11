mod cli;

use clap::Parser;
use cli::{App, FilePcrTrustStore, PolicyInput};
use std::{
    error::Error,
    io::{self, Write},
    process,
    sync::Arc,
};
use steve_sdk::PcrPolicy;
use thiserror::Error;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Initialize tracing subscriber with environment filter support
    // Use RUST_LOG env var to control log levels (e.g., RUST_LOG=debug,reqwest=trace)
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // Default to warning level if RUST_LOG is not set
                tracing_subscriber::EnvFilter::new("warn")
            }),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    // Bridge the `log` crate to `tracing` so reqwest's log messages are captured
    tracing_log::LogTracer::init().ok();

    if let Err(e) = run().await {
        log_error_with_chain(&e);
        process::exit(1);
    }
}

/// Error type specific to the `run()` function.
///
/// This enum captures all error variants that can arise during request execution,
/// with semantically correct error categories for each failure mode.
#[derive(Error, Debug)]
enum RunError {
    /// Invalid URL parsing error.
    #[error("Invalid URL")]
    InvalidUrl(#[source] url::ParseError),

    /// Unsupported HTTP method.
    #[error("Unsupported HTTP method: {0}")]
    UnsupportedMethod(String),

    /// Response body is not valid UTF-8.
    #[error("Response body is not valid UTF-8")]
    InvalidResponseBody(#[source] std::str::Utf8Error),

    /// Error parsing headers from command-line arguments.
    #[error("Invalid header")]
    Headers(#[from] cli::ParseHeadersError),

    /// Error loading trusted hashes file.
    #[error("Failed to load trusted hashes file")]
    TrustedHashes(#[from] cli::TrustedHashesError),

    /// Invalid key exchange suite.
    #[error("Invalid KEM")]
    InvalidKeyExchangeSuite(#[from] cli::ParseKeyExchangeError),

    /// Invalid JSON body.
    #[error("Invalid JSON")]
    InvalidJson(#[source] serde_json::Error),

    /// Steve SDK error.
    #[error(transparent)]
    Steve(#[from] steve_sdk::Error),

    /// Error reading or validating the TOFU store.
    #[error("Failed to validate TOFU store")]
    TrustStore(#[from] cli::TrustStoreError),

    /// Error writing the response body.
    #[error("Failed to write response body")]
    Output(#[source] io::Error),
}

/// Log an error and its full cause chain using tracing.
fn log_error_with_chain(err: &(dyn Error + 'static)) {
    let mut err = Some(err);
    let mut chain = String::new();
    while let Some(cause) = err {
        if !chain.is_empty() {
            chain.push_str(": ");
        }
        chain.push_str(&cause.to_string());
        err = cause.source();
    }
    tracing::error!(%chain, "Application error");
}

async fn run() -> Result<(), RunError> {
    let app = App::parse();

    let headers = app.parse_headers()?;
    let key_exchange = app.parse_key_exchange()?;
    let url = url::Url::parse(&app.url).map_err(RunError::InvalidUrl)?;
    let (policy, policy_description) = resolve_policy(&app)?;
    let client_builder =
        steve_sdk::Client::builder_with_policy(url.origin().ascii_serialization(), policy)?
            .expected_key_exchange(key_exchange);

    let method = if app.body().is_some() {
        http::Method::POST
    } else {
        http::Method::GET
    };

    // Dry-run mode: validate configuration without making a request
    if app.dry_run {
        println!("Dry-run mode: configuration validated successfully");
        println!();
        println!("Would make request:");
        println!("  URL: {}", app.url);
        println!("  Method: {method}");
        println!("  Key exchange: {key_exchange}");
        println!("  PCR policy: {policy_description}");

        if let Some(body) = app.body() {
            println!("  Body: {} bytes", body.len());
            if app.is_json() {
                // Validate JSON syntax in dry-run mode
                let _json_value: serde_json::Value =
                    serde_json::from_str(body).map_err(RunError::InvalidJson)?;
                println!("  Content-Type: application/json");
                println!("  JSON: valid");
            }
        }

        if !headers.is_empty() {
            println!("  Headers: {} header(s)", headers.len());
            for (name, value) in &headers {
                println!(
                    "    {}: {}",
                    name,
                    value.to_str().expect("checked at creation time")
                );
            }
        }

        println!();
        println!("No request was made.");
        return Ok(());
    }

    // Create and connect Steve SDK client
    let client = client_builder.connect().await?;
    let attestation = client.verify_attestation().await?;
    eprintln!("PCR trust: {:?}", attestation.pcr_trust);

    let target = request_target(&url);

    let mut request_builder = match method {
        http::Method::GET => client.get(target),
        http::Method::POST => client.post(target),
        _ => return Err(RunError::UnsupportedMethod(method.to_string())),
    };

    for (name, value) in &headers {
        request_builder = request_builder
            .header(
                name.as_str(),
                value
                    .to_str()
                    .expect("ASCII checked during argument parsing"),
            )
            .expect("infallible conversion");
    }

    if let Some(body) = app.body() {
        if app.is_json() {
            let json_value: serde_json::Value =
                serde_json::from_str(body).map_err(RunError::InvalidJson)?;
            request_builder = request_builder.json(&json_value)?;
        } else {
            request_builder = request_builder.body(body.to_owned());
        }
    }

    let response = request_builder.send().await?;

    // Print response body to stdout (script-compatible)
    let body = response.text().map_err(RunError::InvalidResponseBody)?;

    io::stdout()
        .write_all(body.as_bytes())
        .map_err(RunError::Output)?;

    Ok(())
}

fn resolve_policy(app: &App) -> Result<(PcrPolicy, String), RunError> {
    match app.policy_input() {
        PolicyInput::Pinned(paths) => {
            let profiles = cli::load_profiles(&paths)?;
            let description = if paths.len() == 1 {
                let mut description = String::from("pinned (");
                description.push_str(&paths[0].display().to_string());
                description.push(')');
                description
            } else {
                let mut description = String::from("pinned allowlist (");
                description.push_str(&paths.len().to_string());
                description.push_str(" profiles)");
                description
            };
            Ok((PcrPolicy::pinned(profiles)?, description))
        }
        PolicyInput::Tofu(path) => {
            let store = Arc::new(FilePcrTrustStore::new(path.clone()));
            store.validate()?;
            let mut description = String::from("TOFU (");
            description.push_str(&path.display().to_string());
            description.push(')');
            Ok((PcrPolicy::trust_on_first_use(store), description))
        }
    }
}

fn request_target(url: &url::Url) -> String {
    let mut target = url.path().to_owned();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    target
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_with_policy(
        pcrs_files: Vec<std::path::PathBuf>,
        tofu_store: Option<std::path::PathBuf>,
    ) -> App {
        App {
            url: "https://example.com/health".into(),
            pcrs_files,
            tofu_store,
            key_exchange: "X25519".into(),
            dry_run: true,
            data: None,
            json: None,
            headers: Vec::new(),
        }
    }

    #[test]
    fn request_target_preserves_query_and_ignores_fragment() {
        let url = url::Url::parse("https://example.com/items?limit=2#ignored").unwrap();
        assert_eq!(request_target(&url), "/items?limit=2");
    }

    #[test]
    fn policy_resolution_validates_pinned_input_before_networking() {
        let missing = tempfile::tempdir().unwrap().path().join("missing.json");
        assert!(matches!(
            resolve_policy(&app_with_policy(vec![missing], None)),
            Err(RunError::TrustedHashes(_))
        ));
    }

    #[test]
    fn policy_resolution_does_not_create_a_missing_tofu_store() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trust.json");
        resolve_policy(&app_with_policy(Vec::new(), Some(path.clone()))).unwrap();
        assert!(!path.exists());
    }
}
