mod cli;

use clap::Parser;
use cli::App;
use std::error::Error;
use std::process;
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
    let url = reqwest::Url::parse(&app.url).map_err(RunError::InvalidUrl)?;

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
        println!("  Trusted hashes file: {}", app.trusted_hashes_file);

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

    // Load trusted hashes from file (only for non-dry-run)
    let trusted_hashes = cli::TrustedHashes::load(&app.trusted_hashes_file)?;
    let expected_pcrs = trusted_hashes.to_nitro_pcrs()?;

    tracing::debug!("Loaded PCRs from {}", app.trusted_hashes_file);

    // Create and connect Steve SDK client
    let client = steve_sdk::Client::builder(url.origin().ascii_serialization(), expected_pcrs)?
        .expected_key_exchange(key_exchange)
        .connect()
        .await?;

    let mut request_builder = match method {
        http::Method::GET => client.get(url.path()),
        http::Method::POST => client.post(url.path()),
        _ => return Err(RunError::UnsupportedMethod(method.to_string())),
    };

    for (name, value) in &headers {
        request_builder = request_builder
            .header(name, value)
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

    println!("{body}");

    Ok(())
}
