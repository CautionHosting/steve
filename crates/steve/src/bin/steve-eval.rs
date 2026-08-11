//! Local-only STEVE server with signed synthetic Nitro-shaped evidence.

use std::sync::Arc;

use steve::{
    ServerConfig, build_router_with_provider, eval_attestation::EvalAttestationProvider,
    write_metadata,
};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

type Result<T, E = Box<dyn std::error::Error + Send + Sync>> = std::result::Result<T, E>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(false)
        .init();

    write_metadata()?;

    let config = ServerConfig::from_env()?;
    let listen_addr = config.listen_addr.clone();
    let upstream_url = config.upstream_url.clone();
    let app = build_router_with_provider(config, Arc::new(EvalAttestationProvider))?
        .layer(TraceLayer::new_for_http());

    info!(%listen_addr, %upstream_url, "starting local-eval STEVE v2");
    let listener = TcpListener::bind(&listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
