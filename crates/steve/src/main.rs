//! Secure Transport Encryption Via Enclave

use steve::{ServerConfig, build_router, write_metadata};
use tokio::net::TcpListener;
use tracing::debug;

type Result<T, E = Box<dyn std::error::Error + Send + Sync>> = std::result::Result<T, E>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    write_metadata()?;

    let config = ServerConfig::from_env()?;
    let listen_addr = config.listen_addr.clone();
    let app = build_router(config)?;

    debug!(%listen_addr, "binding STEVE v2 listener");
    let listener = TcpListener::bind(&listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
