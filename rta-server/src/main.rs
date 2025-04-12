// src/main.rs
mod config;
mod domain;
mod application;
mod infrastructure;
mod token_exchange_quic;

use anyhow::Result;
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber;
use config::Settings;
use infrastructure::quic_server::run_quic_token_exchange;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber for logging.
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    info!("Starting RealTimeAuth IdP server...");

    // Load configuration from the specified file.
    let settings = Settings::new("config/config.toml")
        .expect("Failed to load configuration");

    // Launch the QUIC token exchange endpoint on a dedicated port (e.g., port 8082).
    let exchange_addr: SocketAddr = format!("{}:{}", settings.server.host, 8082)
        .parse()?;
    tokio::spawn(async move {
        if let Err(e) = run_quic_token_exchange(
            exchange_addr,
            &settings.server,
            &settings.idp,
            &settings.token,
            &settings.redis,
        ).await {
            eprintln!("QUIC Token Exchange endpoint error: {:?}", e);
        }
    });

    // Keep the main task alive indefinitely.
    futures::future::pending::<()>().await;
    Ok(())
}
