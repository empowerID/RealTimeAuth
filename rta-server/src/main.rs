mod config;
mod token;
mod server;
mod events;
mod context;

use anyhow::Result;
use tracing::info;
use tracing_subscriber;
use crate::config::Settings;
use crate::events::EventNotifier;
use crate::context::ContextManager;
use crate::server::RTAServer;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    info!("Starting RealTimeAuth IdP server...");

    // Load configuration
    let settings = Settings::new("config/config.toml")
        .expect("Failed to load configuration");

    // Initialize event notifier (Redis)
    let notifier = EventNotifier::new(&settings.redis.url).await?;

    // Initialize authorization context manager
    let ctx_manager = ContextManager::new();

    // Initialize and run RTAServer
    let mut rta_server = RTAServer::new(
        &settings.server,
        &notifier,
        ctx_manager,
    )
    .await?;

    rta_server.run().await?;

    Ok(())
}
