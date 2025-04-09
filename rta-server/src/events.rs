// src/events.rs (fully corrected)
use anyhow::Result;
use redis::AsyncCommands;
use futures::StreamExt;
use tracing::{info, warn};

pub struct EventNotifier {
    pub redis_client: redis::Client,
}

impl EventNotifier {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self { redis_client: client })
    }

    pub async fn publish_revocation(&self, session_id: &str) -> Result<()> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        conn.publish::<_, _, ()>("revocation_channel", session_id).await?;
        info!("Published revocation for session_id: {}", session_id);
        Ok(())
    }

    pub async fn subscribe_revocations<F>(&self, mut callback: F) -> Result<()>
    where
        F: FnMut(String) + Send + 'static,
    {
        let conn = self.redis_client.get_async_connection().await?;
        let mut pubsub = conn.into_pubsub();
        pubsub.subscribe("revocation_channel").await?;

        tokio::spawn(async move {
            let mut stream = pubsub.into_on_message(); // fixed lifetime issue
            info!("Subscribed to revocation_channel");
            
            while let Some(msg) = stream.next().await {
                let payload: String = msg.get_payload().unwrap_or_default();
                warn!("Received revocation for session_id: {}", payload);
                callback(payload);
            }
        });

        Ok(())
    }
}
