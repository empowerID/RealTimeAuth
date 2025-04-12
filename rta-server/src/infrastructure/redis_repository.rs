// src/infrastructure/redis_repository.rs
use anyhow::Result;
use redis::AsyncCommands;
use crate::domain::token::RTAToken;

pub struct TokenRepository {
    pub client: redis::Client,
}

impl TokenRepository {
    pub async fn new(url: String) -> Result<Self> {
        let client = redis::Client::open(url)?;
        Ok(Self { client })
    }

    pub async fn save(&self, token: &RTAToken) -> Result<()> {
        let mut conn = self.client.get_async_connection().await?;
        let session_id_hex = hex::encode(token.session_id);
        let token_bytes = bincode::serialize(token)?;
        conn.set(format!("rtatoken:{}", session_id_hex), token_bytes).await?;
        Ok(())
    }

    pub async fn get(&self, session_id_hex: &str) -> Result<RTAToken> {
        let mut conn = self.client.get_async_connection().await?;
        let token_bytes: Vec<u8> = conn.get(format!("rtatoken:{}", session_id_hex)).await?;
        let token = bincode::deserialize(&token_bytes)?;
        Ok(token)
    }
}
