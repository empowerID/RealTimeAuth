// src/application/commands.rs
use anyhow::Result;
use ring::rand::{self, SecureRandom};
use crate::domain::token::RTAToken;
use crate::domain::events::DomainEvent;
use crate::infrastructure::idp_adapter;
use crate::config::IdpProviders;

pub struct IssueTokenCommand {
    pub oauth_token: String,
    pub agent_id: String,
    pub provider: Option<String>,
}

pub struct RevokeTokenCommand {
    pub session_id: String,
}

pub async fn handle_issue_token(cmd: IssueTokenCommand, context_data: &[u8], idp_providers: &IdpProviders) -> Result<(RTAToken, DomainEvent)> {
    // Validate the OAuth token via IdP introspection using the selected provider.
    let prov = cmd.provider.as_deref();
    let valid = idp_adapter::introspect(&cmd.oauth_token, prov, idp_providers).await?;
    if !valid {
        return Err(anyhow::anyhow!("OAuth token introspection failed"));
    }

    // Generate a random 16-byte session ID.
    let mut session_id = [0u8; 16];
    let rng = rand::SystemRandom::new();
    rng.fill(&mut session_id)?;

    // Issue the RTAToken.
    let token = RTAToken::issue(session_id, context_data)?;
    let session_id_hex = hex::encode(session_id);
    let event = DomainEvent::TokenIssued { session_id: session_id_hex };
    Ok((token, event))
}

pub async fn handle_revoke_token(cmd: RevokeTokenCommand) -> Result<DomainEvent> {
    // Domain logic to revoke a token goes here.
    Ok(DomainEvent::TokenRevoked { session_id: cmd.session_id })
}
