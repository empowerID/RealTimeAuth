// src/infrastructure/quic_server.rs
use anyhow::{anyhow, Result};
use quinn::{Endpoint, Connection};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, private_key};
use serde::{Deserialize, Serialize};
use std::{fs, net::SocketAddr, sync::Arc};
use tracing::{info, error};
use base64::engine::general_purpose::STANDARD; // using new base64 encode engine
use base64::Engine;
use hex;

use crate::config::{ServerConfig, IdpConfig, TokenConfig, RedisConfig, IdpProviders};
use crate::application::commands::{IssueTokenCommand, handle_issue_token};
use crate::domain::token::RTAToken;

/// Structure representing the token exchange request.
#[derive(Debug, Deserialize)]
pub struct TokenExchangeRequest {
    pub grant_type: String,
    pub oauth_token: String,
    pub agent_id: String,
    // Added field for the IdP provider selection (e.g., "azure", "okta", "auth0").
    pub provider: Option<String>,
}

/// Structure representing the token exchange response.
#[derive(Debug, Serialize)]
pub struct TokenExchangeResponse {
    pub rtatoken: String, // Base64-encoded token
}

/// Runs the QUIC Token Exchange endpoint.
///
/// Binds the QUIC endpoint to the supplied address, listens for incoming connections,
/// and processes token exchange requests. The idp_providers reference is cloned into each async task
/// to satisfy the `'static` requirement.
pub async fn run_quic_token_exchange(
    addr: SocketAddr,
    server_config: &ServerConfig,
    idp_providers: &IdpProviders, // Updated parameter type
    token_config: &TokenConfig,
    _redis_config: &RedisConfig, // Not used for in-memory binding.
) -> Result<()> {
    // Load TLS certificates.
    let cert_file = fs::File::open(&server_config.cert_path)?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<Result<_, _>>()?;

    // Load the private key.
    let key_file = fs::File::open(&server_config.key_path)?;
    let mut key_reader = std::io::BufReader::new(key_file);
    let private_key: PrivateKeyDer<'static> = private_key(&mut key_reader)?
        .ok_or_else(|| anyhow!("No private key found"))?;

    // Build the TLS configuration for QUIC.
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?;
    let quic_server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    // Bind the QUIC endpoint.
    let mut endpoint = Endpoint::server(quic_server_config, addr)?;
    info!("QUIC Token Exchange endpoint listening on {}", addr);

    // Process incoming connections.
    while let Some(connecting) = endpoint.accept().await {
        // Clone the token configuration and the IdP providers to satisfy the 'static lifetime.
        let token_config_cloned = token_config.clone();
        let idp_providers_cloned = idp_providers.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => {
                    info!("Established connection from {}", conn.remote_address());
                    if let Err(e) = handle_exchange_connection(conn, &token_config_cloned, &idp_providers_cloned).await {
                        error!("Error processing exchange connection: {:?}", e);
                    }
                }
                Err(e) => error!("Connection failed: {:?}", e),
            }
        });
    }
    Ok(())
}

/// Processes a single token exchange connection.
///
/// Accepts a bidirectional QUIC stream, reads and parses a token exchange request,
/// validates the custom grant type, and calls the application command handler
/// to issue an RTAToken. Finally, it serializes and encodes the token as Base64,
/// sending it back to the client as a JSON response.
async fn handle_exchange_connection(
    conn: Connection,
    token_config: &TokenConfig,
    idp_providers: &IdpProviders, // New parameter for IdP selection
) -> Result<()> {
    // Accept a bidirectional stream.
    let (mut send, mut recv) = conn.accept_bi().await?;
    
    // Read the request into a buffer (assume the request fits within 4KB).
    let mut buf = vec![0u8; 4096];
    let n = recv.read(&mut buf).await?
        .ok_or_else(|| anyhow!("Stream closed prematurely"))?;
    buf.truncate(n);

    // Parse the JSON request.
    let req: TokenExchangeRequest = serde_json::from_slice(&buf)
        .map_err(|e| anyhow!("Failed to parse token exchange request: {:?}", e))?;
    
    // Validate the custom grant type.
    if req.grant_type != "urn:ietf:params:oauth:grant-type:rta_token_exchange" {
        let msg = "Unsupported grant type";
        send.write_all(msg.as_bytes()).await?;
        send.finish()?;
        return Err(anyhow!(msg));
    }
    
    // Build the command to issue a token, including the provider field.
    let cmd = IssueTokenCommand {
        oauth_token: req.oauth_token,
        agent_id: req.agent_id,
        provider: req.provider, // Passed from the request (if provided)
    };
    
    // In a real system, context data could come from IdP introspection; we use a static value here.
    let context_data = b"introspection_based_context";
    let (token, _event) = handle_issue_token(cmd, context_data, idp_providers).await?;
    
    // Serialize the RTAToken and encode it in Base64 using the new engine API.
    let token_bytes = token.serialize()?;
    let encoded_token = STANDARD.encode(&token_bytes);

    // Build the JSON response.
    let resp = TokenExchangeResponse { rtatoken: encoded_token };
    let resp_json = serde_json::to_vec(&resp)?;
    send.write_all(&resp_json).await?;
    send.finish()?;
    
    let session_id_hex = hex::encode(token.session_id);
    info!("Issued token for session_id: {}", session_id_hex);
    Ok(())
}
