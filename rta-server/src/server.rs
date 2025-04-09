use anyhow::{Result, anyhow};
use quinn::{Endpoint, ServerConfig, Connection, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, private_key};
use std::{net::SocketAddr, fs, sync::Arc, collections::HashSet};
use tracing::{info, error, warn};
use crate::config::ServerConfig as AppConfig;
use crate::token::{RTAToken, Token};
use crate::events::EventNotifier;
use crate::context::ContextManager;
use tokio::sync::RwLock;
use hex;

pub struct RTAServer {
    endpoint: Endpoint,
    revoked_sessions: Arc<RwLock<HashSet<String>>>,
    ctx_manager: ContextManager,
}

impl RTAServer {
    pub async fn new(config: &AppConfig, notifier: &EventNotifier, ctx_manager: ContextManager) -> Result<Self> {
        // Load TLS certificates
        let cert_file = fs::File::open(&config.cert_path)?;
        let mut cert_reader = std::io::BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
            .collect::<Result<_, _>>()?;

        // Load private key
        let key_file = fs::File::open(&config.key_path)?;
        let mut key_reader = std::io::BufReader::new(key_file);
        let private_key: PrivateKeyDer<'static> = private_key(&mut key_reader)?
            .ok_or_else(|| anyhow!("No private key found"))?;

        // Configure Rustls for QUIC explicitly
        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)?;

        // Wrap Rustls ServerConfig explicitly in QuicServerConfig
        let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?;
        let server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

        // Bind QUIC endpoint
        let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
        let endpoint = Endpoint::server(server_config, addr)?;

        info!("RTA QUIC server listening at {}", addr);

        // Setup revoked session storage and event notifier
        let revoked_sessions = Arc::new(RwLock::new(HashSet::new()));
        let revoked_sessions_clone = revoked_sessions.clone();

        notifier.subscribe_revocations(move |session_id| {
            let revoked_sessions = revoked_sessions_clone.clone();
            tokio::spawn(async move {
                revoked_sessions.write().await.insert(session_id.clone()); // <-- explicitly cloned here
                warn!("Session revoked: {}", session_id);
            });
        }).await?;

        Ok(Self { endpoint, revoked_sessions, ctx_manager })
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Some(connecting) = self.endpoint.accept().await {
            let revoked_sessions = self.revoked_sessions.clone();
            let ctx_manager = self.ctx_manager.clone();
            tokio::spawn(async move {
                match connecting.await {
                    Ok(connection) => {
                        info!("Connected: {}", connection.remote_address());
                        if let Err(e) = handle_connection(connection, revoked_sessions, ctx_manager).await {
                            error!("Connection error: {:?}", e);
                        }
                    }
                    Err(e) => error!("Connection failed: {:?}", e),
                }
            });
        }
        Ok(())
    }
}

// Handle incoming QUIC connections
async fn handle_connection(conn: Connection, revoked_sessions: Arc<RwLock<HashSet<String>>>, ctx_manager: ContextManager) -> Result<()> {
    while let Ok((send, recv)) = conn.accept_bi().await {
        let revoked_sessions = revoked_sessions.clone();
        let ctx_manager = ctx_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, revoked_sessions, ctx_manager).await {
                error!("Stream handling error: {:?}", e);
            }
        });
    }
    Ok(())
}

// Handle individual QUIC streams
async fn handle_stream(mut send: SendStream, mut recv: RecvStream, revoked_sessions: Arc<RwLock<HashSet<String>>>, ctx_manager: ContextManager) -> Result<()> {
    let mut buf = [0u8; 4096];
    let n = recv.read(&mut buf).await?
        .ok_or_else(|| anyhow!("Stream closed unexpectedly"))?;

    if n == 0 {
        warn!("Empty stream received, closing.");
        return Ok(());
    }

    // Deserialize RTAToken
    let token = match RTAToken::deserialize(&buf[..n]) {
        Ok(token) => token,
        Err(e) => {
            let err_msg = format!("Failed to deserialize token: {}", e);
            error!("{}", err_msg);
            send.write_all(err_msg.as_bytes()).await?;
            send.finish()?;
            return Ok(());
        }
    };

    let session_id_hex = hex::encode(token.session_id);

    // Check token revocation status
    if revoked_sessions.read().await.contains(&session_id_hex) {
        send.write_all(b"Token revoked").await?;
        send.finish()?;
        warn!("Rejected revoked token for session_id: {}", session_id_hex);
        return Ok(());
    }

    let requested_resource = "document-123";

    // Validate token and check context
    match token.validate(b"dynamic-context-data", 3600)
        .and_then(|_| ctx_manager.validate_action(&session_id_hex, requested_resource)) {
        Ok(_) => {
            let success_msg = format!("Access granted to {}", requested_resource);
            send.write_all(success_msg.as_bytes()).await?;
            info!("{} for session_id: {}", success_msg, session_id_hex);
        }
        Err(e) => {
            let error_message = format!("Access denied: {}", e);
            send.write_all(error_message.as_bytes()).await?;
            error!("{} for session_id: {}", error_message, session_id_hex);
        }
    }

    send.finish()?;
    Ok(())
}
