use quinn::{ClientConfig, Endpoint};
use std::{net::ToSocketAddrs, sync::Arc};
use anyhow::Result;
use tracing::info;
use tracing_subscriber;
use serde::{Serialize, Deserialize};
use bincode;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct RTAToken {
    header: [u8; 8],
    session_id: [u8; 16],
    context_hash: [u8; 32],
    timestamp: u64,
    signature: Vec<u8>, // placeholder signature
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let server_addr = "127.0.0.1:4433";
    let server_name = "localhost"; // match your server's certificate CN if validating

    info!("Connecting to {}", server_addr);

    // Explicit QUIC client config
    let crypto_config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    let client_cfg = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)?,
    ));

    let endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_cfg);

    let conn = endpoint
        .connect(server_addr.to_socket_addrs()?.next().unwrap(), server_name)?
        .await?;

    info!("Connected!");

    let (mut send, mut recv) = conn.open_bi().await?;

    // Construct dummy RTAToken explicitly
    let token = RTAToken {
        header: *b"RTA1TOKN",
        session_id: [0u8; 16],
        context_hash: [0u8; 32],
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        signature: vec![],
    };

    let serialized = bincode::serialize(&token)?;

    send.write_all(&serialized).await?;
    send.finish().await?;

    info!("RTAToken sent. Awaiting response...");

    let mut response_buf = Vec::new();
    recv.read_to_end(usize::MAX).await.map(|data| response_buf = data)?;

    let response = String::from_utf8(response_buf)?;
    info!("Server response: {}", response);

    Ok(())
}
