// src/domain/token.rs
use anyhow::Result;
use ring::{digest, rand::{self, SecureRandom}, signature};
use serde::{Serialize, Deserialize};
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};

const TOKEN_HEADER: &[u8; 8] = b"RTA1TOKN";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RTAToken {
    header: [u8; 8],
    pub session_id: [u8; 16],
    context_hash: [u8; 32],
    timestamp: u64,
    signature: Vec<u8>,
}

impl RTAToken {
    pub fn issue(session_id: [u8; 16], context_data: &[u8]) -> Result<Self> {
        let rng = rand::SystemRandom::new();
        // In production, load a persistent signing key.
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
        let signing_key = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
        let context_hash = digest::digest(&digest::SHA256, context_data);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let mut token_data = Vec::new();
        token_data.extend_from_slice(TOKEN_HEADER);
        token_data.extend_from_slice(&session_id);
        token_data.extend_from_slice(context_hash.as_ref());
        token_data.extend_from_slice(&timestamp.to_be_bytes());
        let sig = signing_key.sign(&token_data);

        Ok(Self {
            header: *TOKEN_HEADER,
            session_id,
            context_hash: context_hash.as_ref().try_into()?,
            timestamp,
            signature: sig.as_ref().to_vec(),
        })
    }

    pub fn validate(&self, context_data: &[u8], max_age_secs: u64) -> Result<()> {
        let mut token_data = Vec::new();
        token_data.extend_from_slice(&self.header);
        token_data.extend_from_slice(&self.session_id);
        token_data.extend_from_slice(&self.context_hash);
        token_data.extend_from_slice(&self.timestamp.to_be_bytes());

        // In production, retrieve the persistent public key from configuration.
        let public_key_bytes = include_bytes!("../../certs/public_key.der");
        let verifying_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
        verifying_key.verify(&token_data, &self.signature)
            .map_err(|_| anyhow::anyhow!("Invalid signature"))?;

        let expected_hash = digest::digest(&digest::SHA256, context_data);
        if expected_hash.as_ref() != self.context_hash {
            return Err(anyhow::anyhow!("Context mismatch"));
        }

        let current_ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if current_ts - self.timestamp > max_age_secs {
            return Err(anyhow::anyhow!("Token expired"));
        }
        Ok(())
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub fn deserialize(token_bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(token_bytes)?)
    }
}
