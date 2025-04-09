use anyhow::Result;

pub trait Token {
    fn new(session_id: [u8; 16], context_data: &[u8]) -> Result<Self> where Self: Sized;
    fn validate(&self, context_data: &[u8], max_age_secs: u64) -> Result<()>;
    fn serialize(&self) -> Result<Vec<u8>>;
    fn deserialize(token_bytes: &[u8]) -> Result<Self> where Self: Sized;
}
