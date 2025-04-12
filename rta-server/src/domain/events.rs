// src/domain/events.rs
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum DomainEvent {
    TokenIssued { session_id: String },
    TokenRevoked { session_id: String },
}
