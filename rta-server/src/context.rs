// src/context.rs
use dashmap::DashMap;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthorizationContext {
    pub user_id: String,
    pub allowed_resources: Vec<String>,
    pub risk_score: u8,
}

impl AuthorizationContext {
    pub fn is_action_allowed(&self, resource: &str) -> bool {
        self.allowed_resources.contains(&resource.to_string()) && self.risk_score < 50
    }
}

#[derive(Clone)]
pub struct ContextManager {
    contexts: Arc<DashMap<String, AuthorizationContext>>,
}

impl ContextManager {
    pub fn new() -> Self {
        Self {
            contexts: Arc::new(DashMap::new()),
        }
    }

    pub fn validate_action(&self, session_id: &str, resource: &str) -> Result<()> {
        match self.contexts.get(session_id) {
            Some(ctx) if ctx.is_action_allowed(resource) => Ok(()),
            _ => Err(anyhow!("Unauthorized")),
        }
    }
}
