// src/infrastructure/idp_adapter.rs
use anyhow::Result;
use reqwest::Client;
use serde_json::Value;
use crate::config::IdpProviders;

/// Introspects the provided OAuth token using the configuration for the selected provider.
/// If `provider` is None, the default provider is used.
pub async fn introspect(oauth_token: &str, provider: Option<&str>, providers: &IdpProviders) -> Result<bool> {
    // Select the provider – use the provided value, or fall back to the default.
    let selected = provider.unwrap_or(&providers.default).to_lowercase();
    let idp_config = match selected.as_str() {
        "azure" => &providers.azure,
        "okta"  => &providers.okta,
        "auth0" => &providers.auth0,
        _ => return Err(anyhow::anyhow!("Unknown IdP provider: {}", selected)),
    };

    // Prepare the HTTP client.
    let client = Client::new();
    let params = [
        ("token", oauth_token),
        ("client_id", &idp_config.client_id),
        ("client_secret", &idp_config.client_secret),
    ];
    
    // Send the introspection request.
    let resp = client.post(&idp_config.introspection_url)
        .form(&params)
        .send()
        .await?;
    let status = resp.status();

    // Parse the response body as JSON (optional).
    let _json: Value = resp.json().await.unwrap_or(Value::Null);
    Ok(status.is_success())
}
