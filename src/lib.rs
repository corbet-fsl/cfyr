//! Foyer forwards member, admin and root operations through the cvld owner client.
//! Frontends use cmsg; this facade is a private composition dependency behind it.
//! No action list, role policy, gate evaluator, server or key custody lives here.
#![forbid(unsafe_code)]

#[cfg(all(feature = "browser", target_arch = "wasm32"))]
pub use cvld::client::BrowserClient;
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use cvld::client::HttpClient;
pub use cvld::client::{Action, Transport, action, contract};
pub use cvld::error::{Error, Result};
use serde_json::Value;

/// Thin device facade over the original owner's client and transport.
pub struct Foyer<T> {
    client: cvld::client::Client<T>,
}

impl<T: Transport> Foyer<T> {
    /// Compose an authenticated runtime; this does not mint a session or grant.
    pub fn new(transport: T) -> Self {
        Self {
            client: cvld::client::Client::new(transport),
        }
    }

    /// Forward a registered owner action with its original response and errors.
    /// PRF outputs, wallet roots and local custody handles are never JSON inputs.
    pub async fn call(&mut self, action: &str, request: Value) -> Result<Value> {
        self.client.call(action, request).await
    }
}
