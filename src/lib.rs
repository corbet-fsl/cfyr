//! Foyer forwards member, admin and root operations through the cvld owner client.
//! Frontends use cmsg; this facade is a private composition dependency behind it.
//! No action list, role policy, gate evaluator, server or key custody lives here.
#![forbid(unsafe_code)]

#[cfg(all(feature = "browser", target_arch = "wasm32"))]
pub use cvld::client::BrowserClient;
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use cvld::client::HttpClient;
pub use cvld::client::{
    Action, SessionInfo, SessionTransport, Transport, forwarding_action as action,
    forwarding_contract as contract,
};
pub use cvld::error::{Error, Result};
use serde_json::Value;

/// Retained original Charter and Envoy composition for public community trust.
pub mod trust;
/// Device passkey owner. Foyer is its canonical facade home.
pub use cpky as passkeys;
#[cfg(not(target_arch = "wasm32"))]
/// Public native browser challenge/assertion forwarding and retained session.
pub mod login;

/// Thin device facade over the original owner's client and transport.
pub struct Foyer<T> {
    client: cvld::client::Client<T>,
    trust: Option<trust::Trust>,
}

impl<T> Foyer<T> {
    /// Borrow the one retained community trust follower. A forwarding-only Foyer
    /// has no policy authority and returns the original unavailable error.
    pub fn trust(&mut self) -> cnvy::Result<&mut trust::Trust> {
        self.trust.as_mut().ok_or(cnvy::Error::Unavailable)
    }

    /// Borrow current verified community policy after both original owners check
    /// the current time. Consumers must reborrow after a network or authority wait.
    pub fn current(&mut self, now: u64) -> cnvy::Result<&cnvy::cchr::VerifiedCharter> {
        self.trust()?.current(now)
    }
}

impl<T: Transport> Foyer<T> {
    /// Compose an authenticated runtime; this does not mint a session or grant.
    pub fn new(transport: T) -> Self {
        Self {
            client: cvld::client::Client::new(transport),
            trust: None,
        }
    }

    /// Retain one configured original public trust follower beside the selected
    /// session transport. Runtime construction selects both; shell JSON cannot.
    pub fn with_trust(transport: T, trust: trust::Trust) -> Self {
        Self {
            client: cvld::client::Client::new(transport),
            trust: Some(trust),
        }
    }

    /// Forward a registered owner action with its original response and errors.
    /// PRF outputs, wallet roots and local custody handles are never JSON inputs.
    pub async fn call(&mut self, action: &str, request: Value) -> Result<Value> {
        self.client.forward(action, request).await
    }
}

impl<T: SessionTransport> Foyer<T> {
    /// Consume a real public passkey assertion and retain the server session.
    /// Only the authenticated identity, role and deadline may reach the shell.
    pub async fn authenticate(&mut self, request: Value) -> Result<SessionInfo> {
        self.client.authenticate(request).await
    }
}
