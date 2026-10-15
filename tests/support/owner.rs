//! Original resolved Door fixture plus its assertion-before-adoption helper.
#![allow(dead_code)]
#[path = "../owner/mod.rs"]
mod original;
pub use original::*;
#[path = "../owner/client_faults.rs"]
pub mod client_faults;

use cvld::api::Ceremony;
use serde_json::{Value, json};
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

/// Prepare the genuine original Keyhole login assertion, without finishing it.
/// Foyer must submit this assertion through its own original authenticated client.
pub async fn login_request(
    service: &Running,
    host: &str,
    authenticator: &mut SoftToken,
    user: &str,
    credential: &[u8],
) -> Value {
    let start: Ceremony = serde_json::from_value(
        client(service, host, None)
            .call("login_begin", json!({"user":user,"credential":credential}))
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge: ckyh::RequestChallengeResponse = serde_json::from_value(start.options).unwrap();
    let credential = authenticator
        .perform_auth(
            ckyh::Url::parse(&origin_for(host)).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    json!({"ceremony":start.ceremony,"credential":credential})
}
