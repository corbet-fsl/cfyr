//! A fresh user-verifying assertion for exactly one action, as a real member's device
//! produces it: `step_up_begin` through the Foyer, the passkey answers, and the proof
//! is the `step_up` field of the guarded call.
use crate::{Foyer, Transport};
use cpky::software::SoftwareAuthenticator;
use serde_json::{Value, json};

/// The `step_up` proof for `action` (the owner's `{"kind": ..}` action JSON).
pub(crate) async fn step_up<T: Transport>(
    foyer: &mut Foyer<T>,
    keys: &mut cpky::Client<SoftwareAuthenticator>,
    action: Value,
) -> Value {
    let begin = foyer
        .call("step_up_begin", json!({"action": action}))
        .await
        .unwrap();
    let (assertion, _) = keys
        .sign_in(begin["options"].clone())
        .await
        .unwrap()
        .into_parts();
    json!({"ceremony": begin["ceremony"], "credential": assertion.into_json()})
}

/// `body` with the proof for `action` added as its `step_up` field.
pub(crate) async fn proven<T: Transport>(
    foyer: &mut Foyer<T>,
    keys: &mut cpky::Client<SoftwareAuthenticator>,
    action: Value,
    mut body: Value,
) -> Value {
    body["step_up"] = step_up(foyer, keys, action).await;
    body
}

/// The raw `step_up_begin` reply, for callers whose authenticator is not a `cpky::Client`
/// (the owner fixture's `SoftToken` answers `options` itself).
pub(crate) async fn begin<T: Transport>(foyer: &mut Foyer<T>, action: Value) -> Value {
    foyer
        .call("step_up_begin", json!({"action": action}))
        .await
        .unwrap()
}
