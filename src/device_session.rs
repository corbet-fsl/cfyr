//! Device-key session forwarding. The device owner signs the public nonce with its community
//! device key (no passkey, no prompt); Foyer only forwards and retains the resulting session.
use crate::{Error, Foyer, Result, SessionInfo, SessionTransport, Transport};
use serde::Deserialize;

/// The join protocol's public constants and signed message, from the original server.
pub use cvld::device_session::{
    JOIN_ACTION, UNFOUNDED_FINGERPRINT_TAG, join_message, join_payload, scope_fingerprint,
};

/// The original server's one-use nonce. The signed message is rebuilt with
/// `cvld::device_session::message(community, &nonce, issued)`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    /// One-use nonce, valid for a minute.
    pub nonce: [u8; 32],
    /// Server issue time, part of the signed message.
    pub issued: u64,
}

impl Challenge {
    /// The exact bytes the device signs: bound to the community, the nonce and the issue time.
    pub fn message(&self, community: &str) -> Vec<u8> {
        cvld::device_session::message(community, &self.nonce, self.issued)
    }
}

impl<T: Transport> Foyer<T> {
    /// Ask the original server for a nonce to sign with the community device key.
    pub async fn begin_device_session(&mut self) -> Result<Challenge> {
        let value = self
            .call("device_session_begin", serde_json::json!({}))
            .await?;
        serde_json::from_value(value).map_err(|_| Error::Reconcile)
    }
}

impl<T: SessionTransport> Foyer<T> {
    /// Open or renew the session from the device key's signature. The bearer stays in the
    /// original transport; only identity, role and deadline are returned. The device key is
    /// the session's login credential, as the passkey is for a passkey session.
    pub async fn finish_device_session(
        &mut self,
        nonce: [u8; 32],
        user: &str,
        device_key: [u8; 32],
        signature: Vec<u8>,
    ) -> Result<SessionInfo> {
        self.install(
            serde_json::json!({
                "nonce": nonce, "user": user, "device_key": device_key, "signature": signature,
            }),
            Some(device_key.to_vec()),
            true,
        )
        .await
    }
}
