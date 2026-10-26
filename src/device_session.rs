//! Device-key session forwarding. The device owner signs the public nonce with its community
//! device key (no passkey, no prompt); Foyer only forwards and retains the resulting session.
use crate::{Error, Foyer, Opening, Result, SessionInfo, SessionTransport, Transport};
use serde::Deserialize;

/// The join protocol's public constants and signed message, from the original server.
pub use cvld::device_session::{
    ACTIVATE_ACTION, ADD_ACTION, GARDEN_ACTION, JOIN_ACTION, PAIR_ACTION, garden_payload,
    join_message, join_payload, pair_payload, pairing_message,
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

    /// The exact bytes the device signs to open an admin session.
    pub fn garden_message(&self, community: &str) -> Vec<u8> {
        cvld::device_session::garden_message(community, &self.nonce, self.issued)
    }
}

impl<T: Transport> Foyer<T> {
    /// Ask the original server for a nonce to sign with the community device key.
    pub async fn begin_device_session(&mut self) -> Result<Challenge> {
        let value = self
            .call("device_session_begin", serde_json::json!({}))
            .await?;
        serde_json::from_value(value).map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Reconcile",
                Error::Reconcile,
                &__cause,
            )
        })
    }

    /// Join by device key (`device_join`): the passport presentation, the confirmation stamp
    /// and the key's signature. A trusted owner action, so it is sent here and never through
    /// the shell forwarding of [`Foyer::call`]. Returns the member the key belongs to.
    pub async fn device_join(&mut self, request: serde_json::Value) -> Result<String> {
        let response = {
            let mut retained = self.shared.session.lock().await;
            retained.client.call("device_join", request).await?
        };
        response
            .get("user")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or(Error::Reconcile)
    }

    /// Pairing step one (`device_add`): register a further device key PENDING, which grants
    /// nothing until [`Foyer::device_activate`]. The request carries the passport
    /// presentation, the community's ONE pairing stamp slot ([`PAIR_ACTION`] with
    /// [`pair_payload`]), the pairing session and the new key's signature over
    /// [`pairing_message`] of [`ADD_ACTION`]. A trusted owner action, sent here and never
    /// through the shell forwarding of [`Foyer::call`].
    pub async fn device_add(&mut self, request: serde_json::Value) -> Result<()> {
        self.pairing_step("device_add", request).await
    }

    /// Pairing step two (`device_activate`): make the approved PENDING key ACTIVE once its
    /// lineage revision is published. No stamp: the passport presentation and the new key's
    /// signature over [`pairing_message`] of [`ACTIVATE_ACTION`].
    pub async fn device_activate(&mut self, request: serde_json::Value) -> Result<()> {
        self.pairing_step("device_activate", request).await
    }

    async fn pairing_step(&mut self, action: &str, request: serde_json::Value) -> Result<()> {
        let mut retained = self.shared.session.lock().await;
        retained.client.call(action, request).await.map(|_| ())
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
            Opening::Device,
        )
        .await
    }

    /// Open an ADMIN session from the device key's signature over the garden message and one
    /// confirmation stamp (`stamp`, `salt`) that covers exactly this key and nonce. Retained
    /// like any session; it never carries wallet custody.
    #[allow(clippy::too_many_arguments)]
    pub async fn finish_garden_session(
        &mut self,
        nonce: [u8; 32],
        user: &str,
        device_key: [u8; 32],
        signature: Vec<u8>,
        stamp: Vec<u8>,
        salt: [u8; 32],
    ) -> Result<SessionInfo> {
        self.install(
            serde_json::json!({
                "nonce": nonce, "user": user, "device_key": device_key,
                "signature": signature, "stamp": stamp, "salt": salt,
            }),
            Some(device_key.to_vec()),
            Opening::Garden,
        )
        .await
    }
}
