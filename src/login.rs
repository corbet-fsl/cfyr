//! Public browser sign-in forwarding. Passkeys and its opaque custody result
//! stay with the composing device owner; Foyer receives only public assertions.
use crate::{Error, Foyer, Result, SessionInfo, SessionTransport, Transport};
use serde::Deserialize;

/// The original server's public discoverable challenge. No callback capability,
/// authenticator output, PRF or local vault state belongs in this value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    /// Original one-use server ceremony identifier.
    pub ceremony: String,
    /// Original public WebAuthn options, passed unchanged to Passkeys.
    pub options: serde_json::Value,
}

impl<T: Transport> Foyer<T> {
    /// Fetch the original discoverable request. The composing device owner
    /// binds its trusted RP/origin and runs the actual Passkeys ceremony.
    pub async fn begin_browser_login(&mut self) -> Result<Challenge> {
        let value = self
            .call("login_discoverable_begin", serde_json::json!({}))
            .await?;
        serde_json::from_value(value).map_err(|_| Error::Reconcile)
    }
}

impl<T: SessionTransport> Foyer<T> {
    /// Verify only the public assertion with the original server and retain its
    /// bearer solely in the original transport. The caller fences cancellation
    /// while this mutation is outstanding and must not retry unknown effects.
    pub async fn finish_browser_login(
        &mut self,
        ceremony: String,
        credential: cpky::PublicCredential,
    ) -> Result<SessionInfo> {
        let original_id = credential.credential_id().map_err(|_| Error::Invalid)?;
        self.authenticate_pinned(
            serde_json::json!({
                "ceremony": ceremony, "credential": credential.into_json(),
            }),
            Some(original_id),
        )
        .await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../tests/cases/login.rs"]
mod tests;
