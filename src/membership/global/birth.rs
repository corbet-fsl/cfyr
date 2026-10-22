//! One-ceremony registration (C3, C4) over the retained wallet session that holds the birth
//! grant: the account's first wallet device bind by that device's own signature, and the
//! wallet-signed birth statement for the device-signed wallet genesis receipt. The server
//! decides the birth grant; this owner only forwards over the same retained session.
use super::passport::bytes;
use super::*;
use serde_json::{Value, json};

/// The wallet-signed `BirthStatement` (COSE bytes) and its time `at`, exactly as
/// `cchr::BirthGenesisEvidence` carries them. Public bytes, never authority: the device
/// verifies them with `cchr::verify_birth_genesis` before relying on them.
pub struct WalletBirthStatement {
    statement: Vec<u8>,
    at: u64,
}
impl WalletBirthStatement {
    /// The signed statement bytes.
    pub fn statement(&self) -> &[u8] {
        &self.statement
    }
    /// The statement time the verification is judged at.
    pub fn at(&self) -> u64 {
        self.at
    }
    /// The statement bytes and time.
    pub fn into_parts(self) -> (Vec<u8>, u64) {
        (self.statement, self.at)
    }
}
impl std::fmt::Debug for WalletBirthStatement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WalletBirthStatement([redacted])")
    }
}

impl<T: AuthenticatedTransport> GlobalWalletLease<T> {
    /// Bind the account's first wallet device `key` (C3) by `signature`, the device key's
    /// own signature (purpose `WalletBirthDevice`) over the wallet origin, account, this
    /// session's credential, the registration's seed commitment and `key`. Accepted only
    /// under the birth grant of this session; a failed or unknown outcome is never retried
    /// here.
    pub async fn authorize_birth_device(
        &mut self,
        key: [u8; 32],
        signature: [u8; 64],
        mut clock: impl FnMut() -> u64,
    ) -> Result<()> {
        if key == [0; 32] {
            return Err(Error::Invalid);
        }
        self.passport_call(
            "wallet_device_authorize",
            json!({"key":key,"birth_signature":signature.to_vec()}),
            true,
            &mut clock,
        )
        .await?;
        Ok(())
    }

    /// The account's one wallet-signed birth statement (C4) for the wallet genesis receipt
    /// whose passkey challenge digest is `digest`. The same digest returns the same
    /// statement; another one is refused by the wallet.
    pub async fn birth_genesis(
        &mut self,
        digest: [u8; 32],
        mut clock: impl FnMut() -> u64,
    ) -> Result<WalletBirthStatement> {
        let reply = self
            .passport_call(
                "wallet_birth_genesis",
                json!({ "digest": digest }),
                true,
                &mut clock,
            )
            .await?;
        let statement = bytes(&reply, "statement")?;
        let at = reply
            .get("at")
            .and_then(Value::as_u64)
            .ok_or(Error::Reconcile)?;
        Ok(WalletBirthStatement { statement, at })
    }
}
