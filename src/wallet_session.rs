//! Wallet session renewal by the wallet device key K (A13, secure convenience). The wallet
//! login carries K's proof of possession, so the wallet anchors the login's session family to
//! K; before the session's deadline the device signs a one-use server nonce with K and adopts a
//! NEW session of the same family (no token is ever extended). No passkey, no prompt. The
//! signer is the caller's: Foyer never holds K, only its signatures.
use crate::{Error, Foyer, Result, SessionInfo, SessionTransport};
use serde::Deserialize;
use serde_json::json;

/// A wallet session renews once it has at most this many seconds left (or has expired): the
/// window cvld accepts a renewal in (`auth::renew::RENEW_WINDOW_SECONDS`).
pub const RENEW_WINDOW_SECONDS: u64 = 300;

/// The original server's one-use renewal nonce.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    nonce: [u8; 32],
    issued: u64,
}

/// The 16 account bytes of a member id (a hyphenated UUID), as the wallet messages bind them.
fn account(user: &str) -> Result<[u8; 16]> {
    let hex: Vec<u8> = user.bytes().filter(|byte| *byte != b'-').collect();
    if user.len() != 36 || hex.len() != 32 {
        return Err(Error::Invalid);
    }
    let mut bytes = [0u8; 16];
    for (byte, pair) in bytes.iter_mut().zip(hex.chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| Error::Invalid)?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| Error::Invalid)?;
    }
    Ok(bytes)
}

/// The signed payload: the wallet message minus the tag ckmg prepends.
fn payload(message: &[u8]) -> &[u8] {
    &message[cvld_client::device_session::WALLET_SESSION_TAG.len()..]
}

impl<T: SessionTransport> Foyer<T> {
    /// Finish the wallet passkey login with K's proof of possession (M2): `sign` signs the
    /// payload of `cvld_client::device_session::wallet_login_message` for the wallet `host` and this
    /// ceremony. When K is the passkey's current binding, the session names its family and
    /// [`Foyer::renew_wallet_session`] keeps it alive without a prompt.
    pub async fn finish_wallet_login(
        &mut self,
        host: &str,
        ceremony: String,
        credential: cpky::PublicCredential,
        device_key: [u8; 32],
        sign: impl FnOnce(&[u8]) -> Option<[u8; 64]>,
    ) -> Result<SessionInfo> {
        let original_id = credential.credential_id().map_err(|__cause| {
            crate::cause::emit(file!(), line!(), "Error::Invalid", Error::Invalid, &__cause)
        })?;
        let message = cvld_client::device_session::wallet_login_message(host, &ceremony);
        let signature = sign(payload(&message)).ok_or(Error::Invalid)?;
        self.authenticate_pinned(
            json!({
                "ceremony": ceremony, "credential": credential.into_json(),
                "device_proof": {"device_key": device_key, "signature": signature.to_vec()},
            }),
            Some(original_id),
        )
        .await
    }

    /// The family this Foyer's retained wallet session may renew, if its login, device bind or
    /// renewal named one.
    pub async fn wallet_family(&self) -> Option<[u8; 32]> {
        let retained = self.shared.session.lock().await;
        retained.info.as_ref().and_then(|info| info.family)
    }

    /// Renew the retained wallet session by K once it has at most [`RENEW_WINDOW_SECONDS`] left
    /// (or has expired) on the WALLET's clock: the server's one-use nonce, K's signature (`sign`,
    /// over the payload of `cvld_client::device_session::wallet_message`), and the new session of
    /// the same family adopted in place, with the same passkey credential. The device clock
    /// (`now`) only schedules the ask, corrected by the wallet's offset from the last challenge;
    /// the challenge's own time decides, so a device clock ahead of the wallet's never spends a
    /// renewal the wallet refuses (A13 F1). `Ok(false)` when not due. No passkey: a session whose
    /// family is not anchored is `Unauthorized`, and so is a refused renewal (revoked K or
    /// passkey, rebinding, logout); `Unavailable` is transient.
    pub async fn renew_wallet_session(
        &mut self,
        host: &str,
        now: u64,
        device_key: [u8; 32],
        sign: impl FnOnce(&[u8]) -> Option<[u8; 64]>,
    ) -> Result<bool> {
        self.renew_wallet(host, now, device_key, sign, false).await
    }

    /// The wallet refused a call with the retained session: a device clock behind the wallet's
    /// lets the session expire before the device thinks it is due. Ask the wallet's clock
    /// (whatever the device clock says) and renew once if it is due there, as
    /// [`Foyer::renew_wallet_session`] does (A13 F1). `Ok(false)`: not due on the wallet's
    /// clock, so the refusal had another cause.
    pub async fn renew_wallet_session_after_refusal(
        &mut self,
        host: &str,
        now: u64,
        device_key: [u8; 32],
        sign: impl FnOnce(&[u8]) -> Option<[u8; 64]>,
    ) -> Result<bool> {
        self.renew_wallet(host, now, device_key, sign, true).await
    }

    async fn renew_wallet(
        &mut self,
        host: &str,
        now: u64,
        device_key: [u8; 32],
        sign: impl FnOnce(&[u8]) -> Option<[u8; 64]>,
        refused: bool,
    ) -> Result<bool> {
        let mut retained = self.shared.session.lock().await;
        let info = retained.info.clone().ok_or(Error::Unauthorized)?;
        let family = info.family.ok_or(Error::Unauthorized)?;
        if retained.device_session || not_member(&info.role) {
            return Err(Error::Unauthorized);
        }
        // The device's estimate of the wallet's clock schedules the ask; after a refusal the
        // wallet is always asked.
        let estimate = wallet_time(now, retained.wallet_clock);
        if !refused && info.expires > estimate.saturating_add(RENEW_WINDOW_SECONDS) {
            return Ok(false);
        }
        let account = account(&info.user)?;
        let challenge: Challenge = serde_json::from_value(
            retained
                .client
                .forward("wallet_session_begin", json!({}))
                .await?,
        )
        .map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Reconcile",
                Error::Reconcile,
                &__cause,
            )
        })?;
        // The wallet's clock decides; its offset schedules the next ask. Not due there: nothing
        // more is sent (the unused nonce lapses on its own) and the session stays.
        retained.wallet_clock = Some(clock_offset(challenge.issued, now));
        if info.expires > challenge.issued.saturating_add(RENEW_WINDOW_SECONDS) {
            return Ok(false);
        }
        let message = cvld_client::device_session::wallet_message(
            host,
            &account,
            &family,
            &challenge.nonce,
            challenge.issued,
        );
        let signature = sign(payload(&message)).ok_or(Error::Invalid)?;
        // Earlier session bindings end before the renewal can be sent, as at any install.
        retained.info = None;
        retained.authentication = retained
            .authentication
            .checked_add(1)
            .ok_or(Error::Unavailable)?;
        let renewed = match retained
            .client
            .renew_wallet(json!({
                "account": info.user, "family": family, "device_key": device_key,
                "nonce": challenge.nonce, "signature": signature.to_vec(),
            }))
            .await
        {
            Ok(renewed) => renewed,
            Err(error) => {
                // The transport adopted nothing: it still holds the current session.
                retained.info = Some(info);
                return Err(error);
            }
        };
        if renewed.user != info.user || renewed.role != info.role || renewed.family != Some(family)
        {
            return Err(Error::Reconcile);
        }
        retained.info = Some(renewed);
        Ok(true)
    }
}

/// Only a member's wallet session renews by K.
fn not_member(role: &str) -> bool {
    role != "member"
}

/// The wallet's clock minus the device's (`issued` is the wallet's time, `now` the device's).
fn clock_offset(issued: u64, now: u64) -> i64 {
    let offset = i128::from(issued) - i128::from(now);
    i64::try_from(offset).unwrap_or(if offset < 0 { i64::MIN } else { i64::MAX })
}

/// The device's estimate of the wallet's clock: `now` corrected by the last known offset.
fn wallet_time(now: u64, offset: Option<i64>) -> u64 {
    match offset {
        Some(offset) => now.checked_add_signed(offset).unwrap_or(if offset < 0 {
            0
        } else {
            u64::MAX
        }),
        None => now,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn the_account_bytes_are_the_member_uuid() {
        assert_eq!(
            account("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        assert!(account("00010203040506070809").is_err());
        assert!(account("0001020x-0405-0607-0809-0a0b0c0d0e0f").is_err());
    }

    #[test]
    fn the_wallet_clock_estimate_follows_the_last_offset_in_both_directions() {
        assert_eq!(wallet_time(1_000, None), 1_000);
        // Device 30 s ahead of the wallet, then 600 s behind.
        assert_eq!(clock_offset(970, 1_000), -30);
        assert_eq!(wallet_time(1_000, Some(clock_offset(970, 1_000))), 970);
        assert_eq!(clock_offset(1_600, 1_000), 600);
        assert_eq!(wallet_time(1_000, Some(600)), 1_600);
        // Out-of-range offsets saturate instead of wrapping.
        assert_eq!(clock_offset(u64::MAX, 0), i64::MAX);
        assert_eq!(clock_offset(0, u64::MAX), i64::MIN);
        assert_eq!(wallet_time(10, Some(-20)), 0);
        assert_eq!(wallet_time(u64::MAX - 1, Some(5)), u64::MAX);
    }
}
