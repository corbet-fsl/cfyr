//! The wallet's confirmation-stamp exchange over the same retained global session as the
//! passport: reserve a stamp nonce, then submit exactly one request with the one user
//! verification of the wallet passkey over that request's confirmation challenge.
use super::passport::bytes;
use super::*;
use serde_json::{Value, json};

/// A reserved stamp nonce with the wallet's stamp key and its passkey request options. It
/// owns no holder: the caller durably begins the stamp in Wallet before submitting.
pub struct GlobalStampIssuance<T> {
    lease: GlobalWalletLease<T>,
    issuer: Vec<u8>,
    key: Vec<u8>,
    challenge: Vec<u8>,
    options: Value,
    submitted: bool,
}

impl<T: AuthenticatedTransport> GlobalWalletLease<T> {
    /// Reserve one stamp nonce through this retained wallet session. Never retried.
    pub async fn stamp_challenge(
        mut self,
        mut clock: impl FnMut() -> u64,
    ) -> Result<GlobalStampIssuance<T>> {
        let issuer = self.passport_current(&mut clock).await?;
        let reply = self
            .passport_call("stamp_challenge", json!({}), true, &mut clock)
            .await?;
        let challenge = bytes(&reply, "challenge")?;
        let key = bytes(&reply, "key")?;
        let options = reply.get("options").cloned().ok_or(Error::Reconcile)?;
        if self
            .passport_current(&mut clock)
            .await
            .map_err(|_| Error::Reconcile)?
            != issuer
        {
            return Err(Error::Reconcile);
        }
        Ok(GlobalStampIssuance {
            lease: self,
            issuer,
            key,
            challenge,
            options,
            submitted: false,
        })
    }
}

impl<T: AuthenticatedTransport> GlobalStampIssuance<T> {
    /// Exact HTTPS endpoint of the retained wallet transport (checked routing data).
    pub fn origin(&mut self, mut clock: impl FnMut() -> u64) -> Result<&str> {
        self.lease.check(&mut clock)?;
        Ok(&self.lease.origin)
    }

    /// Account, passkey credential, stamp key, nonce and passkey request options, checked
    /// against the same retained session. None of it is a signature or grant.
    pub fn with_current<R>(
        &mut self,
        mut clock: impl FnMut() -> u64,
        inspect: impl FnOnce(&str, &[u8], &[u8], &[u8], &Value) -> R,
    ) -> Result<R> {
        let now = self.lease.check(&mut clock)?;
        self.lease.checked_at = None;
        let result = inspect(
            &self.lease.user,
            &self.lease.credential,
            &self.key,
            &self.challenge,
            &self.options,
        );
        self.lease.checked_at = Some(now);
        self.lease.check(&mut clock)?;
        Ok(result)
    }

    /// Submit exactly one durable stamp request with its one passkey assertion. An unknown
    /// outcome consumes this continuation; the blind answer stays public bytes until Wallet
    /// verifies its signature.
    pub async fn issue(
        &mut self,
        request: Vec<u8>,
        assertion: Value,
        clock: impl FnMut() -> u64,
    ) -> Result<Vec<u8>> {
        self.submit(request, Some(assertion), clock).await
    }

    /// The account's first stamp during a one-ceremony registration (C5): submitted without
    /// a passkey assertion, under this session's birth grant. The wallet issues it at most
    /// once and only while no stamp was issued for the account; the stamp is byte-identical.
    pub async fn issue_birth(
        &mut self,
        request: Vec<u8>,
        clock: impl FnMut() -> u64,
    ) -> Result<Vec<u8>> {
        self.submit(request, None, clock).await
    }

    async fn submit(
        &mut self,
        request: Vec<u8>,
        assertion: Option<Value>,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Vec<u8>> {
        if self.submitted || request.is_empty() || request.len() > 1_048_576 {
            return Err(Error::Unauthorized);
        }
        self.submitted = true;
        let result = async {
            if self.lease.passport_current(&mut clock).await? != self.issuer {
                return Err(Error::Unauthorized);
            }
            let mut body = json!({"challenge":self.challenge,"request":request});
            if let Some(assertion) = assertion {
                body["assertion"] = assertion;
            }
            let response = self
                .lease
                .passport_call("stamp_issue", body, true, &mut clock)
                .await?;
            let answer = bytes(&response, "bytes")?;
            if self
                .lease
                .passport_current(&mut clock)
                .await
                .map_err(|_| Error::Reconcile)?
                != self.issuer
            {
                return Err(Error::Reconcile);
            }
            Ok(answer)
        }
        .await;
        if result.is_err() {
            self.lease.checked_at = None;
        }
        result
    }
}
