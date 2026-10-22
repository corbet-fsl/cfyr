//! The original global issuer exchange over one retained same-key HTTPS client.
use super::*;
use serde_json::{Value, json};

/// Actual issuer/challenge continuation. It owns neither a holder nor Keys
/// authority. The caller must durably prepare the original holder opening before
/// sending its request and signature-verify the returned blind answer in Wallet.
pub struct GlobalPassportIssuance<T> {
    lease: GlobalWalletLease<T>,
    issuer: Vec<u8>,
    challenge: Vec<u8>,
    submitted: bool,
}

pub(super) fn bytes(value: &Value, field: &str) -> Result<Vec<u8>> {
    let result: Vec<u8> =
        serde_json::from_value(value.get(field).cloned().ok_or(Error::Reconcile)?)
            .map_err(|_| Error::Reconcile)?;
    if result.is_empty() || result.len() > 1_048_576 {
        return Err(Error::Reconcile);
    }
    Ok(result)
}

impl<T: AuthenticatedTransport> GlobalWalletLease<T> {
    // Fixed original endpoints only. Every await is bracketed by this same
    // retained identity, exclusive deadline and monotonic observation. Calling
    // this through the Foyer that already holds a creation lease refuses in
    // Shared::begin_pending before it can wait on that same session mutex.
    pub(super) async fn passport_call(
        &mut self,
        action: &'static str,
        input: Value,
        mutation: bool,
        clock: &mut impl FnMut() -> u64,
    ) -> Result<Value> {
        let started = self.check(&mut *clock)?;
        self.checked_at = None;
        let shared = self.owner.upgrade().ok_or(Error::Unavailable)?;
        let (abort, registration) = AbortHandle::new_pair();
        {
            let mut lifetime = shared.lifetime.borrow_mut();
            if lifetime.closed
                || lifetime.generation != self._pending.generation
                || lifetime.pending.is_none()
            {
                return Err(Error::Unavailable);
            }
            lifetime.pending = Some(abort);
        }
        let response = Abortable::new(self.held.client.forward(action, input), registration)
            .await
            .map_err(|_| {
                if mutation {
                    Error::Reconcile
                } else {
                    Error::Unavailable
                }
            })?
            .map_err(|error| if mutation { Error::Reconcile } else { error })?;
        let completed = clock();
        if completed < started || completed >= self.expires || shared.is_closed() {
            return Err(if mutation {
                Error::Reconcile
            } else {
                Error::Unauthorized
            });
        }
        self.checked_at = Some(completed);
        self.check(clock)
            .map_err(|error| if mutation { Error::Reconcile } else { error })?;
        Ok(response)
    }

    pub(super) async fn passport_current(&mut self, clock: &mut impl FnMut() -> u64) -> Result<Vec<u8>> {
        let public = self
            .passport_call("global_public", json!({}), false, clock)
            .await?;
        let rows = self
            .passport_call("passkey_list", json!({}), false, clock)
            .await?;
        let rows = rows
            .get("passkeys")
            .and_then(Value::as_array)
            .ok_or(Error::Reconcile)?;
        let mut selected = rows.iter().filter(|row| row["current"] == true);
        let row = selected.next().ok_or(Error::Unauthorized)?;
        if selected.next().is_some()
            || row["revoked"] != false
            || bytes(row, "credential")? != self.credential
        {
            self.checked_at = None;
            return Err(Error::Unauthorized);
        }
        bytes(&public, "issuer")
    }

    /// Reserve an original challenge only through this actual retained global
    /// issuer session. A failed or canceled Record call is never retried by this
    /// continuation. This observation grants no Create/Use or root operation.
    pub async fn passport_challenge(
        mut self,
        mut clock: impl FnMut() -> u64,
    ) -> Result<GlobalPassportIssuance<T>> {
        let issuer = self.passport_current(&mut clock).await?;
        let reply = self
            .passport_call("passport_challenge", json!({}), true, &mut clock)
            .await?;
        let challenge = bytes(&reply, "bytes")?;
        if self
            .passport_current(&mut clock)
            .await
            .map_err(|_| Error::Reconcile)?
            != issuer
        {
            return Err(Error::Reconcile);
        }
        Ok(GlobalPassportIssuance {
            lease: self,
            issuer,
            challenge,
            submitted: false,
        })
    }
}

impl<T: AuthenticatedTransport> GlobalPassportIssuance<T> {
    /// Exact HTTPS endpoint of the original retained authenticated transport.
    /// This is checked routing data, never a caller-selected issuer authority.
    pub fn origin(&mut self, mut clock: impl FnMut() -> u64) -> Result<&str> {
        self.lease.check(&mut clock)?;
        Ok(&self.lease.origin)
    }

    /// Original public account/key/issuer/challenge data, checked against the
    /// same retained session. This is not an issuer signature or Wallet grant.
    pub fn with_current<R>(
        &mut self,
        mut clock: impl FnMut() -> u64,
        inspect: impl FnOnce(&str, &[u8], &[u8], &[u8], u64) -> R,
    ) -> Result<R> {
        let now = self.lease.check(&mut clock)?;
        self.lease.checked_at = None;
        let result = inspect(
            &self.lease.user,
            &self.lease.credential,
            &self.issuer,
            &self.challenge,
            now,
        );
        self.lease.checked_at = Some(now);
        self.lease.check(&mut clock)?;
        Ok(result)
    }

    /// Submit exactly one original durable holder request. Unknown outcomes
    /// consume this continuation, never replay the issuer's mutation. The blind
    /// answer remains public bytes until original Wallet signature verification.
    pub async fn issue(&mut self, request: Vec<u8>, clock: impl FnMut() -> u64) -> Result<Vec<u8>> {
        self.submit(request, None, clock).await
    }

    /// The birth passport (Q5) during a one-ceremony registration: `signature` is the bound
    /// birth device key's signature (purpose `WalletBirthPassport`) over the hash of this
    /// exact `request`. Accepted only under this session's birth grant, at most once.
    pub async fn issue_birth(
        &mut self,
        request: Vec<u8>,
        signature: [u8; 64],
        clock: impl FnMut() -> u64,
    ) -> Result<Vec<u8>> {
        self.submit(request, Some(signature), clock).await
    }

    async fn submit(
        &mut self,
        request: Vec<u8>,
        birth_signature: Option<[u8; 64]>,
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
            if let Some(signature) = birth_signature {
                body["birth_signature"] = json!(signature.to_vec());
            }
            let response = self
                .lease
                .passport_call("passport_issue", body, true, &mut clock)
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
