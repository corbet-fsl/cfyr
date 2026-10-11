//! Global wallet session observation; no community or Keys authority.
use super::*;
use cvld::client::AuthenticatedTransport;
mod passport;
pub use passport::GlobalPassportIssuance;

/// Weak read port for the trusted runtime's global-wallet HTTPS origin. Public
/// request JSON cannot select this origin or supply an authenticated account.
pub struct LiveGlobalWallet<T> {
    owner: Weak<Shared<T>>,
    origin: String,
}

/// A fresh global-host/current-passkey observation retaining the original local
/// session. This is neither a community pseudonym nor Create/Use permission.
/// The lock freezes local login replacement only; it does not freeze revocation
/// on the server. A later operation needs its own fresh original-owner checks.
pub struct GlobalWalletLease<T> {
    owner: Weak<Shared<T>>,
    held: OwnedMutexGuard<Retained<T>>,
    authentication: u64,
    user: String,
    credential: Vec<u8>,
    expires: u64,
    origin: String,
    checked_at: Option<u64>,
    _pending: Pending<T>,
}

impl<T> Foyer<T> {
    /// Compose a weak global-wallet read port from the trusted runtime's exact
    /// configured HTTPS origin. This does not authenticate or accept a bearer.
    pub fn live_global_wallet(&self, trusted_origin: String) -> LiveGlobalWallet<T> {
        LiveGlobalWallet {
            owner: Rc::downgrade(&self.shared),
            origin: trusted_origin,
        }
    }
}

impl<T: AuthenticatedTransport> LiveGlobalWallet<T> {
    /// Read the actual global endpoint and the exact current credential through
    /// this Foyer's sealed original transport. Generic JSON login has no retained
    /// Passkeys credential and cannot qualify. Cancellation drops both the real
    /// request and the original session guard; owner close aborts the waiter.
    pub async fn observe_lease(
        &mut self,
        mut clock: impl FnMut() -> u64,
    ) -> Result<GlobalWalletLease<T>> {
        let shared = self.owner.upgrade().ok_or(Error::Unavailable)?;
        let (pending, registration) = shared.begin_pending()?;
        let started = clock();
        let (held, authentication, user, credential, expires, completed) = Abortable::new(
            async {
                let mut held = shared.session.clone().lock_owned().await;
                if held.client.authenticated_origin()? != self.origin {
                    return Err(Error::Unauthorized);
                }
                let info = held.info.as_ref().ok_or(Error::Unauthorized)?;
                let expires = info.expires;
                let user = info.user.clone();
                let credential = held
                    .login_credential
                    .as_ref()
                    .filter(|id| !id.is_empty())
                    .ok_or(Error::Unauthorized)?
                    .clone();
                let authentication = held.authentication;
                let sending = clock();
                if info.role != "member"
                    || sending < started
                    || sending >= expires
                    || shared.is_closed()
                {
                    return Err(Error::Unauthorized);
                }
                // A community's passkey_list has the same shape. Only the
                // genuine global endpoint on this same pinned origin qualifies.
                held.client
                    .forward("global_public", serde_json::json!({}))
                    .await?;
                let global_checked = clock();
                if global_checked < sending || global_checked >= expires || shared.is_closed() {
                    return Err(Error::Unauthorized);
                }
                let response = held
                    .client
                    .forward("passkey_list", serde_json::json!({}))
                    .await?;
                let completed = clock();
                if completed < global_checked || completed >= expires || shared.is_closed() {
                    return Err(Error::Unauthorized);
                }
                // Original generated response schema was checked by Client.
                // `current` comes from the server's actual authenticated grant.
                let rows = response
                    .get("passkeys")
                    .and_then(serde_json::Value::as_array)
                    .ok_or(Error::Reconcile)?;
                let mut current = rows.iter().filter(|row| row["current"] == true);
                let row = current.next().ok_or(Error::Unauthorized)?;
                if current.next().is_some() || row["revoked"] != false {
                    return Err(Error::Unauthorized);
                }
                let actual: Vec<u8> = serde_json::from_value(row["credential"].clone())
                    .map_err(|_| Error::Reconcile)?;
                if actual != credential {
                    return Err(Error::Unauthorized);
                }
                Ok((held, authentication, user, credential, expires, completed))
            },
            registration,
        )
        .await
        .map_err(|_| Error::Unavailable)??;
        Ok(GlobalWalletLease {
            owner: Rc::downgrade(&shared),
            held,
            authentication,
            user,
            credential,
            expires,
            origin: self.origin.clone(),
            checked_at: Some(completed),
            _pending: pending,
        })
    }
}

impl<T: AuthenticatedTransport> GlobalWalletLease<T> {
    pub(super) async fn bind_initial(
        &mut self,
        seed: [u8; 32],
        publication: [u8; 32],
        clock: &mut impl FnMut() -> u64,
    ) -> Result<()> {
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
        let completed = Abortable::new(
            async {
                self.held
                    .client
                    .forward("global_public", serde_json::json!({}))
                    .await?;
                let observed = clock();
                if shared.is_closed() || observed < started || observed >= self.expires {
                    return Err(Error::Unauthorized);
                }
                let response = self
                    .held
                    .client
                    .forward(
                        "initial_publication_bind",
                        serde_json::json!({"seed":seed,"publication":publication}),
                    )
                    .await
                    .map_err(|_| Error::Reconcile)?;
                let completed = clock();
                let actual: super::global_initial::InitialResponse =
                    serde_json::from_value(response).map_err(|_| Error::Reconcile)?;
                if actual.seed != seed
                    || actual.publication != Some(publication)
                    || actual.checked_at < started
                    || completed < observed.max(actual.checked_at)
                    || completed >= self.expires
                    || shared.is_closed()
                {
                    return Err(Error::Reconcile);
                }
                Ok(completed)
            },
            registration,
        )
        .await
        .map_err(|_| Error::Reconcile)??;
        self.checked_at = Some(completed);
        self.check(&mut *clock).map_err(|_| Error::Reconcile)?;
        Ok(())
    }

    /// Exact original global account ID. It is public session metadata, never
    /// community membership, a pseudonym, a certificate or a custody verdict.
    pub fn user(&self) -> Result<&str> {
        self.checked_at.ok_or(Error::Unauthorized)?;
        Ok(&self.user)
    }

    /// Exact public credential joined to the typed successful login and the
    /// fresh server-derived current row. This read grants no signing authority.
    pub fn credential_id(&self) -> Result<&[u8]> {
        self.checked_at.ok_or(Error::Unauthorized)?;
        Ok(&self.credential)
    }

    /// Original exclusive session deadline, never renewed by these observations.
    pub fn expires(&self) -> Result<u64> {
        self.checked_at.ok_or(Error::Unauthorized)?;
        Ok(self.expires)
    }

    /// Inspect this exact retained local session synchronously after an await.
    /// Refusal is terminal. No second lock, cached remote policy, or inferred
    /// server revocation status authorizes a later operation through this check.
    pub fn check(&mut self, mut clock: impl FnMut() -> u64) -> Result<u64> {
        let floor = self.checked_at.take().ok_or(Error::Unauthorized)?;
        let now = clock();
        let owner = self.owner.upgrade().ok_or(Error::Unavailable)?;
        let info = self.held.info.as_ref().ok_or(Error::Unauthorized)?;
        if owner.is_closed()
            || now < floor
            || now >= self.expires
            || info.role != "member"
            || info.user != self.user
            || info.expires != self.expires
            || self.held.authentication != self.authentication
            || self.held.login_credential.as_deref() != Some(self.credential.as_slice())
            || self.held.client.authenticated_origin()? != self.origin
        {
            return Err(Error::Unauthorized);
        }
        self.checked_at = Some(now);
        Ok(now)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../tests/cases/global_wallet.rs"]
mod tests;
