//! Original first-key provenance under the retained authenticated certificate lease.
use super::*;

/// The original server's immutable first-key commitment, observed on this exact
/// live community session. It grants no Create, signing, Store or recovery access.
/// The composer must separately authenticate the matching encrypted candidate.
pub struct InitialCreationLease<'p, T> {
    certified: CertifiedMembershipLease<'p, T>,
    seed: [u8; 32],
    publication: Option<[u8; 32]>,
    checked_at: Option<u64>,
}

impl<'p, T: AuthenticatedTransport> CertifiedMembershipLease<'p, T> {
    /// Fetch the original initial-key provenance through the same held HTTPS
    /// client. Legacy and additional credentials retain the server's refusal.
    /// Neither caller-supplied JSON nor a certificate alone constructs the result.
    pub async fn initial_creation(
        mut self,
        mut clock: impl FnMut() -> u64,
    ) -> Result<InitialCreationLease<'p, T>> {
        let response = self
            .initial_request("initial_creation", serde_json::json!({}), false, &mut clock)
            .await?;
        let (seed, publication, checked_at) = projection(&response)?;
        let completed = self.check(&mut clock)?;
        if completed < checked_at || seed == [0; 32] || publication == Some([0; 32]) {
            return Err(Error::Unauthorized);
        }
        Ok(InitialCreationLease {
            certified: self,
            seed,
            publication,
            checked_at: Some(completed),
        })
    }

    async fn initial_request(
        &mut self,
        action: &'static str,
        body: serde_json::Value,
        mutation: bool,
        clock: &mut impl FnMut() -> u64,
    ) -> Result<serde_json::Value> {
        self.check(&mut *clock)?;
        let shared = self.lease.owner.upgrade().ok_or(Error::Unavailable)?;
        let (abort, registration) = AbortHandle::new_pair();
        {
            let mut lifetime = shared.lifetime.borrow_mut();
            if lifetime.closed
                || lifetime.generation != self.lease._pending.generation
                || lifetime.pending.is_none()
            {
                return Err(Error::Unavailable);
            }
            lifetime.pending = Some(abort);
        }
        let response = Abortable::new(self.lease.held.client.forward(action, body), registration)
            .await
            .map_err(|_| {
                if mutation {
                    Error::Reconcile
                } else {
                    Error::Unavailable
                }
            })??;
        self.check(&mut *clock)
            .map_err(|error| if mutation { Error::Reconcile } else { error })?;
        Ok(response)
    }
}

// Only projections of the genuinely generated owner schema, already checked by
// the original client. These values are never accepted from a public constructor.
fn projection(response: &serde_json::Value) -> Result<([u8; 32], Option<[u8; 32]>, u64)> {
    let seed = serde_json::from_value(response.get("seed").cloned().ok_or(Error::Reconcile)?)
        .map_err(|_| Error::Reconcile)?;
    let publication = serde_json::from_value(
        response
            .get("publication")
            .cloned()
            .ok_or(Error::Reconcile)?,
    )
    .map_err(|_| Error::Reconcile)?;
    let checked_at = response
        .get("checked_at")
        .and_then(serde_json::Value::as_u64)
        .ok_or(Error::Reconcile)?;
    Ok((seed, publication, checked_at))
}

impl<T> InitialCreationLease<'_, T> {
    /// Authentic original server commitment, not a root or accepted local state.
    pub fn seed(&self) -> Result<[u8; 32]> {
        self.checked_at.ok_or(Error::Unauthorized)?;
        Ok(self.seed)
    }
    /// Immutable original publication commitment, if the server accepted one.
    pub fn publication(&self) -> Result<Option<[u8; 32]>> {
        self.checked_at.ok_or(Error::Unauthorized)?;
        Ok(self.publication)
    }
    /// Original selected credential; the candidate owner must match its own key.
    pub fn credential_id(&self) -> Result<&[u8]> {
        self.checked_at.ok_or(Error::Unauthorized)?;
        self.certified.credential_id()
    }
    /// Fresh server/current-owner observation floor, not an invented timestamp.
    pub fn checked_at(&self) -> Result<u64> {
        self.checked_at.ok_or(Error::Unauthorized)
    }
    /// Original current certificate bytes. These never replace genesis evidence.
    pub fn certificate_bytes(&self) -> Result<&[u8]> {
        self.checked_at.ok_or(Error::Unauthorized)?;
        self.certified.certificate_bytes()
    }
    /// Same original member/device observation, without a remote-state freeze.
    pub fn observation(&self) -> Result<&Observation> {
        self.checked_at.ok_or(Error::Unauthorized)?;
        self.certified.observation()
    }
    /// Exclusive bound of the retained original session/certificate/publication.
    pub fn expires(&self) -> Result<u64> {
        self.checked_at.ok_or(Error::Unauthorized)?;
        self.certified.expires()
    }
    /// Fresh synchronous reborrow after awaits; any refusal consumes this lease's
    /// check state. A valid result is still not a Keys or publication grant.
    pub fn check(&mut self, mut clock: impl FnMut() -> u64) -> Result<u64> {
        let floor = self.checked_at.take().ok_or(Error::Unauthorized)?;
        let now = self.certified.check(&mut clock)?;
        if now < floor {
            return Err(Error::Unauthorized);
        }
        self.checked_at = Some(now);
        Ok(now)
    }

    /// Borrow this same current original Charter only inside a synchronous
    /// composition check. The lease rechecks its live owner before and after the
    /// callback; the callback cannot turn stored public evidence into authority.
    pub fn with_current<R>(
        &mut self,
        mut clock: impl FnMut() -> u64,
        inspect: impl FnOnce(&cnvy::cchr::VerifiedCharter) -> R,
    ) -> Result<R> {
        let now = self.check(&mut clock)?;
        self.checked_at = None;
        let result = self
            .certified
            .policy
            .with_current(now, inspect)
            .map_err(|_| Error::Unauthorized)?;
        self.checked_at = Some(now);
        self.check(&mut clock)?;
        Ok(result)
    }
}

impl<T: AuthenticatedTransport> InitialCreationLease<'_, T> {
    /// Bind exactly one original candidate's publication commitment using the
    /// server's same-key compare-and-set. Equal retries agree; a different winner
    /// refuses. Unknown completion consumes this attempt and requires a fresh
    /// authenticated query, never a replacement candidate or another Create.
    pub async fn bind_publication(
        mut self,
        publication: [u8; 32],
        mut clock: impl FnMut() -> u64,
    ) -> Result<Self> {
        if publication == [0; 32] || self.publication.is_some_and(|prior| prior != publication) {
            return Err(Error::Invalid);
        }
        self.check(&mut clock)?;
        let response = self
            .certified
            .initial_request(
                "initial_publication_bind",
                serde_json::json!({ "seed": self.seed, "publication": publication }),
                true,
                &mut clock,
            )
            .await?;
        let (seed, observed, checked_at) = projection(&response)?;
        let completed = self.check(&mut clock).map_err(|_| Error::Reconcile)?;
        if seed != self.seed || observed != Some(publication) || completed < checked_at {
            return Err(Error::Reconcile);
        }
        self.publication = observed;
        self.checked_at = Some(completed);
        Ok(self)
    }
}
