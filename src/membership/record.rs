//! Same original member/policy owner around the fixed anonymous binary resource.
use super::*;
use crate::policy::CurrentPolicy;
use cvld::client::AuthenticatedTransport;

/// A held original community session and its actual current Charter. This owns
/// no account, Epoch or recipient key. The outer account owner must authenticate
/// the original descriptor/period and verify the complete downloaded object.
pub struct CommonRecordLease<'p, T> {
    lease: MembershipLease<T>,
    policy: &'p mut CurrentPolicy<T>,
    origin: String,
    credential: Vec<u8>,
    available: bool,
}

impl<T: AuthenticatedTransport> MembershipLease<T> {
    /// Retain the same actual HTTPS/current-policy owner for common reception.
    /// Wallet/global observations cannot supply a community record capability.
    pub fn common_record<'p>(
        mut self,
        policy: &'p mut CurrentPolicy<T>,
        mut clock: impl FnMut() -> u64,
    ) -> Result<CommonRecordLease<'p, T>> {
        if !matches!(self.scope, ObservationScope::Community) {
            return Err(Error::Unauthorized);
        }
        self.check(&mut clock)?;
        let credential = self
            .held
            .login_credential
            .clone()
            .filter(|id| !id.is_empty())
            .ok_or(Error::Unauthorized)?;
        let origin = self.held.client.authenticated_origin()?;
        policy.check_origin(&self.owner, &origin)?;
        let mut result = CommonRecordLease {
            lease: self,
            policy,
            origin,
            credential,
            available: true,
        };
        result.check(&mut clock)?;
        Ok(result)
    }
}

impl<T> CommonRecordLease<'_, T> {
    fn check(&mut self, clock: &mut impl FnMut() -> u64) -> Result<u64> {
        if !self.available {
            return Err(Error::Unauthorized);
        }
        self.available = false;
        let checked = current::check_community(
            &mut self.lease,
            self.policy,
            &self.origin,
            &self.credential,
            clock,
        )?;
        self.available = true;
        Ok(checked)
    }

    /// Reborrow the original current signed publications and actual member only.
    /// A callback cannot receive the client, bearer, guard or a policy constructor.
    pub fn with_current<R>(
        &mut self,
        clock: impl FnMut() -> u64,
        inspect: impl FnOnce(&cnvy::cchr::VerifiedCharter, &Observation, &[u8], &str, u64) -> R,
    ) -> Result<R> {
        self.with_current_checked(clock, inspect)
            .map(|(output, _)| output)
    }

    /// Return the final synchronous held-owner completion sample with the
    /// callback output. This is no new remote HTTPS observation or authority;
    /// the consumer checks its original object lifetime at this exact sample.
    pub fn with_current_checked<R>(
        &mut self,
        mut clock: impl FnMut() -> u64,
        inspect: impl FnOnce(&cnvy::cchr::VerifiedCharter, &Observation, &[u8], &str, u64) -> R,
    ) -> Result<(R, u64)> {
        if !self.available {
            return Err(Error::Unauthorized);
        }
        self.available = false;
        let output = current::with_checked_community(
            &mut self.lease,
            self.policy,
            &self.origin,
            &self.credential,
            &mut clock,
            inspect,
        )?;
        self.available = true;
        Ok(output)
    }
}

impl<T: AuthenticatedTransport> CommonRecordLease<'_, T> {
    async fn refresh_key(&mut self, clock: &mut impl FnMut() -> u64) -> Result<()> {
        let started = self.lease.check(&mut *clock)?;
        self.lease.checked_at = None;
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
        let rows = Abortable::new(
            self.lease
                .held
                .client
                .forward("lobby", serde_json::json!({})),
            registration,
        )
        .await
        .map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Unavailable",
                Error::Unavailable,
                &__cause,
            )
        })??;
        let completed = clock();
        if completed < started || completed >= self.lease.observation.expires || shared.is_closed()
        {
            return Err(Error::Unauthorized);
        }
        // `lobby` is a Member read that device-key and passkey sessions may both make; the
        // server answers 401 for an expired lease or a revoked device. The retained login
        // credential is joined to the lease by `check`, so the probe only needs to show that
        // the same member is still served.
        let member = rows
            .get("member_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Reconcile)?;
        if member != self.lease.observation.member {
            return Err(Error::Unauthorized);
        }
        self.lease.checked_at = Some(completed);
        self.lease.check(clock)?;
        Ok(())
    }
    /// Fetch the complete fixed anonymous object. The outer caller derives this
    /// exact bounded length from its current signed Epoch, never a leaf selector.
    /// Cancellation/refusal permanently consumes this live attempt; no transport
    /// success creates an account or authenticates the returned packet.
    pub async fn download(
        &mut self,
        expected_length: usize,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Vec<u8>> {
        self.check(&mut clock)?;
        self.available = false;
        self.lease.refresh_observation(&mut clock).await?;
        self.refresh_key(&mut clock).await?;
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
        let bytes = Abortable::new(
            self.lease
                .held
                .client
                .account_record_object(expected_length),
            registration,
        )
        .await
        .map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Unavailable",
                Error::Unavailable,
                &__cause,
            )
        })??;
        self.lease.refresh_observation(&mut clock).await?;
        self.refresh_key(&mut clock).await?;
        self.available = true;
        self.check(&mut clock)?;
        Ok(bytes)
    }
}
