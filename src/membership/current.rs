//! Borrow the actual held community session and its same-owner Charter.
use super::*;
use crate::policy::CurrentPolicy;
use cvld_client::client::AuthenticatedTransport;

pub(super) fn check_community<T>(
    lease: &mut MembershipLease<T>,
    policy: &mut CurrentPolicy<T>,
    origin: &str,
    credential: &[u8],
    clock: &mut impl FnMut() -> u64,
) -> Result<u64> {
    let checked = lease.check(clock)?;
    lease.checked_at = None;
    if !matches!(lease.scope, ObservationScope::Community)
        || credential.is_empty()
        || lease.held.login_credential.as_deref() != Some(credential)
    {
        return Err(Error::Unauthorized);
    }
    policy.check_origin(&lease.owner, origin)?;
    policy
        .with_current(checked, |current| {
            if current.community() == "wallet" {
                Err(Error::Unauthorized)
            } else {
                Ok(())
            }
        })
        .map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })??;
    lease.checked_at = Some(checked);
    Ok(checked)
}

pub(super) fn with_checked_community<T, R>(
    lease: &mut MembershipLease<T>,
    policy: &mut CurrentPolicy<T>,
    origin: &str,
    credential: &[u8],
    mut clock: impl FnMut() -> u64,
    inspect: impl FnOnce(&cnvy::cchr::VerifiedCharter, &Observation, &[u8], &str, u64) -> R,
) -> Result<(R, u64)> {
    let checked = check_community(lease, policy, origin, credential, &mut clock)?;
    lease.checked_at = None;
    let output = policy
        .with_current(checked, |current| {
            inspect(current, &lease.observation, credential, origin, checked)
        })
        .map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })?;
    lease.checked_at = Some(checked);
    let completed = check_community(lease, policy, origin, credential, &mut clock)?;
    Ok((output, completed))
}

impl<T: AuthenticatedTransport> MembershipLease<T> {
    /// Inspect the original held community session and same-owner current
    /// Charter. The original client supplies HTTPS origin and typed login ID;
    /// no caller identity, client, guard or authority constructor is accepted.
    /// This performs no new remote read. The callback supplies no permission by
    /// itself; an outer owner must verify its actual records and purpose.
    /// Refusal, rollback, expiry, disposal or callback unwind is terminal.
    pub fn with_community_policy<R>(
        &mut self,
        policy: &mut CurrentPolicy<T>,
        mut clock: impl FnMut() -> u64,
        inspect: impl FnOnce(&cnvy::cchr::VerifiedCharter, &Observation, &[u8], &str, u64) -> R,
    ) -> Result<(R, u64)> {
        let checked = self.check(&mut clock)?;
        self.checked_at = None;
        let origin = self.held.client.authenticated_origin()?;
        let credential = self
            .held
            .login_credential
            .clone()
            .ok_or(Error::Unauthorized)?;
        policy.check_origin(&self.owner, &origin)?;
        self.checked_at = Some(checked);
        with_checked_community(self, policy, &origin, &credential, clock, inspect)
    }
}
