//! Fresh original server certificate under one held Foyer session and policy.
use super::*;
use crate::{policy::CurrentPolicy, registration::RegisteredSession};
use cvld::client::AuthenticatedTransport;

mod initial_creation;
pub use initial_creation::InitialCreationLease;

struct CheckedCertificate {
    credential: Vec<u8>,
    server_checked_at: u64,
    last_checked: u64,
    expires: u64,
}

/// One actual certificate response, retaining the exact original local session.
/// It is not ordinary Keys permission, a lineage observation or remote freeze.
/// No response JSON, supplied certificate or caller timestamp constructs it.
pub struct CertifiedMembershipLease<'p, T> {
    lease: MembershipLease<T>,
    policy: HeldPolicy<'p, T>,
    signed: Vec<u8>,
    origin: String,
    checked: Option<CheckedCertificate>,
    /// A device-key session: the credential is the session's own device key and no passkey
    /// certificate exists (`signed` is empty).
    device: bool,
}

/// The same original registered key joined to its exact next successful session.
/// This consumes registration provenance; it grants no Keys or publication API.
pub struct RegisteredCertificateLease<'p, T> {
    certified: CertifiedMembershipLease<'p, T>,
    registration: RegisteredSession<T>,
}

/// The current policy a certified lease checks against: lent by the caller for `'p`, or owned
/// by the lease (and dropped with it). Ownership changes nothing about the checks; it lets a
/// long-lived holder keep the lease without leaking a `&'static mut` policy.
pub enum HeldPolicy<'p, T> {
    Borrowed(&'p mut CurrentPolicy<T>),
    Owned(Box<CurrentPolicy<T>>),
}

impl<'p, T> From<&'p mut CurrentPolicy<T>> for HeldPolicy<'p, T> {
    fn from(policy: &'p mut CurrentPolicy<T>) -> Self {
        Self::Borrowed(policy)
    }
}

impl<T> From<CurrentPolicy<T>> for HeldPolicy<'static, T> {
    fn from(policy: CurrentPolicy<T>) -> Self {
        Self::Owned(Box::new(policy))
    }
}

impl<T> std::ops::Deref for HeldPolicy<'_, T> {
    type Target = CurrentPolicy<T>;
    fn deref(&self) -> &CurrentPolicy<T> {
        match self {
            Self::Borrowed(policy) => policy,
            Self::Owned(policy) => policy,
        }
    }
}

impl<T> std::ops::DerefMut for HeldPolicy<'_, T> {
    fn deref_mut(&mut self) -> &mut CurrentPolicy<T> {
        match self {
            Self::Borrowed(policy) => policy,
            Self::Owned(policy) => policy,
        }
    }
}

impl<T: AuthenticatedTransport> MembershipLease<T> {
    /// Consume this local lease and fetch only through its held original client.
    /// Missing owner-generated action/response metadata refuses before sealing.
    /// Cancellation drops the held session guard; owner closure aborts this call.
    pub async fn passkey_certificate<'p>(
        mut self,
        policy: impl Into<HeldPolicy<'p, T>>,
        mut clock: impl FnMut() -> u64,
    ) -> Result<CertifiedMembershipLease<'p, T>>
    where
        T: 'p,
    {
        let mut policy = policy.into();
        // This bound is sealed by CVLD to its actual native/browser clients.
        // HTTPS and this instance's retained origin are checked by that owner;
        // schema-valid replies from arbitrary Transport implementations cannot
        // serve as fresh authenticated server clock observations.
        let origin = self.held.client.authenticated_origin()?;
        policy.check_origin(&self.owner, &origin)?;
        let started = self.check(&mut clock)?;
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
            // Preserve this actual attempt's generation while replacing its
            // completed observation waiter with the new certificate waiter.
            lifetime.pending = Some(abort);
        }
        let response = Abortable::new(
            self.held
                .client
                .forward("passkey_certificate", serde_json::json!({})),
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
        // The original client already validated the owner's generated schema.
        // These are private field projections, never a second response contract.
        let signed: Vec<u8> =
            serde_json::from_value(response.get("bytes").cloned().ok_or(Error::Reconcile)?)
                .map_err(|__cause| {
                    crate::cause::emit(
                        file!(),
                        line!(),
                        "Error::Reconcile",
                        Error::Reconcile,
                        &__cause,
                    )
                })?;
        let server_checked_at = response
            .get("checked_at")
            .and_then(serde_json::Value::as_u64)
            .ok_or(Error::Reconcile)?;
        let completed = self.check(&mut clock)?;
        if completed < started || completed < server_checked_at {
            return Err(Error::Unauthorized);
        }
        policy.check_origin(&self.owner, &origin)?;
        let (credential, expires) = policy
            .with_current(completed, |current| {
                if matches!(self.scope, ObservationScope::Wallet) && current.community() != "wallet"
                {
                    return Err(cnvy::cchr::Error::Unauthenticated);
                }
                let certificate =
                    current.passkey_certificate(&signed, &self.observation.member, completed)?;
                Ok::<_, cnvy::cchr::Error>((
                    certificate.credential_id(completed)?.to_vec(),
                    certificate.valid_until(),
                ))
            })
            .map_err(|__cause| {
                crate::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })?
            .map_err(|__cause| {
                crate::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })?;
        let expires = expires.min(self.observation.expires);
        if completed >= expires || self.credential.as_ref().is_some_and(|id| id != &credential) {
            return Err(Error::Unauthorized);
        }
        Ok(CertifiedMembershipLease {
            lease: self,
            policy,
            signed,
            origin,
            checked: Some(CheckedCertificate {
                credential,
                server_checked_at,
                last_checked: completed,
                expires,
            }),
            device: false,
        })
    }

    /// The initial-creation provenance of a DEVICE-KEY member (one-confirmation model): the
    /// same held original session and Charter, with the session's own device key in place of
    /// a passkey certificate. The key must be the held session's login credential and among
    /// the member's live device keys at every check; the server answers from the commitment
    /// stored with the member's first device key at the stamped join. A passkey session,
    /// a wallet observation or a key no longer live refuses.
    pub async fn device_initial_creation<'p>(
        self,
        policy: impl Into<HeldPolicy<'p, T>>,
        mut clock: impl FnMut() -> u64,
    ) -> Result<InitialCreationLease<'p, T>>
    where
        T: 'p,
    {
        let mut policy = policy.into();
        let origin = self.held.client.authenticated_origin()?;
        policy.check_origin(&self.owner, &origin)?;
        let mut lease = self;
        let completed = lease.check(&mut clock)?;
        let key = lease
            .held
            .login_credential
            .clone()
            .filter(|key| lease.held.device_session && key.len() == 32)
            .ok_or(Error::Unauthorized)?;
        let expires = lease.observation.expires;
        let mut certified = CertifiedMembershipLease {
            lease,
            policy,
            signed: Vec::new(),
            origin,
            checked: Some(CheckedCertificate {
                credential: key,
                server_checked_at: completed,
                last_checked: completed,
                expires,
            }),
            device: true,
        };
        certified.check(&mut clock)?;
        certified.initial_creation(clock).await
    }
}

impl<T: AuthenticatedTransport> CertifiedMembershipLease<'_, T> {
    async fn refresh_observation(&mut self, clock: &mut impl FnMut() -> u64) -> Result<u64> {
        self.check(&mut *clock)?;
        let checked = self.checked.take().ok_or(Error::Unauthorized)?;
        self.lease.refresh_observation(clock).await?;
        self.checked = Some(checked);
        // Verify the same genuine certificate under this owner's current Charter
        // after the fresh membership reads. Its exclusive lifetime never renews.
        self.check(clock)
    }
}

impl<'p, T> CertifiedMembershipLease<'p, T> {
    /// Actual original member/device observation, never remote frozen authority.
    pub fn observation(&self) -> Result<&Observation> {
        self.checked.as_ref().ok_or(Error::Unauthorized)?;
        Ok(&self.lease.observation)
    }
    /// Original authenticated certificate bytes; this read proves no currentness.
    /// A device-key lease has no passkey certificate and refuses.
    pub fn certificate_bytes(&self) -> Result<&[u8]> {
        self.checked.as_ref().ok_or(Error::Unauthorized)?;
        if self.device {
            return Err(Error::Unauthorized);
        }
        Ok(&self.signed)
    }
    /// Exact registered credential ID obtained from the current original verifier; for a
    /// device-key lease, the session's device key.
    pub fn credential_id(&self) -> Result<&[u8]> {
        Ok(&self.checked.as_ref().ok_or(Error::Unauthorized)?.credential)
    }
    /// The session's device key for a device-key lease; `None` for a passkey lease.
    pub fn device_key(&self) -> Result<Option<[u8; 32]>> {
        let checked = self.checked.as_ref().ok_or(Error::Unauthorized)?;
        if !self.device {
            return Ok(None);
        }
        checked
            .credential
            .as_slice()
            .try_into()
            .map(Some)
            .map_err(|__cause| {
                crate::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })
    }
    /// Actual checked time from this fresh authenticated server response. It is
    /// not memory of any later observation lost during a device restart.
    pub fn server_checked_at(&self) -> Result<u64> {
        Ok(self
            .checked
            .as_ref()
            .ok_or(Error::Unauthorized)?
            .server_checked_at)
    }
    /// Original session/certificate/policy bound. Later checks may shorten it;
    /// a refreshed publication never extends this operation's deadline.
    pub fn expires(&self) -> Result<u64> {
        Ok(self.checked.as_ref().ok_or(Error::Unauthorized)?.expires)
    }
    /// Borrow the same current original Charter only inside one synchronous check, with the
    /// lease rechecked before and after. The callback cannot turn stored public evidence
    /// into authority; it can, for example, build a passkey request or verify evidence.
    pub fn with_current<R>(
        &mut self,
        mut clock: impl FnMut() -> u64,
        inspect: impl FnOnce(&cnvy::cchr::VerifiedCharter) -> R,
    ) -> Result<R> {
        let now = self.check(&mut clock)?;
        let result = self.policy.with_current(now, inspect).map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })?;
        self.check(&mut clock)?;
        Ok(result)
    }

    /// Reborrow actual current policy and inspect the held original session
    /// synchronously after every await. Refusal consumes this check state.
    pub fn check(&mut self, mut clock: impl FnMut() -> u64) -> Result<u64> {
        let mut checked = self.checked.take().ok_or(Error::Unauthorized)?;
        let now = self.lease.check(&mut clock)?;
        if now < checked.last_checked
            || now < checked.server_checked_at
            || now >= checked.expires
            || !self.policy.belongs_to(&self.lease.owner)
            || self
                .lease
                .credential
                .as_ref()
                .is_some_and(|id| id != &checked.credential)
        {
            return Err(Error::Unauthorized);
        }
        self.policy.check_origin(&self.lease.owner, &self.origin)?;
        let expires = if self.device {
            self.device_current(&checked.credential, now)?
        } else {
            self.passkey_current(&checked.credential, now)?
        };
        checked.expires = checked.expires.min(expires);
        if now >= checked.expires {
            return Err(Error::Unauthorized);
        }
        checked.last_checked = now;
        self.checked = Some(checked);
        Ok(now)
    }

    /// The passkey certificate, verified under the current Charter for this member and key.
    fn passkey_current(&mut self, credential: &[u8], now: u64) -> Result<u64> {
        self.policy
            .with_current(now, |current| {
                if matches!(self.lease.scope, ObservationScope::Wallet)
                    && current.community() != "wallet"
                {
                    return Err(cnvy::cchr::Error::Unauthenticated);
                }
                let certificate = current.passkey_certificate(
                    &self.signed,
                    &self.lease.observation.member,
                    now,
                )?;
                if certificate.credential_id(now)? != credential {
                    return Err(cnvy::cchr::Error::Unauthenticated);
                }
                Ok(certificate.valid_until())
            })
            .map_err(|__cause| {
                crate::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })?
            .map_err(|__cause| {
                crate::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })
    }

    /// The held community session's own device key, still among the member's live keys of
    /// the latest original observation, under a current community (never wallet) Charter.
    /// Bounded by the session deadline only.
    fn device_current(&mut self, key: &[u8], now: u64) -> Result<u64> {
        let held = &self.lease.held;
        if !matches!(self.lease.scope, ObservationScope::Community)
            || !held.device_session
            || held.login_credential.as_deref() != Some(key)
            || !self
                .lease
                .observation
                .device_keys
                .iter()
                .any(|live| live.as_slice() == key)
        {
            return Err(Error::Unauthorized);
        }
        self.policy
            .with_current(now, |current| current.community() != "wallet")
            .map_err(|__cause| {
                crate::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })?
            .then_some(self.lease.observation.expires)
            .ok_or(Error::Unauthorized)
    }
    /// Join only original successful registration on this same owner/session/key.
    /// A foreign, expired or different-key registration consumes both owners.
    pub fn bind_registration(
        mut self,
        mut registration: RegisteredSession<T>,
        mut clock: impl FnMut() -> u64,
    ) -> Result<RegisteredCertificateLease<'p, T>> {
        self.check(&mut clock)?;
        registration.check_with_lease(&mut self.lease, &mut clock)?;
        if registration.original_credential_id()? != self.credential_id()? {
            return Err(Error::Unauthorized);
        }
        self.check(&mut clock)?;
        Ok(RegisteredCertificateLease {
            certified: self,
            registration,
        })
    }
    /// Final consumption after one last actual owner/policy/clock recheck.
    pub fn consume_checked(mut self, clock: impl FnMut() -> u64) -> Result<()> {
        self.check(clock).map(|_| ())
    }
}

impl<T> RegisteredCertificateLease<'_, T> {
    /// Original retained public member/device data, not a Keys grant.
    pub fn observation(&self) -> Result<&Observation> {
        self.certified.observation()
    }
    /// Original certificate bytes; no generic Keys operation follows from them.
    pub fn certificate_bytes(&self) -> Result<&[u8]> {
        self.certified.certificate_bytes()
    }
    /// Exact original registered passkey ID shared by both original owners.
    pub fn credential_id(&self) -> Result<&[u8]> {
        self.certified.credential_id()
    }
    /// Fresh server response observation, never a retained historical maximum.
    pub fn server_checked_at(&self) -> Result<u64> {
        self.certified.server_checked_at()
    }
    /// The unchanged exclusive bound of this joined operation.
    pub fn expires(&self) -> Result<u64> {
        self.certified.expires()
    }
    /// Recheck both original owners without re-locking the held session.
    pub fn check(&mut self, mut clock: impl FnMut() -> u64) -> Result<u64> {
        // Invalidate the certificate state on registration refusal as well.
        let checked = self.certified.checked.take().ok_or(Error::Unauthorized)?;
        self.registration
            .check_with_lease(&mut self.certified.lease, &mut clock)?;
        self.certified.checked = Some(checked);
        self.certified.check(clock)
    }
    /// Consume both owners at the final checkpoint/publication boundary.
    pub fn consume_checked(mut self, clock: impl FnMut() -> u64) -> Result<()> {
        self.check(clock).map(|_| ())
    }
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "http"))]
#[path = "../../tests/cases/certificate.rs"]
mod tests;
