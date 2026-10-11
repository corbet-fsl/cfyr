//! Fresh original server certificate under one held Foyer session and policy.
use super::*;
use crate::{policy::CurrentPolicy, registration::RegisteredSession};
use cvld::client::AuthenticatedTransport;

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
    policy: &'p mut CurrentPolicy<T>,
    signed: Vec<u8>,
    origin: String,
    checked: Option<CheckedCertificate>,
}

/// The same original registered key joined to its exact next successful session.
/// This consumes registration provenance; it grants no Keys or publication API.
pub struct RegisteredCertificateLease<'p, T> {
    certified: CertifiedMembershipLease<'p, T>,
    registration: RegisteredSession<T>,
}

impl<T: AuthenticatedTransport> MembershipLease<T> {
    /// Consume this local lease and fetch only through its held original client.
    /// Missing owner-generated action/response metadata refuses before sealing.
    /// Cancellation drops the held session guard; owner closure aborts this call.
    pub async fn passkey_certificate<'p>(
        mut self,
        policy: &'p mut CurrentPolicy<T>,
        mut clock: impl FnMut() -> u64,
    ) -> Result<CertifiedMembershipLease<'p, T>> {
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
        .map_err(|_| Error::Unavailable)??;
        // The original client already validated the owner's generated schema.
        // These are private field projections, never a second response contract.
        let signed: Vec<u8> =
            serde_json::from_value(response.get("bytes").cloned().ok_or(Error::Reconcile)?)
                .map_err(|_| Error::Reconcile)?;
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
                let certificate =
                    current.passkey_certificate(&signed, &self.observation.member, completed)?;
                Ok::<_, cnvy::cchr::Error>((
                    certificate.credential_id(completed)?.to_vec(),
                    certificate.valid_until(),
                ))
            })
            .map_err(|_| Error::Unauthorized)?
            .map_err(|_| Error::Unauthorized)?;
        let expires = expires.min(self.observation.expires);
        if completed >= expires {
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
        })
    }
}

impl<'p, T> CertifiedMembershipLease<'p, T> {
    /// Actual original member/device observation, never remote frozen authority.
    pub fn observation(&self) -> Result<&Observation> {
        self.checked.as_ref().ok_or(Error::Unauthorized)?;
        Ok(&self.lease.observation)
    }
    /// Original authenticated certificate bytes; this read proves no currentness.
    pub fn certificate_bytes(&self) -> Result<&[u8]> {
        self.checked.as_ref().ok_or(Error::Unauthorized)?;
        Ok(&self.signed)
    }
    /// Exact registered credential ID obtained from the current original verifier.
    pub fn credential_id(&self) -> Result<&[u8]> {
        Ok(&self.checked.as_ref().ok_or(Error::Unauthorized)?.credential)
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
    /// Reborrow actual current policy and inspect the held original session
    /// synchronously after every await. Refusal consumes this check state.
    pub fn check(&mut self, mut clock: impl FnMut() -> u64) -> Result<u64> {
        let mut checked = self.checked.take().ok_or(Error::Unauthorized)?;
        let now = self.lease.check(&mut clock)?;
        if now < checked.last_checked
            || now < checked.server_checked_at
            || now >= checked.expires
            || !self.policy.belongs_to(&self.lease.owner)
        {
            return Err(Error::Unauthorized);
        }
        self.policy.check_origin(&self.lease.owner, &self.origin)?;
        let expires = self
            .policy
            .with_current(now, |current| {
                let certificate = current.passkey_certificate(
                    &self.signed,
                    &self.lease.observation.member,
                    now,
                )?;
                if certificate.credential_id(now)? != checked.credential.as_slice() {
                    return Err(cnvy::cchr::Error::Unauthenticated);
                }
                Ok(certificate.valid_until())
            })
            .map_err(|_| Error::Unauthorized)?
            .map_err(|_| Error::Unauthorized)?;
        checked.expires = checked.expires.min(expires);
        if now >= checked.expires {
            return Err(Error::Unauthorized);
        }
        checked.last_checked = now;
        self.checked = Some(checked);
        Ok(now)
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
