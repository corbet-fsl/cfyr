//! Correlate original member registration with its first authenticated session.
//! PRF custody stays in the vault caller; this grants no Keys or lineage authority.
use crate::{Error, Foyer, Result, Transport, membership::Shared};
use serde::Deserialize;
use serde_json::{Value, json};
use std::rc::{Rc, Weak};

mod global;
mod initial;
pub use global::{
    GlobalFinishContinuation, GlobalRegistrationReservation, PendingGlobalInitialRegistration,
};
pub use initial::{FinishContinuation, PendingInitialRegistration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    ceremony: String,
    user: String,
    options: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completed {
    user: String,
    certificate: Option<Vec<u8>>,
}

/// One original pending ceremony. It cannot be copied, serialized or applied to
/// another Foyer. Server verification still decides whether registration succeeds.
pub struct PendingRegistration<T> {
    owner: Weak<Shared<T>>,
    authentication: u64,
    challenge: Challenge,
}
impl<T> PendingRegistration<T> {
    /// Original server options for the maintained Passkeys adapter, unchanged.
    pub fn options(&self) -> &Value {
        &self.challenge.options
    }
}

/// Original successful public registration awaiting this Foyer's first
/// subsequent login. A global response may have no certificate; this type never
/// supplies one or treats registration as admission or lineage authority.
pub struct RegisteredMember<T> {
    owner: Weak<Shared<T>>,
    authentication: u64,
    completed: Completed,
    original_id: Vec<u8>,
}

struct PinnedSession {
    authentication: u64,
    user: String,
    expires: u64,
    last_checked: u64,
    original_id: Vec<u8>,
}

/// Consume-only continuation of an original registration and its exact next
/// successful member login. This is session correlation, never Keys permission,
/// admission, a passkey certificate or current lineage authority.
///
/// The trusted composer checks this owner around its original Foyer calls and
/// consumes it at the final handover. Cancellation or refusal permanently loses
/// the continuation without changing the Foyer's original session.
pub struct RegisteredSession<T> {
    owner: Weak<Shared<T>>,
    pinned: Option<PinnedSession>,
}

impl<T: Transport> Foyer<T> {
    /// Begin original first-member registration with an optional original Wallet
    /// presentation. Operator bootstrap is deliberately absent from this path.
    /// The owner-generated contract validates the public presentation shape.
    pub async fn begin_member_registration(
        &mut self,
        passport: Option<Value>,
    ) -> Result<PendingRegistration<T>> {
        if self.shared.is_closed() {
            return Err(Error::Unavailable);
        }
        let mut retained = self.shared.session.lock().await;
        if self.shared.is_closed() || retained.info.is_some() {
            return Err(Error::Unauthorized);
        }
        let value = retained
            .client
            .forward(
                "register_begin",
                json!({"bootstrap": null, "passport": passport}),
            )
            .await?;
        if self.shared.is_closed() {
            return Err(Error::Unavailable);
        }
        let challenge: Challenge = serde_json::from_value(value).map_err(|_| Error::Reconcile)?;
        if challenge.ceremony.is_empty() || challenge.user.is_empty() {
            return Err(Error::Reconcile);
        }
        Ok(PendingRegistration {
            owner: Rc::downgrade(&self.shared),
            authentication: retained.authentication,
            challenge,
        })
    }

    /// Forward the sanitized public half of the maintained ceremony and retain
    /// the original reply. The vault caller keeps the independent PRF handover.
    /// Cancellation or uncertain transport consumes the attempt; never replay it.
    pub async fn finish_member_registration(
        &mut self,
        pending: PendingRegistration<T>,
        credential: cpky::PublicCredential,
    ) -> Result<RegisteredMember<T>> {
        if !pending.owner.ptr_eq(&Rc::downgrade(&self.shared)) || self.shared.is_closed() {
            return Err(Error::Unauthorized);
        }
        let mut retained = self.shared.session.lock().await;
        if self.shared.is_closed()
            || retained.info.is_some()
            || retained.authentication != pending.authentication
        {
            return Err(Error::Unauthorized);
        }
        let original_id = credential.credential_id().map_err(|_| Error::Invalid)?;
        let value = retained
            .client
            .forward(
                "register_finish",
                json!({
                    "ceremony": pending.challenge.ceremony,
                    "credential": credential.into_json(),
                }),
            )
            .await?;
        if self.shared.is_closed() {
            return Err(Error::Unavailable);
        }
        let completed: Completed = serde_json::from_value(value).map_err(|_| Error::Reconcile)?;
        if completed.user != pending.challenge.user {
            return Err(Error::Reconcile);
        }
        Ok(RegisteredMember {
            owner: pending.owner,
            authentication: pending.authentication,
            completed,
            original_id,
        })
    }
}

impl<T> RegisteredMember<T> {
    /// Exact original public credential ID, retained only after successful
    /// server registration. It grants no currentness or custody permission.
    pub fn original_credential_id(&self) -> &[u8] {
        &self.original_id
    }

    /// Retain sealed registration provenance through subsequent original Foyer
    /// operations. Only the successful next login on this same owner can bind it;
    /// a copied bearer, supplied SessionInfo or later replacement cannot do so.
    /// No certificate bytes or vault custody are inferred from this handover.
    pub async fn continue_after_login(
        self,
        owner: &Foyer<T>,
        clock: impl FnMut() -> u64,
    ) -> Result<RegisteredSession<T>> {
        self.first_session(owner, clock)
            .await
            .map(|(continued, _)| continued)
    }

    /// Consume this public registration receipt after the next successful login
    /// identifies this registered member in this same Foyer. No copied bearer or
    /// caller-supplied SessionInfo can satisfy this correlation. A failed login,
    /// replacement session or owner close consumes/refuses this handover.
    /// Certificate bytes still require current issuer/revocation/assertion checks;
    /// this method grants neither Create nor Use and releases no vault secret.
    pub async fn into_certificate(
        self,
        owner: &Foyer<T>,
        clock: impl FnMut() -> u64,
    ) -> Result<Option<Vec<u8>>> {
        self.first_session(owner, clock)
            .await
            .map(|(_, certificate)| certificate)
    }

    async fn first_session(
        self,
        owner: &Foyer<T>,
        mut clock: impl FnMut() -> u64,
    ) -> Result<(RegisteredSession<T>, Option<Vec<u8>>)> {
        if !self.owner.ptr_eq(&Rc::downgrade(&owner.shared)) || owner.shared.is_closed() {
            return Err(Error::Unauthorized);
        }
        let started = clock();
        let retained = owner.shared.session.lock().await;
        let now = clock();
        if owner.shared.is_closed() || now < started {
            return Err(Error::Unauthorized);
        }
        let info = retained.info.as_ref().ok_or(Error::Unauthorized)?;
        if Some(retained.authentication) != self.authentication.checked_add(1)
            || info.user != self.completed.user
            || info.role != "member"
            || now >= info.expires
        {
            return Err(Error::Unauthorized);
        }
        let certificate = self.completed.certificate;
        let continued = RegisteredSession {
            owner: self.owner,
            pinned: Some(PinnedSession {
                authentication: retained.authentication,
                user: self.completed.user,
                expires: info.expires,
                last_checked: now,
                original_id: self.original_id,
            }),
        };
        Ok((continued, certificate))
    }
}

impl<T> RegisteredSession<T> {
    /// Original registered key's public ID, never a current certificate verdict.
    /// A cancelled, consumed or refused continuation cannot expose this relation.
    pub fn original_credential_id(&self) -> Result<&[u8]> {
        Ok(&self.pinned.as_ref().ok_or(Error::Unauthorized)?.original_id)
    }

    /// Join this original registration to the retained original membership
    /// session without acquiring its mutex again. This checks provenance and
    /// time only; it grants no Keys operation or certificate authority.
    pub fn check_with_lease(
        &mut self,
        lease: &mut crate::membership::MembershipLease<T>,
        clock: impl FnMut() -> u64,
    ) -> Result<()> {
        let mut pinned = self.pinned.take().ok_or(Error::Unauthorized)?;
        let checked = lease.check_registered(
            crate::membership::RegistrationCheck {
                owner: &self.owner,
                authentication: pinned.authentication,
                user: &pinned.user,
                expires: pinned.expires,
                floor: pinned.last_checked,
            },
            clock,
        )?;
        pinned.last_checked = checked;
        self.pinned = Some(pinned);
        Ok(())
    }

    /// Consume the registration at the final checkpoint/publication boundary
    /// while the same local session is still retained by the original lease.
    pub fn consume_with_lease(
        mut self,
        lease: &mut crate::membership::MembershipLease<T>,
        clock: impl FnMut() -> u64,
    ) -> Result<()> {
        self.check_with_lease(lease, clock)
    }

    /// Recheck the exact original session after an external await. Taking the
    /// private state before waiting makes cancelled and refused checks terminal;
    /// a later check cannot revive the continuation or renew its deadline.
    pub async fn check(&mut self, owner: &Foyer<T>, mut clock: impl FnMut() -> u64) -> Result<()> {
        let mut pinned = self.pinned.take().ok_or(Error::Unauthorized)?;
        if !self.owner.ptr_eq(&Rc::downgrade(&owner.shared)) || owner.shared.is_closed() {
            return Err(Error::Unauthorized);
        }
        let started = clock();
        if started < pinned.last_checked || started >= pinned.expires {
            return Err(Error::Unauthorized);
        }
        let retained = owner.shared.session.lock().await;
        let now = clock();
        if owner.shared.is_closed() || now < started || now >= pinned.expires {
            return Err(Error::Unauthorized);
        }
        let info = retained.info.as_ref().ok_or(Error::Unauthorized)?;
        if retained.authentication != pinned.authentication
            || info.user != pinned.user
            || info.role != "member"
            || info.expires != pinned.expires
        {
            return Err(Error::Unauthorized);
        }
        pinned.last_checked = now;
        self.pinned = Some(pinned);
        Ok(())
    }

    /// Consume this continuation only after one last original owner, session and
    /// clock check. Success grants no Keys operation or certificate authority.
    pub async fn consume_checked(
        mut self,
        owner: &Foyer<T>,
        clock: impl FnMut() -> u64,
    ) -> Result<()> {
        self.check(owner, clock).await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../tests/cases/registration.rs"]
mod tests;
