//! Correlate original member registration with its first authenticated session.
//! PRF custody stays in the vault caller; this grants no Keys or lineage authority.
use crate::{Error, Foyer, Result, Transport, membership::Shared};
use serde::Deserialize;
use serde_json::{Value, json};
use std::rc::{Rc, Weak};

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
        })
    }
}

impl<T> RegisteredMember<T> {
    /// Consume this public registration receipt after the next successful login
    /// identifies this registered member in this same Foyer. No copied bearer or
    /// caller-supplied SessionInfo can satisfy this correlation. A failed login,
    /// replacement session or owner close consumes/refuses this handover.
    /// Certificate bytes still require current issuer/revocation/assertion checks;
    /// this method grants neither Create nor Use and releases no vault secret.
    pub async fn into_certificate(
        self,
        owner: &Foyer<T>,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Option<Vec<u8>>> {
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
        Ok(self.completed.certificate)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../tests/cases/registration.rs"]
mod tests;
