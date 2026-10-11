//! Narrow live reads over the original Foyer session. No trust or bearer copies.
use crate::{Error, Foyer, Result, SessionInfo, Transport};
use futures::{
    future::{AbortHandle, AbortRegistration, Abortable},
    lock::{Mutex, OwnedMutexGuard},
};
mod certificate;
mod global;
mod global_initial;
pub use certificate::{CertifiedMembershipLease, InitialCreationLease, RegisteredCertificateLease};
pub use global::{GlobalWalletLease, LiveGlobalWallet};
pub use global_initial::GlobalInitialCreationLease;

use std::{
    cell::RefCell,
    rc::{Rc, Weak},
};

pub(crate) struct Retained<T> {
    pub(crate) client: cvld::client::Client<T>,
    pub(crate) info: Option<SessionInfo>,
    pub(crate) authentication: u64,
    pub(crate) login_credential: Option<Vec<u8>>,
}
#[derive(Default)]
struct Lifetime {
    closed: bool,
    generation: u64,
    pending: Option<AbortHandle>,
}
pub(crate) struct Shared<T> {
    pub(crate) session: std::sync::Arc<Mutex<Retained<T>>>,
    lifetime: RefCell<Lifetime>,
}
impl<T> Shared<T> {
    pub(crate) fn begin_pending(self: &Rc<Self>) -> Result<(Pending<T>, AbortRegistration)> {
        let (abort, registration) = AbortHandle::new_pair();
        let generation = {
            let mut lifetime = self.lifetime.borrow_mut();
            if lifetime.closed || lifetime.pending.is_some() {
                return Err(Error::Unavailable);
            }
            lifetime.generation = lifetime
                .generation
                .checked_add(1)
                .ok_or(Error::Unavailable)?;
            lifetime.pending = Some(abort);
            lifetime.generation
        };
        Ok((
            Pending {
                shared: Rc::downgrade(self),
                generation,
            },
            registration,
        ))
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.lifetime.try_borrow().map_or(true, |life| life.closed)
    }
    pub(crate) fn close(&self) {
        let pending = {
            let mut lifetime = self.lifetime.borrow_mut();
            lifetime.closed = true;
            lifetime.pending.take()
        };
        if let Some(pending) = pending {
            pending.abort();
        }
    }
}
impl<T: Transport> Shared<T> {
    pub(crate) fn new(transport: T) -> Self {
        Self {
            session: std::sync::Arc::new(Mutex::new(Retained {
                client: cvld::client::Client::new(transport),
                info: None,
                authentication: 0,
                login_credential: None,
            })),
            lifetime: RefCell::default(),
        }
    }
}

/// A public observation, not a membership, lineage or signing capability.
/// The pseudonym comes from the actual lobby; it is never the session user UUID.
pub struct Observation {
    /// Actual community pseudonym from the original lobby owner.
    pub member: String,
    /// Actual currently passkey-authorized signing keys from Membership.
    pub device_keys: Vec<[u8; 32]>,
    /// Exclusive session deadline checked again after both original requests.
    pub expires: u64,
}

/// Weak, non-cloneable read port. It cannot authenticate, forward arbitrary
/// actions, expose a bearer or keep the owning Foyer alive. Dropping that Foyer
/// cancels pending reads, including their original transport futures.
pub struct LiveMembership<T>(Weak<Shared<T>>);

/// One original live observation retaining the exact local session lock. It
/// cannot be built from public Observation data or extend remote authority.
/// The composer holds it across its owned checkpoint await and checks it again
/// before publication; current signed Policy must still be borrowed separately.
pub struct MembershipLease<T> {
    owner: Weak<Shared<T>>,
    held: OwnedMutexGuard<Retained<T>>,
    authentication: u64,
    user: String,
    observation: Observation,
    checked_at: Option<u64>,
    _pending: Pending<T>,
}

pub(crate) struct RegistrationCheck<'a, T> {
    pub(crate) owner: &'a Weak<Shared<T>>,
    pub(crate) authentication: u64,
    pub(crate) user: &'a str,
    pub(crate) expires: u64,
    pub(crate) floor: u64,
}

impl<T> MembershipLease<T> {
    /// Existing public observation only, never a current-authority verdict.
    pub fn observation(&self) -> &Observation {
        &self.observation
    }

    /// Bound synchronous validation after the composer's await. The held guard
    /// is inspected directly: re-locking this session would deadlock. Refusal is
    /// terminal, and the original exclusive deadline is never renewed.
    pub fn check(&mut self, mut clock: impl FnMut() -> u64) -> Result<u64> {
        let floor = self.checked_at.take().ok_or(Error::Unauthorized)?;
        let now = clock();
        let owner = self.owner.upgrade().ok_or(Error::Unavailable)?;
        let info = self.held.info.as_ref().ok_or(Error::Unauthorized)?;
        if owner.is_closed()
            || now < floor
            || now >= self.observation.expires
            || self.held.authentication != self.authentication
            || info.user != self.user
            || info.role != "member"
            || info.expires != self.observation.expires
        {
            return Err(Error::Unauthorized);
        }
        self.checked_at = Some(now);
        Ok(now)
    }

    pub(crate) fn check_registered(
        &mut self,
        expected: RegistrationCheck<'_, T>,
        clock: impl FnMut() -> u64,
    ) -> Result<u64> {
        let now = self.check(clock)?;
        if !self.owner.ptr_eq(expected.owner)
            || self.authentication != expected.authentication
            || self.user != expected.user
            || self.observation.expires != expected.expires
            || now < expected.floor
        {
            return Err(Error::Unauthorized);
        }
        Ok(now)
    }

    fn into_observation(self) -> Observation {
        self.observation
    }
}

impl<T> Foyer<T> {
    /// Give the trusted custody composer only the original live membership read
    /// port. The sole Charter/Follower remains owned by this Foyer.
    pub fn live_membership(&self) -> LiveMembership<T> {
        LiveMembership(Rc::downgrade(&self.shared))
    }
}

pub(crate) struct Pending<T> {
    shared: Weak<Shared<T>>,
    generation: u64,
}
impl<T> Drop for Pending<T> {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            let mut lifetime = shared.lifetime.borrow_mut();
            if lifetime.generation == self.generation {
                lifetime.pending = None;
            }
        }
    }
}

impl<T: Transport> LiveMembership<T> {
    /// Make two actual owner reads under the same retained session lock. No
    /// cached roster authorizes a later use. A constructor-provided bearer alone
    /// has no authenticated deadline here: this port requires original login.
    /// The trusted composer supplies Unix seconds and must still verify current
    /// record lineage and exact one-use intent before authorizing Keys.
    pub async fn observe(&mut self, clock: impl FnMut() -> u64) -> Result<Observation> {
        self.observe_lease(clock)
            .await
            .map(MembershipLease::into_observation)
    }

    /// Retain the original Foyer session while the trusted composer commits its
    /// checkpoint. This freezes only local replacement/logout, not server state.
    /// Cancellation drops the real guard and the pending original observation.
    pub async fn observe_lease(
        &mut self,
        mut clock: impl FnMut() -> u64,
    ) -> Result<MembershipLease<T>> {
        let shared = self.0.upgrade().ok_or(Error::Unavailable)?;
        let (pending, registration) = shared.begin_pending()?;
        let started = clock();
        let observed = Abortable::new(
            async {
                let mut retained = shared.session.clone().lock_owned().await;
                let observed = read_held(&mut retained, &shared, started, &mut clock).await?;
                Ok(MembershipLease {
                    owner: self.0.clone(),
                    held: retained,
                    authentication: observed.authentication,
                    user: observed.user,
                    observation: observed.observation,
                    checked_at: Some(observed.checked_at),
                    _pending: pending,
                })
            },
            registration,
        )
        .await
        .map_err(|_| Error::Unavailable)??;
        if shared.lifetime.borrow().closed {
            return Err(Error::Unavailable);
        }
        Ok(observed)
    }
}

// One original verifier reused by both the first observation and retained-session
// refresh. It forwards only these two reads and never installs authentication.
struct HeldObservation {
    observation: Observation,
    user: String,
    authentication: u64,
    checked_at: u64,
}
async fn read_held<T: Transport>(
    retained: &mut Retained<T>,
    shared: &Shared<T>,
    started: u64,
    clock: &mut impl FnMut() -> u64,
) -> Result<HeldObservation> {
    let info = retained.info.as_ref().ok_or(Error::Unauthorized)?;
    let expires = info.expires;
    let user = info.user.clone();
    let authentication = retained.authentication;
    let sending = clock();
    if info.role != "member" || sending < started || sending >= expires {
        return Err(Error::Unauthorized);
    }
    let lobby = retained
        .client
        .forward("lobby", serde_json::json!({}))
        .await?;
    let keys = retained
        .client
        .forward("device_keys", serde_json::json!({}))
        .await?;
    let finished = clock();
    if finished < sending || finished >= expires || shared.is_closed() {
        return Err(Error::Unauthorized);
    }
    let member = lobby
        .get("member_id")
        .and_then(serde_json::Value::as_str)
        .filter(|member| !member.is_empty())
        .ok_or(Error::Reconcile)?
        .to_owned();
    let device_keys = serde_json::from_value(keys.get("keys").cloned().ok_or(Error::Reconcile)?)
        .map_err(|_| Error::Reconcile)?;
    Ok(HeldObservation {
        observation: Observation {
            member,
            device_keys,
            expires,
        },
        user,
        authentication,
        checked_at: finished,
    })
}
impl<T: Transport> MembershipLease<T> {
    async fn refresh_observation(&mut self, clock: &mut impl FnMut() -> u64) -> Result<u64> {
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
        let observed = Abortable::new(
            read_held(&mut self.held, &shared, started, clock),
            registration,
        )
        .await
        .map_err(|_| Error::Unavailable)??;
        if observed.authentication != self.authentication
            || observed.user != self.user
            || observed.observation.expires != self.observation.expires
            || observed.observation.member != self.observation.member
        {
            return Err(Error::Unauthorized);
        }
        self.observation = observed.observation;
        self.checked_at = Some(observed.checked_at);
        self.check(clock)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../tests/cases/membership.rs"]
mod tests;
