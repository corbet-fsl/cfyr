//! Narrow live reads over the original Foyer session. No trust or bearer copies.
use crate::{Error, Foyer, Result, SessionInfo, Transport};
use futures::{
    future::{AbortHandle, Abortable},
    lock::Mutex,
};
use std::{
    cell::RefCell,
    rc::{Rc, Weak},
};

pub(crate) struct Retained<T> {
    pub(crate) client: cvld::client::Client<T>,
    pub(crate) info: Option<SessionInfo>,
    pub(crate) authentication: u64,
}
#[derive(Default)]
struct Lifetime {
    closed: bool,
    generation: u64,
    pending: Option<AbortHandle>,
}
pub(crate) struct Shared<T> {
    pub(crate) session: Mutex<Retained<T>>,
    lifetime: RefCell<Lifetime>,
}
impl<T> Shared<T> {
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
            session: Mutex::new(Retained {
                client: cvld::client::Client::new(transport),
                info: None,
                authentication: 0,
            }),
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

impl<T> Foyer<T> {
    /// Give the trusted custody composer only the original live membership read
    /// port. The sole Charter/Follower remains owned by this Foyer.
    pub fn live_membership(&self) -> LiveMembership<T> {
        LiveMembership(Rc::downgrade(&self.shared))
    }
}

struct Pending<T> {
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
    pub async fn observe(&mut self, mut clock: impl FnMut() -> u64) -> Result<Observation> {
        let shared = self.0.upgrade().ok_or(Error::Unavailable)?;
        let (abort, registration) = AbortHandle::new_pair();
        let generation = {
            let mut lifetime = shared.lifetime.borrow_mut();
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
        let _pending = Pending {
            shared: self.0.clone(),
            generation,
        };
        let started = clock();
        let observed = Abortable::new(
            async {
                let mut retained = shared.session.lock().await;
                let info = retained.info.as_ref().ok_or(Error::Unauthorized)?;
                let expires = info.expires;
                let sending = clock();
                if sending < started || sending >= expires {
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
                if finished < sending || finished >= expires || shared.lifetime.borrow().closed {
                    return Err(Error::Unauthorized);
                }
                let member = lobby
                    .get("member_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|member| !member.is_empty())
                    .ok_or(Error::Reconcile)?
                    .to_owned();
                let device_keys =
                    serde_json::from_value(keys.get("keys").cloned().ok_or(Error::Reconcile)?)
                        .map_err(|_| Error::Reconcile)?;
                Ok(Observation {
                    member,
                    device_keys,
                    expires,
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

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../tests/cases/membership.rs"]
mod tests;
