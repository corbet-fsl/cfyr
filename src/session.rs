//! Correlate custody with one retained original session, without exporting it.
use crate::{Error, Foyer, Result, membership::Shared};
use std::rc::{Rc, Weak};

/// Weak, non-cloneable stamp of a successful original authentication. It conveys
/// no remote authority, bearer, identity conversion or current lineage verdict.
pub struct SessionBinding<T> {
    owner: Weak<Shared<T>>,
    authentication: u64,
}
impl<T> Foyer<T> {
    /// Pin the currently installed original session. Constructor-supplied bearer
    /// strings have no authenticated session information and cannot mint a stamp.
    pub fn session_binding(&self) -> Result<SessionBinding<T>> {
        if self.shared.is_closed() {
            return Err(Error::Unavailable);
        }
        let retained = self.shared.session.try_lock().ok_or(Error::Unavailable)?;
        retained.info.as_ref().ok_or(Error::Unauthorized)?;
        Ok(SessionBinding {
            owner: Rc::downgrade(&self.shared),
            authentication: retained.authentication,
        })
    }
}
impl<T> SessionBinding<T> {
    /// Check exact owning Foyer, successful installation and exclusive deadline.
    /// Call synchronously at custody handover. Later key use still requires the
    /// real live membership, current policy, record lineage and local intent.
    pub fn check(&self, owner: &Foyer<T>, now: u64) -> Result<()> {
        if !self.owner.ptr_eq(&Rc::downgrade(&owner.shared)) || owner.shared.is_closed() {
            return Err(Error::Unauthorized);
        }
        let retained = owner.shared.session.try_lock().ok_or(Error::Unavailable)?;
        let info = retained.info.as_ref().ok_or(Error::Unauthorized)?;
        if self.authentication != retained.authentication || now >= info.expires {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
