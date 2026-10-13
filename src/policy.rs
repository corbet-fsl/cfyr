//! Synchronous scoped reads of the sole Foyer-owned Charter/Follower.
use crate::{Foyer, membership::Shared, trust::Trust};
use futures::lock::Mutex;
use std::rc::{Rc, Weak};

/// Weak read port with the same close lifetime as the original Foyer session.
/// It owns no Trust, cached policy, accepting verdict or signing capability.
pub struct CurrentPolicy<T> {
    session: Weak<Shared<T>>,
    trust: Weak<Mutex<Option<Trust>>>,
}

impl<T> Foyer<T> {
    /// Lend only a scoped callback into this Foyer's one original Trust. The
    /// borrowing callback is synchronous and cannot retain a policy reference.
    pub fn current_policy(&self) -> CurrentPolicy<T> {
        CurrentPolicy {
            session: Rc::downgrade(&self.shared),
            trust: Rc::downgrade(&self.trust),
        }
    }
}

impl<T> CurrentPolicy<T> {
    pub(crate) fn require_independent_owner(&self, owner: &Weak<Shared<T>>) -> crate::Result<()> {
        let original = owner.upgrade().ok_or(crate::Error::Unavailable)?;
        let other = self.session.upgrade().ok_or(crate::Error::Unavailable)?;
        if original.is_closed() || other.is_closed() || self.trust.upgrade().is_none() {
            return Err(crate::Error::Unavailable);
        }
        if self.session.ptr_eq(owner) {
            return Err(crate::Error::Unauthorized);
        }
        Ok(())
    }

    pub(crate) fn belongs_to(&self, owner: &Weak<Shared<T>>) -> bool {
        self.session.ptr_eq(owner)
    }

    pub(crate) fn check_origin(&self, owner: &Weak<Shared<T>>, origin: &str) -> crate::Result<()> {
        if !self.belongs_to(owner) {
            return Err(crate::Error::Unauthorized);
        }
        let session = self.session.upgrade().ok_or(crate::Error::Unavailable)?;
        if session.is_closed() {
            return Err(crate::Error::Unavailable);
        }
        let retained = self.trust.upgrade().ok_or(crate::Error::Unavailable)?;
        let trust = retained.try_lock().ok_or(crate::Error::Unavailable)?;
        let trust = trust.as_ref().ok_or(crate::Error::Unavailable)?;
        if trust.origin() != origin || session.is_closed() {
            return Err(crate::Error::Unauthorized);
        }
        Ok(())
    }

    /// Reborrow and revalidate original current policy at the supplied trusted
    /// Unix-second time. Call after every authority await and before returning
    /// authorization; this port performs no caching or independent verification.
    /// Reentrant access or an in-flight feed refresh refuses with Busy.
    /// Owner disposal inside the callback discards its result.
    ///
    /// ```compile_fail
    /// fn cannot_escape<T>(port: &mut cfyr::policy::CurrentPolicy<T>) {
    ///     let _borrowed = port.with_current(1, |policy| policy);
    /// }
    /// ```
    pub fn with_current<R>(
        &mut self,
        now: u64,
        inspect: impl FnOnce(&cnvy::cchr::VerifiedCharter) -> R,
    ) -> cnvy::Result<R> {
        let session = self.session.upgrade().ok_or(cnvy::Error::Unavailable)?;
        if session.is_closed() {
            return Err(cnvy::Error::Unavailable);
        }
        let retained = self.trust.upgrade().ok_or(cnvy::Error::Unavailable)?;
        let output = {
            let mut trust = retained.try_lock().ok_or(cnvy::Error::Busy)?;
            let trust = trust.as_mut().ok_or(cnvy::Error::Unavailable)?;
            inspect(trust.current(now)?)
        };
        if session.is_closed() {
            if let Some(mut trust) = retained.try_lock()
                && let Some(trust) = trust.as_mut()
            {
                trust.stop();
            }
            return Err(cnvy::Error::Unavailable);
        }
        Ok(output)
    }
}
