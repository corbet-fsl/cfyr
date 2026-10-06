//! Foyer forwards member, admin and root operations through the cvld owner client.
//! Frontends use cmsg; this facade is a private composition dependency behind it.
//! No action list, role policy, gate evaluator, server or key custody lives here.
#![forbid(unsafe_code)]

#[cfg(all(feature = "browser", target_arch = "wasm32"))]
pub use cvld::client::BrowserClient;
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use cvld::client::HttpClient;
pub use cvld::client::{
    Action, SessionInfo, SessionTransport, Transport, forwarding_action as action,
    forwarding_contract as contract,
};
pub use cvld::error::{Error, Result};
use futures::lock::{MappedMutexGuard, Mutex, MutexGuard};
use serde_json::Value;
use std::rc::Rc;

/// Retained original Charter and Envoy composition for public community trust.
pub mod trust;
/// Device passkey owner. Foyer is its canonical facade home.
pub use cpky as passkeys;
/// Public browser challenge/assertion forwarding and retained session on both targets.
pub mod login;
/// Original public first-registration response, correlated with its first login.
pub mod registration;
/// Live membership observations through this Foyer's original retained session.
pub mod membership;
/// Scoped access to the one original current public trust owner.
pub mod policy;
/// Opaque correlation with one original successful session installation.
pub mod session;

/// Thin device facade over the original owner's client and transport.
pub struct Foyer<T> {
    shared: Rc<membership::Shared<T>>,
    trust: Rc<Mutex<Option<trust::Trust>>>,
}

impl<T> Foyer<T> {
    /// Borrow the one retained community trust follower. A forwarding-only Foyer
    /// has no policy authority and returns the original unavailable error.
    pub fn trust(
        &mut self,
    ) -> cnvy::Result<MappedMutexGuard<'_, Option<trust::Trust>, trust::Trust>> {
        let trust = self.trust.try_lock().ok_or(cnvy::Error::Busy)?;
        if trust.is_none() {
            return Err(cnvy::Error::Unavailable);
        }
        Ok(MutexGuard::map(trust, |trust| {
            trust
                .as_mut()
                .expect("checked under the same exclusive guard")
        }))
    }

    /// Borrow current verified community policy after both original owners check
    /// the current time. Consumers must reborrow after a network or authority wait.
    pub fn current<R>(
        &mut self,
        now: u64,
        inspect: impl FnOnce(&cnvy::cchr::VerifiedCharter) -> R,
    ) -> cnvy::Result<R> {
        self.current_policy().with_current(now, inspect)
    }
}

impl<T: Transport> Foyer<T> {
    /// Compose an authenticated runtime; this does not mint a session or grant.
    pub fn new(transport: T) -> Self {
        Self {
            shared: Rc::new(membership::Shared::new(transport)),
            trust: Rc::new(Mutex::new(None)),
        }
    }

    /// Retain one configured original public trust follower beside the selected
    /// session transport. Runtime construction selects both; shell JSON cannot.
    pub fn with_trust(transport: T, trust: trust::Trust) -> Self {
        Self {
            shared: Rc::new(membership::Shared::new(transport)),
            trust: Rc::new(Mutex::new(Some(trust))),
        }
    }

    /// Forward a registered owner action with its original response and errors.
    /// PRF outputs, wallet roots and local custody handles are never JSON inputs.
    pub async fn call(&mut self, action: &str, request: Value) -> Result<Value> {
        let mut retained = self.shared.session.lock().await;
        // Once logout may have been sent, a former login cannot be used for
        // custody handover even if its reply or waiter is lost.
        if action == "logout" {
            retained.info = None;
        }
        retained.client.forward(action, request).await
    }
}

impl<T: SessionTransport> Foyer<T> {
    /// Consume a real public passkey assertion and retain the server session.
    /// Only the authenticated identity, role and deadline may reach the shell.
    pub async fn authenticate(&mut self, request: Value) -> Result<SessionInfo> {
        let mut retained = self.shared.session.lock().await;
        // Invalidate earlier stamps before the mutation can be sent. Identical
        // public SessionInfo values do not identify the same server session.
        retained.info = None;
        retained.authentication = retained
            .authentication
            .checked_add(1)
            .ok_or(Error::Unavailable)?;
        let info = retained.client.authenticate(request).await?;
        retained.info = Some(info.clone());
        Ok(info)
    }
}

impl<T> Drop for Foyer<T> {
    fn drop(&mut self) {
        self.shared.close();
        // A callback can close the owner while it holds this borrow. Its weak
        // port observes closure before returning; no panic or escaping borrow.
        if let Some(mut trust) = self.trust.try_lock()
            && let Some(trust) = trust.as_mut()
        {
            trust.stop();
        }
    }
}
