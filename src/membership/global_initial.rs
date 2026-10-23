//! Fresh global initial provenance and eligibility from the actual owner bind.
use super::global::GlobalWalletLease;
use super::*;
use cvld::client::AuthenticatedTransport;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InitialResponse {
    pub(super) seed: [u8; 32],
    pub(super) publication: Option<[u8; 32]>,
    pub(super) checked_at: u64,
}

/// A retained original wallet session whose latest operation was the genuine
/// eligible same-key initial publication bind. This is not community authority,
/// an admitted account, a passport, or permission to create replacement roots.
/// Custody must still join the exact original encrypted candidate and operation.
pub struct GlobalInitialCreationLease<T> {
    wallet: GlobalWalletLease<T>,
    seed: [u8; 32],
    publication: [u8; 32],
}

impl<T: AuthenticatedTransport> GlobalWalletLease<T> {
    /// Invoke the actual original initial-key CAS. Equal retries perform the
    /// same live eligibility checks on the server; the data-only provenance
    /// query is deliberately not an alternative to this operation.
    pub async fn bind_initial_creation(
        mut self,
        seed: [u8; 32],
        publication: [u8; 32],
        mut clock: impl FnMut() -> u64,
    ) -> Result<GlobalInitialCreationLease<T>> {
        if seed == [0; 32] || publication == [0; 32] {
            return Err(Error::Invalid);
        }
        self.bind_initial(seed, publication, &mut clock).await?;
        Ok(GlobalInitialCreationLease {
            wallet: self,
            seed,
            publication,
        })
    }
}

impl<T: AuthenticatedTransport> GlobalInitialCreationLease<T> {
    /// Original wallet UUID only; never a community pseudonym.
    pub fn user(&self) -> Result<&str> {
        self.wallet.user()
    }
    /// Exact original current login credential. The private candidate must be
    /// joined to this same CPky credential and its original PRF result.
    pub fn credential_id(&self) -> Result<&[u8]> {
        self.wallet.credential_id()
    }
    /// Immutable original candidate and publication commitments, not authority
    /// to reconstruct either private candidate from public server metadata.
    pub fn commitments(&self) -> Result<([u8; 32], [u8; 32])> {
        self.wallet.user()?;
        Ok((self.seed, self.publication))
    }
    /// Fresh actual eligible bind using the already-held original session, with
    /// no nested lock and no extension of its original exclusive deadline.
    /// Cancellation or any uncertain result permanently fences this handle.
    pub async fn refresh(&mut self, mut clock: impl FnMut() -> u64) -> Result<()> {
        self.wallet
            .bind_initial(self.seed, self.publication, &mut clock)
            .await
    }
    /// Final local-session/clock fence immediately after a fresh bind. It does
    /// not freeze remote eligibility; every later custody action must refresh.
    pub fn check(&mut self, clock: impl FnMut() -> u64) -> Result<u64> {
        self.wallet.check(clock)
    }
}
