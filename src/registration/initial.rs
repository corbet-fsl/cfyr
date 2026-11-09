//! Data-only continuation of original community initial registration.
use super::*;
use cvld_client::client::AuthenticatedTransport;
use futures::future::Abortable;
use serde::Serialize;

const HEADER: &[u8] = b"cfyr.initial-finish.v1\0";
const MAX_FINISH_BYTES: usize = 512 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialChallenge {
    ceremony: String,
    user: String,
    options: Value,
    checked_at: u64,
    expires_at: u64,
}

/// Original live pending challenge, scoped to this Foyer and its current Charter.
/// It conveys no registration, membership, certificate or Keys permission.
pub struct PendingInitialRegistration<T> {
    owner: Weak<Shared<T>>,
    authentication: u64,
    origin: String,
    community: String,
    seed: [u8; 32],
    challenge: InitialChallenge,
    checked_at: u64,
    expires: u64,
}
impl<T> PendingInitialRegistration<T> {
    /// Original public options, unchanged for the maintained Passkeys owner.
    pub fn options(&self) -> &Value {
        &self.challenge.options
    }
    /// Original verified Charter community, never a session UUID conversion.
    pub fn community(&self) -> &str {
        &self.community
    }
    /// Opaque commitment sent to the original pending registration owner.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }
    /// Original exclusive deadline, bounded by the retained current Charter.
    pub fn expires_at(&self) -> u64 {
        self.expires
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishWire {
    origin: String,
    community: String,
    ceremony: String,
    user: String,
    seed: [u8; 32],
    raw_id: Vec<u8>,
    credential: Value,
    checked_at: u64,
    expires_at: u64,
}

/// Immutable public finish request data for the encrypted original Store.
/// Restoring this data never restores a successful registration, session or
/// passkey authority. Only the original server can accept its retained ceremony.
pub struct FinishContinuation(FinishWire);
impl FinishContinuation {
    /// Encode only this bounded data envelope for the composer's durable Store.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = HEADER.to_vec();
        bytes.extend(serde_json::to_vec(&self.0).map_err(|__cause| {
            crate::cause::emit(file!(), line!(), "Error::Invalid", Error::Invalid, &__cause)
        })?);
        if bytes.len() > MAX_FINISH_BYTES {
            return Err(Error::Invalid);
        }
        Ok(bytes)
    }
    /// Restore exact canonical request data, never an accepted owner capability.
    /// Duplicate/unknown envelope fields and noncanonical encodings refuse.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_FINISH_BYTES {
            return Err(Error::Invalid);
        }
        let wire: FinishWire = serde_json::from_slice(
            bytes.strip_prefix(HEADER).ok_or(Error::Invalid)?,
        )
        .map_err(|__cause| {
            crate::cause::emit(file!(), line!(), "Error::Invalid", Error::Invalid, &__cause)
        })?;
        if wire.origin.is_empty()
            || wire.community.is_empty()
            || wire.ceremony.is_empty()
            || wire.user.is_empty()
            || wire.raw_id.is_empty()
            || wire.seed == [0; 32]
            || wire.checked_at >= wire.expires_at
            || !wire.credential.is_object()
        {
            return Err(Error::Invalid);
        }
        let restored = Self(wire);
        if restored.to_bytes()? != bytes {
            return Err(Error::Invalid);
        }
        Ok(restored)
    }
    /// Retained opaque seed data only. This does not prove server acceptance.
    pub fn seed(&self) -> [u8; 32] {
        self.0.seed
    }
    /// Retained public routing data only. Fresh same-key server verification is
    /// required independently after any lost or unknown registration response.
    pub fn original_credential_id(&self) -> &[u8] {
        &self.0.raw_id
    }
}

fn policy<T>(owner: &Foyer<T>, origin: &str, now: u64) -> Result<(String, u64)> {
    let mut current = owner.current_policy();
    current.check_origin(&Rc::downgrade(&owner.shared), origin)?;
    current
        .with_current(now, |charter| {
            (charter.community().to_owned(), charter.valid_until())
        })
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

impl<T: AuthenticatedTransport> Foyer<T> {
    /// Begin the actual community initial ceremony under the same original
    /// HTTPS transport and live Charter. The opaque seed grants no authority.
    pub async fn begin_initial_registration(
        &mut self,
        passport: Value,
        seed: [u8; 32],
        mut clock: impl FnMut() -> u64,
    ) -> Result<PendingInitialRegistration<T>> {
        if seed == [0; 32] {
            return Err(Error::Invalid);
        }
        let shared = self.shared.clone();
        let (_pending, registration) = shared.begin_pending()?;
        let started = clock();
        Abortable::new(
            async {
                let mut held = shared.session.clone().lock_owned().await;
                let sending = clock();
                if shared.is_closed() || held.info.is_some() || sending < started {
                    return Err(Error::Unauthorized);
                }
                let origin = held.client.authenticated_origin()?;
                let (community, deadline) = policy(self, &origin, sending)?;
                let authentication = held.authentication;
                let response = held
                    .client
                    .forward(
                        "initial_registration_begin",
                        json!({
                            "passport":passport, "seed":seed,
                        }),
                    )
                    .await?;
                let completed = clock();
                let challenge: InitialChallenge =
                    serde_json::from_value(response).map_err(|__cause| {
                        crate::cause::emit(
                            file!(),
                            line!(),
                            "Error::Reconcile",
                            Error::Reconcile,
                            &__cause,
                        )
                    })?;
                let (current, until) = policy(self, &origin, completed)?;
                let expires = challenge.expires_at.min(deadline).min(until);
                if shared.is_closed()
                    || held.authentication != authentication
                    || held.info.is_some()
                    || completed < sending
                    || completed < challenge.checked_at
                    || completed >= expires
                    || current != community
                    || challenge.ceremony.is_empty()
                    || challenge.user.is_empty()
                {
                    return Err(Error::Unauthorized);
                }
                Ok(PendingInitialRegistration {
                    owner: Rc::downgrade(&shared),
                    authentication,
                    origin,
                    community,
                    seed,
                    challenge,
                    checked_at: completed,
                    expires,
                })
            },
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
        })?
    }

    /// Replay only the exact retained public finish data through the original
    /// owner. Success returns no RegisteredMember or RegisteredSession. Unknown
    /// or lost replies require fresh same-key UV and original seed/certificate
    /// checks; a later NotFound/Unauthorized never establishes prior absence.
    pub async fn resume_initial_registration(
        &mut self,
        continuation: FinishContinuation,
        mut clock: impl FnMut() -> u64,
    ) -> Result<()> {
        let shared = self.shared.clone();
        let (_pending, registration) = shared.begin_pending()?;
        let wire = continuation.0;
        let started = clock();
        Abortable::new(
            async {
                let mut held = shared.session.clone().lock_owned().await;
                let sending = clock();
                let origin = held.client.authenticated_origin()?;
                let (community, until) = policy(self, &origin, sending)?;
                let expires = wire.expires_at.min(until);
                if shared.is_closed()
                    || held.info.is_some()
                    || origin != wire.origin
                    || community != wire.community
                    || sending < started.max(wire.checked_at)
                    || sending >= expires
                {
                    return Err(Error::Unauthorized);
                }
                let authentication = held.authentication;
                let response = held
                    .client
                    .forward(
                        "register_finish",
                        json!({
                            "ceremony":wire.ceremony, "credential":wire.credential,
                        }),
                    )
                    .await?;
                // The original insertion may now be durable. Every local refusal
                // after this await is reconciliation, never inferred absence.
                let completed = clock();
                let (current, until) = policy(self, &origin, completed).map_err(|__cause| {
                    crate::cause::emit(
                        file!(),
                        line!(),
                        "Error::Reconcile",
                        Error::Reconcile,
                        &__cause,
                    )
                })?;
                let result: Completed = serde_json::from_value(response).map_err(|__cause| {
                    crate::cause::emit(
                        file!(),
                        line!(),
                        "Error::Reconcile",
                        Error::Reconcile,
                        &__cause,
                    )
                })?;
                if shared.is_closed()
                    || held.info.is_some()
                    || held.authentication != authentication
                    || completed < sending
                    || completed >= expires.min(until)
                    || current != community
                    || result.user != wire.user
                {
                    return Err(Error::Reconcile);
                }
                Ok(())
            },
            registration,
        )
        .await
        .map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Reconcile",
                Error::Reconcile,
                &__cause,
            )
        })?
    }
}

impl<T: AuthenticatedTransport> PendingInitialRegistration<T> {
    /// Consume the live challenge and the original CPky public response into
    /// data for a durable write before finish. The original server still checks
    /// the precise WebAuthn ceremony; preparing data does not accept that proof.
    pub async fn prepare_finish(
        self,
        owner: &Foyer<T>,
        credential: cpky::PublicCredential,
        mut clock: impl FnMut() -> u64,
    ) -> Result<FinishContinuation> {
        if !self.owner.ptr_eq(&Rc::downgrade(&owner.shared)) {
            return Err(Error::Unauthorized);
        }
        let shared = owner.shared.clone();
        let (_pending, registration) = shared.begin_pending()?;
        let started = clock();
        Abortable::new(
            async {
                let held = shared.session.clone().lock_owned().await;
                let now = clock();
                let origin = held.client.authenticated_origin()?;
                let (community, until) = policy(owner, &origin, now)?;
                let expires = self.expires.min(until);
                if shared.is_closed()
                    || held.info.is_some()
                    || held.authentication != self.authentication
                    || origin != self.origin
                    || community != self.community
                    || now < started.max(self.checked_at)
                    || now >= expires
                {
                    return Err(Error::Unauthorized);
                }
                let raw_id = credential.credential_id().map_err(|__cause| {
                    crate::cause::emit(file!(), line!(), "Error::Invalid", Error::Invalid, &__cause)
                })?;
                let finished = FinishContinuation(FinishWire {
                    origin,
                    community,
                    ceremony: self.challenge.ceremony,
                    user: self.challenge.user,
                    seed: self.seed,
                    raw_id,
                    credential: credential.into_json(),
                    checked_at: now,
                    expires_at: expires,
                });
                // Bound the exact public data before the composer commits it.
                finished.to_bytes()?;
                Ok(finished)
            },
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
        })?
    }
}
