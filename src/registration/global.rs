//! Original global wallet enrollment, isolated from community membership.
use super::*;
use cvld::client::AuthenticatedTransport;
use futures::future::Abortable;
use serde::Serialize;

const HEADER: &[u8] = b"cfyr.global-initial-finish.v1\0";
const MAX_BYTES: usize = 512 * 1024;

/// Original server-generated wallet UUID before Passkeys registration. This is
/// pending lifecycle data, never an authenticated account or community member.
pub struct GlobalRegistrationReservation<T> {
    owner: Weak<Shared<T>>,
    authentication: u64,
    origin: String,
    challenge: Challenge,
    checked_at: Option<u64>,
    seed: Option<[u8; 32]>,
    completed: bool,
}
impl<T> GlobalRegistrationReservation<T> {
    /// Original global UUID, for the private literal `wallet` custody scope only.
    pub fn account(&self) -> &str {
        &self.challenge.user
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialChallenge {
    ceremony: String,
    user: String,
    options: Value,
    checked_at: u64,
    expires_at: u64,
}

/// The genuine refreshed challenge bound to the frozen seed before CPky runs.
/// Neither the seed nor this pending handle grants registration or Create.
pub struct PendingGlobalInitialRegistration<T> {
    owner: Weak<Shared<T>>,
    authentication: u64,
    origin: String,
    seed: [u8; 32],
    challenge: InitialChallenge,
    checked_at: u64,
}
impl<T> PendingGlobalInitialRegistration<T> {
    /// Unchanged original challenge for the maintained Passkeys owner.
    pub fn options(&self) -> &Value {
        &self.challenge.options
    }
    /// Exact pending global account UUID; never a community pseudonym.
    pub fn account(&self) -> &str {
        &self.challenge.user
    }
    /// Original opaque seed commitment; this proves no acceptance.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }
    /// Original absolute server deadline, never extended by continuation.
    pub fn expires_at(&self) -> u64 {
        self.challenge.expires_at
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishWire {
    origin: String,
    ceremony: String,
    account: String,
    seed: [u8; 32],
    raw_id: Vec<u8>,
    credential: Value,
    checked_at: u64,
    expires_at: u64,
}

/// Exact public finish data to retain inside the original encrypted candidate
/// before accepting registration. Decoding never reconstructs session authority.
pub struct GlobalFinishContinuation(FinishWire);
impl GlobalFinishContinuation {
    /// Canonical bounded data for durable original Storage, with no secrets.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = HEADER.to_vec();
        bytes.extend(serde_json::to_vec(&self.0).map_err(|_| Error::Invalid)?);
        if bytes.len() > MAX_BYTES {
            return Err(Error::Invalid);
        }
        Ok(bytes)
    }
    /// Decode replay data only; the original server still verifies the ceremony.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::Invalid);
        }
        let wire: FinishWire =
            serde_json::from_slice(bytes.strip_prefix(HEADER).ok_or(Error::Invalid)?)
                .map_err(|_| Error::Invalid)?;
        if wire.origin.is_empty()
            || wire.ceremony.is_empty()
            || wire.account.is_empty()
            || wire.seed == [0; 32]
            || wire.raw_id.is_empty()
            || !wire.credential.is_object()
            || wire.checked_at >= wire.expires_at
        {
            return Err(Error::Invalid);
        }
        let value = Self(wire);
        if value.to_bytes()? != bytes {
            return Err(Error::Invalid);
        }
        Ok(value)
    }
    /// Original global routing data, requiring a fresh same-key login afterward.
    pub fn account(&self) -> &str {
        &self.0.account
    }
    /// Original opaque candidate identity, never inferred server acceptance.
    pub fn seed(&self) -> [u8; 32] {
        self.0.seed
    }
    /// Original CPky credential ID retained with its actual public response.
    pub fn original_credential_id(&self) -> &[u8] {
        &self.0.raw_id
    }
}

impl<T: AuthenticatedTransport> Foyer<T> {
    /// Start only a wallet-member ceremony at this trusted runtime's exact
    /// authenticated global HTTPS origin. No caller account UUID or operator
    /// bootstrap is accepted; the old options are deliberately not exposed.
    pub async fn begin_global_initial_registration(
        &mut self,
        trusted_origin: &str,
        mut clock: impl FnMut() -> u64,
    ) -> Result<GlobalRegistrationReservation<T>> {
        let shared = self.shared.clone();
        let (_pending, registration) = shared.begin_pending()?;
        let started = clock();
        Abortable::new(
            async {
                let mut held = shared.session.clone().lock_owned().await;
                let sending = clock();
                let origin = held.client.authenticated_origin()?;
                if shared.is_closed()
                    || held.info.is_some()
                    || origin != trusted_origin
                    || sending < started
                {
                    return Err(Error::Unauthorized);
                }
                let authentication = held.authentication;
                held.client.forward("global_public", json!({})).await?;
                let observed = clock();
                if observed < sending || shared.is_closed() {
                    return Err(Error::Unauthorized);
                }
                let response = held
                    .client
                    .forward("register_begin", json!({"bootstrap":null,"passport":null}))
                    .await?;
                let completed = clock();
                let challenge: Challenge =
                    serde_json::from_value(response).map_err(|_| Error::Reconcile)?;
                if completed < observed
                    || shared.is_closed()
                    || held.info.is_some()
                    || held.authentication != authentication
                    || challenge.user.is_empty()
                    || challenge.ceremony.is_empty()
                {
                    return Err(Error::Reconcile);
                }
                Ok(GlobalRegistrationReservation {
                    owner: Rc::downgrade(&shared),
                    authentication,
                    origin,
                    challenge,
                    checked_at: Some(completed),
                    seed: None,
                    completed: false,
                })
            },
            registration,
        )
        .await
        .map_err(|_| Error::Unavailable)?
    }

    /// Submit only exact durably retained global finish data. Success conveys no
    /// eligibility, certificate or Keys authority; lost replies reconcile through actual
    /// same-key authentication and original initial provenance.
    ///
    /// When the wallet answers with its birth session (one-ceremony registration, C1), this
    /// Foyer adopts it as its login of the just-registered credential, exactly as a login
    /// would: it carries the birth grant for the account's first device bind, genesis
    /// statement, stamp and passport. Without one the Foyer stays logged out.
    pub async fn resume_global_initial_registration(
        &mut self,
        continuation: GlobalFinishContinuation,
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
                if shared.is_closed()
                    || held.info.is_some()
                    || held.client.authenticated_origin()? != wire.origin
                    || sending < started.max(wire.checked_at)
                    || sending >= wire.expires_at
                {
                    return Err(Error::Unauthorized);
                }
                let authentication = held.authentication;
                held.client.forward("global_public", json!({})).await?;
                let observed = clock();
                if observed < sending || observed >= wire.expires_at || shared.is_closed() {
                    return Err(Error::Unauthorized);
                }
                // A birth session replaces this logged-out Foyer's session: earlier stamps
                // of this owner end here, as before any login.
                held.authentication = held
                    .authentication
                    .checked_add(1)
                    .ok_or(Error::Unavailable)?;
                let (response, session) = held
                    .client
                    .finish_registration(
                        json!({"ceremony":wire.ceremony,"credential":wire.credential}),
                    )
                    .await
                    .map_err(|_| Error::Reconcile)?;
                let completed = clock();
                let actual: Completed =
                    serde_json::from_value(response).map_err(|_| Error::Reconcile)?;
                if completed < observed
                    || completed >= wire.expires_at
                    || shared.is_closed()
                    || held.info.is_some()
                    || held.authentication != authentication + 1
                    || actual.user != wire.account
                    || actual.certificate.is_some()
                {
                    return Err(Error::Reconcile);
                }
                if let Some(info) = session {
                    if info.user != wire.account
                        || info.role != "member"
                        || completed >= info.expires
                    {
                        return Err(Error::Reconcile);
                    }
                    held.info = Some(info);
                    held.login_credential = Some(wire.raw_id.clone());
                    held.device_session = false;
                }
                Ok(())
            },
            registration,
        )
        .await
        .map_err(|_| Error::Reconcile)?
    }
}

impl<T: AuthenticatedTransport> GlobalRegistrationReservation<T> {
    /// Bind the already frozen original candidate seed to the same server UUID
    /// and pending ceremony before running CPky. The original deadline remains.
    pub async fn continue_initial(
        &mut self,
        owner: &Foyer<T>,
        seed: [u8; 32],
        mut clock: impl FnMut() -> u64,
    ) -> Result<PendingGlobalInitialRegistration<T>> {
        if seed == [0; 32]
            || self.completed
            || self.seed.is_some_and(|original| original != seed)
            || !self.owner.ptr_eq(&Rc::downgrade(&owner.shared))
        {
            return Err(Error::Unauthorized);
        }
        let floor = self.checked_at.take().ok_or(Error::Unauthorized)?;
        let started = clock();
        if started < floor {
            return Err(Error::Unauthorized);
        }
        // Fence the exact seed and every observed clock before an await. A lost
        // response may retry only this same original server ceremony and seed.
        self.seed = Some(seed);
        self.checked_at = Some(started);
        let shared = owner.shared.clone();
        let (_pending, registration) = shared.begin_pending()?;
        Abortable::new(
            async {
                let mut held = shared.session.clone().lock_owned().await;
                let floor = self.checked_at.take().ok_or(Error::Unauthorized)?;
                let sending = clock();
                if shared.is_closed()
                    || held.info.is_some()
                    || held.authentication != self.authentication
                    || held.client.authenticated_origin()? != self.origin
                    || sending < floor
                {
                    return Err(Error::Unauthorized);
                }
                self.checked_at = Some(sending);
                let response = held
                    .client
                    .forward(
                        "global_initial_registration_continue",
                        json!({"ceremony":self.challenge.ceremony,"seed":seed}),
                    )
                    .await
                    .map_err(|_| Error::Reconcile)?;
                self.checked_at.take().ok_or(Error::Unauthorized)?;
                let completed = clock();
                let challenge: InitialChallenge =
                    serde_json::from_value(response).map_err(|_| Error::Reconcile)?;
                if shared.is_closed()
                    || held.info.is_some()
                    || held.authentication != self.authentication
                    || challenge.ceremony != self.challenge.ceremony
                    || challenge.user != self.challenge.user
                    || completed < sending.max(challenge.checked_at)
                    || completed >= challenge.expires_at
                {
                    return Err(Error::Reconcile);
                }
                self.checked_at = Some(completed);
                self.completed = true;
                Ok(PendingGlobalInitialRegistration {
                    owner: self.owner.clone(),
                    authentication: self.authentication,
                    origin: self.origin.clone(),
                    seed,
                    challenge,
                    checked_at: completed,
                })
            },
            registration,
        )
        .await
        .map_err(|_| Error::Reconcile)?
    }
}

impl<T: AuthenticatedTransport> PendingGlobalInitialRegistration<T> {
    /// Retain the actual CPky public response with this pending original owner.
    /// The caller must join the inseparable PRF result and persist before finish.
    pub async fn prepare_finish(
        self,
        owner: &Foyer<T>,
        credential: cpky::PublicCredential,
        mut clock: impl FnMut() -> u64,
    ) -> Result<GlobalFinishContinuation> {
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
                if shared.is_closed()
                    || held.info.is_some()
                    || held.authentication != self.authentication
                    || held.client.authenticated_origin()? != self.origin
                    || now < started.max(self.checked_at)
                    || now >= self.challenge.expires_at
                {
                    return Err(Error::Unauthorized);
                }
                let value = GlobalFinishContinuation(FinishWire {
                    origin: self.origin,
                    ceremony: self.challenge.ceremony,
                    account: self.challenge.user,
                    seed: self.seed,
                    raw_id: credential.credential_id().map_err(|_| Error::Invalid)?,
                    credential: credential.into_json(),
                    checked_at: now,
                    expires_at: self.challenge.expires_at,
                });
                value.to_bytes()?;
                Ok(value)
            },
            registration,
        )
        .await
        .map_err(|_| Error::Unavailable)?
    }
}
