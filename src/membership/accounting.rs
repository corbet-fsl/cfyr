//! Original account admission through one retained authenticated member session.
use super::*;
use crate::policy::CurrentPolicy;
use cvld::client::AuthenticatedTransport;
use serde_json::{Value, json};

/// Largest community credential accepted from the server.
pub const MAX_COMMUNITY_CREDENTIAL_BYTES: usize = 16 * 1024;

/// One original server challenge retained with its exact HTTPS/member owner.
/// The wallet must authenticate `signed_request` using its current Charter and
/// use the original global passport owner. This is not a passport or admission.
pub struct AccountChallenge<'p, T> {
    owner: AccountOwner<'p, T>,
    challenge: String,
    signed_request: Vec<u8>,
}

/// Actual account issuance response under the same retained current owner.
/// Public response fields remain data until the original account verifier joins
/// the independently authenticated challenge cohort, policy, device and intent.
pub struct AccountGrantLease<'p, T> {
    owner: AccountOwner<'p, T>,
    signed_request: Vec<u8>,
    grant: Value,
    credential: Vec<u8>,
    device: [u8; 32],
    enrollment_submitted: bool,
    apply_sent: bool,
}

struct AccountOwner<'p, T> {
    lease: MembershipLease<T>,
    policy: &'p mut CurrentPolicy<T>,
    origin: String,
    checked: bool,
}

impl<T> AccountOwner<'_, T> {
    fn check(&mut self, clock: &mut impl FnMut() -> u64) -> Result<u64> {
        if !self.checked {
            return Err(Error::Unauthorized);
        }
        self.checked = false;
        let now = self.lease.check(clock)?;
        self.policy.check_origin(&self.lease.owner, &self.origin)?;
        self.policy
            .with_current(now, |_| ())
            .map_err(|_| Error::Unauthorized)?;
        self.checked = true;
        Ok(now)
    }

    fn with_current<R>(
        &mut self,
        clock: &mut impl FnMut() -> u64,
        inspect: impl FnOnce(&cnvy::cchr::VerifiedCharter, &Observation, &str, u64) -> R,
    ) -> Result<R> {
        let now = self.check(clock)?;
        self.checked = false;
        let result = self
            .policy
            .with_current(now, |current| {
                inspect(current, &self.lease.observation, &self.origin, now)
            })
            .map_err(|_| Error::Unauthorized)?;
        self.checked = true;
        self.check(clock)?;
        Ok(result)
    }
}

impl<T: AuthenticatedTransport> AccountOwner<'_, T> {
    async fn call(
        &mut self,
        action: &str,
        input: Value,
        clock: &mut impl FnMut() -> u64,
    ) -> Result<Value> {
        self.check(clock)?;
        self.checked = false;
        self.lease.refresh_observation(clock).await?;
        let shared = self.lease.owner.upgrade().ok_or(Error::Unavailable)?;
        let (abort, registration) = AbortHandle::new_pair();
        {
            let mut lifetime = shared.lifetime.borrow_mut();
            if lifetime.closed
                || lifetime.generation != self.lease._pending.generation
                || lifetime.pending.is_none()
            {
                return Err(Error::Unavailable);
            }
            lifetime.pending = Some(abort);
        }
        // After the Record action starts, a lost response or failed fresh owner
        // observation cannot establish whether issuance committed. Never expose
        // an ordinary retryable failure for that uncertain write boundary.
        let after_send = |error| {
            if matches!(
                action,
                "account_credential_issue" | "account_enroll" | "account_checkpoint" | "account"
            ) {
                Error::Reconcile
            } else {
                error
            }
        };
        let response = Abortable::new(self.lease.held.client.forward(action, input), registration)
            .await
            .map_err(|_| after_send(Error::Unavailable))?
            .map_err(after_send)?;
        self.lease
            .refresh_observation(clock)
            .await
            .map_err(after_send)?;
        self.checked = true;
        self.check(clock).map_err(after_send)?;
        Ok(response)
    }
}

impl<T: AuthenticatedTransport> MembershipLease<T> {
    /// Fetch the original presentation challenge through this actual held HTTPS
    /// client. The generated owner registry validates its unchanged wire shape.
    pub async fn account_challenge<'p>(
        self,
        policy: &'p mut CurrentPolicy<T>,
        mut clock: impl FnMut() -> u64,
    ) -> Result<AccountChallenge<'p, T>> {
        let origin = self.held.client.authenticated_origin()?;
        policy.check_origin(&self.owner, &origin)?;
        let mut owner = AccountOwner {
            lease: self,
            policy,
            origin,
            checked: true,
        };
        let value = owner
            .call("presentation_challenge", json!({}), &mut clock)
            .await?;
        let challenge = value
            .get("challenge")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 4096)
            .ok_or(Error::Reconcile)?
            .to_owned();
        let signed_request: Vec<u8> =
            serde_json::from_value(value.get("request").cloned().ok_or(Error::Reconcile)?)
                .map_err(|_| Error::Reconcile)?;
        if signed_request.is_empty() || signed_request.len() > 65_536 {
            return Err(Error::Reconcile);
        }
        Ok(AccountChallenge {
            owner,
            challenge,
            signed_request,
        })
    }
}

impl<T> AccountChallenge<'_, T> {
    /// Reborrow the original current Charter and exact signed request. The
    /// callback must use the maintained request verifier; these bytes alone do
    /// not establish a global holder, cohort or account authority.
    pub fn with_current<R>(
        &mut self,
        mut clock: impl FnMut() -> u64,
        inspect: impl FnOnce(&cnvy::cchr::VerifiedCharter, &Observation, &str, &[u8], u64) -> R,
    ) -> Result<R> {
        let signed = &self.signed_request;
        self.owner
            .with_current(&mut clock, |current, member, origin, now| {
                inspect(current, member, origin, signed, now)
            })
    }
}

impl<'p, T: AuthenticatedTransport> AccountChallenge<'p, T> {
    /// Submit the original passport presentation for this exact challenge and
    /// one currently authorized logical device. Consumes the challenge even on
    /// uncertainty; it never signs a root, creates a holder or retries issuance.
    pub async fn finish(
        mut self,
        presentation: Vec<u8>,
        device: [u8; 32],
        mut clock: impl FnMut() -> u64,
    ) -> Result<AccountGrantLease<'p, T>> {
        self.owner.check(&mut clock)?;
        if presentation.is_empty()
            || presentation.len() > 1_048_576
            || !self.owner.lease.observation.device_keys.contains(&device)
        {
            return Err(Error::Unauthorized);
        }
        let response = self
            .owner
            .call(
                "account_credential_issue",
                json!({
                    "credential": { "presentation": {
                        "challenge": self.challenge, "proof": presentation
                    }, "devices": [device] }, "device": device
                }),
                &mut clock,
            )
            .await?;
        if !self.owner.lease.observation.device_keys.contains(&device)
            || response
                .get("lobby")
                .and_then(|l| l.get("member_id"))
                .and_then(Value::as_str)
                != Some(self.owner.lease.observation.member.as_str())
            || response.get("credential").is_none_or(Value::is_null)
        {
            return Err(Error::Reconcile);
        }
        // The same admission decision that issued the grant issued the community
        // credential. It is public signed data; the consumer stores it in the Vault.
        let credential: Vec<u8> = serde_json::from_value(
            response
                .get("credential")
                .cloned()
                .ok_or(Error::Reconcile)?,
        )
        .map_err(|_| Error::Reconcile)?;
        if credential.is_empty() || credential.len() > MAX_COMMUNITY_CREDENTIAL_BYTES {
            return Err(Error::Reconcile);
        }
        let grant = response
            .get("account")
            .filter(|a| a.is_object())
            .cloned()
            .ok_or(Error::Reconcile)?;
        Ok(AccountGrantLease {
            owner: self.owner,
            signed_request: self.signed_request,
            grant,
            credential,
            device,
            enrollment_submitted: false,
            apply_sent: false,
        })
    }
}

impl<T> AccountGrantLease<'_, T> {
    /// The signed community credential issued with this grant, exactly as the
    /// server returned it. It authorizes nothing by itself: Profile and Guard
    /// verify it, and the Vault stores it.
    pub fn community_credential(&self) -> &[u8] {
        &self.credential
    }

    /// Reborrow the actual current response owner. The account consumer must
    /// strictly decode the original grant and verify every independent binding.
    pub fn with_current<R>(
        &mut self,
        mut clock: impl FnMut() -> u64,
        inspect: impl FnOnce(
            &cnvy::cchr::VerifiedCharter,
            &Observation,
            &str,
            &[u8],
            &Value,
            [u8; 32],
            u64,
        ) -> R,
    ) -> Result<R> {
        let signed = &self.signed_request;
        let grant = &self.grant;
        let device = self.device;
        self.owner
            .with_current(&mut clock, |current, member, origin, now| {
                inspect(current, member, origin, signed, grant, device, now)
            })
    }
}

impl<T: AuthenticatedTransport> AccountGrantLease<'_, T> {
    /// Submit the original signed delegation once through this same current
    /// member owner. The generated registry validates its exact wire schema;
    /// the accounting consumer must still compare the original response with
    /// its verified delegation. This never installs a checkpoint or account.
    pub async fn submit_enrollment(
        &mut self,
        delegation: Value,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        if self.enrollment_submitted || !delegation.is_object() {
            return Err(Error::Unauthorized);
        }
        self.enrollment_submitted = true;
        self.owner
            .call("account_enroll", delegation, &mut clock)
            .await
    }
    /// Acquire the actual current common checkpoint through the same retained
    /// HTTPS owner. The fixed omitted slot may install a publication: uncertain
    /// completion is Reconcile, and response bytes remain unverified public data.
    pub async fn current_enrollment_checkpoint(
        &mut self,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        if !self.enrollment_submitted {
            return Err(Error::Unauthorized);
        }
        self.owner
            .call("account_checkpoint", json!({"slot": null}), &mut clock)
            .await
    }
    /// Send the exact stored, already signed account operation once through this
    /// same current member owner. The generated registry validates its wire
    /// schema. A reopened lease may send the same stored bytes, so this does not
    /// require an enrollment submitted by this lease. The uncertain outcome after
    /// sending is Reconcile; the consumer verifies the response independently.
    pub async fn apply_account(
        &mut self,
        wire: Value,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        if self.apply_sent || !wire.is_object() {
            return Err(Error::Unauthorized);
        }
        self.apply_sent = true;
        self.owner.call("account", wire, &mut clock).await
    }
}

impl<T: AuthenticatedTransport> MembershipLease<T> {
    /// Read the member's lobby (missing requirements and gate steps) through this
    /// held lease. Read-only; a changed member refuses.
    pub async fn lobby(&mut self, mut clock: impl FnMut() -> u64) -> Result<Value> {
        self.forward_gate("lobby", json!({}), false, &mut clock)
            .await
    }

    /// Submit one member-bound voucher, given in its `cvch1.` text form, through
    /// this held lease. The server decides admission; the answer is the lobby. A
    /// lost response is Reconcile, because the voucher may have been spent.
    pub async fn submit_voucher(
        &mut self,
        code: &str,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        let voucher = cvch::Voucher::from_code(code.trim()).map_err(|_| Error::Invalid)?;
        let voucher = serde_json::to_value(&voucher).map_err(|_| Error::Invalid)?;
        self.forward_gate("gate_voucher", voucher, true, &mut clock)
            .await
    }

    async fn forward_gate(
        &mut self,
        action: &str,
        input: Value,
        uncertain_after_send: bool,
        clock: &mut impl FnMut() -> u64,
    ) -> Result<Value> {
        if !matches!(self.scope, ObservationScope::Community) {
            return Err(Error::Unauthorized);
        }
        self.check(&mut *clock)?;
        self.refresh_observation(clock).await?;
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
        // Only a lost answer is uncertain; a verdict the server gave (refused,
        // invalid, throttled) is exactly that and stays plain.
        let after_send = |error| match error {
            Error::Unavailable if uncertain_after_send => Error::Reconcile,
            other => other,
        };
        let response = Abortable::new(self.held.client.forward(action, input), registration)
            .await
            .map_err(|_| after_send(Error::Unavailable))?
            .map_err(after_send)?;
        self.refresh_observation(clock).await.map_err(after_send)?;
        // Both gate answers are the lobby of exactly this member.
        if response.get("member_id").and_then(Value::as_str)
            != Some(self.observation.member.as_str())
        {
            return Err(Error::Reconcile);
        }
        Ok(response)
    }
}
