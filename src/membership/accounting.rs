//! Original account admission through one retained authenticated member session.
use super::*;
use crate::policy::CurrentPolicy;
use cvld_client::client::AuthenticatedTransport;
use serde_json::{Value, json};

/// Largest community credential accepted from the server.
pub const MAX_COMMUNITY_CREDENTIAL_BYTES: usize = 16 * 1024;

/// The lobby after presenting a voucher link, and the bond secret both devices
/// derive. The bond belongs in vault custody; it is only usable once admitted.
pub struct VoucherRedeemed {
    /// The member's own lobby.
    pub lobby: Value,
    /// Bond secret shared with the issuer's device.
    pub bond: cvch::link::Bond,
}

/// One original server challenge retained with its exact HTTPS/member owner.
/// The wallet must authenticate `signed_request` using its current Charter and
/// use the original global passport owner. This is not a passport or admission.
pub struct AccountChallenge<'p, T> {
    owner: AccountOwner<'p, T>,
    challenge: String,
    signed_request: Vec<u8>,
    /// Creation id presented with the admission of a community's creator.
    creation: Option<String>,
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
    enrollment: EnrollmentSends,
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
        self.revalidate(clock)
    }

    /// The full current-owner validation without the `checked` precondition: it
    /// re-establishes `checked` only when every check passes again. Used to resume
    /// after a failed call, never to skip a check.
    fn revalidate(&mut self, clock: &mut impl FnMut() -> u64) -> Result<u64> {
        self.checked = false;
        let now = self.lease.check(clock)?;
        self.policy.check_origin(&self.lease.owner, &self.origin)?;
        self.policy.with_current(now, |_| ()).map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Unauthorized",
                Error::Unauthorized,
                &__cause,
            )
        })?;
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
            .map_err(|__cause| {
                crate::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unauthorized",
                    Error::Unauthorized,
                    &__cause,
                )
            })?;
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
        // The one certain answer after sending: the owner refused before its
        // commitment because the request window had elapsed (409, reason expired).
        let response = Abortable::new(self.lease.held.client.forward(action, input), registration)
            .await
            .map_err(|__cause| {
                crate::cause::emit(
                    file!(),
                    line!(),
                    "after_send Error::Unavailable",
                    after_send(Error::Unavailable),
                    &__cause,
                )
            })?
            .map_err(|error| match error {
                Error::Expired => error,
                error => after_send(error),
            })?;
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
                .map_err(|__cause| {
                    crate::cause::emit(
                        file!(),
                        line!(),
                        "Error::Reconcile",
                        Error::Reconcile,
                        &__cause,
                    )
                })?;
        if signed_request.is_empty() || signed_request.len() > 65_536 {
            return Err(Error::Reconcile);
        }
        Ok(AccountChallenge {
            owner,
            challenge,
            signed_request,
            creation: None,
        })
    }
}

impl<T> AccountChallenge<'_, T> {
    /// Present the creation id of a community this member just claimed, so the
    /// same admission decision seats the creator as first admin.
    pub fn with_creation(mut self, id: String) -> Self {
        self.creation = Some(id);
        self
    }

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
        let mut credential = json!({ "presentation": {
            "challenge": self.challenge, "proof": presentation
        }, "devices": [device] });
        if let Some(id) = &self.creation {
            credential["creation"] = json!(id);
        }
        let response = self
            .owner
            .call(
                "account_credential_issue",
                json!({ "credential": credential, "device": device }),
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
        .map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Reconcile",
                Error::Reconcile,
                &__cause,
            )
        })?;
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
            enrollment: EnrollmentSends::default(),
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

/// The one enrollment request of a lease and its single permitted resend. The
/// request is stored when first submitted and only ever cloned back out.
#[derive(Default)]
struct EnrollmentSends {
    request: Option<Value>,
    failed: bool,
    resent: bool,
}

impl EnrollmentSends {
    fn first(&mut self, request: Value) -> Result<Value> {
        if self.request.is_some() {
            return Err(Error::Unauthorized);
        }
        self.request = Some(request.clone());
        Ok(request)
    }
    fn failed(&mut self) {
        self.failed = true;
    }
    fn resend(&mut self) -> Result<Value> {
        match &self.request {
            Some(request) if self.failed && !self.resent => {
                self.resent = true;
                Ok(request.clone())
            }
            _ => Err(Error::Unauthorized),
        }
    }
}

#[cfg(test)]
mod enrollment_sends_tests {
    use super::*;

    #[test]
    fn one_resend_of_the_identical_first_request_after_a_failure() {
        let first = json!({"delegation": [1, 2, 3], "n": 7});
        let mut sends = EnrollmentSends::default();
        // No resend before any submission.
        assert!(matches!(sends.resend(), Err(Error::Unauthorized)));
        assert_eq!(sends.first(first.clone()).unwrap(), first);
        // No resend while the first submission has not failed.
        assert!(matches!(sends.resend(), Err(Error::Unauthorized)));
        sends.failed();
        let again = sends.resend().unwrap();
        assert_eq!(
            serde_json::to_vec(&again).unwrap(),
            serde_json::to_vec(&first).unwrap()
        );
        // A second resend is refused.
        assert!(matches!(sends.resend(), Err(Error::Unauthorized)));
    }

    #[test]
    fn a_different_second_enrollment_is_refused_per_lease() {
        let mut sends = EnrollmentSends::default();
        sends.first(json!({"a": 1})).unwrap();
        assert!(matches!(
            sends.first(json!({"a": 2})),
            Err(Error::Unauthorized)
        ));
        sends.failed();
        // The resend still carries the first bytes, never the refused second ones.
        assert_eq!(sends.resend().unwrap(), json!({"a": 1}));
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
        if !delegation.is_object() {
            return Err(Error::Unauthorized);
        }
        let request = self.enrollment.first(delegation)?;
        let result = self.owner.call("account_enroll", request, &mut clock).await;
        if result.is_err() {
            self.enrollment.failed();
        }
        result
    }
    /// After the first submission ended in Reconcile (the write may or may not have
    /// been applied), send the EXACT bytes of that first submission once more. The
    /// owner registry answers an identical replay with the original entry and
    /// refuses different content. No API takes new bytes; a second resend, a resend
    /// before a failed first submission, or one after success is refused.
    pub async fn resend_enrollment(&mut self, mut clock: impl FnMut() -> u64) -> Result<Value> {
        let request = self.enrollment.resend()?;
        self.owner.revalidate(&mut clock)?;
        self.owner.call("account_enroll", request, &mut clock).await
    }
    /// Acquire the actual current common checkpoint through the same retained
    /// HTTPS owner. The fixed omitted slot may install a publication: uncertain
    /// completion is Reconcile, and response bytes remain unverified public data.
    pub async fn current_enrollment_checkpoint(
        &mut self,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        if self.enrollment.request.is_none() {
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

    /// Whether a community handle is free and well-formed. Read-only. A malformed
    /// handle is Invalid; a taken one is `false`.
    pub async fn handle_available(
        &mut self,
        handle: &str,
        mut clock: impl FnMut() -> u64,
    ) -> Result<bool> {
        let answer = self
            .forward_member(
                "handle_available",
                json!({ "handle": handle }),
                false,
                &mut clock,
            )
            .await?;
        answer
            .get("available")
            .and_then(Value::as_bool)
            .ok_or(Error::Reconcile)
    }

    /// Reserve the member's chosen handle through this held lease. The answer is
    /// the lobby of exactly this member. A lost answer is Reconcile: the handle
    /// may have been reserved, and the lobby then shows it.
    pub async fn reserve_handle(
        &mut self,
        handle: &str,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        self.forward_gate(
            "handle_reserve",
            json!({ "handle": handle }),
            true,
            &mut clock,
        )
        .await
    }

    /// Present one voucher link, given as the text after `#` in its URL, through
    /// this held lease. `nonce` is this device's bond contribution; keep it with
    /// the pending join and pass the same value on every retry, because the
    /// issuer's device derives the bond from the first notice it receives. The
    /// `key_package` is the newcomer device's single-use Threads key package
    /// (empty when none is offered); it travels only inside the sealed notice.
    /// The notice is sealed to the issuer's device here; the server relays it opaque.
    /// The server decides admission (a link with sign-off keeps the member in the
    /// lobby until the issuer confirms); the answer is the lobby. A lost response
    /// is Reconcile, because the link may have been used.
    pub async fn submit_voucher(
        &mut self,
        link: &str,
        handle: Option<&str>,
        nonce: [u8; cvch::link::NONCE_BYTES],
        key_package: &[u8],
        mut clock: impl FnMut() -> u64,
    ) -> Result<VoucherRedeemed> {
        let token =
            cvch::link::Token::parse(link.trim().trim_start_matches('#')).map_err(|__cause| {
                crate::cause::emit(file!(), line!(), "Error::Invalid", Error::Invalid, &__cause)
            })?;
        let member = self.observation.member.clone();
        let notice = cvch::link::Notice {
            member: member.clone(),
            nonce,
            handle: handle.map(str::to_owned),
            key_package: key_package.to_vec(),
        };
        let request = cvch::link::Request::new(&token, &notice).map_err(|__cause| {
            crate::cause::emit(file!(), line!(), "Error::Invalid", Error::Invalid, &__cause)
        })?;
        let lobby = self
            .forward_gate(
                "voucher_redeem",
                json!({"id": request.id, "secret": request.secret, "notice": request.notice}),
                true,
                &mut clock,
            )
            .await?;
        Ok(VoucherRedeemed {
            lobby,
            bond: token.bond(&member, &nonce),
        })
    }

    /// Begin a fresh user-verifying passkey assertion for exactly one account
    /// action (`passkey_add`, `passkey_revoke` or `device_authorize`). Nothing
    /// changes on the server; the answer carries the ceremony and WebAuthn options
    /// for the member's ordinary ceremony path (browser vault frame or the embedded
    /// authenticator). The assertion itself never passes through here.
    pub async fn step_up_begin(
        &mut self,
        action: StepUpAction<'_>,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        let wire = action.wire();
        let begun = clock();
        let answer = self
            .forward_member(
                "step_up_begin",
                json!({ "action": wire.clone() }),
                false,
                &mut clock,
            )
            .await?;
        // One outstanding step-up per lease: a new begin replaces the old one.
        self.step_up = answer
            .get("ceremony")
            .and_then(Value::as_str)
            .map(|ceremony| PendingStepUp {
                ceremony: ceremony.into(),
                action: wire,
                begun,
            });
        Ok(answer)
    }

    /// Consume the lease's single outstanding step-up: it must be the one this
    /// proof answers, begun on this lease for exactly this action, and fresh.
    fn take_step_up(
        &mut self,
        action: &StepUpAction<'_>,
        proof: &StepUpProof,
        now: u64,
    ) -> Result<()> {
        let pending = self.step_up.take().ok_or(Error::Unauthorized)?;
        if pending.ceremony != proof.ceremony
            || pending.action != action.wire()
            || now < pending.begun
            || now - pending.begun > STEP_UP_FRESH_SECONDS
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    /// Bind one lineage device key to this account with a completed step-up
    /// assertion for exactly that key. The answer lists the account's current
    /// device keys and must contain the new one. A lost answer is Reconcile: the
    /// key may have been bound.
    pub async fn device_authorize(
        &mut self,
        key: [u8; 32],
        step_up: StepUpProof,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        self.take_step_up(&StepUpAction::DeviceAuthorize { key }, &step_up, clock())?;
        let response = self
            .forward_member(
                "device_authorize",
                json!({ "key": key, "step_up": step_up.wire() }),
                true,
                &mut clock,
            )
            .await?;
        let listed = response
            .get("keys")
            .and_then(Value::as_array)
            .is_some_and(|keys| keys.contains(&json!(key)));
        if !listed || !self.observation.device_keys.contains(&key) {
            return Err(Error::Reconcile);
        }
        Ok(response)
    }

    /// Pairing, new device's own session: authorize its key as PENDING with a step-up for
    /// exactly that key. A pending key grants nothing and expires on its own, so the answer
    /// and the observation must NOT list it yet. A lost answer is Reconcile.
    pub async fn device_pair_authorize(
        &mut self,
        key: [u8; 32],
        step_up: StepUpProof,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        self.take_step_up(&StepUpAction::DeviceAuthorize { key }, &step_up, clock())?;
        let response = self
            .forward_member(
                "device_pair_authorize",
                json!({ "key": key, "step_up": step_up.wire() }),
                true,
                &mut clock,
            )
            .await?;
        if lists(&response, &key) || self.observation.device_keys.contains(&key) {
            return Err(Error::Reconcile);
        }
        Ok(response)
    }

    /// Pairing, existing device's session: approve the new device's pending key with a
    /// step-up for exactly that key, after the lineage revision containing it is published.
    /// The key stays pending (not live) until the new device confirms; the answer must not
    /// list it yet. A lost answer is Reconcile.
    pub async fn device_approve(
        &mut self,
        key: [u8; 32],
        step_up: StepUpProof,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        self.take_step_up(&StepUpAction::DeviceApprove { key }, &step_up, clock())?;
        let response = self
            .forward_member(
                "device_approve",
                json!({ "key": key, "step_up": step_up.wire() }),
                true,
                &mut clock,
            )
            .await?;
        if lists(&response, &key) || self.observation.device_keys.contains(&key) {
            return Err(Error::Reconcile);
        }
        Ok(response)
    }

    /// Pairing: make this session's pending key live, after its lineage revision is
    /// published. The answer and the refreshed observation must list it. A lost answer is
    /// Reconcile (the confirmation may have happened).
    pub async fn device_confirm(
        &mut self,
        key: [u8; 32],
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        let response = self
            .forward_member("device_confirm", json!({ "key": key }), true, &mut clock)
            .await?;
        if !lists(&response, &key) || !self.observation.device_keys.contains(&key) {
            return Err(Error::Reconcile);
        }
        Ok(response)
    }

    /// Remove one device key (live or pending) of this account with a step-up for exactly
    /// that key. The answer and the refreshed observation must no longer list it. A lost
    /// answer is Reconcile.
    pub async fn device_revoke(
        &mut self,
        key: [u8; 32],
        step_up: StepUpProof,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        self.take_step_up(&StepUpAction::DeviceRevoke { key }, &step_up, clock())?;
        let response = self
            .forward_member(
                "device_revoke",
                json!({ "key": key, "step_up": step_up.wire() }),
                true,
                &mut clock,
            )
            .await?;
        if lists(&response, &key) || self.observation.device_keys.contains(&key) {
            return Err(Error::Reconcile);
        }
        Ok(response)
    }

    /// First half of registering another passkey: the server's registration
    /// challenge for the step-up-authorized request.
    pub async fn passkey_add_begin(
        &mut self,
        step_up: StepUpProof,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        self.take_step_up(&StepUpAction::PasskeyAdd, &step_up, clock())?;
        self.adding = None;
        let answer = self
            .forward_member(
                "passkey_add",
                json!({ "step": "begin", "step_up": step_up.wire() }),
                false,
                &mut clock,
            )
            .await?;
        // Exactly a registration challenge, never another step's answer.
        let ceremony = (answer.get("step").and_then(Value::as_str) == Some("challenge"))
            .then(|| answer.get("ceremony").and_then(Value::as_str))
            .flatten()
            .ok_or(Error::Reconcile)?;
        self.adding = Some(ceremony.into());
        Ok(answer)
    }

    /// Second half: the new passkey's registration. A lost answer is Reconcile.
    pub async fn passkey_add_finish(
        &mut self,
        ceremony: &str,
        credential: Value,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        if self.adding.as_deref() != Some(ceremony) {
            return Err(Error::Unauthorized);
        }
        self.adding = None;
        let answer = self
            .forward_member(
                "passkey_add",
                json!({ "step": "finish", "ceremony": ceremony, "credential": credential }),
                true,
                &mut clock,
            )
            .await?;
        let registered = answer.get("step").and_then(Value::as_str) == Some("registered")
            && answer
                .get("credential")
                .and_then(Value::as_array)
                .is_some_and(|id| !id.is_empty());
        if !registered {
            return Err(Error::Reconcile);
        }
        Ok(answer)
    }

    /// Revoke one passkey of this account with a step-up assertion for exactly
    /// that credential. A lost answer is Reconcile.
    pub async fn passkey_revoke(
        &mut self,
        credential: &[u8],
        step_up: StepUpProof,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Value> {
        self.take_step_up(
            &StepUpAction::PasskeyRevoke { credential },
            &step_up,
            clock(),
        )?;
        let answer = self
            .forward_member(
                "passkey_revoke",
                json!({ "credential": credential, "step_up": step_up.wire() }),
                true,
                &mut clock,
            )
            .await?;
        // The server answers Empty; anything else is not this action's answer.
        if answer.as_object().is_none_or(|fields| !fields.is_empty()) {
            return Err(Error::Reconcile);
        }
        Ok(answer)
    }

    async fn forward_gate(
        &mut self,
        action: &str,
        input: Value,
        uncertain_after_send: bool,
        clock: &mut impl FnMut() -> u64,
    ) -> Result<Value> {
        let response = self
            .forward_member(action, input, uncertain_after_send, clock)
            .await?;
        // Both gate answers are the lobby of exactly this member.
        if response.get("member_id").and_then(Value::as_str)
            != Some(self.observation.member.as_str())
        {
            return Err(Error::Reconcile);
        }
        Ok(response)
    }

    async fn forward_member(
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
            .map_err(|__cause| {
                crate::cause::emit(
                    file!(),
                    line!(),
                    "after_send Error::Unavailable",
                    after_send(Error::Unavailable),
                    &__cause,
                )
            })?
            .map_err(after_send)?;
        self.refresh_observation(clock).await.map_err(after_send)?;
        Ok(response)
    }
}

fn lists(response: &Value, key: &[u8; 32]) -> bool {
    response
        .get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| keys.contains(&json!(key)))
}

const STEP_UP_FRESH_SECONDS: u64 = 120;

/// The step-up this lease began and has not yet spent.
pub(crate) struct PendingStepUp {
    ceremony: String,
    action: Value,
    begun: u64,
}

/// The one account-authority action a step-up assertion authorizes.
#[derive(Clone, Copy, Debug)]
pub enum StepUpAction<'a> {
    /// Begin registering another passkey.
    PasskeyAdd,
    /// Revoke this exact passkey.
    PasskeyRevoke {
        /// Credential id of the passkey to revoke.
        credential: &'a [u8],
    },
    /// Authorize this exact device signing key.
    DeviceAuthorize {
        /// The device's public signing key.
        key: [u8; 32],
    },
    /// Approve this pending device signing key from the existing device's passkey.
    DeviceApprove {
        /// The device's public signing key.
        key: [u8; 32],
    },
    /// Remove this exact device signing key, live or pending.
    DeviceRevoke {
        /// The device's public signing key.
        key: [u8; 32],
    },
}

impl StepUpAction<'_> {
    fn wire(&self) -> Value {
        match self {
            Self::PasskeyAdd => json!({ "kind": "passkey_add" }),
            Self::PasskeyRevoke { credential } => {
                json!({ "kind": "passkey_revoke", "credential": credential })
            }
            Self::DeviceAuthorize { key } => json!({ "kind": "device_authorize", "key": key }),
            Self::DeviceApprove { key } => json!({ "kind": "device_approve", "key": key }),
            Self::DeviceRevoke { key } => json!({ "kind": "device_revoke", "key": key }),
        }
    }
}

/// A completed step-up assertion: the ceremony `step_up_begin` returned and the
/// credential the member's authenticator produced for it.
#[derive(Clone, Debug)]
pub struct StepUpProof {
    ceremony: String,
    credential: Value,
}

impl StepUpProof {
    /// Pair a ceremony with the assertion produced for it; an empty ceremony or a
    /// non-object credential is Invalid.
    pub fn new(ceremony: String, credential: Value) -> Result<Self> {
        if ceremony.is_empty() || !credential.is_object() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            ceremony,
            credential,
        })
    }

    fn wire(&self) -> Value {
        json!({ "ceremony": self.ceremony, "credential": self.credential })
    }
}
