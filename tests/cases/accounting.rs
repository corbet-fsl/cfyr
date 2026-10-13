//! Genuine TLS/original challenge owner; no successful account grant is mocked.
use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn actual_signed_account_challenge_binds_current_origin_and_refuses_forged_passport() {
    let f = Fixture::new().await;
    let mut policy = f.foyer.current_policy();
    let lease = f
        .foyer
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap();
    let device = lease.observation().device_keys[0];
    let mut challenge = lease.account_challenge(&mut policy, || NOW).await.unwrap();
    challenge
        .with_current(
            || NOW,
            |current, observed, origin, signed, checked| {
                assert_eq!(origin, f.tls.origin);
                assert!(observed.device_keys.contains(&device));
                let anchor = cpsd::AuthenticatedCommunity::from_authenticated_origin(
                    cpsd::CommunityId::new(current.community()).unwrap(),
                    current.key_ring().clone(),
                );
                let request = anchor.authenticate(signed, checked).unwrap();
                assert_eq!(request.community().as_str(), "alpha");
                assert!(request.policy_epoch() > 0);
                assert!(request.epoch_expiry().is_some());
            },
        )
        .unwrap();
    assert!(challenge.finish(vec![0], device, || NOW).await.is_err());
    assert!(
        f.foyer
            .live_membership()
            .observe_lease(|| NOW)
            .await
            .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn real_account_challenge_refuses_owner_disposal_and_backward_completion_clock() {
    for disposed in [false, true] {
        let f = Fixture::new().await;
        let mut policy = f.foyer.current_policy();
        let lease = f
            .foyer
            .live_membership()
            .observe_lease(|| NOW)
            .await
            .unwrap();
        f.tls.gate.action.store(7, Ordering::SeqCst);
        f.tls.gate.enabled.store(true, Ordering::SeqCst);
        let time = Arc::new(AtomicU64::new(NOW));
        let clock = time.clone();
        let pending = lease.account_challenge(&mut policy, move || clock.load(Ordering::SeqCst));
        tokio::pin!(pending);
        tokio::select! {
            _ = f.tls.gate.arrived.notified() => {},
            _ = &mut pending => panic!("real challenge response must wait"),
        }
        if disposed {
            drop(f.foyer);
        } else {
            time.store(NOW - 1, Ordering::SeqCst);
        }
        f.tls.gate.release.notify_one();
        assert!(pending.await.is_err());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_real_account_challenge_releases_original_owner_lock() {
    let f = Fixture::new().await;
    let mut policy = f.foyer.current_policy();
    let lease = f
        .foyer
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap();
    f.tls.gate.action.store(7, Ordering::SeqCst);
    f.tls.gate.enabled.store(true, Ordering::SeqCst);
    let mut pending = Box::pin(lease.account_challenge(&mut policy, || NOW));
    tokio::select! {
        _ = f.tls.gate.arrived.notified() => {},
        _ = &mut pending => panic!("real challenge response must wait"),
    }
    drop(pending);
    f.tls.gate.enabled.store(false, Ordering::SeqCst);
    f.tls.gate.release.notify_one();
    let next = tokio::time::timeout(
        Duration::from_secs(2),
        f.foyer.live_membership().observe_lease(|| NOW),
    )
    .await
    .unwrap();
    assert!(next.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn sent_account_issue_refuses_unknown_completion_as_reconcile() {
    for disposed in [false, true] {
        let f = Fixture::new().await;
        let mut policy = f.foyer.current_policy();
        let lease = f
            .foyer
            .live_membership()
            .observe_lease(|| NOW)
            .await
            .unwrap();
        let device = lease.observation().device_keys[0];
        let challenge = lease.account_challenge(&mut policy, || NOW).await.unwrap();
        f.tls.gate.action.store(8, Ordering::SeqCst);
        f.tls.gate.enabled.store(true, Ordering::SeqCst);
        let time = Arc::new(AtomicU64::new(NOW));
        let clock = time.clone();
        // Original owner receives and processes this refused proof. This tests
        // transport uncertainty, not successful account admission or issuance.
        let pending = challenge.finish(vec![0], device, move || clock.load(Ordering::SeqCst));
        tokio::pin!(pending);
        tokio::select! {
            _ = f.tls.gate.arrived.notified() => {},
            _ = &mut pending => panic!("real issue response must wait"),
        }
        if disposed {
            drop(f.foyer);
        } else {
            time.store(NOW - 1, Ordering::SeqCst);
        }
        f.tls.gate.release.notify_one();
        assert!(matches!(pending.await, Err(Error::Reconcile)));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn held_lease_reads_the_lobby_and_submits_only_a_decodable_member_voucher() {
    let f = Fixture::new().await;
    let mut lease = f
        .foyer
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap();
    let lobby = lease.lobby(|| NOW).await.unwrap();
    let member = lobby["member_id"].as_str().unwrap().to_owned();
    assert!(
        !lobby["missing"].as_array().unwrap().is_empty(),
        "a new member still lacks admission"
    );
    // Text that is not a voucher never reaches the server.
    for bad in ["", "garbage", "cvch1.", "cvch1.AAAA"] {
        assert!(matches!(
            lease.submit_voucher(bad, || NOW).await,
            Err(crate::Error::Invalid)
        ));
    }
    // A voucher bound to another member is the server's verdict, kept plain.
    let foreign = voucher("alpha", "someone-else", "held-lease-foreign", NOW + 172800);
    let foreign: cvch::Voucher = serde_json::from_value(foreign).unwrap();
    assert!(matches!(
        lease
            .submit_voucher(&foreign.to_code().unwrap(), || NOW)
            .await,
        Err(crate::Error::Refused)
    ));
    // The member's own voucher is accepted and answers that member's lobby; the
    // second submission is spent and refused.
    let own = voucher("alpha", &member, "held-lease-own", NOW + 172800);
    let own: cvch::Voucher = serde_json::from_value(own).unwrap();
    let code = own.to_code().unwrap();
    let after = lease.submit_voucher(&code, || NOW).await.unwrap();
    assert_eq!(after["member_id"], member.as_str());
    assert!(lease.submit_voucher(&code, || NOW).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn held_lease_reserves_the_chosen_handle_once_and_shows_it_in_the_lobby() {
    let f = Fixture::new().await;
    let mut lease = f
        .foyer
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap();
    assert!(
        lease
            .handle_available("held_lease_handle", || NOW)
            .await
            .unwrap()
    );
    assert!(matches!(
        lease.handle_available("no spaces!", || NOW).await,
        Err(crate::Error::Invalid)
    ));
    let lobby = lease
        .reserve_handle("held_lease_handle", || NOW)
        .await
        .unwrap();
    assert_eq!(lobby["handle"], "held_lease_handle");
    assert!(
        !lease
            .handle_available("held_lease_handle", || NOW)
            .await
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn step_up_authorizes_exactly_the_named_device_key_through_the_held_lease() {
    use crate::membership::{StepUpAction, StepUpProof};
    let mut f = Fixture::new().await;
    let key = [42u8; 32];
    let mut lease = f
        .foyer
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap();
    let mut prove = async |lease: &mut crate::membership::MembershipLease<_>,
                           action: StepUpAction<'_>| {
        let begin = lease.step_up_begin(action, || NOW).await.unwrap();
        let (credential, _) = f
            .passkeys
            .sign_in(begin["options"].clone())
            .await
            .unwrap()
            .into_parts();
        StepUpProof::new(
            begin["ceremony"].as_str().unwrap().into(),
            credential.into_json(),
        )
        .unwrap()
    };
    // An assertion for one key never authorizes another.
    let proof = prove(&mut lease, StepUpAction::DeviceAuthorize { key }).await;
    assert!(
        lease
            .device_authorize([43u8; 32], proof, || NOW)
            .await
            .is_err()
    );
    assert!(!lease.observation().device_keys.contains(&[43u8; 32]));
    let proof = prove(&mut lease, StepUpAction::DeviceAuthorize { key }).await;
    lease.device_authorize(key, proof, || NOW).await.unwrap();
    assert!(lease.observation().device_keys.contains(&key));
}

#[tokio::test(flavor = "multi_thread")]
async fn passkey_add_and_revoke_need_their_own_fresh_single_use_step_up_and_exact_answers() {
    use crate::membership::{StepUpAction, StepUpProof};
    let mut f = Fixture::new().await;
    let mut lease = f
        .foyer
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap();
    let mut prove = async |lease: &mut crate::membership::MembershipLease<_>,
                           action: StepUpAction<'_>| {
        let begin = lease.step_up_begin(action, || NOW).await.unwrap();
        let (credential, _) = f
            .passkeys
            .sign_in(begin["options"].clone())
            .await
            .unwrap()
            .into_parts();
        StepUpProof::new(
            begin["ceremony"].as_str().unwrap().into(),
            credential.into_json(),
        )
        .unwrap()
    };
    // A step-up for another action never opens passkey_add, and is spent by the try.
    let wrong = prove(&mut lease, StepUpAction::DeviceAuthorize { key: [9u8; 32] }).await;
    assert!(lease.passkey_add_begin(wrong, || NOW).await.is_err());
    // A step-up older than the freshness window is refused.
    let stale = prove(&mut lease, StepUpAction::PasskeyAdd).await;
    assert!(lease.passkey_add_begin(stale, || NOW + 10_000).await.is_err());
    // A proof is single use.
    let proof = prove(&mut lease, StepUpAction::PasskeyAdd).await;
    let begin = lease.passkey_add_begin(proof.clone(), || NOW).await.unwrap();
    assert_eq!(begin["step"], "challenge");
    assert!(lease.passkey_add_begin(proof, || NOW).await.is_err());
    // Finish only for the ceremony this lease began.
    let proof = prove(&mut lease, StepUpAction::PasskeyAdd).await;
    let begin = lease.passkey_add_begin(proof, || NOW).await.unwrap();
    let (credential, _) = f
        .passkeys
        .register_member(begin["options"].clone())
        .await
        .unwrap()
        .into_parts();
    let credential = credential.into_json();
    assert!(
        lease
            .passkey_add_finish("some-other-ceremony", credential.clone(), || NOW)
            .await
            .is_err()
    );
    let added = lease
        .passkey_add_finish(begin["ceremony"].as_str().unwrap(), credential, || NOW)
        .await
        .unwrap();
    assert_eq!(added["step"], "registered");
    let id: Vec<u8> = serde_json::from_value(added["credential"].clone()).unwrap();
    // Revoke: a step-up for the add action never opens revoke; its own proof does, once.
    let wrong = prove(&mut lease, StepUpAction::PasskeyAdd).await;
    assert!(lease.passkey_revoke(&id, wrong, || NOW).await.is_err());
    let proof = prove(&mut lease, StepUpAction::PasskeyRevoke { credential: &id }).await;
    lease.passkey_revoke(&id, proof.clone(), || NOW).await.unwrap();
    assert!(lease.passkey_revoke(&id, proof, || NOW).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_paired_device_key_stays_pending_without_another_passkeys_approval_and_is_revocable() {
    use crate::membership::{StepUpAction, StepUpProof};
    let mut f = Fixture::new().await;
    let key = [44u8; 32];
    let mut lease = f
        .foyer
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap();
    let mut prove = async |lease: &mut crate::membership::MembershipLease<_>,
                           action: StepUpAction<'_>| {
        let begin = lease.step_up_begin(action, || NOW).await.unwrap();
        let (credential, _) = f
            .passkeys
            .sign_in(begin["options"].clone())
            .await
            .unwrap()
            .into_parts();
        StepUpProof::new(
            begin["ceremony"].as_str().unwrap().into(),
            credential.into_json(),
        )
        .unwrap()
    };
    // Pending: accepted, but the key is not live, a revoke proof does not open it, and the
    // same passkey can neither confirm nor approve its own key.
    let proof = prove(&mut lease, StepUpAction::DeviceAuthorize { key }).await;
    lease.device_pair_authorize(key, proof, || NOW).await.unwrap();
    assert!(!lease.observation().device_keys.contains(&key));
    let wrong = prove(&mut lease, StepUpAction::DeviceAuthorize { key }).await;
    assert!(lease.device_revoke(key, wrong, || NOW).await.is_err());
    assert!(lease.device_confirm(key, || NOW).await.is_err());
    let own = prove(&mut lease, StepUpAction::DeviceApprove { key }).await;
    assert!(lease.device_approve(key, own, || NOW).await.is_err());
    assert!(!lease.observation().device_keys.contains(&key));
    // Its own revoke step-up removes the pending key.
    let proof = prove(&mut lease, StepUpAction::DeviceRevoke { key }).await;
    lease.device_revoke(key, proof, || NOW).await.unwrap();
    assert!(lease.device_confirm(key, || NOW).await.is_err());
}
