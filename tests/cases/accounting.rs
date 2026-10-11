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
