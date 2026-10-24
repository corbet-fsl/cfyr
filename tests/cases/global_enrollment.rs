//! Original global initial continuation, real UV, current eligibility and TLS.
use super::*;
use crate::registration::GlobalFinishContinuation;

const SEED: [u8; 32] = [21; 32];
const PUBLICATION: [u8; 32] = [22; 32];

fn delay(tls: &TlsIngress, action: usize) {
    tls.mutation.target.store(action, Ordering::SeqCst);
    tls.mutation.enabled.store(true, Ordering::SeqCst);
}
async fn prepare(
    api: &mut Foyer<crate::HttpClient>,
    tls: &TlsIngress,
    keys: &mut cpky::Client<SoftwareAuthenticator>,
) -> GlobalFinishContinuation {
    let mut reservation = api
        .begin_global_initial_registration(&tls.origin, || NOW)
        .await
        .unwrap();
    let account = reservation.account().to_owned();
    let pending = reservation
        .continue_initial(api, SEED, || NOW)
        .await
        .unwrap();
    assert_eq!(pending.account(), account);
    assert_eq!(pending.seed(), SEED);
    let (public, prf) = keys
        .register_member(pending.options().clone())
        .await
        .unwrap()
        .into_parts();
    // These are Foyer owner tests, not a durable Keys candidate or wallet test.
    drop(prf);
    pending.prepare_finish(api, public, || NOW).await.unwrap()
}
async fn registered() -> Fixture {
    let service = global(100).await;
    let tls = TlsIngress::new(&service).await;
    let mut foyer = foyer(&tls);
    let mut keys = passkeys();
    let finish = prepare(&mut foyer, &tls, &mut keys).await;
    let user = finish.account().to_owned();
    let original_id = finish.original_credential_id().to_vec();
    foyer
        .resume_global_initial_registration(finish, || NOW)
        .await
        .unwrap();
    // C1: the finish adopted the wallet's birth session of exactly this account; a later
    // login replaces it as any login does.
    assert_eq!(
        foyer
            .shared
            .session
            .lock()
            .await
            .info
            .as_ref()
            .unwrap()
            .user,
        user
    );
    assert_eq!(login(&mut foyer, &mut keys).await, original_id);
    Fixture {
        tls,
        service,
        foyer,
        keys,
        original_id,
        user,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn original_continue_lost_reply_retries_exact_seed_and_never_replaces_uuid() {
    let service = global(100).await;
    let tls = TlsIngress::new(&service).await;
    let mut api = foyer(&tls);
    let mut reservation = api
        .begin_global_initial_registration(&tls.origin, || NOW)
        .await
        .unwrap();
    let account = reservation.account().to_owned();
    delay(&tls, 1);
    let mut request = Box::pin(reservation.continue_initial(&api, SEED, || NOW));
    tokio::select! {
        _ = tls.mutation.arrived.notified() => {},
        _ = &mut request => panic!("actual continuation reply must be held"),
    }
    drop(request);
    tls.mutation.release.notify_one();
    assert!(
        reservation
            .continue_initial(&api, [23; 32], || NOW)
            .await
            .is_err()
    );
    let pending = reservation
        .continue_initial(&api, SEED, || NOW)
        .await
        .unwrap();
    assert_eq!(pending.account(), account);
    let mut keys = passkeys();
    let (public, prf) = keys
        .register_member(pending.options().clone())
        .await
        .unwrap()
        .into_parts();
    drop(prf);
    let finish = pending.prepare_finish(&api, public, || NOW).await.unwrap();
    api.resume_global_initial_registration(finish, || NOW)
        .await
        .unwrap();
    assert!(
        reservation
            .continue_initial(&api, SEED, || NOW)
            .await
            .is_err()
    );
    login(&mut api, &mut keys).await;
    assert_eq!(
        api.shared.session.lock().await.info.as_ref().unwrap().user,
        account
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn exact_public_finish_reopens_before_send_and_lost_acceptance_requires_real_login() {
    for uncertain in [false, true] {
        let service = global(100).await;
        let tls = TlsIngress::new(&service).await;
        let mut original = foyer(&tls);
        let mut keys = passkeys();
        let finish = prepare(&mut original, &tls, &mut keys).await;
        let bytes = finish.to_bytes().unwrap();
        let account = finish.account().to_owned();
        let id = finish.original_credential_id().to_vec();
        if uncertain {
            delay(&tls, 2);
            let mut request = Box::pin(original.resume_global_initial_registration(finish, || NOW));
            tokio::select! {
                _ = tls.mutation.arrived.notified() => {},
                _ = &mut request => panic!("actual accepted finish reply must be held"),
            }
            drop(request);
            tls.mutation.release.notify_one();
        }
        drop(original);
        let mut restarted = foyer(&tls);
        let retained = GlobalFinishContinuation::from_bytes(&bytes).unwrap();
        assert_eq!(retained.to_bytes().unwrap(), bytes);
        let result = restarted
            .resume_global_initial_registration(retained, || NOW)
            .await;
        assert_eq!(result.is_ok(), !uncertain);
        // Only an accepted finish carries the birth session; a lost acceptance needs a login.
        assert_eq!(
            restarted.shared.session.lock().await.info.is_some(),
            !uncertain
        );
        assert_eq!(login(&mut restarted, &mut keys).await, id);
        let lease = restarted
            .live_global_wallet(tls.origin.clone())
            .observe_lease(|| NOW)
            .await
            .unwrap();
        let mut bound = lease
            .bind_initial_creation(SEED, PUBLICATION, || NOW)
            .await
            .unwrap();
        assert_eq!(bound.user().unwrap(), account);
        assert_eq!(bound.credential_id().unwrap(), id);
        assert_eq!(bound.commitments().unwrap(), (SEED, PUBLICATION));
        bound.refresh(|| NOW).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lost_bind_reconciles_only_by_eligible_equal_retry_and_ban_refuses() {
    let mut f = registered().await;
    let lease = f.live().observe_lease(|| NOW).await.unwrap();
    delay(&f.tls, 3);
    let mut request = Box::pin(lease.bind_initial_creation(SEED, PUBLICATION, || NOW));
    tokio::select! {
        _ = f.tls.mutation.arrived.notified() => {},
        _ = &mut request => panic!("actual bound reply must be held"),
    }
    drop(request);
    f.tls.mutation.release.notify_one();
    let state = f.foyer.call("initial_creation", json!({})).await.unwrap();
    assert_eq!(state["publication"], json!(PUBLICATION));
    let mut bound = f
        .live()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .bind_initial_creation(SEED, PUBLICATION, || NOW)
        .await
        .unwrap();
    bound.refresh(|| NOW).await.unwrap();
    drop(bound);
    let begin = f
        .foyer
        .call("global_self_ban_begin", json!({}))
        .await
        .unwrap();
    let (credential, prf) = f
        .keys
        .sign_in(begin["options"].clone())
        .await
        .unwrap()
        .into_parts();
    drop(prf);
    f.foyer
        .call(
            "global_self_ban_finish",
            json!({"ceremony":begin["ceremony"],"credential":credential.into_json()}),
        )
        .await
        .unwrap();
    login(&mut f.foyer, &mut f.keys).await;
    let state = f.foyer.call("initial_creation", json!({})).await.unwrap();
    assert_eq!(state["publication"], json!(PUBLICATION));
    // Own metadata remains readable after ban; even equal bind cannot qualify.
    let observed = f.live().observe_lease(|| NOW).await.unwrap();
    assert!(
        observed
            .bind_initial_creation(SEED, PUBLICATION, || NOW)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn global_bind_afterawait_rollback_expiry_and_refresh_cancellation_are_terminal() {
    for final_time in [NOW - 1, NOW + 600] {
        let f = registered().await;
        let lease = f.live().observe_lease(|| NOW).await.unwrap();
        delay(&f.tls, 3);
        let clock = Arc::new(AtomicU64::new(NOW));
        let observed = clock.clone();
        let mut request = Box::pin(
            lease.bind_initial_creation(SEED, PUBLICATION, move || observed.load(Ordering::SeqCst)),
        );
        tokio::select! {
            _ = f.tls.mutation.arrived.notified() => {},
            _ = &mut request => panic!("actual bound reply must be held"),
        }
        clock.store(final_time, Ordering::SeqCst);
        f.tls.mutation.release.notify_one();
        assert!(request.await.is_err());
    }
    let f = registered().await;
    let mut bound = f
        .live()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .bind_initial_creation(SEED, PUBLICATION, || NOW)
        .await
        .unwrap();
    delay(&f.tls, 3);
    let mut request = Box::pin(bound.refresh(|| NOW));
    tokio::select! {
        _ = f.tls.mutation.arrived.notified() => {},
        _ = &mut request => panic!("actual equal bound reply must be held"),
    }
    drop(request);
    f.tls.mutation.release.notify_one();
    assert!(bound.user().is_err());
    assert!(bound.refresh(|| NOW).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn successful_bind_final_local_refusal_preserves_unknown_durable_winner() {
    for final_time in [NOW - 1, NOW + 600] {
        let mut f = registered().await;
        let lease = f.live().observe_lease(|| NOW).await.unwrap();
        let mut reads = 0;
        let result = lease
            .bind_initial_creation(SEED, PUBLICATION, || {
                reads += 1;
                if reads == 4 { final_time } else { NOW }
            })
            .await;
        assert!(matches!(result, Err(Error::Reconcile)));
        let state = f.foyer.call("initial_creation", json!({})).await.unwrap();
        assert_eq!(state["publication"], json!(PUBLICATION));
        let bound = f
            .live()
            .observe_lease(|| NOW)
            .await
            .unwrap()
            .bind_initial_creation(SEED, PUBLICATION, || NOW)
            .await
            .unwrap();
        assert_eq!(bound.commitments().unwrap(), (SEED, PUBLICATION));
    }
}

/// The device clock is never ordered against the wallet's time: the bind trusts only its
/// nonce echo, so a device clock off by more than the platform's 300 s stamp tolerance,
/// ahead or behind, still binds.
#[tokio::test(flavor = "multi_thread")]
async fn bind_never_compares_the_device_clock_with_the_wallet_time() {
    for device in [NOW + 301, NOW - 301] {
        let f = registered().await;
        let bound = f
            .live()
            .observe_lease(move || device)
            .await
            .unwrap()
            .bind_initial_creation(SEED, PUBLICATION, move || device)
            .await
            .unwrap();
        assert_eq!(bound.commitments().unwrap(), (SEED, PUBLICATION));
    }
}

/// An earlier genuine answer to an equal bind, replayed for a later bind, does not carry
/// that bind's nonce and is refused, though its seed, publication and time all match.
#[tokio::test(flavor = "multi_thread")]
async fn a_replayed_earlier_bind_answer_is_refused() {
    let f = registered().await;
    f.live()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .bind_initial_creation(SEED, PUBLICATION, || NOW)
        .await
        .unwrap();
    f.tls.replay.enabled.store(true, Ordering::SeqCst);
    let result = f
        .live()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .bind_initial_creation(SEED, PUBLICATION, || NOW)
        .await;
    assert!(matches!(result, Err(Error::Reconcile)));
    assert!(!f.tls.replay.enabled.load(Ordering::SeqCst));
    let bound = f
        .live()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .bind_initial_creation(SEED, PUBLICATION, || NOW)
        .await
        .unwrap();
    assert_eq!(bound.commitments().unwrap(), (SEED, PUBLICATION));
}
