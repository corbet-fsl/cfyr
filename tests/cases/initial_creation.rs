//! Sealed initial provenance from the actual HTTPS/Keyhole membership owner.
use super::*;

async fn enrolled() -> (
    Foyer<crate::HttpClient>,
    TlsIngress,
    Running,
    cpky::Client<SoftwareAuthenticator>,
    Vec<u8>,
) {
    let mut f = InitialFixture::new().await;
    let finish = f
        .pending
        .prepare_finish(&f.api, f.public, || NOW)
        .await
        .unwrap();
    f.api
        .resume_initial_registration(finish, || NOW)
        .await
        .unwrap();
    login(&mut f.api, &mut f.keys).await;
    (f.api, f.tls, f.service, f.keys, f.raw_id)
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_initial_key_seed_and_immutable_publication_are_sealed() {
    let (api, _tls, _service, _keys, raw_id) = enrolled().await;
    let mut policy = api.current_policy();
    let certified = api
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .passkey_certificate(&mut policy, || NOW)
        .await
        .unwrap();
    let original = certified.initial_creation(|| NOW).await.unwrap();
    assert_eq!(original.seed().unwrap(), SEED);
    assert_eq!(original.credential_id().unwrap(), raw_id);
    assert_eq!(original.publication().unwrap(), None);
    assert_eq!(original.checked_at().unwrap(), NOW);
    let bound = original.bind_publication([92; 32], || NOW).await.unwrap();
    assert_eq!(bound.publication().unwrap(), Some([92; 32]));
    let bound = bound.bind_publication([92; 32], || NOW).await.unwrap();
    assert!(matches!(
        bound.bind_publication([93; 32], || NOW).await,
        Err(Error::Invalid)
    ));
    let certified = api
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .passkey_certificate(&mut policy, || NOW)
        .await
        .unwrap();
    let mut reopened = certified.initial_creation(|| NOW).await.unwrap();
    assert_eq!(reopened.publication().unwrap(), Some([92; 32]));
    assert!(reopened.check(|| NOW - 1).is_err());
    assert!(reopened.check(|| NOW).is_err());
    assert!(reopened.seed().is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn real_same_key_clones_observe_one_immutable_server_winner() {
    let (api, tls, service, mut keys, _) = enrolled().await;
    let mut other = Foyer::with_trust(
        crate::HttpClient::with_roots(
            tls.origin.clone(),
            "127.0.0.1".into(),
            None,
            std::slice::from_ref(&tls.root),
        )
        .unwrap(),
        trust(&service, &tls).await,
    );
    login(&mut other, &mut keys).await;
    let mut first_policy = api.current_policy();
    let first = api
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .passkey_certificate(&mut first_policy, || NOW)
        .await
        .unwrap()
        .initial_creation(|| NOW)
        .await
        .unwrap();
    let mut second_policy = other.current_policy();
    let second = other
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .passkey_certificate(&mut second_policy, || NOW)
        .await
        .unwrap()
        .initial_creation(|| NOW)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        first.bind_publication([94; 32], || NOW),
        second.bind_publication([95; 32], || NOW)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let winner = a.ok().or_else(|| b.ok()).unwrap();
    let expected = winner.publication().unwrap().unwrap();
    drop(winner);
    let reopened = api
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .passkey_certificate(&mut first_policy, || NOW)
        .await
        .unwrap()
        .initial_creation(|| NOW)
        .await
        .unwrap();
    assert_eq!(reopened.publication().unwrap(), Some(expected));
}

#[tokio::test(flavor = "multi_thread")]
async fn committed_bind_lost_reply_or_late_refusal_requires_fresh_query() {
    for cancellation in [false, true] {
        let (api, tls, service, mut keys, _) = enrolled().await;
        let mut policy = api.current_policy();
        let original = api
            .live_membership()
            .observe_lease(|| NOW)
            .await
            .unwrap()
            .passkey_certificate(&mut policy, || NOW)
            .await
            .unwrap()
            .initial_creation(|| NOW)
            .await
            .unwrap();
        let deadline = original.expires().unwrap();
        let time = Arc::new(AtomicU64::new(NOW));
        let observed = time.clone();
        tls.gate.action.store(4, Ordering::SeqCst);
        tls.gate.enabled.store(true, Ordering::SeqCst);
        let mut future =
            Box::pin(original.bind_publication([96; 32], move || observed.load(Ordering::SeqCst)));
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(5), tls.gate.arrived.notified()) => result.unwrap(),
            _ = &mut future => panic!("actual committed bind reply should be gated"),
        }
        if cancellation {
            drop(future);
            tls.gate.release.notify_one();
        } else {
            time.store(deadline, Ordering::SeqCst);
            tls.gate.release.notify_one();
            assert!(matches!(future.await, Err(Error::Reconcile)));
        }
        let mut fresh = Foyer::with_trust(
            crate::HttpClient::with_roots(
                tls.origin.clone(),
                "127.0.0.1".into(),
                None,
                std::slice::from_ref(&tls.root),
            )
            .unwrap(),
            trust(&service, &tls).await,
        );
        login(&mut fresh, &mut keys).await;
        let mut current = fresh.current_policy();
        let winner = fresh
            .live_membership()
            .observe_lease(|| NOW)
            .await
            .unwrap()
            .passkey_certificate(&mut current, || NOW)
            .await
            .unwrap()
            .initial_creation(|| NOW)
            .await
            .unwrap();
        assert_eq!(winner.seed().unwrap(), SEED);
        assert_eq!(winner.publication().unwrap(), Some([96; 32]));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ordinary_registration_cannot_acquire_initial_candidate_provenance() {
    let f = Fixture::new().await;
    let mut policy = f.foyer.current_policy();
    let original = f
        .foyer
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .passkey_certificate(&mut policy, || NOW)
        .await
        .unwrap();
    assert!(original.initial_creation(|| NOW).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn original_policy_contention_and_callback_unwind_consume_initial_lease() {
    let (mut api, _tls, _service, _keys, _) = enrolled().await;
    let mut policy = api.current_policy();
    let mut initial = api
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .passkey_certificate(&mut policy, || NOW)
        .await
        .unwrap()
        .initial_creation(|| NOW)
        .await
        .unwrap();
    assert_eq!(initial.with_current(|| NOW, |_| 7).unwrap(), 7);
    let held = api.trust().unwrap();
    assert!(initial.with_current(|| NOW, |_| ()).is_err());
    drop(held);
    assert!(initial.check(|| NOW).is_err());
    drop(initial);
    let mut initial = api
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .passkey_certificate(&mut policy, || NOW)
        .await
        .unwrap()
        .initial_creation(|| NOW)
        .await
        .unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = initial.with_current(|| NOW, |_| panic!("consumer callback"));
        }))
        .is_err()
    );
    assert!(initial.check(|| NOW).is_err());
    assert!(initial.seed().is_err());
}
