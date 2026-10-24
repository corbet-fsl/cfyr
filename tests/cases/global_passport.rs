//! Actual global HTTP issuer/current-key exchange, with original opaque CPSD.
//! This tests the network continuation, not Vault durability or Tor acceptance.
use super::*;
use crate::membership::GlobalPassportIssuance;

async fn begin(f: &Fixture) -> GlobalPassportIssuance<crate::HttpClient> {
    f.live()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .passport_challenge(|| NOW)
        .await
        .unwrap()
}
fn request(
    pending: &mut GlobalPassportIssuance<crate::HttpClient>,
    holder: &mut cpsd::OpaqueHolder,
) -> Vec<u8> {
    pending
        .with_current(
            || NOW,
            |_, _, issuer, challenge, _| {
                holder
                    .begin_issuance(
                        &mut cpsd::rand::rngs::OsRng,
                        &cpsd::IssuerPublicKey::from_bytes(issuer).unwrap(),
                        &cpsd::IssuanceChallenge::from_bytes(challenge.try_into().unwrap()),
                    )
                    .unwrap()
                    .to_bytes()
            },
        )
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn same_https_key_issues_only_the_original_opaque_holder_request_once() {
    let mut f = Fixture::new().await;
    f.foyer.call("development_gate", json!({})).await.unwrap();
    let mut pending = begin(&f).await;
    pending
        .with_current(
            || NOW,
            |user, key, _, _, _| {
                assert_eq!(user, f.user);
                assert_eq!(key, f.original_id);
            },
        )
        .unwrap();
    // The same real pending owner refuses before relocking the session mutex.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            f.live().observe_lease(|| NOW)
        )
        .await
        .unwrap()
        .is_err()
    );
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [73; 32]);
    let scope = cpsd::CommunityId::new(b"alpha").unwrap();
    let original = holder.pseudonym(&scope);
    let public = request(&mut pending, &mut holder);
    let answer = pending.issue(public.clone(), || NOW).await.unwrap();
    holder
        .finish_issuance(&cpsd::BlindPassport::from_bytes(&answer).unwrap())
        .unwrap();
    assert!(holder.attributes().is_some());
    assert_eq!(holder.pseudonym(&scope), original);
    assert!(pending.issue(public, || NOW).await.is_err());
    pending.with_current(|| NOW, |_, _, _, _, _| ()).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn issuer_record_reply_cancellation_clock_failure_and_close_never_retry() {
    for (cut, close) in [
        (None, false),
        (None, true),
        (Some(NOW - 1), false),
        (Some(NOW), false),
    ] {
        let mut f = Fixture::new().await;
        f.foyer.call("development_gate", json!({})).await.unwrap();
        let mut pending = begin(&f).await;
        let mut holder = cpsd::OpaqueHolder::from_seed(&mut [74; 32]);
        let public = request(&mut pending, &mut holder);
        f.tls.mutation.target.store(7, Ordering::SeqCst);
        f.tls.mutation.enabled.store(true, Ordering::SeqCst);
        let clock = Arc::new(AtomicU64::new(NOW));
        let observed = clock.clone();
        let mut issue =
            Box::pin(pending.issue(public.clone(), move || observed.load(Ordering::SeqCst)));
        tokio::select! { _ = f.tls.mutation.arrived.notified() => {},
        _ = &mut issue => panic!("actual committed issuer reply must wait") }
        if close {
            f.foyer.shared.close();
            assert!(issue.await.is_err());
            f.tls.mutation.release.notify_one();
        } else if let Some(at) = cut {
            clock.store(at, Ordering::SeqCst);
            // The SERVER clock passes the expiry; the server refuses, not the device.
            f.service.clock.set(NOW + 600);
            f.tls.mutation.release.notify_one();
            assert!(issue.await.is_err());
        } else {
            drop(issue);
            f.tls.mutation.release.notify_one();
        }
        assert!(
            pending
                .with_current(|| NOW + 1, |_, _, _, _, _| ())
                .is_err()
        );
        assert!(pending.issue(public, || NOW + 1).await.is_err());
        assert!(holder.attributes().is_none());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn original_issuer_rejects_foreign_challenge_and_revoked_session_key() {
    let mut f = Fixture::new().await;
    f.foyer.call("development_gate", json!({})).await.unwrap();
    let (mut added, _) = f.add_key().await;
    let mut pending = begin(&f).await;
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [75; 32]);
    let public = request(&mut pending, &mut holder);
    let mut companion = foyer(&f.tls);
    login(&mut companion, &mut added).await;
    let body = crate::test_step_up::proven(
        &mut companion,
        &mut added,
        json!({"kind":"passkey_revoke","credential":f.original_id}),
        json!({"credential":f.original_id}),
    )
    .await;
    companion.call("passkey_revoke", body).await.unwrap();
    assert!(pending.issue(public, || NOW).await.is_err());
    assert!(pending.with_current(|| NOW, |_, _, _, _, _| ()).is_err());

    let mut other = Fixture::new().await;
    other
        .foyer
        .call("development_gate", json!({}))
        .await
        .unwrap();
    let mut pending = begin(&other).await;
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [76; 32]);
    let request = pending
        .with_current(
            || NOW,
            |_, _, issuer, _, _| {
                holder
                    .begin_issuance(
                        &mut cpsd::rand::rngs::OsRng,
                        &cpsd::IssuerPublicKey::from_bytes(issuer).unwrap(),
                        &cpsd::IssuanceChallenge::generate(&mut cpsd::rand::rngs::OsRng),
                    )
                    .unwrap()
                    .to_bytes()
            },
        )
        .unwrap();
    assert!(pending.issue(request, || NOW).await.is_err());
    assert!(holder.attributes().is_none());
}
