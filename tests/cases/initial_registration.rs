//! Real original enrollment requests; restored bytes remain public replay data.
use super::*;
use crate::registration::{FinishContinuation, PendingInitialRegistration};

const SEED: [u8; 32] = [81; 32];
const HEADER: &[u8] = b"cfyr.initial-finish.v1\0";

struct InitialFixture {
    tls: TlsIngress,
    service: Running,
    api: Foyer<crate::HttpClient>,
    pending: PendingInitialRegistration<crate::HttpClient>,
    keys: cpky::Client<SoftwareAuthenticator>,
    public: cpky::PublicCredential,
    raw_id: Vec<u8>,
}
impl InitialFixture {
    async fn new() -> Self {
        let (service, tls, mut api, proof) = environment().await;
        let pending = api
            .begin_initial_registration(proof, SEED, || NOW)
            .await
            .unwrap();
        let mut keys = passkeys();
        let (public, custody) = keys
            .register_member(pending.options().clone())
            .await
            .unwrap()
            .into_parts();
        drop(custody);
        let raw_id = public.credential_id().unwrap();
        Self {
            tls,
            service,
            api,
            pending,
            keys,
            public,
            raw_id,
        }
    }
}
async fn environment() -> (
    Running,
    TlsIngress,
    Foyer<crate::HttpClient>,
    serde_json::Value,
) {
    assert!(cvld::client::forwarding_action("initial_registration_begin").is_some());
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let tls = TlsIngress::new(&service).await;
    let retained = trust(&service, &tls).await;
    let api = Foyer::with_trust(
        crate::HttpClient::with_roots(
            tls.origin.clone(),
            "127.0.0.1".into(),
            None,
            std::slice::from_ref(&tls.root),
        )
        .unwrap(),
        retained,
    );
    let proof = presentation(&service, HOST, None, &passport).await;
    (service, tls, api, serde_json::to_value(proof).unwrap())
}
async fn prove_current_original(
    api: &mut Foyer<crate::HttpClient>,
    keys: &mut cpky::Client<SoftwareAuthenticator>,
    raw_id: &[u8],
) {
    login(api, keys).await;
    let state = api.call("initial_creation", json!({})).await.unwrap();
    assert_eq!(state["seed"], json!(SEED));
    assert!(state["publication"].is_null());
    let lease = api.live_membership().observe_lease(|| NOW).await.unwrap();
    let mut policy = api.current_policy();
    let checked = lease
        .passkey_certificate(&mut policy, || NOW)
        .await
        .unwrap();
    assert_eq!(checked.credential_id().unwrap(), raw_id);
    assert_eq!(checked.server_checked_at().unwrap(), NOW);
    // This original certificate and current seed still grant no Keys operation.
}
fn edit_field(bytes: &[u8], field: &str, replacement: serde_json::Value) -> Vec<u8> {
    let body = std::str::from_utf8(bytes.strip_prefix(HEADER).unwrap()).unwrap();
    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    let exact = format!(
        "\"{field}\":{}",
        serde_json::to_string(&value[field]).unwrap()
    );
    let replacement = format!(
        "\"{field}\":{}",
        serde_json::to_string(&replacement).unwrap()
    );
    assert!(body.contains(&exact));
    let mut altered = HEADER.to_vec();
    altered.extend_from_slice(body.replacen(&exact, &replacement, 1).as_bytes());
    altered
}

#[tokio::test(flavor = "multi_thread")]
async fn real_initial_owner_roundtrip_restores_only_data_then_requires_fresh_same_key() {
    let mut f = InitialFixture::new().await;
    assert_eq!(f.pending.community(), "alpha");
    assert_eq!(f.pending.seed(), SEED);
    let data = f
        .pending
        .prepare_finish(&f.api, f.public, || NOW)
        .await
        .unwrap();
    assert_eq!(data.original_credential_id(), f.raw_id);
    let bytes = data.to_bytes().unwrap();
    drop(data);
    let restored = FinishContinuation::from_bytes(&bytes).unwrap();
    assert_eq!(restored.to_bytes().unwrap(), bytes);
    assert_eq!(restored.seed(), SEED);
    // The only completion result is (), never RegisteredMember/RegisteredSession.
    f.api
        .resume_initial_registration(restored, || NOW)
        .await
        .unwrap();
    prove_current_original(&mut f.api, &mut f.keys, &f.raw_id).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn forged_and_noncanonical_data_cannot_restore_accepted_registration() {
    let f = InitialFixture::new().await;
    let data = f
        .pending
        .prepare_finish(&f.api, f.public, || NOW)
        .await
        .unwrap();
    let bytes = data.to_bytes().unwrap();
    let mut unknown = bytes.clone();
    unknown.pop();
    unknown.extend_from_slice(b",\"unrecognized\":true}");
    assert!(FinishContinuation::from_bytes(&unknown).is_err());
    let mut duplicate = bytes.clone();
    duplicate.pop();
    duplicate.extend_from_slice(b",\"seed\":[0]}");
    assert!(FinishContinuation::from_bytes(&duplicate).is_err());
    assert!(FinishContinuation::from_bytes(&vec![0; 512 * 1024 + 1]).is_err());
    // None of these data errors touched the actual server ceremony.
    assert!(f.api.shared.session.lock().await.info.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn canonical_forged_public_claims_still_cannot_mint_registration_or_session_authority() {
    for wrong_user in [false, true] {
        let mut f = InitialFixture::new().await;
        let data = f
            .pending
            .prepare_finish(&f.api, f.public, || NOW)
            .await
            .unwrap();
        let bytes = data.to_bytes().unwrap();
        let altered = if wrong_user {
            edit_field(&bytes, "user", json!("unrelated-user"))
        } else {
            edit_field(&bytes, "raw_id", json!([1, 2, 3]))
        };
        // The codec restores data, so syntactically valid false public claims
        // can decode. It never constructs RegisteredMember/RegisteredSession.
        let restored = FinishContinuation::from_bytes(&altered).unwrap();
        if !wrong_user {
            assert_ne!(restored.original_credential_id(), f.raw_id);
        }
        let result = f.api.resume_initial_registration(restored, || NOW).await;
        if wrong_user {
            assert!(matches!(result, Err(Error::Reconcile)));
        } else {
            // Only the real credential JSON is submitted to the actual server;
            // the restored routing claim does not replace its genuine key.
            result.unwrap();
        }
        assert!(f.api.shared.session.lock().await.info.is_none());
        prove_current_original(&mut f.api, &mut f.keys, &f.raw_id).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn original_owner_origin_generation_current_charter_and_deadline_are_bound() {
    for refusal in 0..4 {
        let mut f = InitialFixture::new().await;
        match refusal {
            0 => {
                let other = Foyer::with_trust(
                    crate::HttpClient::with_roots(
                        f.tls.origin.clone(),
                        "127.0.0.1".into(),
                        None,
                        std::slice::from_ref(&f.tls.root),
                    )
                    .unwrap(),
                    trust(&f.service, &f.tls).await,
                );
                assert!(
                    f.pending
                        .prepare_finish(&other, f.public, || NOW)
                        .await
                        .is_err()
                );
            }
            1 => {
                // A genuine failed login still invalidates the exact generation.
                assert!(
                    f.api
                        .authenticate(json!({"ceremony":"missing","credential":{}}))
                        .await
                        .is_err()
                );
                assert!(
                    f.pending
                        .prepare_finish(&f.api, f.public, || NOW)
                        .await
                        .is_err()
                );
            }
            2 => {
                f.api.trust().unwrap().stop();
                assert!(
                    f.pending
                        .prepare_finish(&f.api, f.public, || NOW)
                        .await
                        .is_err()
                );
            }
            _ => {
                let expires = f.pending.expires_at();
                assert!(
                    f.pending
                        .prepare_finish(&f.api, f.public, || expires)
                        .await
                        .is_err()
                );
            }
        }
    }
    let mut f = InitialFixture::new().await;
    let data = f
        .pending
        .prepare_finish(&f.api, f.public, || NOW + 10)
        .await
        .unwrap();
    assert!(
        f.api
            .resume_initial_registration(data, || NOW + 9)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lost_real_finish_reply_never_infers_absence_and_fresh_login_reads_original_seed() {
    for outcome in 0..3 {
        let mut f = InitialFixture::new().await;
        let expires = f.pending.expires_at();
        let data = f
            .pending
            .prepare_finish(&f.api, f.public, || NOW)
            .await
            .unwrap();
        let bytes = data.to_bytes().unwrap();
        f.tls.gate.action.store(2, Ordering::SeqCst);
        f.tls.gate.enabled.store(true, Ordering::SeqCst);
        let clock = Arc::new(AtomicU64::new(NOW));
        let observed = clock.clone();
        let closing_owner = f.api.shared.clone();
        let mut future = Box::pin(
            f.api
                .resume_initial_registration(data, move || observed.load(Ordering::SeqCst)),
        );
        tokio::select! {
            _ = f.tls.gate.arrived.notified() => {},
            _ = &mut future => panic!("original insertion reply should be gated"),
        }
        if outcome == 0 {
            drop(future);
            f.tls.gate.release.notify_one();
        } else if outcome == 1 {
            clock.store(expires, Ordering::SeqCst);
            f.tls.gate.release.notify_one();
            assert!(matches!(future.await, Err(Error::Reconcile)));
        } else {
            closing_owner.close();
            assert!(matches!(future.await, Err(Error::Reconcile)));
            f.tls.gate.release.notify_one();
            f.api = Foyer::with_trust(
                crate::HttpClient::with_roots(
                    f.tls.origin.clone(),
                    "127.0.0.1".into(),
                    None,
                    std::slice::from_ref(&f.tls.root),
                )
                .unwrap(),
                trust(&f.service, &f.tls).await,
            );
        }
        // The actual server already inserted before the lost/refused reply.
        // An exact replay refuses, while real same-key UV proves enrollment.
        assert!(
            f.api
                .resume_initial_registration(
                    FinishContinuation::from_bytes(&bytes).unwrap(),
                    || NOW
                )
                .await
                .is_err()
        );
        prove_current_original(&mut f.api, &mut f.keys, &f.raw_id).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn genuine_wrong_cpky_challenge_is_public_data_then_refused_by_original_server() {
    let mut first = InitialFixture::new().await;
    let other = InitialFixture::new().await;
    let data = first
        .pending
        .prepare_finish(&first.api, other.public, || NOW)
        .await
        .unwrap();
    assert!(
        first
            .api
            .resume_initial_registration(data, || NOW)
            .await
            .is_err()
    );
    // Sanitized CPky provenance alone cannot accept a different server ceremony.
    assert!(first.api.shared.session.lock().await.info.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn original_initial_begin_afterawait_clock_policy_close_and_cancellation_refuse() {
    for outcome in 0..5 {
        let (_service, tls, mut api, proof) = environment().await;
        tls.gate.action.store(1, Ordering::SeqCst);
        tls.gate.enabled.store(true, Ordering::SeqCst);
        let shared = api.shared.clone();
        let trust_owner = api.trust.clone();
        let clock = Arc::new(AtomicU64::new(NOW));
        let observed = clock.clone();
        let mut future = Box::pin(
            api.begin_initial_registration(proof, SEED, move || observed.load(Ordering::SeqCst)),
        );
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(5), tls.gate.arrived.notified()) => result.unwrap(),
            _ = &mut future => panic!("original pending challenge reply should be gated"),
        }
        match outcome {
            0 => clock.store(NOW - 1, Ordering::SeqCst),
            1 => clock.store(NOW + 300, Ordering::SeqCst),
            2 => shared.close(),
            3 => trust_owner.try_lock().unwrap().as_mut().unwrap().stop(),
            _ => {
                drop(future);
                tls.gate.release.notify_one();
                // The actual pending request and held mutex were released.
                let (_pending, _) = shared.begin_pending().unwrap();
                assert!(shared.session.try_lock().is_some());
                continue;
            }
        }
        tls.gate.release.notify_one();
        assert!(future.await.is_err());
    }
}
