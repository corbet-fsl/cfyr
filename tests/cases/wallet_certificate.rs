//! Same original Wallet owners over actual pinned TLS; no Keys/G3/Tor verdict.
use super::*;
use crate::membership::InitialCreationLease;

const SEED: [u8; 32] = [21; 32];
const PUBLICATION: [u8; 32] = [22; 32];
const DEVICE: [u8; 32] = [49; 32];
const SIGNER_SECONDS: u64 = 100 * 86_400;

async fn running() -> Running {
    let dir = tempfile::tempdir().unwrap();
    let mut config = global_config(dir.path(), 1000).await;
    let mut rules = cmty::cplc::crbk::Rulebook::default();
    rules
        .define(
            "quota",
            cmty::cplc::crbk::Setting {
                value_type: cmty::cplc::crbk::SettingType::Integer,
                nullable: false,
                default: json!(17),
                bounds: cmty::cplc::crbk::Bounds {
                    min: Some(0.into()),
                    max: Some(100.into()),
                },
                lowest_layer: cmty::cplc::crbk::Layer::Community,
                kind: cmty::cplc::crbk::SettingKind::Technical,
            },
        )
        .unwrap();
    let schema = serde_json::from_value(json!({"community":"wallet","version":1,
        "public":[{"id":"consent","label":"Receive invitations?","kind":{"type":"yes_no"},
            "required":true,"filterable":false,"change_preset":"stable","no_contact_details":false}],"private":[]})).unwrap();
    let publication = cgbl::WalletPublicationConfig::new(
        WALLET,
        VAULT,
        rules,
        cmty::cplc::SchemaVersions {
            purpose: cmty::cplc::SchemaVersionsPurpose::SchemaVersionsV1,
            current: 1,
            versions: vec![cmty::cplc::SchemaVersion {
                schema,
                changes: None,
            }],
        },
        std::collections::BTreeSet::new(),
        2 * 86_400,
    )
    .unwrap();
    let seed = dir.path().join("wallet-seed");
    std::fs::write(&seed, [47; 32]).unwrap();
    let settings = dir.path().join("wallet-publication.json");
    std::fs::write(&settings, serde_json::to_vec(&publication).unwrap()).unwrap();
    config.wallet = Some(cvld::config::WalletConfig {
        signing_seed_file: seed.to_str().unwrap().into(),
        publication_file: settings.to_str().unwrap().into(),
        signer_max_seconds: SIGNER_SECONDS,
    });
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let door = cvld::service::Door::global(config, clock.clone())
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = cvld::api::router(door.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Running {
        base,
        door,
        clock,
        task,
        dir,
    }
}

fn following() -> crate::trust::Config {
    crate::trust::Config {
        retry_entropy: 0,
        refresh_seconds: 40,
        poll_seconds: 2,
        request_seconds: 26,
        initial_backoff_seconds: 2,
        maximum_backoff_seconds: 16,
        maximum_staleness_seconds: 60,
    }
}
async fn api(tls: &TlsIngress) -> Foyer<crate::HttpClient> {
    // Trusted test deployment seed, lifetime and activation exactly match the
    // actual producer configuration. A received feed never supplies this root.
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "wallet",
        csgn::SecretKey::from_seed(&mut [47; 32]),
        NOW / 86_400 * 86_400,
        SIGNER_SECONDS,
    )
    .await
    .unwrap();
    let configuration = crate::trust::Configuration {
        origin: tls.origin.clone(),
        community: "wallet".into(),
        key_ring: signer.key_ring().unwrap().to_cbor(),
        minimum_revision: 1,
        ring_revision: 0,
    };
    let mut trust = crate::trust::Trust::wallet_native(
        configuration,
        following(),
        std::slice::from_ref(&tls.root),
    )
    .unwrap();
    trust.start(|| NOW).await.unwrap();
    Foyer::with_trust(
        crate::HttpClient::with_roots(
            tls.origin.clone(),
            "127.0.0.1".into(),
            None,
            std::slice::from_ref(&tls.root),
        )
        .unwrap(),
        trust,
    )
}

struct WalletFixture {
    _service: Running,
    tls: TlsIngress,
    foyer: Foyer<crate::HttpClient>,
    keys: cpky::Client<SoftwareAuthenticator>,
    user: String,
    id: Vec<u8>,
}
impl WalletFixture {
    async fn new() -> Self {
        for name in [
            "wallet_trust_feed",
            "wallet_trust_changes",
            "wallet_device_keys",
            "wallet_device_authorize",
        ] {
            assert!(
                cvld::client::forwarding_action(name).is_some(),
                "requires genuine generated Wallet action"
            );
        }
        let service = running().await;
        let tls = TlsIngress::new(&service).await;
        let mut foyer = api(&tls).await;
        let mut keys = passkeys();
        let mut reservation = foyer
            .begin_global_initial_registration(&tls.origin, || NOW)
            .await
            .unwrap();
        let user = reservation.account().to_owned();
        let pending = reservation
            .continue_initial(&foyer, SEED, || NOW)
            .await
            .unwrap();
        let (public, prf) = keys
            .register_member(pending.options().clone())
            .await
            .unwrap()
            .into_parts();
        drop(prf);
        let id = public.credential_id().unwrap();
        let finish = pending
            .prepare_finish(&foyer, public, || NOW)
            .await
            .unwrap();
        foyer
            .resume_global_initial_registration(finish, || NOW)
            .await
            .unwrap();
        assert_eq!(login(&mut foyer, &mut keys).await, id);
        let body = crate::test_step_up::proven(
            &mut foyer,
            &mut keys,
            json!({"kind":"device_authorize","key":DEVICE}),
            json!({"key":DEVICE}),
        )
        .await;
        foyer.call("wallet_device_authorize", body).await.unwrap();
        // Authorizing the device changed the actual signed publication. The
        // same original Follower refreshes it before certificate composition.
        {
            let mut trust = foyer.trust().unwrap();
            trust.refresh(NOW).unwrap();
            trust.poll(|| NOW).await.unwrap();
        }
        Self {
            _service: service,
            tls,
            foyer,
            keys,
            user,
            id,
        }
    }
    async fn initial<'p>(
        &self,
        policy: &'p mut crate::policy::CurrentPolicy<crate::HttpClient>,
    ) -> InitialCreationLease<'p, crate::HttpClient> {
        self.foyer
            .live_wallet_membership()
            .observe_lease(|| NOW)
            .await
            .unwrap()
            .passkey_certificate(policy, || NOW)
            .await
            .unwrap()
            .initial_creation(|| NOW)
            .await
            .unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn original_wallet_uuid_key_devices_and_charter_join_the_same_certificate_protocol() {
    let f = WalletFixture::new().await;
    let mut policy = f.foyer.current_policy();
    let initial = f.initial(&mut policy).await;
    assert_eq!(initial.seed().unwrap(), SEED);
    assert_eq!(initial.publication().unwrap(), None);
    assert_eq!(initial.credential_id().unwrap(), f.id);
    assert_eq!(initial.observation().unwrap().member, f.user);
    assert_eq!(initial.observation().unwrap().device_keys, vec![DEVICE]);
    let mut initial = initial.bind_publication(PUBLICATION, || NOW).await.unwrap();
    let deadline = initial.expires().unwrap();
    initial.refresh(|| NOW).await.unwrap();
    assert_eq!(initial.publication().unwrap(), Some(PUBLICATION));
    assert_eq!(initial.expires().unwrap(), deadline);
    initial
        .with_current(|| NOW, |current| assert_eq!(current.community(), "wallet"))
        .unwrap();
    assert!(initial.check(|| deadline).is_err());
    assert!(initial.certificate_bytes().is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn readable_seed_metadata_after_real_permanent_ban_cannot_restore_wallet_authority() {
    let mut f = WalletFixture::new().await;
    let mut policy = f.foyer.current_policy();
    let mut initial = f
        .initial(&mut policy)
        .await
        .bind_publication(PUBLICATION, || NOW)
        .await
        .unwrap();
    let mut companion = api(&f.tls).await;
    login(&mut companion, &mut f.keys).await;
    let begin = companion
        .call("global_self_ban_begin", json!({}))
        .await
        .unwrap();
    let (public, prf) = f
        .keys
        .sign_in(begin["options"].clone())
        .await
        .unwrap()
        .into_parts();
    drop(prf);
    companion
        .call(
            "global_self_ban_finish",
            json!({"ceremony":begin["ceremony"],"credential":public.into_json()}),
        )
        .await
        .unwrap();
    login(&mut companion, &mut f.keys).await;
    let state = companion.call("initial_creation", json!({})).await.unwrap();
    assert_eq!(state["seed"], json!(SEED));
    assert_eq!(state["publication"], json!(PUBLICATION));
    assert!(initial.refresh(|| NOW).await.is_err());
    assert!(initial.check(|| NOW).is_err());
    assert!(initial.observation().is_err());
    assert!(
        companion
            .live_wallet_membership()
            .observe_lease(|| NOW)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_wallet_refresh_cancellation_and_postreply_time_refusal_are_terminal() {
    for (completion, close) in [
        (None, false),
        (None, true),
        (Some(NOW - 1), false),
        (Some(NOW + 600), false),
    ] {
        let f = WalletFixture::new().await;
        let mut policy = f.foyer.current_policy();
        let mut initial = f
            .initial(&mut policy)
            .await
            .bind_publication(PUBLICATION, || NOW)
            .await
            .unwrap();
        f.tls.mutation.target.store(3, Ordering::SeqCst);
        f.tls.mutation.enabled.store(true, Ordering::SeqCst);
        let clock = Arc::new(AtomicU64::new(NOW));
        let observed = clock.clone();
        let mut request = Box::pin(initial.refresh(move || observed.load(Ordering::SeqCst)));
        tokio::select! {
            _ = f.tls.mutation.arrived.notified() => {},
            _ = &mut request => panic!("genuine equal bind reply must be held"),
        }
        if close {
            f.foyer.shared.close();
            assert!(request.await.is_err());
            f.tls.mutation.release.notify_one();
        } else if let Some(now) = completion {
            clock.store(now, Ordering::SeqCst);
            f.tls.mutation.release.notify_one();
            assert!(request.await.is_err());
        } else {
            drop(request);
            f.tls.mutation.release.notify_one();
        }
        assert!(initial.check(|| NOW + 1).is_err());
        assert!(initial.credential_id().is_err());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn another_current_policy_or_same_account_noncurrent_key_cannot_join_the_wallet_certificate()
{
    let mut f = WalletFixture::new().await;
    let mut companion = api(&f.tls).await;
    login(&mut companion, &mut f.keys).await;
    let mut foreign = companion.current_policy();
    let lease = f
        .foyer
        .live_wallet_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap();
    assert!(
        lease
            .passkey_certificate(&mut foreign, || NOW)
            .await
            .is_err()
    );

    let body = crate::test_step_up::proven(
        &mut f.foyer,
        &mut f.keys,
        json!({"kind":"passkey_add"}),
        json!({"step":"begin"}),
    )
    .await;
    let begin = f.foyer.call("passkey_add", body).await.unwrap();
    let mut added = passkeys();
    let (public, prf) = added
        .register_member(begin["options"].clone())
        .await
        .unwrap()
        .into_parts();
    drop(prf);
    let other_id = public.credential_id().unwrap();
    f.foyer
        .call(
            "passkey_add",
            json!({"step":"finish","ceremony":begin["ceremony"],"credential":public.into_json()}),
        )
        .await
        .unwrap();
    let response = f.foyer.call("passkey_list", json!({})).await.unwrap();
    assert!(
        response["passkeys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["credential"] == json!(other_id)
                && row["current"] == false
                && row["revoked"] == false)
    );
    // The attack changes only a retained local claim. The real server still
    // identifies the original current A key, so its actual fresh row refuses B.
    f.foyer.shared.session.lock().await.login_credential = Some(other_id.clone());
    assert!(
        f.foyer
            .live_wallet_membership()
            .observe_lease(|| NOW)
            .await
            .is_err()
    );
    assert_eq!(login(&mut f.foyer, &mut added).await, other_id);
    let mut policy = f.foyer.current_policy();
    let certified = f
        .foyer
        .live_wallet_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .passkey_certificate(&mut policy, || NOW)
        .await
        .unwrap();
    assert_eq!(certified.credential_id().unwrap(), other_id);
    // Equal passkeys can obtain their own real certificate, but the additional
    // key does not acquire the original first-key immutable creation binding.
    assert!(certified.initial_creation(|| NOW).await.is_err());
}
