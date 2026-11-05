#![cfg(not(target_arch = "wasm32"))]
#[path = "../cases/member.rs"]
mod member;
#[path = "../support/owner.rs"]
mod support;

use cfyr::{Error, Foyer, HttpClient, action};
use serde_json::json;
use support::*;
use webauthn_authenticator_rs::AuthenticatorBackend as _;

fn foyer(service: &Running, host: &str, session: Option<String>) -> Foyer<HttpClient> {
    Foyer::new(HttpClient::new(service.base.clone(), host.into(), session).unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn discoverable_browser_request_keeps_original_public_owner_options() {
    let service = global(100).await;
    let mut api = foyer(&service, WALLET, None);
    let challenge = api.begin_browser_login().await.unwrap();
    assert!(!challenge.ceremony.is_empty());
    assert_eq!(challenge.options["publicKey"]["rpId"], WALLET);
    assert!(matches!(
        api.call("passport_challenge", json!({})).await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn trusted_login_installs_a_session_and_exports_only_safe_identity_fields() {
    let service = global(100).await;
    for (host, bootstrap, role) in [
        (WALLET, None, "member"),
        (
            ROOT,
            Some("synthetic-operator-enrolment-capability"),
            "root",
        ),
    ] {
        // The operator Root is enrolled once per Global: its sign-in assertion comes from that
        // one passkey (the enrolment helper only returns a session for it).
        let (user, request) = if host == ROOT {
            active::root_login_request(&service).await
        } else {
            let mut member = enrol(&service, host, bootstrap).await;
            let request = login_request(
                &service,
                host,
                &mut member.authenticator,
                &member.user,
                &member.credential,
            )
            .await;
            (member.user, request)
        };
        let mut api = foyer(&service, host, None);
        assert!(action("login_finish").is_none());
        assert!(cfyr::contract()["paths"]["/v1/login_finish"].is_null());
        assert!(matches!(
            api.call("login_finish", request.clone()).await,
            Err(Error::Invalid)
        ));
        let info = api.authenticate(request.clone()).await.unwrap();
        assert_eq!(info.user, user);
        assert_eq!(info.role, role);
        assert!(info.expires > NOW);
        let safe = serde_json::to_value(&info).unwrap();
        assert!(safe.get("token").is_none());
        assert_eq!(safe.as_object().unwrap().len(), 3);
        assert!(matches!(
            api.authenticate(request).await,
            Err(Error::Unauthorized)
        ));
        api.call("logout", json!({})).await.unwrap();
        assert!(matches!(
            api.call("logout", json!({})).await,
            Err(Error::Unauthorized)
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn public_member_and_root_requests_reach_the_real_owner() {
    let service = global(100).await;
    let mut public = foyer(&service, WALLET, None);
    assert!(public.call("global_public", json!({})).await.unwrap()["issuer"].is_array());
    assert!(matches!(
        public.call("passport_challenge", json!({})).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        public.call("../logout", json!({})).await,
        Err(Error::Invalid)
    ));
    let mut enrolled = enrol(&service, WALLET, None).await;
    let mut member = foyer(&service, WALLET, Some(enrolled.session.clone()));
    member.call("development_gate", json!({})).await.unwrap();
    assert!(member.call("passport_challenge", json!({})).await.is_ok());
    let root = enrol(
        &service,
        ROOT,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
    let mut root = foyer(&service, ROOT, Some(root.session));
    // The operator routes that warned or suspended a member were removed: no role can call them, and
    // the owner contract does not forward them.
    for name in ["global_warn", "global_suspend"] {
        assert!(action(name).is_none());
        let body = json!({"user":"00000000-0000-4000-8000-0000000000ff","until":NOW+1});
        assert!(matches!(
            member.call(name, body.clone()).await,
            Err(Error::Invalid)
        ));
        assert!(matches!(root.call(name, body).await, Err(Error::Invalid)));
    }
    assert!(member.call("passport_challenge", json!({})).await.is_ok());
    // The member alone ends its own access, permanently, with a fresh passkey ceremony.
    let begin = member
        .call("global_self_ban_begin", json!({}))
        .await
        .unwrap();
    let challenge: ckyh::RequestChallengeResponse =
        serde_json::from_value(begin["options"].clone()).unwrap();
    let credential = enrolled
        .authenticator
        .perform_auth(
            ckyh::Url::parse(&origin_for(WALLET)).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    member
        .call(
            "global_self_ban_finish",
            json!({"ceremony": begin["ceremony"], "credential": credential}),
        )
        .await
        .unwrap();
    assert!(member.call("passport_challenge", json!({})).await.is_err());
    root.call("logout", json!({})).await.unwrap();
    assert!(matches!(
        root.call("logout", json!({})).await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn community_admin_uses_the_same_registry_and_cannot_become_root() {
    let wallet = global(100).await;
    let public = serde_json::from_value(
        foyer(&wallet, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let community = community("alpha", &public).await;
    let host = "api.admin.alpha.example.test";
    // Signup cannot assign a role: the community's first admin is its founder, who signs in on
    // the admin host with the passkey that founded it.
    let mut founder = active::take_founder(&community).expect("a founded community has a founder");
    let session = login(
        &community,
        host,
        &mut founder.authenticator,
        &founder.user,
        &founder.credential,
    )
    .await;
    let mut admin = foyer(&community, host, Some(session));
    let metadata = action("setting_set").unwrap();
    assert_eq!(metadata.schema()["x-role"], "admin");
    assert_eq!(metadata.schema()["x-scope"], "community");
    community.clock.set(NOW + 1);
    let changed = admin
        .call(
            "setting_set",
            json!({"key":"quota","value":5,"inherit":false,"effective_at":NOW+1}),
        )
        .await
        .unwrap();
    assert!(changed["policy_epoch"].as_u64().unwrap() > 1);
    assert!(matches!(admin.call("platform_set", json!({"setting":{"key":"quota","value":3,"inherit":false,"effective_at":NOW+2},"force":true})).await, Err(Error::Forbidden)));
    assert!(matches!(
        admin.call("global_public", json!({})).await,
        Err(Error::WrongHost)
    ));
    let root = enrol(
        &community,
        ROOT,
        Some("synthetic-root-enrolment-capability"),
    )
    .await;
    let mut root = foyer(&community, ROOT, Some(root.session));
    community.clock.set(NOW + 2);
    let forced = root.call("platform_set", json!({"setting":{"key":"quota","value":3,"inherit":false,"effective_at":NOW+2},"force":true})).await.unwrap();
    assert_ne!(forced["settings"], changed["settings"]);
}

/// A device without an enrolling lease (a reopened lease, the wave and record jobs) reads the
/// current roster through the PUBLIC `account_checkpoint` route, over a Foyer that installed no
/// session: the real owner answers it exactly as the plain public call. A Foyer that holds a
/// member session refuses it before anything is sent, and its session is untouched.
#[tokio::test(flavor = "multi_thread")]
async fn the_public_roster_read_never_rides_a_member_session() {
    let wallet = global(100).await;
    let public = serde_json::from_value(
        foyer(&wallet, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let community = community("alpha", &public).await;
    let host = "api.alpha.example.test";
    let mut anonymous = foyer(&community, host, None);
    let direct = anonymous
        .call("account_checkpoint", json!({"slot": null}))
        .await;
    let read = anonymous.public_enrollment_checkpoint().await;
    assert_eq!(format!("{read:?}"), format!("{direct:?}"));
    assert!(!matches!(read, Err(Error::Unauthorized)), "{read:?}");
    let mut member = enrol(&wallet, WALLET, None).await;
    let request = login_request(
        &wallet,
        WALLET,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
    let mut signed_in = foyer(&wallet, WALLET, None);
    signed_in.authenticate(request).await.unwrap();
    assert!(matches!(
        signed_in.public_enrollment_checkpoint().await,
        Err(Error::Unauthorized)
    ));
    signed_in.call("logout", json!({})).await.unwrap();
}

/// A13 (ALPHA-CRYPTO-GAPS row A13): a long operation crosses the wallet session lifetime four
/// times with 0 extra passkey prompts. The wallet login carries the wallet device key K's proof
/// of possession, so the wallet anchors its family to K (bound to the passkey by a step-up
/// before); from then on `Foyer::renew_wallet_session` keeps the session alive by K alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_long_operation_crosses_the_wallet_lifetime_with_no_prompt() {
    use ed25519_dalek::Signer as _;
    let service = wallet_global(100).await;
    let mut member = enrol(&service, WALLET, None).await;
    let k = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
    let device = k.verifying_key().to_bytes();
    let bind = proven(
        &service,
        WALLET,
        &member.session,
        &mut member.authenticator,
        json!({"kind":"device_authorize","key":device}),
        json!({"key":device}),
    )
    .await;
    client(&service, WALLET, Some(&member.session))
        .call("wallet_device_authorize", bind)
        .await
        .unwrap();
    // The wallet login with K's proof: the only prompt of the whole operation.
    let mut request = login_request(
        &service,
        WALLET,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
    drop(member.authenticator);
    let ceremony = request["ceremony"].as_str().unwrap().to_owned();
    let proof = k.sign(&cvld::device_session::wallet_login_message(
        WALLET, &ceremony,
    ));
    request["device_proof"] = json!({"device_key":device,"signature":proof.to_bytes().to_vec()});
    let mut api = foyer(&service, WALLET, None);
    let login = api.authenticate(request).await.unwrap();
    let family = login.family.expect("the login anchored its family to K");
    assert_eq!(api.wallet_family().await, Some(family));
    // K signs the tagged message, as ckmg's `WalletSessionKey::sign` does.
    let sign = |payload: &[u8]| {
        let message = [cvld::device_session::WALLET_SESSION_TAG, payload].concat();
        Some(k.sign(&message).to_bytes())
    };
    // The current passkey C stays the session's credential through every renewal.
    let current = |list: serde_json::Value| {
        list["passkeys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["current"] == true)
    };
    let mut expires = login.expires;
    // Not due yet: nothing is sent, the session stays.
    assert!(
        !api.renew_wallet_session(WALLET, expires - 400, device, sign)
            .await
            .unwrap()
    );
    for _ in 0..4 {
        // The operation keeps working on its session until 60 s before the deadline ...
        let now = expires - 60;
        service.clock.set(now);
        assert!(current(api.call("passkey_list", json!({})).await.unwrap()));
        // ... and the renewer keeps it alive by K, silently.
        assert!(
            api.renew_wallet_session(WALLET, now, device, sign)
                .await
                .unwrap()
        );
        assert_eq!(api.wallet_family().await, Some(family));
        assert!(current(api.call("passkey_list", json!({})).await.unwrap()));
        expires = now + 600;
    }
    // Far past four lifetimes of the login, the operation still works without a prompt.
    service.clock.set(expires - 1);
    assert!(expires - 1 > login.expires + 3 * 500);
    assert!(current(api.call("passkey_list", json!({})).await.unwrap()));
}
