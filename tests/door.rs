#![cfg(not(target_arch = "wasm32"))]
#[path = "cases/member.rs"]
mod member;
#[path = "support/owner.rs"]
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
