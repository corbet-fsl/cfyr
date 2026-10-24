//! Original HTTPS client, server, passport, enrolment and passkey session. No
//! substitute roster/authority supplies the successful observations.
use super::*;
#[path = "../support/owner.rs"]
mod owner;
use owner::*;
use serde_json::json;
use webauthn_authenticator_rs::AuthenticatorBackend as _;

async fn authenticated(
    service: &Running,
    member: &mut Member,
) -> (Foyer<crate::HttpClient>, SessionInfo) {
    let host = "api.alpha.example.test";
    let mut foyer =
        Foyer::new(crate::HttpClient::new(service.base.clone(), host.into(), None).unwrap());
    let assertion = login_request(
        service,
        host,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
    let info = foyer.authenticate(assertion).await.unwrap();
    (foyer, info)
}

struct RegisteredCommunity {
    foyer: Foyer<crate::HttpClient>,
    registered: crate::registration::RegisteredSession<crate::HttpClient>,
    passkeys: cpky::Client<cpky::software::SoftwareAuthenticator>,
    info: SessionInfo,
    device: [u8; 32],
}

async fn registered_session(service: &Running, passport: &cpsd::Passport) -> RegisteredCommunity {
    use cpky::software::{SoftwareAuthenticator, TestConfiguration};
    let host = "api.alpha.example.test";
    let origin = "https://vault.alpha.example.test";
    let proof = presentation(service, host, None, passport).await;
    let mut foyer =
        Foyer::new(crate::HttpClient::new(service.base.clone(), host.into(), None).unwrap());
    let pending = foyer
        .begin_member_registration(Some(serde_json::to_value(proof).unwrap()))
        .await
        .unwrap();
    let mut passkeys = cpky::Client::new(
        cpky::Context::new(origin, "alpha.example.test").unwrap(),
        SoftwareAuthenticator::new(
            origin,
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap(),
    );
    let (credential, custody) = passkeys
        .register_member(pending.options().clone())
        .await
        .unwrap()
        .into_parts();
    drop(custody);
    let registered = foyer
        .finish_member_registration(pending, credential)
        .await
        .unwrap();
    let info = login_registered(&mut foyer, &mut passkeys).await;
    let continued = registered
        .continue_after_login(&foyer, || NOW)
        .await
        .unwrap();
    // The actual external device key is bound by the original authenticated
    // owner, never inserted into a returned observation or accepted authority.
    let device = ed25519_dalek::SigningKey::from_bytes(&[53; 32])
        .verifying_key()
        .to_bytes();
    authorize_device_with_step_up(&mut foyer, &mut passkeys, device).await;
    RegisteredCommunity {
        foyer,
        registered: continued,
        passkeys,
        info,
        device,
    }
}

/// Authorize a device key as a real member does: `step_up_begin` for exactly this action, the passkey assertion for
/// that ceremony, then the action with the proof (cvld requires a fresh step-up for every device action).
async fn authorize_device_with_step_up(
    foyer: &mut Foyer<crate::HttpClient>,
    passkeys: &mut cpky::Client<cpky::software::SoftwareAuthenticator>,
    key: [u8; 32],
) {
    let begin = foyer
        .call(
            "step_up_begin",
            json!({"action": {"kind": "device_authorize", "key": key}}),
        )
        .await
        .unwrap();
    let (credential, _) = passkeys
        .sign_in(begin["options"].clone())
        .await
        .unwrap()
        .into_parts();
    foyer
        .call(
            "device_authorize",
            json!({"key": key, "step_up": {"ceremony": begin["ceremony"], "credential": credential.into_json()}}),
        )
        .await
        .unwrap();
}

async fn login_registered(
    foyer: &mut Foyer<crate::HttpClient>,
    passkeys: &mut cpky::Client<cpky::software::SoftwareAuthenticator>,
) -> SessionInfo {
    let challenge = foyer.begin_browser_login().await.unwrap();
    let (credential, custody) = passkeys
        .sign_in(challenge.options)
        .await
        .unwrap()
        .into_parts();
    drop(custody);
    foyer
        .finish_browser_login(challenge.ceremony, credential)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_membership_lease_joins_registration_and_defers_local_logout_until_drop() {
    let wallet = global(200).await;
    let (_, passport, public) = wallet_passport(&wallet).await;
    let service = community("alpha", &public).await;
    let RegisteredCommunity {
        mut foyer,
        mut registered,
        info,
        device,
        ..
    } = registered_session(&service, &passport).await;
    let mut port = foyer.live_membership();
    let mut lease = port.observe_lease(|| NOW).await.unwrap();
    assert_eq!(
        lease.observation().member,
        passport
            .pseudonym(&cpsd::CommunityId::new("alpha").unwrap())
            .to_hex()
    );
    assert_ne!(lease.observation().member, info.user);
    assert_eq!(lease.observation().device_keys, vec![device]);
    assert_eq!(lease.observation().expires, info.expires);
    registered.check_with_lease(&mut lease, || NOW).unwrap();
    registered
        .consume_with_lease(&mut lease, || NOW + 1)
        .unwrap();
    assert!(matches!(foyer.session_binding(), Err(Error::Unavailable)));
    assert!(matches!(
        port.observe_lease(|| NOW + 1).await,
        Err(Error::Unavailable)
    ));
    let mut logout = Box::pin(foyer.call("logout", json!({})));
    assert!(futures::poll!(logout.as_mut()).is_pending());
    lease.check(|| NOW + 1).unwrap();
    drop(lease);
    logout.await.unwrap();
    assert!(matches!(foyer.session_binding(), Err(Error::Unauthorized)));
}

#[tokio::test(flavor = "multi_thread")]
async fn lease_refuses_expiry_rollback_and_owner_disposal_without_revival() {
    for failure in 0..3 {
        let wallet = global(200).await;
        let (_, passport, public) = wallet_passport(&wallet).await;
        let service = community("alpha", &public).await;
        let RegisteredCommunity { foyer, info, .. } = registered_session(&service, &passport).await;
        let mut port = foyer.live_membership();
        let mut lease = port.observe_lease(|| NOW).await.unwrap();
        lease.check(|| NOW + 1).unwrap();
        if failure == 2 {
            drop(foyer);
        }
        let time = if failure == 0 {
            info.expires
        } else if failure == 1 {
            NOW
        } else {
            NOW + 1
        };
        assert!(lease.check(|| time).is_err());
        assert!(lease.check(|| NOW + 2).is_err());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_original_lease_read_releases_its_pending_attempt_and_session_lock() {
    let wallet = global(200).await;
    let (_, passport, public) = wallet_passport(&wallet).await;
    let service = community("alpha", &public).await;
    let RegisteredCommunity { foyer, .. } = registered_session(&service, &passport).await;
    let mut port = foyer.live_membership();
    let held = foyer.shared.session.lock().await;
    let mut read = Box::pin(port.observe_lease(|| NOW));
    assert!(futures::poll!(read.as_mut()).is_pending());
    drop(read);
    drop(held);
    let lease = port.observe_lease(|| NOW).await.unwrap();
    drop(lease);
    assert!(port.observe(|| NOW).await.is_ok());
    foyer.session_binding().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn genuine_later_login_lease_cannot_consume_the_first_registered_session() {
    let wallet = global(200).await;
    let (_, passport, public) = wallet_passport(&wallet).await;
    let service = community("alpha", &public).await;
    let RegisteredCommunity {
        mut foyer,
        mut registered,
        mut passkeys,
        ..
    } = registered_session(&service, &passport).await;
    login_registered(&mut foyer, &mut passkeys).await;
    let mut port = foyer.live_membership();
    let mut lease = port.observe_lease(|| NOW).await.unwrap();
    assert!(matches!(
        registered.check_with_lease(&mut lease, || NOW),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        registered.consume_with_lease(&mut lease, || NOW),
        Err(Error::Unauthorized)
    ));
    // A failed registration join does not fabricate or replace this separately
    // authenticated original member observation.
    lease.check(|| NOW).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn identical_real_member_sessions_on_another_foyer_cannot_share_registration_provenance() {
    let wallet = global(200).await;
    let (_, passport, public) = wallet_passport(&wallet).await;
    let service = community("alpha", &public).await;
    let RegisteredCommunity {
        foyer,
        mut registered,
        mut passkeys,
        info,
        ..
    } = registered_session(&service, &passport).await;
    let mut foreign = Foyer::new(
        crate::HttpClient::new(service.base.clone(), "api.alpha.example.test".into(), None)
            .unwrap(),
    );
    let same = login_registered(&mut foreign, &mut passkeys).await;
    assert_eq!(same, info);
    let mut port = foreign.live_membership();
    let mut lease = port.observe_lease(|| NOW).await.unwrap();
    assert!(matches!(
        registered.check_with_lease(&mut lease, || NOW),
        Err(Error::Unauthorized)
    ));
    let mut original = foyer.live_membership();
    let mut original_lease = original.observe_lease(|| NOW).await.unwrap();
    assert!(matches!(
        registered.consume_with_lease(&mut original_lease, || NOW),
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn original_session_roster_uses_real_pseudonym_and_refuses_after_passkey_revocation() {
    let wallet = global(200).await;
    let (_, passport, public) = wallet_passport(&wallet).await;
    let service = community("alpha", &public).await;
    let mut member = enrol_community(&service, "api.alpha.example.test", &passport).await;
    let (mut foyer, info) = authenticated(&service, &mut member).await;
    let mut port = foyer.live_membership();
    let actual = port.observe(|| NOW).await.unwrap();
    assert_eq!(
        actual.member,
        passport
            .pseudonym(&cpsd::CommunityId::new("alpha").unwrap())
            .to_hex()
    );
    assert_ne!(actual.member, info.user);
    assert_eq!(actual.device_keys, vec![member.signing_key]);
    assert_eq!(actual.expires, info.expires);
    let begin = crate::test_step_up::begin(
        &mut foyer,
        json!({"kind":"passkey_revoke","credential":member.credential}),
    )
    .await;
    let challenge: ckyh::RequestChallengeResponse =
        serde_json::from_value(begin["options"].clone()).unwrap();
    let credential = member
        .authenticator
        .perform_auth(
            ckyh::Url::parse(&owner::origin_for("api.alpha.example.test")).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    let body = json!({
        "credential": member.credential,
        "step_up": {"ceremony": begin["ceremony"], "credential": credential},
    });
    foyer.call("passkey_revoke", body).await.unwrap();
    assert!(port.observe(|| NOW).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn constructor_bearer_is_not_a_deadline_and_original_login_updates_the_same_port() {
    let wallet = global(200).await;
    let (_, passport, public) = wallet_passport(&wallet).await;
    let service = community("alpha", &public).await;
    let host = "api.alpha.example.test";
    let mut member = enrol_community(&service, host, &passport).await;
    let mut foyer = Foyer::new(
        crate::HttpClient::new(
            service.base.clone(),
            host.into(),
            Some(member.session.clone()),
        )
        .unwrap(),
    );
    let mut port = foyer.live_membership();
    assert!(matches!(
        port.observe(|| NOW).await,
        Err(Error::Unauthorized)
    ));
    let assertion = login_request(
        &service,
        host,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
    let info = foyer.authenticate(assertion).await.unwrap();
    assert_eq!(port.observe(|| NOW).await.unwrap().expires, info.expires);
    assert!(matches!(
        port.observe(|| info.expires).await,
        Err(Error::Unauthorized)
    ));
    let mut call = 0;
    assert!(matches!(
        port.observe(|| {
            call += 1;
            if call < 3 { NOW } else { NOW - 1 }
        })
        .await,
        Err(Error::Unauthorized)
    ));
    let mut call = 0;
    assert!(matches!(
        port.observe(|| {
            call += 1;
            if call < 3 { NOW } else { info.expires }
        })
        .await,
        Err(Error::Unauthorized)
    ));
    drop(foyer);
    assert!(matches!(
        port.observe(|| NOW).await,
        Err(Error::Unavailable)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_owner_aborts_a_waiting_read_and_read_cancellation_releases_the_slot() {
    let wallet = global(200).await;
    let (_, passport, public) = wallet_passport(&wallet).await;
    let service = community("alpha", &public).await;
    let mut member = enrol_community(&service, "api.alpha.example.test", &passport).await;
    let (foyer, _) = authenticated(&service, &mut member).await;
    let mut port = foyer.live_membership();
    // Hold the actual owner mutex to exercise cancellation before HTTP begins;
    // successful reads before/after still use the original server above.
    let shared = foyer.shared.clone();
    let guard = shared.session.lock().await;
    let mut pending = Box::pin(port.observe(|| NOW));
    assert!(futures::poll!(pending.as_mut()).is_pending());
    drop(pending);
    drop(guard);
    assert_eq!(
        port.observe(|| NOW).await.unwrap().device_keys,
        vec![member.signing_key]
    );
    let guard = shared.session.lock().await;
    let mut pending = Box::pin(port.observe(|| NOW));
    assert!(futures::poll!(pending.as_mut()).is_pending());
    drop(foyer);
    assert!(matches!(pending.await, Err(Error::Unavailable)));
    drop(guard);
    drop(shared);
    assert!(matches!(
        port.observe(|| NOW).await,
        Err(Error::Unavailable)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn session_binding_pins_exact_owner_and_installation_without_bearer_export() {
    let wallet = global(200).await;
    let (_, passport, public) = wallet_passport(&wallet).await;
    let service = community("alpha", &public).await;
    let host = "api.alpha.example.test";
    let mut member = enrol_community(&service, host, &passport).await;
    let (mut foyer, info) = authenticated(&service, &mut member).await;
    let stamp = foyer.session_binding().unwrap();
    stamp.check(&foyer, NOW).unwrap();
    assert!(matches!(
        stamp.check(&foyer, info.expires),
        Err(Error::Unauthorized)
    ));
    let foreign =
        Foyer::new(crate::HttpClient::new(service.base.clone(), host.into(), None).unwrap());
    assert!(matches!(
        foreign.session_binding(),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        stamp.check(&foreign, NOW),
        Err(Error::Unauthorized)
    ));
    {
        let _borrow = foyer.shared.session.lock().await;
        assert!(matches!(foyer.session_binding(), Err(Error::Unavailable)));
        assert!(matches!(stamp.check(&foyer, NOW), Err(Error::Unavailable)));
    }
    let request = login_request(
        &service,
        host,
        &mut member.authenticator,
        &member.user,
        &member.credential,
    )
    .await;
    let renewed = foyer.authenticate(request).await.unwrap();
    // Same real account and server clock can produce identical public metadata;
    // the private retained bearer installation must nevertheless invalidate it.
    assert_eq!(renewed, info);
    assert!(matches!(stamp.check(&foyer, NOW), Err(Error::Unauthorized)));
    let current = foyer.session_binding().unwrap();
    current.check(&foyer, NOW).unwrap();
    foyer.call("logout", json!({})).await.unwrap();
    assert!(matches!(
        current.check(&foyer, NOW),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(foyer.session_binding(), Err(Error::Unauthorized)));
    drop(foyer);
    assert!(matches!(
        current.check(&foreign, NOW),
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_original_authentication_invalidates_prior_custody_stamp() {
    let wallet = global(200).await;
    let (_, passport, public) = wallet_passport(&wallet).await;
    let service = community("alpha", &public).await;
    let mut member = enrol_community(&service, "api.alpha.example.test", &passport).await;
    let (mut foyer, _) = authenticated(&service, &mut member).await;
    let stamp = foyer.session_binding().unwrap();
    assert!(foyer.authenticate(json!({})).await.is_err());
    assert!(matches!(stamp.check(&foyer, NOW), Err(Error::Unauthorized)));
    assert!(matches!(foyer.session_binding(), Err(Error::Unauthorized)));
}
