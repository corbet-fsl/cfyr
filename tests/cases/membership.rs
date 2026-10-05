//! Original HTTPS client, server, passport, enrolment and passkey session. No
//! substitute roster/authority supplies the successful observations.
use super::*;
#[path = "../owner/mod.rs"]
mod owner;
use owner::*;
use serde_json::json;

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
    foyer
        .call("passkey_revoke", json!({"credential":member.credential}))
        .await
        .unwrap();
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
