//! Original member registration correlated with its first login, through the
//! real owner server and the maintained software authenticator.
use super::*;
#[path = "../support/owner.rs"]
mod owner;
use cpky::Context;
use cpky::software::{SoftwareAuthenticator, TestConfiguration};
use owner::*;
use serde_json::json;

const ORIGIN: &str = "https://vault.wallet.example.test";

fn passkeys() -> cpky::Client<SoftwareAuthenticator> {
    cpky::Client::new(
        Context::new(ORIGIN, WALLET).unwrap(),
        SoftwareAuthenticator::new(
            ORIGIN,
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap(),
    )
}

/// Real registration ceremony through this Foyer. The vault PRF handover is
/// dropped by the caller; only the public credential reaches the Foyer.
async fn registered(
    service: &Running,
) -> (
    Foyer<crate::HttpClient>,
    RegisteredMember<crate::HttpClient>,
    cpky::Client<SoftwareAuthenticator>,
) {
    let mut api =
        Foyer::new(crate::HttpClient::new(service.base.clone(), WALLET.into(), None).unwrap());
    let pending = api.begin_member_registration(None).await.unwrap();
    let mut authenticator = passkeys();
    let (public, custody) = authenticator
        .register_member(pending.options().clone())
        .await
        .unwrap()
        .into_parts();
    drop(custody);
    let original_id = public.credential_id().unwrap();
    let receipt = api
        .finish_member_registration(pending, public)
        .await
        .unwrap();
    assert_eq!(receipt.original_credential_id(), original_id.as_slice());
    (api, receipt, authenticator)
}

/// Real first login on the same Foyer with the registering authenticator.
async fn first_login(
    api: &mut Foyer<crate::HttpClient>,
    authenticator: &mut cpky::Client<SoftwareAuthenticator>,
) -> crate::SessionInfo {
    let challenge = api.begin_browser_login().await.unwrap();
    let (credential, custody) = authenticator
        .sign_in(challenge.options)
        .await
        .unwrap()
        .into_parts();
    drop(custody);
    let info = api
        .finish_browser_login(challenge.ceremony, credential)
        .await
        .unwrap();
    assert_eq!(info.role, "member");
    assert!(info.expires > NOW);
    assert!(!info.user.is_empty());
    info
}

#[tokio::test(flavor = "multi_thread")]
async fn global_first_login_redeems_receipt_with_no_certificate() {
    let service = global(100).await;
    let (mut api, receipt, mut authenticator) = registered(&service).await;
    first_login(&mut api, &mut authenticator).await;
    // The receipt waits on the real session mutex instead of being lost on contention.
    let guard = api.shared.session.lock().await;
    let mut pending = Box::pin(receipt.into_certificate(&api, || NOW));
    assert!(futures::poll!(pending.as_mut()).is_pending());
    let (certificate, ()) = futures::join!(pending, async {
        drop(guard);
    });
    // Global original registration returns no certificate; none is inferred.
    assert!(certificate.unwrap().is_none());
    // The handover grants no extra authority: the ordinary session is unchanged.
    api.call("logout", json!({})).await.unwrap();
    assert!(matches!(api.session_binding(), Err(Error::Unauthorized)));
}

#[tokio::test(flavor = "multi_thread")]
async fn injected_clock_is_reread_after_lock_await() {
    let service = global(100).await;
    // Deadline reached while the receipt waits: refused.
    let (mut api, receipt, mut authenticator) = registered(&service).await;
    let info = first_login(&mut api, &mut authenticator).await;
    let guard = api.shared.session.lock().await;
    let mut calls = 0;
    let mut pending = Box::pin(receipt.into_certificate(&api, || {
        calls += 1;
        if calls == 1 { NOW } else { info.expires }
    }));
    assert!(futures::poll!(pending.as_mut()).is_pending());
    let (outcome, ()) = futures::join!(pending, async {
        drop(guard);
    });
    assert!(matches!(outcome, Err(Error::Unauthorized)));
    assert_eq!(calls, 2);
    // Clock regression after the wait: refused.
    let (mut api, receipt, mut authenticator) = registered(&service).await;
    let info = first_login(&mut api, &mut authenticator).await;
    assert!(info.expires > NOW);
    let mut calls = 0;
    assert!(matches!(
        receipt
            .into_certificate(&api, || {
                calls += 1;
                if calls == 1 { NOW } else { NOW - 1 }
            })
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(calls, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn receipt_refused_for_foreign_foyer() {
    let service = global(100).await;
    let (mut api, receipt, mut authenticator) = registered(&service).await;
    let foreign =
        Foyer::new(crate::HttpClient::new(service.base.clone(), WALLET.into(), None).unwrap());
    assert!(matches!(
        receipt.into_certificate(&foreign, || NOW).await,
        Err(Error::Unauthorized)
    ));
    // Neither Foyer changed: the foreign one never gained a session, and the
    // original still completes its own first login afterwards.
    assert!(matches!(
        foreign.session_binding(),
        Err(Error::Unauthorized)
    ));
    first_login(&mut api, &mut authenticator).await;
    api.call("logout", json!({})).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn receipt_refused_when_first_login_is_another_member() {
    let service = global(100).await;
    let (mut api, receipt, _authenticator) = registered(&service).await;
    // The first login uses a different real member, isolating identity binding
    // from the separate replacement-session refusal below.
    let mut other = enrol(&service, WALLET, None).await;
    let request = login_request(
        &service,
        WALLET,
        &mut other.authenticator,
        &other.user,
        &other.credential,
    )
    .await;
    let second = api.authenticate(request).await.unwrap();
    assert_eq!(second.user, other.user);
    assert!(matches!(
        receipt.into_certificate(&api, || NOW).await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn receipt_refused_after_failed_login() {
    let service = global(100).await;
    let (mut api, receipt, mut authenticator) = registered(&service).await;
    first_login(&mut api, &mut authenticator).await;
    assert!(api.authenticate(json!({})).await.is_err());
    assert!(matches!(
        receipt.into_certificate(&api, || NOW).await,
        Err(Error::Unauthorized)
    ));
    // The failed login cleared the session it had installed.
    assert!(matches!(api.session_binding(), Err(Error::Unauthorized)));
}

#[tokio::test(flavor = "multi_thread")]
async fn receipt_refused_after_same_member_replaces_first_session() {
    let service = global(100).await;
    let (mut api, receipt, mut authenticator) = registered(&service).await;
    let first = first_login(&mut api, &mut authenticator).await;
    let second = first_login(&mut api, &mut authenticator).await;
    assert_eq!(first.user, second.user);
    assert!(matches!(
        receipt.into_certificate(&api, || NOW).await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn sealed_continuation_survives_original_calls_without_changing_the_session() {
    let service = global(100).await;
    let (mut api, receipt, mut authenticator) = registered(&service).await;
    first_login(&mut api, &mut authenticator).await;
    let stamp = api.session_binding().unwrap();
    let mut continued = receipt.continue_after_login(&api, || NOW).await.unwrap();
    continued.check(&api, || NOW).await.unwrap();
    api.call("global_public", json!({})).await.unwrap();
    continued.check(&api, || NOW + 1).await.unwrap();
    continued.consume_checked(&api, || NOW + 1).await.unwrap();
    stamp.check(&api, NOW + 1).unwrap();
    api.call("logout", json!({})).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn continuation_requires_the_exact_first_login_before_binding() {
    let service = global(100).await;
    for replaced in [false, true] {
        let (mut api, receipt, mut authenticator) = registered(&service).await;
        if replaced {
            first_login(&mut api, &mut authenticator).await;
            first_login(&mut api, &mut authenticator).await;
        }
        assert!(matches!(
            receipt.continue_after_login(&api, || NOW).await,
            Err(Error::Unauthorized)
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn continued_session_refuses_replacement_failed_login_logout_and_owner_close() {
    let service = global(100).await;
    for failure in 0..4 {
        let (mut api, receipt, mut authenticator) = registered(&service).await;
        first_login(&mut api, &mut authenticator).await;
        let mut continued = receipt.continue_after_login(&api, || NOW).await.unwrap();
        match failure {
            0 => {
                first_login(&mut api, &mut authenticator).await;
            }
            1 => {
                assert!(api.authenticate(json!({})).await.is_err());
            }
            2 => {
                api.call("logout", json!({})).await.unwrap();
            }
            3 => api.shared.close(),
            _ => unreachable!(),
        }
        assert!(matches!(
            continued.check(&api, || NOW).await,
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            continued.check(&api, || NOW).await,
            Err(Error::Unauthorized)
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_foyer_refusal_consumes_only_the_original_continuation() {
    let service = global(100).await;
    let (mut api, receipt, mut authenticator) = registered(&service).await;
    first_login(&mut api, &mut authenticator).await;
    let stamp = api.session_binding().unwrap();
    let mut continued = receipt.continue_after_login(&api, || NOW).await.unwrap();
    let foreign =
        Foyer::new(crate::HttpClient::new(service.base.clone(), WALLET.into(), None).unwrap());
    assert!(matches!(
        continued.check(&foreign, || NOW).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        continued.check(&api, || NOW).await,
        Err(Error::Unauthorized)
    ));
    stamp.check(&api, NOW).unwrap();
    assert!(matches!(
        foreign.session_binding(),
        Err(Error::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn continued_mutex_wait_rechecks_deadline_and_clock_without_revival() {
    let service = global(100).await;
    for expiry in [false, true] {
        let (mut api, receipt, mut authenticator) = registered(&service).await;
        let info = first_login(&mut api, &mut authenticator).await;
        let stamp = api.session_binding().unwrap();
        let mut continued = receipt.continue_after_login(&api, || NOW).await.unwrap();
        let held = api.shared.session.lock().await;
        let mut calls = 0;
        let mut check = Box::pin(continued.check(&api, || {
            calls += 1;
            if calls == 1 {
                NOW
            } else if expiry {
                info.expires
            } else {
                NOW - 1
            }
        }));
        assert!(futures::poll!(check.as_mut()).is_pending());
        drop(held);
        assert!(matches!(check.await, Err(Error::Unauthorized)));
        assert_eq!(calls, 2);
        assert!(matches!(
            continued.check(&api, || NOW).await,
            Err(Error::Unauthorized)
        ));
        stamp.check(&api, NOW).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_continuation_check_cannot_return_to_the_first_session() {
    let service = global(100).await;
    let (mut api, receipt, mut authenticator) = registered(&service).await;
    first_login(&mut api, &mut authenticator).await;
    let stamp = api.session_binding().unwrap();
    let mut continued = receipt.continue_after_login(&api, || NOW).await.unwrap();
    let held = api.shared.session.lock().await;
    let mut check = Box::pin(continued.check(&api, || NOW));
    assert!(futures::poll!(check.as_mut()).is_pending());
    drop(check);
    drop(held);
    assert!(matches!(
        continued.consume_checked(&api, || NOW).await,
        Err(Error::Unauthorized)
    ));
    stamp.check(&api, NOW).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn continued_clock_floor_and_final_consumption_use_the_original_deadline() {
    let service = global(100).await;
    for rollback in [false, true] {
        let (mut api, receipt, mut authenticator) = registered(&service).await;
        let info = first_login(&mut api, &mut authenticator).await;
        let stamp = api.session_binding().unwrap();
        let mut continued = receipt.continue_after_login(&api, || NOW).await.unwrap();
        continued.check(&api, || NOW + 1).await.unwrap();
        let time = if rollback { NOW } else { info.expires };
        assert!(matches!(
            continued.consume_checked(&api, || time).await,
            Err(Error::Unauthorized)
        ));
        stamp.check(&api, NOW).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn original_registration_key_id_survives_next_login_and_terminal_refusal() {
    let service = global(100).await;
    let (mut api, receipt, mut authenticator) = registered(&service).await;
    let original = receipt.original_credential_id().to_vec();
    first_login(&mut api, &mut authenticator).await;
    let mut continued = receipt.continue_after_login(&api, || NOW).await.unwrap();
    assert_eq!(
        continued.original_credential_id().unwrap(),
        original.as_slice()
    );
    continued.check(&api, || NOW + 1).await.unwrap();
    assert_eq!(
        continued.original_credential_id().unwrap(),
        original.as_slice()
    );
    api.call("logout", json!({})).await.unwrap();
    assert!(continued.check(&api, || NOW + 2).await.is_err());
    assert!(continued.original_credential_id().is_err());
    first_login(&mut api, &mut authenticator).await;
    assert!(continued.check(&api, || NOW + 3).await.is_err());
    assert!(continued.original_credential_id().is_err());
}
