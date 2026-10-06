//! Actual Passkeys HTTP handover and original cvld database/session verification.
use super::*;
#[path = "../owner/mod.rs"]
mod owner;
use cpky::software::{SoftwareAuthenticator, TestConfiguration};
use cpky::{CeremonyKind, CeremonyRequest, CeremonyResult, Context, VaultOutcome};
use owner::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn original_browser_callback_and_server_acceptance_retain_separate_opaque_custody() {
    let service = global(100).await;
    for (host, rp, origin, bootstrap, role) in [
        (
            WALLET,
            WALLET,
            "https://vault.wallet.example.test",
            None,
            "member",
        ),
        (
            ROOT,
            "root.example.test",
            "https://vault.root.example.test",
            Some("synthetic-operator-enrolment-capability"),
            "root",
        ),
    ] {
        let mut api =
            Foyer::new(crate::HttpClient::new(service.base.clone(), host.into(), None).unwrap());
        let registration = client(&service, host, None)
            .call(
                "register_begin",
                json!({"bootstrap":bootstrap,"passport":null}),
            )
            .await
            .unwrap();
        let platform = SoftwareAuthenticator::new(
            origin,
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap();
        let mut passkeys = cpky::Client::new(Context::new(origin, rp).unwrap(), platform);
        let credential = if bootstrap.is_some() {
            passkeys
                .register_privileged(registration["options"].clone())
                .await
                .unwrap()
        } else {
            passkeys
                .register_member(registration["options"].clone())
                .await
                .unwrap()
                .into_parts()
                .0
        };
        let registered = client(&service, host, None)
            .call(
                "register_finish",
                json!({
                    "ceremony":registration["ceremony"], "credential":credential.into_json(),
                }),
            )
            .await
            .unwrap();
        let challenge = api.begin_browser_login().await.unwrap();
        let pending = cpky::native::BrowserCeremony::start(
            Context::new(origin, rp).unwrap(),
            url::Url::parse(&format!("{origin}/cli-login.html")).unwrap(),
            CeremonyRequest {
                kind: CeremonyKind::Authentication,
                options: challenge.options,
            },
        )
        .await
        .unwrap();
        pending
            .complete_with_test_authenticator(passkeys.into_authenticator())
            .await
            .unwrap();
        let CeremonyResult::Authentication(authentication) = pending.wait().await.unwrap() else {
            panic!("wrong original ceremony result");
        };
        // Split in the device composer: Foyer never holds or receives the PRF.
        let (credential, custody) = authentication.into_parts();
        let authenticated = api
            .finish_browser_login(challenge.ceremony, credential)
            .await
            .unwrap();
        assert_eq!(authenticated.user, registered["user"].as_str().unwrap());
        assert_eq!(authenticated.role, role);
        assert!(authenticated.expires > NOW);
        assert!(
            serde_json::to_value(authenticated)
                .unwrap()
                .get("token")
                .is_none()
        );
        assert!(matches!(custody, VaultOutcome::Ready(_)));
        // This succeeds only with the exact real session retained by HttpClient.
        api.call("logout", json!({})).await.unwrap();
        assert!(matches!(
            api.call("logout", json!({})).await,
            Err(Error::Unauthorized)
        ));
    }
}
