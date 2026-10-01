#![cfg(target_arch = "wasm32")]
#[cfg(owned_browser_coverage)]
use browser_coverage_runtime as _;
use cfyr::{BrowserClient, Error, Foyer, action, contract};
use serde_json::json;
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

const BASE: &str = "https://wallet.example.test";
const HOST: &str = "wallet.example.test";

#[wasm_bindgen_test]
async fn foyer_forwards_original_browser_responses_and_ambiguous_commits() {
    let fixture: serde_json::Value = gloo_net::http::Request::get("/__fixture")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut public = Foyer::new(BrowserClient::new(BASE.into(), HOST.into(), None).unwrap());
    assert_eq!(action("global_public").unwrap().path(), "/v1/global_public");
    assert_eq!(contract()["info"]["title"], "cvld");
    assert!(public.call("global_public", json!({})).await.unwrap()["issuer"].is_array());
    assert!(matches!(
        public.call("passport_challenge", json!({})).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        public.call("../logout", json!({})).await,
        Err(Error::Invalid)
    ));
    let mut member = Foyer::new(
        BrowserClient::new(
            BASE.into(),
            HOST.into(),
            Some(fixture["session"].as_str().unwrap().into()),
        )
        .unwrap(),
    );
    assert!(member.call("passport_challenge", json!({})).await.is_ok());
    assert!(matches!(
        member
            .call(
                "global_suspend",
                json!({"user":"wrong","until":1_800_000_001})
            )
            .await,
        Err(Error::Forbidden)
    ));
    assert!(member.call("logout", json!({})).await.is_ok());
    assert!(matches!(
        member.call("passport_challenge", json!({})).await,
        Err(Error::Unauthorized)
    ));
    for session in fixture["fault_sessions"].as_array().unwrap() {
        let mut member = Foyer::new(
            BrowserClient::new(
                BASE.into(),
                HOST.into(),
                Some(session.as_str().unwrap().into()),
            )
            .unwrap(),
        );
        assert!(matches!(
            member.call("logout", json!({})).await,
            Err(Error::Reconcile)
        ));
        assert!(matches!(
            member.call("passport_challenge", json!({})).await,
            Err(Error::Unauthorized)
        ));
    }
    let counts: Vec<usize> = gloo_net::http::Request::get("/__faults")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(counts, vec![1; 11]);
}
