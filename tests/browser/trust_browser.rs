#![cfg(target_arch = "wasm32")]
#[cfg(owned_browser_coverage)]
use browser_coverage_runtime as _;
use cfyr::{
    BrowserClient, Foyer,
    trust::{Config, Configuration, Error, State, Trust},
};
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

const NOW: u64 = 1_800_000_000;

#[wasm_bindgen_test]
async fn vault_origin_uses_one_original_charter_over_real_cross_origin_https() {
    let fixture: serde_json::Value = gloo_net::http::Request::get("/__fixture")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Explicit trusted fixture configuration, obtained from the original service
    // setup; production never constructs this anchor from a member request.
    let value = &fixture["trust_configuration"];
    let configuration = Configuration {
        origin: value["origin"].as_str().unwrap().into(),
        community: value["community"].as_str().unwrap().into(),
        key_ring: serde_json::from_value(value["key_ring"].clone()).unwrap(),
        minimum_revision: value["minimum_revision"].as_u64().unwrap(),
        ring_revision: value["ring_revision"].as_u64().unwrap(),
    };
    let trust = Trust::browser(
        configuration,
        Config {
            retry_entropy: 0,
            refresh_seconds: 40,
            poll_seconds: 2,
            request_seconds: 26,
            initial_backoff_seconds: 2,
            maximum_backoff_seconds: 16,
            maximum_staleness_seconds: 60,
        },
    )
    .unwrap();
    let transport = BrowserClient::new(
        "https://api.alpha.example.test".into(),
        "api.alpha.example.test".into(),
        Some("must-stay-in-session-transport".into()),
    )
    .unwrap();
    let mut foyer = Foyer::with_trust(transport, trust);
    assert!(foyer.current(NOW).is_err());
    assert_eq!(foyer.trust().unwrap().state(), State::Stopped);
    foyer.trust().unwrap().start(|| NOW).await.unwrap();
    assert_eq!(foyer.current(NOW).unwrap().community(), "alpha");
    assert!(foyer.current(NOW).unwrap().valid_until() > NOW);
    let revision = foyer.current(NOW).unwrap().revision();
    let epoch = foyer.current(NOW).unwrap().policy_epoch();
    assert!(matches!(
        foyer.trust().unwrap().start(|| NOW).await,
        Err(Error::Busy)
    ));
    assert!(!foyer.trust().unwrap().poll(|| NOW).await.unwrap());
    foyer.trust().unwrap().refresh(NOW).unwrap();
    assert!(foyer.trust().unwrap().poll(|| NOW).await.unwrap());
    assert_eq!(foyer.current(NOW).unwrap().revision(), revision);
    foyer.trust().unwrap().on_change(revision, NOW).unwrap();
    foyer
        .trust()
        .unwrap()
        .on_policy_epoch(epoch + 1, NOW)
        .unwrap();
    assert!(matches!(foyer.current(NOW), Err(Error::Unavailable)));
    assert!(matches!(
        foyer.trust().unwrap().poll(|| NOW).await,
        Err(Error::BehindAnnouncement)
    ));
    assert!(foyer.current(NOW + 60).is_err());
    foyer.trust().unwrap().stop();
    assert_eq!(foyer.trust().unwrap().state(), State::Stopped);
    assert!(foyer.current(NOW + 61).is_err());
    let requests: Vec<serde_json::Value> = gloo_net::http::Request::get("/__trust_requests")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(requests.len(), 3);
    for request in requests {
        assert_eq!(request["path"], "/v1/trust_feed");
        assert_eq!(request["authorization"], false);
        assert_eq!(request["cookie"], false);
        assert_eq!(request["referer"], false);
    }
}
