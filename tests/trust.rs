#![cfg(all(feature = "http", not(target_arch = "wasm32")))]
#[path = "owner/mod.rs"]
mod support;

use cfyr::{
    Foyer, HttpClient,
    trust::{Config, Configuration, Error, State, Trust},
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};

fn config() -> Config {
    Config {
        retry_entropy: 0,
        refresh_seconds: 40,
        poll_seconds: 2,
        request_seconds: 26,
        initial_backoff_seconds: 2,
        maximum_backoff_seconds: 16,
        maximum_staleness_seconds: 60,
    }
}

struct TlsDoor {
    origin: String,
    root: Vec<u8>,
    task: tokio::task::JoinHandle<()>,
    traces: tokio::sync::mpsc::Receiver<String>,
    completion: Arc<AtomicU64>,
    clock: Arc<AtomicU64>,
}
impl Drop for TlsDoor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn tls_door(service: &Running) -> TlsDoor {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let root = cert.der().clone();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![root.clone()],
        PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let upstream = service.base.clone();
    let (tx, traces) = tokio::sync::mpsc::channel(16);
    let completion = Arc::new(AtomicU64::new(NOW));
    let clock = Arc::new(AtomicU64::new(NOW));
    let after = completion.clone();
    let observed = clock.clone();
    let task = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(Arc::new(config));
        loop {
            let (io, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(io).await.unwrap();
            let mut bytes = Vec::new();
            let (path, body) = loop {
                let mut chunk = [0; 4096];
                let count = tls.read(&mut chunk).await.unwrap();
                assert!(count > 0 && bytes.len() < 8192);
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                    let length: usize = header
                        .lines()
                        .find_map(|v| v.strip_prefix("content-length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if bytes.len() >= end + 4 + length {
                        let path = header
                            .lines()
                            .next()
                            .unwrap()
                            .split_whitespace()
                            .nth(1)
                            .unwrap()
                            .to_owned();
                        break (path, bytes[end + 4..].to_vec());
                    }
                }
            };
            assert!(matches!(
                path.as_str(),
                "/v1/trust_feed" | "/v1/trust_changes"
            ));
            // Forward the actual public request to the original Door, retaining
            // its exact signed response bytes and original status.
            let response = reqwest::Client::new()
                .post(format!("{upstream}{path}"))
                .header("host", "api.alpha.example.test")
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .unwrap();
            let status = response.status().as_u16();
            let body = response.bytes().await.unwrap();
            let header = format!(
                "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            observed.store(after.load(Ordering::SeqCst), Ordering::SeqCst);
            tls.write_all(header.as_bytes()).await.unwrap();
            tls.write_all(&body).await.unwrap();
            tls.shutdown().await.unwrap();
            tx.send(String::from_utf8(bytes).unwrap()).await.unwrap();
        }
    });
    TlsDoor {
        origin,
        root: root.to_vec(),
        task,
        traces,
        completion,
        clock,
    }
}

async fn trust_configuration(service: &Running, origin: &str) -> Configuration {
    let value = client(service, "api.alpha.example.test", None)
        .call("trust_feed", json!({}))
        .await
        .unwrap();
    Configuration {
        origin: origin.into(),
        community: "alpha".into(),
        key_ring: serde_json::from_value(value["key_ring"].clone()).unwrap(),
        minimum_revision: 1,
        ring_revision: 0,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn foyer_retains_one_real_charter_and_follows_without_session_identifiers() {
    let wallet = global(100).await;
    let public = serde_json::from_value(
        client(&wallet, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let community = community("alpha", &public).await;
    let admin = enrol(
        &community,
        "api.admin.alpha.example.test",
        Some("synthetic-admin-enrolment-capability"),
    )
    .await;
    let mut tls = tls_door(&community).await;
    let settings = trust_configuration(&community, &tls.origin).await;
    let trust = Trust::native(settings, config(), std::slice::from_ref(&tls.root)).unwrap();
    let transport = HttpClient::new(
        community.base.clone(),
        "api.admin.alpha.example.test".into(),
        Some(admin.session),
    )
    .unwrap();
    let mut foyer = Foyer::with_trust(transport, trust);
    let clock = || tls.clock.load(Ordering::SeqCst);
    assert!(foyer.current(NOW, |_| ()).is_err());
    assert_eq!(foyer.trust().unwrap().state(), State::Stopped);
    assert!(matches!(
        foyer.trust().unwrap().refresh(NOW),
        Err(Error::Stopped)
    ));
    foyer.trust().unwrap().start(clock).await.unwrap();
    let mut scoped = foyer.current_policy();
    let mut reentrant = foyer.current_policy();
    {
        let _borrowed = foyer.trust().unwrap();
        assert!(matches!(scoped.with_current(NOW, |_| ()), Err(Error::Busy)));
    }
    scoped
        .with_current(NOW, |_| {
            assert!(matches!(
                reentrant.with_current(NOW, |_| ()),
                Err(Error::Busy)
            ));
        })
        .unwrap();
    let revision = foyer.current(NOW, |policy| policy.revision()).unwrap();
    let epoch = foyer.current(NOW, |policy| policy.policy_epoch()).unwrap();
    assert_eq!(
        foyer
            .current(NOW, |policy| policy.community().to_owned())
            .unwrap(),
        "alpha"
    );
    assert!(foyer.current(NOW, |policy| policy.valid_until()).unwrap() > NOW);
    let trace = tls.traces.recv().await.unwrap().to_lowercase();
    assert!(trace.starts_with("post /v1/trust_feed "));
    assert!(trace.ends_with("{}"));
    for name in ["authorization:", "cookie:", "referer:"] {
        assert!(!trace.contains(name));
    }
    assert!(matches!(
        foyer.trust().unwrap().start(clock).await,
        Err(Error::Busy)
    ));
    assert!(!foyer.trust().unwrap().poll(clock).await.unwrap());
    // A normal poll follows the actual original changes endpoint. Refresh the
    // real policy first so it returns immediately rather than long-polling.
    community.clock.set(NOW + 1);
    foyer
        .call(
            "setting_set",
            json!({"key":"quota","value":5,"inherit":false,"effective_at":NOW+1}),
        )
        .await
        .unwrap();
    tls.clock.store(NOW + 2, Ordering::SeqCst);
    tls.completion.store(NOW + 2, Ordering::SeqCst);
    assert!(foyer.trust().unwrap().poll(clock).await.unwrap());
    assert!(
        tls.traces
            .recv()
            .await
            .unwrap()
            .starts_with("POST /v1/trust_changes ")
    );
    assert!(matches!(
        foyer.current(NOW + 2, |_| ()),
        Err(Error::Unavailable)
    ));
    assert!(foyer.trust().unwrap().poll(clock).await.unwrap());
    assert!(foyer.current(NOW + 2, |policy| policy.revision()).unwrap() > revision);
    assert!(
        foyer
            .current(NOW + 2, |policy| policy.policy_epoch())
            .unwrap()
            > epoch
    );
    tls.traces.recv().await.unwrap();
    let revision = foyer.current(NOW + 2, |policy| policy.revision()).unwrap();
    foyer.trust().unwrap().on_change(revision, NOW + 2).unwrap();
    foyer
        .trust()
        .unwrap()
        .on_policy_epoch(epoch, NOW + 2)
        .unwrap();
    assert!(foyer.current(NOW + 2, |_| ()).is_ok());
    assert_eq!(
        scoped
            .with_current(NOW + 2, |policy| policy.revision())
            .unwrap(),
        revision
    );
    assert!(foyer.current(NOW + 62, |_| ()).is_err());
    assert!(foyer.current(NOW + 1, |_| ()).is_err());
    foyer.trust().unwrap().stop();
    assert!(foyer.current(NOW + 63, |_| ()).is_err());
    let mut absent = Foyer::new(
        HttpClient::new(
            community.base.clone(),
            "api.alpha.example.test".into(),
            None,
        )
        .unwrap(),
    );
    assert!(matches!(
        absent.current(NOW, |_| ()),
        Err(Error::Unavailable)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn scoped_policy_discards_result_when_the_actual_foyer_closes_inside_callback() {
    let wallet = global(100).await;
    let public = serde_json::from_value(
        client(&wallet, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let community = community("alpha", &public).await;
    let tls = tls_door(&community).await;
    let settings = trust_configuration(&community, &tls.origin).await;
    let trust = Trust::native(settings, config(), std::slice::from_ref(&tls.root)).unwrap();
    let transport = HttpClient::new(
        community.base.clone(),
        "api.alpha.example.test".into(),
        None,
    )
    .unwrap();
    let mut foyer = Some(Foyer::with_trust(transport, trust));
    foyer
        .as_mut()
        .unwrap()
        .trust()
        .unwrap()
        .start(|| NOW)
        .await
        .unwrap();
    let mut port = foyer.as_ref().unwrap().current_policy();
    assert!(matches!(
        port.with_current(NOW, |_| {
            drop(foyer.take());
            1
        }),
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        port.with_current(NOW, |_| 2),
        Err(Error::Unavailable)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn network_completion_cannot_install_expired_authority_or_hide_connection_failure() {
    let wallet = global(100).await;
    let public = serde_json::from_value(
        client(&wallet, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let community = community("alpha", &public).await;
    let mut tls = tls_door(&community).await;
    let settings = trust_configuration(&community, &tls.origin).await;
    let mut trust =
        Trust::native(settings.clone(), config(), std::slice::from_ref(&tls.root)).unwrap();
    tls.completion.store(NOW + 26, Ordering::SeqCst);
    assert!(matches!(
        trust.start(|| tls.clock.load(Ordering::SeqCst)).await,
        Err(Error::Timeout)
    ));
    assert!(trust.current(NOW + 26).is_err());
    tls.traces.recv().await.unwrap();
    tls.task.abort();
    (&mut tls.task).await.unwrap_err();
    let mut failed =
        Trust::native(settings.clone(), config(), std::slice::from_ref(&tls.root)).unwrap();
    assert!(matches!(failed.start(|| NOW).await, Err(Error::Network)));
    assert_eq!(failed.state(), State::Backoff);
    assert!(failed.current(NOW).is_err());
    let mut invalid = settings;
    invalid.origin = "http://localhost".into();
    assert!(Trust::native(invalid, config(), &[]).is_err());
}
