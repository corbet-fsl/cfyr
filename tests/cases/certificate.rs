//! Actual pinned TLS ingress into the original owner, never accepted reply mocks.
use super::*;
#[path = "../support/owner.rs"]
mod owner;
use cpky::{
    Context,
    software::{SoftwareAuthenticator, TestConfiguration},
};
use owner::*;
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};

const HOST: &str = "api.alpha.example.test";
const VAULT: &str = "https://vault.alpha.example.test";

#[derive(Default)]
struct Gate {
    enabled: AtomicBool,
    action: AtomicUsize,
    arrived: Notify,
    release: Notify,
}
struct TlsIngress {
    origin: String,
    root: Vec<u8>,
    certificates: Arc<AtomicUsize>,
    gate: Arc<Gate>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for TlsIngress {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl TlsIngress {
    async fn new(service: &Running) -> Self {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let upstream = service.base.clone();
        let certificates = Arc::new(AtomicUsize::new(0));
        let observed = certificates.clone();
        let gate = Arc::new(Gate::default());
        let paused = gate.clone();
        let task = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let mut active = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (io, _) = accepted.unwrap();
                        let acceptor = acceptor.clone();
                        let upstream = upstream.clone();
                        let observed = observed.clone();
                        let paused = paused.clone();
                        active.spawn(async move {
                            let Ok(mut tls) = acceptor.accept(io).await else { return; };
                            let mut bytes = Vec::new();
                            let (path, headers, body) = loop {
                                let mut chunk = [0; 4096];
                                let Ok(count) = tls.read(&mut chunk).await else { return; };
                                if count == 0 { return; }
                                assert!(bytes.len() + count <= 1024 * 1024);
                                bytes.extend_from_slice(&chunk[..count]);
                                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                                    let header = std::str::from_utf8(&bytes[..end]).unwrap();
                                    let length: usize = header.lines().find_map(|line| {
                                        let (name, value) = line.split_once(':')?;
                                        name.eq_ignore_ascii_case("content-length").then_some(value.trim())
                                    }).unwrap().parse().unwrap();
                                    if bytes.len() >= end + 4 + length {
                                        let path = header.lines().next().unwrap().split_whitespace().nth(1).unwrap().to_owned();
                                        let headers: Vec<(String, String)> = header.lines().skip(1).map(|line| {
                                            let (name, value) = line.split_once(':').unwrap();
                                            (name.into(), value.trim().into())
                                        }).collect();
                                        break (path, headers, bytes[end + 4..end + 4 + length].to_vec());
                                    }
                                }
                            };
                            assert!(matches!(path.as_str(), "/v1/register_begin" | "/v1/register_finish"
                                | "/v1/login_discoverable_begin" | "/v1/login_finish" | "/v1/logout"
                                | "/v1/lobby" | "/v1/device_keys" | "/v1/device_authorize"
                                | "/v1/trust_feed" | "/v1/trust_changes" | "/v1/passkey_certificate"
                                | "/v1/passkey_add" | "/v1/passkey_revoke"
                                | "/v1/initial_registration_begin" | "/v1/initial_creation"
                                | "/v1/initial_publication_bind"));
                            // Fixed, test-owned virtual-host ingress route. It never
                            // takes the upstream URL or Host from request JSON.
                            // The WebAuthn vault realm stays the original VAULT;
                            // transport routing itself certifies no membership.
                            let mut request = reqwest::Client::new().post(format!("{upstream}{path}")).header("host", HOST);
                            for (name, value) in headers {
                                if !["host", "content-length", "connection"].iter().any(|skip| name.eq_ignore_ascii_case(skip)) {
                                    request = request.header(name, value);
                                }
                            }
                            let response = request.body(body).send().await.unwrap();
                            let status = response.status().as_u16();
                            let body = response.bytes().await.unwrap();
                            // Preserve original status/body/bearer/signed material and
                            // server checked_at. Only reply timing can be gated.
                            if path == "/v1/passkey_certificate" {
                                observed.fetch_add(1, Ordering::SeqCst);
                            }
                            let selected = match paused.action.load(Ordering::SeqCst) {
                                1 => "/v1/initial_registration_begin",
                                2 => "/v1/register_finish",
                                3 => "/v1/initial_creation",
                                4 => "/v1/initial_publication_bind",
                                _ => "/v1/passkey_certificate",
                            };
                            if path == selected && paused.enabled.swap(false, Ordering::SeqCst) {
                                paused.arrived.notify_one();
                                paused.release.notified().await;
                            }
                            let head = format!("HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                            if tls.write_all(head.as_bytes()).await.is_ok() && tls.write_all(&body).await.is_ok() {
                                let _ = tls.shutdown().await;
                            }
                        });
                    },
                    _ = active.join_next(), if !active.is_empty() => {},
                }
            }
        });
        Self {
            origin,
            root: root.to_vec(),
            certificates,
            gate,
            task,
        }
    }
}
fn feed_config() -> crate::trust::Config {
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
async fn trust(service: &Running, tls: &TlsIngress) -> crate::trust::Trust {
    let feed = client(service, HOST, None)
        .call("trust_feed", json!({}))
        .await
        .unwrap();
    let configuration = crate::trust::Configuration {
        origin: tls.origin.clone(),
        community: "alpha".into(),
        key_ring: serde_json::from_value(feed["key_ring"].clone()).unwrap(),
        minimum_revision: 1,
        ring_revision: 0,
    };
    let mut trust = crate::trust::Trust::native(
        configuration,
        feed_config(),
        std::slice::from_ref(&tls.root),
    )
    .unwrap();
    trust.start(|| NOW).await.unwrap();
    trust
}
fn passkeys() -> cpky::Client<SoftwareAuthenticator> {
    cpky::Client::new(
        Context::new(VAULT, "alpha.example.test").unwrap(),
        SoftwareAuthenticator::new(
            VAULT,
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap(),
    )
}
async fn login(api: &mut Foyer<crate::HttpClient>, keys: &mut cpky::Client<SoftwareAuthenticator>) {
    let challenge = api.begin_browser_login().await.unwrap();
    let (public, custody) = keys.sign_in(challenge.options).await.unwrap().into_parts();
    drop(custody);
    api.finish_browser_login(challenge.ceremony, public)
        .await
        .unwrap();
}
struct Fixture {
    tls: TlsIngress,
    service: Running,
    foyer: Foyer<crate::HttpClient>,
    registered: RegisteredSession<crate::HttpClient>,
    passkeys: cpky::Client<SoftwareAuthenticator>,
    clock: Arc<AtomicU64>,
    original_id: Vec<u8>,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_same_member_other_key(false).await
    }
    async fn with_same_member_other_key(substitute: bool) -> Self {
        assert!(
            cvld::client::forwarding_action("passkey_certificate").is_some(),
            "requires the genuine generated owner action"
        );
        let global = global(100).await;
        let (_, passport, public) = wallet_passport(&global).await;
        let service = community("alpha", &public).await;
        let tls = TlsIngress::new(&service).await;
        let original = trust(&service, &tls).await;
        let mut foyer = Foyer::with_trust(
            crate::HttpClient::with_roots(
                tls.origin.clone(),
                "127.0.0.1".into(),
                None,
                std::slice::from_ref(&tls.root),
            )
            .unwrap(),
            original,
        );
        let proof = presentation(&service, HOST, None, &passport).await;
        let pending = foyer
            .begin_member_registration(Some(serde_json::to_value(proof).unwrap()))
            .await
            .unwrap();
        let mut keys = passkeys();
        let (credential, custody) = keys
            .register_member(pending.options().clone())
            .await
            .unwrap()
            .into_parts();
        drop(custody);
        let original_id = credential.credential_id().unwrap();
        let registered = foyer
            .finish_member_registration(pending, credential)
            .await
            .unwrap();
        if substitute {
            // A separate actual session adds another equal key before this
            // registering Foyer completes its first login. User/generation
            // still match, so only the original-key relation can refuse it.
            let mut companion = Foyer::new(
                crate::HttpClient::with_roots(
                    tls.origin.clone(),
                    "127.0.0.1".into(),
                    None,
                    std::slice::from_ref(&tls.root),
                )
                .unwrap(),
            );
            login(&mut companion, &mut keys).await;
            let begin = companion
                .call("passkey_add", json!({"step":"begin"}))
                .await
                .unwrap();
            let mut added = passkeys();
            let (credential, custody) = added
                .register_member(begin["options"].clone())
                .await
                .unwrap()
                .into_parts();
            drop(custody);
            let added_id = credential.credential_id().unwrap();
            assert_ne!(added_id, original_id);
            let result = companion.call("passkey_add", json!({"step":"finish","ceremony":begin["ceremony"],"credential":credential.into_json()})).await.unwrap();
            assert_eq!(
                serde_json::from_value::<Vec<u8>>(result["credential"].clone()).unwrap(),
                added_id
            );
            keys = added;
        }
        login(&mut foyer, &mut keys).await;
        let registered = registered
            .continue_after_login(&foyer, || NOW)
            .await
            .unwrap();
        let device = ed25519_dalek::SigningKey::from_bytes(&[53; 32])
            .verifying_key()
            .to_bytes();
        foyer
            .call("device_authorize", json!({"key": device}))
            .await
            .unwrap();
        Self {
            tls,
            service,
            foyer,
            registered,
            passkeys: keys,
            clock: Arc::new(AtomicU64::new(NOW)),
            original_id,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn original_tls_certificate_is_joined_to_registered_key_and_expires_terminally() {
    let f = Fixture::new().await;
    let mut live = f.foyer.live_membership();
    let lease = live
        .observe_lease(|| f.clock.load(Ordering::SeqCst))
        .await
        .unwrap();
    let mut policy = f.foyer.current_policy();
    let certified = lease
        .passkey_certificate(&mut policy, || f.clock.load(Ordering::SeqCst))
        .await
        .unwrap();
    assert_eq!(certified.credential_id().unwrap(), f.original_id.as_slice());
    assert_eq!(certified.server_checked_at().unwrap(), NOW);
    assert!(!certified.observation().unwrap().member.is_empty());
    let mut joined = certified.bind_registration(f.registered, || NOW).unwrap();
    assert_eq!(joined.credential_id().unwrap(), f.original_id.as_slice());
    joined.check(|| NOW + 20).unwrap();
    assert!(joined.check(|| NOW + 10).is_err());
    assert!(joined.credential_id().is_err());
    assert!(joined.check(|| NOW + 30).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn same_owner_tls_origin_and_exclusive_deadline_are_required() {
    for foreign in [true, false] {
        let f = Fixture::new().await;
        let other = Foyer::with_trust(
            crate::HttpClient::with_roots(
                f.tls.origin.clone(),
                "127.0.0.1".into(),
                None,
                std::slice::from_ref(&f.tls.root),
            )
            .unwrap(),
            trust(&f.service, &f.tls).await,
        );
        let mut policy = if foreign {
            other.current_policy()
        } else {
            f.foyer.current_policy()
        };
        let mut live = f.foyer.live_membership();
        let lease = live.observe_lease(|| NOW).await.unwrap();
        if foreign {
            assert!(matches!(
                lease.passkey_certificate(&mut policy, || NOW).await,
                Err(Error::Unauthorized)
            ));
            assert_eq!(f.tls.certificates.load(Ordering::SeqCst), 0);
        } else {
            let mut certified = lease
                .passkey_certificate(&mut policy, || NOW)
                .await
                .unwrap();
            let expires = certified.expires().unwrap();
            assert!(certified.check(|| expires).is_err());
            assert!(certified.check(|| NOW).is_err());
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_http_member_session_cannot_supply_the_server_time_capability() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let mut member = enrol_community(&service, HOST, &passport).await;
    let mut foyer =
        Foyer::new(crate::HttpClient::new(service.base.clone(), HOST.into(), None).unwrap());
    foyer
        .authenticate(
            login_request(
                &service,
                HOST,
                &mut member.authenticator,
                &member.user,
                &member.credential,
            )
            .await,
        )
        .await
        .unwrap();
    let lease = foyer.live_membership().observe_lease(|| NOW).await.unwrap();
    let mut policy = foyer.current_policy();
    assert!(matches!(
        lease.passkey_certificate(&mut policy, || NOW).await,
        Err(Error::WrongHost)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn original_owner_close_aborts_the_rearmed_certificate_waiter() {
    let f = Fixture::new().await;
    let lease = f
        .foyer
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap();
    let mut policy = f.foyer.current_policy();
    f.tls.gate.enabled.store(true, Ordering::SeqCst);
    let mut pending = Box::pin(lease.passkey_certificate(&mut policy, || NOW));
    tokio::select! {
        result = &mut pending => panic!("original certificate waiter must be gated, success={}", result.is_ok()),
        result = tokio::time::timeout(Duration::from_secs(5), f.tls.gate.arrived.notified()) => result.unwrap(),
    }
    drop(f.foyer);
    assert!(matches!(pending.await, Err(Error::Unavailable)));
    f.tls.gate.release.notify_one();
}

#[tokio::test(flavor = "multi_thread")]
async fn certificate_wait_checks_completion_clock_and_session_expiry() {
    for expired in [false, true] {
        let mut f = Fixture::new().await;
        f.clock.store(NOW + 20, Ordering::SeqCst);
        let lease = f
            .foyer
            .live_membership()
            .observe_lease(|| f.clock.load(Ordering::SeqCst))
            .await
            .unwrap();
        let expires = lease.observation().expires;
        let mut policy = f.foyer.current_policy();
        f.tls.gate.enabled.store(true, Ordering::SeqCst);
        let mut pending =
            Box::pin(lease.passkey_certificate(&mut policy, || f.clock.load(Ordering::SeqCst)));
        tokio::select! {
            result = &mut pending => panic!("certificate waiter must be gated, success={}", result.is_ok()),
            result = tokio::time::timeout(Duration::from_secs(5), f.tls.gate.arrived.notified()) => result.unwrap(),
        }
        f.clock
            .store(if expired { expires } else { NOW + 10 }, Ordering::SeqCst);
        f.tls.gate.release.notify_one();
        assert!(matches!(pending.await, Err(Error::Unauthorized)));
        assert!(f.foyer.call("lobby", json!({})).await.is_ok());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn same_member_other_passkey_cannot_join_original_registration() {
    let mut f = Fixture::with_same_member_other_key(true).await;
    let lease = f
        .foyer
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap();
    let mut policy = f.foyer.current_policy();
    let certified = lease
        .passkey_certificate(&mut policy, || NOW)
        .await
        .unwrap();
    assert_ne!(certified.credential_id().unwrap(), f.original_id.as_slice());
    assert_eq!(
        f.registered.original_credential_id().unwrap(),
        f.original_id.as_slice()
    );
    assert!(matches!(
        certified.bind_registration(f.registered, || NOW),
        Err(Error::Unauthorized)
    ));
    assert!(f.foyer.call("lobby", json!({})).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_configured_trust_origin_must_match_this_tls_client() {
    let mut f = Fixture::new().await;
    let other = TlsIngress::new(&f.service).await;
    let replaced = trust(&f.service, &other).await;
    *f.foyer.trust().unwrap() = replaced;
    let lease = f
        .foyer
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap();
    let mut policy = f.foyer.current_policy();
    assert!(matches!(
        lease.passkey_certificate(&mut policy, || NOW).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.tls.certificates.load(Ordering::SeqCst), 0);
    assert_eq!(other.certificates.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_certificate_fetch_releases_original_session_and_pending_slot() {
    let mut f = Fixture::new().await;
    let mut live = f.foyer.live_membership();
    let lease = live.observe_lease(|| NOW).await.unwrap();
    let mut policy = f.foyer.current_policy();
    f.tls.gate.enabled.store(true, Ordering::SeqCst);
    let mut pending = Box::pin(lease.passkey_certificate(&mut policy, || NOW));
    tokio::select! {
        result = &mut pending => panic!("certificate waiter must be gated, success={}", result.is_ok()),
        result = tokio::time::timeout(Duration::from_secs(5), f.tls.gate.arrived.notified()) => result.unwrap(),
    }
    drop(pending);
    f.tls.gate.release.notify_one();
    assert!(live.observe_lease(|| NOW).await.is_ok());
    assert!(f.foyer.call("lobby", json!({})).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_passkey_revocation_feed_is_reborrowed_after_certificate_wait() {
    let mut f = Fixture::new().await;
    let real = f.passkeys.into_authenticator().synced_test_device();
    let mut keys = cpky::Client::new(Context::new(VAULT, "alpha.example.test").unwrap(), real);
    let mut companion = Foyer::new(
        crate::HttpClient::with_roots(
            f.tls.origin.clone(),
            "127.0.0.1".into(),
            None,
            std::slice::from_ref(&f.tls.root),
        )
        .unwrap(),
    );
    login(&mut companion, &mut keys).await;
    let lease = f
        .foyer
        .live_membership()
        .observe_lease(|| NOW)
        .await
        .unwrap();
    let mut policy = f.foyer.current_policy();
    f.tls.gate.enabled.store(true, Ordering::SeqCst);
    let mut pending =
        Box::pin(lease.passkey_certificate(&mut policy, || f.clock.load(Ordering::SeqCst)));
    tokio::select! {
        result = &mut pending => panic!("certificate waiter must be gated, success={}", result.is_ok()),
        result = tokio::time::timeout(Duration::from_secs(5), f.tls.gate.arrived.notified()) => result.unwrap(),
    }
    companion
        .call("passkey_revoke", json!({"credential":f.original_id}))
        .await
        .unwrap();
    f.clock.store(NOW + 40, Ordering::SeqCst);
    {
        let mut trust = f.foyer.trust().unwrap();
        assert!(trust.poll(|| NOW + 40).await.unwrap());
        assert!(
            trust
                .current(NOW + 40)
                .unwrap()
                .revocations()
                .passkey_revoked(&f.original_id)
                .unwrap()
        );
    }
    f.tls.gate.release.notify_one();
    assert!(matches!(pending.await, Err(Error::Unauthorized)));
}

#[path = "initial_registration.rs"]
mod initial_registration;
