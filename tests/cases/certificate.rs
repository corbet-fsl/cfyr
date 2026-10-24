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
                                | "/v1/passkey_add" | "/v1/passkey_revoke" | "/v1/step_up_begin"
                                | "/v1/device_pair_authorize" | "/v1/device_approve" | "/v1/device_confirm" | "/v1/device_revoke"
                                | "/v1/handle_available" | "/v1/handle_reserve" | "/v1/voucher_redeem" | "/v1/development_voucher_link"
                                | "/v1/initial_registration_begin" | "/v1/initial_creation"
                                | "/v1/initial_publication_bind" | "/v1/presentation_challenge"
                                | "/v1/account_credential_issue"
                                | "/v1/device_session_begin" | "/v1/device_session_finish" | "/v1/device_join"
                                | "/v1/device_add" | "/v1/device_activate"));
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
                                5 => "/v1/lobby",
                                6 => "/v1/device_keys",
                                7 => "/v1/presentation_challenge",
                                8 => "/v1/account_credential_issue",
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

/// Authorize a device key as a real member does: `step_up_begin` for exactly this action, the passkey assertion for
/// that ceremony, then the action with the proof (cvld requires a fresh step-up for every device action).
async fn authorize_device_with_step_up(
    foyer: &mut Foyer<crate::HttpClient>,
    passkeys: &mut cpky::Client<SoftwareAuthenticator>,
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
            let begin = {
                let body = crate::test_step_up::proven(
                    &mut companion,
                    &mut keys,
                    json!({"kind":"passkey_add"}),
                    json!({"step":"begin"}),
                )
                .await;
                companion.call("passkey_add", body).await.unwrap()
            };
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
        authorize_device_with_step_up(&mut foyer, &mut keys, device).await;
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
    let body = crate::test_step_up::proven(
        &mut companion,
        &mut keys,
        json!({"kind":"passkey_revoke","credential":f.original_id}),
        json!({"credential":f.original_id}),
    )
    .await;
    companion.call("passkey_revoke", body).await.unwrap();
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

#[path = "accounting.rs"]
mod accounting;

/// A wallet member holding a passport in an opaque holder, as the device keeps it.
async fn stamp_wallet(global: &Running, seed: u8) -> (Member, cpsd::OpaqueHolder) {
    let member = enrol(global, WALLET, None).await;
    let wallet = client(global, WALLET, Some(&member.session));
    wallet.call("development_gate", json!({})).await.unwrap();
    let public: cvld::api::GlobalPublic =
        serde_json::from_value(wallet.call("global_public", json!({})).await.unwrap()).unwrap();
    let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [seed; 32]);
    let challenge: cvld::api::Bytes =
        serde_json::from_value(wallet.call("passport_challenge", json!({})).await.unwrap())
            .unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
    let request = holder
        .begin_issuance(&mut cpsd::rand::rngs::OsRng, &issuer, &challenge)
        .unwrap();
    let response: cvld::api::Bytes = serde_json::from_value(
        wallet
            .call(
                "passport_issue",
                json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes()}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    holder
        .finish_issuance(&cpsd::BlindPassport::from_bytes(&response.bytes).unwrap())
        .unwrap();
    (member, holder)
}

/// The ONE wallet confirmation: a stamp covering `actions`, issued blindly after one
/// user-verifying assertion of the wallet passkey over the request's confirmation challenge.
async fn issue_stamp(
    global: &Running,
    member: &mut Member,
    holder: &mut cpsd::OpaqueHolder,
    actions: &[(cpsd::StampScope, cpsd::StampAction)],
) {
    use webauthn_authenticator_rs::AuthenticatorBackend as _;
    let wallet = client(global, WALLET, Some(&member.session));
    let reserved: cvld::api::StampChallenge =
        serde_json::from_value(wallet.call("stamp_challenge", json!({})).await.unwrap()).unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(reserved.challenge.try_into().unwrap());
    let key = cpsd::StampPublicKey::from_bytes(&reserved.key).unwrap();
    let request = holder
        .begin_stamp(&mut cpsd::rand::rngs::OsRng, &key, &challenge, actions, NOW)
        .unwrap();
    let mut options: ckyh::RequestChallengeResponse =
        serde_json::from_value(reserved.options).unwrap();
    options.public_key.challenge = request.confirmation_challenge(&challenge).to_vec().into();
    let credential = member
        .authenticator
        .perform_auth(
            ckyh::Url::parse(&origin_for(WALLET)).unwrap(),
            options.public_key,
            300_000,
        )
        .unwrap();
    let public: ckyh::PublicKeyCredential =
        serde_json::from_value(serde_json::to_value(&credential).unwrap()).unwrap();
    let assertion = json!({
        "credential_id": public.raw_id.as_ref().to_vec(),
        "client_data_json": public.response.client_data_json.as_ref().to_vec(),
        "authenticator_data": public.response.authenticator_data.as_ref().to_vec(),
        "signature": public.response.signature.as_ref().to_vec(),
        "user_handle": public.response.user_handle.as_ref().map(|h| h.as_ref().to_vec()),
    });
    let blind: cvld::api::Bytes = serde_json::from_value(
        wallet
            .call(
                "stamp_issue",
                json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes(),"assertion":assertion}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    // The device expects the epoch of the signed global status, not one from the reply.
    let public: cvld::api::GlobalPublic =
        serde_json::from_value(wallet.call("global_public", json!({})).await.unwrap()).unwrap();
    let epoch = cchr::global_stamp_trust(&public.key_ring, &public.status, NOW)
        .unwrap()
        .epoch()
        .unwrap();
    holder
        .finish_stamp(
            &cpsd::BlindStamp::from_bytes(&blind.bytes).unwrap(),
            epoch,
            NOW,
        )
        .unwrap();
}

#[derive(Clone, Default)]
struct KeysStore(
    std::rc::Rc<std::cell::RefCell<std::collections::HashMap<ckmg::Locator, Vec<u8>>>>,
);
impl ckmg::SecureStore for KeysStore {
    async fn load(
        &mut self,
        location: &ckmg::Locator,
    ) -> std::result::Result<Option<Vec<u8>>, ckmg::Error> {
        Ok(self.0.borrow().get(location).cloned())
    }
    async fn compare_exchange(
        &mut self,
        location: &ckmg::Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
    ) -> std::result::Result<ckmg::Commit, ckmg::Error> {
        let mut records = self.0.borrow_mut();
        if records
            .get(location)
            .map(|value| *blake3::hash(value).as_bytes())
            != expected
        {
            return Ok(ckmg::Commit::Conflict);
        }
        records.insert(*location, replacement.to_vec());
        Ok(ckmg::Commit::Committed)
    }
}
struct KeysClock;
impl ckmg::Clock for KeysClock {
    fn now(&mut self) -> std::result::Result<u64, ckmg::Error> {
        Ok(NOW)
    }
}
/// Test-only lineage authority: every request of this one binding (no production G3).
struct KeysAuthority(ckmg::Binding);
impl ckmg::Authority for KeysAuthority {
    async fn check(
        &mut self,
        request: ckmg::Authorization<'_>,
    ) -> std::result::Result<(), ckmg::Error> {
        if request.binding != &self.0 {
            return Err(ckmg::Error::Unauthorized);
        }
        Ok(())
    }
}
/// A member's first lineage made by Keys, and the same PRF-derived device key's enrollment
/// candidate. Device signatures are typed: the join and the session are signed the way a
/// device-key member signs them before activation.
struct KeysDevice {
    _keys: ckmg::Keys<KeysStore, KeysClock, ckmg::SystemEntropy, KeysAuthority>,
    candidate: ckmg::UnenrolledCreation,
}

/// The member's first community lineage made by Keys on the device, and its device key.
async fn keys_device(community: &str, member: &str) -> (KeysDevice, [u8; 32], ckmg::Receipt) {
    keys_device_with(community, member, 27, 7).await
}

/// Another device of the same member: its own PRF output and device identity, so its key differs.
async fn keys_device_with(
    community: &str,
    member: &str,
    prf_seed: u8,
    device_seed: u8,
) -> (KeysDevice, [u8; 32], ckmg::Receipt) {
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[prf_seed; 32]).unwrap();
    let binding = ckmg::Binding::new(community, member).unwrap();
    let mut keys = ckmg::Keys::new(
        KeysStore::default(),
        KeysClock,
        ckmg::SystemEntropy,
        KeysAuthority(binding.clone()),
    );
    let receipt = keys
        .create_scope(
            &prf,
            binding,
            ckmg::DeviceInfo::new("fixture", &[device_seed; 16]).unwrap(),
            b"fixture",
        )
        .await
        .unwrap();
    keys.acknowledge(receipt.operation).await.unwrap();
    keys.unlock(&prf, community).await.unwrap();
    let key = *keys.device_public_key().await.unwrap().value();
    let candidate = ckmg::EnrollmentSeed::new(
        ckmg::Binding::new(community, member).unwrap(),
        &mut ckmg::SystemEntropy,
    )
    .unwrap()
    .seal(
        &prf,
        ckmg::DeviceInfo::new("fixture", &[device_seed; 16]).unwrap(),
        &mut KeysClock,
        &mut ckmg::SystemEntropy,
    )
    .unwrap();
    (
        KeysDevice {
            _keys: keys,
            candidate,
        },
        key,
        receipt,
    )
}

async fn device_sign(device: &mut KeysDevice, message: &[u8]) -> Vec<u8> {
    let format = ckmg::DeviceFormat::of(message).unwrap();
    device
        .candidate
        .sign_device(format, &message[format.tag().len()..])
        .unwrap()
        .to_vec()
}

#[tokio::test(flavor = "multi_thread")]
async fn device_key_member_reads_and_binds_initial_creation_without_a_passkey_certificate() {
    let global = configured_wallet(100).await;
    let (mut member, mut holder) = stamp_wallet(&global, 61).await;
    let public: cvld::api::GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
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
    let pseudonym = holder
        .pseudonym(&cpsd::CommunityId::new("alpha").unwrap())
        .to_hex();
    // The device makes the member's first lineage locally; its Keys device key joins.
    let (mut device, key, receipt) = keys_device("alpha", &pseudonym).await;
    let (seed, salt, genesis_salt) = ([33; 32], [9; 32], [12; 32]);
    // Join by passport plus ONE stamp over the device key and the creation seed.
    let anonymous = client(&service, HOST, None);
    let feed: cvld::api::TrustFeed =
        serde_json::from_value(anonymous.call("trust_feed", json!({})).await.unwrap()).unwrap();
    // The device pins the community fingerprint (SHA-256 of the founding key), follows the
    // community anchored to it, and builds the scope from its verified Charter as cmsg
    // device_join::stamp_scope does. The server accepting the join below proves that it
    // derives the same scope.
    let founding = csgn::verify_genesis(feed.genesis.as_deref().unwrap())
        .unwrap()
        .founding_key();
    let pinned = csgn::community_fingerprint("alpha", Some(&founding));
    let mut anchored = crate::trust::Trust::anchored_native(
        &crate::trust::Anchor {
            origin: &tls.origin,
            community: "alpha",
            fingerprint: pinned,
            minimum_revision: 1,
            pin: None,
        },
        feed_config(),
        std::slice::from_ref(&tls.root),
    )
    .unwrap();
    anchored.start(|| NOW).await.unwrap();
    let verified = anchored.current(NOW).unwrap().fingerprint().copied();
    assert_eq!(
        verified,
        Some(pinned),
        "the device verifies the pinned fingerprint"
    );
    let scope =
        cpsd::StampScope::of_community(cpsd::CommunityId::new("alpha").unwrap(), verified.as_ref());
    let action = cpsd::StampAction::new(
        cpsd::ActionKind::new(crate::device_session::JOIN_ACTION).unwrap(),
        cpsd::PayloadDigest::from_bytes(crate::device_session::join_payload(&key, &seed)),
        cpsd::StampSalt::from_bytes(salt),
    );
    // ONE stamp, two slots: the join and the lineage genesis of the device's first receipt.
    let genesis = cchr::lineage_genesis_action(&receipt, genesis_salt, NOW).unwrap();
    issue_stamp(
        &global,
        &mut member,
        &mut holder,
        &[
            (scope.clone(), action.clone()),
            (scope.clone(), genesis.clone()),
        ],
    )
    .await;
    let challenge: cvld::api::PresentationChallenge = serde_json::from_value(
        anonymous
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new("alpha").unwrap(),
        csgn::KeyRing::from_cbor(&feed.key_ring).unwrap(),
    );
    let proof = holder
        .present(
            &mut cpsd::rand::rngs::OsRng,
            &expected,
            &challenge.request,
            NOW,
        )
        .unwrap();
    let stamp = holder
        .present_stamp(&mut cpsd::rand::rngs::OsRng, &scope, &action, NOW)
        .unwrap();
    let join = json!({
        "passport": {"challenge": challenge.challenge, "proof": proof.to_bytes()},
        "stamp": stamp.to_bytes(),
        "salt": salt,
        "device_key": key,
        "seed": seed,
        "signature": device_sign(
            &mut device,
            &crate::device_session::join_message("alpha", &challenge.challenge, &key),
        )
        .await,
    });
    // A trusted owner action: never forwarded from the shell.
    assert!(matches!(
        foyer.call("device_join", join.clone()).await,
        Err(Error::Invalid)
    ));
    let user = foyer.device_join(join).await.unwrap();
    // The pairing steps are trusted owner actions as well, and a malformed request is refused.
    for action in ["device_add", "device_activate"] {
        assert!(matches!(
            foyer.call(action, json!({})).await,
            Err(Error::Invalid)
        ));
    }
    assert!(foyer.device_add(json!({})).await.is_err());
    assert!(foyer.device_activate(json!({})).await.is_err());
    // Silent device session through the same held TLS Foyer.
    let nonce = foyer.begin_device_session().await.unwrap();
    let signature = device_sign(&mut device, &nonce.message("alpha")).await;
    foyer
        .finish_device_session(nonce.nonce, &user, key, signature)
        .await
        .unwrap();
    let mut live = foyer.live_membership();
    let mut policy = foyer.current_policy();
    // No passkey certificate exists for a device-key member.
    let lease = live.observe_lease(|| NOW).await.unwrap();
    assert!(lease.observation().device_keys.contains(&key));
    assert!(
        lease
            .passkey_certificate(&mut policy, || NOW)
            .await
            .is_err()
    );
    // The device lease answers from the commitment the stamped join stored.
    let lease = live.observe_lease(|| NOW).await.unwrap();
    let mut initial = lease
        .device_initial_creation(&mut policy, || NOW)
        .await
        .unwrap();
    assert_eq!(initial.seed().unwrap(), seed);
    assert_eq!(initial.publication().unwrap(), None);
    assert_eq!(initial.device_key().unwrap(), Some(key));
    assert_eq!(initial.credential_id().unwrap(), key.as_slice());
    assert!(initial.certificate_bytes().is_err());
    initial.check(|| NOW + 1).unwrap();
    // Clocks never run backwards.
    assert!(initial.check(|| NOW).is_err());
    drop(initial);
    let lease = live.observe_lease(|| NOW + 2).await.unwrap();
    let initial = lease
        .device_initial_creation(&mut policy, || NOW + 2)
        .await
        .unwrap();
    // A device-key member binds only with the genesis stamp evidence of its receipt.
    assert!(
        initial
            .bind_publication([55; 32], || NOW + 2)
            .await
            .is_err()
    );
    let evidence = cchr::GenesisStampEvidence::new(
        receipt.clone(),
        &holder
            .present_stamp(&mut cpsd::rand::rngs::OsRng, &scope, &genesis, NOW)
            .unwrap(),
        genesis_salt,
        NOW,
    )
    .to_bytes()
    .unwrap();
    let lease = live.observe_lease(|| NOW + 2).await.unwrap();
    let initial = lease
        .device_initial_creation(&mut policy, || NOW + 2)
        .await
        .unwrap();
    let mut bound = initial
        .bind_publication_with_evidence([55; 32], &evidence, || NOW + 2)
        .await
        .unwrap();
    assert_eq!(bound.publication().unwrap(), Some([55; 32]));
    bound.refresh(|| NOW + 3).await.unwrap();
    // A different winner is refused by the server's one-winner bind.
    drop(bound);
    let lease = live.observe_lease(|| NOW + 4).await.unwrap();
    let initial = lease
        .device_initial_creation(&mut policy, || NOW + 4)
        .await
        .unwrap();
    assert_eq!(initial.publication().unwrap(), Some([55; 32]));
    assert!(
        initial
            .bind_publication_with_evidence([56; 32], &evidence, || NOW + 4)
            .await
            .is_err()
    );
}

/// The community's one-use presentation challenge, answered by the member's passport.
async fn passport_over_challenge(
    anonymous: &cvld::cli::Client,
    holder: &mut cpsd::OpaqueHolder,
    key_ring: &[u8],
) -> (cvld::api::PresentationChallenge, Vec<u8>) {
    let challenge: cvld::api::PresentationChallenge = serde_json::from_value(
        anonymous
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new("alpha").unwrap(),
        csgn::KeyRing::from_cbor(key_ring).unwrap(),
    );
    let proof = holder
        .present(
            &mut cpsd::rand::rngs::OsRng,
            &expected,
            &challenge.request,
            NOW,
        )
        .unwrap();
    (challenge, proof.to_bytes())
}

#[tokio::test(flavor = "multi_thread")]
async fn one_stamp_pairs_a_further_device_key_pending_then_active() {
    let global = configured_wallet(100).await;
    let (mut member, mut holder) = stamp_wallet(&global, 62).await;
    let public: cvld::api::GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let service = community("alpha", &public).await;
    let tls = TlsIngress::new(&service).await;
    let original = trust(&service, &tls).await;
    let new_foyer = || async {
        Foyer::with_trust(
            crate::HttpClient::with_roots(
                tls.origin.clone(),
                "127.0.0.1".into(),
                None,
                std::slice::from_ref(&tls.root),
            )
            .unwrap(),
            trust(&service, &tls).await,
        )
    };
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
    let community_id = cpsd::CommunityId::new("alpha").unwrap();
    let pseudonym = holder.pseudonym(&community_id).to_hex();
    let anonymous = client(&service, HOST, None);
    let feed: cvld::api::TrustFeed =
        serde_json::from_value(anonymous.call("trust_feed", json!({})).await.unwrap()).unwrap();
    let founding = csgn::verify_genesis(feed.genesis.as_deref().unwrap())
        .unwrap()
        .founding_key();
    let fingerprint = csgn::community_fingerprint("alpha", Some(&founding));
    let scope = cpsd::StampScope::of_community(community_id, Some(&fingerprint));

    // The member's first device joins (one stamp), as in the device-key join.
    let (mut first, first_key, _) = keys_device("alpha", &pseudonym).await;
    let (seed, join_salt) = ([34; 32], [10; 32]);
    let join_action = cpsd::StampAction::new(
        cpsd::ActionKind::new(crate::device_session::JOIN_ACTION).unwrap(),
        cpsd::PayloadDigest::from_bytes(crate::device_session::join_payload(&first_key, &seed)),
        cpsd::StampSalt::from_bytes(join_salt),
    );
    issue_stamp(
        &global,
        &mut member,
        &mut holder,
        &[(scope.clone(), join_action.clone())],
    )
    .await;
    let (challenge, proof) = passport_over_challenge(&anonymous, &mut holder, &feed.key_ring).await;
    let stamp = holder
        .present_stamp(&mut cpsd::rand::rngs::OsRng, &scope, &join_action, NOW)
        .unwrap();
    let user = foyer
        .device_join(json!({
            "passport": {"challenge": challenge.challenge, "proof": proof},
            "stamp": stamp.to_bytes(),
            "salt": join_salt,
            "device_key": first_key,
            "seed": seed,
            "signature": device_sign(
                &mut first,
                &crate::device_session::join_message("alpha", &challenge.challenge, &first_key),
            )
            .await,
        }))
        .await
        .unwrap();

    // The new device holds a key of its own; ONE stamp covers BOTH pairing steps for it.
    let (mut second, second_key, _) = keys_device_with("alpha", &pseudonym, 28, 8).await;
    let action = |kind: &str, key: &[u8; 32], salt: u8| {
        cpsd::StampAction::new(
            cpsd::ActionKind::new(kind).unwrap(),
            cpsd::PayloadDigest::from_bytes(crate::device_session::pairing_payload(kind, key)),
            cpsd::StampSalt::from_bytes([salt; 32]),
        )
    };
    let add = action(crate::device_session::ADD_ACTION, &second_key, 21);
    let activate = action(crate::device_session::ACTIVATE_ACTION, &second_key, 22);
    issue_stamp(
        &global,
        &mut member,
        &mut holder,
        &[
            (scope.clone(), add.clone()),
            (scope.clone(), activate.clone()),
        ],
    )
    .await;
    // The pairing request of one step: fresh challenge, passport, the given stamp action, and
    // the new key's possession signature over that same challenge.
    let step = async |holder: &mut cpsd::OpaqueHolder,
                      device: &mut KeysDevice,
                      key: [u8; 32],
                      presented: &cpsd::StampAction,
                      salt: u8| {
        let (challenge, proof) = passport_over_challenge(&anonymous, holder, &feed.key_ring).await;
        let stamp = holder
            .present_stamp(&mut cpsd::rand::rngs::OsRng, &scope, presented, NOW)
            .unwrap();
        let salt = [salt; 32];
        json!({
            "passport": {"challenge": challenge.challenge, "proof": proof},
            "stamp": stamp.to_bytes(),
            "salt": salt,
            "device_key": key,
            "signature": device_sign(
                device,
                &crate::device_session::join_message("alpha", &challenge.challenge, &key),
            )
            .await,
        })
    };
    let try_session = async |device: &mut KeysDevice, key: [u8; 32]| {
        let mut foyer = new_foyer().await;
        let nonce = foyer.begin_device_session().await.unwrap();
        let signature = device_sign(device, &nonce.message("alpha")).await;
        foyer
            .finish_device_session(nonce.nonce, &user, key, signature)
            .await
    };

    // Cross-use of the one stamp is refused: the add slot never activates, and a stamp for
    // this key never pairs another key.
    let early = step(&mut holder, &mut second, second_key, &add, 21).await;
    assert!(
        foyer.device_activate(early).await.is_err(),
        "the add stamp is no activation"
    );
    let (mut third, third_key, _) = keys_device_with("alpha", &pseudonym, 29, 9).await;
    let stolen = step(&mut holder, &mut third, third_key, &add, 21).await;
    let stolen = foyer.device_add(stolen).await;
    assert!(
        stolen.is_err(),
        "the stamp covers exactly one key: {stolen:?}"
    );
    // The join's stamp is no pairing stamp.
    let replay = step(&mut holder, &mut second, second_key, &join_action, 10).await;
    assert!(
        foyer.device_add(replay).await.is_err(),
        "a join stamp never adds a key"
    );
    // Activating a key that was never added is refused too.
    let early = step(&mut holder, &mut second, second_key, &activate, 22).await;
    assert!(
        foyer.device_activate(early).await.is_err(),
        "no activation before the add"
    );

    // Step one registers the key PENDING: it grants nothing, no session opens.
    let request = step(&mut holder, &mut second, second_key, &add, 21).await;
    foyer.device_add(request).await.unwrap();
    assert!(
        try_session(&mut second, second_key).await.is_err(),
        "a pending key has no session"
    );
    // A retry of the same step with the same stamp is idempotent (a lost answer costs nothing).
    let request = step(&mut holder, &mut second, second_key, &add, 21).await;
    foyer.device_add(request).await.unwrap();
    assert!(
        try_session(&mut second, second_key).await.is_err(),
        "still pending without an activate"
    );

    // Step two, with the SAME stamp's second slot, makes it ACTIVE: its sessions work, and the
    // first device keeps working.
    let request = step(&mut holder, &mut second, second_key, &activate, 22).await;
    foyer.device_activate(request).await.unwrap();
    try_session(&mut second, second_key).await.unwrap();
    try_session(&mut first, first_key).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_passkey_session_has_no_device_initial_creation() {
    let f = Fixture::new().await;
    let mut live = f.foyer.live_membership();
    let lease = live.observe_lease(|| NOW).await.unwrap();
    let mut policy = f.foyer.current_policy();
    assert!(
        lease
            .device_initial_creation(&mut policy, || NOW)
            .await
            .is_err()
    );
}
