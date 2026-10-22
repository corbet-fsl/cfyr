//! Genuine global Door/Keyhole/Passkeys over fixed test-owned TLS ingress.
//! No certificate, community admission, or Keys authority is manufactured here.
use super::*;
#[path = "../support/owner.rs"]
mod owner;
use cpky::{
    Context,
    software::{SoftwareAuthenticator, TestConfiguration},
};
use owner::*;
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};

const HOST: &str = WALLET;
const COMMUNITY: &str = "api.alpha.example.test";
// Exact original global Passkeys RP origin; the wallet has its own realm.
const VAULT: &str = "https://vault.wallet.example.test";

#[derive(Default)]
struct Gate {
    enabled: AtomicBool,
    target: AtomicUsize,
    arrived: Notify,
    release: Notify,
}
fn passkeys() -> cpky::Client<SoftwareAuthenticator> {
    cpky::Client::new(
        Context::new(VAULT, WALLET).unwrap(),
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
fn foyer(tls: &TlsIngress) -> Foyer<crate::HttpClient> {
    Foyer::new(
        crate::HttpClient::with_roots(
            tls.origin.clone(),
            "127.0.0.1".into(),
            None,
            std::slice::from_ref(&tls.root),
        )
        .unwrap(),
    )
}
async fn login(
    api: &mut Foyer<crate::HttpClient>,
    keys: &mut cpky::Client<SoftwareAuthenticator>,
) -> Vec<u8> {
    let challenge = api.begin_browser_login().await.unwrap();
    let (public, custody) = keys.sign_in(challenge.options).await.unwrap().into_parts();
    drop(custody);
    let id = public.credential_id().unwrap();
    api.finish_browser_login(challenge.ceremony, public)
        .await
        .unwrap();
    id
}
struct Fixture {
    tls: TlsIngress,
    service: Running,
    foyer: Foyer<crate::HttpClient>,
    keys: cpky::Client<SoftwareAuthenticator>,
    original_id: Vec<u8>,
    user: String,
}
impl Fixture {
    async fn new() -> Self {
        Self::on(global(100).await).await
    }
    async fn on(service: Running) -> Self {
        let tls = TlsIngress::new(&service).await;
        let mut foyer = foyer(&tls);
        let pending = foyer.begin_member_registration(None).await.unwrap();
        let mut keys = passkeys();
        let (public, custody) = keys
            .register_member(pending.options().clone())
            .await
            .unwrap()
            .into_parts();
        drop(custody);
        let original_id = public.credential_id().unwrap();
        let registered = foyer
            .finish_member_registration(pending, public)
            .await
            .unwrap();
        assert_eq!(registered.original_credential_id(), original_id);
        assert_eq!(login(&mut foyer, &mut keys).await, original_id);
        let user = foyer
            .shared
            .session
            .lock()
            .await
            .info
            .as_ref()
            .unwrap()
            .user
            .clone();
        Self {
            tls,
            service,
            foyer,
            keys,
            original_id,
            user,
        }
    }
    fn live(&self) -> LiveGlobalWallet<crate::HttpClient> {
        self.foyer.live_global_wallet(self.tls.origin.clone())
    }
    async fn add_key(&mut self) -> (cpky::Client<SoftwareAuthenticator>, Vec<u8>) {
        let body = crate::test_step_up::proven(
            &mut self.foyer,
            &mut self.keys,
            json!({"kind":"passkey_add"}),
            json!({"step":"begin"}),
        )
        .await;
        let begin = self.foyer.call("passkey_add", body).await.unwrap();
        let mut added = passkeys();
        let (public, custody) = added
            .register_member(begin["options"].clone())
            .await
            .unwrap()
            .into_parts();
        drop(custody);
        let id = public.credential_id().unwrap();
        let reply = self.foyer.call("passkey_add", json!({"step":"finish", "ceremony":begin["ceremony"], "credential":public.into_json()})).await.unwrap();
        assert_eq!(
            serde_json::from_value::<Vec<u8>>(reply["credential"].clone()).unwrap(),
            id
        );
        (added, id)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_global_host_and_current_login_key_have_a_terminal_live_clock() {
    let f = Fixture::new().await;
    let mut live = f.live();
    let mut lease = live.observe_lease(|| NOW).await.unwrap();
    assert_eq!(lease.user().unwrap(), f.user);
    assert_eq!(lease.credential_id().unwrap(), f.original_id);
    let deadline = lease.expires().unwrap();
    lease.check(|| NOW + 10).unwrap();
    assert!(lease.check(|| NOW + 9).is_err());
    assert!(lease.credential_id().is_err());
    assert!(lease.check(|| NOW + 11).is_err());
    drop(lease);
    let mut lease = live.observe_lease(|| NOW).await.unwrap();
    assert!(lease.check(|| deadline).is_err());
    assert!(lease.user().is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_stamp_trust_comes_from_the_signed_global_status_of_this_session() {
    let f = Fixture::on(configured_wallet(100).await).await;
    let mut lease = f.live().observe_lease(|| NOW).await.unwrap();
    let trust = lease.stamp_trust(|| NOW).await.unwrap();
    // The genuine wallet's configured stamp key, the open period of its ring.
    assert!(format!("{trust:?}").contains("KeyId(wallet-stamp-1)"));
    assert_eq!(lease.check(|| NOW + 1).unwrap(), NOW + 1);
    // The session deadline still holds after the read.
    let deadline = lease.expires().unwrap();
    assert!(lease.stamp_trust(|| deadline).await.is_err());
    assert!(lease.user().is_err());
    // A wallet that issues no stamps names no stamp key: no trust.
    let f = Fixture::new().await;
    let mut lease = f.live().observe_lease(|| NOW).await.unwrap();
    assert!(matches!(
        lease.stamp_trust(|| NOW).await,
        Err(Error::Reconcile)
    ));
    assert!(lease.check(|| NOW).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fork_lets_two_leases_hold_one_wallet_session_family_at_once() {
    let mut f = Fixture::new().await;
    // Nothing to fork without a passkey session.
    let mut unsigned = foyer(&f.tls);
    let mut sibling = foyer(&f.tls);
    assert!(matches!(
        unsigned.fork_into(&mut sibling).await,
        Err(Error::Unauthorized)
    ));
    let info = f.foyer.fork_into(&mut sibling).await.unwrap();
    assert_eq!(info.user, f.user);
    {
        let mut parent_live = f.live();
        let mut parent = parent_live.observe_lease(|| NOW).await.unwrap();
        let mut sibling_live = sibling.live_global_wallet(f.tls.origin.clone());
        let mut forked = sibling_live.observe_lease(|| NOW).await.unwrap();
        assert_eq!(forked.user().unwrap(), f.user);
        assert_eq!(forked.credential_id().unwrap(), f.original_id);
        assert_eq!(forked.expires().unwrap(), parent.expires().unwrap());
        assert_eq!(forked.expires().unwrap(), info.expires);
    }
    // Ending the sibling ends its parent: one family.
    sibling.call("logout", json!({})).await.unwrap();
    assert!(f.live().observe_lease(|| NOW).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_same_account_noncurrent_key_never_substitutes_for_current_login() {
    let mut f = Fixture::new().await;
    let (mut added, id) = f.add_key().await;
    assert_ne!(id, f.original_id);
    let rows = f.foyer.call("passkey_list", json!({})).await.unwrap();
    let rows = rows["passkeys"].as_array().unwrap();
    assert!(rows.iter().any(|row| row["credential"] == json!(id)
        && row["current"] == false
        && row["revoked"] == false));
    assert!(
        rows.iter()
            .any(|row| row["credential"] == json!(f.original_id) && row["current"] == true)
    );
    // Adversarial local pin corruption cannot turn an enrolled noncurrent key
    // into the original server's current credential. Both rows are genuine.
    f.foyer.shared.session.lock().await.login_credential = Some(id.clone());
    assert!(f.live().observe_lease(|| NOW).await.is_err());
    assert_eq!(login(&mut f.foyer, &mut added).await, id);
    let lease = f.live().observe_lease(|| NOW).await.unwrap();
    assert_eq!(lease.user().unwrap(), f.user);
    assert_eq!(lease.credential_id().unwrap(), id);
}

#[tokio::test(flavor = "multi_thread")]
async fn generic_successful_login_and_copied_bearer_do_not_supply_a_typed_pin() {
    let mut f = Fixture::new().await;
    let challenge = f.foyer.begin_browser_login().await.unwrap();
    let (public, custody) = f
        .keys
        .sign_in(challenge.options)
        .await
        .unwrap()
        .into_parts();
    drop(custody);
    f.foyer
        .authenticate(json!({"ceremony":challenge.ceremony,"credential":public.into_json()}))
        .await
        .unwrap();
    assert!(f.live().observe_lease(|| NOW).await.is_err());
    let member = enrol(&f.service, WALLET, None).await;
    let copied = Foyer::new(
        crate::HttpClient::with_roots(
            f.tls.origin.clone(),
            "127.0.0.1".into(),
            Some(member.session),
            std::slice::from_ref(&f.tls.root),
        )
        .unwrap(),
    );
    assert!(
        copied
            .live_global_wallet(f.tls.origin.clone())
            .observe_lease(|| NOW)
            .await
            .is_err()
    );
    assert_eq!(login(&mut f.foyer, &mut f.keys).await, f.original_id);
    assert!(f.live().observe_lease(|| NOW).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn fresh_original_server_revocation_and_wrong_runtime_origin_refuse() {
    let mut f = Fixture::new().await;
    assert!(
        f.foyer
            .live_global_wallet("https://other.example.test".into())
            .observe_lease(|| NOW)
            .await
            .is_err()
    );
    assert_eq!(f.tls.observations.load(Ordering::SeqCst), 0);
    let (mut added, _) = f.add_key().await;
    let mut other = foyer(&f.tls);
    login(&mut other, &mut added).await;
    let body = crate::test_step_up::proven(
        &mut other,
        &mut added,
        json!({"kind":"passkey_revoke","credential":f.original_id}),
        json!({"credential":f.original_id}),
    )
    .await;
    other.call("passkey_revoke", body).await.unwrap();
    assert!(f.live().observe_lease(|| NOW).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn genuine_community_session_cannot_qualify_as_global_wallet_scope() {
    let global = global(100).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let service = community("alpha", &public).await;
    let tls = TlsIngress::fixed_host(&service, COMMUNITY).await;
    let mut api = foyer(&tls);
    let proof = presentation(&service, COMMUNITY, None, &passport).await;
    let pending = api
        .begin_member_registration(Some(serde_json::to_value(proof).unwrap()))
        .await
        .unwrap();
    let vault = "https://vault.alpha.example.test";
    let mut keys = cpky::Client::new(
        Context::new(vault, "alpha.example.test").unwrap(),
        SoftwareAuthenticator::new(
            vault,
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap(),
    );
    let (public, custody) = keys
        .register_member(pending.options().clone())
        .await
        .unwrap()
        .into_parts();
    drop(custody);
    api.finish_member_registration(pending, public)
        .await
        .unwrap();
    login(&mut api, &mut keys).await;
    // This is a genuine community member login at the exact selected origin.
    // Its original owner refuses global_public before any passkey-list read.
    assert!(
        api.live_global_wallet(tls.origin.clone())
            .observe_lease(|| NOW)
            .await
            .is_err()
    );
    assert_eq!(tls.observations.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_pending_read_close_cancellation_and_afterawait_deadline_refuse() {
    for outcome in 0..3 {
        let f = Fixture::new().await;
        let mut live = f.live();
        f.tls.gate.enabled.store(true, Ordering::SeqCst);
        let clock = Arc::new(AtomicU64::new(NOW + 10));
        let observed = clock.clone();
        let mut future = Box::pin(live.observe_lease(move || observed.load(Ordering::SeqCst)));
        tokio::select! {
            _ = f.tls.gate.arrived.notified() => {},
            _ = &mut future => panic!("genuine original read should await reply"),
        }
        match outcome {
            0 => clock.store(NOW + 600, Ordering::SeqCst),
            1 => drop(f.foyer),
            _ => clock.store(NOW + 9, Ordering::SeqCst),
        }
        f.tls.gate.release.notify_one();
        assert!(future.await.is_err());
    }
    let f = Fixture::new().await;
    let mut live = f.live();
    f.tls.gate.enabled.store(true, Ordering::SeqCst);
    let mut future = Box::pin(live.observe_lease(|| NOW));
    tokio::select! {
        _ = f.tls.gate.arrived.notified() => {},
        _ = &mut future => panic!("genuine original read should await reply"),
    }
    drop(future);
    f.tls.gate.release.notify_one();
    // Cancellation releases the actual pending/owned-lock fence.
    assert!(live.observe_lease(|| NOW).await.is_ok());
    let mut lease = live.observe_lease(|| NOW).await.unwrap();
    drop(f.foyer);
    assert!(lease.check(|| NOW).is_err());
    assert!(lease.expires().is_err());
}
struct TlsIngress {
    origin: String,
    root: Vec<u8>,
    observations: Arc<AtomicUsize>,
    gate: Arc<Gate>,
    mutation: Arc<Gate>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for TlsIngress {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl TlsIngress {
    async fn new(service: &Running) -> Self {
        Self::fixed_host(service, HOST).await
    }
    async fn fixed_host(service: &Running, host: &'static str) -> Self {
        assert!(matches!(host, HOST | COMMUNITY));
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
        let observations = Arc::new(AtomicUsize::new(0));
        let observed = observations.clone();
        let gate = Arc::new(Gate::default());
        let paused = gate.clone();
        let mutation = Arc::new(Gate::default());
        let delayed = mutation.clone();
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
                        let delayed = delayed.clone();
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
                                | "/v1/global_public" | "/v1/passkey_list"
                                | "/v1/passkey_add" | "/v1/passkey_revoke" | "/v1/step_up_begin"
                                | "/v1/global_initial_registration_continue" | "/v1/initial_creation"
                                | "/v1/initial_publication_bind" | "/v1/global_self_ban_begin"
                                | "/v1/global_self_ban_finish" | "/v1/wallet_trust_feed"
                                | "/v1/wallet_trust_changes" | "/v1/wallet_device_keys"
                                | "/v1/wallet_device_authorize" | "/v1/passkey_certificate"
                                | "/v1/development_gate" | "/v1/passport_challenge" | "/v1/passport_issue"
                                | "/v1/session_fork" | "/v1/wallet_birth_genesis" | "/v1/stamp_challenge"
                                | "/v1/stamp_issue"));
                            // Fixed, test-owned virtual-host ingress route. It never
                            // takes the upstream URL or Host from request JSON.
                            // The WebAuthn vault realm stays the original VAULT;
                            // transport routing itself certifies no membership.
                            let mut request = reqwest::Client::new().post(format!("{upstream}{path}")).header("host", host);
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
                            if path == "/v1/passkey_list" {
                                observed.fetch_add(1, Ordering::SeqCst);
                                if paused.enabled.swap(false, Ordering::SeqCst) {
                                    paused.arrived.notify_one();
                                    paused.release.notified().await;
                                }
                            }
                            let target = match path.as_str() {
                                "/v1/global_initial_registration_continue" => 1,
                                "/v1/register_finish" => 2,
                                "/v1/initial_publication_bind" => 3,
                                "/v1/wallet_device_keys" => 4,
                                "/v1/passkey_certificate" => 5,
                                "/v1/passport_challenge" => 6,
                                "/v1/passport_issue" => 7,
                                _ => 0,
                            };
                            if target != 0 && delayed.target.load(Ordering::SeqCst) == target
                                && delayed.enabled.swap(false, Ordering::SeqCst) {
                                delayed.arrived.notify_one();
                                delayed.release.notified().await;
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
            observations,
            gate,
            mutation,
            task,
        }
    }
}

#[path = "global_enrollment.rs"]
mod enrollment;

#[cfg(feature = "http")]
#[path = "wallet_certificate.rs"]
mod certificates;

#[path = "global_passport.rs"]
mod passport;

#[path = "birth_stamp.rs"]
mod birth_stamp;
