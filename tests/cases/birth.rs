//! One-ceremony registration through the genuine wallet Door over pinned TLS: the Foyer adopts
//! the birth session register_finish returns (C1), binds the wallet device by the device's own
//! signature (C3), obtains the wallet-signed birth statement (C4), binds the first publication
//! with that birth evidence, and receives the birth passport (Q5). No login and no second
//! passkey ceremony after the creation.
use super::*;

const OTHER_SEED: [u8; 32] = [23; 32];

#[derive(Clone, Default)]
struct Store(std::rc::Rc<std::cell::RefCell<std::collections::HashMap<ckmg::Locator, Vec<u8>>>>);
impl ckmg::SecureStore for Store {
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
struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> std::result::Result<u64, ckmg::Error> {
        Ok(NOW)
    }
}
struct Allow;
impl ckmg::Authority for Allow {
    async fn check(
        &mut self,
        _request: ckmg::Authorization<'_>,
    ) -> std::result::Result<(), ckmg::Error> {
        Ok(())
    }
}

/// The device-signed wallet genesis receipt of `account` (a real Keys `Created` receipt) and
/// the PRF its device key K derives from.
async fn genesis(account: &str, credential: &[u8]) -> (ckmg::passkey::PrfOutput, ckmg::Receipt) {
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap();
    let mut keys = ckmg::Keys::new(Store::default(), Clock, ckmg::SystemEntropy, Allow);
    let receipt = keys
        .create_scope(
            &prf,
            ckmg::Binding::new("wallet", account).unwrap(),
            ckmg::DeviceInfo::new("fixture", credential).unwrap(),
            b"fixture",
        )
        .await
        .unwrap();
    (prf, receipt)
}

/// A fresh wallet registration with creation commitment SEED, finished WITHOUT a login.
async fn born() -> (
    Running,
    TlsIngress,
    Foyer<crate::HttpClient>,
    String,
    Vec<u8>,
) {
    let service = running().await;
    let tls = TlsIngress::new(&service).await;
    let mut foyer = api(&tls).await;
    let mut keys = passkeys();
    let mut reservation = foyer
        .begin_global_initial_registration(&tls.origin, || NOW)
        .await
        .unwrap();
    let user = reservation.account().to_owned();
    let pending = reservation
        .continue_initial(&foyer, SEED, || NOW)
        .await
        .unwrap();
    let (public, prf) = keys
        .register_member(pending.options().clone())
        .await
        .unwrap()
        .into_parts();
    drop(prf);
    let id = public.credential_id().unwrap();
    let finish = pending
        .prepare_finish(&foyer, public, || NOW)
        .await
        .unwrap();
    foyer
        .resume_global_initial_registration(finish, || NOW)
        .await
        .unwrap();
    (service, tls, foyer, user, id)
}

async fn lease(
    foyer: &Foyer<crate::HttpClient>,
    tls: &TlsIngress,
) -> crate::membership::GlobalWalletLease<crate::HttpClient> {
    foyer
        .live_global_wallet(tls.origin.clone())
        .observe_lease(|| NOW)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn one_ceremony_registration_binds_device_birth_statement_publication_and_passport() {
    let (_service, tls, mut foyer, user, id) = born().await;
    // C1: the Foyer holds the birth session of exactly the new credential; no login ran.
    {
        let held = foyer.shared.session.lock().await;
        let info = held.info.as_ref().unwrap();
        assert_eq!(info.user, user);
        assert_eq!(info.role, "member");
        assert_eq!(held.login_credential.as_deref(), Some(id.as_slice()));
        assert!(!held.device_session);
    }
    let (prf, receipt) = genesis(&user, &id).await;
    let device = *receipt.attested_lineage().unwrap().1.value();
    let bind_signature = |commitment: &[u8; 32]| {
        let payload =
            ckmg::wallet_birth_device_payload(VAULT, &user, &id, commitment, &device).unwrap();
        ckmg::passkey::sign_device_birth(
            &prf,
            "wallet",
            ckmg::DeviceFormat::WalletBirthDevice,
            &payload,
        )
        .unwrap()
    };
    // C3: a signature over another seed commitment is refused and binds nothing.
    let mut wallet = lease(&foyer, &tls).await;
    assert!(
        wallet
            .authorize_birth_device(device, bind_signature(&OTHER_SEED), || NOW)
            .await
            .is_err()
    );
    drop(wallet);
    let mut wallet = lease(&foyer, &tls).await;
    wallet
        .authorize_birth_device(device, bind_signature(&SEED), || NOW)
        .await
        .unwrap();
    // C4: the wallet-signed statement for the genesis receipt; the same digest repeats it.
    let digest = receipt.passkey_challenge().unwrap();
    let statement = wallet.birth_genesis(digest, || NOW).await.unwrap();
    let again = wallet.birth_genesis(digest, || NOW).await.unwrap();
    assert_eq!(again.statement(), statement.statement());
    assert_eq!(again.at(), statement.at());
    let (bytes, at) = statement.into_parts();
    let evidence = cchr::BirthGenesisEvidence::new(receipt.clone(), bytes, at);
    // The evidence verifies offline under the wallet Charter this Foyer follows, names this
    // credential and K, and is bound to this account only.
    {
        let mut trust = foyer.trust().unwrap();
        trust.refresh(NOW).unwrap();
        trust.poll(|| NOW).await.unwrap();
    }
    foyer
        .current(NOW, |current| {
            assert_eq!(current.community(), "wallet");
            let verified = cchr::verify_birth_genesis(
                current.key_ring(),
                &evidence,
                &cchr::wallet_fingerprint(None),
                &user,
                NOW,
            )
            .unwrap();
            assert_eq!(verified.statement().commitment(), &SEED);
            verified.check_restoring(&id, &device).unwrap();
            assert!(
                verified
                    .check_restoring(b"another credential", &device)
                    .is_err()
            );
            assert!(
                cchr::verify_birth_genesis(
                    current.key_ring(),
                    &evidence,
                    &cchr::wallet_fingerprint(None),
                    "another-account",
                    NOW,
                )
                .is_err()
            );
        })
        .unwrap();
    // The first publication bind carries the birth evidence; malformed evidence or another
    // seed commitment is refused before anything binds.
    assert!(
        wallet
            .bind_birth_creation(SEED, PUBLICATION, b"not evidence".to_vec(), || NOW)
            .await
            .is_err()
    );
    let wallet = lease(&foyer, &tls).await;
    assert!(
        wallet
            .bind_birth_creation(
                OTHER_SEED,
                PUBLICATION,
                evidence.to_bytes().unwrap(),
                || NOW
            )
            .await
            .is_err()
    );
    let wallet = lease(&foyer, &tls).await;
    let mut initial = wallet
        .bind_birth_creation(SEED, PUBLICATION, evidence.to_bytes().unwrap(), || NOW)
        .await
        .unwrap();
    assert_eq!(initial.commitments().unwrap(), (SEED, PUBLICATION));
    assert_eq!(initial.credential_id().unwrap(), id);
    initial.refresh(|| NOW).await.unwrap();
    drop(initial);
    // Q5: the birth passport, signed by the bound K over this exact request, once.
    foyer.call("development_gate", json!({})).await.unwrap();
    let mut pending = lease(&foyer, &tls)
        .await
        .passport_challenge(|| NOW)
        .await
        .unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [74; 32]);
    let request = pending
        .with_current(
            || NOW,
            |_, _, issuer, challenge, _| {
                holder
                    .begin_issuance(
                        &mut cpsd::rand::rngs::OsRng,
                        &cpsd::IssuerPublicKey::from_bytes(issuer).unwrap(),
                        &cpsd::IssuanceChallenge::from_bytes(challenge.try_into().unwrap()),
                    )
                    .unwrap()
                    .to_bytes()
            },
        )
        .unwrap();
    let passport_signature = ckmg::passkey::sign_device_birth(
        &prf,
        "wallet",
        ckmg::DeviceFormat::WalletBirthPassport,
        &ckmg::wallet_birth_passport_payload(&request),
    )
    .unwrap();
    let answer = pending
        .issue_birth(request, passport_signature, || NOW)
        .await
        .unwrap();
    holder
        .finish_issuance(&cpsd::BlindPassport::from_bytes(&answer).unwrap())
        .unwrap();
    assert!(holder.attributes().is_some());
}
