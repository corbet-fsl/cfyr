//! The assertion-free first stamp (C5) through the retained wallet session: a wallet login
//! within the birth window of an account with one passkey holds the birth grant, so the
//! account's first stamp needs no passkey assertion, exactly once.
use super::*;

fn actions() -> Vec<(cpsd::StampScope, cpsd::StampAction)> {
    vec![(
        cpsd::StampScope::of_community(cpsd::CommunityId::new("alpha").unwrap(), None),
        cpsd::StampAction::new(
            cpsd::ActionKind::new("fixture.birth-stamp").unwrap(),
            cpsd::PayloadDigest::from_bytes([5; 32]),
            cpsd::StampSalt::from_bytes([6; 32]),
        ),
    )]
}

/// Reserve a stamp nonce and build the holder's request for it.
async fn stamp_request(
    f: &Fixture,
    holder: &mut cpsd::OpaqueHolder,
) -> (
    crate::membership::GlobalStampIssuance<crate::HttpClient>,
    Vec<u8>,
) {
    let mut pending = f
        .live()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .stamp_challenge(|| NOW)
        .await
        .unwrap();
    let request = pending
        .with_current(
            || NOW,
            |_, _, key, challenge, _| {
                holder
                    .begin_stamp(
                        &mut cpsd::rand::rngs::OsRng,
                        &cpsd::StampPublicKey::from_bytes(key).unwrap(),
                        &cpsd::IssuanceChallenge::from_bytes(challenge.try_into().unwrap()),
                        &actions(),
                        NOW,
                    )
                    .unwrap()
                    .to_bytes()
            },
        )
        .unwrap();
    (pending, request)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_birth_grant_issues_the_first_stamp_without_an_assertion_once() {
    let mut f = Fixture::on(configured_wallet(100).await).await;
    f.foyer.call("development_gate", json!({})).await.unwrap();
    // The stamp is bound to the member's own passport holder.
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [75; 32]);
    let mut passport = f
        .live()
        .observe_lease(|| NOW)
        .await
        .unwrap()
        .passport_challenge(|| NOW)
        .await
        .unwrap();
    let request = passport
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
    let answer = passport.issue(request, || NOW).await.unwrap();
    holder
        .finish_issuance(&cpsd::BlindPassport::from_bytes(&answer).unwrap())
        .unwrap();
    drop(passport);
    let (mut pending, request) = stamp_request(&f, &mut holder).await;
    let blind = pending.issue_birth(request, || NOW).await.unwrap();
    holder
        .finish_stamp(&cpsd::BlindStamp::from_bytes(&blind).unwrap(), NOW)
        .unwrap();
    // Submitted once per continuation, and the birth stamp item is closed for good.
    assert!(pending.issue_birth(vec![1], || NOW).await.is_err());
    drop(pending);
    let (mut pending, request) = stamp_request(&f, &mut holder).await;
    assert!(pending.issue_birth(request, || NOW).await.is_err());
}
