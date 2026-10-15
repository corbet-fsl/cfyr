//! The thin facade carries the original door's real member workflow unchanged.
use super::*;
use webauthn_authenticator_rs::AuthenticatorBackend as _;
use cvld::api::{CredentialResponse, Lobby, PresentationChallenge, PresentationInput, TrustFeed};

async fn issue(
    foyer: &mut Foyer<HttpClient>,
    passport: &cpsd::Passport,
    expected: &cpsd::AuthenticatedCommunity,
    device: [u8; 32],
    now: u64,
) -> CredentialResponse {
    let challenge: PresentationChallenge = serde_json::from_value(
        foyer
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let proof = passport
        .present(
            &mut cpsd::rand::rngs::OsRng,
            expected,
            &challenge.request,
            now,
        )
        .unwrap();
    serde_json::from_value(
        foyer
            .call(
                "credential_issue",
                json!({
                    "presentation": PresentationInput {
                        challenge: challenge.challenge,
                        proof: proof.to_bytes(),
                    },
                    "devices": [device],
                }),
            )
            .await
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn lobby_voucher_and_renewal_use_real_owner_authority_until_passkey_revocation() {
    let wallet = global(200).await;
    let (_, passport, public) = wallet_passport(&wallet).await;
    let service = community("alpha", &public).await;
    let host = "api.alpha.example.test";
    let enrolled = enrol_community(&service, host, &passport).await;
    let mut member = foyer(&service, host, Some(enrolled.session.clone()));
    let lobby: Lobby =
        serde_json::from_value(member.call("lobby", json!({})).await.unwrap()).unwrap();
    let scope = cpsd::CommunityId::new("alpha").unwrap();
    assert_eq!(lobby.member_id, passport.pseudonym(&scope).to_hex());
    assert_ne!(lobby.state, "admitted");
    member
        .call("handle_reserve", json!({"handle":"foyer_member"}))
        .await
        .unwrap();
    let pin = cmty::cmbr::PinV2::seal(
        &cpns::FingerprintContext {
            community: "alpha",
            member: &lobby.member_id,
            field: "restricted",
        },
        b"true",
        &cpns::Salt::from_bytes(vec![11; 32]).unwrap(),
    );
    member
        .call("pin_set", json!({"field":"restricted","pin":pin}))
        .await
        .unwrap();

    let feed: TrustFeed =
        serde_json::from_value(member.call("trust_feed", json!({})).await.unwrap()).unwrap();
    let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
    // Independent fictional deployment key from the exact owner fixture, never
    // authority derived merely from the response's supplied key ring.
    let configured = ed25519_dalek::SigningKey::from_bytes(&[b'a'; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(ring.issuer(), "alpha");
    assert_eq!(ring.keys().len(), 1);
    assert_eq!(ring.keys()[0].public_key(), configured);
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(scope, ring.clone());
    assert!(
        issue(&mut member, &passport, &expected, enrolled.signing_key, NOW)
            .await
            .credential
            .is_none()
    );
    // A link the server never registered is refused.
    let wrong = voucher("alpha", "foreign-member", "foyer-unknown", NOW + 172800);
    assert!(
        member
            .call("voucher_redeem", wrong["redeem"].clone())
            .await
            .is_err()
    );
    let valid = voucher("alpha", &lobby.member_id, "foyer-voucher", NOW + 172800);
    member
        .call("development_voucher_link", valid["seed"].clone())
        .await
        .unwrap();
    member
        .call("voucher_redeem", valid["redeem"].clone())
        .await
        .unwrap();
    assert!(
        member
            .call("voucher_redeem", valid["redeem"].clone())
            .await
            .is_err()
    );

    for now in [NOW, NOW + 1] {
        service.clock.set(now);
        let issued = issue(&mut member, &passport, &expected, enrolled.signing_key, now).await;
        assert_eq!(issued.lobby.state, "admitted");
        let bytes = issued.credential.unwrap();
        let signed = ring.verify(&bytes, csgn::Kind::Credential, now).unwrap();
        let claims: cmty::cplc::Credential = serde_json::from_slice(signed.payload()).unwrap();
        assert_eq!(claims.community, "alpha");
        assert_eq!(claims.member, lobby.member_id);
        assert_eq!(claims.devices, vec![enrolled.signing_key]);
        assert_eq!(claims.pins.len(), 1);
    }
    let mut enrolled = enrolled;
    let begin = member
        .call(
            "step_up_begin",
            json!({"action": {"kind":"passkey_revoke","credential":enrolled.credential}}),
        )
        .await
        .unwrap();
    let challenge: ckyh::RequestChallengeResponse =
        serde_json::from_value(begin["options"].clone()).unwrap();
    let credential = enrolled
        .authenticator
        .perform_auth(
            ckyh::Url::parse(&origin_for("api.alpha.example.test")).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    let body = json!({
        "credential": enrolled.credential,
        "step_up": {"ceremony": begin["ceremony"], "credential": credential},
    });
    member.call("passkey_revoke", body).await.unwrap();
    assert!(matches!(
        member.call("lobby", json!({})).await,
        Err(Error::Unauthorized)
    ));
    let refreshed: TrustFeed = serde_json::from_value(
        foyer(&service, host, None)
            .call("trust_feed", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(refreshed.policy_epoch > feed.policy_epoch);
}
