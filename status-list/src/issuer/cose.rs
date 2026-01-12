use crate::{
    CborAny, Status, StatusList, StatusListResult,
    issuer::{StatusListIssuerParams, StatusListToken, elapsed_since_epoch},
};
use ciborium::Value;
use coset::{CborSerializable, TaggedCborSerializable, iana::CwtClaimName};
use signature::{Keypair, SignatureEncoding, Signer};

pub mod codec;
pub mod model;

pub const LABEL_TYPE: i64 = 16;
pub const MEDIATYPE_STATUS_LIST_CWT: &str = "application/statuslist+cwt";

pub trait StatusListIssuer {
    type StatusListIssuerError: core::error::Error + Send + Sync;
    type StatusListIssuerHasher: digest::Digest + Clone;
    type StatusListIssuerSignature: SignatureEncoding;

    type StatusListIssuerSigner: Signer<Self::StatusListIssuerSignature> + Keypair;

    fn status_list_token_signer(&self) -> &Self::StatusListIssuerSigner;

    fn status_list_token_cwt_algorithm(&self) -> coset::iana::Algorithm;

    fn issue_raw_status_list_token<S: Status>(&self, status_list: &StatusList<S>, mut params: StatusListIssuerParams) -> StatusListResult<Vec<u8>> {
        let protected = coset::HeaderBuilder::new()
            .algorithm(self.status_list_token_cwt_algorithm())
            .value(LABEL_TYPE, Value::Text(MEDIATYPE_STATUS_LIST_CWT.to_string()))
            .build();

        let mut unprotected_builder = coset::HeaderBuilder::new();
        if let Some(kid) = params.key_id.take() {
            unprotected_builder = unprotected_builder.key_id(kid);
        }
        let unprotected = unprotected_builder.build();

        let mut payload = coset::cwt::ClaimsSetBuilder::new()
            // Required. As generally defined in [RFC7519].
            // The sub (subject) claim MUST specify the URI of the Status List Token.
            // The value MUST be equal to that of the uri claim contained in the status_list claim of the Referenced Token.
            .subject(params.uri.to_string());

        let now = params.artificial_time.unwrap_or_else(elapsed_since_epoch);
        if let Some(expiry) = params.expiry {
            payload = payload
                // RECOMMENDED. As generally defined in [RFC7519].
                // The exp (expiration time) claim, if present, MUST specify the time at which the Status List Token is considered expired by the Status Issuer
                .expiration_time(coset::cwt::Timestamp::WholeSeconds(expiry.to_absolute(now).as_secs() as i64));
        }
        payload = payload
            // Required. As generally defined in [RFC7519]. The iat (issued at) claim MUST specify the time at which the Status List Token was issued.
            .issued_at(coset::cwt::Timestamp::WholeSeconds(now.as_secs() as i64));
        if let Some(ttl) = params.ttl {
            // RECOMMENDED. The ttl (time to live) claim, if present, MUST specify the maximum amount of time, in seconds, that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved.
            // The value of the claim MUST be a positive number
            payload = payload.claim(CwtClaimName::Ttl, ttl.as_secs().into());
        }
        // REQUIRED. The status_list (status list) claim MUST specify the Status List conforming to the structure defined in Section 4.2.
        payload = payload.claim(CwtClaimName::StatusList, Value::serialized(&status_list)?);

        let payload = payload.build().to_vec()?;

        Ok(coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload)
            .try_create_signature(&[], |tbs| {
                let signature = self.status_list_token_signer().try_sign(tbs)?;
                Result::<_, signature::Error>::Ok(signature.to_bytes().as_ref().to_vec())
            })?
            .build()
            .to_tagged_vec()?)
    }

    fn issue_status_list_token<S: Status>(&self, status_list: &StatusList<S>, params: StatusListIssuerParams) -> StatusListResult<StatusListToken<S>> {
        let status_list_token = self.issue_raw_status_list_token(status_list, params)?;
        StatusListToken::from_cbor_bytes(&status_list_token)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{Lst, RawStatus, issuer::params::TimeArg};
    use core::time::Duration;
    use coset::AsCborValue;
    use p256::elliptic_curve::JwkEcKey;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_pass_rfc_example() {
        let expected = "d2845820a2012610781a6170706c69636174696f6e2f7374617475736c6973742b637774a1044231325850a502782168747470733a2f2f6578616d706c652e636f6d2f7374617475736c697374732f31061a648c5bea041a8898dfea19fffe19a8c019fffda2646269747301636c73744a78dadbb918000217015d584030e39052d23cc3cdeca77c915d5e8763353565fa772c47f5176f77b5e406b11430b3dce2ae21c07f4491fc12acdd7ec82875099d28f035d9b1893e2825e63488";
        let signer = rfc_signer();
        let issuer = P256StatusListIssuer { signer };

        let params = StatusListIssuerParams {
            uri: "https://example.com/statuslists/1".parse().unwrap(),
            artificial_time: Some(Duration::from_secs(1686920170)),
            expiry: Some(TimeArg::Absolute(Duration::from_secs(2291720170))),
            ttl: Some(Duration::from_secs(43200)),
            key_id: Some(b"12".to_vec()),
        };
        let status_list = StatusList::<RawStatus<1>> {
            lst: Lst::from_slice(b"abcd"),
            aggregation_uri: None,
        };

        let status_list_token = issuer.issue_raw_status_list_token(&status_list, params).unwrap();
        let actual_token = coset::CoseSign1::from_tagged_slice(&status_list_token).unwrap();
        let _status_list_token_cbor = hex::encode(status_list_token);

        let expected_token = hex::decode(expected.as_bytes()).unwrap();
        let expected_token = coset::CoseSign1::from_tagged_slice(&expected_token).unwrap();

        assert_eq!(expected_token.protected.to_cbor_value().unwrap(), actual_token.protected.to_cbor_value().unwrap());
        assert_eq!(expected_token.unprotected.to_cbor_value().unwrap(), actual_token.unprotected.to_cbor_value().unwrap());
        // assert_eq!(expected_token.payload.to_cbor_value().unwrap(), actual_token.payload.to_cbor_value().unwrap());

        // println!(">>> expected: {:?}", hex::encode(&expected_token.payload.unwrap()));
        // println!(">>> actual  : {:?}", hex::encode(&actual_token.payload.unwrap()));

        // assert_eq!(&status_list_token_cbor, expected);
    }

    pub fn rfc_signer() -> p256::ecdsa::SigningKey {
        let jwk = serde_json::json!({
            "kty": "EC",
            "d": "xzUEdsyLosZF0acZGRAjTKImb0lQvAvssDK5XIZELd0",
            "crv": "P-256",
            "x": "I3HWm_0Ds1dPMI-IWmf4mBmH-YaeAVbPVu7vB27CxXo",
            "y": "6N_d5Elj9bs1htgV3okJKIdbHEpkgTmAluYKJemzn1M",
        });
        let jwk = serde_json::from_value::<JwkEcKey>(jwk).unwrap();
        let sk: p256::SecretKey = jwk.to_secret_key::<p256::NistP256>().unwrap();
        p256::ecdsa::SigningKey::from(sk)
    }

    struct P256StatusListIssuer {
        signer: p256::ecdsa::SigningKey,
    }

    impl StatusListIssuer for P256StatusListIssuer {
        type StatusListIssuerError = core::convert::Infallible;
        type StatusListIssuerHasher = sha2::Sha256;
        type StatusListIssuerSignature = p256::ecdsa::Signature;
        type StatusListIssuerSigner = p256::ecdsa::SigningKey;

        fn status_list_token_signer(&self) -> &Self::StatusListIssuerSigner {
            &self.signer
        }

        fn status_list_token_cwt_algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::ES256
        }
    }
}
