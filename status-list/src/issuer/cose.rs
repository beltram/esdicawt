use crate::{
    CborAny, StatusList, StatusListResult,
    issuer::{StatusListIssuerParams, cose::model::StatusListTokenTagged, elapsed_since_epoch},
};
use ciborium::Value;
use coset::iana::CwtClaimName;
use coset::{CborSerializable, TaggedCborSerializable};
use signature::{Keypair, SignatureEncoding, Signer};

pub mod codec;
pub mod model;

pub const LABEL_TYPE: i64 = 16;
pub const MEDIATYPE_STATUS_LIST_CWT: &str = "application/statuslist+cwt";

pub trait StatusListIssuer {
    type Error: core::error::Error + Send + Sync;
    type Hasher: digest::Digest + Clone;
    type Signature: SignatureEncoding;

    #[cfg(not(any(feature = "pem", feature = "der")))]
    type Signer: Signer<Self::Signature> + Keypair;

    #[cfg(any(feature = "pem", feature = "der"))]
    type Signer: Signer<Self::Signature> + Keypair + pkcs8::DecodePrivateKey;

    fn new(signing_key: Self::Signer) -> Self
    where
        Self: Sized;

    #[cfg(feature = "pem")]
    fn try_from_pem(pem: &str) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::Error: From<pkcs8::Error>,
    {
        use pkcs8::DecodePrivateKey as _;
        let signer = Self::Signer::from_pkcs8_pem(pem)?;
        Ok(Self::new(signer))
    }

    #[cfg(feature = "der")]
    fn try_from_der(der: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::Error: From<pkcs8::Error>,
    {
        use pkcs8::DecodePrivateKey as _;
        let signer = Self::Signer::from_pkcs8_der(der)?;
        Ok(Self::new(signer))
    }

    fn signer(&self) -> &Self::Signer;

    fn cwt_algorithm(&self) -> coset::iana::Algorithm;

    fn issue_raw_status_list_token(&self, status_list: StatusList, params: StatusListIssuerParams) -> StatusListResult<Vec<u8>> {
        let protected = coset::HeaderBuilder::new()
            .algorithm(self.cwt_algorithm())
            .value(LABEL_TYPE, Value::Text(MEDIATYPE_STATUS_LIST_CWT.to_string()))
            .build();

        let unprotected = coset::HeaderBuilder::new().key_id(b"12".to_vec()).build();

        let mut payload = coset::cwt::ClaimsSetBuilder::new().subject(params.uri.to_string());

        let now = params.artificial_time.unwrap_or_else(elapsed_since_epoch);
        if let Some(expiry) = params.expiry {
            payload = payload.expiration_time(coset::cwt::Timestamp::WholeSeconds(expiry.to_absolute(now).as_secs() as i64));
        }
        payload = payload.issued_at(coset::cwt::Timestamp::WholeSeconds(now.as_secs() as i64));
        if let Some(ttl) = params.ttl {
            payload = payload.claim(CwtClaimName::Ttl, ttl.as_secs().into());
        }
        payload = payload.claim(CwtClaimName::StatusList, Value::serialized(&status_list)?);

        let payload = payload.build().to_vec()?;

        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload)
            .try_create_signature(&[], |tbs| {
                let signature = self.signer().try_sign(tbs)?;
                Result::<_, signature::Error>::Ok(signature.to_bytes().as_ref().to_vec())
            })?
            .build()
            .to_tagged_vec()?;
        Ok(sign1)
    }

    fn issue_status_list_token(&self, status_list: StatusList, params: StatusListIssuerParams) -> StatusListResult<StatusListTokenTagged> {
        StatusListTokenTagged::from_cbor_bytes(&self.issue_raw_status_list_token(status_list, params)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Lst, StatusBits, issuer::params::TimeArg};
    use core::time::Duration;
    use coset::AsCborValue;
    use p256::elliptic_curve::JwkEcKey;

    #[test]
    fn should_pass_rfc_example() {
        let expected = "d2845820a2012610781a6170706c69636174696f6e2f7374617475736c6973742b637774a1044231325850a502782168747470733a2f2f6578616d706c652e636f6d2f7374617475736c697374732f31061a648c5bea041a8898dfea19fffe19a8c019fffda2646269747301636c73744a78dadbb918000217015d584030e39052d23cc3cdeca77c915d5e8763353565fa772c47f5176f77b5e406b11430b3dce2ae21c07f4491fc12acdd7ec82875099d28f035d9b1893e2825e63488";
        let signer = rfc_signer();
        let issuer = P256StatusListIssuer::new(signer);

        let params = StatusListIssuerParams {
            uri: "https://example.com/statuslists/1".parse().unwrap(),
            artificial_time: Some(Duration::from_secs(1686920170)),
            expiry: Some(TimeArg::Absolute(Duration::from_secs(2291720170))),
            ttl: Some(Duration::from_secs(43200)),
        };
        let status_list = StatusList {
            bits: StatusBits::One,
            lst: Lst::from_slice(b"abcd", StatusBits::One),
            aggregation_uri: None,
        };

        let status_list_token = issuer.issue_raw_status_list_token(status_list, params).unwrap();
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

    #[test]
    fn toto() {
        let expected = "d2845820a2012610781a6170706c69636174696f6e2f7374617475736c6973742b637774a1044231325850a502782168747470733a2f2f6578616d706c652e636f6d2f7374617475736c697374732f31061a648c5bea041a8898dfea19fffe19a8c019fffda2646269747301636c73744a78dadbb918000217015d584030e39052d23cc3cdeca77c915d5e8763353565fa772c47f5176f77b5e406b11430b3dce2ae21c07f4491fc12acdd7ec82875099d28f035d9b1893e2825e63488";
        let expected = hex::decode(expected.as_bytes()).unwrap();
        let value = coset::CoseSign1::from_tagged_slice(&expected).unwrap();
        // let value = Value::from_cbor_bytes(&expected).unwrap();
        // println!("{:?}", value);
        println!("{:?}", value.protected);
    }

    fn rfc_signer() -> p256::ecdsa::SigningKey {
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
        type Error = core::convert::Infallible;
        type Hasher = sha2::Sha256;
        type Signature = p256::ecdsa::Signature;
        type Signer = p256::ecdsa::SigningKey;

        fn new(signer: Self::Signer) -> Self
        where
            Self: Sized,
        {
            Self { signer }
        }

        fn signer(&self) -> &Self::Signer {
            &self.signer
        }

        fn cwt_algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::ES256
        }
    }
}
