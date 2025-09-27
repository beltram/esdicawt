pub mod error;
pub mod params;
mod redaction;

use crate::issuer::{error::SdCwtIssuerError, params::IssuerParams, redaction::redact};
use ciborium::Value;
use esdicawt_spec::{
    COSE_SD_CLAIMS, CWT_CLAIM_AUDIENCE, CWT_CLAIM_CNONCE, CWT_CLAIM_CTI, CWT_CLAIM_EXPIRES_AT, CWT_CLAIM_ISSUED_AT, CWT_CLAIM_ISSUER, CWT_CLAIM_KEY_CONFIRMATION,
    CWT_CLAIM_NOT_BEFORE, CWT_CLAIM_SD_ALG, CWT_CLAIM_SUBJECT, CWT_MEDIATYPE, CustomClaims, CwtAny, MEDIATYPE_SD_CWT, SdHashAlg, Select,
    issuance::SdCwtIssuedTagged,
    reexports::coset::{
        TaggedCborSerializable, {self},
    },
};
use signature::{Keypair, SignatureEncoding, Signer};

pub trait Issuer {
    type Error: core::error::Error + Send + Sync;
    type Hasher: digest::Digest + Clone;

    type Signature: signature::SignatureEncoding;

    type ProtectedClaims: CustomClaims;
    type UnprotectedClaims: CustomClaims;
    type PayloadClaims: Select;

    #[cfg(not(feature = "pem"))]
    type Signer: Signer<Self::Signature> + Keypair;

    #[cfg(feature = "pem")]
    type Signer: Signer<<Self as Issuer>::Signature> + Keypair + pkcs8::DecodePrivateKey;

    fn new(signing_key: <Self as Issuer>::Signer) -> Self
    where
        Self: Sized;

    #[cfg(feature = "pem")]
    fn try_from_pem(pem: &str) -> Result<Self, <Self as Issuer>::Error>
    where
        Self: Sized,
        <Self as Issuer>::Error: From<pkcs8::Error>,
    {
        use pkcs8::DecodePrivateKey as _;
        let signer = <Self as Issuer>::Signer::from_pkcs8_pem(pem)?;
        Ok(<Self as Issuer>::new(signer))
    }

    #[cfg(feature = "pem")]
    fn try_from_der(der: &[u8]) -> Result<Self, <Self as Issuer>::Error>
    where
        Self: Sized,
        <Self as Issuer>::Error: From<pkcs8::Error>,
    {
        use pkcs8::DecodePrivateKey as _;
        let signer = <Self as Issuer>::Signer::from_pkcs8_der(der)?;
        Ok(<Self as Issuer>::new(signer))
    }

    fn signer(&self) -> &<Self as Issuer>::Signer;

    fn cwt_algorithm(&self) -> coset::iana::Algorithm;

    fn hash_algorithm(&self) -> SdHashAlg;

    #[allow(clippy::type_complexity)]
    fn issue_cwt(
        &self,
        csprng: &mut dyn rand_core::CryptoRngCore,
        params: IssuerParams<'_, Self::PayloadClaims, Self::ProtectedClaims, Self::UnprotectedClaims>,
    ) -> Result<SdCwtIssuedTagged<Self::PayloadClaims, <Self as Issuer>::Hasher, Self::ProtectedClaims, Self::UnprotectedClaims>, SdCwtIssuerError<<Self as Issuer>::Error>> {
        let alg = Issuer::cwt_algorithm(self);

        let mut protected_builder = coset::HeaderBuilder::new()
            .algorithm(alg)
            .value(CWT_MEDIATYPE, Value::Text(MEDIATYPE_SD_CWT.to_string()))
            .value(CWT_CLAIM_SD_ALG, Value::Integer((self.hash_algorithm() as i64).into()))
            .key_id(params.key_location.as_bytes().into());

        if let Some(protected_claims) = params.protected_claims {
            let protected_extra_claims = protected_claims.to_cbor_value()?.into_map()?;
            for (k, v) in protected_extra_claims {
                protected_builder = match k {
                    Value::Integer(i) => protected_builder.value(i.try_into()?, v),
                    Value::Text(label) => protected_builder.text_value(label, v),
                    _ => protected_builder,
                };
            }
        }

        let protected = protected_builder.build();

        let mut to_be_redacted_payload = params.payload.map(Self::PayloadClaims::select).transpose()?;

        let mut unprotected_builder = coset::HeaderBuilder::new();

        if let Some(salted_array) = to_be_redacted_payload
            .as_mut()
            .map(|tbr| redact::<<Self as Issuer>::Error, <Self as Issuer>::Hasher>(csprng, tbr))
            .transpose()?
        {
            unprotected_builder = unprotected_builder.value(COSE_SD_CLAIMS, salted_array.to_cbor_value()?);
        }

        if let Some(unprotected_claims) = params.unprotected_claims {
            let unprotected_extra_claims = unprotected_claims.to_cbor_value()?.into_map()?;
            for (k, v) in unprotected_extra_claims {
                unprotected_builder = match k {
                    Value::Integer(i) => unprotected_builder.value(i.try_into()?, v),
                    Value::Text(label) => unprotected_builder.text_value(label, v),
                    _ => unprotected_builder,
                };
            }
        }

        let mut payload = Vec::with_capacity(1);

        payload.push((Value::Integer(CWT_CLAIM_ISSUER.into()), params.issuer.into()));
        if let Some(sub) = params.subject {
            payload.push((Value::Integer(CWT_CLAIM_SUBJECT.into()), sub.into()));
        }
        if let Some(aud) = params.audience {
            payload.push((Value::Integer(CWT_CLAIM_AUDIENCE.into()), aud.into()));
        }
        if let Some(cti) = params.cti {
            payload.push((Value::Integer(CWT_CLAIM_CTI.into()), cti.into()));
        }
        if let Some(cnonce) = params.cnonce {
            payload.push((Value::Integer(CWT_CLAIM_CNONCE.into()), cnonce.into()));
        }

        #[cfg(feature = "status")]
        {
            use crate::coset::iana::EnumI64 as _;
            let status = status_list::StatusClaim::new(params.status.status_list_bit_index, params.status.uri);
            payload.push((Value::Integer(crate::coset::iana::CwtClaimName::Status.to_i64().into()), status.to_cbor_value()?));
        }

        if params.expiry.is_some() || params.with_issued_at || params.with_not_before {
            #[cfg(feature = "test-vectors")]
            let now = params.artificial_time.unwrap_or_else(crate::elapsed_since_epoch);
            #[cfg(not(feature = "test-vectors"))]
            let now = crate::elapsed_since_epoch();

            if let Some(expiry) = params.expiry {
                let expiry = expiry.to_absolute(now);
                payload.push((Value::Integer(CWT_CLAIM_EXPIRES_AT.into()), expiry.as_secs().into()));
            }
            if params.with_not_before {
                let nbf = now - params.leeway;
                payload.push((Value::Integer(CWT_CLAIM_NOT_BEFORE.into()), nbf.as_secs().into()));
            }
            if params.with_issued_at {
                let iat = now;
                payload.push((Value::Integer(CWT_CLAIM_ISSUED_AT.into()), iat.as_secs().into()));
            }
        }

        payload.push((Value::Integer(CWT_CLAIM_KEY_CONFIRMATION.into()), params.holder_confirmation_key.to_cbor_value()?));

        if let Some(payload_claims) = to_be_redacted_payload.map(Value::into_map).transpose()? {
            for (k, v) in payload_claims {
                payload.push((k, v));
            }
        }

        let payload = Value::Map(payload);

        let unprotected = unprotected_builder.build();

        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload.to_cbor_bytes()?)
            .try_create_signature(&[], |tbs| {
                let signature = Issuer::signer(self).try_sign(tbs)?;
                Result::<_, signature::Error>::Ok(signature.to_bytes().as_ref().to_vec())
            })?
            .build()
            .to_tagged_vec()?;

        Ok(SdCwtIssuedTagged::from_cbor_bytes(&sign1)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{claims::CustomTokenClaims, test_utils::Ed25519Issuer};
    use crate::{
        CwtStdLabel, Issuer, IssuerParams, StatusParams, TimeArg, elapsed_since_epoch,
        spec::{
            ClaimName, CwtAny, NoClaims, Select, SelectExt,
            blinded_claims::{Salted, SaltedClaim, SaltedElement},
            issuance::SdCwtIssuedTagged,
            redacted_claims::RedactedClaimKeys,
            reexports::coset::{CoseSign1, TaggedCborSerializable},
            sd,
        },
    };
    use ciborium::{Value, cbor};
    use digest::Digest as _;
    use std::collections::HashMap;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_generate_sd_cwt() {
        let payload = CustomTokenClaims { name: Some("Alice Smith".into()) };
        let (mut sd_cwt, _) = issue(Some(payload));

        let sd_cwt_bytes = sd_cwt.to_cbor_bytes().unwrap();
        let sd_cwt_2 = SdCwtIssuedTagged::<CustomTokenClaims, sha2::Sha256>::from_cbor_bytes(&sd_cwt_bytes).unwrap();
        assert_eq!(sd_cwt.to_cbor_bytes().unwrap(), sd_cwt_2.to_cbor_bytes().unwrap());

        // is a valid CWT
        CoseSign1::from_tagged_slice(&sd_cwt_bytes).unwrap();

        // should have 'redacted_claim_keys' in the payload
        let mut payload = sd_cwt.0.payload.clone();
        let payload = payload.to_value().unwrap();
        let rck = payload.redacted_claim_keys.as_ref().unwrap();
        assert_eq!(rck.len(), 1);
        let rck_name = rck.first().unwrap();

        let payload = sd_cwt.0.disclosures_mut().unwrap().iter().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(payload.len(), 1);
        let d0 = payload.first().unwrap();
        let Salted::Claim(SaltedClaim { name, value, .. }) = d0 else { unreachable!() };

        // verify content of disclosure
        assert_eq!(name, &ClaimName::Text("name".into()));
        assert_eq!(value, &cbor!("Alice Smith").unwrap());

        // verify digest of disclosure in 'redacted_key_claims'
        let digest = sha2::Sha256::digest(d0.to_cbor_bytes().unwrap()).to_vec();
        assert_eq!(digest, rck_name.to_vec());
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_generate_valid_sd_cwt() {
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer = Ed25519Issuer::new(issuer_signing_key);

        let exp = core::time::Duration::from_secs(90);
        let params = IssuerParams {
            protected_claims: None,
            unprotected_claims: None,
            payload: None::<Value>,
            issuer: "https://example.com/i/acme.io",
            subject: Some("https://example.com/alice.smith"),
            audience: Some("https://example.com/r/party"),
            cti: Some(b"cti"),
            cnonce: Some(b"cnonce"),
            expiry: Some(TimeArg::Relative(exp)),
            with_not_before: true,
            with_issued_at: true,
            leeway: core::time::Duration::from_secs(1),
            key_location: "https://auth.acme.io/issuer.cwk",
            holder_confirmation_key: (&holder_signing_key.verifying_key()).try_into().unwrap(),
            artificial_time: None,
            status: StatusParams {
                status_list_bit_index: 0,
                uri: "https://example.com/statuslists/1".parse().unwrap(),
            },
        };

        let sd_cwt_bytes = issuer.issue_cwt(&mut rand::thread_rng(), params).unwrap().to_cbor_bytes().unwrap();
        let raw_sd_cwt = CoseSign1::from_tagged_slice(&sd_cwt_bytes).unwrap();
        let payload = Value::from_cbor_bytes(&raw_sd_cwt.payload.unwrap()).unwrap().into_map().unwrap();

        let now = elapsed_since_epoch().as_secs();
        for entry in payload {
            match entry {
                (Value::Integer(label), Value::Text(issuer)) if label == CwtStdLabel::Issuer => assert_eq!(&issuer, "https://example.com/i/acme.io"),
                (Value::Integer(label), Value::Text(sub)) if label == CwtStdLabel::Subject => assert_eq!(&sub, "https://example.com/alice.smith"),
                (Value::Integer(label), Value::Text(aud)) if label == CwtStdLabel::Audience => assert_eq!(&aud, "https://example.com/r/party"),
                (Value::Integer(label), Value::Integer(actual_exp)) if label == CwtStdLabel::ExpiresAt => {
                    let actual = u64::try_from(actual_exp).unwrap();
                    let expected = now + exp.as_secs();
                    assert!((expected - 1..expected + 1).contains(&actual));
                }
                (Value::Integer(label), Value::Integer(actual_iat)) if label == CwtStdLabel::IssuedAt => {
                    let actual = u64::try_from(actual_iat).unwrap();
                    assert!((now - 1..=now + 1).contains(&actual));
                }
                (Value::Integer(label), Value::Integer(actual_nbf)) if label == CwtStdLabel::NotBefore => {
                    let actual = u64::try_from(actual_nbf).unwrap();
                    assert!((now - 1..=now + 1).contains(&actual));
                }
                (Value::Integer(label), Value::Bytes(cti)) if label == CwtStdLabel::Cti => assert_eq!(cti, b"cti"),
                (Value::Integer(label), Value::Bytes(cnonce)) if label == CwtStdLabel::Cnonce => assert_eq!(cnonce, b"cnonce"),
                (Value::Integer(label), Value::Map(_)) if label == CwtStdLabel::KeyConfirmation => {}
                (Value::Integer(label), Value::Map(_)) if label == CwtStdLabel::Status => {}
                (Value::Simple(label), Value::Bytes(_)) if label == RedactedClaimKeys::CWT_LABEL => {}
                e => panic!("unexpected: {e:?}"),
            }
        }
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_issue_complex_types() {
        let verify_issuance = |value: Value, expected: (Option<ClaimName>, Result<Value, ciborium::value::Error>)| {
            let payload = cbor!({ "___claim" => value }).unwrap().select_all().unwrap();
            let (mut sd_cwt, _) = issue(Some(payload));

            let disclosable_claims = sd_cwt.0.disclosures_mut().unwrap().iter().collect::<Result<Vec<_>, _>>().unwrap();

            let (expected_name, expected_value) = expected;
            let expected_value = expected_value.unwrap();
            let found = disclosable_claims.iter().any(|d| match d {
                Salted::Claim(SaltedClaim { name, value, .. }) => value == &expected_value && Some(name) == expected_name.as_ref(),
                Salted::Element(SaltedElement { value, .. }) => value == &expected_value,
                _ => false,
            });
            assert!(found);
        };

        // simple string
        verify_issuance(cbor!("a").unwrap(), (Some(ClaimName::Text("___claim".into())), cbor!("a")));

        // simple mapping
        verify_issuance(cbor!({ "a" => "b" }).unwrap(), (Some(ClaimName::Text("a".into())), cbor!("b")));

        // simple array
        verify_issuance(cbor!([0]).unwrap(), (None, cbor!(0)));

        // nested mapping
        verify_issuance(cbor!({ "a" => "b" }).unwrap(), (Some(ClaimName::Text("a".into())), cbor!("b")));

        // nested array
        verify_issuance(cbor!([[0]]).unwrap(), (None, cbor!(0)));

        // mapping in array
        verify_issuance(cbor!([{ "a" => "b" }]).unwrap(), (Some(ClaimName::Text("a".into())), cbor!("b")));

        // array in mapping
        verify_issuance(cbor!({ "a" => [0] }).unwrap(), (None, cbor!(0)));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_selectively_disclose() {
        #[derive(Default, Debug, Clone, PartialEq, serde::Serialize)]
        pub struct Model {
            pub name: Option<String>,
            pub age: Option<u64>,
            pub numbers: Vec<u64>,
            pub inner: HashMap<String, String>,
        }

        impl<'de> serde::Deserialize<'de> for Model {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = <Value as serde::Deserialize>::deserialize(deserializer).unwrap();

                let mut model = Self::default();
                for (k, v) in value.into_map().unwrap() {
                    match (k, v) {
                        (Value::Text(label), Value::Text(name)) if &label == "name" => {
                            model.name.replace(name);
                        }
                        (Value::Text(label), Value::Integer(age)) if &label == "age" => {
                            model.age.replace(age.try_into().unwrap());
                        }
                        (Value::Text(label), Value::Array(numbers)) if &label == "numbers" => {
                            // filter out tags
                            let numbers = numbers.iter().filter_map(Value::as_integer).map(u64::try_from).collect::<Result<Vec<_>, _>>().unwrap();
                            model.numbers.extend(numbers);
                        }
                        (Value::Text(label), Value::Map(inner)) if &label == "inner" => {
                            model.inner = inner
                                .into_iter()
                                .filter(|(k, _)| !k.is_simple())
                                .map(|(k, v)| (k.into_text().unwrap(), v.into_text().unwrap()))
                                .collect();
                        }
                        _ => unreachable!(),
                    }
                }
                Ok(model)
            }
        }

        impl Select for Model {
            fn select(self) -> Result<Value, ciborium::value::Error> {
                let mut map = Vec::with_capacity(2);
                if let Some(name) = self.name {
                    map.push((sd!("name"), Value::Text(name)));
                }
                if let Some(age) = self.age {
                    map.push((Value::Text("age".into()), age.into()));
                }
                let numbers = self
                    .numbers
                    .iter()
                    .enumerate()
                    .map(|(i, &n)| match i {
                        1 => sd!(n),
                        _ => Value::Integer(n.into()),
                    })
                    .collect();
                map.push((Value::Text("numbers".into()), Value::Array(numbers)));

                let inner = self.inner.clone().into_iter().map(|(k, v)| (sd!(Value::from(k)), v.into())).collect();
                map.push((Value::Text("inner".into()), Value::Map(inner)));

                Ok(Value::Map(map))
            }
        }

        let model = Model {
            name: Some("Alice Smith".to_string()),
            age: Some(42),
            numbers: vec![0, 1, 2],
            inner: HashMap::from_iter([("a".into(), "b".into())]),
        };
        let (mut sd_cwt, _) = issue(Some(model));

        let mut payload = sd_cwt.0.payload.clone();
        let payload = payload.to_value().unwrap().clone();
        let model = payload.inner.extra.unwrap();

        // name has been redacted but not age
        assert_eq!(model.age, Some(42));
        assert!(model.name.is_none());
        assert_eq!(model.numbers, vec![0, 2]);
        assert!(model.inner.is_empty());

        let disclosures = sd_cwt.0.disclosures_mut().unwrap().iter().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(disclosures.len(), 3);

        let [d0, d1, d2] = disclosures.try_into().unwrap();
        let Salted::Claim(SaltedClaim { name, value, .. }) = &d0 else { unreachable!() };
        // verify content of disclosure
        assert_eq!(*name, ClaimName::Text("name".into()));
        assert_eq!(value, &cbor!("Alice Smith").unwrap());

        let Salted::Element(SaltedElement { value, .. }) = d1 else { unreachable!() };
        assert_eq!(value, &cbor!(1).unwrap());

        let Salted::Claim(SaltedClaim { name, value, .. }) = &d2 else { unreachable!() };
        assert_eq!(*name, ClaimName::Text("a".into()));
        assert_eq!(value, &cbor!("b").unwrap());
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_work_when_no_disclosure() {
        #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
        pub struct ModelPublic {
            pub name: Option<String>,
            pub age: Option<u32>,
        }

        impl Select for ModelPublic {
            fn select(self) -> Result<Value, ciborium::value::Error> {
                self.select_none()
            }
        }

        let model = ModelPublic {
            name: Some("Alice".to_string()),
            age: Some(42),
        };
        let (mut sd_cwt, _) = issue(Some(model));

        let mut payload = sd_cwt.0.payload.clone();
        let payload = payload.to_value().unwrap().clone();
        let model = payload.inner.extra.unwrap();

        // nothing redacted
        assert!(model.age.is_some());
        assert!(model.name.is_some());

        let mut disclosures = sd_cwt.0.disclosures_mut().unwrap().iter().map(|d| d.unwrap());
        assert!(disclosures.next().is_none());
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_support_empty_payload() {
        issue(None::<Value>);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_read_cnf() {
        let payload = CustomTokenClaims { name: Some("Alice Smith".into()) };
        let (mut sd_cwt, holder_sk) = issue(Some(payload));
        let cnf = sd_cwt.0.cnf::<ed25519_dalek::VerifyingKey>().unwrap();
        assert_eq!(cnf, holder_sk.verifying_key());
    }

    fn issue<T: Select>(payload: Option<T>) -> (SdCwtIssuedTagged<T, sha2::Sha256>, ed25519_dalek::SigningKey) {
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer = Ed25519Issuer::new(issuer_signing_key);

        let sd_cwt = issuer
            .issue_cwt(
                &mut rand::thread_rng(),
                IssuerParams {
                    protected_claims: None,
                    unprotected_claims: None,
                    payload,
                    issuer: "https://example.com/i/acme.io",
                    subject: Some("https://example.com/alice.smith"),
                    audience: Default::default(),
                    cti: Default::default(),
                    cnonce: Default::default(),
                    expiry: None,
                    with_not_before: true,
                    with_issued_at: true,
                    leeway: core::time::Duration::from_secs(1),
                    key_location: "https://auth.acme.io/issuer.cwk",
                    holder_confirmation_key: (&holder_signing_key.verifying_key()).try_into().unwrap(),
                    artificial_time: None,
                    status: StatusParams {
                        status_list_bit_index: 0,
                        uri: "https://example.com/statuslists/1".parse().unwrap(),
                    },
                },
            )
            .unwrap();
        (sd_cwt, holder_signing_key)
    }

    #[allow(dead_code, unused_variables)]
    fn should_be_object_safe(
        issuer: Box<
            dyn Issuer<
                    Signature = ed25519_dalek::Signature,
                    ProtectedClaims = NoClaims,
                    UnprotectedClaims = NoClaims,
                    PayloadClaims = CustomTokenClaims,
                    Signer = ed25519_dalek::SigningKey,
                    Hasher = sha2::Sha256,
                    Error = std::convert::Infallible,
                >,
        >,
    ) {
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod claims {
    use ciborium::Value;
    use esdicawt_spec::{Select, sd};

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub(super) struct CustomTokenClaims {
        pub name: Option<String>,
    }

    impl Select for CustomTokenClaims {
        fn select(self) -> Result<Value, ciborium::value::Error> {
            let mut map = Vec::with_capacity(1);
            if let Some(name) = self.name {
                map.push((sd!("name"), Value::Text(name)));
            }
            Ok(Value::Map(map))
        }
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use super::*;
    use esdicawt_spec::{EsdicawtSpecError, NoClaims, Select};
    use status_list::issuer::StatusListIssuer;

    pub struct Ed25519Issuer<T: Select> {
        pub signer: ed25519_dalek::SigningKey,
        pub _marker: core::marker::PhantomData<T>,
    }

    impl<T: Select> Issuer for Ed25519Issuer<T> {
        type Error = EsdicawtSpecError;
        type Signer = ed25519_dalek::SigningKey;
        type Hasher = sha2::Sha256;
        type Signature = ed25519_dalek::Signature;

        type ProtectedClaims = NoClaims;
        type UnprotectedClaims = NoClaims;
        type PayloadClaims = T;

        fn new(signing_key: Self::Signer) -> Self {
            Self {
                signer: signing_key,
                _marker: Default::default(),
            }
        }

        fn signer(&self) -> &Self::Signer {
            &self.signer
        }

        fn cwt_algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::EdDSA
        }

        fn hash_algorithm(&self) -> SdHashAlg {
            SdHashAlg::Sha256
        }
    }

    impl<T: Select> StatusListIssuer for Ed25519Issuer<T> {
        type StatusListIssuerError = EsdicawtSpecError;
        type StatusListIssuerSigner = ed25519_dalek::SigningKey;
        type StatusListIssuerHasher = sha2::Sha256;
        type StatusListIssuerSignature = ed25519_dalek::Signature;

        fn status_list_token_signer(&self) -> &Self::StatusListIssuerSigner {
            &self.signer
        }

        fn status_list_token_cwt_algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::EdDSA
        }
    }

    pub struct P256Issuer<T: Select> {
        signing_key: p256::ecdsa::SigningKey,
        _marker: core::marker::PhantomData<T>,
    }

    impl<T: Select> Issuer for P256Issuer<T> {
        type Error = EsdicawtSpecError;
        type Signer = p256::ecdsa::SigningKey;
        type Hasher = sha2::Sha256;
        type Signature = p256::ecdsa::Signature;

        type ProtectedClaims = NoClaims;
        type UnprotectedClaims = NoClaims;
        type PayloadClaims = T;

        fn new(signing_key: Self::Signer) -> Self {
            Self {
                signing_key,
                _marker: Default::default(),
            }
        }

        fn signer(&self) -> &Self::Signer {
            &self.signing_key
        }

        fn cwt_algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::ES256
        }

        fn hash_algorithm(&self) -> SdHashAlg {
            SdHashAlg::Sha256
        }
    }
}
