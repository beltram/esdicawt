pub mod error;
pub mod params;
mod redaction;

use crate::{
    issuer::{error::SdCwtIssuerError, params::IssuerParams, redaction::redact},
    now,
};
use ciborium::Value;
use esdicawt_spec::{
    COSE_SD_CLAIMS, CWT_CLAIM_AUDIENCE, CWT_CLAIM_CNONCE, CWT_CLAIM_CTI, CWT_CLAIM_EXPIRES_AT, CWT_CLAIM_ISSUED_AT, CWT_CLAIM_ISSUER, CWT_CLAIM_KEY_CONFIRMATION,
    CWT_CLAIM_NOT_BEFORE, CWT_CLAIM_SD_ALG, CWT_CLAIM_SUBJECT, CWT_MEDIATYPE, CustomClaims, CwtAny, MEDIATYPE_SD_CWT, SdHashAlg, Select,
    issuance::SdCwtIssuedTagged,
    reexports::coset::{
        TaggedCborSerializable, {self},
    },
};
use signature::{Keypair, Signer};

pub trait Issuer {
    type Error: core::error::Error + Send + Sync;
    type Hasher: digest::Digest + Clone;

    type Signature;

    type ProtectedClaims: CustomClaims;
    type UnprotectedClaims: CustomClaims;
    type PayloadClaims: Select;

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

    fn hash_algorithm(&self) -> SdHashAlg;

    fn serialize_signature(&self, signature: &Self::Signature) -> Result<Vec<u8>, Self::Error>;

    fn deserialize_signature(&self, bytes: &[u8]) -> Result<Self::Signature, Self::Error>;

    #[allow(clippy::type_complexity)]
    fn issue_cwt(
        &self,
        csprng: &mut dyn rand_core::CryptoRngCore,
        params: IssuerParams<'_, Self::PayloadClaims, Self::ProtectedClaims, Self::UnprotectedClaims>,
    ) -> Result<SdCwtIssuedTagged<Self::PayloadClaims, Self::Hasher, Self::ProtectedClaims, Self::UnprotectedClaims>, SdCwtIssuerError<Self::Error>> {
        let alg = self.cwt_algorithm();

        let mut protected_builder = coset::HeaderBuilder::new()
            .algorithm(alg)
            .value(CWT_MEDIATYPE, Value::Text(MEDIATYPE_SD_CWT.to_string()))
            .value(CWT_CLAIM_SD_ALG, Value::Integer((self.hash_algorithm() as i64).into()))
            .key_id(params.key_location.as_bytes().into());

        if let Some(protected_claims) = params.protected_claims {
            let protected_extra_claims = Value::serialized(&protected_claims)?.into_map()?;
            for (k, v) in protected_extra_claims {
                protected_builder = match k {
                    Value::Integer(i) => protected_builder.value(i.try_into()?, v),
                    Value::Text(label) => protected_builder.text_value(label, v),
                    _ => protected_builder,
                };
            }
        }

        let protected = protected_builder.build();

        let mut payload_claims = params.payload.map(|c| c.select()).transpose()?;

        let mut unprotected_builder = coset::HeaderBuilder::new();

        let payload = if let Some(sd) = payload_claims.as_mut() {
            let sd_claims = redact::<Self::Error, Self::Hasher>(csprng, sd)?;

            unprotected_builder = unprotected_builder.value(COSE_SD_CLAIMS, Value::serialized(&sd_claims)?);

            if let Some(unprotected_claims) = params.unprotected_claims {
                let unprotected_extra_claims = Value::serialized(&unprotected_claims)?.into_map()?;
                for (k, v) in unprotected_extra_claims {
                    unprotected_builder = match k {
                        Value::Integer(i) => unprotected_builder.value(i.try_into()?, v),
                        Value::Text(label) => unprotected_builder.text_value(label, v),
                        _ => unprotected_builder,
                    };
                }
            }

            let payload = sd.as_map_mut().ok_or(SdCwtIssuerError::InputError)?;

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

            if params.expiry.is_some() || params.with_issued_at || params.with_not_before {
                #[cfg(feature = "test-vectors")]
                let now = params.now.map(|d| d.as_secs()).unwrap_or_else(now);
                #[cfg(not(feature = "test-vectors"))]
                let now = now();
                if let Some(expiry) = params.expiry {
                    let expiry = now + expiry.as_secs();
                    payload.push((Value::Integer(CWT_CLAIM_EXPIRES_AT.into()), expiry.into()));
                }
                if params.with_not_before {
                    let nbf = now - params.leeway.as_secs();
                    payload.push((Value::Integer(CWT_CLAIM_NOT_BEFORE.into()), nbf.into()));
                }
                if params.with_issued_at {
                    let iat = now;
                    payload.push((Value::Integer(CWT_CLAIM_ISSUED_AT.into()), iat.into()));
                }
            }

            payload.push((Value::Integer(CWT_CLAIM_KEY_CONFIRMATION.into()), Value::serialized(&params.holder_confirmation_key)?));

            Value::Map(payload.clone())
        } else {
            Value::Bytes(vec![])
        };

        let unprotected = unprotected_builder.build();

        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload.to_cbor_bytes()?)
            .try_create_signature(&[], |tbs| {
                let signature = self.signer().try_sign(tbs)?;
                self.serialize_signature(&signature).map_err(SdCwtIssuerError::CustomError)
            })?
            .build()
            .to_tagged_vec()?;

        Ok(SdCwtIssuedTagged::from_cbor_bytes(&sign1).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::{claims::CustomTokenClaims, test_utils::Ed25519IssuerClaims};
    use crate::{
        Issuer, IssuerParams,
        spec::{
            blinded_claims::{Salted, SaltedClaim, SaltedElement},
            sd,
        },
    };
    use ciborium::value::Error;
    use ciborium::{Value, cbor};
    use digest::Digest as _;
    use esdicawt_spec::{ClaimName, CwtAny, NoClaims, Select, SelectExt, issuance::SdCwtIssuedTagged};
    use rand_core::SeedableRng;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_generate_sd_cwt() {
        let payload = CustomTokenClaims { name: Some("Alice Smith".into()) };
        let mut sd_cwt = issue(payload);

        let cwt_cbor = sd_cwt.to_cbor_bytes().unwrap();
        let sd_cwt_2 = SdCwtIssuedTagged::<CustomTokenClaims, sha2::Sha256>::from_cbor_bytes(&cwt_cbor).unwrap();
        assert_eq!(sd_cwt.to_cbor_bytes().unwrap(), sd_cwt_2.to_cbor_bytes().unwrap());

        // should have 'redacted_claim_keys' in the payload
        let mut payload = sd_cwt.0.payload.clone();
        let payload = payload.to_value().unwrap();
        let rck = payload.redacted_claim_keys.as_ref().unwrap();
        assert_eq!(rck.len(), 1);
        let rck_name = rck.first().unwrap();

        let payload = sd_cwt.0.disclosures_mut().iter().map(|d| d.unwrap()).collect::<Vec<_>>();
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
    fn should_issue_complex_types() {
        let verify_issuance = |value: Value, expected: (Option<ClaimName>, Result<Value, ciborium::value::Error>)| {
            let payload = cbor!({ "___claim" => value }).unwrap().select_all().unwrap();
            let mut sd_cwt = issue(payload);

            let disclosable_claims = sd_cwt.0.disclosures_mut().iter().map(|d| d.unwrap()).collect::<Vec<_>>();

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
                            let numbers = numbers.iter().filter_map(|n| n.as_integer()).map(|i| u64::try_from(i).unwrap()).collect::<Vec<_>>();
                            model.numbers.extend(numbers);
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
                Ok(Value::Map(map))
            }
        }

        let model = Model {
            name: Some("Alice Smith".to_string()),
            age: Some(42),
            numbers: vec![0, 1, 2],
        };
        let mut sd_cwt = issue(model);

        let mut payload = sd_cwt.0.payload.clone();
        let payload = payload.to_value().unwrap().clone();
        let model = payload.inner.extra.unwrap();

        // name has been redacted but not age
        assert_eq!(model.age, Some(42));
        assert!(model.name.is_none());
        assert_eq!(model.numbers, vec![0, 2]);

        let disclosures = sd_cwt.0.disclosures_mut().iter().map(|d| d.unwrap()).collect::<Vec<_>>();
        assert_eq!(disclosures.len(), 2);

        let d0 = disclosures.first().unwrap();
        let Salted::Claim(SaltedClaim { name, value, .. }) = d0 else { unreachable!() };

        // verify content of disclosure
        assert_eq!(name, &ClaimName::Text("name".into()));
        assert_eq!(value, &cbor!("Alice Smith").unwrap());

        let d1 = disclosures.get(1).unwrap();
        let Salted::Element(SaltedElement { value, .. }) = d1 else { unreachable!() };
        assert_eq!(value, &cbor!(1).unwrap());
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
            fn select(self) -> Result<Value, Error> {
                self.select_none()
            }
        }

        let model = ModelPublic {
            name: Some("Alice".to_string()),
            age: Some(42),
        };
        let mut sd_cwt = issue(model);

        let mut payload = sd_cwt.0.payload.clone();
        let payload = payload.to_value().unwrap().clone();
        let model = payload.inner.extra.unwrap();

        // nothing redacted
        assert!(model.age.is_some());
        assert!(model.name.is_some());

        let mut disclosures = sd_cwt.0.disclosures_mut().iter().map(|d| d.unwrap());
        assert!(disclosures.next().is_none());
    }

    fn issue<T: Select>(payload: T) -> SdCwtIssuedTagged<T, sha2::Sha256> {
        let mut csprng = rand_chacha::ChaCha20Rng::from_entropy();

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let issuer = Ed25519IssuerClaims::new(issuer_signing_key);

        issuer
            .issue_cwt(
                &mut csprng,
                IssuerParams {
                    protected_claims: None,
                    unprotected_claims: None,
                    payload: Some(payload),
                    issuer: "mimi://example.com/i/acme.io",
                    subject: Some("mimi://example.com/alice.smith"),
                    audience: Default::default(),
                    cti: Default::default(),
                    cnonce: Default::default(),
                    expiry: Some(core::time::Duration::from_secs(90)),
                    with_not_before: true,
                    with_issued_at: true,
                    leeway: core::time::Duration::from_secs(1),
                    key_location: "https://auth.acme.io/issuer.cwk",
                    holder_confirmation_key: (&holder_signing_key.verifying_key()).try_into().unwrap(),
                    now: None,
                },
            )
            .unwrap()
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

    pub struct Ed25519IssuerClaims<T: Select> {
        signing_key: ed25519_dalek::SigningKey,
        _marker: core::marker::PhantomData<T>,
    }

    impl<T: Select> Issuer for Ed25519IssuerClaims<T> {
        type Error = EsdicawtSpecError;
        type Signer = ed25519_dalek::SigningKey;
        type Hasher = sha2::Sha256;
        type Signature = ed25519_dalek::Signature;

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
            coset::iana::Algorithm::EdDSA
        }

        fn hash_algorithm(&self) -> SdHashAlg {
            SdHashAlg::Sha256
        }

        fn serialize_signature(&self, signature: &ed25519_dalek::Signature) -> Result<Vec<u8>, Self::Error> {
            Ok(ed25519_dalek::Signature::to_bytes(signature).into())
        }

        fn deserialize_signature(&self, bytes: &[u8]) -> Result<ed25519_dalek::Signature, Self::Error> {
            Ok(ed25519_dalek::Signature::try_from(bytes).unwrap())
        }
    }

    pub struct P256IssuerClaims<T: Select> {
        signing_key: p256::ecdsa::SigningKey,
        _marker: core::marker::PhantomData<T>,
    }

    impl<T: Select> Issuer for P256IssuerClaims<T> {
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

        fn serialize_signature(&self, signature: &p256::ecdsa::Signature) -> Result<Vec<u8>, Self::Error> {
            Ok(signature.to_bytes().to_vec())
        }

        fn deserialize_signature(&self, bytes: &[u8]) -> Result<p256::ecdsa::Signature, Self::Error> {
            Ok(p256::ecdsa::Signature::from_slice(bytes).unwrap())
        }
    }
}
