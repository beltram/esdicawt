pub mod error;
mod redaction;

use crate::{
    issuer::{error::SdCwtIssuerError, redaction::redact},
    now,
};
use ciborium::Value;
use cose_key_confirmation::KeyConfirmation;
use esdicawt_spec::issuance::SdCwtPayloadBuilder;
use esdicawt_spec::{
    AnyMap, COSE_SD_CLAIMS, CWT_CLAIM_SD_ALG, CWT_MEDIATYPE, ClaimName, CustomClaims, CwtAny, EsdicawtSpecError, MEDIATYPE_SD_CWT, SelectiveDisclosureHashAlg,
    issuance::{SelectiveDisclosureIssuedTagged, SelectiveDisclosurePayloadBuilder},
    reexports::{
        coset::TaggedCborSerializable,
        coset::{self},
    },
};
use signature::{Keypair, Signer};

pub trait Issuer {
    type Error: std::error::Error + Send + Sync;
    type Hasher: digest::Digest;

    type Signature;

    type ProtectedClaims: CustomClaims;
    type UnprotectedClaims: CustomClaims;
    type PayloadClaims: CustomClaims;
    type DisclosableClaims: CustomClaims;

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
    fn hash_algorithm(&self) -> SelectiveDisclosureHashAlg;

    fn serialize_signature(&self, signature: &Self::Signature) -> Result<Vec<u8>, Self::Error>;

    fn deserialize_signature(&self, bytes: &[u8]) -> Result<Self::Signature, Self::Error>;

    #[allow(clippy::type_complexity)]
    fn issue_cwt(
        &self,
        csprng: &mut dyn rand_core::CryptoRngCore,
        params: IssueCwtParams<'_, Self::ProtectedClaims, Self::UnprotectedClaims, Self::PayloadClaims, Self::DisclosableClaims>,
    ) -> Result<SelectiveDisclosureIssuedTagged<Self::ProtectedClaims, Self::UnprotectedClaims, Self::PayloadClaims, Self::DisclosableClaims>, SdCwtIssuerError<Self::Error>> {
        let alg = self.cwt_algorithm();
        let issuer = params.identifier;
        let key_location = params.key_location;

        let mut protected_builder = coset::HeaderBuilder::new()
            .algorithm(alg)
            .value(CWT_MEDIATYPE, Value::Text(MEDIATYPE_SD_CWT.to_string()))
            .value(CWT_CLAIM_SD_ALG, Value::Integer((self.hash_algorithm() as i64).into()))
            .key_id(key_location.as_bytes().into());

        if let Some(protected_claims) = params.protected_claims {
            let protected_extra_claims: AnyMap = protected_claims.into();
            for (k, v) in protected_extra_claims {
                protected_builder = match k {
                    ClaimName::Integer(identifier) => protected_builder.value(identifier, v),
                    ClaimName::Text(named_claim) => protected_builder.text_value(named_claim, v),
                    _ => protected_builder,
                };
            }
        }

        let protected = protected_builder.build();

        let mut disclosable_claims = Value::serialized(&params.disclosable_claims)?;
        let sd_claims = redact::<Self::Error, Self::Hasher>(csprng, &mut disclosable_claims)?;

        let mut unprotected_builder = coset::HeaderBuilder::new().value(COSE_SD_CLAIMS, sd_claims.to_cbor_bytes()?.into());

        if let Some(unprotected_claims) = params.unprotected_claims {
            let unprotected_extra_claims: AnyMap = unprotected_claims.into();
            for (k, v) in unprotected_extra_claims {
                unprotected_builder = match k {
                    ClaimName::Integer(identifier) => unprotected_builder.value(identifier, v),
                    ClaimName::Text(named_claim) => unprotected_builder.text_value(named_claim, v),
                    _ => unprotected_builder,
                };
            }
        }

        let unprotected = unprotected_builder.build();

        let now = now();
        let nbf = now - params.leeway.as_secs();
        let iat = now;
        let expiry = now + params.expiry.as_secs();

        let mut inner_payload_builder = SdCwtPayloadBuilder::default();
        inner_payload_builder
            .issuer(issuer)
            .subject(params.subject)
            .expiration(expiry as i64)
            .not_before(nbf as i64)
            .issued_at(iat as i64);

        if let Some(payload_claims) = params.payload_claims {
            inner_payload_builder.claims(payload_claims);
        }

        let inner = inner_payload_builder.build().map_err(EsdicawtSpecError::from)?;

        let payload = SelectiveDisclosurePayloadBuilder::default()
            .inner(inner)
            .key_confirmation(params.holder_confirmation_key)
            .build()
            .map_err(EsdicawtSpecError::from)?;
        let mut payload = Value::serialized(&payload).map_err(EsdicawtSpecError::from)?;

        // merging redacted claims with the rest of the payload
        if !sd_claims.is_empty() {
            // if there is any disclosure
            let payload = payload.as_map_mut().ok_or_else(|| ciborium::value::Error::Custom("CWT payload must be a Mapping".into()))?;

            let disclosable_claims = disclosable_claims
                .into_map()
                .map_err(|_| ciborium::value::Error::Custom("CWT payload must be a Mapping".into()))?;

            for (k, v) in disclosable_claims {
                // disclosable claims supersede regular ones
                let existing = payload.iter_mut().find(|(pk, _)| pk == &k);
                match existing {
                    Some((_, pv)) => *pv = v,
                    None => payload.push((k, v)),
                }
            }
        }

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

        Ok(SelectiveDisclosureIssuedTagged::from_cbor_bytes(&sign1)?)
    }
}

pub struct IssueCwtParams<'a, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims, DisclosableClaims: CustomClaims> {
    /// Extra claims in the protected header of the sd-cwt
    pub protected_claims: Option<ProtectedClaims>,
    /// Extra claims in the unprotected header of the sd-cwt
    pub unprotected_claims: Option<UnprotectedClaims>,
    /// Extra claims in the payload of the sd-cwt
    pub payload_claims: Option<PayloadClaims>,
    /// Claims to redact
    pub disclosable_claims: DisclosableClaims,
    pub subject: &'a str,
    /// Used to be inserted in the Issuer claim
    pub identifier: &'a str,
    pub expiry: core::time::Duration,
    /// Dealing with clocks skew
    pub leeway: core::time::Duration,
    pub key_location: &'a str,
    pub holder_confirmation_key: KeyConfirmation,
}

#[cfg(test)]
pub mod tests {
    use super::{claims::CustomTokenClaims, test_utils::Ed25519IssuerClaims};
    use crate::{
        Issuer,
        spec::{blinded_claims::SaltedClaim, blinded_claims::SaltedElement},
    };
    use ciborium::{Value, cbor};
    use digest::Digest as _;
    use esdicawt_spec::{AnyMap, ClaimName, CustomClaims, CwtAny, MapKey, NoClaims, blinded_claims::Salted, issuance::SelectiveDisclosureIssuedTagged};
    use rand_core::SeedableRng;

    #[test]
    fn should_generate_sd_cwt() {
        let disclosable_claims = CustomTokenClaims { name: "Alice Smith".into() };
        let mut cwt = issue(disclosable_claims);

        let cwt_cbor = cwt.to_cbor_bytes().unwrap();
        let cwt_2 = SelectiveDisclosureIssuedTagged::from_cbor_bytes(&cwt_cbor).unwrap();
        assert_eq!(cwt, cwt_2);

        // should have 'redacted_claim_keys' in the payload
        let mut payload = cwt.0.payload.clone();
        let payload = payload.to_value().unwrap();
        let rck = payload.redacted_claim_keys.as_ref().unwrap();
        assert_eq!(rck.len(), 1);
        let rck_name = rck.first().unwrap();

        let disclosable_claims = cwt.0.disclosures().unwrap().iter().map(|d| d.unwrap()).collect::<Vec<_>>();
        assert_eq!(disclosable_claims.len(), 1);
        let d0 = disclosable_claims.first().unwrap();
        let Salted::Claim(SaltedClaim { name, value, .. }) = d0 else { unreachable!() };

        // verify content of disclosure
        assert_eq!(name, &ClaimName::Text("name".into()));
        assert_eq!(value, &cbor!("Alice Smith").unwrap());

        // verify digest of disclosure in 'redacted_key_claims'
        let digest = sha2::Sha256::digest(d0.to_cbor_bytes().unwrap()).to_vec();
        assert_eq!(digest, rck_name.to_vec());
    }

    #[test]
    fn should_issue_complex_types() {
        let verify_issuance = |value: Result<Value, ciborium::value::Error>, expected: (Option<ClaimName>, Result<Value, ciborium::value::Error>)| {
            let value = value.unwrap();
            let mut disclosable_claims = AnyMap::new();
            disclosable_claims.insert(MapKey::Text("___claim".into()), value);
            let mut sd_cwt = issue(disclosable_claims);

            let disclosable_claims = sd_cwt.0.disclosures().unwrap().iter().map(|d| d.unwrap()).collect::<Vec<_>>();

            let (expected_name, expected_value) = expected;
            let expected_value = expected_value.unwrap();
            let found = disclosable_claims.iter().any(|d| match d {
                Salted::Claim(SaltedClaim { name, value, .. }) => value == &expected_value && Some(name) == expected_name.as_ref(),
                Salted::Element(SaltedElement { value, .. }) => value == &expected_value,
                Salted::Decoy(_) => false,
            });
            assert!(found);
        };

        // simple string
        verify_issuance(cbor!("a"), (Some(ClaimName::Text("___claim".into())), cbor!("a")));

        // simple mapping
        verify_issuance(cbor!({ "a" => "b" }), (Some(ClaimName::Text("a".into())), cbor!("b")));

        // simple array
        verify_issuance(cbor!([0]), (None, cbor!(0)));

        // nested mapping
        verify_issuance(cbor!({ "a" => "b" }), (Some(ClaimName::Text("a".into())), cbor!("b")));

        // nested array
        verify_issuance(cbor!([[0]]), (None, cbor!(0)));

        // mapping in array
        verify_issuance(cbor!([{ "a" => "b" }]), (Some(ClaimName::Text("a".into())), cbor!("b")));

        // array in mapping
        verify_issuance(cbor!({ "a" => [0] }), (None, cbor!(0)));
    }

    fn issue<D: CustomClaims>(disclosable_claims: D) -> SelectiveDisclosureIssuedTagged<NoClaims, NoClaims, NoClaims, D> {
        let mut csprng = rand_chacha::ChaCha20Rng::from_entropy();

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let issuer = Ed25519IssuerClaims::new(issuer_signing_key);

        issuer
            .issue_cwt(
                &mut csprng,
                crate::IssueCwtParams {
                    protected_claims: None,
                    unprotected_claims: None,
                    payload_claims: None,
                    disclosable_claims,
                    subject: "mimi://example.com/alice.smith",
                    identifier: "mimi://example.com/i/acme.io",
                    expiry: core::time::Duration::from_secs(90),
                    leeway: core::time::Duration::from_secs(1),
                    key_location: "https://auth.acme.io/issuer.cwk",
                    holder_confirmation_key: (&holder_signing_key.verifying_key()).try_into().unwrap(),
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
                    PayloadClaims = NoClaims,
                    Signer = ed25519_dalek::SigningKey,
                    Hasher = sha2::Sha256,
                    DisclosableClaims = CustomTokenClaims,
                    Error = std::convert::Infallible,
                >,
        >,
    ) {
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod claims {
    use esdicawt_spec::{AnyMap, ClaimName};

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct CustomTokenClaims {
        pub name: String,
    }

    impl From<CustomTokenClaims> for AnyMap {
        fn from(val: CustomTokenClaims) -> Self {
            Self::from([(ClaimName::Text("name".into()), val.name.into())])
        }
    }

    impl TryFrom<AnyMap> for CustomTokenClaims {
        type Error = std::convert::Infallible;
        fn try_from(mut value: AnyMap) -> Result<Self, Self::Error> {
            let name = value
                .remove(&ClaimName::Text("name".into()))
                .map(|name| name.into_text().unwrap())
                .unwrap_or_else(|| "UNKNOWN".to_string());
            Ok(Self { name })
        }
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use super::*;
    use esdicawt_spec::NoClaims;

    pub struct Ed25519IssuerClaims<Disclosable: CustomClaims> {
        signing_key: ed25519_dalek::SigningKey,
        _marker: core::marker::PhantomData<Disclosable>,
    }

    impl<Disclosable: CustomClaims> Issuer for Ed25519IssuerClaims<Disclosable> {
        type Error = std::convert::Infallible;
        type Signer = ed25519_dalek::SigningKey;
        type Hasher = sha2::Sha256;
        type Signature = ed25519_dalek::Signature;

        type ProtectedClaims = NoClaims;
        type UnprotectedClaims = NoClaims;
        type PayloadClaims = NoClaims;
        type DisclosableClaims = Disclosable;

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

        fn hash_algorithm(&self) -> SelectiveDisclosureHashAlg {
            SelectiveDisclosureHashAlg::Sha256
        }

        fn serialize_signature(&self, signature: &ed25519_dalek::Signature) -> Result<Vec<u8>, Self::Error> {
            Ok(ed25519_dalek::Signature::to_bytes(signature).into())
        }

        fn deserialize_signature(&self, bytes: &[u8]) -> Result<ed25519_dalek::Signature, Self::Error> {
            Ok(ed25519_dalek::Signature::try_from(bytes).unwrap())
        }
    }

    pub struct P256IssuerClaims<Disclosable: CustomClaims> {
        signing_key: p256::ecdsa::SigningKey,
        _marker: core::marker::PhantomData<Disclosable>,
    }

    impl<Disclosable: CustomClaims> Issuer for P256IssuerClaims<Disclosable> {
        type Error = std::convert::Infallible;
        type Signer = p256::ecdsa::SigningKey;
        type Hasher = sha2::Sha256;
        type Signature = p256::ecdsa::Signature;

        type ProtectedClaims = NoClaims;
        type UnprotectedClaims = NoClaims;
        type PayloadClaims = NoClaims;
        type DisclosableClaims = Disclosable;

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

        fn hash_algorithm(&self) -> SelectiveDisclosureHashAlg {
            SelectiveDisclosureHashAlg::Sha256
        }

        fn serialize_signature(&self, signature: &p256::ecdsa::Signature) -> Result<Vec<u8>, Self::Error> {
            Ok(signature.to_bytes().to_vec())
        }

        fn deserialize_signature(&self, bytes: &[u8]) -> Result<p256::ecdsa::Signature, Self::Error> {
            Ok(p256::ecdsa::Signature::from_slice(bytes).unwrap())
        }
    }
}
