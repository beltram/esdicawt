#![allow(clippy::borrow_interior_mutable_const, clippy::declare_interior_mutable_const, dead_code)]

#[path = "crypto.rs"]
mod crypto;
#[path = "model.rs"]
mod model;

use crypto::rng::*;
use model::*;

use ciborium::{Value, value::Integer};
use cose_key::keyset::CoseKeySet;
use esdicawt::{
    Holder, HolderParams, Issuer, IssuerParams, StatusParams, TimeArg,
    spec::{
        CwtAny, EsdicawtSpecError, NoClaims, SdHashAlg, Select,
        reexports::{coset, coset::iana::Algorithm},
    },
};
use pkcs8::DecodePrivateKey;

pub struct P384Issuer<T: Select> {
    signing_key: p384::ecdsa::SigningKey,
    _marker: core::marker::PhantomData<T>,
}

impl<T: Select> Issuer for P384Issuer<T> {
    type Error = EsdicawtSpecError;
    type Signer = p384::ecdsa::SigningKey;
    type Hasher = sha2::Sha256;
    type Signature = p384::ecdsa::Signature;

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
        Algorithm::ES384
    }

    fn hash_algorithm(&self) -> SdHashAlg {
        SdHashAlg::Sha256
    }
}

pub struct P256Holder<T: Select> {
    signing_key: p256::ecdsa::SigningKey,
    verifying_key: p256::ecdsa::VerifyingKey,
    _marker: core::marker::PhantomData<T>,
}

impl<T: Select> Holder for P256Holder<T> {
    type Error = EsdicawtSpecError;
    type Hasher = sha2::Sha256;
    type Signer = p256::ecdsa::SigningKey;

    type Signature = p256::ecdsa::Signature;
    type Verifier = p256::ecdsa::VerifyingKey;

    type IssuerPayloadClaims = T;
    type IssuerProtectedClaims = NoClaims;
    type IssuerUnprotectedClaims = NoClaims;
    type KbtProtectedClaims = NoClaims;
    type KbtUnprotectedClaims = NoClaims;
    type KbtPayloadClaims = NoClaims;

    fn cwt_algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }

    fn new(signing_key: Self::Signer) -> Self {
        Self {
            verifying_key: *signing_key.as_ref(),
            signing_key,
            _marker: Default::default(),
        }
    }

    fn signer(&self) -> &Self::Signer {
        &self.signing_key
    }

    fn verifier(&self) -> &Self::Verifier {
        &self.verifying_key
    }
}

#[test]
fn normal_test_vectors() {
    let payload = Payload {
        most_recent_inspection_passed: true,
        inspector_license_number: Some("ABCD-123456".into()),
        inspection_dates: vec![1549560720, 1612560720, 1674004740],
        inspection_location: InspectionLocation {
            country: "us".into(),
            region: "ca".into(),
            postal_code: "94188".into(),
        },
    };

    let spec_sd_cwt_bytes = include_bytes!("../../draft-ietf-spice-sd-cwt/examples/issuer_cwt.cbor");
    let spec_sd_kbt_bytes = include_bytes!("../../draft-ietf-spice-sd-cwt/examples/kbt.cbor");

    test_vectors::<Payload>(payload, spec_sd_cwt_bytes, spec_sd_kbt_bytes, false)
}

#[test]
fn nested_test_vectors() {
    let payload1 = PayloadLog {
        most_recent_inspection_passed: true,
        inspector_license_number: Some("DCBA-101777".into()),
        inspection_date: 1549560720,
        inspection_location: InspectionLocation {
            country: "us".into(),
            region: "co".into(),
            postal_code: "80302".into(),
        },
    };
    let payload2 = PayloadLog {
        most_recent_inspection_passed: true,
        inspector_license_number: Some("EFGH-789012".into()),
        inspection_date: 1612560720,
        inspection_location: InspectionLocation {
            country: "us".into(),
            region: "nv".into(),
            postal_code: "89155".into(),
        },
    };
    let payload3 = PayloadLog {
        most_recent_inspection_passed: true,
        inspector_license_number: Some("ABCD-123456".into()),
        inspection_date: 1674004740,
        inspection_location: InspectionLocation {
            country: "us".into(),
            region: "ca".into(),
            postal_code: "94188".into(),
        },
    };

    let spec_sd_cwt_bytes = include_bytes!("../../draft-ietf-spice-sd-cwt/examples/nested_issuer_cwt.cbor");
    let spec_sd_kbt_bytes = include_bytes!("../../draft-ietf-spice-sd-cwt/examples/nested_kbt.cbor");

    test_vectors::<NestedPayload>(
        NestedPayload {
            nested: vec![payload1, payload2, payload3],
        },
        spec_sd_cwt_bytes,
        spec_sd_kbt_bytes,
        true,
    )
}

fn test_vectors<P: Select>(payload: P, spec_sd_cwt_bytes: &[u8], spec_sd_kbt_bytes: &[u8], nested: bool) {
    // === Issuer ===
    let sd_issuer = P384Issuer::<P>::new(issuer_signing_key());

    const NOW: u64 = 1725244200;
    const LEEWAY: u64 = 300;
    const EXPIRY: u64 = 3600 * 24;
    let params = IssuerParams {
        protected_claims: None::<NoClaims>,
        unprotected_claims: None::<NoClaims>,
        payload: Some(payload),
        issuer: "https://issuer.example",
        subject: Some("https://holder.example"),
        audience: Default::default(),
        cti: Default::default(),
        cnonce: Default::default(),
        expiry: Some(TimeArg::Relative(core::time::Duration::from_secs(EXPIRY))),
        with_not_before: true,
        with_issued_at: true,
        leeway: core::time::Duration::from_secs(LEEWAY),
        artificial_time: Some(core::time::Duration::from_secs(NOW)),
        key_location: "https://issuer.example/cose-key3",
        holder_confirmation_key: holder_signing_key().verifying_key().try_into().unwrap(),
        status: StatusParams {
            status_list_bit_index: 0,
            uri: "https://example.com/statuslists/1".parse().unwrap(),
        },
    };

    let spec_sd_cwt = Value::from_cbor_bytes(spec_sd_cwt_bytes).unwrap();
    let mut spec_sd_cwt = spec_sd_cwt.into_tag().unwrap().1.into_array().unwrap();
    let _spec_protected = spec_sd_cwt.remove(0);
    let spec_unprotected = spec_sd_cwt.remove(0);
    let spec_payload = spec_sd_cwt.remove(0);
    let spec_payload = spec_payload.as_bytes().unwrap();
    let spec_payload = Value::from_cbor_bytes(spec_payload).unwrap().into_map().unwrap();

    let salt_ranges = if nested { NESTED_SALT_RANGES } else { NORMAL_SALT_RANGES };
    let esdicawt_sd_cwt = sd_issuer.issue_cwt(&mut TestVectorRng::new(salt_ranges), params).unwrap();
    let esdicawt_sd_cwt_bytes = esdicawt_sd_cwt.to_cbor_bytes().unwrap();
    let esdicawt_sd_cwt = Value::from_cbor_bytes(&esdicawt_sd_cwt_bytes).unwrap();
    let mut esdicawt_sd_cwt = esdicawt_sd_cwt.into_tag().unwrap().1.into_array().unwrap();
    let _esdicawt_protected = esdicawt_sd_cwt.remove(0);
    let esdicawt_unprotected = esdicawt_sd_cwt.remove(0);
    let esdicawt_payload = esdicawt_sd_cwt.remove(0);
    let esdicawt_payload = esdicawt_payload.as_bytes().unwrap();
    let esdicawt_payload = Value::from_cbor_bytes(esdicawt_payload).unwrap().into_map().unwrap();

    // protected
    // FIXME: pending test vectors use CoAP content formats
    // assert_eq!(spec_protected, esdicawt_protected);

    // unprotected
    assert_eq!(spec_unprotected.as_map().unwrap().len(), 1);
    assert_eq!(esdicawt_unprotected.as_map().unwrap().len(), 1);

    let (_, spec_sd_claims) = spec_unprotected.as_map().unwrap().first().unwrap();
    let (_, esdicawt_sd_claims) = esdicawt_unprotected.as_map().unwrap().first().unwrap();
    let spec_sd_claims = spec_sd_claims.as_array().unwrap();
    let esdicawt_sd_claims = esdicawt_sd_claims.as_array().unwrap();

    assert!(spec_sd_claims.iter().all(|v| v.is_bytes()));
    assert!(esdicawt_sd_claims.iter().all(|v| v.is_bytes()));

    assert_eq!(spec_sd_claims.len(), esdicawt_sd_claims.len());

    // every disclosure should have been generated with the same salt as in the spec
    let salt = |disclosure: &Value| Value::from_cbor_bytes(disclosure.as_bytes().unwrap()).unwrap().into_array().unwrap().remove(0);
    for (i, (spec, esdicawt)) in spec_sd_claims.iter().zip(esdicawt_sd_claims).enumerate() {
        assert_eq!(salt(spec), salt(esdicawt), "salt mismatch for disclosure {i}");
    }

    let claim = |map: &Vec<(Value, Value)>, i: i64| {
        let found = map.iter().find_map(|(k, v)| matches!(k, Value::Integer(int) if *int == Integer::from(i)).then_some(v));
        found.cloned()
    };
    let assert_claim = |i: i64| {
        assert_eq!(
            claim(&spec_payload, i).unwrap_or_else(|| panic!("{i} not found")),
            claim(&esdicawt_payload, i).unwrap_or_else(|| panic!("{i} not found"))
        );
    };

    assert_claim(1); // issuer
    assert_claim(2); // sub
    assert_claim(4); // exp
    assert_claim(5); // nbf
    assert_claim(6); // iat
    if !nested {
        assert_claim(500); // most_recent_inspection_passed
    }
    // assert_claim(502); // inspection_dates
    // assert_claim(503); // inspection_location

    // cnf
    let spec_cnf = claim(&spec_payload, 8).unwrap().into_map().unwrap();
    let (_, spec_cnf) = spec_cnf.first().unwrap().clone();
    let mut spec_cnf = spec_cnf.into_map().unwrap();
    let esdicawt_cnf = claim(&esdicawt_payload, 8).unwrap().into_map().unwrap();
    let (_, esdicawt_cnf) = esdicawt_cnf.first().unwrap().clone();
    let mut esdicawt_cnf = esdicawt_cnf.into_map().unwrap();

    // all labels are integers
    spec_cnf.sort_by_key(|(k, _)| i64::try_from(k.as_integer().unwrap()).unwrap());
    esdicawt_cnf.sort_by_key(|(k, _)| i64::try_from(k.as_integer().unwrap()).unwrap());

    assert_eq!(spec_cnf, esdicawt_cnf);

    // === Holder ===
    let spec_sd_kbt = Value::from_cbor_bytes(spec_sd_kbt_bytes).unwrap();
    let mut spec_sd_kbt = spec_sd_kbt.into_tag().unwrap().1.into_array().unwrap();
    let spec_protected = spec_sd_kbt.remove(0);
    let spec_protected = spec_protected.as_bytes().unwrap();
    let spec_protected = Value::from_cbor_bytes(spec_protected).unwrap().into_map().unwrap();
    let spec_unprotected = spec_sd_kbt.remove(0);
    let spec_payload = spec_sd_kbt.remove(0);
    let spec_payload = spec_payload.as_bytes().unwrap();
    let spec_payload = Value::from_cbor_bytes(spec_payload).unwrap().into_map().unwrap();

    let sd_holder = P256Holder::<P>::new(holder_signing_key());

    let params = HolderParams {
        presentation: Default::default(),
        audience: "https://verifier.example/app",
        cnonce: Some(&hex::decode("8c0f5f523b95bea44a9a48c649240803").unwrap()),
        expiry: None,
        with_not_before: false,
        artificial_time: Some(core::time::Duration::from_secs(NOW + 37)),
        time_verification: Default::default(),
        leeway: Default::default(),
        extra_kbt_protected: None,
        extra_kbt_unprotected: None,
        extra_kbt_payload: None,
    };
    let sd_cwt = sd_holder.verify_sd_cwt(&esdicawt_sd_cwt_bytes[..], Default::default(), &issuer_verifying_key()).unwrap();

    let esdicawt_sd_kbt = sd_holder.new_presentation(sd_cwt, params).unwrap();
    let esdicawt_sd_kbt_bytes = esdicawt_sd_kbt.to_cbor_bytes().unwrap();
    let esdicawt_sd_kbt = Value::from_cbor_bytes(&esdicawt_sd_kbt_bytes[..]).unwrap();
    let mut esdicawt_sd_kbt = esdicawt_sd_kbt.into_tag().unwrap().1.into_array().unwrap();
    let esdicawt_protected = esdicawt_sd_kbt.remove(0);
    let esdicawt_protected = esdicawt_protected.as_bytes().unwrap();
    let esdicawt_protected = Value::from_cbor_bytes(esdicawt_protected).unwrap().into_map().unwrap();
    let esdicawt_unprotected = esdicawt_sd_kbt.remove(0);
    let esdicawt_payload = esdicawt_sd_kbt.remove(0);
    let esdicawt_payload = esdicawt_payload.as_bytes().unwrap();
    let esdicawt_payload = Value::from_cbor_bytes(esdicawt_payload).unwrap().into_map().unwrap();

    // FIXME: pending test vectors use CoAP content formats
    // assert_eq!(claim(&spec_protected, 16), claim(&esdicawt_protected, 16)); // typ
    assert_eq!(claim(&spec_protected, 1), claim(&esdicawt_protected, 1)); // alg
    // should find kcwt claim
    claim(&spec_protected, 13);
    claim(&esdicawt_protected, 13);

    assert_eq!(spec_unprotected, esdicawt_unprotected);

    assert_eq!(spec_payload, esdicawt_payload);
}

fn holder_signing_key() -> p256::ecdsa::SigningKey {
    p256::SecretKey::from_pkcs8_pem(include_str!("../../draft-ietf-spice-sd-cwt/holder_privkey.pem").trim())
        .unwrap()
        .into()
}

fn issuer_signing_key() -> p384::ecdsa::SigningKey {
    p384::SecretKey::from_pkcs8_pem(include_str!("../../draft-ietf-spice-sd-cwt/issuer_privkey.pem").trim())
        .unwrap()
        .into()
}

fn issuer_verifying_key() -> CoseKeySet {
    CoseKeySet::builder().with_signing_key(&issuer_signing_key()).unwrap().build()
}
