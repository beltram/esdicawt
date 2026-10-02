#![allow(clippy::borrow_interior_mutable_const, clippy::declare_interior_mutable_const, dead_code)]

mod model;
mod rng;

use model::*;
use rng::*;

use esdicawt::{
    Holder, HolderParams, Issuer, IssuerParams, Presentation, TimeArg,
    cose_key::keyset::CoseKeySet,
    spec::{
        EsdicawtSpecError, NoClaims, SdHashAlg, Select,
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
            region: Some("ca".into()),
            postal_code: Some("94188".into()),
        },
    };

    let spec_sd_cwt_bytes = include_bytes!("../../../draft-ietf-spice-sd-cwt/examples/issuer_cwt.cbor");
    let spec_sd_kbt_bytes = include_bytes!("../../../draft-ietf-spice-sd-cwt/examples/kbt.cbor");

    // the holder discloses "inspector_license_number", "inspected 7-Feb-2019" and "region=California"
    test_vectors::<Payload>(payload, spec_sd_cwt_bytes, spec_sd_kbt_bytes, false, &[0, 1, 3])
}

#[test]
#[ignore]
fn nested_test_vectors() {
    let payload1 = PayloadLog {
        most_recent_inspection_passed: true,
        inspector_license_number: Some("DCBA-101777".into()),
        inspection_date: 1549560720,
        inspection_location: InspectionLocation {
            country: "us".into(),
            region: Some("co".into()),
            postal_code: Some("80302".into()),
        },
    };
    let payload2 = PayloadLog {
        most_recent_inspection_passed: true,
        inspector_license_number: Some("EFGH-789012".into()),
        inspection_date: 1612560720,
        inspection_location: InspectionLocation {
            country: "us".into(),
            region: Some("nv".into()),
            postal_code: Some("89155".into()),
        },
    };
    let payload3 = PayloadLog {
        most_recent_inspection_passed: true,
        inspector_license_number: Some("ABCD-123456".into()),
        inspection_date: 1674004740,
        inspection_location: InspectionLocation {
            country: "us".into(),
            region: Some("ca".into()),
            postal_code: Some("94188".into()),
        },
    };

    let spec_sd_cwt_bytes = include_bytes!("../../../draft-ietf-spice-sd-cwt/examples/nested_issuer_cwt.cbor");
    let spec_sd_kbt_bytes = include_bytes!("../../../draft-ietf-spice-sd-cwt/examples/nested_kbt.cbor");

    test_vectors::<NestedPayload>(
        NestedPayload {
            nested: vec![payload1, payload2, payload3],
        },
        spec_sd_cwt_bytes,
        spec_sd_kbt_bytes,
        true,
        &[14, 11, 0, 13, 10, 3, 4],
    )
}

/// `presented` are the indexes, in the issued SD-CWT, of the disclosures presented by the holder, in the order of the SD-KBT
fn test_vectors<P: Select>(payload: P, spec_sd_cwt_bytes: &[u8], spec_sd_kbt_bytes: &[u8], nested: bool, presented: &'static [usize]) {
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
    };

    let salt_ranges = if nested { NESTED_SALT_RANGES } else { NORMAL_SALT_RANGES };
    let esdicawt_sd_cwt_bytes = sd_issuer.issue_raw_cwt(&mut TestVectorRng::new(salt_ranges), params).unwrap();

    assert_eq!(hex::encode(&esdicawt_sd_cwt_bytes), hex::encode(spec_sd_cwt_bytes), "SD-CWT mismatch");

    // === Holder ===
    let sd_holder = P256Holder::<P>::new(holder_signing_key());

    let params = HolderParams {
        presentation: Presentation::Custom(Box::new(|issued| presented.iter().filter_map(|&i| issued.get(i).cloned()).collect::<Vec<_>>().into())),
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

    let esdicawt_sd_kbt_bytes = sd_holder.new_presentation_raw(sd_cwt, params).unwrap();
    assert_eq!(hex::encode(&esdicawt_sd_kbt_bytes), hex::encode(spec_sd_kbt_bytes), "SD-KBT mismatch");
}

fn holder_signing_key() -> p256::ecdsa::SigningKey {
    p256::SecretKey::from_pkcs8_pem(include_str!("../../../draft-ietf-spice-sd-cwt/holder_privkey.pem").trim())
        .unwrap()
        .into()
}

fn issuer_signing_key() -> p384::ecdsa::SigningKey {
    p384::SecretKey::from_pkcs8_pem(include_str!("../../../draft-ietf-spice-sd-cwt/issuer_privkey.pem").trim())
        .unwrap()
        .into()
}

fn issuer_verifying_key() -> CoseKeySet {
    CoseKeySet::builder().with_signing_key(&issuer_signing_key()).unwrap().build()
}
