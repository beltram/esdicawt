#![allow(clippy::borrow_interior_mutable_const, clippy::declare_interior_mutable_const, dead_code)]

use ciborium::{Value, value::Integer};
use cose_key_set::CoseKeySet;
use esdicawt::{Holder, HolderParams, Issuer, IssuerParams, StatusParams, TimeArg, cwt_label};
use esdicawt_spec::{
    CwtAny, EsdicawtSpecError, NoClaims, SdHashAlg, Select,
    reexports::{coset, coset::iana::Algorithm},
    sd,
};
use pkcs8::DecodePrivateKey;
use rand_core::{CryptoRng, Error, RngCore};
use serde::ser::SerializeMap;
use spice_oidc_cwt::{CwtOidcAddressLabel, OidcAddressClaim};
use std::{
    io::Write,
    sync::atomic::{AtomicU32, Ordering},
};

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable")]
pub struct Payload {
    pub most_recent_inspection_passed: bool,
    #[builder(default, setter(into, strip_option))]
    pub inspector_license_number: Option<String>,
    #[builder(default)]
    pub inspection_dates: Vec<u64>,
    pub inspection_location: OidcAddressClaim,
}

#[derive(Debug, Copy, Clone, serde_repr::Serialize_repr, serde_repr::Deserialize_repr)]
#[repr(i64)]
pub enum CwtLabel {
    MostRecentInspectionPassed = 500,
    InspectorLicenseNumber = 501,
    InspectionDates = 502,
    InspectionLocation = 503,
    NestedPayload = 504,
}

cwt_label!(CwtLabel);

impl serde::Serialize for Payload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(&CwtLabel::MostRecentInspectionPassed, &self.most_recent_inspection_passed)?;
        map.serialize_entry(&CwtLabel::InspectorLicenseNumber, &self.inspector_license_number)?;
        map.serialize_entry(&CwtLabel::InspectionDates, &self.inspection_dates)?;
        let location = self.inspection_location.to_cbor_value().map_err(S::Error::custom)?;
        map.serialize_entry(&CwtLabel::InspectionLocation, &location)?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for Payload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        // I'm lazy to go with a visitor
        let value = <Value as serde::Deserialize>::deserialize(deserializer)?;
        let values = value.into_map().map_err(|_| D::Error::custom("expected a map"))?;

        let mut builder = PayloadBuilder::create_empty();

        for entry in values {
            match entry {
                (Value::Integer(i), Value::Bool(b)) if i == CwtLabel::MostRecentInspectionPassed => builder.most_recent_inspection_passed(b),
                (Value::Integer(i), Value::Text(s)) if i == CwtLabel::InspectorLicenseNumber => builder.inspector_license_number(s),
                (Value::Integer(i), Value::Array(values)) if i == CwtLabel::InspectionDates => {
                    let values = values.into_iter().filter(|v| !matches!(v, Value::Tag(_, _))).collect::<Vec<_>>();
                    builder.inspection_dates(Value::Array(values).deserialized().map_err(D::Error::custom)?)
                }
                (Value::Integer(i), value) if i == CwtLabel::InspectionLocation => builder.inspection_location(value.deserialized().map_err(D::Error::custom)?),
                _ => unreachable!("Unexpected claim"),
            };
        }

        builder.build().map_err(D::Error::custom)
    }
}

impl Select for Payload {
    fn select(self) -> Result<Value, ciborium::value::Error> {
        let mut map = Vec::with_capacity(4);

        map.push((CwtLabel::MostRecentInspectionPassed.into(), Value::Bool(self.most_recent_inspection_passed)));

        if let Some(inspector_license_number) = self.inspector_license_number {
            map.push((sd!(CwtLabel::InspectorLicenseNumber as i64), Value::Text(inspector_license_number)));
        }

        let inspection_dates = self
            .inspection_dates
            .iter()
            .enumerate()
            .map(|(i, &d)| if i < 2 { sd!(d) } else { Value::Integer(d.into()) })
            .collect();
        map.push((CwtLabel::InspectionDates.into(), Value::Array(inspection_dates)));

        let mut inspection_location = Vec::with_capacity(3);
        if let Some(country) = self.inspection_location.country {
            inspection_location.push((CwtOidcAddressLabel::Country.into(), Value::Text(country)));
        }
        if let Some(region) = self.inspection_location.region {
            inspection_location.push((sd!(CwtOidcAddressLabel::Region), Value::Text(region)));
        }
        if let Some(postal_code) = self.inspection_location.postal_code {
            inspection_location.push((sd!(CwtOidcAddressLabel::PostalCode), Value::Text(postal_code)));
        }
        map.push((CwtLabel::InspectionLocation.into(), Value::Map(inspection_location)));

        Ok(Value::Map(map))
    }
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable")]
pub struct NestedPayload {
    pub nested: Vec<PayloadLog>,
}

impl serde::Serialize for NestedPayload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(&CwtLabel::NestedPayload, &self.nested)?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for NestedPayload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        // I'm lazy to go with a visitor
        let value = <Value as serde::Deserialize>::deserialize(deserializer)?;
        let values = value.into_map().map_err(|_| D::Error::custom("expected a map"))?;

        let mut builder = NestedPayloadBuilder::create_empty();

        for entry in values {
            match entry {
                (Value::Integer(i), Value::Array(values)) if i == CwtLabel::NestedPayload => {
                    let values = values.into_iter().filter(|v| !matches!(v, Value::Tag(_, _))).collect::<Vec<_>>();
                    builder.nested(Value::Array(values).deserialized().map_err(D::Error::custom)?)
                }
                _ => unreachable!("Unexpected claim"),
            };
        }

        builder.build().map_err(D::Error::custom)
    }
}

impl Select for NestedPayload {
    fn select(self) -> Result<Value, ciborium::value::Error> {
        let mut map = Vec::with_capacity(1);

        let nested = self.nested.into_iter().map(|n| sd!(n.select().unwrap())).collect::<Vec<_>>();

        map.push((CwtLabel::NestedPayload.into(), Value::Array(nested)));
        Ok(Value::Map(map))
    }
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable")]
pub struct PayloadLog {
    pub most_recent_inspection_passed: bool,
    #[builder(default, setter(into, strip_option))]
    pub inspector_license_number: Option<String>,
    pub inspection_date: u64,
    pub inspection_location: OidcAddressClaim,
}

impl serde::Serialize for PayloadLog {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(&CwtLabel::MostRecentInspectionPassed, &self.most_recent_inspection_passed)?;
        map.serialize_entry(&CwtLabel::InspectorLicenseNumber, &self.inspector_license_number)?;
        map.serialize_entry(&CwtLabel::InspectionDates, &self.inspection_date)?;
        let location = self.inspection_location.to_cbor_value().map_err(S::Error::custom)?;
        map.serialize_entry(&CwtLabel::InspectionLocation, &location)?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for PayloadLog {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        // I'm lazy to go with a visitor
        let value = <Value as serde::Deserialize>::deserialize(deserializer)?;
        let values = value.into_map().map_err(|_| D::Error::custom("expected a map"))?;

        let mut builder = PayloadLogBuilder::create_empty();

        for entry in values {
            match entry {
                (Value::Integer(i), Value::Bool(b)) if i == CwtLabel::MostRecentInspectionPassed => builder.most_recent_inspection_passed(b),
                (Value::Integer(i), Value::Text(s)) if i == CwtLabel::InspectorLicenseNumber => builder.inspector_license_number(s),
                (Value::Integer(i), Value::Integer(d)) if i == CwtLabel::InspectionDates => builder.inspection_date(d.try_into().map_err(D::Error::custom)?),
                (Value::Integer(i), value) if i == CwtLabel::InspectionLocation => builder.inspection_location(value.deserialized().map_err(D::Error::custom)?),
                _ => unreachable!("Unexpected claim"),
            };
        }

        builder.build().map_err(D::Error::custom)
    }
}

impl Select for PayloadLog {
    fn select(self) -> Result<Value, ciborium::value::Error> {
        let mut map = Vec::with_capacity(4);

        map.push((CwtLabel::MostRecentInspectionPassed.into(), Value::Bool(self.most_recent_inspection_passed)));

        if let Some(inspector_license_number) = self.inspector_license_number {
            map.push((sd!(CwtLabel::InspectorLicenseNumber as i64), Value::Text(inspector_license_number)));
        }

        map.push((CwtLabel::InspectionDates.into(), Value::Integer(self.inspection_date.into())));

        let mut inspection_location = Vec::with_capacity(3);
        if let Some(country) = self.inspection_location.country {
            inspection_location.push((CwtOidcAddressLabel::Country.into(), Value::Text(country)));
        }
        if let Some(region) = self.inspection_location.region {
            inspection_location.push((sd!(CwtOidcAddressLabel::Region), Value::Text(region)));
        }
        if let Some(postal_code) = self.inspection_location.postal_code {
            inspection_location.push((sd!(CwtOidcAddressLabel::PostalCode), Value::Text(postal_code)));
        }
        map.push((sd!(Value::Integer((CwtLabel::InspectionLocation as i64).into())), Value::Map(inspection_location)));

        Ok(Value::Map(map))
    }
}

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
        inspection_dates: vec![1549560720, 1612560720, 17183928],
        inspection_location: OidcAddressClaim {
            country: Some("us".into()),
            region: Some("ca".into()),
            postal_code: Some("94188".into()),
            ..Default::default()
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
        inspection_location: OidcAddressClaim {
            country: Some("us".into()),
            region: Some("co".into()),
            postal_code: Some("80302".into()),
            ..Default::default()
        },
    };
    let payload2 = PayloadLog {
        most_recent_inspection_passed: true,
        inspector_license_number: Some("EFGH-789012".into()),
        inspection_date: 1612560720,
        inspection_location: OidcAddressClaim {
            country: Some("us".into()),
            region: Some("nv".into()),
            postal_code: Some("89155".into()),
            ..Default::default()
        },
    };
    let payload3 = PayloadLog {
        most_recent_inspection_passed: true,
        inspector_license_number: Some("ABCD-123456".into()),
        inspection_date: 17183928,
        inspection_location: OidcAddressClaim {
            country: Some("us".into()),
            region: Some("ca".into()),
            postal_code: Some("94188".into()),
            ..Default::default()
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
        subject: Some("https://device.example"),
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
    let spec_protected = spec_sd_cwt.remove(0);
    let spec_unprotected = spec_sd_cwt.remove(0);
    let spec_payload = spec_sd_cwt.remove(0);
    let spec_payload = spec_payload.as_bytes().unwrap();
    let spec_payload = Value::from_cbor_bytes(spec_payload).unwrap().into_map().unwrap();

    let esdicawt_sd_cwt = sd_issuer.issue_cwt(&mut TestVectorRng, params).unwrap();
    let esdicawt_sd_cwt_bytes = esdicawt_sd_cwt.to_cbor_bytes().unwrap();
    let esdicawt_sd_cwt = Value::from_cbor_bytes(&esdicawt_sd_cwt_bytes).unwrap();
    let mut esdicawt_sd_cwt = esdicawt_sd_cwt.into_tag().unwrap().1.into_array().unwrap();
    let esdicawt_protected = esdicawt_sd_cwt.remove(0);
    let esdicawt_unprotected = esdicawt_sd_cwt.remove(0);
    let esdicawt_payload = esdicawt_sd_cwt.remove(0);
    let esdicawt_payload = esdicawt_payload.as_bytes().unwrap();
    let esdicawt_payload = Value::from_cbor_bytes(esdicawt_payload).unwrap().into_map().unwrap();

    // protected
    assert_eq!(spec_protected, esdicawt_protected);

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

    assert_eq!(claim(&spec_protected, 16), claim(&esdicawt_protected, 16)); // typ
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
    CoseKeySet::new(issuer_signing_key().as_ref()).unwrap()
}

struct TestVectorRng;

impl CryptoRng for TestVectorRng {}

impl RngCore for TestVectorRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        unimplemented!()
    }

    fn try_fill_bytes(&mut self, mut dest: &mut [u8]) -> Result<(), Error> {
        static CTR: AtomicU32 = AtomicU32::new(0);
        const SALTS: &[&str] = &[
            // first disclosure
            "bae611067bb823486797da1ebbb52f83",
            // second disclosure
            "8de86a012b3043ae6e4457b9e1aaab80",
            // third disclosure
            "7af7084b50badeb57d49ea34627c7a52",
            // fourth disclosure
            "ec615c3035d5a4ff2f5ae29ded683c8e",
            // fifth disclosure
            "37c23d4ec4db0806601e6b6dc6670df9",
            // nested disclosure 1
            "ff220dbc9b033e5086f6d382e0760ddf",
            // nested disclosure 2
            "52da9de5dc61b33775f9348b991d3d78",
            // nested disclosure 3
            "a965de35aa599d603fe1b7aa89490eb0",
            // nested disclosure 4
            "7d2505257e7850b70295a87b3c8748e5",
            // nested disclosure 5
            "78b8a19cc53f1ed43f5e2751398d2704",
            // nested disclosure 6
            "9a3bc899090435650b377199450c1fa1",
            // nested disclosure 7
            "5e852d2eef59c0ebeab8c08fca252cc5",
            // nested disclosure 8
            "3dd46bd7dea09c9ee7dfe4e0d510129b",
            // nested disclosure 9
            "a1658ffb2a45e2684ac664bcce00c92c",
            // nested disclosure 10
            "2715ebca1d42af16a6d4560dc231c448",
            // nested disclosure 11
            "b492ab1cfb415a31821138648c7a559a",
            // A
            "591eb2081b05be2dcbb6f8459cc0fe51",
            // B
            "e70e23e77176fa59beb0b2559943a079",
            // C
            "cbbf1cd3d1a5da83e1d92c08d566a481",
            // D
            "d7abeb9016448caeb018b5bdbaee17de",
            // E
            "b52272341715f2a0b476e33e55ce7501",
            // F
            "e3aa33644123fdbf819ad534653f4aaa",
            // G
            "d2be8cc99c185ef10e3f91a61d2d9bf9",
        ];
        let i = CTR.fetch_add(1, Ordering::SeqCst);
        #[allow(clippy::indexing_slicing)]
        let salt = SALTS[i as usize];
        let _ = dest.write(&hex::decode(salt).unwrap()[..]).unwrap();
        Ok(())
    }
}
