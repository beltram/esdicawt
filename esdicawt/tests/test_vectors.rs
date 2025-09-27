#![allow(clippy::borrow_interior_mutable_const, clippy::declare_interior_mutable_const)]

use ciborium::Value;
use esdicawt::{IssueCwtParams, Issuer};
use esdicawt_spec::{EsdicawtSpecError, NoClaims, SdHashAlg, Select, SelectiveDisclosure, reexports::coset, sd};
use pkcs8::DecodePrivateKey;
use rand_core::{CryptoRng, Error, RngCore};
use spice_oidc_cwt::OidcAddressClaim;
use std::{
    io::Write,
    sync::atomic::{AtomicU32, Ordering},
};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Payload {
    pub most_recent_inspection_passed: bool,
    pub inspector_license_number: String,
    pub inspection_dates: Vec<u64>,
    pub inspection_location: OidcAddressClaim,
}

impl Select for Payload {
    type Error = EsdicawtSpecError;

    fn select(self) -> Result<SelectiveDisclosure, <Self as Select>::Error> {
        let mut map = Vec::with_capacity(4);

        map.push((Value::Integer(500.into()), Value::Bool(self.most_recent_inspection_passed)));

        map.push((sd(Value::Integer(501.into())), Value::Text(self.inspector_license_number)));

        let inspection_dates = self
            .inspection_dates
            .iter()
            .enumerate()
            .map(|(i, &d)| if i < 2 { sd(Value::Integer(d.into())) } else { Value::Integer(d.into()) })
            .collect();
        map.push((sd(Value::Integer(502.into())), Value::Array(inspection_dates)));

        let mut inspection_location = Vec::with_capacity(3);
        if let Some(country) = self.inspection_location.country {
            inspection_location.push((Value::Text("country".into()), Value::Text(country)));
        }
        if let Some(region) = self.inspection_location.region {
            inspection_location.push((sd(Value::Text("region".into())), Value::Text(region)));
        }
        if let Some(postal_code) = self.inspection_location.postal_code {
            inspection_location.push((sd(Value::Text("postal_code".into())), Value::Text(postal_code)));
        }
        map.push((Value::Integer(503.into()), Value::Map(inspection_location)));

        Ok(Value::Map(map).into())
    }
}

pub struct P384Issuer<T: Select<Error = EsdicawtSpecError>> {
    signing_key: p384::ecdsa::SigningKey,
    _marker: core::marker::PhantomData<T>,
}

impl<T: Select<Error = EsdicawtSpecError>> Issuer for P384Issuer<T> {
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
        coset::iana::Algorithm::ES384
    }

    fn hash_algorithm(&self) -> SdHashAlg {
        SdHashAlg::Sha256
    }

    fn serialize_signature(&self, signature: &p384::ecdsa::Signature) -> Result<Vec<u8>, Self::Error> {
        Ok(signature.to_bytes().to_vec())
    }

    fn deserialize_signature(&self, bytes: &[u8]) -> Result<p384::ecdsa::Signature, Self::Error> {
        Ok(p384::ecdsa::Signature::from_slice(bytes).unwrap())
    }
}

#[test]
fn issuer() {
    let mut csprng = TestVectorRng;

    let holder_signing_key: p256::ecdsa::SigningKey = p256::SecretKey::from_pkcs8_pem(include_str!("../../draft-ietf-spice-sd-cwt/holder_privkey.pem").trim())
        .unwrap()
        .into();
    let issuer_signing_key: p384::ecdsa::SigningKey = p384::SecretKey::from_pkcs8_pem(include_str!("../../draft-ietf-spice-sd-cwt/issuer_privkey.pem").trim())
        .unwrap()
        .into();

    let sd_issuer = P384Issuer::<Payload>::new(issuer_signing_key);

    let payload = Payload {
        most_recent_inspection_passed: true,
        inspector_license_number: "ABCD-123456".to_string(),
        inspection_dates: vec![1549560720, 1612560720, 17183928],
        inspection_location: OidcAddressClaim {
            country: Some("us".into()),
            region: Some("ca".into()),
            postal_code: Some("94188".into()),
            ..Default::default()
        },
    };

    let params = IssueCwtParams {
        protected_claims: None::<NoClaims>,
        unprotected_claims: None::<NoClaims>,
        payload: Some(payload),
        subject: "https://device.example",
        issuer: "https://issuer.example",
        expiry: Default::default(),
        leeway: Default::default(),
        key_location: "",
        holder_confirmation_key: (holder_signing_key.verifying_key()).try_into().unwrap(),
    };

    let _sd_cwt = sd_issuer.issue_cwt(&mut csprng, params);
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
        const CTR: AtomicU32 = AtomicU32::new(0);
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
        let _ = dest.write(&hex::decode(SALTS[i as usize]).unwrap()[..]).unwrap();
        Ok(())
    }
}
