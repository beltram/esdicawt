use ciborium::Value;
use serde::ser::SerializeMap;

use crate::{
    COSE_HEADER_SD_AEAD, COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS, COSE_HEADER_SD_CLAIMS, CustomClaims, EsdicawtSpecError,
    aead::{AeadAlgorithm, AeadEncryptedArray},
    blinded_claims::SaltedArray,
};

use super::SdUnprotected;

impl<Extra: CustomClaims> serde::Serialize for SdUnprotected<Extra> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let extras = self
            .extra
            .as_ref()
            .map(Extra::to_cbor_value)
            .transpose()
            .map_err(S::Error::custom)?
            .map(Value::into_map)
            .transpose()
            .map_err(|e| S::Error::custom(format!("{e:?} should have been a mapping")))?
            .unwrap_or_default();

        let map_size = usize::from(self.sd_claims.is_some()) + usize::from(self.sd_aead_encrypted_claims.is_some()) + usize::from(self.sd_aead.is_some()) + extras.len();

        let mut map = serializer.serialize_map(Some(map_size))?;

        if let Some(sd_claims) = &self.sd_claims {
            if sd_claims.is_empty() {
                return Err(S::Error::custom(EsdicawtSpecError::EmptySdClaims));
            }
            map.serialize_entry(&COSE_HEADER_SD_CLAIMS, sd_claims)?;
        }

        if let Some(sd_aead_encrypted_claims) = &self.sd_aead_encrypted_claims {
            map.serialize_entry(&COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS, sd_aead_encrypted_claims)?;
        }

        if let Some(sd_aead) = &self.sd_aead {
            map.serialize_entry(&COSE_HEADER_SD_AEAD, sd_aead)?;
        }

        for (k, v) in extras {
            map.serialize_entry(&k, &v)?;
        }
        map.end()
    }
}

impl<'de, Extra: CustomClaims> serde::Deserialize<'de> for SdUnprotected<Extra> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SdUnprotectedVisitor<Extra: CustomClaims>(std::marker::PhantomData<Extra>);

        impl<'de, Extra: CustomClaims> serde::de::Visitor<'de> for SdUnprotectedVisitor<Extra> {
            type Value = SdUnprotected<Extra>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an unprotected-issued header")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;
                let mut extra = vec![];
                let mut sd_claims = None;
                let mut sd_aead_encrypted_claims = None;
                let mut sd_aead = None;
                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    match k {
                        Value::Integer(label) if label == COSE_HEADER_SD_CLAIMS.into() => {
                            let salted_array = v
                                .deserialized::<SaltedArray>()
                                .map_err(|err| A::Error::custom(format!("Cannot deserialize sd_claims: {err}")))?;
                            if salted_array.is_empty() {
                                return Err(A::Error::custom(EsdicawtSpecError::EmptySdClaims));
                            }
                            if sd_claims.replace(salted_array).is_some() {
                                return Err(A::Error::custom("Duplicate sd_claims"));
                            }
                        }
                        Value::Integer(label) if label == COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS.into() => {
                            let encrypted = v
                                .deserialized::<AeadEncryptedArray>()
                                .map_err(|err| A::Error::custom(format!("Cannot deserialize sd_aead_encrypted_claims: {err}")))?;
                            if sd_aead_encrypted_claims.replace(encrypted).is_some() {
                                return Err(A::Error::custom("Duplicate sd_aead_encrypted_claims"));
                            }
                        }
                        Value::Integer(label) if label == COSE_HEADER_SD_AEAD.into() => {
                            let alg = v
                                .deserialized::<AeadAlgorithm>()
                                .map_err(|err| A::Error::custom(format!("Cannot deserialize sd_aead: {err}")))?;
                            if sd_aead.replace(alg).is_some() {
                                return Err(A::Error::custom("Duplicate sd_aead"));
                            }
                        }
                        k => extra.push((k, v)),
                    }
                }

                let extra = if extra.is_empty() {
                    None
                } else {
                    Some(Value::deserialized::<Extra>(&Value::Map(extra)).map_err(A::Error::custom)?)
                };
                Ok(SdUnprotected {
                    sd_claims,
                    sd_aead_encrypted_claims,
                    sd_aead,
                    extra,
                })
            }
        }

        deserializer.deserialize_map(SdUnprotectedVisitor::<Extra>(Default::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CwtAny, NoClaims,
        aead::{AeadEncryptedDisclosure, AeadKeyContext},
        blinded_claims::{Decoy, SaltedEntry},
        inlined_cbor::InlinedCbor,
    };
    use ciborium::cbor;

    fn salted_array() -> SaltedArray {
        let decoy = SaltedEntry::<Value>::Decoy(Decoy { salt: crate::Salt::empty() });
        vec![InlinedCbor::from_bytes(decoy.to_cbor_bytes().unwrap())].into()
    }

    fn encrypted() -> AeadEncryptedArray {
        AeadEncryptedArray::try_new(vec![AeadEncryptedDisclosure {
            nonce: vec![1; 12].into(),
            ciphertext: vec![2; 35].into(),
            tag: vec![3; 16].into(),
            key_context: Some(AeadKeyContext::Uint(7)),
        }])
        .unwrap()
    }

    fn unprotected(sd_claims: Option<SaltedArray>, sd_aead_encrypted_claims: Option<AeadEncryptedArray>, sd_aead: Option<AeadAlgorithm>) -> SdUnprotected<NoClaims> {
        SdUnprotected {
            sd_claims,
            sd_aead_encrypted_claims,
            sd_aead,
            extra: None,
        }
    }

    #[test]
    fn should_roundtrip() {
        let cases = [
            unprotected(None, None, None),
            unprotected(Some(salted_array()), None, None),
            unprotected(None, Some(encrypted()), Some(AeadAlgorithm::AES_256_GCM)),
            unprotected(Some(salted_array()), Some(encrypted()), Some(AeadAlgorithm::AES_128_GCM)),
            unprotected(Some(salted_array()), Some(encrypted()), None),
        ];
        for case in cases {
            let bytes = case.to_cbor_bytes().unwrap();
            assert_eq!(SdUnprotected::<NoClaims>::from_cbor_bytes(&bytes).unwrap(), case);
        }
    }

    #[test]
    fn should_use_registered_labels() {
        let bytes = unprotected(Some(salted_array()), Some(encrypted()), Some(AeadAlgorithm::CHACHA20_POLY1305))
            .to_cbor_bytes()
            .unwrap();
        let map = Value::from_cbor_bytes(&bytes).unwrap().into_map().unwrap();
        let labels = map.iter().map(|(k, _)| k.as_integer().unwrap()).map(i128::from).collect::<Vec<_>>();
        assert_eq!(labels, vec![17, 171, 172]);
        assert_eq!(map.get(2).unwrap().1, Value::from(29));
    }

    #[test]
    fn should_reject_empty_arrays() {
        let empty_sd_claims = cbor!({ 17 => [] }).unwrap().to_cbor_bytes().unwrap();
        assert!(SdUnprotected::<NoClaims>::from_cbor_bytes(&empty_sd_claims).is_err());

        let empty_encrypted = cbor!({ 171 => [] }).unwrap().to_cbor_bytes().unwrap();
        assert!(SdUnprotected::<NoClaims>::from_cbor_bytes(&empty_encrypted).is_err());

        assert!(unprotected(Some(SaltedArray::default()), None, None).to_cbor_bytes().is_err());
    }

    #[test]
    fn should_reject_duplicate_labels() {
        let salted = Value::serialized(&salted_array()).unwrap();
        let encrypted = Value::serialized(&encrypted()).unwrap();
        let duplicates = [
            Value::Map(vec![(Value::from(17), salted.clone()), (Value::from(17), salted)]),
            Value::Map(vec![(Value::from(171), encrypted.clone()), (Value::from(171), encrypted)]),
            Value::Map(vec![(Value::from(172), Value::from(1)), (Value::from(172), Value::from(2))]),
        ];
        for duplicate in duplicates {
            let bytes = duplicate.to_cbor_bytes().unwrap();
            assert!(SdUnprotected::<NoClaims>::from_cbor_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn should_reject_invalid_sd_aead() {
        for invalid in [Value::from(-1), Value::from(65536), Value::from("A128GCM")] {
            let bytes = Value::Map(vec![(Value::from(172), invalid)]).to_cbor_bytes().unwrap();
            assert!(SdUnprotected::<NoClaims>::from_cbor_bytes(&bytes).is_err());
        }
    }
}
