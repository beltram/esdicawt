use ciborium::Value;
use serde::ser::SerializeMap;

use crate::{COSE_HEADER_SD_CLAIMS, CustomClaims, blinded_claims::SaltedArray};

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

        let map_size = self.sd_claims.as_ref().map(|_| 1).unwrap_or_default() + extras.len();
        #[cfg(feature = "aead")]
        let map_size = map_size + usize::from(self.sd_aead_encrypted_claims.is_some()) + usize::from(self.sd_aead.is_some());

        let mut map = serializer.serialize_map(Some(map_size))?;

        if let Some(sd_claims) = &self.sd_claims {
            // previous versions' Verifiers only remove the undisclosed claims when 'sd_claims' is present, hence an empty one is produced for them
            #[cfg(not(feature = "backward"))]
            if sd_claims.is_empty() {
                return Err(S::Error::custom(crate::EsdicawtSpecError::EmptySdClaims));
            }
            map.serialize_entry(&COSE_HEADER_SD_CLAIMS, sd_claims)?;
        }

        #[cfg(feature = "aead")]
        if let Some(sd_aead_encrypted_claims) = &self.sd_aead_encrypted_claims {
            map.serialize_entry(&crate::COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS, sd_aead_encrypted_claims)?;
        }

        #[cfg(feature = "aead")]
        if let Some(sd_aead) = &self.sd_aead {
            map.serialize_entry(&crate::COSE_HEADER_SD_AEAD, sd_aead)?;
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
                #[cfg(feature = "aead")]
                let (mut sd_aead_encrypted_claims, mut sd_aead) = (None, None);
                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    if matches!(k, Value::Integer(label) if label == COSE_HEADER_SD_CLAIMS.into()) {
                        let salted_array = v
                            .deserialized::<SaltedArray>()
                            .map_err(|err| A::Error::custom(format!("Cannot deserialize sd_claims: {err}")))?;
                        // see https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-kbt-and-sd-cwt-verifier-val
                        if salted_array.is_empty() {
                            // previous versions used to encode an empty 'sd_claims' instead of omitting it: treat it as absent
                            #[cfg(feature = "backward")]
                            continue;
                            #[cfg(not(feature = "backward"))]
                            return Err(A::Error::custom(crate::EsdicawtSpecError::EmptySdClaims));
                        }
                        sd_claims.replace(salted_array);
                    } else {
                        #[cfg(feature = "aead")]
                        if k == Value::from(crate::COSE_HEADER_SD_AEAD_ENCRYPTED_CLAIMS) {
                            decode_once(&mut sd_aead_encrypted_claims, &v, "sd_aead_encrypted_claims")?;
                            continue;
                        } else if k == Value::from(crate::COSE_HEADER_SD_AEAD) {
                            decode_once(&mut sd_aead, &v, "sd_aead")?;
                            continue;
                        }
                        extra.push((k, v));
                    }
                }

                let extra = if extra.is_empty() {
                    None
                } else {
                    Some(Value::deserialized::<Extra>(&Value::Map(extra)).map_err(A::Error::custom)?)
                };
                Ok(SdUnprotected {
                    sd_claims,
                    #[cfg(feature = "aead")]
                    sd_aead_encrypted_claims,
                    #[cfg(feature = "aead")]
                    sd_aead,
                    extra,
                })
            }
        }

        deserializer.deserialize_map(SdUnprotectedVisitor::<Extra>(Default::default()))
    }
}

/// Decodes a header parameter which must appear at most once
#[cfg(feature = "aead")]
fn decode_once<T: serde::de::DeserializeOwned, E: serde::de::Error>(slot: &mut Option<T>, value: &Value, name: &str) -> Result<(), E> {
    let decoded = value.deserialized::<T>().map_err(|err| E::custom(format!("Cannot deserialize {name}: {err}")))?;
    if slot.replace(decoded).is_some() {
        return Err(E::custom(format!("Duplicate {name}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CwtAny, NoClaims, Salt,
        blinded_claims::{Decoy, SaltedEntry},
        inlined_cbor::InlinedCbor,
    };
    use ciborium::cbor;

    fn unprotected(sd_claims: Option<SaltedArray>) -> SdUnprotected<NoClaims> {
        SdUnprotected {
            sd_claims,
            #[cfg(feature = "aead")]
            sd_aead_encrypted_claims: None,
            #[cfg(feature = "aead")]
            sd_aead: None,
            extra: None,
        }
    }

    #[test]
    fn should_roundtrip() {
        let decoy = SaltedEntry::<Value>::Decoy(Decoy { salt: Salt::empty() });
        let salted_array: SaltedArray = vec![InlinedCbor::from_bytes(decoy.to_cbor_bytes().unwrap())].into();
        for case in [unprotected(None), unprotected(Some(salted_array))] {
            let bytes = case.to_cbor_bytes().unwrap();
            assert_eq!(SdUnprotected::<NoClaims>::from_cbor_bytes(&bytes).unwrap(), case);
        }
    }

    #[test]
    fn should_reject_empty_sd_claims() {
        let empty = cbor!({ 17 => [] }).unwrap().to_cbor_bytes().unwrap();
        #[cfg(not(feature = "backward"))]
        assert!(SdUnprotected::<NoClaims>::from_cbor_bytes(&empty).is_err());
        // previous versions encoded an empty 'sd_claims': it is ignored
        #[cfg(feature = "backward")]
        assert_eq!(SdUnprotected::<NoClaims>::from_cbor_bytes(&empty).unwrap(), unprotected(None));
        #[cfg(not(feature = "backward"))]
        assert!(unprotected(Some(SaltedArray::default())).to_cbor_bytes().is_err());
        // previous versions' Verifiers expect an empty 'sd_claims' when nothing is disclosed
        #[cfg(feature = "backward")]
        assert_eq!(unprotected(Some(SaltedArray::default())).to_cbor_bytes().unwrap(), empty);
    }

    #[cfg(feature = "aead")]
    mod aead {
        use super::*;
        use crate::aead::{AeadAlgorithm, AeadEncryptedArray, AeadEncryptedDisclosure, AeadKeyContext};

        fn salted_array() -> SaltedArray {
            let decoy = SaltedEntry::<Value>::Decoy(Decoy { salt: Salt::empty() });
            vec![InlinedCbor::from_bytes(decoy.to_cbor_bytes().unwrap())].into()
        }

        fn encrypted() -> AeadEncryptedArray {
            AeadEncryptedArray::new(vec![AeadEncryptedDisclosure {
                nonce: vec![1; 12],
                ciphertext: vec![2; 35],
                tag: vec![3; 16],
                key_context: Some(AeadKeyContext::Uint(7)),
            }])
            .unwrap()
        }

        fn aead_unprotected(sd_claims: Option<SaltedArray>, sd_aead_encrypted_claims: Option<AeadEncryptedArray>, sd_aead: Option<AeadAlgorithm>) -> SdUnprotected<NoClaims> {
            SdUnprotected {
                sd_aead_encrypted_claims,
                sd_aead,
                ..unprotected(sd_claims)
            }
        }

        #[test]
        fn should_roundtrip() {
            let cases = [
                aead_unprotected(None, Some(encrypted()), Some(AeadAlgorithm::AES_256_GCM)),
                aead_unprotected(Some(salted_array()), Some(encrypted()), Some(AeadAlgorithm::AES_128_GCM)),
                aead_unprotected(Some(salted_array()), Some(encrypted()), None),
            ];
            for case in cases {
                let bytes = case.to_cbor_bytes().unwrap();
                assert_eq!(SdUnprotected::<NoClaims>::from_cbor_bytes(&bytes).unwrap(), case);
            }
        }

        #[test]
        fn should_use_registered_labels() {
            let bytes = aead_unprotected(Some(salted_array()), Some(encrypted()), Some(AeadAlgorithm::CHACHA20_POLY1305))
                .to_cbor_bytes()
                .unwrap();
            let map = Value::from_cbor_bytes(&bytes).unwrap().into_map().unwrap();
            let labels = map.iter().map(|(k, _)| k.as_integer().unwrap()).map(i128::from).collect::<Vec<_>>();
            assert_eq!(labels, vec![17, 171, 172]);
            assert_eq!(map.get(2).unwrap().1, Value::from(29));
        }

        #[test]
        fn should_reject_empty_encrypted_claims() {
            let empty_encrypted = cbor!({ 171 => [] }).unwrap().to_cbor_bytes().unwrap();
            assert!(SdUnprotected::<NoClaims>::from_cbor_bytes(&empty_encrypted).is_err());
        }

        #[test]
        fn should_reject_duplicate_labels() {
            let encrypted = Value::serialized(&encrypted()).unwrap();
            let duplicates = [
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
}
