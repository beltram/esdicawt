use ciborium::Value;
use serde::ser::SerializeMap;

use crate::{COSE_HEADER_SD_CLAIMS, CustomClaims, EsdicawtSpecError, blinded_claims::SaltedArray};

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

        let mut map = serializer.serialize_map(Some(map_size))?;

        if let Some(sd_claims) = &self.sd_claims {
            if sd_claims.is_empty() {
                return Err(S::Error::custom(EsdicawtSpecError::EmptySdClaims));
            }
            map.serialize_entry(&COSE_HEADER_SD_CLAIMS, sd_claims)?;
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
                            return Err(A::Error::custom(EsdicawtSpecError::EmptySdClaims));
                        }
                        sd_claims.replace(salted_array);
                    } else {
                        extra.push((k, v));
                    }
                }

                let extra = if extra.is_empty() {
                    None
                } else {
                    Some(Value::deserialized::<Extra>(&Value::Map(extra)).map_err(A::Error::custom)?)
                };
                Ok(SdUnprotected { sd_claims, extra })
            }
        }

        deserializer.deserialize_map(SdUnprotectedVisitor::<Extra>(Default::default()))
    }
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
        SdUnprotected { sd_claims, extra: None }
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
        assert!(unprotected(Some(SaltedArray::default())).to_cbor_bytes().is_err());
    }
}
