use ciborium::Value;
use coset::AsCborValue;
use serde::ser::SerializeMap;

use super::SdProtected;
use crate::{COSE_HEADER_SD_ALG, CWT_CLAIM_ALG, CWT_MEDIA_TYPE, CustomClaims, MEDIA_TYPE_SD_CWT, SdHashAlg};

impl<Extra: CustomClaims> serde::Serialize for SdProtected<Extra> {
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

        #[cfg(feature = "backward")]
        let sd_alg_size = 1;
        #[cfg(not(feature = "backward"))]
        let sd_alg_size = self.sd_alg.map(|_| 1).unwrap_or_default();

        let map_size = 2 + sd_alg_size + extras.len();
        let mut map = serializer.serialize_map(Some(map_size))?;

        map.serialize_entry(&CWT_MEDIA_TYPE, &MEDIA_TYPE_SD_CWT)?;

        let alg = (*self.alg).clone().to_cbor_value().map_err(|e| S::Error::custom(format!("Cannot set Alg: {e}")))?;
        map.serialize_entry(&CWT_CLAIM_ALG, &alg)?;

        #[cfg(feature = "backward")]
        map.serialize_entry(&COSE_HEADER_SD_ALG, &self.sd_alg())?;

        // absent means SHA-256, it is not added to keep the encoding signed by the Issuer
        #[cfg(not(feature = "backward"))]
        if let Some(sd_alg) = &self.sd_alg {
            map.serialize_entry(&COSE_HEADER_SD_ALG, sd_alg)?;
        }

        for (k, v) in extras {
            map.serialize_entry(&k, &v)?;
        }

        map.end()
    }
}

impl<'de, Extra: CustomClaims> serde::Deserialize<'de> for SdProtected<Extra> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SdProtectedVisitor<E>(std::marker::PhantomData<E>);
        impl<'de, Extra: CustomClaims> serde::de::Visitor<'de> for SdProtectedVisitor<Extra> {
            type Value = SdProtected<Extra>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a sd-protected header")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;
                let (mut alg, mut sd_alg) = (None, None);
                let mut extra = vec![];
                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    match k {
                        Value::Integer(label) => match label.try_into() {
                            Ok(CWT_MEDIA_TYPE) => {
                                let media_type = v.into_integer().map_err(|_| A::Error::custom("SD-CWT media type MUST be a CoAP content format"))?;
                                if media_type != MEDIA_TYPE_SD_CWT.into() {
                                    return Err(A::Error::custom(format!("Invalid SD-CWT media-type, MUST be {MEDIA_TYPE_SD_CWT}")));
                                }
                            }
                            Ok(CWT_CLAIM_ALG) => {
                                alg = Some(coset::Algorithm::from_cbor_value(v).map_err(|e| A::Error::custom(format!("Cannot deserialize sd-protected.alg: {e}")))?);
                            }
                            Ok(COSE_HEADER_SD_ALG) => {
                                sd_alg = Some(
                                    v.deserialized::<SdHashAlg>()
                                        .map_err(|value| A::Error::custom(format!("sd_alg is not a correct enum value: {value:?}")))?,
                                );
                            }
                            _ => {
                                extra.push((k, v));
                            }
                        },
                        _ => {
                            extra.push((k, v));
                        }
                    }
                }

                let extra = if extra.is_empty() {
                    None
                } else {
                    Some(Value::deserialized::<Extra>(&Value::Map(extra)).map_err(A::Error::custom)?)
                };

                const CONTEXT: &str = "Cannot build sd-protected: ";
                Ok(SdProtected {
                    alg: crate::required_in::<coset::Algorithm, _>(alg, CONTEXT, "alg")?.into(),
                    sd_alg,
                    extra,
                })
            }
        }

        deserializer.deserialize_map(SdProtectedVisitor::<Extra>(Default::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{COSE_HEADER_SD_ALG, CwtAny, NoClaims};
    use ciborium::cbor;

    #[test]
    #[cfg(not(feature = "backward"))]
    fn should_default_sd_alg_to_sha256_when_absent() {
        let bytes = cbor!({ CWT_MEDIA_TYPE => MEDIA_TYPE_SD_CWT, CWT_CLAIM_ALG => -8 }).unwrap().to_cbor_bytes().unwrap();
        let protected = SdProtected::<NoClaims>::from_cbor_bytes(&bytes).unwrap();
        assert_eq!(protected.sd_alg, None);
        assert_eq!(protected.sd_alg(), SdHashAlg::Sha256);
        // must not be added back since it would alter what the Issuer signed
        assert_eq!(protected.to_cbor_bytes().unwrap(), bytes);
    }

    #[test]
    fn should_use_sd_alg_when_present() {
        let bytes = cbor!({ CWT_MEDIA_TYPE => MEDIA_TYPE_SD_CWT, CWT_CLAIM_ALG => -8, COSE_HEADER_SD_ALG => SdHashAlg::Sha384 as i64 })
            .unwrap()
            .to_cbor_bytes()
            .unwrap();
        let protected = SdProtected::<NoClaims>::from_cbor_bytes(&bytes).unwrap();
        assert_eq!(protected.sd_alg(), SdHashAlg::Sha384);
        assert_eq!(protected.to_cbor_bytes().unwrap(), bytes);
    }
}
