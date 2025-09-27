use ciborium::Value;
use coset::AsCborValue;
use serde::ser::SerializeMap;

use super::SdProtected;
use crate::{CWT_CLAIM_ALG, CWT_CLAIM_SD_ALG, CWT_MEDIATYPE, CustomClaims, MEDIATYPE_SD_CWT, SdHashAlg, issuance::SdProtectedBuilder};

impl<Extra: CustomClaims> serde::Serialize for SdProtected<Extra> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let mut extra = self
            .extra
            .as_ref()
            .map(|extra| Value::serialized(extra).map_err(S::Error::custom))
            .transpose()?
            .map(|v| v.into_map().map_err(|_| S::Error::custom("should have been a mapping")))
            .transpose()?;

        // let mut extra: Option<AnyMap> = self.extra.clone().map(|extra| extra.into());
        let extra_len = extra.as_ref().map(|extra| extra.len()).unwrap_or_default();
        let mut map = serializer.serialize_map(Some(3 + extra_len))?;
        map.serialize_entry(&CWT_MEDIATYPE, MEDIATYPE_SD_CWT)?;

        let alg = (*self.alg).clone().to_cbor_value().map_err(|e| S::Error::custom(format!("Cannot set Alg: {e}")))?;
        map.serialize_entry(&CWT_CLAIM_ALG, &alg)?;

        map.serialize_entry(&CWT_CLAIM_SD_ALG, &self.sd_alg)?;

        if let Some(extra) = extra.take() {
            for (k, v) in extra {
                map.serialize_entry(&k, &v)?;
            }
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
                let mut found_mediatype = false;
                let mut builder = SdProtectedBuilder::<Extra>::default();
                let mut extra = vec![];
                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    match k {
                        Value::Integer(label) => match label.try_into() {
                            // Ignore, but it must be there and have the correct value
                            Ok(CWT_MEDIATYPE) => {
                                found_mediatype = v.into_text().map(|s| s == MEDIATYPE_SD_CWT).unwrap_or_default();
                            }
                            Ok(CWT_CLAIM_ALG) => {
                                builder.alg(coset::Algorithm::from_cbor_value(v).map_err(|e| A::Error::custom(format!("Cannot deserialize sd-protected.alg: {e}")))?);
                            }
                            Ok(CWT_CLAIM_SD_ALG) => {
                                builder.sd_alg(
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

                if !found_mediatype {
                    return Err(A::Error::missing_field("typ"));
                }

                if !extra.is_empty() {
                    let extra = Value::deserialized::<Extra>(&Value::Map(extra)).map_err(A::Error::custom)?;
                    builder.extra(extra);
                }

                builder.build().map_err(|e| A::Error::custom(format!("Cannot build sd-protected: {e}")))
            }
        }

        deserializer.deserialize_map(SdProtectedVisitor::<Extra>(Default::default()))
    }
}

impl<Extra: CustomClaims> TryFrom<SdProtected<Extra>> for coset::Header {
    type Error = Box<dyn core::error::Error>;

    fn try_from(sdp: SdProtected<Extra>) -> Result<Self, Self::Error> {
        let mut builder = coset::HeaderBuilder::new();

        // map alg
        use coset::iana::EnumI64 as _;
        let alg = match *sdp.alg {
            coset::Algorithm::PrivateUse(i) => coset::iana::Algorithm::from_i64(i),
            coset::Algorithm::Assigned(i) => coset::iana::Algorithm::from_i64(i.to_i64()),
            _ => return Err("Only IANA registered or private use algorithms are supported".into()),
        }
        .ok_or_else::<Box<dyn core::error::Error>, _>(|| "Invalid IANA algorithm".into())?;
        builder = builder.algorithm(alg);

        // map extra claims
        if let Some(claims) = sdp
            .extra
            .map(|e| Value::serialized(&e))
            .transpose()?
            .map(|v| v.into_map().map_err(|_| "should have been a maping"))
            .transpose()?
        {
            for (k, v) in claims {
                builder = match k {
                    Value::Integer(i) => builder.value(i.try_into()?, v),
                    Value::Text(t) => builder.text_value(t, v),
                    _ => builder,
                }
            }
        }

        // map typ
        let builder = builder.value(CWT_MEDIATYPE, Value::Text(MEDIATYPE_SD_CWT.to_string()));

        Ok(builder.build())
    }
}
