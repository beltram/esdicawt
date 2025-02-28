use ciborium::Value;
use coset::AsCborValue;
use serde::ser::SerializeMap;

use super::SdProtected;
use crate::{AnyMap, CWT_CLAIM_ALG, CWT_CLAIM_SD_ALG, CWT_MEDIATYPE, ClaimName, CustomClaims, MEDIATYPE_SD_CWT, MapKey, SdHashAlg, issuance::SdProtectedBuilder};

impl<E: CustomClaims> serde::Serialize for SdProtected<E> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let mut extra: Option<AnyMap> = self.extra.clone().map(|extra| extra.into());
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

impl<'de, E: CustomClaims> serde::Deserialize<'de> for SdProtected<E> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SdProtectedVisitor<E>(std::marker::PhantomData<E>);
        impl<'de, E: CustomClaims> serde::de::Visitor<'de> for SdProtectedVisitor<E> {
            type Value = SdProtected<E>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a sd-protected header")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde::de::Error as _;
                let mut found_mediatype = false;
                let mut builder = SdProtectedBuilder::<E>::default();
                let mut extra = AnyMap::default();
                while let Some((k, v)) = map.next_entry::<MapKey, Value>()? {
                    match k {
                        ClaimName::Integer(int_claim) => match int_claim {
                            // Ignore, but it must be there and have the correct value
                            CWT_MEDIATYPE => {
                                found_mediatype = v.into_text().map(|s| s == MEDIATYPE_SD_CWT).unwrap_or_default();
                            }
                            CWT_CLAIM_ALG => {
                                builder.alg(coset::Algorithm::from_cbor_value(v).map_err(|e| A::Error::custom(format!("Cannot deserialize sd-protected.alg: {e}")))?);
                            }
                            CWT_CLAIM_SD_ALG => {
                                builder.sd_alg(
                                    v.deserialized::<SdHashAlg>()
                                        .map_err(|value| A::Error::custom(format!("sd_alg is not a correct enum value: {value:?}")))?,
                                );
                            }
                            _ => {
                                extra.insert(k, v);
                            }
                        },
                        _ => {
                            extra.insert(k, v);
                        }
                    }
                }

                if !found_mediatype {
                    return Err(A::Error::missing_field("typ"));
                }

                if !extra.is_empty() {
                    let custom_keys: E = extra.try_into().map_err(|_err| A::Error::custom("Cannot deserialize custom keys".to_string()))?;
                    builder.extra(custom_keys);
                }

                builder.build().map_err(|e| A::Error::custom(format!("Cannot build sd-protected: {e}")))
            }
        }

        deserializer.deserialize_map(SdProtectedVisitor::<E>(Default::default()))
    }
}

impl<E: CustomClaims> TryFrom<SdProtected<E>> for coset::Header {
    type Error = Box<dyn std::error::Error>;

    fn try_from(sdp: SdProtected<E>) -> Result<Self, Self::Error> {
        let mut builder = coset::HeaderBuilder::new();

        // map alg
        use coset::iana::EnumI64 as _;
        let alg = match *sdp.alg {
            coset::Algorithm::PrivateUse(i) => coset::iana::Algorithm::from_i64(i),
            coset::Algorithm::Assigned(i) => coset::iana::Algorithm::from_i64(i.to_i64()),
            _ => return Err("Only IANA registered or private use algorithms are supported".into()),
        }
        .ok_or_else::<Box<dyn std::error::Error>, _>(|| "Invalid IANA algorithm".into())?;
        builder = builder.algorithm(alg);

        // map extra claims
        if let Some(claims) = sdp.extra.map(Into::into) {
            for (k, v) in claims {
                builder = match k {
                    MapKey::Integer(i) => builder.value(i, v),
                    MapKey::Text(t) => builder.text_value(t, v),
                    _ => builder,
                }
            }
        }

        // map typ
        let builder = builder.value(CWT_MEDIATYPE, Value::Text(MEDIATYPE_SD_CWT.to_string()));

        Ok(builder.build())
    }
}
