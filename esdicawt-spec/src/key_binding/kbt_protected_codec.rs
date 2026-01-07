use ciborium::Value;
use coset::AsCborValue;
use serde::ser::SerializeMap;

use super::KbtProtected;
use crate::{
    COSE_HEADER_KCWT, CWT_CLAIM_ALG, CWT_MEDIA_TYPE, CustomClaims, CwtAny, MEDIA_TYPE_KB_CWT, Select, inlined_cbor::InlinedCbor, issuance::SdCwtIssuedTagged,
    key_binding::KbtProtectedBuilder,
};

impl<IssuerPayloadClaims: Select, Hasher: digest::Digest + Clone, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, Extra: CustomClaims> serde::Serialize
    for KbtProtected<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let extras = self
            .extra
            .as_ref()
            .map(|extra| extra.to_cbor_value().map_err(S::Error::custom))
            .transpose()?
            .map(|v| v.into_map().map_err(|_| S::Error::custom("should have been a mapping")))
            .transpose()?
            .unwrap_or_default();

        let map_size = 3 + extras.len();
        let mut map = serializer.serialize_map(Some(map_size))?;

        map.serialize_entry(&CWT_MEDIA_TYPE, &MEDIA_TYPE_KB_CWT)?;

        let alg = (*self.alg).clone().to_cbor_value().map_err(|e| S::Error::custom(format!("Cannot set Alg: {e}")))?;
        map.serialize_entry(&CWT_CLAIM_ALG, &alg)?;

        map.serialize_entry(&COSE_HEADER_KCWT, &self.kcwt)?;

        for (k, v) in extras {
            map.serialize_entry(&k, &v)?;
        }

        map.end()
    }
}

impl<'de, IssuerPayloadClaims: Select, Hasher: digest::Digest + Clone, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, Extra: CustomClaims>
    serde::Deserialize<'de> for KbtProtected<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KbtProtectedVisitor<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>(
            std::marker::PhantomData<(IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra)>,
        );
        impl<'de, IssuerPayloadClaims: Select, Hasher: digest::Digest + Clone, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, Extra: CustomClaims>
            serde::de::Visitor<'de> for KbtProtectedVisitor<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>
        {
            type Value = KbtProtected<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a sd-protected CWT")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;
                let mut builder = KbtProtectedBuilder::<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>::default();
                let mut extra = vec![];
                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    match k {
                        Value::Integer(label) => match label.try_into() {
                            Ok(CWT_MEDIA_TYPE) => {
                                let media_type = v.into_integer().map_err(|_| A::Error::custom("SD-KBT media type MUST be a CoAP content format"))?;
                                if media_type != MEDIA_TYPE_KB_CWT.into() {
                                    return Err(A::Error::custom(format!("Invalid SD-KBT media-type, MUST be {MEDIA_TYPE_KB_CWT}")));
                                }
                            }
                            Ok(CWT_CLAIM_ALG) => {
                                builder.alg(coset::Algorithm::from_cbor_value(v).map_err(|e| A::Error::custom(format!("Cannot deserialize sd-protected.alg: {e}")))?);
                            }
                            Ok(COSE_HEADER_KCWT) => {
                                let issuer_sd_cwt: InlinedCbor<SdCwtIssuedTagged<_, _, _, _>> = v
                                    .deserialized()
                                    .map_err(|value| A::Error::custom(format!("'issuer-sd-cwt' is not a sd-cwt-presentation: {value:?}")))?;

                                builder.kcwt(issuer_sd_cwt);
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

                if !extra.is_empty() {
                    let extra = Value::deserialized::<Extra>(&Value::Map(extra)).map_err(A::Error::custom)?;
                    builder.extra(extra);
                }

                builder.build().map_err(|e| A::Error::custom(format!("Cannot build sd-protected: {e}")))
            }
        }

        deserializer.deserialize_map(KbtProtectedVisitor(Default::default()))
    }
}

impl<IssuerPayloadClaims: Select, Hasher: digest::Digest + Clone, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, Extra: CustomClaims>
    TryFrom<KbtProtected<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>> for coset::Header
{
    type Error = Box<dyn core::error::Error>;

    fn try_from(kbtp: KbtProtected<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>) -> Result<Self, Self::Error> {
        let mut builder = coset::HeaderBuilder::new();

        // map alg
        use coset::iana::EnumI64 as _;
        let alg = match *kbtp.alg {
            coset::Algorithm::PrivateUse(i) => coset::iana::Algorithm::from_i64(i),
            coset::Algorithm::Assigned(a) => coset::iana::Algorithm::from_i64(a.to_i64()),
            _ => return Err("Only IANA registered or private use algorithms are supported".into()),
        }
        .ok_or_else::<Box<dyn core::error::Error>, _>(|| "Invalid IANA algorithm".into())?;
        builder = builder.algorithm(alg);

        // map extra claims
        let extra = kbtp
            .extra
            .as_ref()
            .map(Value::serialized)
            .transpose()?
            .map(|v| v.into_map().map_err(|_| "should have been a mapping"))
            .transpose()?;
        if let Some(claims) = extra {
            for (k, v) in claims {
                builder = match k {
                    Value::Integer(i) => builder.value(i.try_into()?, v),
                    Value::Text(t) => builder.text_value(t, v),
                    _ => builder,
                }
            }
        }

        // map typ
        let builder = builder.value(CWT_MEDIA_TYPE, Value::Integer(MEDIA_TYPE_KB_CWT.into()));

        // map sd_cwt_issued in kcwt
        let builder = builder.value(COSE_HEADER_KCWT, kbtp.kcwt.to_cbor_value()?);

        Ok(builder.build())
    }
}
