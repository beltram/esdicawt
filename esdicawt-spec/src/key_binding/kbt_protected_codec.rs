use ciborium::Value;
use coset::AsCborValue;
use serde::ser::SerializeMap;

use super::KeyBindingTokenProtected;
use crate::inlined_cbor::InlinedCbor;
use crate::issuance::SelectiveDisclosureIssuedTagged;
use crate::{AnyMap, COSE_HEADER_KCWT, CWT_CLAIM_ALG, CWT_MEDIATYPE, ClaimName, CustomClaims, MEDIATYPE_KB_CWT, MapKey, key_binding::KeyBindingTokenProtectedBuilder};

impl<IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, IssuerPayloadClaims: CustomClaims, E: CustomClaims, DisclosedClaims: CustomClaims> serde::Serialize
    for KeyBindingTokenProtected<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, E, DisclosedClaims>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let mut extra: Option<AnyMap> = self.claims.clone().map(E::into);
        let extra_len = extra.as_ref().map(|extra| extra.len()).unwrap_or_default();
        let mut map = serializer.serialize_map(Some(3 + extra_len))?;
        map.serialize_entry(&CWT_MEDIATYPE, MEDIATYPE_KB_CWT)?;

        let alg = (*self.alg).clone().to_cbor_value().map_err(|e| S::Error::custom(format!("Cannot set Alg: {e}")))?;
        map.serialize_entry(&CWT_CLAIM_ALG, &alg)?;

        map.serialize_entry(&COSE_HEADER_KCWT, &self.issuer_sd_cwt)?;

        if let Some(extra) = extra.take() {
            for (k, v) in extra {
                map.serialize_entry(&k, &v)?;
            }
        }

        map.end()
    }
}

impl<'de, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, IssuerPayloadClaims: CustomClaims, E: CustomClaims, DisclosedClaims: CustomClaims>
    serde::Deserialize<'de> for KeyBindingTokenProtected<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, E, DisclosedClaims>
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KbtProtectedVisitor<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, E, DisclosedClaims>(
            std::marker::PhantomData<(IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, E, DisclosedClaims)>,
        );
        impl<'de, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, IssuerPayloadClaims: CustomClaims, E: CustomClaims, DisclosedClaims: CustomClaims>
            serde::de::Visitor<'de> for KbtProtectedVisitor<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, E, DisclosedClaims>
        {
            type Value = KeyBindingTokenProtected<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, E, DisclosedClaims>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a sd-protected CWT")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde::de::Error as _;
                let mut found_mediatype = false;
                let mut builder = KeyBindingTokenProtectedBuilder::<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, E, DisclosedClaims>::default();
                let mut extra = AnyMap::default();
                while let Some((k, v)) = map.next_entry::<MapKey, Value>()? {
                    match k {
                        ClaimName::Integer(int_claim) => match int_claim {
                            // Ignore, but it must be there and have the correct value
                            CWT_MEDIATYPE => {
                                found_mediatype = v.into_text().map(|s| s == MEDIATYPE_KB_CWT).unwrap_or_default();
                            }
                            CWT_CLAIM_ALG => {
                                builder.alg(coset::Algorithm::from_cbor_value(v).map_err(|e| A::Error::custom(format!("Cannot deserialize sd-protected.alg: {e}")))?);
                            }
                            COSE_HEADER_KCWT => {
                                let issuer_sd_cwt: InlinedCbor<SelectiveDisclosureIssuedTagged<_, _, _, _>> = v
                                    .deserialized()
                                    .map_err(|value| A::Error::custom(format!("'issuer-sd-cwt' is not a sd-cwt-presentation: {value:?}")))?;

                                builder.issuer_sd_cwt(issuer_sd_cwt);
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
                    builder.claims(custom_keys);
                }

                builder.build().map_err(|e| A::Error::custom(format!("Cannot build sd-protected: {e}")))
            }
        }

        deserializer.deserialize_map(KbtProtectedVisitor(Default::default()))
    }
}

impl<IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, IssuerPayloadClaims: CustomClaims, E: CustomClaims, DisclosedClaims: CustomClaims>
    TryFrom<KeyBindingTokenProtected<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, E, DisclosedClaims>> for coset::Header
{
    type Error = Box<dyn std::error::Error>;

    fn try_from(kbtp: KeyBindingTokenProtected<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, E, DisclosedClaims>) -> Result<Self, Self::Error> {
        let mut builder = coset::HeaderBuilder::new();

        // map alg
        use coset::iana::EnumI64 as _;
        let alg = match *kbtp.alg {
            coset::Algorithm::PrivateUse(i) => coset::iana::Algorithm::from_i64(i),
            coset::Algorithm::Assigned(a) => coset::iana::Algorithm::from_i64(a.to_i64()),
            _ => return Err("Only IANA registered or private use algorithms are supported".into()),
        }
        .ok_or_else::<Box<dyn std::error::Error>, _>(|| "Invalid IANA algorithm".into())?;
        builder = builder.algorithm(alg);

        // map extra claims
        if let Some(claims) = kbtp.claims.map(Into::into) {
            for (k, v) in claims {
                builder = match k {
                    MapKey::Integer(i) => builder.value(i, v),
                    MapKey::Text(t) => builder.text_value(t, v),
                    _ => builder,
                }
            }
        }

        // map typ
        let builder = builder.value(CWT_MEDIATYPE, Value::Text(MEDIATYPE_KB_CWT.to_string()));

        // map sd_cwt_issued in kcwt
        let builder = builder.value(COSE_HEADER_KCWT, Value::serialized(&kbtp.issuer_sd_cwt)?);

        Ok(builder.build())
    }
}
