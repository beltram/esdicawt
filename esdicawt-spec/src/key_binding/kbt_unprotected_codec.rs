use crate::{CustomClaims, EsdicawtSpecError, key_binding::KbtUnprotected};
use ciborium::Value;

impl<Extra: CustomClaims> TryFrom<KbtUnprotected<Extra>> for coset::Header {
    type Error = EsdicawtSpecError;

    fn try_from(kbtu: KbtUnprotected<Extra>) -> Result<Self, Self::Error> {
        let mut builder = coset::HeaderBuilder::new();

        // map extra claims
        if let Some(claims) = kbtu.extra.as_ref().map(|e| Value::serialized(&e)).transpose()?.map(|v| v.into_map()).transpose()? {
            for (k, v) in claims {
                builder = match k {
                    Value::Integer(i) => builder.value(i.try_into()?, v),
                    Value::Text(t) => builder.text_value(t, v),
                    _ => builder,
                }
            }
        }

        Ok(builder.build())
    }
}
