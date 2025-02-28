use crate::{CustomClaims, MapKey, key_binding::KbtUnprotected};

impl<E: CustomClaims> From<KbtUnprotected<E>> for coset::Header {
    fn from(kbtu: KbtUnprotected<E>) -> Self {
        let mut builder = coset::HeaderBuilder::new();

        // map extra claims
        if let Some(claims) = kbtu.extra.map(Into::into) {
            for (k, v) in claims {
                builder = match k {
                    MapKey::Integer(i) => builder.value(i, v),
                    MapKey::Text(t) => builder.text_value(t, v),
                    _ => builder,
                }
            }
        }

        builder.build()
    }
}
