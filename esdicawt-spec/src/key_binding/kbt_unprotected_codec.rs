use crate::{CustomClaims, MapKey, key_binding::KeyBindingTokenUnprotected};

impl<E: CustomClaims> From<KeyBindingTokenUnprotected<E>> for coset::Header {
    fn from(kbtu: KeyBindingTokenUnprotected<E>) -> Self {
        let mut builder = coset::HeaderBuilder::new();

        // map extra claims
        if let Some(claims) = kbtu.claims.map(Into::into) {
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
