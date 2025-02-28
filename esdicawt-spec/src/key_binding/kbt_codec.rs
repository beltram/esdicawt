use ciborium::Value;
use serde::ser::SerializeSeq;

use super::{KeyBindingToken, KeyBindingTokenBuilder};
use crate::CustomClaims;

impl<
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
    DisclosedClaims: CustomClaims,
> serde::Serialize for KeyBindingToken<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosedClaims>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(4))?;
        seq.serialize_element(&self.protected)?;
        seq.serialize_element(&self.unprotected)?;
        seq.serialize_element(&self.payload)?;
        seq.serialize_element(&serde_bytes::Bytes::new(&self.signature))?;
        seq.end()
    }
}

impl<
    'de,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
    DisclosedClaims: CustomClaims,
> serde::Deserialize<'de>
    for KeyBindingToken<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosedClaims>
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KbtVisitor<
            IssuerProtectedClaims: CustomClaims,
            IssuerUnprotectedClaims: CustomClaims,
            IssuerPayloadClaims: CustomClaims,
            ProtectedClaims: CustomClaims,
            UnprotectedClaims: CustomClaims,
            PayloadClaims: CustomClaims,
            DisclosedClaims: CustomClaims,
        >(
            std::marker::PhantomData<(
                IssuerProtectedClaims,
                IssuerUnprotectedClaims,
                IssuerPayloadClaims,
                ProtectedClaims,
                UnprotectedClaims,
                PayloadClaims,
                DisclosedClaims,
            )>,
        );

        impl<
            'de,
            IssuerProtectedClaims: CustomClaims,
            IssuerUnprotectedClaims: CustomClaims,
            IssuerPayloadClaims: CustomClaims,
            ProtectedClaims: CustomClaims,
            UnprotectedClaims: CustomClaims,
            PayloadClaims: CustomClaims,
            DisclosedClaims: CustomClaims,
        > serde::de::Visitor<'de>
            for KbtVisitor<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosedClaims>
        {
            type Value = KeyBindingToken<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosedClaims>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a kbt payload")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                use serde::de::Error as _;

                let mut kbt_builder = KeyBindingTokenBuilder::default();
                let mut index = 0u8;
                while let Some(element) = seq.next_element::<Value>()? {
                    match index {
                        0 => {
                            kbt_builder.protected(
                                element
                                    .deserialized()
                                    .map_err(|e| A::Error::custom(format!("Cannot deserialize element `protected`: {e}")))?,
                            );
                        }
                        1 => {
                            kbt_builder.unprotected(
                                element
                                    .deserialized()
                                    .map_err(|e| A::Error::custom(format!("Cannot deserialize element `unprotected`: {e}")))?,
                            );
                        }
                        2 => {
                            kbt_builder.payload(element.deserialized().map_err(|e| A::Error::custom(format!("Cannot deserialize element `payload`: {e}")))?);
                        }
                        3 => {
                            let bytes: serde_bytes::ByteBuf = element
                                .deserialized()
                                .map_err(|e| A::Error::custom(format!("Cannot deserialize element `signature`: {e}")))?;

                            kbt_builder.signature(bytes.into_vec());
                        }
                        _ => break,
                    }

                    index += 1;
                }

                kbt_builder
                    ._disclosed(Default::default())
                    .build()
                    .map_err(|e| A::Error::custom(format!("Cannot build kbt: {e}")))
            }
        }

        deserializer.deserialize_seq(KbtVisitor(Default::default()))
    }
}
