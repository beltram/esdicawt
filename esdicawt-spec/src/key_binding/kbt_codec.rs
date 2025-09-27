use ciborium::Value;
use serde::ser::SerializeSeq;

use super::{KbtCwt, KbtCwtBuilder};
use crate::{CustomClaims, Select};

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
> serde::Serialize for KbtCwt<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, PayloadClaims, ProtectedClaims, UnprotectedClaims>
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
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
> serde::Deserialize<'de> for KbtCwt<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, PayloadClaims, ProtectedClaims, UnprotectedClaims>
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KbtVisitor<
            IssuerPayloadClaims: Select,
            Hasher: digest::Digest + Clone,
            IssuerProtectedClaims: CustomClaims,
            IssuerUnprotectedClaims: CustomClaims,
            ProtectedClaims: CustomClaims,
            UnprotectedClaims: CustomClaims,
            PayloadClaims: CustomClaims,
        >(
            std::marker::PhantomData<(
                IssuerPayloadClaims,
                Hasher,
                IssuerProtectedClaims,
                IssuerUnprotectedClaims,
                ProtectedClaims,
                UnprotectedClaims,
                PayloadClaims,
            )>,
        );

        impl<
            'de,
            IssuerPayloadClaims: Select,
            Hasher: digest::Digest + Clone,
            IssuerProtectedClaims: CustomClaims,
            IssuerUnprotectedClaims: CustomClaims,
            ProtectedClaims: CustomClaims,
            UnprotectedClaims: CustomClaims,
            PayloadClaims: CustomClaims,
        > serde::de::Visitor<'de> for KbtVisitor<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, PayloadClaims, ProtectedClaims, UnprotectedClaims>
        {
            type Value = KbtCwt<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, PayloadClaims, ProtectedClaims, UnprotectedClaims>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a kbt payload")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                use serde::de::Error as _;

                let mut kbt_builder = KbtCwtBuilder::default();
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

                            kbt_builder.signature(bytes);
                        }
                        _ => break,
                    }

                    index += 1;
                }

                kbt_builder.build().map_err(|e| A::Error::custom(format!("Cannot build kbt: {e}")))
            }
        }

        deserializer.deserialize_seq(KbtVisitor(Default::default()))
    }
}
