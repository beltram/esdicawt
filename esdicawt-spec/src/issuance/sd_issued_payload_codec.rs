use ciborium::Value;
use serde::ser::SerializeSeq;

use super::SelectiveDisclosureIssued;
use crate::{issuance::SelectiveDisclosureIssuedBuilder, CustomClaims};

impl<ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims, DisclosableClaims: CustomClaims> serde::Serialize
    for SelectiveDisclosureIssued<ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosableClaims>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(4))?;
        seq.serialize_element(&self.protected)?;
        seq.serialize_element(&self.sd_unprotected)?;
        seq.serialize_element(&self.payload)?;
        seq.serialize_element(&serde_bytes::Bytes::new(&self.signature))?;
        seq.end()
    }
}

impl<'de, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims, DisclosableClaims: CustomClaims> serde::Deserialize<'de>
    for SelectiveDisclosureIssued<ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosableClaims>
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SdIssuedVisitor<ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims, DisclosableClaims: CustomClaims>(
            std::marker::PhantomData<(ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosableClaims)>,
        );

        impl<'de, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims, DisclosableClaims: CustomClaims> serde::de::Visitor<'de>
            for SdIssuedVisitor<ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosableClaims>
        {
            type Value = SelectiveDisclosureIssued<ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosableClaims>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a sd-issued payload")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                use serde::de::Error as _;

                let mut issued_builder = SelectiveDisclosureIssuedBuilder::default();
                let mut index = 0u8;
                while let Some(element) = seq.next_element::<Value>()? {
                    match index {
                        0 => {
                            issued_builder.protected(
                                element
                                    .deserialized()
                                    .map_err(|e| A::Error::custom(format!("Cannot deserialize element `protected`: {e}")))?,
                            );
                        }
                        1 => {
                            issued_builder.sd_unprotected(
                                element
                                    .deserialized()
                                    .map_err(|e| A::Error::custom(format!("Cannot deserialize element `sd_unprotected`: {e}")))?,
                            );
                        }
                        2 => {
                            issued_builder.payload(element.deserialized().map_err(|e| A::Error::custom(format!("Cannot deserialize element `payload`: {e}")))?);
                        }
                        3 => {
                            let bytes: serde_bytes::ByteBuf = element
                                .deserialized()
                                .map_err(|e| A::Error::custom(format!("Cannot deserialize element `signature`: {e}")))?;

                            issued_builder.signature(bytes.into_vec());
                        }
                        _ => break,
                    }

                    index += 1;
                }

                issued_builder
                    ._disclosable(Default::default())
                    .build()
                    .map_err(|e| A::Error::custom(format!("Cannot build sd-issued: {e}")))
            }
        }

        deserializer.deserialize_seq(SdIssuedVisitor(Default::default()))
    }
}
