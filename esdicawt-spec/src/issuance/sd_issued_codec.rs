use super::SdCwtIssued;
use crate::{CustomClaims, CwtAny, Select};
use ciborium::Value;

impl<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> serde::Serialize
    for SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ciborium::tag::RequireExact::<_, { <coset::CoseSign1 as coset::TaggedCborSerializable>::TAG }>(&[
            self.protected.to_cbor_value().map_err(serde::ser::Error::custom)?,
            self.sd_unprotected.to_cbor_value().map_err(serde::ser::Error::custom)?,
            self.payload.to_cbor_value().map_err(serde::ser::Error::custom)?,
            self.signature.to_cbor_value().map_err(serde::ser::Error::custom)?,
        ])
        .serialize(serializer)
    }
}

impl<'de, PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> serde::Deserialize<'de>
    for SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let tagged = <ciborium::tag::RequireExact<Value, { <coset::CoseSign1 as coset::TaggedCborSerializable>::TAG }> as serde::Deserialize>::deserialize(deserializer)?;
        let array = tagged.0.into_array().map_err(|e| D::Error::custom(format!("Invalid CoseSign1 structure: {e:?}")))?;

        let (mut protected, mut unprotected, mut payload, mut signature) = (None, None, None, None);
        for (index, element) in array.into_iter().enumerate() {
            match index {
                0 => {
                    let element_protected = element
                        .deserialized()
                        .map_err(|e| D::Error::custom(format!("Cannot deserialize element `protected`: {e}")))?;
                    protected = Some(element_protected);
                }
                1 => {
                    let element_unprotected = element
                        .deserialized()
                        .map_err(|e| D::Error::custom(format!("Cannot deserialize element `sd_unprotected`: {e}")))?;
                    unprotected = Some(element_unprotected);
                }
                2 => {
                    let element_payload = element.deserialized().map_err(|e| D::Error::custom(format!("Cannot deserialize element `payload`: {e}")))?;
                    payload = Some(element_payload);
                }
                3 => {
                    let bytes: serde_bytes::ByteBuf = element
                        .deserialized()
                        .map_err(|e| D::Error::custom(format!("Cannot deserialize element `signature`: {e}")))?;
                    signature = Some(bytes);
                }
                _ => return Err(D::Error::custom("Invalid SD-CWT, contains more parts than expected")),
            }
        }
        const CONTEXT: &str = "Cannot build sd-issued: ";
        Ok(Self {
            protected: crate::required_in(protected, CONTEXT, "protected")?,
            sd_unprotected: crate::required_in(unprotected, CONTEXT, "sd_unprotected")?,
            payload: crate::required_in(payload, CONTEXT, "payload")?,
            signature: crate::required_in(signature, CONTEXT, "signature")?,
            _marker: Default::default(),
        })
    }
}
