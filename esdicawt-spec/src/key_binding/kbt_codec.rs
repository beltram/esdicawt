use ciborium::Value;

use super::KbtCwt;
use crate::{CustomClaims, CwtAny, Select};

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
> serde::Serialize for KbtCwt<IssuerPayloadClaims, Hasher, PayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, ProtectedClaims, UnprotectedClaims>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ciborium::tag::RequireExact::<_, { <coset::CoseSign1 as coset::TaggedCborSerializable>::TAG }>(&[
            self.protected.to_cbor_value().map_err(serde::ser::Error::custom)?,
            self.unprotected.to_cbor_value().map_err(serde::ser::Error::custom)?,
            self.payload.to_cbor_value().map_err(serde::ser::Error::custom)?,
            self.signature.to_cbor_value().map_err(serde::ser::Error::custom)?,
        ])
        .serialize(serializer)
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
> serde::Deserialize<'de> for KbtCwt<IssuerPayloadClaims, Hasher, PayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, ProtectedClaims, UnprotectedClaims>
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
                _ => return Err(D::Error::custom("Invalid SD-KBT, contains more parts than expected")),
            }
        }
        const CONTEXT: &str = "Cannot build kbt: ";
        Ok(Self {
            protected: crate::required_in(protected, CONTEXT, "protected")?,
            unprotected: crate::required_in(unprotected, CONTEXT, "unprotected")?,
            payload: crate::required_in(payload, CONTEXT, "payload")?,
            signature: crate::required_in(signature, CONTEXT, "signature")?,
        })
    }
}
