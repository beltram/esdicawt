use crate::{
    SdCwtHolderError, SdCwtHolderResult,
    holder::params::CborPath,
    spec::{
        CWT_LABEL_REDACTED_TAG, REDACTED_CLAIM_ELEMENT_TAG,
        blinded_claims::{SaltedArrayWithDigests, SaltedClaim, SaltedElement, SaltedEntry},
        redacted_claims::ToRedacted,
    },
};
use ciborium::Value;
use digest::Digest;
use std::borrow::Cow;

type PathAndSalted = Vec<(Vec<CborPath>, SaltedEntry<Value>)>;
type PathAndSaltedAndDigest = Vec<(Vec<CborPath>, SaltedEntry<Value>, Vec<u8>)>;

/// Given disclosures, this method returns all the possible paths one can build from it
// FIXME: this does not work for orphan disclosures, not anchored at the root of the payload
pub fn traverse_all_cbor_paths_in_disclosures<Hasher: Digest, E>(hashed_disclosures: &SaltedArrayWithDigests<'_>) -> SdCwtHolderResult<PathAndSalted, E>
where
    E: core::error::Error + Send + Sync,
{
    // there are at least as many paths in the ClaimSet as there are disclosures, small optimization
    let mut paths = Vec::with_capacity(hashed_disclosures.len());

    for salted in hashed_disclosures.values() {
        __traverse::<Hasher, _>(&salted.into(), vec![], hashed_disclosures, &mut paths)?;
    }
    Ok(paths.into_iter().map(|(p, s, _)| (p, s)).collect())
}

#[tailcall::tailcall]
fn __traverse<'a, Hasher: Digest, E>(
    salted_or_value: &'a SaltedOrValue<'a>,
    mut current: Vec<CborPath>,
    disclosures: &SaltedArrayWithDigests<'_>,
    paths: &mut PathAndSaltedAndDigest,
) -> SdCwtHolderResult<(), E>
where
    E: core::error::Error + Send + Sync,
{
    match salted_or_value {
        SaltedOrValue::Salted(salted) => {
            let digest = salted.to_redacted::<Hasher>()?.to_vec();
            let previous_depth = paths.iter().find_map(|(p, _, d)| (d == &digest).then_some(p.len()));
            let retract_previous = previous_depth.map(|prev| prev <= current.len()).unwrap_or_default();
            let insert = previous_depth.is_none() || previous_depth.map(|prev| current.len() >= prev).unwrap_or_default() || retract_previous;

            match &**salted {
                SaltedEntry::Claim(SaltedClaim { value, .. }) | SaltedEntry::Element(SaltedElement { value, .. }) if value.is_map() || value.is_array() => {
                    if let SaltedEntry::Claim(SaltedClaim { name, .. }) = &**salted {
                        current.push(name.into());
                    }
                    if retract_previous {
                        paths.retain(|(_, _, d)| d != &digest);
                    }
                    if insert {
                        let salted = match salted {
                            Cow::Borrowed(s) => (*s).clone(),
                            Cow::Owned(s) => s.clone(),
                        };
                        paths.push((current.clone(), salted, digest));
                    }

                    let mut traverse_salted_collection = |index: usize, label: Option<&Value>, value: &Value| {
                        match (label, value) {
                            // rcks in a mapping
                            (Some(Value::Simple(CWT_LABEL_REDACTED_TAG)), Value::Array(hashes)) => {
                                let hashes = hashes.iter().filter_map(|h| h.as_bytes()).collect::<Vec<_>>();
                                for hash in hashes {
                                    if let Some(salted_child) = disclosures.get(hash) {
                                        __traverse::<Hasher, E>(&salted_child.into(), current.clone(), disclosures, paths)?;
                                    }
                                }
                            }
                            // redacted in an array
                            (None, Value::Tag(REDACTED_CLAIM_ELEMENT_TAG, value)) => {
                                let Some(hash) = value.as_bytes() else {
                                    return Err(SdCwtHolderError::<E>::ImplementationError("Invalid redacted array element"));
                                };
                                if let Some(salted_child) = disclosures.get(hash) {
                                    current.push(CborPath::Index(index as u64));
                                    __traverse::<Hasher, E>(&salted_child.into(), current.clone(), disclosures, paths)?;
                                    current.pop();
                                }
                            }
                            // complex in a mapping or array
                            (label, value) if value.is_map() || value.is_array() => {
                                let path = label.map(TryInto::try_into).transpose()?.unwrap_or(CborPath::Index(index as u64));
                                current.push(path);
                                __traverse::<Hasher, E>(&value.into(), current.clone(), disclosures, paths)?;
                                current.pop();
                            }
                            _ => {}
                        }
                        Ok(())
                    };

                    match value {
                        Value::Array(values) => {
                            for (index, value) in values.iter().enumerate() {
                                traverse_salted_collection(index, None, value)?;
                            }
                        }
                        Value::Map(values) => {
                            for (index, (label, value)) in values.iter().enumerate() {
                                traverse_salted_collection(index, Some(label), value)?;
                            }
                        }
                        _ => return Err(SdCwtHolderError::ImplementationError("Traverse impl error. Should be either Map or Array")),
                    };
                }
                // leaf
                SaltedEntry::Claim(SaltedClaim { .. }) | SaltedEntry::Element(SaltedElement { .. }) => {
                    if let SaltedEntry::Claim(SaltedClaim { name, .. }) = &**salted {
                        current.push(name.into());
                    }
                    if retract_previous {
                        paths.retain(|(_, _, d)| d != &digest);
                    }
                    if insert || retract_previous {
                        let salted = match salted {
                            Cow::Borrowed(s) => (*s).clone(),
                            Cow::Owned(s) => s.clone(),
                        };
                        paths.push((current.clone(), salted, digest));
                    }
                }
                // ignored
                SaltedEntry::Decoy(_) => {}
            }
        }
        SaltedOrValue::Value(Value::Map(values)) => {
            for (label, value) in values {
                match (label, value) {
                    (Value::Simple(st), Value::Array(hashes)) if *st == CWT_LABEL_REDACTED_TAG => {
                        let hashes = hashes.iter().filter_map(|h| h.as_bytes()).collect::<Vec<_>>();
                        for hash in hashes {
                            if let Some(salted_child) = disclosures.get(hash) {
                                __traverse::<Hasher, E>(&salted_child.into(), current.clone(), disclosures, paths)?;
                            }
                        }
                    }
                    (_, value) if value.is_map() || value.is_array() => {
                        current.push(label.try_into()?);
                        __traverse::<Hasher, E>(&value.into(), current.clone(), disclosures, paths)?;
                        current.pop();
                    }
                    _ => {}
                }
            }
        }
        SaltedOrValue::Value(Value::Array(values)) => {
            for (index, value) in values.iter().enumerate() {
                match value {
                    Value::Tag(REDACTED_CLAIM_ELEMENT_TAG, hash) => {
                        let Some(hash) = hash.as_bytes() else {
                            return Err(SdCwtHolderError::<E>::ImplementationError("Invalid redacted array element"));
                        };
                        if let Some(salted_child) = disclosures.get(hash) {
                            current.push(CborPath::Index(index as u64));
                            __traverse::<Hasher, E>(&salted_child.into(), current.clone(), disclosures, paths)?;
                            current.pop();
                        }
                    }
                    value if value.is_map() || value.is_array() => {
                        current.push(CborPath::Index(index as u64));
                        __traverse::<Hasher, E>(&value.into(), current.clone(), disclosures, paths)?;
                        current.pop();
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum SaltedOrValue<'a> {
    Salted(Cow<'a, SaltedEntry<Value>>),
    Value(&'a Value),
}

impl<'a> From<Cow<'a, SaltedEntry<Value>>> for SaltedOrValue<'a> {
    fn from(value: Cow<'a, SaltedEntry<Value>>) -> Self {
        Self::Salted(value)
    }
}

impl<'a> From<&'a Cow<'_, SaltedEntry<Value>>> for SaltedOrValue<'a> {
    fn from(value: &'a Cow<SaltedEntry<Value>>) -> Self {
        match value {
            Cow::Borrowed(value) => Self::Salted(Cow::Borrowed(value)),
            Cow::Owned(value) => Self::Salted(Cow::Owned(value.clone())),
        }
    }
}

impl<'a> From<&'a Value> for SaltedOrValue<'a> {
    fn from(value: &'a Value) -> Self {
        Self::Value(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        salted,
        spec::{
            Salt,
            blinded_claims::{SaltedArray, SaltedClaimRef, SaltedElementRef, SaltedEntryRef},
        },
    };
    use ciborium::{Value, Value::Simple, cbor, tag::RequireExact};
    use sha2::Sha256;

    #[test]
    fn tstr() {
        let [a] = find_cbor_paths([salted!("a", 1)]);
        assert_eq!(a, vec![CborPath::Str("a".into())]);
    }

    #[test]
    fn int() {
        let [zero] = find_cbor_paths([salted!(0, 1)]);
        assert_eq!(zero, vec![CborPath::Int(0)]);
    }

    #[test]
    fn many_simple() {
        let cbor_paths = find_cbor_paths([salted!(0, 1), salted!("a", 1), salted!(1, 1), salted!("b", 1)]);
        assert!(cbor_paths.contains(&vec![CborPath::Int(0)]));
        assert!(cbor_paths.contains(&vec![CborPath::Int(1)]));
        assert!(cbor_paths.contains(&vec![CborPath::Str("a".into())]));
        assert!(cbor_paths.contains(&vec![CborPath::Str("b".into())]));
    }

    #[test]
    fn mapping() {
        let paths = find_cbor_paths([
            salted!(obj => "map", cbor!({
                "c" => "d",
                Simple(59) => [salted!(digest => "a", cbor!(1))],
            })),
            salted!("a", 1),
        ]);
        assert!(paths.iter().any(|p| p == &[CborPath::Str("map".into())]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("map".into()), CborPath::Str("a".into())]));
    }

    #[test]
    fn mapping_reversed_order() {
        let paths = find_cbor_paths([
            salted!("a", 1),
            salted!(obj => "map", cbor!({
                Simple(59) => [salted!(digest => "a", cbor!(1))],
            })),
        ]);
        assert!(paths.iter().any(|p| p == &[CborPath::Str("map".into())]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("map".into()), CborPath::Str("a".into())]));
    }

    #[test]
    fn mapping_many_claims() {
        let paths = find_cbor_paths([
            salted!(obj => "map", cbor!({
                "c" => "d",
                Simple(59) => [
                    salted!(digest => "a", cbor!(1)),
                    salted!(digest => "b", cbor!(1))
                ],
            })),
            salted!("a", 1),
            salted!("b", 1),
        ]);
        assert!(paths.iter().any(|p| p == &[CborPath::Str("map".into())]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("map".into()), CborPath::Str("a".into())]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("map".into()), CborPath::Str("b".into())]));
    }

    #[test]
    fn mapping_nested_redacted_mapping() {
        let paths = find_cbor_paths([
            salted!(obj => "map1", cbor!({
                "c" => "d",
                Simple(59) => [salted!(digest => "map2", cbor!({Simple(59) => [salted!(digest => "a", cbor!(1))]}))],
            })),
            salted!(obj => "map2", cbor!({
                Simple(59) => [salted!(digest => "a", cbor!(1))],
            })),
            salted!("a", 1),
        ]);

        assert!(paths.iter().any(|p| p == &[CborPath::Str("map1".into())]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("map1".into()), CborPath::Str("map2".into())]));
        assert!(
            paths
                .iter()
                .any(|p| p == &[CborPath::Str("map1".into()), CborPath::Str("map2".into()), CborPath::Str("a".into())])
        );
    }

    #[test]
    fn mapping_nested_unredacted_mapping() {
        let paths = find_cbor_paths([
            salted!(obj => "map", cbor!({
                "wrap1" => {
                    Simple(59) => [salted!(digest => "a", cbor!(1))]
                },
                "wrap2" => {
                    Simple(59) => [salted!(digest => "b", cbor!(1))]
                },
            })),
            salted!("a", 1),
            salted!("b", 1),
        ]);
        assert!(paths.iter().any(|p| p == &[CborPath::Str("map".into())]));
        assert!(
            paths
                .iter()
                .any(|p| p == &[CborPath::Str("map".into()), CborPath::Str("wrap1".into()), CborPath::Str("a".into())])
        );
        assert!(
            paths
                .iter()
                .any(|p| p == &[CborPath::Str("map".into()), CborPath::Str("wrap2".into()), CborPath::Str("b".into())])
        );
    }

    #[test]
    fn mapping_nested_unredacted_nested_unredacted_mapping() {
        let paths = find_cbor_paths([
            salted!(obj => "map", cbor!({
                "wrap1" => {
                    "wrap2" => {
                        Simple(59) => [salted!(digest => "a", cbor!(1))]
                    }
                }
            })),
            salted!("a", 1),
        ]);
        assert!(paths.iter().any(|p| p == &[CborPath::Str("map".into())]));
        assert!(paths.iter().any(|p| p
            == &[
                CborPath::Str("map".into()),
                CborPath::Str("wrap1".into()),
                CborPath::Str("wrap2".into()),
                CborPath::Str("a".into())
            ]));
    }

    #[test]
    fn array() {
        let paths = find_cbor_paths([
            salted!(obj => "array", cbor!([
                RequireExact::<_, 60>(salted!(digest => cbor!("a"))),
                RequireExact::<_, 60>(salted!(digest => cbor!("b"))),
            ])),
            salted!("a"),
            salted!("b"),
        ]);
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into())]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(0)]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(1)]));
    }

    #[test]
    fn array_reverse_order() {
        let paths = find_cbor_paths([
            salted!("a"),
            salted!(obj => "array", cbor!([
                RequireExact::<_, 60>(salted!(digest => cbor!("a"))),
            ])),
        ]);
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into())]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(0)]));
    }

    #[test]
    fn array_many_elements() {
        let paths = find_cbor_paths([
            salted!(obj => "array", cbor!([
                RequireExact::<_, 60>(salted!(digest => cbor!("a"))),
                RequireExact::<_, 60>(salted!(digest => cbor!("b"))),
            ])),
            salted!("a"),
            salted!("b"),
        ]);
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into())]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(0)]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(1)]));
    }

    #[test]
    fn array_nested_redacted_array() {
        let paths = find_cbor_paths([
            salted!(obj => "array", cbor!([
                RequireExact::<_, 60>(salted!(digest => cbor!([
                    RequireExact::<_, 60>(salted!(digest => cbor!("a")))
                ]))),
            ])),
            salted!(obj => cbor!([
                RequireExact::<_, 60>(salted!(digest => cbor!("a")))
            ])),
            salted!("a"),
        ]);
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into())]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(0)]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(0), CborPath::Index(0)]));
    }

    #[test]
    fn array_nested_unredacted_array() {
        let paths = find_cbor_paths([
            salted!(obj => "array", cbor!([
                [
                    RequireExact::<_, 60>(salted!(digest => cbor!("a"))),
                    RequireExact::<_, 60>(salted!(digest => cbor!("b"))),
                ],
                [
                    RequireExact::<_, 60>(salted!(digest => cbor!("c"))),
                ],
            ])),
            salted!("a"),
            salted!("b"),
            salted!("c"),
        ]);
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into())]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(0), CborPath::Index(0)]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(0), CborPath::Index(1)]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(1), CborPath::Index(0)]));
    }

    #[test]
    fn array_nested_unredacted_nested_unredacted_array() {
        let paths = find_cbor_paths([
            salted!(obj => "array", cbor!([
                [
                    [
                        RequireExact::<_, 60>(salted!(digest => cbor!("a"))),
                    ]
                ]
            ])),
            salted!("a"),
        ]);
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into())]));
        assert!(
            paths
                .iter()
                .any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(0), CborPath::Index(0), CborPath::Index(0)])
        );
    }

    #[test]
    fn array_nested_redacted_mapping() {
        let paths = find_cbor_paths([
            salted!(obj => "array", cbor!([
                RequireExact::<_, 60>(salted!(digest => cbor!({
                    Simple(59) => [salted!(digest => "a", cbor!(1))]
                }))),
            ])),
            salted!(obj => cbor!({
                Simple(59) => [salted!(digest => "a", cbor!(1))],
            })),
            salted!("a", 1),
        ]);
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into())]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(0)]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(0), CborPath::Str("a".into())]));
    }

    #[test]
    fn array_nested_unredacted_mapping() {
        let paths = find_cbor_paths([
            salted!(obj => "array", cbor!([
                {
                    "c" => "d",
                    Simple(59) => [salted!(digest => "a", cbor!(1))]
                }
            ])),
            salted!("a", 1),
        ]);
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into())]));
        assert!(paths.iter().any(|p| p == &[CborPath::Str("array".into()), CborPath::Index(0), CborPath::Str("a".into())]));
    }

    fn find_cbor_paths<const N: usize>(disclosures: [SaltedEntryRef<Value>; N]) -> [Vec<CborPath>; N] {
        let mut d = SaltedArray::new();
        for s in disclosures {
            d.push_ref_bytes(s).unwrap();
        }
        let d = d.digested::<Sha256>().unwrap();

        let traversed = traverse_all_cbor_paths_in_disclosures::<Sha256, core::convert::Infallible>(&d).unwrap();
        let paths = traversed.into_iter().map(|(p, _)| p).collect::<Vec<_>>();
        let size = paths.len();
        paths.try_into().unwrap_or_else(|_| panic!("Expected {N} got {size}"))
    }

    #[macro_export]
    macro_rules! salted {
        // salted claim of a simple type
        ($name:literal, $value:expr) => {
            SaltedEntryRef::Claim(SaltedClaimRef {
                salt: Salt::empty(),
                name: &$name.clone().into(),
                value: &$value.into(),
            })
        };
        // salted claim where the value is a mapping or an array
        (obj => $name:literal, $value:expr) => {
            SaltedEntryRef::Claim(SaltedClaimRef {
                salt: Salt::empty(),
                name: &$name.clone().into(),
                value: &$value.unwrap(),
            })
        };
        // salted element of a simple type
        ($value:expr) => {
            SaltedEntryRef::Element(SaltedElementRef {
                salt: Salt::empty(),
                value: &$value.into(),
            })
        };
        // salted element where the value is a mapping or an array
        (obj => $value:expr) => {
            SaltedEntryRef::Element(SaltedElementRef {
                salt: Salt::empty(),
                value: &$value.unwrap(),
            })
        };
        // digest of a salted claim
        (digest => $name:literal, $value:expr) => {
            Value::Bytes(
                SaltedClaimRef {
                    salt: Salt::empty(),
                    name: &$name.clone().into(),
                    value: &$value.unwrap(),
                }
                .to_redacted::<Sha256>()
                .unwrap()
                .to_vec(),
            )
        };
        // digest of a salted element
        (digest => $value:expr) => {
            Value::Bytes(
                SaltedElementRef {
                    salt: Salt::empty(),
                    value: &$value.unwrap(),
                }
                .to_redacted::<Sha256>()
                .unwrap()
                .to_vec(),
            )
        };
    }
}
