use crate::{SdCwtHolderError, SdCwtHolderResult, holder::params::CborPath};
use ciborium::Value;
use digest::Digest;
use esdicawt_spec::{
    CWT_LABEL_REDACTED_KEYS, CwtAny, REDACTED_CLAIM_ELEMENT_TAG,
    blinded_claims::{Salted, SaltedArray, SaltedClaim, SaltedElement},
};

type PathAndSalted = Vec<(Vec<CborPath>, Salted<Value>)>;
type PathAndSaltedAndDigest = Vec<(Vec<CborPath>, Salted<Value>, Vec<u8>)>;

/// TODO: very inefficient implementation, disclosures are traversed many times, hashes are computed many times.
/// Will be easier when we have semantics for order of disclosures
pub fn traverse_disclosures<Hasher: Digest, E>(disclosures: &SaltedArray) -> SdCwtHolderResult<PathAndSalted, E>
where
    E: core::error::Error + Send + Sync,
{
    let mut paths = vec![];
    for salted in disclosures.iter_clone().filter_map(Result::ok) {
        _traverse::<Hasher, _>(SaltedOrValue::Salted(salted), vec![], disclosures, &mut paths)?;
    }
    let paths = paths.into_iter().map(|(p, s, _)| (p, s)).collect();
    Ok(paths)
}

// wrapping "_traverse" is required for fallible recursion
fn _traverse<Hasher: Digest, E>(salted: SaltedOrValue, current: Vec<CborPath>, disclosures: &SaltedArray, paths: &mut PathAndSaltedAndDigest) -> SdCwtHolderResult<(), E>
where
    E: core::error::Error + Send + Sync,
{
    __traverse::<Hasher, _>(salted, current, disclosures, paths)
}

#[tailcall::tailcall]
fn __traverse<Hasher: Digest, E>(
    salted_or_value: SaltedOrValue,
    mut current: Vec<CborPath>,
    disclosures: &SaltedArray,
    paths: &mut PathAndSaltedAndDigest,
) -> SdCwtHolderResult<(), E>
where
    E: core::error::Error + Send + Sync,
{
    let find_hash = |hash: &[u8]| {
        disclosures
            .0
            .iter()
            .find(|h| h.clone_bytes().map(|b| Hasher::digest(b).to_vec() == hash).unwrap_or_default())
    };
    match &salted_or_value {
        SaltedOrValue::Salted(salted) => {
            let digest = Hasher::digest(&salted.to_cbor_bytes()?).to_vec();
            let previous_depth = paths.iter().find_map(|(p, _, d)| (d == &digest).then_some(p.len()));
            let retract_previous = previous_depth.map(|prev| prev <= current.len()).unwrap_or_default();
            let insert = previous_depth.is_none() || previous_depth.map(|prev| current.len() >= prev).unwrap_or_default() || retract_previous;

            match salted {
                Salted::Claim(SaltedClaim { value, .. }) | Salted::Element(SaltedElement { value, .. }) if value.is_map() || value.is_array() => {
                    if let Salted::Claim(SaltedClaim { name, .. }) = salted {
                        current.push(name.into());
                    }
                    if retract_previous {
                        paths.retain(|(_, _, d)| d != &digest);
                    }
                    if insert {
                        paths.push((current.clone(), salted.clone(), digest));
                    }

                    let values = match value {
                        Value::Array(values) => values.iter().enumerate().map(|(i, v)| (i, None, v)).collect::<Vec<_>>(),
                        Value::Map(values) => values.iter().enumerate().map(|(i, (k, v))| (i, Some(k), v)).collect::<Vec<_>>(),
                        _ => unreachable!(),
                    };

                    for (index, label, value) in values {
                        match (label, value) {
                            // rcks in a mapping
                            (Some(Value::Simple(st)), Value::Array(hashes)) if *st == CWT_LABEL_REDACTED_KEYS => {
                                let hashes = hashes.iter().filter_map(|h| h.as_bytes()).collect::<Vec<_>>();
                                for hash in hashes {
                                    if let Some(salted_child) = find_hash(hash) {
                                        let salted = salted_child.clone_value()?;
                                        _traverse::<Hasher, E>(SaltedOrValue::Salted(salted), current.clone(), disclosures, paths)?;
                                    }
                                }
                            }
                            // redacted in an array
                            (None, Value::Tag(tag, value)) if *tag == REDACTED_CLAIM_ELEMENT_TAG => {
                                let Some(hash) = value.as_bytes() else {
                                    return Err(SdCwtHolderError::<E>::ImplementationError("Invalid redacted array element"));
                                };
                                if let Some(salted_child) = find_hash(hash) {
                                    current.push(CborPath::Index(index as u64));
                                    let salted = salted_child.clone_value()?;
                                    _traverse::<Hasher, E>(SaltedOrValue::Salted(salted), current.clone(), disclosures, paths)?;
                                    current.pop();
                                }
                            }
                            // complex in a mapping or array
                            (label, value) if value.is_map() || value.is_array() => {
                                let path = label.map(TryInto::try_into).transpose()?.unwrap_or(CborPath::Index(index as u64));
                                current.push(path);
                                _traverse::<Hasher, E>(SaltedOrValue::Value(value.clone()), current.clone(), disclosures, paths)?;
                                current.pop();
                            }
                            _ => {}
                        }
                    }
                }
                // leaf
                Salted::Claim(SaltedClaim { .. }) | Salted::Element(SaltedElement { .. }) => {
                    if let Salted::Claim(SaltedClaim { name, .. }) = salted {
                        current.push(name.into());
                    }
                    if retract_previous {
                        paths.retain(|(_, _, d)| d != &digest);
                    }
                    if insert || retract_previous {
                        paths.push((current.clone(), salted.clone(), digest));
                    }
                }
                // ignored
                Salted::Decoy(_) => {}
            }
        }
        SaltedOrValue::Value(Value::Map(values)) => {
            for (label, value) in values {
                match (label, value) {
                    (Value::Simple(st), Value::Array(hashes)) if *st == CWT_LABEL_REDACTED_KEYS => {
                        let hashes = hashes.iter().filter_map(|h| h.as_bytes()).collect::<Vec<_>>();
                        for hash in hashes {
                            if let Some(salted_child) = find_hash(hash) {
                                let salted = salted_child.clone_value()?;
                                _traverse::<Hasher, E>(SaltedOrValue::Salted(salted), current.clone(), disclosures, paths)?;
                            }
                        }
                    }
                    (_, value) if value.is_map() || value.is_array() => {
                        current.push(label.try_into()?);
                        _traverse::<Hasher, E>(SaltedOrValue::Value(value.clone()), current.clone(), disclosures, paths)?;
                        current.pop();
                    }
                    _ => {}
                }
            }
        }
        SaltedOrValue::Value(Value::Array(values)) => {
            for (index, value) in values.iter().enumerate() {
                match value {
                    Value::Tag(tag, hash) if *tag == REDACTED_CLAIM_ELEMENT_TAG => {
                        let Some(hash) = hash.as_bytes() else {
                            return Err(SdCwtHolderError::<E>::ImplementationError("Invalid redacted array element"));
                        };
                        if let Some(salted_child) = find_hash(hash) {
                            let salted = salted_child.clone_value()?;
                            current.push(CborPath::Index(index as u64));
                            _traverse::<Hasher, E>(SaltedOrValue::Salted(salted), current.clone(), disclosures, paths)?;
                            current.pop();
                        }
                    }
                    value if value.is_map() || value.is_array() => {
                        current.push(CborPath::Index(index as u64));
                        _traverse::<Hasher, E>(SaltedOrValue::Value(value.clone()), current.clone(), disclosures, paths)?;
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
enum SaltedOrValue {
    Salted(Salted<Value>),
    Value(Value),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::salted;
    use ciborium::{Value, Value::Simple, cbor, tag::Required};
    use esdicawt_spec::{
        Salt,
        blinded_claims::{SaltedClaimRef, SaltedElementRef, SaltedRef},
    };
    use sha2::Sha256;

    #[test]
    fn tstr() {
        let [a] = traverse([salted!("a", 1)]);
        assert_eq!(a, vec![CborPath::Str("a".into())]);
    }

    #[test]
    fn int() {
        let [zero] = traverse([salted!(0, 1)]);
        assert_eq!(zero, vec![CborPath::Int(0)]);
    }

    #[test]
    fn many_simple() {
        let [zero, a, one, b] = traverse([salted!(0, 1), salted!("a", 1), salted!(1, 1), salted!("b", 1)]);
        assert_eq!(zero, vec![CborPath::Int(0)]);
        assert_eq!(a, vec![CborPath::Str("a".into())]);
        assert_eq!(one, vec![CborPath::Int(1)]);
        assert_eq!(b, vec![CborPath::Str("b".into())]);
    }

    #[test]
    fn mapping() {
        let [map, a] = traverse([
            salted!(obj => "map", cbor!({
                "c" => "d",
                Simple(59) => [salted!(digest => "a", cbor!(1))],
            })),
            salted!("a", 1),
        ]);
        assert_eq!(map, vec![CborPath::Str("map".into())]);
        assert_eq!(a, vec![CborPath::Str("map".into()), CborPath::Str("a".into())]);
    }

    #[test]
    fn mapping_reversed_order() {
        let [map, a] = traverse([
            salted!("a", 1),
            salted!(obj => "map", cbor!({
                Simple(59) => [salted!(digest => "a", cbor!(1))],
            })),
        ]);
        assert_eq!(map, vec![CborPath::Str("map".into())]);
        assert_eq!(a, vec![CborPath::Str("map".into()), CborPath::Str("a".into())]);
    }

    #[test]
    fn mapping_many_claims() {
        let [map, a, b] = traverse([
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
        assert_eq!(map, vec![CborPath::Str("map".into())]);
        assert_eq!(a, vec![CborPath::Str("map".into()), CborPath::Str("a".into())]);
        assert_eq!(b, vec![CborPath::Str("map".into()), CborPath::Str("b".into())]);
    }

    #[test]
    fn mapping_nested_redacted_mapping() {
        let [map1, map2, a] = traverse([
            salted!(obj => "map1", cbor!({
                "c" => "d",
                Simple(59) => [salted!(digest => "map2", cbor!({Simple(59) => [salted!(digest => "a", cbor!(1))]}))],
            })),
            salted!(obj => "map2", cbor!({
                Simple(59) => [salted!(digest => "a", cbor!(1))],
            })),
            salted!("a", 1),
        ]);
        assert_eq!(map1, vec![CborPath::Str("map1".into())]);
        assert_eq!(map2, vec![CborPath::Str("map1".into()), CborPath::Str("map2".into())]);
        assert_eq!(a, vec![CborPath::Str("map1".into()), CborPath::Str("map2".into()), CborPath::Str("a".into())]);
    }

    #[test]
    fn mapping_nested_unredacted_mapping() {
        let [map, a, b] = traverse([
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
        assert_eq!(map, vec![CborPath::Str("map".into())]);
        assert_eq!(a, vec![CborPath::Str("map".into()), CborPath::Str("wrap1".into()), CborPath::Str("a".into())]);
        assert_eq!(b, vec![CborPath::Str("map".into()), CborPath::Str("wrap2".into()), CborPath::Str("b".into())]);
    }

    #[test]
    fn mapping_nested_unredacted_nested_unredacted_mapping() {
        let [map, a] = traverse([
            salted!(obj => "map", cbor!({
                "wrap1" => {
                    "wrap2" => {
                        Simple(59) => [salted!(digest => "a", cbor!(1))]
                    }
                }
            })),
            salted!("a", 1),
        ]);
        assert_eq!(map, vec![CborPath::Str("map".into())]);
        assert_eq!(
            a,
            vec![
                CborPath::Str("map".into()),
                CborPath::Str("wrap1".into()),
                CborPath::Str("wrap2".into()),
                CborPath::Str("a".into())
            ]
        );
    }

    #[test]
    fn array() {
        let [array, a] = traverse([
            salted!(obj => "array", cbor!([
                Required::<_, 60>(salted!(digest => cbor!("a"))),
            ])),
            salted!("a"),
        ]);
        assert_eq!(array, vec![CborPath::Str("array".into())]);
        assert_eq!(a, vec![CborPath::Str("array".into()), CborPath::Index(0)]);
    }

    #[test]
    fn array_reverse_order() {
        let [array, a] = traverse([
            salted!("a"),
            salted!(obj => "array", cbor!([
                Required::<_, 60>(salted!(digest => cbor!("a"))),
            ])),
        ]);
        assert_eq!(array, vec![CborPath::Str("array".into())]);
        assert_eq!(a, vec![CborPath::Str("array".into()), CborPath::Index(0)]);
    }

    #[test]
    fn array_many_elements() {
        let [array, a, b] = traverse([
            salted!(obj => "array", cbor!([
                Required::<_, 60>(salted!(digest => cbor!("a"))),
                Required::<_, 60>(salted!(digest => cbor!("b"))),
            ])),
            salted!("a"),
            salted!("b"),
        ]);
        assert_eq!(array, vec![CborPath::Str("array".into())]);
        assert_eq!(a, vec![CborPath::Str("array".into()), CborPath::Index(0)]);
        assert_eq!(b, vec![CborPath::Str("array".into()), CborPath::Index(1)]);
    }

    #[test]
    fn array_nested_redacted_array() {
        let [array1, array2, a] = traverse([
            salted!(obj => "array", cbor!([
                Required::<_, 60>(salted!(digest => cbor!([
                    Required::<_, 60>(salted!(digest => cbor!("a")))
                ]))),
            ])),
            salted!(obj => cbor!([
                Required::<_, 60>(salted!(digest => cbor!("a")))
            ])),
            salted!("a"),
        ]);
        assert_eq!(array1, vec![CborPath::Str("array".into())]);
        assert_eq!(array2, vec![CborPath::Str("array".into()), CborPath::Index(0)]);
        assert_eq!(a, vec![CborPath::Str("array".into()), CborPath::Index(0), CborPath::Index(0)]);
    }

    #[test]
    fn array_nested_unredacted_array() {
        let [array, a, b, c] = traverse([
            salted!(obj => "array", cbor!([
                [
                    Required::<_, 60>(salted!(digest => cbor!("a"))),
                    Required::<_, 60>(salted!(digest => cbor!("b"))),
                ],
                [
                    Required::<_, 60>(salted!(digest => cbor!("c"))),
                ],
            ])),
            salted!("a"),
            salted!("b"),
            salted!("c"),
        ]);
        assert_eq!(array, vec![CborPath::Str("array".into())]);
        assert_eq!(a, vec![CborPath::Str("array".into()), CborPath::Index(0), CborPath::Index(0)]);
        assert_eq!(b, vec![CborPath::Str("array".into()), CborPath::Index(0), CborPath::Index(1)]);
        assert_eq!(c, vec![CborPath::Str("array".into()), CborPath::Index(1), CborPath::Index(0)]);
    }

    #[test]
    fn array_nested_unredacted_nested_unredacted_array() {
        let [array, a] = traverse([
            salted!(obj => "array", cbor!([
                [
                    [
                        Required::<_, 60>(salted!(digest => cbor!("a"))),
                    ]
                ]
            ])),
            salted!("a"),
        ]);
        assert_eq!(array, vec![CborPath::Str("array".into())]);
        assert_eq!(a, vec![CborPath::Str("array".into()), CborPath::Index(0), CborPath::Index(0), CborPath::Index(0)]);
    }

    #[test]
    fn array_nested_redacted_mapping() {
        let [array, map, a] = traverse([
            salted!(obj => "array", cbor!([
                Required::<_, 60>(salted!(digest => cbor!({
                    Simple(59) => [salted!(digest => "a", cbor!(1))]
                }))),
            ])),
            salted!(obj => cbor!({
                Simple(59) => [salted!(digest => "a", cbor!(1))],
            })),
            salted!("a", 1),
        ]);
        assert_eq!(array, vec![CborPath::Str("array".into())]);
        assert_eq!(map, vec![CborPath::Str("array".into()), CborPath::Index(0)]);
        assert_eq!(a, vec![CborPath::Str("array".into()), CborPath::Index(0), CborPath::Str("a".into())]);
    }

    #[test]
    fn array_nested_unredacted_mapping() {
        let [array, a] = traverse([
            salted!(obj => "array", cbor!([
                {
                    "c" => "d",
                    Simple(59) => [salted!(digest => "a", cbor!(1))]
                }
            ])),
            salted!("a", 1),
        ]);
        assert_eq!(array, vec![CborPath::Str("array".into())]);
        assert_eq!(a, vec![CborPath::Str("array".into()), CborPath::Index(0), CborPath::Str("a".into())]);
    }

    fn traverse<const N: usize>(disclosures: [SaltedRef<Value>; N]) -> [Vec<CborPath>; N] {
        let mut d = SaltedArray::with_capacity(0);
        for s in disclosures {
            d.push_ref(s).unwrap();
        }

        let traversed = traverse_disclosures::<Sha256, core::convert::Infallible>(&d).unwrap();
        let paths = traversed.into_iter().map(|(p, _)| p).collect::<Vec<_>>();
        let size = paths.len();
        paths.try_into().unwrap_or_else(|_| panic!("Expected {N} got {size}"))
    }

    #[macro_export]
    macro_rules! salted {
        // salted claim of a simple type
        ($name:literal, $value:expr) => {
            SaltedRef::Claim(SaltedClaimRef {
                salt: Salt::empty(),
                name: &$name.clone().into(),
                value: &$value.into(),
            })
        };
        // salted claim where the value is a mapping or an array
        (obj => $name:literal, $value:expr) => {
            SaltedRef::Claim(SaltedClaimRef {
                salt: Salt::empty(),
                name: &$name.clone().into(),
                value: &$value.unwrap(),
            })
        };
        // salted element of a simple type
        ($value:expr) => {
            SaltedRef::Element(SaltedElementRef {
                salt: Salt::empty(),
                value: &$value.into(),
            })
        };
        // salted element where the value is a mapping or an array
        (obj => $value:expr) => {
            SaltedRef::Element(SaltedElementRef {
                salt: Salt::empty(),
                value: &$value.unwrap(),
            })
        };
        // digest of a salted claim
        (digest => $name:literal, $value:expr) => {
            Value::Bytes(
                Sha256::digest(
                    Value::serialized(&SaltedRef::Claim(SaltedClaimRef {
                        salt: Salt::empty(),
                        name: &$name.clone().into(),
                        value: &$value.unwrap(),
                    }))
                    .unwrap()
                    .to_cbor_bytes()
                    .unwrap(),
                )
                .to_vec(),
            )
        };
        // digest of a salted element
        (digest => $value:expr) => {
            Value::Bytes(
                Sha256::digest(
                    Value::serialized(&SaltedRef::Element(SaltedElementRef {
                        salt: Salt::empty(),
                        value: &$value.unwrap(),
                    }))
                    .unwrap()
                    .to_cbor_bytes()
                    .unwrap(),
                )
                .to_vec(),
            )
        };
    }
}
