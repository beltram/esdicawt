use rand_core::{CryptoRng, Error, RngCore};
use std::io::Write;

/// Salts used by the spec to generate the test vectors. Each row is `sha256(cbor([key, value])),salt`
pub const SALT_LIST: &str = include_str!("../../../draft-ietf-spice-sd-cwt/examples/salt_list.csv");

/// Salts used by the spec to generate the decoys. Each row is `decoy index,salt`
pub const DECOY_LIST: &str = include_str!("../../../draft-ietf-spice-sd-cwt/examples/decoy_list.csv");

/// The first row (0-indexed) of a list holding the salts of a range
#[derive(Debug, Clone, Copy)]
pub enum SaltSource {
    /// in "salt_list.csv"
    SaltList(usize),
    /// in "decoy_list.csv"
    DecoyList(usize),
}

use SaltSource::*;

/// Maps a range of [TestVectorRng] counter values (i.e. the n-th salt requested by the issuer) to the list and first
/// row holding the salts for this range
pub type SaltRanges = &'static [(core::ops::RangeInclusive<usize>, SaltSource)];

/// Salts for "issuer_cwt.cbor"
pub const NORMAL_SALT_RANGES: SaltRanges = &[
    // ctr 0..=4 => rows 13..=17
    // [salt, "ABCD-123456", 501], [salt, 1549560720], [salt, 1612560720], [salt, "ca", region], [salt, "94188", postal_code]
    (0..=4, SaltList(13)),
];

/// Salts for "nested_issuer_cwt.cbor". Inner disclosures are requested before the ones of the element containing them
pub const NESTED_SALT_RANGES: SaltRanges = &[
    // ctr 0..=2 => rows 29..=31
    // 1st inspection: [salt, "DCBA-101777", 501], [salt, "co", region], [salt, "80302", postal_code]
    (0..=2, SaltList(29)),
    // ctr 3..=4 => rows 1..=2
    // 1st inspection: [salt, {country, ..}] (inspection location), [salt, {500, 502, ..}] (array element)
    (3..=4, SaltList(1)),
    // ctr 5..=7 => rows 23..=25
    // 2nd inspection: [salt, "EFGH-789012", 501], [salt, "nv", region], [salt, "89155", postal_code]
    (5..=7, SaltList(23)),
    // ctr 8..=9 => rows 3..=4
    // 2nd inspection: [salt, {country, ..}] (inspection location), [salt, {500, 502, ..}] (array element)
    (8..=9, SaltList(3)),
    // ctr 10 => row 13 (same claim as the 1st disclosure of "issuer_cwt.cbor")
    // 3rd inspection: [salt, "ABCD-123456", 501]
    (10..=10, SaltList(13)),
    // ctr 11..=12 => rows 19..=20
    // 3rd inspection: [salt, "ca", region], [salt, "94188", postal_code]
    (11..=12, SaltList(19)),
    // ctr 13 => row 5
    // 3rd inspection: [salt, {country, ..}] (inspection location)
    (13..=13, SaltList(5)),
    // ctr 14 => row 0
    // 3rd inspection: [salt, {500, 502, ..}] (array element)
    (14..=14, SaltList(0)),
];

/// Salts for "decoy.cbor". Decoys are requested in the order they appear in the payload
pub const DECOY_SALT_RANGES: SaltRanges = &[
    // ctr 0 => row 36
    // [salt, "fr"] (country)
    (0..=0, SaltList(36)),
    // ctr 1 => decoy row 0
    // [salt] (decoy 1, in the countries array)
    (1..=1, DecoyList(0)),
    // ctr 2 => row 37
    // [salt, true, 500] (inspection result)
    (2..=2, SaltList(37)),
    // ctr 3 => decoy row 1
    // [salt] (decoy 2, in the payload)
    (3..=3, DecoyList(1)),
];

/// Deterministic RNG returning the salts of "salt_list.csv" and "decoy_list.csv" in the order they were used to
/// generate the spec's test vectors
pub struct TestVectorRng {
    ctr: usize,
    salts: Vec<Vec<u8>>,
    decoy_salts: Vec<Vec<u8>>,
    ranges: SaltRanges,
}

impl TestVectorRng {
    pub fn new(ranges: SaltRanges) -> Self {
        Self {
            ctr: 0,
            salts: Self::read_salts(SALT_LIST),
            decoy_salts: Self::read_salts(DECOY_LIST),
            ranges,
        }
    }

    /// Reads the salts in the last column of a csv list
    fn read_salts(list: &str) -> Vec<Vec<u8>> {
        list.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let (_, salt) = l.split_once(',').expect("malformed salt list row");
                hex::decode(salt.trim()).unwrap()
            })
            .collect()
    }

    fn next_salt(&mut self) -> &[u8] {
        let ctr = self.ctr;
        self.ctr += 1;
        let (range, source) = self
            .ranges
            .iter()
            .find(|(range, _)| range.contains(&ctr))
            .unwrap_or_else(|| panic!("no salt registered for counter {ctr}"));
        let (salts, first_row) = match source {
            SaltList(row) => (&self.salts, row),
            DecoyList(row) => (&self.decoy_salts, row),
        };
        let row = first_row + (ctr - range.start());
        salts.get(row).unwrap_or_else(|| panic!("no row {row} in {source:?}"))
    }
}

impl CryptoRng for TestVectorRng {}

impl RngCore for TestVectorRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        unimplemented!()
    }

    fn try_fill_bytes(&mut self, mut dest: &mut [u8]) -> Result<(), Error> {
        let salt = self.next_salt();
        assert_eq!(salt.len(), dest.len(), "salt length mismatch");
        let _ = dest.write(salt).unwrap();
        Ok(())
    }
}
