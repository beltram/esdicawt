use crate::{BitIndex, Status, StatusListResult};

#[derive(Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct Lst<S: Status = u8>(pub(crate) bytes::Bytes, pub(crate) core::marker::PhantomData<S>);

impl<S: Status> Default for Lst<S> {
    fn default() -> Self {
        Self(Default::default(), Default::default())
    }
}

impl<S: Status> Lst<S> {
    /// Create a new StatusList.
    /// Arguments:
    /// * nb_statuses: number of statuses this list should hold
    pub fn new(nb_statuses: usize) -> Self {
        let byte_capacity = crate::inner::byte_capacity::<S>(nb_statuses);
        Self(bytes::BytesMut::zeroed(byte_capacity).into(), Default::default())
    }

    /// Create a new StatusList.
    /// It is RECOMMENDED that the size of a Status List in bits is divisible in bytes (8 bits) without a remainder.
    /// Arguments:
    /// * bit_capacity: in bits
    pub fn with_capacity(bit_capacity: usize) -> Self {
        Self(bytes::BytesMut::zeroed(bit_capacity / 8).into(), Default::default())
    }

    pub fn from_vec(bits: Vec<u8>) -> Self {
        Self(bits.into(), Default::default())
    }

    pub fn from_slice(bits: &[u8]) -> Self {
        Self(bytes::Bytes::copy_from_slice(bits), Default::default())
    }

    #[inline(always)]
    pub fn status_list(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn status_list_compressed(&self) -> StatusListResult<Vec<u8>> {
        crate::inner::status_list_compressed(self.status_list())
    }

    pub(crate) fn from_compressed(bytes: &[u8]) -> StatusListResult<Vec<u8>> {
        crate::inner::from_compressed(bytes)
    }

    /// Read a status from the list as bit.
    /// Might panic in case of overflow, prefer [Self::get]
    pub fn get_unchecked(&self, index: BitIndex) -> S {
        crate::inner::get_unchecked::<S>(self.status_list(), index)
    }

    /// Read a status from the list as bit
    pub fn get(&self, index: BitIndex) -> Option<S> {
        crate::inner::get::<S>(self.status_list(), index)
    }

    /// Highest bit index possible with the current list
    pub fn max_index(&self) -> BitIndex {
        crate::inner::max_index::<S>(self.0.as_ref())
    }

    /// Iterates all the bytes in the StatusList and returns all the Statuses in there, alongside their [BitIndex]
    pub fn iter_statuses(&self) -> impl Iterator<Item = (BitIndex, S)> + '_ {
        let per_byte = S::status_per_byte() as usize;
        self.status_list().iter().enumerate().flat_map(move |(byte_idx, &byte)| {
            let base = byte_idx * per_byte;
            S::from_byte(byte).enumerate().map(move |(i, s)| ((base + i) as BitIndex, s))
        })
    }

    /// Iterates all the bytes in the StatusList and returns all the Statuses that are not the default Status
    /// (usually the valid one), alongside their [BitIndex].
    /// This is faster than [Self::iter_statuses] because runs of consecutive bytes that only encode default statuses
    /// (the overwhelming majority of a StatusList in practice) are skipped as a whole byte slice scan instead of
    /// being decoded status by status.
    pub fn iter_non_default_statuses(&self) -> impl Iterator<Item = (BitIndex, S)> + '_ {
        let bytes = self.status_list();
        let per_byte = S::status_per_byte() as usize;
        let default_byte = crate::inner::default_byte::<S>();
        let mut pos = 0usize;
        let mut pending = std::collections::VecDeque::with_capacity(S::status_per_byte() as usize);

        std::iter::from_fn(move || {
            loop {
                if let Some(entry) = pending.pop_front() {
                    return Some(entry);
                }

                // fast forward over the run of default-only bytes starting at `pos`
                pos += bytes.get(pos..).unwrap_or_default().iter().take_while(|&&b| b == default_byte).count();

                // the byte that is different
                let byte_idx = pos;
                let non_default_byte = *bytes.get(pos)?;
                pos += 1;

                let base = byte_idx * per_byte;
                for (i, s) in S::from_byte(non_default_byte).enumerate() {
                    if s != S::default() {
                        pending.push_back(((base + i) as BitIndex, s));
                    }
                }
            }
        })
    }
}

impl<S: Status> Lst<S> {
    /// Finds an empty entry in the StatusList
    #[cfg(feature = "rand")]
    pub fn next_vacant_bit_index(&self, rng: &mut dyn rand_core::CryptoRngCore) -> Option<BitIndex> {
        crate::inner::next_vacant_bit_index::<S>(self.status_list(), rng)
    }
}

impl<S: Status> std::ops::Deref for Lst<S> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S: Status> std::fmt::Debug for Lst<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use hex::ToHex as _;
        write!(f, "{}", self.0.encode_hex::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OauthStatus, RawStatus, StatusBits, issuer::LstMut};

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.1-6
    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn example1() {
        let status = Lst::<RawStatus<1>>::from_vec(vec![0xB9, 0xA3]);
        assert_eq!(status.get_unchecked(0), RawStatus(1));
        assert_eq!(status.get_unchecked(1), RawStatus(0));
        assert_eq!(status.get_unchecked(2), RawStatus(0));
        assert_eq!(status.get_unchecked(3), RawStatus(1));
        assert_eq!(status.get_unchecked(4), RawStatus(1));
        assert_eq!(status.get_unchecked(5), RawStatus(1));
        assert_eq!(status.get_unchecked(6), RawStatus(0));
        assert_eq!(status.get_unchecked(7), RawStatus(1));
        assert_eq!(status.get_unchecked(8), RawStatus(1));
        assert_eq!(status.get_unchecked(9), RawStatus(1));
        assert_eq!(status.get_unchecked(10), RawStatus(0));
        assert_eq!(status.get_unchecked(11), RawStatus(0));
        assert_eq!(status.get_unchecked(12), RawStatus(0));
        assert_eq!(status.get_unchecked(13), RawStatus(1));
        assert_eq!(status.get_unchecked(14), RawStatus(0));
        assert_eq!(status.get_unchecked(15), RawStatus(1));
    }

    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.1-10
    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn example2() {
        let status = Lst::<RawStatus<2>>::from_vec(vec![0xC9, 0x44, 0xF9]);
        assert_eq!(status.get_unchecked(0), RawStatus(1));
        assert_eq!(status.get_unchecked(1), RawStatus(2));
        assert_eq!(status.get_unchecked(2), RawStatus(0));
        assert_eq!(status.get_unchecked(3), RawStatus(3));
        assert_eq!(status.get_unchecked(4), RawStatus(0));
        assert_eq!(status.get_unchecked(5), RawStatus(1));
        assert_eq!(status.get_unchecked(6), RawStatus(0));
        assert_eq!(status.get_unchecked(7), RawStatus(1));
        assert_eq!(status.get_unchecked(8), RawStatus(1));
        assert_eq!(status.get_unchecked(9), RawStatus(2));
        assert_eq!(status.get_unchecked(10), RawStatus(3));
        assert_eq!(status.get_unchecked(11), RawStatus(3));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn iter_statuses_should_work() {
        let status = Lst::<RawStatus<1>>::from_vec(vec![0xB9, 0xA3]);
        assert_eq!(
            status.iter_statuses().collect::<Vec<_>>(),
            vec![
                (0, RawStatus(1)),
                (1, RawStatus(0)),
                (2, RawStatus(0)),
                (3, RawStatus(1)),
                (4, RawStatus(1)),
                (5, RawStatus(1)),
                (6, RawStatus(0)),
                (7, RawStatus(1)),
                (8, RawStatus(1)),
                (9, RawStatus(1)),
                (10, RawStatus(0)),
                (11, RawStatus(0)),
                (12, RawStatus(0)),
                (13, RawStatus(1)),
                (14, RawStatus(0)),
                (15, RawStatus(1)),
            ]
        );
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn iter_non_default_statuses_should_match_iter_statuses_filtered() {
        let status = Lst::<RawStatus<1>>::from_vec(vec![0xB9, 0xA3]);
        assert_eq!(
            status.iter_non_default_statuses().collect::<Vec<_>>(),
            vec![
                (0, RawStatus(1)),
                (3, RawStatus(1)),
                (4, RawStatus(1)),
                (5, RawStatus(1)),
                (7, RawStatus(1)),
                (8, RawStatus(1)),
                (9, RawStatus(1)),
                (13, RawStatus(1)),
                (15, RawStatus(1)),
            ]
        );

        // a StatusList made of nothing but default (Valid) statuses should yield nothing
        let all_default = Lst::<OauthStatus>::from_vec(vec![0x00; 1_000]);
        assert_eq!(all_default.iter_non_default_statuses().count(), 0);

        // default-only runs surrounding a single non-default byte should still be found, with the correct BitIndex
        let mut bytes = vec![0x00; 1_000];
        *bytes.get_mut(500).unwrap() = 0b0000_1001; // Invalid + Suspended packed in one byte
        let mixed = Lst::<OauthStatus>::from_vec(bytes);
        let actual: Vec<_> = mixed.iter_non_default_statuses().collect();
        assert_eq!(actual, vec![(2000, OauthStatus::Invalid), (2001, OauthStatus::Suspended)]);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_roundtrip() {
        let input = Lst::<RawStatus<1>>::from_vec(vec![0xB9, 0xA3]);
        let compressed = input.status_list_compressed().unwrap();
        let decompressed = Lst::<RawStatus<1>>::from_compressed(&compressed).unwrap();
        assert_eq!(input.status_list(), &decompressed);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_find_next_vacant() {
        #[derive(Default, Debug, Clone, Eq, PartialEq, Hash)]
        #[repr(u8)]
        enum Status {
            #[default]
            Valid = 0x00,
            Revoked = 0x01,
            Suspended = 0x02,
            Undefined = 0x03,
        }

        impl crate::Status for Status {
            const BITS: StatusBits = StatusBits::Two;

            fn is_valid(&self) -> bool {
                matches!(self, Self::Valid)
            }
            fn is_undefined(&self) -> bool {
                self == &Self::Undefined
            }
            fn iter() -> impl Iterator<Item = Self> {
                [Self::Valid, Self::Revoked, Self::Suspended, Self::Undefined].into_iter()
            }
        }
        impl From<u8> for Status {
            fn from(s: u8) -> Self {
                match s {
                    0 => Self::Valid,
                    1 => Self::Revoked,
                    2 => Self::Suspended,
                    3 => Self::Undefined,
                    _ => unreachable!(),
                }
            }
        }
        impl From<Status> for u8 {
            fn from(s: Status) -> Self {
                s as Self
            }
        }

        let mut lst = LstMut::<Status>::from_vec(vec![0xff; 1_000_000]);
        let mut rng = rand::thread_rng();

        // there's 0.1% chance this fails, fine :D
        for _ in 0..1000 {
            let idx = lst.next_vacant_bit_index(&mut rng).expect("Did not find a vacant index");
            assert_eq!(lst.set(idx, Status::Valid).unwrap(), Status::Undefined);
        }
    }
}
