use crate::{BitIndex, Status, StatusListResult, StatusUndefined};

#[derive(Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct Lst<S: Status = u8>(pub(crate) bytes::Bytes, pub(crate) core::marker::PhantomData<S>);

impl<S: Status> Lst<S> {
    /// Create a new StatusList.
    /// It is RECOMMENDED that the size of a Status List in bits is divisible in bytes (8 bits) without a remainder.
    /// Arguments:
    /// * capacity: in bits
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
    /// Might panic in case of overflow, prefer [Self::get_raw]
    pub fn get_raw_unchecked(&self, index: BitIndex) -> S {
        crate::inner::get_raw_unchecked::<S>(self.status_list(), index)
    }

    /// Read a status from the list as bit
    pub fn get_raw(&self, index: BitIndex) -> Option<S> {
        crate::inner::get_raw::<S>(self.status_list(), index)
    }

    /// Highest bit index possible with the current list
    pub fn max_index(&self) -> BitIndex {
        crate::inner::max_index::<S>(self.0.as_ref())
    }
}

impl<S: Status + StatusUndefined> Lst<S> {
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
    use crate::issuer::LstMut;
    use crate::{RawStatus, StatusBits};

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.1-6
    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn example1() {
        let status = Lst::<RawStatus<1>>::from_vec(vec![0xB9, 0xA3]);
        assert_eq!(status.get_raw_unchecked(0), RawStatus(1));
        assert_eq!(status.get_raw_unchecked(1), RawStatus(0));
        assert_eq!(status.get_raw_unchecked(2), RawStatus(0));
        assert_eq!(status.get_raw_unchecked(3), RawStatus(1));
        assert_eq!(status.get_raw_unchecked(4), RawStatus(1));
        assert_eq!(status.get_raw_unchecked(5), RawStatus(1));
        assert_eq!(status.get_raw_unchecked(6), RawStatus(0));
        assert_eq!(status.get_raw_unchecked(7), RawStatus(1));
        assert_eq!(status.get_raw_unchecked(8), RawStatus(1));
        assert_eq!(status.get_raw_unchecked(9), RawStatus(1));
        assert_eq!(status.get_raw_unchecked(10), RawStatus(0));
        assert_eq!(status.get_raw_unchecked(11), RawStatus(0));
        assert_eq!(status.get_raw_unchecked(12), RawStatus(0));
        assert_eq!(status.get_raw_unchecked(13), RawStatus(1));
        assert_eq!(status.get_raw_unchecked(14), RawStatus(0));
        assert_eq!(status.get_raw_unchecked(15), RawStatus(1));
    }

    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.1-10
    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn example2() {
        let status = Lst::<RawStatus<2>>::from_vec(vec![0xC9, 0x44, 0xF9]);
        assert_eq!(status.get_raw_unchecked(0), RawStatus(1));
        assert_eq!(status.get_raw_unchecked(1), RawStatus(2));
        assert_eq!(status.get_raw_unchecked(2), RawStatus(0));
        assert_eq!(status.get_raw_unchecked(3), RawStatus(3));
        assert_eq!(status.get_raw_unchecked(4), RawStatus(0));
        assert_eq!(status.get_raw_unchecked(5), RawStatus(1));
        assert_eq!(status.get_raw_unchecked(6), RawStatus(0));
        assert_eq!(status.get_raw_unchecked(7), RawStatus(1));
        assert_eq!(status.get_raw_unchecked(8), RawStatus(1));
        assert_eq!(status.get_raw_unchecked(9), RawStatus(2));
        assert_eq!(status.get_raw_unchecked(10), RawStatus(3));
        assert_eq!(status.get_raw_unchecked(11), RawStatus(3));
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
        #[derive(Debug, Clone, Eq, PartialEq, Hash)]
        #[repr(u8)]
        enum Status {
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
        }
        impl StatusUndefined for Status {
            fn is_undefined(&self) -> bool {
                self == &Self::Undefined
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
            assert_eq!(lst.replace(idx, Status::Valid).unwrap(), Status::Undefined);
        }
    }
}
