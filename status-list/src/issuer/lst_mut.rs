use crate::{BitIndex, Lst, Status, StatusListResult, StatusUndefined};

#[derive(Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
pub struct LstMut<S: Status = u8>(bytes::BytesMut, core::marker::PhantomData<S>);

impl<S: Status> LstMut<S> {
    /// Create a new StatusList.
    /// Arguments:
    /// * nb_statuses: number of statuses this list should hold
    pub fn new(nb_statuses: usize) -> Self {
        let byte_capacity = (nb_statuses / 8usize) * S::BITS.size() as usize;
        Self(bytes::BytesMut::zeroed(byte_capacity), Default::default())
    }

    /// Create a new StatusList.
    /// It is RECOMMENDED that the size of a Status List in bits is divisible in bytes (8 bits) without a remainder.
    /// Arguments:
    /// * bit_capacity: in bits
    pub fn with_capacity(bit_capacity: usize) -> Self {
        Self(bytes::BytesMut::zeroed(bit_capacity / 8), Default::default())
    }

    #[inline(always)]
    pub fn from_vec(bits: Vec<u8>) -> Self {
        Self(bytes::Bytes::from(bits).into(), Default::default())
    }

    pub fn from_slice(bits: &[u8]) -> Self {
        Self(bits.into(), Default::default())
    }

    #[allow(unused)]
    fn from_compressed(bytes: &[u8]) -> StatusListResult<Vec<u8>> {
        crate::inner::from_compressed(bytes)
    }

    #[inline(always)]
    pub fn status_list(&self) -> &[u8] {
        &self.0
    }

    #[allow(unused)]
    fn status_list_compressed(&self) -> StatusListResult<Vec<u8>> {
        crate::inner::status_list_compressed(self.status_list())
    }

    fn byte_offset(index: BitIndex) -> usize {
        crate::inner::byte_offset::<S>(index)
    }

    fn bit_offset(index: BitIndex) -> u8 {
        crate::inner::bit_offset::<S>(index)
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

    /// Replace the bit(s) at the ['index'] given, returning the old index.
    /// Does not do anything if the index is incorrect and returns ['None']
    pub fn set(&mut self, index: BitIndex, new: impl Into<S>) -> Option<S> {
        let bit_offset = Self::bit_offset(index);
        let byte = self.get_byte_mut(index)?;
        let old_byte = *byte;
        let new = new.into();
        crate::twiddling::write_bit(byte, bit_offset, new.into(), S::BITS);

        let mask = S::BITS.mask();
        let old_status = old_byte.wrapping_shr(bit_offset as u32) & mask;

        Some(old_status.into())
    }

    fn get_byte_mut(&mut self, index: BitIndex) -> Option<&mut u8> {
        let byte_offset = Self::byte_offset(index);
        self.0.get_mut(byte_offset)
    }

    /// Highest bit index possible with the current list
    pub fn max_index(&self) -> BitIndex {
        crate::inner::max_index::<S>(self.status_list())
    }
}

impl<S: Status + StatusUndefined> LstMut<S> {
    /// Finds an empty entry in the StatusList
    #[cfg(feature = "rand")]
    pub fn next_vacant_bit_index(&self, rng: &mut dyn rand_core::CryptoRngCore) -> Option<BitIndex> {
        crate::inner::next_vacant_bit_index::<S>(self.status_list(), rng)
    }
}

impl<S: Status> From<LstMut<S>> for Lst<S> {
    fn from(lst: LstMut<S>) -> Self {
        Self(lst.0.into(), Default::default())
    }
}

impl<S: Status> From<Lst<S>> for LstMut<S> {
    fn from(lst: Lst<S>) -> Self {
        Self(bytes::BytesMut::from(lst.0), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RawStatus;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.1-6
    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_replace_in_example1() {
        let mut status = LstMut::<RawStatus<1>>::from_vec(vec![0xB9, 0xA3]);
        assert_eq!(status.get_raw_unchecked(0), 1.into());
        assert_eq!(status.set(0, 0).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(0), 0.into());

        assert_eq!(status.get_raw_unchecked(1), 0.into());
        assert_eq!(status.set(1, 1).unwrap(), 0.into());
        assert_eq!(status.get_raw_unchecked(1), 1.into());

        assert_eq!(status.get_raw_unchecked(7), 1.into());
        assert_eq!(status.set(7, 0).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(7), 0.into());

        assert_eq!(status.get_raw_unchecked(8), 1.into());
        assert_eq!(status.set(8, 0).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(8), 0.into());

        assert_eq!(status.get_raw_unchecked(9), 1.into());
        assert_eq!(status.set(9, 0).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(9), 0.into());

        assert_eq!(status.get_raw_unchecked(15), 1.into());
        assert_eq!(status.set(15, 0).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(15), 0.into());
    }

    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.1-10
    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_replace_in_example2() {
        let mut status = LstMut::<RawStatus<2>>::from_vec(vec![0xC9, 0x44, 0xF9]);
        assert_eq!(status.get_raw_unchecked(0), 1.into());
        assert_eq!(status.set(0, 3).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(0), 3.into());

        assert_eq!(status.get_raw_unchecked(1), 2.into());
        assert_eq!(status.set(1, 0).unwrap(), 2.into());
        assert_eq!(status.get_raw_unchecked(1), 0.into());

        assert_eq!(status.get_raw_unchecked(2), 0.into());
        assert_eq!(status.set(2, 2).unwrap(), 0.into());
        assert_eq!(status.get_raw_unchecked(2), 2.into());

        assert_eq!(status.get_raw_unchecked(3), 3.into());
        assert_eq!(status.set(3, 1).unwrap(), 3.into());
        assert_eq!(status.get_raw_unchecked(3), 1.into());

        assert_eq!(status.get_raw_unchecked(4), 0.into());
        assert_eq!(status.set(4, 1).unwrap(), 0.into());
        assert_eq!(status.get_raw_unchecked(4), 1.into());

        assert_eq!(status.get_raw_unchecked(8), 1.into());
        assert_eq!(status.set(8, 2).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(8), 2.into());

        assert_eq!(status.get_raw_unchecked(11), 3.into());
        assert_eq!(status.set(11, 0).unwrap(), 3.into());
        assert_eq!(status.get_raw_unchecked(11), 0.into());
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_grow_the_list_on_demand() {}
}
