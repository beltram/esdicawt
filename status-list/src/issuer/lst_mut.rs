use crate::{BitIndex, Lst, Status, StatusBits, StatusListResult};

#[derive(Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub struct LstMut<S: Status> {
    status_list: bytes::BytesMut,
    len: usize,
    _marker: core::marker::PhantomData<S>,
}

impl<S: Status> LstMut<S> {
    #[inline(always)]
    pub fn new(bits: Vec<u8>) -> Self {
        Self {
            len: bits.len() / S::BITS.size() as usize,
            status_list: bytes::Bytes::from(bits).into(),
            _marker: Default::default(),
        }
    }

    /// Create a new StatusList.
    /// It is RECOMMENDED that the size of a Status List in bits is divisible in bytes (8 bits) without a remainder.
    /// Arguments:
    /// * capacity: in bits
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            len: 0,
            status_list: bytes::BytesMut::zeroed(capacity / 8),
            _marker: Default::default(),
        }
    }

    #[inline(always)]
    pub fn status_list(&self) -> &[u8] {
        &self.status_list
    }

    #[inline(always)]
    pub fn status_bits(&self) -> StatusBits {
        S::BITS
    }

    pub fn from_slice(bits: &[u8], status_bits: StatusBits) -> Self {
        Self {
            len: bits.len() / status_bits.size() as usize,
            status_list: bits.into(),
            _marker: Default::default(),
        }
    }

    #[allow(unused)]
    fn status_list_compressed(&self) -> StatusListResult<Vec<u8>> {
        crate::inner::status_list_compressed(self.status_list())
    }

    #[allow(unused)]
    fn from_compressed(bytes: &[u8]) -> StatusListResult<Vec<u8>> {
        crate::inner::from_compressed(bytes)
    }

    fn byte_offset(&self, index: BitIndex) -> usize {
        crate::inner::byte_offset(self.status_bits(), index)
    }

    fn bit_offset(&self, index: BitIndex) -> u8 {
        crate::inner::bit_offset(self.status_bits(), index)
    }

    /// Read a status from the list as bit.
    /// Might panic in case of overflow, prefer [Self::get_raw]
    pub fn get_raw_unchecked(&self, index: BitIndex) -> S {
        crate::inner::get_raw_unchecked(self.status_bits(), self.status_list(), index).into()
    }

    /// Read a status from the list as bit
    pub fn get_raw(&self, index: BitIndex) -> Option<S> {
        crate::inner::get_raw(self.status_bits(), self.status_list(), index).map(Into::into)
    }

    /// Replace the bit(s) at the ['index'] given, returning the old index.
    /// Does not do anything if the index is incorrect and returns ['None']
    pub fn replace(&mut self, index: BitIndex, new: impl Into<S>) -> Option<S> {
        let status_bits = self.status_bits();
        let bit_offset = self.bit_offset(index);
        let byte = self.get_byte_mut(index)?;
        let old_byte = *byte;
        let new = new.into();
        crate::twiddling::write_bit(byte, bit_offset, new.into(), status_bits);

        let mask = status_bits.mask();
        let old_status = old_byte.wrapping_shr(bit_offset as u32) & mask;

        Some(old_status.into())
    }

    fn get_byte_mut(&mut self, index: BitIndex) -> Option<&mut u8> {
        let byte_offset = self.byte_offset(index);
        self.status_list.get_mut(byte_offset)
    }
}

impl<S: Status> From<LstMut<S>> for Lst<S> {
    fn from(lst: LstMut<S>) -> Self {
        Self(lst.status_list.into(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RawStatus;

    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.1-6
    #[test]
    fn should_replace_in_example1() {
        let mut status = LstMut::<RawStatus<1>>::new(vec![0xB9, 0xA3]);
        assert_eq!(status.get_raw_unchecked(0), 1.into());
        assert_eq!(status.replace(0, 0).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(0), 0.into());

        assert_eq!(status.get_raw_unchecked(1), 0.into());
        assert_eq!(status.replace(1, 1).unwrap(), 0.into());
        assert_eq!(status.get_raw_unchecked(1), 1.into());

        assert_eq!(status.get_raw_unchecked(7), 1.into());
        assert_eq!(status.replace(7, 0).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(7), 0.into());

        assert_eq!(status.get_raw_unchecked(8), 1.into());
        assert_eq!(status.replace(8, 0).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(8), 0.into());

        assert_eq!(status.get_raw_unchecked(9), 1.into());
        assert_eq!(status.replace(9, 0).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(9), 0.into());

        assert_eq!(status.get_raw_unchecked(15), 1.into());
        assert_eq!(status.replace(15, 0).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(15), 0.into());
    }

    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.1-10
    #[test]
    fn should_replace_in_example2() {
        let mut status = LstMut::<RawStatus<2>>::new(vec![0xC9, 0x44, 0xF9]);
        assert_eq!(status.get_raw_unchecked(0), 1.into());
        assert_eq!(status.replace(0, 3).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(0), 3.into());

        assert_eq!(status.get_raw_unchecked(1), 2.into());
        assert_eq!(status.replace(1, 0).unwrap(), 2.into());
        assert_eq!(status.get_raw_unchecked(1), 0.into());

        assert_eq!(status.get_raw_unchecked(2), 0.into());
        assert_eq!(status.replace(2, 2).unwrap(), 0.into());
        assert_eq!(status.get_raw_unchecked(2), 2.into());

        assert_eq!(status.get_raw_unchecked(3), 3.into());
        assert_eq!(status.replace(3, 1).unwrap(), 3.into());
        assert_eq!(status.get_raw_unchecked(3), 1.into());

        assert_eq!(status.get_raw_unchecked(4), 0.into());
        assert_eq!(status.replace(4, 1).unwrap(), 0.into());
        assert_eq!(status.get_raw_unchecked(4), 1.into());

        assert_eq!(status.get_raw_unchecked(8), 1.into());
        assert_eq!(status.replace(8, 2).unwrap(), 1.into());
        assert_eq!(status.get_raw_unchecked(8), 2.into());

        assert_eq!(status.get_raw_unchecked(11), 3.into());
        assert_eq!(status.replace(11, 0).unwrap(), 3.into());
        assert_eq!(status.get_raw_unchecked(11), 0.into());
    }

    #[test]
    fn should_grow_the_list_on_demand() {}
}
