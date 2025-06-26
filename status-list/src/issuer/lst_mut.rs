use crate::{BitIndex, Lst, StatusBits, StatusListResult};

#[derive(Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub struct LstMut {
    status_list: bytes::BytesMut,
    status_bits: StatusBits,
    len: usize,
}

impl LstMut {
    #[inline(always)]
    pub fn new(bits: Vec<u8>, status_bits: StatusBits) -> Self {
        Self {
            len: bits.len() / status_bits.size() as usize,
            status_list: bytes::Bytes::from(bits).into(),
            status_bits,
        }
    }

    #[inline(always)]
    pub fn status_list(&self) -> &[u8] {
        &self.status_list
    }

    #[inline(always)]
    pub fn status_bits(&self) -> StatusBits {
        self.status_bits
    }

    pub fn from_slice(bits: &[u8], status_bits: StatusBits) -> Self {
        Self {
            len: bits.len() / status_bits.size() as usize,
            status_list: bits.into(),
            status_bits,
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
    pub fn get_raw_unchecked(&self, index: BitIndex) -> u8 {
        crate::inner::get_raw_unchecked(self.status_bits(), self.status_list(), index)
    }

    /// Read a status from the list as bit
    pub fn get_raw(&self, index: BitIndex) -> Option<u8> {
        crate::inner::get_raw(self.status_bits(), self.status_list(), index)
    }
}

impl LstMut {
    /// Create a new StatusList.
    /// It is RECOMMENDED that the size of a Status List in bits is divisible in bytes (8 bits) without a remainder.
    /// Arguments:
    /// * capacity: in bits
    pub fn with_capacity(capacity: usize, status_bits: StatusBits) -> Self {
        Self {
            len: 0,
            status_list: bytes::BytesMut::zeroed(capacity / 8),
            status_bits,
        }
    }

    /// Replace the bit(s) at the ['index'] given, returning the old index.
    /// Does not do anything if the index is incorrect and returns ['None']
    pub fn replace(&mut self, index: BitIndex, new: u8) -> Option<u8> {
        let status_bits = self.status_bits();
        let bit_offset = self.bit_offset(index);
        let byte = self.get_byte_mut(index)?;
        let old_byte = *byte;
        crate::twiddling::write_bit(byte, bit_offset, new, status_bits);
        Some(old_byte)
    }

    fn get_byte_mut(&mut self, index: BitIndex) -> Option<&mut u8> {
        let byte_offset = self.byte_offset(index);
        self.status_list.get_mut(byte_offset)
    }
}

impl From<LstMut> for Lst {
    fn from(lst: LstMut) -> Self {
        Self(lst.status_list.into(), lst.status_bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StatusBits;

    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.1-6
    #[test]
    fn should_replace_in_example1() {
        let mut status = LstMut::new(vec![0xB9, 0xA3], StatusBits::One);
        assert_eq!(status.get_raw_unchecked(0), 1);
        status.replace(0, 0).unwrap();
        assert_eq!(status.get_raw_unchecked(0), 0);

        assert_eq!(status.get_raw_unchecked(1), 0);
        status.replace(1, 1).unwrap();
        assert_eq!(status.get_raw_unchecked(1), 1);

        assert_eq!(status.get_raw_unchecked(7), 1);
        status.replace(7, 0).unwrap();
        assert_eq!(status.get_raw_unchecked(7), 0);

        assert_eq!(status.get_raw_unchecked(8), 1);
        status.replace(8, 0).unwrap();
        assert_eq!(status.get_raw_unchecked(8), 0);

        assert_eq!(status.get_raw_unchecked(9), 1);
        status.replace(9, 0).unwrap();
        assert_eq!(status.get_raw_unchecked(9), 0);

        assert_eq!(status.get_raw_unchecked(15), 1);
        status.replace(15, 0).unwrap();
        assert_eq!(status.get_raw_unchecked(15), 0);
    }

    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.1-10
    #[test]
    fn should_replace_in_example2() {
        let mut status = LstMut::new(vec![0xC9, 0x44, 0xF9], StatusBits::Two);
        assert_eq!(status.get_raw_unchecked(0), 1);
        status.replace(0, 3).unwrap();
        assert_eq!(status.get_raw_unchecked(0), 3);

        assert_eq!(status.get_raw_unchecked(1), 2);
        status.replace(1, 0).unwrap();
        assert_eq!(status.get_raw_unchecked(1), 0);

        assert_eq!(status.get_raw_unchecked(2), 0);
        status.replace(2, 2).unwrap();
        assert_eq!(status.get_raw_unchecked(2), 2);

        assert_eq!(status.get_raw_unchecked(3), 3);
        status.replace(3, 1).unwrap();
        assert_eq!(status.get_raw_unchecked(3), 1);

        assert_eq!(status.get_raw_unchecked(4), 0);
        status.replace(4, 1).unwrap();
        assert_eq!(status.get_raw_unchecked(4), 1);

        assert_eq!(status.get_raw_unchecked(8), 1);
        status.replace(8, 2).unwrap();
        assert_eq!(status.get_raw_unchecked(8), 2);

        assert_eq!(status.get_raw_unchecked(11), 3);
        status.replace(11, 0).unwrap();
        assert_eq!(status.get_raw_unchecked(11), 0);
    }

    #[test]
    fn should_grow_the_list_on_demand() {}
}
