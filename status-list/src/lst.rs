use crate::{BitIndex, StatusBits, StatusListResult};

impl Lst {
    pub fn new(bits: Vec<u8>, status_bits: StatusBits) -> Self {
        Self(bits.into(), status_bits)
    }

    #[inline(always)]
    pub fn status_list(&self) -> &[u8] {
        &self.0
    }

    #[inline(always)]
    pub fn status_bits(&self) -> StatusBits {
        self.1
    }

    pub fn from_slice(bits: &[u8], status_bits: StatusBits) -> Self {
        Self(bytes::Bytes::copy_from_slice(bits), status_bits)
    }

    pub(crate) fn status_list_compressed(&self) -> StatusListResult<Vec<u8>> {
        crate::inner::status_list_compressed(self.status_list())
    }

    pub(crate) fn from_compressed(bytes: &[u8]) -> StatusListResult<Vec<u8>> {
        crate::inner::from_compressed(bytes)
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

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Lst(pub(crate) bytes::Bytes, pub(crate) StatusBits); // bits len todo

impl std::ops::Deref for Lst {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for Lst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use hex::ToHex as _;
        write!(f, "{}", self.0.encode_hex::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.1-6
    #[test]
    fn example1() {
        let status = Lst::new(vec![0xB9, 0xA3], StatusBits::One);
        assert_eq!(status.get_raw_unchecked(0), 1);
        assert_eq!(status.get_raw_unchecked(1), 0);
        assert_eq!(status.get_raw_unchecked(2), 0);
        assert_eq!(status.get_raw_unchecked(3), 1);
        assert_eq!(status.get_raw_unchecked(4), 1);
        assert_eq!(status.get_raw_unchecked(5), 1);
        assert_eq!(status.get_raw_unchecked(6), 0);
        assert_eq!(status.get_raw_unchecked(7), 1);
        assert_eq!(status.get_raw_unchecked(8), 1);
        assert_eq!(status.get_raw_unchecked(9), 1);
        assert_eq!(status.get_raw_unchecked(10), 0);
        assert_eq!(status.get_raw_unchecked(11), 0);
        assert_eq!(status.get_raw_unchecked(12), 0);
        assert_eq!(status.get_raw_unchecked(13), 1);
        assert_eq!(status.get_raw_unchecked(14), 0);
        assert_eq!(status.get_raw_unchecked(15), 1);
    }

    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.1-10
    #[test]
    fn example2() {
        let status = Lst::new(vec![0xC9, 0x44, 0xF9], StatusBits::Two);
        assert_eq!(status.get_raw_unchecked(0), 1);
        assert_eq!(status.get_raw_unchecked(1), 2);
        assert_eq!(status.get_raw_unchecked(2), 0);
        assert_eq!(status.get_raw_unchecked(3), 3);
        assert_eq!(status.get_raw_unchecked(4), 0);
        assert_eq!(status.get_raw_unchecked(5), 1);
        assert_eq!(status.get_raw_unchecked(6), 0);
        assert_eq!(status.get_raw_unchecked(7), 1);
        assert_eq!(status.get_raw_unchecked(8), 1);
        assert_eq!(status.get_raw_unchecked(9), 2);
        assert_eq!(status.get_raw_unchecked(10), 3);
        assert_eq!(status.get_raw_unchecked(11), 3);
    }

    #[test]
    fn should_roundtrip() {
        let input = Lst::new(vec![0xB9, 0xA3], StatusBits::One);
        let compressed = input.status_list_compressed().unwrap();
        let decompressed = Lst::from_compressed(&compressed).unwrap();
        assert_eq!(input.status_list(), &decompressed);
    }
}
