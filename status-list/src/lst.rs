use crate::{BitIndex, Status, StatusBits, StatusListResult};

impl<S: Status> Lst<S> {
    pub fn new(bits: Vec<u8>) -> Self {
        Self(bits.into(), Default::default())
    }

    #[inline(always)]
    pub fn status_list(&self) -> &[u8] {
        &self.0
    }

    #[inline(always)]
    pub fn status_bits(&self) -> StatusBits {
        S::BITS
    }

    pub fn from_slice(bits: &[u8]) -> Self {
        Self(bytes::Bytes::copy_from_slice(bits), Default::default())
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
        crate::inner::get_raw_unchecked(self.status_bits(), self.status_list(), index).into()
    }

    /// Read a status from the list as bit
    pub fn get_raw(&self, index: BitIndex) -> Option<S> {
        crate::inner::get_raw(self.status_bits(), self.status_list(), index).map(Into::into)
    }
}

#[derive(Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct Lst<S: Status>(pub(crate) bytes::Bytes, pub(crate) core::marker::PhantomData<S>);

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
    use crate::RawStatus;

    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.1-6
    #[test]
    fn example1() {
        let status = Lst::<RawStatus<1>>::new(vec![0xB9, 0xA3]);
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
    fn example2() {
        let status = Lst::<RawStatus<2>>::new(vec![0xC9, 0x44, 0xF9]);
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
    fn should_roundtrip() {
        let input = Lst::<RawStatus<1>>::new(vec![0xB9, 0xA3]);
        let compressed = input.status_list_compressed().unwrap();
        let decompressed = Lst::<RawStatus<1>>::from_compressed(&compressed).unwrap();
        assert_eq!(input.status_list(), &decompressed);
    }
}
