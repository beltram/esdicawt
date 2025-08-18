use crate::{Status, StatusBits, StatusUndefined};

/// Just an u8 with the right bounds for representing a Status
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct RawStatus<const B: usize>(pub u8);

impl<const B: usize> Status for RawStatus<B> {
    const BITS: StatusBits = StatusBits::from_raw(B);

    fn is_valid(&self) -> bool {
        self.0 == 0
    }
}
impl<const B: usize> From<RawStatus<B>> for u8 {
    fn from(s: RawStatus<B>) -> Self {
        s.0
    }
}
impl<const B: usize> From<u8> for RawStatus<B> {
    fn from(s: u8) -> Self {
        Self(s)
    }
}

/// see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-12#section-7.1
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum OauthStatus {
    Valid = 0x00,
    Invalid = 0x01,
    Suspended = 0x02,
    Unknown = 0x03,
}

impl Status for OauthStatus {
    const BITS: StatusBits = StatusBits::from_raw(2);

    fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

impl StatusUndefined for OauthStatus {
    fn is_undefined(&self) -> bool {
        false
    }
}

impl From<OauthStatus> for u8 {
    fn from(s: OauthStatus) -> Self {
        s as Self
    }
}

impl From<u8> for OauthStatus {
    fn from(s: u8) -> Self {
        match s {
            0x00 => Self::Valid,
            0x01 => Self::Invalid,
            0x02 => Self::Suspended,
            _ => Self::Unknown,
        }
    }
}

impl Status for u8 {
    const BITS: StatusBits = StatusBits::One;

    fn is_valid(&self) -> bool {
        *self == 0
    }
}
