use crate::{BitIndex, Status, StatusListResult};
use flate2::Compression;
use std::io::{Read, Write};

#[inline(always)]
pub fn status_list_compressed(status_list: &[u8]) -> StatusListResult<Vec<u8>> {
    let mut encoder = flate2::write::ZlibEncoder::new(vec![], Compression::best());
    encoder.write_all(status_list)?;
    Ok(encoder.finish()?)
}

// TODO: optimize by having the len in the token
#[inline(always)]
pub fn from_compressed(bytes: &[u8]) -> StatusListResult<Vec<u8>> {
    // let mut buf = Vec::with_capacity(len);
    let mut buf = vec![];

    // TODO: speed up
    // let decoder = flate2::read::ZlibDecoder::new_with_buf(bytes, Vec::<u8>::with_capacity(len));

    let mut decoder = flate2::read::ZlibDecoder::new(bytes);
    // let mut decoder = flate2::read::ZlibDecoder::new_with_decompress(bytes, Default::default());
    decoder.read_to_end(&mut buf)?;
    Ok(buf)
}

#[inline(always)]
pub fn byte_offset<S: Status>(index: BitIndex) -> usize {
    // either 1, 2, 4 or 8
    let size = S::BITS as usize;

    // offset of the byte we want to read in the byte array.
    // We have to consider the status bit here.
    // For example if it's 2 then there are only 4 status per byte hence the whole byte offset changes
    (index as usize) / (8 / size)
}

#[inline(always)]
pub fn bit_offset<S: Status>(index: BitIndex) -> u8 {
    (((index % 8) * S::BITS.size() as BitIndex) % 8) as u8
}

/// Read a status from the list as bit.
/// Might panic in case of overflow, prefer [crate::IntellijRustImportsMock::AnyLst::get_raw]
#[inline(always)]
pub fn get_unchecked<S: Status>(status_list: &[u8], index: BitIndex) -> S {
    get(status_list, index).expect("Byte offset ouf of bounds")
}

/// Read a status from the list as bit
#[inline(always)]
pub fn get<S: Status>(status_list: &[u8], index: BitIndex) -> Option<S> {
    // offset of the byte we want to read in the byte array.
    // We have to consider the status bit here.
    // For example if it's 2 then there are only 4 status per byte hence the whole byte offset changes
    let byte_offset = byte_offset::<S>(index);

    // we read the byte at given offset
    let byte = status_list.get(byte_offset)?;

    let bit_offset = bit_offset::<S>(index) as u32;

    let mask = S::BITS.mask();

    // 'overflowing_shr' is safe since we '%8' at the end of bit_lower
    let status = byte.overflowing_shr(bit_offset).0 & mask;
    Some(status.into())
}

/// Highest bit index possible with the current list
#[inline(always)]
pub fn max_index<S: Status>(bytes: &[u8]) -> BitIndex {
    let ratio = (8 / S::BITS.size()) as BitIndex;
    let byte_len = bytes.len() as BitIndex;
    byte_len.wrapping_mul(ratio)
}

/// Finds an empty entry in the StatusList
#[cfg(feature = "rand")]
pub fn next_vacant_bit_index<S: Status + crate::StatusUndefined>(bytes: &[u8], rng: &mut dyn rand_core::CryptoRngCore) -> Option<BitIndex> {
    use rand::Rng as _;
    let max = max_index::<S>(bytes);

    let mut i = 0;
    const TRIES: usize = 10_000;

    loop {
        if i > TRIES {
            return None;
        }
        let proposed_index = rng.gen_range(0..max);
        match get::<S>(bytes, proposed_index) {
            Some(s) if s.is_undefined() => return Some(proposed_index),
            _ => i += 1,
        }
    }
}
