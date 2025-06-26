use crate::{BitIndex, StatusBits, StatusListResult};
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
pub fn byte_offset(status_bits: StatusBits, index: BitIndex) -> usize {
    // either 1, 2, 4 or 8
    let size = status_bits as usize;

    // offset of the byte we want to read in the byte array.
    // We have to consider the status bit here.
    // For example if it's 2 then there are only 4 status per byte hence the whole byte offset changes
    (index as usize) / (8 / size)
}

#[inline(always)]
pub fn bit_offset(status_bits: StatusBits, index: BitIndex) -> u8 {
    (((index % 8) * status_bits.size() as u32) % 8) as u8
}

/// Read a status from the list as bit.
/// Might panic in case of overflow, prefer [crate::IntellijRustImportsMock::AnyLst::get_raw]
#[inline(always)]
pub fn get_raw_unchecked(status_bits: StatusBits, status_list: &[u8], index: BitIndex) -> u8 {
    get_raw(status_bits, status_list, index).expect("Byte offset ouf of bounds")
}

/// Read a status from the list as bit
#[inline(always)]
pub fn get_raw(status_bits: StatusBits, status_list: &[u8], index: BitIndex) -> Option<u8> {
    // offset of the byte we want to read in the byte array.
    // We have to consider the status bit here.
    // For example if it's 2 then there are only 4 status per byte hence the whole byte offset changes
    let byte_offset = byte_offset(status_bits, index);

    // we read the byte at given offset
    let byte = status_list.get(byte_offset)?;

    let bit_offset = bit_offset(status_bits, index) as u32;

    let mask = status_bits.mask();

    // 'overflowing_shr' is safe since we '%8' at the end of bit_lower
    Some(byte.overflowing_shr(bit_offset).0 & mask)
}
