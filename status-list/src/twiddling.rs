use crate::StatusBits;

/// Set a bit in the given u8
/// see https://graphics.stanford.edu/~seander/bithacks.html#ConditionalSetOrClearBitsWithoutBranching
#[inline(always)]
pub fn write_bit(word: &mut u8, index: u8, flag: u8, status_bits: StatusBits) {
    let size = status_bits.size();
    for i in 0..size {
        let f = (flag >> i) & 1;
        set_bit(word, index + i, f == 1)
    }
}

/// Set a bit in the given u8
/// see https://graphics.stanford.edu/~seander/bithacks.html#ConditionalSetOrClearBitsWithoutBranching
#[inline(always)]
fn set_bit(word: &mut u8, index: u8, flag: bool) {
    let m = 1u8.wrapping_shl(index as u32);
    let f = -(flag as i8);
    let w: u8 = *word;
    *word = w ^ (((f ^ w as i8) & m as i8) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn write_bit_should_work() {
        // lower bits
        assert_eq!(wr_bit(0b0000_0000, 0, 1, StatusBits::One), 0b0000_0001);
        assert_eq!(wr_bit(0b0000_0000, 0, 0, StatusBits::One), 0b0000_0000);
        assert_eq!(wr_bit(0b0000_0001, 0, 1, StatusBits::One), 0b0000_0001);
        assert_eq!(wr_bit(0b0000_0001, 0, 0, StatusBits::One), 0b0000_0000);

        // middle bits
        assert_eq!(wr_bit(0b0000_0000, 1, 1, StatusBits::One), 0b0000_0010);
        assert_eq!(wr_bit(0b0001_0000, 3, 1, StatusBits::One), 0b0001_1000);

        // high order bits
        assert_eq!(wr_bit(0b1000_0000, 7, 1, StatusBits::One), 0b1000_0000);
        assert_eq!(wr_bit(0b1000_0000, 7, 0, StatusBits::One), 0b0000_0000);

        // varying StatusBit
        assert_eq!(wr_bit(0b0000_0000, 0, 1, StatusBits::Two), 0b0000_0001);
        assert_eq!(wr_bit(0b0000_0000, 2, 1, StatusBits::Two), 0b0000_0100);
        assert_eq!(wr_bit(0b0000_0000, 4, 1, StatusBits::Two), 0b0001_0000);
        assert_eq!(wr_bit(0b0000_0000, 6, 1, StatusBits::Two), 0b0100_0000);

        assert_eq!(wr_bit(0b0000_0000, 0, 0, StatusBits::Two), 0b0000_0000);
        assert_eq!(wr_bit(0b0000_0000, 0, 1, StatusBits::Two), 0b0000_0001);
        assert_eq!(wr_bit(0b0000_0000, 0, 2, StatusBits::Two), 0b0000_0010);
        assert_eq!(wr_bit(0b0000_0000, 0, 3, StatusBits::Two), 0b0000_0011);
        assert_eq!(wr_bit(0b0000_0000, 0, 3, StatusBits::Two), 0b0000_0011);
        assert_eq!(wr_bit(0b11001011, 2, 0, StatusBits::Two), 0b11000011);

        // more StatusBit
        assert_eq!(wr_bit(0b0000_0000, 0, 1, StatusBits::Four), 0b0000_0001);
        assert_eq!(wr_bit(0b0000_0000, 4, 1, StatusBits::Four), 0b0001_0000);
        assert_eq!(wr_bit(0b0000_0000, 4, 7, StatusBits::Four), 0b0111_0000);
        assert_eq!(wr_bit(0b0000_0000, 4, 8, StatusBits::Four), 0b1000_0000);
        assert_eq!(wr_bit(0b0000_0000, 4, 15, StatusBits::Four), 0b1111_0000);

        assert_eq!(wr_bit(0b0000_0000, 0, 0, StatusBits::Eight), 0b0000_0000);
        assert_eq!(wr_bit(0b0000_0000, 0, 1, StatusBits::Eight), 0b0000_0001);
        assert_eq!(wr_bit(0b0000_0000, 0, 2, StatusBits::Eight), 0b0000_0010);
    }

    #[test]
    fn should_be_idempotent() {
        assert_eq!(wr_bit(0b01000100, 6, 1, StatusBits::Two), 0b01000100);
    }

    fn wr_bit(mut word: u8, index: u8, flag: u8, status_bits: StatusBits) -> u8 {
        write_bit(&mut word, index, flag, status_bits);
        word
    }
}
