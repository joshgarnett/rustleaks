const POLYNOMIAL: u32 = 0x04c1_1db7;

/// Slice-by-8 tables for the MSB-first CRC. `TABLES[k][i]` is the CRC remainder
/// of byte `i` followed by `k` zero bytes.
static TABLES: [[u32; 256]; 8] = build_tables();

const fn build_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0; 256]; 8];
    let mut index = 0;
    while index < 256 {
        let mut value = (index as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 0x8000_0000 == 0 {
                value << 1
            } else {
                (value << 1) ^ POLYNOMIAL
            };
            bit += 1;
        }
        tables[0][index] = value;
        index += 1;
    }
    let mut table = 1;
    while table < 8 {
        let mut index = 0;
        while index < 256 {
            let previous = tables[table - 1][index];
            tables[table][index] = (previous << 8) ^ tables[0][(previous >> 24) as usize];
            index += 1;
        }
        table += 1;
    }
    tables
}

#[derive(Clone)]
pub struct Hasher {
    value: u32,
}

impl Hasher {
    pub const fn new() -> Self {
        Self { value: u32::MAX }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let mut crc = self.value;
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            let head =
                (u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ crc).to_be_bytes();
            crc = TABLES[7][usize::from(head[0])]
                ^ TABLES[6][usize::from(head[1])]
                ^ TABLES[5][usize::from(head[2])]
                ^ TABLES[4][usize::from(head[3])]
                ^ TABLES[3][usize::from(chunk[4])]
                ^ TABLES[2][usize::from(chunk[5])]
                ^ TABLES[1][usize::from(chunk[6])]
                ^ TABLES[0][usize::from(chunk[7])];
        }
        for &byte in chunks.remainder() {
            let index = usize::from(crc.to_be_bytes()[0] ^ byte);
            crc = (crc << 8) ^ TABLES[0][index];
        }
        self.value = crc;
    }

    pub const fn finalyze(&self) -> u32 {
        !self.value
    }
}

#[cfg(test)]
mod tests {
    use super::{Hasher, POLYNOMIAL};

    fn bitwise_update(mut value: u32, bytes: &[u8]) -> u32 {
        for &byte in bytes {
            value ^= u32::from(byte) << 24;
            for _ in 0..8 {
                value = if value & 0x8000_0000 == 0 {
                    value << 1
                } else {
                    (value << 1) ^ POLYNOMIAL
                };
            }
        }
        value
    }

    fn deterministic_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678_u32;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            bytes.push(state.to_be_bytes()[0]);
        }
        bytes
    }

    #[test]
    fn matches_the_bzip2_check_value() {
        let mut hasher = Hasher::new();
        hasher.update(b"123456789");
        assert_eq!(hasher.finalyze(), 0xfc89_1918);
    }

    #[test]
    fn matches_the_bzip2_empty_input_value() {
        let mut hasher = Hasher::new();
        hasher.update(b"");
        assert_eq!(hasher.finalyze(), 0);
    }

    #[test]
    fn table_update_matches_the_retained_bitwise_update() {
        for len in (0..=257).chain([1024, 4095, 4096, 4097, 65_536]) {
            let bytes = deterministic_bytes(len);
            let mut hasher = Hasher::new();
            hasher.update(&bytes);
            assert_eq!(hasher.value, bitwise_update(u32::MAX, &bytes), "len {len}");
        }
    }

    #[test]
    fn split_updates_match_a_single_update() {
        let bytes = deterministic_bytes(64);
        let whole = bitwise_update(u32::MAX, &bytes);
        for split in 0..=bytes.len() {
            let mut hasher = Hasher::new();
            hasher.update(&bytes[..split]);
            hasher.update(&bytes[split..]);
            assert_eq!(hasher.value, whole, "split {split}");
        }
    }
}
