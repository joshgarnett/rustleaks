const POLYNOMIAL: u32 = 0xedb8_8320;

/// Slice-by-8 tables for the reflected CRC. `TABLES[k][i]` is the CRC remainder
/// of byte `i` followed by `k` zero bytes.
static TABLES: [[u32; 256]; 8] = build_tables();

const fn build_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0; 256]; 8];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = (value >> 1) ^ (POLYNOMIAL & 0_u32.wrapping_sub(value & 1));
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
            tables[table][index] = (previous >> 8) ^ tables[0][(previous & 0xff) as usize];
            index += 1;
        }
        table += 1;
    }
    tables
}

#[derive(Default)]
pub(crate) struct Hasher {
    state: u32,
}

impl Hasher {
    pub(crate) const fn new() -> Self {
        Self { state: u32::MAX }
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        let mut crc = self.state;
        let mut chunks = input.chunks_exact(8);
        for chunk in &mut chunks {
            let head =
                (u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ crc).to_le_bytes();
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
            let index = usize::from(crc.to_le_bytes()[0] ^ byte);
            crc = (crc >> 8) ^ TABLES[0][index];
        }
        self.state = crc;
    }

    pub(crate) const fn finalize(self) -> u32 {
        !self.state
    }
}

pub(crate) fn hash(input: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bitwise_hash(input: &[u8]) -> u32 {
        let mut state = u32::MAX;
        for byte in input {
            state ^= u32::from(*byte);
            for _ in 0..8 {
                let polynomial = POLYNOMIAL & 0_u32.wrapping_sub(state & 1);
                state = (state >> 1) ^ polynomial;
            }
        }
        !state
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
    fn matches_the_ieee_check_value() {
        assert_eq!(hash(b""), 0);
        assert_eq!(hash(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn table_hash_matches_the_retained_bitwise_hash() {
        for len in (0..=257).chain([1024, 4095, 4096, 4097, 65_536]) {
            let bytes = deterministic_bytes(len);
            assert_eq!(hash(&bytes), bitwise_hash(&bytes), "len {len}");
        }
    }

    #[test]
    fn split_updates_match_a_single_update() {
        let bytes = deterministic_bytes(64);
        let whole = bitwise_hash(&bytes);
        for split in 0..=bytes.len() {
            let mut hasher = Hasher::new();
            hasher.update(&bytes[..split]);
            hasher.update(&bytes[split..]);
            assert_eq!(hasher.finalize(), whole, "split {split}");
        }
    }
}
