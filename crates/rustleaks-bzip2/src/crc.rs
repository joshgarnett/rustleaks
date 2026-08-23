#[derive(Clone)]
pub struct Hasher {
    value: u32,
}

impl Hasher {
    pub const fn new() -> Self {
        Self { value: u32::MAX }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.value ^= u32::from(byte) << 24;
            for _ in 0..8 {
                self.value = if self.value & 0x8000_0000 == 0 {
                    self.value << 1
                } else {
                    (self.value << 1) ^ 0x04c1_1db7
                };
            }
        }
    }

    pub const fn finalyze(&self) -> u32 {
        !self.value
    }
}

#[cfg(test)]
mod tests {
    use super::Hasher;

    #[test]
    fn matches_the_bzip2_check_value() {
        let mut hasher = Hasher::new();
        hasher.update(b"123456789");
        assert_eq!(hasher.finalyze(), 0xfc89_1918);
    }
}
