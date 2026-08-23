#[derive(Default)]
pub(crate) struct Hasher {
    state: u32,
}

impl Hasher {
    pub(crate) const fn new() -> Self {
        Self { state: u32::MAX }
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        for byte in input {
            self.state ^= u32::from(*byte);
            for _ in 0..8 {
                let polynomial = 0xedb8_8320 & 0_u32.wrapping_sub(self.state & 1);
                self.state = (self.state >> 1) ^ polynomial;
            }
        }
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

    #[test]
    fn matches_the_ieee_check_value() {
        assert_eq!(hash(b""), 0);
        assert_eq!(hash(b"123456789"), 0xcbf4_3926);
    }
}
