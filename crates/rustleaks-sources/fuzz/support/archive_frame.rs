//! Versioned archive fuzz input framing, shared with seed generation and tests.

pub const MAGIC: &[u8; 4] = b"RLA\x01";
pub const HEADER_BYTES: usize = MAGIC.len() + 2;
pub const MAX_INPUT_BYTES: usize = 8 * 1024;
pub const FORMAT_NAMES: &[&str] = &[
    "input.tar",
    "input.zip",
    "input.7z",
    "input.rar",
    "input.tar.gz",
    "input.gz",
    "input.tar.xz",
    "input.xz",
    "input.bz2",
    "input.br",
    "input.lz4",
    "input.sz",
    "input.mz",
    "input.zst",
    "input.zz",
    "input.lz",
];

pub struct Frame<'a> {
    pub format: usize,
    pub control: u8,
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    pub fn decode(data: &'a [u8]) -> Option<Self> {
        Self::decode_bounded(data, MAX_INPUT_BYTES)
    }

    pub fn decode_bounded(data: &'a [u8], maximum: usize) -> Option<Self> {
        let data = &data[..data.len().min(maximum)];
        if data.len() < HEADER_BYTES || !data.starts_with(MAGIC) {
            return None;
        }
        Some(Self {
            format: usize::from(data[MAGIC.len()]) % FORMAT_NAMES.len(),
            control: data[MAGIC.len() + 1],
            payload: &data[HEADER_BYTES..],
        })
    }

    pub const fn cancel_before(&self) -> bool {
        self.control & 1 != 0
    }

    pub const fn cancel_after_event(&self) -> bool {
        self.control & 2 != 0
    }

    pub const fn stop_after_event(&self) -> bool {
        self.control & 4 != 0
    }
}

pub fn encode(format: u8, control: u8, payload: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(HEADER_BYTES + payload.len());
    framed.extend_from_slice(MAGIC);
    framed.extend_from_slice(&[format, control]);
    framed.extend_from_slice(payload);
    framed
}

/// Preserve the previous one-byte selector's behavior while making its fields explicit.
pub fn migrate_legacy(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() > MAX_INPUT_BYTES - (HEADER_BYTES - 1) {
        return None;
    }
    let control = data.first().copied().unwrap_or_default();
    let payload = &data[data.len().min(1)..];
    Some(encode(control, control, payload))
}
