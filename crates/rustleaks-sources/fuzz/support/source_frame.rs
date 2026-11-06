//! Versioned, independently controlled reader/Git inputs with legacy fallback.
//!
//! Complete `RLR\x01` and `RLG\x01` headers opt into v1. All other inputs,
//! including short/unknown-version headers, retain the original interpretation.
//! These complete prefixes reserve a small part of the former arbitrary input
//! space. Reviewed committed/generated legacy seeds have no prefix collisions.
//! Input caps include headers. Deep increases input length, not per-operation
//! limits. No production API or source limit is changed by these test helpers.

use super::campaign_profile::{self, Profile};

pub const READER_MAGIC: &[u8; 4] = b"RLR\x01";
pub const GIT_MAGIC: &[u8; 4] = b"RLG\x01";
pub const READER_HEADER_BYTES: usize = 12;
pub const GIT_HEADER_BYTES: usize = 7;
pub const MAX_CHUNK_BYTES: usize = 64;
pub const MAX_READ_AHEAD_BYTES: usize = 63;
pub const MAX_GIT_FILES: usize = 32;
pub const MAX_GIT_HUNKS: usize = 256;
pub const MAX_GIT_LINES: usize = 2_048;
pub const MAX_GIT_METADATA_BYTES: usize = 4 * 1024;
pub const MAX_GIT_PATH_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Encoding {
    Legacy,
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "fuzz controls are independent bits, including simultaneous callback actions"
)]
pub struct ReaderControls {
    pub chunk_bytes: usize,
    pub read_ahead_bytes: usize,
    pub callback_stop: bool,
    pub callback_error: bool,
    pub cancel_before: bool,
    pub cancel_in_callback: bool,
}

pub struct ReaderFrame<'a> {
    pub encoding: Encoding,
    pub controls: ReaderControls,
    pub schedule: &'a [u8],
    pub payload: &'a [u8],
    pub input_bytes: usize,
}

impl<'a> ReaderFrame<'a> {
    /// V1: magic, chunk, read-ahead, stop, error, pre-cancel, callback-cancel,
    /// little-endian u16 schedule length, schedule, payload. Boolean fields
    /// use only bit zero; numeric fields keep the legacy per-operation caps.
    pub fn decode(data: &'a [u8], profile: Profile) -> Self {
        let data = bounded(data, profile, "reader_schedule");
        if data.len() >= READER_HEADER_BYTES && data.starts_with(READER_MAGIC) {
            let requested = usize::from(u16::from_le_bytes([data[10], data[11]]));
            let rest = &data[READER_HEADER_BYTES..];
            let (schedule, payload) = rest.split_at(requested.min(rest.len()));
            return Self {
                encoding: Encoding::V1,
                controls: ReaderControls {
                    chunk_bytes: usize::from(data[4]) % MAX_CHUNK_BYTES + 1,
                    read_ahead_bytes: usize::from(data[5]) % (MAX_READ_AHEAD_BYTES + 1),
                    callback_stop: data[6] & 1 != 0,
                    callback_error: data[7] & 1 != 0,
                    cancel_before: data[8] & 1 != 0,
                    cancel_in_callback: data[9] & 1 != 0,
                },
                schedule,
                payload,
                input_bytes: data.len(),
            };
        }
        let (control, schedule, payload) = campaign_profile::reader_parts(data, profile);
        Self {
            encoding: Encoding::Legacy,
            controls: ReaderControls {
                chunk_bytes: usize::from(control & 0x3f) + 1,
                read_ahead_bytes: usize::from(control >> 2) & 0x3f,
                callback_stop: control & 0x08 != 0,
                callback_error: control & 0x10 != 0,
                cancel_before: control & 0x40 != 0,
                cancel_in_callback: control & 0x20 != 0,
            },
            schedule,
            payload,
            input_bytes: data.len(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitControls {
    pub files: usize,
    pub hunks: usize,
    pub cancel_before: bool,
}

pub struct GitFrame<'a> {
    pub encoding: Encoding,
    pub controls: GitControls,
    pub patch: &'a [u8],
    pub input_bytes: usize,
}

impl<'a> GitFrame<'a> {
    /// V1: magic, file ceiling minus one, hunk ceiling minus one, pre-cancel
    /// (bit zero), patch bytes. Each control has its own byte.
    pub fn decode(data: &'a [u8], profile: Profile) -> Self {
        let data = bounded(data, profile, "git_patch");
        if data.len() >= GIT_HEADER_BYTES && data.starts_with(GIT_MAGIC) {
            return Self {
                encoding: Encoding::V1,
                controls: GitControls {
                    files: usize::from(data[4]) % MAX_GIT_FILES + 1,
                    hunks: usize::from(data[5]) % MAX_GIT_HUNKS + 1,
                    cancel_before: data[6] & 1 != 0,
                },
                patch: &data[GIT_HEADER_BYTES..],
                input_bytes: data.len(),
            };
        }
        let control = data.first().copied().unwrap_or_default();
        Self {
            encoding: Encoding::Legacy,
            controls: GitControls {
                files: usize::from(control & 0x1f) + 1,
                hunks: usize::from(control) + 1,
                cancel_before: control & 0x80 != 0,
            },
            patch: &data[data.len().min(1)..],
            input_bytes: data.len(),
        }
    }
}

fn bounded<'a>(data: &'a [u8], profile: Profile, target: &str) -> &'a [u8] {
    let maximum = profile.input_limit(target).expect("known source target");
    &data[..data.len().min(maximum)]
}

/// Synthetic v1 seeds for ordinary campaign initialization and proof tests.
/// Legacy committed and deep seeds remain unchanged and are still replayed.
pub fn seeds(target: &str) -> Vec<(&'static str, Vec<u8>)> {
    match target {
        "reader_schedule" => reader_seeds(),
        "git_patch" => git_seeds(),
        _ => Vec::new(),
    }
}

fn reader_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut ordinary = READER_MAGIC.to_vec();
    ordinary.extend_from_slice(&[3, 0, 0, 0, 0, 0, 3, 0]);
    ordinary.extend_from_slice(&[4, 4, 0x24]);
    ordinary.extend_from_slice(b"abcdEFGHijkl");
    let mut seeds = vec![("reader-v1-consume", ordinary.clone())];
    for (name, offset) in [
        ("reader-v1-stop", 6),
        ("reader-v1-callback-error", 7),
        ("reader-v1-pre-cancel", 8),
        ("reader-v1-callback-cancel", 9),
    ] {
        let mut data = ordinary.clone();
        data[offset] = 1;
        seeds.push((name, data));
    }
    for (name, instruction) in [
        ("reader-v1-data-error", 0x34),
        ("reader-v1-overreport", 0x80),
        ("reader-v1-zero-progress", 0),
    ] {
        let mut data = ordinary.clone();
        data[READER_HEADER_BYTES + 1] = instruction;
        seeds.push((name, data));
    }
    seeds
}

fn git_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut ordinary = GIT_MAGIC.to_vec();
    ordinary.extend_from_slice(&[1, 2, 0]);
    ordinary.extend_from_slice(b"diff --git a/one.txt b/one.txt\n--- a/one.txt\n+++ b/one.txt\n@@ -0,0 +1 @@\n+synthetic-one\n@@ -2,0 +3 @@\n+synthetic-two\ndiff --git a/two.txt b/two.txt\n--- a/two.txt\n+++ b/two.txt\n@@ -0,0 +1 @@\n+synthetic-three\n");
    let mut seeds = vec![("git-v1-parse", ordinary.clone())];
    for (name, offset, value) in [
        ("git-v1-file-limit", 4, 0),
        ("git-v1-hunk-limit", 5, 1),
        ("git-v1-pre-cancel", 6, 1),
    ] {
        let mut data = ordinary.clone();
        data[offset] = value;
        seeds.push((name, data));
    }
    seeds
}
