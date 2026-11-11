//! Synthetic archive and Git-archive scale workloads for the opt-in runner.
//!
//! Generators here produce high-ratio streams, deep nesting, wide archives, and
//! Git histories of archive blobs. Every expected count, path, and limit issue
//! is computed from the generator manifest and the documented archive limits,
//! never from decoder output.

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::hint::black_box;
use std::io::{Cursor, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustleaks_core::Engine;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{CommitMetadata, Finding, Fragment, ScanOptions};
use rustleaks_core::session::SessionPolicy;
use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, ArchiveSource, CallbackError, CancellationToken,
    DirectoryOptions, DirectorySource, FileOptions, GitMode, GitSource, Source, SourceControl,
    SourceEvent, SourceIssue, SourceIssueKind, SourceRunner, SourceTermination,
};
use serde_json::{Value, json};

use super::archive_seeds::{gzip_stored, synthetic_tar};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const SCOPE: &str = "representative-v1-operation-only";
const SIMPLE_CONFIG: &str = "[[rules]]\nid = 'perf-token'\ndescription = 'synthetic token'\nregex = 'A{16}'\nkeywords = ['AAAA']\n";
const TOKEN: &[u8; 16] = b"AAAAAAAAAAAAAAAA";
const GIT_AUTHOR: &str = "Performance Fixture";
const GIT_EMAIL: &str = "perf@example.invalid";
const GIT_BASE_TIME: u64 = 946_684_800; // 2000-01-01T00:00:00Z

/// Sizes and limits for one driver run. Unit tests use the small variant.
#[derive(Clone, Copy)]
pub struct Scale {
    limits: ArchiveLimits,
    zstd_files: usize,
    git_commits: usize,
}

impl Scale {
    #[allow(
        clippy::unnecessary_wraps,
        reason = "fixture constructors share one fallible signature"
    )]
    pub fn full() -> Result<Self> {
        Ok(Self {
            limits: ArchiveLimits::default(),
            zstd_files: 500,
            git_commits: 200,
        })
    }

    pub fn small() -> Result<Self> {
        Ok(Self {
            // Depth stays at the pinned default so nesting boundaries match.
            limits: ArchiveLimits::new(8, 16, 256 * KIB, 8 * MIB, MIB)?,
            zstd_files: 8,
            git_commits: 12,
        })
    }
}

pub fn run(id: &str, iterations: usize, scale: Scale) -> Result<Vec<Value>> {
    if !(1..=1_000).contains(&iterations) {
        return Err("archive scale iterations outside 1..=1000".into());
    }
    match id {
        "archive-high-ratio-gzip" => high_ratio(Codec::Gzip, iterations, scale),
        "archive-high-ratio-zstd" => high_ratio(Codec::Zstd, iterations, scale),
        "archive-high-ratio-bzip2" => high_ratio(Codec::Bzip2, iterations, scale),
        "archive-nested-depth-8" => nested(iterations, scale, 8),
        "archive-nested-depth-9" => nested(iterations, scale, 9),
        "archive-tar-10000-members" => tar_members(iterations, scale, false),
        "archive-tar-10001-members" => tar_members(iterations, scale, true),
        "archive-zstd-many-small" => zstd_many_small(iterations, scale),
        "git-archive-blobs" => git_archive_blobs(iterations, scale),
        _ => Err(format!("unknown archive scale workload {id}").into()),
    }
}

fn fingerprint(bytes: &[u8]) -> String {
    let hash = bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    format!("{hash:016x}")
}

struct RowInput<'a> {
    phase: &'a str,
    iterations: usize,
    elapsed: Duration,
    unit: &'a str,
    units: u64,
    input: &'a [u8],
    config: &'a [u8],
    outcome: &'a [u8],
    findings: usize,
    counts: Value,
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "row builders consume their borrowed inputs"
)]
fn row(input: RowInput<'_>) -> Result<Value> {
    Ok(json!({
        "phase": input.phase,
        "iterations": input.iterations,
        "elapsed_ns": u64::try_from(input.elapsed.as_nanos())?,
        "logical_unit": input.unit,
        "logical_units_per_iteration": input.units,
        "input_fnv1a64": fingerprint(input.input),
        "config_fnv1a64": fingerprint(input.config),
        "outcome_fnv1a64": fingerprint(input.outcome),
        "findings": input.findings,
        "errors": 0,
        "complete": true,
        "counts": input.counts,
        "scope": SCOPE,
    }))
}

/// Collects all fragments and issues without treating issues as errors.
fn collect(source: &mut dyn Source) -> Result<(Vec<Fragment>, Vec<SourceIssue>)> {
    let mut fragments = Vec::new();
    let mut issues = Vec::new();
    let control = source.visit(&CancellationToken::new(), &mut |event| {
        match event {
            SourceEvent::Fragment {
                fragment,
                issue: None,
            } => fragments.push(*fragment),
            SourceEvent::Issue(issue) => issues.push(issue),
            SourceEvent::Fragment { .. } => {
                return Err(CallbackError::new(
                    "archive scale fragment carried an issue",
                ));
            }
            _ => {
                return Err(CallbackError::new(
                    "archive scale received an unknown event",
                ));
            }
        }
        Ok(SourceControl::Continue)
    })?;
    if control != SourceControl::Continue {
        return Err("archive scale traversal stopped".into());
    }
    Ok((fragments, issues))
}

fn archive_options(limits: ArchiveLimits) -> ArchiveOptions {
    ArchiveOptions::new(limits).emit_limit_issues(true)
}

fn archive_source(payload: &[u8], name: &str, limits: ArchiveLimits) -> ArchiveSource {
    ArchiveSource::with_options(
        Cursor::new(payload.to_vec()),
        name,
        FileOptions::default(),
        archive_options(limits),
    )
}

// High-ratio streams.

#[derive(Clone, Copy)]
enum Codec {
    Gzip,
    Zstd,
    Bzip2,
}

impl Codec {
    fn name(self) -> &'static str {
        match self {
            Self::Gzip => "zeros.gz",
            Self::Zstd => "zeros.zst",
            Self::Bzip2 => "zeros.bz2",
        }
    }

    fn encode(self, zeros: usize, member_limit: usize) -> Result<Vec<u8>> {
        Ok(match self {
            Self::Gzip => gzip_zero_stream(zeros),
            Self::Zstd => zstd_rle_stream(zeros, zstd_window_exponent(member_limit)),
            Self::Bzip2 => bzip2_zero_stream(zeros)?,
        })
    }

    /// Exact expanded size nearest `target`; bzip2 runs are 255-zero tokens.
    fn expansion_size(self, target: usize) -> usize {
        match self {
            Self::Bzip2 => target / 255 * 255,
            _ => target,
        }
    }

    /// Smallest exact expanded size strictly above the member limit.
    fn over_limit_size(self, limit: usize) -> usize {
        match self {
            Self::Bzip2 => (limit / 255 + 1) * 255,
            _ => limit + 1,
        }
    }
}

/// Fragments for zero-filled input: read-ahead always hits its cap.
fn zero_fragment_bytes(total: usize) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut remaining = total;
    let mut first = true;
    while remaining > 0 {
        let size = if first { 125_000 } else { 28_672 }.min(remaining);
        sizes.push(size);
        remaining -= size;
        first = false;
    }
    sizes
}

fn high_ratio(codec: Codec, iterations: usize, scale: Scale) -> Result<Vec<Value>> {
    let member_limit = scale.limits.maximum_member_bytes();
    let under = codec.expansion_size(member_limit / 16 * 15);
    let over = codec.over_limit_size(member_limit);
    let under_payload = codec.encode(under, member_limit)?;
    let over_payload = codec.encode(over, member_limit)?;
    let config = format!(
        "archive-scale-v1;member={member_limit};total={};entries={};depth={}",
        scale.limits.maximum_total_bytes(),
        scale.limits.maximum_entries(),
        scale.limits.maximum_depth()
    );
    let expected_sizes = zero_fragment_bytes(under);
    let name = codec.name();
    let mut under_elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let mut source = archive_source(&under_payload, name, scale.limits);
        let start = Instant::now();
        let result = black_box(collect(&mut source));
        under_elapsed += start.elapsed();
        let (fragments, issues) = result?;
        if !issues.is_empty() {
            return Err(format!("{name} under the limit produced issues").into());
        }
        let sizes = fragments
            .iter()
            .map(|fragment| fragment.content().len())
            .collect::<Vec<_>>();
        if sizes != expected_sizes || fragments.iter().any(|fragment| !is_all_zero(fragment)) {
            return Err(format!("{name} expanded fragments differ from the manifest").into());
        }
    }
    let mut over_elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let mut source = archive_source(&over_payload, name, scale.limits);
        let start = Instant::now();
        let result = black_box(collect(&mut source));
        over_elapsed += start.elapsed();
        let (fragments, issues) = result?;
        let [issue] = issues.as_slice() else {
            return Err(format!("{name} over the limit produced {} issues", issues.len()).into());
        };
        if !fragments.is_empty()
            || issue.kind() != SourceIssueKind::Limit
            || issue.message() != "archive expansion limit exceeded"
        {
            return Err(format!("{name} over-limit outcome differs from the limits table").into());
        }
    }
    Ok(vec![
        row(RowInput {
            phase: "archive-expand-under-limit",
            iterations,
            elapsed: under_elapsed,
            unit: "expanded-bytes",
            units: under as u64,
            input: &under_payload,
            config: config.as_bytes(),
            outcome: format!("{expected_sizes:?}").as_bytes(),
            findings: 0,
            counts: json!({"expanded_bytes": under, "compressed_bytes": under_payload.len(), "fragments": expected_sizes.len(), "member_limit_bytes": member_limit, "scope": "in-memory decode and fragment emission; no detection"}),
        })?,
        row(RowInput {
            phase: "archive-expand-over-limit",
            iterations,
            elapsed: over_elapsed,
            unit: "expanded-bytes",
            units: over as u64,
            input: &over_payload,
            config: config.as_bytes(),
            outcome: b"one-limit-issue",
            findings: 0,
            counts: json!({"expanded_bytes_requested": over, "excess_over_limit_bytes": over - member_limit, "compressed_bytes": over_payload.len(), "limit_issues": 1, "member_limit_bytes": member_limit, "scope": "decode until the member limit rejects output"}),
        })?,
    ])
}

fn is_all_zero(fragment: &Fragment) -> bool {
    fragment.content().as_bytes().iter().all(|byte| *byte == 0)
}

fn gzip_zero_stream(zeros: usize) -> Vec<u8> {
    let data = vec![0_u8; zeros];
    let mut output = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    output.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(&data, 6));
    output.extend_from_slice(&crc32(&data).to_le_bytes());
    output.extend_from_slice(&u32::try_from(zeros).expect("bounded size").to_le_bytes());
    output
}

fn crc32(bytes: &[u8]) -> u32 {
    const fn table() -> [u32; 256] {
        let mut table = [0_u32; 256];
        let mut index = 0;
        while index < 256 {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "table indices are below 256"
            )]
            let mut crc = index as u32;
            let mut bit = 0;
            while bit < 8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
                bit += 1;
            }
            table[index] = crc;
            index += 1;
        }
        table
    }
    static TABLE: [u32; 256] = table();
    !bytes.iter().fold(!0_u32, |crc, byte| {
        (crc >> 8) ^ TABLE[((crc ^ u32::from(*byte)) & 0xff) as usize]
    })
}

/// Window exponent whose size fits the decoder history: `min(limit, 8 MiB)`.
fn zstd_window_exponent(member_limit: usize) -> u8 {
    u8::try_from(member_limit.ilog2().saturating_sub(10))
        .expect("window exponent fits a byte")
        .min(13)
}

/// A Zstandard frame of RLE blocks. Each block repeats a zero byte up to the
/// 128 KiB block maximum, so 60 MiB expands from about two kilobytes.
fn zstd_rle_stream(zeros: usize, window_exponent: u8) -> Vec<u8> {
    const MAX_RLE_BLOCK: usize = 128 * KIB;
    let mut output = zstd_frame_header(window_exponent);
    let mut remaining = zeros;
    loop {
        let block = remaining.min(MAX_RLE_BLOCK);
        remaining -= block;
        let header = (u32::try_from(block).expect("bounded block") << 3)
            | (1 << 1)
            | u32::from(remaining == 0);
        output.extend_from_slice(&header.to_le_bytes()[..3]);
        output.push(0);
        if remaining == 0 {
            return output;
        }
    }
}

/// A Zstandard frame of one raw block holding `payload` verbatim.
fn zstd_raw_frame(payload: &[u8], window_exponent: u8) -> Vec<u8> {
    let mut output = zstd_frame_header(window_exponent);
    let header = (u32::try_from(payload.len()).expect("bounded block") << 3) | 1;
    output.extend_from_slice(&header.to_le_bytes()[..3]);
    output.extend_from_slice(payload);
    output
}

/// Frame magic plus a window descriptor with no content size or checksum.
fn zstd_frame_header(window_exponent: u8) -> Vec<u8> {
    let mut output = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00];
    output.push(window_exponent << 3);
    output
}

/// Minimal bzip2 encoder for zero runs. `RUN_TOKEN` encodes 255 zero bytes as
/// four literal zeros and a repeat count of 251, and each block's BWT is a run
/// of the two byte values, computed analytically below.
fn bzip2_zero_stream(zeros: usize) -> Result<Vec<u8>> {
    const RUN_ZEROS: usize = 255;
    // 900,000 bytes minus the bzip2 19-byte block safety margin, in 5-byte tokens.
    const MAX_BLOCK_TOKENS: usize = 179_996;
    if !zeros.is_multiple_of(RUN_ZEROS) {
        return Err("bzip2 zero stream length must be a multiple of 255".into());
    }
    let mut writer = BitWriter::default();
    for byte in *b"BZh9" {
        writer.bits(8, u64::from(byte));
    }
    let mut remaining = zeros / RUN_ZEROS;
    let mut combined = 0_u32;
    while remaining > 0 {
        let tokens = remaining.min(MAX_BLOCK_TOKENS);
        let crc = bzip2_crc_of_zeros(tokens * RUN_ZEROS);
        combined = combined.rotate_left(1) ^ crc;
        write_zero_block(&mut writer, tokens, crc);
        remaining -= tokens;
    }
    writer.bits(48, 0x1772_4538_5090);
    writer.bits(32, u64::from(combined));
    Ok(writer.finish())
}

fn write_zero_block(writer: &mut BitWriter, tokens: usize, crc: u32) {
    writer.bits(48, 0x3141_5926_5359);
    writer.bits(32, u64::from(crc));
    writer.bits(1, 0); // not randomized
    writer.bits(24, 0); // origPtr: any identical rotation decodes identically
    // Used-symbol map: bytes 0 and 251 (group 0 bit 0, group 15 offset 11).
    writer.bits(16, 0b1000_0000_0000_0001);
    writer.bits(16, 0b1000_0000_0000_0000);
    writer.bits(16, 0b0000_0000_0001_0000);
    // Alphabet RUNA, RUNB, MTF-one, EOB with length-2 codes in symbol order.
    let symbols = zero_block_symbols(tokens);
    let selectors = symbols.len().div_ceil(50).max(1);
    writer.bits(3, 2);
    writer.bits(15, selectors as u64);
    for _ in 0..selectors {
        writer.bits(1, 0);
    }
    for _ in 0..2 {
        writer.bits(5, 2);
        for _ in 0..4 {
            writer.bits(1, 0);
        }
    }
    for symbol in symbols {
        writer.bits(2, u64::from(symbol));
    }
}

/// The 5-periodic RLE block sorts to rotation classes whose last column is
/// `f^k z^(4k)`, with z the zero byte and f the run count 251. After the
/// initial MTF list [z, f], that output is MTF1, a zero run of k-1, MTF1, a
/// zero run of 4k-1, and end of block, using bzip2 bijective RUNA/RUNB runs.
fn zero_block_symbols(tokens: usize) -> Vec<u8> {
    let mut symbols = vec![2];
    push_run(&mut symbols, tokens - 1);
    symbols.push(2);
    push_run(&mut symbols, 4 * tokens - 1);
    symbols.push(3);
    symbols
}

fn push_run(symbols: &mut Vec<u8>, mut run: usize) {
    while run > 0 {
        if run % 2 == 1 {
            symbols.push(0);
            run = (run - 1) / 2;
        } else {
            symbols.push(1);
            run = (run - 2) / 2;
        }
    }
}

fn bzip2_crc_of_zeros(bytes: usize) -> u32 {
    let mut crc = u32::MAX;
    for _ in 0..bytes {
        // Each iteration is the bitwise form of (crc << 8) ^ table[crc >> 24].
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            };
        }
    }
    !crc
}

#[derive(Default)]
struct BitWriter {
    output: Vec<u8>,
    accumulator: u64,
    filled: u32,
}

impl BitWriter {
    fn bits(&mut self, count: u32, value: u64) {
        for shift in (0..count).rev() {
            self.accumulator = (self.accumulator << 1) | ((value >> shift) & 1);
            self.filled += 1;
            if self.filled == 8 {
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "eight accumulated bits fit one byte"
                )]
                self.output.push(self.accumulator as u8);
                self.accumulator = 0;
                self.filled = 0;
            }
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.filled > 0 {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "fewer than eight accumulated bits fit one byte"
            )]
            self.output
                .push((self.accumulator << (8 - self.filled)) as u8);
        }
        self.output
    }
}

// Nested archives and wide TAR members.

/// Builds `layers` TAR archives nested inside one another, the innermost one
/// containing `secret.txt`. Layer names are `layer-<i>.tar`.
#[allow(
    clippy::unnecessary_wraps,
    reason = "fixture constructors share one fallible signature"
)]
fn nested_archive(layers: usize, payload: &[u8]) -> Result<Vec<u8>> {
    let mut inner = synthetic_tar(&[("secret.txt", payload)]);
    for layer in (1..layers).rev() {
        let name = format!("layer-{layer}.tar");
        inner = synthetic_tar(&[(name.as_str(), inner.as_slice())]);
    }
    Ok(inner)
}

fn nested(iterations: usize, scale: Scale, layers: usize) -> Result<Vec<Value>> {
    let payload = b"nested payload line\n".to_vec();
    let archive = nested_archive(layers, &payload)?;
    let mut expected_path = "layer-0.tar".to_owned();
    for layer in 1..layers {
        #[allow(
            clippy::format_push_string,
            reason = "this bounded fixture path is built outside any timer"
        )]
        expected_path.push_str(&format!("!layer-{layer}.tar"));
    }
    expected_path.push_str("!secret.txt");
    let depth_limit = scale.limits.maximum_depth();
    let mut elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let mut source = archive_source(&archive, "layer-0.tar", scale.limits);
        let start = Instant::now();
        let result = black_box(collect(&mut source));
        elapsed += start.elapsed();
        let (fragments, issues) = result?;
        // Layers 0..depth-1 are expanded; a layer at index `depth` is skipped.
        if layers <= depth_limit {
            let [fragment] = fragments.as_slice() else {
                return Err("nested archive under the depth limit lost its member".into());
            };
            if !issues.is_empty()
                || fragment.content().as_bytes() != payload.as_slice()
                || fragment.file_path().as_bytes() != expected_path.as_bytes()
                || fragment.start_line() != 1
            {
                return Err("nested archive member differs from the manifest".into());
            }
        } else {
            let [issue] = issues.as_slice() else {
                return Err(format!("nested archive produced {} issues", issues.len()).into());
            };
            if !fragments.is_empty()
                || issue.kind() != SourceIssueKind::Limit
                || issue.message() != "skipping archive: exceeds maximum archive depth"
            {
                return Err("nested archive depth limit differs from the limits table".into());
            }
        }
    }
    Ok(vec![row(RowInput {
        phase: "archive-expand-nested-layers",
        iterations,
        elapsed,
        unit: "archive-layers",
        units: layers as u64,
        input: &archive,
        config: format!("archive-scale-v1;depth={depth_limit}").as_bytes(),
        outcome: expected_path.as_bytes(),
        findings: 0,
        counts: json!({"layers": layers, "depth_limit": depth_limit, "limit_issues": usize::from(layers > depth_limit), "payload_bytes": payload.len()}),
    })?])
}

fn tar_members(iterations: usize, scale: Scale, over: bool) -> Result<Vec<Value>> {
    let limit = scale.limits.maximum_entries();
    let members = limit + usize::from(over);
    let mut entries = Vec::with_capacity(members);
    let mut expected = Vec::with_capacity(limit);
    for index in 0..members {
        let name = format!("member-{index:06}.txt");
        let content = format!(
            "member row {index:06}\n{}\n",
            "synthetic padding ".repeat(2)
        );
        entries.push((name, content.into_bytes()));
    }
    let borrowed: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(name, content)| (name.as_str(), content.as_slice()))
        .collect();
    let archive = synthetic_tar(&borrowed);
    for (name, content) in entries.iter().take(limit) {
        expected.push((format!("wide.tar!{name}"), content.clone()));
    }
    let mut elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let mut source = archive_source(&archive, "wide.tar", scale.limits);
        let start = Instant::now();
        let result = black_box(collect(&mut source));
        elapsed += start.elapsed();
        let (fragments, issues) = result?;
        let exact = fragments.len() == expected.len()
            && fragments
                .iter()
                .zip(&expected)
                .all(|(fragment, (path, content))| {
                    fragment.file_path().as_bytes() == path.as_bytes()
                        && fragment.content().as_bytes() == content.as_slice()
                        && fragment.start_line() == 1
                });
        if !exact {
            return Err("TAR member fragments differ from the manifest".into());
        }
        match (over, issues.as_slice()) {
            (false, []) => {}
            (true, [issue])
                if issue.kind() == SourceIssueKind::Limit
                    && issue.message() == "archive entry limit exceeded" => {}
            _ => {
                return Err(format!("TAR member limit produced {} issues", issues.len()).into());
            }
        }
    }
    let bytes: usize = expected.iter().map(|(_, content)| content.len()).sum();
    Ok(vec![row(RowInput {
        phase: "archive-expand-members",
        iterations,
        elapsed,
        unit: "members",
        units: limit as u64,
        input: &archive,
        config: format!("archive-scale-v1;entries={limit}").as_bytes(),
        outcome: format!("{}:{}", expected.len(), usize::from(over)).as_bytes(),
        findings: 0,
        counts: json!({"members_in_archive": members, "entry_limit": limit, "members_emitted": expected.len(), "member_bytes_total": bytes, "limit_issues": usize::from(over)}),
    })?])
}

// Many small zstd files.

fn zstd_many_small(iterations: usize, scale: Scale) -> Result<Vec<Value>> {
    let scratch = Scratch::new()?;
    let input = scratch.0.join("input");
    fs::create_dir(&input)?;
    let window_exponent = zstd_window_exponent(scale.limits.maximum_member_bytes());
    let mut expected = Vec::with_capacity(scale.zstd_files);
    for index in 0..scale.zstd_files {
        let mut payload = format!("synthetic zstd member {index:06}\n").into_bytes();
        payload.resize(KIB, b'.');
        payload[KIB - 1] = b'\n';
        let name = format!("blob-{index:06}.zst");
        fs::write(input.join(&name), zstd_raw_frame(&payload, window_exponent))?;
        expected.push((format!("input/{name}"), payload));
    }
    let mut elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let mut source = DirectorySource::with_options(
            &input,
            DirectoryOptions::default()
                .logical_root("input")
                .archives(archive_options(scale.limits)),
        );
        let start = Instant::now();
        let result = black_box(collect(&mut source));
        elapsed += start.elapsed();
        let (fragments, issues) = result?;
        let exact = issues.is_empty()
            && fragments.len() == expected.len()
            && fragments
                .iter()
                .zip(&expected)
                .all(|(fragment, (path, content))| {
                    fragment.file_path().as_bytes() == path.as_bytes()
                        && fragment.content().as_bytes() == content.as_slice()
                        && fragment.start_line() == 1
                });
        if !exact {
            return Err("zstd member fragments differ from the manifest".into());
        }
    }
    let bytes: usize = expected.iter().map(|(_, content)| content.len()).sum();
    Ok(vec![row(RowInput {
        phase: "archive-expand-many-files",
        iterations,
        elapsed,
        unit: "expanded-bytes",
        units: bytes as u64,
        input: format!("zstd-many-small-v1;{}", scale.zstd_files).as_bytes(),
        config: format!(
            "archive-scale-v1;member={}",
            scale.limits.maximum_member_bytes()
        )
        .as_bytes(),
        outcome: format!("{}:{bytes}", expected.len()).as_bytes(),
        findings: 0,
        counts: json!({"files": scale.zstd_files, "decoded_bytes_total": bytes, "maximum_member_bytes": scale.limits.maximum_member_bytes(), "declared_window_bytes": 1024_usize << window_exponent, "peak_rss": "recorded by the representative collector for the whole child process"}),
    })?])
}

// Git commits touching archive blobs.

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rustleaks-perf-archive-scale-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        fs::create_dir(root.join("empty"))?;
        fs::write(root.join("empty-config"), b"")?;
        Ok(Self(root))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn git_executable() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("RUSTLEAKS_PERF_GIT") {
        let path = PathBuf::from(path);
        if !path.is_absolute() || !path.is_file() {
            return Err("RUSTLEAKS_PERF_GIT must name an existing absolute executable".into());
        }
        return Ok(path);
    }
    Err("RUSTLEAKS_PERF_GIT is required for the Git archive-blob workload".into())
}

fn git_environment(root: &Path) -> Vec<(OsString, OsString)> {
    let text = OsString::from;
    vec![
        (text("GIT_CONFIG_NOSYSTEM"), text("1")),
        (
            text("GIT_CONFIG_SYSTEM"),
            root.join("empty-config").into_os_string(),
        ),
        (
            text("GIT_CONFIG_GLOBAL"),
            root.join("empty-config").into_os_string(),
        ),
        (text("GIT_CONFIG_COUNT"), text("3")),
        (text("GIT_CONFIG_KEY_0"), text("core.hooksPath")),
        (
            text("GIT_CONFIG_VALUE_0"),
            root.join("empty").into_os_string(),
        ),
        (text("GIT_CONFIG_KEY_1"), text("core.attributesFile")),
        (
            text("GIT_CONFIG_VALUE_1"),
            root.join("empty-config").into_os_string(),
        ),
        (text("GIT_CONFIG_KEY_2"), text("core.autocrlf")),
        (text("GIT_CONFIG_VALUE_2"), text("false")),
        (text("GIT_TERMINAL_PROMPT"), text("0")),
        (text("GIT_OPTIONAL_LOCKS"), text("0")),
        (text("LC_ALL"), text("C")),
        (text("TZ"), text("UTC")),
    ]
}

fn git_command(executable: &Path, root: &Path) -> Command {
    let mut command = Command::new(executable);
    command
        .env_clear()
        .current_dir(root)
        .envs(git_environment(root));
    for name in ["SystemRoot", "WINDIR", "TMPDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

fn git_run(mut command: Command, input: Option<&[u8]>) -> Result<()> {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or("child stdin missing")?
            .write_all(input)?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "synthetic Git command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

/// A distinct `.tar.gz` blob holding two members with one planted token each.
fn git_archive_blob(blob: usize) -> (Vec<u8>, [GitArchiveMember; 2]) {
    let first = format!("{}\nblob {blob} body\n", String::from_utf8_lossy(TOKEN));
    let second = format!(
        "blob {blob} heading\n{}\ntail row {blob}\n",
        String::from_utf8_lossy(TOKEN)
    );
    let tar = synthetic_tar(&[
        ("first.txt", first.as_bytes()),
        ("second.txt", second.as_bytes()),
    ]);
    (
        gzip_stored(&tar),
        [
            GitArchiveMember {
                name: "first.txt",
                content: first.into_bytes(),
                token_line: 1,
            },
            GitArchiveMember {
                name: "second.txt",
                content: second.into_bytes(),
                token_line: 2,
            },
        ],
    )
}

struct GitArchiveMember {
    name: &'static str,
    content: Vec<u8>,
    token_line: usize,
}

fn git_archive_fragment(member: &GitArchiveMember, sha: &str, commit: usize) -> Fragment {
    let path = format!("pack.tar.gz!{}", member.name);
    let metadata = CommitMetadata::builder()
        .sha(sha)
        .author_name(GIT_AUTHOR)
        .author_email(GIT_EMAIL)
        .date(format!(
            "2000-01-01T{:02}:{:02}:{:02}Z",
            commit / 3600,
            commit / 60 % 60,
            commit % 60
        ))
        .message(b"fixture")
        .build();
    let mut builder = Fragment::builder(member.content.clone())
        .file_path(path.clone())
        .commit(sha)
        .start_line(1)
        .commit_metadata(metadata);
    if cfg!(windows) {
        builder = builder.windows_file_path(path);
    }
    builder.build()
}

fn sort_git_archive_fragments(fragments: &mut [Fragment]) {
    fragments.sort_by(|left, right| {
        left.commit()
            .cmp(right.commit())
            .then_with(|| left.file_path().cmp(right.file_path()))
    });
}

/// The generated manifest has one fragment per member and unique commit/path
/// pairs. Compare every retained field after ignoring only emission order.
fn verify_git_archive_fragments(actual: &mut [Fragment], expected: &[Fragment]) -> Result<()> {
    sort_git_archive_fragments(actual);
    if actual != expected {
        return Err("Git archive fragments differ from the generator manifest".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FindingKey {
    file: Vec<u8>,
    commit: Vec<u8>,
    line: usize,
    column: usize,
    secret: Vec<u8>,
}

fn finding_keys(findings: &[Finding]) -> Vec<FindingKey> {
    let mut keys = findings
        .iter()
        .map(|finding| FindingKey {
            file: finding.file().as_bytes().to_vec(),
            commit: finding.commit().as_bytes().to_vec(),
            line: finding.location().start_line(),
            column: finding.location().start_column(),
            secret: finding.secret().as_bytes().to_vec(),
        })
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

#[allow(
    clippy::too_many_lines,
    reason = "keep repository setup, timers, and exact expectations together"
)]
fn git_archive_blobs(iterations: usize, scale: Scale) -> Result<Vec<Value>> {
    let git = git_executable()?;
    let scratch = Scratch::new()?;
    let repository = scratch.0.join("repo");
    let mut init = git_command(&git, &scratch.0);
    init.arg("init")
        .arg("--quiet")
        .arg("--initial-branch=main")
        .arg("--object-format=sha1")
        .arg("--template")
        .arg(scratch.0.join("empty"))
        .arg(&repository);
    git_run(init, None)?;
    let blobs: Vec<_> = (0..4).map(git_archive_blob).collect();
    let mut stream = Vec::new();
    for commit in 0..scale.git_commits {
        let time = GIT_BASE_TIME + commit as u64;
        let (payload, _) = &blobs[commit % blobs.len()];
        stream.extend_from_slice(
            format!(
                "commit refs/heads/main\nmark :{}\nauthor {GIT_AUTHOR} <{GIT_EMAIL}> {time} +0000\ncommitter {GIT_AUTHOR} <{GIT_EMAIL}> {time} +0000\ndata 7\nfixture\n",
                commit + 1
            )
            .as_bytes(),
        );
        if commit > 0 {
            stream.extend_from_slice(format!("from :{commit}\n").as_bytes());
        }
        stream.extend_from_slice(
            format!("M 100644 inline pack.tar.gz\ndata {}\n", payload.len()).as_bytes(),
        );
        stream.extend_from_slice(payload);
        stream.extend_from_slice(b"\n\n");
    }
    stream.extend_from_slice(b"done\n");
    let marks_path = scratch.0.join("marks");
    let mut import = git_command(&git, &scratch.0);
    import
        .arg("-C")
        .arg(&repository)
        .arg("fast-import")
        .arg("--quiet")
        .arg("--done")
        .arg(format!("--export-marks={}", marks_path.display()));
    git_run(import, Some(&stream))?;
    let marks = fs::read_to_string(&marks_path)?;
    let mut shas = vec![String::new(); scale.git_commits];
    for line in marks.lines() {
        let (mark, sha) = line
            .strip_prefix(':')
            .and_then(|rest| rest.split_once(' '))
            .ok_or("malformed Git marks line")?;
        sha.clone_into(&mut shas[mark.parse::<usize>()? - 1]);
    }
    let mut expected = Vec::new();
    let mut expected_fragments = Vec::new();
    for (commit, sha) in shas.iter().enumerate() {
        let (_, members) = &blobs[commit % blobs.len()];
        for member in members {
            expected_fragments.push(git_archive_fragment(member, sha, commit));
            expected.push(FindingKey {
                file: format!("pack.tar.gz!{}", member.name).into_bytes(),
                commit: sha.clone().into_bytes(),
                line: member.token_line,
                // Line-initial token: column 1 on a fragment's first line,
                // otherwise start - previous newline + 1, which is 2.
                column: if member.token_line == 1 { 1 } else { 2 },
                secret: TOKEN.to_vec(),
            });
        }
    }
    expected.sort();
    sort_git_archive_fragments(&mut expected_fragments);
    let fragment_manifest = serde_json::to_vec(&expected_fragments)?;
    let source = || -> Result<GitSource> {
        Ok(GitSource::new(&repository)
            .executable(git.clone().into_os_string())
            .mode(GitMode::LogArguments(
                [
                    "--all",
                    "--full-history",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-renames",
                ]
                .map(OsString::from)
                .to_vec(),
            ))
            .archives(archive_options(scale.limits))
            .command_environment(git_environment(&scratch.0)))
    };
    let engine = Engine::builder(ConfigLoader::new().load_toml(SIMPLE_CONFIG)?).build()?;
    let runner = SourceRunner::new(1, 8)?;
    let policy = SessionPolicy::default();
    let cancellation = CancellationToken::new();
    let counts = json!({"commits": scale.git_commits, "distinct_blobs": blobs.len(), "members_per_blob": 2, "tokens_per_blob": 2, "expected_findings": expected.len(), "filesystem_state": "setup-written-cache-uncontrolled", "workers": 1, "queue_capacity": 8});
    let mut parse_elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let mut git_source = source()?;
        let start = Instant::now();
        let result = black_box(collect(&mut git_source));
        parse_elapsed += start.elapsed();
        let (mut fragments, issues) = result?;
        if !issues.is_empty() || fragments.len() != expected.len() {
            return Err(format!(
                "Git archive blobs produced {} fragments and {} issues, manifest expects {}",
                fragments.len(),
                issues.len(),
                expected.len()
            )
            .into());
        }
        verify_git_archive_fragments(&mut fragments, &expected_fragments)?;
    }
    let mut detection_elapsed = Duration::ZERO;
    let mut outcome = Vec::new();
    for _ in 0..iterations {
        let mut git_source = source()?;
        let start = Instant::now();
        let result = black_box(runner.run(
            &mut git_source,
            &engine,
            ScanOptions::default(),
            &policy,
            &cancellation,
        ));
        detection_elapsed += start.elapsed();
        if result.termination() != &SourceTermination::Completed || !result.issues().is_empty() {
            return Err("Git archive blob scan stopped or produced issues".into());
        }
        let keys = finding_keys(result.findings());
        if keys != expected {
            return Err(format!(
                "Git archive blob findings differ from the manifest: expected {}, observed {}",
                expected.len(),
                keys.len()
            )
            .into());
        }
        outcome = format!("{keys:?}").into_bytes();
    }
    let bytes = stream.len() as u64;
    Ok(vec![
        row(RowInput {
            phase: "git-history-and-parse",
            iterations,
            elapsed: parse_elapsed,
            unit: "git-stream-bytes",
            units: bytes,
            input: &stream,
            config: b"no-scan",
            outcome: &fragment_manifest,
            findings: 0,
            counts: counts.clone(),
        })?,
        row(RowInput {
            phase: "git-history-and-detection",
            iterations,
            elapsed: detection_elapsed,
            unit: "git-stream-bytes",
            units: bytes,
            input: &stream,
            config: SIMPLE_CONFIG.as_bytes(),
            outcome: &outcome,
            findings: expected.len(),
            counts,
        })?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_archive_verifier_rejects_changes_that_preserve_fragment_count() {
        let (_, members) = git_archive_blob(0);
        let mut expected = members
            .iter()
            .map(|member| git_archive_fragment(member, "synthetic-commit", 0))
            .collect::<Vec<_>>();
        sort_git_archive_fragments(&mut expected);

        let mut reordered = expected.clone();
        reordered.reverse();
        verify_git_archive_fragments(&mut reordered, &expected).unwrap();
        assert!(verify_git_archive_fragments(&mut expected[..1].to_vec(), &expected).is_err());

        let mut duplicate = vec![expected[0].clone(), expected[0].clone()];
        assert!(verify_git_archive_fragments(&mut duplicate, &expected).is_err());

        // Preserve both planted tokens while altering only non-token bytes.
        let changed_member = GitArchiveMember {
            name: members[0].name,
            content: [TOKEN.as_slice(), b"\nwrong clean body\n"].concat(),
            token_line: members[0].token_line,
        };
        let wrong_line = Fragment::builder(members[0].content.clone())
            .file_path(expected[0].file_path().clone())
            .windows_file_path(expected[0].windows_file_path().clone())
            .commit(expected[0].commit().clone())
            .commit_metadata(expected[0].commit_metadata().unwrap().clone())
            .start_line(2)
            .build();
        for replacement in [
            git_archive_fragment(&changed_member, "synthetic-commit", 0),
            expected[0].clone().with_source_paths(
                "wrong-path".into(),
                expected[0].symlink_file().clone(),
                expected[0].windows_file_path().clone(),
            ),
            git_archive_fragment(&members[0], "wrong-commit", 0),
            git_archive_fragment(&members[0], "synthetic-commit", 1),
            wrong_line,
        ] {
            let mut changed = vec![replacement, expected[1].clone()];
            assert!(verify_git_archive_fragments(&mut changed, &expected).is_err());
        }
    }
}
