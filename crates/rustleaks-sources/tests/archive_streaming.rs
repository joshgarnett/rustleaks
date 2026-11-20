//! Streamed archive members give fixed fragments and findings, and large
//! archives scan with bounded storage.
//!
//! Member reads fill the buffer unless the member ends, so fragments do not
//! depend on how a decoder splits its output. 7z members are read one chunk
//! at a time. The reference functions below rebuild both read patterns from
//! the member bytes and the 7z decoder, independently of the archive source,
//! and the tests compare fragments and findings.
#![cfg(feature = "archives")]
#![forbid(unsafe_code)]

#[path = "../fuzz/support/archive_frame.rs"]
#[allow(dead_code)]
mod archive_frame;
#[path = "../fuzz/support/archive_seeds.rs"]
#[allow(dead_code)]
mod archive_seeds;
#[path = "../fuzz/support/sevenz_seeds.rs"]
#[allow(dead_code)]
mod sevenz_seeds;

use std::fs;
use std::io::{Cursor, Read};
use std::path::PathBuf;

use rustleaks_core::Engine;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_rar_codec::crc32::{Crc32, crc32};
use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, ArchiveSource, CancellationToken, DirectoryOptions,
    DirectorySource, FileOptions, FileSource, Source, SourceControl, SourceError, SourceEvent,
    SourceIssueKind,
};
use sevenz_seeds::{Member, Method};

const PIECE: usize = 100_000;

/// Synthetic text with tokens at and across piece and read-ahead boundaries.
fn content(size: usize, seed: u8) -> Vec<u8> {
    let words: [&[u8]; 6] = [
        b"alpha ",
        b"bravo ",
        b"charlie ",
        b"delta ",
        b"echo ",
        b"fox ",
    ];
    let mut output = Vec::with_capacity(size);
    let mut line = 0_usize;
    while output.len() < size {
        for index in 0..9 {
            output.extend_from_slice(words[(index + line + usize::from(seed)) % words.len()]);
        }
        output.push(b'\n');
        // A blank line now and then gives the boundary search a safe split.
        if line % 97 == 13 {
            output.push(b'\n');
        }
        line += 1;
    }
    output.truncate(size);
    let token = |at: usize, output: &mut Vec<u8>, id: &[u8; 4]| {
        if at + 10 <= output.len() {
            output[at..at + 6].copy_from_slice(b"token=");
            output[at + 6..at + 10].copy_from_slice(id);
        }
    };
    token(10, &mut output, b"A001");
    token(4_093, &mut output, b"B002");
    // Across the first piece boundary at 100,000 bytes.
    token(PIECE - 5, &mut output, b"C003");
    token(PIECE + 24_997, &mut output, b"D004");
    token(2 * PIECE - 3, &mut output, b"E005");
    if size >= 10 {
        token(size - 10, &mut output, b"F006");
    }
    output
}

fn sizes() -> [usize; 7] {
    [1, 4_096, PIECE - 1, PIECE, PIECE + 1, 250_000, 300_007]
}

fn engine() -> Engine {
    Engine::builder(
        ConfigLoader::new()
            .load_toml("[[rules]]\nid='token'\nregex='token=([A-Z0-9]{4})'\nkeywords=['token']\n")
            .unwrap(),
    )
    .build()
    .unwrap()
}

/// Fragments of one source, failing on any issue.
fn fragments(source: &mut dyn Source) -> Vec<Fragment> {
    let mut fragments = Vec::new();
    let control = source
        .visit(&CancellationToken::new(), &mut |event| {
            match event {
                SourceEvent::Fragment {
                    fragment,
                    issue: None,
                } => fragments.push(*fragment),
                SourceEvent::Fragment {
                    issue: Some(issue), ..
                }
                | SourceEvent::Issue(issue) => panic!("unexpected issue: {issue:?}"),
                _ => unreachable!("future source event"),
            }
            Ok(SourceControl::Continue)
        })
        .expect("source scan succeeds");
    assert_eq!(control, SourceControl::Continue);
    fragments
}

/// The fragments that a whole member read from a cursor gives.
fn cursor_reference(member: &[u8], path: &str) -> Vec<(String, usize, Vec<u8>)> {
    with_path(
        fragments(&mut FileSource::new(Cursor::new(member.to_vec()), "member")),
        path,
    )
}

/// Replays recorded read sizes, as the 7z path did before streaming.
struct Chunked {
    data: Vec<u8>,
    chunks: Vec<usize>,
    position: usize,
    chunk: usize,
    chunk_end: usize,
}

impl Read for Chunked {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() || self.position == self.data.len() {
            return Ok(0);
        }
        while self.position == self.chunk_end && self.chunk + 1 < self.chunks.len() {
            self.chunk += 1;
            self.chunk_end += self.chunks[self.chunk];
        }
        let count = output.len().min(self.chunk_end - self.position);
        output[..count].copy_from_slice(&self.data[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

/// The fragments of each 7z member read with chunk-sized reads, by name.
fn seven_reference(archive: &[u8], prefix: &str) -> Vec<(String, usize, Vec<u8>)> {
    let mut reader = rustleaks_sevenz::ArchiveReader::new(Cursor::new(archive.to_vec())).unwrap();
    let mut members = Vec::new();
    reader
        .for_each_entries(|entry, stream| {
            let mut data = Vec::new();
            let mut chunks = Vec::new();
            let mut buffer = vec![0_u8; PIECE];
            loop {
                let count = stream.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                data.extend_from_slice(&buffer[..count]);
                chunks.push(count);
            }
            members.push((entry.name().to_owned(), data, chunks));
            Ok(true)
        })
        .unwrap();
    let mut expected = Vec::new();
    for (name, data, chunks) in members {
        let chunk_end = chunks.first().copied().unwrap_or(data.len());
        let replay = Chunked {
            data,
            chunks,
            position: 0,
            chunk: 0,
            chunk_end,
        };
        expected.extend(with_path(
            fragments(&mut FileSource::new(replay, "member")),
            &format!("{prefix}!{name}"),
        ));
    }
    expected
}

fn with_path(fragments: Vec<Fragment>, path: &str) -> Vec<(String, usize, Vec<u8>)> {
    fragments
        .into_iter()
        .map(|fragment| {
            (
                path.to_owned(),
                fragment.start_line(),
                fragment.content().as_bytes().to_vec(),
            )
        })
        .collect()
}

fn summary(fragments: &[Fragment]) -> Vec<(String, usize, Vec<u8>)> {
    fragments
        .iter()
        .map(|fragment| {
            (
                fragment.file_path().to_string_lossy().into_owned(),
                fragment.start_line(),
                fragment.content().as_bytes().to_vec(),
            )
        })
        .collect()
}

/// Findings as rule, file, secret, location and fingerprint.
fn findings(fragments: &[(String, usize, Vec<u8>)]) -> Vec<String> {
    let engine = engine();
    let mut output = Vec::new();
    for (path, line, bytes) in fragments {
        let fragment = Fragment::builder(bytes.clone())
            .file_path(path.as_str())
            .start_line(*line)
            .build();
        for finding in engine
            .scan_fragment(&fragment, &ScanOptions::default())
            .findings()
        {
            output.push(format!(
                "{}|{}|{}|{:?}|{}",
                finding.rule_id().to_string_lossy(),
                finding.file().to_string_lossy(),
                finding.secret().to_string_lossy(),
                finding.location(),
                finding.fingerprint().to_string_lossy(),
            ));
        }
    }
    output
}

fn archive(bytes: Vec<u8>, name: &str) -> ArchiveSource {
    ArchiveSource::with_options(
        Cursor::new(bytes),
        name,
        FileOptions::default(),
        ArchiveOptions::new(ArchiveLimits::new(8, 1_000, 64 << 20, 1 << 30, 64 << 20).unwrap()),
    )
}

/// Checks that streaming gives the reference fragments and findings.
fn assert_same(actual: &[Fragment], expected: &[(String, usize, Vec<u8>)], case: &str) {
    let actual = summary(actual);
    assert_eq!(actual.len(), expected.len(), "{case}: fragment count");
    for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        assert_eq!(actual.0, expected.0, "{case}: path of fragment {index}");
        assert_eq!(actual.1, expected.1, "{case}: line of fragment {index}");
        assert!(actual.2 == expected.2, "{case}: bytes of fragment {index}");
    }
    let expected_findings = findings(expected);
    assert!(
        !expected_findings.is_empty(),
        "{case}: no findings to compare"
    );
    assert_eq!(findings(&actual), expected_findings, "{case}: findings");
}

fn gzip(payload: &[u8]) -> Vec<u8> {
    let mut output = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    output.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(payload, 6));
    output.extend_from_slice(&crc32(payload).to_le_bytes());
    output.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    output
}

/// A ZIP of stored or DEFLATE members.
fn zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut central = Vec::new();
    for &(name, body, deflate) in entries {
        let packed = if deflate {
            miniz_oxide::deflate::compress_to_vec(body, 6)
        } else {
            body.to_vec()
        };
        let method: u16 = if deflate { 8 } else { 0 };
        let crc = crc32(body).to_le_bytes();
        let packed_size = u32::try_from(packed.len()).unwrap().to_le_bytes();
        let size = u32::try_from(body.len()).unwrap().to_le_bytes();
        let name_size = u16::try_from(name.len()).unwrap().to_le_bytes();
        let offset = u32::try_from(data.len()).unwrap().to_le_bytes();
        let mut local = [0_u8; 30];
        local[..4].copy_from_slice(b"PK\x03\x04");
        local[4..6].copy_from_slice(&20_u16.to_le_bytes());
        local[8..10].copy_from_slice(&method.to_le_bytes());
        local[14..18].copy_from_slice(&crc);
        local[18..22].copy_from_slice(&packed_size);
        local[22..26].copy_from_slice(&size);
        local[26..28].copy_from_slice(&name_size);
        data.extend_from_slice(&local);
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(&packed);
        let mut entry = [0_u8; 46];
        entry[..4].copy_from_slice(b"PK\x01\x02");
        entry[4..6].copy_from_slice(&20_u16.to_le_bytes());
        entry[6..8].copy_from_slice(&20_u16.to_le_bytes());
        entry[10..12].copy_from_slice(&method.to_le_bytes());
        entry[16..20].copy_from_slice(&crc);
        entry[20..24].copy_from_slice(&packed_size);
        entry[24..28].copy_from_slice(&size);
        entry[28..30].copy_from_slice(&name_size);
        entry[42..46].copy_from_slice(&offset);
        central.extend_from_slice(&entry);
        central.extend_from_slice(name.as_bytes());
    }
    let mut end = [0_u8; 22];
    end[..4].copy_from_slice(b"PK\x05\x06");
    let count = u16::try_from(entries.len()).unwrap().to_le_bytes();
    end[8..10].copy_from_slice(&count);
    end[10..12].copy_from_slice(&count);
    end[12..16].copy_from_slice(&u32::try_from(central.len()).unwrap().to_le_bytes());
    end[16..20].copy_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
    data.extend_from_slice(&central);
    data.extend_from_slice(&end);
    data
}

fn put_vint(output: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = u8::try_from(value & 0x7f).unwrap();
        value >>= 7;
        output.push(if value == 0 { byte } else { byte | 0x80 });
        if value == 0 {
            return;
        }
    }
}

fn rar_block(output: &mut Vec<u8>, kind: u64, flags: u64, data: &[u8], payload: &[u8]) {
    let mut header = Vec::new();
    put_vint(&mut header, kind);
    put_vint(&mut header, flags);
    if flags & 2 != 0 {
        put_vint(&mut header, payload.len() as u64);
    }
    header.extend_from_slice(data);
    let mut checked = Vec::new();
    put_vint(&mut checked, header.len() as u64);
    checked.extend_from_slice(&header);
    output.extend_from_slice(&crc32(&checked).to_le_bytes());
    output.extend_from_slice(&checked);
    output.extend_from_slice(payload);
}

/// A RAR5 archive of stored members.
fn rar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut output = b"Rar!\x1a\x07\x01\x00".to_vec();
    rar_block(&mut output, 1, 0, &[0], &[]);
    for &(name, body) in entries {
        let mut file = Vec::new();
        put_vint(&mut file, 0x0004); // CRC32 present.
        put_vint(&mut file, body.len() as u64);
        put_vint(&mut file, 0);
        file.extend_from_slice(&crc32(body).to_le_bytes());
        put_vint(&mut file, 0); // Stored.
        put_vint(&mut file, 1);
        put_vint(&mut file, name.len() as u64);
        file.extend_from_slice(name.as_bytes());
        rar_block(&mut output, 2, 2, &file, body);
    }
    rar_block(&mut output, 5, 0, &[0], &[]);
    output
}

fn members() -> Vec<(String, Vec<u8>)> {
    sizes()
        .iter()
        .enumerate()
        .map(|(index, size)| {
            (
                format!("dir/member-{index}.txt"),
                content(*size, u8::try_from(index).unwrap()),
            )
        })
        .collect()
}

fn reference(members: &[(String, Vec<u8>)], prefix: &str) -> Vec<(String, usize, Vec<u8>)> {
    members
        .iter()
        .flat_map(|(name, body)| cursor_reference(body, &format!("{prefix}!{name}")))
        .collect()
}

#[test]
fn tar_and_compressed_tar_members_match_whole_member_fragments() {
    let members = members();
    let entries = members
        .iter()
        .map(|(name, body)| (name.as_str(), body.as_slice()))
        .collect::<Vec<_>>();
    let tar = archive_seeds::synthetic_tar(&entries);
    let lz4 = {
        use std::io::Write as _;
        let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
        encoder.write_all(&tar).unwrap();
        encoder.finish().unwrap()
    };
    for (bytes, name) in [
        (tar.clone(), "files.tar"),
        (gzip(&tar), "files.tar.gz"),
        (lz4, "files.tar.lz4"),
    ] {
        let actual = fragments(&mut archive(bytes, name));
        assert_same(&actual, &reference(&members, name), name);
    }
}

#[test]
fn zip_7z_and_rar_members_match_whole_member_fragments() {
    let members = members();
    let zip_entries = members
        .iter()
        .enumerate()
        .map(|(index, (name, body))| (name.as_str(), body.as_slice(), index % 2 == 1))
        .collect::<Vec<_>>();
    let actual = fragments(&mut archive(zip(&zip_entries), "files.zip"));
    assert_same(&actual, &reference(&members, "files.zip"), "files.zip");

    let entries = members
        .iter()
        .map(|(name, body)| (name.as_str(), body.as_slice()))
        .collect::<Vec<_>>();
    let actual = fragments(&mut archive(rar(&entries), "files.rar"));
    assert_same(&actual, &reference(&members, "files.rar"), "files.rar");

    for method in [Method::Copy, Method::Deflate, Method::Lz4] {
        let seven = sevenz_seeds::archive(
            &members
                .iter()
                .map(|(name, body)| Member::new(name, body, method))
                .collect::<Vec<_>>(),
        );
        let actual = fragments(&mut archive(seven.clone(), "files.7z"));
        assert_same(
            &actual,
            &seven_reference(&seven, "files.7z"),
            &format!("files.7z/{method:?}"),
        );
    }
}

#[test]
fn compressed_streams_match_whole_stream_fragments() {
    let body = content(300_007, 3);
    let lz4 = {
        use std::io::Write as _;
        let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
        encoder.write_all(&body).unwrap();
        encoder.finish().unwrap()
    };
    for (bytes, name) in [
        (gzip(&body), "app.log.gz"),
        (
            miniz_oxide::deflate::compress_to_vec_zlib(&body, 6),
            "app.log.zz",
        ),
        (lz4, "app.log.lz4"),
    ] {
        let actual = fragments(&mut archive(bytes, name));
        let expected = cursor_reference(&body, name);
        assert_same(&actual, &expected, name);
    }
}

#[test]
fn nested_archives_match_whole_member_fragments() {
    let members = members();
    let deep = sevenz_seeds::archive(&[Member::new(&members[5].0, &members[5].1, Method::Deflate)]);
    let inner = zip(&[
        (members[6].0.as_str(), members[6].1.as_slice(), true),
        ("deep.7z", deep.as_slice(), false),
    ]);
    let middle = archive_seeds::synthetic_tar(&[
        (members[3].0.as_str(), members[3].1.as_slice()),
        ("inner.zip", inner.as_slice()),
    ]);
    let outer = gzip(&middle);
    let actual = fragments(&mut archive(outer, "outer.tar.gz"));
    let mut expected = cursor_reference(&members[3].1, &format!("outer.tar.gz!{}", members[3].0));
    expected.extend(cursor_reference(
        &members[6].1,
        &format!("outer.tar.gz!inner.zip!{}", members[6].0),
    ));
    expected.extend(seven_reference(&deep, "outer.tar.gz!inner.zip!deep.7z"));
    assert_same(&actual, &expected, "outer.tar.gz");
}

#[test]
fn standard_input_archive_bytes_stay_plain_text() {
    // Standard input has no name, so it is never opened as an archive, and
    // it keeps the read sizes of the input.
    let body = content(250_000, 4);
    let actual = fragments(&mut archive(body.clone(), ""));
    let expected = with_path(
        fragments(&mut FileSource::new(Cursor::new(body.clone()), "")),
        "",
    );
    assert_same(&actual, &expected, "stdin");
    let tar = archive_seeds::synthetic_tar(&[("member.txt", body.as_slice())]);
    let actual = fragments(&mut archive(tar.clone(), ""));
    let expected = with_path(fragments(&mut FileSource::new(Cursor::new(tar), "")), "");
    assert_eq!(summary(&actual), expected, "stdin archive bytes");
}

/// A gzip stream of stored DEFLATE blocks around a TAR, made while it is read.
struct GeneratedTarGz {
    members: usize,
    member_size: usize,
    next_member: usize,
    raw: Vec<u8>,
    output: Vec<u8>,
    position: usize,
    crc: Crc32,
    size: u32,
    finished: bool,
}

impl GeneratedTarGz {
    fn new(members: usize, member_size: usize) -> Self {
        Self {
            members,
            member_size,
            next_member: 0,
            raw: Vec::new(),
            output: vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255],
            position: 0,
            crc: Crc32::new(),
            size: 0,
            finished: false,
        }
    }

    fn refill(&mut self) {
        self.output.clear();
        self.position = 0;
        if self.next_member < self.members {
            let name = format!("part-{:04}.txt", self.next_member);
            let mut body = content(
                self.member_size,
                u8::try_from(self.next_member % 7).unwrap(),
            );
            if self.next_member + 1 == self.members {
                let at = body.len() / 2;
                body[at..at + 10].copy_from_slice(b"token=Z999");
            }
            let mut tar = archive_seeds::synthetic_tar(&[(name.as_str(), body.as_slice())]);
            tar.truncate(tar.len() - 1024);
            self.raw = tar;
            self.next_member += 1;
        } else {
            self.raw = vec![0; 1024];
            self.finished = true;
        }
        self.crc.update(&self.raw);
        self.size = self
            .size
            .wrapping_add(u32::try_from(self.raw.len()).unwrap());
        for chunk in self.raw.chunks(usize::from(u16::MAX)) {
            let length = u16::try_from(chunk.len()).unwrap();
            self.output.push(0);
            self.output.extend_from_slice(&length.to_le_bytes());
            self.output.extend_from_slice(&(!length).to_le_bytes());
            self.output.extend_from_slice(chunk);
        }
        if self.finished {
            self.output.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
            self.output
                .extend_from_slice(&self.crc.finish().to_le_bytes());
            self.output.extend_from_slice(&self.size.to_le_bytes());
        }
    }
}

impl Read for GeneratedTarGz {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.position == self.output.len() {
            if self.finished {
                return Ok(0);
            }
            self.refill();
        }
        let count = buffer.len().min(self.output.len() - self.position);
        buffer[..count].copy_from_slice(&self.output[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

#[test]
fn large_tar_gz_streams_completely_far_above_its_storage_limits() {
    // About 200 MiB of TAR in a gzip stream, made while it is read. The
    // spool and member limits are far below the archive size, which before
    // streaming skipped the whole archive: it was copied into a spool first.
    const MEMBERS: usize = 200;
    const MEMBER: usize = 1 << 20;
    let limits = ArchiveLimits::new(2, 1_000, 2 * MEMBER, 1 << 30, 1 << 20).unwrap();
    let mut source = ArchiveSource::with_options(
        GeneratedTarGz::new(MEMBERS, MEMBER),
        "release.tar.gz",
        FileOptions::default(),
        ArchiveOptions::new(limits).emit_limit_issues(true),
    );
    let mut bytes = 0_usize;
    let mut last_token = false;
    let control = source
        .visit(&CancellationToken::new(), &mut |event| {
            let SourceEvent::Fragment {
                fragment,
                issue: None,
            } = event
            else {
                panic!("unexpected issue");
            };
            bytes += fragment.content().len();
            last_token |= fragment
                .file_path()
                .as_bytes()
                .ends_with(format!("part-{:04}.txt", MEMBERS - 1).as_bytes())
                && fragment
                    .content()
                    .as_bytes()
                    .windows(10)
                    .any(|window| window == b"token=Z999");
            Ok(SourceControl::Continue)
        })
        .unwrap();
    assert_eq!(control, SourceControl::Continue);
    assert_eq!(bytes, MEMBERS * MEMBER);
    assert!(last_token);
}

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "rustleaks-streaming-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn zip_files_on_disk_are_read_in_place_above_the_spool_limit() {
    const MEMBERS: usize = 48;
    const MEMBER: usize = 1 << 20;
    let tree = TempTree::new("zip");
    let bodies = (0..MEMBERS)
        .map(|index| content(MEMBER, u8::try_from(index % 5).unwrap()))
        .collect::<Vec<_>>();
    let names = (0..MEMBERS)
        .map(|index| format!("part-{index:02}.txt"))
        .collect::<Vec<_>>();
    let entries = names
        .iter()
        .zip(&bodies)
        .map(|(name, body)| (name.as_str(), body.as_slice(), false))
        .collect::<Vec<_>>();
    fs::write(tree.0.join("backup.zip"), zip(&entries)).unwrap();
    // The spool limit is far below the ZIP size; the file is read in place.
    let limits = ArchiveLimits::new(1, 1_000, 2 * MEMBER, 1 << 30, 1 << 20).unwrap();
    let options =
        DirectoryOptions::default().archives(ArchiveOptions::new(limits).emit_limit_issues(true));
    let mut source = DirectorySource::with_options(&tree.0, options);
    let actual = fragments(&mut source);
    let total = actual
        .iter()
        .map(|fragment| fragment.content().len())
        .sum::<usize>();
    assert_eq!(total, MEMBERS * MEMBER);
    for name in &names {
        assert!(
            actual
                .iter()
                .any(|fragment| fragment.file_path().as_bytes().ends_with(name.as_bytes())),
            "{name}"
        );
    }
}

/// Names of this process's spool files in the system temporary folder.
fn spool_names() -> Vec<String> {
    let prefix = format!("rustleaks-spool-{}-", std::process::id());
    fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(&prefix))
        .collect()
}

fn nested_zip_in_tar(member: usize) -> Vec<u8> {
    let body = content(member, 1);
    let inner = zip(&[("inner.txt", body.as_slice(), false)]);
    archive_seeds::synthetic_tar(&[("inner.zip", inner.as_slice())])
}

#[test]
fn spooled_temporary_files_are_removed_on_every_path() {
    // A nested ZIP above the 1 MiB memory spool is copied to a temporary file.
    let tar = nested_zip_in_tar(3 << 20);
    let limits = ArchiveLimits::new(2, 100, 8 << 20, 1 << 30, 8 << 20).unwrap();
    let source = || {
        ArchiveSource::with_options(
            Cursor::new(tar.clone()),
            "outer.tar",
            FileOptions::default(),
            ArchiveOptions::new(limits).emit_limit_issues(true),
        )
    };

    // Completed: no name is visible while the spool is in use or after it.
    let mut fragments = 0;
    let result = source().visit(&CancellationToken::new(), &mut |event| {
        assert!(matches!(event, SourceEvent::Fragment { issue: None, .. }));
        #[cfg(unix)]
        assert!(
            spool_names().is_empty(),
            "spool file has a name during the scan"
        );
        fragments += 1;
        Ok(SourceControl::Continue)
    });
    assert_eq!(result, Ok(SourceControl::Continue));
    assert!(fragments > 1);
    assert!(spool_names().is_empty());

    // Cancelled and stopped scans also leave nothing behind.
    let token = CancellationToken::new();
    let result = source().visit(&token, &mut |_| {
        token.cancel();
        Ok(SourceControl::Continue)
    });
    assert_eq!(result, Err(SourceError::Cancelled));
    assert!(spool_names().is_empty());
    let result = source().visit(&CancellationToken::new(), &mut |_| Ok(SourceControl::Stop));
    assert_eq!(result, Ok(SourceControl::Stop));
    assert!(spool_names().is_empty());

    // A spool over its limit is a limit issue, and nothing of it is scanned.
    let small = ArchiveLimits::new(2, 100, 8 << 20, 1 << 30, 2 << 20).unwrap();
    let mut issues = Vec::new();
    let result = ArchiveSource::with_options(
        Cursor::new(tar),
        "outer.tar",
        FileOptions::default(),
        ArchiveOptions::new(small),
    )
    .visit(&CancellationToken::new(), &mut |event| {
        match event {
            SourceEvent::Issue(issue) => issues.push((issue.kind(), issue.message().to_owned())),
            SourceEvent::Fragment { .. } => panic!("over-limit spool was scanned"),
            _ => unreachable!("future source event"),
        }
        Ok(SourceControl::Continue)
    });
    assert_eq!(result, Ok(SourceControl::Continue));
    assert_eq!(
        issues,
        [(
            SourceIssueKind::Limit,
            "archive spool limit exceeded".to_owned()
        )]
    );
    assert!(spool_names().is_empty());
}

#[test]
fn directory_archives_use_the_same_member_fragments_as_readers() {
    // Archive files found in a folder are read in place, not as streams.
    let members = members();
    let tree = TempTree::new("dir");
    let entries = members
        .iter()
        .map(|(name, body)| (name.as_str(), body.as_slice(), true))
        .collect::<Vec<_>>();
    let tar_entries = members
        .iter()
        .map(|(name, body)| (name.as_str(), body.as_slice()))
        .collect::<Vec<_>>();
    let seven = sevenz_seeds::archive(
        &members
            .iter()
            .map(|(name, body)| Member::new(name, body, Method::Lz4))
            .collect::<Vec<_>>(),
    );
    let cases = [
        ("files.zip", zip(&entries)),
        (
            "files.tar.gz",
            gzip(&archive_seeds::synthetic_tar(&tar_entries)),
        ),
        ("files.7z", seven.clone()),
    ];
    for (name, bytes) in cases {
        let folder = tree.0.join(name.replace('.', "-"));
        fs::create_dir(&folder).unwrap();
        fs::write(folder.join(name), bytes).unwrap();
        let options = DirectoryOptions::default().archives(ArchiveOptions::new(
            ArchiveLimits::new(2, 1_000, 64 << 20, 1 << 30, 64 << 20).unwrap(),
        ));
        let actual = fragments(&mut DirectorySource::with_options(&folder, options));
        let prefix = outer_path(&actual);
        let expected = if name == "files.7z" {
            seven_reference(&seven, &prefix)
        } else {
            reference(&members, &prefix)
        };
        assert_same(&actual, &expected, name);
    }
}

/// The archive path that the directory source gave, before the first `!`.
fn outer_path(fragments: &[Fragment]) -> String {
    let path = fragments[0].file_path().to_string_lossy().into_owned();
    path.split('!').next().unwrap().to_owned()
}
