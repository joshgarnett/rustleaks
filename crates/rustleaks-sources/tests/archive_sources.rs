//! Optional archive decorator coverage against committed upstream fixtures.
#![cfg(feature = "archives")]

use std::fs;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::Fragment;
use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, ArchiveSource, Cancellation, CancellationToken,
    DirectoryOptions, DirectorySource, FileOptions, Source, SourceControl, SourceError,
    SourceEvent, SourceIssueKind, SourceStage,
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../compat/fixtures/upstream/testdata/archives")
        .join(name)
}

fn collect(source: &mut dyn Source) -> Result<(Vec<Fragment>, Vec<SourceIssueKind>), SourceError> {
    let mut fragments = Vec::new();
    let mut issues = Vec::new();
    source.visit(&CancellationToken::new(), &mut |event| {
        match event {
            SourceEvent::Fragment { fragment, issue } => {
                fragments.push(*fragment);
                if let Some(issue) = issue {
                    issues.push(issue.kind());
                }
            }
            SourceEvent::Issue(issue) => issues.push(issue.kind()),
            _ => unreachable!("future source event"),
        }
        Ok(SourceControl::Continue)
    })?;
    Ok((fragments, issues))
}

fn collect_issues(
    source: &mut dyn Source,
) -> Result<Vec<(SourceStage, SourceIssueKind)>, SourceError> {
    let mut issues = Vec::new();
    source.visit(&CancellationToken::new(), &mut |event| {
        match event {
            SourceEvent::Fragment {
                issue: Some(issue), ..
            }
            | SourceEvent::Issue(issue) => {
                issues.push((issue.stage(), issue.kind()));
            }
            SourceEvent::Fragment { issue: None, .. } => {}
            _ => unreachable!("future source event"),
        }
        Ok(SourceControl::Continue)
    })?;
    Ok(issues)
}

fn source_for_fixture(name: &str, logical: &str, depth: usize) -> ArchiveSource {
    let bytes = fs::read(fixture(name)).expect("read committed archive fixture");
    let limits = ArchiveLimits::new(depth, 10_000, 64 << 20, 256 << 20, 64 << 20)
        .expect("valid archive limits");
    ArchiveSource::with_options(
        Cursor::new(bytes),
        logical,
        FileOptions::default(),
        ArchiveOptions::new(limits),
    )
}

#[test]
fn committed_container_matrix_preserves_backend_paths() {
    for name in [
        "files.tar",
        "files.tar.xz",
        "files.tar.zst",
        "files.zip",
        "files.7z",
    ] {
        let logical = format!("archives/{name}");
        let mut source = source_for_fixture(name, &logical, 8);
        let (fragments, issues) = collect(&mut source).expect("archive scan succeeds");
        assert!(issues.is_empty(), "{name}: {issues:?}");
        assert_eq!(fragments.len(), 4, "{name}");
        assert!(fragments.iter().all(|fragment| {
            fragment
                .file_path()
                .as_bytes()
                .starts_with(format!("{logical}!").as_bytes())
        }));
    }
}

#[test]
fn single_stream_matrix_retains_outer_name() {
    for name in ["files/main.go.gz", "files/main.go.xz", "files/main.go.zst"] {
        let logical = format!("archives/{name}");
        let mut source = source_for_fixture(name, &logical, 8);
        let (fragments, issues) = collect(&mut source).expect("stream scan succeeds");
        assert!(issues.is_empty(), "{name}: {issues:?}");
        assert_eq!(fragments.len(), 1, "{name}");
        assert_eq!(fragments[0].file_path().as_bytes(), logical.as_bytes());
        assert!(
            fragments[0]
                .content()
                .as_bytes()
                .starts_with(b"package main")
        );
    }

    let zlib = miniz_oxide::deflate::compress_to_vec_zlib(b"zlib payload", 6);
    let mut source = ArchiveSource::new(Cursor::new(zlib), "archives/payload.zz");
    let (fragments, issues) = collect(&mut source).expect("zlib scan succeeds");
    assert!(issues.is_empty());
    assert_eq!(fragments.len(), 1);
    assert_eq!(fragments[0].content().as_bytes(), b"zlib payload");
    assert_eq!(fragments[0].file_path().as_bytes(), b"archives/payload.zz");
}

#[test]
fn concatenated_gzip_members_are_decoded_in_order() {
    let member = fs::read(fixture("files/main.go.gz")).expect("gzip fixture");
    let mut single = ArchiveSource::new(Cursor::new(member.clone()), "single.go.gz");
    let (single_fragments, single_issues) = collect(&mut single).expect("single gzip member");
    assert!(single_issues.is_empty());

    let mut concatenated = member.clone();
    concatenated.extend_from_slice(&member);
    let mut source = ArchiveSource::new(Cursor::new(concatenated), "combined.go.gz");
    let (fragments, issues) = collect(&mut source).expect("concatenated gzip members");
    assert!(issues.is_empty());
    assert_eq!(fragments.len(), 1);
    let mut expected = single_fragments[0].content().as_bytes().to_vec();
    expected.extend_from_slice(single_fragments[0].content().as_bytes());
    assert_eq!(fragments[0].content().as_bytes(), expected);
}

#[test]
fn identification_is_name_only_case_insensitive_and_substring_based() {
    let zip = fs::read(fixture("files.zip")).expect("zip fixture");
    for logical in ["archives/FILES.ZIP", "archives/files.zip.backup"] {
        let mut source = ArchiveSource::new(Cursor::new(zip.clone()), logical);
        let (fragments, issues) = collect(&mut source).expect("recognized zip");
        assert_eq!(fragments.len(), 4);
        assert!(issues.is_empty());
    }

    let mut magic_only = ArchiveSource::new(Cursor::new(zip), "archives/blob");
    let (fragments, issues) = collect(&mut magic_only).expect("ordinary file fallback");
    assert!(fragments.is_empty());
    assert!(issues.is_empty());
}

#[test]
fn compressed_tar_consumes_one_depth_and_recurses_synchronously() {
    let config = Arc::new(
        ConfigLoader::new()
            .load_toml(
                r#"
        [[rules]]
        id = "unused"
        regex = '''never'''
        [[allowlists]]
        paths = ['''\.env\.prod$''']
        "#,
            )
            .expect("valid config"),
    );
    for (depth, expected) in [(0, 0), (1, 3), (2, 26), (8, 26)] {
        let bytes = fs::read(fixture("nested.tar.gz")).expect("nested fixture");
        let limits =
            ArchiveLimits::new(depth, 10_000, 64 << 20, 256 << 20, 64 << 20).expect("limits");
        let mut source = ArchiveSource::with_options(
            Cursor::new(bytes),
            "archives/nested.tar.gz",
            FileOptions::default(),
            ArchiveOptions::new(limits).path_config(Arc::clone(&config)),
        );
        let (fragments, issues) = collect(&mut source).expect("nested scan succeeds");
        assert!(issues.is_empty(), "depth {depth}: {issues:?}");
        assert_eq!(fragments.len(), expected, "depth {depth}");
    }
}

#[test]
fn identified_nested_archive_over_depth_emits_a_recoverable_limit_issue() {
    let nested = tar(&[("secret.txt", b"nested")]);
    let outer = tar(&[("plain.txt", b"plain"), ("nested.tar", &nested)]);
    let options =
        ArchiveOptions::new(ArchiveLimits::new(1, 20, 1 << 20, 4 << 20, 4 << 20).expect("limits"))
            .emit_limit_issues(true);
    let mut source = ArchiveSource::with_options(
        Cursor::new(outer),
        "outer.tar",
        FileOptions::default(),
        options,
    );

    assert_eq!(
        collect_issues(&mut source).expect("depth limit is recoverable"),
        [(SourceStage::Limit, SourceIssueKind::Limit)]
    );
}

#[test]
fn first_level_allowlist_is_not_propagated_to_nested_members() {
    let nested = tar(&[("skip/deep.txt", b"deep")]);
    let outer = tar(&[("skip/first.txt", b"first"), ("nested.tar", &nested)]);
    let config = ConfigLoader::new()
        .load_toml(
            r#"
        [[rules]]
        id = "unused"
        regex = '''never'''
        [[allowlists]]
        paths = ['''(?:^|/)skip(?:/|$)''']
        "#,
        )
        .expect("valid config");
    let options =
        ArchiveOptions::new(ArchiveLimits::new(2, 20, 1 << 20, 4 << 20, 4 << 20).expect("limits"))
            .path_config(Arc::new(config));
    let mut source = ArchiveSource::with_options(
        Cursor::new(outer),
        "outer.tar",
        FileOptions::default(),
        options,
    );
    let (fragments, issues) = collect(&mut source).expect("nested allowlist scan");
    assert!(issues.is_empty());
    assert_eq!(fragments.len(), 1);
    assert_eq!(
        fragments[0].file_path().as_bytes(),
        b"outer.tar!nested.tar!skip/deep.txt"
    );
}

#[test]
fn corrupt_and_limit_failures_are_structured() {
    let mut corrupt = ArchiveSource::new(Cursor::new(b"short tar".to_vec()), "broken.tar");
    let (fragments, issues) = collect(&mut corrupt).expect("corrupt is recoverable");
    assert!(fragments.is_empty());
    assert_eq!(issues, [SourceIssueKind::CorruptArchive]);

    let mut malformed_rar = ArchiveSource::new(Cursor::new(b"payload".to_vec()), "data.rar");
    let (_, issues) = collect(&mut malformed_rar).expect("malformed RAR is recoverable");
    assert_eq!(issues, [SourceIssueKind::CorruptArchive]);

    let mut malformed_lzip = ArchiveSource::new(Cursor::new(b"payload".to_vec()), "data.lz");
    assert_eq!(
        collect_issues(&mut malformed_lzip).expect("malformed LZIP is recoverable"),
        [(SourceStage::Decode, SourceIssueKind::Decode)]
    );

    let bytes = fs::read(fixture("files.zip")).expect("zip fixture");
    let options =
        ArchiveOptions::new(ArchiveLimits::new(8, 100, 8, 1 << 20, 1 << 20).expect("limits"));
    let mut limited = ArchiveSource::with_options(
        Cursor::new(bytes),
        "files.zip",
        FileOptions::default(),
        options,
    );
    let (_, issues) = collect(&mut limited).expect("limit is recoverable");
    assert!(issues.contains(&SourceIssueKind::Limit));

    let bytes = fs::read(fixture("files.zip")).expect("zip fixture");
    let options =
        ArchiveOptions::new(ArchiveLimits::new(8, 100, 1 << 20, 1 << 20, 8).expect("limits"));
    let mut spool_limited = ArchiveSource::with_options(
        Cursor::new(bytes),
        "files.zip",
        FileOptions::default(),
        options,
    );
    let (_, issues) = collect(&mut spool_limited).expect("spool limit is recoverable");
    assert_eq!(issues, [SourceIssueKind::Limit]);

    let bytes = fs::read(fixture("files.tar")).expect("tar fixture");
    let options =
        ArchiveOptions::new(ArchiveLimits::new(8, 1, 1 << 20, 4 << 20, 4 << 20).expect("limits"));
    let mut entry_limited = ArchiveSource::with_options(
        Cursor::new(bytes),
        "files.tar",
        FileOptions::default(),
        options,
    );
    let (_, issues) = collect(&mut entry_limited).expect("entry limit is recoverable");
    assert!(issues.contains(&SourceIssueKind::Limit));

    let bytes = tar(&[("first", b"1234"), ("second", b"5678")]);
    let options = ArchiveOptions::new(ArchiveLimits::new(8, 10, 8, 6, 1 << 20).expect("limits"));
    let mut total_limited = ArchiveSource::with_options(
        Cursor::new(bytes),
        "values.tar",
        FileOptions::default(),
        options,
    );
    let (_, issues) = collect(&mut total_limited).expect("cumulative limit is recoverable");
    assert!(issues.contains(&SourceIssueKind::Limit));
}

#[test]
fn seven_zip_declared_header_range_is_rejected_before_backend_parsing() {
    let mut bytes = vec![0_u8; 32];
    bytes[..6].copy_from_slice(b"7z\xbc\xaf'\x1c");
    bytes[6] = 0;
    bytes[7] = 4;
    bytes[8..12].copy_from_slice(&1_u32.to_le_bytes());
    bytes[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut source = ArchiveSource::new(Cursor::new(bytes), "hostile.7z");
    let (fragments, issues) = collect(&mut source).expect("7z preflight is recoverable");
    assert!(fragments.is_empty());
    assert_eq!(issues, [SourceIssueKind::Limit]);
}

#[test]
fn cancellation_stops_before_archive_work() {
    let bytes = fs::read(fixture("nested.tar.gz")).expect("nested fixture");
    let mut source = ArchiveSource::new(Cursor::new(bytes), "nested.tar.gz");
    let token = CancellationToken::new();
    token.cancel();
    let error = source
        .visit(&token, &mut |_| Ok(SourceControl::Continue))
        .expect_err("cancelled");
    assert_eq!(error, SourceError::Cancelled);
}

#[test]
fn cancellation_is_observed_while_building_the_seekable_spool() {
    struct CancellingReader {
        bytes: Cursor<Vec<u8>>,
        token: CancellationToken,
        cancelled: bool,
    }
    impl Read for CancellingReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let requested = output.len().min(1);
            let count = self.bytes.read(&mut output[..requested])?;
            if count != 0 && !self.cancelled {
                self.cancelled = true;
                self.token.cancel();
            }
            Ok(count)
        }
    }

    let token = CancellationToken::new();
    let reader = CancellingReader {
        bytes: Cursor::new(fs::read(fixture("files.zip")).expect("zip fixture")),
        token: token.clone(),
        cancelled: false,
    };
    let mut source = ArchiveSource::new(reader, "files.zip");
    let error = source
        .visit(&token, &mut |_| Ok(SourceControl::Continue))
        .expect_err("cancelled");
    assert_eq!(error, SourceError::Cancelled);
}

#[test]
fn cancellation_is_observed_during_deflate_decoding() {
    struct CountdownCancellation {
        checks: AtomicUsize,
    }
    impl Cancellation for CountdownCancellation {
        fn is_cancelled(&self) -> bool {
            self.checks.fetch_sub(1, Ordering::AcqRel) == 0
        }
    }

    let payload = vec![b'x'; 256 * 1024];
    let encoded = miniz_oxide::deflate::compress_to_vec_zlib(&payload, 6);
    let mut source = ArchiveSource::new(Cursor::new(encoded), "payload.zz");
    let cancellation = CountdownCancellation {
        checks: AtomicUsize::new(6),
    };
    let error = source
        .visit(&cancellation, &mut |_| Ok(SourceControl::Continue))
        .expect_err("cancelled during incremental DEFLATE decoding");
    assert_eq!(error, SourceError::Cancelled);
}

#[test]
fn directory_source_can_opt_into_archive_decoration() {
    let unique = format!("rustleaks-archive-test-{}", std::process::id());
    let root = std::env::temp_dir().join(unique);
    fs::create_dir(&root).expect("create temporary directory");
    fs::copy(fixture("files.zip"), root.join("files.zip")).expect("copy fixture");
    let options = DirectoryOptions::default().archives(ArchiveOptions::default());
    let mut source = DirectorySource::with_options(&root, options);
    let result = collect(&mut source);
    let _ = fs::remove_dir_all(&root);
    let (fragments, issues) = result.expect("directory archive scan");
    assert_eq!(fragments.len(), 4);
    assert!(issues.is_empty());
}

fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut output = Vec::new();
    for (name, body) in entries {
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        write_octal(&mut header[124..136], body.len());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: usize = header.iter().map(|byte| *byte as usize).sum();
        let encoded = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(encoded.as_bytes());
        output.extend_from_slice(&header);
        output.extend_from_slice(body);
        output.resize(output.len().div_ceil(512) * 512, 0);
    }
    output.resize(output.len() + 1024, 0);
    output
}

fn write_octal(field: &mut [u8], value: usize) {
    let encoded = format!("{:0width$o}\0", value, width = field.len() - 1);
    field.copy_from_slice(encoded.as_bytes());
}
