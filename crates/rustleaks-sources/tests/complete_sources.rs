//! Opt-in complete logical targets, independent of reader partition boundaries.
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine as _;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{ByteText, FindingRange, Fragment, ScanOptions};
use rustleaks_core::session::SessionPolicy;
use rustleaks_core::{Engine, ScanBudget};
use rustleaks_sources::{
    COMPLETE_MIME_WINDOW, CancellationToken, DirectoryOptions, DirectorySource, FileOptions,
    FileSource, ReadOutcome, ReadStatus, Source, SourceBudget, SourceBudgetKind, SourceBudgetScope,
    SourceControl, SourceError, SourceEvent, SourceIssueDisposition, SourceIssueKind,
    SourceOutcome, SourceReader, SourceRunner, SourceStage, SourceTermination,
};

struct Partitioned {
    inner: Cursor<Vec<u8>>,
    maximum: usize,
    consumed: Arc<AtomicUsize>,
}

impl Read for Partitioned {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let maximum = buffer.len().min(self.maximum);
        let count = self.inner.read(&mut buffer[..maximum])?;
        self.consumed.fetch_add(count, Ordering::SeqCst);
        Ok(count)
    }
}

fn partitioned(bytes: Vec<u8>, maximum: usize) -> (Partitioned, Arc<AtomicUsize>) {
    let consumed = Arc::new(AtomicUsize::new(0));
    (
        Partitioned {
            inner: Cursor::new(bytes),
            maximum,
            consumed: Arc::clone(&consumed),
        },
        consumed,
    )
}

fn fragments(source: &mut dyn Source) -> Result<Vec<Fragment>, SourceError> {
    let mut fragments = Vec::new();
    source.visit(&CancellationToken::new(), &mut |event| {
        match event {
            SourceEvent::Fragment {
                fragment,
                issue: None,
            } => fragments.push(*fragment),
            SourceEvent::Issue(issue)
                if issue.disposition() == SourceIssueDisposition::Excluded => {}
            _ => panic!("complete source emitted failed coverage"),
        }
        Ok(SourceControl::Continue)
    })?;
    Ok(fragments)
}

fn detector(config: &str) -> Engine {
    Engine::builder(ConfigLoader::new().load_toml(config).unwrap())
        .build()
        .unwrap()
}

fn token_detector() -> Engine {
    detector("[[rules]]\nid='token'\nregex='token=([A-Z0-9]{4})'\n")
}

fn run(source: &mut dyn Source, engine: &Engine, options: ScanOptions) -> SourceOutcome {
    SourceRunner::new(1, 1).unwrap().run(
        source,
        engine,
        options,
        &SessionPolicy::default(),
        &CancellationToken::new(),
    )
}

#[test]
fn complete_limit_is_inclusive_and_the_probe_consumes_only_cap_plus_one() {
    assert!(FileOptions::complete(0).is_err());
    assert_eq!(FileOptions::default().complete_target_bytes(), None);
    for cap in [1, 31, 4095, 4096, 8192] {
        for size in [cap - 1, cap, cap + 1, cap + 4096] {
            for partition in [1, 7, 8192] {
                let data = vec![b'.'; size];
                let (reader, consumed) = partitioned(data.clone(), partition);
                let mut source = FileSource::with_options(
                    reader,
                    "exact.txt",
                    FileOptions::complete(cap).unwrap(),
                );
                let result = fragments(&mut source);
                assert_eq!(consumed.load(Ordering::SeqCst), size.min(cap + 1));
                if size <= cap {
                    let output = result.unwrap();
                    assert_eq!(output.len(), 1);
                    assert_eq!(output[0].content().as_bytes(), data);
                    assert_eq!(output[0].start_line(), 1);
                } else {
                    assert!(matches!(
                        result,
                        Err(SourceError::Terminal {
                            stage: SourceStage::Limit,
                            ..
                        })
                    ));
                }
            }
        }
    }
}

struct Outcomes(VecDeque<(Vec<u8>, ReadStatus)>);

impl SourceReader for Outcomes {
    fn read_source(&mut self, buffer: &mut [u8]) -> ReadOutcome {
        let (bytes, status) = self.0.pop_front().expect("read schedule exhausted");
        assert!(bytes.len() <= buffer.len());
        buffer[..bytes.len()].copy_from_slice(&bytes);
        ReadOutcome::new(bytes.len(), status)
    }
}

#[test]
fn only_clean_eof_publishes_a_target_including_data_with_eof() {
    let failed = ReadStatus::Error {
        kind: io::ErrorKind::Other,
        message: "synthetic failure".to_owned(),
    };
    for terminal in [ReadStatus::Eof, failed.clone(), ReadStatus::Continue] {
        let mut source = FileSource::from_source_reader(
            Box::new(Outcomes(VecDeque::from([
                (b"token=A001".to_vec(), ReadStatus::Continue),
                (Vec::new(), terminal.clone()),
            ]))),
            "read.txt",
            FileOptions::complete(32).unwrap(),
        );
        let outcome = run(&mut source, &token_detector(), ScanOptions::default());
        if terminal == ReadStatus::Eof {
            assert_eq!(outcome.termination(), &SourceTermination::Completed);
            assert_eq!(outcome.findings().len(), 1);
        } else {
            assert!(matches!(
                outcome.termination(),
                SourceTermination::SourceError(SourceError::Terminal {
                    stage: SourceStage::Read,
                    ..
                })
            ));
            assert!(outcome.findings().is_empty());
        }
    }
    for terminal in [ReadStatus::Eof, failed] {
        let mut source = FileSource::from_source_reader(
            Box::new(Outcomes(VecDeque::from([(
                b"token=A001".to_vec(),
                terminal.clone(),
            )]))),
            "combined.txt",
            FileOptions::complete(10).unwrap(),
        );
        let output = fragments(&mut source);
        assert_eq!(output.is_ok(), terminal == ReadStatus::Eof);
    }
}

#[test]
fn cancellation_after_a_read_discards_the_target() {
    struct Cancelling(CancellationToken);
    impl Read for Cancelling {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            buffer[..10].copy_from_slice(b"token=A001");
            self.0.cancel();
            Ok(10)
        }
    }
    let cancellation = CancellationToken::new();
    let mut source = FileSource::with_options(
        Cancelling(cancellation.clone()),
        "cancel.txt",
        FileOptions::complete(32).unwrap(),
    );
    let mut emitted = 0;
    let result = source.visit(&cancellation, &mut |_| {
        emitted += 1;
        Ok(SourceControl::Continue)
    });
    assert_eq!(result, Err(SourceError::Cancelled));
    assert_eq!(emitted, 0);
}

#[test]
fn mime_window_is_fixed_and_assembled_independently_of_short_reads() {
    let mut iso = vec![b'.'; 32_774];
    iso[32_769..32_774].copy_from_slice(b"CD001");
    let mut beyond = vec![b'.'; COMPLETE_MIME_WINDOW + 4];
    beyond[..4].copy_from_slice(&0x184d_2a50_u32.to_le_bytes());
    beyond[4..8].copy_from_slice(
        &u32::try_from(COMPLETE_MIME_WINDOW - 8)
            .unwrap()
            .to_le_bytes(),
    );
    beyond[COMPLETE_MIME_WINDOW..].copy_from_slice(b"\x28\xb5\x2f\xfd");
    let mut inside = beyond.clone();
    inside[4..8].copy_from_slice(
        &u32::try_from(COMPLETE_MIME_WINDOW - 12)
            .unwrap()
            .to_le_bytes(),
    );
    inside[COMPLETE_MIME_WINDOW - 4..COMPLETE_MIME_WINDOW].copy_from_slice(b"\x28\xb5\x2f\xfd");
    for (data, excluded) in [
        (iso, true),
        (inside, true),
        (beyond, false),
        (b"%PDF".to_vec(), true),
    ] {
        for partition in [1, 31, 4096, 8192] {
            let (reader, _) = partitioned(data.clone(), partition);
            let mut source = FileSource::with_options(
                reader,
                "mime.dat",
                FileOptions::complete(data.len()).unwrap(),
            );
            assert_eq!(fragments(&mut source).unwrap().is_empty(), excluded);
        }
    }
    // The resource ceiling precedes MIME classification, including tiny caps.
    let mut source = FileSource::with_options(
        Cursor::new(b"%PDF".to_vec()),
        "small.dat",
        FileOptions::complete(3).unwrap(),
    );
    assert!(matches!(
        fragments(&mut source),
        Err(SourceError::Terminal {
            stage: SourceStage::Limit,
            ..
        })
    ));
}

#[test]
fn plain_and_padded_base64_tokens_survive_normal_cut_positions() {
    let engine = detector("[[rules]]\nid='pat'\nregex='ghp_[0-9a-zA-Z]{36}'\nkeywords=['ghp_']\n");
    let secret = b"ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
    assert_eq!(encoded.len(), 56);
    assert!(encoded.ends_with("=="));
    // These cuts model the observed nominal-plus-read-ahead cut and subsequent
    // buffered-reader leftovers. Expected locations come from construction.
    for index in 0..33 {
        let boundary = 125_000 + index * 28_672;
        let offset = boundary - 55; // The final Base64 padding byte is after the cut.
        let mut data = vec![b'.'; offset];
        data.extend_from_slice(encoded.as_bytes());
        data.push(b'\n');
        let maximum = data.len();
        let (reader, _) = partitioned(data, 4093);
        let mut source = FileSource::with_options(
            reader,
            "padded.txt",
            FileOptions::complete(maximum).unwrap(),
        );
        let outcome = run(
            &mut source,
            &engine,
            ScanOptions::builder().max_decode_depth(1).build(),
        );
        assert_eq!(outcome.termination(), &SourceTermination::Completed);
        assert_eq!(outcome.findings().len(), 1, "encoded cut {index}");
        assert_eq!(outcome.findings()[0].secret().as_bytes(), secret);
        assert_eq!(
            outcome.findings()[0].match_range(),
            FindingRange::Unavailable
        );
        assert_eq!(
            outcome.findings()[0].secret_range(),
            FindingRange::Unavailable
        );
        if index < 10 {
            let offset = boundary - 20;
            let mut data = vec![b'.'; offset];
            data.extend_from_slice(secret);
            data.push(b'\n');
            let maximum = data.len();
            let (reader, _) = partitioned(data, 4093);
            let mut source = FileSource::with_options(
                reader,
                "plain.txt",
                FileOptions::complete(maximum).unwrap(),
            );
            let outcome = run(&mut source, &engine, ScanOptions::default());
            assert_eq!(outcome.termination(), &SourceTermination::Completed);
            assert_eq!(outcome.findings().len(), 1, "plain cut {index}");
            assert_eq!(outcome.findings()[0].secret().as_bytes(), secret);
            assert_eq!(
                outcome.findings()[0]
                    .secret_range()
                    .exact()
                    .unwrap()
                    .as_range(),
                offset..offset + 40
            );
        }
    }
}

struct ScheduledReader {
    bytes: Vec<u8>,
    cursor: usize,
    sizes: &'static [usize],
    read_index: usize,
    error_at: Option<usize>,
    reads: Arc<std::sync::Mutex<Vec<(usize, bool)>>>,
}

impl Read for ScheduledReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.error_at == Some(self.cursor) {
            self.reads.lock().unwrap().push((0, true));
            return Err(io::Error::other("prescribed synthetic read failure"));
        }
        let limit = self.error_at.unwrap_or(self.bytes.len());
        let count = self.sizes[self.read_index % self.sizes.len()]
            .min(limit - self.cursor)
            .min(buffer.len());
        buffer[..count].copy_from_slice(&self.bytes[self.cursor..self.cursor + count]);
        self.cursor += count;
        self.read_index += 1;
        self.reads.lock().unwrap().push((count, false));
        Ok(count)
    }
}

const READER_SCHEDULE_CASES: [(&str, bool, &[usize], Option<usize>); 16] = [
    ("maintained-reader-schedule::00", false, &[1], None),
    ("maintained-reader-schedule::01", false, &[2], None),
    ("maintained-reader-schedule::02", false, &[7], None),
    ("maintained-reader-schedule::03", false, &[4096], None),
    (
        "maintained-reader-schedule::04",
        false,
        &[1, 3, 2, 7, 31, 64, 5],
        None,
    ),
    ("maintained-reader-schedule::05", false, &[4096], Some(0)),
    ("maintained-reader-schedule::06", false, &[4096], Some(4096)),
    ("maintained-reader-schedule::07", false, &[4096], Some(4180)),
    ("maintained-reader-schedule::08", true, &[1], None),
    ("maintained-reader-schedule::09", true, &[2], None),
    ("maintained-reader-schedule::10", true, &[7], None),
    ("maintained-reader-schedule::11", true, &[4096], None),
    (
        "maintained-reader-schedule::12",
        true,
        &[1, 3, 2, 7, 31, 64, 5],
        None,
    ),
    ("maintained-reader-schedule::13", true, &[4096], Some(0)),
    ("maintained-reader-schedule::14", true, &[4096], Some(4096)),
    ("maintained-reader-schedule::15", true, &[4096], Some(4161)),
];

#[test]
fn maintained_reader_schedules_execute_all_sixteen_prescribed_cases() {
    let engine = detector("[[rules]]\nid='pat'\nregex='ghp_[0-9a-zA-Z]{36}'\nkeywords=['ghp_']\n");
    for (id, encoded, sizes, error_at) in READER_SCHEDULE_CASES {
        check_reader_schedule_case(&engine, id, encoded, sizes, error_at);
    }
}

fn check_reader_schedule_case(
    engine: &Engine,
    id: &str,
    encoded: bool,
    sizes: &'static [usize],
    error_at: Option<usize>,
) {
    // These literals are independently derived from the development SHA-256
    // rejection-sampling recipe: family boundary, ordinals 409620 and 409655.
    // The byte anchors, splits and schedules are prescribed before scanning.
    const RAW_SECRET: &[u8] = b"ghp_ihm2HhUdK7NGp1kAexrgmVByn69BSQY0Vp6E";
    const ENCODED_SECRET: &[u8] = b"ghp_UNQKM5ZedJTvMuCpznzt0fiaXCkx3GZZ4Wyh";
    let secret = if encoded { ENCODED_SECRET } else { RAW_SECRET };
    let carrier = if encoded {
        base64::engine::general_purpose::STANDARD
            .encode(secret)
            .into_bytes()
    } else {
        secret.to_vec()
    };
    let start = if encoded { 4041 } else { 4076 };
    let end = start + carrier.len();
    let mut bytes = vec![b' '; end + 64];
    bytes[start..end].copy_from_slice(&carrier);
    assert_eq!(bytes.len(), if encoded { 4161 } else { 4180 }, "{id}");
    let expected_reads = expected_reader_schedule(sizes, error_at, bytes.len());
    let reads = Arc::new(std::sync::Mutex::new(Vec::new()));
    let cap = bytes.len();
    let reader = ScheduledReader {
        bytes,
        cursor: 0,
        sizes,
        read_index: 0,
        error_at,
        reads: Arc::clone(&reads),
    };
    let mut source = FileSource::with_options(reader, id, FileOptions::complete(cap).unwrap());
    let options = ScanOptions::builder()
        .max_decode_depth(usize::from(encoded))
        .build();
    let outcome = run(&mut source, engine, options);
    assert_eq!(*reads.lock().unwrap(), expected_reads, "{id}");
    if error_at.is_some() {
        assert!(
            matches!(
                outcome.termination(),
                SourceTermination::SourceError(SourceError::Terminal {
                    stage: SourceStage::Read,
                    ..
                })
            ),
            "{id}"
        );
        assert!(outcome.findings().is_empty(), "{id}");
        return;
    }
    assert_eq!(outcome.termination(), &SourceTermination::Completed, "{id}");
    assert_eq!(outcome.findings().len(), 1, "{id}");
    let finding = &outcome.findings()[0];
    assert_eq!(finding.rule_id().as_bytes(), b"pat", "{id}");
    assert_eq!(finding.secret().as_bytes(), secret, "{id}");
    assert_eq!(finding.match_text().as_bytes(), secret, "{id}");
    if encoded {
        assert_eq!(finding.secret_range(), FindingRange::Unavailable, "{id}");
        assert_eq!(finding.match_range(), FindingRange::Unavailable, "{id}");
        assert_eq!(
            finding
                .tags()
                .iter()
                .map(ByteText::as_bytes)
                .collect::<Vec<_>>(),
            vec![b"decoded:base64".as_slice(), b"decode-depth:1"],
            "{id}"
        );
    } else {
        assert_eq!(
            finding.secret_range().exact().unwrap().as_range(),
            start..end,
            "{id}"
        );
        assert_eq!(
            finding.match_range().exact().unwrap().as_range(),
            start..end,
            "{id}"
        );
        assert_eq!(finding.location().start_line(), 1, "{id}");
        assert_eq!(finding.location().end_line(), 1, "{id}");
        assert_eq!(finding.location().start_column(), start + 1, "{id}");
        assert_eq!(finding.location().end_column(), end, "{id}");
        assert!(finding.tags().is_empty(), "{id}");
    }
}

fn expected_reader_schedule(
    sizes: &[usize],
    error_at: Option<usize>,
    bytes_len: usize,
) -> Vec<(usize, bool)> {
    let mut expected_reads = Vec::new();
    let limit = error_at.unwrap_or(bytes_len);
    let mut cursor = 0;
    for size in sizes.iter().cycle() {
        if cursor == limit {
            break;
        }
        let count = (*size).min(limit - cursor);
        expected_reads.push((count, false));
        cursor += count;
    }
    expected_reads.push((0, error_at.is_some()));
    expected_reads
}

#[test]
fn whole_target_context_preserves_multiline_allowlists_required_rules_and_duplicates() {
    let engine = detector(
        r"
[[rules]]
id='multiline'
regex='(?s)BEGIN.*END'
[[rules]]
id='token'
regex='token=([A-Z0-9]{4})'
[[rules]]
id='primary'
regex='PRIMARY'
[[rules.required]]
id='support'
[[rules]]
id='support'
regex='SUPPORT'
skipReport=true
",
    );
    let mut data = b"BEGIN\n".to_vec();
    data.extend(vec![b'.'; 130_000]);
    data.extend_from_slice(b"\nEND\nPRIMARY\n");
    data.extend(vec![b'.'; 130_000]);
    data.extend_from_slice(b"\nSUPPORT\ntoken=A001 token=A001\n");
    let duplicate_start = data.len() - 22;
    let mut source = FileSource::with_options(
        Cursor::new(data.clone()),
        "context.txt",
        FileOptions::complete(data.len()).unwrap(),
    );
    let outcome = run(&mut source, &engine, ScanOptions::default());
    assert_eq!(outcome.termination(), &SourceTermination::Completed);
    let tokens = outcome
        .findings()
        .iter()
        .filter(|finding| finding.rule_id().as_bytes() == b"token")
        .collect::<Vec<_>>();
    assert_eq!(tokens.len(), 2);
    assert_eq!(
        tokens[0].secret_range().exact().unwrap().as_range(),
        duplicate_start + 6..duplicate_start + 10
    );
    assert_eq!(
        tokens[1].secret_range().exact().unwrap().as_range(),
        duplicate_start + 17..duplicate_start + 21
    );
    let multiline = outcome
        .findings()
        .iter()
        .find(|finding| finding.rule_id().as_bytes() == b"multiline")
        .unwrap();
    assert_eq!(
        multiline.match_range().exact().unwrap().as_range(),
        0..130_010
    );
    let primary = outcome
        .findings()
        .iter()
        .find(|finding| finding.rule_id().as_bytes() == b"primary")
        .unwrap();
    assert_eq!(primary.required_findings().len(), 1);
    let mut allowed = b"token=A001".to_vec();
    allowed.extend(vec![b'.'; 150_000]);
    allowed.extend_from_slice(b" // gitleaks:allow\n");
    let mut source = FileSource::with_options(
        Cursor::new(allowed.clone()),
        "allowed.txt",
        FileOptions::complete(allowed.len()).unwrap(),
    );
    assert!(
        run(&mut source, &engine, ScanOptions::default())
            .findings()
            .is_empty()
    );
}

#[test]
fn invalid_bytes_and_negative_controls_keep_exact_raw_coordinates() {
    let data = b"\xff\xfetoken=A001 token=short token=lower\n".to_vec();
    let mut source = FileSource::with_options(
        Cursor::new(data.clone()),
        "invalid.txt",
        FileOptions::complete(data.len()).unwrap(),
    );
    let outcome = run(&mut source, &token_detector(), ScanOptions::default());
    assert_eq!(outcome.termination(), &SourceTermination::Completed);
    assert_eq!(outcome.findings().len(), 1);
    assert_eq!(
        outcome.findings()[0]
            .match_range()
            .exact()
            .unwrap()
            .as_range(),
        2..12
    );
    assert_eq!(
        outcome.findings()[0]
            .secret_range()
            .exact()
            .unwrap()
            .as_range(),
        8..12
    );
}

static NEXT_TREE: AtomicUsize = AtomicUsize::new(0);
struct Tree(PathBuf);
impl Tree {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rustleaks-complete-{}-{}",
            std::process::id(),
            NEXT_TREE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn directory_coverage_failure_keeps_completed_files_and_exclusions_remain_explicit() {
    let tree = Tree::new();
    fs::write(tree.0.join("a.txt"), b"token=A001").unwrap();
    fs::write(tree.0.join("b.txt"), vec![b'.'; 33]).unwrap();
    let options = DirectoryOptions::default().file_options(FileOptions::complete(32).unwrap());
    let outcome = run(
        &mut DirectorySource::with_options(&tree.0, options.clone()),
        &token_detector(),
        ScanOptions::default(),
    );
    assert!(matches!(
        outcome.termination(),
        SourceTermination::SourceError(SourceError::Terminal {
            stage: SourceStage::Limit,
            ..
        })
    ));
    assert_eq!(outcome.findings().len(), 1);
    let mut excluded = DirectorySource::with_options(
        &tree.0,
        options.max_file_size(Some(32)).emit_limit_issues(true),
    );
    let outcome = run(&mut excluded, &token_detector(), ScanOptions::default());
    assert_eq!(outcome.termination(), &SourceTermination::Completed);
    assert_eq!(outcome.findings().len(), 1);
    assert_eq!(outcome.issues().len(), 1);
    assert_eq!(
        outcome.issues()[0].disposition(),
        SourceIssueDisposition::Excluded
    );
    let mut missing = DirectorySource::with_options(
        tree.0.join("absent"),
        DirectoryOptions::default().file_options(FileOptions::complete(32).unwrap()),
    );
    assert!(matches!(
        run(&mut missing, &token_detector(), ScanOptions::default()).termination(),
        SourceTermination::SourceError(SourceError::Terminal {
            stage: SourceStage::Metadata,
            ..
        })
    ));
}

#[test]
fn aggregate_finding_payload_does_not_multiply_with_target_or_worker_count() {
    for workers in [1, 4] {
        let tree = Tree::new();
        let mut data = vec![b'.'; 512];
        data.extend_from_slice(b"token=A001");
        for index in 0..8 {
            fs::write(tree.0.join(format!("{index}.txt")), &data).unwrap();
        }
        let mut source = DirectorySource::with_options(
            &tree.0,
            DirectoryOptions::default()
                .logical_root(".")
                .file_options(FileOptions::complete(1024).unwrap()),
        );
        // Each finding owns more than its 522-byte source line, but less than
        // 1000 bytes across all fields. Two records cannot fit this aggregate.
        let budget = SourceBudget::unlimited()
            .per_fragment(
                ScanBudget::unlimited()
                    .max_finding_payload_bytes(1000)
                    .max_finding_records(8),
            )
            .aggregate(
                ScanBudget::unlimited()
                    .max_finding_payload_bytes(1000)
                    .max_finding_records(64),
            );
        let outcome = SourceRunner::new(workers, 1)
            .unwrap()
            .with_budget(budget)
            .unwrap()
            .run(
                &mut source,
                &token_detector(),
                ScanOptions::default(),
                &SessionPolicy::default(),
                &CancellationToken::new(),
            );
        let SourceTermination::BudgetExceeded(exceeded) = outcome.termination() else {
            panic!("aggregate must be incomplete");
        };
        assert_eq!(exceeded.scope(), SourceBudgetScope::Operation);
        assert_eq!(exceeded.kind(), SourceBudgetKind::FindingPayloadBytes);
        assert_eq!(outcome.findings().len(), 1);
        assert!(outcome.usage().unwrap().finding_payload_bytes() <= 1000);
    }
}

#[test]
fn overreported_reader_counts_never_publish_a_target() {
    struct Overreported;
    impl SourceReader for Overreported {
        fn read_source(&mut self, buffer: &mut [u8]) -> ReadOutcome {
            ReadOutcome::new(buffer.len() + 1, ReadStatus::Eof)
        }
    }
    let mut source = FileSource::from_source_reader(
        Box::new(Overreported),
        "overreported.txt",
        FileOptions::complete(1).unwrap(),
    );
    assert!(matches!(
        fragments(&mut source),
        Err(SourceError::Terminal {
            stage: SourceStage::Limit,
            ..
        })
    ));
}

#[test]
fn aggregate_new_dimensions_require_matching_fragment_reservations() {
    for (budget, kind) in [
        (
            ScanBudget::unlimited().max_finding_payload_bytes(1),
            rustleaks_core::ScanBudgetKind::FindingPayloadBytes,
        ),
        (
            ScanBudget::unlimited().max_collected_spans(1),
            rustleaks_core::ScanBudgetKind::CollectedSpans,
        ),
        (
            ScanBudget::unlimited().max_normalization_bytes(1),
            rustleaks_core::ScanBudgetKind::NormalizationBytes,
        ),
    ] {
        let result = SourceRunner::new(1, 1)
            .unwrap()
            .with_budget(SourceBudget::unlimited().aggregate(budget));
        assert_eq!(result.unwrap_err().kind(), kind);
    }
}

#[cfg(feature = "archives")]
#[allow(dead_code, reason = "shared fuzz support; this binary uses part of it")]
#[path = "../fuzz/support/sevenz_seeds.rs"]
mod sevenz_seeds;

#[cfg(feature = "archives")]
mod archives {
    use super::*;
    use rustleaks_sources::{ArchiveLimits, ArchiveOptions, ArchiveSource};
    use sevenz_seeds::{Folder, Member, Method, archive, folder_archive};

    fn options(depth: usize, member: usize, spool: usize) -> ArchiveOptions {
        ArchiveOptions::new(ArchiveLimits::new(depth, 10, member, member * 4, spool).unwrap())
    }

    fn source(bytes: Vec<u8>, path: &str, cap: usize, options: ArchiveOptions) -> ArchiveSource {
        ArchiveSource::with_options(
            Cursor::new(bytes),
            path,
            FileOptions::complete(cap).unwrap(),
            options,
        )
    }

    #[test]
    fn archive_members_use_complete_targets_across_decoder_read_partitions() {
        let mut content = vec![b'.'; 124_995];
        content.extend_from_slice(b"token=A001\n");
        for method in [Method::Copy, Method::Deflate, Method::Lz4] {
            let bytes = archive(&[Member::new("value.txt", &content, method)]);
            let mut source = source(
                bytes,
                "fixture.7z",
                content.len(),
                options(4, 1 << 20, 1 << 20),
            );
            let outcome = run(&mut source, &token_detector(), ScanOptions::default());
            assert_eq!(outcome.termination(), &SourceTermination::Completed);
            assert_eq!(outcome.findings().len(), 1);
            assert_eq!(
                outcome.findings()[0]
                    .secret_range()
                    .exact()
                    .unwrap()
                    .as_range(),
                125_001..125_005
            );
            assert_eq!(
                outcome.findings()[0].file().as_bytes(),
                b"fixture.7z!value.txt"
            );
        }
    }

    #[test]
    fn complete_archives_force_strict_declared_member_lengths() {
        for method in [Method::Copy, Method::Deflate, Method::Lz4] {
            let mut folder = Folder::new(&[("value.txt", b"token=A001")], &[method]);
            folder.overstate_last_member(7);
            let bytes = folder_archive(&[folder]);
            let mut source = source(
                bytes,
                "short.7z",
                1024,
                options(4, 1 << 20, 1 << 20).strict_7z_member_lengths(false),
            );
            let outcome = run(&mut source, &token_detector(), ScanOptions::default());
            assert!(matches!(
                outcome.termination(),
                SourceTermination::SourceError(SourceError::Terminal {
                    stage: SourceStage::Decode,
                    ..
                })
            ));
            assert!(outcome.findings().is_empty());
        }
    }

    #[test]
    fn corrupt_decode_spool_and_member_limit_failures_are_incomplete() {
        let valid = archive(&[Member::new("value.txt", b"token=A001", Method::Copy)]);
        for (bytes, path, archive_options) in [
            (b"not a tar".to_vec(), "bad.tar", options(4, 1024, 1024)),
            (b"not gzip".to_vec(), "bad.gz", options(4, 1024, 1024)),
            (valid.clone(), "spool.7z", options(4, 1024, valid.len() - 1)),
            (valid, "member.7z", options(4, 9, 1024)),
        ] {
            let outcome = run(
                &mut source(bytes, path, 1024, archive_options),
                &token_detector(),
                ScanOptions::default(),
            );
            assert!(matches!(
                outcome.termination(),
                SourceTermination::SourceError(SourceError::Terminal { .. })
            ));
            assert!(outcome.findings().is_empty());
        }
    }

    #[test]
    fn nested_archive_depth_remains_an_explicit_exclusion() {
        let inner = archive(&[Member::new("value.txt", b"token=A001", Method::Copy)]);
        let outer = archive(&[Member::new("nested.7z", &inner, Method::Copy)]);
        let mut source = source(
            outer,
            "outer.7z",
            1024,
            options(1, 1 << 20, 1 << 20).emit_limit_issues(true),
        );
        let outcome = run(&mut source, &token_detector(), ScanOptions::default());
        assert_eq!(outcome.termination(), &SourceTermination::Completed);
        assert!(outcome.findings().is_empty());
        assert_eq!(outcome.issues().len(), 1);
        assert_eq!(
            outcome.issues()[0].disposition(),
            SourceIssueDisposition::Excluded
        );
    }
}

#[test]
fn runner_complete_failure_policy_distinguishes_custom_source_exclusions() {
    struct IssueSource(bool);
    impl Source for IssueSource {
        fn visit(
            &mut self,
            _: &dyn rustleaks_sources::Cancellation,
            emit: &mut dyn FnMut(
                SourceEvent,
            )
                -> Result<SourceControl, rustleaks_sources::CallbackError>,
        ) -> Result<SourceControl, SourceError> {
            let mut issue = rustleaks_sources::SourceIssue::new(
                SourceStage::Limit,
                rustleaks_sources::SourceIssueKind::Limit,
                None,
                "synthetic limit",
            );
            if self.0 {
                issue = issue.excluded();
            }
            emit(SourceEvent::Issue(issue)).map_err(SourceError::Callback)
        }
    }
    for bounded in [false, true] {
        for excluded in [false, true] {
            let mut runner = SourceRunner::new(1, 1)
                .unwrap()
                .fail_on_coverage_error(true);
            if bounded {
                runner = runner.with_budget(SourceBudget::unlimited()).unwrap();
            }
            let outcome = runner.run(
                &mut IssueSource(excluded),
                &token_detector(),
                ScanOptions::default(),
                &SessionPolicy::default(),
                &CancellationToken::new(),
            );
            if excluded {
                assert_eq!(outcome.termination(), &SourceTermination::Completed);
                assert_eq!(outcome.issues().len(), 1);
            } else {
                assert!(matches!(
                    outcome.termination(),
                    SourceTermination::SourceError(SourceError::Terminal {
                        stage: SourceStage::Limit,
                        ..
                    })
                ));
            }
        }
    }
}

#[test]
fn whole_target_anchors_and_line_allowlists_use_the_complete_context() {
    let engine = detector(
        r"
[[rules]]
id='anchored'
regex='(?s)\ABEGIN.*END\z'
[[rules]]
id='line-allowed'
regex='token=([A-Z0-9]{4})'
[[rules.allowlists]]
regexTarget='line'
regexes=['IGNORE-LINE']
",
    );
    let mut data = b"BEGIN token=A001".to_vec();
    data.extend(vec![b'.'; 150_000]);
    data.extend_from_slice(b" IGNORE-LINE END");
    let mut source = FileSource::with_options(
        Cursor::new(data.clone()),
        "anchors.txt",
        FileOptions::complete(data.len()).unwrap(),
    );
    let outcome = run(&mut source, &engine, ScanOptions::default());
    assert_eq!(outcome.termination(), &SourceTermination::Completed);
    assert_eq!(outcome.findings().len(), 1);
    assert_eq!(outcome.findings()[0].rule_id().as_bytes(), b"anchored");
    assert_eq!(
        outcome.findings()[0]
            .match_range()
            .exact()
            .unwrap()
            .as_range(),
        0..data.len()
    );
    data.push(b'.');
    let mut source = FileSource::with_options(
        Cursor::new(data.clone()),
        "negative.txt",
        FileOptions::complete(data.len()).unwrap(),
    );
    assert!(
        run(&mut source, &engine, ScanOptions::default())
            .findings()
            .is_empty()
    );
}

#[cfg(unix)]
#[test]
fn complete_directory_excludes_a_dangling_link_before_resolution() {
    use std::os::unix::fs::symlink;

    let tree = Tree::new();
    symlink("missing-target", tree.0.join("a-ignored")).unwrap();
    fs::write(tree.0.join("b.txt"), b"token=A001").unwrap();
    let config = Arc::new(ConfigLoader::new().load_toml(
        "[[allowlists]]\npaths=['(?:^|/)a-ignored$']\n[[rules]]\nid='token'\nregex='token=([A-Z0-9]{4})'\n",
    ).unwrap());
    for excluded in [false, true] {
        let mut options = DirectoryOptions::default()
            .follow_symlinks(true)
            .file_options(FileOptions::complete(32).unwrap());
        if excluded {
            options = options.path_config(Arc::clone(&config));
        }
        let outcome = run(
            &mut DirectorySource::with_options(&tree.0, options),
            &token_detector(),
            ScanOptions::default(),
        );
        if excluded {
            assert_eq!(outcome.termination(), &SourceTermination::Completed);
            assert_eq!(outcome.findings().len(), 1);
            assert_eq!(outcome.findings()[0].secret().as_bytes(), b"A001");
        } else {
            assert!(matches!(
                outcome.termination(),
                SourceTermination::SourceError(SourceError::Terminal {
                    stage: SourceStage::Symlink,
                    ..
                })
            ));
            assert!(outcome.findings().is_empty());
        }
    }
    // A normal scan still reports the link issue before continuing.
    let mut normal = DirectorySource::with_options(
        &tree.0,
        DirectoryOptions::default()
            .follow_symlinks(true)
            .path_config(config),
    );
    let outcome = run(&mut normal, &token_detector(), ScanOptions::default());
    assert_eq!(outcome.termination(), &SourceTermination::Completed);
    assert_eq!(outcome.issues().len(), 1);
    assert_eq!(outcome.findings().len(), 1);
}

#[test]
fn aggregate_span_and_normalization_limits_do_not_multiply_with_workers() {
    let normalization = 4 * (3 + std::mem::size_of::<usize>());
    for workers in [1, 4] {
        for (data, fragment, aggregate, kind, consumed, findings) in [
            (
                b"A".to_vec(),
                ScanBudget::unlimited().max_collected_spans(2),
                ScanBudget::unlimited().max_collected_spans(1),
                SourceBudgetKind::CollectedSpans,
                1,
                1,
            ),
            (
                vec![0xff; 4],
                ScanBudget::unlimited().max_normalization_bytes(normalization * 2),
                ScanBudget::unlimited().max_normalization_bytes(normalization),
                SourceBudgetKind::NormalizationBytes,
                normalization,
                0,
            ),
        ] {
            let tree = Tree::new();
            for index in 0..8 {
                fs::write(tree.0.join(format!("{index}.txt")), &data).unwrap();
            }
            let mut source = DirectorySource::with_options(
                &tree.0,
                DirectoryOptions::default().file_options(FileOptions::complete(32).unwrap()),
            );
            let outcome = SourceRunner::new(workers, 1)
                .unwrap()
                .with_budget(
                    SourceBudget::unlimited()
                        .per_fragment(fragment)
                        .aggregate(aggregate),
                )
                .unwrap()
                .run(
                    &mut source,
                    &detector("[[rules]]\nid='single'\nregex='A'\n"),
                    ScanOptions::default(),
                    &SessionPolicy::default(),
                    &CancellationToken::new(),
                );
            let SourceTermination::BudgetExceeded(exceeded) = outcome.termination() else {
                panic!("aggregate must be incomplete");
            };
            assert_eq!(exceeded.scope(), SourceBudgetScope::Operation);
            assert_eq!(exceeded.kind(), kind);
            assert_eq!(outcome.findings().len(), findings);
            let usage = outcome.usage().unwrap();
            assert_eq!(usage.completed_fragments(), 1);
            assert_eq!(
                if kind == SourceBudgetKind::CollectedSpans {
                    usage.collected_spans()
                } else {
                    usage.normalization_bytes()
                },
                consumed
            );
        }
    }
}

#[cfg(feature = "archives")]
#[allow(dead_code, reason = "shared fuzz support; this binary uses part of it")]
#[path = "../fuzz/support/archive_frame.rs"]
mod archive_frame;
#[cfg(feature = "archives")]
#[allow(dead_code, reason = "shared fuzz support; this binary uses part of it")]
#[path = "../fuzz/support/archive_seeds.rs"]
mod archive_seeds;

#[cfg(feature = "archives")]
mod excluded_archive_members {
    use super::*;
    use rustleaks_sources::{ArchiveLimits, ArchiveOptions, ArchiveSource};

    // Independent minimal stored-ZIP writer. Both headers describe the same
    // body; the test can deliberately corrupt only its payload CRC.
    pub(super) fn stored_zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut central = Vec::new();
        for &(name, body, corrupt_crc) in entries {
            let crc = !body.iter().fold(!0_u32, |state, &byte| {
                (0..8).fold(state ^ u32::from(byte), |value, _| {
                    (value >> 1) ^ (0xedb8_8320_u32 & 0_u32.wrapping_sub(value & 1))
                })
            }) ^ u32::from(corrupt_crc);
            let size = u32::try_from(body.len()).unwrap().to_le_bytes();
            let name_size = u16::try_from(name.len()).unwrap().to_le_bytes();
            let offset = u32::try_from(data.len()).unwrap().to_le_bytes();
            let mut local = [0_u8; 30];
            local[..4].copy_from_slice(b"PK\x03\x04");
            local[4..6].copy_from_slice(&20_u16.to_le_bytes());
            local[14..18].copy_from_slice(&crc.to_le_bytes());
            local[18..22].copy_from_slice(&size);
            local[22..26].copy_from_slice(&size);
            local[26..28].copy_from_slice(&name_size);
            data.extend_from_slice(&local);
            data.extend_from_slice(name.as_bytes());
            data.extend_from_slice(body);
            let mut entry = [0_u8; 46];
            entry[..4].copy_from_slice(b"PK\x01\x02");
            entry[4..6].copy_from_slice(&20_u16.to_le_bytes());
            entry[6..8].copy_from_slice(&20_u16.to_le_bytes());
            entry[16..20].copy_from_slice(&crc.to_le_bytes());
            entry[20..24].copy_from_slice(&size);
            entry[24..28].copy_from_slice(&size);
            entry[28..30].copy_from_slice(&name_size);
            entry[42..46].copy_from_slice(&offset);
            central.extend_from_slice(&entry);
            central.extend_from_slice(name.as_bytes());
        }
        let mut end = [0_u8; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        let entries = u16::try_from(entries.len()).unwrap().to_le_bytes();
        end[8..10].copy_from_slice(&entries);
        end[10..12].copy_from_slice(&entries);
        end[12..16].copy_from_slice(&u32::try_from(central.len()).unwrap().to_le_bytes());
        end[16..20].copy_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        data.extend_from_slice(&central);
        data.extend_from_slice(&end);
        data
    }

    fn source(
        data: Vec<u8>,
        name: &str,
        complete: bool,
        excluded: bool,
        entries: usize,
    ) -> ArchiveSource {
        let mut options =
            ArchiveOptions::new(ArchiveLimits::new(2, entries, 1024, 16_384, 16_384).unwrap());
        if excluded {
            options = options.path_config(Arc::new(ConfigLoader::new().load_toml(
                "[[allowlists]]\npaths=['(?:^|/)skip(?:/|$)']\n[[rules]]\nid='token'\nregex='token=([A-Z0-9]{4})'\n",
            ).unwrap()));
        }
        ArchiveSource::with_options(
            Cursor::new(data),
            name,
            if complete {
                FileOptions::complete(2048).unwrap()
            } else {
                FileOptions::default()
            },
            options,
        )
    }

    #[test]
    fn excluded_tar_and_zip_payloads_do_not_prevent_later_eligible_members() {
        let large = vec![b'.'; 1025];
        let tar = archive_seeds::synthetic_tar(&[
            ("skip/first.txt", &large),
            ("value.txt", b"token=A001"),
        ]);
        let zip = stored_zip(&[
            ("skip/first.txt", &large, false),
            ("value.txt", b"token=A001", false),
        ]);
        let bad_crc = stored_zip(&[
            ("skip/first.txt", b"ignored", true),
            ("value.txt", b"token=A001", false),
        ]);
        for (data, name) in [
            (tar, "fixture.tar"),
            (zip, "fixture.zip"),
            (bad_crc, "bad-crc.zip"),
        ] {
            for excluded in [false, true] {
                let outcome = run(
                    &mut source(data.clone(), name, true, excluded, 10),
                    &token_detector(),
                    ScanOptions::default(),
                );
                if excluded {
                    assert_eq!(outcome.termination(), &SourceTermination::Completed);
                    assert_eq!(outcome.findings().len(), 1);
                    assert_eq!(outcome.findings()[0].secret().as_bytes(), b"A001");
                    assert!(outcome.issues().is_empty());
                } else {
                    assert!(matches!(
                        outcome.termination(),
                        SourceTermination::SourceError(SourceError::Terminal { .. })
                    ));
                    assert!(outcome.findings().is_empty());
                }
            }
            let normal = run(
                &mut source(data, name, false, true, 10),
                &token_detector(),
                ScanOptions::default(),
            );
            assert_eq!(normal.termination(), &SourceTermination::Completed);
            assert_eq!(normal.issues().len(), 1);
        }
    }

    #[test]
    fn excluded_members_still_validate_container_layout_and_entry_budgets() {
        let payload = vec![b'.'; 1025];
        let tar = archive_seeds::synthetic_tar(&[
            ("skip/first.txt", &payload),
            ("value.txt", b"token=A001"),
        ]);
        let zip = stored_zip(&[
            ("skip/first.txt", &payload, false),
            ("value.txt", b"token=A001", false),
        ]);
        for (data, name) in [(tar.clone(), "entry.tar"), (zip.clone(), "entry.zip")] {
            let outcome = run(
                &mut source(data, name, true, true, 1),
                &token_detector(),
                ScanOptions::default(),
            );
            assert!(matches!(
                outcome.termination(),
                SourceTermination::SourceError(SourceError::Terminal {
                    stage: SourceStage::Limit,
                    ..
                })
            ));
        }
        let mut bad_header = tar.clone();
        bad_header[148] ^= 1;
        let mut bad_local = zip;
        bad_local[0] = 0;
        for (data, name) in [
            (bad_header, "header.tar"),
            (tar[..512 + payload.len()].to_vec(), "padding.tar"),
            (bad_local, "local.zip"),
        ] {
            let outcome = run(
                &mut source(data, name, true, true, 10),
                &token_detector(),
                ScanOptions::default(),
            );
            assert!(matches!(
                outcome.termination(),
                SourceTermination::SourceError(SourceError::Terminal { .. })
            ));
            assert!(outcome.findings().is_empty());
        }
    }

    /// Expected findings as secret and file.
    type Found = &'static [(&'static [u8], &'static [u8])];

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table covers every corruption case"
    )]
    fn structural_corruption_has_typed_stage_kind_and_no_partial_leaf() {
        // Byte 148 is the first octal digit of the first header checksum.
        let mut header = archive_seeds::synthetic_tar(&[
            ("first.txt", b"token=A001"),
            ("second.txt", b"token=B002"),
        ]);
        header[148] ^= 1;
        let crc = stored_zip(&[
            ("first.txt", b"token=A001", true),
            ("second.txt", b"token=B002", false),
        ]);
        // Drop exactly the 22-byte end of central directory record.
        let mut no_end = stored_zip(&[("value.txt", b"token=A001", false)]);
        no_end.truncate(no_end.len() - 22);
        assert_eq!(&no_end[no_end.len() - 46 - 9..][..4], b"PK\x01\x02");
        // 10 header + 5 stored-block header + 2048 TAR + 8 trailer bytes. Half
        // ends inside the stored payload.
        let mut half = archive_seeds::gzip_stored(&archive_seeds::synthetic_tar(&[(
            "value.txt",
            b"token=A001",
        )]));
        assert_eq!(half.len(), 2071);
        half.truncate(half.len() / 2);

        // Members are scanned while they are read. A normal scan publishes
        // the bytes read before a failure, so the ZIP member whose CRC fails
        // at its end is scanned, and the TAR member that ends before the
        // truncated gzip stream is too. A complete target is published only
        // when it ends without a failure, so the member whose CRC fails is
        // never published, while the whole TAR member is.
        // (bytes, name, normal issues, normal findings, complete stage,
        // owned message, complete findings)
        let crc_findings: Found = &[
            (b"A001", b"crc.zip!first.txt"),
            (b"B002", b"crc.zip!second.txt"),
        ];
        let half_findings: Found = &[(b"A001", b"half.tar.gz!value.txt")];
        let cases: [(_, _, _, Found, _, _, Found); 4] = [
            (
                header,
                "header.tar",
                &[(SourceStage::Archive, SourceIssueKind::CorruptArchive)][..],
                &[],
                SourceStage::Archive,
                Some("invalid TAR header checksum"),
                &[],
            ),
            (
                crc,
                "crc.zip",
                &[(SourceStage::Decode, SourceIssueKind::Decode)][..],
                crc_findings,
                SourceStage::Decode,
                Some("ZIP member size or CRC mismatch"),
                &[],
            ),
            (
                no_end,
                "noend.zip",
                &[(SourceStage::Archive, SourceIssueKind::CorruptArchive)][..],
                &[],
                SourceStage::Archive,
                None,
                &[],
            ),
            (
                half,
                "half.tar.gz",
                &[(SourceStage::Decode, SourceIssueKind::Decode)][..],
                half_findings,
                SourceStage::Decode,
                None,
                half_findings,
            ),
        ];
        for (
            data,
            name,
            normal_issues,
            normal_findings,
            complete_stage,
            owned_message,
            complete_findings,
        ) in cases
        {
            let normal = run(
                &mut source(data.clone(), name, false, false, 10),
                &token_detector(),
                ScanOptions::default(),
            );
            assert_eq!(
                normal.termination(),
                &SourceTermination::Completed,
                "{name}"
            );
            let issues = normal
                .issues()
                .iter()
                .map(|issue| (issue.stage(), issue.kind()))
                .collect::<Vec<_>>();
            assert_eq!(issues, normal_issues, "{name}");
            let findings = normal
                .findings()
                .iter()
                .map(|finding| (finding.secret().as_bytes(), finding.file().as_bytes()))
                .collect::<Vec<_>>();
            assert_eq!(findings, normal_findings, "{name}");

            let complete = run(
                &mut source(data, name, true, false, 10),
                &token_detector(),
                ScanOptions::default(),
            );
            let SourceTermination::SourceError(SourceError::Terminal { stage, message, .. }) =
                complete.termination()
            else {
                panic!("{name}: {:?}", complete.termination());
            };
            assert_eq!(*stage, complete_stage, "{name}");
            if let Some(owned_message) = owned_message {
                assert_eq!(message, owned_message, "{name}");
            }
            let findings = complete
                .findings()
                .iter()
                .map(|finding| (finding.secret().as_bytes(), finding.file().as_bytes()))
                .collect::<Vec<_>>();
            assert_eq!(findings, complete_findings, "{name}");
            assert!(complete.issues().is_empty(), "{name}");
        }
    }
}

#[cfg(feature = "archives")]
mod exact_leaf_exclusions {
    use super::*;
    use rustleaks_core::model::ByteText;
    use rustleaks_sources::{ArchiveLimits, ArchiveOptions, ArchiveSource};
    use sevenz_seeds::{Member, Method, archive};

    fn source(bytes: Vec<u8>, path: &str, complete: bool, excluded: &str) -> ArchiveSource {
        let options =
            ArchiveOptions::new(ArchiveLimits::new(4, 20, 1 << 20, 4 << 20, 1 << 20).unwrap())
                .exclude_paths(vec![ByteText::from(excluded)]);
        ArchiveSource::with_options(
            Cursor::new(bytes),
            path,
            if complete {
                FileOptions::complete(10).unwrap()
            } else {
                FileOptions::default()
            },
            options,
        )
    }

    #[test]
    fn exact_container_paths_do_not_exclude_nested_emitted_leaves() {
        let inner = archive_seeds::synthetic_tar(&[("leaf.txt", b"token=A001")]);
        let outer = archive_seeds::synthetic_tar(&[("inner.tar", &inner)]);
        for excluded in [
            "outer.tar",
            "outer.tar!inner.tar",
            "outer.tar!inner.tar!leaf.txt",
        ] {
            for complete in [false, true] {
                let outcome = run(
                    &mut source(outer.clone(), "outer.tar", complete, excluded),
                    &token_detector(),
                    ScanOptions::default(),
                );
                assert_eq!(outcome.termination(), &SourceTermination::Completed);
                let expected = usize::from(!complete || excluded != "outer.tar!inner.tar!leaf.txt");
                assert_eq!(outcome.findings().len(), expected);
                if expected != 0 {
                    assert_eq!(
                        outcome.findings()[0].file().as_bytes(),
                        b"outer.tar!inner.tar!leaf.txt"
                    );
                    assert_eq!(outcome.findings()[0].secret().as_bytes(), b"A001");
                }
            }
        }
    }

    #[test]
    fn exact_excluded_sevenz_leaves_bypass_complete_reads_for_each_partition_route() {
        for method in [Method::Copy, Method::Deflate, Method::Lz4] {
            let bytes = archive(&[
                Member::new("skip.txt", b"token=B002\n", method),
                Member::new("keep.txt", b"token=A001", method),
            ]);
            let complete = run(
                &mut source(bytes.clone(), "values.7z", true, "values.7z!skip.txt"),
                &token_detector(),
                ScanOptions::default(),
            );
            assert_eq!(complete.termination(), &SourceTermination::Completed);
            assert_eq!(complete.findings().len(), 1);
            assert_eq!(complete.findings()[0].secret().as_bytes(), b"A001");
            assert_eq!(
                complete.findings()[0].file().as_bytes(),
                b"values.7z!keep.txt"
            );
            let nonmatching = run(
                &mut source(bytes.clone(), "values.7z", true, "values.7z!skip.txt.other"),
                &token_detector(),
                ScanOptions::default(),
            );
            assert!(matches!(
                nonmatching.termination(),
                SourceTermination::SourceError(_)
            ));
            let normal = run(
                &mut source(bytes, "values.7z", false, "values.7z!skip.txt"),
                &token_detector(),
                ScanOptions::default(),
            );
            assert_eq!(normal.termination(), &SourceTermination::Completed);
            assert_eq!(normal.findings().len(), 2);
        }
    }

    #[test]
    fn compressed_stream_paths_are_emitted_leaves_for_exact_exclusions() {
        let gzip = archive_seeds::gzip_stored(b"token=B002\n");
        let outer =
            archive_seeds::synthetic_tar(&[("value.gz", &gzip), ("keep.txt", b"token=A001")]);
        let complete = run(
            &mut source(outer.clone(), "outer.tar", true, "outer.tar!value.gz"),
            &token_detector(),
            ScanOptions::default(),
        );
        assert_eq!(complete.termination(), &SourceTermination::Completed);
        assert_eq!(complete.findings().len(), 1);
        assert_eq!(complete.findings()[0].secret().as_bytes(), b"A001");
        let nonmatching = run(
            &mut source(outer.clone(), "outer.tar", true, "outer.tar!value.gz.other"),
            &token_detector(),
            ScanOptions::default(),
        );
        assert!(matches!(
            nonmatching.termination(),
            SourceTermination::SourceError(_)
        ));
        let normal = run(
            &mut source(outer, "outer.tar", false, "outer.tar!value.gz"),
            &token_detector(),
            ScanOptions::default(),
        );
        assert_eq!(normal.termination(), &SourceTermination::Completed);
        assert_eq!(normal.findings().len(), 2);
    }
}

#[cfg(feature = "archives")]
mod tgz_targets {
    use super::*;
    use rustleaks_sources::{ArchiveLimits, ArchiveOptions, ArchiveSource};

    fn tar_gzip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        archive_seeds::gzip_stored(&archive_seeds::synthetic_tar(entries))
    }

    fn options(depth: usize, member: usize, spool: usize) -> ArchiveOptions {
        ArchiveOptions::new(ArchiveLimits::new(depth, 20, member, 1 << 20, spool).unwrap())
            .emit_limit_issues(true)
    }

    fn source(bytes: Vec<u8>, name: &str, options: ArchiveOptions) -> ArchiveSource {
        ArchiveSource::with_options(
            Cursor::new(bytes),
            name,
            FileOptions::complete(10).unwrap(),
            options,
        )
    }

    #[test]
    fn tgz_preserves_leaf_bytes_paths_and_spans_at_one_depth() {
        let bytes = tar_gzip(&[("leaf.txt", b"token=A001")]);
        for name in ["outer.tgz", "outer.TGZ"] {
            let outcome = run(
                &mut source(bytes.clone(), name, options(1, 4096, 4096)),
                &token_detector(),
                ScanOptions::default(),
            );
            assert_eq!(outcome.termination(), &SourceTermination::Completed);
            assert!(outcome.issues().is_empty());
            assert_eq!(outcome.findings().len(), 1);
            let finding = &outcome.findings()[0];
            assert_eq!(
                finding.file().as_bytes(),
                format!("{name}!leaf.txt").as_bytes()
            );
            assert_eq!(finding.secret().as_bytes(), b"A001");
            assert_eq!(finding.secret_range().exact().unwrap().as_range(), 6..10);
            let actual =
                fragments(&mut source(bytes.clone(), name, options(1, 4096, 4096))).unwrap();
            assert_eq!(actual.len(), 1);
            assert_eq!(actual[0].content().as_bytes(), b"token=A001");
        }
        // A normal scan reads the same `.tgz` as gzip TAR.
        let normal = run(
            &mut ArchiveSource::new(Cursor::new(bytes.clone()), "outer.tgz"),
            &token_detector(),
            ScanOptions::default(),
        );
        assert_eq!(normal.termination(), &SourceTermination::Completed);
        assert!(normal.issues().is_empty());
        assert_eq!(normal.findings().len(), 1);
        assert_eq!(
            normal.findings()[0].file().as_bytes(),
            b"outer.tgz!leaf.txt"
        );
        assert_eq!(normal.findings()[0].secret().as_bytes(), b"A001");
        let cap = bytes.len();
        let mut backup = ArchiveSource::with_options(
            Cursor::new(bytes),
            "outer.tgz.backup",
            FileOptions::complete(cap).unwrap(),
            options(1, 4096, 4096),
        );
        // The non-alias remains a binary ordinary target, with no archive leaves.
        assert!(fragments(&mut backup).unwrap().is_empty());
    }

    fn assert_one_token(outcome: &SourceOutcome, file: &[u8]) {
        assert_eq!(outcome.termination(), &SourceTermination::Completed);
        assert!(outcome.issues().is_empty(), "{:?}", outcome.issues());
        assert_eq!(outcome.findings().len(), 1);
        assert_eq!(outcome.findings()[0].file().as_bytes(), file);
        assert_eq!(outcome.findings()[0].secret().as_bytes(), b"A001");
        assert_eq!(
            outcome.findings()[0]
                .secret_range()
                .exact()
                .unwrap()
                .as_range(),
            6..10
        );
    }

    #[test]
    fn tgz_name_without_the_gzip_magic_is_scanned_as_plain_bytes() {
        use sevenz_seeds::{Member, Method, archive};

        let text = b"token=A001";
        let normal = |bytes: Vec<u8>, name: &str, depth: usize| {
            run(
                &mut ArchiveSource::with_options(
                    Cursor::new(bytes),
                    name,
                    FileOptions::default(),
                    options(depth, 4096, 4096),
                ),
                &token_detector(),
                ScanOptions::default(),
            )
        };
        let complete = |bytes: Vec<u8>, name: &str, depth: usize| {
            run(
                &mut source(bytes, name, options(depth, 4096, 4096)),
                &token_detector(),
                ScanOptions::default(),
            )
        };
        type Scan = fn(Vec<u8>, &str, usize) -> SourceOutcome;
        let scans: [Scan; 2] = [normal, complete];
        for scan in scans {
            for name in ["notes.tgz", "notes.TGZ"] {
                assert_one_token(&scan(text.to_vec(), name, 1), name.as_bytes());
            }
            // One byte, which cannot hold the two-byte magic.
            let short = scan(b"t".to_vec(), "notes.tgz", 1);
            assert_eq!(short.termination(), &SourceTermination::Completed);
            assert!(short.issues().is_empty());
            assert!(short.findings().is_empty());
            // A TAR member, also at the depth limit, and a 7z member.
            let tar = archive_seeds::synthetic_tar(&[("notes.tgz", text)]);
            for depth in [1, 2] {
                assert_one_token(
                    &scan(tar.clone(), "outer.tar", depth),
                    b"outer.tar!notes.tgz",
                );
            }
            for method in [Method::Copy, Method::Deflate] {
                let sevenz = archive(&[Member::new("notes.tgz", text, method)]);
                assert_one_token(&scan(sevenz, "outer.7z", 2), b"outer.7z!notes.tgz");
            }
        }
        // A gzip `.tgz` member is still read as gzip TAR.
        let inner = tar_gzip(&[("leaf.txt", text)]);
        let tar = archive_seeds::synthetic_tar(&[("inner.tgz", &inner)]);
        for scan in scans {
            assert_one_token(
                &scan(tar.clone(), "outer.tar", 2),
                b"outer.tar!inner.tgz!leaf.txt",
            );
        }
    }

    #[test]
    fn tgz_names_keep_the_format_of_their_other_suffixes() {
        use sevenz_seeds::{Member, Method, archive};

        type Scan = fn(Vec<u8>, &str) -> SourceOutcome;
        let normal: Scan = |bytes, name| {
            run(
                &mut ArchiveSource::with_options(
                    Cursor::new(bytes),
                    name,
                    FileOptions::default(),
                    options(2, 4096, 4096),
                ),
                &token_detector(),
                ScanOptions::default(),
            )
        };
        let complete: Scan = |bytes, name| {
            run(
                &mut source(bytes, name, options(2, 4096, 4096)),
                &token_detector(),
                ScanOptions::default(),
            )
        };
        let leaf = b"token=A001";
        let tar = archive_seeds::synthetic_tar(&[("leaf.txt", leaf)]);
        let zip = super::excluded_archive_members::stored_zip(&[("leaf.txt", leaf, false)]);
        let sevenz = archive(&[Member::new("leaf.txt", leaf, Method::Copy)]);
        for scan in [normal, complete] {
            // Without the gzip magic, the earlier suffix names the format.
            assert_one_token(&scan(tar.clone(), "x.tar.tgz"), b"x.tar.tgz!leaf.txt");
            assert_one_token(&scan(zip.clone(), "x.zip.tgz"), b"x.zip.tgz!leaf.txt");
            assert_one_token(&scan(sevenz.clone(), "x.7z.tgz"), b"x.7z.tgz!leaf.txt");
            // With it, `x.gz.tgz` is a gzip stream of one file and other
            // names are a gzip TAR.
            assert_one_token(
                &scan(archive_seeds::gzip_stored(leaf), "x.gz.tgz"),
                b"x.gz.tgz",
            );
            assert_one_token(
                &scan(tar_gzip(&[("leaf.txt", leaf)]), "x.tar.tgz"),
                b"x.tar.tgz!leaf.txt",
            );
        }
    }

    #[test]
    fn depth_zero_skips_a_gzip_tgz_without_an_issue_and_scans_text() {
        let scan = |bytes: Vec<u8>| {
            run(
                &mut ArchiveSource::with_options(
                    Cursor::new(bytes),
                    "x.tgz",
                    FileOptions::default(),
                    options(0, 4096, 4096),
                ),
                &token_detector(),
                ScanOptions::default(),
            )
        };
        let skipped = scan(tar_gzip(&[("leaf.txt", b"token=A001")]));
        assert_eq!(skipped.termination(), &SourceTermination::Completed);
        assert!(skipped.issues().is_empty());
        assert!(skipped.findings().is_empty());
        assert_one_token(&scan(b"token=A001".to_vec()), b"x.tgz");
    }

    #[test]
    fn complete_directory_exact_exclusions_apply_to_tgz_leaves() {
        let tree = Tree::new();
        fs::write(tree.0.join("notes.tgz"), b"token=A001").unwrap();
        fs::write(
            tree.0.join("x.gz.tgz"),
            archive_seeds::gzip_stored(b"token=A001"),
        )
        .unwrap();
        let scan = |excluded: &str| {
            let directory_options = DirectoryOptions::default()
                .file_options(FileOptions::complete(64).unwrap())
                .logical_root("root")
                .archives(options(1, 4096, 4096))
                .exclude_paths(vec![ByteText::from(excluded)]);
            let mut source = DirectorySource::with_options(&tree.0, directory_options);
            let outcome = run(&mut source, &token_detector(), ScanOptions::default());
            assert_eq!(outcome.termination(), &SourceTermination::Completed);
            assert!(outcome.issues().is_empty(), "{:?}", outcome.issues());
            outcome
                .findings()
                .iter()
                .map(|finding| finding.file().as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        assert_eq!(scan("root/notes.tgz"), [b"root/x.gz.tgz".to_vec()]);
        assert_eq!(scan("root/x.gz.tgz"), [b"root/notes.tgz".to_vec()]);
    }

    #[test]
    fn directory_tgz_files_are_read_by_their_bytes() {
        let tree = Tree::new();
        fs::write(tree.0.join("notes.tgz"), b"token=A001\n").unwrap();
        fs::write(
            tree.0.join("outer.tgz"),
            tar_gzip(&[("leaf.txt", b"token=A001")]),
        )
        .unwrap();
        for file_options in [FileOptions::default(), FileOptions::complete(64).unwrap()] {
            let directory_options = DirectoryOptions::default()
                .file_options(file_options)
                .logical_root("root")
                .archives(options(1, 4096, 4096));
            let mut source = DirectorySource::with_options(&tree.0, directory_options);
            let outcome = run(&mut source, &token_detector(), ScanOptions::default());
            assert_eq!(outcome.termination(), &SourceTermination::Completed);
            assert!(outcome.issues().is_empty(), "{:?}", outcome.issues());
            let mut files = outcome
                .findings()
                .iter()
                .map(|finding| finding.file().as_bytes().to_vec())
                .collect::<Vec<_>>();
            files.sort();
            assert_eq!(
                files,
                [
                    b"root/notes.tgz".to_vec(),
                    b"root/outer.tgz!leaf.txt".to_vec()
                ]
            );
        }
    }

    #[test]
    fn nested_tgz_containers_are_not_leaf_exclusions() {
        let inner = tar_gzip(&[("leaf.txt", b"token=A001")]);
        let outer = tar_gzip(&[("inner.TGZ", &inner)]);
        for excluded in [
            "outer.tgz",
            "outer.tgz!inner.TGZ",
            "outer.tgz!inner.TGZ!leaf.txt",
        ] {
            let archive_options =
                options(2, 16_384, 16_384).exclude_paths(vec![ByteText::from(excluded)]);
            let outcome = run(
                &mut source(outer.clone(), "outer.tgz", archive_options),
                &token_detector(),
                ScanOptions::default(),
            );
            assert_eq!(outcome.termination(), &SourceTermination::Completed);
            let expected = usize::from(excluded != "outer.tgz!inner.TGZ!leaf.txt");
            assert_eq!(outcome.findings().len(), expected);
            if expected == 1 {
                assert_eq!(
                    outcome.findings()[0].file().as_bytes(),
                    b"outer.tgz!inner.TGZ!leaf.txt"
                );
            }
        }
        let outcome = run(
            &mut source(outer, "outer.tgz", options(1, 16_384, 16_384)),
            &token_detector(),
            ScanOptions::default(),
        );
        assert_eq!(outcome.termination(), &SourceTermination::Completed);
        assert!(outcome.findings().is_empty());
        assert_eq!(outcome.issues().len(), 1);
        assert_eq!(
            outcome.issues()[0].disposition(),
            SourceIssueDisposition::Excluded
        );
    }

    #[test]
    fn sevenz_member_partitions_recurse_into_complete_tgz_targets() {
        use sevenz_seeds::{Member, Method, archive};

        let inner = tar_gzip(&[("leaf.txt", b"token=A001")]);
        for method in [Method::Copy, Method::Deflate, Method::Lz4] {
            let outer = archive(&[Member::new("inner.tgz", &inner, method)]);
            let outcome = run(
                &mut source(outer, "outer.7z", options(2, 16_384, 16_384)),
                &token_detector(),
                ScanOptions::default(),
            );
            assert_eq!(outcome.termination(), &SourceTermination::Completed);
            assert_eq!(outcome.findings().len(), 1);
            assert_eq!(
                outcome.findings()[0].file().as_bytes(),
                b"outer.7z!inner.tgz!leaf.txt"
            );
            assert_eq!(
                outcome.findings()[0]
                    .secret_range()
                    .exact()
                    .unwrap()
                    .as_range(),
                6..10
            );
        }
    }

    #[test]
    fn complete_directory_tgz_exclusions_apply_only_to_emitted_leaves() {
        let tree = Tree::new();
        fs::write(
            tree.0.join("outer.tgz"),
            tar_gzip(&[("leaf.txt", b"token=A001")]),
        )
        .unwrap();
        for excluded in ["root/outer.tgz", "root/outer.tgz!leaf.txt"] {
            let directory_options = DirectoryOptions::default()
                .file_options(FileOptions::complete(10).unwrap())
                .logical_root("root")
                .archives(options(1, 4096, 4096))
                .exclude_paths(vec![ByteText::from(excluded)]);
            let mut source = DirectorySource::with_options(&tree.0, directory_options);
            let outcome = run(&mut source, &token_detector(), ScanOptions::default());
            assert_eq!(outcome.termination(), &SourceTermination::Completed);
            assert_eq!(
                outcome.findings().len(),
                usize::from(excluded == "root/outer.tgz")
            );
        }
    }

    fn run_counted(source: &mut dyn Source) -> SourceOutcome {
        SourceRunner::new(1, 1)
            .unwrap()
            .with_budget(SourceBudget::unlimited())
            .unwrap()
            .run(
                source,
                &token_detector(),
                ScanOptions::default(),
                &SessionPolicy::default(),
                &CancellationToken::new(),
            )
    }

    #[test]
    fn truncated_tar_retains_only_verified_prefix_members() {
        let mut bytes = archive_seeds::synthetic_tar(&[
            ("first.txt", b"token=A001"),
            ("second.txt", b"token=B002"),
        ]);
        // One complete header/body/padding, then a header and partial body.
        bytes.truncate(1024 + 512 + 7);
        let outcome = run_counted(&mut source(bytes, "partial.tar", options(1, 4096, 4096)));
        assert!(matches!(
            outcome.termination(),
            SourceTermination::SourceError(SourceError::Terminal {
                stage: SourceStage::Archive,
                message,
                ..
            }) if message == "truncated TAR member"
        ));
        assert!(outcome.issues().is_empty());
        assert_eq!(outcome.scanned_bytes(), 10);
        let usage = outcome.usage().unwrap();
        assert_eq!(usage.original_bytes(), 10);
        assert_eq!(usage.fragments(), 1);
        assert_eq!(usage.completed_fragments(), 1);
        assert!(usage.is_exact());
        assert_eq!(outcome.findings().len(), 1);
        let finding = &outcome.findings()[0];
        assert_eq!(finding.file().as_bytes(), b"partial.tar!first.txt");
        assert_eq!(finding.secret().as_bytes(), b"A001");
        assert_eq!(finding.secret_range().exact().unwrap().as_range(), 6..10);
    }

    #[test]
    fn tgz_corruption_and_finite_limits_never_publish_incomplete_leaves() {
        let bytes = tar_gzip(&[("leaf.txt", b"token=A001")]);
        let mut corrupt = bytes.clone();
        let crc = corrupt.len() - 8;
        corrupt[crc] ^= 1;
        let corrupt_outcome =
            run_counted(&mut source(corrupt, "outer.tgz", options(1, 4096, 4096)));
        // The gzip trailer follows the TAR end, so the whole leaf is
        // published before the CRC fails. The scan still fails.
        assert!(matches!(
            corrupt_outcome.termination(),
            SourceTermination::SourceError(SourceError::Terminal {
                stage: SourceStage::Decode,
                message,
                ..
            }) if message == "gzip size or CRC mismatch"
        ));
        assert_eq!(corrupt_outcome.findings().len(), 1);
        assert!(corrupt_outcome.issues().is_empty());
        assert_eq!(corrupt_outcome.scanned_bytes(), 10);
        let usage = corrupt_outcome.usage().unwrap();
        assert_eq!(usage.original_bytes(), 10);
        assert_eq!(usage.fragments(), 1);
        assert_eq!(usage.completed_fragments(), 1);
        assert!(usage.is_exact());

        // A gzip stream decodes while it is read, so spool storage does not
        // limit it.
        let spooled = run(
            &mut source(bytes.clone(), "outer.tgz", options(1, 4096, 1)),
            &token_detector(),
            ScanOptions::default(),
        );
        assert_eq!(spooled.termination(), &SourceTermination::Completed);
        assert_eq!(spooled.findings().len(), 1);

        // A member over the member limit is never published.
        let limited = run(
            &mut source(bytes, "outer.tgz", options(1, 9, 4096)),
            &token_detector(),
            ScanOptions::default(),
        );
        assert!(matches!(
            limited.termination(),
            SourceTermination::SourceError(SourceError::Terminal {
                stage: SourceStage::Limit,
                ..
            })
        ));
        assert!(limited.findings().is_empty());
    }
}
