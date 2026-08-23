#![forbid(unsafe_code)]
//! Differential replay of the frozen scan-session oracle corpus.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use rustleaks_core::model::{Finding, Fragment, Location, RequiredFinding};
use rustleaks_core::session::{
    Baseline, IgnoreSet, ScanSession, SessionPolicy, SuppressionReason, global_fingerprint,
    qualified_fingerprint, sort_findings_canonical,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Request {
    id: String,
    redact_percent: usize,
    ignore_file: Option<FileInput>,
    baseline_file: Option<FileInput>,
    findings: Vec<FindingWire>,
}

#[derive(Deserialize)]
struct FileInput {
    content_base64: String,
    missing: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FindingWire {
    rule_id: String,
    description_base64: String,
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
    line_base64: String,
    match_base64: String,
    secret_base64: String,
    file_base64: String,
    symlink_file_base64: String,
    commit_base64: String,
    link_base64: String,
    entropy_bits: u32,
    author_base64: String,
    email_base64: String,
    date_base64: String,
    message_base64: String,
    tags_base64: Vec<String>,
    fingerprint_base64: String,
    #[serde(default)]
    fragment: Option<FragmentWire>,
    #[serde(default)]
    required_findings: Vec<RequiredWire>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FragmentWire {
    raw_base64: String,
    bytes_base64: String,
    file_base64: String,
    windows_file_base64: String,
    symlink_file_base64: String,
    commit_base64: String,
    start_line: usize,
    inherited_from_finding: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RequiredWire {
    rule_id: String,
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
    line_base64: String,
    match_base64: String,
    secret_base64: String,
}

#[derive(Deserialize)]
struct Outcome {
    id: String,
    ignore: IgnoreOutcome,
    baseline: BaselineOutcome,
    decisions: Vec<Decision>,
    collected_findings: Vec<FindingWire>,
    canonical_findings: Vec<FindingWire>,
    error: Option<OracleError>,
}

#[derive(Deserialize)]
struct IgnoreOutcome {
    entries_base64: Vec<String>,
}

#[derive(Deserialize)]
struct BaselineOutcome {
    findings: Vec<FindingWire>,
}

#[derive(Deserialize)]
struct Decision {
    global_fingerprint_base64: String,
    qualified_fingerprint_base64: String,
    assigned_fingerprint_base64: String,
    ignored_by_global: bool,
    ignored_by_commit: bool,
    baseline_is_new: bool,
    disposition: String,
}

#[derive(Deserialize)]
struct OracleError {
    class: String,
}

#[test]
fn session_corpus_matches_every_frozen_oracle_outcome() {
    let corpus = corpus_root();
    let requests = json_lines::<Request>(&corpus.join("requests-v1.jsonl"));
    let outcomes = json_lines::<Outcome>(&corpus.join("outcomes-v1.jsonl"))
        .into_iter()
        .map(|outcome| (outcome.id.clone(), outcome))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(requests.len(), 45);
    assert_eq!(outcomes.len(), 45);

    for request in requests {
        let expected = outcomes.get(&request.id).unwrap();
        replay(&request, expected);
    }
}

#[allow(clippy::too_many_lines)] // One linear replay keeps every oracle field visibly asserted.
fn replay(request: &Request, expected: &Outcome) {
    if let Some(error) = &expected.error {
        match error.class.as_str() {
            "ignore-open" => assert!(
                request
                    .ignore_file
                    .as_ref()
                    .is_some_and(|file| file.missing)
            ),
            "baseline-open" => {
                assert!(
                    request
                        .baseline_file
                        .as_ref()
                        .is_some_and(|file| file.missing)
                );
            }
            "baseline-format" => {
                let bytes = decode(&request.baseline_file.as_ref().unwrap().content_base64);
                assert!(Baseline::from_go_json(&bytes).is_err(), "{}", request.id);
            }
            class => panic!("unhandled oracle error class {class} for {}", request.id),
        }
        return;
    }

    let ignores = request
        .ignore_file
        .as_ref()
        .map_or_else(IgnoreSet::default, |file| {
            assert!(!file.missing);
            IgnoreSet::parse_go_compatible(&decode(&file.content_base64)).ignores
        });
    let actual_ignore = ignores
        .iter()
        .map(|entry| encode(entry.as_bytes()))
        .collect::<Vec<_>>();
    assert_eq!(
        actual_ignore, expected.ignore.entries_base64,
        "{}",
        request.id
    );

    let baseline = request.baseline_file.as_ref().map(|file| {
        assert!(!file.missing);
        Baseline::from_go_json(&decode(&file.content_base64)).unwrap()
    });
    assert_eq!(
        baseline.as_ref().map_or(0, Baseline::len),
        expected.baseline.findings.len(),
        "{}",
        request.id
    );
    if let Some(baseline) = &baseline {
        for (actual, expected) in baseline.entries().iter().zip(&expected.baseline.findings) {
            assert_eq!(
                actual.rule_id().as_bytes(),
                expected.rule_id.as_bytes(),
                "{}",
                request.id
            );
            assert_eq!(
                actual.description().as_bytes(),
                decode(&expected.description_base64),
                "{}",
                request.id
            );
            assert_eq!(
                actual.link().as_bytes(),
                decode(&expected.link_base64),
                "{}",
                request.id
            );
            assert_eq!(
                actual.start_line(),
                expected.start_line as i128,
                "{}",
                request.id
            );
            assert_eq!(
                actual.end_line(),
                expected.end_line as i128,
                "{}",
                request.id
            );
            assert_eq!(
                actual.start_column(),
                expected.start_column as i128,
                "{}",
                request.id
            );
            assert_eq!(
                actual.end_column(),
                expected.end_column as i128,
                "{}",
                request.id
            );
            assert_eq!(
                actual.entropy().to_bits(),
                expected.entropy_bits,
                "{}",
                request.id
            );
        }
    }

    let mut builder = SessionPolicy::builder()
        .ignores(ignores.clone())
        .redaction_percent(request.redact_percent);
    if let Some(baseline) = baseline.clone() {
        builder = builder.baseline(baseline);
    }
    let mut session = ScanSession::new(builder.build());
    assert_eq!(
        request.findings.len(),
        expected.decisions.len(),
        "{}",
        request.id
    );

    for (input, decision) in request.findings.iter().zip(&expected.decisions) {
        let finding = build_finding(input);
        let original_fingerprint = finding.fingerprint().clone();
        let global = global_fingerprint(&finding);
        let qualified = qualified_fingerprint(&finding);
        assert_eq!(
            encode(global.as_bytes()),
            decision.global_fingerprint_base64,
            "{}",
            request.id
        );
        assert_eq!(
            encode(qualified.as_bytes()),
            decision.qualified_fingerprint_base64,
            "{}",
            request.id
        );
        assert_eq!(
            ignores.contains(global.as_bytes()),
            decision.ignored_by_global,
            "{}",
            request.id
        );
        assert_eq!(
            !finding.commit().is_empty() && ignores.contains(qualified.as_bytes()),
            decision.ignored_by_commit,
            "{}",
            request.id
        );
        assert_eq!(
            baseline
                .as_ref()
                .is_none_or(|baseline| baseline.is_new(&finding, request.redact_percent)),
            decision.baseline_is_new,
            "{}",
            request.id
        );
        let outcome = session.add_finding(finding);
        assert_eq!(
            encode(outcome.fingerprint().as_bytes()),
            decision.assigned_fingerprint_base64,
            "{}",
            request.id
        );
        let disposition = match outcome.suppression_reason() {
            None => "accepted",
            Some(SuppressionReason::GlobalIgnore) => "ignored-global",
            Some(SuppressionReason::CommitIgnore) => "ignored-commit",
            Some(SuppressionReason::Baseline) => "ignored-baseline",
        };
        assert_eq!(disposition, decision.disposition, "{}", request.id);
        assert_eq!(
            original_fingerprint.as_bytes(),
            decode(&input.fingerprint_base64),
            "{}",
            request.id
        );
    }

    let actual = session
        .findings()
        .iter()
        .map(project_finding)
        .collect::<Vec<_>>();
    assert_eq!(actual, expected.collected_findings, "{}", request.id);
    let mut canonical = session.snapshot();
    sort_findings_canonical(&mut canonical);
    let canonical = canonical.iter().map(project_finding).collect::<Vec<_>>();
    assert_eq!(canonical, expected.canonical_findings, "{}", request.id);
}

fn build_finding(input: &FindingWire) -> Finding {
    let mut builder = Finding::builder()
        .rule_id(input.rule_id.clone())
        .description(decode(&input.description_base64))
        .location(
            Location::new(
                input.start_line,
                input.end_line,
                input.start_column,
                input.end_column,
            )
            .unwrap(),
        )
        .line(decode(&input.line_base64))
        .match_text(decode(&input.match_base64))
        .secret(decode(&input.secret_base64))
        .file(decode(&input.file_base64))
        .symlink_file(decode(&input.symlink_file_base64))
        .commit(decode(&input.commit_base64))
        .link(decode(&input.link_base64))
        .entropy(f32::from_bits(input.entropy_bits))
        .author(decode(&input.author_base64))
        .email(decode(&input.email_base64))
        .date(decode(&input.date_base64))
        .message(decode(&input.message_base64))
        .tags(input.tags_base64.iter().map(|value| decode(value)))
        .fingerprint(decode(&input.fingerprint_base64));
    if let Some(fragment) = &input.fragment {
        assert!(!fragment.bytes_base64.is_empty());
        builder = builder.fragment(
            Fragment::builder(decode(&fragment.raw_base64))
                .file_path(decode(&fragment.file_base64))
                .windows_file_path(decode(&fragment.windows_file_base64))
                .symlink_file(decode(&fragment.symlink_file_base64))
                .commit(decode(&fragment.commit_base64))
                .start_line(fragment.start_line)
                .inherited_from_finding(fragment.inherited_from_finding)
                .build(),
        );
    }
    builder = builder.required_findings(input.required_findings.iter().map(|required| {
        RequiredFinding::builder()
            .rule_id(required.rule_id.clone())
            .location(
                Location::new(
                    required.start_line,
                    required.end_line,
                    required.start_column,
                    required.end_column,
                )
                .unwrap(),
            )
            .line(decode(&required.line_base64))
            .match_text(decode(&required.match_base64))
            .secret(decode(&required.secret_base64))
            .build()
            .unwrap()
    }));
    builder.build().unwrap()
}

fn project_finding(finding: &Finding) -> FindingWire {
    let location = finding.location();
    FindingWire {
        rule_id: finding.rule_id().to_string_lossy().into_owned(),
        description_base64: encode(finding.description().as_bytes()),
        start_line: location.start_line(),
        end_line: location.end_line(),
        start_column: location.start_column(),
        end_column: location.end_column(),
        line_base64: encode(finding.line().as_bytes()),
        match_base64: encode(finding.match_text().as_bytes()),
        secret_base64: encode(finding.secret().as_bytes()),
        file_base64: encode(finding.file().as_bytes()),
        symlink_file_base64: encode(finding.symlink_file().as_bytes()),
        commit_base64: encode(finding.commit().as_bytes()),
        link_base64: encode(finding.link().as_bytes()),
        entropy_bits: finding.entropy().to_bits(),
        author_base64: encode(finding.author().as_bytes()),
        email_base64: encode(finding.email().as_bytes()),
        date_base64: encode(finding.date().as_bytes()),
        message_base64: encode(finding.message().as_bytes()),
        tags_base64: finding
            .tags()
            .iter()
            .map(|tag| encode(tag.as_bytes()))
            .collect(),
        fingerprint_base64: encode(finding.fingerprint().as_bytes()),
        fragment: finding.fragment().map(|fragment| FragmentWire {
            raw_base64: encode(fragment.content().as_bytes()),
            bytes_base64: String::new(),
            file_base64: encode(fragment.file_path().as_bytes()),
            windows_file_base64: encode(fragment.windows_file_path().as_bytes()),
            symlink_file_base64: encode(fragment.symlink_file().as_bytes()),
            commit_base64: encode(fragment.commit().as_bytes()),
            start_line: fragment.start_line(),
            inherited_from_finding: fragment.inherited_from_finding(),
        }),
        required_findings: finding
            .required_findings()
            .iter()
            .map(|required| {
                let location = required.location();
                RequiredWire {
                    rule_id: required.rule_id().to_string_lossy().into_owned(),
                    start_line: location.start_line(),
                    end_line: location.end_line(),
                    start_column: location.start_column(),
                    end_column: location.end_column(),
                    line_base64: encode(required.line().as_bytes()),
                    match_base64: encode(required.match_text().as_bytes()),
                    secret_base64: encode(required.secret().as_bytes()),
                }
            })
            .collect(),
    }
}

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../compat/session-corpus")
}

fn json_lines<T: for<'de> Deserialize<'de>>(path: &Path) -> Vec<T> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn decode(value: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap()
}

fn encode(value: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}
