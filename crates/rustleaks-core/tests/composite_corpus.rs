#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use rustleaks_core::Engine;
use rustleaks_core::config::{CompiledConfig, ConfigLoader, ConfigOrigin, VirtualResolver};
use rustleaks_core::model::{CommitMetadata, Finding, Fragment, ScanOptions};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Request {
    id: String,
    operation: String,
    #[serde(default)]
    config_base64: String,
    #[serde(default)]
    config_fixture: String,
    #[serde(default)]
    config_entry: String,
    #[serde(default)]
    config_files: Vec<ConfigFile>,
    #[serde(default)]
    config_working_directory: String,
    #[serde(default)]
    fragment: RequestFragment,
    #[serde(default)]
    options: RequestOptions,
    #[serde(default)]
    redaction: FindingInput,
    #[serde(default)]
    redact_percent: usize,
}

#[derive(Deserialize)]
struct ConfigFile {
    path: String,
    content_base64: String,
}

#[derive(Default, Deserialize)]
struct RequestFragment {
    content_base64: String,
    file_base64: String,
    windows_file_base64: String,
    symlink_file_base64: String,
    commit_base64: String,
    start_line: i64,
    author_base64: String,
    email_base64: String,
    date_base64: String,
    message_base64: String,
    inherited_from_finding: bool,
}

#[derive(Default, Deserialize)]
struct RequestOptions {
    max_decode_depth: i64,
    max_target_megabytes: i64,
    redact_percent: usize,
    ignore_allow_marker: bool,
}

#[derive(Default, Deserialize)]
struct FindingInput {
    rule_id: String,
    description_base64: String,
    start_line: i64,
    end_line: i64,
    start_column: i64,
    end_column: i64,
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
    fragment: Option<CanonicalFragment>,
    #[serde(default)]
    required_findings: Vec<CanonicalRequiredFinding>,
}

#[derive(Deserialize)]
struct Response {
    id: String,
    operation: String,
    findings: Vec<CanonicalFinding>,
    original: Option<CanonicalFinding>,
    redacted: Option<CanonicalFinding>,
    mask_secret_base64: String,
    error: Option<OracleError>,
}

#[derive(Deserialize)]
struct OracleError {
    class: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalFinding {
    rule_id: String,
    description_base64: String,
    start_line: i64,
    end_line: i64,
    start_column: i64,
    end_column: i64,
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
    fragment: Option<CanonicalFragment>,
    required_findings: Vec<CanonicalRequiredFinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalFragment {
    raw_base64: String,
    bytes_base64: String,
    file_base64: String,
    windows_file_base64: String,
    symlink_file_base64: String,
    commit_base64: String,
    start_line: i64,
    inherited_from_finding: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalRequiredFinding {
    rule_id: String,
    start_line: i64,
    end_line: i64,
    start_column: i64,
    end_column: i64,
    line_base64: String,
    match_base64: String,
    secret_base64: String,
}

#[test]
fn frozen_composite_and_redaction_corpus_matches_go() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../compat/composite-corpus");
    let requests = json_lines::<Request>(&corpus.join("requests-v1.jsonl"));
    let responses = json_lines::<Response>(&corpus.join("outcomes-v1.jsonl"))
        .into_iter()
        .map(|response| (response.id.clone(), response))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(requests.len(), 182);
    assert_eq!(requests.len(), responses.len());

    let mut private_operations = BTreeSet::new();
    let mut bounded_resource_exclusions = BTreeSet::new();
    let mut valid_domain_exclusions = BTreeSet::new();
    for request in requests {
        let response = responses.get(&request.id).unwrap();
        assert_eq!(request.operation, response.operation, "{}", request.id);
        if bounded_resource_ids().contains(&request.id.as_str()) {
            bounded_resource_exclusions.insert(request.id);
            continue;
        }
        match request.operation.as_str() {
            "detect" => {
                if response
                    .error
                    .as_ref()
                    .is_some_and(|error| error.class == "config")
                {
                    assert!(load_config(&request).is_err(), "{}", request.id);
                    continue;
                }
                assert!(response.error.is_none(), "{}: Go oracle error", request.id);
                if request.fragment.start_line.is_negative() {
                    valid_domain_exclusions.insert(request.id);
                    continue;
                }
                let config = load_config(&request)
                    .unwrap_or_else(|error| panic!("{}: Rust config error: {error}", request.id));
                let fragment = build_fragment(&request.fragment);
                let options = build_options(&request.options);
                let mut actual = Engine::builder(config)
                    .build()
                    .unwrap()
                    .scan_fragment(&fragment, &options)
                    .findings()
                    .iter()
                    .map(canonical_finding)
                    .collect::<Vec<_>>();
                actual.sort();
                let mut expected = response.findings.clone();
                expected.sort();
                assert_eq!(actual, expected, "composite corpus case {}", request.id);
            }
            "redact" => {
                assert!(response.error.is_none(), "{}: Go oracle error", request.id);
                let finding = build_finding(&request.redaction);
                assert_eq!(
                    response.original.as_ref(),
                    Some(&canonical_finding(&finding))
                );
                let actual = finding.redacted(request.redact_percent);
                assert_eq!(
                    response.redacted.as_ref(),
                    Some(&canonical_finding(&actual)),
                    "redaction corpus case {}",
                    request.id
                );
            }
            "mask_secret" | "filter_probe" => {
                assert!(response.error.is_none(), "{}: Go oracle error", request.id);
                if request.operation == "mask_secret" {
                    assert!(!response.mask_secret_base64.is_empty(), "{}", request.id);
                }
                private_operations.insert(request.id);
            }
            "probe_missing_required" => {
                assert!(response.error.is_none(), "{}: Go oracle error", request.id);
                assert!(response.findings.is_empty(), "{}", request.id);
                valid_domain_exclusions.insert(request.id);
            }
            operation => panic!("unknown composite operation {operation}"),
        }
    }

    assert_replay_inventory(
        &bounded_resource_exclusions,
        &valid_domain_exclusions,
        &private_operations,
    );
}

fn assert_replay_inventory(
    bounded_resource_exclusions: &BTreeSet<String>,
    valid_domain_exclusions: &BTreeSet<String>,
    private_operations: &BTreeSet<String>,
) {
    let expected_resources = bounded_resource_ids()
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(bounded_resource_exclusions, &expected_resources);
    let expected_domain_exclusions = BTreeSet::from([
        "proximity-negative-fragment-start".to_owned(),
        "required-runtime-missing-fail-closed".to_owned(),
    ]);
    assert_eq!(valid_domain_exclusions, &expected_domain_exclusions);
    let expected_private_operations = BTreeSet::from([
        "filter-exact-duplicate-primaries-required".to_owned(),
        "generic-filter-adapter-different-commit".to_owned(),
        "generic-filter-adapter-ignores-file-column-end".to_owned(),
        "generic-filter-adapter-same-rule-id".to_owned(),
        "generic-filter-duplicate-order".to_owned(),
        "upstream-tm-0246-high-masking".to_owned(),
        "upstream-tm-0247-invalid-masking".to_owned(),
        "upstream-tm-0248-low-masking".to_owned(),
        "upstream-tm-0249-normal-masking".to_owned(),
    ]);
    assert_eq!(private_operations, &expected_private_operations);
}

#[test]
fn resource_primary_aux_duplicate_cartesian_is_bounded() {
    if !bounded_resource_test_enabled("resource_primary_aux_duplicate_cartesian_is_bounded") {
        return;
    }
    assert_detect_resource_case(
        "resource-primary-aux-duplicate-cartesian",
        Some((16, 1_024)),
        2 * 1_024 * 1_024,
    );
}

#[test]
fn resource_many_generics_is_bounded() {
    if !bounded_resource_test_enabled("resource_many_generics_is_bounded") {
        return;
    }
    assert_detect_resource_case("resource-many-generics", Some((128, 0)), 512 * 1_024);
}

#[test]
fn resource_empty_full_long_malformed_is_bounded() {
    if !bounded_resource_test_enabled("resource_empty_full_long_malformed_is_bounded") {
        return;
    }
    let (request, response) = composite_case("resource-empty-full-long-malformed");
    assert_eq!(request.operation, "redact");
    let actual = build_finding(&request.redaction).redacted(request.redact_percent);
    let canonical = canonical_finding(&actual);
    assert_eq!(response.redacted.as_ref(), Some(&canonical));
    let encoded = serde_json::to_vec(&canonical).unwrap();
    assert!(
        encoded.len() <= 128 * 1_024,
        "resource-empty-full-long-malformed exceeded its 128 KiB output ceiling: {} bytes",
        encoded.len()
    );
}

#[test]
fn resource_deep_required_graph_is_bounded() {
    if !bounded_resource_test_enabled("resource_deep_required_graph_is_bounded") {
        return;
    }
    for id in [
        "resource-deep-required-graph",
        "resource-deep-required-graph-missing-tail",
        "resource-deep-required-cycle",
    ] {
        assert_detect_resource_case(id, Some((1, 1)), 512 * 1_024);
    }
}

fn bounded_resource_ids() -> [&'static str; 6] {
    [
        "resource-primary-aux-duplicate-cartesian",
        "resource-many-generics",
        "resource-empty-full-long-malformed",
        "resource-deep-required-graph",
        "resource-deep-required-graph-missing-tail",
        "resource-deep-required-cycle",
    ]
}

fn bounded_resource_test_enabled(test: &str) -> bool {
    std::env::var("RUSTLEAKS_BOUNDED_RESOURCE_TEST").is_ok_and(|selected| selected == test)
}

fn assert_detect_resource_case(
    id: &str,
    expected_shape: Option<(usize, usize)>,
    maximum_output_bytes: usize,
) {
    let (request, response) = composite_case(id);
    assert_eq!(request.operation, "detect", "{id}");
    assert!(response.error.is_none(), "{id}: Go oracle error");
    let config = load_config(&request).unwrap_or_else(|error| panic!("{id}: {error}"));
    let actual = Engine::builder(config)
        .build()
        .unwrap()
        .scan_fragment(
            &build_fragment(&request.fragment),
            &build_options(&request.options),
        )
        .findings()
        .iter()
        .map(canonical_finding)
        .collect::<Vec<_>>();
    let required_count = actual
        .iter()
        .map(|finding| finding.required_findings.len())
        .sum::<usize>();
    if let Some((finding_count, required_count_expected)) = expected_shape {
        assert_eq!(actual.len(), finding_count, "{id}");
        assert_eq!(required_count, required_count_expected, "{id}");
    }
    let mut comparable_actual = actual.clone();
    comparable_actual.sort();
    let mut comparable_expected = response.findings.clone();
    comparable_expected.sort();
    assert_eq!(comparable_actual, comparable_expected, "{id}");
    let encoded = serde_json::to_vec(&actual).unwrap();
    assert!(
        encoded.len() <= maximum_output_bytes,
        "{id} exceeded its {maximum_output_bytes} byte output ceiling: {} bytes",
        encoded.len()
    );
}

fn composite_case(id: &str) -> (Request, Response) {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../compat/composite-corpus");
    let request = json_lines::<Request>(&corpus.join("requests-v1.jsonl"))
        .into_iter()
        .find(|request| request.id == id)
        .unwrap_or_else(|| panic!("missing frozen composite request {id}"));
    let response = json_lines::<Response>(&corpus.join("outcomes-v1.jsonl"))
        .into_iter()
        .find(|response| response.id == id)
        .unwrap_or_else(|| panic!("missing frozen composite outcome {id}"));
    (request, response)
}

fn load_config(request: &Request) -> Result<CompiledConfig, String> {
    if !request.config_base64.is_empty() {
        let bytes = decode_base64(&request.config_base64);
        let text = std::str::from_utf8(&bytes).map_err(|error| error.to_string())?;
        return ConfigLoader::new()
            .load_toml(text)
            .map_err(|error| error.to_string());
    }
    if !request.config_fixture.is_empty() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../compat/fixtures/upstream/testdata/config")
            .join(&request.config_fixture);
        let text = fs::read_to_string(path).map_err(|error| error.to_string())?;
        return ConfigLoader::new()
            .load_toml(text.as_str())
            .map_err(|error| error.to_string());
    }

    let mut resolver = VirtualResolver::new();
    let mut entry = None;
    for file in &request.config_files {
        let text = String::from_utf8(decode_base64(&file.content_base64))
            .map_err(|error| error.to_string())?;
        if file.path == request.config_entry {
            entry = Some(text.clone());
        }
        resolver.insert(&file.path, text);
    }
    let entry = entry.ok_or_else(|| "config bundle entry is missing".to_owned())?;
    let origin = if request.config_working_directory.is_empty() {
        request.config_entry.clone()
    } else {
        let basename = Path::new(&request.config_entry)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "config entry has no basename".to_owned())?;
        format!("{}/{basename}", request.config_working_directory)
    };
    ConfigLoader::new()
        .with_resolver(resolver)
        .load_toml_at(&entry, Some(ConfigOrigin::virtual_path(origin)))
        .map_err(|error| error.to_string())
}

fn build_fragment(input: &RequestFragment) -> Fragment {
    let author = decode_base64(&input.author_base64);
    let email = decode_base64(&input.email_base64);
    let date = decode_base64(&input.date_base64);
    let message = decode_base64(&input.message_base64);
    let mut fragment = Fragment::builder(decode_base64(&input.content_base64))
        .file_path(decode_base64(&input.file_base64))
        .windows_file_path(decode_base64(&input.windows_file_base64))
        .symlink_file(decode_base64(&input.symlink_file_base64))
        .commit(decode_base64(&input.commit_base64))
        .start_line(usize::try_from(input.start_line).unwrap())
        .inherited_from_finding(input.inherited_from_finding);
    if [&author, &email, &date, &message]
        .into_iter()
        .any(|value| !value.is_empty())
    {
        fragment = fragment.commit_metadata(
            CommitMetadata::builder()
                .author_name(author)
                .author_email(email)
                .date(date)
                .message(message)
                .build(),
        );
    }
    fragment.build()
}

fn build_options(input: &RequestOptions) -> ScanOptions {
    let maximum = (input.max_target_megabytes > 0).then(|| {
        usize::try_from(input.max_target_megabytes)
            .unwrap()
            .saturating_add(1)
            .saturating_mul(1_000_000)
            .saturating_sub(1)
    });
    ScanOptions::builder()
        .max_decode_depth(usize::try_from(input.max_decode_depth).unwrap_or(0))
        .max_target_bytes(maximum)
        .redaction_percent(input.redact_percent)
        .honor_gitleaks_allow(!input.ignore_allow_marker)
        .build()
}

fn build_finding(input: &FindingInput) -> Finding {
    let mut builder = Finding::builder()
        .rule_id(input.rule_id.as_str())
        .description(decode_base64(&input.description_base64))
        .location(
            rustleaks_core::model::Location::new(
                usize::try_from(input.start_line).unwrap(),
                usize::try_from(input.end_line).unwrap(),
                usize::try_from(input.start_column).unwrap(),
                usize::try_from(input.end_column).unwrap(),
            )
            .unwrap(),
        )
        .line(decode_base64(&input.line_base64))
        .match_text(decode_base64(&input.match_base64))
        .secret(decode_base64(&input.secret_base64))
        .file(decode_base64(&input.file_base64))
        .symlink_file(decode_base64(&input.symlink_file_base64))
        .commit(decode_base64(&input.commit_base64))
        .link(decode_base64(&input.link_base64))
        .entropy(f32::from_bits(input.entropy_bits))
        .author(decode_base64(&input.author_base64))
        .email(decode_base64(&input.email_base64))
        .date(decode_base64(&input.date_base64))
        .message(decode_base64(&input.message_base64))
        .tags(input.tags_base64.iter().map(|tag| decode_base64(tag)))
        .fingerprint(decode_base64(&input.fingerprint_base64));
    if let Some(fragment) = &input.fragment {
        assert!(
            fragment.bytes_base64.is_empty(),
            "redaction fixture uses the unsupported dual Raw/Bytes fragment shape"
        );
        builder = builder.fragment(
            Fragment::builder(decode_base64(&fragment.raw_base64))
                .file_path(decode_base64(&fragment.file_base64))
                .windows_file_path(decode_base64(&fragment.windows_file_base64))
                .symlink_file(decode_base64(&fragment.symlink_file_base64))
                .commit(decode_base64(&fragment.commit_base64))
                .start_line(usize::try_from(fragment.start_line).unwrap())
                .inherited_from_finding(fragment.inherited_from_finding)
                .build(),
        );
    }
    builder
        .required_findings(input.required_findings.iter().map(|required| {
            rustleaks_core::model::RequiredFinding::builder()
                .rule_id(required.rule_id.as_str())
                .location(
                    rustleaks_core::model::Location::new(
                        usize::try_from(required.start_line).unwrap(),
                        usize::try_from(required.end_line).unwrap(),
                        usize::try_from(required.start_column).unwrap(),
                        usize::try_from(required.end_column).unwrap(),
                    )
                    .unwrap(),
                )
                .line(decode_base64(&required.line_base64))
                .match_text(decode_base64(&required.match_base64))
                .secret(decode_base64(&required.secret_base64))
                .build()
                .unwrap()
        }))
        .build()
        .unwrap()
}

fn canonical_finding(finding: &Finding) -> CanonicalFinding {
    CanonicalFinding {
        rule_id: finding.rule_id().to_string_lossy().into_owned(),
        description_base64: encode_base64(finding.description().as_bytes()),
        start_line: i64::try_from(finding.location().start_line()).unwrap(),
        end_line: i64::try_from(finding.location().end_line()).unwrap(),
        start_column: i64::try_from(finding.location().start_column()).unwrap(),
        end_column: i64::try_from(finding.location().end_column()).unwrap(),
        line_base64: encode_base64(finding.line().as_bytes()),
        match_base64: encode_base64(finding.match_text().as_bytes()),
        secret_base64: encode_base64(finding.secret().as_bytes()),
        file_base64: encode_base64(finding.file().as_bytes()),
        symlink_file_base64: encode_base64(finding.symlink_file().as_bytes()),
        commit_base64: encode_base64(finding.commit().as_bytes()),
        link_base64: encode_base64(finding.link().as_bytes()),
        entropy_bits: finding.entropy().to_bits(),
        author_base64: encode_base64(finding.author().as_bytes()),
        email_base64: encode_base64(finding.email().as_bytes()),
        date_base64: encode_base64(finding.date().as_bytes()),
        message_base64: encode_base64(finding.message().as_bytes()),
        tags_base64: finding
            .tags()
            .iter()
            .map(|tag| encode_base64(tag.as_bytes()))
            .collect(),
        fingerprint_base64: encode_base64(finding.fingerprint().as_bytes()),
        fragment: finding.fragment().map(|fragment| CanonicalFragment {
            raw_base64: encode_base64(fragment.content().as_bytes()),
            bytes_base64: String::new(),
            file_base64: encode_base64(fragment.file_path().as_bytes()),
            windows_file_base64: encode_base64(fragment.windows_file_path().as_bytes()),
            symlink_file_base64: encode_base64(fragment.symlink_file().as_bytes()),
            commit_base64: encode_base64(fragment.commit().as_bytes()),
            start_line: i64::try_from(fragment.start_line()).unwrap(),
            inherited_from_finding: fragment.inherited_from_finding(),
        }),
        required_findings: finding
            .required_findings()
            .iter()
            .map(|required| CanonicalRequiredFinding {
                rule_id: required.rule_id().to_string_lossy().into_owned(),
                start_line: i64::try_from(required.location().start_line()).unwrap(),
                end_line: i64::try_from(required.location().end_line()).unwrap(),
                start_column: i64::try_from(required.location().start_column()).unwrap(),
                end_column: i64::try_from(required.location().end_column()).unwrap(),
                line_base64: encode_base64(required.line().as_bytes()),
                match_base64: encode_base64(required.match_text().as_bytes()),
                secret_base64: encode_base64(required.secret().as_bytes()),
            })
            .collect(),
    }
}

fn json_lines<T: for<'de> Deserialize<'de>>(path: &Path) -> Vec<T> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn decode_base64(encoded: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(encoded.len() / 4 * 3);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in encoded.bytes().take_while(|byte| *byte != b'=') {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid frozen base64 fixture"),
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    output
}

fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(char::from(TABLE[((value >> 18) & 63) as usize]));
        output.push(char::from(TABLE[((value >> 12) & 63) as usize]));
        output.push(if chunk.len() > 1 {
            char::from(TABLE[((value >> 6) & 63) as usize])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(TABLE[(value & 63) as usize])
        } else {
            '='
        });
    }
    output
}
