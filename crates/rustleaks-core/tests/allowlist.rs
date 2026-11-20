#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use rustleaks_core::Engine;
use rustleaks_core::config::{ConfigLoader, ConfigOrigin, VirtualResolver};
use rustleaks_core::model::{CommitMetadata, Fragment, ScanOptions};
use serde::Deserialize;

#[allow(dead_code)]
#[path = "support/corpus.rs"]
mod corpus;

use corpus::{CanonicalFinding, canonical_finding, decode_base64, json_lines};

#[derive(Deserialize)]
struct Request {
    id: String,
    operation: String,
    method: Option<String>,
    validate: Option<bool>,
    #[serde(default)]
    validate_count: usize,
    #[serde(default)]
    nil_allowlist: bool,
    #[serde(default)]
    base_global: bool,
    allowlist: Option<RequestAllowlist>,
    input_base64: Option<String>,
    #[serde(default)]
    use_default: bool,
    #[serde(default)]
    config_base64: String,
    #[serde(default)]
    config_fixture: String,
    #[serde(default)]
    config_entry: String,
    #[serde(default)]
    config_files: Vec<RequestConfigFile>,
    fragment: Option<RequestFragment>,
    options: Option<RequestOptions>,
}

#[derive(Deserialize)]
struct RequestAllowlist {
    description_base64: String,
    condition: String,
    commits_base64: Vec<String>,
    paths_base64: Vec<String>,
    regex_target: String,
    regexes_base64: Vec<String>,
    stopwords_base64: Vec<String>,
}

#[derive(Deserialize)]
struct RequestConfigFile {
    path: String,
    content_base64: String,
}

#[derive(Deserialize)]
struct RequestFragment {
    content_base64: String,
    file_base64: String,
    windows_file_base64: String,
    symlink_file_base64: String,
    commit_base64: String,
    start_line: usize,
    author_base64: String,
    email_base64: String,
    date_base64: String,
    message_base64: String,
    inherited_from_finding: bool,
}

#[derive(Deserialize)]
struct RequestOptions {
    max_target_megabytes: i64,
    ignore_allow_marker: bool,
}

#[derive(Deserialize)]
struct Response {
    id: String,
    operation: String,
    validation: Option<Validation>,
    normalized: Option<NormalizedAllowlist>,
    method_result: Option<MethodResult>,
    findings: Vec<CanonicalFinding>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Validation {
    success: bool,
    error: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct NormalizedAllowlist {
    description: String,
    condition: String,
    commits: Vec<String>,
    paths: Vec<String>,
    regex_target: String,
    regexes: Vec<String>,
    stop_words: Vec<String>,
}

#[derive(Deserialize)]
struct MethodResult {
    method: String,
    allowed: bool,
    matched_value_base64: String,
}

#[derive(Deserialize)]
struct Coverage {
    behavior_ids: Vec<BehaviorDisposition>,
}

#[derive(Deserialize)]
struct BehaviorDisposition {
    id: String,
    status: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum MethodDisposition {
    ExecutedValidated,
    DeferredNilReceiver,
    DeferredUnvalidated,
    DeferredProgrammaticBase,
}

#[test]
fn frozen_allowlist_corpus_matches_go() {
    let corpus = corpus_dir();
    let requests = json_lines::<Request>(&corpus.join("requests-v1.jsonl"));
    let responses = json_lines::<Response>(&corpus.join("outcomes-v1.jsonl"));
    assert_eq!(requests.len(), 188);
    assert_eq!(responses.len(), 188);

    let mut method_dispositions = BTreeMap::<MethodDisposition, usize>::new();
    let mut detector_rows = 0;
    for (request, response) in requests.iter().zip(&responses) {
        assert_eq!(request.id, response.id);
        assert_eq!(request.operation, response.operation);
        assert!(response.error.is_none(), "{}: Go oracle error", request.id);
        match request.operation.as_str() {
            "method" => {
                let disposition = method_disposition(request);
                *method_dispositions.entry(disposition).or_default() += 1;
                if disposition == MethodDisposition::ExecutedValidated {
                    assert_validated_method(request, response);
                } else {
                    // These rows are source evidence, not silently skipped:
                    // immutable Rust configs cannot have nil receivers, stale
                    // unvalidated state, or the programmatic base's pre-Validate
                    // fallback. Their exact disposition totals are gated below.
                    assert!(response.method_result.is_some());
                }
            }
            "detect" => {
                detector_rows += 1;
                assert_detector(request, response);
            }
            operation => panic!("{}: unknown operation {operation}", request.id),
        }
    }
    assert_eq!(detector_rows, 61);
    assert_eq!(
        method_dispositions,
        BTreeMap::from([
            (MethodDisposition::ExecutedValidated, 18),
            (MethodDisposition::DeferredNilReceiver, 4),
            (MethodDisposition::DeferredUnvalidated, 13),
            (MethodDisposition::DeferredProgrammaticBase, 92),
        ])
    );

    let coverage: Coverage =
        serde_json::from_str(&fs::read_to_string(corpus.join("coverage-v1.json")).unwrap())
            .unwrap();
    let statuses = coverage
        .behavior_ids
        .into_iter()
        .map(|entry| (entry.id, entry.status))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        statuses.get("AL-014").map(String::as_str),
        Some("future-m7-ordering-cases-frozen-no-positive-composite-claim")
    );
    assert_eq!(
        statuses.get("AL-015").map(String::as_str),
        Some("raw-line-observed-decoded-line-deferred-m6")
    );
}

fn method_disposition(request: &Request) -> MethodDisposition {
    if request.validate == Some(true) || request.validate_count > 0 {
        MethodDisposition::ExecutedValidated
    } else if request.nil_allowlist {
        MethodDisposition::DeferredNilReceiver
    } else if request.base_global {
        MethodDisposition::DeferredProgrammaticBase
    } else {
        MethodDisposition::DeferredUnvalidated
    }
}

fn assert_validated_method(request: &Request, response: &Response) {
    let validation = response.validation.as_ref().unwrap();
    let text = method_probe_toml(request.allowlist.as_ref().unwrap());
    let loaded = ConfigLoader::new().load_toml(&text);
    if !validation.success {
        let error = loaded.unwrap_err().to_string();
        assert!(
            error.ends_with(&validation.error),
            "{}: {error:?} did not end with {:?}",
            request.id,
            validation.error
        );
        return;
    }
    let config = loaded.unwrap();
    let allowlist = &config.allowlists()[0];
    let expected = response.normalized.as_ref().unwrap();
    let mut actual = NormalizedAllowlist {
        description: allowlist.description().to_owned(),
        condition: allowlist.condition().to_string(),
        commits: allowlist.commits().map(str::to_owned).collect(),
        paths: allowlist.paths().to_vec(),
        regex_target: allowlist.regex_target().as_str().to_owned(),
        regexes: allowlist.regexes().to_vec(),
        stop_words: allowlist.stop_words().map(str::to_owned).collect(),
    };
    actual.commits.sort();
    actual.stop_words.sort();
    let mut expected_sorted = NormalizedAllowlist {
        description: expected.description.clone(),
        condition: expected.condition.clone(),
        commits: expected.commits.clone(),
        paths: expected.paths.clone(),
        regex_target: expected.regex_target.clone(),
        regexes: expected.regexes.clone(),
        stop_words: expected.stop_words.clone(),
    };
    expected_sorted.commits.sort();
    expected_sorted.stop_words.sort();
    assert_eq!(actual, expected_sorted, "{} normalization", request.id);

    let result = response.method_result.as_ref().unwrap();
    assert_eq!(request.method.as_deref(), Some(result.method.as_str()));
    let input = decode_base64(request.input_base64.as_deref().unwrap());
    let fragment = match result.method.as_str() {
        "commit" => Fragment::builder(b"probe".to_vec()).commit(input).build(),
        "path" => Fragment::builder(b"probe".to_vec())
            .file_path(input)
            .build(),
        "regex" | "stopword" => Fragment::new(input),
        method => panic!("{}: unknown method {method}", request.id),
    };
    let actual_allowed = Engine::builder(config)
        .build()
        .unwrap()
        .scan_fragment(&fragment, &ScanOptions::default())
        .findings()
        .is_empty();
    assert_eq!(actual_allowed, result.allowed, "{} decision", request.id);

    // Commit's validated success payload is always empty. Stopword payload
    // geometry is exercised against the private matcher in engine unit tests.
    if result.method == "commit" && result.allowed {
        assert!(result.matched_value_base64.is_empty());
    }
}

fn method_probe_toml(allowlist: &RequestAllowlist) -> String {
    let mut text =
        String::from("[[rules]]\nid = \"probe\"\nregex = '''(?s).+'''\n\n[[allowlists]]\n");
    if !allowlist.description_base64.is_empty() {
        push_toml_string(
            &mut text,
            "description",
            &go_string(&decode_base64(&allowlist.description_base64)),
        );
    }
    if !allowlist.condition.is_empty() {
        push_toml_string(&mut text, "condition", &allowlist.condition);
    }
    push_toml_array(&mut text, "commits", &allowlist.commits_base64);
    push_toml_array(&mut text, "paths", &allowlist.paths_base64);
    if !allowlist.regex_target.is_empty() {
        push_toml_string(&mut text, "regexTarget", &allowlist.regex_target);
    }
    push_toml_array(&mut text, "regexes", &allowlist.regexes_base64);
    push_toml_array(&mut text, "stopwords", &allowlist.stopwords_base64);
    text
}

fn push_toml_array(output: &mut String, key: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    output.push_str(key);
    output.push_str(" = [");
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        output.push_str(&toml_string(&go_string(&decode_base64(value))));
    }
    output.push_str("]\n");
}

fn push_toml_string(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    output.push_str(" = ");
    output.push_str(&toml_string(value));
    output.push('\n');
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}

fn assert_detector(request: &Request, response: &Response) {
    let config = load_detector_config(request);
    let engine = Engine::builder(config).build().unwrap();
    let source = request.fragment.as_ref().unwrap();
    let author = decode_base64(&source.author_base64);
    let email = decode_base64(&source.email_base64);
    let date = decode_base64(&source.date_base64);
    let message = decode_base64(&source.message_base64);
    let mut fragment = Fragment::builder(decode_base64(&source.content_base64))
        .file_path(decode_base64(&source.file_base64))
        .windows_file_path(decode_base64(&source.windows_file_base64))
        .symlink_file(decode_base64(&source.symlink_file_base64))
        .commit(decode_base64(&source.commit_base64))
        .start_line(source.start_line)
        .inherited_from_finding(source.inherited_from_finding);
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
    let options = request.options.as_ref().unwrap();
    let maximum = (options.max_target_megabytes > 0).then(|| {
        usize::try_from(options.max_target_megabytes)
            .unwrap()
            .saturating_add(1)
            .saturating_mul(1_000_000)
            .saturating_sub(1)
    });
    let scan_options = ScanOptions::builder()
        .max_target_bytes(maximum)
        .honor_allow_markers(!options.ignore_allow_marker)
        .build();
    let mut actual = engine
        .scan_fragment(&fragment.build(), &scan_options)
        .findings()
        .iter()
        .map(canonical_finding)
        .collect::<Vec<_>>();
    let mut expected = response.findings.clone();
    actual.sort_by_cached_key(|finding| serde_json::to_string(finding).unwrap());
    expected.sort_by_cached_key(|finding| serde_json::to_string(finding).unwrap());
    assert_eq!(actual, expected, "detector corpus case {}", request.id);
}

fn load_detector_config(request: &Request) -> rustleaks_core::config::CompiledConfig {
    if request.use_default {
        return ConfigLoader::new().load_default().unwrap();
    }
    if !request.config_fixture.is_empty() {
        let fixture = fixture_root().join(&request.config_fixture);
        return ConfigLoader::new()
            .with_resolver(fixture_resolver())
            .load_toml_at(
                &fs::read_to_string(fixture).unwrap(),
                Some(ConfigOrigin::virtual_path(format!(
                    "../testdata/config/{}",
                    request.config_fixture
                ))),
            )
            .unwrap();
    }
    if !request.config_entry.is_empty() {
        let mut resolver = VirtualResolver::new();
        for file in &request.config_files {
            resolver.insert(&file.path, go_string(&decode_base64(&file.content_base64)));
        }
        return ConfigLoader::new()
            .with_resolver(resolver)
            .load_resolved(&request.config_entry)
            .unwrap();
    }
    ConfigLoader::new()
        .load_toml(&go_string(&decode_base64(&request.config_base64)))
        .unwrap()
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../compat/fixtures/upstream/testdata/config")
}

fn fixture_resolver() -> VirtualResolver {
    let root = fixture_root();
    let mut resolver = VirtualResolver::new();
    let mut directories = vec![root.clone()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                directories.push(entry.path());
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let contents = fs::read_to_string(entry.path()).unwrap();
            resolver.insert(&relative, &contents);
            resolver.insert(format!("../testdata/config/{relative}"), contents);
        }
    }
    resolver
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../compat/allowlist-corpus")
}

fn go_string(bytes: &[u8]) -> String {
    let mut output = String::new();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                output.push_str(valid);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                output.push_str(std::str::from_utf8(&remaining[..valid]).unwrap());
                output.push('\u{fffd}');
                remaining = &remaining[valid + 1..];
            }
        }
    }
    output
}
