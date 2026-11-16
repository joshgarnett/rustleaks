//! Reviewed presentation dispositions for the frozen CLI corpus replay.
//!
//! The frozen CLI corpus pins every observed field exactly. A presentation
//! disposition lets one reviewed help, usage or message text replace one
//! frozen presentation field of one corpus variant. Exit status, findings,
//! reports, error class, severity, child cleanup and disclosure stay exact.
//! Behavior supersessions record how a frozen behavior matrix guarantee
//! changed scope without editing the matrix.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::ops::Range;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;

use super::support::sha256_bytes;

/// Repository path of the reviewed presentation ledger.
pub(crate) const LEDGER_PATH: &str = "compat/presentation-dispositions.toml";

/// Synthetic inline configuration marker that CLI output must never disclose.
pub(crate) const DISCLOSURE_MARKER: &str = "CLI_CORPUS_DISCLOSURE_MARKER_8F20C3";

/// Observation fields that carry functional behavior and never take a
/// presentation disposition.
const FUNCTIONAL_FIELDS: &[&str] = &[
    "exit",
    "findings",
    "finding_count",
    "report",
    "child_reaped",
    "stderr_contains_disclosure_marker",
    "implementation",
    "stderr_event_severity",
    "stderr_event_class",
    "stderr_event_fields",
];

/// Variants whose first stderr event is replaced with the current build version.
const BUILD_VERSION_FIRST_EVENT: &[&str] = &[
    "CLI-BB-007/file-embedded",
    "CLI-BB-007/directory-embedded-empty",
];

/// Variants whose replay uses a native Windows expectation instead of the
/// frozen observation. Their event layout differs by platform, so they take
/// no presentation disposition.
pub(crate) const NATIVE_EXPECTATION_VARIANTS: &[&str] = &[
    "CLI-BB-013/outside-baseline",
    "CLI-BB-030/corrupt-archive-and-broken-symlink",
];

/// One presentation field of a CLI corpus observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Field {
    /// Normalized standard output bytes.
    Stdout,
    /// Normalized parser usage block on standard error, including the stderr
    /// events produced by its lines.
    StderrUsage,
    /// Normalized message of one frozen stderr event, by zero-based index.
    StderrEventMessage(usize),
}

/// A reviewed replacement of one frozen presentation field.
#[derive(Clone, Debug)]
pub(crate) struct Disposition {
    pub(crate) id: String,
    pub(crate) variant: String,
    pub(crate) field: Field,
    pub(crate) frozen_sha256: String,
    pub(crate) expected: String,
    pub(crate) reason: String,
}

/// A recorded change of scope for one frozen behavior matrix row.
#[derive(Clone, Debug)]
pub(crate) struct Supersession {
    pub(crate) behavior: String,
    pub(crate) historical_status: String,
    pub(crate) status: String,
    pub(crate) statement: String,
}

/// The parsed presentation ledger.
#[derive(Debug)]
pub(crate) struct Ledger {
    pub(crate) dispositions: Vec<Disposition>,
    pub(crate) supersessions: Vec<Supersession>,
}

/// Frozen facts about one CLI corpus variant that dispositions depend on.
pub(crate) struct FrozenVariant {
    /// True when the request prints help on stdout and nothing else.
    pub(crate) help_stdout: bool,
    pub(crate) observation: Value,
}

/// Validates the repository ledger and prints its counts.
pub(crate) fn check_ledger(root: &Path) -> Result<(), String> {
    let ledger = load_ledger(root)?;
    println!(
        "presentation ledger: {} dispositions, {} behavior supersessions",
        ledger.dispositions.len(),
        ledger.supersessions.len()
    );
    Ok(())
}

/// Reads, parses and validates the repository ledger against the frozen CLI
/// corpus and the frozen behavior matrix.
pub(crate) fn load_ledger(root: &Path) -> Result<Ledger, String> {
    let ledger = parse_ledger(&read_text(&root.join(LEDGER_PATH))?)?;
    let corpus = root.join("compat/cli-corpus");
    let variants = frozen_variants(
        &read_text(&corpus.join("requests-v1.jsonl"))?,
        &read_text(&corpus.join("outcomes-v1.jsonl"))?,
    )?;
    validate_dispositions(&ledger.dispositions, &variants)?;
    let matrix = behavior_statuses(&read_text(&root.join("compat/behavior-matrix.toml"))?)?;
    validate_supersessions(&ledger.supersessions, &matrix)?;
    Ok(ledger)
}

/// Parses ledger TOML and rejects unknown keys and malformed entries.
pub(crate) fn parse_ledger(text: &str) -> Result<Ledger, String> {
    let document: toml::Table =
        toml::from_str(text).map_err(|error| format!("cannot parse {LEDGER_PATH}: {error}"))?;
    only_keys(
        &document,
        &[
            "schema_version",
            "presentation_disposition",
            "behavior_supersession",
        ],
        "presentation ledger",
    )?;
    if document
        .get("schema_version")
        .and_then(toml::Value::as_integer)
        != Some(1)
    {
        return Err("presentation ledger schema_version must be 1".into());
    }
    let dispositions = entries(&document, "presentation_disposition")?
        .into_iter()
        .map(parse_disposition)
        .collect::<Result<Vec<_>, _>>()?;
    let supersessions = entries(&document, "behavior_supersession")?
        .into_iter()
        .map(parse_supersession)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Ledger {
        dispositions,
        supersessions,
    })
}

fn entries<'a>(document: &'a toml::Table, key: &str) -> Result<Vec<&'a toml::Table>, String> {
    let Some(value) = document.get(key) else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .ok_or_else(|| format!("{key} must be an array of tables"))?
        .iter()
        .map(|entry| {
            entry
                .as_table()
                .ok_or_else(|| format!("{key} must be an array of tables"))
        })
        .collect()
}

fn parse_disposition(entry: &toml::Table) -> Result<Disposition, String> {
    let id = string(entry, "id", "presentation disposition")?;
    let label = format!("presentation disposition {id}");
    only_keys(
        entry,
        &[
            "id",
            "variant",
            "field",
            "event",
            "frozen_sha256",
            "expected",
            "reason",
        ],
        &label,
    )?;
    let name = string(entry, "field", &label)?;
    let event = entry.get("event");
    let field = match name.as_str() {
        "stdout" => Field::Stdout,
        "stderr_usage" => Field::StderrUsage,
        "stderr_event_message" => {
            let index = event
                .and_then(toml::Value::as_integer)
                .and_then(|index| usize::try_from(index).ok())
                .ok_or_else(|| format!("{label}: event must be a non-negative integer"))?;
            Field::StderrEventMessage(index)
        }
        functional if FUNCTIONAL_FIELDS.contains(&functional) => {
            return Err(format!(
                "{label}: {functional} is functional behavior and cannot take a presentation disposition"
            ));
        }
        other => return Err(format!("{label}: unknown presentation field {other}")),
    };
    if event.is_some() && !matches!(field, Field::StderrEventMessage(_)) {
        return Err(format!(
            "{label}: event is only valid for stderr_event_message"
        ));
    }
    let disposition = Disposition {
        variant: string(entry, "variant", &label)?,
        field,
        frozen_sha256: string(entry, "frozen_sha256", &label)?,
        expected: string(entry, "expected", &label)?,
        reason: string(entry, "reason", &label)?,
        id,
    };
    if disposition.reason.trim().is_empty() {
        return Err(format!("{label}: reason is empty"));
    }
    if disposition.expected.contains(DISCLOSURE_MARKER) {
        return Err(format!(
            "{label}: expected text contains the disclosure marker"
        ));
    }
    Ok(disposition)
}

fn parse_supersession(entry: &toml::Table) -> Result<Supersession, String> {
    let behavior = string(entry, "behavior", "behavior supersession")?;
    let label = format!("behavior supersession {behavior}");
    only_keys(
        entry,
        &["behavior", "historical_status", "status", "statement"],
        &label,
    )?;
    let supersession = Supersession {
        historical_status: string(entry, "historical_status", &label)?,
        status: string(entry, "status", &label)?,
        statement: string(entry, "statement", &label)?,
        behavior,
    };
    if !matches!(supersession.status.as_str(), "superseded" | "narrowed") {
        return Err(format!(
            "{label}: status must be superseded or narrowed, not {}",
            supersession.status
        ));
    }
    if supersession.statement.trim().is_empty() {
        return Err(format!("{label}: statement is empty"));
    }
    Ok(supersession)
}

/// Checks dispositions against the frozen corpus variants they replace.
pub(crate) fn validate_dispositions(
    dispositions: &[Disposition],
    variants: &BTreeMap<String, FrozenVariant>,
) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for disposition in dispositions {
        let label = format!("presentation disposition {}", disposition.id);
        if !ids.insert(disposition.id.as_str()) {
            return Err(format!("{label}: duplicate id"));
        }
        if !targets.insert((disposition.variant.as_str(), field_key(disposition.field))) {
            return Err(format!(
                "{label}: duplicate disposition for the same variant field"
            ));
        }
        let variant = variants
            .get(&disposition.variant)
            .ok_or_else(|| format!("{label}: unknown variant {}", disposition.variant))?;
        if NATIVE_EXPECTATION_VARIANTS.contains(&disposition.variant.as_str()) {
            return Err(format!(
                "{label}: {} uses a native platform expectation",
                disposition.variant
            ));
        }
        let observation = &variant.observation;
        let frozen = match disposition.field {
            Field::Stdout => {
                // Other stdout carries findings, reports or the build version.
                if !variant.help_stdout {
                    return Err(format!(
                        "{label}: stdout of {} is not help output",
                        disposition.variant
                    ));
                }
                decode(observation, "/stdout_base64", &label)?
            }
            Field::StderrUsage => {
                if observation["stderr_usage"].is_null() {
                    return Err(format!("{label}: frozen variant has no usage block"));
                }
                decode(observation, "/stderr_usage/bytes_base64", &label)?
            }
            Field::StderrEventMessage(index) => {
                let count = observation["stderr_events"].as_array().map_or(0, Vec::len);
                if index >= count {
                    return Err(format!(
                        "{label}: event {index} is outside the {count} frozen events"
                    ));
                }
                if index == 0 && BUILD_VERSION_FIRST_EVENT.contains(&disposition.variant.as_str()) {
                    return Err(format!(
                        "{label}: event 0 carries the build version for {}",
                        disposition.variant
                    ));
                }
                if usage_event_range(observation, &label)?
                    .is_some_and(|range| range.contains(&index))
                {
                    return Err(format!(
                        "{label}: event {index} belongs to the usage block; use stderr_usage"
                    ));
                }
                decode(
                    observation,
                    &format!("/stderr_events/{index}/normalized_message_base64"),
                    &label,
                )?
            }
        };
        if sha256_bytes(&frozen) != disposition.frozen_sha256 {
            return Err(format!(
                "{label}: frozen_sha256 does not match the frozen text"
            ));
        }
        if disposition.expected.as_bytes() == frozen
            || legacy_spelling(&disposition.expected).as_bytes() == frozen
        {
            return Err(format!(
                "{label}: expected text does not change the frozen presentation"
            ));
        }
    }
    Ok(())
}

/// Checks supersessions against frozen behavior matrix statuses by ID.
pub(crate) fn validate_supersessions(
    supersessions: &[Supersession],
    matrix: &BTreeMap<String, String>,
) -> Result<(), String> {
    let mut behaviors = BTreeSet::new();
    for supersession in supersessions {
        let label = format!("behavior supersession {}", supersession.behavior);
        if !behaviors.insert(supersession.behavior.as_str()) {
            return Err(format!("{label}: duplicate behavior"));
        }
        let status = matrix
            .get(&supersession.behavior)
            .ok_or_else(|| format!("{label}: behavior is not in the behavior matrix"))?;
        if *status != supersession.historical_status {
            return Err(format!(
                "{label}: historical_status does not match the behavior matrix"
            ));
        }
    }
    Ok(())
}

/// Returns the range of frozen stderr events produced by the usage block.
///
/// The usage block starts at the first `Usage:` event and has one event per
/// non-blank line of the recorded usage text. Each event message must match
/// its usage line, so a range is only returned when the two records agree.
pub(crate) fn usage_event_range(
    observation: &Value,
    label: &str,
) -> Result<Option<Range<usize>>, String> {
    let usage = &observation["stderr_usage"];
    if usage.is_null() {
        return Ok(None);
    }
    let usage = decode(observation, "/stderr_usage/bytes_base64", label)?;
    let usage = String::from_utf8(usage).map_err(|_| format!("{label}: usage is not UTF-8"))?;
    let lines = usage
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let events = observation["stderr_events"]
        .as_array()
        .ok_or_else(|| format!("{label}: stderr_events is not an array"))?;
    let messages = (0..events.len())
        .map(|index| {
            decode(
                observation,
                &format!("/stderr_events/{index}/normalized_message_base64"),
                label,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let start = messages
        .iter()
        .position(|message| message == b"Usage:")
        .ok_or_else(|| format!("{label}: usage block has no Usage: event"))?;
    let range = start..start + lines.len();
    let block = messages
        .get(range.clone())
        .ok_or_else(|| format!("{label}: usage block exceeds stderr events"))?;
    for (message, line) in block.iter().zip(&lines) {
        if String::from_utf8_lossy(message).replace("Gitleaks", "gitleaks") != *line {
            return Err(format!("{label}: usage block and stderr events disagree"));
        }
    }
    Ok(Some(range))
}

/// Indexes frozen Rust observations and finding sources by variant ID.
pub(crate) fn frozen_variants(
    requests: &str,
    outcomes: &str,
) -> Result<BTreeMap<String, FrozenVariant>, String> {
    let rows = |text: &str, label: &str| {
        text.lines()
            .map(|line| {
                serde_json::from_str::<Value>(line)
                    .map_err(|error| format!("invalid {label} JSON: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()
    };
    let requests = rows(requests, "CLI request")?;
    let outcomes = rows(outcomes, "CLI outcome")?;
    let mut result = BTreeMap::new();
    for (request, outcome) in requests.iter().zip(&outcomes) {
        let case = request["id"].as_str().ok_or("CLI request lacks an id")?;
        let empty = Vec::new();
        let variants = request["variants"].as_array().unwrap_or(&empty);
        let frozen = outcome["variants"].as_array().unwrap_or(&empty);
        for (variant, frozen) in variants.iter().zip(frozen) {
            let id = variant["id"].as_str().ok_or("CLI variant lacks an id")?;
            if frozen["id"] != variant["id"] || outcome["id"] != request["id"] {
                return Err(format!("{case}/{id}: frozen outcome identity differs"));
            }
            result.insert(
                format!("{case}/{id}"),
                FrozenVariant {
                    help_stdout: help_stdout(variant),
                    observation: frozen["rust"].clone(),
                },
            );
        }
    }
    Ok(result)
}

/// Returns true when a request prints only help on stdout: the bare command
/// or an explicit help flag.
pub(crate) fn help_stdout(request: &Value) -> bool {
    request["args"].as_array().is_some_and(|args| {
        args.is_empty()
            || args
                .iter()
                .any(|arg| matches!(arg.as_str(), Some("-h" | "--help")))
    })
}

fn behavior_statuses(text: &str) -> Result<BTreeMap<String, String>, String> {
    let matrix: toml::Table =
        toml::from_str(text).map_err(|error| format!("cannot parse behavior matrix: {error}"))?;
    matrix
        .get("behavior")
        .and_then(toml::Value::as_array)
        .ok_or("behavior matrix has no behavior rows")?
        .iter()
        .map(|row| {
            let field = |name: &str| {
                row.get(name)
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| format!("behavior matrix row lacks {name}"))
            };
            Ok((field("id")?, field("status")?))
        })
        .collect()
}

/// Applies the frozen comparison's executable spelling to native text.
fn legacy_spelling(text: &str) -> String {
    text.replace("rustleaks", "gitleaks")
        .replace("Rustleaks", "Gitleaks")
}

fn field_key(field: Field) -> String {
    match field {
        Field::Stdout => "stdout".into(),
        Field::StderrUsage => "stderr_usage".into(),
        Field::StderrEventMessage(index) => format!("stderr_event_message/{index}"),
    }
}

fn decode(observation: &Value, pointer: &str, label: &str) -> Result<Vec<u8>, String> {
    let encoded = observation
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label}: frozen {pointer} is missing"))?;
    BASE64
        .decode(encoded)
        .map_err(|_| format!("{label}: frozen {pointer} is not base64"))
}

fn only_keys(table: &toml::Table, allowed: &[&str], label: &str) -> Result<(), String> {
    match table.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(key) if FUNCTIONAL_FIELDS.contains(&key.as_str()) => Err(format!(
            "{label}: {key} is functional behavior and cannot take a presentation disposition"
        )),
        Some(key) => Err(format!("{label}: unknown key {key}")),
        None => Ok(()),
    }
}

fn string(table: &toml::Table, key: &str, label: &str) -> Result<String, String> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{label}: {key} must be a string"))
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HELP: &str = "Usage:\n  gitleaks dir [flags]\n";
    const USAGE: &str = "Usage:\n  gitleaks dir [flags]\n\nFlags:\n  -h, --help   help\n";
    const MESSAGE: &str = "synthetic failure in gitleaks";

    fn event(message: &str) -> Value {
        json!({"severity": "error", "class": "diagnostic.other", "fields": {},
            "normalized_message_base64": BASE64.encode(message)})
    }

    fn variants() -> BTreeMap<String, FrozenVariant> {
        let observation = json!({
            "exit": 1,
            "stdout_base64": BASE64.encode(HELP),
            "stderr_usage": {"bytes_base64": BASE64.encode(USAGE)},
            "stderr_events": [
                event(MESSAGE), event("Usage:"), event("gitleaks dir [flags]"),
                event("Flags:"), event("-h, --help   help"), event("final"),
            ],
        });
        let mut result = BTreeMap::new();
        for (id, help_stdout) in [
            ("SYN-1/plain", true),
            ("SYN-1/report-stdout", false),
            ("CLI-BB-007/file-embedded", true),
            ("CLI-BB-013/outside-baseline", true),
        ] {
            result.insert(
                id.to_owned(),
                FrozenVariant {
                    help_stdout,
                    observation: observation.clone(),
                },
            );
        }
        result
    }

    fn entry(variant: &str, field: &str, frozen: &str, expected: &str) -> String {
        format!(
            "[[presentation_disposition]]\nid = \"SYN-PRESENT\"\nvariant = \"{variant}\"\nfield = \"{field}\"\nfrozen_sha256 = \"{}\"\nexpected = {expected:?}\nreason = \"Synthetic review.\"\n",
            sha256_bytes(frozen.as_bytes())
        )
    }

    fn check(body: &str) -> Result<Ledger, String> {
        let ledger = parse_ledger(&format!("schema_version = 1\n{body}"))?;
        validate_dispositions(&ledger.dispositions, &variants())?;
        Ok(ledger)
    }

    #[test]
    fn repository_ledger_loads_with_its_supersessions() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let ledger = load_ledger(&root).unwrap();
        let rows = ledger
            .supersessions
            .iter()
            .map(|row| (row.behavior.as_str(), row.status.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            rows,
            [("CLI-DEFER-001", "superseded"), ("CLI-009", "narrowed")]
        );
    }

    #[test]
    fn valid_dispositions_parse_for_every_presentation_field() {
        let stdout = entry(
            "SYN-1/plain",
            "stdout",
            HELP,
            "Usage:\n  rustleaks dir PATH\n",
        );
        let ledger = check(&stdout).unwrap();
        assert_eq!(ledger.dispositions[0].field, Field::Stdout);
        let usage = entry(
            "SYN-1/plain",
            "stderr_usage",
            USAGE,
            "Usage: rustleaks dir\n",
        );
        assert_eq!(
            check(&usage).unwrap().dispositions[0].field,
            Field::StderrUsage
        );
        let message = format!(
            "{}event = 5\n",
            entry("SYN-1/plain", "stderr_event_message", "final", "done")
        );
        assert_eq!(
            check(&message).unwrap().dispositions[0].field,
            Field::StderrEventMessage(5)
        );
    }

    #[test]
    fn functional_and_unknown_fields_are_rejected() {
        for field in FUNCTIONAL_FIELDS {
            let error = check(&entry("SYN-1/plain", field, HELP, "x")).unwrap_err();
            assert!(error.contains("functional behavior"), "{field}: {error}");
            let extra = format!("{}{field} = 0\n", entry("SYN-1/plain", "stdout", HELP, "x"));
            assert!(check(&extra).unwrap_err().contains("functional behavior"));
        }
        assert!(check(&entry("SYN-1/plain", "stdout_sha256", HELP, "x")).is_err());
        let extra = format!(
            "{}note = \"x\"\n",
            entry("SYN-1/plain", "stdout", HELP, "x")
        );
        assert!(check(&extra).unwrap_err().contains("unknown key"));
        assert!(parse_ledger("schema_version = 2\n").is_err());
        assert!(parse_ledger("schema_version = 1\nextra = true\n").is_err());
    }

    #[test]
    fn malformed_dispositions_are_rejected() {
        let valid = entry("SYN-1/plain", "stdout", HELP, "new help\n");
        check(&valid).unwrap();
        let cases = [
            // Unknown variant.
            entry("SYN-1/missing", "stdout", HELP, "new help\n"),
            // Duplicate ID and duplicate target.
            format!("{valid}{valid}"),
            // Wrong frozen digest.
            entry("SYN-1/plain", "stdout", "other", "new help\n"),
            // Expected text equal to the frozen text, directly or after the
            // legacy executable respelling.
            entry("SYN-1/plain", "stdout", HELP, HELP),
            entry(
                "SYN-1/plain",
                "stdout",
                HELP,
                &HELP.replace("gitleaks", "rustleaks"),
            ),
            // Empty reason.
            valid.replace("Synthetic review.", " "),
            // Disclosure marker in expected text.
            entry("SYN-1/plain", "stdout", HELP, DISCLOSURE_MARKER),
            // Stdout that is not help output.
            entry("SYN-1/report-stdout", "stdout", HELP, "new help\n"),
            // A variant with a native platform expectation.
            entry("CLI-BB-013/outside-baseline", "stdout", HELP, "new help\n"),
            // Event index missing, out of range, inside usage, or build version.
            entry("SYN-1/plain", "stderr_event_message", MESSAGE, "new"),
            format!(
                "{}event = 6\n",
                entry("SYN-1/plain", "stderr_event_message", MESSAGE, "new")
            ),
            format!(
                "{}event = 2\n",
                entry(
                    "SYN-1/plain",
                    "stderr_event_message",
                    "gitleaks dir [flags]",
                    "new"
                )
            ),
            format!(
                "{}event = 0\n",
                entry(
                    "CLI-BB-007/file-embedded",
                    "stderr_event_message",
                    MESSAGE,
                    "new"
                )
            ),
            // Event index on a field without events.
            format!("{valid}event = 0\n"),
        ];
        for body in cases {
            assert!(check(&body).is_err(), "{body}");
        }
    }

    #[test]
    fn supersessions_must_match_the_behavior_matrix() {
        let matrix = BTreeMap::from([("CLI-SYN".to_owned(), "implemented".to_owned())]);
        let row = |behavior: &str, historical: &str, status: &str, statement: &str| {
            format!(
                "schema_version = 1\n[[behavior_supersession]]\nbehavior = \"{behavior}\"\nhistorical_status = \"{historical}\"\nstatus = \"{status}\"\nstatement = \"{statement}\"\n"
            )
        };
        let check = |text: &str| {
            let ledger = parse_ledger(text)?;
            validate_supersessions(&ledger.supersessions, &matrix)
        };
        let valid = row("CLI-SYN", "implemented", "narrowed", "Wording only.");
        check(&valid).unwrap();
        let duplicate = format!(
            "{valid}{}",
            valid.trim_start_matches("schema_version = 1\n")
        );
        for invalid in [
            row("CLI-MISSING", "implemented", "narrowed", "Wording only."),
            row("CLI-SYN", "partial", "narrowed", "Wording only."),
            row("CLI-SYN", "implemented", "retired", "Wording only."),
            row("CLI-SYN", "implemented", "narrowed", " "),
            duplicate,
        ] {
            assert!(check(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn usage_event_range_requires_matching_records() {
        let observation = &variants()["SYN-1/plain"].observation;
        assert_eq!(usage_event_range(observation, "test").unwrap(), Some(1..5));
        let mut changed = observation.clone();
        changed["stderr_events"][3] = event("Options:");
        assert!(usage_event_range(&changed, "test").is_err());
        changed["stderr_events"] = json!([event("Usage:")]);
        assert!(usage_event_range(&changed, "test").is_err());
        changed["stderr_usage"] = Value::Null;
        assert_eq!(usage_event_range(&changed, "test").unwrap(), None);
    }

    #[test]
    fn stdout_dispositions_are_limited_to_help_output() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/cli-corpus");
        let variants = frozen_variants(
            &read_text(&root.join("requests-v1.jsonl")).unwrap(),
            &read_text(&root.join("outcomes-v1.jsonl")).unwrap(),
        )
        .unwrap();
        let help = variants
            .iter()
            .filter(|(_, variant)| variant.help_stdout)
            .map(|(id, _)| id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(help, ["CLI-BB-001/help", "CLI-BB-001/root"]);
        let disposition = |variant: &str| {
            let frozen = &variants[variant].observation;
            let text = decode(frozen, "/stdout_base64", "test").unwrap();
            Disposition {
                id: "SYN-STDOUT".into(),
                variant: variant.into(),
                field: Field::Stdout,
                frozen_sha256: sha256_bytes(&text),
                expected: "synthetic rustleaks help\n".into(),
                reason: "Synthetic review.".into(),
            }
        };
        for variant in help {
            validate_dispositions(&[disposition(variant)], &variants).unwrap();
        }
        for variant in [
            "CLI-BB-021/json",
            "CLI-BB-021/sarif",
            "CLI-BB-021/template",
            "CLI-BB-025/verbose",
            "CLI-BB-025/verbose-stdout-json",
            "CLI-BB-001/version-flag",
        ] {
            let error = validate_dispositions(&[disposition(variant)], &variants).unwrap_err();
            assert!(error.contains("not help output"), "{variant}: {error}");
        }
    }

    #[test]
    fn frozen_usage_blocks_match_their_stderr_events() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/cli-corpus");
        let variants = frozen_variants(
            &read_text(&root.join("requests-v1.jsonl")).unwrap(),
            &read_text(&root.join("outcomes-v1.jsonl")).unwrap(),
        )
        .unwrap();
        let blocks = variants
            .iter()
            .filter_map(|(id, variant)| usage_event_range(&variant.observation, id).unwrap())
            .count();
        assert_eq!(blocks, 8);
    }
}
