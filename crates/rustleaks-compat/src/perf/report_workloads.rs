//! Session classification, report-byte and configuration-compile workloads.
//!
//! Expected dispositions, bytes and counts come from generators written from the
//! documented suppression order and report layouts, never from their output.

use std::error::Error;
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Finding, Location};
use rustleaks_core::session::{Baseline, IgnoreSet, SessionPolicy, SuppressionReason};
use rustleaks_report::{CsvReporter, JsonReporter, JunitReporter, Reporter};
use serde_json::json;

use super::{FNV_OFFSET, Phase, elapsed, fingerprint, fnv_extend, phase};

const SESSION_FINDINGS: usize = 10_000;
const REPORT_FINDINGS: usize = 10_000;
const ESCAPE_FINDINGS: usize = 1_000;
// 4,096 sixteen-byte units form each 64 KiB `Match` value.
const ESCAPE_UNITS: usize = 4_096;
const HEAVY_ALLOWLISTS: usize = 500;
const DEFAULT_RULES: usize = 222;
const DEFAULT_ALLOWLISTS: usize = 1;

pub(super) const WORKLOADS: &[&str] = &[
    "session-classify-baseline-10000x10000",
    "serialize-json-escape-heavy",
    "serialize-csv-10000",
    "serialize-junit-10000",
    "config-compile-extend-default",
    "config-compile-allowlist-heavy",
];

pub(super) fn run(id: &str, iterations: usize) -> Result<Vec<Phase>, Box<dyn Error>> {
    match id {
        "session-classify-baseline-10000x10000" => run_session(SESSION_FINDINGS, iterations),
        "serialize-json-escape-heavy" => {
            let fixture = escape_fixture(ESCAPE_FINDINGS, ESCAPE_UNITS)?;
            let mut result = serialize(
                &JsonReporter,
                &fixture.findings,
                &fixture.expected,
                b"go-json-escape-heavy",
                iterations,
            )?;
            result.counts["expected_output_bytes_from_classes"] = json!(fixture.expected_length);
            Ok(vec![result])
        }
        "serialize-csv-10000" => Ok(vec![serialize(
            &CsvReporter,
            &super::super::report_findings()?,
            &csv_expected(REPORT_FINDINGS),
            b"csv-10000",
            iterations,
        )?]),
        "serialize-junit-10000" => Ok(vec![serialize(
            &JunitReporter,
            &super::super::report_findings()?,
            &junit_expected(REPORT_FINDINGS),
            b"junit-10000",
            iterations,
        )?]),
        "config-compile-extend-default" => run_config(
            &extend_default_config(),
            DEFAULT_RULES + 1,
            DEFAULT_ALLOWLISTS,
            "synthetic-extend-token",
            iterations,
        ),
        "config-compile-allowlist-heavy" => run_config(
            &allowlist_heavy_config(None),
            DEFAULT_RULES,
            HEAVY_ALLOWLISTS + DEFAULT_ALLOWLISTS,
            "generic-api-key",
            iterations,
        ),
        _ => Err(format!("unknown report workload {id}").into()),
    }
}

struct SessionFixture {
    findings: Vec<Finding>,
    policy: SessionPolicy,
    ignore_text: String,
    expected: Vec<(Option<SuppressionReason>, String)>,
    baseline_suppressions: usize,
    global_ignores: usize,
    commit_ignores: usize,
    accepted: usize,
}

fn session_file(index: usize) -> String {
    format!("src/file-{index:05}.txt")
}

fn session_commit(index: usize) -> String {
    format!("{:040x}", index + 1)
}

fn session_finding(index: usize, start_line: usize) -> Result<Finding, Box<dyn Error>> {
    Ok(Finding::builder()
        .rule_id("token")
        .description("token")
        .location(Location::new(start_line, index + 3, 1, 22)?)
        .line("token=ABCDEFGHIJKLMNOP")
        .match_text("token=ABCDEFGHIJKLMNOP")
        .secret("ABCDEFGHIJKLMNOP")
        .file(session_file(index))
        .commit(session_commit(index))
        .entropy(4.0)
        .build()?)
}

/// Partitions findings across the three suppression stages and acceptance.
///
/// Half are exact baseline entries. The other half appear in the baseline only
/// as near-misses differing in `start_line`. Of those, one fifth of all findings
/// are global-ignored and three twentieths commit-ignored, and the remainder
/// survive. The ignore stages run before the baseline stage.
fn session_fixture(count: usize) -> Result<SessionFixture, Box<dyn Error>> {
    let baseline_hits = count / 2;
    let global_ignores = count / 5;
    let commit_ignores = count * 3 / 20;
    let global_start = baseline_hits;
    let commit_start = global_start + global_ignores;
    let accepted_start = commit_start + commit_ignores;
    if commit_ignores == 0 || accepted_start >= count {
        return Err("session fixture needs every disposition".into());
    }
    let findings = (0..count)
        .map(|index| session_finding(index, index + 2))
        .collect::<Result<Vec<_>, _>>()?;
    let mut entries = Vec::with_capacity(count);
    for (index, finding) in findings.iter().enumerate() {
        entries.push(if index < baseline_hits {
            finding.clone()
        } else {
            // Still ends on the finding's line, so only `start_line` differs.
            session_finding(index, index + 1)?
        });
    }
    let baseline = Baseline::from_findings(&entries);

    let mut ignore_text = String::new();
    for index in global_start..commit_start {
        writeln!(ignore_text, "{}:token:{}", session_file(index), index + 2)?;
    }
    for index in commit_start..accepted_start {
        writeln!(
            ignore_text,
            "{}:{}:token:{}",
            session_commit(index),
            session_file(index),
            index + 2
        )?;
    }
    // Decoys bring the set to one entry per finding without matching any.
    for decoy in 0..count - global_ignores - commit_ignores {
        if decoy % 2 == 0 {
            writeln!(ignore_text, "decoy/file-{decoy:05}.txt:token:1")?;
        } else {
            writeln!(
                ignore_text,
                "{:040x}:decoy/file-{decoy:05}.txt:token:1",
                count + decoy
            )?;
        }
    }
    let parsed = IgnoreSet::parse_go_compatible(ignore_text.as_bytes());
    if !parsed.issues.is_empty() || parsed.ignores.len() != count {
        return Err("session ignore set must parse to one entry per finding".into());
    }

    let expected = (0..count)
        .map(|index| {
            let reason = if index < baseline_hits {
                Some(SuppressionReason::Baseline)
            } else if index < commit_start {
                Some(SuppressionReason::GlobalIgnore)
            } else if index < accepted_start {
                Some(SuppressionReason::CommitIgnore)
            } else {
                None
            };
            let qualified = format!(
                "{}:{}:token:{}",
                session_commit(index),
                session_file(index),
                index + 2
            );
            (reason, qualified)
        })
        .collect();
    Ok(SessionFixture {
        findings,
        policy: SessionPolicy::builder()
            .ignores(parsed.ignores)
            .baseline(baseline)
            .build(),
        ignore_text,
        expected,
        baseline_suppressions: baseline_hits,
        global_ignores,
        commit_ignores,
        accepted: count - accepted_start,
    })
}

fn reason_code(reason: Option<SuppressionReason>) -> u8 {
    match reason {
        None => 0,
        Some(SuppressionReason::GlobalIgnore) => 1,
        Some(SuppressionReason::CommitIgnore) => 2,
        Some(SuppressionReason::Baseline) => 3,
    }
}

fn run_session(count: usize, iterations: usize) -> Result<Vec<Phase>, Box<dyn Error>> {
    let fixture = session_fixture(count)?;
    let mut result = phase(
        "session-classify",
        iterations,
        0,
        count as u64,
        "findings",
        &super::super::findings_fingerprint(&fixture.findings).to_le_bytes(),
        fixture.ignore_text.as_bytes(),
    );
    for _ in 0..iterations {
        // Cloning inputs and retaining classified results stay outside the timer.
        let inputs = fixture.findings.clone();
        let mut classified = Vec::with_capacity(count);
        let start = Instant::now();
        for finding in inputs {
            classified.push(black_box(fixture.policy.classify(black_box(finding))));
        }
        black_box(&classified);
        result.elapsed_ns += elapsed(start)?;

        let mut hash = FNV_OFFSET;
        for (index, (item, (reason, fingerprint))) in
            classified.iter().zip(&fixture.expected).enumerate()
        {
            let outcome = item.outcome();
            if outcome.suppression_reason() != *reason
                || outcome.fingerprint().as_bytes() != fingerprint.as_bytes()
            {
                return Err(format!("session disposition of finding {index} differs").into());
            }
            hash = fnv_extend(hash, &[reason_code(*reason)]);
            hash = fnv_extend(hash, fingerprint.as_bytes());
        }
        let observed = |kind| {
            classified
                .iter()
                .filter(|item| item.outcome().suppression_reason() == kind)
                .count()
        };
        if observed(Some(SuppressionReason::Baseline)) != fixture.baseline_suppressions
            || observed(Some(SuppressionReason::GlobalIgnore)) != fixture.global_ignores
            || observed(Some(SuppressionReason::CommitIgnore)) != fixture.commit_ignores
            || observed(None) != fixture.accepted
        {
            return Err("session disposition counts differ".into());
        }
        result.outcome_fnv1a64 = format!("{hash:016x}");
    }
    result.findings = count as u64;
    result.counts["baseline_suppressions"] = json!(fixture.baseline_suppressions);
    result.counts["global_ignores"] = json!(fixture.global_ignores);
    result.counts["commit_ignores"] = json!(fixture.commit_ignores);
    result.counts["accepted"] = json!(fixture.accepted);
    result.counts["baseline_entries"] = json!(count);
    result.counts["ignore_entries"] = json!(count);
    Ok(vec![result])
}

// One sixteen-byte unit covers every escape class in `go_json::write_string_body`.
const ESCAPE_UNIT: [u8; 16] = [
    b'<', b'>', b'&', b'"', 0x01, 0x1f, b'\n', b'\t', 0xff, 0xc0, 0xe2, 0x80, 0xa8, b'A', b'B',
    b'C',
];
const ESCAPED_UNIT: &[u8] = br#"\u003c\u003e\u0026\"\u0001\u001f\n\t\ufffd\ufffd\u2028ABC"#;
// Raw length and escaped length of each class, in unit order: `<`, `>`, `&` and
// other low controls become six-byte escapes; `"`, newline and tab take two;
// each invalid byte becomes a six-byte `\ufffd`; U+2028 is three source bytes
// and six escaped bytes; plain ASCII is copied.
const ESCAPE_CLASSES: [(usize, usize); 14] = [
    (1, 6),
    (1, 6),
    (1, 6),
    (1, 2),
    (1, 6),
    (1, 6),
    (1, 2),
    (1, 2),
    (1, 6),
    (1, 6),
    (3, 6),
    (1, 1),
    (1, 1),
    (1, 1),
];

struct EscapeFixture {
    findings: Vec<Finding>,
    expected: Vec<u8>,
    expected_length: usize,
}

/// Builds the report's exact Go JSON text without calling its writer.
fn escape_fixture(findings: usize, units: usize) -> Result<EscapeFixture, Box<dyn Error>> {
    let raw_unit: usize = ESCAPE_CLASSES.iter().map(|(raw, _)| raw).sum();
    let escaped_unit: usize = ESCAPE_CLASSES.iter().map(|(_, escaped)| escaped).sum();
    if raw_unit != ESCAPE_UNIT.len() || escaped_unit != ESCAPED_UNIT.len() {
        return Err("escape classes disagree with the fixture unit".into());
    }
    let value = ESCAPE_UNIT.repeat(units);
    let escaped_match = ESCAPED_UNIT.repeat(units);
    let mut records = Vec::with_capacity(findings);
    let mut expected = Vec::with_capacity(findings * (escaped_match.len() + 512));
    expected.extend_from_slice(b"[\n");
    let mut expected_length = b"[\n".len() + b"]\n".len();
    for index in 0..findings {
        let line = index + 1;
        let file = format!("src/file-{index:05}.txt");
        let identity = format!("{file}:token:{line}");
        records.push(
            Finding::builder()
                .rule_id("token")
                .description("token")
                .location(Location::new(line, line, 1, 22)?)
                .line("synthetic")
                .match_text(value.clone())
                .secret("ABCDEFGHIJKLMNOP")
                .file(file.as_str())
                .entropy(4.0)
                .fingerprint(identity.as_str())
                .build()?,
        );
        let head = format!(
            " {{\n  \"RuleID\": \"token\",\n  \"Description\": \"token\",\n  \"StartLine\": {line},\n  \"EndLine\": {line},\n  \"StartColumn\": 1,\n  \"EndColumn\": 22,\n  \"Match\": \""
        );
        let tail = format!(
            "\",\n  \"Secret\": \"ABCDEFGHIJKLMNOP\",\n  \"File\": \"{file}\",\n  \"SymlinkFile\": \"\",\n  \"Commit\": \"\",\n  \"Entropy\": 4,\n  \"Author\": \"\",\n  \"Email\": \"\",\n  \"Date\": \"\",\n  \"Message\": \"\",\n  \"Tags\": [],\n  \"Fingerprint\": \"{identity}\"\n }}"
        );
        expected.extend_from_slice(head.as_bytes());
        expected.extend_from_slice(&escaped_match);
        expected.extend_from_slice(tail.as_bytes());
        expected_length += head.len() + units * escaped_unit + tail.len();
        if index + 1 != findings {
            expected.push(b',');
            expected_length += 1;
        }
        expected.push(b'\n');
        expected_length += 1;
    }
    expected.extend_from_slice(b"]\n");
    if expected.len() != expected_length {
        return Err("escape-class length disagrees with the generated report".into());
    }
    Ok(EscapeFixture {
        findings: records,
        expected,
        expected_length,
    })
}

fn csv_expected(count: usize) -> Vec<u8> {
    let mut output = String::from(
        "RuleID,Commit,File,SymlinkFile,Secret,Match,StartLine,EndLine,StartColumn,EndColumn,Author,Message,Date,Email,Fingerprint,Tags\n",
    );
    for index in 0..count {
        let line = index + 1;
        let file = format!("src/file-{index:05}.txt");
        writeln!(
            output,
            "token,,{file},,ABCDEFGHIJKLMNOP,token=ABCDEFGHIJKLMNOP,{line},{line},1,22,,,,,{file}:token:{line},benchmark json"
        )
        .expect("writing to a String cannot fail");
    }
    output.into_bytes()
}

fn xml_escape_json(text: &str) -> String {
    text.replace('"', "&#34;")
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
}

fn junit_expected(count: usize) -> Vec<u8> {
    let mut output = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n\t<testsuite failures=\"{count}\" name=\"gitleaks\" tests=\"{count}\" time=\"\">\n"
    );
    for index in 0..count {
        let line = index + 1;
        let file = format!("src/file-{index:05}.txt");
        let message = format!("token has detected a secret in file {file}, line {line}.");
        let json = format!(
            "{{\n\t\"RuleID\": \"token\",\n\t\"Description\": \"token\",\n\t\"StartLine\": {line},\n\t\"EndLine\": {line},\n\t\"StartColumn\": 1,\n\t\"EndColumn\": 22,\n\t\"Match\": \"token=ABCDEFGHIJKLMNOP\",\n\t\"Secret\": \"ABCDEFGHIJKLMNOP\",\n\t\"File\": \"{file}\",\n\t\"SymlinkFile\": \"\",\n\t\"Commit\": \"\",\n\t\"Entropy\": 4,\n\t\"Author\": \"\",\n\t\"Email\": \"\",\n\t\"Date\": \"\",\n\t\"Message\": \"\",\n\t\"Tags\": [\n\t\t\"benchmark\",\n\t\t\"json\"\n\t],\n\t\"Fingerprint\": \"{file}:token:{line}\"\n}}"
        );
        let json = xml_escape_json(&json);
        write!(
            output,
            "\t\t<testcase classname=\"token\" file=\"{file}\" name=\"{message}\" time=\"\">\n\t\t\t<failure message=\"{message}\" type=\"token\">{json}</failure>\n\t\t</testcase>\n"
        )
        .expect("writing to a String cannot fail");
    }
    output.push_str("\t</testsuite>\n</testsuites>");
    output.into_bytes()
}

fn serialize(
    reporter: &dyn Reporter,
    findings: &[Finding],
    expected: &[u8],
    config: &[u8],
    iterations: usize,
) -> Result<Phase, Box<dyn Error>> {
    let mut result = phase(
        "report-serialization",
        iterations,
        0,
        findings.len() as u64,
        "findings",
        &super::super::findings_fingerprint(findings).to_le_bytes(),
        config,
    );
    for _ in 0..iterations {
        // The exact capacity keeps buffer growth out of the serialization timer.
        let mut output = Vec::with_capacity(expected.len());
        let start = Instant::now();
        reporter.write(black_box(&mut output), black_box(findings))?;
        black_box(&output);
        result.elapsed_ns += elapsed(start)?;
        if output != expected {
            let mismatch = output
                .iter()
                .zip(expected)
                .position(|(observed, expected)| observed != expected)
                .unwrap_or_else(|| output.len().min(expected.len()));
            return Err(format!(
                "report differs from independent bytes at offset {mismatch} ({} observed, {} expected)",
                output.len(),
                expected.len()
            )
            .into());
        }
        result.outcome_fnv1a64 = fingerprint(&output);
    }
    result.findings = findings.len() as u64;
    result.counts["output_bytes"] = json!(expected.len());
    result.counts["independent_fnv1a64"] = json!(fingerprint(expected));
    Ok(result)
}

fn extend_default_config() -> String {
    "[extend]\nuseDefault = true\n\n[[rules]]\nid = \"synthetic-extend-token\"\ndescription = \"synthetic extension rule\"\nregex = '''synthetic-extend-token=([A-Z0-9]{16})'''\nsecretGroup = 1\nkeywords = [\"synthetic-extend-token\"]\n".to_owned()
}

/// Declares one allowlist per pattern so each compiles individually.
fn allowlist_heavy_config(replacement: Option<(usize, &str)>) -> String {
    let mut config = String::from("[extend]\nuseDefault = true\n");
    for index in 0..HEAVY_ALLOWLISTS {
        let pattern = match replacement {
            Some((target, pattern)) if target == index => pattern.to_owned(),
            _ => format!("synthetic-allow-{index:04}-[a-z]{{4,8}}"),
        };
        write!(config, "\n[[allowlists]]\nregexes = ['''{pattern}''']\n")
            .expect("writing to a String cannot fail");
    }
    config
}

fn run_config(
    text: &str,
    expected_rules: usize,
    expected_allowlists: usize,
    required_rule: &str,
    iterations: usize,
) -> Result<Vec<Phase>, Box<dyn Error>> {
    let mut result = phase(
        "config-compile",
        iterations,
        0,
        text.len() as u64,
        "config-bytes",
        text.as_bytes(),
        text.as_bytes(),
    );
    for _ in 0..iterations {
        let start = Instant::now();
        let config = black_box(ConfigLoader::new().load_toml(black_box(text))?);
        result.elapsed_ns += elapsed(start)?;
        if config.rules().len() != expected_rules
            || config.allowlists().len() != expected_allowlists
            || config.rule(required_rule).is_none()
        {
            return Err(format!(
                "compiled configuration counts differ: expected {expected_rules} rules and {expected_allowlists} allowlists, observed {} and {}",
                config.rules().len(),
                config.allowlists().len()
            )
            .into());
        }
        result.outcome_fnv1a64 = fingerprint(config.ordered_rule_ids().join("\0").as_bytes());
    }
    result.counts["rules"] = json!(expected_rules);
    result.counts["allowlists"] = json!(expected_allowlists);
    Ok(vec![result])
}

#[cfg(test)]
mod tests {
    use rustleaks_core::config::ConfigError;

    use super::*;

    const BAD_ALLOWLIST_INDEX: usize = 137;
    const BAD_ALLOWLIST_PATTERN: &str = "[syntheticallowunterminated";

    #[test]
    fn session_control_counts_every_disposition_and_rejects_changes() {
        let phases = run_session(40, 1).unwrap();
        assert_eq!(phases.len(), 1);
        assert_eq!(phases[0].counts["baseline_suppressions"], 20);
        assert_eq!(phases[0].counts["global_ignores"], 8);
        assert_eq!(phases[0].counts["commit_ignores"], 6);
        assert_eq!(phases[0].counts["accepted"], 6);

        let fixture = session_fixture(40).unwrap();
        let no_baseline = SessionPolicy::builder()
            .ignores(IgnoreSet::parse_go_compatible(fixture.ignore_text.as_bytes()).ignores)
            .build();
        let outcome = no_baseline
            .classify(fixture.findings[0].clone())
            .into_parts()
            .1;
        assert_eq!(outcome.suppression_reason(), None);
        assert_eq!(
            fixture.expected[0].0,
            Some(SuppressionReason::Baseline),
            "the fixture must rely on its baseline entry"
        );
    }

    #[test]
    fn near_miss_baseline_entries_do_not_suppress() {
        let near_miss = session_finding(5, 6).unwrap();
        let baseline = Baseline::from_findings(std::slice::from_ref(&near_miss));
        let policy = SessionPolicy::builder().baseline(baseline).build();
        let finding = session_finding(5, 7).unwrap();
        assert_eq!(
            policy
                .classify(finding.clone())
                .outcome()
                .suppression_reason(),
            None
        );
        let exact = SessionPolicy::builder()
            .baseline(Baseline::from_findings(std::slice::from_ref(&finding)))
            .build();
        assert_eq!(
            exact.classify(finding).outcome().suppression_reason(),
            Some(SuppressionReason::Baseline)
        );
    }

    #[test]
    fn escape_classes_expand_to_exact_report_bytes() {
        assert_eq!(
            ESCAPE_CLASSES
                .iter()
                .map(|(_, escaped)| escaped)
                .sum::<usize>(),
            57
        );
        let fixture = escape_fixture(3, 8).unwrap();
        serialize(
            &JsonReporter,
            &fixture.findings,
            &fixture.expected,
            b"control",
            1,
        )
        .unwrap();
        let mut changed = fixture.expected.clone();
        changed[100] ^= 1;
        assert!(serialize(&JsonReporter, &fixture.findings, &changed, b"control", 1).is_err());
    }

    #[test]
    fn csv_and_junit_match_independent_bytes() {
        for id in ["serialize-csv-10000", "serialize-junit-10000"] {
            let phases = run(id, 1).unwrap_or_else(|error| panic!("{id}: {error}"));
            assert_eq!(phases[0].findings, 10_000);
        }
    }

    #[test]
    fn configuration_controls_report_exact_counts() {
        let extended = run("config-compile-extend-default", 1).unwrap();
        assert_eq!(extended[0].counts["rules"], DEFAULT_RULES + 1);
        assert_eq!(extended[0].counts["allowlists"], DEFAULT_ALLOWLISTS);
        let heavy = run("config-compile-allowlist-heavy", 1).unwrap();
        assert_eq!(heavy[0].counts["rules"], DEFAULT_RULES);
        assert_eq!(heavy[0].counts["allowlists"], HEAVY_ALLOWLISTS + 1);
    }

    #[test]
    fn injected_bad_pattern_has_an_exact_error_identity() {
        let text = allowlist_heavy_config(Some((BAD_ALLOWLIST_INDEX, BAD_ALLOWLIST_PATTERN)));
        let error = ConfigLoader::new().load_toml(&text).unwrap_err();
        let ConfigError::InvalidPattern {
            scope,
            field,
            pattern,
            message,
        } = error
        else {
            panic!("expected an invalid-pattern error");
        };
        assert_eq!(scope, "[[allowlists]]");
        assert_eq!(field, "regex");
        assert_eq!(pattern, BAD_ALLOWLIST_PATTERN);
        // The class parser reports its opening byte when no terminator exists.
        assert_eq!(
            message,
            "regexp syntax error at byte 0: unclosed character class"
        );
    }
}
