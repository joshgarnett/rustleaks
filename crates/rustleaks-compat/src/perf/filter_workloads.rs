//! Allowlist, stopword, capture group, composite rule and finding construction
//! costs at library level.
//!
//! These extend the eight ported Gitleaks allowlist benchmarks with larger
//! allowlists and stopword lists, hit and miss inputs, and adapt Betterleaks
//! benchmark specifications 12 to 14 (capture extraction by group count,
//! component proximity, finding construction and rejection). Every input is
//! generated so the expected findings follow from its construction: a value
//! that contains a stopword or matches an allowlist entry is not reported, and
//! one control value in each rejection case is reported.

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanControl, ScanOutcome};
use serde_json::json;

use super::source_scale_workloads::{FindingKey, key, verify_findings};
use super::suite_support::{Lcg, Result};
use super::{Phase, elapsed, fingerprint, outcome_signature, phase};

pub(super) const WORKLOADS: &[&str] = &[
    "filters-allowlist-build",
    "filters-match",
    "filters-capture-groups",
    "filters-composite-proximity",
    "filters-finding-construction",
];

const RECORDS: usize = 1_000;
/// Values never contain `q` or `z`, so no generated stopword or allowlist
/// pattern can occur in a value by chance.
const VALUE_ALPHABET: &[u8] = b"abcdefgh0123456789";
const FILTER_RULE: &str = "[[rules]]\nid = 'perf-filter'\ndescription = 'filter probe'\nregex = '''token=([a-z0-9]{24})'''\nsecretGroup = 1\nkeywords = ['token']\n";

pub(super) fn run(id: &str, iterations: usize) -> Result<Vec<Phase>> {
    if !(1..=super::MAX_ITERATIONS).contains(&iterations) {
        return Err("filter iterations are outside representative bounds".into());
    }
    match id {
        "filters-allowlist-build" => allowlist_build(iterations),
        "filters-match" => filter_match(iterations),
        "filters-capture-groups" => capture_groups(iterations),
        "filters-composite-proximity" => composite_proximity(iterations),
        "filters-finding-construction" => finding_construction(iterations),
        _ => Err(format!("unknown filter workload {id}").into()),
    }
}

fn stopword(index: usize) -> String {
    format!("qz{index:04}")
}

fn allow_pattern(index: usize) -> String {
    format!("zq{index:04}")
}

fn rule_with_stopwords(count: usize) -> String {
    let mut config = FILTER_RULE.to_owned();
    config.push_str("[[rules.allowlists]]\nstopwords = [");
    for index in 0..count {
        let separator = if index == 0 { "" } else { ", " };
        write!(config, "{separator}'{}'", stopword(index)).expect("writing to a String");
    }
    config.push_str("]\n");
    config
}

fn rule_with_regexes(count: usize) -> String {
    let mut config = FILTER_RULE.to_owned();
    config.push_str("[[rules.allowlists]]\nregexes = [");
    for index in 0..count {
        let separator = if index == 0 { "" } else { ", " };
        write!(config, "{separator}'''{}'''", allow_pattern(index)).expect("writing to a String");
    }
    config.push_str("]\n");
    config
}

fn global_paths(count: usize) -> String {
    let mut config = FILTER_RULE.to_owned();
    config.push_str("[[allowlists]]\npaths = [");
    for index in 0..count {
        let separator = if index == 0 { "" } else { ", " };
        write!(config, "{separator}'''^vendor/pkg{index:04}/'''").expect("writing to a String");
    }
    config.push_str("]\n");
    config
}

/// One hundred rules that share one twenty-entry allowlist, so a compile cache
/// for repeated patterns has work to share.
fn shared_allowlist_rules(rules: usize) -> String {
    let mut config = String::new();
    for rule in 0..rules {
        write!(
            config,
            "[[rules]]\nid = 'perf-shared-{rule:03}'\ndescription = 'shared allowlist'\nregex = '''token{rule:03}=([a-z0-9]{{24}})'''\nsecretGroup = 1\nkeywords = ['token{rule:03}']\n[[rules.allowlists]]\nregexes = ["
        )
        .expect("writing to a String");
        for index in 0..20 {
            let separator = if index == 0 { "" } else { ", " };
            write!(config, "{separator}'''{}'''", allow_pattern(index))
                .expect("writing to a String");
        }
        config.push_str("]\n");
    }
    config
}

/// A value of 24 bytes from `VALUE_ALPHABET`, with `marker` placed at byte 9
/// when given.
fn value(rng: &mut Lcg, marker: Option<&str>) -> Vec<u8> {
    let mut value = rng.string(VALUE_ALPHABET, 24);
    if let Some(marker) = marker {
        value[9..9 + marker.len()].copy_from_slice(marker.as_bytes());
    }
    value
}

/// Lines of `token=<value>`; each value holds `marker(line)` when given.
fn token_lines(marker: Option<&dyn Fn(usize) -> String>) -> (Vec<u8>, Vec<FindingKey>) {
    let mut rng = Lcg::new(0x6669_6c74);
    let mut input = Vec::with_capacity(RECORDS * 31);
    let mut findings = Vec::with_capacity(RECORDS);
    for index in 0..RECORDS {
        let text = marker.map(|marker| marker(index));
        let value = value(&mut rng, text.as_deref());
        let line = index + 1;
        findings.push(key(
            "perf-filter",
            "",
            "",
            line,
            if line == 1 { 1 } else { 2 },
            &value,
        ));
        input.extend_from_slice(b"token=");
        input.extend_from_slice(&value);
        input.push(b'\n');
    }
    findings.sort();
    (input, findings)
}

fn validate(outcome: &ScanOutcome, expected: &[FindingKey]) -> Result<()> {
    if !outcome.is_complete() || outcome.termination().is_some() {
        return Err("filter scan did not complete".into());
    }
    verify_findings(outcome.findings(), expected)?;
    Ok(())
}

/// Times `iterations` scans of one fragment and checks every outcome.
fn scan_phase(
    name: &str,
    iterations: usize,
    engine: &Engine,
    fragment: &Fragment,
    expected: &[FindingKey],
    config: &str,
) -> Result<Phase> {
    let input = fragment.content().as_bytes();
    let options = ScanOptions::builder().max_decode_depth(0).build();
    let mut result = phase(
        name,
        iterations,
        0,
        input.len() as u64,
        "input-bytes",
        input,
        config.as_bytes(),
    );
    for _ in 0..iterations {
        let start = Instant::now();
        let outcome = black_box(engine.scan_fragment_controlled(
            black_box(fragment),
            &options,
            &ScanControl::unlimited(),
        ));
        result.elapsed_ns += elapsed(start)?;
        // Validation and outcome destruction stay outside the timer.
        validate(&outcome, expected)?;
        result.outcome_fnv1a64 = outcome_signature(&outcome);
        result.counts = json!({
            "workers": 1, "decode_depth": 0,
            "work_units": outcome.usage().work_units(),
            "finding_records": outcome.usage().finding_records(),
        });
    }
    result.findings = expected.len() as u64;
    Ok(result)
}

fn engine(config: &str) -> Result<Engine> {
    Ok(Engine::builder(ConfigLoader::new().load_toml(config)?).build()?)
}

fn fragment(input: Vec<u8>, path: Option<&str>) -> Fragment {
    let builder = Fragment::builder(input).start_line(1);
    match path {
        Some(path) => builder.file_path(path.to_owned()).build(),
        None => builder.build(),
    }
}

/// Configuration compile and engine construction with growing allowlists.
/// After each phase a probe outside the timer checks that the last entry
/// rejects a value and that a value without any entry is reported.
fn allowlist_build(iterations: usize) -> Result<Vec<Phase>> {
    let mut cases: Vec<(String, String, String, usize)> = Vec::new();
    for count in [10, 100, 1_000] {
        cases.push((
            format!("compile-regex-allowlist-{count}"),
            rule_with_regexes(count),
            allow_pattern(count - 1),
            1,
        ));
    }
    for count in [10, 100, 1_000] {
        cases.push((
            format!("compile-stopwords-{count}"),
            rule_with_stopwords(count),
            stopword(count - 1),
            1,
        ));
    }
    cases.push((
        "compile-shared-allowlist-100-rules".into(),
        shared_allowlist_rules(100),
        allow_pattern(19),
        100,
    ));
    let mut phases = Vec::new();
    for (name, config, marker, rules) in cases {
        let mut result = phase(
            &name,
            iterations,
            0,
            config.len() as u64,
            "config-bytes",
            config.as_bytes(),
            config.as_bytes(),
        );
        let mut built = None;
        for _ in 0..iterations {
            drop(built.take());
            let start = Instant::now();
            let compiled = black_box(ConfigLoader::new().load_toml(&config)?);
            let engine = black_box(Engine::builder(compiled).build()?);
            result.elapsed_ns += elapsed(start)?;
            built = Some(engine);
        }
        let engine = built.ok_or("allowlist build did not run")?;
        let mut rng = Lcg::new(0x6275_696c);
        let token = if rules == 1 { "token" } else { "token099" };
        let rule = if rules == 1 {
            "perf-filter"
        } else {
            "perf-shared-099"
        };
        let hit = value(&mut rng, Some(&marker));
        let miss = value(&mut rng, None);
        let mut probe = format!("{token}=").into_bytes();
        probe.extend_from_slice(&hit);
        probe.extend_from_slice(format!("\n{token}=").as_bytes());
        probe.extend_from_slice(&miss);
        probe.push(b'\n');
        let outcome = engine.scan_fragment(&fragment(probe, None), &ScanOptions::default());
        validate(&outcome, &[key(rule, "", "", 2, 2, &miss)])?;
        result.outcome_fnv1a64 = fingerprint(name.as_bytes());
        result.counts = json!({"rules": rules, "operation": "config-load-and-engine-build"});
        phases.push(result);
    }
    Ok(phases)
}

/// Stopword, regex allowlist and global path allowlist matching, each with an
/// input where every value is rejected and one where none is.
fn filter_match(iterations: usize) -> Result<Vec<Phase>> {
    let stopwords = rule_with_stopwords(1_000);
    let regexes = rule_with_regexes(100);
    let paths = global_paths(100);
    let stop_marker = |index: usize| stopword(index % 1_000);
    let regex_marker = |index: usize| allow_pattern(index % 100);
    let (stop_hit, _) = token_lines(Some(&stop_marker));
    let (regex_hit, _) = token_lines(Some(&regex_marker));
    let (plain, plain_findings) = token_lines(None);
    let mut phases = Vec::new();
    let stop_engine = engine(&stopwords)?;
    phases.push(scan_phase(
        "stopwords-1000-hit",
        iterations,
        &stop_engine,
        &fragment(stop_hit, None),
        &[],
        &stopwords,
    )?);
    phases.push(scan_phase(
        "stopwords-1000-miss",
        iterations,
        &stop_engine,
        &fragment(plain.clone(), None),
        &plain_findings,
        &stopwords,
    )?);
    let regex_engine = engine(&regexes)?;
    phases.push(scan_phase(
        "regex-allowlist-100-hit",
        iterations,
        &regex_engine,
        &fragment(regex_hit, None),
        &[],
        &regexes,
    )?);
    phases.push(scan_phase(
        "regex-allowlist-100-miss",
        iterations,
        &regex_engine,
        &fragment(plain.clone(), None),
        &plain_findings,
        &regexes,
    )?);
    let path_engine = engine(&paths)?;
    phases.push(scan_phase(
        "path-allowlist-100-hit",
        iterations,
        &path_engine,
        &fragment(plain.clone(), Some("vendor/pkg0099/data.txt")),
        &[],
        &paths,
    )?);
    let miss_findings = plain_findings
        .iter()
        .map(|row| {
            let mut row = row.clone();
            row.file = b"src/app/data.txt".to_vec();
            row
        })
        .collect::<Vec<_>>();
    phases.push(scan_phase(
        "path-allowlist-100-miss",
        iterations,
        &path_engine,
        &fragment(plain, Some("src/app/data.txt")),
        &miss_findings,
        &paths,
    )?);
    Ok(phases)
}

/// `token=secret-NNNNNN account=user-NNNNNN` lines with rules of 0, 1, 2 named
/// and 6 named capture groups (Betterleaks specification 12).
fn capture_groups(iterations: usize) -> Result<Vec<Phase>> {
    let mut input = Vec::with_capacity(RECORDS * 40);
    for index in 0..RECORDS {
        input.extend_from_slice(
            format!("token=secret-{index:06} account=user-{index:06}\n").as_bytes(),
        );
    }
    let cases: [(&str, &str, Option<usize>, bool); 4] = [
        ("groups-0", "token=secret-[0-9]{6}", None, true),
        ("groups-1", "token=(secret-[0-9]{6})", None, false),
        (
            "groups-2-named",
            "token=(?P<secret>secret-[0-9]{6}) account=(?P<account>user-[0-9]{6})",
            Some(1),
            false,
        ),
        (
            "groups-6-named",
            "(?P<key>token)=(?P<secret>secret-(?P<number>[0-9]{6})) (?P<field>account)=(?P<account>user-(?P<id>[0-9]{6}))",
            Some(2),
            false,
        ),
    ];
    let mut phases = Vec::new();
    for (name, regex, group, whole) in cases {
        let mut config = format!(
            "[[rules]]\nid = 'perf-capture'\ndescription = 'capture probe'\nregex = '''{regex}'''\nkeywords = ['token']\n"
        );
        if let Some(group) = group {
            writeln!(config, "secretGroup = {group}")?;
        }
        let mut expected = (0..RECORDS)
            .map(|index| {
                let line = index + 1;
                let secret = if whole {
                    format!("token=secret-{index:06}")
                } else {
                    format!("secret-{index:06}")
                };
                key(
                    "perf-capture",
                    "",
                    "",
                    line,
                    if line == 1 { 1 } else { 2 },
                    secret.as_bytes(),
                )
            })
            .collect::<Vec<_>>();
        expected.sort();
        phases.push(scan_phase(
            name,
            iterations,
            &engine(&config)?,
            &fragment(input.clone(), None),
            &expected,
            &config,
        )?);
    }
    Ok(phases)
}

/// 1, 10 or 40 primary and component pairs followed by lines of 999 dots up to
/// at least 100,000 bytes. Each primary requires the component rule within
/// 100,000 lines, so every primary is reported with every component
/// (Betterleaks specification 13).
fn composite_proximity(iterations: usize) -> Result<Vec<Phase>> {
    const CONFIG: &str = "[[rules]]\nid = 'perf-primary'\ndescription = 'primary'\nregex = '''PRIMARY[0-9]{4}'''\nkeywords = ['primary']\n[[rules.required]]\nid = 'perf-component'\nwithinLines = 100000\n\n[[rules]]\nid = 'perf-component'\ndescription = 'component'\nregex = '''COMPONENT[0-9]{4}'''\nkeywords = ['component']\nskipReport = true\n";
    let engine = engine(CONFIG)?;
    let mut phases = Vec::new();
    for pairs in [1, 10, 40] {
        let mut input = Vec::new();
        let mut expected = Vec::new();
        for index in 0..pairs {
            let line = 2 * index + 1;
            let primary = format!("PRIMARY{index:04}");
            expected.push(key(
                "perf-primary",
                "",
                "",
                line,
                if line == 1 { 1 } else { 2 },
                primary.as_bytes(),
            ));
            input.extend_from_slice(format!("{primary}\nCOMPONENT{index:04}\n").as_bytes());
        }
        while input.len() < 100_000 {
            input.extend_from_slice(&[b'.'; 999]);
            input.push(b'\n');
        }
        expected.sort();
        let fragment = fragment(input, None);
        let phase = scan_phase(
            &format!("pairs-{pairs}"),
            iterations,
            &engine,
            &fragment,
            &expected,
            CONFIG,
        )?;
        let outcome = engine.scan_fragment(&fragment, &ScanOptions::default());
        if outcome
            .findings()
            .iter()
            .any(|finding| finding.required_findings().len() != pairs)
        {
            return Err("composite primary omits a component within range".into());
        }
        phases.push(phase);
    }
    Ok(phases)
}

/// 1,000 records of `token=` with six digits and 88 dots, one per line or all
/// on one line (Betterleaks specification 14). Every rule finds the 1,000
/// candidates. The accepting rule reports all of them. The filtering rule
/// allowlists values that start with 0, so only the last value, 999999, is
/// reported. The composite rule needs `COMPMARK` on the same line within 50
/// columns, which only the last record has.
fn finding_construction(iterations: usize) -> Result<Vec<Phase>> {
    const RULE: &str = "[[rules]]\nid = 'perf-record'\ndescription = 'record'\nregex = '''token=([0-9]{6})'''\nsecretGroup = 1\nkeywords = ['token']\n";
    let accepted = RULE.to_owned();
    let filtered = format!("{RULE}[[rules.allowlists]]\nregexes = ['''^0[0-9]{{5}}$''']\n");
    let missing = format!(
        "{RULE}[[rules.required]]\nid = 'perf-mark'\nwithinLines = 0\nwithinColumns = 50\n\n[[rules]]\nid = 'perf-mark'\ndescription = 'mark'\nregex = '''COMPMARK'''\nkeywords = ['compmark']\nskipReport = true\n"
    );
    let mut phases = Vec::new();
    for per_line in [true, false] {
        let layout = if per_line { "per-line" } else { "one-line" };
        let mut input = Vec::with_capacity(RECORDS * 96);
        let mut all = Vec::with_capacity(RECORDS);
        for index in 0..RECORDS {
            let value = if index + 1 == RECORDS {
                "999999".to_owned()
            } else {
                format!("{index:06}")
            };
            let line = if per_line { index + 1 } else { 1 };
            let column = if per_line {
                if line == 1 { 1 } else { 2 }
            } else {
                input.len() + 1
            };
            all.push(key("perf-record", "", "", line, column, value.as_bytes()));
            input.extend_from_slice(format!("token={value}").as_bytes());
            if index + 1 == RECORDS {
                input.extend_from_slice(b" COMPMARK");
            } else {
                input.extend_from_slice(&[b'.'; 88]);
            }
            if per_line {
                input.push(b'\n');
            }
        }
        all.sort();
        let last = all
            .iter()
            .filter(|row| row.secret == b"999999")
            .cloned()
            .collect::<Vec<_>>();
        let fragment = fragment(input, None);
        for (mode, config, expected) in [
            ("accepted", &accepted, &all),
            ("filtered", &filtered, &last),
            ("missing-component", &missing, &last),
        ] {
            phases.push(scan_phase(
                &format!("{mode}-{layout}"),
                iterations,
                &engine(config)?,
                &fragment,
                expected,
                config,
            )?);
        }
    }
    Ok(phases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_workloads_have_exact_outcomes() {
        for id in WORKLOADS {
            let phases = run(id, 1).unwrap_or_else(|error| panic!("{id}: {error}"));
            assert!(!phases.is_empty(), "{id}");
        }
    }

    #[test]
    fn generated_values_avoid_every_marker() {
        let mut rng = Lcg::new(1);
        for _ in 0..1_000 {
            let value = value(&mut rng, None);
            assert!(!value.contains(&b'q') && !value.contains(&b'z'));
        }
    }
}
