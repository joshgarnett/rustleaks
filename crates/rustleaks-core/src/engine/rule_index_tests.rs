//! The rule index must not change what a scan observes. The scan tests scan the
//! same fragment twice: once visiting only the rules that [`RuleIndex`]
//! selects, and once visiting every rule as an explained scan does. The two
//! must return the same findings in the same order, the same usage and
//! termination, and poll cancellation the same number of times, also when a
//! work budget or a cancellation stops the scan part way. The last test
//! checks that one `work_many` call charges and polls like one `work` call
//! per unit.

use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use serde::Deserialize;

use super::*;
use crate::config::ConfigLoader;

#[derive(Debug, PartialEq)]
struct Observed {
    findings: Vec<Finding>,
    usage: ScanUsage,
    termination: Option<ScanTermination>,
    /// Cancellation polls, or `None` for a scan without a signal.
    polls: Option<usize>,
}

#[derive(Clone, Copy)]
enum Stop {
    /// No cancellation signal.
    Never,
    /// A signal that is never set, so every poll is counted.
    Counted,
    /// A signal set from this poll on.
    AtPoll(usize),
}

fn observe(
    engine: &Engine,
    fragment: &Fragment,
    visit_every_rule: bool,
    budget: ScanBudget,
    stop: Stop,
) -> Observed {
    // Decode like the CLI, so decoded passes run the rules too.
    let options = ScanOptions::builder().max_decode_depth(5).build();
    let polls = AtomicUsize::new(0);
    let limit = match stop {
        Stop::AtPoll(limit) => limit,
        Stop::Never | Stop::Counted => usize::MAX,
    };
    let signal = || polls.fetch_add(1, Ordering::Relaxed) >= limit;
    let control = match stop {
        Stop::Never => ScanControl::unlimited(),
        Stop::Counted | Stop::AtPoll(_) => ScanControl::cancellable(&signal),
    }
    .with_budget(budget);
    let mut context = ScanContext::new(control);
    context.visit_every_rule = visit_every_rule;
    let outcome = engine.scan_fragment_with_context(
        fragment,
        &options,
        &mut context,
        &mut ScanBuffers::default(),
    );
    Observed {
        findings: outcome.findings().to_vec(),
        usage: outcome.usage(),
        termination: outcome.termination().cloned(),
        polls: match stop {
            Stop::Never => None,
            Stop::Counted | Stop::AtPoll(_) => Some(polls.load(Ordering::Relaxed)),
        },
    }
}

/// Asserts that both paths observe the same scan and returns it.
fn assert_same(
    engine: &Engine,
    fragment: &Fragment,
    budget: ScanBudget,
    stop: Stop,
    label: &str,
) -> Observed {
    let indexed = observe(engine, fragment, false, budget, stop);
    let every = observe(engine, fragment, true, budget, stop);
    assert_eq!(indexed, every, "{label}");
    indexed
}

/// Compares the paths without limits, then at spread work limits and
/// cancellation points up to what the complete scan used.
fn assert_same_at_every_stop(engine: &Engine, fragment: &Fragment, steps: usize, label: &str) {
    let unlimited = ScanBudget::unlimited();
    let complete = assert_same(engine, fragment, unlimited, Stop::Never, label);
    assert!(complete.termination.is_none(), "{label}");
    let counted = assert_same(engine, fragment, unlimited, Stop::Counted, label);
    let used = complete.usage.work_units();
    let polls = counted.polls.unwrap();
    let stride = |total: usize| (total / steps).max(1);
    for limit in (0..=used)
        .step_by(stride(used))
        .chain([used.saturating_sub(1)])
    {
        let budget = ScanBudget::unlimited().max_work_units(limit);
        assert_same(engine, fragment, budget, Stop::Never, label);
        assert_same(engine, fragment, budget, Stop::Counted, label);
    }
    for poll in (0..=polls)
        .step_by(stride(polls))
        .chain([polls.saturating_sub(1)])
    {
        assert_same(engine, fragment, unlimited, Stop::AtPoll(poll), label);
    }
}

fn default_engine() -> Engine {
    Engine::builder(ConfigLoader::new().load_default().unwrap())
        .build()
        .unwrap()
}

#[test]
fn every_keyword_combination_runs_the_same_rules_in_rule_order() {
    // Rules share keywords, need none, have only an empty keyword, check only
    // the path, or have a keyword with a Go-lowercase rune.
    let engine = Engine::builder(
        ConfigLoader::new()
            .load_toml(
                r#"
[[rules]]
id = "a-two"
regex = 'A[0-9]{3}'
keywords = ["alpha", "beta"]
[[rules]]
id = "b-repeated"
regex = 'B[0-9]{3}'
keywords = ["beta", "beta"]
[[rules]]
id = "c-none"
regex = 'C[0-9]{3}'
[[rules]]
id = "d-empty"
regex = 'D[0-9]{3}'
keywords = [""]
[[rules]]
id = "e-empty-and-real"
regex = 'E[0-9]{3}'
keywords = ["", "gamma"]
[[rules]]
id = "f-path-only"
path = '\.pem$'
[[rules]]
id = "g-path-and-keyword"
path = '\.pem$'
keywords = ["delta"]
[[rules]]
id = "h-go-lowercase"
regex = 'H[0-9]{3}'
keywords = ["\U0000212Aey"]
"#,
            )
            .unwrap(),
    )
    .build()
    .unwrap();
    let keywords = ["alpha", "beta", "gamma", "delta", "key"];
    for mask in 0_u32..(1 << keywords.len()) {
        let present = |index: usize| mask & (1 << index) != 0;
        let mut content = String::from("A100 B200 C300 D400 E500 H800\n");
        for (index, keyword) in keywords.iter().enumerate() {
            if present(index) {
                content.push_str(keyword);
                content.push('\n');
            }
        }
        for path in ["", "key.pem"] {
            let fragment = Fragment::builder(content.as_bytes())
                .file_path(path)
                .build();
            let label = format!("mask {mask:05b}, path {path:?}");
            let complete = assert_same(
                &engine,
                &fragment,
                ScanBudget::unlimited(),
                Stop::Never,
                &label,
            );
            // Stated independently: each rule whose gate opens reports once,
            // in rule ID order.
            let mut expected = Vec::new();
            if present(0) || present(1) {
                expected.push("a-two");
            }
            if present(1) {
                expected.push("b-repeated");
            }
            expected.push("c-none");
            if present(2) {
                expected.push("e-empty-and-real");
            }
            if !path.is_empty() {
                expected.push("f-path-only");
                if present(3) {
                    expected.push("g-path-and-keyword");
                }
            }
            if present(4) {
                expected.push("h-go-lowercase");
            }
            let found = complete
                .findings
                .iter()
                .map(|finding| finding.rule_id().as_bytes())
                .collect::<Vec<_>>();
            let expected = expected.iter().map(|id| id.as_bytes()).collect::<Vec<_>>();
            assert_eq!(found, expected, "{label}");
            assert_same_at_every_stop(&engine, &fragment, 64, &label);
        }
    }
}

#[derive(Deserialize)]
struct Sample {
    case_id: String,
    input_base64: String,
}

fn generator_samples() -> Vec<Sample> {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/generator-corpus/samples-v1.jsonl");
    std::fs::read_to_string(corpus)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Sample>(line).unwrap())
        .collect()
}

#[test]
fn default_rules_scan_generator_samples_the_same_way() {
    let engine = default_engine();
    let samples = generator_samples();
    assert!(samples.len() > 1_000);
    let mut with_findings = 0;
    for sample in &samples {
        let input = BASE64_STANDARD.decode(&sample.input_base64).unwrap();
        let fragment = Fragment::new(input.as_slice());
        let complete = assert_same(
            &engine,
            &fragment,
            ScanBudget::unlimited(),
            Stop::Counted,
            &sample.case_id,
        );
        with_findings += usize::from(!complete.findings.is_empty());
    }
    assert!(with_findings > 1_000, "{with_findings}");
    // Many rules in one fragment, plain and as a decoded pass.
    for (index, chunk) in samples.chunks(97).enumerate() {
        let mut input = Vec::new();
        let mut encoded = Vec::new();
        for sample in chunk {
            let decoded = BASE64_STANDARD.decode(&sample.input_base64).unwrap();
            encoded.extend(b"value: ");
            encoded.extend(BASE64_STANDARD.encode(&decoded).into_bytes());
            encoded.push(b'\n');
            input.extend(decoded);
            input.push(b'\n');
        }
        for (form, bytes) in [("plain", input), ("base64", encoded)] {
            let fragment = Fragment::new(bytes.as_slice());
            let label = format!("chunk {index} {form}");
            let complete = assert_same(
                &engine,
                &fragment,
                ScanBudget::unlimited(),
                Stop::Never,
                &label,
            );
            assert!(!complete.findings.is_empty(), "{label}");
            if index % 8 == 0 {
                assert_same_at_every_stop(&engine, &fragment, 40, &label);
            }
        }
    }
}

#[test]
fn native_rule_keywords_open_the_same_native_gates() {
    let engine = default_engine();
    let gated = engine
        .native_fast_gates
        .iter()
        .filter(|gate| gate.is_some())
        .count();
    assert!(gated >= 25, "{gated}");
    // Each native rule's ASCII keywords, alone and beside a GitHub-shaped
    // token, then every keyword in one fragment.
    let token = ["ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"].concat();
    let mut all = String::new();
    for rule in engine.config.rules.values() {
        let keywords = rule
            .native_keywords
            .iter()
            .flatten()
            .filter_map(|keyword| match keyword {
                NativeKeyword::Ascii(text) => Some(text.as_str()),
                NativeKeyword::UnicodeLower(_) | NativeKeyword::Empty => None,
            })
            .collect::<Vec<_>>();
        if keywords.is_empty() {
            continue;
        }
        let text = format!("{} = value_0123456789abcdef\n", keywords.join(" "));
        all.push_str(&text);
        for input in [text.clone(), format!("{text}token: {token}\n")] {
            assert_same(
                &engine,
                &Fragment::new(input.as_bytes()),
                ScanBudget::unlimited(),
                Stop::Counted,
                &format!("{} {input:?}", rule.id),
            );
        }
    }
    all.push_str(&format!("GITHUB_TOKEN={token}\n"));
    let label = "every native keyword";
    assert_same_at_every_stop(&engine, &Fragment::new(all.as_bytes()), 40, label);
    // The Kelvin sign leaves native patterns to the native automaton, so no
    // rule is skipped by its native keywords.
    let kelvin = format!("\u{212a}ey {all}");
    assert_same_at_every_stop(&engine, &Fragment::new(kelvin.as_bytes()), 40, "Kelvin");
    for input in [
        String::new(),
        "plain text without any keyword\n".to_owned(),
        format!("export GITHUB_TOKEN={token}\n"),
        BASE64_STANDARD.encode(format!("GITHUB_TOKEN={token}\n")),
        "caf\u{e9} au lait\n".to_owned(),
    ] {
        assert_same_at_every_stop(&engine, &Fragment::new(input.as_bytes()), 40, &input);
    }
}

#[test]
fn rule_candidates_list_selected_and_native_gated_rules_in_order() {
    let visit = [0b1010_u64, 1 << 63, 0];
    let gated = [0b0110_u64, 0, 1];
    let walked = RuleCandidates::new(Some(&visit), &gated, 129).collect::<Vec<_>>();
    assert_eq!(
        walked,
        [(1, true), (2, false), (3, true), (127, true), (128, false)]
    );
    let every = RuleCandidates::new(None, &gated, 3).collect::<Vec<_>>();
    assert_eq!(every, [(0, true), (1, true), (2, true)]);
    assert_eq!(RuleCandidates::new(Some(&[]), &[], 0).count(), 0);
}

/// Usage, polls and result after charging `units` from `start`, either with
/// one `work_many` call or with one `work` call per unit.
fn charge_units(
    start: usize,
    units: usize,
    budget: Option<usize>,
    stop: Stop,
    at_once: bool,
) -> (usize, usize, Result<(), ScanTermination>) {
    let polls = AtomicUsize::new(0);
    let limit = match stop {
        Stop::AtPoll(limit) => limit,
        Stop::Never | Stop::Counted => usize::MAX,
    };
    let signal = || polls.fetch_add(1, Ordering::Relaxed) >= limit;
    let budget = budget.map_or(ScanBudget::unlimited(), |maximum| {
        ScanBudget::unlimited().max_work_units(maximum)
    });
    let control = match stop {
        Stop::Never => ScanControl::unlimited(),
        Stop::Counted | Stop::AtPoll(_) => ScanControl::cancellable(&signal),
    }
    .with_budget(budget);
    let mut context = ScanContext::new(control);
    context.usage.work_units = start;
    let result = if at_once {
        context.work_many(units)
    } else {
        (0..units).try_for_each(|_| context.work())
    };
    (
        context.usage.work_units,
        polls.load(Ordering::Relaxed),
        result,
    )
}

#[test]
fn work_many_matches_one_work_call_per_unit() {
    let mut stopped = [0_usize; 2];
    for start in [0, 3, 7, usize::MAX - 2] {
        for units in [0, 1, 2, 5, 9] {
            for budget in [None, Some(0), Some(3), Some(7), Some(10), Some(usize::MAX)] {
                if budget.is_some_and(|maximum| start > maximum) {
                    continue;
                }
                for stop in [
                    Stop::Never,
                    Stop::Counted,
                    Stop::AtPoll(0),
                    Stop::AtPoll(1),
                    Stop::AtPoll(4),
                ] {
                    let at_once = charge_units(start, units, budget, stop, true);
                    let each = charge_units(start, units, budget, stop, false);
                    assert_eq!(at_once, each, "{start} {units} {budget:?}");
                    match at_once.2 {
                        Err(ScanTermination::Cancelled) => stopped[0] += 1,
                        Err(ScanTermination::BudgetExceeded { .. }) => stopped[1] += 1,
                        _ => {}
                    }
                }
            }
        }
    }
    // Both ways of stopping are covered.
    assert!(stopped.iter().all(|&count| count > 10), "{stopped:?}");
}
