//! Small controls for the default-rule workloads. They exercise the same
//! generators as the full workloads at sizes suitable for ordinary test runs.

use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl};

use super::*;

fn default_config() -> CompiledConfig {
    ConfigLoader::new().load_default().unwrap()
}

fn engine(config: &CompiledConfig) -> Engine {
    Engine::builder(config.clone()).build().unwrap()
}

fn check(detector: &Engine, rules: &[RuleMeta], scan: &Scan) {
    let outcome = detector.scan_fragment_controlled(
        &scan.fragment,
        &ScanOptions::builder().max_decode_depth(0).build(),
        &budget(&scan.expected),
    );
    validate(rules, scan, &outcome).unwrap();
}

#[test]
fn workload_ids_are_unique_and_every_selector_family_is_declared() {
    let unique = WORKLOADS.iter().collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), WORKLOADS.len());
    assert_eq!(WORKLOADS.len(), 46);
    assert!(run("core-unknown", 1).is_err());
}

#[test]
fn entropy_and_location_restate_upstream_helpers() {
    // Eleven symbols over 22 bytes, each twice: exactly log2(11).
    let even = b"0123456789a0123456789a";
    assert!((go_entropy(even).unwrap() - 11_f64.log2()).abs() < 1e-12);
    assert!(go_entropy(b"\xff").is_err());
    assert_eq!(go_entropy(b"").unwrap().to_bits(), 0_f64.to_bits());

    let raw = b"first\nsecond\nthird";
    let newlines = newline_positions(raw);
    // Newlines sit at bytes 5 and 12. Upstream measures from the newline's own
    // index, so the first byte after a newline is column (6 - 5) + 1 = 2.
    let second = go_location(&newlines, raw, 6, 12);
    assert_eq!(
        (
            second.start_line,
            second.end_line,
            second.start_column,
            second.end_column
        ),
        (1, 1, 2, 7)
    );
    assert_eq!((second.start_index, second.end_index), (5, 12));

    // After the last newline: upstream's zero-start, no-line-matched path.
    // Columns are (13 - 12) + 1 = 2 and 18 - 12 = 6.
    let tail = go_location(&newlines, raw, 13, 18);
    assert_eq!((tail.start_line, tail.end_line), (2, 2));
    assert_eq!((tail.start_column, tail.end_column), (2, 6));
    assert_eq!((tail.start_index, tail.end_index), (0, raw.len()));

    // No newline at all: upstream's one virtual newline at the end.
    let flat = b"abcdef";
    let virtual_newline = newline_positions(flat);
    assert_eq!(virtual_newline, vec![flat.len()]);
    let only = go_location(&virtual_newline, flat, 2, 4);
    assert_eq!(
        (only.start_line, only.start_column, only.end_column),
        (0, 3, 4)
    );
    assert_eq!((only.start_index, only.end_index), (0, flat.len()));
}

#[test]
fn keyword_view_maps_only_the_two_go_code_points_that_reach_ascii() {
    assert_eq!(keyword_view("KEY".as_bytes()), b"key");
    assert_eq!(keyword_view("\u{212A}EY".as_bytes()), b"key");
    assert_eq!(keyword_view("\u{130}D".as_bytes()), b"id");
    // Long s and Cyrillic stay non-ASCII, so they can never form a keyword.
    assert_eq!(
        keyword_view("\u{17F}ecret".as_bytes()),
        "\u{17F}ecret".as_bytes()
    );
    assert!(
        !keyword_view("СЕКРЕТ \u{17F}ecret".as_bytes())
            .windows(6)
            .any(|window| window == b"secret")
    );
}

#[test]
fn filler_is_keyword_free_and_exactly_sized() {
    let config = default_config();
    let text = filler(64 * KIB);
    assert_eq!(text.len(), 64 * KIB);
    assert!(text.is_ascii());
    assert_eq!(census(&config, &text).occurrences, 0);
    assert!(text.iter().all(|byte| *byte != 0));
}

#[test]
fn admission_selection_is_independent_and_tracks_rule_count() {
    let config = default_config();
    for count in [1, 16, 64, 150] {
        let selected = admission_keywords(&config, count).unwrap();
        assert_eq!(selected.len(), count);
        // No selected keyword contains another default keyword.
        for keyword in &selected {
            assert!(
                !config
                    .keywords()
                    .iter()
                    .any(|other| other != keyword && keyword.contains(other.as_str())),
                "{keyword}"
            );
        }
        let mut raw = selected.join(" ").into_bytes();
        raw.push(b'\n');
        let literal = census(&config, &raw);
        assert_eq!(literal.occurrences, count);
        let admitted = admitted_rules(&config, &literal);
        // Small selections have disjoint single owners, so admitted rules are
        // the keywords plus the one keywordless rule. The 150 case must use
        // keywords shared by several rules, so it can only be a lower bound.
        if count <= 64 {
            assert_eq!(admitted, count + 1);
        } else {
            assert!(admitted > count);
        }
    }
}

#[test]
fn small_controls_satisfy_their_independent_oracles() {
    let config = default_config();
    let detector = engine(&config);
    let mut ctx = Context::new(&config);
    let scans = vec![
        admission(&mut ctx, 16, 8 * KIB).unwrap().0,
        prose(&ctx, 8 * KIB).unwrap().0,
        all_admitted(&ctx, 8 * KIB).unwrap().0,
        keyword_run_repeat(&ctx, 8 * KIB).unwrap().0,
        keyword_run_blob(&ctx, 8 * KIB).unwrap().0,
        prefix_storm(&ctx, 8 * KIB).unwrap().0,
        thrash_generic(&ctx, 8 * KIB).unwrap().0,
        multibyte(&mut ctx, Script::Cjk, 8 * KIB, 4).unwrap().0,
        multibyte(&mut ctx, Script::Cyrillic, 8 * KIB, 4).unwrap().0,
        groupless_private_key(&mut ctx, 8 * KIB).unwrap().0,
        groupless_tokens(&mut ctx, 16).unwrap().0,
        minified_one_line(&mut ctx, 8, 8 * KIB).unwrap().0,
        minified_tail(&mut ctx, 8, 8 * KIB).unwrap().0,
        huge_secret(&mut ctx, 4 * KIB).unwrap().0,
    ];
    for scan in &scans {
        check(&detector, &ctx.rules, scan);
    }
}

#[test]
fn small_realistic_controls_satisfy_their_independent_oracles() {
    let config = default_config();
    let detector = engine(&config);
    let mut ctx = Context::new(&config);
    let size = 16 * KIB;
    let scans = vec![
        realistic::lockfile(&ctx, size, "web/package-lock.json", true)
            .unwrap()
            .0,
        realistic::lockfile(&ctx, size, "web/deps-snapshot.json", false)
            .unwrap()
            .0,
        realistic::env_file(&mut ctx, size).unwrap().0,
        realistic::k8s_yaml(&mut ctx, size).unwrap().0,
        realistic::jwt_log(&mut ctx, size).unwrap().0,
        realistic::multi_language(&mut ctx, size).unwrap().0,
        realistic::binary(&mut ctx, size).unwrap().0,
        realistic::utf16(&ctx, size).unwrap().0,
    ];
    for scan in &scans {
        check(&detector, &ctx.rules, scan);
    }
    // The allowlisted lockfile stops at the path gate; the other path does not.
    assert_eq!(scans[0].expected.work, Some(0));
    assert_eq!(scans[1].expected.work, Some(2));
}

#[test]
fn near_miss_candidates_are_killed_only_by_their_filter() {
    let config = default_config();
    let detector = engine(&config);
    for killer in [
        Killer::Entropy,
        Killer::Stopword,
        Killer::RuleAllowlist,
        Killer::GlobalAllowlist,
    ] {
        let mut ctx = Context::new(&config);
        let rule = ctx.rule_index(GENERIC_RULE).unwrap();
        let lines = 8;
        let mut raw = near_miss_input(&ctx, killer, lines).unwrap();
        assert_eq!(raw.len(), lines * 64);
        let suppressed = Scan {
            expected: ctx.expected(&raw, Vec::new(), lines).unwrap(),
            fragment: Fragment::builder(raw.clone()).build(),
        };
        check(&detector, &ctx.rules, &suppressed);

        // One byte flipped in one candidate must produce exactly one finding.
        let line = 5;
        let start = line * 64;
        let (offset, replacement) = killer.positive_flip();
        let secret = start + 4;
        assert_ne!(raw[secret + offset], replacement);
        raw[secret + offset] = replacement;
        let plant = Plant {
            rule,
            matched: (start, secret + NEAR_MISS_VALUE),
            secret: (secret, secret + NEAR_MISS_VALUE),
        };
        let positive = Scan {
            expected: ctx.expected(&raw, vec![plant], lines).unwrap(),
            fragment: Fragment::builder(raw).build(),
        };
        check(&detector, &ctx.rules, &positive);
    }
}

#[test]
fn tiny_fragments_carry_path_and_commit_and_exact_work() {
    let config = default_config();
    let detector = engine(&config);
    let ctx = Context::new(&config);
    for size in [64, 128, 256, 512] {
        let scans = tiny_scans(&ctx, size, 16).unwrap();
        // One pass, one `token` occurrence, the keywordless path rule and
        // `generic-api-key`; `token` is not a substring of any other keyword.
        assert_eq!(scans[0].expected.work, Some(4));
        for scan in &scans {
            assert_eq!(scan.fragment.content().len(), size);
            assert!(!scan.fragment.file_path().is_empty());
            assert!(!scan.fragment.commit().is_empty());
            check(&detector, &ctx.rules, scan);
        }
    }
}

#[test]
fn generated_config_controls_satisfy_their_independent_oracles() {
    for (id, rules) in [
        ("core-custom-config-allowlist-heavy", 1),
        ("core-custom-config-keywordless-50", 50),
        ("core-generic-filter-4096", 2),
    ] {
        let text = custom::config_text(id).unwrap();
        let config = ConfigLoader::new().load_toml(&text).unwrap();
        assert_eq!(config.rules().len(), rules);
        let detector = engine(&config);
        let mut ctx = Context::new(&config);
        let plan = custom::build(id, &mut ctx).unwrap().unwrap();
        for scan in &plan.scans {
            check(&detector, &plan.rules, scan);
        }
    }
    assert_eq!(
        ConfigLoader::new()
            .load_toml(&custom::config_text("core-custom-config-1000-rules").unwrap())
            .unwrap()
            .rules()
            .len(),
        1_000
    );
    assert!(custom::config_text("core-prose-keywords-16-kib").is_none());
}

#[test]
fn validation_rejects_skipped_budget_terminated_and_altered_outcomes() {
    let config = default_config();
    let detector = engine(&config);
    let mut ctx = Context::new(&config);
    let (scan, _) = groupless_tokens(&mut ctx, 4).unwrap();
    let options = ScanOptions::builder().max_decode_depth(0).build();
    let complete =
        detector.scan_fragment_controlled(&scan.fragment, &options, &budget(&scan.expected));
    validate(&ctx.rules, &scan, &complete).unwrap();

    let skipped = detector.scan_fragment(&Fragment::new(b""), &options);
    assert!(validate(&ctx.rules, &scan, &skipped).is_err());

    let work = scan.expected.work.unwrap();
    let partial = detector.scan_fragment_controlled(
        &scan.fragment,
        &options,
        &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(work - 1)),
    );
    assert!(!partial.is_complete());
    assert!(validate(&ctx.rules, &scan, &partial).is_err());

    // A plant shifted by one byte must not validate against the real outcome.
    let mut shifted = Scan {
        fragment: scan.fragment.clone(),
        expected: Expected {
            work: scan.expected.work,
            findings: scan
                .expected
                .findings
                .iter()
                .map(|finding| ExpectedFinding {
                    rule: finding.rule,
                    matched: finding.matched,
                    secret: finding.secret,
                    line: finding.line,
                    location: finding.location,
                    entropy: finding.entropy,
                })
                .collect(),
        },
    };
    shifted.expected.findings[0].matched.0 += 1;
    assert!(validate(&ctx.rules, &shifted, &complete).is_err());
    shifted.expected.findings[0].matched.0 -= 1;
    shifted.expected.work = Some(work + 1);
    assert!(validate(&ctx.rules, &shifted, &complete).is_err());
}
