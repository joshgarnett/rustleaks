//! Generated-configuration fixtures: large rule counts, allowlists and keywordless rules.
//!
//! Every generated literal is unique and fixed-width, so no keyword is a
//! substring of another. The plants alone determine findings and candidates.

use std::fmt::Write as _;

use rustleaks_core::model::Fragment;
use serde_json::json;

use super::{Context, Expected, Fallible, KIB, Lcg, MIB, Plan, Plant, Scan, ensure, filler};

const SMALL_FRAGMENT: usize = 16 * KIB;
const LARGE_FRAGMENT: usize = MIB;

/// Configuration text for workloads that do not use the packaged defaults.
pub(super) fn config_text(id: &str) -> Option<String> {
    match id {
        "core-generic-filter-4096" | "core-generic-filter-16384" | "core-generic-filter-65536" => {
            Some(GENERIC_FILTER_CONFIG.to_owned())
        }
        "core-custom-config-1000-rules" => Some(many_rules_config(1_000)),
        "core-custom-config-5000-rules" => Some(many_rules_config(5_000)),
        "core-custom-config-allowlist-heavy" => Some(allowlist_heavy_config()),
        "core-custom-config-keywordless-50" => Some(keywordless_config(50)),
        _ => None,
    }
}

pub(super) fn build(id: &str, ctx: &mut Context<'_>) -> Fallible<Option<Plan>> {
    Ok(Some(match id {
        "core-generic-filter-4096" => generic_filter(ctx, 4_096)?,
        "core-generic-filter-16384" => generic_filter(ctx, 16_384)?,
        "core-generic-filter-65536" => generic_filter(ctx, 65_536)?,
        "core-custom-config-1000-rules" => many_rules(ctx, 1_000)?,
        "core-custom-config-5000-rules" => many_rules(ctx, 5_000)?,
        "core-custom-config-allowlist-heavy" => allowlist_heavy(ctx)?,
        "core-custom-config-keywordless-50" => keywordless(ctx, 50)?,
        _ => return Ok(None),
    }))
}

fn plan_of(ctx: &Context<'_>, scans: Vec<Scan>, counts: serde_json::Value) -> Plan {
    let rules = ctx
        .rules
        .iter()
        .map(|rule| super::RuleMeta {
            id: rule.id.clone(),
            description: rule.description.clone(),
        })
        .collect();
    let scans_per_operation = scans.len();
    Plan {
        rules,
        scans,
        scans_per_operation,
        counts,
    }
}

/// Generated configurations must compile to exactly the planned rule count.
fn ensure_rule_count(ctx: &Context<'_>, rules: usize) -> Fallible<()> {
    ensure(
        ctx.config.rules().len() == rules,
        "generated configuration compiled the wrong rule count",
    )
}

fn scan_of(fragment: Fragment, expected: Expected) -> Scan {
    Scan { fragment, expected }
}

const GENERIC_FILTER_CONFIG: &str = r#"
[[rules]]
id = "generic-filter-token"
description = "synthetic generic-named rule"
regex = '''gentoken=([0-9a-f]{16})'''
secretGroup = 1
keywords = ["gentoken="]

[[rules]]
id = "specific-filter-token"
description = "synthetic specific rule"
regex = '''spectoken=([0-9a-f]{16})'''
secretGroup = 1
keywords = ["spectoken="]
"#;

/// Generic-rule findings are filtered only against non-generic findings on
/// their own line. Every generic finding here has its own line, and specific
/// findings use separate lines, so all of them must be retained while the
/// quadratic comparison still runs over every pair.
fn generic_filter(ctx: &mut Context<'_>, generic: usize) -> Fallible<Plan> {
    ensure_rule_count(ctx, 2)?;
    let generic_rule = ctx.rule_index("generic-filter-token")?;
    let specific_rule = ctx.rule_index("specific-filter-token")?;
    let specific = generic / 8;
    let mut rng = Lcg::new(0x6766_696c);
    let mut raw = Vec::with_capacity((generic + specific) * 28);
    let mut plants = Vec::with_capacity(generic + specific);
    for index in 0..generic {
        plant_hex_line(&mut raw, &mut plants, &mut rng, generic_rule, b"gentoken=");
        if index % 8 == 0 && plants.len() < generic + specific {
            plant_hex_line(
                &mut raw,
                &mut plants,
                &mut rng,
                specific_rule,
                b"spectoken=",
            );
        }
    }
    let candidates = plants.len();
    ensure(
        candidates == generic + specific,
        "generic-filter fixture must plant every specific finding",
    )?;
    let expected = ctx.expected(&raw, plants, candidates)?;
    Ok(plan_of(
        ctx,
        vec![scan_of(Fragment::builder(raw).build(), expected)],
        json!({"generic_findings": generic, "specific_findings": specific}),
    ))
}

fn plant_hex_line(
    raw: &mut Vec<u8>,
    plants: &mut Vec<Plant>,
    rng: &mut Lcg,
    rule: usize,
    prefix: &[u8],
) {
    let start = raw.len();
    raw.extend_from_slice(prefix);
    let secret = raw.len();
    raw.extend_from_slice(&rng.string(b"0123456789abcdef", 16));
    plants.push(Plant {
        rule,
        matched: (start, raw.len()),
        secret: (secret, raw.len()),
    });
    raw.push(b'\n');
}

fn many_rules_config(rules: usize) -> String {
    let mut config = String::with_capacity(rules * 140);
    for index in 0..rules {
        writeln!(
            config,
            "[[rules]]\nid = \"custom-{index:05}\"\ndescription = \"custom rule {index}\"\nregex = '''zq{index:05}kw=([a-z0-9]{{12}})'''\nsecretGroup = 1\nkeywords = [\"zq{index:05}kw\"]\n"
        )
        .expect("writing to a String cannot fail");
    }
    config
}

/// The first, middle and last rules are planted, spread across the fragment.
fn many_rules(ctx: &mut Context<'_>, rules: usize) -> Fallible<Plan> {
    ensure_rule_count(ctx, rules)?;
    let selected = [0, rules / 2, rules - 1];
    let mut scans = Vec::with_capacity(2);
    for (size, repeats) in [(SMALL_FRAGMENT, 1), (LARGE_FRAGMENT, 16)] {
        let mut rng = Lcg::new(0x6d61_6e79 + size as u64);
        let mut raw = Vec::with_capacity(size);
        let mut plants = Vec::new();
        for _ in 0..repeats {
            for rule_number in selected {
                let rule = ctx.rule_index(&format!("custom-{rule_number:05}"))?;
                let prefix = format!("zq{rule_number:05}kw=");
                let start = raw.len();
                raw.extend_from_slice(prefix.as_bytes());
                let secret = raw.len();
                raw.extend_from_slice(&rng.string(b"0123456789abcdefghij", 12));
                plants.push(Plant {
                    rule,
                    matched: (start, raw.len()),
                    secret: (secret, raw.len()),
                });
                raw.push(b'\n');
            }
            raw.extend_from_slice(&filler(size / repeats / 2));
            raw.push(b'\n');
        }
        ensure(raw.len() <= size, "many-rules fixture exceeds its size")?;
        raw.extend_from_slice(&filler(size - raw.len()));
        let candidates = plants.len();
        let expected = ctx.expected(&raw, plants, candidates)?;
        scans.push(scan_of(Fragment::builder(raw).build(), expected));
    }
    Ok(plan_of(
        ctx,
        scans,
        json!({"rules": rules, "fragment_bytes": [SMALL_FRAGMENT, LARGE_FRAGMENT]}),
    ))
}

const HEAVY_REGEXES: usize = 500;
const HEAVY_PATHS: usize = 500;
const HEAVY_STOPWORDS: usize = 10_000;

fn allowlist_heavy_config() -> String {
    let mut config = String::with_capacity(HEAVY_STOPWORDS * 20 + 64 * 1_024);
    config.push_str("[[allowlists]]\ndescription = \"generated heavy allowlist\"\nregexes = [\n");
    for index in 0..HEAVY_REGEXES {
        writeln!(config, "  '''^ZZH{index:03}[A-Z]{{10}}$''',")
            .expect("writing to a String cannot fail");
    }
    config.push_str("]\npaths = [\n");
    for index in 0..HEAVY_PATHS {
        writeln!(config, "  '''^denied/p{index:03}/''',").expect("writing to a String cannot fail");
    }
    config.push_str("]\nstopwords = [\n");
    for index in 0..HEAVY_STOPWORDS {
        writeln!(config, "  \"zzstop{index:05}\",").expect("writing to a String cannot fail");
    }
    config.push_str(
        "]\n\n[[rules]]\nid = \"heavy-target\"\ndescription = \"heavy allowlist target\"\nregex = '''heavyval=([A-Z0-9]{16})'''\nsecretGroup = 1\nkeywords = [\"heavyval=\"]\n",
    );
    config
}

/// Each value is 16 uppercase or digit bytes. A retained value starts `KP` and
/// holds no `ZZ`, so it can match neither the anchored `^ZZH...` regexes nor a
/// lowered `zzstop...` stopword. The non-allowlisted path makes all 500 path
/// patterns run first, and the two rejected shapes prove both criteria fire.
fn heavy_scan(
    ctx: &mut Context<'_>,
    size: usize,
    per_shape: usize,
) -> Fallible<(Scan, usize, usize)> {
    let rule = ctx.rule_index("heavy-target")?;
    let mut rng = Lcg::new(0x6865_6176 + size as u64);
    let mut raw = Vec::with_capacity(size);
    let mut plants = Vec::new();
    let mut candidates = 0;
    for index in 0..per_shape {
        for shape in 0..3 {
            let value = match shape {
                0 => format!(
                    "KP{}",
                    String::from_utf8_lossy(&rng.string(b"23456789BCDFGHJK", 14))
                ),
                1 => format!(
                    "ZZH{:03}{}",
                    index % HEAVY_REGEXES,
                    String::from_utf8_lossy(&rng.string(b"BCDFGHJKLM", 10))
                ),
                _ => format!(
                    "ZZSTOP{:05}{}",
                    index % HEAVY_STOPWORDS,
                    String::from_utf8_lossy(&rng.string(b"BCDFGHJKLM", 5))
                ),
            };
            let start = raw.len();
            raw.extend_from_slice(b"heavyval=");
            let secret = raw.len();
            raw.extend_from_slice(value.as_bytes());
            if shape == 0 {
                plants.push(Plant {
                    rule,
                    matched: (start, raw.len()),
                    secret: (secret, raw.len()),
                });
            }
            raw.push(b'\n');
            candidates += 1;
        }
    }
    ensure(raw.len() < size, "allowlist fixture exceeds its size")?;
    raw.extend_from_slice(&filler(size - raw.len()));
    let retained = plants.len();
    let expected = ctx.expected(&raw, plants, candidates)?;
    let fragment = Fragment::builder(raw)
        .file_path("src/heavy/allowed-path.rs")
        .build();
    Ok((scan_of(fragment, expected), candidates, retained))
}

fn allowlist_heavy(ctx: &mut Context<'_>) -> Fallible<Plan> {
    ensure_rule_count(ctx, 1)?;
    let (small, small_candidates, small_retained) = heavy_scan(ctx, SMALL_FRAGMENT, 16)?;
    let (large, large_candidates, large_retained) = heavy_scan(ctx, LARGE_FRAGMENT, 256)?;
    Ok(plan_of(
        ctx,
        vec![small, large],
        json!({
            "allowlist_regexes": HEAVY_REGEXES,
            "allowlist_paths": HEAVY_PATHS,
            "stopwords": HEAVY_STOPWORDS,
            "candidates": [small_candidates, large_candidates],
            "retained": [small_retained, large_retained],
        }),
    ))
}

fn keywordless_config(rules: usize) -> String {
    let mut config = String::with_capacity(rules * 120);
    for index in 0..rules {
        writeln!(
            config,
            "[[rules]]\nid = \"keywordless-{index:02}\"\ndescription = \"keywordless rule {index}\"\nregex = '''zqk{index:02}=([0-9a-f]{{16}})'''\nsecretGroup = 1\n"
        )
        .expect("writing to a String cannot fail");
    }
    config
}

/// With no keyword at all there is no prefilter, so all 50 rules run on every
/// fragment. Only rules 0, 7, 14, ... have a planted match.
fn keywordless(ctx: &mut Context<'_>, rules: usize) -> Fallible<Plan> {
    ensure_rule_count(ctx, rules)?;
    let mut scans = Vec::with_capacity(2);
    let mut planted_counts = Vec::with_capacity(2);
    for size in [SMALL_FRAGMENT, LARGE_FRAGMENT] {
        let mut rng = Lcg::new(0x6b77_6c73 + size as u64);
        let mut raw = Vec::with_capacity(size);
        let mut plants = Vec::new();
        for rule_number in (0..rules).step_by(7) {
            let rule = ctx.rule_index(&format!("keywordless-{rule_number:02}"))?;
            plant_hex_line(
                &mut raw,
                &mut plants,
                &mut rng,
                rule,
                format!("zqk{rule_number:02}=").as_bytes(),
            );
        }
        raw.extend_from_slice(&filler(size - raw.len()));
        let candidates = plants.len();
        planted_counts.push(candidates);
        let expected = ctx.expected(&raw, plants, candidates)?;
        scans.push(scan_of(Fragment::builder(raw).build(), expected));
    }
    Ok(plan_of(
        ctx,
        scans,
        json!({"keywordless_rules": rules, "planted": planted_counts}),
    ))
}
