#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use rustleaks_core::Engine;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use serde::Deserialize;

#[derive(Deserialize)]
struct Sample {
    case_id: String,
    rule_id: String,
    polarity: String,
    contract: String,
    input_base64: String,
    path_present: bool,
    path_base64: Option<String>,
    oracle_observed_count: usize,
    findings: Vec<ExpectedFinding>,
}

#[derive(Deserialize)]
struct ExpectedFinding {
    match_base64: String,
    secret_base64: String,
}

#[test]
fn every_default_rule_positive_and_negative_matches_the_pinned_oracle() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../compat/generator-corpus/samples-v1.jsonl");
    let samples = fs::read_to_string(corpus)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Sample>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(samples.len(), 6_770);

    let default = ConfigLoader::new().load_default().unwrap();
    let mut engines = BTreeMap::new();
    for sample in &samples {
        if engines.contains_key(&sample.rule_id) {
            continue;
        }
        let selected = default.select_rules([sample.rule_id.as_str()]).unwrap();
        engines.insert(
            sample.rule_id.clone(),
            Engine::builder(selected).build().unwrap(),
        );
    }
    assert_eq!(engines.len(), 220);

    let mut ordinary_positive = 0_usize;
    let mut ordinary_negative = 0_usize;
    let mut path_positive = 0_usize;
    let mut path_negative = 0_usize;
    for sample in samples {
        match sample.polarity.as_str() {
            "ordinary_true" => ordinary_positive += 1,
            "ordinary_false" => ordinary_negative += 1,
            "path_true" => path_positive += 1,
            "path_false" => path_negative += 1,
            other => panic!("{}: unknown polarity {other}", sample.case_id),
        }

        let input = BASE64_STANDARD.decode(&sample.input_base64).unwrap();
        let mut fragment = Fragment::builder(input);
        if sample.path_present {
            let path = BASE64_STANDARD
                .decode(sample.path_base64.as_deref().unwrap())
                .unwrap();
            fragment = fragment.file_path(path);
        } else {
            assert!(sample.path_base64.is_none(), "{}", sample.case_id);
        }
        let outcome =
            engines[&sample.rule_id].scan_fragment(&fragment.build(), &ScanOptions::default());
        assert!(outcome.is_complete(), "{}", sample.case_id);
        assert_eq!(
            outcome.findings().len(),
            sample.oracle_observed_count,
            "{}",
            sample.case_id
        );
        match sample.contract.as_str() {
            "zero" => assert!(outcome.findings().is_empty(), "{}", sample.case_id),
            "at_least_one" => assert!(!outcome.findings().is_empty(), "{}", sample.case_id),
            "exactly_one" => assert_eq!(outcome.findings().len(), 1, "{}", sample.case_id),
            other => panic!("{}: unknown contract {other}", sample.case_id),
        }

        let actual = outcome
            .findings()
            .iter()
            .map(|finding| {
                assert_eq!(finding.rule_id().as_bytes(), sample.rule_id.as_bytes());
                (
                    BASE64_STANDARD.encode(finding.match_text().as_bytes()),
                    BASE64_STANDARD.encode(finding.secret().as_bytes()),
                )
            })
            .collect::<Vec<_>>();
        let expected = sample
            .findings
            .iter()
            .map(|finding| (finding.match_base64.clone(), finding.secret_base64.clone()))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "{}", sample.case_id);
    }

    assert_eq!(ordinary_positive, 6_368);
    assert_eq!(ordinary_negative, 342);
    assert_eq!(path_positive, 28);
    assert_eq!(path_negative, 32);
}
