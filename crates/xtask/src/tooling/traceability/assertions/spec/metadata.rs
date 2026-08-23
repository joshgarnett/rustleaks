//! Benchmark links and explicit platform-skip traceability rows.

use super::super::{Json, boolean, byte_text, deep_bytes, integer, object, strings, text};

pub(super) fn build_benchmarks() -> Vec<Json> {
    let source = "config/allowlist_test.go";
    let specs = [
        (
            "AS-BM-0001-ASSERT",
            "BM-0001",
            269,
            "CommitAllowed",
            "d0dbe09bb150bbd5bb4b85adc273df87350e7e6c",
            true,
            None,
        ),
        (
            "AS-BM-0002-ASSERT",
            "BM-0002",
            276,
            "CommitAllowed",
            "5fe58bf0b0be1735ad27aa6053b56323a905c223",
            false,
            None,
        ),
        (
            "AS-BM-0007-ASSERT",
            "BM-0007",
            318,
            "RegexAllowed",
            "environment {\n\tCREDENTIALS_ID = \"K8S_CRED\"\n}",
            true,
            None,
        ),
        (
            "AS-BM-0008-ASSERT",
            "BM-0008",
            327,
            "RegexAllowed",
            "\"credentials\" : \"0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506\"",
            false,
            None,
        ),
        (
            "AS-BM-0005-ASSERT",
            "BM-0005",
            368,
            "PathAllowed",
            "src/main/resources/static/js/jquery-ui-1.10.4.min.js",
            true,
            Some("AS-BASE-PATH-javascript-A-04"),
        ),
        (
            "AS-BM-0006-ASSERT",
            "BM-0006",
            375,
            "PathAllowed",
            "azure_scale_templates/sub_modules/vpc_template/inputs.auto.tfvars.json_backup",
            false,
            None,
        ),
    ];
    specs
        .into_iter()
        .map(|(id, benchmark, line, operation, sample, value, overlap)| {
            object([
                ("schema_version", integer(1)),
                ("id", text(id)),
                ("benchmark_id", text(benchmark)),
                ("upstream_revision", text(super::super::PIN)),
                ("mapping_id", text("M1-ASSERTIONS-002")),
                ("source_file", text(source)),
                ("source_line", integer(line)),
                ("source_occurrence", text(benchmark)),
                ("observation", text("public-api")),
                ("comparison", text("exact")),
                (
                    "input",
                    deep_bytes(object([
                        ("operation", text(operation)),
                        ("sample", text(sample)),
                    ])),
                ),
                (
                    "expected",
                    deep_bytes(object([("kind", text("bool")), ("value", boolean(value))])),
                ),
                (
                    "semantic_overlap_assertion_id",
                    overlap.map_or(Json::Null, text),
                ),
                (
                    "rust_test",
                    text("tests::exact_upstream_benchmark_inputs_and_outcomes_run"),
                ),
                (
                    "rust_evidence",
                    text(
                        "crates/rustleaks-compat/src/bin/rustleaks-perf.rs; cargo xtask perf check",
                    ),
                ),
                ("status", text("implemented")),
            ])
        })
        .collect()
}

pub(super) fn build_skips() -> Vec<Json> {
    [
        ("SKIP-TM-0133-WINDOWS", "TM-0133", &["TM-0134", "TM-0135", "TM-0136"][..], 850,
         "TODO: this fails on Windows: [git] fatal: bad object refs/remotes/origin/main?",
         "crates/rustleaks-sources/tests/git_corpus.rs::matrix_n_isolated_platform_fixtures_use_distinct_private_copies; portable Git corpus replaces the upstream Windows skip"),
        ("SKIP-TM-0126-WINDOWS", "TM-0126", &[][..], 2127,
         "TODO: this returns no results on windows, I'm not sure why.",
         "crates/rustleaks-sources/tests/source_corpus.rs::complete_source_corpus_matches_frozen_go_outcomes_or_exact_safe_dispositions; portable source corpus replaces the upstream Windows skip"),
    ].into_iter().map(|(id, parent, children, line, reason, evidence)| object([
        ("schema_version", integer(1)), ("upstream_revision", text(super::super::PIN)),
        ("mapping_id", text("M1-ASSERTIONS-002")), ("source_file", text("detect/detect_test.go")),
        ("platform", text("windows")), ("effect", text("skip")), ("rust_evidence", text(evidence)),
        ("status", text("implemented")), ("id", text(id)), ("parent_case_id", text(parent)),
        ("child_case_ids", strings(children)), ("source_line", integer(line)),
        ("reason", byte_text(reason)),
    ])).collect()
}
