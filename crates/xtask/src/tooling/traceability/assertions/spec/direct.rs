//! Direct assertion rows whose upstream tests do not use shared sample tables.

#[path = "direct/report.rs"]
mod report;

use super::super::{Json, array, boolean, float, integer, object, record, strings, text};

pub(super) fn add_direct_rows(rows: &mut Vec<Json>) {
    add_allowlist_predicates(rows);
    add_allowlist_validation(rows);
    add_baseline(rows);
    add_location(rows);
    add_staged_source(rows);
    add_symlink_source(rows);
    add_ignore_normalization(rows);
    report::add_report_rows(rows);
}

fn add_allowlist_predicates(rows: &mut Vec<Json>) {
    let source = "config/allowlist_test.go";
    for (index, (id, line, commits, query, value)) in [
        ("AS-CFG-COMMIT-01", 20, &["commitA"][..], "commitA", true),
        ("AS-CFG-COMMIT-02", 27, &["commitB"][..], "commitA", false),
        ("AS-CFG-COMMIT-03", 34, &["commitB"][..], "", false),
    ]
    .into_iter()
    .enumerate()
    {
        rows.push(record(
            id,
            "TM-0028",
            source,
            line,
            &format!("tests[{index}]"),
            "config-allowlist",
            "public-api",
            object([
                ("operation", text("CommitAllowed")),
                ("commits", strings(commits)),
                ("query", text(query)),
            ]),
            object([("kind", text("bool")), ("value", boolean(value))]),
            Vec::new(),
        ));
    }
    for (index, (id, line, secret, value)) in [
        ("AS-CFG-REGEX-01", 54, "a secret: matchthis, done", true),
        ("AS-CFG-REGEX-02", 61, "a secret", false),
    ]
    .into_iter()
    .enumerate()
    {
        rows.push(record(
            id,
            "TM-0033",
            source,
            line,
            &format!("tests[{index}]"),
            "config-allowlist",
            "public-api",
            object([
                ("operation", text("RegexAllowed")),
                ("regex", text("matchthis")),
                ("secret", text(secret)),
            ]),
            object([("kind", text("bool")), ("value", boolean(value))]),
            Vec::new(),
        ));
    }
    for (index, (id, line, path, value)) in [
        ("AS-CFG-PATH-01", 80, "a path", true),
        ("AS-CFG-PATH-02", 87, "a ???", false),
    ]
    .into_iter()
    .enumerate()
    {
        rows.push(record(
            id,
            "TM-0032",
            source,
            line,
            &format!("tests[{index}]"),
            "config-allowlist",
            "public-api",
            object([
                ("operation", text("PathAllowed")),
                ("regex", text("path")),
                ("path", text(path)),
            ]),
            object([("kind", text("bool")), ("value", boolean(value))]),
            Vec::new(),
        ));
    }
}

fn add_allowlist_validation(rows: &mut Vec<Json>) {
    let source = "config/allowlist_test.go";
    rows.push(implemented(record(
        "AS-CFG-VALIDATE-EMPTY", "TM-0072", source, 106, "tests[empty conditions]",
        "config-allowlist-validation", "public-api", object([("allowlist", object([]))]),
        object([
            ("kind", text("exact-error-and-state")),
            ("error", text("must contain at least one check for: commits, paths, regexes, or stopwords")),
            ("allowlist", object([])),
        ]), Vec::new(),
    ), "config_compile_002_validates_and_normalizes_rules", "crates/rustleaks-core/tests/config.rs"));
    rows.push(implemented(
        record(
            "AS-CFG-VALIDATE-DEDUP",
            "TM-0072",
            source,
            110,
            "tests[deduplicated commits and stopwords]",
            "config-allowlist-validation",
            "public-api",
            object([
                ("commits", strings(&["commitA", "commitB", "commitA"])),
                (
                    "stopwords",
                    strings(&["stopwordA", "stopwordB", "stopwordA"]),
                ),
            ]),
            object([
                ("kind", text("no-error-normalized-sets")),
                ("error", Json::Null),
                ("commits_unordered", strings(&["commita", "commitb"])),
                ("stopwords_unordered", strings(&["stopworda", "stopwordb"])),
            ]),
            Vec::new(),
        ),
        "config_compile_002_validates_and_normalizes_rules",
        "crates/rustleaks-core/tests/config.rs",
    ));
}

fn add_baseline(rows: &mut Vec<Json>) {
    let baseline = "detect/baseline_test.go";
    for (index, (id, line, path, error, fixtures)) in [
        (
            "AS-BASELINE-LOAD-CSV",
            162,
            "../testdata/baseline/baseline.csv",
            "the format of the file ../testdata/baseline/baseline.csv is not supported",
            &["FIX-0014"][..],
        ),
        (
            "AS-BASELINE-LOAD-SARIF",
            166,
            "../testdata/baseline/baseline.sarif",
            "the format of the file ../testdata/baseline/baseline.sarif is not supported",
            &["FIX-0016"][..],
        ),
        (
            "AS-BASELINE-LOAD-MISSING",
            170,
            "../testdata/baseline/notfound.json",
            "could not open ../testdata/baseline/notfound.json",
            &[][..],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        rows.push(record(
            id,
            "TM-0127",
            baseline,
            line,
            &format!("tests[{index}]"),
            "baseline-load",
            "public-api",
            object([("path", text(path))]),
            object([("kind", text("exact-error")), ("error", text(error))]),
            fixtures.iter().map(|value| text(*value)).collect(),
        ));
    }
    for (index, (id, line, finding, base)) in [
        (
            "AS-BASELINE-IGNORE-01",
            189,
            object([("author", text("a")), ("commit", text("5"))]),
            object([("author", text("a")), ("commit", text("5"))]),
        ),
        (
            "AS-BASELINE-IGNORE-FINGERPRINT",
            204,
            object([
                ("author", text("a")),
                ("commit", text("5")),
                ("fingerprint", text("a")),
            ]),
            object([
                ("author", text("a")),
                ("commit", text("5")),
                ("fingerprint", text("b")),
            ]),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        rows.push(record(
            id,
            "TM-0139",
            baseline,
            line,
            &format!("tests[{index}]"),
            "baseline-suppression",
            "oracle-adapter-or-public-e2e",
            object([("finding", finding), ("baseline", array([base]))]),
            object([("kind", text("count")), ("value", integer(0))]),
            Vec::new(),
        ));
    }
}

fn add_location(rows: &mut Vec<Json>) {
    let location = "detect/location_test.go";
    for (index, (id, line, span, values)) in [
        (
            "AS-LOCATION-01",
            17,
            &[35, 38][..],
            &[1, 36, 1, 38, 0, 40][..],
        ),
        (
            "AS-LOCATION-02",
            34,
            &[40, 44][..],
            &[2, 1, 2, 4, 40, 56][..],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let row = record(
            id,
            "TM-0138",
            location,
            line,
            &format!("tests[{index}]"),
            "detector-location",
            "oracle-adapter",
            object([
                (
                    "line_pairs",
                    array([[0, 39], [40, 55], [56, 57]].map(|pair| array(pair.map(integer)))),
                ),
                ("span", array(span.iter().copied().map(integer))),
                ("fragment", text("")),
            ]),
            object([
                ("kind", text("location")),
                (
                    "field_order",
                    strings(&[
                        "start_line",
                        "start_column",
                        "end_line",
                        "end_column",
                        "start_line_index",
                        "end_line_index",
                    ]),
                ),
                ("values", array(values.iter().copied().map(integer))),
            ]),
            Vec::new(),
        );
        rows.push(implemented(
            row,
            "engine::tests::upstream_location_matches_pinned_helper_assertions",
            "crates/rustleaks-core/src/engine.rs",
        ));
    }
}

fn add_staged_source(rows: &mut Vec<Json>) {
    let finding = object([
        ("rule_id", text("aws-access-key")),
        ("description", text("AWS Access Key")),
        ("start_line", integer(7)),
        ("end_line", integer(7)),
        ("start_column", integer(18)),
        ("end_column", integer(37)),
        (
            "line",
            text("\n\taws_token2 := \"AKIALALEMEL33243OLIA\" // this one is not"),
        ),
        ("match", text("AKIALALEMEL33243OLIA")),
        ("secret", text("AKIALALEMEL33243OLIA")),
        ("file", text("api/api.go")),
        ("symlink_file", text("")),
        ("commit", text("")),
        ("entropy", float(3.084_183_7)),
        ("author", text("")),
        ("email", text("")),
        ("date", text("0001-01-01T00:00:00Z")),
        ("message", text("")),
        ("tags", strings(&["key", "AWS"])),
        ("fingerprint", text("api/api.go:aws-access-key:7")),
        ("link", text("")),
    ]);
    let mut fixtures = vec![text("FIX-0034")];
    fixtures.extend((161..=213).map(|number| text(format!("FIX-{number:04}"))));
    rows.push(record(
        "AS-DETECT-STAGED-01",
        "TM-0137",
        "detect/detect_test.go",
        1328,
        "tests[0]",
        "source-git-staged",
        "public-integration",
        object([
            ("config", text("simple")),
            ("source", text("../testdata/repos/staged")),
            ("git_metadata_name", text("dotGit")),
            ("isolated_copy_required", boolean(true)),
        ]),
        object([
            ("kind", text("finding-multiset")),
            ("count", integer(1)),
            ("findings", array([finding])),
        ]),
        fixtures,
    ));
}

fn add_symlink_source(rows: &mut Vec<Json>) {
    let symlink_finding = object([
        ("rule_id", text("apkey")),
        ("description", text("Asymmetric Private Key")),
        ("start_line", integer(1)),
        ("end_line", integer(1)),
        ("start_column", integer(1)),
        ("end_column", integer(35)),
        ("match", text("-----BEGIN OPENSSH PRIVATE KEY-----")),
        ("secret", text("-----BEGIN OPENSSH PRIVATE KEY-----")),
        ("line", text("-----BEGIN OPENSSH PRIVATE KEY-----")),
        (
            "file",
            text("../testdata/repos/symlinks/source_file/id_ed25519"),
        ),
        (
            "symlink_file",
            text("../testdata/repos/symlinks/file_symlink/symlinked_id_ed25519"),
        ),
        ("commit", text("")),
        ("entropy", float(3.587_164)),
        ("author", text("")),
        ("email", text("")),
        ("date", text("")),
        ("message", text("")),
        ("tags", strings(&["key", "AsymmetricPrivateKey"])),
        (
            "fingerprint",
            text("../testdata/repos/symlinks/source_file/id_ed25519:apkey:1"),
        ),
        ("link", text("")),
    ]);
    rows.push(record(
        "AS-DETECT-SYMLINK-01",
        "TM-0126",
        "detect/detect_test.go",
        2127,
        "tests[0]",
        "source-symlink",
        "public-integration",
        object([
            ("config", text("simple")),
            ("source", text("../testdata/repos/symlinks/file_symlink")),
            ("follow_symlinks", boolean(true)),
        ]),
        object([
            ("kind", text("finding-multiset")),
            ("count", integer(1)),
            ("findings", array([symlink_finding])),
        ]),
        ["FIX-0034", "FIX-0214", "FIX-0215"].map(text).to_vec(),
    ));
}

fn add_ignore_normalization(rows: &mut Vec<Json>) {
    rows.push(record(
        "AS-IGNORE-NORMALIZE-01", "TM-0146", "detect/detect_test.go", 2461, "single-test",
        "ignore-normalization", "oracle-adapter", object([("path", text("../testdata/gitleaksignore/.windowspaths"))]),
        object([
            ("kind", text("unordered-exact-set")), ("count", integer(3)),
            ("values", strings(&[
                "foo/bar/gitleaks-false-positive.yaml:aws-access-token:4",
                "foo/bar/gitleaks-false-positive.yaml:aws-access-token:5",
                "b55d88dc151f7022901cda41a03d43e0e508f2b7:test_data/test_local_repo_three_leaks.json:aws-access-token:73",
            ])),
        ]), vec![text("FIX-0077")],
    ));
}

pub(super) fn implemented(mut row: Json, test: &str, evidence: &str) -> Json {
    row.set("rust_test", text(test))
        .expect("record has rust_test");
    row.set("rust_evidence", text(evidence))
        .expect("record has rust_evidence");
    row.set("status", text("implemented"))
        .expect("record has status");
    row
}
