#![forbid(unsafe_code)]
#![allow(missing_docs)]

use rustleaks_core::model::{Finding, Location};
use rustleaks_report::{
    CsvReporter, JsonReporter, JunitReporter, ReportRule, Reporter, SarifReporter,
};

fn simple_finding(description: &str, start_line: usize, commit: &str) -> Finding {
    Finding::builder()
        .rule_id("test-rule")
        .description(description)
        .location(Location::new(start_line, start_line + 1, 1, 2).unwrap())
        .match_text("line containing secret")
        .secret("a secret")
        .file("auth.py")
        .commit(commit)
        .author(if commit.is_empty() { "" } else { "John Doe" })
        .email(if commit.is_empty() {
            ""
        } else {
            "johndoe@gmail.com"
        })
        .date(if commit.is_empty() { "" } else { "10-19-2003" })
        .message(if commit.is_empty() { "" } else { "opps" })
        .build()
        .unwrap()
}

fn render(reporter: &dyn Reporter, findings: &[Finding]) -> Vec<u8> {
    let mut bytes = Vec::new();
    reporter.write(&mut bytes, findings).unwrap();
    bytes
}

#[test]
fn json_matches_upstream_fixtures_byte_for_byte() {
    let finding = simple_finding("", 1, "0000000000000000");
    assert_eq!(
        render(&JsonReporter, &[finding]),
        include_bytes!(
            "../../../compat/fixtures/upstream/testdata/expected/report/json_simple.json"
        )
    );
    assert_eq!(
        render(&JsonReporter, &[]),
        include_bytes!("../../../compat/fixtures/upstream/testdata/expected/report/empty.json")
    );
}

#[test]
fn csv_matches_upstream_fixture_byte_for_byte() {
    let finding = Finding::builder()
        .rule_id("test-rule")
        .location(Location::new(1, 2, 1, 2).unwrap())
        .match_text("line containing secret")
        .secret("a secret")
        .file("auth.py")
        .commit("0000000000000000")
        .author("John Doe")
        .email("johndoe@gmail.com")
        .date("10-19-2003")
        .message("opps")
        .fingerprint("fingerprint")
        .tags(["tag1", "tag2", "tag3"])
        .build()
        .unwrap();
    assert_eq!(
        render(&CsvReporter, &[finding]),
        include_bytes!("../../../compat/fixtures/upstream/testdata/expected/report/csv_simple.csv")
    );
    assert!(render(&CsvReporter, &[]).is_empty());
}

#[test]
fn junit_matches_upstream_fixtures_byte_for_byte() {
    let findings = [
        simple_finding("Test Rule", 1, "0000000000000000"),
        simple_finding("Test Rule", 2, ""),
    ];
    assert_eq!(
        render(&JunitReporter, &findings),
        include_bytes!(
            "../../../compat/fixtures/upstream/testdata/expected/report/junit_simple.xml"
        )
    );
    assert_eq!(
        render(&JunitReporter, &[]),
        include_bytes!(
            "../../../compat/fixtures/upstream/testdata/expected/report/junit_empty.xml"
        )
    );
}

#[test]
fn sarif_matches_upstream_fixture_byte_for_byte() {
    let finding = Finding::builder()
        .rule_id("test-rule")
        .description("A test rule")
        .location(Location::new(1, 2, 1, 2).unwrap())
        .match_text("line containing secret")
        .secret("a secret")
        .file("auth.py")
        .commit("0000000000000000")
        .author("John Doe")
        .email("johndoe@gmail.com")
        .date("10-19-2003")
        .message("opps")
        .tags(["tag1", "tag2", "tag3"])
        .build()
        .unwrap();
    let reporter = SarifReporter::try_new([
        ReportRule::try_new("aws-access-key", "AWS Access Key").unwrap(),
        ReportRule::try_new("pypi", "PyPI upload token").unwrap(),
    ])
    .unwrap();
    assert_eq!(
        render(&reporter, &[finding]),
        include_bytes!(
            "../../../compat/fixtures/upstream/testdata/expected/report/sarif_simple.sarif"
        )
    );
}

#[test]
fn csv_preserves_bytes_and_uses_first_finding_for_link_column() {
    let first = Finding::builder()
        .rule_id([0xff, b',', b'"'])
        .location(Location::new(1, 1, 1, 1).unwrap())
        .link("https://example.test/one")
        .tags(["a b", "c"])
        .build()
        .unwrap();
    let second = Finding::builder()
        .rule_id("second")
        .location(Location::new(2, 2, 1, 1).unwrap())
        .build()
        .unwrap();
    let output = render(&CsvReporter, &[first, second]);
    assert!(output.starts_with(b"RuleID,Commit,File,SymlinkFile"));
    assert!(
        output
            .windows(5)
            .any(|window| window == [b'"', 0xff, b',', b'"', b'"'])
    );
    assert!(output.ends_with(b",\n"));
}
