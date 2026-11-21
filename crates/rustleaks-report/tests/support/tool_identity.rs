//! The tool identity in SARIF and `JUnit` reports.
//!
//! Upstream fixtures and the frozen report corpus name the tool `gitleaks`.
//! Rustleaks names itself instead. Every other byte of those reports stays
//! the same, so the tests replace exactly this identity and compare the rest
//! of each report byte for byte.

/// SARIF driver members in the upstream fixtures.
const UPSTREAM_SARIF_DRIVER: &str = concat!(
    "     \"name\": \"gitleaks\",\n",
    "     \"semanticVersion\": \"v8.0.0\",\n",
    "     \"informationUri\": \"https://github.com/gitleaks/gitleaks\",\n",
);

/// `JUnit` test suite name attribute in the upstream fixtures.
const UPSTREAM_JUNIT_SUITE: &str = " name=\"gitleaks\" ";

/// SARIF driver members that Rustleaks writes: its name, its package
/// version and its repository.
pub fn rustleaks_sarif_driver() -> String {
    format!(
        concat!(
            "     \"name\": \"rustleaks\",\n",
            "     \"semanticVersion\": \"{}\",\n",
            "     \"informationUri\": \"https://github.com/joshgarnett/rustleaks\",\n",
        ),
        env!("CARGO_PKG_VERSION")
    )
}

/// `JUnit` test suite name attribute that Rustleaks writes.
pub const RUSTLEAKS_JUNIT_SUITE: &str = " name=\"rustleaks\" ";

/// Returns an upstream SARIF or `JUnit` report with the Rustleaks tool
/// identity. Panics unless the upstream identity occurs exactly once.
pub fn with_rustleaks_identity(format: &str, upstream: &[u8]) -> Vec<u8> {
    let (old, new) = match format {
        "sarif" => (UPSTREAM_SARIF_DRIVER.to_owned(), rustleaks_sarif_driver()),
        "junit" => (
            UPSTREAM_JUNIT_SUITE.to_owned(),
            RUSTLEAKS_JUNIT_SUITE.to_owned(),
        ),
        other => panic!("{other} reports have no tool identity"),
    };
    let old = old.as_bytes();
    let starts = upstream
        .windows(old.len())
        .enumerate()
        .filter(|(_, window)| *window == old)
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    assert_eq!(starts.len(), 1, "{}", String::from_utf8_lossy(upstream));
    let start = starts[0];
    let mut report = upstream[..start].to_vec();
    report.extend_from_slice(new.as_bytes());
    report.extend_from_slice(&upstream[start + old.len()..]);
    report
}
