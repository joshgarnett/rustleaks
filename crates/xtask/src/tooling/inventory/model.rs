use std::collections::BTreeMap;

pub(super) const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
pub(super) const MODULE: &str = "github.com/zricethezav/gitleaks/v8";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SourceLocation {
    pub(super) path: String,
    pub(super) line: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TestFile {
    pub(super) path: String,
    pub(super) tests: Vec<String>,
    pub(super) benchmarks: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TestEvent {
    pub(super) package: String,
    pub(super) name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Constructor {
    pub(super) name: String,
    pub(super) source: SourceLocation,
    pub(super) helper: String,
    pub(super) rule_id: String,
    pub(super) selected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum FixturePayload {
    Regular { size: u64, sha256: String },
    Symlink { target: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Fixture {
    pub(super) path: String,
    pub(super) mode: String,
    pub(super) payload: FixturePayload,
}

#[derive(Debug)]
pub(super) struct Inventory {
    pub(super) packages: Vec<String>,
    pub(super) test_files: Vec<TestFile>,
    pub(super) tests: BTreeMap<String, SourceLocation>,
    pub(super) benchmarks: BTreeMap<String, SourceLocation>,
    pub(super) events: Vec<TestEvent>,
    pub(super) constructors: Vec<Constructor>,
    pub(super) fixtures: Vec<Fixture>,
}
