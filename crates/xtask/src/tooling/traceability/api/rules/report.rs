//! Finding and reporter disposition rules.

use super::super::inventory::Record;
use super::super::model::{Attrs, attrs};
use super::member;

const EVIDENCE: &str = "crates/rustleaks-report/src; crates/rustleaks-report/tests; compat/report-corpus; cargo xtask report-check";

pub(super) fn annotation(record: &Record) -> Result<Attrs, String> {
    let name = record.name.as_str();
    let owner = record.owner.as_str();
    let kind = record.kind.as_str();
    if owner == "Finding" || (kind == "type" && name == "Finding") {
        return finding(record);
    }
    if owner == "RequiredFinding" || (kind == "type" && name == "RequiredFinding") {
        return Ok(model(
            "report.required-finding-model",
            "rustleaks_core::RequiredFinding",
            &["MODEL-001", "MODEL-003"],
        ));
    }
    if ["CWE", "CWE_DESCRIPTION"].contains(&name) {
        return Ok(attrs("equivalent-public-api", "report.cwe-metadata", "rustleaks-report", "lib",
            format!("rustleaks_report::{name}"), "public",
            "Reporter consumers may use the same stable CWE metadata constants; they do not belong in core.",
            "findings-and-reports").links(&["TM-ALL-001", "REPORT-008"]).tested(EVIDENCE));
    }
    if name == "StdoutReportPath" {
        return Ok(attrs(
            "out-of-public-product-scope",
            "report.stdout-routing",
            "rustleaks-cli",
            "report",
            "rustleaks_cli::report::OutputTarget::Stdout",
            "binary-private",
            "Stdout routing is a CLI output-target choice, not a core or reusable reporter constant.",
            "findings-and-reports",
        ));
    }
    let junit = ["TestSuites", "TestSuite", "TestCase", "Failure"];
    if junit.contains(&name) || junit.contains(&owner) {
        return Ok(attrs("compatibility-tooling-private-implementation", "report.junit-dto", "rustleaks-report",
            "junit::dto", format!("rustleaks_report::junit::dto::{}", member(record)), "crate-private",
            "JUnit DTO layout is private serialization machinery; exact XML bytes/shape are the public compatibility contract.",
            "findings-and-reports").links(&["TM-ALL-001", "REPORT-006", "REPORT-007"]).tested(EVIDENCE));
    }
    let sarif = [
        "PartialFingerPrints",
        "Sarif",
        "ShortDescription",
        "FullDescription",
        "Rules",
        "Driver",
        "Tool",
        "Message",
        "ArtifactLocation",
        "Region",
        "Snippet",
        "PhysicalLocation",
        "Locations",
        "Properties",
        "Results",
        "Runs",
    ];
    if sarif.contains(&name) || sarif.contains(&owner) {
        return Ok(attrs("compatibility-tooling-private-implementation", "report.sarif-dto", "rustleaks-report",
            "sarif::dto", format!("rustleaks_report::sarif::dto::{}", member(record)), "crate-private",
            "SARIF DTO names/fields remain private serialization machinery; exact JSON keys and output shape are golden behavior.",
            "findings-and-reports").links(&["TM-ALL-001", "REPORT-008", "REPORT-009"]).tested(EVIDENCE));
    }
    if owner == "TemplateReporter" || name == "TemplateReporter" || name == "NewTemplateReporter" {
        return Ok(attrs("compatibility-shim", "report.template-reporter", "rustleaks-report", "template",
            "rustleaks_report::TemplateReporter", "compatibility-public",
            "The template reporter is public only as a restricted compatibility feature after Go-template semantics and safety pass.",
            "findings-and-reports").links(&["TM-ALL-001", "REPORT-010", "REPORT-011"]).tested(EVIDENCE));
    }
    if owner == "Reporter" || name == "Reporter" {
        return Ok(attrs("idiomatic-public-replacement", "report.reporter-trait", "rustleaks-report", "lib",
            "rustleaks_report::Reporter", "public",
            "A public Reporter trait writes to std::io::Write and returns ReportError while caller retains closing ownership.",
            "findings-and-reports").links(&["TM-ALL-001", "REPORT-001"]).tested(EVIDENCE));
    }
    let reporters = [
        "CsvReporter",
        "JsonReporter",
        "JunitReporter",
        "SarifReporter",
    ];
    if reporters.contains(&name) || reporters.contains(&owner) {
        let method = kind == "method" || (owner == "SarifReporter" && name == "OrderedRules");
        let path_name = if owner.is_empty() { name } else { owner };
        return Ok(attrs(if method { "idiomatic-public-replacement" } else { "equivalent-public-api" },
            "report.public-reporters", "rustleaks-report", "lib", format!("rustleaks_report::{path_name}"), "public",
            if method { "Reusable reporters stay public, but Write uses Rust writer ownership/errors and SARIF receives ordered rule metadata at construction." }
            else { "The reusable reporter type keeps the same role while serialization details remain private." },
            "findings-and-reports").links(&["TM-ALL-001", "REPORT-001", "REPORT-002", "REPORT-004", "REPORT-006", "REPORT-008"]).tested(EVIDENCE));
    }
    Err(format!("unclassified report API: {}", record.key))
}

fn finding(record: &Record) -> Result<Attrs, String> {
    if record.kind == "method" {
        return match record.name.as_str() {
            "PrintRequiredFindings" => Ok(attrs("out-of-public-product-scope", "report.finding-printing",
                "rustleaks-cli", "finding", "rustleaks_cli::finding::print_required", "binary-private",
                "Printing required findings belongs to CLI/report presentation; core exposes queryable required-finding data.",
                "findings-and-reports").links(&["MODEL-003"])),
            "Redact" => Ok(attrs("idiomatic-public-replacement", "report.finding-redaction", "rustleaks-core",
                "model", "rustleaks_core::Finding::redacted", "public",
                "Redaction is a consuming transformation that preserves immutable caller state and reproduces the pinned byte-oriented mutation result.",
                "findings-and-reports").links(&["MODEL-003", "RED-001", "RED-002", "RED-003"])
                .tested("crates/rustleaks-core/src/model.rs; crates/rustleaks-core/tests/model.rs; crates/rustleaks-core/tests/composite_corpus.rs; cargo xtask composite-check")),
            "AddRequiredFindings" => Ok(attrs("idiomatic-public-replacement", "report.finding-required", "rustleaks-core",
                "model", "rustleaks_core::Finding::add_required_findings", "public",
                "Required findings are appended through builders/transformations while order and duplicates remain observable.",
                "findings-and-reports").links(&["MODEL-003", "COMP-005"])
                .tested("crates/rustleaks-core/src/model.rs; crates/rustleaks-core/tests/model.rs; crates/rustleaks-core/tests/composite_corpus.rs; cargo xtask composite-check")),
            _ => Err(format!("unclassified Finding method: {}", record.key)),
        };
    }
    Ok(model(
        "report.finding-model",
        "rustleaks_core::Finding",
        &["MODEL-001", "MODEL-003"],
    ))
}

fn model(cluster: &str, path: &str, links: &[&str]) -> Attrs {
    attrs("equivalent-public-api", cluster, "rustleaks-core", "model", path, "public",
        "The byte-preserving Rust core model has the same observable data role, with validated builders and read-only access instead of mutable public fields.",
        "findings-and-reports").links(links).tested("crates/rustleaks-core/tests/model.rs")
}
