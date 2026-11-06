//! Offline integrity of frozen composite observations.
mod identities;
mod spec;
mod validation;

use std::path::Path;

pub(crate) fn check_composite_corpus(root: &Path) -> Result<(), String> {
    let canonical = spec::load(root)?;
    let outcomes = std::fs::read(root.join("compat/composite-corpus/outcomes-v1.jsonl"))
        .map_err(|error| format!("cannot read composite outcomes: {error}"))?;
    let summary = validation::validate(&canonical, &outcomes)?;
    println!(
        "frozen composite integrity: {} requests, {} findings, {} required attachments, outcomes {}",
        summary.requests, summary.findings, summary.required_findings, summary.outcomes_sha256
    );
    Ok(())
}
