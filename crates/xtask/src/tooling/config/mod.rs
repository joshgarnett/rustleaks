//! Offline integrity of the frozen configuration corpus.
mod filetree;
mod metadata;
mod spec;
mod validation;

use std::path::Path;

struct Frozen {
    outcomes: Vec<u8>,
    default_config: Vec<u8>,
}

pub(crate) fn check_config_corpus(root: &Path) -> Result<(), String> {
    let canonical = spec::load(root)?;
    let frozen = Frozen {
        outcomes: std::fs::read(root.join("compat/config-corpus/outcomes-v1.jsonl"))
            .map_err(|error| format!("cannot read config outcomes: {error}"))?,
        default_config: canonical.committed_default.clone(),
    };
    let summary = validation::validate_all(&canonical, &frozen)?;
    println!(
        "frozen config integrity: {} cases ({} effective, {} errors), outcomes {}",
        summary.case_count, summary.success_count, summary.error_count, summary.outcomes_sha256
    );
    Ok(())
}
