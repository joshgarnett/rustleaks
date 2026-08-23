//! Frozen generator-constructor and randomized sample traceability.

mod extract;
mod inventory;
mod json;
mod observer;
mod process;
mod validate;

use std::fs;
use std::path::Path;

pub(super) const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
pub(super) const CONFIG_SHA256: &str =
    "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";
const CONSTRUCTORS_SHA256: &str =
    "b7f69ca6317157c7ca8015ec897ec82371e6e362067c6c799c61f0c4819cd7c1";
const SAMPLES_SHA256: &str = "b0d1e24c04f88ec3c875bcbd08a6e0cafbabd7f7cf8757af5e385eb83259b750";

/// Check frozen artifacts and compare their stable identities with a fresh observation.
pub(crate) fn check_generator_samples(upstream: &Path, corpus: &Path) -> Result<String, String> {
    inventory::verify_upstream(upstream)?;
    let constructor_path = corpus.join("constructors-v1.jsonl");
    let sample_path = corpus.join("samples-v1.jsonl");
    require_digest(&constructor_path, CONSTRUCTORS_SHA256, "constructor")?;
    require_digest(&sample_path, SAMPLES_SHA256, "sample")?;

    let frozen_inventory = json::read_jsonl(&constructor_path)?;
    let frozen_samples = json::read_jsonl(&sample_path)?;
    validate::inventory(&frozen_inventory)?;
    validate::samples(&frozen_samples, &frozen_inventory)?;
    validate::negative_identity_control(&frozen_samples)?;

    let current_inventory = inventory::build(upstream)?;
    validate::inventory(&current_inventory)?;
    if current_inventory != frozen_inventory {
        return Err("constructor inventory/source drift".into());
    }
    let current_samples = extract::observations(upstream, &current_inventory)?;
    validate::samples(&current_samples, &current_inventory)?;
    validate::same_identities(&frozen_samples, &current_samples)?;
    let changed = validate::changed_observations(&frozen_samples, &current_samples)?;
    Ok(format!(
        "verified 6770 frozen generator samples, 222 selected constructors, 220 helper-covered constructors at {REVISION}; {changed} fresh observations differed while stable identities matched\n"
    ))
}

/// Regenerate both JSONL files from a fresh, pinned upstream observation.
pub(crate) fn regenerate_generator_samples(
    upstream: &Path,
    corpus: &Path,
) -> Result<String, String> {
    inventory::verify_upstream(upstream)?;
    let records = inventory::build(upstream)?;
    validate::inventory(&records)?;
    let samples = extract::observations(upstream, &records)?;
    validate::samples(&samples, &records)?;
    validate::negative_identity_control(&samples)?;
    fs::create_dir_all(corpus)
        .map_err(|error| format!("cannot create {}: {error}", corpus.display()))?;
    let constructors = json::jsonl(&records)?;
    let sample_bytes = json::jsonl(&samples)?;
    let constructor_path = corpus.join("constructors-v1.jsonl");
    let sample_path = corpus.join("samples-v1.jsonl");
    fs::write(&constructor_path, &constructors)
        .map_err(|error| format!("cannot write {}: {error}", constructor_path.display()))?;
    fs::write(&sample_path, &sample_bytes)
        .map_err(|error| format!("cannot write {}: {error}", sample_path.display()))?;
    Ok(format!(
        "regenerated 6770 generator samples; deterministic observations frozen in {}\nreview and update FROZEN_CONSTRUCTORS_SHA256={}\nreview and update FROZEN_SAMPLES_SHA256={}\n",
        sample_path.display(),
        crate::tooling::support::sha256_bytes(&constructors),
        crate::tooling::support::sha256_bytes(&sample_bytes)
    ))
}

fn require_digest(path: &Path, expected: &str, kind: &str) -> Result<(), String> {
    let actual = crate::tooling::support::sha256_file(path).unwrap_or_else(|_| "<missing>".into());
    if actual != expected {
        return Err(format!("frozen {kind} corpus digest mismatch: {actual}"));
    }
    Ok(())
}
