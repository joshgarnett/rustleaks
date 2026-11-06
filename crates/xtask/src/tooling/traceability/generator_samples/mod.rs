//! Frozen generator-constructor and randomized sample traceability.

mod json;
mod validate;

use std::path::Path;

pub(super) const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
const CONSTRUCTORS_SHA256: &str =
    "b7f69ca6317157c7ca8015ec897ec82371e6e362067c6c799c61f0c4819cd7c1";
const SAMPLES_SHA256: &str = "b0d1e24c04f88ec3c875bcbd08a6e0cafbabd7f7cf8757af5e385eb83259b750";

/// Check frozen artifact hashes, constructor joins, and sample identity controls.
pub(crate) fn check_generator_samples(corpus: &Path) -> Result<String, String> {
    let constructor_path = corpus.join("constructors-v1.jsonl");
    let sample_path = corpus.join("samples-v1.jsonl");
    require_digest(&constructor_path, CONSTRUCTORS_SHA256, "constructor")?;
    require_digest(&sample_path, SAMPLES_SHA256, "sample")?;

    let frozen_inventory = json::read_jsonl(&constructor_path)?;
    let frozen_samples = json::read_jsonl(&sample_path)?;
    validate::inventory(&frozen_inventory)?;
    validate::samples(&frozen_samples, &frozen_inventory)?;
    validate::negative_identity_control(&frozen_samples)?;

    Ok(format!(
        "verified 6770 frozen generator samples, 222 selected constructors, 220 helper-covered constructors at {REVISION}\n"
    ))
}

fn require_digest(path: &Path, expected: &str, kind: &str) -> Result<(), String> {
    let actual = crate::tooling::support::sha256_file(path).unwrap_or_else(|_| "<missing>".into());
    if actual != expected {
        return Err(format!("frozen {kind} corpus digest mismatch: {actual}"));
    }
    Ok(())
}
