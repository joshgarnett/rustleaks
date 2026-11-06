//! Offline mechanical identity, disposition, reference, and mutation checks.
mod baselines;
mod controls;
mod frozen;
mod mechanical;
mod model;
mod records;
mod traceability;
use std::fs;
use std::path::Path;

pub(crate) fn check_inventory(root: &Path, candidate: &Path) -> Result<(), String> {
    super::frozen::verify_artifact(root, "compat/test-manifest.toml")?;
    let canonical = read_text(&root.join("compat/test-manifest.toml"))?;
    let candidate = read_text(candidate)?;
    let behavior = read_text(&root.join("compat/behavior-matrix.toml"))?;
    let api = read_text(&root.join("compat/api-dispositions-v1.jsonl"))?;
    let inventory = frozen::load(&canonical)?;
    mechanical::verify(&inventory, &candidate)?;
    baselines::validate(root, &candidate)?;
    traceability::verify(&candidate, &behavior, &api)?;
    controls::run(&inventory, &canonical, &candidate, &behavior, &api)?;
    if canonical != candidate {
        return Err("inventory candidate differs from the immutable historical manifest".into());
    }
    println!(
        "verified frozen identities and mutation controls: 275 cases, 8 benchmarks, 225 constructors, 215 fixtures"
    );
    Ok(())
}
fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}
