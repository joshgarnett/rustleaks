//! Generate and check packaged native identities and imported-rule provenance.
//!
//! The rules before the generated marker in the provider and connection packs,
//! and their provenance, are pinned by SHA-256 in
//! `native_coverage/reviewed.json`. This module adds the checks that those
//! hashes do not cover: the pack shape and the license files next to the packs.

use std::path::Path;

const DIRECTORY: &str = "crates/rustleaks-core/default";
const PACKS: [&str; 3] = [
    "rustleaks-extra-v1",
    "rustleaks-providers-v1",
    "rustleaks-connections-v1",
];

pub(crate) fn generate(root: &Path, check: bool) -> Result<(), String> {
    super::tokenizer_assets::generate(root, check)?;
    super::native_coverage_assets::generate(root, check)?;
    validate_pack(
        root,
        "rustleaks-providers-v1",
        "Rustleaks provider rules v1",
        &[("source", "LICENSE.betterleaks")],
    )?;
    validate_pack(
        root,
        "rustleaks-connections-v1",
        "Rustleaks connection rules v1",
        &[
            ("source", "LICENSE.kingfisher"),
            ("database_uri_source", "LICENSE.betterleaks"),
        ],
    )?;
    for name in PACKS {
        let pack = root.join(DIRECTORY).join(format!("{name}.toml"));
        let identity = root.join(DIRECTORY).join(format!("{name}.sha256"));
        let digest = super::sha256_file(&pack)?;
        if check {
            let retained = std::fs::read_to_string(&identity)
                .map_err(|error| format!("cannot read native pack identity: {error}"))?;
            if retained != digest {
                return Err(format!(
                    "{name} identity is stale; run xtask generate native-pack-identity"
                ));
            }
        } else {
            std::fs::write(identity, digest)
                .map_err(|error| format!("cannot write native pack identity: {error}"))?;
        }
    }
    Ok(())
}

/// Checks that a pack holds only a title and a rule list, and that each
/// `(provenance object, license file)` pair records the license file's SHA-256.
fn validate_pack(
    root: &Path,
    name: &str,
    title: &str,
    licenses: &[(&str, &str)],
) -> Result<(), String> {
    let directory = root.join(DIRECTORY);
    let source = std::fs::read_to_string(directory.join(format!("{name}.toml")))
        .map_err(|error| format!("cannot read {name}: {error}"))?;
    let config: toml::Value =
        toml::from_str(&source).map_err(|error| format!("invalid {name}: {error}"))?;
    let config = config
        .as_table()
        .ok_or_else(|| format!("{name} must be a table"))?;
    if config.len() != 2
        || config.get("title").and_then(toml::Value::as_str) != Some(title)
        || !config.get("rules").is_some_and(toml::Value::is_array)
    {
        return Err(format!("{name} contains an unreviewed configuration field"));
    }
    let provenance = std::fs::read_to_string(directory.join(format!("{name}.provenance.json")))
        .map_err(|error| format!("cannot read {name} provenance: {error}"))?;
    let provenance: serde_json::Value = serde_json::from_str(&provenance)
        .map_err(|error| format!("invalid {name} provenance: {error}"))?;
    for (object, license) in licenses {
        if provenance[*object]["license_sha256"] != super::sha256_file(&directory.join(license))? {
            return Err(format!("{name} {object} license differs from {license}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_reject_extra_fields_and_changed_licenses() {
        let root = crate::workspace_root().unwrap();
        let licenses = [("source", "LICENSE.betterleaks")];
        let title = "Rustleaks provider rules v1";
        validate_pack(&root, "rustleaks-providers-v1", title, &licenses).unwrap();
        assert!(validate_pack(&root, "rustleaks-providers-v1", "other", &licenses).is_err());
        let wrong = [("source", "LICENSE.kingfisher")];
        assert!(validate_pack(&root, "rustleaks-providers-v1", title, &wrong).is_err());
    }
}
