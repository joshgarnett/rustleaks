//! Fresh pinned-Go generation of the composite detector corpus.

mod identities;
mod overlay;
mod process;
mod runner;
mod serialize;
mod spec;
mod validation;

use std::path::Path;

use super::artifacts::GeneratedTree;
use super::support::TempDir;

/// Rebuilds all composite observations and checks the committed exact tree.
pub(crate) fn check_composite_corpus(root: &Path) -> Result<(), String> {
    generate(root, &root.join("compat/composite-corpus"), true)
}

/// Rebuilds the complete composite corpus into an explicit exact-tree root.
pub(crate) fn write_composite_corpus(root: &Path, output_root: &Path) -> Result<(), String> {
    generate(root, output_root, false)
}

fn generate(root: &Path, output_root: &Path, check: bool) -> Result<(), String> {
    let canonical = spec::load(root)?;
    let upstream = root
        .parent()
        .ok_or_else(|| format!("repository root {} has no parent", root.display()))?
        .join("gitleaks");
    let temporary = TempDir::new("composite corpus ü")?;
    let observed = process::observe(root, &upstream, &canonical, &temporary)?;
    let summary = validation::validate(&canonical, &observed)?;
    let readme = spec::rust_readme(&canonical.readme)?;
    let manifest = spec::rust_manifest(&canonical.manifest, &readme)?;

    let mut tree = GeneratedTree::default();
    tree.insert("README.md", readme)?;
    tree.insert("coverage-v1.json", canonical.coverage)?;
    tree.insert("manifest-v1.json", manifest)?;
    tree.insert("negative-controls-v1.json", canonical.negative_controls)?;
    tree.insert("outcomes-v1.jsonl", observed.outcomes)?;
    tree.insert("requests-v1.jsonl", canonical.requests)?;
    tree.write_or_check(output_root, check)?;
    println!(
        "composite corpus: {} requests, {} findings, {} required attachments, outcomes {}",
        summary.requests, summary.findings, summary.required_findings, summary.outcomes_sha256
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::spec;

    #[test]
    fn readme_provenance_is_rust_owned() {
        let ruby = b"env GOCACHE=/private/tmp/rustleaks-composite-oracle-gocache   GOMODCACHE=/private/tmp/rustleaks-go-mod-cache   ruby compat/generate_composite_corpus.rb --check\n";
        let changed = spec::rust_readme(ruby).unwrap();
        assert!(!String::from_utf8(changed).unwrap().contains(".rb"));
    }

    #[test]
    fn rust_provenance_rewrite_is_idempotent() {
        let readme = b"cargo xtask generate composite\ncargo xtask generate composite --check\n";
        assert_eq!(spec::rust_readme(readme).unwrap(), readme);

        let hash = crate::tooling::support::sha256_bytes(readme);
        let manifest = format!("{{\"files\":{{\"README.md\":\"{hash}\"}}}}\n");
        assert_eq!(
            spec::rust_manifest(manifest.as_bytes(), readme).unwrap(),
            manifest.as_bytes()
        );
    }
}
