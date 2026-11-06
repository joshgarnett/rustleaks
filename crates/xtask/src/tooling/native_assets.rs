//! Generate and check the persistent identity of the first-party native pack.

use std::path::Path;

const PACK: &str = "crates/rustleaks-core/default/rustleaks-extra-v1.toml";
const DIGEST: &str = "crates/rustleaks-core/default/rustleaks-extra-v1.sha256";

pub(crate) fn generate(root: &Path, check: bool) -> Result<(), String> {
    let digest = super::sha256_file(&root.join(PACK))?;
    if check {
        let retained = std::fs::read_to_string(root.join(DIGEST))
            .map_err(|error| format!("cannot read native pack identity: {error}"))?;
        if retained != digest {
            return Err(
                "native pack identity is stale; run xtask generate native-pack-identity".into(),
            );
        }
    } else {
        std::fs::write(root.join(DIGEST), digest)
            .map_err(|error| format!("cannot write native pack identity: {error}"))?;
    }
    Ok(())
}
