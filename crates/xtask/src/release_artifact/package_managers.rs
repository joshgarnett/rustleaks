//! Homebrew formula and Scoop manifest for a published release.
//!
//! Both point at the release archives on GitHub. The hashes come from the
//! downloaded archives and must match each target's `SHA256SUMS`, so every
//! channel installs the bytes that the release workflow attested.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use semver::Version;
use serde_json::{Value, json};

use super::REPOSITORY;
use crate::tooling::sha256_file;

const DESCRIPTION: &str =
    "Secret scanner for Git repositories, folders, archives and standard input";

/// Homebrew `on_*` blocks and the release target each one installs.
const HOMEBREW_TARGETS: &[(&str, &str, &str)] = &[
    ("on_macos", "on_arm", "aarch64-apple-darwin"),
    ("on_macos", "on_intel", "x86_64-apple-darwin"),
    ("on_linux", "on_arm", "aarch64-unknown-linux-gnu"),
    ("on_linux", "on_intel", "x86_64-unknown-linux-gnu"),
];

/// Scoop architecture names and the release target each one installs.
const SCOOP_TARGETS: &[(&str, &str)] = &[
    ("64bit", "x86_64-pc-windows-msvc"),
    ("arm64", "aarch64-pc-windows-msvc"),
];

/// Writes `Formula/rustleaks.rb` and `bucket/rustleaks.json` under `output`
/// from the archives and checksum files in `assets`.
pub(super) fn write(assets: &Path, version: &str, output: &Path) -> Result<(), String> {
    let version = release_version(version)?;
    let mut hashes = Vec::new();
    for target in HOMEBREW_TARGETS
        .iter()
        .map(|(_, _, target)| *target)
        .chain(SCOOP_TARGETS.iter().map(|(_, target)| *target))
    {
        hashes.push((target, archive_sha256(assets, &version, target)?));
    }
    let hash = |target: &str| -> &str {
        hashes
            .iter()
            .find_map(|(candidate, sha256)| (*candidate == target).then_some(sha256.as_str()))
            .expect("every target was hashed")
    };
    let formula = homebrew_formula(&version, hash);
    let manifest = scoop_manifest(&version, hash);
    super::prepare_output_directory(output)?;
    for (path, contents) in [
        ("Formula/rustleaks.rb", formula),
        ("bucket/rustleaks.json", manifest),
    ] {
        let path = output.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        fs::write(&path, contents)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    }
    println!("wrote the Homebrew formula and Scoop manifest for {version}");
    Ok(())
}

/// Fails when `next` is older than `current`, so a channel never moves back.
pub(super) fn check_upgrade(current: &str, next: &str) -> Result<(), String> {
    let current = Version::parse(current)
        .map_err(|error| format!("published version {current:?} is not semver: {error}"))?;
    let next = Version::parse(next)
        .map_err(|error| format!("new version {next:?} is not semver: {error}"))?;
    if next < current {
        return Err(format!(
            "{next} is older than the published {current}; the channel would move back"
        ));
    }
    println!("{next} is not older than the published {current}");
    Ok(())
}

fn release_version(version: &str) -> Result<String, String> {
    let parsed = Version::parse(version)
        .map_err(|error| format!("release version {version:?} is not semver: {error}"))?;
    if !parsed.build.is_empty() || parsed.to_string() != version {
        return Err(format!(
            "release version {version:?} must be a plain semver version without build metadata"
        ));
    }
    Ok(version.to_owned())
}

fn stem(version: &str, target: &str) -> String {
    format!("rustleaks-{version}-{target}")
}

fn archive_url(version: &str, target: &str) -> String {
    format!(
        "{REPOSITORY}/releases/download/v{version}/{}.tar.gz",
        stem(version, target)
    )
}

fn archive_sha256(assets: &Path, version: &str, target: &str) -> Result<String, String> {
    let stem = stem(version, target);
    let archive = format!("{stem}.tar.gz");
    let sha256 = sha256_file(&assets.join(&archive))?;
    let sums_path = assets.join(format!("{stem}.SHA256SUMS"));
    let sums = fs::read_to_string(&sums_path)
        .map_err(|error| format!("cannot read {}: {error}", sums_path.display()))?;
    let expected = format!("{sha256}  {archive}");
    if !sums.lines().any(|line| line == expected) {
        return Err(format!(
            "{archive} has SHA-256 {sha256}, which its SHA256SUMS does not list"
        ));
    }
    Ok(sha256)
}

fn homebrew_formula<'a>(version: &str, hash: impl Fn(&str) -> &'a str) -> String {
    let mut formula = format!(
        "# Written by the Rustleaks release workflow. Do not edit.\n\
         class Rustleaks < Formula\n  \
           desc \"{DESCRIPTION}\"\n  \
           homepage \"{REPOSITORY}\"\n  \
           license \"MIT\"\n"
    );
    let mut previous_os = "";
    for (os, cpu, target) in HOMEBREW_TARGETS {
        if *os != previous_os {
            if !previous_os.is_empty() {
                formula.push_str("  end\n");
            }
            write!(formula, "\n  {os} do\n").expect("writing to a String cannot fail");
            previous_os = os;
        } else {
            formula.push('\n');
        }
        write!(
            formula,
            "    {cpu} do\n      url \"{}\"\n      sha256 \"{}\"\n    end\n",
            archive_url(version, target),
            hash(target)
        )
        .expect("writing to a String cannot fail");
    }
    formula.push_str(
        "  end\n\n  \
         def install\n    \
           bin.install \"rustleaks\"\n    \
           doc.install \"licenses\"\n  \
         end\n\n  \
         test do\n    \
           assert_match version.to_s, shell_output(\"#{bin}/rustleaks --version\")\n  \
         end\n\
         end\n",
    );
    formula
}

fn scoop_manifest<'a>(version: &str, hash: impl Fn(&str) -> &'a str) -> String {
    let mut architecture = serde_json::Map::new();
    let mut autoupdate = serde_json::Map::new();
    for (name, target) in SCOOP_TARGETS {
        architecture.insert(
            (*name).to_owned(),
            json!({
                "url": archive_url(version, target),
                "hash": hash(target),
                "extract_dir": stem(version, target),
            }),
        );
        autoupdate.insert(
            (*name).to_owned(),
            json!({
                "url": archive_url("$version", target),
                "hash": {"url": format!("{REPOSITORY}/releases/download/v$version/{}.SHA256SUMS", stem("$version", target))},
                "extract_dir": stem("$version", target),
            }),
        );
    }
    let manifest = json!({
        "version": version,
        "description": DESCRIPTION,
        "homepage": REPOSITORY,
        "license": "MIT",
        "architecture": Value::Object(architecture),
        "bin": "rustleaks.exe",
        "checkver": "github",
        "autoupdate": {"architecture": Value::Object(autoupdate)},
    });
    let mut text = serde_json::to_string_pretty(&manifest).expect("a JSON value always serializes");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::Value;

    use super::{HOMEBREW_TARGETS, SCOOP_TARGETS, check_upgrade, write};
    use crate::tooling::{ScopedTempDir, sha256_bytes};

    fn assets(version: &str) -> ScopedTempDir {
        let root = ScopedTempDir::new("package-manager-assets").unwrap();
        for target in HOMEBREW_TARGETS
            .iter()
            .map(|(_, _, target)| *target)
            .chain(SCOOP_TARGETS.iter().map(|(_, target)| *target))
        {
            let stem = format!("rustleaks-{version}-{target}");
            let bytes = format!("synthetic archive for {target}").into_bytes();
            fs::write(root.path.join(format!("{stem}.tar.gz")), &bytes).unwrap();
            fs::write(
                root.path.join(format!("{stem}.SHA256SUMS")),
                format!(
                    "{}  {stem}.tar.gz\n{}  {stem}.cdx.json\n",
                    sha256_bytes(&bytes),
                    "0".repeat(64)
                ),
            )
            .unwrap();
        }
        root
    }

    #[test]
    fn writes_formula_and_manifest_bound_to_each_archive() {
        let version = "0.2.0";
        let assets = assets(version);
        let output = assets.path.join("out");
        write(&assets.path, version, &output).unwrap();
        let formula = fs::read_to_string(output.join("Formula/rustleaks.rb")).unwrap();
        let sha = |target: &str| sha256_bytes(format!("synthetic archive for {target}").as_bytes());
        let url = "https://github.com/joshgarnett/rustleaks/releases/download/v0.2.0";
        let expected = format!(
            r##"# Written by the Rustleaks release workflow. Do not edit.
class Rustleaks < Formula
  desc "Secret scanner for Git repositories, folders, archives and standard input"
  homepage "https://github.com/joshgarnett/rustleaks"
  license "MIT"

  on_macos do
    on_arm do
      url "{url}/rustleaks-0.2.0-aarch64-apple-darwin.tar.gz"
      sha256 "{}"
    end

    on_intel do
      url "{url}/rustleaks-0.2.0-x86_64-apple-darwin.tar.gz"
      sha256 "{}"
    end
  end

  on_linux do
    on_arm do
      url "{url}/rustleaks-0.2.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "{}"
    end

    on_intel do
      url "{url}/rustleaks-0.2.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "{}"
    end
  end

  def install
    bin.install "rustleaks"
    doc.install "licenses"
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/rustleaks --version")
  end
end
"##,
            sha("aarch64-apple-darwin"),
            sha("x86_64-apple-darwin"),
            sha("aarch64-unknown-linux-gnu"),
            sha("x86_64-unknown-linux-gnu"),
        );
        assert_eq!(formula, expected);

        let manifest: Value = serde_json::from_str(
            &fs::read_to_string(output.join("bucket/rustleaks.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["version"], "0.2.0");
        assert_eq!(manifest["bin"], "rustleaks.exe");
        assert_eq!(manifest["checkver"], "github");
        for (name, target) in SCOOP_TARGETS {
            let entry = &manifest["architecture"][name];
            assert_eq!(
                entry["url"],
                format!(
                    "https://github.com/joshgarnett/rustleaks/releases/download/v0.2.0/rustleaks-0.2.0-{target}.tar.gz"
                )
            );
            assert_eq!(
                entry["hash"],
                sha256_bytes(format!("synthetic archive for {target}").as_bytes())
            );
            assert_eq!(entry["extract_dir"], format!("rustleaks-0.2.0-{target}"));
            let update = &manifest["autoupdate"]["architecture"][name];
            assert_eq!(
                update["hash"]["url"],
                format!(
                    "https://github.com/joshgarnett/rustleaks/releases/download/v$version/rustleaks-$version-{target}.SHA256SUMS"
                )
            );
        }
        assert!(
            write(&assets.path, version, &output).is_err(),
            "overwrote output"
        );
    }

    #[test]
    fn rejects_unlisted_archives_and_unsafe_versions() {
        let version = "0.2.0-rc.1";
        let assets = assets(version);
        write(&assets.path, version, &assets.path.join("ok")).unwrap();
        for bad in ["v0.2.0-rc.1", "0.2.0+build", "0.2", "0.2.0-rc.1\n"] {
            assert!(
                write(&assets.path, bad, &assets.path.join("bad")).is_err(),
                "accepted {bad:?}"
            );
        }
        fs::write(
            assets
                .path
                .join("rustleaks-0.2.0-rc.1-x86_64-pc-windows-msvc.tar.gz"),
            b"replaced archive",
        )
        .unwrap();
        let error = write(&assets.path, version, &assets.path.join("changed")).unwrap_err();
        assert!(error.contains("SHA256SUMS does not list"), "{error}");
    }

    #[test]
    fn channels_never_move_back() {
        check_upgrade("0.1.0-alpha.12", "0.2.0").unwrap();
        check_upgrade("0.2.0-rc.1", "0.2.0").unwrap();
        check_upgrade("0.2.0", "0.2.0").unwrap();
        check_upgrade("0.2.0", "0.3.0-alpha.1").unwrap();
        assert!(check_upgrade("0.2.0", "0.2.0-rc.1").is_err());
        assert!(check_upgrade("0.2.0", "0.1.9").is_err());
        assert!(check_upgrade("latest", "0.2.0").is_err());
    }
}
