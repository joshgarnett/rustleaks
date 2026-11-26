//! Finishes a wheel that Bazel's `py_wheel` built.
//!
//! `py_wheel` writes core metadata 2.1 with a `License:` field and only the
//! license files it was given. A release wheel carries a linked native
//! library, so it also needs the third-party license texts and notices of
//! that library and a `License-Expression` for the whole wheel. This step
//! rewrites `METADATA` to core metadata 2.4, adds the target's notice files
//! from the native notice catalog under `.dist-info/licenses/third-party/`,
//! lists every license file, and writes a new `RECORD`.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use super::{read, read_text, write, zip};

/// The SPDX expression for a wheel and for the linked library: the Rust
/// code (`rustleaks-core` is `MIT AND BSD-3-Clause AND Apache-2.0`, and
/// every other linked crate offers MIT), and the LLVM runtime code that the
/// Rust standard library and the hermetic toolchain link in, under
/// `Apache-2.0 WITH LLVM-exception`. `bindings/python/pyproject.toml` must
/// name the same expression.
pub(super) const LIBRARY_LICENSE: &str =
    "MIT AND BSD-3-Clause AND Apache-2.0 AND Apache-2.0 WITH LLVM-exception";

/// The folder under `.dist-info/licenses/` that holds the notice catalog.
const THIRD_PARTY: &str = "third-party";

/// The project fields of `bindings/python/pyproject.toml` that the wheel
/// metadata takes.
struct Project {
    license: String,
    keywords: Vec<String>,
}

fn project(root: &Path) -> Result<Project, String> {
    let text = read_text(&root.join("bindings/python/pyproject.toml"))?;
    let table = text
        .parse::<toml::Table>()
        .map_err(|error| format!("cannot parse bindings/python/pyproject.toml: {error}"))?;
    let project = table
        .get("project")
        .and_then(toml::Value::as_table)
        .ok_or("bindings/python/pyproject.toml has no [project]")?;
    let license = project
        .get("license")
        .and_then(toml::Value::as_str)
        .ok_or("bindings/python/pyproject.toml has no project.license expression")?
        .to_owned();
    let keywords = project
        .get("keywords")
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(Project { license, keywords })
}

/// Rewrites core metadata 2.1 from `py_wheel` to 2.4: drops `License:`,
/// adds `License-Expression`, `Keywords` and one `License-File` per file,
/// and keeps the description body.
fn rewrite_metadata(
    metadata: &str,
    project: &Project,
    license_files: &[String],
) -> Result<String, String> {
    let (headers, body) = metadata
        .split_once("\n\n")
        .unwrap_or((metadata.trim_end_matches('\n'), ""));
    let mut lines = Vec::new();
    let mut saw_version = false;
    for line in headers.lines() {
        if line.starts_with("Metadata-Version:") {
            lines.push("Metadata-Version: 2.4".to_owned());
            saw_version = true;
        } else if ![
            "License:",
            "License-Expression:",
            "License-File:",
            "Keywords:",
        ]
        .iter()
        .any(|field| line.starts_with(field))
        {
            lines.push(line.to_owned());
        }
    }
    if !saw_version {
        return Err("wheel METADATA has no Metadata-Version".into());
    }
    lines.push(format!("License-Expression: {}", project.license));
    if !project.keywords.is_empty() {
        lines.push(format!("Keywords: {}", project.keywords.join(",")));
    }
    for file in license_files {
        lines.push(format!("License-File: {file}"));
    }
    let mut text = lines.join("\n");
    text.push_str("\n\n");
    text.push_str(body);
    Ok(text)
}

fn record_line(name: &str, bytes: &[u8]) -> String {
    format!(
        "{name},sha256={},{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
        bytes.len()
    )
}

/// Finishes `wheel` for the Rust `target` into `output`, under the same file
/// name, and returns the new path.
pub(super) fn finish(
    root: &Path,
    target: &str,
    wheel: &Path,
    output: &Path,
) -> Result<PathBuf, String> {
    let project = project(root)?;
    if project.license != LIBRARY_LICENSE {
        return Err(format!(
            "bindings/python/pyproject.toml names license {:?}, but the wheel's linked library needs {LIBRARY_LICENSE:?}",
            project.license
        ));
    }
    let notices = crate::release_artifact::target_notice_files(root, target)?;
    finish_with(&project, &notices, wheel, output)
}

fn finish_with(
    project: &Project,
    notices: &std::collections::BTreeMap<String, Vec<u8>>,
    wheel: &Path,
    output: &Path,
) -> Result<PathBuf, String> {
    let name = wheel
        .file_name()
        .ok_or("the wheel path has no file name")?
        .to_owned();
    let entries = zip::read(&read(wheel)?)?;
    let dist_info = entries
        .iter()
        .find_map(|(entry, _)| entry.strip_suffix("/METADATA"))
        .filter(|prefix| prefix.ends_with(".dist-info") && !prefix.contains('/'))
        .ok_or("the wheel has no top-level .dist-info/METADATA")?
        .to_owned();
    let licenses = format!("{dist_info}/licenses/");
    let mut kept = Vec::new();
    let mut metadata = None;
    for (entry, bytes) in entries {
        if entry == format!("{dist_info}/METADATA") {
            metadata = Some(String::from_utf8(bytes).map_err(|_| "METADATA is not UTF-8")?);
        } else if entry != format!("{dist_info}/RECORD")
            && !entry.starts_with(&format!("{licenses}{THIRD_PARTY}/"))
        {
            kept.push((entry, bytes));
        }
    }
    for (path, bytes) in notices {
        let relative = path
            .strip_prefix("licenses/")
            .ok_or_else(|| format!("notice file {path} is not under licenses/"))?;
        kept.push((format!("{licenses}{THIRD_PARTY}/{relative}"), bytes.clone()));
    }
    let mut license_files = kept
        .iter()
        .filter_map(|(entry, _)| entry.strip_prefix(&licenses))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    license_files.sort();
    if !license_files.iter().any(|file| file == "LICENSE") {
        return Err("the wheel has no .dist-info/licenses/LICENSE".into());
    }
    let metadata = rewrite_metadata(
        &metadata.ok_or("the wheel has no METADATA")?,
        project,
        &license_files,
    )?;
    kept.push((format!("{dist_info}/METADATA"), metadata.into_bytes()));
    // Package files first, then .dist-info, with RECORD last, as wheel
    // tools expect.
    kept.sort_by(|left, right| {
        let rank = |entry: &str| entry.starts_with(&format!("{dist_info}/"));
        (rank(&left.0), left.0.clone()).cmp(&(rank(&right.0), right.0.clone()))
    });
    let record_name = format!("{dist_info}/RECORD");
    let mut record = kept
        .iter()
        .map(|(entry, bytes)| record_line(entry, bytes))
        .collect::<Vec<_>>();
    record.push(format!("{record_name},,"));
    let mut record = record.join("\n");
    record.push('\n');
    kept.push((record_name, record.into_bytes()));
    let path = output.join(name);
    write(&path, &zip::write(&kept, true)?)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{LIBRARY_LICENSE, Project, finish_with, rewrite_metadata};
    use crate::bindings::{read, write, zip};
    use crate::tooling::ScopedTempDir;

    fn project() -> Project {
        Project {
            license: LIBRARY_LICENSE.into(),
            keywords: vec!["secret-detection".into(), "security".into()],
        }
    }

    #[test]
    fn metadata_becomes_core_metadata_2_4() {
        let before = "Metadata-Version: 2.1\nName: rustleaks\nLicense: MIT\nVersion: 1.0.0\n\n# Title\n\nBody\n";
        let after =
            rewrite_metadata(before, &project(), &["LICENSE".into(), "NOTICE".into()]).unwrap();
        assert_eq!(
            after,
            format!(
                "Metadata-Version: 2.4\nName: rustleaks\nVersion: 1.0.0\nLicense-Expression: {LIBRARY_LICENSE}\n\
                 Keywords: secret-detection,security\nLicense-File: LICENSE\nLicense-File: NOTICE\n\n# Title\n\nBody\n"
            )
        );
    }

    #[test]
    fn finished_wheels_carry_the_notices_and_a_matching_record() {
        let temp = ScopedTempDir::new("bindings-wheel").unwrap();
        let wheel = temp.path.join("in/rustleaks-1.0.0-py3-none-any.whl");
        let input = zip::write(
            &[
                ("rustleaks/__init__.py".to_owned(), b"".to_vec()),
                (
                    "rustleaks-1.0.0.dist-info/METADATA".to_owned(),
                    b"Metadata-Version: 2.1\nName: rustleaks\nLicense: MIT\n\nReadme\n".to_vec(),
                ),
                (
                    "rustleaks-1.0.0.dist-info/licenses/LICENSE".to_owned(),
                    b"MIT".to_vec(),
                ),
                (
                    "rustleaks-1.0.0.dist-info/RECORD".to_owned(),
                    b"stale".to_vec(),
                ),
            ],
            true,
        )
        .unwrap();
        write(&wheel, &input).unwrap();
        let notices = BTreeMap::from([
            ("licenses/index.json".to_owned(), b"{}".to_vec()),
            (
                "licenses/packages/memchr/COPYING".to_owned(),
                b"text".to_vec(),
            ),
        ]);
        let output = finish_with(&project(), &notices, &wheel, &temp.path.join("out")).unwrap();
        let entries = zip::read(&read(&output).unwrap()).unwrap();
        let names = entries
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "rustleaks/__init__.py",
                "rustleaks-1.0.0.dist-info/METADATA",
                "rustleaks-1.0.0.dist-info/licenses/LICENSE",
                "rustleaks-1.0.0.dist-info/licenses/third-party/index.json",
                "rustleaks-1.0.0.dist-info/licenses/third-party/packages/memchr/COPYING",
                "rustleaks-1.0.0.dist-info/RECORD",
            ]
        );
        let metadata = String::from_utf8(entries[1].1.clone()).unwrap();
        assert!(metadata.contains("License-File: third-party/packages/memchr/COPYING\n"));
        assert!(!metadata.contains("License: MIT"));
        let record = String::from_utf8(entries[5].1.clone()).unwrap();
        assert_eq!(record.lines().count(), 6);
        assert!(record.ends_with("rustleaks-1.0.0.dist-info/RECORD,,\n"));
        assert!(record.contains(
            "rustleaks/__init__.py,sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU,0\n"
        ));
    }
}
