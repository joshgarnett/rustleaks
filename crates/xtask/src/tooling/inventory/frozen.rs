//! Parse immutable historical identities without rediscovering upstream code.
use super::model::{
    Constructor, Fixture, FixturePayload, Inventory, SourceLocation, TestEvent, TestFile,
};
use super::records::{Record, json_string, json_strings, required, section_records};
use std::collections::BTreeMap;

pub(super) fn load(manifest: &str) -> Result<Inventory, String> {
    let packages = section_records(manifest, "api_package")
        .iter()
        .map(|row| text(row, "name"))
        .collect::<Result<Vec<_>, _>>()?;
    let test_files = section_records(manifest, "test_file")
        .iter()
        .map(|row| {
            Ok(TestFile {
                path: text(row, "path")?,
                tests: json_strings(
                    required(row, "top_level_names", "test_file")?,
                    "test_file names",
                )?,
                benchmarks: json_strings(
                    required(row, "benchmark_names", "test_file")?,
                    "benchmark names",
                )?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut tests = BTreeMap::new();
    let mut events = Vec::new();
    for row in section_records(manifest, "case") {
        let name = text(&row, "go_name")?;
        if required(&row, "top_level", "case")? == "true" {
            tests.insert(name.clone(), source(&row)?);
        }
        events.push(TestEvent {
            name,
            package: text(&row, "package")?,
        });
    }
    let benchmarks = section_records(manifest, "benchmark")
        .iter()
        .map(|row| Ok((text(row, "go_name")?, source(row)?)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let constructors = section_records(manifest, "generator_constructor")
        .iter()
        .map(|row| {
            Ok(Constructor {
                name: text(row, "name")?,
                source: source(row)?,
                helper: text(row, "helper")?,
                rule_id: text(row, "rule_id")?,
                selected: text(row, "disposition")? == "selected-default",
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let fixtures = section_records(manifest, "fixture")
        .iter()
        .map(|row| {
            let payload = match text(row, "kind")?.as_str() {
                "regular" => FixturePayload::Regular {
                    size: required(row, "size", "fixture")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                    sha256: text(row, "sha256")?,
                },
                "symlink" => FixturePayload::Symlink {
                    target: text(row, "symlink_target")?,
                },
                kind => return Err(format!("invalid frozen fixture kind {kind}")),
            };
            Ok(Fixture {
                path: text(row, "source")?,
                mode: text(row, "mode")?,
                payload,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Inventory {
        packages,
        test_files,
        tests,
        benchmarks,
        events,
        constructors,
        fixtures,
    })
}
fn text(row: &Record, key: &str) -> Result<String, String> {
    json_string(required(row, key, "frozen identity")?, key)
}
fn source(row: &Record) -> Result<SourceLocation, String> {
    Ok(SourceLocation {
        path: text(row, "source")?,
        line: required(row, "source_line", "frozen identity")?
            .parse::<usize>()
            .map_err(|error| error.to_string())?,
    })
}
