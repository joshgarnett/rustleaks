use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use super::model::{
    Constructor, Fixture, FixturePayload, Inventory, MODULE, REVISION, SourceLocation, TestEvent,
    TestFile,
};
use super::process::{capture, git_capture};
use crate::tooling::support::{TempDir, sha256_bytes, sha256_file};

const EXPECTED_FIXTURE_RECORD_SHA256: &str =
    "a29bcb807fc5466fb38bba0134fe6d5f41364e9efeae4980225cc21524fd4ed1";

type ScannedTests = (
    Vec<TestFile>,
    BTreeMap<String, SourceLocation>,
    BTreeMap<String, SourceLocation>,
);

#[allow(clippy::too_many_lines)] // Keep the isolation audit as one sequential transaction.
pub(super) fn discover(root: &Path) -> Result<Inventory, String> {
    let upstream = root
        .parent()
        .ok_or_else(|| format!("repository root {} has no parent", root.display()))?
        .join("gitleaks");
    let temporary = TempDir::new("inventory")?;
    let revision = text(git_capture(
        &upstream,
        &temporary,
        "revision",
        &["rev-parse", "HEAD"],
    )?)?;
    if revision.trim() != REVISION {
        return Err(format!(
            "upstream revision mismatch: expected {REVISION}, got {}",
            revision.trim()
        ));
    }

    let status_before = git_capture(
        &upstream,
        &temporary,
        "status-before",
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    let index_before = git_capture(
        &upstream,
        &temporary,
        "index-before",
        &["ls-files", "-s", "--", "testdata"],
    )?;
    let (test_files, tests, benchmarks) = scan_tests(&upstream)?;
    let events = isolated_test_events(&upstream, &temporary)?;
    let packages = go_packages(&upstream, &temporary)?;
    let constructors = constructors(&upstream)?;
    let fixtures = fixtures(&upstream, &index_before)?;
    let status_after = git_capture(
        &upstream,
        &temporary,
        "status-after",
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    let index_after = git_capture(
        &upstream,
        &temporary,
        "index-after",
        &["ls-files", "-s", "--", "testdata"],
    )?;
    if status_before != status_after || index_before != index_after {
        return Err("dynamic discovery changed the sibling upstream checkout".into());
    }
    let actual = [
        ("packages", packages.len(), 16),
        ("test files", test_files.len(), 19),
        ("top-level tests", tests.len(), 41),
        ("test events", events.len(), 275),
        ("benchmarks", benchmarks.len(), 8),
        ("constructors", constructors.len(), 225),
        (
            "selected constructors",
            constructors.iter().filter(|item| item.selected).count(),
            222,
        ),
        ("fixtures", fixtures.len(), 215),
    ];
    for (label, found, expected) in actual {
        if found != expected {
            return Err(format!(
                "inventory total mismatch for {label}: expected {expected}, got {found}"
            ));
        }
    }
    let records = fixtures
        .iter()
        .filter_map(|fixture| match &fixture.payload {
            FixturePayload::Regular { size, sha256 } => Some(format!(
                "{}\t{}\t{}\t{}\n",
                fixture.path,
                sha256,
                if fixture.mode == "100755" {
                    "755"
                } else {
                    "644"
                },
                size
            )),
            FixturePayload::Symlink { .. } => None,
        })
        .collect::<String>();
    let fixture_record_sha256 = sha256_bytes(records.as_bytes());
    if fixture_record_sha256 != EXPECTED_FIXTURE_RECORD_SHA256 {
        return Err(format!(
            "fixture record digest mismatch: expected {EXPECTED_FIXTURE_RECORD_SHA256}, got {fixture_record_sha256}"
        ));
    }
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

fn scan_tests(upstream: &Path) -> Result<ScannedTests, String> {
    let mut paths = Vec::new();
    visit(upstream, &mut |path| {
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with("_test.go"))
        {
            paths.push(path.to_path_buf());
        }
        Ok(())
    })?;
    paths.sort();
    let mut tests = BTreeMap::new();
    let mut benchmarks = BTreeMap::new();
    let mut files = Vec::new();
    for path in paths {
        let relative = relative(upstream, &path)?;
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let mut file_tests = Vec::new();
        let mut file_benchmarks = Vec::new();
        for (index, line) in source.lines().enumerate() {
            if let Some(name) = go_function(line, "Test") {
                file_tests.push(name.clone());
                tests.insert(
                    name,
                    SourceLocation {
                        path: relative.clone(),
                        line: index + 1,
                    },
                );
            }
            if let Some(name) = go_function(line, "Benchmark") {
                file_benchmarks.push(name.clone());
                benchmarks.insert(
                    name,
                    SourceLocation {
                        path: relative.clone(),
                        line: index + 1,
                    },
                );
            }
        }
        file_tests.sort();
        file_benchmarks.sort();
        files.push(TestFile {
            path: relative,
            tests: file_tests,
            benchmarks: file_benchmarks,
        });
    }
    Ok((files, tests, benchmarks))
}

fn go_function(line: &str, prefix: &str) -> Option<String> {
    let rest = line.strip_prefix("func ")?;
    let end = rest.find('(')?;
    let name = &rest[..end];
    (name.starts_with(prefix)
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_'))
    .then(|| name.to_owned())
}

fn isolated_test_events(upstream: &Path, temporary: &TempDir) -> Result<Vec<TestEvent>, String> {
    let isolated = temporary.path.join("isolated oracle space Ω");
    capture(
        Command::new("git")
            .args(["clone", "--no-local", "--no-checkout", "--quiet"])
            .arg(upstream)
            .arg(&isolated),
        temporary,
        "isolated-clone",
        Duration::from_secs(60),
    )?;
    capture(
        Command::new("git")
            .current_dir(&isolated)
            .args(["checkout", "--detach", "--quiet", REVISION]),
        temporary,
        "isolated-checkout",
        Duration::from_secs(60),
    )?;
    let probe = isolated.join("testdata/.rustleaks-isolation-probe");
    fs::write(&probe, b"temporary isolated write\n")
        .map_err(|error| format!("cannot write isolation probe: {error}"))?;
    if upstream
        .join("testdata/.rustleaks-isolation-probe")
        .exists()
    {
        return Err("isolated write escaped into sibling upstream checkout".into());
    }
    fs::remove_file(&probe).map_err(|error| format!("cannot remove isolation probe: {error}"))?;
    capture(
        configured_go(
            Command::new("go")
                .current_dir(&isolated)
                .args(["mod", "download"]),
            temporary,
        ),
        temporary,
        "go-mod-download",
        Duration::from_secs(300),
    )?;
    capture(
        configured_go(
            Command::new("go")
                .current_dir(&isolated)
                .args(["mod", "verify"]),
            temporary,
        ),
        temporary,
        "go-mod-verify",
        Duration::from_secs(120),
    )?;
    let status = git_capture(
        &isolated,
        temporary,
        "isolated-status-after-download",
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err("downloading isolated oracle modules changed the checkout".into());
    }
    let output = capture(
        configured_go(
            Command::new("go")
                .current_dir(&isolated)
                .args(["test", "-json", "./..."]),
            temporary,
        ),
        temporary,
        "go-test-json",
        Duration::from_secs(300),
    )?;
    let mut found = BTreeSet::new();
    for (index, line) in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        let event: Value = serde_json::from_slice(line)
            .map_err(|error| format!("invalid go test JSON event {}: {error}", index + 1))?;
        if event["Action"] != "pass" || !event["Test"].is_string() {
            continue;
        }
        let package = event["Package"]
            .as_str()
            .ok_or_else(|| format!("event {} lacks Package", index + 1))?;
        let name = event["Test"].as_str().expect("checked above");
        found.insert((
            package
                .strip_prefix(MODULE)
                .unwrap_or(package)
                .trim_start_matches('/')
                .to_owned(),
            name.to_owned(),
        ));
    }
    Ok(found
        .into_iter()
        .map(|(package, name)| TestEvent { package, name })
        .collect())
}

fn go_packages(upstream: &Path, temporary: &TempDir) -> Result<Vec<String>, String> {
    let output = capture(
        configured_go(
            Command::new("go")
                .current_dir(upstream)
                .args(["list", "./..."]),
            temporary,
        ),
        temporary,
        "go-list",
        Duration::from_secs(120),
    )?;
    let mut packages = text(output)?.lines().map(str::to_owned).collect::<Vec<_>>();
    packages.sort();
    Ok(packages)
}

fn configured_go<'a>(command: &'a mut Command, temporary: &TempDir) -> &'a mut Command {
    let module_cache = std::env::var_os("GOMODCACHE").map_or_else(
        || std::env::temp_dir().join(format!("rustleaks-go-mod-cache-{REVISION}")),
        Into::into,
    );
    command
        .env("GOCACHE", temporary.path.join("go cache space Ω"))
        .env("GOMODCACHE", module_cache)
}

fn constructors(upstream: &Path) -> Result<Vec<Constructor>, String> {
    let directory = upstream.join("cmd/generate/config/rules");
    let mut paths = fs::read_dir(&directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("go"))
        .collect::<Vec<_>>();
    paths.sort();
    let mut constructors = Vec::new();
    for path in paths {
        let relative = relative(upstream, &path)?;
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let starts = source
            .match_indices("func ")
            .filter_map(|(offset, _)| {
                let tail = &source[offset + 5..];
                let name_end = tail.find("() *config.Rule")?;
                let name = &tail[..name_end];
                (name.starts_with(|character: char| character.is_ascii_uppercase())
                    && name
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_'))
                .then(|| (offset, name.to_owned()))
            })
            .collect::<Vec<_>>();
        for (index, (offset, name)) in starts.iter().enumerate() {
            let end = starts.get(index + 1).map_or(source.len(), |item| item.0);
            let body = &source[*offset..end];
            let helper = if body.contains("utils.ValidateWithPaths(") {
                "validate_with_paths"
            } else if body.contains("utils.Validate(") {
                "validate"
            } else {
                "none"
            };
            let rule_id = literal_after(body, "RuleID:")?;
            constructors.push(Constructor {
                name: name.clone(),
                source: SourceLocation {
                    path: relative.clone(),
                    line: source[..*offset]
                        .bytes()
                        .filter(|byte| *byte == b'\n')
                        .count()
                        + 1,
                },
                helper: helper.into(),
                rule_id,
                selected: false,
            });
        }
    }
    constructors.sort_by(|left, right| left.name.cmp(&right.name));
    let main = fs::read_to_string(upstream.join("cmd/generate/config/main.go"))
        .map_err(|error| format!("cannot read default generator main: {error}"))?;
    let selected = main
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .filter_map(|line| line.trim().strip_prefix("rules.")?.strip_suffix("(),"))
        .collect::<BTreeSet<_>>();
    for constructor in &mut constructors {
        constructor.selected = selected.contains(constructor.name.as_str());
    }
    let default_config = fs::read_to_string(upstream.join("config/gitleaks.toml"))
        .map_err(|error| format!("cannot read upstream default config: {error}"))?;
    let default_ids = default_config
        .lines()
        .filter_map(|line| line.strip_prefix("id = \"")?.strip_suffix('"'))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let selected_ids = constructors
        .iter()
        .filter(|item| item.selected)
        .map(|item| item.rule_id.clone())
        .collect::<BTreeSet<_>>();
    if selected_ids != default_ids {
        return Err("selected constructor IDs differ from the upstream default TOML".into());
    }
    Ok(constructors)
}

fn literal_after(source: &str, marker: &str) -> Result<String, String> {
    let tail = source
        .split_once(marker)
        .ok_or_else(|| format!("constructor lacks {marker}"))?
        .1
        .trim_start();
    let quoted = tail
        .strip_prefix('"')
        .ok_or_else(|| format!("{marker} is not a literal"))?;
    Ok(quoted
        .split_once('"')
        .ok_or_else(|| format!("unterminated {marker} literal"))?
        .0
        .to_owned())
}

fn fixtures(upstream: &Path, index: &[u8]) -> Result<Vec<Fixture>, String> {
    let modes = text(index.to_vec())?
        .lines()
        .map(|line| {
            let (metadata, path) = line
                .split_once('\t')
                .ok_or_else(|| format!("invalid git index row {line:?}"))?;
            let mode = metadata
                .split_whitespace()
                .next()
                .ok_or_else(|| format!("missing mode in {line:?}"))?;
            Ok((path.to_owned(), mode.to_owned()))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let mut fixtures = Vec::new();
    visit(&upstream.join("testdata"), &mut |path| {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.is_dir() {
            return Ok(());
        }
        let relative = relative(upstream, path)?;
        let mode = modes
            .get(&relative)
            .ok_or_else(|| format!("fixture {relative} is absent from git index"))?
            .clone();
        let payload = if metadata.file_type().is_symlink() {
            FixturePayload::Symlink {
                target: fs::read_link(path)
                    .map_err(|error| format!("cannot read link {}: {error}", path.display()))?
                    .to_string_lossy()
                    .into_owned(),
            }
        } else {
            FixturePayload::Regular {
                size: metadata.len(),
                sha256: sha256_file(path)?,
            }
        };
        fixtures.push(Fixture {
            path: relative,
            mode,
            payload,
        });
        Ok(())
    })?;
    fixtures.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(fixtures)
}

fn visit(
    directory: &Path,
    callback: &mut impl FnMut(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot read entry in {}: {error}", directory.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if entry.file_name() == ".git" {
            continue;
        }
        callback(&path)?;
        if entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?
            .is_dir()
        {
            visit(&path, callback)?;
        }
    }
    Ok(())
}

fn relative(root: &Path, path: &Path) -> Result<String, String> {
    path.strip_prefix(root)
        .map(|value| value.to_string_lossy().replace('\\', "/"))
        .map_err(|error| format!("{} is outside {}: {error}", path.display(), root.display()))
}

fn text(bytes: Vec<u8>) -> Result<String, String> {
    String::from_utf8(bytes).map_err(|error| format!("command emitted non-UTF-8 output: {error}"))
}
