//! Fixtures, the process runner and the Bazel runfile resolver.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub(crate) struct Fixture(pub(crate) PathBuf);

impl Fixture {
    pub(crate) fn new() -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rustleaks-cli-{}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    pub(crate) fn write(&self, path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) {
        let path = self.0.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn command(cwd: &Path) -> Command {
    let mut command = Command::new(rustleaks_executable());
    command
        .current_dir(cwd)
        .env_remove("RUSTLEAKS_CONFIG")
        .env_remove("RUSTLEAKS_CONFIG_TOML")
        .env_remove("GITLEAKS_CONFIG")
        .env_remove("GITLEAKS_CONFIG_TOML");
    let git = git_executable();
    if git.is_absolute() {
        command.env("PATH", git.parent().expect("declared Git has a parent"));
    }
    command
}

pub(crate) fn rustleaks_executable() -> PathBuf {
    resolve_runfile(PathBuf::from(env!("CARGO_BIN_EXE_rustleaks")), "Rustleaks")
}

pub(crate) fn git_executable() -> PathBuf {
    let runfile = std::env::var_os("RUSTLEAKS_TEST_GIT_RUNFILE")
        .map_or_else(|| PathBuf::from("git"), PathBuf::from);
    resolve_runfile(runfile, "Git")
}

pub(crate) fn resolve_runfile(runfile: PathBuf, label: &str) -> PathBuf {
    if runfile.is_absolute() {
        return runfile;
    }
    for root in ["RUNFILES_DIR", "TEST_SRCDIR"] {
        if let Some(root) = std::env::var_os(root) {
            let root = PathBuf::from(root);
            for candidate in [root.join(&runfile), root.join("_main").join(&runfile)] {
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    if let Some(manifest) = std::env::var_os("RUNFILES_MANIFEST_FILE") {
        let key = runfile.to_string_lossy();
        let contents = fs::read_to_string(manifest).expect("read Bazel runfiles manifest");
        let workspace_key = format!("_main/{key}");
        let external_key = key.strip_prefix("../");
        if let Some((_, resolved)) = contents.lines().find_map(|line| {
            let (entry, resolved) = line.split_once(' ')?;
            (entry == key || entry == workspace_key || external_key == Some(entry))
                .then_some((entry, resolved))
        }) {
            return PathBuf::from(resolved);
        }
    }
    if runfile == Path::new("git") {
        return runfile;
    }
    panic!("cannot resolve {label} runfile {}", runfile.display());
}

pub(crate) fn output(cwd: &Path, arguments: &[&str]) -> Output {
    command(cwd).args(arguments).output().unwrap()
}

pub(crate) fn git(cwd: &Path, arguments: &[&str]) {
    git_stdout(cwd, arguments);
}

pub(crate) fn git_stdout(cwd: &Path, arguments: &[&str]) -> String {
    let result = Command::new(git_executable())
        .current_dir(cwd)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "git {:?}: {}",
        arguments,
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8_lossy(&result.stdout).trim().to_owned()
}

/// JSON report rows as (rule, file, start line, secret, commit).
pub(crate) fn report_rows(result: &Output) -> Vec<(String, String, i128, String, String)> {
    json_report_rows(&result.stdout)
}

/// Rows of a JSON report as (rule, file, start line, secret, commit).
pub(crate) fn json_report_rows(report: &[u8]) -> Vec<(String, String, i128, String, String)> {
    let text = |value: &rustleaks_core::model::ByteText| {
        String::from_utf8_lossy(value.as_bytes()).into_owned()
    };
    rustleaks_core::session::Baseline::from_go_json(report)
        .unwrap()
        .entries()
        .iter()
        .map(|row| {
            (
                text(row.rule_id()),
                text(row.file()),
                row.start_line(),
                text(row.secret()),
                text(row.commit()),
            )
        })
        .collect()
}

pub(crate) fn matching_config() -> &'static str {
    "title='fixture'\n[[rules]]\nid='fixture-token'\ndescription='fixture token'\nregex='''token=([A-Z0-9]{4})'''\nsecretGroup=1\nkeywords=['token']\n"
}

pub(crate) fn two_rule_config() -> &'static str {
    "title='fixture'\n[[rules]]\nid='alpha'\ndescription='alpha'\nregex='''alpha=([A-Z0-9]{4})'''\nsecretGroup=1\n[[rules]]\nid='beta'\ndescription='beta'\nregex='''beta=([A-Z0-9]{4})'''\nsecretGroup=1\n"
}

pub(crate) fn no_match_config() -> &'static str {
    "title='fixture'\n[[rules]]\nid='never'\ndescription='never'\nregex='''NEVER_MATCH_THIS_VALUE'''\n"
}

/// Returns a file under `compat/`, from the source tree or Bazel runfiles.
pub(crate) fn compat_file(name: &str) -> PathBuf {
    let local = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../compat")
        .join(name);
    if local.is_file() {
        return local;
    }
    resolve_runfile(PathBuf::from(format!("compat/{name}")), "compat")
}
