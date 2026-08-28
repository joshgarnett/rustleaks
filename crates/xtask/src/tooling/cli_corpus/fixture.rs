//! Isolated CLI fixtures and per-variant preparation.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use super::TempDir;
use super::process::{self, CASE_TIMEOUT, OUTPUT_LIMIT};

pub(super) const MATCHING_CONFIG: &str = "title='fixture'\n[[rules]]\nid='fixture-token'\ndescription='fixture token'\nregex='''token=([A-Z0-9]{4})'''\nsecretGroup=1\nkeywords=['token']\n";
const NO_MATCH_CONFIG: &str = "title='fixture'\n[[rules]]\nid='never'\ndescription='never'\nregex='''NEVER_MATCH_THIS_VALUE'''\n";
const TWO_RULE_CONFIG: &str = "title='fixture'\n[[rules]]\nid='alpha'\ndescription='alpha'\nregex='''alpha=([A-Z0-9]{4})'''\nsecretGroup=1\n[[rules]]\nid='beta'\ndescription='beta'\nregex='''beta=([A-Z0-9]{4})'''\nsecretGroup=1\n";
const COMPOSITE_CONFIG: &str = "title='fixture'\n[[rules]]\nid='primary-rule'\ndescription='primary'\nregex='''password\\s*=\\s*\"([^\"]+)\"'''\n[[rules.required]]\nid='username-rule'\n[[rules]]\nid='username-rule'\ndescription='username'\nregex='''username\\s*=\\s*\"([^\"]+)\"'''\nskipReport=true\n";
const TEMPLATE: &str = "{{ range . }}{{ .RuleID }}:{{ .Secret }}\\n{{ end }}";

#[derive(Default)]
pub(super) struct Prepared {
    pub(super) env: BTreeMap<String, Vec<u8>>,
    pub(super) stdin: Option<Vec<u8>>,
    pub(super) child_pid_file: Option<String>,
    pub(super) native_path: Option<OsString>,
}

pub(super) fn setup(root: &Path, kind: &str, temporary: &TempDir) -> Result<(), String> {
    write(root, "config.toml", MATCHING_CONFIG.as_bytes())?;
    write(root, "never.toml", NO_MATCH_CONFIG.as_bytes())?;
    write(root, "template.tmpl", TEMPLATE.as_bytes())?;
    match kind {
        "empty" => {}
        "secret-file" | "baseline" => write(root, "secret.txt", b"token=AB12\n")?,
        "aliases" => write(root, "scan/secret.txt", b"token=AB12\n")?,
        "two-rules" => {
            write(root, "two.toml", TWO_RULE_CONFIG.as_bytes())?;
            write(root, "secret.txt", b"alpha=AB12\nbeta=CD34\n")?;
        }
        "composite" => {
            write(root, "composite.toml", COMPOSITE_CONFIG.as_bytes())?;
            write(
                root,
                "secret.txt",
                b"username=\"alice\" password=\"AB12\"\n",
            )?;
        }
        "local-config" => {
            write(root, ".gitleaks.toml", MATCHING_CONFIG.as_bytes())?;
            write(root, "secret.txt", b"token=AB12\n")?;
        }
        "ignores" => {
            write(root, "scan/a.txt", b"token=AB12\n")?;
            write(root, "scan/b.txt", b"token=CD34\n")?;
            write(
                root,
                "scan/.gitleaksignore",
                b"scan/a.txt:fixture-token:1\n",
            )?;
            write(
                root,
                "named.ignore",
                b"scan/b.txt:fixture-token:1\nmalformed\n",
            )?;
        }
        "encoded" => write(root, "encoded.txt", b"dG9rZW49QUIxMnh4eHg=\n")?,
        "archives" => {
            let nested = tar(&[("nested.txt", b"token=CD34\n")]);
            let outer = tar(&[("direct.txt", b"token=AB12\n"), ("nested.tar", &nested)]);
            write(root, "scan/archive.tar", &outer)?;
            write(root, "scan/corrupt.gz", b"\x1f\x8bcorrupt")?;
        }
        "allow-comment" => write(root, "secret.txt", b"token=AB12 # gitleaks:allow\n")?,
        "git" => init_git(root, None, temporary)?,
        "git-remote" => init_git(root, Some("https://github.com/acme/repo.git"), temporary)?,
        "git-unknown-remote" => init_git(
            root,
            Some("https://example.invalid/acme/repo.git"),
            temporary,
        )?,
        "git-malformed-remote" => init_git(root, Some("not a remote"), temporary)?,
        "issues" => {
            write(root, "scan/secret.txt", b"token=AB12\n")?;
            write(root, "scan/bad.gz", b"\x1f\x8bbad")?;
            symlink_missing(root)?;
        }
        "paths" => {
            write(root, "config file.toml", MATCHING_CONFIG.as_bytes())?;
            write(root, "source dir ü/secret file.txt", b"token=AB12\n")?;
            write(root, "source dir ü/C:\\repo\\secret.txt", b"token=CD34\n")?;
        }
        _ => return Err(format!("unknown CLI fixture setup {kind:?}")),
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Preparation variants mirror the explicit versioned fixture matrix.
pub(super) fn prepare(
    root: &Path,
    value: Option<&str>,
    go_binary: &Path,
    fake_git_binary: &Path,
    temporary: &TempDir,
    label: &str,
) -> Result<Prepared, String> {
    let Some(value) = value else {
        return Ok(Prepared::default());
    };
    match value {
        "embedded-secret" => write(root, "aws.txt", b"aws_access_key_id=AKIALALEMEL33243OLIA\n")?,
        "stdin-ignore-union" => {
            write(root, ".gitleaksignore", b":fixture-token:1\n")?;
            write(root, "named.ignore", b"malformed\n")?;
        }
        "valid-baseline" => {
            let args = strings(&[
                "dir",
                "secret.txt",
                "--no-banner",
                "--no-color",
                "-c",
                "config.toml",
                "-r",
                "baseline.json",
                "-f",
                "json",
            ]);
            let result = process::run(
                go_binary,
                &args,
                root,
                &BTreeMap::new(),
                b"",
                temporary,
                &format!("{label}-baseline"),
                CASE_TIMEOUT,
                OUTPUT_LIMIT,
            )?;
            if result.exit != 1 {
                return Err("baseline seed did not find exactly one secret".into());
            }
            let baseline: Value = serde_json::from_slice(
                &fs::read(root.join("baseline.json"))
                    .map_err(|e| format!("cannot read baseline: {e}"))?,
            )
            .map_err(|e| format!("invalid baseline JSON: {e}"))?;
            if baseline.as_array().map(Vec::len) != Some(1) {
                return Err("baseline seed finding count changed".into());
            }
        }
        "malformed-baseline" => write(root, "baseline.json", b"[{broken")?,
        "config-self-secret" => write(
            root,
            "scan/config.toml",
            format!("{MATCHING_CONFIG}# token=AB12\n").as_bytes(),
        )?,
        "outside-baseline-secret" => {
            write(root, "scan/clean.txt", b"clean\n")?;
            write(
                root,
                "other/baseline.json",
                b"[{\"Extra\":\"token=AB12\"}]\n",
            )?;
        }
        "git-config-self-secret" => {
            write(
                root,
                "config.toml",
                format!("{MATCHING_CONFIG}# token=AB12\n").as_bytes(),
            )?;
            git(root, &["add", "config.toml"], temporary, label)?;
            git(
                root,
                &["commit", "--quiet", "--amend", "--no-edit"],
                temporary,
                label,
            )?;
        }
        "windows-logical-exclusions" => {
            write(
                root,
                "C:\\fixture\\config.toml",
                format!("{MATCHING_CONFIG}# token=AB12\n").as_bytes(),
            )?;
            write(root, "scan/clean.txt", b"clean\n")?;
        }
        "dangerous-template" => write(
            root,
            "dangerous.tmpl",
            b"{{ upper \"synthetic-template-value\" }}",
        )?,
        "preexisting-report" => write(root, "report.json", b"preserve-this-report")?,
        "report-directory" => fs::create_dir_all(root.join("report-dir"))
            .map_err(|e| format!("cannot create report-dir: {e}"))?,
        "leading-dash" => write(root, "-source/secret.txt", b"token=AB12\n")?,
        "native-non-utf8" => {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::ffi::OsStringExt as _;
                let native = OsString::from_vec(b"native-\xff.txt".to_vec());
                fs::write(root.join(&native), b"token=AB12\n")
                    .map_err(|e| format!("cannot write native-byte fixture: {e}"))?;
                return Ok(Prepared {
                    native_path: Some(native),
                    ..Prepared::default()
                });
            }
            #[cfg(not(target_os = "linux"))]
            return Ok(Prepared::default());
        }
        _ if value.starts_with("sized:") => {
            let size = number_suffix(value, "sized:")?;
            write(root, "sized.txt", &sized(size, b"token=AB12\n", false)?)?;
        }
        _ if value.starts_with("git-sized:") => {
            let size = number_suffix(value, "git-sized:")?;
            write(root, "secret.txt", &sized(size, b"token=AB12", true)?)?;
            git(root, &["add", "secret.txt"], temporary, label)?;
            git(
                root,
                &["commit", "--quiet", "--amend", "--no-edit"],
                temporary,
                label,
            )?;
        }
        _ if value.starts_with("git-change:") => {
            let mode = &value["git-change:".len()..];
            write(root, "secret.txt", b"token=CD34\n")?;
            if matches!(mode, "staged" | "both") {
                git(root, &["add", "secret.txt"], temporary, label)?;
            }
        }
        _ if value.starts_with("fake-git:") => {
            return fake_git(root, &value["fake-git:".len()..], fake_git_binary);
        }
        _ => return Err(format!("unknown fixture preparation {value:?}")),
    }
    Ok(Prepared::default())
}

fn init_git(root: &Path, remote: Option<&str>, temporary: &TempDir) -> Result<(), String> {
    git(root, &["init", "--quiet"], temporary, "init")?;
    git(
        root,
        &["config", "user.name", "CLI Corpus"],
        temporary,
        "config",
    )?;
    git(
        root,
        &["config", "user.email", "cli@example.invalid"],
        temporary,
        "config",
    )?;
    write(root, "secret.txt", b"token=AB12\n")?;
    git(root, &["add", "secret.txt"], temporary, "add")?;
    git(
        root,
        &["commit", "--quiet", "-m", "initial"],
        temporary,
        "commit",
    )?;
    if let Some(remote) = remote {
        git(
            root,
            &["remote", "add", "origin", remote],
            temporary,
            "remote",
        )?;
    }
    Ok(())
}

fn git(root: &Path, args: &[&str], temporary: &TempDir, label: &str) -> Result<(), String> {
    let env = BTreeMap::from([
        ("GIT_AUTHOR_NAME".into(), b"CLI Corpus".to_vec()),
        ("GIT_AUTHOR_EMAIL".into(), b"cli@example.invalid".to_vec()),
        ("GIT_COMMITTER_NAME".into(), b"CLI Corpus".to_vec()),
        (
            "GIT_COMMITTER_EMAIL".into(),
            b"cli@example.invalid".to_vec(),
        ),
        ("GIT_AUTHOR_DATE".into(), b"2001-02-03T04:05:06Z".to_vec()),
        (
            "GIT_COMMITTER_DATE".into(),
            b"2001-02-03T04:05:06Z".to_vec(),
        ),
    ]);
    process::command(
        Path::new("git"),
        &strings(args),
        root,
        &env,
        temporary,
        &format!("git-{label}"),
        Duration::from_secs(30),
        OUTPUT_LIMIT,
    )?;
    Ok(())
}

fn fake_git(root: &Path, mode: &str, binary: &Path) -> Result<Prepared, String> {
    let relative = if cfg!(windows) {
        "fake-bin/git.exe"
    } else {
        "fake-bin/git"
    };
    let destination = root.join(relative);
    fs::create_dir_all(
        destination
            .parent()
            .ok_or("fake Git destination has no parent")?,
    )
    .map_err(|error| format!("cannot create fake Git directory: {error}"))?;
    fs::copy(binary, &destination)
        .map_err(|error| format!("cannot copy native fake Git helper: {error}"))?;
    let path = format!(
        "{}{}{}",
        root.join("fake-bin").display(),
        if cfg!(windows) { ';' } else { ':' },
        std::env::var("PATH").unwrap_or_default()
    );
    Ok(Prepared {
        env: BTreeMap::from([
            ("PATH".into(), path.into_bytes()),
            (
                "RUSTLEAKS_CLI_FAKE_GIT_MODE".into(),
                mode.as_bytes().to_vec(),
            ),
        ]),
        stdin: None,
        child_pid_file: Some("fake-git.pid".into()),
        native_path: None,
    })
}

fn write(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), String> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    fs::write(&path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn number_suffix(value: &str, prefix: &str) -> Result<usize, String> {
    value[prefix.len()..]
        .parse()
        .map_err(|e| format!("invalid preparation size: {e}"))
}

fn sized(size: usize, marker: &[u8], suffix: bool) -> Result<Vec<u8>, String> {
    if size < marker.len() {
        return Err("invalid sized fixture".into());
    }
    let mut bytes = vec![b'x'; size];
    if suffix {
        bytes[size - marker.len()..].copy_from_slice(marker);
    } else {
        bytes[..marker.len()].copy_from_slice(marker);
    }
    Ok(bytes)
}

fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut result = Vec::new();
    for (name, bytes) in entries {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        octal(&mut header[100..108], 0o644);
        octal(&mut header[108..116], 0);
        octal(&mut header[116..124], 0);
        octal(&mut header[124..136], bytes.len() as u64);
        octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
        octal(&mut header[148..156], checksum);
        result.extend(header);
        result.extend_from_slice(bytes);
        result.resize(result.len().div_ceil(512) * 512, 0);
    }
    result.resize(result.len() + 1024, 0);
    result
}

fn octal(field: &mut [u8], value: u64) {
    let rendered = format!("{:0width$o}\0", value, width = field.len() - 1);
    field.copy_from_slice(rendered.as_bytes());
}

#[cfg(unix)]
fn symlink_missing(root: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink("missing-target", root.join("scan/broken-link"))
        .map_err(|e| format!("cannot make broken link: {e}"))
}

#[cfg(not(unix))]
fn symlink_missing(_root: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Stdio};

    use super::fake_git;

    #[test]
    fn fake_git_pid_file_uses_child_working_directory() {
        let base = std::env::temp_dir().join(format!("cli-fake-git-test-{}", std::process::id()));
        let caller = base.join("caller");
        let fixture = base.join("fixture");
        let helper = base.join("fake-git-helper");
        fs::create_dir_all(&caller).unwrap();
        fs::create_dir_all(&fixture).unwrap();
        fs::write(&helper, b"#!/bin/sh\nprintf '%s' $$ > fake-git.pid\n").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let prepared = fake_git(&fixture, "malformed", &helper).unwrap();
        assert_eq!(prepared.env["RUSTLEAKS_CLI_FAKE_GIT_MODE"], b"malformed");
        let status = Command::new(fixture.join("fake-bin/git"))
            .current_dir(&fixture)
            .env("PWD", &caller)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        assert!(fixture.join(prepared.child_pid_file.unwrap()).is_file());
        assert!(!caller.join("fake-git.pid").exists());
        fs::remove_dir_all(base).unwrap();
    }
}
