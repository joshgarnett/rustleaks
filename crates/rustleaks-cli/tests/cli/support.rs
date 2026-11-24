//! Fixtures, the process runner and the Bazel runfile resolver.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
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

/// Runs `command` with `bytes` on standard input and returns its output.
pub(crate) fn output_with_stdin(command: &mut Command, bytes: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The command may exit before it reads its input, for example when it
    // refuses an argument; a broken pipe on this write is then expected.
    if let Err(error) = child.stdin.take().unwrap().write_all(bytes) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe, "{error}");
    }
    child.wait_with_output().unwrap()
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

pub(crate) fn tar_named_leaf(name: &[u8], bytes: &[u8]) -> Vec<u8> {
    assert!(name.len() <= 100);
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name);
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| usize::from(*byte)).sum::<usize>();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    let mut archive = header.to_vec();
    archive.extend_from_slice(bytes);
    archive.resize(512 + bytes.len().div_ceil(512) * 512 + 1024, 0);
    archive
}

pub(crate) fn stored_gzip(payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(payload.len()).expect("small synthetic gzip payload");
    let mut bytes = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255, 1];
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&(!length).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&crc32(payload).to_le_bytes());
    bytes.extend_from_slice(&u32::from(length).to_le_bytes());
    bytes
}

fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0_u32, |state, &byte| {
        (0..8).fold(state ^ u32::from(byte), |value, _| {
            (value >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(value & 1))
        })
    })
}

// Minimal stored ZIP writer: a local header, name and data per entry, then
// the central directory and the end of central directory record.
pub(crate) fn stored_zip(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut central = Vec::new();
    for &(name, body) in entries {
        let crc = crc32(body).to_le_bytes();
        let size = u32::try_from(body.len()).unwrap().to_le_bytes();
        let name_size = u16::try_from(name.len()).unwrap().to_le_bytes();
        let offset = u32::try_from(data.len()).unwrap().to_le_bytes();
        let mut local = [0_u8; 30];
        local[..4].copy_from_slice(b"PK\x03\x04");
        local[4..6].copy_from_slice(&20_u16.to_le_bytes());
        local[14..18].copy_from_slice(&crc);
        local[18..22].copy_from_slice(&size);
        local[22..26].copy_from_slice(&size);
        local[26..28].copy_from_slice(&name_size);
        data.extend_from_slice(&local);
        data.extend_from_slice(name);
        data.extend_from_slice(body);
        let mut entry = [0_u8; 46];
        entry[..4].copy_from_slice(b"PK\x01\x02");
        entry[4..6].copy_from_slice(&20_u16.to_le_bytes());
        entry[6..8].copy_from_slice(&20_u16.to_le_bytes());
        entry[16..20].copy_from_slice(&crc);
        entry[20..24].copy_from_slice(&size);
        entry[24..28].copy_from_slice(&size);
        entry[28..30].copy_from_slice(&name_size);
        entry[42..46].copy_from_slice(&offset);
        central.extend_from_slice(&entry);
        central.extend_from_slice(name);
    }
    let mut end = [0_u8; 22];
    end[..4].copy_from_slice(b"PK\x05\x06");
    let count = u16::try_from(entries.len()).unwrap().to_le_bytes();
    end[8..10].copy_from_slice(&count);
    end[10..12].copy_from_slice(&count);
    end[12..16].copy_from_slice(&u32::try_from(central.len()).unwrap().to_le_bytes());
    end[16..20].copy_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
    data.extend_from_slice(&central);
    data.extend_from_slice(&end);
    data
}
