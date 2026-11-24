//! Opens the file that `--report-path` names.
//!
//! A report can hold secrets, so the file is opened with these rules:
//!
//! - Stream names are opened as a plain path, as `File::create` opens them.
//!   On Unix they are `/dev/stdout`, `/dev/stderr` and `/dev/fd/N`, which
//!   name streams that the process already has open; their symbolic links
//!   are followed. On Windows they are the DOS device names, such as `NUL`
//!   and `CON`, and paths that start with `\\.\`. Windows gives no file
//!   information for a device handle, so the checks below cannot run there.
//! - A path with nothing at it gets a new file. `create_new` does not follow
//!   a symbolic link, and on Unix the new file has mode `0600`.
//! - A symbolic link at the path is refused. Its target is not opened.
//! - An existing regular file is opened without truncation. It is truncated
//!   only after the opened file is checked to be the file that was found at
//!   the path, so a link put in its place after the check is never
//!   truncated. The file keeps its owner and mode.
//! - Another existing entry, such as `/dev/null` or a named pipe, is opened
//!   with the same check and is not truncated.
//!
//! Only the last component of the path is checked. Links in the parent
//! folders are followed.
//!
//! On Unix, the existing entry is opened with `O_CREAT` but without
//! `O_EXCL`, as `File::create` opens it, so the Linux `protected_regular`
//! and `protected_fifos` checks for sticky folders such as `/tmp` still
//! apply. The standard library has no portable `O_NOFOLLOW` or `O_NONBLOCK`.
//! So if a link replaces the entry between the check and the open, the open
//! follows it: a missing target is created empty with mode `0600`, and a
//! named pipe with no reader blocks the open. The identity check then
//! refuses the file, so no report is written to it and nothing is
//! truncated. The same check refuses a new file that was created in place
//! of a removed entry.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::Path;

/// Why a report file was not opened.
#[derive(Debug)]
pub(crate) enum OpenError {
    /// The path is a symbolic link.
    SymbolicLink,
    /// The entry at the path changed between the check and the open.
    Changed,
    /// The operating system refused the operation.
    Io(io::Error),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SymbolicLink => {
                formatter.write_str("the path is a symbolic link, which is not followed")
            }
            Self::Changed => formatter.write_str("the path changed while it was opened"),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl From<io::Error> for OpenError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Fails when the path is a symbolic link that the report would not follow.
///
/// This lets a scan fail before it starts. [`open`] checks again.
pub(crate) fn check(path: &Path) -> Result<(), OpenError> {
    if is_stream_name(path) {
        return Ok(());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(OpenError::SymbolicLink),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Opens the report file at `path` with the rules of this module.
pub(crate) fn open(path: &Path) -> Result<File, OpenError> {
    if is_stream_name(path) {
        return Ok(File::create(path)?);
    }
    match create_new(path) {
        Ok(file) => return Ok(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let expected = fs::symlink_metadata(path)?;
    if expected.file_type().is_symlink() {
        return Err(OpenError::SymbolicLink);
    }
    let file = open_existing(path)?;
    let actual = file.metadata()?;
    if actual.file_type().is_symlink() {
        return Err(OpenError::SymbolicLink);
    }
    if !same_entry(&expected, &actual) {
        return Err(OpenError::Changed);
    }
    if actual.is_file() {
        file.set_len(0)?;
    }
    Ok(file)
}

/// Reports a name that a Unix system gives to a stream of this process.
#[cfg(unix)]
pub(crate) fn is_stream_name(path: &Path) -> bool {
    let Some(path) = path.to_str() else {
        return false;
    };
    matches!(path, "/dev/stdout" | "/dev/stderr")
        || path
            .strip_prefix("/dev/fd/")
            .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
}

/// Reports a Windows device path: one that starts with `\\.\`, or whose last
/// component is a DOS device name.
#[cfg(windows)]
pub(crate) fn is_stream_name(path: &Path) -> bool {
    path.as_os_str()
        .to_str()
        .is_some_and(|text| text.starts_with(r"\\.\"))
        || path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(is_dos_device_name)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn is_stream_name(_path: &Path) -> bool {
    false
}

/// Reports a DOS device name, such as `NUL`, `con` or `COM1.txt`. Windows
/// opens the device for these names in any folder, with any letter case and
/// with any extension.
#[cfg(any(windows, test))]
fn is_dos_device_name(name: &str) -> bool {
    let stem = name.split_once('.').map_or(name, |(stem, _)| stem);
    let stem = stem.to_ascii_uppercase();
    match stem.as_str() {
        "NUL" | "CON" | "AUX" | "PRN" | "CONIN$" | "CONOUT$" => true,
        _ => ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|number| {
                matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
        }),
    }
}

#[cfg(unix)]
fn create_new(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_new(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(windows)]
fn open_existing(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    // FILE_FLAG_OPEN_REPARSE_POINT opens a symbolic link itself, not its
    // target, so the check of the opened file sees the link.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Opens an existing entry with `O_CREAT`, so the kernel checks for sticky
/// folders apply as they do to `File::create`. See the module notes.
#[cfg(unix)]
fn open_existing(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create(true)
        // Truncate only after the identity check.
        .truncate(false)
        .mode(0o600)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_existing(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).open(path)
}

/// Reports whether the opened file is the entry that was found at the path.
#[cfg(unix)]
fn same_entry(expected: &Metadata, actual: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    expected.dev() == actual.dev()
        && expected.ino() == actual.ino()
        && expected.file_type() == actual.file_type()
}

/// Reports whether the opened file has the type of the entry that was found
/// at the path. The standard library has no stable file identity on this
/// platform; the open did not follow a link, and a link is refused above.
#[cfg(not(unix))]
fn same_entry(expected: &Metadata, actual: &Metadata) -> bool {
    expected.file_type() == actual.file_type()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rustleaks-report-file-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn stream_names_are_exact() {
        let expected = cfg!(unix);
        for name in ["/dev/stdout", "/dev/stderr", "/dev/fd/1", "/dev/fd/12"] {
            assert_eq!(is_stream_name(Path::new(name)), expected, "{name}");
        }
        for name in [
            "/dev/fd/",
            "/dev/fd/1a",
            "/dev/fd/../stdout",
            "/dev/./stdout",
            "dev/stdout",
            "/dev/shm/report.json",
            "/dev/null",
        ] {
            assert!(!is_stream_name(Path::new(name)), "{name}");
        }
    }

    #[test]
    fn dos_device_names_match_any_case_and_extension() {
        for name in [
            "NUL", "nul", "Nul.txt", "CON", "con.json", "AUX", "PRN", "COM1", "com9.log", "LPT1",
            "lpt9", "CONIN$", "conout$",
        ] {
            assert!(is_dos_device_name(name), "{name}");
        }
        for name in [
            "NULL",
            "NUL1",
            "COM",
            "COM0",
            "COM10",
            "LPT",
            "LPTX",
            "report.json",
            "xNUL",
            "",
        ] {
            assert!(!is_dos_device_name(name), "{name}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_device_paths_are_stream_names() {
        for name in ["NUL", r"C:\work\nul", r"C:\work\CON.txt", r"\\.\NUL"] {
            assert!(is_stream_name(Path::new(name)), "{name}");
        }
        assert!(!is_stream_name(Path::new(r"C:\work\report.json")));
        check(Path::new("NUL")).unwrap();
        drop(open(Path::new("NUL")).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_file_created_in_place_of_the_checked_one_is_refused() {
        let root = temporary_directory("recreated");
        let path = root.join("report.json");
        fs::write(&path, b"first").unwrap();
        let first = fs::symlink_metadata(&path).unwrap();
        // Keep the first file alive under another name, so the new file
        // cannot reuse its inode number.
        fs::rename(&path, root.join("kept.json")).unwrap();
        fs::write(&path, b"second").unwrap();
        let second = open_existing(&path).unwrap().metadata().unwrap();
        assert!(!same_entry(&first, &second));
        assert!(same_entry(&fs::symlink_metadata(&path).unwrap(), &second));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_new_report_is_created() {
        let root = temporary_directory("new");
        let path = root.join("report.json");
        check(&path).unwrap();
        drop(open(&path).unwrap());
        assert!(fs::symlink_metadata(&path).unwrap().is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_existing_report_is_truncated_and_keeps_its_mode() {
        let root = temporary_directory("existing");
        let path = root.join("report.json");
        fs::write(&path, b"old report contents").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        }
        check(&path).unwrap();
        drop(open(&path).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o640);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_refused_and_its_target_is_kept() {
        let root = temporary_directory("link");
        let target = root.join("target.txt");
        fs::write(&target, b"keep me").unwrap();
        let link = root.join("report.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(check(&link), Err(OpenError::SymbolicLink)));
        assert!(matches!(open(&link), Err(OpenError::SymbolicLink)));
        assert_eq!(fs::read(&target).unwrap(), b"keep me");

        // A link to a missing file is refused and creates nothing.
        let dangling = root.join("dangling.json");
        let missing = root.join("missing.txt");
        std::os::unix::fs::symlink(&missing, &dangling).unwrap();
        assert!(matches!(check(&dangling), Err(OpenError::SymbolicLink)));
        assert!(matches!(open(&dangling), Err(OpenError::SymbolicLink)));
        assert!(!missing.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_device_is_opened_without_a_new_file() {
        let path = Path::new("/dev/null");
        check(path).unwrap();
        let metadata = open(path).unwrap().metadata().unwrap();
        assert!(!metadata.is_file());
    }
}
