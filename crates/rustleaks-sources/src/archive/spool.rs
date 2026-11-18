//! Bounded storage that gives archive readers random access.
//!
//! ZIP and 7z need random access. An archive that is a file on disk is read
//! through that file. Any other archive input, such as an archive inside
//! another archive, standard input or a Git blob, is copied to a spool first.
//! Small spools stay in memory. Larger ones use an anonymous temporary file
//! with owner-only permissions in the system temporary folder. The file has no
//! name after creation on Unix and is deleted on close on Windows, so it is
//! removed on every path, including errors, cancellation and a killed process.

use std::fs::{File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::stream::{Budget, Failure, INPUT_BUFFER, ReadErrors};
use crate::Cancellation;

/// Spools up to this many bytes in memory before using a temporary file.
pub(crate) const MEMORY_SPOOL_BYTES: usize = 1024 * 1024;

const CREATE_ATTEMPTS: usize = 16;

/// An anonymous temporary file that only the owner can read or write.
pub(crate) struct TempFile {
    file: File,
}

impl TempFile {
    /// Creates the file in `directory`.
    ///
    /// # Errors
    ///
    /// Returns the operating system error when no file can be created.
    pub(crate) fn create(directory: &Path) -> io::Result<Self> {
        let mut last = None;
        for _ in 0..CREATE_ATTEMPTS {
            let path = directory.join(format!(
                "rustleaks-spool-{}-{:016x}",
                std::process::id(),
                random_name()
            ));
            match open_new(&path) {
                Ok(file) => return finish_create(file, &path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not create a unique temporary file",
            )
        }))
    }

    /// Creates the file in the system temporary folder.
    pub(crate) fn create_in_temp_dir() -> io::Result<Self> {
        Self::create(&temp_dir())
    }

    pub(crate) const fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub(crate) fn into_file(self) -> File {
        self.file
    }
}

/// The system temporary folder: `TMPDIR` on Unix, `TMP` or `TEMP` on Windows.
fn temp_dir() -> PathBuf {
    std::env::temp_dir()
}

/// Returns 64 unpredictable bits from the standard library's random hash keys.
fn random_name() -> u64 {
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

#[cfg(unix)]
fn open_new(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(unix)]
fn finish_create(file: File, path: &Path) -> io::Result<TempFile> {
    // Remove the name at once. The open handle keeps the data until it closes.
    if let Err(error) = std::fs::remove_file(path) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(TempFile { file })
}

#[cfg(windows)]
fn open_new(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
    // No sharing: no other handle can open the file while it exists. The
    // per-user temporary folder gives owner-only access.
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE)
        .open(path)
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // Matches the Unix signature.
fn finish_create(file: File, _path: &Path) -> io::Result<TempFile> {
    Ok(TempFile { file })
}

#[cfg(not(any(unix, windows)))]
fn open_new(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn finish_create(file: File, path: &Path) -> io::Result<TempFile> {
    if let Err(error) = std::fs::remove_file(path) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(TempFile { file })
}

/// Bytes copied from a stream, in memory or in a temporary file.
pub(crate) enum Spool {
    Memory(Vec<u8>),
    File(TempFile),
}

/// Collects bytes pushed in chunks, in memory up to `memory_limit` and then
/// in a temporary file, up to `limit` bytes in total.
pub(crate) struct PushSpool {
    memory: Vec<u8>,
    file: Option<TempFile>,
    length: usize,
    limit: usize,
    memory_limit: usize,
}

impl PushSpool {
    pub(crate) const fn new(limit: usize, memory_limit: usize) -> Self {
        Self {
            memory: Vec::new(),
            file: None,
            length: 0,
            limit,
            memory_limit,
        }
    }

    /// Adds `chunk`; returns false, and keeps nothing more, when it does not fit.
    ///
    /// # Errors
    ///
    /// Returns an error when memory or the temporary file cannot grow.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> io::Result<bool> {
        let Some(length) = self
            .length
            .checked_add(chunk.len())
            .filter(|length| *length <= self.limit)
        else {
            return Ok(false);
        };
        if let Some(file) = &mut self.file {
            file.file_mut().write_all(chunk)?;
        } else if length <= self.memory_limit {
            self.memory
                .try_reserve(chunk.len())
                .map_err(|error| io::Error::other(error.to_string()))?;
            self.memory.extend_from_slice(chunk);
        } else {
            let mut file = TempFile::create_in_temp_dir()?;
            file.file_mut().write_all(&self.memory)?;
            file.file_mut().write_all(chunk)?;
            self.memory = Vec::new();
            self.file = Some(file);
        }
        self.length = length;
        Ok(true)
    }

    pub(crate) const fn len(&self) -> usize {
        self.length
    }

    pub(crate) fn finish(self) -> Spool {
        match self.file {
            Some(file) => Spool::File(file),
            None => Spool::Memory(self.memory),
        }
    }
}

/// Why a spool could not be built.
pub(super) enum SpoolError {
    /// The input is larger than the storage that is left.
    Limit,
    /// Reading the input or writing the temporary file failed.
    Failure(Failure),
}

/// A spool whose size counts toward the traversal storage until it drops.
pub(super) struct SpoolGuard<'b> {
    spool: Spool,
    length: usize,
    budget: &'b Budget,
}

impl Drop for SpoolGuard<'_> {
    fn drop(&mut self) {
        self.budget
            .spooled
            .set(self.budget.spooled.get().saturating_sub(self.length));
    }
}

impl SpoolGuard<'_> {
    pub(super) const fn spool(&self) -> &Spool {
        &self.spool
    }
}

/// Copies `reader` to a spool of at most `limit` bytes in total storage.
pub(super) fn spool<'b>(
    reader: &mut dyn Read,
    budget: &'b Budget,
    limit: usize,
    memory_limit: usize,
    cancellation: &dyn Cancellation,
) -> Result<SpoolGuard<'b>, SpoolError> {
    let available = limit.saturating_sub(budget.spooled.get());
    let mut spool = PushSpool::new(available, memory_limit);
    let mut buffer = vec![0_u8; INPUT_BUFFER];
    loop {
        if cancellation.is_cancelled() {
            return Err(SpoolError::Failure(Failure::Cancelled));
        }
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(SpoolError::Failure(Failure::from_io(error))),
        };
        if !spool.push(&buffer[..count]).map_err(write_failure)? {
            return Err(SpoolError::Limit);
        }
    }
    let length = spool.len();
    budget
        .spooled
        .set(budget.spooled.get().saturating_add(length));
    Ok(SpoolGuard {
        spool: spool.finish(),
        length,
        budget,
    })
}

#[allow(clippy::needless_pass_by_value)] // Used as a `map_err` function.
fn write_failure(error: io::Error) -> SpoolError {
    SpoolError::Failure(Failure::Read(format!(
        "could not write the archive spool: {error}"
    )))
}

/// Reads a whole file from its start, through a buffer.
pub(super) fn file_reader(file: &File) -> Result<BufReader<ReadErrors<&File>>, Failure> {
    let mut handle = file;
    handle
        .seek(SeekFrom::Start(0))
        .map_err(|error| Failure::Read(error.to_string()))?;
    Ok(BufReader::with_capacity(INPUT_BUFFER, ReadErrors(handle)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporary_files_have_no_name_and_owner_only_access() {
        let directory =
            std::env::temp_dir().join(format!("rustleaks-spool-test-{:016x}", random_name()));
        std::fs::create_dir(&directory).unwrap();
        let mut temp = TempFile::create(&directory).unwrap();
        temp.file_mut().write_all(b"spooled bytes").unwrap();
        let mut text = String::new();
        file_reader(temp.file())
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "spooled bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = temp.file().metadata().unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            // The name is gone while the file is still open.
            assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        }
        drop(temp);
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn spools_stay_in_memory_until_the_memory_limit_and_count_toward_storage() {
        let budget = Budget::new(usize::MAX);
        let cancellation = crate::CancellationToken::new();
        let small = spool(&mut [7_u8; 10].as_slice(), &budget, 100, 16, &cancellation)
            .ok()
            .unwrap();
        assert!(matches!(small.spool(), Spool::Memory(bytes) if bytes.len() == 10));
        assert_eq!(budget.spooled.get(), 10);
        let large = spool(&mut [9_u8; 40].as_slice(), &budget, 100, 16, &cancellation)
            .ok()
            .unwrap();
        let Spool::File(file) = large.spool() else {
            panic!("a spool above the memory limit uses a file");
        };
        let mut bytes = Vec::new();
        file_reader(file.file())
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, [9_u8; 40]);
        assert_eq!(budget.spooled.get(), 50);
        // Storage is shared: 50 bytes are in use, so 51 more do not fit.
        assert!(matches!(
            spool(&mut [1_u8; 51].as_slice(), &budget, 100, 16, &cancellation),
            Err(SpoolError::Limit)
        ));
        drop(large);
        drop(small);
        assert_eq!(budget.spooled.get(), 0);
    }
}
