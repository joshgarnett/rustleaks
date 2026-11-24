use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::num::NonZeroUsize;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use rustleaks_core::config::CompiledConfig;
use rustleaks_core::model::{ByteText, Fragment};

use crate::path::clean_native_path;
use crate::source::emit_issue;
use crate::{
    CallbackError, Cancellation, FileOptions, FileSource, LogicalPath, Source, SourceConfigError,
    SourceControl, SourceError, SourceEvent, SourceIssue, SourceIssueKind, SourceStage,
};

mod readers;

const DEFAULT_MAX_SYMLINK_HOPS: NonZeroUsize = NonZeroUsize::new(64).unwrap();

/// Files and issues that the walk may hold ahead of the callback for each
/// reader thread when `DirectoryOptions::read_threads` is above 1.
const READ_AHEAD_PER_THREAD: usize = 8;

/// The folder name whose plain-text metadata `scan_git_metadata` selects.
const GIT_FOLDER: &str = ".git";
/// Files directly inside a `.git` folder that hold plain-text metadata.
const GIT_METADATA_FILES: &[&str] = &[
    "config",
    "config.worktree",
    "HEAD",
    "FETCH_HEAD",
    "ORIG_HEAD",
    "description",
    "packed-refs",
    ".git-credentials",
    "credentials",
];
/// Folders directly inside a `.git` folder whose files are all selected,
/// except lock files.
const GIT_METADATA_TREES: &[&str] = &["hooks", "info", "logs"];
/// Folder of submodule Git folders. Only their `config` files are selected.
const GIT_MODULES: &str = "modules";
/// Object store folder of a submodule Git folder, in any ASCII case. It is
/// never inspected.
const GIT_OBJECTS: &str = "objects";
/// Index file of a submodule Git folder. It is never inspected.
const GIT_INDEX: &str = "index";
/// Suffix of Git lock files, in any ASCII case. They are never inspected.
const GIT_LOCK_SUFFIX: &str = ".lock";

/// Validated recursive filesystem-source options.
#[derive(Clone, Debug)]
pub struct DirectoryOptions {
    follow_symlinks: bool,
    max_file_size: Option<u64>,
    file_options: FileOptions,
    path_config: Option<Arc<CompiledConfig>>,
    excluded_paths: Vec<ByteText>,
    logical_root: Option<PathBuf>,
    emit_limit_issues: bool,
    scan_git_metadata: bool,
    max_symlink_hops: NonZeroUsize,
    read_threads: NonZeroUsize,
    #[cfg(feature = "archives")]
    archive_options: Option<crate::ArchiveOptions>,
}

impl DirectoryOptions {
    /// Creates options with an exact positive nominal chunk size.
    ///
    /// # Errors
    ///
    /// Returns [`SourceConfigError`] when `chunk_size` is zero.
    pub fn new(chunk_size: usize) -> Result<Self, SourceConfigError> {
        Ok(Self {
            file_options: FileOptions::new(chunk_size)?,
            ..Self::default()
        })
    }

    /// Sets the file assembly policy used by every eligible file and member.
    ///
    /// Complete mode prunes known excluded paths before metadata or symlink
    /// resolution and makes failures obtaining eligible input terminal.
    #[must_use]
    pub const fn file_options(mut self, options: FileOptions) -> Self {
        self.file_options = options;
        self
    }

    /// Enables or disables followed file symlinks.
    #[must_use]
    pub const fn follow_symlinks(mut self, enabled: bool) -> Self {
        self.follow_symlinks = enabled;
        self
    }

    /// Sets an exact inclusive maximum file size in bytes.
    ///
    /// `None` disables the size gate. Equality is scanned.
    #[must_use]
    pub const fn max_file_size(mut self, maximum: Option<u64>) -> Self {
        self.max_file_size = maximum;
        self
    }

    /// Emits recoverable issues when configured size limits skip files.
    ///
    /// The default remains silent so callers that only consume fragments do
    /// not receive command-oriented diagnostics unexpectedly.
    #[must_use]
    pub const fn emit_limit_issues(mut self, enabled: bool) -> Self {
        self.emit_limit_issues = enabled;
        self
    }

    /// Scans plain-text metadata files in `.git` folders that path
    /// allowlists would otherwise skip.
    ///
    /// The default is off, which keeps the pinned traversal: a `.git` folder
    /// that matches a path allowlist is skipped as a whole. When enabled, such
    /// a folder is entered, but only these entries are visited: `config`,
    /// `config.worktree`, `HEAD`, `FETCH_HEAD`, `ORIG_HEAD`, `description`,
    /// `packed-refs`, `.git-credentials` and `credentials` directly inside it;
    /// every file below `hooks`, `info` and `logs` except names ending in
    /// `.lock`; and every file named `config` below `modules`, outside any
    /// `objects` folder. Names alone decide, before any metadata call, so the
    /// object store, index files, pack files and lock files are never listed,
    /// inspected or opened. The `objects` and `.lock` checks ignore ASCII
    /// case, so a submodule named `objects` or `index`, or one whose name ends
    /// in `.lock`, is not covered. The `.git` name match is exact, like the
    /// default path allowlist, so a folder named `.GIT` is not entered by
    /// this option. Each selected entry still passes the path allowlists, the
    /// size limit and the symlink rules, and a `.git` folder that is a
    /// symlink is never entered. A `.git` folder that no path allowlist
    /// matches is walked in full, as before, so the option never removes
    /// input.
    #[must_use]
    pub const fn scan_git_metadata(mut self, enabled: bool) -> Self {
        self.scan_git_metadata = enabled;
        self
    }

    /// Returns whether plain-text `.git` metadata is scanned.
    #[must_use]
    pub const fn scans_git_metadata(&self) -> bool {
        self.scan_git_metadata
    }

    /// Installs immutable compiled configuration for early global path pruning.
    #[must_use]
    pub fn path_config(mut self, config: Arc<CompiledConfig>) -> Self {
        self.path_config = Some(config);
        self
    }

    /// Adds exact normalized logical paths excluded before complete-mode reads.
    ///
    /// File paths are compared after symlink resolution, using the emitted
    /// `FilePath` domain rather than the alias spelling. Archive descendants
    /// retain their full decorated paths. Chunked scans ignore this option.
    #[must_use]
    pub fn exclude_paths(mut self, paths: Vec<ByteText>) -> Self {
        self.excluded_paths.extend(paths);
        self
    }

    /// Maps the physical traversal root to a caller-visible logical root.
    ///
    /// The mapping is applied both to early allowlist checks and emitted
    /// fragment path metadata; filesystem traversal and diagnostics retain
    /// physical paths.
    #[must_use]
    pub fn logical_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.logical_root = Some(root.into());
        self
    }

    /// Sets how many threads open and read the files that the walk finds.
    ///
    /// The default, 1, reads every file on the calling thread. A larger
    /// value starts up to that many reader threads, while the calling thread
    /// walks the tree in the same order and reads archives one at a time.
    /// Events still reach the callback on the calling thread and in walk
    /// order, so fragments, issues, errors and their order do not depend on
    /// this value.
    ///
    /// Each reader thread keeps its own nominal read buffer and builds at
    /// most one fragment at a time. The walk stays at most eight times the
    /// thread count files and issues ahead of the callback, and each of those
    /// holds at most one finished fragment.
    #[must_use]
    pub const fn read_threads(mut self, threads: NonZeroUsize) -> Self {
        self.read_threads = threads;
        self
    }

    /// Enables the optional native archive decorator for discovered files.
    #[cfg(feature = "archives")]
    #[must_use]
    pub fn archives(mut self, options: crate::ArchiveOptions) -> Self {
        self.archive_options = Some(options);
        self
    }
}

impl Default for DirectoryOptions {
    fn default() -> Self {
        Self {
            follow_symlinks: false,
            max_file_size: None,
            file_options: FileOptions::default(),
            path_config: None,
            excluded_paths: Vec::new(),
            logical_root: None,
            emit_limit_issues: false,
            scan_git_metadata: false,
            max_symlink_hops: DEFAULT_MAX_SYMLINK_HOPS,
            read_threads: NonZeroUsize::MIN,
            #[cfg(feature = "archives")]
            archive_options: None,
        }
    }
}

/// Lexically ordered recursive file/directory source.
///
/// Physical paths remain [`PathBuf`] values through discovery and opening.
/// Directory symlinks are never traversed. When enabled, a file symlink emits
/// the resolved target as `FilePath` and its discovered spelling as
/// `SymlinkFile`.
pub struct DirectorySource {
    root: PathBuf,
    options: DirectoryOptions,
}

impl DirectorySource {
    /// Creates a directory source with safe defaults.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            options: DirectoryOptions::default(),
        }
    }

    /// Creates a directory source with explicit validated options.
    #[must_use]
    pub fn with_options(root: impl Into<PathBuf>, options: DirectoryOptions) -> Self {
        Self {
            root: root.into(),
            options,
        }
    }

    /// Sets how many threads read files, as
    /// [`DirectoryOptions::read_threads`] does.
    pub const fn set_read_threads(&mut self, threads: NonZeroUsize) {
        self.options.read_threads = threads;
    }

    /// Returns the physical traversal root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn walk(
        &self,
        path: &Path,
        git_root: Option<&Path>,
        cancellation: &dyn Cancellation,
        sink: &mut dyn WalkSink,
    ) -> Result<SourceControl, SourceError> {
        if cancellation.is_cancelled() {
            return Err(SourceError::Cancelled);
        }

        // Inside an entered `.git` folder, names alone decide what is
        // visited, so the object store and the index are never inspected.
        let git_entry =
            git_root.map(|root| git_metadata_entry(path.strip_prefix(root).unwrap_or(path)));
        if git_entry.is_some_and(|entry| !entry.file && !entry.directory) {
            return Ok(SourceControl::Continue);
        }

        // Complete coverage applies only to the selected path domain. The
        // discovered spelling is known before metadata or symlink resolution.
        // Chunked scans keep their own gate order. A
        // `.git` name that metadata scanning may enter waits for metadata,
        // and stays pruned unless it is a folder.
        let complete_pruned =
            self.options.file_options.complete_target_bytes().is_some() && self.path_allowed(path);
        if complete_pruned && !self.names_git_folder(path, git_root) {
            return Ok(SourceControl::Continue);
        }

        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return sink.issue(io_issue(SourceStage::Metadata, path, &error));
            }
        };

        if metadata.is_dir() {
            if git_entry.is_some_and(|entry| !entry.directory) {
                return Ok(SourceControl::Continue);
            }
            return self.walk_directory(path, git_root, cancellation, sink);
        }
        if complete_pruned || git_entry.is_some_and(|entry| !entry.file) {
            return Ok(SourceControl::Continue);
        }

        // Upstream applies these gates to symlink metadata before resolution.
        if metadata.len() == 0 {
            return Ok(SourceControl::Continue);
        }
        if self
            .options
            .max_file_size
            .is_some_and(|maximum| metadata.len() > maximum)
        {
            if !self.options.emit_limit_issues {
                return Ok(SourceControl::Continue);
            }
            return sink.issue(
                SourceIssue::new(
                    SourceStage::Limit,
                    SourceIssueKind::Limit,
                    Some(path.to_path_buf()),
                    "skipping file: exceeds maximum file size",
                )
                .excluded(),
            );
        }

        let (target, alias) = if metadata.file_type().is_symlink() {
            if !self.options.follow_symlinks {
                return Ok(SourceControl::Continue);
            }
            match self.followed_target(path) {
                Ok(Some(target)) => (target, Some(path.to_path_buf())),
                Ok(None) => return Ok(SourceControl::Continue),
                Err(issue) => return sink.issue(issue),
            }
        } else {
            (path.to_path_buf(), None)
        };

        if self.path_allowed(path) {
            return Ok(SourceControl::Continue);
        }
        if self
            .complete_target_excluded(&target)
            .map_err(SourceError::Callback)?
        {
            return Ok(SourceControl::Continue);
        }
        sink.file(target, alias)
    }

    /// Opens and scans one file that passed every walk check. Reader threads
    /// call this too, so it depends on no walk state.
    fn visit_file(
        &self,
        target: PathBuf,
        alias: Option<PathBuf>,
        nominal: &mut Vec<u8>,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let file = match fs::File::open(&target) {
            Ok(file) => file,
            Err(error) => return emit_issue(io_issue(SourceStage::Open, &target, &error), emit),
        };
        #[cfg(feature = "archives")]
        if let Some(options) = &self.options.archive_options {
            let mut options = options.clone();
            if self.options.file_options.complete_target_bytes().is_some() {
                options = options.exclude_paths(
                    self.archive_exclusions(&target)
                        .map_err(SourceError::Callback)?,
                );
            }
            if let Some(config) = &self.options.path_config {
                options = options.path_config(Arc::clone(config));
            }
            let mut source =
                crate::ArchiveSource::from_file(file, target, self.options.file_options, options);
            if let Some(alias) = alias {
                source = source.with_symlink_path(alias);
            }
            return source.visit_with_buffer(nominal, cancellation, emit);
        }
        let mut source = FileSource::with_options(file, target, self.options.file_options);
        if let Some(alias) = alias {
            source = source.with_symlink_path(alias);
        }
        source.visit_with_buffer(nominal, cancellation, emit)
    }

    fn walk_directory(
        &self,
        path: &Path,
        git_root: Option<&Path>,
        cancellation: &dyn Cancellation,
        sink: &mut dyn WalkSink,
    ) -> Result<SourceControl, SourceError> {
        let mut git_root = git_root;
        if self.path_allowed(path) {
            // An allowlisted `.git` folder is entered only for its selected
            // metadata. Any other allowlisted folder is skipped as before.
            if !self.names_git_folder(path, git_root) {
                return Ok(SourceControl::Continue);
            }
            git_root = Some(path);
        }
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) => return sink.issue(io_issue(SourceStage::Traverse, path, &error)),
        };
        let mut children = Vec::new();
        for entry in entries {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }
            match entry {
                Ok(entry) => {
                    if let Err(error) = children.try_reserve(1) {
                        return sink.issue(SourceIssue::new(
                            SourceStage::Limit,
                            SourceIssueKind::Limit,
                            Some(path.to_path_buf()),
                            format!("could not retain directory entry: {error}"),
                        ));
                    }
                    #[cfg(not(windows))]
                    children.push(entry.file_name());
                    // Windows entries store names inline; owned filenames can
                    // increase retained memory for wide directories.
                    #[cfg(windows)]
                    children.push(entry);
                }
                Err(error) => {
                    let control = sink.issue(io_issue(SourceStage::Traverse, path, &error))?;
                    if control == SourceControl::Stop {
                        return Ok(control);
                    }
                }
            }
        }
        #[cfg(not(windows))]
        children.sort();
        #[cfg(windows)]
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            #[cfg(not(windows))]
            let control = self.walk(&path.join(child), git_root, cancellation, sink)?;
            #[cfg(windows)]
            let control = self.walk(&child.path(), git_root, cancellation, sink)?;
            if control == SourceControl::Stop {
                return Ok(control);
            }
        }
        Ok(SourceControl::Continue)
    }

    /// Whether metadata scanning may enter `path`, judged by name only. The
    /// name comparison is exact, as in the default `.git` path allowlist.
    /// Callers enter only a path whose symlink metadata is a folder.
    fn names_git_folder(&self, path: &Path, git_root: Option<&Path>) -> bool {
        self.options.scan_git_metadata
            && git_root.is_none()
            && path.file_name() == Some(OsStr::new(GIT_FOLDER))
    }

    /// Resolves a followed file symlink to the target that is scanned.
    ///
    /// Returns `None` for a target that is not a regular file, such as a
    /// FIFO, socket or device. Such a target is skipped without an issue, as
    /// a non-regular file found directly is, so a scan never blocks on it
    /// or reads it without end.
    fn followed_target(&self, path: &Path) -> Result<Option<PathBuf>, SourceIssue> {
        let target = resolve_symlink(path, self.options.max_symlink_hops.get())?;
        let target_metadata = fs::metadata(&target).map_err(|error| {
            SourceIssue::new(
                SourceStage::Symlink,
                SourceIssueKind::DanglingSymlink,
                Some(path.to_path_buf()),
                error.to_string(),
            )
        })?;
        if target_metadata.is_dir() {
            return Err(SourceIssue::new(
                SourceStage::Symlink,
                SourceIssueKind::DirectorySymlink,
                Some(path.to_path_buf()),
                "followed symlink target is a directory",
            )
            .excluded());
        }
        Ok(target_metadata.is_file().then_some(target))
    }

    fn path_allowed(&self, path: &Path) -> bool {
        let Some(config) = &self.options.path_config else {
            return false;
        };
        let logical = self.logical_path(path);
        config.source_path_allowed(
            logical.normalized().as_bytes(),
            logical
                .windows_original()
                .map(rustleaks_core::model::ByteText::as_bytes),
        )
    }

    fn complete_target_excluded(&self, target: &Path) -> Result<bool, CallbackError> {
        if self.options.file_options.complete_target_bytes().is_none()
            || self.options.excluded_paths.is_empty()
        {
            return Ok(false);
        }
        #[cfg(feature = "archives")]
        if self.options.archive_options.is_some() && !crate::archive::path_is_leaf(target) {
            return Ok(false);
        }
        let emitted = self.emitted_path(target)?;
        Ok(self.options.excluded_paths.contains(&emitted))
    }

    fn path_translation(&self) -> Option<(LogicalPath, LogicalPath)> {
        let logical_root = self.options.logical_root.as_ref()?;
        let physical = LogicalPath::from_native(&self.root);
        let logical = LogicalPath::from_native(logical_root);
        // Match the event-emission path exactly, including preserved "./".
        if physical == logical && logical.normalized().as_bytes() != b"." {
            None
        } else {
            Some((physical, logical))
        }
    }

    fn emitted_path(&self, target: &Path) -> Result<ByteText, CallbackError> {
        let path = LogicalPath::from_native(target);
        match self.path_translation() {
            None => Ok(path.normalized().clone()),
            Some((physical, logical)) => translate_path(
                path.normalized(),
                physical.normalized(),
                logical.normalized(),
            ),
        }
    }

    #[cfg(feature = "archives")]
    fn archive_exclusions(&self, target: &Path) -> Result<Vec<ByteText>, CallbackError> {
        let logical = self.emitted_path(target)?;
        let physical = LogicalPath::from_native(target);
        let prefix = logical.as_bytes();
        let mut paths = Vec::new();
        for excluded in &self.options.excluded_paths {
            if excluded.as_bytes().starts_with(prefix)
                && excluded.as_bytes().get(prefix.len()) == Some(&b'!')
            {
                paths.try_reserve(1).map_err(|error| {
                    CallbackError::new(format!("could not retain archive exclusion: {error}"))
                })?;
                paths.push(translate_path(excluded, &logical, physical.normalized())?);
            }
        }
        Ok(paths)
    }

    fn logical_path(&self, path: &Path) -> LogicalPath {
        let Some(root) = &self.options.logical_root else {
            return LogicalPath::from_native(path);
        };
        path.strip_prefix(&self.root).map_or_else(
            |_| LogicalPath::from_native(path),
            |suffix| {
                if root == Path::new(".") && !suffix.as_os_str().is_empty() {
                    LogicalPath::from_native(suffix)
                } else {
                    LogicalPath::from_native(&root.join(suffix))
                }
            },
        )
    }
}

impl Source for DirectorySource {
    fn visit(
        &mut self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        crate::source::visit_with_coverage(
            self.options.file_options.complete_target_bytes().is_some(),
            emit,
            |emit| self.visit_inner(cancellation, emit),
        )
    }
}

impl DirectorySource {
    fn visit_inner(
        &self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let Some((physical, logical)) = self.path_translation() else {
            return self.walk_and_read(cancellation, emit);
        };
        self.walk_and_read(cancellation, &mut |event| {
            emit(translate_event(event, &physical, &logical)?)
        })
    }

    /// Walks the tree and reads the files it finds, on this thread or on
    /// reader threads. Events reach `emit` on this thread and in walk order
    /// either way.
    fn walk_and_read(
        &self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        if self.options.read_threads.get() > 1 {
            return readers::walk(self, self.options.read_threads, cancellation, emit);
        }
        let mut sink = SerialSink {
            source: self,
            nominal: Vec::new(),
            cancellation,
            emit,
        };
        self.walk(&self.root, None, cancellation, &mut sink)
    }

    /// Whether a found file is read as an archive. Archives are read on the
    /// walking thread, so a scan reads one archive at a time.
    fn reads_as_archive(&self, target: &Path) -> bool {
        #[cfg(feature = "archives")]
        if self.options.archive_options.is_some() {
            return crate::archive::path_is_archive(target);
        }
        let _ = target;
        false
    }
}

/// Receives what the walk finds, in walk order.
trait WalkSink {
    /// Delivers one issue found by the walk.
    fn issue(&mut self, issue: SourceIssue) -> Result<SourceControl, SourceError>;

    /// Reads one file that passed every walk check.
    fn file(
        &mut self,
        target: PathBuf,
        alias: Option<PathBuf>,
    ) -> Result<SourceControl, SourceError>;
}

/// Reads each file on the walking thread as soon as the walk finds it.
struct SerialSink<'a, 'e> {
    source: &'a DirectorySource,
    nominal: Vec<u8>,
    cancellation: &'a dyn Cancellation,
    emit: &'a mut (dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError> + 'e),
}

impl WalkSink for SerialSink<'_, '_> {
    fn issue(&mut self, issue: SourceIssue) -> Result<SourceControl, SourceError> {
        emit_issue(issue, self.emit)
    }

    fn file(
        &mut self,
        target: PathBuf,
        alias: Option<PathBuf>,
    ) -> Result<SourceControl, SourceError> {
        self.source.visit_file(
            target,
            alias,
            &mut self.nominal,
            self.cancellation,
            self.emit,
        )
    }
}

fn translate_event(
    event: SourceEvent,
    physical: &LogicalPath,
    logical: &LogicalPath,
) -> Result<SourceEvent, CallbackError> {
    match event {
        SourceEvent::Fragment { fragment, issue } => Ok(SourceEvent::Fragment {
            fragment: Box::new(translate_fragment(*fragment, physical, logical)?),
            issue,
        }),
        other => Ok(other),
    }
}

fn translate_fragment(
    fragment: Fragment,
    physical: &LogicalPath,
    logical: &LogicalPath,
) -> Result<Fragment, CallbackError> {
    let file_path = translate_path(
        fragment.file_path(),
        physical.normalized(),
        logical.normalized(),
    )?;
    let symlink_file = translate_path(
        fragment.symlink_file(),
        physical.normalized(),
        logical.normalized(),
    )?;
    let windows_file_path = if fragment.windows_file_path().is_empty() {
        ByteText::default()
    } else {
        translate_path(
            fragment.windows_file_path(),
            physical
                .windows_original()
                .unwrap_or_else(|| physical.normalized()),
            logical
                .windows_original()
                .unwrap_or_else(|| logical.normalized()),
        )?
    };
    Ok(fragment.with_source_paths(file_path, symlink_file, windows_file_path))
}

fn translate_path(
    value: &ByteText,
    physical: &ByteText,
    logical: &ByteText,
) -> Result<ByteText, CallbackError> {
    if value.is_empty() {
        return Ok(ByteText::default());
    }
    let bytes = value.as_bytes();
    let prefix = physical.as_bytes();
    let boundary = bytes.get(prefix.len()).copied();
    let (head, tail) = if bytes.starts_with(prefix)
        && (bytes.len() == prefix.len() || matches!(boundary, Some(b'/' | b'\\' | b'!')))
    {
        let tail = &bytes[prefix.len()..];
        if logical.as_bytes() == b"." && matches!(tail.first(), Some(b'/' | b'\\')) {
            (&[][..], &tail[1..])
        } else {
            (logical.as_bytes(), tail)
        }
    } else {
        (&[][..], bytes)
    };
    let capacity = head
        .len()
        .checked_add(tail.len())
        .ok_or_else(|| CallbackError::new("translated source path length overflowed"))?;
    let mut translated = Vec::new();
    translated.try_reserve_exact(capacity).map_err(|error| {
        CallbackError::new(format!(
            "could not allocate translated source path: {error}"
        ))
    })?;
    translated.extend_from_slice(head);
    translated.extend_from_slice(tail);
    Ok(ByteText::new(translated))
}

/// What an entry inside an entered `.git` folder may be.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GitMetadataEntry {
    file: bool,
    directory: bool,
}

/// Classifies a path relative to an entered `.git` folder by name only.
fn git_metadata_entry(relative: &Path) -> GitMetadataEntry {
    const NONE: GitMetadataEntry = GitMetadataEntry {
        file: false,
        directory: false,
    };
    let named = |names: &[&str], value: &OsStr| names.iter().any(|name| value == OsStr::new(name));
    let mut components = relative.components();
    let (Some(Component::Normal(first)), Some(name)) = (components.next(), relative.file_name())
    else {
        return NONE;
    };
    if components.next().is_none() {
        return GitMetadataEntry {
            file: named(GIT_METADATA_FILES, first),
            directory: first == OsStr::new(GIT_MODULES) || named(GIT_METADATA_TREES, first),
        };
    }
    // Lock files are never inspected, not even as possible folders.
    if is_lock_name(name) {
        return NONE;
    }
    if named(GIT_METADATA_TREES, first) {
        return GitMetadataEntry {
            file: true,
            directory: true,
        };
    }
    // Below `modules`, only `config` files are selected. Folders are listed
    // because submodule names can contain `/`. The object store and the
    // index of a submodule Git folder are never inspected.
    if first == OsStr::new(GIT_MODULES)
        && name != OsStr::new(GIT_INDEX)
        && !relative.components().any(|component| {
            component
                .as_os_str()
                .as_encoded_bytes()
                .eq_ignore_ascii_case(GIT_OBJECTS.as_bytes())
        })
    {
        return GitMetadataEntry {
            file: name == OsStr::new("config"),
            directory: true,
        };
    }
    NONE
}

/// Whether `name` ends in `.lock`, in any ASCII case.
fn is_lock_name(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    bytes.len() >= GIT_LOCK_SUFFIX.len()
        && bytes[bytes.len() - GIT_LOCK_SUFFIX.len()..]
            .eq_ignore_ascii_case(GIT_LOCK_SUFFIX.as_bytes())
}

fn io_issue(stage: SourceStage, path: &Path, error: &io::Error) -> SourceIssue {
    let kind = match error.kind() {
        io::ErrorKind::NotFound => SourceIssueKind::NotFound,
        io::ErrorKind::PermissionDenied => SourceIssueKind::PermissionDenied,
        _ if stage == SourceStage::Open => SourceIssueKind::Open,
        _ => SourceIssueKind::Metadata,
    };
    SourceIssue::new(stage, kind, Some(path.to_path_buf()), error.to_string())
}

fn resolve_symlink(path: &Path, maximum_hops: usize) -> Result<PathBuf, SourceIssue> {
    let alias = path.to_path_buf();
    let mut current = clean_native_path(path);
    let mut visited = BTreeSet::new();

    for _ in 0..maximum_hops {
        let Some((link, remainder)) = first_symlink_component(&current).map_err(|error| {
            SourceIssue::new(
                SourceStage::Symlink,
                SourceIssueKind::DanglingSymlink,
                Some(alias.clone()),
                error.to_string(),
            )
        })?
        else {
            return Ok(current);
        };
        if !visited.insert(current.clone()) {
            return Err(SourceIssue::new(
                SourceStage::Symlink,
                SourceIssueKind::SymlinkLoop,
                Some(alias),
                "symlink cycle detected",
            ));
        }
        let target = fs::read_link(&link).map_err(|error| {
            SourceIssue::new(
                SourceStage::Symlink,
                SourceIssueKind::DanglingSymlink,
                Some(alias.clone()),
                error.to_string(),
            )
        })?;
        let resolved_target = if target.is_absolute() {
            target
        } else {
            link.parent().unwrap_or_else(|| Path::new(".")).join(target)
        };
        current = clean_native_path(&resolved_target.join(remainder));
    }

    Err(SourceIssue::new(
        SourceStage::Symlink,
        SourceIssueKind::SymlinkLoop,
        Some(alias),
        format!("symlink resolution exceeded {maximum_hops} hops"),
    ))
}

fn first_symlink_component(path: &Path) -> io::Result<Option<(PathBuf, PathBuf)>> {
    let components = path.components().collect::<Vec<_>>();
    let mut candidate = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        candidate.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&candidate)?;
        if metadata.file_type().is_symlink() {
            let mut remainder = PathBuf::new();
            for trailing in &components[index + 1..] {
                remainder.push(trailing.as_os_str());
            }
            return Ok(Some((candidate, remainder)));
        }
    }
    Ok(None)
}
