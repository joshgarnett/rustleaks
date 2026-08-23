use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustleaks_core::config::CompiledConfig;
use rustleaks_core::model::{ByteText, Fragment};

use crate::path::clean_native_path;
use crate::{
    CallbackError, Cancellation, FileOptions, FileSource, LogicalPath, Source, SourceConfigError,
    SourceControl, SourceError, SourceEvent, SourceIssue, SourceIssueKind, SourceStage,
};

const DEFAULT_MAX_SYMLINK_HOPS: usize = 64;

/// Validated recursive filesystem-source options.
#[derive(Clone, Debug)]
pub struct DirectoryOptions {
    follow_symlinks: bool,
    max_file_size: Option<u64>,
    file_options: FileOptions,
    path_config: Option<Arc<CompiledConfig>>,
    logical_root: Option<PathBuf>,
    emit_limit_issues: bool,
    max_symlink_hops: NonZeroUsize,
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

    /// Installs immutable compiled configuration for early global path pruning.
    #[must_use]
    pub fn path_config(mut self, config: Arc<CompiledConfig>) -> Self {
        self.path_config = Some(config);
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

    /// Sets a positive defensive ceiling for chained symlink resolution.
    ///
    /// # Errors
    ///
    /// Returns [`SourceConfigError`] when `maximum` is zero.
    pub fn with_max_symlink_hops(mut self, maximum: usize) -> Result<Self, SourceConfigError> {
        self.max_symlink_hops = NonZeroUsize::new(maximum)
            .ok_or_else(|| SourceConfigError::positive("max_symlink_hops"))?;
        Ok(self)
    }

    /// Returns whether file symlinks are followed.
    #[must_use]
    pub const fn follows_symlinks(&self) -> bool {
        self.follow_symlinks
    }

    /// Returns the inclusive file-size gate.
    #[must_use]
    pub const fn maximum_file_size(&self) -> Option<u64> {
        self.max_file_size
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
            logical_root: None,
            emit_limit_issues: false,
            max_symlink_hops: NonZeroUsize::new(DEFAULT_MAX_SYMLINK_HOPS)
                .expect("the default symlink hop ceiling is positive"),
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

    /// Returns the physical traversal root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn walk(
        &self,
        path: &Path,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        if cancellation.is_cancelled() {
            return Err(SourceError::Cancelled);
        }

        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return emit_issue(io_issue(SourceStage::Metadata, path, &error), emit);
            }
        };

        if metadata.is_dir() {
            return self.walk_directory(path, cancellation, emit);
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
            return emit_issue(
                SourceIssue::new(
                    SourceStage::Limit,
                    SourceIssueKind::Limit,
                    Some(path.to_path_buf()),
                    "skipping file: exceeds maximum file size",
                ),
                emit,
            );
        }

        let is_symlink = metadata.file_type().is_symlink();
        let (target, alias) = if is_symlink {
            if !self.options.follow_symlinks {
                return Ok(SourceControl::Continue);
            }
            match resolve_symlink(path, self.options.max_symlink_hops.get()) {
                Ok(target) => {
                    let target_metadata = match fs::metadata(&target) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            let issue = SourceIssue::new(
                                SourceStage::Symlink,
                                SourceIssueKind::DanglingSymlink,
                                Some(path.to_path_buf()),
                                error.to_string(),
                            );
                            return emit_issue(issue, emit);
                        }
                    };
                    if target_metadata.is_dir() {
                        let issue = SourceIssue::new(
                            SourceStage::Symlink,
                            SourceIssueKind::DirectorySymlink,
                            Some(path.to_path_buf()),
                            "followed symlink target is a directory",
                        );
                        return emit_issue(issue, emit);
                    }
                    (target, Some(path.to_path_buf()))
                }
                Err(issue) => return emit_issue(issue, emit),
            }
        } else {
            (path.to_path_buf(), None)
        };

        if self.path_allowed(path) {
            return Ok(SourceControl::Continue);
        }
        let file = match fs::File::open(&target) {
            Ok(file) => file,
            Err(error) => return emit_issue(io_issue(SourceStage::Open, &target, &error), emit),
        };
        #[cfg(feature = "archives")]
        if let Some(options) = &self.options.archive_options {
            let mut options = options.clone();
            if let Some(config) = &self.options.path_config {
                options = options.path_config(Arc::clone(config));
            }
            let mut source = crate::ArchiveSource::with_options(
                file,
                target,
                self.options.file_options,
                options,
            );
            if let Some(alias) = alias {
                source = source.with_symlink_path(alias);
            }
            return source.visit(cancellation, emit);
        }
        let mut source = FileSource::with_options(file, target, self.options.file_options);
        if let Some(alias) = alias {
            source = source.with_symlink_path(alias);
        }
        source.visit(cancellation, emit)
    }

    fn walk_directory(
        &self,
        path: &Path,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        if self.path_allowed(path) {
            return Ok(SourceControl::Continue);
        }
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) => return emit_issue(io_issue(SourceStage::Traverse, path, &error), emit),
        };
        let mut children = Vec::new();
        for entry in entries {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }
            match entry {
                Ok(entry) => {
                    if let Err(error) = children.try_reserve(1) {
                        return emit_issue(
                            SourceIssue::new(
                                SourceStage::Limit,
                                SourceIssueKind::Limit,
                                Some(path.to_path_buf()),
                                format!("could not retain directory entry: {error}"),
                            ),
                            emit,
                        );
                    }
                    children.push(entry);
                }
                Err(error) => {
                    let control = emit_issue(io_issue(SourceStage::Traverse, path, &error), emit)?;
                    if control == SourceControl::Stop {
                        return Ok(control);
                    }
                }
            }
        }
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            let control = self.walk(&child.path(), cancellation, emit)?;
            if control == SourceControl::Stop {
                return Ok(control);
            }
        }
        Ok(SourceControl::Continue)
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
        let Some(logical_root) = &self.options.logical_root else {
            return self.walk(&self.root, cancellation, emit);
        };
        let physical = LogicalPath::from_native(&self.root);
        let logical = LogicalPath::from_native(logical_root);
        self.walk(&self.root, cancellation, &mut |event| {
            emit(translate_event(event, &physical, &logical)?)
        })
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

fn emit_issue(
    issue: SourceIssue,
    emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
) -> Result<SourceControl, SourceError> {
    emit(SourceEvent::Issue(issue)).map_err(SourceError::Callback)
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
