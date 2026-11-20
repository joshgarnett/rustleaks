use std::collections::HashSet;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use rustleaks_core::config::CompiledConfig;
use rustleaks_core::model::{ByteText, Fragment};
use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, ArchiveSource, CallbackError, Cancellation, DirectoryOptions,
    DirectorySource, FileSource, GitMode, GitSource, Source, SourceControl, SourceError,
    SourceEvent,
};

use crate::args::{CommandKind, Invocation};
use crate::complete_profile::CompleteProfile;
use crate::config::resolve;
use crate::limits::ScanLimits;

pub(crate) struct BuiltSource {
    source: InnerSource,
    excluded: Vec<ByteText>,
    excluded_bytes: u64,
    excluded_commits: CommitCounter,
}

const MAX_UNIQUE_EXCLUDED_COMMITS: usize = 100_000_000;

/// The source of a scan. A directory stays typed so that the scan can set
/// its reader threads after the detection threads are known.
enum InnerSource {
    Directory(Box<DirectorySource>),
    Other(Box<dyn Source>),
}

impl InnerSource {
    fn as_source(&mut self) -> &mut dyn Source {
        match self {
            Self::Directory(source) => source.as_mut(),
            Self::Other(source) => source.as_mut(),
        }
    }
}

struct CommitCounter {
    values: Vec<ByteText>,
    index: HashSet<ByteText>,
    maximum: usize,
}

impl CommitCounter {
    fn new(maximum: usize) -> Self {
        Self {
            values: Vec::new(),
            index: HashSet::new(),
            maximum,
        }
    }

    fn observe(&mut self, value: &ByteText) -> Result<(), CallbackError> {
        if value.is_empty()
            || self.values.last() == Some(value)
            || self.index.contains(value.as_bytes())
        {
            return Ok(());
        }
        if self.values.len() == self.maximum {
            return Err(CallbackError::new(format!(
                "excluded commit count exceeds the {}-commit safety limit",
                self.maximum
            )));
        }
        self.values.try_reserve(1).map_err(|error| {
            CallbackError::new(format!("not enough memory for excluded commit: {error}"))
        })?;
        self.index.try_reserve(1).map_err(|error| {
            CallbackError::new(format!("not enough memory for excluded commit: {error}"))
        })?;
        let retained = copy_commit(value)?;
        let indexed = copy_commit(value)?;
        self.index.insert(indexed);
        self.values.push(retained);
        Ok(())
    }
}

fn copy_commit(value: &ByteText) -> Result<ByteText, CallbackError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(value.len())
        .map_err(|error| CallbackError::new(format!("could not copy excluded commit: {error}")))?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(ByteText::new(bytes))
}

impl BuiltSource {
    pub fn excluded_bytes(&self) -> u64 {
        self.excluded_bytes
    }
    pub fn excluded_commits(&self) -> &[ByteText] {
        &self.excluded_commits.values
    }

    /// Sets how many threads read the files of a directory scan. Other
    /// sources read on one thread.
    pub fn set_read_threads(&mut self, threads: NonZeroUsize) {
        if let InnerSource::Directory(source) = &mut self.source {
            source.set_read_threads(threads);
        }
    }
}

impl Source for BuiltSource {
    fn visit(
        &mut self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let excluded = &self.excluded;
        let excluded_bytes = &mut self.excluded_bytes;
        let excluded_commits = &mut self.excluded_commits;
        self.source.as_source().visit(cancellation, &mut |event| {
            if let SourceEvent::Fragment {
                fragment,
                issue: None,
            } = &event
                && is_excluded(excluded, fragment)
            {
                let length = u64::try_from(fragment.content().len()).map_err(|_| {
                    CallbackError::new("excluded fragment byte count is out of range")
                })?;
                *excluded_bytes = excluded_bytes
                    .checked_add(length)
                    .ok_or_else(|| CallbackError::new("excluded fragment byte count overflowed"))?;
                excluded_commits.observe(fragment.commit())?;
                return Ok(SourceControl::Continue);
            }
            emit(event)
        })
    }
}

fn is_excluded(excluded: &[ByteText], fragment: &Fragment) -> bool {
    // Self-exclusions compare only the slash-normalized path, not the
    // Windows spelling.
    excluded.iter().any(|path| path == fragment.file_path())
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a separate input that the scan command has already built"
)]
pub(crate) fn build<R: Read + Send + 'static>(
    invocation: &Invocation,
    stdin: R,
    full_config: &Arc<CompiledConfig>,
    excluded: Vec<ByteText>,
    cwd: &Path,
    limits: &ScanLimits,
    profile: Option<&CompleteProfile>,
    git_history_processes: NonZeroUsize,
) -> Result<BuiltSource, String> {
    // Sources name the physical path in issue and Git messages. When the
    // injected directory is the process directory, the path stays as typed,
    // so those messages show the path that the user gave. Otherwise it is
    // resolved against the injected directory.
    let injected_cwd_differs = match std::env::current_dir() {
        Ok(current) => current != cwd,
        Err(_) => true,
    };
    let physical_source = if injected_cwd_differs {
        resolve(cwd, &invocation.source)
    } else {
        invocation.source.clone()
    };
    let logical_root =
        (invocation.command == CommandKind::Directory).then(|| invocation.source.clone());
    let file_options = profile.map_or_else(
        || Ok(rustleaks_sources::FileOptions::default()),
        CompleteProfile::file_options,
    )?;
    let archive = archive_options(limits.archive_depth, full_config, profile)?;
    let source = match invocation.command {
        CommandKind::Directory => {
            let mut options = DirectoryOptions::default()
                .file_options(file_options)
                .follow_symlinks(invocation.options.follow_symlinks)
                .scan_git_metadata(invocation.options.scan_git_metadata)
                .max_file_size(limits.source_max)
                .path_config(Arc::clone(full_config))
                .emit_limit_issues(true);
            if profile.is_some() {
                options = options.exclude_paths(excluded.clone());
            }
            if let Some(logical_root) = logical_root {
                options = options.logical_root(logical_root);
            }
            if let Some(archive) = archive {
                options = options.archives(archive);
            }
            InnerSource::Directory(Box::new(DirectorySource::with_options(
                physical_source,
                options,
            )))
        }
        CommandKind::Git => {
            let mode = if invocation.options.pre_commit || invocation.options.staged {
                GitMode::Diff {
                    staged: invocation.options.staged,
                }
            } else {
                GitMode::Log {
                    options: invocation.options.git_log_args.clone(),
                }
            };
            let mut git = GitSource::new(physical_source)
                .mode(mode)
                .history_processes(git_history_processes);
            if let Some(profile) = profile {
                git = git
                    .limits(profile.git_limits()?)
                    .archive_file_options(file_options);
            }
            if let Some(mut archive) = archive {
                if profile.is_some() {
                    archive = archive.exclude_paths(excluded.clone());
                }
                git = git.archives(archive);
            }
            InnerSource::Other(Box::new(git))
        }
        CommandKind::Stdin => InnerSource::Other(match archive {
            Some(options) => Box::new(ArchiveSource::with_options(
                stdin,
                std::path::PathBuf::new(),
                file_options,
                options,
            )),
            None => Box::new(FileSource::with_options(
                stdin,
                std::path::PathBuf::new(),
                file_options,
            )),
        }),
    };
    Ok(BuiltSource {
        source,
        excluded,
        excluded_bytes: 0,
        excluded_commits: CommitCounter::new(MAX_UNIQUE_EXCLUDED_COMMITS),
    })
}

fn archive_options(
    depth: usize,
    config: &Arc<CompiledConfig>,
    profile: Option<&CompleteProfile>,
) -> Result<Option<ArchiveOptions>, String> {
    if depth == 0 {
        return Ok(None);
    }
    let defaults = ArchiveLimits::default();
    let limits = if let Some(profile) = profile {
        profile.archive_limits(depth)?
    } else {
        ArchiveLimits::new(
            depth,
            defaults.maximum_entries(),
            defaults.maximum_member_bytes(),
            defaults.maximum_total_bytes(),
            defaults.maximum_spool_bytes(),
        )
        .map_err(|error| error.to_string())?
    };
    Ok(Some(
        ArchiveOptions::new(limits)
            .emit_limit_issues(true)
            .path_config(Arc::clone(config)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excluded_commit_counter_has_a_deterministic_growth_limit() {
        let mut commits = CommitCounter::new(1);
        commits.observe(&ByteText::from("first")).unwrap();
        commits.observe(&ByteText::from("first")).unwrap();
        let error = commits.observe(&ByteText::from("second")).unwrap_err();
        assert!(error.to_string().contains("1-commit safety limit"));
        assert_eq!(commits.values.len(), 1);
    }

    #[test]
    fn excluded_commit_counter_keeps_discovery_order_for_non_contiguous_repeats() {
        let mut commits = CommitCounter::new(3);
        for value in ["b", "a", "", "b", "c", "a", "c", "b"] {
            commits.observe(&ByteText::from(value)).unwrap();
        }
        assert_eq!(
            commits.values,
            [
                ByteText::from("b"),
                ByteText::from("a"),
                ByteText::from("c")
            ]
        );
        assert!(commits.observe(&ByteText::from("d")).is_err());
        assert!(commits.observe(&ByteText::from("a")).is_ok());
        assert_eq!(commits.values.len(), 3);
    }

    #[test]
    fn exclusions_match_the_upstream_normalized_file_path_only() {
        let fragment = Fragment::builder(Vec::<u8>::new())
            .file_path(ByteText::from("other/baseline.json"))
            .windows_file_path(ByteText::from(r"other\baseline.json"))
            .build();
        assert!(is_excluded(
            &[ByteText::from("other/baseline.json")],
            &fragment
        ));
        assert!(!is_excluded(
            &[ByteText::from(r"other\baseline.json")],
            &fragment
        ));
    }
}
