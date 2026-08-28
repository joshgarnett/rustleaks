use std::io::Read;
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
use crate::config::resolve;

pub(crate) struct BuiltSource {
    source: Box<dyn Source>,
    excluded: Vec<ByteText>,
    excluded_bytes: u64,
    excluded_commits: CommitCounter,
}

const MAX_UNIQUE_EXCLUDED_COMMITS: usize = 1_000_000;

struct CommitCounter {
    values: Vec<ByteText>,
    maximum: usize,
}

impl CommitCounter {
    fn new(maximum: usize) -> Self {
        Self {
            values: Vec::new(),
            maximum,
        }
    }

    fn observe(&mut self, value: &ByteText) -> Result<(), CallbackError> {
        if value.is_empty() || self.values.iter().any(|known| known == value) {
            return Ok(());
        }
        if self.values.len() == self.maximum {
            return Err(CallbackError::new(format!(
                "excluded commit count exceeds the {}-commit safety limit",
                self.maximum
            )));
        }
        self.values.try_reserve(1).map_err(|error| {
            CallbackError::new(format!("could not retain excluded commit: {error}"))
        })?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(value.len()).map_err(|error| {
            CallbackError::new(format!("could not copy excluded commit: {error}"))
        })?;
        bytes.extend_from_slice(value.as_bytes());
        self.values.push(ByteText::new(bytes));
        Ok(())
    }
}

impl BuiltSource {
    pub fn excluded_bytes(&self) -> u64 {
        self.excluded_bytes
    }
    pub fn excluded_commit_count(&self) -> usize {
        self.excluded_commits().len()
    }
    pub fn excluded_commits(&self) -> &[ByteText] {
        &self.excluded_commits.values
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
        self.source.visit(cancellation, &mut |event| {
            if let SourceEvent::Fragment {
                fragment,
                issue: None,
            } = &event
            {
                if is_excluded(excluded, fragment) {
                    let length = u64::try_from(fragment.content().len()).map_err(|_| {
                        CallbackError::new("excluded fragment byte count is out of range")
                    })?;
                    *excluded_bytes = excluded_bytes.checked_add(length).ok_or_else(|| {
                        CallbackError::new("excluded fragment byte count overflowed")
                    })?;
                    excluded_commits.observe(fragment.commit())?;
                    return Ok(SourceControl::Continue);
                }
            }
            emit(event)
        })
    }
}

fn is_excluded(excluded: &[ByteText], fragment: &Fragment) -> bool {
    // The pinned detector compares config and baseline self-exclusions only
    // with its slash-normalized FilePath, not its retained WindowsFilePath.
    excluded.iter().any(|path| path == fragment.file_path())
}

pub(crate) fn build<R: Read + Send + 'static>(
    invocation: &Invocation,
    stdin: R,
    full_config: &Arc<CompiledConfig>,
    excluded: Vec<ByteText>,
    cwd: &Path,
) -> Result<BuiltSource, String> {
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
    let early_config = Some(Arc::clone(full_config));
    let archive = archive_options(invocation, early_config.clone())?;
    let source: Box<dyn Source> = match invocation.command {
        CommandKind::Directory => {
            let mut options = DirectoryOptions::default()
                .follow_symlinks(invocation.options.follow_symlinks)
                .max_file_size(source_maximum(invocation)?)
                .emit_limit_issues(true);
            if let Some(config) = early_config {
                options = options.path_config(config);
            }
            if let Some(logical_root) = logical_root {
                options = options.logical_root(logical_root);
            }
            if let Some(archive) = archive {
                options = options.archives(archive);
            }
            Box::new(DirectorySource::with_options(physical_source, options))
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
            let mut git = GitSource::new(physical_source).mode(mode);
            if let Some(archive) = archive {
                git = git.archives(archive);
            }
            Box::new(git)
        }
        CommandKind::Stdin => match archive {
            Some(options) => Box::new(ArchiveSource::with_options(
                stdin,
                std::path::PathBuf::new(),
                rustleaks_sources::FileOptions::default(),
                options,
            )),
            None => Box::new(FileSource::new(stdin, std::path::PathBuf::new())),
        },
    };
    Ok(BuiltSource {
        source,
        excluded,
        excluded_bytes: 0,
        excluded_commits: CommitCounter::new(MAX_UNIQUE_EXCLUDED_COMMITS),
    })
}

fn source_maximum(invocation: &Invocation) -> Result<Option<u64>, String> {
    let value = invocation.options.max_target_megabytes;
    if value <= 0 {
        return Ok(None);
    }
    u64::try_from(value)
        .ok()
        .and_then(|value| value.checked_mul(1_000_000))
        .map(Some)
        .ok_or_else(|| "--max-target-megabytes overflows the source byte domain".to_owned())
}

fn archive_options(
    invocation: &Invocation,
    config: Option<Arc<CompiledConfig>>,
) -> Result<Option<ArchiveOptions>, String> {
    if invocation.options.max_archive_depth <= 0 {
        return Ok(None);
    }
    let depth = usize::try_from(invocation.options.max_archive_depth)
        .map_err(|_| "--max-archive-depth is out of range".to_owned())?;
    let defaults = ArchiveLimits::default();
    let limits = ArchiveLimits::new(
        depth,
        defaults.maximum_entries(),
        defaults.maximum_member_bytes(),
        defaults.maximum_total_bytes(),
        defaults.maximum_spool_bytes(),
    )
    .map_err(|error| error.to_string())?;
    let mut options = ArchiveOptions::new(limits).emit_limit_issues(true);
    if let Some(config) = config {
        options = options.path_config(config);
    }
    Ok(Some(options))
}

pub(crate) fn engine_maximum(invocation: &Invocation) -> Result<Option<usize>, String> {
    let value = invocation.options.max_target_megabytes;
    if value <= 0 {
        return Ok(None);
    }
    usize::try_from(value)
        .ok()
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_mul(1_000_000))
        .and_then(|value| value.checked_sub(1))
        .map(Some)
        .ok_or_else(|| "--max-target-megabytes overflows the engine byte domain".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::Options;
    use std::path::PathBuf;

    #[test]
    fn megabyte_thresholds_match_source_and_engine_quirk() {
        let invocation = Invocation {
            command: CommandKind::Directory,
            source: PathBuf::from("."),
            options: Options {
                max_target_megabytes: 2,
                ..Options::default()
            },
        };
        assert_eq!(source_maximum(&invocation).unwrap(), Some(2_000_000));
        assert_eq!(engine_maximum(&invocation).unwrap(), Some(2_999_999));
    }

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
