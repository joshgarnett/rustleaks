//! Source-control remote discovery and platform-specific finding links.

use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use rustleaks_core::model::{ByteText, Finding, Location};

use crate::{Cancellation, INNER_PATH_SEPARATOR};

const OUTPUT_LIMIT: usize = 1024 * 1024;
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(2);
const NO_REMOTE_MESSAGE: &[u8] = b"No remote configured";

/// Supported source-control hosting platforms.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum ScmPlatform {
    /// Infer a known platform from the normalized remote hostname.
    #[default]
    Unknown,
    /// Disable source-control discovery and link generation.
    NoPlatform,
    /// GitHub.
    GitHub,
    /// GitLab.
    GitLab,
    /// Azure DevOps.
    AzureDevOps,
    /// Gitea or Forgejo.
    Gitea,
    /// Bitbucket Cloud.
    Bitbucket,
}

impl ScmPlatform {
    /// Returns the upstream-compatible command-line spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::NoPlatform => "none",
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
            Self::AzureDevOps => "azuredevops",
            Self::Gitea => "gitea",
            Self::Bitbucket => "bitbucket",
        }
    }
}

impl fmt::Display for ScmPlatform {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ScmPlatform {
    type Err = ScmError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() || value.eq_ignore_ascii_case("unknown") {
            Ok(Self::Unknown)
        } else if value.eq_ignore_ascii_case("none") {
            Ok(Self::NoPlatform)
        } else if value.eq_ignore_ascii_case("github") {
            Ok(Self::GitHub)
        } else if value.eq_ignore_ascii_case("gitlab") {
            Ok(Self::GitLab)
        } else if value.eq_ignore_ascii_case("azuredevops") {
            Ok(Self::AzureDevOps)
        } else if value.eq_ignore_ascii_case("gitea") {
            Ok(Self::Gitea)
        } else if value.eq_ignore_ascii_case("bitbucket") {
            Ok(Self::Bitbucket)
        } else {
            Err(ScmError::new(
                ScmErrorKind::InvalidPlatform,
                format!("invalid source-control platform: {value}"),
            ))
        }
    }
}

/// Stable categories for source-control discovery and link errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ScmErrorKind {
    /// A platform name was not recognized.
    InvalidPlatform,
    /// The caller cancelled discovery.
    Cancelled,
    /// The Git child could not be started.
    Spawn,
    /// A child output stream could not be read or joined.
    ChildOutput,
    /// The child produced more output than the retained safety limit.
    OutputLimit,
    /// Git exited unsuccessfully for a reason other than an absent remote.
    GitExit,
    /// Git returned a remote that could not be parsed safely.
    InvalidRemote,
    /// The child could not be killed or reaped cleanly.
    Cleanup,
    /// Link allocation exceeded the process resource boundary.
    Allocation,
}

/// A recoverable source-control discovery or link-construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScmError {
    kind: ScmErrorKind,
    message: String,
    stderr: ByteText,
}

impl ScmError {
    fn new(kind: ScmErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            stderr: ByteText::default(),
        }
    }

    fn git_exit(status: ExitStatus, stderr: Vec<u8>) -> Self {
        let code = status
            .code()
            .map_or_else(|| "signal".to_owned(), |code| code.to_string());
        Self {
            kind: ScmErrorKind::GitExit,
            message: format!("git remote discovery exited with status {code}"),
            stderr: ByteText::new(stderr),
        }
    }

    /// Returns the stable error category.
    #[must_use]
    pub const fn kind(&self) -> ScmErrorKind {
        self.kind
    }

    /// Returns captured Git standard error, when applicable.
    #[must_use]
    pub const fn stderr(&self) -> &ByteText {
        &self.stderr
    }
}

impl fmt::Display for ScmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)?;
        if !self.stderr.is_empty() {
            write!(formatter, ": {}", self.stderr.to_string_lossy())?;
        }
        Ok(())
    }
}

impl Error for ScmError {}

/// A normalized repository remote and its resolved hosting platform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteMetadata {
    platform: ScmPlatform,
    url: ByteText,
}

impl RemoteMetadata {
    /// Creates metadata from an already normalized remote URL.
    #[must_use]
    pub fn new(platform: ScmPlatform, url: impl Into<ByteText>) -> Self {
        Self {
            platform,
            url: url.into(),
        }
    }

    /// Discovers and normalizes the first configured Git remote.
    ///
    /// `NoPlatform` returns immediately without spawning Git. An absent remote
    /// is represented by successful `NoPlatform` metadata; all other failures
    /// are returned explicitly.
    ///
    /// # Errors
    ///
    /// Returns a [`ScmError`] for cancellation, child-process failures,
    /// excessive output, or an invalid remote URL.
    pub fn discover(
        platform: ScmPlatform,
        repository: impl AsRef<Path>,
        cancellation: &dyn Cancellation,
    ) -> Result<Self, ScmError> {
        Self::discover_with_executable(platform, repository, OsStr::new("git"), cancellation)
    }

    /// Discovers a remote using an explicitly selected Git executable.
    ///
    /// This is useful for embedding applications with a configured Git path
    /// and for proving that `NoPlatform` never starts a child process.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`RemoteMetadata::discover`].
    pub fn discover_with_executable(
        platform: ScmPlatform,
        repository: impl AsRef<Path>,
        executable: impl AsRef<OsStr>,
        cancellation: &dyn Cancellation,
    ) -> Result<Self, ScmError> {
        if platform == ScmPlatform::NoPlatform {
            return Ok(Self::new(ScmPlatform::NoPlatform, ByteText::default()));
        }
        if cancellation.is_cancelled() {
            return Err(ScmError::new(
                ScmErrorKind::Cancelled,
                "git remote discovery cancelled before spawn",
            ));
        }

        let output = run_git_remote(executable.as_ref(), repository.as_ref(), cancellation)?;
        if !output.status.success() {
            if contains_subslice(&output.stderr, NO_REMOTE_MESSAGE) {
                return Ok(Self::new(ScmPlatform::NoPlatform, ByteText::default()));
            }
            return Err(ScmError::git_exit(output.status, output.stderr));
        }

        let remote = trim_remote_space(&output.stdout);
        let parsed = normalize_remote(remote)?;
        let resolved_platform = if platform == ScmPlatform::Unknown {
            platform_for_host(parsed.hostname.as_deref().unwrap_or_default())
        } else {
            platform
        };
        Ok(Self::new(resolved_platform, parsed.url))
    }

    /// Returns the selected or inferred platform.
    #[must_use]
    pub const fn platform(&self) -> ScmPlatform {
        self.platform
    }

    /// Returns the normalized, credential-free remote URL.
    #[must_use]
    pub const fn url(&self) -> &ByteText {
        &self.url
    }

    /// Constructs this platform's source link for a finding.
    ///
    /// No link is returned for an unknown or disabled platform, an empty
    /// commit, or an absent remote URL. Archive member paths use the outer
    /// archive path and intentionally omit all line anchors and display flags.
    ///
    /// # Errors
    ///
    /// Returns [`ScmErrorKind::Allocation`] when link storage cannot be
    /// reserved.
    pub fn link_for(&self, finding: &Finding) -> Result<Option<ByteText>, ScmError> {
        if matches!(
            self.platform,
            ScmPlatform::Unknown | ScmPlatform::NoPlatform
        ) || self.url.is_empty()
            || finding.commit().is_empty()
        {
            return Ok(None);
        }

        let file = finding.file().as_bytes();
        let (outer_file, is_archive_member) =
            match find_subslice(file, INNER_PATH_SEPARATOR.as_bytes()) {
                Some(index) => (&file[..index], true),
                None => (file, false),
            };
        let escaped_file = escape_link_path(outer_file)?;
        let location = finding.location();
        let mut link = Vec::new();
        let link_capacity = self
            .url
            .len()
            .checked_add(finding.commit().len())
            .and_then(|length| length.checked_add(escaped_file.len()))
            .and_then(|length| length.checked_add(256))
            .ok_or_else(|| allocation_error("source-control link"))?;
        try_reserve(&mut link, link_capacity, "source-control link")?;
        link.extend_from_slice(self.url.as_bytes());

        match self.platform {
            ScmPlatform::GitHub => github_link(
                &mut link,
                finding.commit().as_bytes(),
                outer_file,
                &escaped_file,
                location,
                is_archive_member,
            ),
            ScmPlatform::GitLab => gitlab_link(
                &mut link,
                finding.commit().as_bytes(),
                &escaped_file,
                location,
                is_archive_member,
            ),
            ScmPlatform::AzureDevOps => azure_link(
                &mut link,
                finding.commit().as_bytes(),
                &escaped_file,
                location,
                is_archive_member,
            ),
            ScmPlatform::Gitea => gitea_link(
                &mut link,
                finding.commit().as_bytes(),
                outer_file,
                &escaped_file,
                location,
                is_archive_member,
            ),
            ScmPlatform::Bitbucket => bitbucket_link(
                &mut link,
                finding.commit().as_bytes(),
                &escaped_file,
                location,
                is_archive_member,
            ),
            ScmPlatform::Unknown | ScmPlatform::NoPlatform => return Ok(None),
        }
        Ok(Some(ByteText::new(link)))
    }
}

/// Constructs a link when remote metadata is available.
///
/// # Errors
///
/// Returns allocation errors from [`RemoteMetadata::link_for`].
pub fn scm_link(
    remote: Option<&RemoteMetadata>,
    finding: &Finding,
) -> Result<Option<ByteText>, ScmError> {
    remote.map_or(Ok(None), |remote| remote.link_for(finding))
}

struct ChildOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
struct RetainedOutput {
    bytes: Vec<u8>,
    exceeded_limit: bool,
    retention_failed: bool,
}

fn run_git_remote(
    executable: &OsStr,
    repository: &Path,
    cancellation: &dyn Cancellation,
) -> Result<ChildOutput, ScmError> {
    let mut command = Command::new(executable);
    command
        .args(["ls-remote", "--quiet", "--get-url"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if repository != Path::new(".") {
        command.current_dir(repository);
    }

    let mut child = command.spawn().map_err(|error| {
        ScmError::new(
            ScmErrorKind::Spawn,
            format!("failed to spawn git remote discovery: {error}"),
        )
    })?;
    let Some(stdout) = child.stdout.take() else {
        return cleanup_after_pipe_failure(child, "stdout pipe was unavailable");
    };
    let Some(stderr) = child.stderr.take() else {
        return cleanup_after_pipe_failure(child, "stderr pipe was unavailable");
    };

    thread::scope(|scope| {
        let stdout_reader = scope.spawn(move || read_bounded_and_drain(stdout));
        let stderr_reader = scope.spawn(move || read_bounded_and_drain(stderr));

        let status = loop {
            if cancellation.is_cancelled() {
                let kill_error = child.kill().err();
                let wait_result = child.wait();
                let stdout_result = join_reader(stdout_reader, "stdout");
                let stderr_result = join_reader(stderr_reader, "stderr");
                if let Some(error) = kill_error.filter(|error| {
                    !matches!(
                        error.kind(),
                        io::ErrorKind::InvalidInput | io::ErrorKind::NotFound
                    )
                }) {
                    return Err(ScmError::new(
                        ScmErrorKind::Cleanup,
                        format!("failed to kill cancelled git remote discovery: {error}"),
                    ));
                }
                wait_result.map_err(|error| {
                    ScmError::new(
                        ScmErrorKind::Cleanup,
                        format!("failed to reap cancelled git remote discovery: {error}"),
                    )
                })?;
                stdout_result?;
                stderr_result?;
                return Err(ScmError::new(
                    ScmErrorKind::Cancelled,
                    "git remote discovery cancelled",
                ));
            }

            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => thread::sleep(CHILD_POLL_INTERVAL),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = join_reader(stdout_reader, "stdout");
                    let _ = join_reader(stderr_reader, "stderr");
                    return Err(ScmError::new(
                        ScmErrorKind::Cleanup,
                        format!("failed while waiting for git remote discovery: {error}"),
                    ));
                }
            }
        };

        let stdout = join_reader(stdout_reader, "stdout")?;
        let stderr = join_reader(stderr_reader, "stderr")?;
        if stdout.retention_failed || stderr.retention_failed {
            return Err(ScmError::new(
                ScmErrorKind::Allocation,
                "failed to retain bounded git remote discovery output",
            ));
        }
        if stdout.exceeded_limit || stderr.exceeded_limit {
            return Err(ScmError::new(
                ScmErrorKind::OutputLimit,
                format!("git remote discovery exceeded the {OUTPUT_LIMIT}-byte output limit"),
            ));
        }
        Ok(ChildOutput {
            status,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        })
    })
}

fn cleanup_after_pipe_failure(
    mut child: std::process::Child,
    message: &'static str,
) -> Result<ChildOutput, ScmError> {
    let kill_error = child.kill().err();
    let wait_error = child.wait().err();
    let detail = match (kill_error, wait_error) {
        (None, None) => message.to_owned(),
        (kill, wait) => format!("{message}; kill={kill:?}; wait={wait:?}"),
    };
    Err(ScmError::new(ScmErrorKind::Cleanup, detail))
}

fn read_bounded_and_drain(mut reader: impl Read) -> io::Result<RetainedOutput> {
    let mut retained = Vec::new();
    let mut exceeded_limit = false;
    let mut retention_failed = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let available = OUTPUT_LIMIT.saturating_sub(retained.len());
        let keep = count.min(available);
        if keep != 0 && !retention_failed {
            if retained.try_reserve(keep).is_err() {
                retention_failed = true;
                continue;
            }
            retained.extend_from_slice(&buffer[..keep]);
        }
        exceeded_limit |= keep != count;
    }
    Ok(RetainedOutput {
        bytes: retained,
        exceeded_limit,
        retention_failed,
    })
}

fn join_reader(
    handle: thread::ScopedJoinHandle<'_, io::Result<RetainedOutput>>,
    stream: &'static str,
) -> Result<RetainedOutput, ScmError> {
    match handle.join() {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(ScmError::new(
            ScmErrorKind::ChildOutput,
            format!("failed to read git {stream}: {error}"),
        )),
        Err(_) => Err(ScmError::new(
            ScmErrorKind::ChildOutput,
            format!("git {stream} reader panicked"),
        )),
    }
}

struct ParsedRemote {
    url: Vec<u8>,
    hostname: Option<Vec<u8>>,
}

fn normalize_remote(remote: &[u8]) -> Result<ParsedRemote, ScmError> {
    let mut normalized = if let Some(rewritten) = rewrite_scp_remote(remote)? {
        rewritten
    } else {
        let mut copied = Vec::new();
        try_reserve(&mut copied, remote.len(), "normalized remote URL")?;
        copied.extend_from_slice(remote);
        copied
    };
    if normalized.ends_with(b".git") {
        normalized.truncate(normalized.len() - 4);
    }
    validate_remote_bytes(&normalized)?;

    let authority = authority_range(&normalized)?;
    let hostname = authority.as_ref().map_or(Ok(None), |range| {
        let authority = &normalized[range.clone()];
        let without_user = authority
            .iter()
            .rposition(|byte| *byte == b'@')
            .map_or(authority, |index| &authority[index + 1..]);
        remote_hostname(without_user)
    })?;

    if let Some(range) = authority {
        if let Some(at) = normalized[range.clone()]
            .iter()
            .rposition(|byte| *byte == b'@')
        {
            normalized.drain(range.start..=range.start + at);
        }
    }

    Ok(ParsedRemote {
        url: normalized,
        hostname,
    })
}

fn rewrite_scp_remote(remote: &[u8]) -> Result<Option<Vec<u8>>, ScmError> {
    let Some(remainder) = remote.strip_prefix(b"git@") else {
        return Ok(None);
    };
    let Some(colon) = remainder.iter().position(|byte| *byte == b':') else {
        return Ok(None);
    };
    let host = &remainder[..colon];
    let mut path = &remainder[colon + 1..];
    if host.is_empty()
        || !host
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        || path.is_empty()
        || !path
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'/' | b'.' | b'-'))
    {
        return Ok(None);
    }

    if let Some(slash) = path.iter().position(|byte| *byte == b'/') {
        let possible_port = &path[..slash];
        if (1..=5).contains(&possible_port.len()) && possible_port.iter().all(u8::is_ascii_digit) {
            path = &path[slash + 1..];
        }
    }
    if path.ends_with(b".git") {
        path = &path[..path.len() - 4];
    }
    if path.is_empty() {
        return Ok(None);
    }

    let mut rewritten = Vec::new();
    let capacity = 8_usize
        .checked_add(host.len())
        .and_then(|length| length.checked_add(path.len()))
        .ok_or_else(|| allocation_error("SCP-style remote URL"))?;
    try_reserve(&mut rewritten, capacity, "SCP-style remote URL")?;
    rewritten.extend_from_slice(b"https://");
    rewritten.extend_from_slice(host);
    rewritten.push(b'/');
    rewritten.extend_from_slice(path);
    Ok(Some(rewritten))
}

fn validate_remote_bytes(remote: &[u8]) -> Result<(), ScmError> {
    if remote.is_empty() {
        return Err(ScmError::new(
            ScmErrorKind::InvalidRemote,
            "git returned an empty remote URL",
        ));
    }
    if std::str::from_utf8(remote).is_err() {
        return Err(ScmError::new(
            ScmErrorKind::InvalidRemote,
            "git returned a non-UTF-8 remote URL",
        ));
    }
    for (index, byte) in remote.iter().copied().enumerate() {
        if byte.is_ascii_control() {
            return Err(ScmError::new(
                ScmErrorKind::InvalidRemote,
                "git returned a remote URL containing a control byte",
            ));
        }
        if byte == b'%'
            && (index + 2 >= remote.len()
                || !remote[index + 1].is_ascii_hexdigit()
                || !remote[index + 2].is_ascii_hexdigit())
        {
            return Err(ScmError::new(
                ScmErrorKind::InvalidRemote,
                "git returned a remote URL with an invalid percent escape",
            ));
        }
    }
    Ok(())
}

fn authority_range(remote: &[u8]) -> Result<Option<std::ops::Range<usize>>, ScmError> {
    let Some(scheme_end) = remote.iter().position(|byte| *byte == b':') else {
        return Ok(None);
    };
    if remote[..scheme_end]
        .iter()
        .any(|byte| matches!(byte, b'/' | b'?' | b'#'))
    {
        return Ok(None);
    }
    let scheme = &remote[..scheme_end];
    if scheme.is_empty()
        || !scheme[0].is_ascii_alphabetic()
        || !scheme[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return Err(ScmError::new(
            ScmErrorKind::InvalidRemote,
            "git returned a remote URL with an invalid scheme",
        ));
    }
    if remote.get(scheme_end + 1..scheme_end + 3) != Some(&b"//"[..]) {
        return Ok(None);
    }
    let start = scheme_end + 3;
    let end = remote[start..]
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
        .map_or(remote.len(), |offset| start + offset);
    if remote[start..end]
        .iter()
        .any(|byte| matches!(byte, b' ' | b'\\'))
    {
        return Err(ScmError::new(
            ScmErrorKind::InvalidRemote,
            "git returned a remote URL with an invalid host",
        ));
    }
    Ok(Some(start..end))
}

fn remote_hostname(authority: &[u8]) -> Result<Option<Vec<u8>>, ScmError> {
    if authority.is_empty() {
        return Ok(None);
    }
    let host = if authority.starts_with(b"[") {
        let Some(end) = authority.iter().position(|byte| *byte == b']') else {
            return Err(ScmError::new(
                ScmErrorKind::InvalidRemote,
                "git returned a remote URL with an unterminated IPv6 host",
            ));
        };
        let suffix = &authority[end + 1..];
        if !suffix.is_empty()
            && (!suffix.starts_with(b":")
                || suffix.len() == 1
                || !suffix[1..].iter().all(u8::is_ascii_digit))
        {
            return Err(ScmError::new(
                ScmErrorKind::InvalidRemote,
                "git returned a remote URL with an invalid port",
            ));
        }
        &authority[1..end]
    } else if let Some(colon) = authority.iter().rposition(|byte| *byte == b':') {
        let port = &authority[colon + 1..];
        if port.is_empty() || !port.iter().all(u8::is_ascii_digit) {
            return Err(ScmError::new(
                ScmErrorKind::InvalidRemote,
                "git returned a remote URL with an invalid port",
            ));
        }
        &authority[..colon]
    } else {
        authority
    };
    let mut lowercase = Vec::new();
    try_reserve(&mut lowercase, host.len(), "normalized remote hostname")?;
    lowercase.extend(host.iter().map(u8::to_ascii_lowercase));
    Ok(Some(lowercase))
}

fn platform_for_host(hostname: &[u8]) -> ScmPlatform {
    match hostname {
        b"github.com" => ScmPlatform::GitHub,
        b"gitlab.com" => ScmPlatform::GitLab,
        b"dev.azure.com" | b"visualstudio.com" => ScmPlatform::AzureDevOps,
        b"gitea.com" | b"code.forgejo.org" | b"codeberg.org" => ScmPlatform::Gitea,
        b"bitbucket.org" => ScmPlatform::Bitbucket,
        _ => ScmPlatform::Unknown,
    }
}

fn escape_link_path(path: &[u8]) -> Result<Vec<u8>, ScmError> {
    let extra = path
        .iter()
        .filter(|byte| matches!(byte, b' ' | b'%'))
        .count()
        .checked_mul(2)
        .ok_or_else(|| allocation_error("escaped source path"))?;
    let capacity = path
        .len()
        .checked_add(extra)
        .ok_or_else(|| allocation_error("escaped source path"))?;
    let mut escaped = Vec::new();
    try_reserve(&mut escaped, capacity, "escaped source path")?;
    for byte in path {
        match byte {
            b' ' => escaped.extend_from_slice(b"%20"),
            b'%' => escaped.extend_from_slice(b"%25"),
            byte => escaped.push(*byte),
        }
    }
    Ok(escaped)
}

fn github_link(
    link: &mut Vec<u8>,
    commit: &[u8],
    file: &[u8],
    escaped_file: &[u8],
    location: Location,
    is_archive_member: bool,
) {
    append_path(link, b"/blob/", commit, escaped_file);
    if is_archive_member {
        return;
    }
    if has_markdown_extension(file) {
        link.extend_from_slice(b"?plain=1");
    }
    append_line_range(
        link,
        b"#L",
        b"-L",
        location.start_line(),
        location.end_line(),
    );
}

fn gitlab_link(
    link: &mut Vec<u8>,
    commit: &[u8],
    escaped_file: &[u8],
    location: Location,
    is_archive_member: bool,
) {
    append_path(link, b"/blob/", commit, escaped_file);
    if !is_archive_member {
        append_line_range(
            link,
            b"#L",
            b"-",
            location.start_line(),
            location.end_line(),
        );
    }
}

fn azure_link(
    link: &mut Vec<u8>,
    commit: &[u8],
    escaped_file: &[u8],
    location: Location,
    is_archive_member: bool,
) {
    link.extend_from_slice(b"/commit/");
    link.extend_from_slice(commit);
    link.extend_from_slice(b"?path=/");
    link.extend_from_slice(escaped_file);
    if is_archive_member {
        return;
    }
    if location.start_line() != 0 {
        link.extend_from_slice(b"&line=");
        append_usize(link, location.start_line());
    }
    if location.end_line() != location.start_line() {
        link.extend_from_slice(b"&lineEnd=");
        append_usize(link, location.end_line());
    }
    link.extend_from_slice(
        b"&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files",
    );
}

fn gitea_link(
    link: &mut Vec<u8>,
    commit: &[u8],
    file: &[u8],
    escaped_file: &[u8],
    location: Location,
    is_archive_member: bool,
) {
    append_path(link, b"/src/commit/", commit, escaped_file);
    if is_archive_member {
        return;
    }
    if has_markdown_extension(file) {
        link.extend_from_slice(b"?display=source");
    }
    append_line_range(
        link,
        b"#L",
        b"-L",
        location.start_line(),
        location.end_line(),
    );
}

fn bitbucket_link(
    link: &mut Vec<u8>,
    commit: &[u8],
    escaped_file: &[u8],
    location: Location,
    is_archive_member: bool,
) {
    append_path(link, b"/src/", commit, escaped_file);
    if !is_archive_member {
        append_line_range(
            link,
            b"#lines-",
            b":",
            location.start_line(),
            location.end_line(),
        );
    }
}

fn append_path(link: &mut Vec<u8>, prefix: &[u8], commit: &[u8], file: &[u8]) {
    link.extend_from_slice(prefix);
    link.extend_from_slice(commit);
    link.push(b'/');
    link.extend_from_slice(file);
}

fn append_line_range(
    link: &mut Vec<u8>,
    start_prefix: &[u8],
    end_prefix: &[u8],
    start_line: usize,
    end_line: usize,
) {
    if start_line != 0 {
        link.extend_from_slice(start_prefix);
        append_usize(link, start_line);
    }
    if end_line != start_line {
        link.extend_from_slice(end_prefix);
        append_usize(link, end_line);
    }
}

fn append_usize(output: &mut Vec<u8>, mut number: usize) {
    let mut digits = [0_u8; 20];
    let mut index = digits.len();
    loop {
        index -= 1;
        digits[index] = b'0' + u8::try_from(number % 10).unwrap_or(0);
        number /= 10;
        if number == 0 {
            break;
        }
    }
    output.extend_from_slice(&digits[index..]);
}

fn has_markdown_extension(file: &[u8]) -> bool {
    let extension = file
        .iter()
        .rposition(|byte| *byte == b'.')
        .map_or(&[][..], |index| &file[index..]);
    extension.eq_ignore_ascii_case(b".md") || extension.eq_ignore_ascii_case(b".ipynb")
}

fn trim_remote_space(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    find_subslice(haystack, needle).is_some()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn try_reserve(output: &mut Vec<u8>, additional: usize, context: &str) -> Result<(), ScmError> {
    output
        .try_reserve(additional)
        .map_err(|error| ScmError::new(ScmErrorKind::Allocation, format!("{context}: {error}")))
}

fn allocation_error(context: &str) -> ScmError {
    ScmError::new(
        ScmErrorKind::Allocation,
        format!("{context} length overflow"),
    )
}
