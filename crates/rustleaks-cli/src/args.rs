use std::ffi::{OsStr, OsString};
use std::num::NonZeroUsize;
use std::path::PathBuf;

use rustleaks_core::Base64Mode;

use crate::cli_spec::{self, Shell, Topic};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandKind {
    Directory,
    Git,
    Stdin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    RootHelp,
    CommandHelp(Topic),
    Version { qualified: bool },
    Completion(Shell),
    Scan(Box<Invocation>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Invocation {
    pub command: CommandKind,
    pub source: PathBuf,
    pub options: Options,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the value is a direct, immutable model of independent CLI switches"
)]
pub(crate) struct Options {
    pub config: Option<PathBuf>,
    pub complete_profile: Option<PathBuf>,
    /// Detection threads from `--jobs`. `None` leaves the choice to the
    /// complete profile or the number of CPUs that the process may use, up
    /// to a fixed maximum.
    pub jobs: Option<NonZeroUsize>,
    pub exit_code: i32,
    pub report_path: Option<PathBuf>,
    pub report_format: Option<String>,
    pub report_template: Option<PathBuf>,
    pub baseline_path: Option<PathBuf>,
    pub log_level: String,
    pub verbose: bool,
    pub no_color: bool,
    pub max_target_megabytes: i64,
    pub ignore_allow_markers: bool,
    pub redact: usize,
    pub no_banner: bool,
    pub enable_rules: Vec<String>,
    pub ignore_path: PathBuf,
    pub max_decode_depth: i64,
    pub base64_mode: Base64Mode,
    pub max_archive_depth: i64,
    pub timeout_seconds: i64,
    pub platform: String,
    pub staged: bool,
    pub pre_commit: bool,
    pub git_log_args: Option<String>,
    pub follow_symlinks: bool,
    pub scan_git_metadata: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            config: None,
            complete_profile: None,
            jobs: None,
            exit_code: 1,
            report_path: None,
            report_format: None,
            report_template: None,
            baseline_path: None,
            log_level: "info".to_owned(),
            verbose: false,
            no_color: false,
            max_target_megabytes: 0,
            ignore_allow_markers: false,
            redact: 0,
            no_banner: false,
            enable_rules: Vec::new(),
            ignore_path: PathBuf::from("."),
            max_decode_depth: 5,
            base64_mode: Base64Mode::Compatible,
            max_archive_depth: 0,
            timeout_seconds: 0,
            platform: String::new(),
            staged: false,
            pre_commit: false,
            git_log_args: None,
            follow_symlinks: false,
            scan_git_metadata: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParseErrorKind {
    UnknownLong,
    UnknownCommand,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParseError {
    pub kind: ParseErrorKind,
    pub message: String,
    /// The command whose usage block follows the error line.
    pub command: Option<Topic>,
}

impl ParseError {
    fn other(message: impl Into<String>) -> Self {
        Self {
            kind: ParseErrorKind::Other,
            message: message.into(),
            command: None,
        }
    }

    fn unknown_long(flag: &str) -> Self {
        Self {
            kind: ParseErrorKind::UnknownLong,
            message: format!("unknown flag: --{flag}"),
            command: None,
        }
    }

    fn unknown_command(value: &str) -> Self {
        Self {
            kind: ParseErrorKind::UnknownCommand,
            message: format!("unknown command {value:?}"),
            command: None,
        }
    }

    fn with_command(mut self, command: Option<Topic>) -> Self {
        self.command = command;
        self
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the parser keeps one auditable, side-effect-free command grammar state machine"
)]
pub(crate) fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Action, ParseError> {
    let arguments = retain_arguments(arguments)?;
    let mut options = Options::default();
    let mut command = None;
    let mut positionals = Vec::<PathBuf>::new();
    let mut index = 0;
    let mut positional_only = false;
    let mut version_command = false;
    // Command words after "version", for its arity message.
    let mut version_words = 0_usize;
    // The command name or alias as typed, for arity messages.
    let mut command_name = "";
    // The help or completion command.
    let mut meta = None::<Topic>;
    while index < arguments.len() {
        // The command whose usage block follows a parser error. The version
        // command has no usage block.
        let topic = command.map(Topic::from).or(meta);
        let argument = &arguments[index];
        if !positional_only && argument == OsStr::new("--") {
            positional_only = true;
            index += 1;
            continue;
        }
        let text = argument.to_str();
        if text.is_none()
            && (topic.is_none() && !version_command
                || !positional_only && argument.as_encoded_bytes().starts_with(b"-"))
        {
            return Err(ParseError::other(
                "command and option names must be valid UTF-8",
            ));
        }
        if !positional_only && matches!(text, Some("--help" | "-h")) {
            let help = topic.or(version_command.then_some(Topic::Version));
            return Ok(help.map_or(Action::RootHelp, Action::CommandHelp));
        }
        if !positional_only && text == Some("--version") {
            if topic.is_some() {
                return Err(ParseError::other("--version works only without a command"));
            }
            return Ok(Action::Version { qualified: true });
        }
        if !positional_only
            && meta == Some(Topic::Completion)
            && let Some(attached) = text.and_then(|value| {
                value
                    .strip_prefix("--no-descriptions")
                    .filter(|rest| rest.is_empty() || rest.starts_with('='))
            })
        {
            // A legacy completion flag. Rustleaks accepts and ignores it.
            boolean("no-descriptions", attached.strip_prefix('='))
                .map_err(|error| error.with_command(topic))?;
            index += 1;
            continue;
        }
        if !positional_only && let Some(value) = text.filter(|value| value.starts_with("--")) {
            parse_long(value, &arguments, &mut index, command, &mut options)
                .map_err(|error| error.with_command(topic))?;
            index += 1;
            continue;
        }
        if !positional_only
            && let Some(value) = text.filter(|value| value.starts_with('-') && *value != "-")
        {
            parse_short(value, &arguments, &mut index, &mut options)
                .map_err(|error| error.with_command(topic))?;
            index += 1;
            continue;
        }
        if topic.is_none() {
            // After "version", one more command name is still parsed here;
            // "version git" prints the version.
            let name = text.ok_or_else(|| ParseError::other("command name is not valid UTF-8"))?;
            if version_command {
                version_words += 1;
            }
            command_name = name;
            match name {
                "git" => command = Some(CommandKind::Git),
                "dir" | "file" | "directory" => command = Some(CommandKind::Directory),
                "stdin" => command = Some(CommandKind::Stdin),
                "version" => version_command = true,
                "help" if !version_command => meta = Some(Topic::Help),
                "completion" if !version_command => meta = Some(Topic::Completion),
                value => return Err(ParseError::unknown_command(value)),
            }
        } else {
            positionals.try_reserve(1).map_err(|error| {
                ParseError::other(format!("not enough memory for source path: {error}"))
            })?;
            positionals.push(copy_path(argument)?);
        }
        index += 1;
    }

    if version_command {
        if !positionals.is_empty() {
            return Err(ParseError::other(format!(
                "version accepts no arguments, but {}",
                given(positionals.len() + version_words)
            )));
        }
        return Ok(Action::Version { qualified: false });
    }
    if let Some(meta) = meta {
        return meta_action(meta, &positionals).map_err(|error| {
            if error.kind == ParseErrorKind::UnknownCommand {
                error
            } else {
                error.with_command(Some(meta))
            }
        });
    }
    let Some(command) = command else {
        return Ok(Action::RootHelp);
    };
    let received = positionals.len();
    let too_many = match command {
        CommandKind::Git if received > 1 => Some(format!(
            "{command_name} accepts at most one repository path, but {}",
            given(received)
        )),
        CommandKind::Directory if received > 1 => Some(format!(
            "{command_name} accepts at most one path, but {}",
            given(received)
        )),
        CommandKind::Stdin if received > 0 => Some(format!(
            "{command_name} accepts no arguments, but {}",
            given(received)
        )),
        _ => None,
    };
    if let Some(message) = too_many {
        return Err(ParseError::other(message).with_command(Some(command.into())));
    }
    let source = positionals
        .pop()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."));
    Ok(Action::Scan(Box::new(Invocation {
        command,
        source,
        options,
    })))
}

/// Describes how many arguments were given, for arity messages.
fn given(count: usize) -> String {
    if count == 1 {
        "1 was given".to_owned()
    } else {
        format!("{count} were given")
    }
}

fn meta_action(meta: Topic, positionals: &[PathBuf]) -> Result<Action, ParseError> {
    let received = positionals.len();
    match meta {
        Topic::Help => match positionals {
            [] => Ok(Action::RootHelp),
            [name] => {
                let name = name
                    .to_str()
                    .ok_or_else(|| ParseError::other("command name is not valid UTF-8"))?;
                cli_spec::topic_by_name(name)
                    .map(Action::CommandHelp)
                    .ok_or_else(|| ParseError::unknown_command(name))
            }
            _ => Err(ParseError::other(format!(
                "help accepts at most one command name, but {}",
                given(received)
            ))),
        },
        Topic::Completion => match positionals {
            [] => Err(ParseError::other(
                "completion needs one argument: bash, zsh, fish or powershell",
            )),
            [name] => name
                .to_str()
                .and_then(Shell::from_name)
                .map(Action::Completion)
                .ok_or_else(|| {
                    ParseError::other(format!(
                        "unknown shell {:?}; use bash, zsh, fish or powershell",
                        name.to_string_lossy()
                    ))
                }),
            _ => Err(ParseError::other(format!(
                "completion accepts at most one shell name, but {}",
                given(received)
            ))),
        },
        Topic::Git | Topic::Directory | Topic::Stdin | Topic::Version => {
            unreachable!("only help and completion are meta commands")
        }
    }
}

fn append_enabled_rules(value: &str, options: &mut Options) -> Result<(), ParseError> {
    const MAX_ENABLED_RULES: usize = 4_096;
    for rule in value.split(',') {
        if options.enable_rules.len() == MAX_ENABLED_RULES {
            return Err(ParseError::other(format!(
                "--enable-rule exceeds the {MAX_ENABLED_RULES}-item safety limit"
            )));
        }
        options.enable_rules.try_reserve(1).map_err(|error| {
            ParseError::other(format!("not enough memory for --enable-rule: {error}"))
        })?;
        options.enable_rules.push(copy_text(rule)?);
    }
    Ok(())
}

fn parse_long(
    argument: &str,
    arguments: &[OsString],
    index: &mut usize,
    command: Option<CommandKind>,
    options: &mut Options,
) -> Result<(), ParseError> {
    let body = &argument[2..];
    let (name, attached) = body
        .split_once('=')
        .map_or((body, None), |(name, value)| (name, Some(value)));
    match name {
        "config" => options.config = nonempty_path(path_value(name, attached, arguments, index)?),
        "complete-profile" => {
            let path = path_value(name, attached, arguments, index)?;
            if path.as_os_str().is_empty() {
                return Err(ParseError::other(
                    "--complete-profile requires a nonempty path",
                ));
            }
            options.complete_profile = Some(path);
        }
        "jobs" => options.jobs = Some(parse_jobs(value(name, attached, arguments, index)?)?),
        "exit-code" => {
            options.exit_code = parse_i32(name, value(name, attached, arguments, index)?)?;
        }
        "report-path" => {
            options.report_path = nonempty_path(path_value(name, attached, arguments, index)?);
        }
        "report-format" => {
            options.report_format = nonempty(value(name, attached, arguments, index)?)?;
        }
        "report-template" => {
            options.report_template = nonempty_path(path_value(name, attached, arguments, index)?);
        }
        "baseline-path" => {
            options.baseline_path = nonempty_path(path_value(name, attached, arguments, index)?);
        }
        "log-level" => options.log_level = copy_text(value(name, attached, arguments, index)?)?,
        "verbose" => options.verbose = boolean(name, attached)?,
        "no-color" => options.no_color = boolean(name, attached)?,
        "max-target-megabytes" => {
            options.max_target_megabytes =
                parse_i64(name, value(name, attached, arguments, index)?)?;
        }
        "ignore-rustleaks-allow" | "ignore-gitleaks-allow" => {
            options.ignore_allow_markers = boolean(name, attached)?;
        }
        "redact" => {
            options.redact = attached.map_or(Ok(100), |v| {
                v.parse::<usize>().map_err(|_| invalid_value(name, v))
            })?;
        }
        "no-banner" => options.no_banner = boolean(name, attached)?,
        "enable-rule" => {
            append_enabled_rules(value(name, attached, arguments, index)?, options)?;
        }
        "rustleaks-ignore-path" | "gitleaks-ignore-path" => {
            options.ignore_path = path_value(name, attached, arguments, index)?;
        }
        "base64-mode" => {
            options.base64_mode = match value(name, attached, arguments, index)? {
                "compatible" => Base64Mode::Compatible,
                "extended" => Base64Mode::Extended,
                other => return Err(invalid_value(name, other)),
            };
        }
        "max-decode-depth" => {
            options.max_decode_depth = parse_i64(name, value(name, attached, arguments, index)?)?;
        }
        "max-archive-depth" => {
            options.max_archive_depth = parse_i64(name, value(name, attached, arguments, index)?)?;
        }
        "timeout" => {
            options.timeout_seconds = parse_i64(name, value(name, attached, arguments, index)?)?;
        }
        "platform" => {
            require_command(command, CommandKind::Git, name)?;
            options.platform = copy_text(value(name, attached, arguments, index)?)?;
        }
        "staged" => {
            require_command(command, CommandKind::Git, name)?;
            options.staged = boolean(name, attached)?;
        }
        "pre-commit" => {
            require_command(command, CommandKind::Git, name)?;
            options.pre_commit = boolean(name, attached)?;
        }
        "log-opts" => {
            require_command(command, CommandKind::Git, name)?;
            options.git_log_args = Some(copy_text(value(name, attached, arguments, index)?)?);
        }
        "follow-symlinks" => {
            require_command(command, CommandKind::Directory, name)?;
            options.follow_symlinks = boolean(name, attached)?;
        }
        "scan-git-metadata" => {
            require_command(command, CommandKind::Directory, name)?;
            options.scan_git_metadata = boolean(name, attached)?;
        }
        _ => return Err(ParseError::unknown_long(name)),
    }
    Ok(())
}

fn parse_short(
    argument: &str,
    arguments: &[OsString],
    index: &mut usize,
    options: &mut Options,
) -> Result<(), ParseError> {
    if let Some(value) = argument.strip_prefix("-c=") {
        options.config = nonempty_path(copy_path(OsStr::new(value))?);
        return Ok(());
    }
    match argument {
        "-v" => options.verbose = true,
        "-c" => options.config = nonempty_path(next_path("config", arguments, index)?),
        "-r" => options.report_path = nonempty_path(next_path("report-path", arguments, index)?),
        "-f" => options.report_format = nonempty(next("report-format", arguments, index)?)?,
        "-b" => {
            options.baseline_path = nonempty_path(next_path("baseline-path", arguments, index)?);
        }
        "-l" => options.log_level = copy_text(next("log-level", arguments, index)?)?,
        "-j" => options.jobs = Some(parse_jobs(next("jobs", arguments, index)?)?),
        "-i" => {
            options.ignore_path = next_path("rustleaks-ignore-path", arguments, index)?;
        }
        _ => {
            let shorthand = argument
                .strip_prefix('-')
                .and_then(|value| value.chars().next())
                .unwrap_or('-');
            return Err(ParseError::other(format!(
                "unknown shorthand flag: '{shorthand}' in {argument}"
            )));
        }
    }
    Ok(())
}

fn require_command(
    actual: Option<CommandKind>,
    expected: CommandKind,
    flag: &str,
) -> Result<(), ParseError> {
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(ParseError::unknown_long(flag))
    }
}

fn boolean(name: &str, attached: Option<&str>) -> Result<bool, ParseError> {
    match attached {
        None | Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(value) => Err(invalid_value(name, value)),
    }
}

fn value<'a>(
    name: &str,
    attached: Option<&'a str>,
    arguments: &'a [OsString],
    index: &mut usize,
) -> Result<&'a str, ParseError> {
    attached.map_or_else(|| next(name, arguments, index), Ok)
}

fn path_value(
    name: &str,
    attached: Option<&str>,
    arguments: &[OsString],
    index: &mut usize,
) -> Result<PathBuf, ParseError> {
    attached.map_or_else(
        || next_path(name, arguments, index),
        |value| copy_path(OsStr::new(value)),
    )
}

fn next_path(name: &str, arguments: &[OsString], index: &mut usize) -> Result<PathBuf, ParseError> {
    *index += 1;
    arguments
        .get(*index)
        .ok_or_else(|| ParseError::other(format!("flag --{name} requires a value")))
        .and_then(|value| copy_path(value))
}

fn next<'a>(
    name: &str,
    arguments: &'a [OsString],
    index: &mut usize,
) -> Result<&'a str, ParseError> {
    *index += 1;
    arguments
        .get(*index)
        .ok_or_else(|| ParseError::other(format!("flag --{name} requires a value")))?
        .to_str()
        .ok_or_else(|| ParseError::other(format!("flag --{name} requires a UTF-8 value")))
}

fn parse_i64(name: &str, value: &str) -> Result<i64, ParseError> {
    value.parse().map_err(|_| invalid_value(name, value))
}
fn parse_i32(name: &str, value: &str) -> Result<i32, ParseError> {
    value.parse().map_err(|_| {
        ParseError::other(format!(
            "the --{name} argument {value:?} is not a whole number from {} to {}",
            i32::MIN,
            i32::MAX
        ))
    })
}
/// Accepts only ASCII digits, so signs, spaces and zero are errors. There is
/// no fixed maximum; the runner reports a thread that cannot be started.
fn parse_jobs(value: &str) -> Result<NonZeroUsize, ParseError> {
    let digits = value.bytes().all(|byte| byte.is_ascii_digit());
    match value.parse::<NonZeroUsize>() {
        Ok(jobs) if digits => Ok(jobs),
        _ => Err(ParseError::other(format!(
            "the --jobs argument {value:?} is not a whole number from 1 to {}",
            usize::MAX
        ))),
    }
}
fn invalid_value(name: &str, value: &str) -> ParseError {
    ParseError::other(format!("invalid value {value:?} for --{name}"))
}
fn nonempty(value: &str) -> Result<Option<String>, ParseError> {
    if value.is_empty() {
        Ok(None)
    } else {
        copy_text(value).map(Some)
    }
}
fn nonempty_path(value: PathBuf) -> Option<PathBuf> {
    (!value.as_os_str().is_empty()).then_some(value)
}

fn copy_text(value: &str) -> Result<String, ParseError> {
    const MAX_TEXT_VALUE_BYTES: usize = 1_048_576;
    if value.len() > MAX_TEXT_VALUE_BYTES {
        return Err(ParseError::other(format!(
            "command-line text value exceeds the {MAX_TEXT_VALUE_BYTES}-byte safety limit"
        )));
    }
    let mut copied = String::new();
    copied.try_reserve_exact(value.len()).map_err(|error| {
        ParseError::other(format!("not enough memory for command-line text: {error}"))
    })?;
    copied.push_str(value);
    Ok(copied)
}

fn copy_path(value: &OsStr) -> Result<PathBuf, ParseError> {
    const MAX_PATH_VALUE_BYTES: usize = 1_048_576;
    let length = value.as_encoded_bytes().len();
    if length > MAX_PATH_VALUE_BYTES {
        return Err(ParseError::other(format!(
            "command-line path exceeds the {MAX_PATH_VALUE_BYTES}-byte safety limit"
        )));
    }
    let mut copied = PathBuf::new();
    copied.try_reserve_exact(length).map_err(|error| {
        ParseError::other(format!("not enough memory for command-line path: {error}"))
    })?;
    copied.push(value);
    Ok(copied)
}

fn retain_arguments(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Vec<OsString>, ParseError> {
    const MAX_ARGUMENTS: usize = 4_096;
    let mut retained = Vec::<OsString>::new();
    for argument in arguments {
        if retained.len() == MAX_ARGUMENTS {
            return Err(ParseError::other(format!(
                "command line exceeds the {MAX_ARGUMENTS}-argument safety limit"
            )));
        }
        retained.try_reserve(1).map_err(|error| {
            ParseError::other(format!("not enough memory for command line: {error}"))
        })?;
        retained.push(argument);
    }
    Ok(retained)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parsed(values: &[&str]) -> Result<Action, ParseError> {
        parse(values.iter().map(OsString::from))
    }

    #[test]
    fn base64_mode_defaults_to_compatible_and_requires_a_known_value() {
        for (arguments, expected) in [
            (vec!["stdin"], Base64Mode::Compatible),
            (
                vec!["stdin", "--base64-mode=compatible"],
                Base64Mode::Compatible,
            ),
            (
                vec!["stdin", "--base64-mode", "extended"],
                Base64Mode::Extended,
            ),
        ] {
            let Action::Scan(invocation) = parsed(&arguments).unwrap() else {
                panic!("expected scan");
            };
            assert_eq!(invocation.options.base64_mode, expected);
        }
        for arguments in [
            vec!["stdin", "--base64-mode"],
            vec!["stdin", "--base64-mode="],
            vec!["stdin", "--base64-mode=unknown"],
            vec!["stdin", "--base64-mode=Extended"],
        ] {
            let error = parsed(&arguments).unwrap_err();
            assert_eq!(error.kind, ParseErrorKind::Other);
            assert!(error.message.contains("--base64-mode"));
        }
    }

    #[test]
    fn jobs_takes_a_positive_whole_number_and_the_last_value_wins() {
        let jobs = |arguments: &[&str]| {
            let Action::Scan(invocation) = parsed(arguments).unwrap() else {
                panic!("expected scan");
            };
            invocation.options.jobs.map(NonZeroUsize::get)
        };
        assert_eq!(jobs(&["stdin"]), None);
        assert_eq!(jobs(&["stdin", "--jobs", "1"]), Some(1));
        assert_eq!(jobs(&["dir", "--jobs=4"]), Some(4));
        assert_eq!(jobs(&["git", "-j", "128"]), Some(128));
        assert_eq!(jobs(&["dir", "--jobs", "007"]), Some(7));
        assert_eq!(jobs(&["dir", "--jobs", "2", "-j", "3"]), Some(3));
        for value in [
            "0",
            "00",
            "-1",
            "+2",
            "",
            " 2",
            "2 ",
            "1.5",
            "x",
            "18446744073709551616",
        ] {
            let error = parsed(&["dir", "--jobs", value]).unwrap_err();
            assert_eq!(error.kind, ParseErrorKind::Other, "{value:?}");
            assert_eq!(
                error.message,
                format!(
                    "the --jobs argument {value:?} is not a whole number from 1 to {}",
                    usize::MAX
                )
            );
            assert_eq!(error.command, Some(Topic::Directory));
            let short = parsed(&["stdin", "-j", value]).unwrap_err();
            assert_eq!(short.message, error.message);
        }
        for arguments in [vec!["dir", "--jobs"], vec!["dir", "-j"]] {
            assert_eq!(
                parsed(&arguments).unwrap_err().message,
                "flag --jobs requires a value"
            );
        }
        assert_eq!(
            parsed(&["version", "--jobs", "2"]).unwrap(),
            Action::Version { qualified: false }
        );
    }

    #[test]
    fn help_and_completion_commands_parse_without_scanning() {
        assert_eq!(parsed(&[]).unwrap(), Action::RootHelp);
        assert_eq!(parsed(&["help"]).unwrap(), Action::RootHelp);
        assert_eq!(parsed(&["-h"]).unwrap(), Action::RootHelp);
        assert_eq!(
            parsed(&["help", "file"]).unwrap(),
            Action::CommandHelp(Topic::Directory)
        );
        assert_eq!(
            parsed(&["version", "--help"]).unwrap(),
            Action::CommandHelp(Topic::Version)
        );
        assert_eq!(
            parsed(&["completion", "-h"]).unwrap(),
            Action::CommandHelp(Topic::Completion)
        );
        assert_eq!(
            parsed(&["completion", "--no-banner", "zsh"]).unwrap(),
            Action::Completion(Shell::Zsh)
        );
        assert_eq!(
            parsed(&["version", "--version"]).unwrap(),
            Action::Version { qualified: true }
        );
        let unknown = parsed(&["help", "nope"]).unwrap_err();
        assert_eq!(unknown.kind, ParseErrorKind::UnknownCommand);
        assert_eq!(unknown.command, None);
        for arguments in [
            vec!["help", "git", "dir"],
            vec!["completion"],
            vec!["completion", "tcsh"],
            vec!["completion", "bash", "zsh"],
        ] {
            let error = parsed(&arguments).unwrap_err();
            assert_eq!(error.kind, ParseErrorKind::Other, "{arguments:?}");
            assert!(error.command.is_some(), "{arguments:?}");
        }
        let flag = parsed(&["completion", "bash", "--platform=github"]).unwrap_err();
        assert_eq!(flag.kind, ParseErrorKind::UnknownLong);
        assert_eq!(flag.command, Some(Topic::Completion));
        assert!(parsed(&["git", "--version"]).unwrap_err().command.is_none());
    }

    #[test]
    fn version_keeps_its_command_name_grammar() {
        for arguments in [
            vec!["version", "git"],
            vec!["version", "file", "--follow-symlinks"],
            vec!["version", "stdin", "--no-banner"],
            vec!["version", "version"],
        ] {
            assert_eq!(
                parsed(&arguments).unwrap(),
                Action::Version { qualified: false },
                "{arguments:?}"
            );
        }
        assert_eq!(
            parsed(&["version", "git", "--help"]).unwrap(),
            Action::CommandHelp(Topic::Git)
        );
        for name in ["help", "completion", "nope"] {
            let error = parsed(&["version", name]).unwrap_err();
            assert_eq!(error.kind, ParseErrorKind::UnknownCommand, "{name}");
        }
        let extra = parsed(&["version", "dir", "a"]).unwrap_err();
        assert_eq!(extra.kind, ParseErrorKind::Other);
        assert_eq!(extra.command, None);
        assert_eq!(
            extra.message,
            "version accepts no arguments, but 2 were given"
        );
        let flag = parsed(&["version", "--platform=github"]).unwrap_err();
        assert_eq!(flag.kind, ParseErrorKind::UnknownLong);
        assert_eq!(flag.command, None);
    }

    #[test]
    fn arity_and_integer_messages_name_the_command_and_value() {
        for (arguments, message) in [
            (
                vec!["git", "a", "b"],
                "git accepts at most one repository path, but 2 were given",
            ),
            (
                vec!["directory", "a", "b", "c"],
                "directory accepts at most one path, but 3 were given",
            ),
            (
                vec!["file", "a", "b"],
                "file accepts at most one path, but 2 were given",
            ),
            (
                vec!["version", "dir", "a"],
                "version accepts no arguments, but 2 were given",
            ),
            (
                vec!["stdin", "a"],
                "stdin accepts no arguments, but 1 was given",
            ),
            (
                vec!["stdin", "--exit-code=x"],
                "the --exit-code argument \"x\" is not a whole number from -2147483648 to 2147483647",
            ),
        ] {
            assert_eq!(parsed(&arguments).unwrap_err().message, message);
        }
    }

    /// Every flag that the parser accepts, with a sample value and the
    /// commands that accept it. Written by hand from `parse_long` and
    /// `parse_short`, not from the help table.
    const ACCEPTED_FLAGS: &[(&str, &[&str])] = &[
        ("--config=x", SCAN),
        ("-c x", SCAN),
        ("--complete-profile=x", SCAN),
        ("--jobs=2", SCAN),
        ("-j 2", SCAN),
        ("--exit-code=3", SCAN),
        ("--report-path=x", SCAN),
        ("-r x", SCAN),
        ("--report-format=json", SCAN),
        ("-f json", SCAN),
        ("--report-template=x", SCAN),
        ("--baseline-path=x", SCAN),
        ("-b x", SCAN),
        ("--log-level=debug", SCAN),
        ("-l debug", SCAN),
        ("--verbose", SCAN),
        ("-v", SCAN),
        ("--no-color", SCAN),
        ("--max-target-megabytes=1", SCAN),
        ("--ignore-rustleaks-allow", SCAN),
        ("--ignore-gitleaks-allow", SCAN),
        ("--redact=5", SCAN),
        ("--no-banner", SCAN),
        ("--enable-rule=x", SCAN),
        ("--rustleaks-ignore-path=x", SCAN),
        ("--gitleaks-ignore-path=x", SCAN),
        ("-i x", SCAN),
        ("--base64-mode=extended", SCAN),
        ("--max-decode-depth=1", SCAN),
        ("--max-archive-depth=1", SCAN),
        ("--timeout=1", SCAN),
        ("--platform=github", &["git"]),
        ("--staged", &["git"]),
        ("--pre-commit", &["git"]),
        ("--log-opts=x", &["git"]),
        ("--follow-symlinks", &["dir", "file", "directory"]),
        ("--scan-git-metadata", &["dir", "file", "directory"]),
        ("--no-descriptions", &["completion"]),
    ];
    const SCAN: &[&str] = &["git", "dir", "file", "directory", "stdin"];

    fn flag_name(spelling: &str) -> &str {
        spelling.split(['=', ' ']).next().unwrap()
    }

    #[test]
    fn every_parser_flag_is_in_the_help_table_for_the_same_commands() {
        use std::collections::BTreeSet;

        let mut literal = BTreeSet::new();
        for (spelling, commands) in ACCEPTED_FLAGS {
            for command in *commands {
                literal.insert((flag_name(spelling).to_owned(), (*command).to_owned()));
                let mut arguments = vec![*command];
                if *command == "completion" {
                    arguments.push("bash");
                }
                arguments.extend(spelling.split(' '));
                let action = parsed(&arguments).unwrap();
                assert!(
                    matches!(action, Action::Scan(_) | Action::Completion(_)),
                    "{arguments:?}"
                );
            }
        }
        let mut table = BTreeSet::new();
        for command in cli_spec::COMMANDS {
            let names = std::iter::once(command.name).chain(command.aliases.iter().copied());
            for name in names {
                let flags = command.flags.iter().chain(if command.scan {
                    cli_spec::SCAN_FLAGS
                } else {
                    &[]
                });
                for flag in flags {
                    table.insert((format!("--{}", flag.long), name.to_owned()));
                    if let Some(short) = flag.short {
                        table.insert((format!("-{short}"), name.to_owned()));
                    }
                }
                if command.scan {
                    for legacy in cli_spec::LEGACY_FLAGS {
                        table.insert((format!("--{}", legacy.long), name.to_owned()));
                    }
                }
            }
        }
        assert_eq!(literal, table);
    }

    #[test]
    fn completion_accepts_and_ignores_no_descriptions() {
        for arguments in [
            vec!["completion", "--no-descriptions", "fish"],
            vec!["completion", "zsh", "--no-descriptions=false"],
            vec!["completion", "--no-descriptions=true", "bash"],
        ] {
            assert!(
                matches!(parsed(&arguments).unwrap(), Action::Completion(_)),
                "{arguments:?}"
            );
        }
        let invalid = parsed(&["completion", "--no-descriptions=maybe", "bash"]).unwrap_err();
        assert_eq!(invalid.kind, ParseErrorKind::Other);
        assert_eq!(invalid.command, Some(Topic::Completion));
        for command in ["stdin", "help", "version"] {
            assert_eq!(
                parsed(&[command, "--no-descriptions"]).unwrap_err().kind,
                ParseErrorKind::UnknownLong,
                "{command}"
            );
        }
    }

    #[test]
    fn redact_does_not_consume_following_token() {
        assert!(parsed(&["stdin", "--redact", "20"]).is_err());
        let Action::Scan(invocation) = parsed(&["stdin", "--redact=20"]).unwrap() else {
            panic!("expected scan");
        };
        assert_eq!(invocation.options.redact, 20);
    }

    #[test]
    fn safe_arity_and_unknown_classification() {
        assert!(parsed(&["dir", "a", "b"]).is_err());
        assert!(parsed(&["stdin", "ignored"]).is_err());
        assert_eq!(
            parsed(&["dir", "--missing"]).unwrap_err().kind,
            ParseErrorKind::UnknownLong
        );
        assert_eq!(
            parsed(&["dir", "-x"]).unwrap_err().kind,
            ParseErrorKind::Other
        );
    }

    #[test]
    fn aliases_and_repeated_rule_csv_are_retained() {
        for alias in ["dir", "file", "directory"] {
            let Action::Scan(invocation) =
                parsed(&[alias, "--enable-rule=a,b", "--enable-rule", "a"]).unwrap()
            else {
                panic!("expected scan");
            };
            assert_eq!(invocation.command, CommandKind::Directory);
            assert_eq!(invocation.options.enable_rules, ["a", "b", "a"]);
        }
    }

    #[test]
    fn major_detector_source_and_git_flags_map_without_global_state() {
        let Action::Scan(invocation) = parsed(&[
            "git",
            "repo",
            "--no-banner",
            "--no-color",
            "--verbose",
            "--ignore-gitleaks-allow",
            "--max-target-megabytes=2",
            "--max-decode-depth=-1",
            "--max-archive-depth=3",
            "--timeout=4",
            "--platform=GitHub",
            "--pre-commit",
            "--staged",
            "--log-opts=--all --since=now",
        ])
        .unwrap() else {
            panic!("expected scan");
        };
        assert_eq!(invocation.source, PathBuf::from("repo"));
        assert!(invocation.options.no_banner);
        assert!(invocation.options.no_color);
        assert!(invocation.options.verbose);
        assert!(invocation.options.ignore_allow_markers);
        assert_eq!(invocation.options.max_target_megabytes, 2);
        assert_eq!(invocation.options.max_decode_depth, -1);
        assert_eq!(invocation.options.max_archive_depth, 3);
        assert_eq!(invocation.options.timeout_seconds, 4);
        assert_eq!(invocation.options.platform, "GitHub");
        assert!(invocation.options.pre_commit);
        assert!(invocation.options.staged);
        assert_eq!(
            invocation.options.git_log_args.as_deref(),
            Some("--all --since=now")
        );
    }

    #[test]
    fn version_accepts_persistent_flags_and_config_equals_shorthand() {
        assert_eq!(
            parsed(&["version", "--no-banner"]).unwrap(),
            Action::Version { qualified: false }
        );
        let Action::Scan(invocation) = parsed(&["stdin", "-c=config.toml"]).unwrap() else {
            panic!("expected scan");
        };
        assert_eq!(
            invocation.options.config,
            Some(PathBuf::from("config.toml"))
        );
    }

    #[test]
    fn public_parser_has_a_deterministic_argument_count_limit() {
        let error = parse(
            std::iter::once(OsString::from("stdin"))
                .chain(std::iter::repeat_n(OsString::from("--no-banner"), 4_096)),
        )
        .unwrap_err();
        assert!(error.message.contains("4096-argument safety limit"));
    }

    #[cfg(unix)]
    #[test]
    fn native_non_utf8_source_and_path_values_are_not_text_decoded() {
        use std::os::unix::ffi::OsStringExt;

        let source = OsString::from_vec(b"source-\xff".to_vec());
        let config = OsString::from_vec(b"config-\xfe".to_vec());
        let Action::Scan(invocation) = parse([
            OsString::from("dir"),
            source.clone(),
            OsString::from("-c"),
            config.clone(),
        ])
        .unwrap() else {
            panic!("expected scan");
        };
        assert_eq!(invocation.source, PathBuf::from(source));
        assert_eq!(invocation.options.config, Some(PathBuf::from(config)));
    }
}
