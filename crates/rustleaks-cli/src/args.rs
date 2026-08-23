use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandKind {
    Directory,
    Git,
    Stdin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    RootHelp,
    CommandHelp(CommandKind),
    Version { qualified: bool },
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
    pub max_archive_depth: i64,
    pub timeout_seconds: i64,
    pub platform: String,
    pub staged: bool,
    pub pre_commit: bool,
    pub git_log_args: Option<String>,
    pub follow_symlinks: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            config: None,
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
            max_archive_depth: 0,
            timeout_seconds: 0,
            platform: String::new(),
            staged: false,
            pre_commit: false,
            git_log_args: None,
            follow_symlinks: false,
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
    pub command: Option<CommandKind>,
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
            message: format!("unknown command {value:?} for \"rustleaks\""),
            command: None,
        }
    }

    fn with_command(mut self, command: Option<CommandKind>) -> Self {
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
    while index < arguments.len() {
        let argument = &arguments[index];
        if !positional_only && argument == OsStr::new("--") {
            positional_only = true;
            index += 1;
            continue;
        }
        let text = argument.to_str();
        if text.is_none()
            && (command.is_none() && !version_command
                || !positional_only && argument.as_encoded_bytes().starts_with(b"-"))
        {
            return Err(ParseError::other(
                "command and option names must be valid UTF-8",
            ));
        }
        if !positional_only && matches!(text, Some("--help" | "-h")) {
            return Ok(command.map_or(Action::RootHelp, Action::CommandHelp));
        }
        if !positional_only && text == Some("--version") {
            if command.is_some() {
                return Err(ParseError::other("--version is a root option"));
            }
            return Ok(Action::Version { qualified: true });
        }
        if !positional_only && text.is_some_and(|value| value.starts_with("--")) {
            let value = text.ok_or_else(|| ParseError::other("option name is not valid UTF-8"))?;
            parse_long(value, &arguments, &mut index, command, &mut options)
                .map_err(|error| error.with_command(command))?;
            index += 1;
            continue;
        }
        if !positional_only && text.is_some_and(|value| value.starts_with('-') && value != "-") {
            let value = text.ok_or_else(|| ParseError::other("option name is not valid UTF-8"))?;
            parse_short(value, &arguments, &mut index, &mut options)
                .map_err(|error| error.with_command(command))?;
            index += 1;
            continue;
        }
        if command.is_none() {
            let name = text.ok_or_else(|| ParseError::other("command name is not valid UTF-8"))?;
            command = Some(match name {
                "git" => CommandKind::Git,
                "dir" | "file" | "directory" => CommandKind::Directory,
                "stdin" => CommandKind::Stdin,
                "version" => {
                    version_command = true;
                    command = None;
                    index += 1;
                    continue;
                }
                value => return Err(ParseError::unknown_command(value)),
            });
        } else {
            positionals.try_reserve(1).map_err(|error| {
                ParseError::other(format!("could not retain source path: {error}"))
            })?;
            positionals.push(copy_path(argument)?);
        }
        index += 1;
    }

    if version_command {
        if !positionals.is_empty() {
            return Err(ParseError::other("version accepts no arguments"));
        }
        return Ok(Action::Version { qualified: false });
    }
    let Some(command) = command else {
        return Ok(Action::RootHelp);
    };
    let maximum = match command {
        CommandKind::Git | CommandKind::Directory => 1,
        CommandKind::Stdin => 0,
    };
    if positionals.len() > maximum {
        return Err(ParseError::other(format!(
            "accepts at most {maximum} arg(s), received {}",
            positionals.len()
        ))
        .with_command(Some(command)));
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
            for rule in value(name, attached, arguments, index)?.split(',') {
                if options.enable_rules.len() == 4_096 {
                    return Err(ParseError::other(
                        "--enable-rule exceeds the 4096-item safety limit",
                    ));
                }
                options.enable_rules.try_reserve(1).map_err(|error| {
                    ParseError::other(format!("could not retain --enable-rule: {error}"))
                })?;
                options.enable_rules.push(copy_text(rule)?);
            }
        }
        "rustleaks-ignore-path" | "gitleaks-ignore-path" => {
            options.ignore_path = path_value(name, attached, arguments, index)?;
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
            "invalid argument {value:?} for \"--{name}\" flag: strconv.ParseInt: parsing {value:?}: invalid syntax"
        ))
    })
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
        ParseError::other(format!("could not retain command-line text: {error}"))
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
        ParseError::other(format!("could not retain command-line path: {error}"))
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
            ParseError::other(format!("could not retain command line: {error}"))
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
