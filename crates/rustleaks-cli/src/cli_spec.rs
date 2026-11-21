//! The command and flag table that drives help, usage blocks and completion
//! scripts.
//!
//! The parser in `args.rs` stays the authority for what is accepted. Unit
//! tests check that every flag in this table parses for its commands.

use crate::args::CommandKind;

/// Every command, alias or meta command that has its own help page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Topic {
    Git,
    Directory,
    Stdin,
    Version,
    Help,
    Completion,
}

impl From<CommandKind> for Topic {
    fn from(command: CommandKind) -> Self {
        match command {
            CommandKind::Git => Self::Git,
            CommandKind::Directory => Self::Directory,
            CommandKind::Stdin => Self::Stdin,
        }
    }
}

/// Shells that `rustleaks completion` supports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Shell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

impl Shell {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "fish" => Some(Self::Fish),
            "powershell" => Some(Self::Powershell),
            _ => None,
        }
    }
}

pub(crate) const SHELLS: &[&str] = &["bash", "zsh", "fish", "powershell"];
pub(crate) const REPORT_FORMATS: &[&str] = &["json", "csv", "junit", "sarif", "template"];
pub(crate) const LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error", "fatal"];
pub(crate) const BASE64_MODES: &[&str] = &["compatible", "extended"];
pub(crate) const PLATFORMS: &[&str] = &[
    "github",
    "gitlab",
    "azuredevops",
    "gitea",
    "bitbucket",
    "none",
];

/// Flag groups in the order that help prints them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Group {
    Configuration,
    Suppression,
    Reports,
    Limits,
    Logging,
}

impl Group {
    pub(crate) const ALL: [Self; 5] = [
        Self::Configuration,
        Self::Suppression,
        Self::Reports,
        Self::Limits,
        Self::Logging,
    ];

    pub(crate) fn heading(self) -> &'static str {
        match self {
            Self::Configuration => "Configuration flags:",
            Self::Suppression => "Suppression flags:",
            Self::Reports => "Report flags:",
            Self::Limits => "Limit and decoding flags:",
            Self::Logging => "Logging flags:",
        }
    }
}

/// How a flag takes its value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Value {
    /// The flag takes no value.
    Switch,
    /// The flag takes a value only in the `--flag=value` form.
    Optional(&'static str),
    /// The value is a file or directory path.
    Path(&'static str),
    /// The value is free text or a number.
    Text(&'static str),
    /// The value is one of a fixed list.
    Choice(&'static str, &'static [&'static str]),
}

impl Value {
    pub(crate) fn takes_separate_value(self) -> bool {
        matches!(self, Self::Path(_) | Self::Text(_) | Self::Choice(..))
    }
}

/// One accepted flag.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Flag {
    pub long: &'static str,
    pub short: Option<char>,
    pub value: Value,
    pub repeatable: bool,
    /// The help section of a shared scan flag. Help ignores it for other
    /// flags, which it lists under their command.
    pub group: Group,
    /// Help lines. The first line is also the short description in
    /// completion scripts.
    pub help: &'static [&'static str],
}

impl Flag {
    pub(crate) fn brief(&self) -> &'static str {
        let line = self.help.first().copied().unwrap_or_default();
        line.strip_suffix('.').unwrap_or(line)
    }
}

/// A legacy Gitleaks flag name with the same meaning as a current flag.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LegacyFlag {
    pub long: &'static str,
    pub current: &'static str,
}

/// What a command accepts after its flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operand {
    None,
    Directory,
    Path,
    Command,
    Shell,
}

/// One command with its help text.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Command {
    pub topic: Topic,
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub summary: &'static str,
    pub usage: &'static str,
    pub details: &'static [&'static str],
    pub examples: &'static [&'static str],
    pub flags_heading: &'static str,
    pub flags: &'static [Flag],
    /// The command accepts the shared scan flags.
    pub scan: bool,
    pub operand: Operand,
}

const fn flag(
    long: &'static str,
    short: Option<char>,
    value: Value,
    group: Group,
    help: &'static [&'static str],
) -> Flag {
    Flag {
        long,
        short,
        value,
        repeatable: false,
        group,
        help,
    }
}

const fn repeatable(flag: Flag) -> Flag {
    Flag {
        repeatable: true,
        ..flag
    }
}

/// Flags that every scan command accepts, in help order within each group.
pub(crate) const SCAN_FLAGS: &[Flag] = &[
    flag(
        "config",
        Some('c'),
        Value::Path("path"),
        Group::Configuration,
        &[
            "Read the configuration from this file.",
            "See \"Configuration order\" in 'rustleaks help'.",
        ],
    ),
    repeatable(flag(
        "enable-rule",
        None,
        Value::Text("ids"),
        Group::Configuration,
        &[
            "Use only these rules. Separate rule IDs with commas.",
            "You can repeat this flag.",
        ],
    )),
    flag(
        "baseline-path",
        Some('b'),
        Value::Path("path"),
        Group::Suppression,
        &["Ignore findings that are already in this JSON report."],
    ),
    flag(
        "rustleaks-ignore-path",
        Some('i'),
        Value::Path("path"),
        Group::Suppression,
        &[
            "Read ignore entries from this file or folder.",
            "In a folder, Rustleaks reads .rustleaksignore and",
            ".gitleaksignore. Default: \".\", the current folder.",
            "Ignore files in the scanned folder are always read.",
        ],
    ),
    flag(
        "ignore-rustleaks-allow",
        None,
        Value::Switch,
        Group::Suppression,
        &[
            "Do not skip lines that have an allow comment.",
            "Allow comments are rustleaks:allow and gitleaks:allow.",
        ],
    ),
    flag(
        "report-path",
        Some('r'),
        Value::Path("path"),
        Group::Reports,
        &[
            "Write a report to this file.",
            "Use \"-\" to write the report to standard output.",
        ],
    ),
    flag(
        "report-format",
        Some('f'),
        Value::Choice("format", REPORT_FORMATS),
        Group::Reports,
        &[
            "Write the report in this format.",
            "Formats: json, csv, junit, sarif and template.",
            "Without this flag, the format comes from the file",
            "extension of --report-path: .json, .csv or .sarif.",
        ],
    ),
    flag(
        "report-template",
        None,
        Value::Path("path"),
        Group::Reports,
        &[
            "Use this template file for the report.",
            "Also give --report-format template.",
        ],
    ),
    flag(
        "exit-code",
        None,
        Value::Text("number"),
        Group::Reports,
        &["Exit with this status when leaks are found.", "Default: 1."],
    ),
    flag(
        "redact",
        None,
        Value::Optional("percent"),
        Group::Reports,
        &[
            "Hide secrets in logs, verbose output and reports.",
            "Without a value, hide the whole secret.",
            "--redact=20 hides 20 percent. Always use \"=\" here.",
        ],
    ),
    flag(
        "verbose",
        Some('v'),
        Value::Switch,
        Group::Reports,
        &["Print each finding to standard output."],
    ),
    flag(
        "no-color",
        None,
        Value::Switch,
        Group::Reports,
        &[
            "Accepted for Gitleaks compatibility.",
            "Rustleaks never prints color.",
        ],
    ),
    flag(
        "max-target-megabytes",
        None,
        Value::Text("number"),
        Group::Limits,
        &[
            "Skip files that are larger than this many megabytes.",
            "0 means no limit. Default: 0.",
        ],
    ),
    flag(
        "max-decode-depth",
        None,
        Value::Text("number"),
        Group::Limits,
        &[
            "Decode encoded text up to this many levels deep.",
            "0 turns decoding off. Default: 5.",
        ],
    ),
    flag(
        "base64-mode",
        None,
        Value::Choice("mode", BASE64_MODES),
        Group::Limits,
        &[
            "Choose how to find base64 text.",
            "Modes: compatible and extended. Default: compatible.",
            "compatible finds the same base64 text as Gitleaks.",
            "extended also finds URL-safe base64, base64 without",
            "padding, and base64 of binary data.",
        ],
    ),
    flag(
        "max-archive-depth",
        None,
        Value::Text("number"),
        Group::Limits,
        &[
            "Scan inside archives nested up to this many levels deep.",
            "0 means archives are not opened. Default: 0.",
        ],
    ),
    flag(
        "timeout",
        None,
        Value::Text("seconds"),
        Group::Limits,
        &[
            "Stop the scan after this many seconds.",
            "0 means no time limit. Default: 0.",
        ],
    ),
    flag(
        "jobs",
        Some('j'),
        Value::Text("number"),
        Group::Limits,
        &[
            "Scan with this many detection threads.",
            "Default: the number of CPUs that Rustleaks may use, up to 12.",
            "This flag overrides workers in a --complete-profile file.",
            "Findings and reports do not depend on this number.",
        ],
    ),
    flag(
        "complete-profile",
        None,
        Value::Path("path"),
        Group::Limits,
        &[
            "Scan with the limits in this profile file.",
            "Rustleaks then reports whether the scan was complete.",
            "The exit status is 2 when the scan was not complete.",
        ],
    ),
    flag(
        "log-level",
        Some('l'),
        Value::Choice("level", LOG_LEVELS),
        Group::Logging,
        &[
            "Show log messages at this level and above.",
            "Levels: trace, debug, info, warn, error and fatal.",
            "Default: info.",
        ],
    ),
    flag(
        "no-banner",
        None,
        Value::Switch,
        Group::Logging,
        &["Do not print the banner."],
    ),
];

/// Legacy Gitleaks names that every scan command accepts.
pub(crate) const LEGACY_FLAGS: &[LegacyFlag] = &[
    LegacyFlag {
        long: "gitleaks-ignore-path",
        current: "rustleaks-ignore-path",
    },
    LegacyFlag {
        long: "ignore-gitleaks-allow",
        current: "ignore-rustleaks-allow",
    },
];

pub(crate) const HELP_FLAG: Flag = flag(
    "help",
    Some('h'),
    Value::Switch,
    Group::Logging,
    &["Print help."],
);

pub(crate) const VERSION_FLAG: Flag = flag(
    "version",
    None,
    Value::Switch,
    Group::Logging,
    &["Print the Rustleaks version."],
);

const GIT_FLAGS: &[Flag] = &[
    flag(
        "log-opts",
        None,
        Value::Text("options"),
        Group::Configuration,
        &[
            "Pass these options to git log.",
            "Example: --log-opts=\"--all\".",
        ],
    ),
    flag(
        "platform",
        None,
        Value::Choice("name", PLATFORMS),
        Group::Configuration,
        &[
            "Make links to findings for this platform.",
            "Platforms: github, gitlab, azuredevops, gitea and",
            "bitbucket. Use none for no links. Without this flag,",
            "Rustleaks finds the platform from the remote URL.",
        ],
    ),
    flag(
        "pre-commit",
        None,
        Value::Switch,
        Group::Configuration,
        &["Scan changes that are not staged or committed yet."],
    ),
    flag(
        "staged",
        None,
        Value::Switch,
        Group::Configuration,
        &["Scan changes that are staged but not committed yet."],
    ),
];

const COMPLETION_FLAGS: &[Flag] = &[flag(
    "no-descriptions",
    None,
    Value::Switch,
    Group::Configuration,
    &["Accepted for Gitleaks compatibility; ignored."],
)];

const DIR_FLAGS: &[Flag] = &[
    flag(
        "follow-symlinks",
        None,
        Value::Switch,
        Group::Configuration,
        &["Scan files that are symbolic links to other files."],
    ),
    flag(
        "scan-git-metadata",
        None,
        Value::Switch,
        Group::Configuration,
        &[
            "Also scan the text metadata files in .git folders.",
            "These are config, config.worktree, HEAD, FETCH_HEAD,",
            "ORIG_HEAD, description, packed-refs, credential files,",
            "the files in hooks, info and logs, and submodule config",
            "files. Objects, the index, packs and lock files are",
            "never read. Without this flag, .git folders that a path",
            "allowlist matches are skipped, as in the default rules.",
        ],
    ),
];

/// Every command in the order that root help lists them.
pub(crate) const COMMANDS: &[Command] = &[
    Command {
        topic: Topic::Git,
        name: "git",
        aliases: &[],
        summary: "Scan the commits of a Git repository.",
        usage: "rustleaks git [flags] [repository]",
        details: &["The default repository is the current folder."],
        examples: &[
            "rustleaks git",
            "rustleaks git --staged",
            "rustleaks git path/to/repo --report-path report.json",
        ],
        flags_heading: "Git flags:",
        flags: GIT_FLAGS,
        scan: true,
        operand: Operand::Directory,
    },
    Command {
        topic: Topic::Directory,
        name: "dir",
        aliases: &["file", "directory"],
        summary: "Scan a directory or a file.",
        usage: "rustleaks dir [flags] [path]",
        details: &[
            "Other names for this command: file, directory.",
            "The default path is the current folder.",
        ],
        examples: &[
            "rustleaks dir",
            "rustleaks dir path/to/folder",
            "rustleaks file notes.txt --verbose",
        ],
        flags_heading: "Directory flags:",
        flags: DIR_FLAGS,
        scan: true,
        operand: Operand::Path,
    },
    Command {
        topic: Topic::Stdin,
        name: "stdin",
        aliases: &[],
        summary: "Scan text from standard input.",
        usage: "rustleaks stdin [flags]",
        details: &[],
        examples: &[
            "cat notes.txt | rustleaks stdin",
            "rustleaks stdin --report-path - --report-format json < notes.txt",
        ],
        flags_heading: "Flags:",
        flags: &[],
        scan: true,
        operand: Operand::None,
    },
    Command {
        topic: Topic::Version,
        name: "version",
        aliases: &[],
        summary: "Print the Rustleaks version.",
        usage: "rustleaks version",
        details: &[
            "'rustleaks version' prints only the version number.",
            "'rustleaks --version' prints \"rustleaks version <number>\".",
            "It also accepts the flags in 'rustleaks help' and ignores them.",
        ],
        examples: &[],
        flags_heading: "Flags:",
        flags: &[],
        scan: false,
        operand: Operand::None,
    },
    Command {
        topic: Topic::Help,
        name: "help",
        aliases: &[],
        summary: "Print help for Rustleaks or for one command.",
        usage: "rustleaks help [command]",
        details: &[
            "'rustleaks help <command>' prints the same text as",
            "'rustleaks <command> --help'.",
            "It also accepts the flags in 'rustleaks help' and ignores them.",
        ],
        examples: &["rustleaks help", "rustleaks help git"],
        flags_heading: "Flags:",
        flags: &[],
        scan: false,
        operand: Operand::Command,
    },
    Command {
        topic: Topic::Completion,
        name: "completion",
        aliases: &[],
        summary: "Print a shell completion script.",
        usage: "rustleaks completion <shell>",
        details: &[
            "Shells: bash, zsh, fish and powershell.",
            "The script is printed to standard output.",
            "It also accepts the flags in 'rustleaks help' and ignores them.",
            "",
            "Bash: save the script in your completions folder.",
            "  mkdir -p ~/.local/share/bash-completion/completions",
            "  rustleaks completion bash > ~/.local/share/bash-completion/completions/rustleaks",
            "Or add this line to ~/.bashrc:",
            "  eval \"$(rustleaks completion bash)\"",
            "",
            "Zsh: save the script as _rustleaks in a folder in $fpath.",
            "  mkdir -p ~/.zfunc",
            "  rustleaks completion zsh > ~/.zfunc/_rustleaks",
            "Then add these lines to ~/.zshrc:",
            "  fpath=(~/.zfunc $fpath)",
            "  autoload -Uz compinit && compinit",
            "",
            "Fish: save the script in your completions folder.",
            "  rustleaks completion fish > ~/.config/fish/completions/rustleaks.fish",
            "",
            "PowerShell: load the script in the current session.",
            "  rustleaks completion powershell | Out-String | Invoke-Expression",
            "To load it in every session, add that line to $PROFILE.",
            "",
            "Open a new shell after you install a script.",
        ],
        examples: &[],
        flags_heading: "Flags:",
        flags: COMPLETION_FLAGS,
        scan: false,
        operand: Operand::Shell,
    },
];

pub(crate) fn command(topic: Topic) -> &'static Command {
    COMMANDS
        .iter()
        .find(|command| command.topic == topic)
        .unwrap_or(&COMMANDS[0])
}

/// Returns the topic for a command name or alias.
pub(crate) fn topic_by_name(name: &str) -> Option<Topic> {
    COMMANDS
        .iter()
        .find(|command| command.name == name || command.aliases.contains(&name))
        .map(|command| command.topic)
}

/// Returns every command name followed by its aliases.
pub(crate) fn command_names() -> impl Iterator<Item = &'static str> {
    COMMANDS
        .iter()
        .flat_map(|command| std::iter::once(command.name).chain(command.aliases.iter().copied()))
}

/// Returns the scan flag with this long name.
pub(crate) fn scan_flag(long: &str) -> Option<&'static Flag> {
    SCAN_FLAGS.iter().find(|flag| flag.long == long)
}

/// Every flag that a command accepts, legacy names excluded.
pub(crate) fn accepted_flags(command: &Command) -> impl Iterator<Item = &'static Flag> {
    let scan: &'static [Flag] = if command.scan { SCAN_FLAGS } else { &[] };
    command
        .flags
        .iter()
        .chain(std::iter::once(&HELP_FLAG))
        .chain(scan.iter())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;
    use crate::args::{Action, parse};

    fn sample(flag: &Flag) -> Vec<String> {
        let name = format!("--{}", flag.long);
        match flag.value {
            Value::Switch => vec![name],
            Value::Optional(_) => vec![format!("{name}=10")],
            Value::Path(_) | Value::Text(_) => vec![name, "1".to_owned()],
            Value::Choice(_, values) => vec![name, values[0].to_owned()],
        }
    }

    fn parses_as_scan(command: &str, extra: &[String]) -> bool {
        let arguments = std::iter::once(command.to_owned())
            .chain(extra.iter().cloned())
            .map(OsString::from);
        matches!(parse(arguments), Ok(Action::Scan(_)))
    }

    #[test]
    fn every_listed_flag_and_short_name_parses_for_each_scan_command() {
        for command in COMMANDS.iter().filter(|command| command.scan) {
            for name in std::iter::once(command.name).chain(command.aliases.iter().copied()) {
                for flag in command.flags.iter().chain(SCAN_FLAGS) {
                    assert!(parses_as_scan(name, &sample(flag)), "{name} {}", flag.long);
                    if let Some(short) = flag.short {
                        let mut arguments = sample(flag);
                        arguments[0] = format!("-{short}");
                        assert!(parses_as_scan(name, &arguments), "{name} -{short}");
                    }
                }
                for legacy in LEGACY_FLAGS {
                    let current = scan_flag(legacy.current).unwrap();
                    let mut arguments = sample(current);
                    arguments[0] = format!("--{}", legacy.long);
                    assert!(parses_as_scan(name, &arguments), "{name} {}", legacy.long);
                }
            }
        }
    }

    #[test]
    fn command_flags_are_rejected_by_other_commands() {
        for command in COMMANDS.iter().filter(|command| command.scan) {
            for other in COMMANDS.iter().filter(|other| other.scan) {
                if other.topic == command.topic {
                    continue;
                }
                for flag in command.flags {
                    assert!(!parses_as_scan(other.name, &sample(flag)));
                }
            }
        }
    }

    #[test]
    fn choice_lists_are_accepted_by_the_parser() {
        for mode in BASE64_MODES {
            assert!(parses_as_scan("stdin", &[format!("--base64-mode={mode}")]));
        }
        for platform in PLATFORMS {
            assert!(parses_as_scan("git", &[format!("--platform={platform}")]));
        }
        for shell in SHELLS {
            assert!(Shell::from_name(shell).is_some());
        }
    }

    #[test]
    fn names_and_briefs_are_safe_in_every_completion_script() {
        let all = COMMANDS
            .iter()
            .flat_map(|command| command.flags.iter())
            .chain(SCAN_FLAGS)
            .chain([&HELP_FLAG, &VERSION_FLAG]);
        for flag in all {
            assert!(
                flag.long
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            );
            let brief = flag.brief();
            assert!(!brief.is_empty());
            assert!(
                !brief.contains(['\'', '"', '[', ']', ':', '\\', '$', '`']),
                "{brief}"
            );
        }
        for command in COMMANDS {
            let summary = command.summary.strip_suffix('.').unwrap();
            assert!(!summary.contains(['\'', '"', '[', ']', ':', '\\', '$', '`']));
        }
        for name in command_names() {
            assert!(name.bytes().all(|byte| byte.is_ascii_lowercase()));
        }
    }

    #[test]
    fn help_names_every_value_of_a_choice_flag() {
        let all = COMMANDS
            .iter()
            .flat_map(|command| command.flags.iter())
            .chain(SCAN_FLAGS);
        for flag in all {
            if let Value::Choice(_, values) = flag.value {
                let help = flag.help.join(" ");
                for value in values {
                    assert!(help.contains(value), "--{} help omits {value}", flag.long);
                }
            }
        }
    }

    #[test]
    fn every_command_name_and_alias_maps_to_its_topic() {
        assert_eq!(topic_by_name("file"), Some(Topic::Directory));
        assert_eq!(topic_by_name("directory"), Some(Topic::Directory));
        assert_eq!(topic_by_name("nope"), None);
        for command in COMMANDS {
            assert_eq!(topic_by_name(command.name), Some(command.topic));
            assert_eq!(super::command(command.topic).name, command.name);
        }
    }
}
