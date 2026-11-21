//! Help, usage, completion and parser error tests.

use super::*;

/// Flags that every scan command accepts, as they appear at the start of a
/// help line. The list is written here, not taken from the CLI source.
const SCAN_FLAG_LINES: &[&str] = &[
    "-c, --config <path>",
    "--enable-rule <ids>",
    "-b, --baseline-path <path>",
    "-i, --rustleaks-ignore-path <path>",
    "--ignore-rustleaks-allow",
    "-r, --report-path <path>",
    "-f, --report-format <format>",
    "--report-template <path>",
    "--exit-code <number>",
    "--redact[=<percent>]",
    "-v, --verbose",
    "--no-color",
    "--max-target-megabytes <number>",
    "--max-decode-depth <number>",
    "--base64-mode <mode>",
    "--max-archive-depth <number>",
    "--timeout <seconds>",
    "-j, --jobs <number>",
    "--complete-profile <path>",
    "-l, --log-level <level>",
    "--no-banner",
    "--gitleaks-ignore-path <path>",
    "--ignore-gitleaks-allow",
    "-h, --help",
];

const GIT_FLAG_LINES: &[&str] = &[
    "--log-opts <options>",
    "--platform <name>",
    "--pre-commit",
    "--staged",
];

const DIR_FLAG_LINES: &[&str] = &["--follow-symlinks", "--scan-git-metadata"];

const COMMAND_NAMES: &[&str] = &[
    "git",
    "dir",
    "file",
    "directory",
    "stdin",
    "version",
    "help",
    "completion",
];

fn stdout_text(cwd: &Path, arguments: &[&str]) -> String {
    let result = output(cwd, arguments);
    assert_eq!(
        result.status.code(),
        Some(0),
        "{arguments:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty(), "{arguments:?}");
    String::from_utf8(result.stdout).unwrap()
}

fn flag_lines(help: &str) -> Vec<&str> {
    help.lines()
        .map(str::trim)
        .filter(|line| line.starts_with('-'))
        .collect()
}

#[test]
fn help_and_version_forms_are_successful_and_side_effect_free() {
    let fixture = Fixture::new();
    for arguments in [vec![], vec!["--help"], vec!["version"], vec!["--version"]] {
        let output = output(&fixture.0, &arguments);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    let version = output(&fixture.0, &["version", "--no-banner"]);
    assert!(version.status.success());
    assert!(!version.stdout.is_empty());
    assert!(version.stderr.is_empty());
    assert!(fs::read_dir(&fixture.0).unwrap().next().is_none());
}

#[test]
fn root_help_forms_agree_and_describe_commands_order_and_exit_status() {
    let fixture = Fixture::new();
    let help = stdout_text(&fixture.0, &[]);
    for arguments in [
        &["--help"][..],
        &["-h"][..],
        &["help"][..],
        &["--no-banner"][..],
    ] {
        assert_eq!(stdout_text(&fixture.0, arguments), help, "{arguments:?}");
    }
    assert!(help.starts_with(
        "Rustleaks finds secrets in Git history, files, directories and standard\ninput. It reads Gitleaks configuration, ignore and baseline files.\n\nUsage:\n  rustleaks <command> [flags]\n\nCommands:\n"
    ));
    for line in [
        "  git         Scan the commits of a Git repository.\n",
        "  dir         Scan a directory or a file. Other names: file, directory.\n",
        "  stdin       Scan text from standard input.\n",
        "  version     Print the Rustleaks version.\n",
        "  help        Print help for Rustleaks or for one command.\n",
        "  completion  Print a shell completion script.\n",
    ] {
        assert!(help.contains(line), "{line}");
    }
    for heading in [
        "\nConfiguration flags:\n",
        "\nSuppression flags:\n",
        "\nReport flags:\n",
        "\nLimit and decoding flags:\n",
        "\nLogging flags:\n",
        "\nLegacy flag names:\n",
    ] {
        assert!(help.contains(heading), "{heading}");
    }
    let lines = flag_lines(&help);
    for flag in SCAN_FLAG_LINES.iter().chain(&["--version"]) {
        assert!(lines.contains(flag), "root help misses {flag}");
    }
    for flag in GIT_FLAG_LINES.iter().chain(DIR_FLAG_LINES) {
        assert!(!lines.contains(flag), "root help lists {flag}");
    }
    assert!(help.contains(
        "Configuration order:
  Rustleaks uses the first configuration that it finds:
    1. --config or -c
    2. RUSTLEAKS_CONFIG, the path of a configuration file
    3. RUSTLEAKS_CONFIG_TOML, the configuration text
    4. GITLEAKS_CONFIG, then GITLEAKS_CONFIG_TOML (legacy names)
    5. .rustleaks.toml in the scanned folder
    6. .gitleaks.toml in the scanned folder (legacy name)
  For stdin, the scanned folder is the current folder.
  If it finds none, Rustleaks uses its built-in default configuration.
"
    ));
    assert!(help.ends_with(
        "Exit status:
  0    No leaks were found.
  1    Leaks were found, the scan stopped early, or an error occurred.
       Use --exit-code to change the status for leaks.
  2    The scan was not complete. Only with --complete-profile.
  126  An unknown long flag, such as --nope, was given.

Run 'rustleaks help <command>' for details.
"
    ));
    assert!(!help.contains(['\u{2013}', '\u{2014}']));

    // The stated exit status for unknown flags matches the parser.
    assert_eq!(
        output(&fixture.0, &["stdin", "--nope"]).status.code(),
        Some(126)
    );
    assert_eq!(output(&fixture.0, &["stdin", "-x"]).status.code(), Some(1));
}

/// Help never offers diagnostics flags or the Gitleaks detect and protect
/// commands, which Rustleaks does not provide.
fn assert_no_unsupported_gitleaks_surface(page: &str) {
    assert!(!page.contains("diagnostics"), "{page}");
    for line in page.lines() {
        let first = line.split_whitespace().next().unwrap_or_default();
        assert!(!["detect", "protect"].contains(&first), "{line}");
    }
}

#[test]
fn command_help_lists_every_accepted_flag() {
    let fixture = Fixture::new();
    let all_command_flags = GIT_FLAG_LINES.iter().chain(DIR_FLAG_LINES);
    for (command_name, usage, command_flags) in [
        ("git", "rustleaks git [flags] [repository]", GIT_FLAG_LINES),
        ("dir", "rustleaks dir [flags] [path]", DIR_FLAG_LINES),
        ("stdin", "rustleaks stdin [flags]", &[][..]),
    ] {
        let help = stdout_text(&fixture.0, &[command_name, "--help"]);
        assert!(
            help.contains(&format!("\n\nUsage:\n  {usage}\n")),
            "{command_name}"
        );
        assert!(
            help.ends_with("\nRun 'rustleaks help' for the configuration order and exit status.\n")
        );
        let lines = flag_lines(&help);
        for flag in SCAN_FLAG_LINES.iter().chain(command_flags) {
            assert!(lines.contains(flag), "{command_name} help misses {flag}");
        }
        for flag in all_command_flags.clone() {
            assert_eq!(
                lines.contains(flag),
                command_flags.contains(flag),
                "{command_name} {flag}"
            );
        }
        assert!(!lines.contains(&"--version"), "{command_name}");
    }
    for (command_name, usage, flags) in [
        ("version", "rustleaks version", &["-h, --help"][..]),
        ("help", "rustleaks help [command]", &["-h, --help"][..]),
        (
            "completion",
            "rustleaks completion <shell>",
            &["--no-descriptions", "-h, --help"][..],
        ),
    ] {
        let help = stdout_text(&fixture.0, &[command_name, "--help"]);
        assert!(help.contains(&format!("\n\nUsage:\n  {usage}\n")));
        assert_eq!(flag_lines(&help), flags, "{command_name}");
    }
}

#[test]
fn help_command_prints_the_same_page_as_the_help_flag() {
    let fixture = Fixture::new();
    let directory = stdout_text(&fixture.0, &["dir", "--help"]);
    let root = stdout_text(&fixture.0, &["--help"]);
    assert_no_unsupported_gitleaks_surface(&root);
    for &name in COMMAND_NAMES {
        let page = stdout_text(&fixture.0, &["help", name]);
        assert_no_unsupported_gitleaks_surface(&page);
        assert_eq!(stdout_text(&fixture.0, &[name, "--help"]), page, "{name}");
        assert_eq!(stdout_text(&fixture.0, &[name, "-h"]), page, "{name}");
        assert_ne!(page, root, "{name}");
        if ["dir", "file", "directory"].contains(&name) {
            assert_eq!(page, directory, "{name}");
        }
    }
}

#[test]
fn help_rejects_unknown_topics_and_extra_arguments() {
    let fixture = Fixture::new();
    let unknown = output(&fixture.0, &["help", "nope"]);
    assert_eq!(unknown.status.code(), Some(1));
    assert!(unknown.stdout.is_empty());
    assert_eq!(
        String::from_utf8(unknown.stderr).unwrap(),
        "Error: unknown command \"nope\"\nRun 'rustleaks help' to list the commands.\nfatal unknown command \"nope\"\n"
    );
    let extra = output(&fixture.0, &["help", "git", "dir"]);
    assert_eq!(extra.status.code(), Some(1));
    assert!(extra.stdout.is_empty());
    assert_eq!(
        String::from_utf8(extra.stderr).unwrap(),
        "Error: help accepts at most one command name, but 2 were given\nUsage:\n  rustleaks help [command]\n\nRun 'rustleaks help help' for details.\n\nfatal help accepts at most one command name, but 2 were given\n"
    );
}

/// Every long flag, written here from the parser, not from the help table.
const COMPLETION_LONG_FLAGS: &[&str] = &[
    "--config",
    "--enable-rule",
    "--baseline-path",
    "--rustleaks-ignore-path",
    "--gitleaks-ignore-path",
    "--ignore-rustleaks-allow",
    "--ignore-gitleaks-allow",
    "--report-path",
    "--report-format",
    "--report-template",
    "--exit-code",
    "--redact",
    "--verbose",
    "--no-color",
    "--max-target-megabytes",
    "--max-decode-depth",
    "--base64-mode",
    "--max-archive-depth",
    "--timeout",
    "--jobs",
    "--complete-profile",
    "--log-level",
    "--no-banner",
    "--help",
    "--version",
    "--log-opts",
    "--platform",
    "--pre-commit",
    "--staged",
    "--follow-symlinks",
    "--scan-git-metadata",
    "--no-descriptions",
];

/// Value lists that each script must offer as one run of tokens.
const COMPLETION_VALUE_LISTS: &[&[&str]] = &[
    &["json", "csv", "junit", "sarif", "template"],
    &["trace", "debug", "info", "warn", "error", "fatal"],
    &["compatible", "extended"],
    &[
        "github",
        "gitlab",
        "azuredevops",
        "gitea",
        "bitbucket",
        "none",
    ],
    &["bash", "zsh", "fish", "powershell"],
    &[
        "git",
        "dir",
        "file",
        "directory",
        "stdin",
        "version",
        "help",
        "completion",
    ],
];

/// Splits a script into words, dropping shell and PowerShell punctuation.
fn script_tokens(script: &str) -> Vec<&str> {
    script
        .split(|c: char| c.is_whitespace() || "'\"(),;|@=[]{}:*".contains(c))
        .filter(|token| !token.is_empty())
        .collect()
}

fn contains_run(tokens: &[&str], run: &[&str]) -> bool {
    tokens.windows(run.len()).any(|window| window == run)
}

#[test]
fn completion_scripts_cover_commands_flags_and_values() {
    let fixture = Fixture::new();
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let script = stdout_text(&fixture.0, &["completion", shell]);
        assert!(script.ends_with('\n'), "{shell}");
        let tokens = script_tokens(&script);
        for list in COMPLETION_VALUE_LISTS {
            assert!(contains_run(&tokens, list), "{shell} misses {list:?}");
        }
        for flag in COMPLETION_LONG_FLAGS {
            // Fish names long flags without dashes: `-l config`.
            let found = if shell == "fish" {
                contains_run(&tokens, &["-l", &flag[2..]])
            } else {
                tokens.contains(flag)
            };
            assert!(found, "{shell} script misses {flag}");
        }
        assert_eq!(
            stdout_text(&fixture.0, &["completion", "--no-descriptions", shell]),
            script
        );
    }
    for arguments in [
        &["completion"][..],
        &["completion", "tcsh"][..],
        &["completion", "bash", "zsh"][..],
    ] {
        let rejected = output(&fixture.0, arguments);
        assert_eq!(rejected.status.code(), Some(1), "{arguments:?}");
        assert!(rejected.stdout.is_empty(), "{arguments:?}");
        let stderr = String::from_utf8(rejected.stderr).unwrap();
        assert!(stderr.starts_with("Error: "), "{stderr}");
        assert!(
            stderr.contains("\nUsage:\n  rustleaks completion <shell>\n"),
            "{stderr}"
        );
    }
    let help = stdout_text(&fixture.0, &["help", "completion"]);
    for install in [
        "rustleaks completion bash > ~/.local/share/bash-completion/completions/rustleaks",
        "eval \"$(rustleaks completion bash)\"",
        "rustleaks completion zsh > ~/.zfunc/_rustleaks",
        "rustleaks completion fish > ~/.config/fish/completions/rustleaks.fish",
        "rustleaks completion powershell | Out-String | Invoke-Expression",
    ] {
        assert!(help.contains(install), "{install}");
    }
}

#[test]
fn completion_scripts_offer_git_flags_only_for_git() {
    let fixture = Fixture::new();
    let zsh = stdout_text(&fixture.0, &["completion", "zsh"]);
    for array in ["stdin_flags", "dir_flags", "root_flags"] {
        let start = zsh.find(&format!("  {array}=(\n")).unwrap();
        let block = &zsh[start..start + zsh[start..].find("\n  )\n").unwrap()];
        assert!(!block.contains("--platform"), "{array}");
    }
    assert!(!zsh.contains("_arguments -s"));
    let fish = stdout_text(&fixture.0, &["completion", "fish"]);
    for line in fish.lines().filter(|line| line.contains("-l platform")) {
        assert!(line.contains("'__rustleaks_using git'"), "{line}");
    }
    let powershell = stdout_text(&fixture.0, &["completion", "powershell"]);
    for name in ["stdin", "dir", "file", "directory"] {
        let line = powershell
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("'{name}' = @('--")))
            .unwrap();
        assert!(!line.contains("'--platform'"), "{line}");
    }
    let bash = stdout_text(&fixture.0, &["completion", "bash"]);
    check_shell_syntax("bash", &fixture.0, &bash);
    check_shell_syntax("zsh", &fixture.0, &zsh);
    // Each case lists the words before the cursor and the expected replies.
    for (words, expected) in [
        (&["rustleaks", "stdin", "--pl"][..], &[][..]),
        (&["rustleaks", "dir", "--pl"][..], &[][..]),
        (&["rustleaks", "git", "--pl"][..], &["--platform"][..]),
        (&["rustleaks", "help", "gi"][..], &["git"][..]),
        (&["rustleaks", "help", "git", ""][..], &[][..]),
        (&["rustleaks", "completion", "z"][..], &["zsh"][..]),
        (&["rustleaks", "completion", "bash", ""][..], &[][..]),
        (
            &["rustleaks", "completion", "--no-"][..],
            &["--no-descriptions"][..],
        ),
        (
            &["rustleaks", "stdin", "--base64-mode", ""][..],
            &["compatible", "extended"][..],
        ),
    ] {
        if let Some(replies) = bash_completion(&fixture.0, words) {
            assert_eq!(replies, expected, "{words:?}");
        }
    }
}

/// Runs the bash completion function for `words`, the last word being the
/// one under the cursor. Returns `None` when bash cannot run. Windows hosts
/// are skipped because `bash` there may be a WSL launcher without a usable
/// shell.
fn bash_completion(cwd: &Path, words: &[&str]) -> Option<Vec<String>> {
    if cfg!(windows) {
        return None;
    }
    let quoted = words
        .iter()
        .map(|word| format!("'{word}'"))
        .collect::<Vec<_>>()
        .join(" ");
    let program = format!(
        "source ./rustleaks.bash; COMP_WORDS=({quoted}); COMP_CWORD={}; _rustleaks; printf '%s\\n' \"${{COMPREPLY[@]}}\"",
        words.len() - 1
    );
    let result = Command::new("bash")
        .current_dir(cwd)
        .arg("-c")
        .arg(program)
        .output()
        .ok()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    Some(
        String::from_utf8(result.stdout)
            .unwrap()
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

/// Checks a script with `<shell> -n` when that shell can run. The script is
/// left in `cwd` as `rustleaks.<shell>`.
fn check_shell_syntax(shell: &str, cwd: &Path, script: &str) {
    let path = cwd.join(format!("rustleaks.{shell}"));
    fs::write(&path, script).unwrap();
    // `bash` on Windows hosts may be a WSL launcher without a usable shell.
    if cfg!(windows) {
        return;
    }
    let Ok(result) = Command::new(shell).arg("-n").arg(&path).output() else {
        return;
    };
    assert!(
        result.status.success(),
        "{shell}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn parser_errors_print_a_usage_block_between_error_and_fatal_lines() {
    let fixture = Fixture::new();
    for (arguments, message, usage) in [
        (
            &["git", "a", "b"][..],
            "git accepts at most one repository path, but 2 were given",
            "rustleaks git [flags] [repository]",
        ),
        (
            &["file", "a", "b"][..],
            "file accepts at most one path, but 2 were given",
            "rustleaks dir [flags] [path]",
        ),
        (
            &["stdin", "a"][..],
            "stdin accepts no arguments, but 1 was given",
            "rustleaks stdin [flags]",
        ),
        (
            &["stdin", "--exit-code", "nope"][..],
            "the --exit-code argument \"nope\" is not a whole number from -2147483648 to 2147483647",
            "rustleaks stdin [flags]",
        ),
    ] {
        let result = output(&fixture.0, arguments);
        assert_eq!(result.status.code(), Some(1), "{arguments:?}");
        assert!(result.stdout.is_empty());
        let name = usage.split(' ').nth(1).unwrap();
        assert_eq!(
            String::from_utf8(result.stderr).unwrap(),
            format!(
                "Error: {message}\nUsage:\n  {usage}\n\nRun 'rustleaks help {name}' for details.\n\nfatal {message}\n"
            ),
            "{arguments:?}"
        );
    }
    let version = output(&fixture.0, &["version", "dir", "a"]);
    assert_eq!(version.status.code(), Some(1));
    assert!(version.stdout.is_empty());
    assert_eq!(
        String::from_utf8(version.stderr).unwrap(),
        "Error: version accepts no arguments, but 2 were given\nfatal version accepts no arguments, but 2 were given\n"
    );
    let unknown = output(&fixture.0, &["unknown"]);
    assert_eq!(unknown.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(unknown.stderr).unwrap(),
        "Error: unknown command \"unknown\"\nRun 'rustleaks help' to list the commands.\nfatal unknown command \"unknown\"\n"
    );
}

#[test]
fn shorthand_unknown_is_not_the_unknown_long_exit_class() {
    let fixture = Fixture::new();
    let result = output(&fixture.0, &["stdin", "-x"]);
    assert_eq!(result.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(
        stderr,
        "Error: unknown shorthand flag: 'x' in -x\nUsage:\n  rustleaks stdin [flags]\n\nRun 'rustleaks help stdin' for details.\n\nfatal unknown shorthand flag: 'x' in -x\n"
    );
    assert!(!result.status.success());
    assert_ne!(OsStr::new("-x"), OsStr::new("--x"));
}
