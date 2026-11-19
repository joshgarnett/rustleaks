#![forbid(unsafe_code)]
//! Fresh-process compatibility checks for the thin CLI.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rustleaks-cli-{}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn write(&self, path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) {
        let path = self.0.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn command(cwd: &Path) -> Command {
    let mut command = Command::new(rustleaks_executable());
    command
        .current_dir(cwd)
        .env_remove("RUSTLEAKS_CONFIG")
        .env_remove("RUSTLEAKS_CONFIG_TOML")
        .env_remove("GITLEAKS_CONFIG")
        .env_remove("GITLEAKS_CONFIG_TOML");
    let git = git_executable();
    if git.is_absolute() {
        command.env("PATH", git.parent().expect("declared Git has a parent"));
    }
    command
}

fn rustleaks_executable() -> PathBuf {
    resolve_runfile(PathBuf::from(env!("CARGO_BIN_EXE_rustleaks")), "Rustleaks")
}

fn git_executable() -> PathBuf {
    let runfile = std::env::var_os("RUSTLEAKS_TEST_GIT_RUNFILE")
        .map_or_else(|| PathBuf::from("git"), PathBuf::from);
    resolve_runfile(runfile, "Git")
}

fn resolve_runfile(runfile: PathBuf, label: &str) -> PathBuf {
    if runfile.is_absolute() {
        return runfile;
    }
    for root in ["RUNFILES_DIR", "TEST_SRCDIR"] {
        if let Some(root) = std::env::var_os(root) {
            let root = PathBuf::from(root);
            for candidate in [root.join(&runfile), root.join("_main").join(&runfile)] {
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    if let Some(manifest) = std::env::var_os("RUNFILES_MANIFEST_FILE") {
        let key = runfile.to_string_lossy();
        let contents = fs::read_to_string(manifest).expect("read Bazel runfiles manifest");
        let workspace_key = format!("_main/{key}");
        let external_key = key.strip_prefix("../");
        if let Some((_, resolved)) = contents.lines().find_map(|line| {
            let (entry, resolved) = line.split_once(' ')?;
            (entry == key || entry == workspace_key || external_key == Some(entry))
                .then_some((entry, resolved))
        }) {
            return PathBuf::from(resolved);
        }
    }
    if runfile == Path::new("git") {
        return runfile;
    }
    panic!("cannot resolve {label} runfile {}", runfile.display());
}

fn output(cwd: &Path, arguments: &[&str]) -> Output {
    command(cwd).args(arguments).output().unwrap()
}

fn git(cwd: &Path, arguments: &[&str]) {
    git_stdout(cwd, arguments);
}

fn git_stdout(cwd: &Path, arguments: &[&str]) -> String {
    let result = Command::new(git_executable())
        .current_dir(cwd)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "git {:?}: {}",
        arguments,
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8_lossy(&result.stdout).trim().to_owned()
}

/// JSON report rows as (rule, file, start line, secret, commit).
fn report_rows(result: &Output) -> Vec<(String, String, i128, String, String)> {
    json_report_rows(&result.stdout)
}

/// Rows of a JSON report as (rule, file, start line, secret, commit).
fn json_report_rows(report: &[u8]) -> Vec<(String, String, i128, String, String)> {
    let text = |value: &rustleaks_core::model::ByteText| {
        String::from_utf8_lossy(value.as_bytes()).into_owned()
    };
    rustleaks_core::session::Baseline::from_go_json(report)
        .unwrap()
        .entries()
        .iter()
        .map(|row| {
            (
                text(row.rule_id()),
                text(row.file()),
                row.start_line(),
                text(row.secret()),
                text(row.commit()),
            )
        })
        .collect()
}

fn matching_config() -> &'static str {
    "title='fixture'\n[[rules]]\nid='fixture-token'\ndescription='fixture token'\nregex='''token=([A-Z0-9]{4})'''\nsecretGroup=1\nkeywords=['token']\n"
}

fn two_rule_config() -> &'static str {
    "title='fixture'\n[[rules]]\nid='alpha'\ndescription='alpha'\nregex='''alpha=([A-Z0-9]{4})'''\nsecretGroup=1\n[[rules]]\nid='beta'\ndescription='beta'\nregex='''beta=([A-Z0-9]{4})'''\nsecretGroup=1\n"
}

fn no_match_config() -> &'static str {
    "title='fixture'\n[[rules]]\nid='never'\ndescription='never'\nregex='''NEVER_MATCH_THIS_VALUE'''\n"
}

/// Flags that every scan command accepts, as they appear at the start of a
/// help line. The list is written here, not taken from the CLI source.
const SCAN_FLAG_LINES: &[&str] = &[
    "-c, --config <path>",
    "--enable-rule <ids>",
    "--native-pack <id>",
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
    "--native-pack",
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
    &[
        "rustleaks-extra-v1",
        "rustleaks-providers-v1",
        "rustleaks-connections-v1",
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
fn config_equals_shorthand_and_raw_template_case_quirk_are_preserved() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    let shorthand = output(&fixture.0, &["stdin", "--no-banner", "-c=config.toml"]);
    assert_eq!(shorthand.status.code(), Some(0));

    fixture.write("template.tmpl", "{{ range . }}{{ .RuleID }}{{ end }}");
    let uppercase = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c=config.toml",
            "-r",
            "-",
            "-f",
            "TEMPLATE",
            "--report-template",
            "template.tmpl",
        ],
    );
    assert_eq!(uppercase.status.code(), Some(1));
    assert!(uppercase.stdout.is_empty());
    assert!(String::from_utf8_lossy(&uppercase.stderr).contains("report format must be template"));
}

#[test]
fn directory_aliases_emit_the_same_json_and_custom_exit() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");
    let mut reports = Vec::new();
    for alias in ["dir", "file", "directory"] {
        let result = output(
            &fixture.0,
            &[
                alias,
                ".",
                "--no-banner",
                "-c",
                "config.toml",
                "-r",
                "-",
                "-f",
                "json",
                "--exit-code",
                "7",
            ],
        );
        assert_eq!(
            result.status.code(),
            Some(7),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stderr).contains("leaks found: 1"));
        reports.push(result.stdout);
    }
    assert_eq!(reports[0], reports[1]);
    assert_eq!(reports[1], reports[2]);
    assert!(String::from_utf8_lossy(&reports[0]).contains("\"secret.txt\""));
}

#[test]
fn stdin_scans_and_rejects_positional_arguments_before_side_effects() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    let mut child = command(&fixture.0)
        .args([
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "-r",
            "-",
            "-f",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"token=AB12\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.starts_with(b"["));

    fixture.write("report.json", b"preserve");
    let rejected = output(&fixture.0, &["stdin", "ignored", "-r", "report.json"]);
    assert_eq!(rejected.status.code(), Some(1));
    assert_eq!(
        fs::read(fixture.0.join("report.json")).unwrap(),
        b"preserve"
    );
}

#[test]
fn extended_base64_mode_is_opt_in_and_respects_decode_depth() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    // Standard and URL-safe encodings of b"\xfftoken=AB12xx\xfe", with and
    // without padding. These literals are independent of the decoder under test.
    for encoded in [
        "/3Rva2VuPUFCMTJ4eP4=",
        "/3Rva2VuPUFCMTJ4eP4",
        "_3Rva2VuPUFCMTJ4eP4=",
        "_3Rva2VuPUFCMTJ4eP4",
    ] {
        fixture.write("encoded.txt", encoded);
        for (extra, expected_exit) in [
            (vec![], 0),
            (vec!["--base64-mode=compatible"], 0),
            (vec!["--base64-mode=extended"], 1),
            (vec!["--base64-mode=extended", "--max-decode-depth=0"], 0),
        ] {
            let result = command(&fixture.0)
                .args([
                    "dir",
                    "encoded.txt",
                    "--config=config.toml",
                    "--no-banner",
                    "--log-level=fatal",
                    "--report-path=-",
                    "--report-format=json",
                ])
                .args(extra)
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(expected_exit),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let report = String::from_utf8(result.stdout).unwrap();
            if expected_exit == 1 {
                assert!(report.contains("\"Secret\": \"AB12\""));
                assert_eq!(report.matches("\"RuleID\"").count(), 1);
            } else {
                assert_eq!(report.trim(), "[]");
            }
        }
    }
    let rejected = output(&fixture.0, &["stdin", "--base64-mode=unknown"]);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("invalid value"));
}

#[test]
fn explicit_config_wins_and_inline_errors_do_not_disclose_contents() {
    let fixture = Fixture::new();
    fixture.write("explicit.toml", no_match_config());
    fixture.write("environment.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");
    let result = command(&fixture.0)
        .args(["dir", "secret.txt", "--no-banner", "-c", "explicit.toml"])
        .env("GITLEAKS_CONFIG", "environment.toml")
        .env("GITLEAKS_CONFIG_TOML", matching_config())
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );

    let marker = "SECRET_MARKER_DO_NOT_PRINT";
    let invalid = command(&fixture.0)
        .args(["stdin", "--no-banner"])
        .env("GITLEAKS_CONFIG_TOML", format!("invalid=[{marker}"))
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains(marker));
}

#[test]
fn native_config_names_precede_backward_compatible_aliases() {
    let fixture = Fixture::new();
    fixture.write("native.toml", no_match_config());
    fixture.write("legacy.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");

    let environment = command(&fixture.0)
        .args(["dir", "secret.txt", "--no-banner"])
        .env("RUSTLEAKS_CONFIG", "native.toml")
        .env("GITLEAKS_CONFIG", "legacy.toml")
        .output()
        .unwrap();
    assert_eq!(environment.status.code(), Some(0));

    fixture.write(
        ".rustleaks.toml",
        "title='native'\n[[rules]]\nid='never'\nregex='''Z{1000}'''\n",
    );
    fixture.write(".gitleaks.toml", matching_config());
    let local = output(&fixture.0, &["dir", ".", "--no-banner"]);
    assert_eq!(local.status.code(), Some(0));

    let legacy_only = command(&fixture.0)
        .args(["dir", "secret.txt", "--no-banner"])
        .env("GITLEAKS_CONFIG", "legacy.toml")
        .output()
        .unwrap();
    assert_eq!(legacy_only.status.code(), Some(1));
}

/// Returns a file under `compat/`, from the source tree or Bazel runfiles.
fn compat_file(name: &str) -> PathBuf {
    let local = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../compat")
        .join(name);
    if local.is_file() {
        return local;
    }
    resolve_runfile(PathBuf::from(format!("compat/{name}")), "compat")
}

#[test]
fn implemented_gitleaks_version_matches_the_pinned_upstream_revision() {
    let revision = fs::read_to_string(compat_file("upstream-revision.txt")).unwrap();
    let description = revision
        .lines()
        .find_map(|line| line.strip_prefix("description="))
        .unwrap();
    let version = description
        .strip_prefix('v')
        .and_then(|rest| rest.split_once('-'))
        .map(|(version, _)| version)
        .unwrap();
    let fixture = Fixture::new();
    let result = command(&fixture.0)
        .args(["stdin", "--no-banner"])
        .env("RUSTLEAKS_CONFIG_TOML", "minVersion = 'v99.0.0'\n")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains(&format!(
            "; Rustleaks implements Gitleaks {version}, so newer settings"
        )),
        "{description}: {stderr}"
    );
}

#[test]
fn minimum_version_warns_only_above_the_implemented_gitleaks_version() {
    let fixture = Fixture::new();
    let default = output(&fixture.0, &["dir", ".", "--no-banner"]);
    let stderr = String::from_utf8_lossy(&default.stderr);
    assert_eq!(default.status.code(), Some(0), "{stderr}");
    assert!(default.stdout.is_empty());
    assert!(!stderr.contains("config requires"), "{stderr}");

    for (min_version, expected) in [
        ("v8.30.0", None),
        ("v8.30.0+meta", None),
        (
            "v8.30.1",
            Some(
                "config requires Gitleaks v8.30.1 or later; Rustleaks implements Gitleaks 8.30.0, so newer settings may not be supported; config path=RUSTLEAKS_CONFIG_TOML",
            ),
        ),
        (
            "v99.0.0",
            Some(
                "config requires Gitleaks v99.0.0 or later; Rustleaks implements Gitleaks 8.30.0, so newer settings may not be supported; config path=RUSTLEAKS_CONFIG_TOML",
            ),
        ),
    ] {
        let result = command(&fixture.0)
            .args(["dir", ".", "--no-banner"])
            .env(
                "RUSTLEAKS_CONFIG_TOML",
                format!("minVersion = '{min_version}'\n"),
            )
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert_eq!(result.status.code(), Some(0), "{min_version}: {stderr}");
        assert!(result.stdout.is_empty());
        match expected {
            None => assert!(!stderr.contains("config requires"), "{stderr}"),
            Some(message) => {
                let warnings = stderr
                    .lines()
                    .filter(|line| line.contains("config requires"))
                    .collect::<Vec<_>>();
                assert_eq!(warnings.len(), 1, "{stderr}");
                assert!(warnings[0].contains("warn"), "{stderr}");
                assert!(warnings[0].ends_with(message), "{stderr}");
            }
        }
    }
}

#[test]
fn source_local_config_and_enabled_rule_projection_are_applied_before_scan() {
    let fixture = Fixture::new();
    fixture.write(".rustleaks.toml", two_rule_config());
    fixture.write("secrets.txt", b"alpha=AB12\nbeta=CD34\n");
    let selected = output(
        &fixture.0,
        &[
            "dir",
            ".",
            "--no-banner",
            "--enable-rule",
            "alpha",
            "-r",
            "-",
            "-f",
            "json",
        ],
    );
    assert_eq!(selected.status.code(), Some(1));
    assert!(
        selected
            .stdout
            .windows(b"alpha".len())
            .any(|v| v == b"alpha")
    );
    assert!(
        !selected
            .stdout
            .windows(b"beta=CD34".len())
            .any(|v| v == b"beta=CD34")
    );
    assert!(
        String::from_utf8_lossy(&selected.stderr).contains("info overriding enabled rules: alpha")
    );

    let suppressed = output(
        &fixture.0,
        &[
            "dir",
            ".",
            "--no-banner",
            "--log-level",
            "warn",
            "--enable-rule",
            "beta,alpha",
        ],
    );
    assert!(!String::from_utf8_lossy(&suppressed.stderr).contains("overriding enabled rules"));

    let invalid = output(
        &fixture.0,
        &[
            "dir",
            ".",
            "--no-banner",
            "--enable-rule",
            "absent",
            "-r",
            "must-not-exist.json",
        ],
    );
    assert_eq!(invalid.status.code(), Some(1));
    assert!(!fixture.0.join("must-not-exist.json").exists());
}

#[test]
fn selected_composite_logs_missing_required_rule_and_completes() {
    let fixture = Fixture::new();
    fixture.write(
        "composite.toml",
        "[[rules]]\nid='primary-rule'\ndescription='primary'\nregex='''password\\s*=\\s*\"([^\"]+)\"'''\n[[rules.required]]\nid='username-rule'\n[[rules]]\nid='username-rule'\ndescription='username'\nregex='''username\\s*=\\s*\"([^\"]+)\"'''\nskipReport=true\n",
    );
    fixture.write("secret.txt", b"username=\"alice\" password=\"AB12\"\n");
    let result = output(
        &fixture.0,
        &[
            "dir",
            "secret.txt",
            "--no-banner",
            "-c",
            "composite.toml",
            "--enable-rule",
            "primary-rule",
            "-r",
            "report.json",
        ],
    );
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(fixture.0.join("report.json")).unwrap(), b"[]\n");
    assert!(String::from_utf8_lossy(&result.stderr).contains(
        "error required rule not found in config path=primary-rule rule-id=username-rule"
    ));
}

#[test]
fn setup_diagnostic_cases_are_fatal_without_report_side_effects() {
    let fixture = Fixture::new();
    fixture.write("never.toml", no_match_config());
    fixture.write("two.toml", two_rule_config());
    fixture.write("secret.txt", b"alpha=AB12\n");
    fixture.write("template.tmpl", "{{ range . }}{{ .RuleID }}{{ end }}");

    let cases: [(&str, &[&str], Option<&str>); 7] = [
        (
            "missing source during config selection",
            &["dir", "missing", "--no-banner", "-r", "missing-source.json"],
            Some("missing-source.json"),
        ),
        (
            "missing enabled rule",
            &[
                "dir",
                "secret.txt",
                "--no-banner",
                "-c",
                "two.toml",
                "--enable-rule",
                "absent",
                "-r",
                "missing-rule.json",
            ],
            Some("missing-rule.json"),
        ),
        (
            "stdout report without format",
            &["stdin", "--no-banner", "-c", "never.toml", "-r", "-"],
            None,
        ),
        (
            "unknown inferred extension",
            &[
                "stdin",
                "--no-banner",
                "-c",
                "never.toml",
                "-r",
                "report.xml",
            ],
            Some("report.xml"),
        ),
        (
            "missing inferred extension",
            &["stdin", "--no-banner", "-c", "never.toml", "-r", "report"],
            Some("report"),
        ),
        (
            "missing template",
            &[
                "stdin",
                "--no-banner",
                "-c",
                "never.toml",
                "-r",
                "report.tmpl",
                "-f",
                "template",
                "--report-template",
                "missing.tmpl",
            ],
            Some("report.tmpl"),
        ),
        (
            "raw uppercase template mismatch",
            &[
                "stdin",
                "--no-banner",
                "-c",
                "never.toml",
                "-r",
                "uppercase.tmpl",
                "-f",
                "TEMPLATE",
                "--report-template",
                "template.tmpl",
            ],
            Some("uppercase.tmpl"),
        ),
    ];

    for (name, arguments, report) in cases {
        let result = output(&fixture.0, arguments);
        assert_eq!(result.status.code(), Some(1), "{name}");
        assert!(result.stdout.is_empty(), "{name}");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.lines().any(|line| line.starts_with("fatal ")),
            "{name}: {stderr}"
        );
        assert!(
            stderr.lines().all(|line| !line.starts_with("error ")),
            "{name}: {stderr}"
        );
        if let Some(report) = report {
            assert!(!fixture.0.join(report).exists(), "{name}");
        }
    }
}

#[test]
fn oversized_source_local_config_is_fatal_before_the_scan() {
    let fixture = Fixture::new();
    let mut config = matching_config().as_bytes().to_vec();
    config.push(b'\n');
    config.resize(16 * 1024 * 1024 + 1, b'#');
    fixture.write("repo/.gitleaks.toml", config);
    fixture.write("repo/secret.txt", b"token=AB12\n");
    let result = output(
        &fixture.0,
        &["dir", "repo", "--no-banner", "-r", "report.json"],
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.lines().any(|line| line.starts_with("fatal ")
            && line.contains("configuration file is larger than the 16 MiB limit")),
        "{stderr}"
    );
    assert!(!fixture.0.join("report.json").exists());
}

#[test]
fn baseline_is_nonfatal_and_excludes_its_own_report_file() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");
    let first = output(
        &fixture.0,
        &[
            "dir",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "-r",
            "baseline.json",
        ],
    );
    assert_eq!(first.status.code(), Some(1));
    let second = output(
        &fixture.0,
        &[
            "dir",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--baseline-path",
            "baseline.json",
        ],
    );
    assert_eq!(
        second.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(String::from_utf8_lossy(&second.stderr).contains("no leaks found"));

    let missing = output(
        &fixture.0,
        &[
            "dir",
            "secret.txt",
            "--no-banner",
            "-c",
            "config.toml",
            "--baseline-path",
            "missing.json",
        ],
    );
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("could not load baseline"));
}

#[test]
fn regular_ignore_file_does_not_make_its_child_probe_fatal() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    fixture.write("ignore.txt", b"# no entries\n");
    fixture.write("secret.txt", b"token=AB12\n");
    let result = output(
        &fixture.0,
        &[
            "dir",
            "secret.txt",
            "--no-banner",
            "-c",
            "config.toml",
            "-i",
            "ignore.txt",
        ],
    );
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("leaks found: 1"));
}

#[test]
fn stdin_source_local_ignore_is_unioned_with_a_custom_ignore_path() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    fixture.write("custom.ignore", b"# intentionally empty\n");
    fixture.write(".rustleaksignore", b":fixture-token:1\n");
    let mut child = command(&fixture.0)
        .args([
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "--rustleaks-ignore-path",
            "custom.ignore",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"token=AB12\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&result.stderr).contains("no leaks found"));
}

#[test]
fn invalid_ignore_entries_are_warned_once_in_plain_text() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    fixture.write("kept.txt", b"token=AB12\n");
    fixture.write("ignored.txt", b"token=CD34\n");
    // Line 2 has two fields. Line 3 is a valid global entry and must still
    // apply after the invalid line.
    fixture.write(
        ".rustleaksignore",
        b"# synthetic ignore file\na:b\nignored.txt:fixture-token:1\n",
    );
    fixture.write("extra.ignore", b"x\n");
    let warning = |fields: &str, file: &Path, line: u32| {
        format!(
            "warn ignore file entry has {fields}, expected 3 or 4 file={} line={line}",
            file.display()
        )
    };
    let source_warning = warning("2 fields", Path::new(".rustleaksignore"), 2);
    // A path that differs in text but names the same file.
    let fixture_name = fixture.0.file_name().unwrap().to_str().unwrap();
    let parent_path = Path::new("..").join(fixture_name).join(".rustleaksignore");
    let parent_path_text = parent_path.to_str().unwrap();
    let cases = vec![
        // The default ignore path "." and the scanned folder "." name the
        // same file, so it is read and reported once.
        (Vec::new(), vec![source_warning.clone()]),
        (
            vec!["-i", "extra.ignore"],
            vec![
                warning("1 field", Path::new("extra.ignore"), 1),
                source_warning.clone(),
            ],
        ),
        (
            vec!["-i", parent_path_text],
            vec![warning("2 fields", &parent_path, 2)],
        ),
    ];
    // A symlink is a second name for the same file.
    #[cfg(unix)]
    let cases = {
        let mut cases = cases;
        std::os::unix::fs::symlink(".rustleaksignore", fixture.0.join("link.ignore")).unwrap();
        cases.push((
            vec!["-i", "link.ignore"],
            vec![warning("2 fields", Path::new("link.ignore"), 2)],
        ));
        cases
    };

    for (arguments, expected) in cases {
        let mut all = vec!["dir", ".", "--no-banner", "-c", "config.toml"];
        all.extend_from_slice(&arguments);
        let result = output(&fixture.0, &all);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert_eq!(result.status.code(), Some(1), "{arguments:?}: {stderr}");
        let warnings = stderr
            .lines()
            .filter(|line| line.contains("ignore file"))
            .collect::<Vec<_>>();
        assert_eq!(warnings, expected, "{arguments:?}: {stderr}");
        assert!(
            !stderr.contains("InvalidFieldCount") && !stderr.contains("ByteText"),
            "{stderr}"
        );
        assert!(stderr.contains("leaks found: 1"), "{arguments:?}: {stderr}");
    }
}

#[test]
fn redaction_and_custom_zero_exit_are_applied_to_reports() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    let mut child = command(&fixture.0)
        .args([
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "--redact",
            "--exit-code",
            "0",
            "-r",
            "-",
            "-f",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"token=AB12\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(0));
    assert!(
        result
            .stdout
            .windows(b"REDACTED".len())
            .any(|v| v == b"REDACTED")
    );
    assert!(!result.stdout.windows(b"AB12".len()).any(|v| v == b"AB12"));
}

#[test]
fn log_level_filters_normalized_summary_severities() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    let quiet = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "--log-level",
            "error",
        ],
    );
    assert_eq!(quiet.status.code(), Some(0));
    assert!(quiet.stderr.is_empty());

    fixture.write("matching.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");
    let warning = output(
        &fixture.0,
        &[
            "dir",
            "secret.txt",
            "--no-banner",
            "-c",
            "matching.toml",
            "--log-level",
            "warn",
        ],
    );
    let stderr = String::from_utf8(warning.stderr).unwrap();
    assert!(stderr.contains("leaks found: 1"));
    assert!(!stderr.contains("scanned ~"));
}

#[test]
fn recoverable_source_issue_severity_distinguishes_corruption_from_limits() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    fixture.write("corrupt.gz", b"\x1f\x8bbad");
    let corrupt = output(
        &fixture.0,
        &[
            "dir",
            "corrupt.gz",
            "--no-banner",
            "-c",
            "config.toml",
            "--max-archive-depth",
            "1",
            "--log-level",
            "error",
        ],
    );
    assert_eq!(corrupt.status.code(), Some(0));
    let corrupt_stderr = String::from_utf8_lossy(&corrupt.stderr);
    assert!(
        corrupt_stderr
            .lines()
            .any(|line| line.starts_with("error source ") && line.contains("Decode")),
        "{corrupt_stderr}"
    );

    let oversized = fs::File::create(fixture.0.join("oversized.txt")).unwrap();
    oversized.set_len(1_000_001).unwrap();
    drop(oversized);
    let limited = output(
        &fixture.0,
        &[
            "dir",
            "oversized.txt",
            "--no-banner",
            "-c",
            "config.toml",
            "--max-target-megabytes",
            "1",
        ],
    );
    assert_eq!(limited.status.code(), Some(0));
    let limited_stderr = String::from_utf8_lossy(&limited.stderr);
    assert!(
        limited_stderr
            .lines()
            .any(|line| line.starts_with("warn source ") && line.contains("Limit/Limit")),
        "{limited_stderr}"
    );
}

#[test]
fn terminal_git_failure_writes_partial_report_then_exits_one() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    let result = output(
        &fixture.0,
        &[
            "git",
            "missing-repository",
            "--no-banner",
            "-c",
            "config.toml",
            "--platform",
            "none",
            "-r",
            "partial.json",
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read(fixture.0.join("partial.json")).unwrap(), b"[]\n");
    assert!(String::from_utf8_lossy(&result.stderr).contains("partial scan"));
}

#[test]
fn git_history_worktree_and_staged_modes_use_native_process_arguments() {
    let fixture = Fixture::new();
    git(&fixture.0, &["init", "--quiet"]);
    git(&fixture.0, &["config", "user.name", "CLI Test"]);
    git(&fixture.0, &["config", "user.email", "cli@example.invalid"]);
    fixture.write("config.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");
    git(&fixture.0, &["add", "secret.txt"]);
    git(&fixture.0, &["commit", "--quiet", "-m", "initial secret"]);

    let history = output(
        &fixture.0,
        &[
            "git",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--platform",
            "none",
            "-r",
            "history.json",
        ],
    );
    assert_eq!(history.status.code(), Some(1));
    assert!(
        fs::read(fixture.0.join("history.json"))
            .unwrap()
            .windows(b"AB12".len())
            .any(|value| value == b"AB12")
    );

    fixture.write("secret.txt", b"token=CD34\n");
    let worktree = output(
        &fixture.0,
        &[
            "git",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--pre-commit",
            "--platform",
            "not-consulted-in-diff-mode",
            "-r",
            "worktree.json",
        ],
    );
    assert_eq!(worktree.status.code(), Some(1));
    assert!(
        fs::read(fixture.0.join("worktree.json"))
            .unwrap()
            .windows(b"CD34".len())
            .any(|value| value == b"CD34")
    );

    git(&fixture.0, &["add", "secret.txt"]);
    let staged = output(
        &fixture.0,
        &[
            "git",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--staged",
            "-r",
            "staged.json",
        ],
    );
    assert_eq!(staged.status.code(), Some(1));
    assert!(
        fs::read(fixture.0.join("staged.json"))
            .unwrap()
            .windows(b"CD34".len())
            .any(|value| value == b"CD34")
    );
}

#[test]
fn staged_and_pre_commit_scan_different_sides_of_the_index() {
    let fixture = Fixture::new();
    git(&fixture.0, &["init", "--quiet"]);
    git(&fixture.0, &["config", "user.name", "CLI Test"]);
    git(&fixture.0, &["config", "user.email", "cli@example.invalid"]);
    // The config is never added, so it is in no diff or commit.
    fixture.write("config.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");
    git(&fixture.0, &["add", "secret.txt"]);
    git(&fixture.0, &["commit", "--quiet", "-m", "c1"]);
    let c1 = git_stdout(&fixture.0, &["rev-parse", "HEAD"]);
    // HEAD has AB12, the index has CD34 and the worktree has EF56.
    fixture.write("secret.txt", b"token=CD34\n");
    git(&fixture.0, &["add", "secret.txt"]);
    fixture.write("secret.txt", b"token=EF56\n");

    for (mode, secret, commit, absent) in [
        ("--staged", "CD34", "", &["AB12", "EF56"]),
        ("--pre-commit", "EF56", "", &["AB12", "CD34"]),
        ("--platform=none", "AB12", c1.as_str(), &["CD34", "EF56"]),
    ] {
        let result = output(
            &fixture.0,
            &[
                "git",
                ".",
                mode,
                "--no-banner",
                "-c",
                "config.toml",
                "--report-path",
                "-",
                "--report-format",
                "json",
                "--log-level",
                "fatal",
            ],
        );
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert_eq!(
            result.status.code(),
            Some(1),
            "{mode}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            report_rows(&result),
            [(
                "fixture-token".to_owned(),
                "secret.txt".to_owned(),
                1,
                secret.to_owned(),
                commit.to_owned(),
            )],
            "{mode}"
        );
        for value in absent {
            assert!(!stdout.contains(value), "{mode}");
        }
    }
}

#[test]
fn log_opts_range_attributes_a_finding_to_its_commit() {
    let fixture = Fixture::new();
    git(&fixture.0, &["init", "--quiet"]);
    git(&fixture.0, &["config", "user.name", "CLI Test"]);
    git(&fixture.0, &["config", "user.email", "cli@example.invalid"]);
    fixture.write("config.toml", matching_config());
    let mut commits = vec![String::new()];
    let mut notes = String::new();
    for k in 1..=8 {
        let _ = writeln!(notes, "entry {k}");
        fixture.write("notes.txt", &notes);
        git(&fixture.0, &["add", "notes.txt"]);
        // Only commit 5 adds the token line.
        if k == 5 {
            fixture.write("secret.txt", b"token=AB12\n");
            git(&fixture.0, &["add", "secret.txt"]);
        }
        git(
            &fixture.0,
            &["commit", "--quiet", "-m", &format!("commit {k}")],
        );
        commits.push(git_stdout(&fixture.0, &["rev-parse", "HEAD"]));
    }
    let row = (
        "fixture-token".to_owned(),
        "secret.txt".to_owned(),
        1,
        "AB12".to_owned(),
        commits[5].clone(),
    );

    for (range, code, rows) in [
        (Some((4, 6)), 1, vec![row.clone()]),
        (Some((5, 8)), 0, Vec::new()),
        (None, 1, vec![row.clone()]),
    ] {
        let log_opts =
            range.map(|(from, to)| format!("--log-opts={}..{}", commits[from], commits[to]));
        let mut arguments = vec![
            "git",
            ".",
            "--platform",
            "none",
            "--no-banner",
            "-c",
            "config.toml",
            "--report-path",
            "-",
            "--report-format",
            "json",
            "--log-level",
            "fatal",
        ];
        arguments.extend(log_opts.as_deref());
        let result = output(&fixture.0, &arguments);
        assert_eq!(
            result.status.code(),
            Some(code),
            "{range:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(report_rows(&result), rows, "{range:?}");
        if rows.is_empty() {
            assert_eq!(result.stdout, b"[]\n");
        }
    }
}

#[test]
fn scm_diagnostic_classes_obey_platform_resolution_and_log_levels() {
    let fixture = Fixture::new();
    git(&fixture.0, &["init", "--quiet"]);
    git(&fixture.0, &["config", "user.name", "CLI Test"]);
    git(&fixture.0, &["config", "user.email", "cli@example.invalid"]);
    fixture.write("config.toml", no_match_config());
    fixture.write("clean.txt", b"clean\n");
    git(&fixture.0, &["add", "clean.txt"]);
    git(&fixture.0, &["commit", "--quiet", "-m", "initial"]);
    git(
        &fixture.0,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/org/repo.git",
        ],
    );

    let unknown = output(
        &fixture.0,
        &["git", ".", "--no-banner", "-c", "config.toml"],
    );
    assert_eq!(unknown.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&unknown.stderr)
            .contains("info unknown SCM platform for host example.invalid; use --platform")
    );
    let suppressed = output(
        &fixture.0,
        &[
            "git",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--log-level",
            "warn",
        ],
    );
    assert!(!String::from_utf8_lossy(&suppressed.stderr).contains("unknown SCM platform"));

    git(
        &fixture.0,
        &[
            "remote",
            "set-url",
            "origin",
            "https://github.com/org/repo.git",
        ],
    );
    let known = output(
        &fixture.0,
        &[
            "git",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--log-level",
            "debug",
        ],
    );
    assert!(
        String::from_utf8_lossy(&known.stderr)
            .contains("info SCM platform github parsed from host github.com")
    );

    git(&fixture.0, &["remote", "remove", "origin"]);
    let absent = output(
        &fixture.0,
        &[
            "git",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--log-level",
            "debug",
        ],
    );
    assert!(
        String::from_utf8_lossy(&absent.stderr).contains("repository has no configured remote")
    );

    git(&fixture.0, &["remote", "add", "origin", "https://[bad"]);
    let malformed = output(
        &fixture.0,
        &["git", ".", "--no-banner", "-c", "config.toml"],
    );
    assert!(
        String::from_utf8_lossy(&malformed.stderr)
            .contains("error skipping finding links: unable to parse remote URL")
    );
}

#[test]
fn report_inference_and_safe_error_routing_are_stable() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    let result = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "-r",
            "empty.json",
        ],
    );
    assert_eq!(result.status.code(), Some(0));
    assert_eq!(fs::read(fixture.0.join("empty.json")).unwrap(), b"[]\n");
    assert!(result.stdout.is_empty());

    let missing = output(
        &fixture.0,
        &["stdin", "--no-banner", "-c", "config.toml", "-r", "-"],
    );
    assert_eq!(missing.status.code(), Some(1));
    assert!(missing.stdout.is_empty());

    let unknown = output(&fixture.0, &["stdin", "--unknown"]);
    assert_eq!(unknown.status.code(), Some(126));
    assert!(unknown.stdout.is_empty());
    let unknown_stderr = String::from_utf8_lossy(&unknown.stderr);
    assert_eq!(
        unknown_stderr,
        "Error: unknown flag: --unknown\nUsage:\n  rustleaks stdin [flags]\n\nRun 'rustleaks help stdin' for details.\n\n"
    );

    for name in [
        "implicit.xml",
        "implicit.junit",
        "implicit.tmpl",
        "implicit.template",
    ] {
        let rejected = output(
            &fixture.0,
            &["stdin", "--no-banner", "-c", "config.toml", "-r", name],
        );
        assert_eq!(rejected.status.code(), Some(1));
        assert!(!fixture.0.join(name).exists());
    }
}

#[test]
fn format_and_template_flags_are_dormant_without_report_path() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    let result = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "--report-format",
            "not-a-format",
            "--report-template",
            "missing.tmpl",
        ],
    );
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
}

#[test]
fn failed_setup_never_truncates_existing_report() {
    let fixture = Fixture::new();
    fixture.write("broken.toml", "not = [ valid");
    fixture.write("report.json", b"preserve-this-report");
    let result = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c",
            "broken.toml",
            "-r",
            "report.json",
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        fs::read(fixture.0.join("report.json")).unwrap(),
        b"preserve-this-report"
    );
}

#[test]
fn report_open_failure_is_observed_by_the_fresh_process() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    let result = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "-r",
            ".",
            "-f",
            "json",
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("could not write json report"), "{stderr}");
    assert!(stderr.contains("could not open report"), "{stderr}");
}

#[test]
fn paths_with_spaces_are_passed_without_a_shell() {
    let fixture = Fixture::new();
    fixture.write("config file.toml", matching_config());
    fixture.write("source dir/secret file.txt", b"token=AB12\n");
    let result = output(
        &fixture.0,
        &[
            "dir",
            "source dir",
            "--no-banner",
            "-c",
            "config file.toml",
            "-r",
            "report file.json",
        ],
    );
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = fs::read(fixture.0.join("report file.json")).unwrap();
    assert!(
        report
            .windows(b"secret file.txt".len())
            .any(|window| window == b"secret file.txt")
    );
}

#[cfg(unix)]
#[test]
fn native_non_utf8_config_and_source_paths_cross_the_process_boundary() {
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new();
    let config = std::ffi::OsString::from_vec(b"config-\xfe.toml".to_vec());
    let source = std::ffi::OsString::from_vec(b"source-\xff.txt".to_vec());
    fixture.write("valid.toml", no_match_config());

    let missing_source = command(&fixture.0)
        .arg("dir")
        .arg(&source)
        .arg("--no-banner")
        .arg("-c")
        .arg("valid.toml")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&missing_source.stderr);
    assert!(!stderr.contains("must be valid UTF-8"), "{stderr}");
    assert!(stderr.contains("source Metadata/NotFound"), "{stderr}");

    let missing_config = command(&fixture.0)
        .arg("stdin")
        .arg("--no-banner")
        .arg("-c")
        .arg(&config)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&missing_config.stderr);
    assert!(!stderr.contains("requires a UTF-8 value"), "{stderr}");
    assert!(stderr.contains("could not read config"), "{stderr}");
}

#[test]
fn dash_separator_allows_a_source_beginning_with_dash() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    fixture.write("-source/file.txt", b"clean\n");
    let result = output(
        &fixture.0,
        &["dir", "--no-banner", "-c", "config.toml", "--", "-source"],
    );
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn template_is_constructed_before_scanning() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    fixture.write("template.tmpl", "{{ range . }}{{ .RuleID }}{{ end }}");
    let result = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "-r",
            "report.tmpl",
            "-f",
            "template",
            "--report-template",
            "template.tmpl",
        ],
    );
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(fs::read(fixture.0.join("report.tmpl")).unwrap().is_empty());
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

mod complete_profile {
    use super::*;
    use std::io::{self, Cursor, Read};

    const PROFILE: &str = "version=1\ntarget_bytes=65536\noperation_original_bytes=1048576\noperation_fragments=100\noperation_issues=10\nworkers=1\nqueue_capacity=1\nfragment_decoded_bytes=1048576\noperation_decoded_bytes=1048576\nfragment_work_units=1000000\noperation_work_units=1000000\nfragment_finding_records=100\noperation_finding_records=100\nfragment_finding_payload_bytes=1048576\noperation_finding_payload_bytes=1048576\nfragment_collected_spans=1000\noperation_collected_spans=1000\nfragment_normalization_bytes=1048576\noperation_normalization_bytes=1048576\narchive_entries=100\narchive_member_bytes=65536\narchive_total_bytes=1048576\narchive_spool_bytes=65536\ngit_patch_bytes=1048576\ngit_patch_lines=10000\ngit_stderr_bytes=65536\ngit_blob_bytes=65536\ngit_metadata_bytes=65536\ngit_path_bytes=4096\ngit_files=100\ngit_hunks=100\nscm_link_bytes=4096\noperation_scm_link_bytes=8192\n";

    #[test]
    fn explicit_native_packs_are_independent_of_complete_target_selection() {
        let fixture = Fixture::new();
        profile(&fixture, &[]);
        let value = format!(
            "dckr_pat_{}",
            "Q7m2Z9v4L1c8R5s0N6b3X"
                .chars()
                .cycle()
                .take(27)
                .collect::<String>()
        );
        fixture.write("secret.txt", &value);
        let common = [
            "--native-pack",
            "rustleaks-providers-v1",
            "--enable-rule",
            "rustleaks.dockerhub-personal-access-token",
            "--complete-profile",
            "scan.limits",
            "--no-banner",
            "--log-level",
            "fatal",
            "--report-path",
            "-",
            "--report-format",
            "json",
        ];
        let mut child = command(&fixture.0)
            .args(["stdin"])
            .args(common)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(value.as_bytes())
            .unwrap();
        let input = child.wait_with_output().unwrap();
        assert_eq!(
            input.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&input.stderr)
        );
        assert!(status(&input.stderr).contains("status=complete"));
        let directory = command(&fixture.0)
            .args(["dir", "secret.txt"])
            .args(common)
            .output()
            .unwrap();
        assert_eq!(
            directory.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&directory.stderr)
        );
        assert!(status(&directory.stderr).contains("status=complete"));
        for result in [&input, &directory] {
            let report = rustleaks_core::session::Baseline::from_go_json(&result.stdout).unwrap();
            assert!(!report.was_null());
            let rows = report.entries();
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].rule_id().as_bytes(),
                b"rustleaks.dockerhub-personal-access-token"
            );
        }
        let conflict = command(&fixture.0)
            .env("RUSTLEAKS_CONFIG_TOML", no_match_config())
            .args(["stdin"])
            .args(common)
            .output()
            .unwrap();
        assert_eq!(conflict.status.code(), Some(2));
        assert!(conflict.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&conflict.stderr)
                .contains("requires embedded-default configuration")
        );
    }

    fn profile(fixture: &Fixture, replacements: &[(&str, usize)]) {
        let text = PROFILE
            .lines()
            .map(|line| {
                let (key, _) = line.split_once('=').unwrap();
                replacements
                    .iter()
                    .find(|(name, _)| *name == key)
                    .map_or_else(
                        || format!("{line}\n"),
                        |(_, value)| format!("{key}={value}\n"),
                    )
            })
            .collect::<String>();
        fixture.write("scan.limits", text);
    }

    fn arguments<'a>(command: &'a [&'a str]) -> Vec<&'a str> {
        let mut args = command.to_vec();
        args.extend([
            "--complete-profile",
            "scan.limits",
            "--no-banner",
            "--log-level",
            "fatal",
            "--config",
            "config.toml",
            "--report-path",
            "-",
            "--report-format",
            "json",
        ]);
        args
    }

    fn stdin(fixture: &Fixture, bytes: &[u8], extra: &[&str]) -> Output {
        let mut args = arguments(&["stdin"]);
        args.extend_from_slice(extra);
        let mut child = command(&fixture.0)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        child.wait_with_output().unwrap()
    }

    fn status(stderr: &[u8]) -> &str {
        let text = std::str::from_utf8(stderr).unwrap();
        let records = text
            .lines()
            .filter(|line| line.starts_with("rustleaks_scan_status "))
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 1, "{text}");
        records[0]
    }

    fn injected<R: Read + Send + 'static>(
        fixture: &Fixture,
        reader: R,
        extra: &[&str],
    ) -> (i32, Vec<u8>, Vec<u8>) {
        let mut args = arguments(&["stdin"]);
        args.extend_from_slice(extra);
        let environment = rustleaks_cli::RunEnvironment {
            cwd: fixture.0.clone(),
            config_path: None,
            config_toml: None,
            legacy_config_path: None,
            legacy_config_toml: None,
        };
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let code = rustleaks_cli::run_from(
            args.into_iter().map(std::ffi::OsString::from),
            environment,
            reader,
            &mut stdout,
            &mut stderr,
        );
        (code, stdout, stderr)
    }

    #[test]
    fn clean_positive_exact_cap_and_overflow_have_distinct_status_and_exit() {
        let fixture = Fixture::new();
        fixture.write("config.toml", matching_config());
        profile(&fixture, &[("target_bytes", 10)]);
        for (bytes, code, state) in [
            (&b"clean\n"[..], 0, "status=complete reason=complete"),
            (&b"token=AB12"[..], 1, "status=complete reason=complete"),
            (
                &b"token=AB12\n"[..],
                2,
                "status=incomplete reason=resource_exhaustion",
            ),
        ] {
            let result = stdin(&fixture, bytes, &[]);
            assert_eq!(
                result.status.code(),
                Some(code),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(status(&result.stderr).contains(state));
            if code == 2 {
                assert_eq!(result.stdout, b"[]\n");
            }
        }
        let redacted = stdin(&fixture, b"token=AB12", &["--redact", "--exit-code", "0"]);
        assert_eq!(redacted.status.code(), Some(0));
        assert!(status(&redacted.stderr).contains("status=complete"));
        assert!(String::from_utf8_lossy(&redacted.stdout).contains("REDACTED"));
        assert!(!String::from_utf8_lossy(&redacted.stdout).contains("AB12"));
        let incomplete = stdin(&fixture, b"token=AB12\n", &["--exit-code", "0"]);
        assert_eq!(incomplete.status.code(), Some(2));
    }

    #[test]
    fn invalid_profiles_and_conflicting_options_fail_before_input() {
        struct MustNotRead;
        impl Read for MustNotRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("invalid profile read stdin")
            }
        }
        let fixture = Fixture::new();
        fixture.write("config.toml", matching_config());
        for field in ["workers", "queue_capacity"] {
            profile(&fixture, &[(field, usize::MAX)]);
            let (code, stdout, stderr) = injected(&fixture, MustNotRead, &[]);
            assert_eq!(code, 2);
            assert!(stdout.is_empty());
            assert!(status(&stderr).contains("reason=profile_error"));
        }
        for extra in [
            vec!["--exit-code", "2"],
            vec!["--max-target-megabytes", "1"],
        ] {
            profile(&fixture, &[]);
            let (code, stdout, stderr) = injected(&fixture, MustNotRead, &extra);
            assert_eq!(code, 2);
            assert!(stdout.is_empty());
            assert!(status(&stderr).contains("reason=profile_error"));
        }
        fixture.write(
            "scan.limits",
            format!("{PROFILE}private_value=synthetic-private-value\n"),
        );
        let (code, stdout, stderr) = injected(&fixture, MustNotRead, &[]);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(!String::from_utf8_lossy(&stderr).contains("synthetic-private-value"));
        assert!(status(&stderr).contains("reason=profile_error"));
    }

    #[test]
    fn engine_limits_discard_failed_fragment_and_report_exact_resource_scope() {
        let fixture = Fixture::new();
        fixture.write("config.toml", matching_config());
        profile(&fixture, &[("fragment_finding_records", 1)]);
        let exact = stdin(&fixture, b"token=AB12\n", &[]);
        assert_eq!(exact.status.code(), Some(1));
        assert!(status(&exact.stderr).contains("finding_records=1"));
        let exceeded = stdin(&fixture, b"token=AB12\ntoken=CD34\n", &[]);
        assert_eq!(exceeded.status.code(), Some(2));
        assert_eq!(exceeded.stdout, b"[]\n");
        assert!(status(&exceeded.stderr).contains(
            "resource=finding_records budget_scope=fragment limit=1 consumed=1 requested=1"
        ));
        profile(&fixture, &[("operation_finding_records", 0)]);
        let exceeded = stdin(&fixture, b"token=AB12\n", &[]);
        assert_eq!(exceeded.status.code(), Some(2));
        assert!(status(&exceeded.stderr).contains(
            "resource=finding_records budget_scope=operation limit=0 consumed=0 requested=1"
        ));
        for (field, resource) in [
            ("fragment_work_units", "work_units"),
            ("fragment_collected_spans", "collected_spans"),
            ("fragment_finding_payload_bytes", "finding_payload_bytes"),
        ] {
            profile(&fixture, &[(field, 0)]);
            let exceeded = stdin(&fixture, b"token=AB12\n", &[]);
            assert_eq!(exceeded.status.code(), Some(2));
            assert_eq!(exceeded.stdout, b"[]\n");
            assert!(status(&exceeded.stderr).contains(&format!(
                "resource={resource} budget_scope=fragment limit=0"
            )));
        }
    }

    #[test]
    fn complete_directory_retains_prior_targets_and_marks_report_partial() {
        let fixture = Fixture::new();
        fixture.write("config.toml", matching_config());
        fixture.write("inputs/a.txt", b"token=AB12");
        fixture.write("inputs/b.txt", b"token=CD34\n");
        profile(&fixture, &[("target_bytes", 10)]);
        let result = output(&fixture.0, &arguments(&["dir", "inputs"]));
        assert_eq!(result.status.code(), Some(2));
        let report = String::from_utf8_lossy(&result.stdout);
        assert!(report.contains("AB12"));
        assert!(!report.contains("CD34"));
        assert_eq!(report.matches("\"RuleID\"").count(), 1);
        assert!(status(&result.stderr).contains("status=incomplete"));
        assert!(status(&result.stderr).contains("reports=partial"));
        assert!(status(&result.stderr).contains("completed_fragments=1"));
    }

    #[test]
    fn read_error_discards_the_whole_target_and_report_write_failure_is_incomplete() {
        struct Failed {
            first: bool,
        }
        impl Read for Failed {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if self.first {
                    self.first = false;
                    output[..10].copy_from_slice(b"token=AB12");
                    Ok(10)
                } else {
                    Err(io::Error::other("synthetic read failure"))
                }
            }
        }
        let fixture = Fixture::new();
        fixture.write("config.toml", matching_config());
        profile(&fixture, &[]);
        let (code, stdout, stderr) =
            injected(&fixture, Failed { first: true }, &["--exit-code", "0"]);
        assert_eq!(code, 2);
        assert_eq!(stdout, b"[]\n");
        assert!(status(&stderr).contains("reason=coverage_failure"));
        let (code, _, stderr) = injected(
            &fixture,
            Cursor::new(Vec::<u8>::new()),
            &["--report-path", "."],
        );
        assert_eq!(code, 2);
        assert!(status(&stderr).contains("reason=report_failure"));
    }

    #[test]
    fn normal_config_precedence_rule_selection_allowlists_and_ignore_remain_active() {
        let fixture = Fixture::new();
        profile(&fixture, &[]);
        fixture.write("config.toml", two_rule_config());
        let selected = stdin(
            &fixture,
            b"alpha=AB12\nbeta=CD34\n",
            &["--enable-rule", "alpha"],
        );
        assert_eq!(selected.status.code(), Some(1));
        let report = String::from_utf8_lossy(&selected.stdout);
        assert!(report.contains("AB12"));
        assert!(!report.contains("CD34"));
        fixture.write(".rustleaksignore", b":alpha:1\n");
        let ignored = stdin(&fixture, b"alpha=AB12\n", &[]);
        assert_eq!(ignored.status.code(), Some(0));
        assert_eq!(ignored.stdout, b"[]\n");
        fs::remove_file(fixture.0.join(".rustleaksignore")).unwrap();
        fixture.write(
            "config.toml",
            format!(
                "{}\n[allowlist]\npaths=['''excluded[.]txt$''']\n",
                matching_config()
            ),
        );
        fixture.write("inputs/excluded.txt", b"token=AB12\n");
        let excluded = output(&fixture.0, &arguments(&["dir", "inputs"]));
        assert_eq!(excluded.status.code(), Some(0));
        assert_eq!(excluded.stdout, b"[]\n");
        fixture.write(".rustleaks.toml", two_rule_config());
        let auto = output(
            &fixture.0,
            &[
                "dir",
                "inputs",
                "--complete-profile",
                "scan.limits",
                "--no-banner",
                "--log-level",
                "fatal",
            ],
        );
        assert_eq!(auto.status.code(), Some(0));
        fixture.write("inputs/active.txt", b"beta=CD34\n");
        let auto = output(
            &fixture.0,
            &[
                "dir",
                ".",
                "--complete-profile",
                "scan.limits",
                "--no-banner",
                "--log-level",
                "fatal",
                "--enable-rule",
                "beta",
            ],
        );
        assert_eq!(auto.status.code(), Some(1));
        let env_selected = command(&fixture.0)
            .env("RUSTLEAKS_CONFIG_TOML", no_match_config())
            .args([
                "dir",
                "inputs",
                "--complete-profile",
                "scan.limits",
                "--no-banner",
                "--log-level",
                "fatal",
            ])
            .output()
            .unwrap();
        assert_eq!(env_selected.status.code(), Some(0));
        assert!(status(&env_selected.stderr).contains("status=complete"));
    }

    #[test]
    fn scm_long_url_preflight_and_aggregate_limits_are_inclusive() {
        let fixture = Fixture::new();
        git(&fixture.0, &["init", "--quiet"]);
        git(&fixture.0, &["config", "user.name", "Complete CLI Test"]);
        git(
            &fixture.0,
            &["config", "user.email", "complete@example.invalid"],
        );
        fixture.write("config.toml", matching_config());
        fixture.write("secret%.txt", b"token=AB12\ntoken=CD34\n");
        git(&fixture.0, &["add", "secret%.txt"]);
        git(
            &fixture.0,
            &["commit", "--quiet", "-m", "synthetic fixture"],
        );
        let remote = format!("https://example.invalid/{}", "x".repeat(6000));
        git(&fixture.0, &["remote", "add", "origin", &remote]);
        let length = remote.len() + b"/blob/".len() + 40 + b"/secret%25.txt#L1".len();
        let args = arguments(&["git", ".", "--platform", "github"]);
        profile(
            &fixture,
            &[
                ("scm_link_bytes", length),
                ("operation_scm_link_bytes", 2 * length),
            ],
        );
        let exact = output(&fixture.0, &args);
        assert_eq!(
            exact.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&exact.stderr)
        );
        assert!(status(&exact.stderr).contains("status=complete"));
        assert!(status(&exact.stderr).contains(&format!("scm_link_bytes={}", 2 * length)));
        assert_eq!(
            String::from_utf8_lossy(&exact.stdout)
                .matches("https://example.invalid/")
                .count(),
            2
        );
        profile(
            &fixture,
            &[
                ("scm_link_bytes", length - 1),
                ("operation_scm_link_bytes", 2 * length),
            ],
        );
        let per_link = output(&fixture.0, &args);
        assert_eq!(per_link.status.code(), Some(2));
        assert!(status(&per_link.stderr).contains("reason=metadata_failure"));
        assert!(status(&per_link.stderr).contains("resource=scm_link_bytes budget_scope=link"));
        assert!(!String::from_utf8_lossy(&per_link.stdout).contains("https://example.invalid/"));
        profile(
            &fixture,
            &[
                ("scm_link_bytes", length),
                ("operation_scm_link_bytes", 2 * length - 1),
            ],
        );
        let total = output(&fixture.0, &args);
        assert_eq!(total.status.code(), Some(2));
        assert!(status(&total.stderr).contains("resource=scm_link_bytes budget_scope=operation"));
        assert_eq!(
            String::from_utf8_lossy(&total.stdout)
                .matches("\"RuleID\"")
                .count(),
            2
        );
        assert_eq!(
            String::from_utf8_lossy(&total.stdout)
                .matches("https://example.invalid/")
                .count(),
            1
        );
        let disabled = output(&fixture.0, &arguments(&["git", ".", "--platform", "none"]));
        assert_eq!(disabled.status.code(), Some(1));
        assert!(status(&disabled.stderr).contains("status=complete"));
        git(
            &fixture.0,
            &[
                "remote",
                "set-url",
                "origin",
                "https://example.invalid/%invalid",
            ],
        );
        let invalid = output(&fixture.0, &args);
        assert_eq!(invalid.status.code(), Some(2));
        assert!(status(&invalid.stderr).contains("reason=metadata_failure"));
    }

    fn tar_leaf(bytes: &[u8]) -> Vec<u8> {
        tar_named_leaf(b"leaf.txt", bytes)
    }

    pub(super) fn tar_named_leaf(name: &[u8], bytes: &[u8]) -> Vec<u8> {
        assert!(name.len() <= 100);
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name);
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| usize::from(*byte)).sum::<usize>();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        let mut archive = header.to_vec();
        archive.extend_from_slice(bytes);
        archive.resize(512 + bytes.len().div_ceil(512) * 512 + 1024, 0);
        archive
    }

    pub(super) fn stored_gzip(payload: &[u8]) -> Vec<u8> {
        let length = u16::try_from(payload.len()).expect("small synthetic gzip payload");
        let mut bytes = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255, 1];
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&(!length).to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&crc32(payload).to_le_bytes());
        bytes.extend_from_slice(&u32::from(length).to_le_bytes());
        bytes
    }

    fn crc32(bytes: &[u8]) -> u32 {
        !bytes.iter().fold(!0_u32, |state, &byte| {
            (0..8).fold(state ^ u32::from(byte), |value, _| {
                (value >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(value & 1))
            })
        })
    }

    // Minimal stored ZIP writer: a local header, name and data per entry, then
    // the central directory and the end of central directory record.
    pub(super) fn stored_zip(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut central = Vec::new();
        for &(name, body) in entries {
            let crc = crc32(body).to_le_bytes();
            let size = u32::try_from(body.len()).unwrap().to_le_bytes();
            let name_size = u16::try_from(name.len()).unwrap().to_le_bytes();
            let offset = u32::try_from(data.len()).unwrap().to_le_bytes();
            let mut local = [0_u8; 30];
            local[..4].copy_from_slice(b"PK\x03\x04");
            local[4..6].copy_from_slice(&20_u16.to_le_bytes());
            local[14..18].copy_from_slice(&crc);
            local[18..22].copy_from_slice(&size);
            local[22..26].copy_from_slice(&size);
            local[26..28].copy_from_slice(&name_size);
            data.extend_from_slice(&local);
            data.extend_from_slice(name);
            data.extend_from_slice(body);
            let mut entry = [0_u8; 46];
            entry[..4].copy_from_slice(b"PK\x01\x02");
            entry[4..6].copy_from_slice(&20_u16.to_le_bytes());
            entry[6..8].copy_from_slice(&20_u16.to_le_bytes());
            entry[16..20].copy_from_slice(&crc);
            entry[20..24].copy_from_slice(&size);
            entry[24..28].copy_from_slice(&size);
            entry[28..30].copy_from_slice(&name_size);
            entry[42..46].copy_from_slice(&offset);
            central.extend_from_slice(&entry);
            central.extend_from_slice(name);
        }
        let mut end = [0_u8; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        let count = u16::try_from(entries.len()).unwrap().to_le_bytes();
        end[8..10].copy_from_slice(&count);
        end[10..12].copy_from_slice(&count);
        end[12..16].copy_from_slice(&u32::try_from(central.len()).unwrap().to_le_bytes());
        end[16..20].copy_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        data.extend_from_slice(&central);
        data.extend_from_slice(&end);
        data
    }

    struct ArchiveCase {
        name: &'static str,
        depth: &'static str,
        code: i32,
        state: &'static str,
        reason: &'static str,
        reports: &'static str,
        fragments: usize,
        issues: usize,
        files: &'static [&'static str],
        diagnostic: &'static str,
    }

    const ARCHIVE_CASES: &[ArchiveCase] = &[
        ArchiveCase {
            name: "partial.tar",
            depth: "1",
            code: 2,
            state: "incomplete",
            reason: "coverage_failure",
            reports: "partial",
            fragments: 1,
            issues: 0,
            files: &["partial.tar!first.txt"],
            diagnostic: "truncated TAR member",
        },
        // Archives stream: the whole leaf is scanned before the gzip
        // trailer after the TAR end fails its CRC check.
        ArchiveCase {
            name: "corrupt.tgz",
            depth: "1",
            code: 2,
            state: "incomplete",
            reason: "coverage_failure",
            reports: "partial",
            fragments: 1,
            issues: 0,
            files: &["corrupt.tgz!leaf.txt"],
            diagnostic: "gzip size or CRC mismatch",
        },
        ArchiveCase {
            name: "outer.tgz",
            depth: "2",
            code: 0,
            state: "complete",
            reason: "complete",
            reports: "complete",
            fragments: 0,
            issues: 2,
            files: &[],
            diagnostic: "skipping archive: exceeds maximum archive depth",
        },
        ArchiveCase {
            name: "outer.tgz",
            depth: "3",
            code: 1,
            state: "complete",
            reason: "complete",
            reports: "complete",
            fragments: 2,
            issues: 0,
            files: &[
                "outer.tgz!wrapper.tgz!left.tgz!leaf.txt",
                "outer.tgz!wrapper.tgz!right.tgz!leaf.txt",
            ],
            diagnostic: "",
        },
        ArchiveCase {
            name: "outer.tar",
            depth: "2",
            code: 0,
            state: "complete",
            reason: "complete",
            reports: "complete",
            fragments: 0,
            issues: 2,
            files: &[],
            diagnostic: "skipping archive: exceeds maximum archive depth",
        },
        ArchiveCase {
            name: "outer.tar",
            depth: "3",
            code: 1,
            state: "complete",
            reason: "complete",
            reports: "complete",
            fragments: 2,
            issues: 0,
            files: &[
                "outer.tar!wrapper.tar!left.tar!leaf.txt",
                "outer.tar!wrapper.tar!right.tar!leaf.txt",
            ],
            diagnostic: "",
        },
        ArchiveCase {
            name: "outer.zip",
            depth: "2",
            code: 0,
            state: "complete",
            reason: "complete",
            reports: "complete",
            fragments: 0,
            issues: 2,
            files: &[],
            diagnostic: "skipping archive: exceeds maximum archive depth",
        },
        ArchiveCase {
            name: "outer.zip",
            depth: "3",
            code: 1,
            state: "complete",
            reason: "complete",
            reports: "complete",
            fragments: 2,
            issues: 0,
            files: &[
                "outer.zip!wrapper.zip!left.zip!leaf.txt",
                "outer.zip!wrapper.zip!right.zip!leaf.txt",
            ],
            diagnostic: "",
        },
        ArchiveCase {
            name: "checksum.tar",
            depth: "1",
            code: 2,
            state: "incomplete",
            reason: "coverage_failure",
            reports: "partial",
            fragments: 0,
            issues: 0,
            files: &[],
            diagnostic: "invalid TAR header checksum",
        },
        ArchiveCase {
            name: "crc.zip",
            depth: "1",
            code: 2,
            state: "incomplete",
            reason: "coverage_failure",
            reports: "partial",
            fragments: 0,
            issues: 0,
            files: &[],
            diagnostic: "ZIP member size or CRC mismatch",
        },
        ArchiveCase {
            name: "noend.zip",
            depth: "1",
            code: 2,
            state: "incomplete",
            reason: "coverage_failure",
            reports: "partial",
            fragments: 0,
            issues: 0,
            files: &[],
            diagnostic: "",
        },
        // The cut is after the whole leaf, in the TAR end blocks.
        ArchiveCase {
            name: "half.tgz",
            depth: "1",
            code: 2,
            state: "incomplete",
            reason: "coverage_failure",
            reports: "partial",
            fragments: 1,
            issues: 0,
            files: &["half.tgz!leaf.txt"],
            diagnostic: "",
        },
    ];

    fn assert_archive_case(case: &ArchiveCase, result: &Output) {
        let ArchiveCase {
            name,
            depth,
            code,
            state,
            reason,
            reports,
            fragments,
            issues,
            files,
            diagnostic,
        } = *case;
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert_eq!(result.status.code(), Some(code), "{name}/{depth}: {stderr}");
        let fields = status(&result.stderr)
            .split_whitespace()
            .collect::<Vec<_>>();
        for expected in [
            format!("status={state}"),
            format!("reason={reason}"),
            format!("reports={reports}"),
            "source_scope=directory_targets".to_owned(),
            "resource=none".to_owned(),
            "budget_scope=none".to_owned(),
            "usage=available".to_owned(),
            "usage_exact=1".to_owned(),
            format!("archive_depth={depth}"),
            format!("findings={fragments}"),
            format!("original_bytes={}", fragments * 10),
            format!("fragments={fragments}"),
            format!("completed_fragments={fragments}"),
            format!("issues={issues}"),
        ] {
            assert!(fields.contains(&expected.as_str()), "{expected}: {stderr}");
        }
        let report = rustleaks_core::session::Baseline::from_go_json(&result.stdout).unwrap();
        assert!(!report.was_null());
        let rows = report.entries();
        assert_eq!(rows.len(), files.len());
        let mut actual_files = rows
            .iter()
            .map(|row| row.file().as_bytes())
            .collect::<Vec<_>>();
        actual_files.sort_unstable();
        let mut expected_files = files.iter().map(|file| file.as_bytes()).collect::<Vec<_>>();
        expected_files.sort_unstable();
        assert_eq!(actual_files, expected_files);
        for row in rows {
            assert_eq!(row.rule_id().as_bytes(), b"fixture-token");
            assert_eq!(row.start_line(), 1);
            assert_eq!(row.end_line(), 1);
            assert_eq!(row.start_column(), 1);
            assert_eq!(row.end_column(), 10);
            assert_eq!(row.match_text().as_bytes(), b"token=AB12");
            assert_eq!(row.secret().as_bytes(), b"AB12");
        }
        if !diagnostic.is_empty() {
            assert!(stderr.contains(diagnostic), "{stderr}");
        }
    }

    #[test]
    fn complete_archive_status_distinguishes_partial_members_and_depth_exclusions() {
        let fixture = Fixture::new();
        fixture.write("config.toml", matching_config());
        profile(&fixture, &[]);
        let mut partial = tar_named_leaf(b"first.txt", b"token=AB12");
        partial.truncate(partial.len() - 1024);
        partial.extend(tar_named_leaf(b"second.txt", b"token=CD34"));
        partial.truncate(1024 + 512 + 7);
        fixture.write("partial.tar", partial);
        let inner = stored_gzip(&tar_leaf(b"token=AB12"));
        let mut corrupt = inner.clone();
        let crc = corrupt.len() - 8;
        corrupt[crc] ^= 1;
        fixture.write("corrupt.tgz", corrupt);
        let mut siblings = tar_named_leaf(b"left.tgz", &inner);
        siblings.truncate(siblings.len() - 1024);
        siblings.extend(tar_named_leaf(b"right.tgz", &inner));
        let middle = stored_gzip(&siblings);
        let outer = stored_gzip(&tar_named_leaf(b"wrapper.tgz", &middle));
        fixture.write("outer.tgz", outer);
        let leaf_tar = tar_leaf(b"token=AB12");
        let mut tar_siblings = tar_named_leaf(b"left.tar", &leaf_tar);
        tar_siblings.truncate(tar_siblings.len() - 1024);
        tar_siblings.extend(tar_named_leaf(b"right.tar", &leaf_tar));
        fixture.write("outer.tar", tar_named_leaf(b"wrapper.tar", &tar_siblings));
        let leaf_zip = stored_zip(&[(b"leaf.txt", b"token=AB12")]);
        let middle_zip = stored_zip(&[(b"left.zip", &leaf_zip), (b"right.zip", &leaf_zip)]);
        fixture.write("outer.zip", stored_zip(&[(b"wrapper.zip", &middle_zip)]));
        let mut checksum = leaf_tar.clone();
        checksum[148] ^= 1;
        fixture.write("checksum.tar", checksum);
        // Data starts after the 30-byte local header and the 8-byte name, so
        // byte 47 is the final '2' of the leaf. Both stored CRCs stay intact.
        let mut crc = leaf_zip.clone();
        assert_eq!(crc[47], b'2');
        crc[47] ^= 1;
        fixture.write("crc.zip", crc);
        // Drop exactly the 22-byte end of central directory record.
        fixture.write("noend.zip", &leaf_zip[..leaf_zip.len() - 22]);
        let half = stored_gzip(&leaf_tar);
        fixture.write("half.tgz", &half[..half.len() / 2]);
        for case in ARCHIVE_CASES {
            let command_args = ["dir", case.name, "--max-archive-depth", case.depth];
            let mut args = arguments(&command_args);
            args.extend(["--log-level", "info"]);
            assert_archive_case(case, &output(&fixture.0, &args));
        }
    }

    #[test]
    fn complete_profile_reaches_stdin_directory_and_git_archive_leaves() {
        let fixture = Fixture::new();
        fixture.write("config.toml", matching_config());
        profile(&fixture, &[("target_bytes", 10)]);
        let archive = tar_leaf(b"token=AB12");
        // Archive recognition uses the source name. Unnamed stdin remains a
        // plaintext target even when archive traversal is enabled.
        let input = stdin(&fixture, b"token=AB12", &["--max-archive-depth", "1"]);
        assert_eq!(
            input.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&input.stderr)
        );
        assert!(status(&input.stderr).contains("status=complete"));
        fixture.write("input.tar", &archive);
        let args = arguments(&["dir", "input.tar", "--max-archive-depth", "1"]);
        let dir = output(&fixture.0, &args);
        assert_eq!(
            dir.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&dir.stderr)
        );
        assert!(status(&dir.stderr).contains("status=complete"));
        git(&fixture.0, &["init", "--quiet"]);
        git(
            &fixture.0,
            &["config", "user.name", "Complete Archive Test"],
        );
        git(
            &fixture.0,
            &["config", "user.email", "archive@example.invalid"],
        );
        git(&fixture.0, &["add", "input.tar"]);
        git(
            &fixture.0,
            &["commit", "--quiet", "-m", "synthetic archive"],
        );
        let history = output(
            &fixture.0,
            &arguments(&["git", ".", "--platform", "none", "--max-archive-depth", "1"]),
        );
        assert_eq!(
            history.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&history.stderr)
        );
        assert!(status(&history.stderr).contains("status=complete"));
        assert!(String::from_utf8_lossy(&history.stdout).contains("AB12"));
        fixture.write("input.tar", tar_leaf(b"token=AB12\n"));
        let exceeded = output(&fixture.0, &args);
        assert_eq!(exceeded.status.code(), Some(2));
        assert_eq!(exceeded.stdout, b"[]\n");
        assert!(status(&exceeded.stderr).contains("status=incomplete"));
        fixture.write("input.tar", b"\x1f\x8bbad");
        let corrupt = output(&fixture.0, &args);
        assert_eq!(corrupt.status.code(), Some(2));
        assert_eq!(corrupt.stdout, b"[]\n");
        assert!(status(&corrupt.stderr).contains("reason=coverage_failure"));
    }

    #[test]
    fn complete_control_files_are_excluded_before_the_source_cap() {
        let fixture = Fixture::new();
        profile(&fixture, &[("target_bytes", 10)]);
        fixture.write("inputs/config.toml", matching_config());
        fixture.write("inputs/baseline.json", format!("[]{}", " ".repeat(100)));
        fixture.write("inputs/z.txt", b"token=AB12");
        let cwd = fixture.0.join("inputs");
        let common = [
            "--complete-profile",
            "../scan.limits",
            "--no-banner",
            "--log-level",
            "fatal",
            "--config",
            "config.toml",
            "--baseline-path",
            "baseline.json",
            "--report-path",
            "-",
            "--report-format",
            "json",
        ];
        for (source, count) in [("config.toml", 0), (".", 1)] {
            let result = command(&cwd)
                .args(["dir", source])
                .args(common)
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(count),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(status(&result.stderr).contains("status=complete"));
            assert_eq!(
                String::from_utf8_lossy(&result.stdout)
                    .matches("\"RuleID\"")
                    .count(),
                usize::try_from(count).unwrap()
            );
        }
        fixture.write("inputs/config.toml.bak", b"token=CD34\n");
        let eligible = command(&cwd)
            .args(["dir", "."])
            .args(common)
            .output()
            .unwrap();
        assert_eq!(eligible.status.code(), Some(2));
        assert!(status(&eligible.stderr).contains("reason=resource_exhaustion"));
        fs::remove_file(cwd.join("config.toml.bak")).unwrap();
        fs::rename(cwd.join("config.toml"), cwd.join(".rustleaks.toml")).unwrap();
        let automatic = command(&cwd)
            .args([
                "dir",
                ".",
                "--complete-profile",
                "../scan.limits",
                "--no-banner",
                "--log-level",
                "fatal",
                "--baseline-path",
                "baseline.json",
                "--report-path",
                "-",
                "--report-format",
                "json",
            ])
            .output()
            .unwrap();
        assert_eq!(
            automatic.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&automatic.stderr)
        );
        assert!(status(&automatic.stderr).contains("status=complete"));
        assert_eq!(
            String::from_utf8_lossy(&automatic.stdout)
                .matches("\"RuleID\"")
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn complete_self_exclusions_compare_resolved_file_paths_not_symlink_aliases() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        profile(&fixture, &[("target_bytes", 10)]);
        fixture.write("inputs/config.toml", matching_config());
        fixture.write("inputs/z.txt", b"token=AB12");
        symlink("config.toml", fixture.0.join("inputs/alias")).unwrap();
        let common = [
            "dir",
            ".",
            "--complete-profile",
            "../scan.limits",
            "--no-banner",
            "--log-level",
            "fatal",
            "--config",
            "config.toml",
            "--follow-symlinks",
            "--report-path",
            "-",
            "--report-format",
            "json",
        ];
        let cwd = fixture.0.join("inputs");
        let excluded = command(&cwd).args(common).output().unwrap();
        assert_eq!(
            excluded.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&excluded.stderr)
        );
        assert!(status(&excluded.stderr).contains("status=complete"));
        // Selecting the alias as --config excludes the alias spelling only;
        // emitted FilePath still names config.toml, as in the legacy route.
        let eligible = command(&cwd)
            .args(common)
            .args(["--config", "alias"])
            .output()
            .unwrap();
        assert_eq!(eligible.status.code(), Some(2));
        assert!(status(&eligible.stderr).contains("reason=resource_exhaustion"));
    }

    #[test]
    fn exact_control_path_exclusions_reach_directory_and_git_archive_leaves() {
        let fixture = Fixture::new();
        profile(&fixture, &[("target_bytes", 10)]);
        fixture.write("outer.tar!leaf.txt", matching_config());
        fixture.write("outer.tar!leaf.txt.other", matching_config());
        let mut archive = tar_leaf(b"token=CD34\n");
        archive.truncate(archive.len() - 1024);
        archive.extend(tar_named_leaf(b"z.txt", b"token=AB12"));
        fixture.write("outer.tar", archive);
        let mut args = arguments(&["dir", "outer.tar", "--max-archive-depth", "1"]);
        args.extend(["--config", "outer.tar!leaf.txt"]);
        let selected = output(&fixture.0, &args);
        assert_eq!(
            selected.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&selected.stderr)
        );
        assert!(status(&selected.stderr).contains("status=complete"));
        assert!(String::from_utf8_lossy(&selected.stdout).contains("AB12"));
        assert!(!String::from_utf8_lossy(&selected.stdout).contains("CD34"));
        let environment = rustleaks_cli::RunEnvironment {
            cwd: fixture.0.clone(),
            config_path: None,
            config_toml: None,
            legacy_config_path: None,
            legacy_config_toml: None,
        };
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let code = rustleaks_cli::run_from(
            args.iter().copied().map(std::ffi::OsString::from),
            environment,
            Cursor::new(Vec::<u8>::new()),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1, "{}", String::from_utf8_lossy(&stderr));
        assert!(status(&stderr).contains("status=complete"));
        assert!(String::from_utf8_lossy(&stdout).contains("AB12"));
        let different = command(&fixture.0)
            .args(&args)
            .args(["--config", "outer.tar!leaf.txt.other"])
            .output()
            .unwrap();
        assert_eq!(different.status.code(), Some(2));
        git(&fixture.0, &["init", "--quiet"]);
        git(
            &fixture.0,
            &["config", "user.name", "Complete Exclusion Test"],
        );
        git(
            &fixture.0,
            &["config", "user.email", "exclusion@example.invalid"],
        );
        git(&fixture.0, &["add", "outer.tar"]);
        git(
            &fixture.0,
            &["commit", "--quiet", "-m", "synthetic exclusion archive"],
        );
        let mut args = arguments(&["git", ".", "--platform", "none", "--max-archive-depth", "1"]);
        args.extend(["--config", "outer.tar!leaf.txt"]);
        let selected = output(&fixture.0, &args);
        assert_eq!(
            selected.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&selected.stderr)
        );
        assert!(status(&selected.stderr).contains("status=complete"));
        assert!(String::from_utf8_lossy(&selected.stdout).contains("AB12"));
        assert!(!String::from_utf8_lossy(&selected.stdout).contains("CD34"));
    }

    #[test]
    fn exact_exclusions_preserve_dot_slash_file_and_archive_spelling() {
        let fixture = Fixture::new();
        profile(&fixture, &[("target_bytes", 10)]);
        fixture.write("inputs/config.toml", matching_config());
        fixture.write("inputs/z.txt", b"token=AB12");
        let cwd = fixture.0.join("inputs");
        for (source, config, expected) in [
            (".", "config.toml", 1),
            ("./", "config.toml", 2),
            ("./", "./config.toml", 1),
        ] {
            let result = command(&cwd)
                .args([
                    "dir",
                    source,
                    "--config",
                    config,
                    "--complete-profile",
                    "../scan.limits",
                    "--no-banner",
                    "--log-level",
                    "fatal",
                    "--report-path",
                    "-",
                    "--report-format",
                    "json",
                ])
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(expected),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                status(&result.stderr).contains("status=complete"),
                expected == 1
            );
            if source == "./" && expected == 1 {
                assert!(String::from_utf8_lossy(&result.stdout).contains("./z.txt"));
            }
        }
        fixture.write("outer.tar!leaf.txt", matching_config());
        let mut archive = tar_leaf(b"token=CD34\n");
        archive.truncate(archive.len() - 1024);
        archive.extend(tar_named_leaf(b"z.txt", b"token=AB12"));
        fixture.write("outer.tar", archive);
        for (source, config, expected) in [
            ("outer.tar", "outer.tar!leaf.txt", 1),
            ("./outer.tar", "outer.tar!leaf.txt", 2),
            ("./outer.tar", "./outer.tar!leaf.txt", 1),
        ] {
            let result = command(&fixture.0)
                .args([
                    "dir",
                    source,
                    "--config",
                    config,
                    "--complete-profile",
                    "scan.limits",
                    "--max-archive-depth",
                    "1",
                    "--no-banner",
                    "--log-level",
                    "fatal",
                    "--report-path",
                    "-",
                    "--report-format",
                    "json",
                ])
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(expected),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                status(&result.stderr).contains("status=complete"),
                expected == 1
            );
        }
    }

    #[test]
    fn exact_self_exclusion_of_nested_container_does_not_hide_its_leaf() {
        let fixture = Fixture::new();
        profile(&fixture, &[("target_bytes", 10)]);
        fixture.write("outer.tar!inner.tar", matching_config());
        fixture.write("outer.tar!inner.tar!leaf.txt", matching_config());
        let inner = tar_leaf(b"token=AB12");
        fixture.write("outer.tar", tar_named_leaf(b"inner.tar", &inner));
        for (config, expected) in [
            ("outer.tar!inner.tar", 1),
            ("outer.tar!inner.tar!leaf.txt", 0),
        ] {
            for complete in [false, true] {
                let mut args = vec![
                    "dir",
                    "outer.tar",
                    "--config",
                    config,
                    "--max-archive-depth",
                    "2",
                    "--no-banner",
                    "--log-level",
                    "fatal",
                    "--report-path",
                    "-",
                    "--report-format",
                    "json",
                ];
                if complete {
                    args.extend(["--complete-profile", "scan.limits"]);
                }
                let result = output(&fixture.0, &args);
                assert_eq!(
                    result.status.code(),
                    Some(expected),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                if complete {
                    assert!(status(&result.stderr).contains("status=complete"));
                }
                assert_eq!(
                    String::from_utf8_lossy(&result.stdout)
                        .matches("\"RuleID\"")
                        .count(),
                    usize::try_from(expected).unwrap()
                );
            }
        }
    }
}

mod native_packs {
    use super::*;

    fn secret() -> String {
        format!(
            "gsk_{}",
            "Q7m2Z9v4L1c8R5s0N6b3X"
                .chars()
                .cycle()
                .take(52)
                .collect::<String>()
        )
    }

    fn args<'a>(prefix: &[&'a str]) -> Vec<&'a str> {
        let mut arguments = prefix.to_vec();
        arguments.extend([
            "--native-pack",
            "rustleaks-providers-v1",
            "--enable-rule",
            "rustleaks.groq-api-key",
            "--no-banner",
            "--log-level",
            "fatal",
            "--report-path",
            "-",
            "--report-format",
            "json",
        ]);
        arguments
    }

    fn stdin(fixture: &Fixture, bytes: &[u8], extra: &[&str]) -> Output {
        let mut arguments = args(&["stdin"]);
        arguments.extend_from_slice(extra);
        let mut child = command(&fixture.0)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        child.wait_with_output().unwrap()
    }

    #[test]
    fn builtin_selection_reaches_normal_pipeline_and_preserves_opt_in() {
        let fixture = Fixture::new();
        let value = secret();
        let accepted = stdin(
            &fixture,
            value.as_bytes(),
            &[
                "--native-pack",
                "rustleaks-extra-v1",
                "--native-pack",
                "rustleaks-connections-v1",
            ],
        );
        assert_eq!(
            accepted.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&accepted.stderr)
        );
        let report = rustleaks_core::session::Baseline::from_go_json(&accepted.stdout).unwrap();
        assert!(!report.was_null());
        let rows = report.entries();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rule_id().as_bytes(), b"rustleaks.groq-api-key");
        assert_eq!(rows[0].secret().as_bytes(), value.as_bytes());
        let rejected = stdin(&fixture, format!("gsk_{}", "0".repeat(52)).as_bytes(), &[]);
        assert_eq!(rejected.status.code(), Some(0));
        assert_eq!(rejected.stdout, b"[]\n");
        let legacy = output(
            &fixture.0,
            &[
                "stdin",
                "--enable-rule",
                "rustleaks.groq-api-key",
                "--no-banner",
            ],
        );
        assert_eq!(legacy.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&legacy.stderr).contains("rustleaks.groq-api-key"));
        let diagnostic = stdin(&fixture, b"unrelated", &["--log-level", "debug"]);
        let stderr = String::from_utf8_lossy(&diagnostic.stderr);
        assert!(stderr.contains("native policy rustleaks-native-v1|"));
        assert!(stderr.contains("providers-sha256:"));
        assert!(!stderr.contains("[[rules]]"));
    }

    #[test]
    fn native_uri_selection_preserves_global_suppression() {
        let fixture = Fixture::new();
        for (secret, found) in [
            ("%B", false),
            ("%D", false),
            ("%S", false),
            ("%Z", true),
            ("%B0", true),
        ] {
            let input = format!("mysql://app:{secret}@db.invalid");
            let mut child = command(&fixture.0)
                .args([
                    "stdin",
                    "--native-pack",
                    "rustleaks-connections-v1",
                    "--enable-rule",
                    "rustleaks.connection-string.password.database-uri",
                    "--no-banner",
                    "--log-level",
                    "fatal",
                    "--report-path",
                    "-",
                    "--report-format",
                    "json",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
            let result = child.wait_with_output().unwrap();
            assert_eq!(
                result.status.code(),
                Some(i32::from(found)),
                "{secret}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let report = rustleaks_core::session::Baseline::from_go_json(&result.stdout).unwrap();
            assert!(!report.was_null());
            let rows = report.entries();
            assert_eq!(rows.len(), usize::from(found), "{secret}");
            if found {
                assert_eq!(rows[0].secret().as_bytes(), secret.as_bytes());
                assert_eq!(
                    rows[0].rule_id().as_bytes(),
                    b"rustleaks.connection-string.password.database-uri"
                );
            }
        }
    }

    #[test]
    fn six_builtin_byte_predicates_survive_cli_rule_selection() {
        let fixture = Fixture::new();
        for (id, prefix, length) in [
            ("rustleaks.dockerhub-personal-access-token", "dckr_pat_", 27),
            (
                "rustleaks.dockerhub-organization-access-token",
                "dckr_oat_",
                32,
            ),
            ("rustleaks.neon-api-key", "napi_", 64),
            ("rustleaks.render-api-key", "rnd_", 28),
            ("rustleaks.deno-account-token", "ddp_", 36),
            ("rustleaks.apify-api-token", "apify_api_", 34),
        ] {
            let high = format!(
                "{prefix}{}",
                "Q7m2Z9v4L1c8R5s0N6b3X"
                    .chars()
                    .cycle()
                    .take(length)
                    .collect::<String>()
            );
            // The fixed prefix plus repeated body passes the regex and does
            // not match the default single-letter placeholder allowlist.
            let low = format!("{prefix}{}", "A".repeat(length));
            for (value, count) in [(high, 1), (low, 0)] {
                let mut child = command(&fixture.0)
                    .args([
                        "stdin",
                        "--native-pack",
                        "rustleaks-providers-v1",
                        "--enable-rule",
                        id,
                        "--no-banner",
                        "--log-level",
                        "fatal",
                        "--report-path",
                        "-",
                        "--report-format",
                        "json",
                    ])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(value.as_bytes())
                    .unwrap();
                let result = child.wait_with_output().unwrap();
                assert_eq!(
                    result.status.code(),
                    Some(count),
                    "{id}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let report =
                    rustleaks_core::session::Baseline::from_go_json(&result.stdout).unwrap();
                assert!(!report.was_null());
                let rows = report.entries();
                assert_eq!(rows.len(), usize::try_from(count).unwrap(), "{id}");
                if count != 0 {
                    assert_eq!(rows[0].rule_id().as_bytes(), id.as_bytes());
                    assert_eq!(rows[0].secret().as_bytes(), value.as_bytes());
                }
            }
        }
    }

    #[test]
    fn conflicting_config_sources_are_not_silently_ignored() {
        let fixture = Fixture::new();
        let marker = "NATIVE_CONFIG_PRIVATE_SENTINEL";
        let custom = format!(
            "# {marker}\n[allowlist]\nregexes=['.*']\n{}",
            no_match_config()
        );
        fixture.write("custom.toml", &custom);
        let explicit = output(&fixture.0, &args(&["stdin", "--config", "custom.toml"]));
        assert_eq!(explicit.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&explicit.stderr).contains("selected from --config"));
        assert!(explicit.stdout.is_empty());
        for (key, value) in [
            ("RUSTLEAKS_CONFIG", "custom.toml"),
            ("RUSTLEAKS_CONFIG_TOML", custom.as_str()),
            ("GITLEAKS_CONFIG", "custom.toml"),
            ("GITLEAKS_CONFIG_TOML", custom.as_str()),
        ] {
            let result = command(&fixture.0)
                .env(key, value)
                .args(args(&["stdin"]))
                .output()
                .unwrap();
            assert_eq!(result.status.code(), Some(1));
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert!(stderr.contains(&format!("selected from {key}")));
            assert!(!stderr.contains(marker));
            assert!(result.stdout.is_empty());
        }
        for filename in [".rustleaks.toml", ".gitleaks.toml"] {
            fixture.write(filename, &custom);
            for mode in [vec!["stdin"], vec!["dir", "."]] {
                let result = output(&fixture.0, &args(&mode));
                assert_eq!(result.status.code(), Some(1));
                assert!(
                    String::from_utf8_lossy(&result.stderr)
                        .contains("selected from source-local config")
                );
                assert!(result.stdout.is_empty());
            }
            fs::remove_file(fixture.0.join(filename)).unwrap();
        }
        let empty = command(&fixture.0)
            .env("RUSTLEAKS_CONFIG", "")
            .env("RUSTLEAKS_CONFIG_TOML", "")
            .env("GITLEAKS_CONFIG", "")
            .env("GITLEAKS_CONFIG_TOML", "")
            .args(args(&["stdin"]))
            .output()
            .unwrap();
        assert_eq!(empty.status.code(), Some(0));
        let missing = output(&fixture.0, &args(&["dir", "absent-source"]));
        assert_eq!(missing.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&missing.stderr).contains("during config selection"));
    }

    #[test]
    fn unknown_and_duplicate_native_packs_fail_before_scanning() {
        let fixture = Fixture::new();
        for (id, message) in [
            (
                "unknown-private-sentinel",
                "unknown builtin native pack identifier",
            ),
            ("rustleaks-providers-v1", "duplicate native pack identifier"),
        ] {
            let result = stdin(&fixture, secret().as_bytes(), &["--native-pack", id]);
            assert_eq!(result.status.code(), Some(1));
            assert!(result.stdout.is_empty());
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert!(stderr.contains(message));
            assert!(!stderr.contains("unknown-private-sentinel"));
        }
    }

    #[test]
    fn native_composition_retains_redaction_ignores_baselines_and_source_exclusions() {
        let fixture = Fixture::new();
        let value = secret();
        let redacted = stdin(
            &fixture,
            value.as_bytes(),
            &["--redact", "--exit-code", "0"],
        );
        assert_eq!(redacted.status.code(), Some(0));
        assert!(!String::from_utf8_lossy(&redacted.stdout).contains(&value));
        assert!(String::from_utf8_lossy(&redacted.stdout).contains("REDACTED"));
        fixture.write(".rustleaksignore", ":rustleaks.groq-api-key:1\n");
        let ignored = stdin(&fixture, value.as_bytes(), &[]);
        assert_eq!(ignored.status.code(), Some(0));
        assert_eq!(ignored.stdout, b"[]\n");
        fs::remove_file(fixture.0.join(".rustleaksignore")).unwrap();
        let marked = stdin(
            &fixture,
            format!("{value} # rustleaks:allow").as_bytes(),
            &[],
        );
        assert_eq!(marked.status.code(), Some(0));
        fixture.write("secret.txt", &value);
        fixture.write("node_modules/ignored.txt", &value);
        let first = output(&fixture.0, &args(&["dir", "."]));
        assert_eq!(first.status.code(), Some(1));
        let report = rustleaks_core::session::Baseline::from_go_json(&first.stdout).unwrap();
        assert!(!report.was_null());
        let rows = report.entries();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].file().as_bytes(), b"secret.txt");
        fixture.write("baseline.json", &first.stdout);
        let second = output(
            &fixture.0,
            &args(&["dir", ".", "--baseline-path", "baseline.json"]),
        );
        assert_eq!(second.status.code(), Some(0));
        assert_eq!(second.stdout, b"[]\n");
    }

    #[test]
    fn ordinary_cli_config_rejects_native_tables_instead_of_discarding_them() {
        let fixture = Fixture::new();
        let source = "[[rules]]\nid='rustleaks.entropy'\nregex='ent=([^ ]+)'\nentropy={algorithm='byte-shannon-f64-v1',reject='lt',threshold=3.5}\n";
        fixture.write("native.toml", source);
        fixture.write(
            "combined.toml",
            format!("[extend]\nuseDefault=true\n{source}"),
        );
        fixture.write("extended.toml", "[extend]\npath='native.toml'\n");
        for path in ["native.toml", "combined.toml", "extended.toml"] {
            let result = output(
                &fixture.0,
                &[
                    "stdin",
                    "--config",
                    path,
                    "--no-banner",
                    "--report-path",
                    "-",
                ],
            );
            assert_eq!(result.status.code(), Some(1));
            assert!(result.stdout.is_empty());
            assert!(String::from_utf8_lossy(&result.stderr).contains("could not compile config"));
        }
        let inline = command(&fixture.0)
            .env("RUSTLEAKS_CONFIG_TOML", source)
            .args(["stdin", "--no-banner", "--report-path", "-"])
            .output()
            .unwrap();
        assert_eq!(inline.status.code(), Some(1));
        assert!(inline.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&inline.stderr);
        assert!(stderr.contains("decode error"));
        assert!(!stderr.contains("byte-shannon-f64-v1"));
    }
}

mod git_metadata {
    use super::*;

    /// A synthetic Bitbucket credential URL. No real account uses it.
    const CREDENTIAL_URL: &str =
        "https://synthetic7:Q4w8E2r6T1y9U3i5O7p0AsDf@bitbucket.org/workspace/repository.git";

    /// A checkout whose `.git` folder holds the credential URL in `config`
    /// and the same text in an object file, the index and a lock file.
    fn checkout() -> Fixture {
        let fixture = Fixture::new();
        fixture.write("repo/README.md", "no secrets here\n");
        let config = format!("[remote \"origin\"]\n\turl = {CREDENTIAL_URL}\n");
        fixture.write("repo/.git/config", &config);
        fixture.write("repo/.git/config.lock", &config);
        fixture.write("repo/.git/index", &config);
        fixture.write("repo/.git/objects/ab/cdef0123456789", &config);
        fixture.write("repo/.git/HEAD", "ref: refs/heads/main\n");
        fixture
    }

    fn scan(fixture: &Fixture, extra: &[&str]) -> Output {
        command(&fixture.0)
            .args([
                "dir",
                "repo",
                "--native-pack",
                "rustleaks-connections-v1",
                "--no-banner",
                "--log-level",
                "fatal",
                "--report-path",
                "-",
                "--report-format",
                "json",
            ])
            .args(extra)
            .output()
            .unwrap()
    }

    #[test]
    fn git_folders_are_skipped_without_the_flag() {
        let fixture = checkout();
        for extra in [&[][..], &["--scan-git-metadata=false"][..]] {
            let result = scan(&fixture, extra);
            assert_eq!(
                result.status.code(),
                Some(0),
                "{extra:?}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(report_rows(&result).is_empty(), "{extra:?}");
        }
    }

    #[test]
    fn the_flag_reports_a_credential_url_in_git_config_only() {
        let fixture = checkout();
        let result = scan(&fixture, &["--scan-git-metadata"]);
        assert_eq!(
            result.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            report_rows(&result),
            [(
                "rustleaks.bitbucket-git-credentials".to_owned(),
                "repo/.git/config".to_owned(),
                2,
                CREDENTIAL_URL.to_owned(),
                String::new(),
            )]
        );
    }

    #[test]
    fn the_flag_works_with_a_complete_profile() {
        let fixture = checkout();
        fixture.write(
            "scan.limits",
            "version=1\ntarget_bytes=65536\noperation_original_bytes=1048576\noperation_fragments=100\noperation_issues=10\nworkers=1\nqueue_capacity=1\nfragment_decoded_bytes=1048576\noperation_decoded_bytes=1048576\nfragment_work_units=1000000\noperation_work_units=1000000\nfragment_finding_records=100\noperation_finding_records=100\nfragment_finding_payload_bytes=1048576\noperation_finding_payload_bytes=1048576\nfragment_collected_spans=1000\noperation_collected_spans=1000\nfragment_normalization_bytes=1048576\noperation_normalization_bytes=1048576\narchive_entries=100\narchive_member_bytes=65536\narchive_total_bytes=1048576\narchive_spool_bytes=65536\ngit_patch_bytes=1048576\ngit_patch_lines=10000\ngit_stderr_bytes=65536\ngit_blob_bytes=65536\ngit_metadata_bytes=65536\ngit_path_bytes=4096\ngit_files=100\ngit_hunks=100\nscm_link_bytes=4096\noperation_scm_link_bytes=8192\n",
        );
        let result = scan(
            &fixture,
            &["--scan-git-metadata", "--complete-profile", "scan.limits"],
        );
        assert_eq!(
            result.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.lines().any(|line| {
                line.starts_with("rustleaks_scan_status ") && line.contains("status=complete")
            }),
            "{stderr}"
        );
        let rows = report_rows(&result);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, "repo/.git/config");
    }

    #[test]
    fn the_flag_respects_the_size_limit() {
        let fixture = checkout();
        let mut large = format!("[remote \"origin\"]\n\turl = {CREDENTIAL_URL}\n");
        large.push_str(&"#\n".repeat(600_000));
        fixture.write("repo/.git/config", &large);
        let result = scan(
            &fixture,
            &[
                "--scan-git-metadata",
                "--max-target-megabytes",
                "1",
                "--log-level",
                "warn",
            ],
        );
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert_eq!(result.status.code(), Some(0), "{stderr}");
        assert!(report_rows(&result).is_empty());
        // The file was reached and then skipped by the size limit.
        let skipped = stderr
            .lines()
            .filter(|line| line.contains("exceeds maximum file size"))
            .collect::<Vec<_>>();
        assert_eq!(skipped.len(), 1, "{stderr}");
        // Windows reports the path with backslashes.
        assert!(
            skipped[0].replace('\\', "/").contains("repo/.git/config"),
            "{stderr}"
        );
    }

    #[test]
    fn a_git_folder_given_as_the_scan_path_is_scanned_in_full() {
        let fixture = checkout();
        let scan_root = |extra: &[&str]| {
            command(&fixture.0)
                .args([
                    "dir",
                    "repo/.git",
                    "--native-pack",
                    "rustleaks-connections-v1",
                    "--no-banner",
                    "--log-level",
                    "fatal",
                    "--report-path",
                    "-",
                    "--report-format",
                    "json",
                ])
                .args(extra)
                .output()
                .unwrap()
        };
        // The scan path itself is not matched by the default `.git` folder
        // entry, so the folder is scanned in full either way. The pack rule's
        // path condition keeps the finding to `config`.
        let expected = [(
            "rustleaks.bitbucket-git-credentials".to_owned(),
            "repo/.git/config".to_owned(),
            2,
            CREDENTIAL_URL.to_owned(),
            String::new(),
        )];
        for result in [scan_root(&[]), scan_root(&["--scan-git-metadata"])] {
            assert_eq!(
                result.status.code(),
                Some(1),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(report_rows(&result), expected);
        }
    }

    #[test]
    fn the_flag_belongs_to_the_dir_command_only() {
        let fixture = Fixture::new();
        for command_name in ["git", "stdin"] {
            let result = output(&fixture.0, &[command_name, "--scan-git-metadata"]);
            assert_eq!(result.status.code(), Some(126), "{command_name}");
        }
    }
}

/// The number of detection threads must not change findings, reports, exit
/// codes or log lines. Each scan below runs with every thread count and report
/// format, and the outputs are compared byte for byte. The expected findings
/// come from the planted inputs, not from scanner output.
mod jobs {
    use super::complete_profile::{stored_gzip, stored_zip, tar_named_leaf};
    use super::*;

    /// One thread, a few, more than the 64 that a profile allows, and no flag,
    /// which uses one thread for each CPU.
    const JOBS: &[Option<&str>] = &[Some("1"), Some("2"), Some("4"), Some("128"), None];
    const FORMATS: &[&str] = &["json", "csv", "sarif", "junit", "template"];
    const CONFIG: &str = "title='jobs'\n[[rules]]\nid='jobs-token'\ndescription='jobs token'\nregex='''token=([A-Z0-9]{8})'''\nsecretGroup=1\nkeywords=['token']\n[[rules]]\nid='jobs-key'\ndescription='jobs key'\nregex='''key-[a-f0-9]{12}'''\nkeywords=['key-']\n";
    const TEMPLATE: &str = "{{ range . }}{{ .RuleID }} {{ .File }} {{ .StartLine }} {{ .Secret }} {{ .Fingerprint }}\n{{ end }}";
    const FILLER: &str = "filler text with no secret value in it, only padding for size";
    const PROFILE: &str = "version=1\ntarget_bytes=1048576\noperation_original_bytes=67108864\noperation_fragments=100000\noperation_issues=100\nworkers=1\nqueue_capacity=4\nfragment_decoded_bytes=16777216\noperation_decoded_bytes=268435456\nfragment_work_units=100000000\noperation_work_units=1000000000\nfragment_finding_records=10000\noperation_finding_records=100000\nfragment_finding_payload_bytes=16777216\noperation_finding_payload_bytes=268435456\nfragment_collected_spans=100000\noperation_collected_spans=1000000\nfragment_normalization_bytes=67108864\noperation_normalization_bytes=1073741824\narchive_entries=1000\narchive_member_bytes=1048576\narchive_total_bytes=16777216\narchive_spool_bytes=16777216\ngit_patch_bytes=16777216\ngit_patch_lines=1000000\ngit_stderr_bytes=65536\ngit_blob_bytes=1048576\ngit_metadata_bytes=65536\ngit_path_bytes=4096\ngit_files=1000\ngit_hunks=10000\nscm_link_bytes=4096\noperation_scm_link_bytes=65536\n";

    type Row = (String, String, i128, String, String);

    fn token(file: &str, line: usize, secret: &str, commit: &str) -> Row {
        (
            "jobs-token".to_owned(),
            file.to_owned(),
            i128::try_from(line).unwrap(),
            secret.to_owned(),
            commit.to_owned(),
        )
    }

    fn fixture() -> Fixture {
        let fixture = Fixture::new();
        fixture.write("config.toml", CONFIG);
        fixture.write("report.tmpl", TEMPLATE);
        fixture
    }

    /// A TAR archive with these members, in order.
    fn tar(members: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut archive = Vec::new();
        for (name, body) in members {
            let member = tar_named_leaf(name, body);
            archive.extend_from_slice(&member[..member.len() - 1024]);
        }
        archive.resize(archive.len() + 1024, 0);
        archive
    }

    /// Text of `lines` filler lines with a token line at each planted
    /// one-based line number.
    fn planted(lines: usize, plants: &[(usize, String)]) -> String {
        let mut text = String::new();
        for line in 1..=lines {
            match plants.iter().find(|(planted, _)| *planted == line) {
                Some((_, secret)) => {
                    let _ = writeln!(text, "value token={secret} end");
                }
                None => {
                    let _ = writeln!(text, "{FILLER} {line}");
                }
            }
        }
        text
    }

    /// Log lines without the elapsed time, the only part that changes between
    /// two identical scans.
    fn stable_log(stderr: &[u8]) -> String {
        String::from_utf8(stderr.to_vec())
            .unwrap()
            .lines()
            .map(|line| {
                if line.starts_with("info scanned ~")
                    || line.starts_with("warn partial scan completed in ")
                {
                    line.rsplit_once(" in ").map_or(line, |(head, _)| head)
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn scan(fixture: &Fixture, arguments: &[&str], stdin: Option<&[u8]>) -> Output {
        let mut child = command(&fixture.0)
            .args(arguments)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(bytes) = stdin {
            let mut input = child.stdin.take().unwrap();
            // A failed write shows up in the exit status check.
            let _ = input.write_all(bytes);
        }
        child.wait_with_output().unwrap()
    }

    /// Runs the scan with every thread count and report format, checks that
    /// each format gives the same report, exit status and log lines for every
    /// count, and returns the JSON report rows and the log lines.
    fn same_for_every_count(
        fixture: &Fixture,
        scan_arguments: &[&str],
        stdin: Option<&[u8]>,
        exit: i32,
    ) -> (Vec<Row>, String) {
        let mut rows = Vec::new();
        let mut log = String::new();
        for &format in FORMATS {
            let mut first: Option<(Vec<u8>, String)> = None;
            for &jobs in JOBS {
                let mut arguments = scan_arguments.to_vec();
                arguments.extend([
                    "--no-banner",
                    "--config",
                    "config.toml",
                    "--exit-code",
                    "7",
                    "--report-path",
                    "-",
                    "--report-format",
                    format,
                ]);
                if format == "template" {
                    arguments.extend(["--report-template", "report.tmpl"]);
                }
                if let Some(jobs) = jobs {
                    arguments.extend(["--jobs", jobs]);
                }
                let result = scan(fixture, &arguments, stdin);
                let stderr = stable_log(&result.stderr);
                assert_eq!(result.status.code(), Some(exit), "{arguments:?}: {stderr}");
                assert!(!result.stdout.is_empty(), "{arguments:?}");
                match &first {
                    None => first = Some((result.stdout, stderr)),
                    Some((report, first_log)) => {
                        assert!(
                            *report == result.stdout,
                            "{format} report differs with --jobs {jobs:?}"
                        );
                        assert_eq!(*first_log, stderr, "{format} log with --jobs {jobs:?}");
                    }
                }
            }
            let (report, first_log) = first.unwrap();
            if format == "json" {
                rows = json_report_rows(&report);
                log = first_log;
            } else {
                assert_eq!(log, first_log, "{format} log differs from the JSON run");
            }
        }
        (rows, log)
    }

    fn sorted(mut rows: Vec<Row>) -> Vec<Row> {
        rows.sort();
        rows
    }

    /// Plants 300 files in six folders. Every tenth file is about 280 KB, so it
    /// is scanned in three pieces. Returns the expected findings.
    fn plant_folders(fixture: &Fixture) -> Vec<Row> {
        let mut expected = Vec::new();
        for folder in 0..6 {
            for file in 0..50 {
                let number = folder * 50 + file;
                let path = format!("input/d{folder}/f{file:03}.txt");
                let (lines, positions) = if number % 10 == 3 {
                    (4_200, vec![5, 1_700, 3_300, 4_200])
                } else {
                    (number % 7 * 40 + 1, vec![number % 7 * 40 + 1])
                };
                let plants = positions
                    .iter()
                    .enumerate()
                    .map(|(index, line)| (*line, format!("{:08}", number * 10 + index)))
                    .collect::<Vec<_>>();
                let mut text = planted(lines, &plants);
                for (line, secret) in &plants {
                    expected.push(token(&path, *line, secret, ""));
                }
                if number % 7 == 2 {
                    let key = format!("key-{:012x}", 0xa0_0000 + number);
                    let _ = writeln!(text, "second rule {key}");
                    expected.push((
                        "jobs-key".to_owned(),
                        path.clone(),
                        i128::try_from(lines + 1).unwrap(),
                        key,
                        String::new(),
                    ));
                }
                fixture.write(&path, text);
            }
        }
        expected
    }

    #[test]
    fn directory_findings_reports_and_warnings_do_not_depend_on_jobs() {
        let fixture = fixture();
        let mut expected = plant_folders(&fixture);

        // An ignore entry and an allow comment each remove one finding.
        let ignored = token("input/d2/f010.txt", 201, "00001100", "");
        assert!(expected.contains(&ignored));
        expected.retain(|row| *row != ignored);
        fixture.write(".gitleaksignore", "input/d2/f010.txt:jobs-token:201\n");
        fixture.write("input/allow.txt", "token=ALLOW123 gitleaks:allow\n");

        // "dG9rZW49QjY0U0VDUlQ=" is the Base64 form of "token=B64SECRT".
        fixture.write("input/encoded.txt", "first line\ndG9rZW49QjY0U0VDUlQ=\n");
        expected.push(token("input/encoded.txt", 2, "B64SECRT", ""));

        fixture.write(
            "input/bundle.tar",
            tar(&[
                (b"a.txt", b"token=TAR00001\n"),
                (b"sub/b.txt", b"x\nx\ntoken=TAR00002\n"),
            ]),
        );
        expected.push(token("input/bundle.tar!a.txt", 1, "TAR00001", ""));
        expected.push(token("input/bundle.tar!sub/b.txt", 3, "TAR00002", ""));
        fixture.write(
            "input/bundle.zip",
            stored_zip(&[(b"c.txt", b"token=ZIP00001\n")]),
        );
        expected.push(token("input/bundle.zip!c.txt", 1, "ZIP00001", ""));
        // Without a profile, `.tgz` is not an archive name, as in Gitleaks.
        fixture.write(
            "input/bundle.tar.gz",
            stored_gzip(&tar(&[(b"e.txt", b"token=TGZ00001\n")])),
        );
        expected.push(token("input/bundle.tar.gz!e.txt", 1, "TGZ00001", ""));
        fixture.write(
            "input/nested.tar",
            tar(&[(
                b"inner.zip",
                &stored_zip(&[(b"d.txt", b"x\ntoken=NEST0001\n")]),
            )]),
        );
        expected.push(token("input/nested.tar!inner.zip!d.txt", 2, "NEST0001", ""));

        // Each gives a warning: an archive deeper than the depth limit and a
        // damaged gzip header.
        let deepest = tar(&[(b"f.txt", b"token=DEEP0001\n")]);
        let deeper = tar(&[(b"deepest.tar", &deepest)]);
        fixture.write("input/deep.tar", tar(&[(b"deeper.tar", &deeper)]));
        fixture.write("input/broken.tar.gz", b"\x1f\x8bbad");

        #[cfg(unix)]
        {
            fixture.write("outside/target.txt", "token=LINK0001\n");
            std::os::unix::fs::symlink("../outside/target.txt", fixture.0.join("input/link.txt"))
                .unwrap();
        }

        let (rows, log) = same_for_every_count(
            &fixture,
            &[
                "dir",
                "input",
                "--max-archive-depth",
                "2",
                "--follow-symlinks",
            ],
            None,
            7,
        );
        let mut rows = sorted(rows);
        #[cfg(unix)]
        {
            let link = rows
                .iter()
                .position(|row| row.3 == "LINK0001")
                .expect("the linked file is scanned");
            let link = rows.remove(link);
            assert_eq!((link.0.as_str(), link.2), ("jobs-token", 1));
            assert!(link.1.ends_with("outside/target.txt"), "{}", link.1);
        }
        assert_eq!(rows, sorted(expected));
        assert!(log.contains("exceeds maximum archive depth"), "{log}");
        assert!(log.contains(" input/broken.tar.gz"), "{log}");
        assert!(
            log.lines()
                .filter(|line| line.starts_with("warn source ") || line.starts_with("error source "))
                .count()
                >= 2,
            "{log}"
        );
    }

    #[test]
    fn complete_profile_scans_do_not_depend_on_jobs() {
        let fixture = fixture();
        let expected = plant_folders(&fixture)
            .into_iter()
            .filter(|row| row.1.starts_with("input/d1/"))
            .collect::<Vec<_>>();
        fixture.write("scan.limits", PROFILE);
        let (rows, log) = same_for_every_count(
            &fixture,
            &["dir", "input/d1", "--complete-profile", "scan.limits"],
            None,
            7,
        );
        assert_eq!(sorted(rows), sorted(expected.clone()));
        let status = log
            .lines()
            .find(|line| line.starts_with("rustleaks_scan_status "))
            .unwrap();
        assert!(
            status.contains(&format!(
                " status=complete reason=complete source_scope=directory_targets findings={} ",
                expected.len()
            )),
            "{status}"
        );
    }

    #[test]
    fn stdin_findings_and_reports_do_not_depend_on_jobs() {
        let fixture = fixture();
        // About 640 KB, so standard input is scanned in several pieces.
        let plants = (0..40)
            .map(|index| (index * 250 + 7, format!("STD{index:05}")))
            .collect::<Vec<_>>();
        let input = planted(10_000, &plants);
        let (rows, _) = same_for_every_count(&fixture, &["stdin"], Some(input.as_bytes()), 7);
        let found = sorted(rows)
            .into_iter()
            .map(|(rule, _, line, secret, commit)| (rule, line, secret, commit))
            .collect::<Vec<_>>();
        let mut expected = plants
            .iter()
            .map(|(line, secret)| {
                (
                    "jobs-token".to_owned(),
                    i128::try_from(*line).unwrap(),
                    secret.clone(),
                    String::new(),
                )
            })
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(found, expected);
    }

    #[test]
    fn git_history_findings_and_reports_do_not_depend_on_jobs() {
        let fixture = fixture();
        let repository = fixture.0.join("repo");
        fs::create_dir_all(repository.join("src")).unwrap();
        git(&repository, &["init", "--quiet"]);
        git(&repository, &["config", "user.name", "Jobs Test"]);
        // This history has enough loose objects for automatic maintenance to
        // repack them in the background while a scan reads them.
        git(&repository, &["config", "gc.auto", "0"]);
        git(&repository, &["config", "maintenance.auto", "false"]);
        git(
            &repository,
            &["config", "user.email", "jobs@example.invalid"],
        );
        let mut contents = vec![String::new(); 5];
        let mut expected = Vec::new();
        for commit in 0..24_usize {
            // Every fourth commit also edits the first line of m0.txt, so
            // that commit has a hunk without a token in another place.
            if commit % 4 == 3 {
                let rest = contents[0]
                    .split_once('\n')
                    .map_or("", |(_, rest)| rest)
                    .to_owned();
                contents[0] = format!("edited line {commit}\n{rest}");
            }
            let mut added = Vec::new();
            for change in 0..3_usize {
                let index = (commit + change) % 5;
                for filler in 0..=(commit * (change + 1)) % 9 {
                    let _ = writeln!(contents[index], "plain {commit} {change} {filler}");
                }
                let secret = format!("G{commit:03}{change:04}");
                let _ = writeln!(contents[index], "value token={secret} end");
                let line = contents[index].lines().count();
                added.push((format!("src/m{index}.txt"), line, secret));
            }
            for (index, text) in contents.iter().enumerate() {
                fs::write(repository.join(format!("src/m{index}.txt")), text).unwrap();
            }
            git(&repository, &["add", "src"]);
            git(
                &repository,
                &["commit", "--quiet", "-m", &format!("change {commit}")],
            );
            let sha = git_stdout(&repository, &["rev-parse", "HEAD"]);
            for (file, line, secret) in added {
                expected.push(token(&file, line, &secret, &sha));
            }
        }
        fs::create_dir(repository.join("pkg")).unwrap();
        fs::write(
            repository.join("pkg/bundle.tar"),
            tar(&[(b"a.txt", b"token=GITTAR01\n")]),
        )
        .unwrap();
        git(&repository, &["add", "pkg"]);
        git(&repository, &["commit", "--quiet", "-m", "archive"]);
        let sha = git_stdout(&repository, &["rev-parse", "HEAD"]);
        expected.push(token("pkg/bundle.tar!a.txt", 1, "GITTAR01", &sha));

        let (rows, log) = same_for_every_count(
            &fixture,
            &[
                "git",
                "repo",
                "--platform",
                "none",
                "--max-archive-depth",
                "1",
            ],
            None,
            7,
        );
        assert_eq!(sorted(rows), sorted(expected));
        assert!(log.contains("25 commits scanned."), "{log}");
    }

    #[test]
    fn jobs_overrides_the_profile_which_overrides_the_cpu_count() {
        let fixture = fixture();
        fixture.write("input/a.txt", "token=PREC0001\n");
        fixture.write("scan.limits", PROFILE.replace("workers=1\n", "workers=2\n"));
        let cpus = std::thread::available_parallelism().map_or(1, |cpus| cpus.get().min(12));
        for (extra, threads) in [
            (&[][..], cpus),
            (&["--jobs", "3"][..], 3),
            (&["-j", "200"][..], 200),
            (&["--complete-profile", "scan.limits"][..], 2),
            (&["--complete-profile", "scan.limits", "--jobs", "5"][..], 5),
            (&["--jobs", "6", "--complete-profile", "scan.limits"][..], 6),
        ] {
            let mut arguments = vec![
                "dir",
                "input",
                "--no-banner",
                "--config",
                "config.toml",
                "--log-level",
                "debug",
            ];
            arguments.extend(extra);
            let result = output(&fixture.0, &arguments);
            let stderr = String::from_utf8(result.stderr).unwrap();
            assert_eq!(result.status.code(), Some(1), "{extra:?}: {stderr}");
            let lines = stderr
                .lines()
                .filter(|line| line.starts_with("info detection threads: "))
                .collect::<Vec<_>>();
            assert_eq!(
                lines,
                [format!("info detection threads: {threads}")],
                "{extra:?}"
            );
        }
        for value in ["0", "-2", "two"] {
            let result = output(&fixture.0, &["dir", "input", "--jobs", value]);
            assert_eq!(result.status.code(), Some(1), "{value}");
            assert!(result.stdout.is_empty());
            let stderr = String::from_utf8(result.stderr).unwrap();
            assert!(
                stderr.starts_with(&format!(
                    "Error: the --jobs argument {value:?} is not a whole number from 1 to "
                )),
                "{stderr}"
            );
        }
    }
}
