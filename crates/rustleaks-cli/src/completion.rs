//! Shell completion scripts rendered from the command table.
//!
//! Each script is a fixed template. Only names, value lists and short
//! descriptions from `cli_spec` are inserted.

use std::fmt::Write as _;
use std::io::{self, Write};

use crate::cli_spec::{
    COMMANDS, Command, Flag, HELP_FLAG, LEGACY_FLAGS, Operand, SCAN_FLAGS, SHELLS, Shell,
    VERSION_FLAG, Value, accepted_flags, command_names, scan_flag,
};

/// Writes the completion script for one shell.
pub(crate) fn write(shell: Shell, writer: &mut dyn Write) -> io::Result<()> {
    let script = match shell {
        Shell::Bash => bash(),
        Shell::Zsh => zsh(),
        Shell::Fish => fish(),
        Shell::Powershell => powershell(),
    };
    writer.write_all(script.as_bytes())
}

/// One flag spelling with the flag that defines its value.
#[derive(Clone, Debug)]
struct Spelling {
    /// The spelling with its dashes, such as `-c` or `--config`.
    dashed: String,
    /// The long name without dashes, or `None` for a short name.
    long: Option<&'static str>,
    flag: &'static Flag,
}

impl Spelling {
    /// Returns true for the current long name of the flag.
    fn is_primary_long(&self) -> bool {
        self.long == Some(self.flag.long)
    }

    /// Returns the short description for this spelling.
    fn brief(&self) -> String {
        match self.long {
            Some(long) if long != self.flag.long => format!("Same as --{}", self.flag.long),
            _ => self.flag.brief().to_owned(),
        }
    }
}

/// Every long and short spelling that a command accepts, legacy names
/// included. `None` is the root, before any command.
fn spellings(command: Option<&Command>) -> Vec<Spelling> {
    let flags: Vec<&'static Flag> = match command {
        Some(command) => accepted_flags(command).collect(),
        None => [&HELP_FLAG, &VERSION_FLAG]
            .into_iter()
            .chain(SCAN_FLAGS)
            .collect(),
    };
    let mut result = Vec::new();
    for flag in flags {
        result.push(Spelling {
            dashed: format!("--{}", flag.long),
            long: Some(flag.long),
            flag,
        });
        if let Some(short) = flag.short {
            result.push(Spelling {
                dashed: format!("-{short}"),
                long: None,
                flag,
            });
        }
    }
    if command.is_none_or(|command| command.scan) {
        for legacy in LEGACY_FLAGS {
            if let Some(flag) = scan_flag(legacy.current) {
                result.push(Spelling {
                    dashed: format!("--{}", legacy.long),
                    long: Some(legacy.long),
                    flag,
                });
            }
        }
    }
    result
}

/// Every spelling that any command accepts.
fn all_spellings() -> Vec<Spelling> {
    let mut result = spellings(None);
    for command in COMMANDS {
        for spelling in spellings(Some(command)) {
            if !result.iter().any(|known| known.dashed == spelling.dashed) {
                result.push(spelling);
            }
        }
    }
    result
}

fn dashed_names(spellings: &[Spelling]) -> Vec<&str> {
    spellings
        .iter()
        .map(|spelling| spelling.dashed.as_str())
        .collect()
}

fn command_patterns(command: &Command) -> String {
    std::iter::once(command.name)
        .chain(command.aliases.iter().copied())
        .collect::<Vec<_>>()
        .join("|")
}

/// Flag spellings grouped by how bash completes their values.
#[derive(Default)]
struct BashFlags {
    /// Spellings whose value may be the next word.
    value: Vec<String>,
    /// Spellings whose value is a file name.
    path: Vec<String>,
    /// Spellings whose value is free text.
    free: Vec<String>,
    /// `case` arms that list the values of each choice spelling.
    choice_cases: String,
}

impl BashFlags {
    fn new(all: &[Spelling]) -> Self {
        let mut flags = Self::default();
        for spelling in all {
            let name = spelling.dashed.clone();
            match spelling.flag.value {
                Value::Path(_) => flags.path.push(name.clone()),
                Value::Text(_) => flags.free.push(name.clone()),
                Value::Choice(_, values) => {
                    let _ = writeln!(
                        flags.choice_cases,
                        "        {name}) words=\"{}\" ;;",
                        values.join(" ")
                    );
                }
                Value::Switch | Value::Optional(_) => {}
            }
            if spelling.flag.value.takes_separate_value() {
                flags.value.push(name);
            }
        }
        flags
    }
}

/// `case` arms that list the flags each command accepts.
fn bash_flag_cases() -> String {
    let mut flag_cases = String::new();
    for command in COMMANDS {
        let _ = writeln!(
            flag_cases,
            "        {}) flags=\"{}\" ;;",
            command_patterns(command),
            dashed_names(&spellings(Some(command))).join(" ")
        );
    }
    let _ = writeln!(
        flag_cases,
        "        *) flags=\"{}\" ;;",
        dashed_names(&spellings(None)).join(" ")
    );
    flag_cases
}

/// `case` arms that complete the operand of each command.
fn bash_operand_cases() -> String {
    let mut operand_cases = String::new();
    for command in COMMANDS {
        let action = match command.operand {
            Operand::None => "return 0".to_owned(),
            Operand::Directory => "_rustleaks_files -d".to_owned(),
            Operand::Path => "_rustleaks_files -f".to_owned(),
            Operand::Command => format!(
                "COMPREPLY=($(compgen -W \"{}\" -- \"$cur\"))",
                command_names().collect::<Vec<_>>().join(" ")
            ),
            Operand::Shell => format!(
                "COMPREPLY=($(compgen -W \"{}\" -- \"$cur\"))",
                SHELLS.join(" ")
            ),
        };
        let _ = writeln!(
            operand_cases,
            "        {}) {action} ;;",
            command_patterns(command)
        );
    }
    operand_cases
}

/// The bash script header and the helper that completes file names.
const BASH_PRELUDE: &str = r#"# Bash completion for rustleaks.
# Generated by 'rustleaks completion bash'.

_rustleaks_files() {
    local IFS=$'\n'
    if type compopt >/dev/null 2>&1; then
        compopt -o filenames 2>/dev/null
    fi
    COMPREPLY=($(compgen "$1" -- "$cur"))
}

"#;

fn bash() -> String {
    let flags = BashFlags::new(&all_spellings());
    let choice_cases = flags.choice_cases;
    let flag_cases = bash_flag_cases();
    let operand_cases = bash_operand_cases();
    let commands = command_names().collect::<Vec<_>>();
    format!(
        r#"{BASH_PRELUDE}_rustleaks() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}"
    local prev=""
    local before=""
    if [[ $COMP_CWORD -gt 0 ]]; then
        prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    fi
    if [[ $COMP_CWORD -gt 1 ]]; then
        before="${{COMP_WORDS[COMP_CWORD-2]}}"
    fi
    COMPREPLY=()

    local command="" operands=0 word i
    for ((i = 1; i < COMP_CWORD; i++)); do
        word="${{COMP_WORDS[i]}}"
        case "$word" in
        {value_patterns})
            if [[ "${{COMP_WORDS[i+1]}}" == "=" ]]; then
                ((i += 2))
            else
                ((i++))
            fi
            ;;
        =)
            ((i++))
            ;;
        -*)
            ;;
        *)
            if [[ -z "$command" ]]; then
                command="$word"
            else
                operands=$((operands + 1))
            fi
            ;;
        esac
    done

    local flag="" equals=""
    if [[ "$cur" == "=" ]]; then
        flag="$prev"
        cur=""
        equals="yes"
    elif [[ "$prev" == "=" ]]; then
        flag="$before"
        equals="yes"
    else
        flag="$prev"
    fi

    local words=""
    case "$flag" in
{choice_cases}        {path_patterns}) _rustleaks_files -f; return 0 ;;
        {free_patterns}) return 0 ;;
        --redact)
            if [[ -n "$equals" ]]; then
                return 0
            fi
            ;;
    esac
    if [[ -n "$words" ]]; then
        COMPREPLY=($(compgen -W "$words" -- "$cur"))
        return 0
    fi

    if [[ "$cur" == -* ]]; then
        local flags=""
        case "$command" in
{flag_cases}        esac
        COMPREPLY=($(compgen -W "$flags" -- "$cur"))
        return 0
    fi

    if [[ $operands -gt 0 ]]; then
        return 0
    fi
    case "$command" in
        "") COMPREPLY=($(compgen -W "{commands}" -- "$cur")) ;;
{operand_cases}    esac
    return 0
}}

complete -F _rustleaks rustleaks
"#,
        value_patterns = flags.value.join("|"),
        path_patterns = flags.path.join("|"),
        free_patterns = flags.free.join("|"),
        commands = commands.join(" "),
    )
}

/// Escapes text for a single-quoted zsh word.
fn zsh_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn zsh_action(value: Value) -> String {
    match value {
        Value::Switch => String::new(),
        Value::Optional(name) => format!("::{name}: "),
        Value::Path(name) => format!(":{name}:_files"),
        Value::Text(name) => format!(":{name}: "),
        Value::Choice(name, values) => format!(":{name}:({})", values.join(" ")),
    }
}

fn zsh_specs(spellings: &[Spelling]) -> Vec<String> {
    let mut result = Vec::new();
    for spelling in spellings {
        let flag = spelling.flag;
        let action = zsh_action(flag.value);
        let repeat = if flag.repeatable { "*" } else { "" };
        let exclusive = if flag.long == "help" || flag.long == "version" {
            "(- *)".to_owned()
        } else if flag.repeatable {
            String::new()
        } else {
            let mut names = vec![format!("--{}", flag.long)];
            if let Some(short) = flag.short {
                names.insert(0, format!("-{short}"));
            }
            for legacy in LEGACY_FLAGS
                .iter()
                .filter(|legacy| legacy.current == flag.long)
            {
                names.push(format!("--{}", legacy.long));
            }
            format!("({})", names.join(" "))
        };
        let name = match (spelling.long, flag.value) {
            (None, _) | (Some(_), Value::Switch) => spelling.dashed.clone(),
            (Some(_), Value::Optional(_)) => format!("{}=-", spelling.dashed),
            (Some(_), _) => format!("{}=", spelling.dashed),
        };
        let brief = spelling.brief();
        result.push(zsh_quote(&format!(
            "{exclusive}{repeat}{name}[{brief}]{action}"
        )));
    }
    result
}

fn zsh_array(name: &str, items: &[String]) -> String {
    let mut text = format!("  local -a {name}\n  {name}=(\n");
    for item in items {
        let _ = writeln!(text, "    {item}");
    }
    text.push_str("  )\n");
    text
}

fn zsh() -> String {
    let mut arrays = zsh_array("root_flags", &zsh_specs(&spellings(None)));
    let mut cases = String::new();
    for command in COMMANDS {
        let array = format!("{}_flags", command.name);
        arrays.push_str(&zsh_array(&array, &zsh_specs(&spellings(Some(command)))));
        let operand = match command.operand {
            Operand::None => String::new(),
            Operand::Directory => format!(" {}", zsh_quote("1:repository:_files -/")),
            Operand::Path => format!(" {}", zsh_quote("1:path:_files")),
            Operand::Command => format!(
                " {}",
                zsh_quote(&format!(
                    "1:command:({})",
                    command_names().collect::<Vec<_>>().join(" ")
                ))
            ),
            Operand::Shell => format!(" {}", zsh_quote(&format!("1:shell:({})", SHELLS.join(" ")))),
        };
        let _ = writeln!(
            cases,
            "        ({})\n          _arguments -S ${array}{operand} && ret=0\n          ;;",
            command_patterns(command)
        );
    }
    let mut descriptions = Vec::new();
    for command in COMMANDS {
        let summary = command.summary.strip_suffix('.').unwrap_or(command.summary);
        descriptions.push(zsh_quote(&format!("{}:{summary}", command.name)));
        for alias in command.aliases {
            descriptions.push(zsh_quote(&format!("{alias}:Same as {}", command.name)));
        }
    }
    let commands = zsh_array("commands", &descriptions);
    format!(
        r#"#compdef rustleaks
# Zsh completion for rustleaks.
# Generated by 'rustleaks completion zsh'.

_rustleaks() {{
  local curcontext="$curcontext" state line ret=1
  typeset -A opt_args
{arrays}
  _arguments -C -S $root_flags '1: :->command' '*:: :->arguments' && ret=0

  case $state in
    (command)
{commands}      _describe -t commands 'rustleaks command' commands && ret=0
      ;;
    (arguments)
      curcontext="${{curcontext%:*:*}}:rustleaks-$line[1]:"
      case $line[1] in
{cases}      esac
      ;;
  esac
  return ret
}}

if [[ "${{zsh_eval_context[-1]}}" == loadautofunc ]]; then
  _rustleaks "$@"
else
  compdef _rustleaks rustleaks
fi
"#,
        commands = indent(&commands, "    "),
    )
}

fn indent(text: &str, prefix: &str) -> String {
    text.lines().fold(String::new(), |mut output, line| {
        let _ = writeln!(output, "{prefix}{line}");
        output
    })
}

/// Escapes text for a single-quoted fish word.
fn fish_quote(text: &str) -> String {
    format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn fish() -> String {
    let all = all_spellings();
    let skip = all
        .iter()
        .filter(|spelling| spelling.flag.value.takes_separate_value())
        .map(|spelling| spelling.dashed.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let commands = command_names().collect::<Vec<_>>().join(" ");
    let lines = fish_completions(&commands);
    format!(
        r"# Fish completion for rustleaks.
# Generated by 'rustleaks completion fish'.

function __rustleaks_command
    set -l tokens (commandline -opc)
    set -e tokens[1]
    set -l skip 0
    for token in $tokens
        if test $skip -eq 1
            set skip 0
            continue
        end
        if contains -- $token {skip}
            set skip 1
        else if contains -- $token {commands}
            echo $token
            return 0
        end
    end
    return 1
end

function __rustleaks_no_command
    not __rustleaks_command >/dev/null
end

function __rustleaks_using
    set -l command (__rustleaks_command)
    or return 1
    contains -- $command $argv
end

function __rustleaks_operand_count
    set -l tokens (commandline -opc)
    set -e tokens[1]
    set -l skip 0
    set -l seen 0
    set -l count 0
    for token in $tokens
        if test $skip -eq 1
            set skip 0
            continue
        end
        if contains -- $token {skip}
            set skip 1
        else if string match -q -- '-*' $token
            continue
        else if test $seen -eq 0
            set seen 1
        else
            set count (math $count + 1)
        end
    end
    echo $count
end

function __rustleaks_needs_operand
    __rustleaks_using $argv
    or return 1
    test (__rustleaks_operand_count) -eq 0
end

complete -c rustleaks -f
{lines}"
    )
}

/// The `complete` lines for commands, their flags and their operands.
fn fish_completions(commands: &str) -> String {
    let mut lines = String::new();
    for command in COMMANDS {
        let summary = command.summary.strip_suffix('.').unwrap_or(command.summary);
        let _ = writeln!(
            lines,
            "complete -c rustleaks -n __rustleaks_no_command -a {} -d {}",
            command.name,
            fish_quote(summary)
        );
        for alias in command.aliases {
            let _ = writeln!(
                lines,
                "complete -c rustleaks -n __rustleaks_no_command -a {alias} -d {}",
                fish_quote(&format!("Same as {}", command.name))
            );
        }
    }
    lines.push('\n');
    write_fish_flags(&mut lines, "__rustleaks_no_command", &spellings(None));
    for command in COMMANDS {
        let names = std::iter::once(command.name)
            .chain(command.aliases.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        let condition = format!("'__rustleaks_using {names}'");
        let operand = format!("'__rustleaks_needs_operand {names}'");
        lines.push('\n');
        write_fish_flags(&mut lines, &condition, &spellings(Some(command)));
        match command.operand {
            Operand::None => {}
            Operand::Directory => {
                let _ = writeln!(
                    lines,
                    "complete -c rustleaks -n {operand} -a '(__fish_complete_directories)'"
                );
            }
            Operand::Path => {
                let _ = writeln!(lines, "complete -c rustleaks -n {operand} -F");
            }
            Operand::Command => {
                let _ = writeln!(
                    lines,
                    "complete -c rustleaks -n {operand} -a {}",
                    fish_quote(commands)
                );
            }
            Operand::Shell => {
                let _ = writeln!(
                    lines,
                    "complete -c rustleaks -n {operand} -a {}",
                    fish_quote(&SHELLS.join(" "))
                );
            }
        }
    }
    lines
}

fn write_fish_flags(lines: &mut String, condition: &str, spellings: &[Spelling]) {
    for spelling in spellings {
        let Some(long) = spelling.long else {
            continue;
        };
        let flag = spelling.flag;
        let mut line = format!("complete -c rustleaks -n {condition} -l {long}");
        if let Some(short) = flag.short.filter(|_| spelling.is_primary_long()) {
            let _ = write!(line, " -s {short}");
        }
        match flag.value {
            Value::Switch | Value::Optional(_) => {}
            Value::Path(_) => line.push_str(" -r -F"),
            Value::Text(_) => line.push_str(" -x"),
            Value::Choice(_, values) => {
                let _ = write!(line, " -x -a {}", fish_quote(&values.join(" ")));
            }
        }
        let _ = writeln!(line, " -d {}", fish_quote(&spelling.brief()));
        lines.push_str(&line);
    }
}

/// Escapes text for a single-quoted PowerShell string.
fn powershell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

fn powershell_list<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    let items = items
        .into_iter()
        .map(powershell_quote)
        .collect::<Vec<_>>()
        .join(", ");
    format!("@({items})")
}

/// Hashtable entries that list the values of each choice spelling.
fn powershell_choices(all: &[Spelling]) -> String {
    let mut choices = String::new();
    for spelling in all {
        if let Value::Choice(_, values) = spelling.flag.value {
            let _ = writeln!(
                choices,
                "        {} = {}",
                powershell_quote(&spelling.dashed),
                powershell_list(values.iter().copied())
            );
        }
    }
    choices
}

/// Hashtable entries that list the flags and the operand values of each
/// command name, in that order.
fn powershell_command_tables() -> (String, String) {
    let mut flags = String::new();
    let _ = writeln!(
        flags,
        "        '' = {}",
        powershell_list(dashed_names(&spellings(None)))
    );
    let mut operands = String::new();
    for command in COMMANDS {
        let spellings = spellings(Some(command));
        let list = dashed_names(&spellings);
        let operand = match command.operand {
            Operand::Command => powershell_list(command_names()),
            Operand::Shell => powershell_list(SHELLS.iter().copied()),
            Operand::None | Operand::Directory | Operand::Path => "@()".to_owned(),
        };
        for name in std::iter::once(command.name).chain(command.aliases.iter().copied()) {
            let _ = writeln!(
                flags,
                "        {} = {}",
                powershell_quote(name),
                powershell_list(list.iter().copied())
            );
            let _ = writeln!(operands, "        {} = {operand}", powershell_quote(name));
        }
    }
    (flags, operands)
}

fn powershell() -> String {
    let all = all_spellings();
    let value_flags = all
        .iter()
        .filter(|spelling| spelling.flag.value.takes_separate_value())
        .map(|spelling| spelling.dashed.as_str())
        .collect::<Vec<_>>();
    let choices = powershell_choices(&all);
    let (flags, operands) = powershell_command_tables();
    format!(
        r"# PowerShell completion for rustleaks.
# Generated by 'rustleaks completion powershell'.

Register-ArgumentCompleter -Native -CommandName 'rustleaks', 'rustleaks.exe' -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)

    $commands = {commands}
    $valueFlags = {value_flags}
    $choices = @{{
{choices}    }}
    $flags = @{{
{flags}    }}
    $operandValues = @{{
{operands}    }}

    $elements = @($commandAst.CommandElements |
        Select-Object -Skip 1 |
        Where-Object {{ $_.Extent.EndOffset -le $cursorPosition }} |
        ForEach-Object {{ $_.Extent.Text }})
    if ($wordToComplete -ne '' -and $elements.Count -gt 0) {{
        $elements = @($elements | Select-Object -First ($elements.Count - 1))
    }}

    $command = ''
    $operandCount = 0
    $skip = $false
    foreach ($element in $elements) {{
        if ($skip) {{
            $skip = $false
            continue
        }}
        if ($valueFlags -contains $element) {{
            $skip = $true
            continue
        }}
        if ($element.StartsWith('-')) {{
            continue
        }}
        if ($command -eq '' -and $commands -contains $element) {{
            $command = $element
        }} elseif ($command -ne '') {{
            $operandCount += 1
        }}
    }}

    $previous = ''
    if ($elements.Count -gt 0) {{
        $previous = $elements[$elements.Count - 1]
    }}

    $candidates = @()
    $prefix = ''
    $word = $wordToComplete
    $kind = 'ParameterValue'
    if ($word -match '^(--[a-z0-9-]+)=(.*)$') {{
        if ($choices.ContainsKey($Matches[1])) {{
            $prefix = $Matches[1] + '='
            $word = $Matches[2]
            $candidates = $choices[$Matches[1]]
        }}
    }} elseif ($choices.ContainsKey($previous)) {{
        $candidates = $choices[$previous]
    }} elseif ($valueFlags -contains $previous) {{
        return
    }} elseif ($word.StartsWith('-')) {{
        $candidates = $flags[$command]
        $kind = 'ParameterName'
    }} elseif ($command -eq '') {{
        $candidates = $commands
    }} elseif ($operandCount -eq 0) {{
        $candidates = $operandValues[$command]
    }}

    $candidates |
        Where-Object {{ $_.StartsWith($word) }} |
        ForEach-Object {{
            $text = $prefix + $_
            [System.Management.Automation.CompletionResult]::new($text, $text, $kind, $text)
        }}
}}
",
        commands = powershell_list(command_names()),
        value_flags = powershell_list(value_flags.iter().copied()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(shell: Shell) -> String {
        let mut output = Vec::new();
        write(shell, &mut output).unwrap();
        String::from_utf8(output).unwrap()
    }

    #[test]
    fn scripts_name_every_spelling_and_end_with_a_newline() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::Powershell] {
            let text = script(shell);
            assert!(text.ends_with('\n'));
            assert!(!text.contains('\r'));
            for spelling in all_spellings() {
                let name = match (shell, spelling.long) {
                    (Shell::Fish, Some(long)) => format!("-l {long}"),
                    (Shell::Fish, None) => format!("-s {}", &spelling.dashed[1..]),
                    _ => spelling.dashed.clone(),
                };
                assert!(text.contains(&name), "{shell:?} misses {name}");
            }
        }
    }

    #[test]
    fn redact_is_not_completed_as_a_separate_value_flag() {
        for spelling in all_spellings() {
            if spelling.long == Some("redact") {
                assert!(!spelling.flag.value.takes_separate_value());
            }
        }
    }
}
