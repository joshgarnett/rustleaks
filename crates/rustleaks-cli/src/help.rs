//! Help pages and parser usage blocks rendered from the command table.

use std::io::{self, Write};

use crate::cli_spec::{
    COMMANDS, Command, Flag, Group, HELP_FLAG, LEGACY_FLAGS, SCAN_FLAGS, Topic, VERSION_FLAG,
    Value, command, scan_flag,
};

const ROOT_INTRO: &str = "\
Rustleaks finds secrets in Git history, files, directories and standard
input. It also reads configuration, ignore and baseline files written for
Gitleaks.

Usage:
  rustleaks <command> [flags]
";

const CONFIGURATION_ORDER: &str = "\
Configuration order:
  Rustleaks uses the first configuration that it finds:
    1. --config or -c
    2. RUSTLEAKS_CONFIG, the path of a configuration file
    3. RUSTLEAKS_CONFIG_TOML, the configuration text
    4. GITLEAKS_CONFIG, then GITLEAKS_CONFIG_TOML (legacy names)
    5. .rustleaks.toml in the scanned folder
    6. .gitleaks.toml in the scanned folder (legacy name)
  For stdin, the scanned folder is the current folder.
  If it finds none, Rustleaks uses its built-in default configuration.
";

const EXIT_STATUS: &str = "\
Exit status:
  0    No leaks were found.
  1    Leaks were found, the scan stopped early, or an error occurred.
       Use --exit-code to change the status for leaks.
  2    The scan was not complete. Only with --complete-profile.
  126  An unknown long flag, such as --nope, was given.
";

const DESCRIPTION_INDENT: &str = "          ";

/// Writes root help. No arguments, `help`, `--help` and `-h` print it.
pub(crate) fn root(writer: &mut dyn Write) -> io::Result<()> {
    writer.write_all(ROOT_INTRO.as_bytes())?;
    writer.write_all(b"\nCommands:\n")?;
    let width = COMMANDS
        .iter()
        .map(|command| command.name.len())
        .max()
        .unwrap_or_default();
    for command in COMMANDS {
        write!(writer, "  {:<width$}  {}", command.name, command.summary)?;
        if !command.aliases.is_empty() {
            write!(writer, " Other names: {}.", command.aliases.join(", "))?;
        }
        writeln!(writer)?;
    }
    write_scan_flags(writer)?;
    writer.write_all(b"\nOther flags:\n")?;
    write_flag(writer, &HELP_FLAG)?;
    write_flag(writer, &VERSION_FLAG)?;
    write_legacy_flags(writer)?;
    writer.write_all(b"\n")?;
    writer.write_all(CONFIGURATION_ORDER.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.write_all(EXIT_STATUS.as_bytes())?;
    writer.write_all(b"\nRun 'rustleaks help <command>' for details.\n")
}

/// Writes the help page of one command. `rustleaks help <command>` and
/// `rustleaks <command> --help` print the same page.
pub(crate) fn command_page(topic: Topic, writer: &mut dyn Write) -> io::Result<()> {
    let command = command(topic);
    writeln!(writer, "{}\n", command.summary)?;
    write_usage(command, writer)?;
    if !command.details.is_empty() {
        writer.write_all(b"\n")?;
        for line in command.details {
            write_line(writer, line)?;
        }
    }
    if !command.examples.is_empty() {
        writer.write_all(b"\nExamples:\n")?;
        for example in command.examples {
            writeln!(writer, "  {example}")?;
        }
    }
    writeln!(writer, "\n{}", command.flags_heading)?;
    for flag in command.flags {
        write_flag(writer, flag)?;
    }
    write_flag(writer, &HELP_FLAG)?;
    if command.scan {
        write_scan_flags(writer)?;
        write_legacy_flags(writer)?;
        writer
            .write_all(b"\nRun 'rustleaks help' for the configuration order and exit status.\n")?;
    }
    Ok(())
}

/// Writes the usage block that follows a parser error line on stderr.
///
/// The block starts with the `Usage:` header line. Help is not repeated here.
pub(crate) fn usage_block(topic: Topic, writer: &mut dyn Write) -> io::Result<()> {
    let command = command(topic);
    write_usage(command, writer)?;
    writeln!(
        writer,
        "\nRun 'rustleaks help {}' for details.\n",
        command.name
    )
}

/// Writes the hint that follows an unknown command error.
pub(crate) fn root_hint(writer: &mut dyn Write) -> io::Result<()> {
    writeln!(writer, "Run 'rustleaks help' to list the commands.")
}

fn write_usage(command: &Command, writer: &mut dyn Write) -> io::Result<()> {
    writeln!(writer, "Usage:\n  {}", command.usage)
}

fn write_scan_flags(writer: &mut dyn Write) -> io::Result<()> {
    for group in Group::ALL {
        writeln!(writer, "\n{}", group.heading())?;
        for flag in SCAN_FLAGS.iter().filter(|flag| flag.group == group) {
            write_flag(writer, flag)?;
        }
    }
    Ok(())
}

fn write_legacy_flags(writer: &mut dyn Write) -> io::Result<()> {
    writeln!(writer, "\n{}", Group::Legacy.heading())?;
    writer.write_all(b"  These older names also work.\n")?;
    for legacy in LEGACY_FLAGS {
        let Some(current) = scan_flag(legacy.current) else {
            continue;
        };
        writeln!(
            writer,
            "      --{}{}\n{DESCRIPTION_INDENT}Same as --{}.",
            legacy.long,
            value_suffix(current.value),
            legacy.current
        )?;
    }
    for flag in SCAN_FLAGS.iter().filter(|flag| flag.group == Group::Legacy) {
        write_flag(writer, flag)?;
    }
    Ok(())
}

fn write_flag(writer: &mut dyn Write, flag: &Flag) -> io::Result<()> {
    match flag.short {
        Some(short) => write!(writer, "  -{short}, --{}", flag.long)?,
        None => write!(writer, "      --{}", flag.long)?,
    }
    writeln!(writer, "{}", value_suffix(flag.value))?;
    for line in flag.help {
        writeln!(writer, "{DESCRIPTION_INDENT}{line}")?;
    }
    Ok(())
}

fn value_suffix(value: Value) -> String {
    match value {
        Value::Switch => String::new(),
        Value::Optional(name) => format!("[=<{name}>]"),
        Value::Path(name) | Value::Text(name) | Value::Choice(name, _) => format!(" <{name}>"),
    }
}

fn write_line(writer: &mut dyn Write, line: &str) -> io::Result<()> {
    if line.is_empty() {
        writer.write_all(b"\n")
    } else {
        writeln!(writer, "{line}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(write: impl FnOnce(&mut Vec<u8>) -> io::Result<()>) -> String {
        let mut output = Vec::new();
        write(&mut output).unwrap();
        String::from_utf8(output).unwrap()
    }

    #[test]
    fn usage_block_starts_with_usage_and_has_no_log_prefixed_lines() {
        for topic in [
            Topic::Git,
            Topic::Directory,
            Topic::Stdin,
            Topic::Version,
            Topic::Help,
            Topic::Completion,
        ] {
            let block = text(|output| usage_block(topic, output));
            assert!(block.starts_with("Usage:\n  rustleaks "), "{block}");
            for line in block.lines().map(str::trim) {
                let lower = line.to_ascii_lowercase();
                for level in ["trace ", "debug ", "info ", "warn ", "error ", "fatal "] {
                    assert!(!lower.starts_with(level), "{line}");
                }
            }
        }
        assert_eq!(
            text(|output| usage_block(Topic::Stdin, output)),
            "Usage:\n  rustleaks stdin [flags]\n\nRun 'rustleaks help stdin' for details.\n\n"
        );
    }

    #[test]
    fn help_has_no_long_dashes_or_long_lines() {
        let mut pages = vec![text(|output| root(output))];
        for command in COMMANDS {
            pages.push(text(|output| command_page(command.topic, output)));
        }
        for page in pages {
            assert!(!page.contains(['\u{2013}', '\u{2014}']));
            for line in page.lines() {
                assert!(line.len() <= 90, "{line}");
                assert_eq!(line, line.trim_end());
            }
        }
    }
}
