use std::ffi::OsStr;
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustleaks_core::config::CompiledConfig;
use rustleaks_core::model::{ByteText, Finding};
use rustleaks_report::{
    CsvReporter, JsonReporter, JunitReporter, Reporter, SarifReporter, TemplateLimits,
    TemplateReporter,
};

use crate::args::{CommandKind, Options};

const GLOBAL_FLAGS_HEAD: &str = "  -b, --baseline-path string          path to baseline with issues that can be ignored
  -c, --config string                 config file path
                                      order of precedence:
                                      1. --config/-c
                                      2. env var RUSTLEAKS_CONFIG
                                      3. env var RUSTLEAKS_CONFIG_TOML with the file content
                                      4. legacy GITLEAKS_CONFIG or GITLEAKS_CONFIG_TOML
                                      5. (target path)/.rustleaks.toml
                                      6. legacy (target path)/.gitleaks.toml
                                      Otherwise Rustleaks uses the embedded default config
      --enable-rule strings           only enable specific rules by id
      --exit-code int                 exit code when leaks have been encountered (default 1)
  -i, --rustleaks-ignore-path string  path to .rustleaksignore file or folder containing one
      --gitleaks-ignore-path string   backward-compatible alias for --rustleaks-ignore-path (default \".\")
";
const GLOBAL_FLAGS_TAIL: &str = "      --ignore-rustleaks-allow        ignore rustleaks:allow and backward-compatible gitleaks:allow comments
      --ignore-gitleaks-allow         backward-compatible alias for --ignore-rustleaks-allow
  -l, --log-level string              log level (trace, debug, info, warn, error, fatal) (default \"info\")
      --max-archive-depth int         allow scanning into nested archives up to this depth (default \"0\", no archive traversal is done)
      --max-decode-depth int          allow recursive decoding up to this depth (default 5)
      --max-target-megabytes int      files larger than this will be skipped
      --no-banner                     suppress banner
      --no-color                      turn off color for verbose output
      --redact uint[=100]             redact secrets from logs and stdout. To redact only parts of the secret just apply a percent value from 0..100. For example --redact=20 (default 100%)
  -f, --report-format string          output format (json, csv, junit, sarif, template)
  -r, --report-path string            report file (use \"-\" for stdout)
      --report-template string        template file used to generate the report (implies --report-format=template)
      --timeout int                   set a timeout for Rustleaks commands in seconds (default \"0\", no timeout is set)
  -v, --verbose                       show verbose output from scan
";
const ROOT_HELP_PREFIX: &str = "Rustleaks scans code, past or present, for secrets

Usage:
  rustleaks [command]

Available Commands:
  dir         scan directories or files for secrets
  git         scan git repositories for secrets
  stdin       detect secrets from stdin
  version     display Rustleaks version

Flags:
";
const ROOT_HELP_SUFFIX: &str = "      --version                       version for rustleaks

Use \"rustleaks [command] --help\" for more information about a command.
";
const BANNER: &str = "\n    ○\n    │╲\n    │ ○\n    ○ ░\n    ░    rustleaks\n\n";

pub(crate) fn root_help(writer: &mut dyn Write) -> io::Result<()> {
    writer.write_all(ROOT_HELP_PREFIX.as_bytes())?;
    writer.write_all(GLOBAL_FLAGS_HEAD.as_bytes())?;
    writer.write_all(b"  -h, --help                          help for rustleaks\n")?;
    writer.write_all(GLOBAL_FLAGS_TAIL.as_bytes())?;
    writer.write_all(ROOT_HELP_SUFFIX.as_bytes())
}

pub(crate) fn command_help(command: CommandKind, writer: &mut dyn Write) -> io::Result<()> {
    let (prefix, local) = match command {
        CommandKind::Directory => (
            "scan directories or files for secrets\n\nUsage:\n  rustleaks dir [flags] [path]\n\nAliases:\n  dir, file, directory\n\nFlags:\n",
            "      --follow-symlinks   scan files that are symlinks to other files\n  -h, --help              help for dir\n",
        ),
        CommandKind::Git => (
            "scan git repositories for secrets\n\nUsage:\n  rustleaks git [flags] [repo]\n\nFlags:\n",
            "  -h, --help              help for git\n      --log-opts string   git log options\n      --platform string   the target platform used to generate links (github, gitlab)\n      --pre-commit        scan using git diff\n      --staged            scan staged commits (good for pre-commit)\n",
        ),
        CommandKind::Stdin => (
            "detect secrets from stdin\n\nUsage:\n  rustleaks stdin [flags]\n\nFlags:\n",
            "  -h, --help   help for stdin\n",
        ),
    };
    writer.write_all(prefix.as_bytes())?;
    writer.write_all(local.as_bytes())?;
    writer.write_all(b"\nGlobal Flags:\n")?;
    writer.write_all(GLOBAL_FLAGS_HEAD.as_bytes())?;
    writer.write_all(GLOBAL_FLAGS_TAIL.as_bytes())
}

pub(crate) fn command_usage(command: CommandKind, writer: &mut dyn Write) -> io::Result<()> {
    let (usage, local) = match command {
        CommandKind::Directory => (
            "Usage:\n  rustleaks dir [flags] [path]\n\nFlags:\n",
            "      --follow-symlinks   scan files that are symlinks to other files\n  -h, --help              help for dir\n",
        ),
        CommandKind::Git => (
            "Usage:\n  rustleaks git [flags] [repo]\n\nFlags:\n",
            "  -h, --help              help for git\n      --log-opts string   git log options\n      --platform string   the target platform used to generate links (github, gitlab)\n      --pre-commit        scan using git diff\n      --staged            scan staged commits (good for pre-commit)\n",
        ),
        CommandKind::Stdin => (
            "Usage:\n  rustleaks stdin [flags]\n\nFlags:\n",
            "  -h, --help   help for stdin\n",
        ),
    };
    writer.write_all(usage.as_bytes())?;
    writer.write_all(local.as_bytes())?;
    writer.write_all(b"\nGlobal Flags:\n")?;
    writer.write_all(GLOBAL_FLAGS_HEAD.as_bytes())?;
    writer.write_all(GLOBAL_FLAGS_TAIL.as_bytes())?;
    writer.write_all(b"\n")
}

pub(crate) fn parse_error(
    writer: &mut dyn Write,
    message: impl std::fmt::Display,
) -> io::Result<()> {
    writeln!(writer, "Error: {message}")
}

pub(crate) fn root_usage_hint(writer: &mut dyn Write) -> io::Result<()> {
    writeln!(writer, "Run 'rustleaks --help' for usage.")
}

pub(crate) fn banner(writer: &mut dyn Write) -> io::Result<()> {
    writer.write_all(BANNER.as_bytes())
}
pub(crate) fn error(writer: &mut dyn Write, message: impl std::fmt::Display) -> io::Result<()> {
    diagnostic(writer, "error ", message)
}
pub(crate) fn fatal(writer: &mut dyn Write, message: impl std::fmt::Display) -> io::Result<()> {
    diagnostic(writer, "fatal ", message)
}
pub(crate) fn warn(writer: &mut dyn Write, message: impl std::fmt::Display) -> io::Result<()> {
    diagnostic(writer, "warn ", message)
}
pub(crate) fn info(writer: &mut dyn Write, message: impl std::fmt::Display) -> io::Result<()> {
    diagnostic(writer, "info ", message)
}

fn diagnostic(
    writer: &mut dyn Write,
    prefix: &str,
    message: impl std::fmt::Display,
) -> io::Result<()> {
    writer.write_all(prefix.as_bytes())?;
    write_terminal_text(writer, &message.to_string())?;
    writer.write_all(b"\n")
}

pub(crate) struct ReportPlan {
    target: ReportTarget,
    reporter: Box<dyn Reporter>,
    pub format: &'static str,
}

enum ReportTarget {
    Stdout,
    File(PathBuf),
}

impl ReportPlan {
    pub fn new(
        options: &Options,
        config: &CompiledConfig,
        cwd: &Path,
    ) -> Result<Option<Self>, String> {
        let Some(path) = options.report_path.as_ref() else {
            return Ok(None);
        };
        let target = if path == Path::new("-") {
            ReportTarget::Stdout
        } else {
            ReportTarget::File(resolve(cwd, path))
        };
        let normalized = options.report_format.as_deref().map(normalize_format);
        let format = match normalized.as_deref() {
            Some(value) if !value.is_empty() => format_name(value)?,
            _ => infer(path)?,
        };
        // The pinned command validates this flag against the raw pflag value,
        // before its later trim/lowercase routing step.
        if options.report_template.is_some() && options.report_format.as_deref() != Some("template")
        {
            return Err(
                "report format must be template when --report-template is specified".to_owned(),
            );
        }
        let reporter: Box<dyn Reporter> = match format {
            "json" => Box::new(JsonReporter),
            "csv" => Box::new(CsvReporter),
            "junit" => Box::new(JunitReporter),
            "sarif" => {
                Box::new(SarifReporter::try_from_config(config).map_err(|error| error.to_string())?)
            }
            "template" => {
                let template = options
                    .report_template
                    .as_ref()
                    .ok_or_else(|| "template reports require --report-template".to_owned())?;
                Box::new(
                    TemplateReporter::from_path(resolve(cwd, template), TemplateLimits::default())
                        .map_err(|error| error.to_string())?,
                )
            }
            _ => return Err(format!("unsupported report format {format}")),
        };
        if let ReportTarget::File(path) = &target {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                let metadata = fs::metadata(parent).map_err(|error| {
                    format!(
                        "could not inspect report parent {}: {error}",
                        parent.display()
                    )
                })?;
                if !metadata.is_dir() {
                    return Err(format!(
                        "report parent {} is not a directory",
                        parent.display()
                    ));
                }
            }
        }
        Ok(Some(Self {
            target,
            reporter,
            format,
        }))
    }

    pub fn write(&self, stdout: &mut dyn Write, findings: &[Finding]) -> Result<(), String> {
        match &self.target {
            ReportTarget::Stdout => {
                self.reporter
                    .write(stdout, findings)
                    .map_err(|error| error.to_string())?;
                stdout
                    .flush()
                    .map_err(|error| format!("could not flush stdout report: {error}"))
            }
            ReportTarget::File(path) => {
                let file = fs::File::create(path).map_err(|error| {
                    format!("could not open report {}: {error}", path.display())
                })?;
                let mut writer = BufWriter::new(file);
                self.reporter
                    .write(&mut writer, findings)
                    .map_err(|error| error.to_string())?;
                writer
                    .flush()
                    .map_err(|error| format!("could not flush report {}: {error}", path.display()))
            }
        }
    }
}

fn format_name(value: &str) -> Result<&'static str, String> {
    match value {
        "json" => Ok("json"),
        "csv" => Ok("csv"),
        "junit" => Ok("junit"),
        "sarif" => Ok("sarif"),
        "template" => Ok("template"),
        _ => Err(format!("unknown report format {value:?}")),
    }
}

fn infer(path: &Path) -> Result<&'static str, String> {
    if path == Path::new("-") {
        return Err("report format is required when report path is '-'".to_owned());
    }
    let extension = path
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "json" => Ok("json"),
        "csv" => Ok("csv"),
        "sarif" => Ok("sarif"),
        _ => Err(format!(
            "could not infer report format from {}",
            path.display()
        )),
    }
}

fn resolve(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

fn normalize_format(value: &str) -> String {
    trim_go_space(value).to_lowercase()
}

pub(crate) fn verbose(writer: &mut dyn Write, findings: &[Finding]) -> io::Result<()> {
    for finding in findings {
        verbose_finding(writer, finding)?;
    }
    Ok(())
}

fn verbose_finding(writer: &mut dyn Write, finding: &Finding) -> io::Result<()> {
    label(writer, "Finding:", trim_bytes(finding.match_text()))?;
    label(writer, "Secret:", trim_bytes(finding.secret()))?;
    label(writer, "RuleID:", finding.rule_id().to_string_lossy())?;
    writeln!(writer, "{:<12} {:.6}", "Entropy:", finding.entropy())?;
    if finding.file().is_empty() {
        required(writer, finding)?;
        return writeln!(writer);
    }
    if !finding.tags().is_empty() {
        write!(writer, "{:<12} [", "Tags:")?;
        for (index, tag) in finding.tags().iter().enumerate() {
            if index != 0 {
                writer.write_all(b" ")?;
            }
            write_terminal_bytes(writer, tag.as_bytes())?;
        }
        writer.write_all(b"]\n")?;
    }
    label(writer, "File:", finding.file().to_string_lossy())?;
    writeln!(
        writer,
        "{:<12} {}",
        "Line:",
        finding.location().start_line()
    )?;
    if finding.commit().is_empty() {
        label(
            writer,
            "Fingerprint:",
            finding.fingerprint().to_string_lossy(),
        )?;
        required(writer, finding)?;
        return writeln!(writer);
    }
    label(writer, "Commit:", finding.commit().to_string_lossy())?;
    label(writer, "Author:", finding.author().to_string_lossy())?;
    label(writer, "Email:", finding.email().to_string_lossy())?;
    label(writer, "Date:", finding.date().to_string_lossy())?;
    label(
        writer,
        "Fingerprint:",
        finding.fingerprint().to_string_lossy(),
    )?;
    if !finding.link().is_empty() {
        label(writer, "Link:", finding.link().to_string_lossy())?;
    }
    required(writer, finding)?;
    writeln!(writer)
}

fn required(writer: &mut dyn Write, finding: &Finding) -> io::Result<()> {
    for (index, value) in finding.required_findings().iter().enumerate() {
        let bytes = trim_raw(value.secret().as_bytes());
        let shown = if bytes.len() > 40 {
            [&bytes[..37], b"..."].concat()
        } else {
            bytes.to_vec()
        };
        let prefix = if index == 0 { "Required:" } else { "" };
        write!(writer, "{prefix:<12} ")?;
        write_terminal_bytes(writer, value.rule_id().as_bytes())?;
        write!(writer, ":{}:", value.location().start_line())?;
        write_terminal_bytes(writer, &shown)?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn label(writer: &mut dyn Write, name: &str, value: impl std::fmt::Display) -> io::Result<()> {
    write!(writer, "{name:<12} ")?;
    write_terminal_text(writer, &value.to_string())?;
    writer.write_all(b"\n")
}
fn trim_bytes(value: &ByteText) -> String {
    String::from_utf8_lossy(trim_raw(value.as_bytes())).into_owned()
}

fn write_terminal_bytes(writer: &mut dyn Write, value: &[u8]) -> io::Result<()> {
    write_terminal_text(writer, &String::from_utf8_lossy(value))
}

fn write_terminal_text(writer: &mut dyn Write, value: &str) -> io::Result<()> {
    for character in value.chars() {
        match character {
            '\n' => writer.write_all(br"\n")?,
            '\r' => writer.write_all(br"\r")?,
            '\t' => writer.write_all(br"\t")?,
            character if character.is_ascii_control() => {
                write!(writer, "\\x{:02x}", u32::from(character))?;
            }
            character if character.is_control() => {
                write!(writer, "\\u{{{:x}}}", u32::from(character))?;
            }
            character => {
                let mut encoded = [0_u8; 4];
                writer.write_all(character.encode_utf8(&mut encoded).as_bytes())?;
            }
        }
    }
    Ok(())
}
fn trim_raw(bytes: &[u8]) -> &[u8] {
    let Ok(value) = std::str::from_utf8(bytes) else {
        return bytes;
    };
    let without_leading = value.trim_start_matches(is_go_space);
    let start = value.len() - without_leading.len();
    let trimmed = without_leading.trim_end_matches(is_go_space);
    &bytes[start..start + trimmed.len()]
}

fn trim_go_space(value: &str) -> &str {
    value.trim_matches(is_go_space)
}

fn is_go_space(character: char) -> bool {
    matches!(character as u32, 0x0009..=0x000d | 0x0020 | 0x0085 | 0x00a0 | 0x1680 | 0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000)
}

pub(crate) fn summary(
    writer: &mut dyn Write,
    bytes: u64,
    elapsed: Duration,
    findings: usize,
    partial: bool,
    show_info: bool,
    show_warn: bool,
) -> io::Result<()> {
    if partial {
        if show_warn {
            warn(
                writer,
                format_args!("scanned ~{bytes} bytes ({})", human_bytes(bytes)),
            )?;
            warn(
                writer,
                format_args!("partial scan completed in {}", format_duration(elapsed)),
            )?;
            if findings == 0 {
                warn(writer, "no leaks found in partial scan")?;
            } else {
                warn(
                    writer,
                    format_args!("{findings} leaks found in partial scan"),
                )?;
            }
        }
    } else if show_info || show_warn && findings != 0 {
        if show_info {
            info(
                writer,
                format_args!(
                    "scanned ~{bytes} bytes ({}) in {}",
                    human_bytes(bytes),
                    format_duration(elapsed)
                ),
            )?;
        }
        if findings == 0 {
            if show_info {
                info(writer, "no leaks found")?;
            }
        } else if show_warn {
            warn(writer, format_args!("leaks found: {findings}"))?;
        }
    }
    Ok(())
}

#[allow(
    clippy::cast_precision_loss,
    reason = "the pinned CLI intentionally performs byte-unit formatting through float32"
)]
fn human_bytes(bytes: u64) -> String {
    if bytes == 0 {
        return "0".to_owned();
    }
    let (value, unit) = if bytes >= 1_000_000_000 {
        (bytes as f32 / 1_000_000_000_f32, "GB")
    } else if bytes >= 1_000_000 {
        (bytes as f32 / 1_000_000_f32, "MB")
    } else if bytes >= 1_000 {
        (bytes as f32 / 1_000_f32, "KB")
    } else {
        (bytes as f32, "bytes")
    };
    let mut rendered = format!("{value:.2}");
    if rendered.ends_with(".00") {
        rendered.truncate(rendered.len() - 3);
    }
    format!("{rendered} {unit}")
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() >= 1 {
        format!("{:.2}s", duration.as_secs_f64())
    } else if duration.as_millis() >= 1 {
        format!("{}ms", duration.as_millis())
    } else {
        format!("{}µs", duration.as_micros())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FlushFailure(Vec<u8>);

    impl Write for FlushFailure {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("injected flush failure"))
        }
    }

    #[test]
    fn byte_units_use_decimal_and_trim_only_dot_zero_zero() {
        assert_eq!(human_bytes(0), "0");
        assert_eq!(human_bytes(1_000), "1 KB");
        assert_eq!(human_bytes(1_250), "1.25 KB");
        assert_eq!(human_bytes(1_200), "1.20 KB");
    }

    #[test]
    fn diagnostics_escape_terminal_control_characters() {
        let mut output = Vec::new();
        error(&mut output, "path\u{1b}[2J\nforged").unwrap();
        assert_eq!(output, b"error path\\x1b[2J\\nforged\n");
        assert!(!output.contains(&0x1b));
    }

    #[test]
    fn verbose_findings_escape_terminal_control_characters() {
        let finding = Finding::builder()
            .rule_id(b"rule\x1b[31m".as_slice())
            .location(rustleaks_core::model::Location::new(1, 1, 1, 1).unwrap())
            .match_text(b"match\x1b[2J".as_slice())
            .secret(b"line1\nline2".as_slice())
            .file(b"file\rname".as_slice())
            .tags([b"tag\tvalue".as_slice()])
            .build()
            .unwrap();
        let mut output = Vec::new();
        verbose(&mut output, &[finding]).unwrap();
        assert!(!output.contains(&0x1b));
        assert!(
            output
                .windows(br"match\x1b[2J".len())
                .any(|part| part == br"match\x1b[2J")
        );
        assert!(
            output
                .windows(br"line1\nline2".len())
                .any(|part| part == br"line1\nline2")
        );
        assert!(
            output
                .windows(br"file\rname".len())
                .any(|part| part == br"file\rname")
        );
        assert!(
            output
                .windows(br"tag\tvalue".len())
                .any(|part| part == br"tag\tvalue")
        );
    }

    #[test]
    fn stdout_requires_explicit_format() {
        assert!(infer(Path::new("-")).is_err());
    }

    #[test]
    fn stdout_report_flush_failures_are_returned() {
        let report = ReportPlan {
            target: ReportTarget::Stdout,
            reporter: Box::new(JsonReporter),
            format: "json",
        };
        let error = report
            .write(&mut FlushFailure(Vec::new()), &[])
            .expect_err("flush failure must be visible");
        assert!(error.contains("could not flush stdout report"), "{error}");
        assert!(error.contains("injected flush failure"), "{error}");
    }
}
