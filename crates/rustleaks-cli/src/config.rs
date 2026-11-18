use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustleaks_core::config::{
    CompiledConfig, ConfigError, ConfigLoader, ConfigOrigin, ConfigResolver, ResolvedConfig,
    ResolverError,
};
use rustleaks_core::model::ByteText;
use rustleaks_core::native::{
    CONNECTION_RULES_V1, EXTRA_RULES_V1, NativePolicy, NativePolicyError, PROVIDER_RULES_V1,
};
use rustleaks_core::session::{Baseline, IgnoreIssue, IgnoreSet, SessionPolicy};
use rustleaks_sources::LogicalPath;

use crate::args::{CommandKind, Invocation};

/// Gitleaks release whose behavior this build implements.
///
/// `compat/upstream-revision.txt` pins the upstream commit with the
/// description `v8.30.0-27-gb58d3f1`. A config `minVersion` above this
/// version produces an advisory warning.
const IMPLEMENTED_GITLEAKS_VERSION: &str = "8.30.0";

/// Bytes in the longest ignore file line, without its line feed, that the
/// core parser rejects. It matches the default Go scanner token limit.
const IGNORE_LINE_LIMIT: u64 = 64 * 1024;

pub(crate) struct ConfigAssembly {
    pub full: Arc<CompiledConfig>,
    pub selected: CompiledConfig,
    pub policy: SessionPolicy,
    pub excluded_paths: Vec<ByteText>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub origin: String,
    pub native_policy_reference: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) struct ConfigEnvironment<'a> {
    pub path: Option<&'a OsString>,
    pub inline: Option<&'a OsString>,
    pub legacy_path: Option<&'a OsString>,
    pub legacy_inline: Option<&'a OsString>,
}

#[derive(Clone, Debug)]
struct CwdResolver {
    cwd: PathBuf,
}

impl ConfigResolver for CwdResolver {
    fn resolve(
        &self,
        _origin: Option<&ConfigOrigin>,
        requested: &str,
    ) -> Result<ResolvedConfig, ResolverError> {
        let path = resolve(&self.cwd, Path::new(requested));
        let contents = fs::read_to_string(&path).map_err(|error| {
            ResolverError::new(requested, self.cwd.display().to_string(), error.to_string())
        })?;
        Ok(ResolvedConfig::new(contents, ConfigOrigin::Path(path)))
    }
}

pub(crate) fn assemble(
    invocation: &Invocation,
    environment: ConfigEnvironment<'_>,
    cwd: &Path,
    enabled_rules: &mut dyn FnMut(&[String]),
) -> Result<ConfigAssembly, String> {
    validate_numbers(invocation)?;
    let loader = ConfigLoader::new()
        .with_current_version(IMPLEMENTED_GITLEAKS_VERSION)
        .map_err(|error| format!("could not configure current version: {error}"))?
        .with_resolver(CwdResolver {
            cwd: cwd.to_path_buf(),
        });
    let source = select_config_source(invocation, environment, cwd)?;
    let (full, origin, native_policy_reference) =
        compile_selected_config(source, &invocation.options.native_packs, cwd, &loader)?;
    let selected = if invocation.options.enable_rules.is_empty() {
        full.clone()
    } else {
        enabled_rules(&invocation.options.enable_rules);
        full.select_rules(invocation.options.enable_rules.iter().map(String::as_str))
            .map_err(|error| error.to_string())?
    };

    let mut ignores = IgnoreSet::default();
    let mut warnings = Vec::new();
    if full.requires_newer_version() {
        warnings
            .try_reserve(1)
            .map_err(|error| format!("could not retain config warning: {error}"))?;
        warnings.push(minimum_version_warning(&full, &origin)?);
    }
    let mut errors = missing_required_rule_errors(&selected)?;
    let named = invocation.options.ignore_path.as_path();
    let source = if invocation.command == CommandKind::Stdin {
        Path::new(".")
    } else {
        invocation.source.as_path()
    };
    let mut loader = IgnoreLoader {
        cwd,
        loaded: Vec::new(),
        ignores: &mut ignores,
        warnings: &mut warnings,
    };
    loader.append_if_file(named)?;
    for directory in [named, source] {
        loader.append_if_file(&directory.join(".rustleaksignore"))?;
        loader.append_if_file(&directory.join(".gitleaksignore"))?;
    }

    let mut policy = SessionPolicy::builder()
        .ignores(ignores)
        .redaction_percent(invocation.options.redact);
    let mut excluded_paths = config_exclusions(invocation)?;
    if let Some(path) = &invocation.options.baseline_path {
        let physical = resolve(cwd, path);
        match Baseline::load_go_json(&physical) {
            Ok(baseline) => match baseline_exclusion(invocation, cwd, &physical) {
                Ok(exclusion) => {
                    policy = policy.baseline(baseline);
                    excluded_paths.push(exclusion);
                }
                Err(error) => errors.push(format!("could not relativize baseline: {error}")),
            },
            Err(error) => errors.push(format!(
                "could not load baseline {}: {error}",
                path.display()
            )),
        }
    }
    Ok(ConfigAssembly {
        full: Arc::new(full),
        selected,
        policy: policy.build(),
        excluded_paths,
        warnings,
        errors,
        origin,
        native_policy_reference,
    })
}

fn minimum_version_warning(config: &CompiledConfig, origin: &str) -> Result<String, String> {
    const PREFIX: &str = "config requires Gitleaks ";
    const IMPLEMENTED: &str = " or later; Rustleaks implements Gitleaks ";
    const SUFFIX: &str = ", so newer settings may not be supported; config path=";
    let capacity = PREFIX
        .len()
        .checked_add(config.min_version().len())
        .and_then(|value| value.checked_add(IMPLEMENTED.len()))
        .and_then(|value| value.checked_add(IMPLEMENTED_GITLEAKS_VERSION.len()))
        .and_then(|value| value.checked_add(SUFFIX.len()))
        .and_then(|value| value.checked_add(origin.len()))
        .ok_or_else(|| "config warning length overflowed".to_owned())?;
    let mut warning = String::new();
    warning
        .try_reserve(capacity)
        .map_err(|error| format!("could not allocate config warning: {error}"))?;
    write!(
        warning,
        "{PREFIX}{}{IMPLEMENTED}{IMPLEMENTED_GITLEAKS_VERSION}{SUFFIX}{origin}",
        config.min_version(),
    )
    .map_err(|_| "could not render config warning".to_owned())?;
    Ok(warning)
}

fn missing_required_rule_errors(config: &CompiledConfig) -> Result<Vec<String>, String> {
    const PREFIX: &str = "required rule not found in config path=";
    const REQUIRED: &str = " rule-id=";
    let missing = config
        .rules()
        .iter()
        .flat_map(|(primary_id, rule)| {
            rule.required_rules()
                .iter()
                .map(move |required| (primary_id, required))
        })
        .filter(|(_, required)| config.rule(&required.id).is_none());
    let (minimum, _) = missing.size_hint();
    let mut errors = Vec::new();
    errors
        .try_reserve(minimum)
        .map_err(|error| format!("could not retain required-rule diagnostics: {error}"))?;
    for (primary_id, required) in missing {
        errors
            .try_reserve(1)
            .map_err(|error| format!("could not retain required-rule diagnostic: {error}"))?;
        let capacity = PREFIX
            .len()
            .checked_add(primary_id.len())
            .and_then(|value| value.checked_add(REQUIRED.len()))
            .and_then(|value| value.checked_add(required.id.len()))
            .ok_or_else(|| "required-rule diagnostic length overflowed".to_owned())?;
        let mut message = String::new();
        message
            .try_reserve(capacity)
            .map_err(|error| format!("could not allocate required-rule diagnostic: {error}"))?;
        message.push_str(PREFIX);
        message.push_str(primary_id);
        message.push_str(REQUIRED);
        message.push_str(&required.id);
        errors.push(message);
    }
    Ok(errors)
}

enum ConfigSource<'a> {
    Path(PathBuf, &'static str),
    Inline(&'a OsString, &'static str),
    EmbeddedDefault,
}

impl ConfigSource<'_> {
    fn category(&self) -> &'static str {
        match self {
            Self::Path(_, source) | Self::Inline(_, source) => source,
            Self::EmbeddedDefault => "embedded default",
        }
    }
}

fn select_config_source<'a>(
    invocation: &Invocation,
    environment: ConfigEnvironment<'a>,
    cwd: &Path,
) -> Result<ConfigSource<'a>, String> {
    if let Some(path) = invocation
        .options
        .config
        .as_deref()
        .filter(|path| !path.as_os_str().is_empty())
    {
        return Ok(ConfigSource::Path(path.to_path_buf(), "--config"));
    }
    if let Some(path) = environment.path.filter(|value| !value.is_empty()) {
        return Ok(ConfigSource::Path(PathBuf::from(path), "RUSTLEAKS_CONFIG"));
    }
    if let Some(contents) = environment.inline.filter(|value| !value.is_empty()) {
        return Ok(ConfigSource::Inline(contents, "RUSTLEAKS_CONFIG_TOML"));
    }
    if let Some(path) = environment.legacy_path.filter(|value| !value.is_empty()) {
        return Ok(ConfigSource::Path(PathBuf::from(path), "GITLEAKS_CONFIG"));
    }
    if let Some(contents) = environment.legacy_inline.filter(|value| !value.is_empty()) {
        return Ok(ConfigSource::Inline(contents, "GITLEAKS_CONFIG_TOML"));
    }

    let discovery = if invocation.command == CommandKind::Stdin {
        Path::new(".")
    } else {
        invocation.source.as_path()
    };
    let physical_source = resolve(cwd, discovery);
    let metadata = fs::metadata(&physical_source).map_err(|error| {
        format!(
            "could not inspect source {} during config selection: {error}",
            discovery.display()
        )
    })?;
    if metadata.is_dir() {
        for name in [".rustleaks.toml", ".gitleaks.toml"] {
            let local = physical_source.join(name);
            match fs::metadata(&local) {
                Ok(metadata) if metadata.is_file() => {
                    return Ok(ConfigSource::Path(local, "source-local config"));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "could not inspect source-local config {}: {error}",
                        local.display()
                    ));
                }
            }
        }
    }
    Ok(ConfigSource::EmbeddedDefault)
}

fn load_config(
    source: ConfigSource<'_>,
    cwd: &Path,
    loader: &ConfigLoader,
) -> Result<(CompiledConfig, String), String> {
    match source {
        ConfigSource::Path(path, source) => load_path(loader, cwd, &path, source),
        ConfigSource::Inline(contents, source) => {
            let contents = contents
                .to_str()
                .ok_or_else(|| format!("{source} is not valid UTF-8"))?;
            let config = loader.load_toml_at(contents, None).map_err(|error| {
                format!(
                    "could not load config from {source} ({})",
                    config_error_category(&error)
                )
            })?;
            Ok((config, source.to_owned()))
        }
        ConfigSource::EmbeddedDefault => loader
            .load_default()
            .map(|config| (config, "<embedded-default>".to_owned()))
            .map_err(|error| format!("could not load embedded config: {error}")),
    }
}

fn compile_selected_config(
    source: ConfigSource<'_>,
    native_packs: &[String],
    cwd: &Path,
    loader: &ConfigLoader,
) -> Result<(CompiledConfig, String, Option<String>), String> {
    if native_packs.is_empty() {
        let (full, origin) = load_config(source, cwd, loader)?;
        return Ok((full, origin, None));
    }
    if !matches!(source, ConfigSource::EmbeddedDefault) {
        return Err(format!(
            "--native-pack requires embedded-default configuration; a configuration was selected from {}; custom-base composition is not supported",
            source.category(),
        ));
    }
    let (full, reference) = compile_native_packs(native_packs)?;
    Ok((full, "<embedded-default>".to_owned(), Some(reference)))
}

fn compile_native_packs(ids: &[String]) -> Result<(CompiledConfig, String), String> {
    let mut policy = NativePolicy::builder();
    for id in ids {
        let contents = match id.as_str() {
            "rustleaks-extra-v1" => EXTRA_RULES_V1,
            "rustleaks-providers-v1" => PROVIDER_RULES_V1,
            "rustleaks-connections-v1" => CONNECTION_RULES_V1,
            _ => return Err("unknown builtin native pack identifier".to_owned()),
        };
        policy = policy
            .with_pack(id, contents)
            .map_err(native_policy_error)?;
    }
    let (config, identity) = policy.compile().map_err(native_policy_error)?;
    let reference = identity
        .builtin_review_reference()
        .ok_or_else(|| "builtin native policy has no review reference".to_owned())?
        .to_owned();
    Ok((config, reference))
}

fn native_policy_error(error: NativePolicyError) -> String {
    // Exact identity and configuration bytes never enter CLI diagnostics.
    let category = match error {
        NativePolicyError::Config(error) => config_error_category(&error).to_owned(),
        NativePolicyError::Engine(_) => "engine compilation error".to_owned(),
        error => error.to_string(),
    };
    format!("could not compile builtin native policy ({category})")
}

fn config_error_category(error: &ConfigError) -> &'static str {
    match error {
        ConfigError::Parse { .. } => "parse error",
        ConfigError::Decode { .. } => "decode error",
        ConfigError::Resolve(_) => "extension resolution error",
        ConfigError::Extended(_) => "extended config error",
        _ => "validation error",
    }
}

fn load_path(
    loader: &ConfigLoader,
    cwd: &Path,
    path: &Path,
    source: &str,
) -> Result<(CompiledConfig, String), String> {
    let physical = resolve(cwd, path);
    let contents = fs::read_to_string(&physical).map_err(|error| {
        format!(
            "could not read config {} from {source}: {error}",
            path.display()
        )
    })?;
    loader
        .load_toml_at(&contents, Some(ConfigOrigin::Path(physical.clone())))
        .map(|config| (config, physical.display().to_string()))
        .map_err(|error| {
            format!(
                "could not compile config {} from {source}: {error}",
                path.display()
            )
        })
}

fn validate_numbers(invocation: &Invocation) -> Result<(), String> {
    let options = &invocation.options;
    if options.max_target_megabytes > 0 {
        let megabytes = usize::try_from(options.max_target_megabytes)
            .map_err(|_| "--max-target-megabytes is out of range".to_owned())?;
        megabytes
            .checked_add(1)
            .and_then(|value| value.checked_mul(1_000_000))
            .and_then(|value| value.checked_sub(1))
            .ok_or_else(|| "--max-target-megabytes overflows the native byte domain".to_owned())?;
        u64::try_from(megabytes)
            .ok()
            .and_then(|value| value.checked_mul(1_000_000))
            .ok_or_else(|| "--max-target-megabytes overflows the source byte domain".to_owned())?;
    }
    for (name, value) in [
        ("--max-decode-depth", options.max_decode_depth),
        ("--max-archive-depth", options.max_archive_depth),
    ] {
        if value > 0 {
            usize::try_from(value).map_err(|_| format!("{name} is out of range"))?;
        }
    }
    if options.timeout_seconds > 0 {
        u64::try_from(options.timeout_seconds)
            .map_err(|_| "--timeout is out of range".to_owned())?;
    }
    Ok(())
}

/// Loads ignore files and reports each physical file at most once.
///
/// The named ignore path and the scanned source often resolve to the same
/// folder, so files are deduplicated by canonical path.
struct IgnoreLoader<'a> {
    cwd: &'a Path,
    loaded: Vec<PathBuf>,
    ignores: &'a mut IgnoreSet,
    warnings: &'a mut Vec<String>,
}

impl IgnoreLoader<'_> {
    fn append_if_file(&mut self, path: &Path) -> Result<(), String> {
        let physical = resolve(self.cwd, path);
        // Errors name the lexically cleaned path; file access uses the
        // resolved path so symlinked parents are not bypassed.
        let shown = clean_native_path(&physical).unwrap_or_else(|_| physical.clone());
        match fs::metadata(&physical) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(());
            }
            Err(error) => {
                return Err(format!(
                    "could not inspect ignore path {}: {error}",
                    shown.display()
                ));
            }
        }
        let canonical = fs::canonicalize(&physical).unwrap_or_else(|_| physical.clone());
        if self.loaded.contains(&canonical) {
            return Ok(());
        }
        self.loaded
            .try_reserve(1)
            .map_err(|error| format!("could not retain ignore file path: {error}"))?;
        self.loaded.push(canonical);
        let read_error =
            |error: io::Error| format!("could not read ignore file {}: {error}", shown.display());
        let mut reader = BufReader::new(fs::File::open(&physical).map_err(read_error)?);
        let display = clean_native_path(path).unwrap_or_else(|_| shown.clone());
        let file = display.display();
        // The scanned repository controls this file, so read one line at a
        // time and never hold more than one line. Each diagnostic can then
        // name its line. The parser splits on line feeds, so the installed
        // entries are the same as for one call over the whole file.
        let mut line = Vec::new();
        for index in 0_usize.. {
            line.clear();
            // A line of IGNORE_LINE_LIMIT bytes or more is rejected by the
            // parser whatever follows, so reading one more byte than the
            // limit is enough to report it.
            (&mut reader)
                .take(IGNORE_LINE_LIMIT + 1)
                .read_until(b'\n', &mut line)
                .map_err(read_error)?;
            if line.is_empty() {
                break;
            }
            let line_number = index.saturating_add(1);
            let mut stop = false;
            for issue in self.ignores.extend_go_compatible(&line) {
                let warning = match issue {
                    IgnoreIssue::InvalidFieldCount { fields, .. } => {
                        let noun = if fields == 1 { "field" } else { "fields" };
                        format!(
                            "ignore file entry has {fields} {noun}, expected 3 or 4 \
                             file={file} line={line_number}"
                        )
                    }
                    IgnoreIssue::TokenTooLong { .. } => {
                        stop = true;
                        format!(
                            "ignore file line is 64 KiB or longer, so it and later \
                             lines are skipped file={file} line={line_number}"
                        )
                    }
                };
                self.warnings
                    .try_reserve(1)
                    .map_err(|error| format!("could not retain ignore warning: {error}"))?;
                self.warnings.push(warning);
            }
            if stop {
                break;
            }
        }
        Ok(())
    }
}

fn config_exclusions(invocation: &Invocation) -> Result<Vec<ByteText>, String> {
    if let Some(path) = &invocation.options.config {
        return Ok(vec![logical_native(path)]);
    }
    Ok(vec![
        logical_native(&clean_native_path(
            &invocation.source.join(".rustleaks.toml"),
        )?),
        logical_native(&clean_native_path(
            &invocation.source.join(".gitleaks.toml"),
        )?),
    ])
}

fn baseline_exclusion(
    invocation: &Invocation,
    cwd: &Path,
    baseline: &Path,
) -> Result<ByteText, String> {
    let source = clean_native_path(&resolve(cwd, &invocation.source))?;
    let baseline = clean_native_path(baseline)?;
    relative_native_path(&source, &baseline).map(|path| {
        let logical = LogicalPath::from_native(&path);
        logical
            .windows_original()
            .unwrap_or_else(|| logical.normalized())
            .clone()
    })
}

fn logical_native(path: &Path) -> ByteText {
    LogicalPath::from_native(path).normalized().clone()
}

fn clean_native_path(path: &Path) -> Result<PathBuf, String> {
    use std::path::Component;

    const MAX_PATH_COMPONENTS: usize = 4_096;
    let mut prefix = None;
    let mut rooted = false;
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(value) => prefix = Some(value.as_os_str().to_os_string()),
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.last().is_some_and(|part| part != "..") {
                    parts.pop();
                } else if !rooted {
                    if parts.len() == MAX_PATH_COMPONENTS {
                        return Err(format!(
                            "path exceeds the {MAX_PATH_COMPONENTS}-component safety limit"
                        ));
                    }
                    parts
                        .try_reserve(1)
                        .map_err(|error| format!("could not retain clean path: {error}"))?;
                    parts.push(OsString::from(".."));
                }
            }
            Component::Normal(value) => {
                if parts.len() == MAX_PATH_COMPONENTS {
                    return Err(format!(
                        "path exceeds the {MAX_PATH_COMPONENTS}-component safety limit"
                    ));
                }
                parts
                    .try_reserve(1)
                    .map_err(|error| format!("could not retain clean path: {error}"))?;
                parts.push(value.to_os_string());
            }
        }
    }
    let mut cleaned = PathBuf::new();
    cleaned
        .try_reserve(path.as_os_str().as_encoded_bytes().len())
        .map_err(|error| format!("could not allocate clean path: {error}"))?;
    if let Some(prefix) = prefix {
        cleaned.push(prefix);
    }
    if rooted {
        cleaned.push(std::path::MAIN_SEPARATOR_STR);
    }
    for part in parts {
        cleaned.push(part);
    }
    if cleaned.as_os_str().is_empty() {
        cleaned.push(".");
    }
    Ok(cleaned)
}

fn relative_native_path(from: &Path, to: &Path) -> Result<PathBuf, String> {
    use std::path::Component;

    const MAX_PATH_COMPONENTS: usize = 4_096;
    fn components(path: &Path) -> Result<Vec<Component<'_>>, String> {
        let mut retained = Vec::new();
        for component in path.components() {
            if retained.len() == MAX_PATH_COMPONENTS {
                return Err(format!(
                    "path exceeds the {MAX_PATH_COMPONENTS}-component safety limit"
                ));
            }
            retained
                .try_reserve(1)
                .map_err(|error| format!("could not retain path components: {error}"))?;
            retained.push(component);
        }
        Ok(retained)
    }
    let from = components(from)?;
    let to = components(to)?;
    if matches!(
        from.first(),
        Some(Component::Prefix(_) | Component::RootDir)
    ) && matches!(to.first(), Some(Component::Prefix(_) | Component::RootDir))
        && from.first() != to.first()
    {
        return Err("source and baseline are on different filesystem volumes".to_owned());
    }
    let common = from
        .iter()
        .zip(&to)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    let capacity = from
        .iter()
        .chain(&to)
        .try_fold(0_usize, |size, component| {
            size.checked_add(component.as_os_str().as_encoded_bytes().len())
                .and_then(|value| value.checked_add(1))
        })
        .ok_or_else(|| "relative path length overflowed".to_owned())?;
    relative
        .try_reserve(capacity)
        .map_err(|error| format!("could not allocate relative path: {error}"))?;
    for component in &from[common..] {
        if matches!(component, Component::Normal(_) | Component::ParentDir) {
            relative.push("..");
        }
    }
    for component in &to[common..] {
        relative.push(component.as_os_str());
    }
    if relative.as_os_str().is_empty() {
        relative.push(".");
    }
    Ok(relative)
}

pub(crate) fn resolve(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::Options;

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rustleaks-cli-config-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn assemble_inline(root: &Path, inline: Option<&str>) -> ConfigAssembly {
        let inline = inline.map(OsString::from);
        let invocation = Invocation {
            command: CommandKind::Stdin,
            source: PathBuf::from("."),
            options: Options::default(),
        };
        assemble(
            &invocation,
            ConfigEnvironment {
                path: None,
                inline: inline.as_ref(),
                legacy_path: None,
                legacy_inline: None,
            },
            root,
            &mut |_| {},
        )
        .unwrap()
    }

    #[test]
    fn ignore_warnings_name_the_line_and_stop_after_an_overlong_line() {
        let root = temporary_directory("ignore-warnings");
        let mut ignore = b"one:two\n".to_vec();
        ignore.extend(std::iter::repeat_n(b'x', 64 * 1024));
        ignore.extend_from_slice(b"\nthree\n");
        std::fs::write(root.join(".rustleaksignore"), ignore).unwrap();
        let assembly = assemble_inline(&root, None);
        assert_eq!(
            assembly.warnings,
            [
                "ignore file entry has 2 fields, expected 3 or 4 file=.rustleaksignore line=1",
                "ignore file line is 64 KiB or longer, so it and later lines are skipped \
                 file=.rustleaksignore line=2",
            ]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    fn load_ignore_file(name: &str, contents: &[u8]) -> (IgnoreSet, Vec<String>) {
        let root = temporary_directory(name);
        std::fs::write(root.join(".gitleaksignore"), contents).unwrap();
        let mut ignores = IgnoreSet::default();
        let mut warnings = Vec::new();
        IgnoreLoader {
            cwd: &root,
            loaded: Vec::new(),
            ignores: &mut ignores,
            warnings: &mut warnings,
        }
        .append_if_file(Path::new(".gitleaksignore"))
        .unwrap();
        std::fs::remove_dir_all(root).unwrap();
        (ignores, warnings)
    }

    fn entries(ignores: &IgnoreSet) -> Vec<&[u8]> {
        ignores.iter().map(ByteText::as_bytes).collect()
    }

    #[test]
    fn ignore_file_lines_keep_their_entries_and_line_numbers() {
        let (ignores, warnings) = load_ignore_file(
            "ignore-lines",
            b"a.txt:rule:1\r\n# comment\n\n  dir\\b.txt:rule:2  \nabc:dir\\c.txt:rule:3\nbad\nlast:rule:4",
        );
        assert_eq!(
            entries(&ignores),
            [
                b"a.txt:rule:1".as_slice(),
                b"abc:dir/c.txt:rule:3",
                b"bad",
                b"dir/b.txt:rule:2",
                b"last:rule:4",
            ]
        );
        assert_eq!(
            warnings,
            ["ignore file entry has 1 field, expected 3 or 4 file=.gitleaksignore line=6"]
        );
    }

    #[test]
    fn ignore_file_line_limit_is_64_kib_without_the_line_feed() {
        let limit = 64 * 1024;
        let mut below = b"x:y:".to_vec();
        below.resize(limit - 2, b'z');
        below.extend_from_slice(b"\r\nnext:rule:1\n");
        let (ignores, warnings) = load_ignore_file("ignore-below", &below);
        assert_eq!(ignores.len(), 2);
        assert!(ignores.contains(b"next:rule:1"));
        assert!(warnings.is_empty());

        let mut at = b"first:rule:1\n".to_vec();
        at.resize(at.len() + limit, b'z');
        at.extend_from_slice(b"\nnext:rule:2\n");
        let (ignores, warnings) = load_ignore_file("ignore-at", &at);
        assert_eq!(entries(&ignores), [b"first:rule:1".as_slice()]);
        assert_eq!(
            warnings,
            [
                "ignore file line is 64 KiB or longer, so it and later lines are skipped \
              file=.gitleaksignore line=2"
            ]
        );
    }

    #[test]
    fn ignore_file_stops_at_a_long_final_line_without_a_line_feed() {
        let mut contents = b"first:rule:1\n".to_vec();
        contents.resize(contents.len() + 4 * 1024 * 1024, b'z');
        let (ignores, warnings) = load_ignore_file("ignore-long-final", &contents);
        assert_eq!(entries(&ignores), [b"first:rule:1".as_slice()]);
        assert_eq!(
            warnings,
            [
                "ignore file line is 64 KiB or longer, so it and later lines are skipped \
              file=.gitleaksignore line=2"
            ]
        );
    }

    #[test]
    fn ignore_file_reading_matches_parsing_the_whole_file() {
        let limit = 64 * 1024;
        let mut cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"\n".to_vec(),
            b"\r\n\r\n".to_vec(),
            b"a:b:c".to_vec(),
            b"a:b:c\n\n\nd:e:f:g\n".to_vec(),
            b"one\ntwo:three\nfour:five:six:seven:eight\n".to_vec(),
            b"\xef\xbb\xbfa:b:c\n\x85x:y:z\x85\n".to_vec(),
        ];
        for length in [limit - 1, limit, limit + 1] {
            for suffix in [&b""[..], b"\n", b"\r\n", b"\nafter:rule:1\n"] {
                let mut case = b"before:rule:1\n".to_vec();
                case.resize(case.len() + length, b'q');
                case.extend_from_slice(suffix);
                cases.push(case);
            }
        }
        for (index, case) in cases.iter().enumerate() {
            let expected = IgnoreSet::parse_go_compatible(case);
            let (ignores, warnings) = load_ignore_file(&format!("ignore-equal-{index}"), case);
            assert_eq!(ignores, expected.ignores, "case {index}");
            assert_eq!(warnings.len(), expected.issues.len(), "case {index}");
        }
    }

    #[test]
    fn embedded_default_minimum_version_is_satisfied() {
        let root = temporary_directory("default-version");
        let assembly = assemble_inline(&root, None);
        assert_eq!(assembly.origin, "<embedded-default>");
        assert_eq!(assembly.full.min_version(), "v8.25.0");
        assert!(!assembly.full.requires_newer_version());
        assert!(assembly.warnings.is_empty(), "{:?}", assembly.warnings);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn minimum_version_warns_only_above_the_implemented_gitleaks_version() {
        let root = temporary_directory("minimum-version");
        for satisfied in [
            "v8.30.0",
            "8.30.0",
            "v8.29.9",
            "v8.30.0-rc.1",
            "v8.30.0+meta",
        ] {
            let config = format!("minVersion = '{satisfied}'\n");
            let assembly = assemble_inline(&root, Some(&config));
            assert!(!assembly.full.requires_newer_version(), "{satisfied}");
            assert!(assembly.warnings.is_empty(), "{satisfied}");
        }
        for (required, expected) in [
            (
                "v8.30.1",
                "config requires Gitleaks v8.30.1 or later; Rustleaks implements Gitleaks 8.30.0, so newer settings may not be supported; config path=RUSTLEAKS_CONFIG_TOML",
            ),
            (
                "v99.0.0",
                "config requires Gitleaks v99.0.0 or later; Rustleaks implements Gitleaks 8.30.0, so newer settings may not be supported; config path=RUSTLEAKS_CONFIG_TOML",
            ),
        ] {
            let config = format!("minVersion = '{required}'\n");
            let assembly = assemble_inline(&root, Some(&config));
            assert!(assembly.full.requires_newer_version(), "{required}");
            assert_eq!(assembly.warnings, [expected]);
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn selected_composite_reports_its_missing_required_rule() {
        let root = temporary_directory("selected-composite");
        std::fs::write(
            root.join("composite.toml"),
            "[[rules]]\nid='primary'\nregex='primary'\n[[rules.required]]\nid='secondary'\n[[rules]]\nid='secondary'\nregex='secondary'\nskipReport=true\n",
        )
        .unwrap();
        let invocation = Invocation {
            command: CommandKind::Stdin,
            source: PathBuf::from("."),
            options: Options {
                config: Some(PathBuf::from("composite.toml")),
                enable_rules: vec!["primary".to_owned()],
                ..Options::default()
            },
        };
        let assembly = assemble(
            &invocation,
            ConfigEnvironment {
                path: None,
                inline: None,
                legacy_path: None,
                legacy_inline: None,
            },
            &root,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(
            assembly.errors,
            ["required rule not found in config path=primary rule-id=secondary"]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checked_megabyte_math_rejects_overflow() {
        let invocation = Invocation {
            command: CommandKind::Directory,
            source: PathBuf::from("."),
            options: Options {
                max_target_megabytes: i64::MAX,
                ..Options::default()
            },
        };
        assert!(validate_numbers(&invocation).is_err());
    }

    #[test]
    fn config_exclusion_covers_native_and_backward_compatible_spellings() {
        let explicit = Invocation {
            command: CommandKind::Directory,
            source: PathBuf::from("repo"),
            options: Options {
                config: Some(PathBuf::from("other/config.toml")),
                ..Options::default()
            },
        };
        assert_eq!(
            config_exclusions(&explicit).unwrap(),
            [ByteText::from("other/config.toml")]
        );

        let default = Invocation {
            command: CommandKind::Directory,
            source: PathBuf::from("repo/./nested/.."),
            options: Options::default(),
        };
        assert_eq!(
            config_exclusions(&default).unwrap(),
            [
                ByteText::from("repo/.rustleaks.toml"),
                ByteText::from("repo/.gitleaks.toml")
            ]
        );
    }

    #[test]
    fn baseline_exclusion_matches_host_filepath_rel_for_outside_and_file_sources() {
        let cwd = Path::new("/workspace");
        let directory = Invocation {
            command: CommandKind::Directory,
            source: PathBuf::from("repo/./nested/.."),
            options: Options::default(),
        };
        let outside = if cfg!(windows) {
            ByteText::from(r"..\other\base.json")
        } else {
            ByteText::from("../other/base.json")
        };
        assert_eq!(
            baseline_exclusion(&directory, cwd, Path::new("/workspace/other/base.json")).unwrap(),
            outside
        );

        let file = Invocation {
            command: CommandKind::Directory,
            source: PathBuf::from("repo/secret.txt"),
            options: Options::default(),
        };
        let sibling = if cfg!(windows) {
            ByteText::from(r"..\base.json")
        } else {
            ByteText::from("../base.json")
        };
        assert_eq!(
            baseline_exclusion(&file, cwd, Path::new("/workspace/repo/base.json")).unwrap(),
            sibling
        );

        let mut excessive = PathBuf::from("/workspace");
        for _ in 0..=4_096 {
            excessive.push("component");
        }
        assert!(
            relative_native_path(Path::new("/workspace"), &excessive)
                .unwrap_err()
                .contains("4096-component safety limit")
        );
    }

    #[cfg(unix)]
    #[test]
    fn explicit_config_exclusion_preserves_native_unix_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let native = OsString::from_vec(b"config-\xff.toml".to_vec());
        let invocation = Invocation {
            command: CommandKind::Directory,
            source: PathBuf::from("."),
            options: Options {
                config: Some(PathBuf::from(native)),
                ..Options::default()
            },
        };
        assert_eq!(
            config_exclusions(&invocation).unwrap()[0].as_bytes(),
            b"config-\xff.toml"
        );
    }

    #[cfg(windows)]
    #[test]
    fn baseline_relative_path_is_drive_and_unc_aware() {
        assert_eq!(
            relative_native_path(
                Path::new(r"C:\workspace\repo"),
                Path::new(r"C:\workspace\other\base.json"),
            )
            .unwrap(),
            PathBuf::from(r"..\other\base.json")
        );
        assert!(
            relative_native_path(
                Path::new(r"C:\workspace\repo"),
                Path::new(r"D:\baseline.json"),
            )
            .is_err()
        );
        assert_eq!(
            relative_native_path(
                Path::new(r"\\server\share\repo"),
                Path::new(r"\\server\share\baseline.json"),
            )
            .unwrap(),
            PathBuf::from(r"..\baseline.json")
        );
    }
}

#[cfg(test)]
mod native_entropy_tests {
    use super::*;

    #[test]
    fn cli_compiles_and_projects_the_requested_byte_predicates() {
        let (full, reference) =
            compile_native_packs(&["rustleaks-providers-v1".to_owned()]).unwrap();
        assert!(reference.contains("providers-sha256:"));
        for id in [
            "rustleaks.dockerhub-personal-access-token",
            "rustleaks.dockerhub-organization-access-token",
            "rustleaks.neon-api-key",
            "rustleaks.render-api-key",
            "rustleaks.deno-account-token",
            "rustleaks.apify-api-token",
        ] {
            let selected = full.select_rules([id]).unwrap();
            assert_eq!(
                selected.rule(id).unwrap().native_entropy(),
                Some(("byte-shannon-f64-v1", "lt", 3.5))
            );
            assert_eq!(full.rule(id), selected.rule(id));
        }
    }

    #[test]
    fn config_source_selection_preserves_native_and_legacy_precedence() {
        let mut invocation = Invocation {
            command: CommandKind::Stdin,
            source: PathBuf::from("."),
            options: crate::args::Options::default(),
        };
        let path = OsString::from("absent.toml");
        let inline = OsString::from("PRIVATE_SOURCE_SENTINEL");
        let mut environment = ConfigEnvironment {
            path: Some(&path),
            inline: Some(&inline),
            legacy_path: Some(&path),
            legacy_inline: Some(&inline),
        };
        invocation.options.config = Some(PathBuf::from("explicit.toml"));
        assert_eq!(
            select_config_source(&invocation, environment, Path::new("absent"))
                .unwrap()
                .category(),
            "--config"
        );
        invocation.options.config = None;
        assert_eq!(
            select_config_source(&invocation, environment, Path::new("absent"))
                .unwrap()
                .category(),
            "RUSTLEAKS_CONFIG"
        );
        environment.path = None;
        assert_eq!(
            select_config_source(&invocation, environment, Path::new("absent"))
                .unwrap()
                .category(),
            "RUSTLEAKS_CONFIG_TOML"
        );
        environment.inline = None;
        assert_eq!(
            select_config_source(&invocation, environment, Path::new("absent"))
                .unwrap()
                .category(),
            "GITLEAKS_CONFIG"
        );
        environment.legacy_path = None;
        assert_eq!(
            select_config_source(&invocation, environment, Path::new("absent"))
                .unwrap()
                .category(),
            "GITLEAKS_CONFIG_TOML"
        );
    }
}
