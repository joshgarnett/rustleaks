use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustleaks_core::config::{
    CompiledConfig, ConfigError, ConfigLoader, ConfigOrigin, ConfigResolver, ResolvedConfig,
    ResolverError,
};
use rustleaks_core::model::ByteText;
use rustleaks_core::session::{Baseline, IgnoreSet, SessionPolicy};
use rustleaks_sources::LogicalPath;

use crate::args::{CommandKind, Invocation};

pub(crate) struct ConfigAssembly {
    pub full: Arc<CompiledConfig>,
    pub selected: CompiledConfig,
    pub policy: SessionPolicy,
    pub excluded_paths: Vec<ByteText>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub origin: String,
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
        .with_current_version(env!("CARGO_PKG_VERSION"))
        .map_err(|error| format!("could not configure current version: {error}"))?
        .with_resolver(CwdResolver {
            cwd: cwd.to_path_buf(),
        });
    let (full, origin) = load_config(invocation, environment, cwd, &loader)?;
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
    let named = resolve(cwd, &invocation.options.ignore_path);
    append_ignore_if_file(&named, &mut ignores, &mut warnings)?;
    append_ignore_if_file(&named.join(".rustleaksignore"), &mut ignores, &mut warnings)?;
    append_ignore_if_file(&named.join(".gitleaksignore"), &mut ignores, &mut warnings)?;
    let source_local = if invocation.command == CommandKind::Stdin {
        cwd.to_path_buf()
    } else {
        resolve(cwd, &invocation.source)
    };
    append_ignore_if_file(
        &source_local.join(".rustleaksignore"),
        &mut ignores,
        &mut warnings,
    )?;
    append_ignore_if_file(
        &source_local.join(".gitleaksignore"),
        &mut ignores,
        &mut warnings,
    )?;

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
    })
}

fn minimum_version_warning(config: &CompiledConfig, origin: &str) -> Result<String, String> {
    const PREFIX: &str = "config requires a newer Gitleaks version... required=";
    const CURRENT: &str = " current=";
    const ORIGIN: &str = " config path=";
    let capacity = PREFIX
        .len()
        .checked_add(config.min_version().len())
        .and_then(|value| value.checked_add(CURRENT.len()))
        .and_then(|value| value.checked_add(env!("CARGO_PKG_VERSION").len()))
        .and_then(|value| value.checked_add(ORIGIN.len()))
        .and_then(|value| value.checked_add(origin.len()))
        .ok_or_else(|| "config warning length overflowed".to_owned())?;
    let mut warning = String::new();
    warning
        .try_reserve(capacity)
        .map_err(|error| format!("could not allocate config warning: {error}"))?;
    write!(
        warning,
        "{PREFIX}{}{CURRENT}{}{ORIGIN}{origin}",
        config.min_version(),
        env!("CARGO_PKG_VERSION")
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

fn load_config(
    invocation: &Invocation,
    environment: ConfigEnvironment<'_>,
    cwd: &Path,
    loader: &ConfigLoader,
) -> Result<(CompiledConfig, String), String> {
    if let Some(path) = invocation
        .options
        .config
        .as_deref()
        .filter(|path| !path.as_os_str().is_empty())
    {
        return load_path(loader, cwd, path, "--config");
    }
    if let Some(path) = environment.path.filter(|value| !value.is_empty()) {
        return load_path(loader, cwd, Path::new(path), "RUSTLEAKS_CONFIG");
    }
    if let Some(contents) = environment.inline.filter(|value| !value.is_empty()) {
        let contents = contents
            .to_str()
            .ok_or_else(|| "RUSTLEAKS_CONFIG_TOML is not valid UTF-8".to_owned())?;
        let config = loader.load_toml_at(contents, None).map_err(|error| {
            format!(
                "could not load config from RUSTLEAKS_CONFIG_TOML ({})",
                config_error_category(&error)
            )
        })?;
        return Ok((config, "RUSTLEAKS_CONFIG_TOML".to_owned()));
    }
    if let Some(path) = environment.legacy_path.filter(|value| !value.is_empty()) {
        return load_path(loader, cwd, Path::new(path), "GITLEAKS_CONFIG");
    }
    if let Some(contents) = environment.legacy_inline.filter(|value| !value.is_empty()) {
        let contents = contents
            .to_str()
            .ok_or_else(|| "GITLEAKS_CONFIG_TOML is not valid UTF-8".to_owned())?;
        let config = loader.load_toml_at(contents, None).map_err(|error| {
            format!(
                "could not load config from GITLEAKS_CONFIG_TOML ({})",
                config_error_category(&error)
            )
        })?;
        return Ok((config, "GITLEAKS_CONFIG_TOML".to_owned()));
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
                    return load_path(loader, cwd, &local, "source-local config");
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
    loader
        .load_default()
        .map(|config| (config, "<embedded-default>".to_owned()))
        .map_err(|error| format!("could not load embedded config: {error}"))
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

fn append_ignore_if_file(
    path: &Path,
    ignores: &mut IgnoreSet,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            let bytes = fs::read(path).map_err(|error| {
                format!("could not read ignore file {}: {error}", path.display())
            })?;
            for issue in ignores.extend_go_compatible(&bytes) {
                warnings.push(format!("ignore file {}: {issue:?}", path.display()));
            }
        }
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) => {}
        Err(error) => {
            return Err(format!(
                "could not inspect ignore path {}: {error}",
                path.display()
            ));
        }
    }
    Ok(())
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
    relative_native_path(&source, &baseline).map(|path| logical_native(&path))
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

    #[test]
    fn embedded_default_warns_against_the_workspace_version() {
        assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0-alpha.1");
        let root = temporary_directory("default-version");
        let invocation = Invocation {
            command: CommandKind::Stdin,
            source: PathBuf::from("."),
            options: Options::default(),
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
        assert!(assembly.full.requires_newer_version());
        assert_eq!(assembly.full.min_version(), "v8.25.0");
        assert_eq!(
            assembly.warnings,
            [
                "config requires a newer Gitleaks version... required=v8.25.0 current=0.1.0-alpha.1 config path=<embedded-default>"
            ]
        );
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
        assert_eq!(
            baseline_exclusion(&directory, cwd, Path::new("/workspace/other/base.json")).unwrap(),
            ByteText::from("../other/base.json")
        );

        let file = Invocation {
            command: CommandKind::Directory,
            source: PathBuf::from("repo/secret.txt"),
            options: Options::default(),
        };
        assert_eq!(
            baseline_exclusion(&file, cwd, Path::new("/workspace/repo/base.json")).unwrap(),
            ByteText::from("../base.json")
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
