use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aho_corasick::{AhoCorasickBuilder, MatchKind};
use semver::Version;
use thiserror::Error;

use crate::regex::GoRegex;

use super::DEFAULT_CONFIG;
use super::compiled::{CompiledAllowlist, CompiledConfig, CompiledRule};
use super::raw::{AllowlistSpec, Condition, RawConfig, RawGlobalAllowlist, RegexTarget, RuleSpec};

const MAX_EXTEND_DEPTH: usize = 2;

/// Stable identity for diagnostics and relative extension resolution.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfigOrigin {
    /// Filesystem path.
    Path(PathBuf),
    /// Resolver-defined virtual path.
    Virtual(String),
    /// The byte-exact embedded default.
    EmbeddedDefault,
}

impl ConfigOrigin {
    /// Creates a filesystem origin.
    #[must_use]
    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    /// Creates a resolver-defined virtual origin.
    #[must_use]
    pub fn virtual_path(path: impl Into<String>) -> Self {
        Self::Virtual(path.into())
    }
}

impl fmt::Display for ConfigOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(path) => path.display().fmt(formatter),
            Self::Virtual(path) => formatter.write_str(path),
            Self::EmbeddedDefault => formatter.write_str("<embedded-default>"),
        }
    }
}

/// Text returned by an injected extension resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedConfig {
    contents: String,
    origin: ConfigOrigin,
}

impl ResolvedConfig {
    /// Creates resolved text with its stable origin.
    #[must_use]
    pub fn new(contents: impl Into<String>, origin: ConfigOrigin) -> Self {
        Self {
            contents: contents.into(),
            origin,
        }
    }

    /// Returns the resolved TOML text.
    #[must_use]
    pub fn contents(&self) -> &str {
        &self.contents
    }

    /// Returns the stable source origin.
    #[must_use]
    pub fn origin(&self) -> &ConfigOrigin {
        &self.origin
    }
}

/// Error from a configuration resolver.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("unable to resolve config path '{path}' from {from}: {message}")]
pub struct ResolverError {
    path: String,
    from: String,
    message: String,
}

impl ResolverError {
    /// Creates a contextual resolver error.
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        from: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            from: from.into(),
            message: message.into(),
        }
    }

    /// Returns the originally requested path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Injected, synchronous configuration text resolver.
pub trait ConfigResolver: Send + Sync {
    /// Resolves `path`, relative to `origin` when applicable.
    ///
    /// # Errors
    ///
    /// Returns [`ResolverError`] when the requested source cannot be read.
    fn resolve(
        &self,
        origin: Option<&ConfigOrigin>,
        path: &str,
    ) -> Result<ResolvedConfig, ResolverError>;
}

/// Resolver used by default. It guarantees that loading a string performs no I/O.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoIoResolver;

impl ConfigResolver for NoIoResolver {
    fn resolve(
        &self,
        origin: Option<&ConfigOrigin>,
        path: &str,
    ) -> Result<ResolvedConfig, ResolverError> {
        Err(ResolverError::new(
            path,
            display_origin(origin),
            "external configuration I/O is disabled",
        ))
    }
}

/// Explicit filesystem-backed resolver.
#[derive(Clone, Debug, Default)]
pub struct FileSystemResolver {
    base_directory: Option<PathBuf>,
}

impl FileSystemResolver {
    /// Creates a filesystem resolver rooted at the process working directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a filesystem resolver with an explicit fallback base directory.
    #[must_use]
    pub fn with_base_directory(path: impl Into<PathBuf>) -> Self {
        Self {
            base_directory: Some(path.into()),
        }
    }

    fn resolve_path(&self, origin: Option<&ConfigOrigin>, requested: &Path) -> PathBuf {
        if requested.is_absolute() {
            return requested.to_owned();
        }
        match origin {
            Some(ConfigOrigin::Path(path)) => path
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .join(requested),
            _ => self
                .base_directory
                .as_deref()
                .unwrap_or_else(|| Path::new(""))
                .join(requested),
        }
    }
}

impl ConfigResolver for FileSystemResolver {
    fn resolve(
        &self,
        origin: Option<&ConfigOrigin>,
        path: &str,
    ) -> Result<ResolvedConfig, ResolverError> {
        let resolved_path = self.resolve_path(origin, Path::new(path));
        let contents = fs::read_to_string(&resolved_path)
            .map_err(|error| ResolverError::new(path, display_origin(origin), error.to_string()))?;
        Ok(ResolvedConfig::new(
            contents,
            ConfigOrigin::Path(resolved_path),
        ))
    }
}

/// Deterministic in-memory resolver suitable for embedders and tests.
#[derive(Clone, Debug, Default)]
pub struct VirtualResolver {
    files: BTreeMap<String, String>,
}

impl VirtualResolver {
    /// Creates an empty virtual resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one virtual file and returns the resolver.
    ///
    /// The path is normalized to the resolver's stable `/`-separated grammar.
    #[must_use]
    pub fn with_file(mut self, path: impl Into<String>, contents: impl Into<String>) -> Self {
        self.files
            .insert(normalize_virtual_path(&path.into()), contents.into());
        self
    }

    /// Adds or replaces one virtual file after stable path normalization.
    pub fn insert(&mut self, path: impl Into<String>, contents: impl Into<String>) {
        self.files
            .insert(normalize_virtual_path(&path.into()), contents.into());
    }

    fn candidates(origin: Option<&ConfigOrigin>, path: &str) -> Vec<String> {
        let mut candidates = Vec::new();
        if let Some(ConfigOrigin::Virtual(origin)) = origin {
            let origin = normalize_virtual_path(origin);
            let parent = origin.rsplit_once('/').map_or("", |(parent, _)| parent);
            let joined = if virtual_path_is_absolute(path) || parent.is_empty() {
                normalize_virtual_path(path)
            } else {
                normalize_virtual_path(&format!("{parent}/{path}"))
            };
            candidates.push(joined);
        }
        let normalized = normalize_virtual_path(path);
        if !candidates.iter().any(|candidate| candidate == &normalized) {
            candidates.push(normalized);
        }
        candidates
    }
}

fn virtual_path_is_absolute(path: &str) -> bool {
    let path = path.replace('\\', "/");
    path.starts_with('/')
        || path
            .as_bytes()
            .get(..3)
            .is_some_and(|prefix| prefix[0].is_ascii_alphabetic() && &prefix[1..] == b":/")
}

fn normalize_virtual_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let absolute = virtual_path_is_absolute(&path);
    let unc = path.starts_with("//") && !path.starts_with("///");
    let prefix = if path
        .as_bytes()
        .get(..2)
        .is_some_and(|prefix| prefix[0].is_ascii_alphabetic() && prefix[1] == b':')
    {
        Some(&path[..2])
    } else {
        None
    };
    let body = prefix.map_or(path.as_str(), |prefix| &path[prefix.len()..]);
    let mut components = Vec::new();
    let protected_components = if unc { 2 } else { 0 };
    for component in body.split('/') {
        match component {
            ".." if components.len() > protected_components
                && components.last().is_some_and(|last| *last != "..") =>
            {
                components.pop();
            }
            ".." if !absolute => components.push(component),
            "" | "." | ".." => {}
            _ => components.push(component),
        }
    }
    let joined = components.join("/");
    match (prefix, absolute, unc, joined.is_empty()) {
        (None, true, true, false) => format!("//{joined}"),
        (None, true, true, true) => "//".to_owned(),
        (Some(prefix), true, false, false) => format!("{prefix}/{joined}"),
        (Some(prefix), true, false, true) => format!("{prefix}/"),
        (None, true, false, false) => format!("/{joined}"),
        (None, true, false, true) => "/".to_owned(),
        (Some(prefix), false, false, false) => format!("{prefix}{joined}"),
        (_, _, _, _) => joined,
    }
}

impl ConfigResolver for VirtualResolver {
    fn resolve(
        &self,
        origin: Option<&ConfigOrigin>,
        path: &str,
    ) -> Result<ResolvedConfig, ResolverError> {
        for candidate in Self::candidates(origin, path) {
            if let Some(contents) = self.files.get(&candidate) {
                return Ok(ResolvedConfig::new(
                    contents.clone(),
                    ConfigOrigin::Virtual(candidate),
                ));
            }
        }
        Err(ResolverError::new(
            path,
            display_origin(origin),
            "virtual config was not found",
        ))
    }
}

/// Structured configuration loading and validation failures.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum ConfigError {
    #[error("failed to parse config{at}: {source}")]
    Parse {
        at: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to decode config{at}: {source}")]
    Decode {
        at: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to load extended config, err: {0}")]
    Resolve(#[source] ResolverError),
    #[error("failed to load extended config, err: {0}")]
    Extended(#[source] Box<ConfigError>),
    #[error("unable to load config due to extend.path and extend.useDefault being set")]
    ConflictingExtension,
    #[error("[allowlist] is deprecated, it cannot be used alongside [[allowlists]]")]
    GlobalAllowlistConflict,
    #[error(
        "{rule_id}: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]"
    )]
    RuleAllowlistConflict { rule_id: String },
    #[error("rule |id| is missing or empty{context}")]
    EmptyRuleId { context: String },
    #[error("{rule_id}: both |regex| and |path| are empty, this rule will have no effect")]
    MissingRulePattern { rule_id: String },
    #[error("{rule_id}: invalid regex secret group {group}, max regex secret group {max}")]
    InvalidSecretGroup {
        rule_id: String,
        group: i64,
        max: usize,
    },
    #[error("{rule_id}: [[rules.required]] rule ID is empty")]
    EmptyRequiredRuleId { rule_id: String },
    #[error("{rule_id}: [[rules.required]] rule ID '{required_id}' does not exist")]
    MissingRequiredRuleId {
        rule_id: String,
        required_id: String,
    },
    #[error("{scope} must contain at least one check for: commits, paths, regexes, or stopwords")]
    EmptyAllowlist { scope: String },
    #[error("{scope} unknown allowlist |condition| '{value}' (expected 'and', 'or')")]
    InvalidAllowlistCondition { scope: String, value: String },
    #[error("{scope} unknown allowlist |regexTarget| '{value}' (expected 'match', 'line')")]
    InvalidRegexTarget { scope: String, value: String },
    #[error("{scope} invalid {field} pattern '{pattern}': {message}")]
    InvalidPattern {
        scope: String,
        field: &'static str,
        pattern: String,
        message: String,
    },
    #[error("[[allowlists]] target rule ID '{rule_id}' does not exist")]
    MissingTargetRuleId { rule_id: String },
    #[error("invalid minVersion '{value}': {message}")]
    InvalidMinVersion { value: String, message: String },
}

/// Reentrant configuration loader. It owns no mutable process-global state.
#[derive(Clone)]
pub struct ConfigLoader {
    resolver: Arc<dyn ConfigResolver>,
    default_config: Arc<str>,
    current_version: Option<Version>,
}

impl fmt::Debug for ConfigLoader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigLoader")
            .field("default_config_len", &self.default_config.len())
            .field("current_version", &self.current_version)
            .finish_non_exhaustive()
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigLoader {
    /// Creates a no-I/O loader using the pinned embedded default.
    #[must_use]
    pub fn new() -> Self {
        Self {
            resolver: Arc::new(NoIoResolver),
            default_config: Arc::from(DEFAULT_CONFIG),
            current_version: None,
        }
    }

    /// Replaces the injected extension resolver.
    #[must_use]
    pub fn with_resolver(mut self, resolver: impl ConfigResolver + 'static) -> Self {
        self.resolver = Arc::new(resolver);
        self
    }

    /// Replaces the text used by `extend.useDefault` and [`Self::load_default`].
    #[must_use]
    pub fn with_default_config(mut self, contents: impl Into<Arc<str>>) -> Self {
        self.default_config = contents.into();
        self
    }

    /// Configures a current version for advisory `minVersion` comparison.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidMinVersion`] for invalid semantic versions.
    pub fn with_current_version(mut self, version: &str) -> Result<Self, ConfigError> {
        self.current_version = Some(parse_version(version)?);
        Ok(self)
    }

    /// Decodes permissive, case-insensitive raw TOML without compiling it.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Parse`] for malformed TOML and
    /// [`ConfigError::Decode`] for incompatible weakly decoded values.
    pub fn parse_toml(
        &self,
        contents: &str,
        origin: Option<&ConfigOrigin>,
    ) -> Result<RawConfig, ConfigError> {
        let mut value =
            toml::from_str::<toml::Value>(contents).map_err(|source| ConfigError::Parse {
                at: origin_suffix(origin),
                source,
            })?;
        normalize_table_keys(&mut value);
        normalize_weak_types(&mut value);
        value.try_into().map_err(|source| ConfigError::Decode {
            at: origin_suffix(origin),
            source,
        })
    }

    /// Parses and compiles in-memory TOML without a source origin.
    ///
    /// # Errors
    ///
    /// Returns a structured parse, resolution, or validation error.
    pub fn load_toml(&self, contents: &str) -> Result<CompiledConfig, ConfigError> {
        self.load_toml_at(contents, None)
    }

    /// Parses and compiles TOML with an origin for relative extension paths.
    ///
    /// # Errors
    ///
    /// Returns a structured parse, resolution, or validation error.
    pub fn load_toml_at(
        &self,
        contents: &str,
        origin: Option<ConfigOrigin>,
    ) -> Result<CompiledConfig, ConfigError> {
        let raw = self.parse_toml(contents, origin.as_ref())?;
        self.compile_at(raw, origin)
    }

    /// Compiles a programmatically constructed raw configuration.
    ///
    /// # Errors
    ///
    /// Returns a structured resolution or validation error.
    pub fn compile(&self, raw: RawConfig) -> Result<CompiledConfig, ConfigError> {
        self.compile_at(raw, None)
    }

    /// Compiles a raw configuration with an explicit origin.
    ///
    /// # Errors
    ///
    /// Returns a structured resolution or validation error.
    pub fn compile_at(
        &self,
        raw: RawConfig,
        origin: Option<ConfigOrigin>,
    ) -> Result<CompiledConfig, ConfigError> {
        let mut config = self.compile_level(raw, origin, 0)?;
        validate_effective_rules(&config.rules)?;
        attach_targeted_allowlists(&mut config)?;
        Ok(config)
    }

    /// Loads and compiles the configured embedded-default text.
    ///
    /// # Errors
    ///
    /// Returns a structured parse or validation error.
    pub fn load_default(&self) -> Result<CompiledConfig, ConfigError> {
        self.load_toml_at(&self.default_config, Some(ConfigOrigin::EmbeddedDefault))
    }

    /// Resolves and loads a top-level path through the injected resolver.
    ///
    /// # Errors
    ///
    /// Returns a structured resolution, parse, or validation error.
    pub fn load_resolved(&self, path: &str) -> Result<CompiledConfig, ConfigError> {
        let resolved = self
            .resolver
            .resolve(None, path)
            .map_err(ConfigError::Resolve)?;
        self.load_toml_at(&resolved.contents, Some(resolved.origin))
    }

    fn compile_level(
        &self,
        raw: RawConfig,
        origin: Option<ConfigOrigin>,
        depth: usize,
    ) -> Result<CompiledConfig, ConfigError> {
        let mut config = self.compile_local(raw, origin)?;
        if depth < MAX_EXTEND_DEPTH {
            if !config.extension.path.is_empty() && config.extension.use_default {
                return Err(ConfigError::ConflictingExtension);
            }
            let base = if config.extension.use_default {
                let raw = self
                    .parse_toml(&self.default_config, Some(&ConfigOrigin::EmbeddedDefault))
                    .map_err(|error| ConfigError::Extended(Box::new(error)))?;
                Some(
                    self.compile_level(raw, Some(ConfigOrigin::EmbeddedDefault), depth + 1)
                        .map_err(|error| ConfigError::Extended(Box::new(error)))?,
                )
            } else if !config.extension.path.is_empty() {
                let resolved = self
                    .resolver
                    .resolve(config.origin.as_ref(), &config.extension.path)
                    .map_err(ConfigError::Resolve)?;
                let raw = self
                    .parse_toml(&resolved.contents, Some(&resolved.origin))
                    .map_err(|error| ConfigError::Extended(Box::new(error)))?;
                Some(
                    self.compile_level(raw, Some(resolved.origin), depth + 1)
                        .map_err(|error| ConfigError::Extended(Box::new(error)))?,
                )
            } else {
                None
            };
            if let Some(base) = base {
                merge_extension(&mut config, base);
            }
        }
        Ok(config)
    }

    fn compile_local(
        &self,
        mut raw: RawConfig,
        origin: Option<ConfigOrigin>,
    ) -> Result<CompiledConfig, ConfigError> {
        if raw.allowlist.is_some() && !raw.allowlists.is_empty() {
            return Err(ConfigError::GlobalAllowlistConflict);
        }
        if let Some(allowlist) = raw.allowlist.take() {
            raw.allowlists.push(allowlist);
        }

        // The pinned Go oracle is a development build and skips parsing
        // minVersion entirely. Supplying `current_version` opts into the
        // release-build parse/advisory branch.
        let requires_newer_version = if raw.min_version.is_empty() {
            false
        } else if let Some(current) = &self.current_version {
            current < &parse_version(&raw.min_version)?
        } else {
            false
        };

        let mut rules = BTreeMap::new();
        let mut keywords = BTreeSet::new();
        let mut ordered_rule_ids = Vec::with_capacity(raw.rules.len());
        for rule in raw.rules {
            let compiled = compile_rule(rule)?;
            keywords.extend(compiled.keywords.iter().cloned());
            ordered_rule_ids.push(compiled.id.clone());
            rules.insert(compiled.id.clone(), compiled);
        }
        validate_required_ids(&rules)?;

        let mut allowlists = Vec::new();
        let mut targeted_allowlists = Vec::new();
        for raw_allowlist in raw.allowlists {
            compile_global_allowlist(raw_allowlist, &mut allowlists, &mut targeted_allowlists)?;
        }

        let config = CompiledConfig {
            title: raw.title,
            description: raw.description,
            extension: raw.extend,
            origin,
            rules,
            ordered_rule_ids,
            keywords,
            allowlists,
            min_version: raw.min_version,
            requires_newer_version,
            targeted_allowlists,
        };
        Ok(config)
    }
}

fn compile_rule(mut rule: RuleSpec) -> Result<CompiledRule, ConfigError> {
    if rule.allowlist.is_some() && !rule.allowlists.is_empty() {
        return Err(ConfigError::RuleAllowlistConflict {
            rule_id: rule.id.clone(),
        });
    }
    if let Some(allowlist) = rule.allowlist.take() {
        rule.allowlists.push(allowlist);
    }

    let mut allowlists = Vec::with_capacity(rule.allowlists.len());
    for allowlist in rule.allowlists {
        let scope = format!("{}: [[rules.allowlists]]", rule.id);
        allowlists.push(compile_allowlist(allowlist, &scope)?);
    }

    for required in &rule.required {
        if required.id.is_empty() {
            return Err(ConfigError::EmptyRequiredRuleId {
                rule_id: rule.id.clone(),
            });
        }
    }

    let (path, path_matcher) = nonempty_pattern(rule.path, &rule.id, "path")?;
    let (regex, regex_matcher) = if rule.regex.is_empty() {
        (None, None)
    } else {
        let compiled =
            GoRegex::compile(&rule.regex).map_err(|error| ConfigError::InvalidPattern {
                scope: rule.id.clone(),
                field: "regex",
                pattern: rule.regex.clone(),
                message: error.to_string(),
            })?;
        (Some(rule.regex), Some(compiled))
    };

    Ok(CompiledRule {
        id: rule.id,
        description: rule.description,
        path,
        regex,
        path_matcher,
        regex_matcher,
        secret_group: rule.secret_group,
        entropy: rule.entropy,
        keywords: rule
            .keywords
            .into_iter()
            .map(|keyword| go_lowercase(&keyword))
            .collect(),
        tags: rule.tags,
        allowlists,
        required: rule.required,
        skip_report: rule.skip_report,
    })
}

fn compile_global_allowlist(
    raw: RawGlobalAllowlist,
    global: &mut Vec<CompiledAllowlist>,
    targeted: &mut Vec<(Vec<String>, CompiledAllowlist)>,
) -> Result<(), ConfigError> {
    let allowlist = compile_allowlist(raw.allowlist, "[[allowlists]]")?;
    if raw.target_rules.is_empty() {
        global.push(allowlist);
    } else {
        targeted.push((raw.target_rules, allowlist));
    }
    Ok(())
}

fn compile_allowlist(raw: AllowlistSpec, scope: &str) -> Result<CompiledAllowlist, ConfigError> {
    let condition = match raw.condition {
        Condition::Unknown(value) => {
            return Err(ConfigError::InvalidAllowlistCondition {
                scope: scope.to_owned(),
                value,
            });
        }
        condition => condition,
    };
    let regex_target = match raw.regex_target {
        RegexTarget::Unknown(value) => {
            return Err(ConfigError::InvalidRegexTarget {
                scope: scope.to_owned(),
                value,
            });
        }
        target => target,
    };
    if raw.commits.is_empty()
        && raw.paths.is_empty()
        && raw.regexes.is_empty()
        && raw.stop_words.is_empty()
    {
        return Err(ConfigError::EmptyAllowlist {
            scope: scope.to_owned(),
        });
    }
    for pattern in &raw.paths {
        validate_pattern(pattern).map_err(|message| ConfigError::InvalidPattern {
            scope: scope.to_owned(),
            field: "path",
            pattern: pattern.clone(),
            message,
        })?;
    }
    for pattern in &raw.regexes {
        validate_pattern(pattern).map_err(|message| ConfigError::InvalidPattern {
            scope: scope.to_owned(),
            field: "regex",
            pattern: pattern.clone(),
            message,
        })?;
    }
    let path_matcher = compile_joined_allowlist_patterns(&raw.paths, scope, "path")?;
    let regex_matcher = compile_joined_allowlist_patterns(&raw.regexes, scope, "regex")?;
    let normalized_stop_words = raw
        .stop_words
        .into_iter()
        .map(|word| go_lowercase(&word))
        .collect::<BTreeSet<_>>();
    let nonempty_stop_words = normalized_stop_words
        .iter()
        .filter(|word| !word.is_empty())
        .map(String::as_str)
        .collect::<Vec<_>>();
    let stopword_matcher = if nonempty_stop_words.is_empty() {
        None
    } else {
        Some(
            AhoCorasickBuilder::new()
                .match_kind(MatchKind::Standard)
                .build(nonempty_stop_words)
                .map_err(|error| ConfigError::InvalidPattern {
                    scope: scope.to_owned(),
                    field: "stopword",
                    pattern: "<normalized stopwords>".to_owned(),
                    message: error.to_string(),
                })?,
        )
    };
    Ok(CompiledAllowlist {
        description: raw.description,
        condition,
        commits: raw
            .commits
            .into_iter()
            .map(|commit| go_lowercase(commit.trim()))
            .collect(),
        paths: raw.paths,
        regex_target,
        regexes: raw.regexes,
        stop_words: normalized_stop_words,
        path_matcher,
        regex_matcher,
        stopword_matcher,
    })
}

fn compile_joined_allowlist_patterns(
    patterns: &[String],
    scope: &str,
    field: &'static str,
) -> Result<Option<GoRegex>, ConfigError> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut joined = String::from("(?:");
    for (index, pattern) in patterns.iter().enumerate() {
        if index != 0 {
            joined.push('|');
        }
        joined.push_str(pattern);
    }
    joined.push(')');
    GoRegex::compile(&joined)
        .map(Some)
        .map_err(|error| ConfigError::InvalidPattern {
            scope: scope.to_owned(),
            field,
            pattern: joined,
            message: error.to_string(),
        })
}

fn nonempty_pattern(
    pattern: String,
    scope: &str,
    field: &'static str,
) -> Result<(Option<String>, Option<GoRegex>), ConfigError> {
    if pattern.is_empty() {
        return Ok((None, None));
    }
    let compiled = GoRegex::compile(&pattern).map_err(|error| ConfigError::InvalidPattern {
        scope: scope.to_owned(),
        field,
        pattern: pattern.clone(),
        message: error.to_string(),
    })?;
    Ok((Some(pattern), Some(compiled)))
}

fn validate_effective_rules(rules: &BTreeMap<String, CompiledRule>) -> Result<(), ConfigError> {
    for rule in rules.values() {
        if rule.id.trim().is_empty() {
            let mut context = String::new();
            if !rule.description.is_empty() {
                context.push_str(", description: ");
                context.push_str(&rule.description);
            }
            if let Some(regex) = &rule.regex {
                context.push_str(", regex: ");
                context.push_str(regex);
            }
            if let Some(path) = &rule.path {
                context.push_str(", path: ");
                context.push_str(path);
            }
            return Err(ConfigError::EmptyRuleId { context });
        }
        if rule.regex.is_none() && rule.path.is_none() {
            return Err(ConfigError::MissingRulePattern {
                rule_id: rule.id.clone(),
            });
        }
        if let Some(regex) = &rule.regex {
            let captures =
                validate_pattern(regex).map_err(|message| ConfigError::InvalidPattern {
                    scope: rule.id.clone(),
                    field: "regex",
                    pattern: regex.clone(),
                    message,
                })?;
            if rule.secret_group > i64::try_from(captures).unwrap_or(i64::MAX) {
                return Err(ConfigError::InvalidSecretGroup {
                    rule_id: rule.id.clone(),
                    group: rule.secret_group,
                    max: captures,
                });
            }
        }
    }
    Ok(())
}

fn validate_required_ids(rules: &BTreeMap<String, CompiledRule>) -> Result<(), ConfigError> {
    for rule in rules.values() {
        for required in &rule.required {
            if !rules.contains_key(&required.id) {
                return Err(ConfigError::MissingRequiredRuleId {
                    rule_id: rule.id.clone(),
                    required_id: required.id.clone(),
                });
            }
        }
    }
    Ok(())
}

fn attach_targeted_allowlists(config: &mut CompiledConfig) -> Result<(), ConfigError> {
    for (ids, allowlist) in std::mem::take(&mut config.targeted_allowlists) {
        for id in ids {
            let rule =
                config
                    .rules
                    .get_mut(&id)
                    .ok_or_else(|| ConfigError::MissingTargetRuleId {
                        rule_id: id.clone(),
                    })?;
            rule.allowlists.push(allowlist.clone());
        }
    }
    Ok(())
}

fn merge_extension(current: &mut CompiledConfig, mut base: CompiledConfig) {
    let disabled: BTreeSet<&str> = current
        .extension
        .disabled_rules
        .iter()
        .map(String::as_str)
        .collect();
    for (id, mut base_rule) in std::mem::take(&mut base.rules) {
        if disabled.contains(id.as_str()) {
            continue;
        }
        if let Some(current_rule) = current.rules.remove(&id) {
            if !current_rule.description.is_empty() {
                base_rule.description = current_rule.description;
            }
            if current_rule.entropy != 0.0 {
                base_rule.entropy = current_rule.entropy;
            }
            if current_rule.secret_group != 0 {
                base_rule.secret_group = current_rule.secret_group;
            }
            if current_rule.regex.is_some() {
                base_rule.regex = current_rule.regex;
                base_rule.regex_matcher = current_rule.regex_matcher;
            }
            if current_rule.path.is_some() {
                base_rule.path = current_rule.path;
                base_rule.path_matcher = current_rule.path_matcher;
            }
            base_rule.tags.extend(current_rule.tags);
            base_rule.keywords.extend(current_rule.keywords);
            base_rule.allowlists.extend(current_rule.allowlists);
            current.keywords.extend(base_rule.keywords.iter().cloned());
            current.rules.insert(id, base_rule);
        } else {
            current.ordered_rule_ids.push(id.clone());
            current.keywords.extend(base_rule.keywords.iter().cloned());
            current.rules.insert(id, base_rule);
        }
    }
    current.allowlists.extend(base.allowlists);
    current.ordered_rule_ids.sort_unstable();
}

fn parse_version(value: &str) -> Result<Version, ConfigError> {
    Version::parse(value.strip_prefix('v').unwrap_or(value)).map_err(|error| {
        ConfigError::InvalidMinVersion {
            value: value.to_owned(),
            message: error.to_string(),
        }
    })
}

fn go_lowercase(value: &str) -> String {
    crate::go_unicode::lowercase(value)
}

fn validate_pattern(pattern: &str) -> Result<usize, String> {
    GoRegex::compile(pattern)
        .map(|compiled| compiled.capture_count())
        .map_err(|error| error.to_string())
}

fn normalize_table_keys(value: &mut toml::Value) {
    match value {
        toml::Value::Table(table) => {
            let old = std::mem::take(table);
            for (key, mut value) in old {
                normalize_table_keys(&mut value);
                table.insert(key.to_ascii_lowercase(), value);
            }
        }
        toml::Value::Array(values) => {
            for value in values {
                normalize_table_keys(value);
            }
        }
        _ => {}
    }
}

fn normalize_weak_types(value: &mut toml::Value) {
    let toml::Value::Table(table) = value else {
        return;
    };
    for (key, value) in table.iter_mut() {
        match value {
            toml::Value::Table(_) => normalize_weak_types(value),
            toml::Value::Array(values) => {
                for element in values {
                    normalize_weak_types(element);
                }
            }
            _ => {}
        }
        match key.as_str() {
            "title" | "description" | "minversion" | "path" | "url" | "id" | "regex"
            | "condition" | "regextarget" => weak_string(value),
            "disabledrules" | "keywords" | "tags" | "commits" | "paths" | "regexes"
            | "stopwords" | "targetrules" => weak_string_slice(value),
            "secretgroup" | "withinlines" | "withincolumns" => weak_integer(value),
            "entropy" => weak_float(value),
            "usedefault" | "skipreport" => weak_bool(value),
            "rules" | "allowlists" | "required" => weak_struct_slice(value),
            "extend" | "allowlist" => require_weak_struct(value),
            _ => {}
        }
    }
}

fn weak_string(value: &mut toml::Value) {
    let converted = match value {
        toml::Value::Boolean(value) => Some(if *value { "1" } else { "0" }.to_owned()),
        toml::Value::Integer(value) => Some(value.to_string()),
        toml::Value::Float(value) => Some(format_weak_float(*value)),
        _ => None,
    };
    if let Some(converted) = converted {
        *value = toml::Value::String(converted);
    }
}

fn weak_string_slice(value: &mut toml::Value) {
    if matches!(value, toml::Value::Table(table) if table.is_empty()) {
        *value = toml::Value::Array(Vec::new());
        return;
    }
    if let toml::Value::String(string) = value {
        let values = if string.is_empty() {
            Vec::new()
        } else {
            string
                .split(',')
                .map(|part| toml::Value::String(part.to_owned()))
                .collect()
        };
        *value = toml::Value::Array(values);
        return;
    }
    if !matches!(value, toml::Value::Array(_)) {
        let scalar = std::mem::replace(value, toml::Value::Array(Vec::new()));
        *value = toml::Value::Array(vec![scalar]);
    }
    if let toml::Value::Array(values) = value {
        for element in values {
            weak_string(element);
        }
    }
}

#[allow(clippy::cast_possible_truncation)] // Viper weak decoding truncates float64 toward zero.
fn weak_integer(value: &mut toml::Value) {
    let converted = match value {
        toml::Value::Float(value) => Some(*value as i64),
        toml::Value::Boolean(value) => Some(i64::from(*value)),
        toml::Value::String(value) => parse_weak_integer(value),
        _ => None,
    };
    if let Some(converted) = converted {
        *value = toml::Value::Integer(converted);
    }
}

fn parse_weak_integer(value: &str) -> Option<i64> {
    if value.is_empty() {
        return Some(0);
    }
    let (negative, unsigned) = if let Some(rest) = value.strip_prefix('-') {
        (true, rest)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    let (radix, digits, prefix_underscore) = if let Some(digits) = unsigned.strip_prefix("0x") {
        (16, digits, true)
    } else if let Some(digits) = unsigned.strip_prefix("0X") {
        (16, digits, true)
    } else if let Some(digits) = unsigned.strip_prefix("0o") {
        (8, digits, true)
    } else if let Some(digits) = unsigned.strip_prefix("0O") {
        (8, digits, true)
    } else if let Some(digits) = unsigned.strip_prefix("0b") {
        (2, digits, true)
    } else if let Some(digits) = unsigned.strip_prefix("0B") {
        (2, digits, true)
    } else if unsigned.starts_with('0') && unsigned.len() > 1 {
        (8, unsigned, false)
    } else {
        (10, unsigned, false)
    };
    let digits = clean_integer_digits(digits, radix, prefix_underscore)?;
    let magnitude = u64::from_str_radix(&digits, radix).ok()?;
    if negative {
        if magnitude == (1_u64 << 63) {
            Some(i64::MIN)
        } else {
            i64::try_from(magnitude).ok()?.checked_neg()
        }
    } else {
        i64::try_from(magnitude).ok()
    }
}

fn clean_integer_digits(value: &str, radix: u32, prefix_underscore: bool) -> Option<String> {
    let bytes = value.as_bytes();
    let mut cleaned = String::with_capacity(value.len());
    for (index, character) in value.char_indices() {
        if character == '_' {
            let previous_is_digit = index > 0
                && value[..index]
                    .chars()
                    .next_back()
                    .is_some_and(|candidate| candidate.is_digit(radix));
            let next_is_digit = bytes
                .get(index + 1)
                .copied()
                .map(char::from)
                .is_some_and(|candidate| candidate.is_digit(radix));
            if !(next_is_digit && (previous_is_digit || (prefix_underscore && index == 0))) {
                return None;
            }
        } else if character.is_digit(radix) {
            cleaned.push(character);
        } else {
            return None;
        }
    }
    (!cleaned.is_empty()).then_some(cleaned)
}

#[allow(clippy::cast_precision_loss)] // Viper weak decoding converts signed integers to float64.
fn weak_float(value: &mut toml::Value) {
    let converted = match value {
        toml::Value::Float(value) if value.is_nan() => Some(go_nan()),
        toml::Value::Integer(value) => Some(*value as f64),
        toml::Value::Boolean(value) => Some(if *value { 1.0 } else { 0.0 }),
        toml::Value::String(value) => parse_weak_float(value),
        _ => None,
    };
    if let Some(converted) = converted {
        *value = toml::Value::Float(converted);
    }
}

fn parse_weak_float(value: &str) -> Option<f64> {
    if value.is_empty() {
        return Some(0.0);
    }
    let (negative, signed, unsigned) = if let Some(rest) = value.strip_prefix('-') {
        (true, true, rest)
    } else if let Some(rest) = value.strip_prefix('+') {
        (false, true, rest)
    } else {
        (false, false, value)
    };
    match unsigned.to_ascii_lowercase().as_str() {
        "nan" => return (!signed).then_some(go_nan()),
        "inf" | "infinity" => {
            return Some(if negative {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            });
        }
        _ => {}
    }

    let parsed = if unsigned.starts_with("0x") || unsigned.starts_with("0X") {
        parse_hex_float(unsigned)?
    } else {
        parse_go_decimal_float(unsigned)?
    };
    let parsed = if negative { -parsed } else { parsed };
    if parsed.is_infinite() {
        None
    } else {
        Some(parsed)
    }
}

fn parse_hex_float(value: &str) -> Option<f64> {
    fn consume_digit(
        digit: u32,
        significand: &mut u64,
        significant_digits: &mut i64,
        stored_digits: &mut i64,
        binary_point: &mut i64,
        truncated: &mut bool,
    ) {
        if digit == 0 && *significant_digits == 0 {
            *binary_point = binary_point.saturating_sub(1);
            return;
        }
        *significant_digits = significant_digits.saturating_add(1);
        if *stored_digits < 16 {
            *significand = significand.wrapping_mul(16).wrapping_add(u64::from(digit));
            *stored_digits += 1;
        } else if digit != 0 {
            *truncated = true;
        }
    }

    let unsigned = value.get(2..)?;
    let (mantissa, exponent) = unsigned.split_once(['p', 'P'])?;
    if exponent.contains(['p', 'P']) {
        return None;
    }
    let mantissa = clean_float_underscores(mantissa, 16, true)?;
    let (integer, fraction) = mantissa.split_once('.').unwrap_or((&mantissa, ""));
    if integer.is_empty() && fraction.is_empty() {
        return None;
    }
    let explicit_exponent = parse_capped_go_exponent(exponent)?;
    let mut significand = 0_u64;
    let mut significant_digits = 0_i64;
    let mut stored_digits = 0_i64;
    let mut binary_point = 0_i64;
    let mut truncated = false;

    for digit in integer.chars() {
        consume_digit(
            digit.to_digit(16)?,
            &mut significand,
            &mut significant_digits,
            &mut stored_digits,
            &mut binary_point,
            &mut truncated,
        );
    }
    if mantissa.contains('.') {
        binary_point = significant_digits;
    }
    for digit in fraction.chars() {
        consume_digit(
            digit.to_digit(16)?,
            &mut significand,
            &mut significant_digits,
            &mut stored_digits,
            &mut binary_point,
            &mut truncated,
        );
    }
    if !mantissa.contains('.') {
        binary_point = significant_digits;
    }
    binary_point = binary_point
        .saturating_mul(4)
        .saturating_add(explicit_exponent);
    stored_digits = stored_digits.saturating_mul(4);
    let exponent = if significand == 0 {
        0
    } else {
        binary_point.saturating_sub(stored_digits)
    };
    go_atof_hex(significand, exponent, truncated)
}

fn parse_capped_go_exponent(value: &str) -> Option<i64> {
    let (negative, unsigned) = if let Some(rest) = value.strip_prefix('-') {
        (true, rest)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    let digits = clean_integer_digits(unsigned, 10, false)?;
    let mut exponent = 0_i64;
    for digit in digits.bytes() {
        if exponent < 10_000 {
            exponent = exponent * 10 + i64::from(digit - b'0');
        }
    }
    Some(if negative { -exponent } else { exponent })
}

fn parse_go_decimal_float(value: &str) -> Option<f64> {
    const STORED_DIGITS: usize = 800;

    let cleaned = clean_float_underscores(value, 10, false)?;
    let (mantissa, explicit_exponent) = match cleaned.find(['e', 'E']) {
        Some(index) => {
            let mantissa = &cleaned[..index];
            let exponent = &cleaned[index + 1..];
            if exponent.contains(['e', 'E']) {
                return None;
            }
            (mantissa, parse_capped_go_exponent(exponent)?)
        }
        None => (cleaned.as_str(), 0),
    };

    let mut digits = String::with_capacity(STORED_DIGITS + 1);
    let mut decimal_point = 0_i64;
    let mut total_digits = 0_i64;
    let mut fast_decimal_point = 0_i64;
    let mut fast_mantissa = 0_u64;
    let mut fast_digits = 0_i64;
    let mut fast_truncated = false;
    let mut saw_dot = false;
    let mut saw_digit = false;
    let mut truncated = false;
    for byte in mantissa.bytes() {
        match byte {
            b'.' if !saw_dot => {
                saw_dot = true;
                decimal_point = i64::try_from(digits.len()).ok()?;
                fast_decimal_point = total_digits;
            }
            b'0'..=b'9' => {
                saw_digit = true;
                if byte == b'0' && digits.is_empty() {
                    decimal_point = decimal_point.saturating_sub(1);
                    fast_decimal_point = fast_decimal_point.saturating_sub(1);
                } else if digits.len() < STORED_DIGITS {
                    digits.push(char::from(byte));
                } else if byte != b'0' {
                    truncated = true;
                }
                if byte != b'0' || total_digits != 0 {
                    total_digits = total_digits.saturating_add(1);
                    if fast_digits < 19 {
                        fast_mantissa = fast_mantissa
                            .saturating_mul(10)
                            .saturating_add(u64::from(byte - b'0'));
                        fast_digits += 1;
                    } else if byte != b'0' {
                        fast_truncated = true;
                    }
                }
            }
            _ => return None,
        }
    }
    if !saw_digit {
        return None;
    }
    if !saw_dot {
        decimal_point = i64::try_from(digits.len()).ok()?;
        fast_decimal_point = total_digits;
    }
    decimal_point = decimal_point.saturating_add(explicit_exponent);
    fast_decimal_point = fast_decimal_point.saturating_add(explicit_exponent);

    if digits.is_empty() {
        return Some(0.0);
    }
    let fast_exponent = fast_decimal_point.saturating_sub(fast_digits);
    if let Some(lower) = super::eisel_lemire::parse_64(fast_mantissa, fast_exponent) {
        if !fast_truncated {
            return Some(lower);
        }
        if let Some(upper) = super::eisel_lemire::parse_64(fast_mantissa + 1, fast_exponent) {
            if lower.to_bits() == upper.to_bits() {
                return Some(lower);
            }
        }
    }
    if truncated {
        // Go retains only whether the discarded tail was nonzero. A one in the
        // next decimal place represents the same directed sticky remainder for
        // binary64 rounding after 800 retained digits.
        digits.push('1');
    }
    let exponent = decimal_point.saturating_sub(i64::try_from(digits.len()).ok()?);
    let bounded = format!("{digits}e{exponent}");
    let parsed = bounded.parse::<f64>().ok()?;
    (!parsed.is_infinite()).then_some(parsed)
}

fn go_atof_hex(mut significand: u64, mut exponent: i64, truncated: bool) -> Option<f64> {
    const MANTISSA_BITS: u32 = 52;
    const BIAS: i64 = -1023;
    const MIN_EXPONENT: i64 = BIAS + 1;
    const MAX_EXPONENT: i64 = (1_i64 << 11) + BIAS - 2;

    exponent = exponent.saturating_add(i64::from(MANTISSA_BITS));
    while significand != 0 && significand >> (MANTISSA_BITS + 2) == 0 {
        significand <<= 1;
        exponent = exponent.saturating_sub(1);
    }
    if truncated {
        significand |= 1;
    }
    while significand >> (1 + MANTISSA_BITS + 2) != 0 {
        significand = (significand >> 1) | (significand & 1);
        exponent = exponent.saturating_add(1);
    }
    while significand > 1 && exponent < MIN_EXPONENT - 2 {
        significand = (significand >> 1) | (significand & 1);
        exponent = exponent.saturating_add(1);
    }

    let mut round = significand & 3;
    significand >>= 2;
    round |= significand & 1;
    exponent = exponent.saturating_add(2);
    if round == 3 {
        significand += 1;
        if significand == 1 << (1 + MANTISSA_BITS) {
            significand >>= 1;
            exponent = exponent.saturating_add(1);
        }
    }
    if significand >> MANTISSA_BITS == 0 {
        exponent = BIAS;
    }
    if exponent > MAX_EXPONENT {
        return None;
    }
    let fraction = significand & ((1 << MANTISSA_BITS) - 1);
    let exponent_bits = u64::try_from(exponent - BIAS).ok()? & ((1 << 11) - 1);
    Some(f64::from_bits(fraction | (exponent_bits << MANTISSA_BITS)))
}

fn clean_float_underscores(
    value: &str,
    radix: u32,
    allow_prefix_underscore: bool,
) -> Option<String> {
    let mut cleaned = String::with_capacity(value.len());
    let characters = value.chars().collect::<Vec<_>>();
    for (index, character) in characters.iter().copied().enumerate() {
        if character == '_' {
            let previous_is_digit = index > 0 && characters[index - 1].is_digit(radix);
            let next_is_digit = characters
                .get(index + 1)
                .is_some_and(|candidate| candidate.is_digit(radix));
            if !(next_is_digit && (previous_is_digit || (allow_prefix_underscore && index == 0))) {
                return None;
            }
        } else {
            cleaned.push(character);
        }
    }
    Some(cleaned)
}

fn go_nan() -> f64 {
    f64::from_bits(0x7ff8_0000_0000_0001)
}

fn format_weak_float(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_owned()
    } else if value == f64::INFINITY {
        "+Inf".to_owned()
    } else if value == f64::NEG_INFINITY {
        "-Inf".to_owned()
    } else {
        value.to_string()
    }
}

fn weak_bool(value: &mut toml::Value) {
    let converted = match value {
        toml::Value::Integer(value) => Some(*value != 0),
        toml::Value::Float(value) => Some(*value != 0.0),
        toml::Value::String(value) if value.is_empty() => Some(false),
        toml::Value::String(value) => match value.as_str() {
            "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
            "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
            _ => None,
        },
        _ => None,
    };
    if let Some(converted) = converted {
        *value = toml::Value::Boolean(converted);
    }
}

fn weak_struct_slice(value: &mut toml::Value) {
    if let toml::Value::Table(table) = value {
        *value = if table.is_empty() {
            toml::Value::Array(Vec::new())
        } else {
            toml::Value::Array(vec![toml::Value::Table(std::mem::take(table))])
        };
    }
}

fn require_weak_struct(value: &mut toml::Value) {
    if matches!(value, toml::Value::Array(_)) {
        // Serde permits sequences for structs and an empty sequence can therefore
        // become a default-valued struct. Viper's weak decoder requires a map for
        // these singular struct destinations, so force the ordinary type error.
        *value = toml::Value::Boolean(false);
    }
}

fn display_origin(origin: Option<&ConfigOrigin>) -> String {
    origin.map_or_else(|| "<memory>".to_owned(), ToString::to_string)
}

fn origin_suffix(origin: Option<&ConfigOrigin>) -> String {
    origin
        .map(|origin| format!(" at {origin}"))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_virtual_path, parse_weak_float, parse_weak_integer, validate_pattern,
        virtual_path_is_absolute,
    };

    #[test]
    fn go_regex_validation_counts_go_groups() {
        assert_eq!(validate_pattern(r"(?:x)(a)(?P<n>b)(?i:c)").unwrap(), 2);
        assert_eq!(validate_pattern(r"a{01}").unwrap(), 0);
        assert!(validate_pattern(r"\p{Age:3.0}").is_err());
        assert!(validate_pattern("(").is_err());
        assert!(validate_pattern("[abc").is_err());
    }

    #[test]
    fn weak_numeric_boundaries_follow_strconv() {
        assert_eq!(parse_weak_integer("-9223372036854775808"), Some(i64::MIN));
        assert_eq!(parse_weak_integer("9223372036854775807"), Some(i64::MAX));
        assert_eq!(parse_weak_integer("9223372036854775808"), None);
        assert_eq!(parse_weak_integer("0x_2"), Some(2));
        assert_eq!(parse_weak_integer("1__2"), None);

        assert_eq!(parse_weak_float("1e999"), None);
        assert_eq!(parse_weak_float("1e-999"), Some(0.0));
        let bounded_decimal = format!("1{}e-801", "0".repeat(801));
        assert_eq!(
            parse_weak_float(&bounded_decimal).unwrap().to_bits(),
            0x3f84_7ae1_47ae_147b
        );
        let certified_decimal = format!("{}e-800", "1".repeat(801));
        assert_eq!(
            parse_weak_float(&certified_decimal).unwrap().to_bits(),
            0x3ff1_c71c_71c7_1c72
        );
        assert_eq!(parse_weak_float("0x1p2"), Some(4.0));
        assert_eq!(parse_weak_float("0x1p-1074").unwrap().to_bits(), 1);
        assert_eq!(
            parse_weak_float("0x1.0000000000000800000000000001p0")
                .unwrap()
                .to_bits(),
            0x3ff0_0000_0000_0001
        );
        assert_eq!(parse_weak_float("0x0p999999999999999999999999"), Some(0.0));
        let capped_overflow = format!("0x1{}p-100000", "0".repeat(25_000));
        assert_eq!(parse_weak_float(&capped_overflow), None);
        let capped_underflow = format!("0x0.{}1p100000", "0".repeat(24_999));
        assert_eq!(parse_weak_float(&capped_underflow), Some(0.0));
        let long_negative_zero = format!("-0{}e100000", "0".repeat(200_000));
        assert_eq!(
            parse_weak_float(&long_negative_zero).unwrap().to_bits(),
            (-0.0_f64).to_bits()
        );
        assert_eq!(parse_weak_float("+inf"), Some(f64::INFINITY));
        assert_eq!(parse_weak_float("-Infinity"), Some(f64::NEG_INFINITY));
        assert_eq!(
            parse_weak_float("NaN").unwrap().to_bits(),
            0x7ff8_0000_0000_0001
        );
        assert!(parse_weak_float("-NaN").is_none());
    }

    #[test]
    fn virtual_paths_are_host_independent_and_preserve_parents() {
        assert_eq!(
            normalize_virtual_path(r"dir\sub\..\base.toml"),
            "dir/base.toml"
        );
        assert_eq!(
            normalize_virtual_path("../dir/../base.toml"),
            "../base.toml"
        );
        assert_eq!(normalize_virtual_path("../../base.toml"), "../../base.toml");
        assert_eq!(normalize_virtual_path("/../../base.toml"), "/base.toml");
        assert_eq!(normalize_virtual_path("1:/base.toml"), "1:/base.toml");
        assert!(!virtual_path_is_absolute("_:/base.toml"));
        assert!(virtual_path_is_absolute("C:/base.toml"));
        assert_eq!(
            normalize_virtual_path(r"\\server\share\dir\..\base.toml"),
            "//server/share/base.toml"
        );
    }
}
