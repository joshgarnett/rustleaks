//! Explicit native composition and additive scan metadata.
//!
//! Existing [`Engine`] construction and scans retain the pinned compatibility
//! behavior. Native composition starts from the same embedded default and
//! appends separately identified TOML packs, rejecting replacements. Identity
//! equality compares exact input bytes, including formatting, pack order and
//! extension selection. It is not a hash and makes no cryptographic claim.
//!
//! ```
//! use rustleaks_core::native::NativePolicy;
//! use rustleaks_core::explanation::ExplanationOptions;
//! use rustleaks_core::model::{Fragment, ScanOptions};
//! use rustleaks_core::{ScanBudget, ScanControl};
//!
//! let engine = NativePolicy::builder().with_pack("example-v1", r#"
//! [[rules]]
//! id = "rustleaks.example"
//! regex = '''example=([A-Z]{4})'''
//! keywords = ["example="]
//! "#)?.build()?;
//! let control = ScanControl::unlimited().with_budget(
//!     ScanBudget::unlimited().max_work_units(10_000).max_finding_records(100),
//! );
//! let result = engine.scan_fragment_controlled(
//!     &Fragment::new(b"example=ABCD"), &ScanOptions::default(), &control,
//!     ExplanationOptions::bounded(1_024),
//! );
//! assert!(result.scan().is_complete());
//! assert_eq!(result.scan().findings().len(), 1);
//! assert_eq!(result.identity(), engine.identity());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use crate::config::{
    CompiledConfig, ConfigError, ConfigExtension, ConfigLoader, DEFAULT_CONFIG,
    DEFAULT_CONFIG_SHA256, RawConfig,
};
use crate::explanation::{ExplanationLog, ExplanationOptions};
use crate::model::{Fragment, ScanOptions};
use crate::{Engine, ScanBudget, ScanControl, ScanError, ScanOutcome, UPSTREAM_REVISION};

pub(crate) mod predicate;

/// Version of native composition, identity and explanation semantics.
pub const NATIVE_POLICY_VERSION: &str = "rustleaks-native-v1";

/// Explicitly selected native pilot pack; never part of the default config.
pub const EXTRA_RULES_V1: &str = include_str!("../default/rustleaks-extra-v1.toml");

/// SHA-256 of the packaged pilot TOML, checked by the maintained generator.
pub const EXTRA_RULES_V1_SHA256: &str = include_str!("../default/rustleaks-extra-v1.sha256");

/// Explicitly selected provider rules adapted from pinned MIT Betterleaks and
/// Apache-2.0 Veles sources. This pack never changes the default configuration.
pub const PROVIDER_RULES_V1: &str = include_str!("../default/rustleaks-providers-v1.toml");

/// SHA-256 of the packaged provider TOML, checked by the maintained generator.
pub const PROVIDER_RULES_V1_SHA256: &str = include_str!("../default/rustleaks-providers-v1.sha256");

/// Explicitly selected ASCII connection-credential rules adapted from pinned
/// Apache-2.0 Kingfisher/Veles and MIT Betterleaks sources. Never in the default config.
pub const CONNECTION_RULES_V1: &str = include_str!("../default/rustleaks-connections-v1.toml");

/// SHA-256 of the packaged connection TOML, checked by the maintained generator.
pub const CONNECTION_RULES_V1_SHA256: &str =
    include_str!("../default/rustleaks-connections-v1.sha256");

/// An explicitly enabled annotation extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NativeExtension {
    /// Historical GitHub classic PAT format assessment; see the validator's
    /// documented checksum-specification limitation. Never suppresses findings.
    GithubClassicPatV1,
}

/// Exact policy identity with configuration bytes omitted from diagnostics.
///
/// Identity includes the policy and crate versions, pinned upstream/config
/// identity, ordered pack IDs and exact TOML bytes, and extension selection.
/// Equal identities imply equal configuration inputs, not equal source input,
/// scan options, budgets, or runtime results. Byte formatting changes produce
/// a different identity deliberately. This type does not serialize implicitly:
/// configurations can contain sensitive literals.
#[derive(Clone, Eq, PartialEq)]
pub struct NativePolicyIdentity {
    exact: Arc<[u8]>,
    builtin_review_reference: Option<Arc<str>>,
}

impl fmt::Debug for NativePolicyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativePolicyIdentity")
            .field("policy_version", &NATIVE_POLICY_VERSION)
            .field("encoded_bytes", &self.exact.len())
            .finish_non_exhaustive()
    }
}

impl NativePolicyIdentity {
    /// Returns an immutable, source-omitting reference for a supported builtin
    /// composition, including checked content hashes and enabled extensions.
    ///
    /// Present for the pinned base alone and exact packaged packs selected as
    /// `rustleaks-extra-v1`, `rustleaks-providers-v1` or
    /// `rustleaks-connections-v1`, including every composition order.
    /// Custom packs return `None` and require a
    /// caller-owned fingerprint bound to exact identity.
    #[must_use]
    pub fn builtin_review_reference(&self) -> Option<&str> {
        self.builtin_review_reference.as_deref()
    }

    /// Returns the exact framed identity for deliberate access-controlled
    /// persistence or hashing by the caller's established cryptographic stack.
    ///
    /// This contains complete pack configuration, potentially sensitive
    /// literals. Never publish it as a supposedly secret-free diagnostic.
    /// Comparing these bytes across scans is equivalent to identity equality.
    #[must_use]
    pub fn sensitive_exact_bytes(&self) -> &[u8] {
        &self.exact
    }
}

/// Explicit composition request; not selected by existing engine APIs.
#[derive(Clone, Default)]
pub struct NativePolicy {
    packs: Vec<(String, String)>,
    github_classic: bool,
}

impl fmt::Debug for NativePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativePolicy")
            .field("pack_count", &self.packs.len())
            .field("github_classic", &self.github_classic)
            .finish_non_exhaustive()
    }
}

impl NativePolicy {
    /// Maximum explicitly appended packs.
    pub const MAX_PACKS: usize = 32;
    /// Maximum aggregate TOML source bytes across appended packs.
    pub const MAX_PACK_BYTES: usize = 1_048_576;
    /// Maximum aggregate native rules across appended packs.
    pub const MAX_NATIVE_RULES: usize = 1_024;

    /// Starts an explicit native policy with only the pinned default rules.
    #[must_use]
    pub fn builder() -> Self {
        Self::default()
    }

    /// Appends a named, versioned rules pack through native TOML semantics.
    ///
    /// Scalar `entropy` retains legacy behavior. A native byte predicate uses
    /// `entropy = { algorithm = "byte-shannon-f64-v1", reject = "lt", threshold = 3.5 }`.
    /// The comparator is `lt` or `le`, and the finite threshold is in `0..=8`.
    /// A structured entropy value requires this loader; the compatibility
    /// [`ConfigLoader`] rejects it instead of silently dropping the predicate.
    ///
    /// A typed `regex = { dialect = "bytes-v1", pattern = "..." }` opts into
    /// raw-byte content matching with Unicode disabled by default. String
    /// patterns retain Go semantics. Byte rules and `buffer-v1` relations use
    /// original keyword classification and each decoded segment's own buffer.
    ///
    /// A rule-level `predicate` table selects `base64url-segment-go-regex-v1`
    /// or `vercel-cl100k-ratio-v1`. These bounded secret predicates require a
    /// nonempty typed `bytes-v1` regex, preserving ordinary-loader rejection.
    /// They run after entropy and before finding admission and allowlists.
    ///
    /// IDs are 1 to 96 ASCII letters, digits, dots, underscores or hyphens.
    /// The caller must version the ID when publishing changed pack semantics.
    /// Exact bytes also participate in identity, so reusing an ID cannot hide
    /// a configuration change. Native rule IDs start with `rustleaks.`.
    /// Extension directives, global allowlists and advisory minimum versions
    /// are rejected. Unknown fields and case-colliding aliases are rejected
    /// before the compatibility parser can discard or overwrite them.
    /// Rule-local allowlists and composites remain supported.
    ///
    /// # Errors
    ///
    /// Returns a structured error for invalid IDs, duplicate packs, limits,
    /// unsupported composition directives, or malformed TOML. Rule collisions
    /// and executable pattern errors are also checked by [`Self::build`].
    pub fn with_pack(mut self, id: &str, contents: &str) -> Result<Self, NativePolicyError> {
        if !valid_identifier(id) {
            return Err(NativePolicyError::InvalidPackId);
        }
        if self.packs.iter().any(|(existing, _)| existing == id) {
            return Err(NativePolicyError::DuplicatePackId);
        }
        if self.packs.len() == Self::MAX_PACKS
            || contents.len() > Self::MAX_PACK_BYTES
            || self.packs.iter().map(|(_, text)| text.len()).sum::<usize>()
                > Self::MAX_PACK_BYTES - contents.len()
        {
            return Err(NativePolicyError::LimitExceeded);
        }
        validate_pack(contents)?;
        self.packs.push((id.to_owned(), contents.to_owned()));
        Ok(self)
    }

    /// Enables an allowlisted annotation extension in the policy identity.
    ///
    /// Annotation work also requires a nonzero per-scan explanation limit.
    #[must_use]
    pub const fn with_extension(mut self, extension: NativeExtension) -> Self {
        match extension {
            NativeExtension::GithubClassicPatV1 => self.github_classic = true,
        }
        self
    }

    /// Compiles the immutable composed engine without I/O or downloads.
    ///
    /// # Errors
    ///
    /// Returns errors for collisions, resource ceilings, unsupported pack
    /// directives or existing loader/engine compilation failures.
    pub fn build(self) -> Result<NativeEngine, NativePolicyError> {
        let github_classic = self.github_classic;
        let (config, identity) = self.compile()?;
        Ok(NativeEngine {
            engine: Engine::builder(config).build()?,
            identity,
            github_classic,
        })
    }

    /// Compiles detection policy and exact identity without building an engine.
    ///
    /// Native predicates remain attached to the compiled rules, including after
    /// cloning or selection. Engines built from this config enforce detection
    /// policy but omit the native envelope and annotation extensions. Identity
    /// describes the full composition; callers must also bind selected rule IDs
    /// and scan options when using a projection.
    ///
    /// # Errors
    ///
    /// Returns errors for collisions, resource ceilings, unsupported pack
    /// directives or configuration compilation failures.
    #[allow(clippy::too_many_lines)] // Pack composition, collision checks and identity binding share one ordered flow.
    pub fn compile(self) -> Result<(CompiledConfig, NativePolicyIdentity), NativePolicyError> {
        let loader = ConfigLoader::new();
        let mut raw = loader.parse_toml(DEFAULT_CONFIG, None)?;
        let mut ids = raw
            .rules
            .iter()
            .map(|rule| rule.id.clone())
            .collect::<BTreeSet<_>>();
        let mut native_count = 0usize;
        let mut native_entropy = BTreeMap::new();
        let mut native_predicates = BTreeMap::new();
        let mut native_required = BTreeMap::new();
        let mut native_bytes = BTreeSet::new();
        let builtin_review_reference = builtin_pack_reference(&self.packs).map(|packs| Arc::<str>::from(format!(
            "{NATIVE_POLICY_VERSION}|core:{}|upstream:{UPSTREAM_REVISION}|default-sha256:{DEFAULT_CONFIG_SHA256}|{packs}|github-classic-pat-v1:{}",
            env!("CARGO_PKG_VERSION"), self.github_classic,
        )));
        let mut identity = Vec::new();
        for component in [
            NATIVE_POLICY_VERSION,
            env!("CARGO_PKG_VERSION"),
            UPSTREAM_REVISION,
            DEFAULT_CONFIG_SHA256,
        ] {
            frame(&mut identity, component.as_bytes());
        }
        frame(
            &mut identity,
            if self.github_classic {
                b"github-classic-pat-v1"
            } else {
                b""
            },
        );
        for (id, contents) in self.packs {
            let pack = validate_pack(&contents)?;
            native_count += pack.raw.rules.len();
            if native_count > Self::MAX_NATIVE_RULES {
                return Err(NativePolicyError::LimitExceeded);
            }
            for rule in &pack.raw.rules {
                if !ids.insert(rule.id.clone()) {
                    return Err(NativePolicyError::RuleCollision);
                }
            }
            frame(&mut identity, id.as_bytes());
            frame(&mut identity, contents.as_bytes());
            native_entropy.extend(pack.native_entropy);
            native_predicates.extend(pack.native_predicates);
            native_required.extend(pack.native_required);
            native_bytes.extend(pack.native_bytes);
            raw.rules.extend(pack.raw.rules);
        }
        // Classify original keywords before compatibility compilation applies
        // Go lowercase. A Unicode keyword can lowercase to ASCII (for example
        // Kelvin sign), so its original category cannot be recovered later.
        let mut keyword_rules = native_bytes.clone();
        for (id, required) in &native_required {
            keyword_rules.insert(id.clone());
            keyword_rules.extend(required.edges.iter().map(|edge| edge.id.clone()));
        }
        let mut native_keywords = BTreeMap::new();
        for rule in &raw.rules {
            if keyword_rules.contains(&rule.id) {
                native_keywords.insert(
                    rule.id.clone(),
                    rule.keywords
                        .iter()
                        .map(|keyword| NativeKeyword::new(keyword))
                        .collect(),
                );
            }
        }
        let mut config = loader.compile_native(raw, &native_bytes)?;
        for (id, keywords) in native_keywords {
            if let Some(rule) = config.rules.get_mut(&id) {
                rule.native_keywords = Some(keywords);
            }
        }
        for (id, predicate) in native_entropy {
            let rule = config
                .rules
                .get_mut(&id)
                .ok_or(NativePolicyError::InvalidNativeEntropy)?;
            if rule.id != id || rule.entropy != 0.0 || rule.native_entropy.is_some() {
                return Err(NativePolicyError::InvalidNativeEntropy);
            }
            rule.native_entropy = Some(predicate);
        }
        for (id, relations) in native_required {
            let rule = config
                .rules
                .get_mut(&id)
                .ok_or(NativePolicyError::InvalidNativeRequired)?;
            rule.native_required = Some(relations);
        }
        for (id, predicate) in native_predicates {
            let rule = config
                .rules
                .get_mut(&id)
                .ok_or(NativePolicyError::InvalidNativePredicate)?;
            rule.native_predicate = Some(predicate);
        }
        Ok((
            config,
            NativePolicyIdentity {
                exact: identity.into(),
                builtin_review_reference,
            },
        ))
    }
}

fn builtin_pack_reference(packs: &[(String, String)]) -> Option<String> {
    let mut extra = "none";
    let mut providers = false;
    let mut connections = false;
    let mut order = Vec::new();
    for (id, contents) in packs {
        match (id.as_str(), contents.as_str()) {
            ("rustleaks-extra-v1", bytes) if bytes == EXTRA_RULES_V1 => {
                extra = EXTRA_RULES_V1_SHA256;
                order.push("extra");
            }
            ("rustleaks-providers-v1", bytes) if bytes == PROVIDER_RULES_V1 => {
                providers = true;
                order.push("providers");
            }
            ("rustleaks-connections-v1", bytes) if bytes == CONNECTION_RULES_V1 => {
                connections = true;
                order.push("connections");
            }
            _ => return None,
        }
    }
    // Preserve every composition without connections byte for byte.
    Some(if connections {
        format!(
            "extra-sha256:{extra}|providers-sha256:{}|connections-sha256:{CONNECTION_RULES_V1_SHA256}|pack-order:{}",
            if providers {
                PROVIDER_RULES_V1_SHA256
            } else {
                "none"
            },
            order.join(",")
        )
    } else if providers {
        format!(
            "extra-sha256:{extra}|providers-sha256:{PROVIDER_RULES_V1_SHA256}|pack-order:{}",
            order.join(",")
        )
    } else {
        format!("extra-sha256:{extra}")
    })
}

fn frame(output: &mut Vec<u8>, bytes: &[u8]) {
    // Inputs have explicit small ceilings; u64 framing is platform-independent.
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn valid_identifier(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 96
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

struct ValidatedPack {
    raw: RawConfig,
    native_entropy: BTreeMap<String, NativeEntropy>,
    native_predicates: BTreeMap<String, predicate::NativePredicate>,
    native_required: BTreeMap<String, NativeRequired>,
    native_bytes: BTreeSet<String>,
}

fn validate_pack(contents: &str) -> Result<ValidatedPack, NativePolicyError> {
    let mut value =
        toml::from_str::<toml::Value>(contents).map_err(|source| ConfigError::Parse {
            at: String::new(),
            source,
        })?;
    validate_pack_table(&value, PackTable::Config)?;
    // These private transforms retain native metadata outside the compatibility
    // raw structs. Exact caller-supplied bytes remain in policy identity.
    let predicates = extract_native_entropy(&mut value)?;
    let relations = extract_native_required(&mut value)?;
    let structural = predicate::extract(&mut value)?;
    let byte_regexes = extract_native_regexes(&mut value)?;
    let transformed;
    let ordinary = if predicates.iter().any(Option::is_some)
        || relations.iter().any(Option::is_some)
        || structural.iter().any(Option::is_some)
        || byte_regexes.iter().any(|bytes| *bytes)
    {
        transformed =
            toml::to_string(&value).map_err(|_| NativePolicyError::InvalidPackStructure)?;
        transformed.as_str()
    } else {
        contents
    };
    let raw = ConfigLoader::new().parse_toml(ordinary, None)?;
    if raw.rules.len() != predicates.len() {
        return Err(NativePolicyError::InvalidPackStructure);
    }
    if raw.extend != ConfigExtension::default()
        || raw.allowlist.is_some()
        || !raw.allowlists.is_empty()
        || !raw.min_version.is_empty()
    {
        return Err(NativePolicyError::UnsupportedPackDirective);
    }
    if raw.rules.len() > NativePolicy::MAX_NATIVE_RULES {
        return Err(NativePolicyError::LimitExceeded);
    }
    for rule in &raw.rules {
        if !rule.id.starts_with("rustleaks.")
            || rule.id.len() == "rustleaks.".len()
            || !valid_identifier(&rule.id)
        {
            return Err(NativePolicyError::InvalidRuleId);
        }
    }
    let native_bytes = raw
        .rules
        .iter()
        .zip(byte_regexes)
        .filter(|(_, bytes)| *bytes)
        .map(|(rule, _)| rule.id.clone())
        .collect::<BTreeSet<_>>();
    let mut native_entropy = BTreeMap::new();
    for (rule, predicate) in raw.rules.iter().zip(predicates) {
        if let Some(predicate) = predicate {
            if rule.regex.is_empty() && !native_bytes.contains(&rule.id) {
                return Err(NativePolicyError::InvalidNativeEntropy);
            }
            if native_entropy.insert(rule.id.clone(), predicate).is_some() {
                return Err(NativePolicyError::RuleCollision);
            }
        }
    }
    let mut native_required = BTreeMap::new();
    for (rule, relations) in raw.rules.iter().zip(relations) {
        if let Some(relations) = relations {
            if rule.regex.is_empty() && !native_bytes.contains(&rule.id) {
                return Err(NativePolicyError::InvalidNativeRequired);
            }
            if native_required.insert(rule.id.clone(), relations).is_some() {
                return Err(NativePolicyError::RuleCollision);
            }
        }
    }
    let mut native_predicates = BTreeMap::new();
    for (rule, predicate) in raw.rules.iter().zip(structural) {
        if let Some(predicate) = predicate
            && native_predicates
                .insert(rule.id.clone(), predicate)
                .is_some()
        {
            return Err(NativePolicyError::RuleCollision);
        }
    }
    Ok(ValidatedPack {
        raw,
        native_entropy,
        native_predicates,
        native_required,
        native_bytes,
    })
}

// This is deliberately separate from the permissive compatibility loader.
// The scope transitions bound traversal depth to Config -> Rule -> Allowlist
// or Required; arrays must contain tables, never positional struct sequences.
#[derive(Clone, Copy)]
enum PackTable {
    Config,
    Rule,
    Required,
    Allowlist,
    GlobalAllowlist,
    Extension,
}

fn validate_pack_table(value: &toml::Value, scope: PackTable) -> Result<(), NativePolicyError> {
    let table = value
        .as_table()
        .ok_or(NativePolicyError::InvalidPackStructure)?;
    let mut names = BTreeSet::new();
    for (key, value) in table {
        let key = key.to_ascii_lowercase();
        if !names.insert(key.clone()) {
            return Err(NativePolicyError::AmbiguousPackField);
        }
        match (scope, key.as_str()) {
            (PackTable::Rule, "regex") if value.is_table() => {
                parse_native_regex(value)?;
            }
            (PackTable::Config, "title" | "description" | "minversion")
            | (
                PackTable::Rule,
                "id" | "description" | "path" | "regex" | "secretgroup" | "entropy" | "keywords"
                | "tags" | "skipreport" | "predicate",
            )
            | (PackTable::Required, "id" | "withinlines" | "withincolumns")
            | (
                PackTable::Allowlist | PackTable::GlobalAllowlist,
                "description" | "condition" | "commits" | "paths" | "regextarget" | "regexes"
                | "stopwords",
            )
            | (PackTable::GlobalAllowlist, "targetrules")
            | (PackTable::Extension, "path" | "url" | "usedefault" | "disabledrules") => {}
            (PackTable::Config, "rules") => validate_pack_tables(value, PackTable::Rule)?,
            (PackTable::Config, "extend") => validate_pack_table(value, PackTable::Extension)?,
            (PackTable::Config, "allowlist") => {
                validate_pack_table(value, PackTable::GlobalAllowlist)?;
            }
            (PackTable::Config, "allowlists") => {
                validate_pack_tables(value, PackTable::GlobalAllowlist)?;
            }
            (PackTable::Rule, "allowlist") => validate_pack_table(value, PackTable::Allowlist)?,
            (PackTable::Rule, "allowlists") => validate_pack_tables(value, PackTable::Allowlist)?,
            (PackTable::Rule, "required") if native_required_table(value) => {
                parse_native_required(value)?;
            }
            (PackTable::Rule, "required") => validate_pack_tables(value, PackTable::Required)?,
            _ => return Err(NativePolicyError::UnknownPackField),
        }
    }
    Ok(())
}

fn validate_pack_tables(value: &toml::Value, scope: PackTable) -> Result<(), NativePolicyError> {
    if let toml::Value::Array(values) = value {
        for value in values {
            validate_pack_table(value, scope)?;
        }
        Ok(())
    } else {
        // Keep the compatibility loader's named single-table shorthand.
        validate_pack_table(value, scope)
    }
}

// Keep classification separate from compatibility-normalized keyword text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NativeKeyword {
    Empty,
    Ascii(String),
    UnicodeLower(String),
}

impl NativeKeyword {
    fn new(keyword: &str) -> Self {
        if keyword.is_empty() {
            Self::Empty
        } else if keyword.is_ascii() {
            Self::Ascii(keyword.to_owned())
        } else {
            Self::UnicodeLower(keyword.to_lowercase())
        }
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        1 + match self {
            Self::Empty => 0,
            Self::Ascii(text) | Self::UnicodeLower(text) => text.len(),
        }
    }
}

fn parse_native_regex(value: &toml::Value) -> Result<&str, NativePolicyError> {
    let fields = native_fields(value, &["dialect", "pattern"])?;
    if fields.get("dialect").and_then(|value| value.as_str()) != Some("bytes-v1") {
        return Err(NativePolicyError::InvalidNativeRegex);
    }
    fields
        .get("pattern")
        .and_then(|value| value.as_str())
        .ok_or(NativePolicyError::InvalidNativeRegex)
}

fn extract_native_regexes(value: &mut toml::Value) -> Result<Vec<bool>, NativePolicyError> {
    fn extract(rule: &mut toml::Value) -> Result<bool, NativePolicyError> {
        let table = rule
            .as_table_mut()
            .ok_or(NativePolicyError::InvalidPackStructure)?;
        let Some((_, regex)) = table
            .iter_mut()
            .find(|(key, _)| key.eq_ignore_ascii_case("regex"))
        else {
            return Ok(false);
        };
        if !regex.is_table() {
            return Ok(false);
        }
        let source = parse_native_regex(regex)?.to_owned();
        *regex = toml::Value::String(source);
        Ok(true)
    }
    let table = value
        .as_table_mut()
        .ok_or(NativePolicyError::InvalidPackStructure)?;
    let Some((_, rules)) = table
        .iter_mut()
        .find(|(key, _)| key.eq_ignore_ascii_case("rules"))
    else {
        return Ok(Vec::new());
    };
    match rules {
        toml::Value::Array(rules) => rules.iter_mut().map(extract).collect(),
        toml::Value::Table(rule) if rule.is_empty() => Ok(Vec::new()),
        rule => Ok(vec![extract(rule)?]),
    }
}

// The enclosing contract opts the primary and its helper evaluations into
// raw-fragment / individual-decoded-buffer coordinates. Ordinary required
// arrays retain the frozen compatibility behavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeRequired {
    pub(crate) edges: Vec<NativeRequiredEdge>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeRequiredEdge {
    pub(crate) id: String,
    pub(crate) relation: NativeRelation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeRelation {
    SameCandidate,
    // None means unlimited; Some stores the source N-1 expansion.
    FullMatchWindow(Option<usize>),
}

fn native_fields<'a>(
    value: &'a toml::Value,
    permitted: &[&str],
) -> Result<BTreeMap<String, &'a toml::Value>, NativePolicyError> {
    let table = value
        .as_table()
        .ok_or(NativePolicyError::InvalidNativeRequired)?;
    let mut fields = BTreeMap::new();
    for (key, value) in table {
        let key = key.to_ascii_lowercase();
        if !permitted.contains(&key.as_str()) {
            return Err(NativePolicyError::UnknownPackField);
        }
        if fields.insert(key, value).is_some() {
            return Err(NativePolicyError::AmbiguousPackField);
        }
    }
    Ok(fields)
}

fn native_required_table(value: &toml::Value) -> bool {
    value.as_table().is_some_and(|table| {
        table
            .keys()
            .any(|key| key.eq_ignore_ascii_case("contract") || key.eq_ignore_ascii_case("edges"))
    })
}

fn parse_native_required(value: &toml::Value) -> Result<NativeRequired, NativePolicyError> {
    let fields = native_fields(value, &["contract", "edges"])?;
    if fields.get("contract").and_then(|value| value.as_str()) != Some("buffer-v1") {
        return Err(NativePolicyError::InvalidNativeRequired);
    }
    let edges = fields
        .get("edges")
        .and_then(|value| value.as_array())
        .filter(|edges| !edges.is_empty())
        .ok_or(NativePolicyError::InvalidNativeRequired)?;
    let mut ids = BTreeSet::new();
    let mut compiled = Vec::new();
    for edge in edges {
        let fields = native_fields(edge, &["id", "relation", "window"])?;
        let id = fields
            .get("id")
            .and_then(|value| value.as_str())
            .filter(|id| !id.is_empty())
            .ok_or(NativePolicyError::InvalidNativeRequired)?;
        if !ids.insert(id) {
            return Err(NativePolicyError::InvalidNativeRequired);
        }
        let relation = match fields.get("relation").and_then(|value| value.as_str()) {
            Some("same-candidate") if !fields.contains_key("window") => {
                NativeRelation::SameCandidate
            }
            Some("full-match-window") => {
                let window = fields
                    .get("window")
                    .and_then(|value| value.as_str())
                    .ok_or(NativePolicyError::InvalidNativeRequired)?;
                let expansion = if window == "0" {
                    None
                } else {
                    let digits = window
                        .strip_suffix('L')
                        .filter(|digits| {
                            !digits.is_empty()
                                && !digits.starts_with('0')
                                && digits.bytes().all(|byte| byte.is_ascii_digit())
                        })
                        .ok_or(NativePolicyError::InvalidNativeRequired)?;
                    Some(
                        digits
                            .parse::<usize>()
                            .ok()
                            .and_then(|lines| lines.checked_sub(1))
                            .ok_or(NativePolicyError::InvalidNativeRequired)?,
                    )
                };
                NativeRelation::FullMatchWindow(expansion)
            }
            _ => return Err(NativePolicyError::InvalidNativeRequired),
        };
        compiled.push(NativeRequiredEdge {
            id: id.to_owned(),
            relation,
        });
    }
    Ok(NativeRequired { edges: compiled })
}

fn extract_native_required(
    value: &mut toml::Value,
) -> Result<Vec<Option<NativeRequired>>, NativePolicyError> {
    let table = value
        .as_table_mut()
        .ok_or(NativePolicyError::InvalidPackStructure)?;
    let Some((_, rules)) = table
        .iter_mut()
        .find(|(key, _)| key.eq_ignore_ascii_case("rules"))
    else {
        return Ok(Vec::new());
    };
    match rules {
        toml::Value::Array(rules) => rules.iter_mut().map(extract_rule_required).collect(),
        toml::Value::Table(rule) if rule.is_empty() => Ok(Vec::new()),
        rule => Ok(vec![extract_rule_required(rule)?]),
    }
}

fn extract_rule_required(
    value: &mut toml::Value,
) -> Result<Option<NativeRequired>, NativePolicyError> {
    let table = value
        .as_table_mut()
        .ok_or(NativePolicyError::InvalidPackStructure)?;
    let Some((_, required)) = table
        .iter_mut()
        .find(|(key, _)| key.eq_ignore_ascii_case("required"))
    else {
        return Ok(None);
    };
    if !native_required_table(required) {
        return Ok(None);
    }
    let native = parse_native_required(required)?;
    *required = toml::Value::Array(
        native
            .edges
            .iter()
            .map(|edge| {
                let mut table = toml::map::Map::new();
                table.insert("id".to_owned(), toml::Value::String(edge.id.clone()));
                toml::Value::Table(table)
            })
            .collect(),
    );
    Ok(Some(native))
}

// This private type is the versioned byte-shannon-f64-v1 algorithm. Its fixed
// histogram and ascending accumulation order are part of that contract.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct NativeEntropy {
    reject: EntropyRejection,
    threshold: f64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntropyRejection {
    Less,
    LessOrEqual,
}

impl NativeEntropy {
    pub(crate) fn metadata(self) -> (&'static str, &'static str, f64) {
        (
            "byte-shannon-f64-v1",
            match self.reject {
                EntropyRejection::Less => "lt",
                EntropyRejection::LessOrEqual => "le",
            },
            self.threshold,
        )
    }

    pub(crate) fn rejects(self, entropy: f64) -> bool {
        match self.reject {
            EntropyRejection::Less => entropy < self.threshold,
            EntropyRejection::LessOrEqual => entropy <= self.threshold,
        }
    }

    #[allow(
        clippy::cast_precision_loss,
        clippy::unused_self,
        reason = "the private policy type fixes the binary64 algorithm contract"
    )]
    pub(crate) fn calculate(self, bytes: &[u8]) -> f64 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = [0_usize; 256];
        for &byte in bytes {
            counts[usize::from(byte)] += 1;
        }
        let length = bytes.len() as f64;
        counts
            .into_iter()
            .filter(|count| *count != 0)
            .fold(0.0, |entropy, count| {
                let frequency = count as f64 / length;
                entropy - frequency * frequency.log2()
            })
    }
}

fn parse_native_entropy(value: &toml::Value) -> Result<NativeEntropy, NativePolicyError> {
    let table = value
        .as_table()
        .ok_or(NativePolicyError::InvalidNativeEntropy)?;
    let mut names = BTreeSet::new();
    for key in table.keys() {
        if !names.insert(key.to_ascii_lowercase()) {
            return Err(NativePolicyError::AmbiguousPackField);
        }
    }
    if table
        .keys()
        .any(|key| !matches!(key.as_str(), "algorithm" | "reject" | "threshold"))
    {
        return Err(NativePolicyError::InvalidNativeEntropy);
    }
    if table.len() != 3
        || table.get("algorithm").and_then(toml::Value::as_str) != Some("byte-shannon-f64-v1")
    {
        return Err(NativePolicyError::InvalidNativeEntropy);
    }
    let reject = match table.get("reject").and_then(toml::Value::as_str) {
        Some("lt") => EntropyRejection::Less,
        Some("le") => EntropyRejection::LessOrEqual,
        _ => return Err(NativePolicyError::InvalidNativeEntropy),
    };
    let threshold = match table.get("threshold") {
        Some(toml::Value::Float(value)) => *value,
        // Byte entropy cannot exceed eight; range-check before converting.
        Some(toml::Value::Integer(value)) if (0..=8).contains(value) => {
            f64::from(u8::try_from(*value).map_err(|_| NativePolicyError::InvalidNativeEntropy)?)
        }
        _ => return Err(NativePolicyError::InvalidNativeEntropy),
    };
    if !threshold.is_finite() || !(0.0..=8.0).contains(&threshold) {
        return Err(NativePolicyError::InvalidNativeEntropy);
    }
    Ok(NativeEntropy { reject, threshold })
}

fn extract_native_entropy(
    value: &mut toml::Value,
) -> Result<Vec<Option<NativeEntropy>>, NativePolicyError> {
    let table = value
        .as_table_mut()
        .ok_or(NativePolicyError::InvalidPackStructure)?;
    let Some((_, rules)) = table
        .iter_mut()
        .find(|(key, _)| key.eq_ignore_ascii_case("rules"))
    else {
        return Ok(Vec::new());
    };
    match rules {
        toml::Value::Array(rules) => rules.iter_mut().map(extract_rule_entropy).collect(),
        toml::Value::Table(rule) if rule.is_empty() => Ok(Vec::new()),
        rule => Ok(vec![extract_rule_entropy(rule)?]),
    }
}

fn extract_rule_entropy(
    value: &mut toml::Value,
) -> Result<Option<NativeEntropy>, NativePolicyError> {
    let table = value
        .as_table_mut()
        .ok_or(NativePolicyError::InvalidPackStructure)?;
    let Some((_, entropy)) = table
        .iter_mut()
        .find(|(key, _)| key.eq_ignore_ascii_case("entropy"))
    else {
        return Ok(None);
    };
    if !entropy.is_table() {
        return Ok(None);
    }
    let predicate = parse_native_entropy(entropy)?;
    *entropy = toml::Value::Float(0.0);
    Ok(Some(predicate))
}

/// Immutable composed engine plus exact native policy identity.
#[derive(Clone, Debug)]
pub struct NativeEngine {
    engine: Engine,
    identity: NativePolicyIdentity,
    github_classic: bool,
}

impl NativeEngine {
    /// Returns the immutable effective engine for sessions or rule projections.
    /// Scans through it omit the native envelope and explanation channel.
    #[must_use]
    pub const fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Returns the exact composition and extension identity.
    #[must_use]
    pub const fn identity(&self) -> &NativePolicyIdentity {
        &self.identity
    }

    /// Scans with unchanged finding, ordering, decoding, error and partial-result
    /// semantics, adding bounded annotations separate from legacy findings.
    #[must_use]
    pub fn scan_fragment_controlled(
        &self,
        fragment: &Fragment,
        options: &ScanOptions,
        control: &ScanControl<'_>,
        explanations: ExplanationOptions,
    ) -> NativeScanOutcome {
        let offline_annotations_enabled = self.github_classic && explanations.record_limit() != 0;
        let (scan, explanations) = self.engine.scan_fragment_explained(
            fragment,
            options,
            control,
            explanations,
            self.github_classic,
        );
        NativeScanOutcome {
            scan,
            identity: self.identity.clone(),
            explanations,
            options: *options,
            budget: control.budget(),
            offline_annotations_enabled,
        }
    }
}

/// Additive native envelope. Legacy finding serialization is untouched.
#[derive(Clone, Debug)]
pub struct NativeScanOutcome {
    scan: ScanOutcome,
    identity: NativePolicyIdentity,
    explanations: ExplanationLog,
    options: ScanOptions,
    budget: ScanBudget,
    offline_annotations_enabled: bool,
}

impl NativeScanOutcome {
    /// Returns the actual detection options used for this scan. Review and
    /// cache consumers must bind these as well as configuration identity.
    #[must_use]
    pub const fn options(&self) -> ScanOptions {
        self.options
    }

    /// Returns the actual aggregate resource limits for this scan. Completion
    /// and termination remain authoritative even when these limits are equal.
    #[must_use]
    pub const fn budget(&self) -> ScanBudget {
        self.budget
    }

    /// Whether the selected policy and nonzero diagnostic budget enabled
    /// offline annotations. This is not evidence that any candidate was checked;
    /// inspect check events and diagnostic truncation for that evidence.
    #[must_use]
    pub const fn offline_annotations_enabled(&self) -> bool {
        self.offline_annotations_enabled
    }

    /// Returns the full legacy outcome; always inspect completion/termination.
    #[must_use]
    pub const fn scan(&self) -> &ScanOutcome {
        &self.scan
    }

    /// Returns the exact policy identity used for this scan.
    #[must_use]
    pub const fn identity(&self) -> &NativePolicyIdentity {
        &self.identity
    }

    /// Returns the bounded source-omitting diagnostic projection.
    #[must_use]
    pub const fn explanations(&self) -> &ExplanationLog {
        &self.explanations
    }

    /// Consumes the envelope and returns the unchanged legacy outcome.
    #[must_use]
    pub fn into_scan(self) -> ScanOutcome {
        self.scan
    }
}

/// Structured native composition failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativePolicyError {
    /// The pack ID is not within the bounded ASCII grammar.
    #[error("invalid native pack identifier")]
    InvalidPackId,
    /// The requested pack ID already exists in this composition.
    #[error("duplicate native pack identifier")]
    DuplicatePackId,
    /// A rule lacks the native namespace or bounded ASCII grammar.
    #[error("invalid native rule identifier")]
    InvalidRuleId,
    /// Two definitions claim the same rule ID.
    #[error("native rule identifier collision")]
    RuleCollision,
    /// A pack requests a directive that could change the pinned base.
    #[error("unsupported native pack composition directive")]
    UnsupportedPackDirective,
    /// A native table contains an unsupported field. The name and value are
    /// deliberately omitted because caller-supplied configuration can be sensitive.
    #[error("unknown native pack field")]
    UnknownPackField,
    /// Two field spellings collide under the loader's ASCII case normalization.
    #[error("ambiguous native pack field spelling")]
    AmbiguousPackField,
    /// A native struct destination is not a named TOML table.
    #[error("invalid native pack table structure")]
    InvalidPackStructure,
    /// A native entropy predicate has invalid fields, values or a missing
    /// content pattern. Configuration text is omitted from this diagnostic.
    #[error("invalid native entropy predicate")]
    InvalidNativeEntropy,
    /// A typed native regex has invalid fields or an unknown dialect.
    #[error("invalid native regex dialect")]
    InvalidNativeRegex,
    /// A native required contract, relation or window is malformed.
    #[error("invalid native required relation")]
    InvalidNativeRequired,
    /// A bounded native predicate has malformed or unsupported parameters,
    /// or lacks the required nonempty typed byte regex.
    #[error("invalid native predicate")]
    InvalidNativePredicate,
    /// A source-byte, pack-count or rule-count limit was exceeded.
    #[error("native composition safety limit exceeded")]
    LimitExceeded,
    /// Existing configuration parser/compiler failure; diagnostics can include
    /// user-supplied configuration text and must be handled accordingly.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Existing engine prefilter failure.
    #[error(transparent)]
    Engine(#[from] ScanError),
}

#[cfg(test)]
mod identity_regressions {
    use super::{
        EXTRA_RULES_V1, EXTRA_RULES_V1_SHA256, PROVIDER_RULES_V1, PROVIDER_RULES_V1_SHA256,
        builtin_pack_reference,
    };

    #[test]
    fn connection_support_preserves_existing_builtin_reference_bytes() {
        let extra = ("rustleaks-extra-v1".to_owned(), EXTRA_RULES_V1.to_owned());
        let providers = (
            "rustleaks-providers-v1".to_owned(),
            PROVIDER_RULES_V1.to_owned(),
        );
        for (packs, expected) in [
            (vec![], "extra-sha256:none".to_owned()),
            (
                vec![extra.clone()],
                format!("extra-sha256:{EXTRA_RULES_V1_SHA256}"),
            ),
            (
                vec![providers.clone()],
                format!(
                    "extra-sha256:none|providers-sha256:{PROVIDER_RULES_V1_SHA256}|pack-order:providers"
                ),
            ),
            (
                vec![extra.clone(), providers.clone()],
                format!(
                    "extra-sha256:{EXTRA_RULES_V1_SHA256}|providers-sha256:{PROVIDER_RULES_V1_SHA256}|pack-order:extra,providers"
                ),
            ),
            (
                vec![providers, extra],
                format!(
                    "extra-sha256:{EXTRA_RULES_V1_SHA256}|providers-sha256:{PROVIDER_RULES_V1_SHA256}|pack-order:providers,extra"
                ),
            ),
        ] {
            assert_eq!(builtin_pack_reference(&packs), Some(expected));
        }
    }
}

#[cfg(test)]
mod byte_entropy_arithmetic {
    use super::{EntropyRejection, NativeEntropy};

    #[test]
    fn named_algorithm_has_independently_specified_histogram_values() {
        let policy = NativeEntropy {
            reject: EntropyRejection::Less,
            threshold: 3.5,
        };
        for (bytes, expected) in [
            (vec![], 0.0_f64),
            (vec![255; 37], 0.0),
            (b"ABCDEFGHIIJJKKLL".to_vec(), 3.5),
            ((0_u8..=255).collect(), 8.0),
            ("éé".as_bytes().to_vec(), 1.0),
            (vec![255, 254, 255, 254], 1.0),
        ] {
            assert_eq!(policy.calculate(&bytes).to_bits(), expected.to_bits());
        }
        for (counts, expected) in [
            (vec![49; 8], 3.0_f64),
            ([vec![49; 8], vec![98; 4]].concat(), 3.5),
        ] {
            let bytes: Vec<u8> = (b'A'..)
                .zip(counts)
                .flat_map(|(byte, count)| std::iter::repeat_n(byte, count))
                .collect();
            assert_eq!(policy.calculate(&bytes).to_bits(), expected.to_bits());
        }
    }
}

#[cfg(test)]
mod native_metadata_tests {
    use super::*;

    #[test]
    fn original_keywords_cover_cross_pack_and_base_helpers_after_selection() {
        let parent = "
[[rules]]
id='rustleaks.parent'
regex={dialect='bytes-v1',pattern='(A)'}
keywords=['\u{212a}ey']
[rules.required]
contract='buffer-v1'
edges=[{id='github-pat',relation='full-match-window',window='0'}, {id='rustleaks.helper',relation='same-candidate'}]
";
        let helper =
            "[[rules]]\nid='rustleaks.helper'\nregex='(A)'\nkeywords=['', 'accesskey', 'İ']\n";
        let (config, _) = NativePolicy::builder()
            .with_pack("parent", parent)
            .unwrap()
            .with_pack("helper", helper)
            .unwrap()
            .compile()
            .unwrap();
        let selected = config
            .clone()
            .select_rules(["rustleaks.parent", "github-pat", "rustleaks.helper"])
            .unwrap();
        assert_eq!(
            selected.rule("github-pat").unwrap().native_keywords,
            Some(vec![NativeKeyword::Ascii("ghp_".to_owned())])
        );
        assert_eq!(
            selected.rule("rustleaks.parent").unwrap().native_keywords,
            Some(vec![NativeKeyword::UnicodeLower("key".to_owned())])
        );
        assert_eq!(
            selected.rule("rustleaks.helper").unwrap().native_keywords,
            Some(vec![
                NativeKeyword::Empty,
                NativeKeyword::Ascii("accesskey".to_owned()),
                NativeKeyword::UnicodeLower("i\u{307}".to_owned())
            ])
        );
        assert!(
            config
                .rule("aws-access-token")
                .unwrap()
                .native_keywords
                .is_none()
        );
        let engine = Engine::builder(selected.clone()).build().unwrap();
        assert_eq!(engine.config(), &selected);
        assert!(
            engine
                .config()
                .rule("rustleaks.parent")
                .unwrap()
                .regex_matcher
                .is_none()
        );
        assert!(
            engine
                .config()
                .rule("rustleaks.parent")
                .unwrap()
                .native_byte_matcher
                .is_some()
        );
    }
}
