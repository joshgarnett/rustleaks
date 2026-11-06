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

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use crate::config::{
    ConfigError, ConfigExtension, ConfigLoader, DEFAULT_CONFIG, DEFAULT_CONFIG_SHA256,
};
use crate::explanation::{ExplanationLog, ExplanationOptions};
use crate::model::{Fragment, ScanOptions};
use crate::{Engine, ScanBudget, ScanControl, ScanError, ScanOutcome, UPSTREAM_REVISION};

/// Version of native composition, identity and explanation semantics.
pub const NATIVE_POLICY_VERSION: &str = "rustleaks-native-v1";

/// Explicitly selected native pilot pack; never part of the default config.
pub const EXTRA_RULES_V1: &str = include_str!("../default/rustleaks-extra-v1.toml");

/// SHA-256 of the packaged pilot TOML, checked by the maintained generator.
pub const EXTRA_RULES_V1_SHA256: &str = include_str!("../default/rustleaks-extra-v1.sha256");

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
    /// Present only for the pinned base alone, or the exact packaged pilot
    /// bytes under `rustleaks-extra-v1`. Custom pack compositions return `None`
    /// and require a caller-owned fingerprint bound to exact identity.
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

    /// Appends a named, versioned rules pack through existing TOML semantics.
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
        let loader = ConfigLoader::new();
        let mut raw = loader.parse_toml(DEFAULT_CONFIG, None)?;
        let mut ids = raw
            .rules
            .iter()
            .map(|rule| rule.id.clone())
            .collect::<BTreeSet<_>>();
        let mut native_count = 0usize;
        let builtin_pack = match self.packs.as_slice() {
            [] => Some("none"),
            [(id, contents)] if id == "rustleaks-extra-v1" && contents == EXTRA_RULES_V1 => {
                Some(EXTRA_RULES_V1_SHA256)
            }
            _ => None,
        };
        let builtin_review_reference = builtin_pack.map(|extra| Arc::<str>::from(format!(
            "{NATIVE_POLICY_VERSION}|core:{}|upstream:{UPSTREAM_REVISION}|default-sha256:{DEFAULT_CONFIG_SHA256}|extra-sha256:{extra}|github-classic-pat-v1:{}",
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
            native_count += pack.rules.len();
            if native_count > Self::MAX_NATIVE_RULES {
                return Err(NativePolicyError::LimitExceeded);
            }
            for rule in &pack.rules {
                if !ids.insert(rule.id.clone()) {
                    return Err(NativePolicyError::RuleCollision);
                }
            }
            frame(&mut identity, id.as_bytes());
            frame(&mut identity, contents.as_bytes());
            raw.rules.extend(pack.rules);
        }
        let engine = Engine::builder(loader.compile(raw)?).build()?;
        Ok(NativeEngine {
            engine,
            identity: NativePolicyIdentity {
                exact: identity.into(),
                builtin_review_reference,
            },
            github_classic: self.github_classic,
        })
    }
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

fn validate_pack(contents: &str) -> Result<crate::config::RawConfig, NativePolicyError> {
    let value = toml::from_str::<toml::Value>(contents).map_err(|source| ConfigError::Parse {
        at: String::new(),
        source,
    })?;
    validate_pack_table(&value, PackTable::Config)?;
    let raw = ConfigLoader::new().parse_toml(contents, None)?;
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
    Ok(raw)
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
            (PackTable::Config, "title" | "description" | "minversion")
            | (
                PackTable::Rule,
                "id" | "description" | "path" | "regex" | "secretgroup" | "entropy" | "keywords"
                | "tags" | "skipreport",
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
