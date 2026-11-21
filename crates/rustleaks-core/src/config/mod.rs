//! Raw and compiled Rustleaks configuration in the Gitleaks TOML format.
//!
//! Parsing is deliberately permissive at the [`RawConfig`] boundary. User
//! supplied patterns are retained as strings here; the private matching
//! backend is introduced when the configuration is compiled.

mod compiled;
mod eisel_lemire;
mod loader;
mod raw;

pub use compiled::{CompiledAllowlist, CompiledConfig, CompiledRule, RuleSelectionError};
pub use loader::{
    ConfigError, ConfigLoader, ConfigOrigin, ConfigResolver, FileSystemResolver, NoIoResolver,
    ResolvedConfig, ResolverError, VirtualResolver,
};
pub use raw::{
    AllowlistCondition, AllowlistSpec, Condition, ConfigExtension, RawAllowlist, RawConfig,
    RawGlobalAllowlist, RegexTarget, RequiredRuleSpec, RuleSpec,
};

/// The Rustleaks default rules. They started from the Gitleaks default
/// configuration; see `NOTICE` for attribution.
pub const DEFAULT_CONFIG: &str = include_str!("../../default/gitleaks.toml");

/// Byte view of [`DEFAULT_CONFIG`].
pub const DEFAULT_CONFIG_BYTES: &[u8] = DEFAULT_CONFIG.as_bytes();

/// SHA-256 of [`DEFAULT_CONFIG_BYTES`], the shipped Rustleaks default rules.
pub const DEFAULT_CONFIG_SHA256: &str =
    "35c17b31383953534b7e5769082564aab30a52606f32a310a217e99b341280b8";
