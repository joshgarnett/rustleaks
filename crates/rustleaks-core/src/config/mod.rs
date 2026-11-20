//! Raw and compiled Rustleaks configuration with upstream compatibility.
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

/// The Rustleaks default rules: the Gitleaks default configuration at
/// [`DEFAULT_CONFIG_REVISION`] with the reviewed Rustleaks changes listed in
/// `docs/user/gitleaks-differences.md`.
pub const DEFAULT_CONFIG: &str = include_str!("../../default/gitleaks.toml");

/// Byte view of [`DEFAULT_CONFIG`].
pub const DEFAULT_CONFIG_BYTES: &[u8] = DEFAULT_CONFIG.as_bytes();

/// Upstream Gitleaks revision on which [`DEFAULT_CONFIG`] is based.
pub const DEFAULT_CONFIG_REVISION: &str = crate::UPSTREAM_REVISION;

/// SHA-256 of [`DEFAULT_CONFIG_BYTES`], the shipped Rustleaks default. The
/// upstream copy has the SHA-256 in `compat/upstream-revision.txt`.
pub const DEFAULT_CONFIG_SHA256: &str =
    "442fca81a914728ebaf843ba59d01bb3e6e71559c1ddb51fddc81fca45df959a";
