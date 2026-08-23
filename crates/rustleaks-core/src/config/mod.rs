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

/// Byte-exact default configuration from [`DEFAULT_CONFIG_REVISION`].
pub const DEFAULT_CONFIG: &str = include_str!("../../default/gitleaks.toml");

/// Byte view of [`DEFAULT_CONFIG`].
pub const DEFAULT_CONFIG_BYTES: &[u8] = DEFAULT_CONFIG.as_bytes();

/// Upstream revision from which [`DEFAULT_CONFIG`] was copied.
pub const DEFAULT_CONFIG_REVISION: &str = crate::UPSTREAM_REVISION;

/// SHA-256 of [`DEFAULT_CONFIG_BYTES`].
pub const DEFAULT_CONFIG_SHA256: &str =
    "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";
