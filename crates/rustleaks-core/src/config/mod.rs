//! Raw and compiled Rustleaks configuration in the Gitleaks TOML format.
//!
//! Parsing is deliberately permissive at the [`RawConfig`] boundary. User
//! supplied patterns are retained as strings here; the private matching
//! backend is introduced when the configuration is compiled.
//!
//! Load a configuration with one custom rule and scan with a cancellation
//! flag and a budget:
//!
//! ```
//! use std::sync::atomic::AtomicBool;
//! use rustleaks_core::config::ConfigLoader;
//! use rustleaks_core::model::{Fragment, ScanOptions};
//! use rustleaks_core::{Engine, ScanBudget, ScanControl};
//!
//! let config = ConfigLoader::new().load_toml(r#"
//!     [[rules]]
//!     id = "example-token"
//!     regex = '''token=([A-Z0-9]{4})'''
//! "#)?;
//! let engine = Engine::builder(config).build()?;
//! let cancelled = AtomicBool::new(false);
//! let control = ScanControl::cancellable(&cancelled).with_budget(
//!     ScanBudget::unlimited()
//!         .max_work_units(32)
//!         .max_finding_records(4),
//! );
//! let outcome = engine.scan_fragment_controlled(
//!     &Fragment::new(b"token=AB12"),
//!     &ScanOptions::default(),
//!     &control,
//! );
//!
//! assert!(outcome.is_complete());
//! assert_eq!(outcome.findings().len(), 1);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

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

/// The rules in `gitleaks.toml`. They started from the Gitleaks default
/// configuration; see `NOTICE` for attribution.
///
/// [`ConfigLoader::load_default`] gives these rules plus the built-in rule
/// files in [`crate::native`]. Use [`ConfigLoader::with_default_config`] with
/// this text for these rules alone.
pub const DEFAULT_CONFIG: &str = include_str!("../../default/gitleaks.toml");

/// Byte view of [`DEFAULT_CONFIG`].
pub const DEFAULT_CONFIG_BYTES: &[u8] = DEFAULT_CONFIG.as_bytes();

/// SHA-256 of [`DEFAULT_CONFIG_BYTES`].
pub const DEFAULT_CONFIG_SHA256: &str =
    "35c17b31383953534b7e5769082564aab30a52606f32a310a217e99b341280b8";
