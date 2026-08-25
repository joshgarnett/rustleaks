#![forbid(unsafe_code)]
//! Byte-first Rustleaks detection engine with a pinned compatibility profile.
//!
//! Source content and finding text retain arbitrary bytes. This example loads
//! the packaged default configuration and scans one in-memory byte slice.
//!
//! ```
//! use rustleaks_core::config::ConfigLoader;
//! use rustleaks_core::model::{Fragment, ScanOptions};
//! use rustleaks_core::{Engine, ScanBudget, ScanControl};
//!
//! let config = ConfigLoader::new().load_default()?;
//! let engine = Engine::builder(config).build()?;
//! let input = b"string AWSToken = \"AKIALALEMEL33243OLIB\";";
//! let control = ScanControl::unlimited().with_budget(
//!     ScanBudget::unlimited()
//!         .max_work_units(10_000)
//!         .max_finding_records(100),
//! );
//! let outcome = engine.scan_fragment_controlled(
//!     &Fragment::new(input),
//!     &ScanOptions::default(),
//!     &control,
//! );
//!
//! assert!(outcome.is_complete());
//! assert_eq!(outcome.findings()[0].rule_id().as_str()?, "aws-access-token");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The engine is immutable and may be shared between threads. Each call owns
//! its normalized keyword buffer, match scratch, and findings. Optional
//! [`session`] policy and batches retain cross-fragment filtering state without
//! creating threads, requiring an async runtime, or logging.
//!
//! Controlled scans remain synchronous and runtime-independent. Budgets are
//! inclusive, and a partial outcome never contains candidates from an
//! unfinished top-level rule. Callers must inspect the termination before
//! treating partial findings as a complete fragment result.
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

pub mod config;
mod decoder;
mod engine;
mod go_unicode;
pub mod model;
mod regex;
pub mod session;

pub use engine::{
    Engine, EngineBuilder, ScanBudget, ScanBudgetKind, ScanCancellation, ScanControl, ScanError,
    ScanOutcome, ScanTermination, ScanUsage,
};

/// Upstream Gitleaks revision targeted for backward compatibility by this build.
pub const UPSTREAM_REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
