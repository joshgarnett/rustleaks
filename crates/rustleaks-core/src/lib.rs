#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
//!
//! ## Controlled scans
//!
//! Each call owns its normalized keyword buffer, match scratch, and findings.
//! Optional [`session`] policy and batches retain cross-fragment filtering
//! state without creating threads, requiring an async runtime, or logging.
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
pub mod explanation;
mod go_unicode;
pub mod model;
pub mod native;
mod regex;
pub mod session;
pub mod triage;
pub mod validation;

pub use engine::{
    Engine, EngineBuilder, ScanBudget, ScanBudgetKind, ScanCancellation, ScanControl, ScanError,
    ScanOutcome, ScanTermination, ScanUsage,
};

pub use model::Base64Mode;

/// Gitleaks commit that the shipped default rules are based on.
pub const UPSTREAM_REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
