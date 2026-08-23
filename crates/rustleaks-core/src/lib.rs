#![forbid(unsafe_code)]
//! Byte-first Rustleaks detection engine with a pinned compatibility profile.
//!
//! Source content and finding text retain arbitrary bytes. Direct fragments
//! start at line zero unless the caller supplies source-specific metadata.
//!
//! ```
//! use rustleaks_core::model::Fragment;
//!
//! let fragment = Fragment::builder([0xff, b'k', b'e', b'y'])
//!     .file_path("src/example.bin")
//!     .start_line(1)
//!     .build();
//!
//! assert_eq!(fragment.content().as_bytes(), &[0xff, b'k', b'e', b'y']);
//! assert!(fragment.content().as_str().is_err());
//! ```
//!
//! The engine is immutable and may be shared between threads. Each call owns
//! its normalized keyword buffer, match scratch, and findings. Optional
//! [`session`] policy and batches retain cross-fragment filtering state without
//! creating threads, requiring an async runtime, or logging.
//!
//! ```
//! use rustleaks_core::config::ConfigLoader;
//! use rustleaks_core::model::{Fragment, ScanOptions};
//! use rustleaks_core::Engine;
//!
//! let config = ConfigLoader::new().load_toml(r#"
//!     [[rules]]
//!     id = "example-token"
//!     regex = '''token=([A-Z0-9]{4})'''
//!     keywords = ["token"]
//! "#)?;
//! let engine = Engine::builder(config).build()?;
//! let fragment = Fragment::builder(b"token=AB12").start_line(1).build();
//! let outcome = engine.scan_fragment(&fragment, &ScanOptions::default());
//!
//! assert_eq!(outcome.findings().len(), 1);
//! assert_eq!(outcome.findings()[0].secret().as_bytes(), b"AB12");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
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
