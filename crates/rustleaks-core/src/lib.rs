#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
//!
//! ## Modules
//!
//! - [`config`]: load and compile configurations.
//! - [`model`]: fragments, scan options and findings.
//! - [`session`]: fingerprints, ignore files and baselines across fragments.
//! - [`native`]: custom compositions of rule files.
//! - [`triage`]: review records for findings.
//! - [`explanation`]: scan explanation records from a
//!   [`native::NativeEngine`].
//! - [`validation`]: offline format checks that never remove a finding.

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
    ScanOutcome, ScanScratch, ScanTermination, ScanUsage,
};

pub use model::Base64Mode;
