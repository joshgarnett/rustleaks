#![forbid(unsafe_code)]
//! Unpublished evaluation tools for Rustleaks maintainers.
//!
//! The library holds the detection-quality evaluation: the generator of the
//! synthetic quality corpus in `testdata/quality-corpus/` and the code that
//! scores the built-in rules against it. The crate's binaries run the quality
//! evaluation (`rustleaks-quality`), the performance workloads
//! (`rustleaks-perf`) and the process fixtures for CLI tests
//! (`rustleaks-cli-fixture`).

pub mod evaluation;
