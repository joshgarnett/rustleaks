#![forbid(unsafe_code)]
//! Fresh-process tests of the `rustleaks` command, one module for each topic.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

#[path = "cli/support.rs"]
mod support;

use support::*;

#[path = "cli/builtin_rules.rs"]
mod builtin_rules;
#[path = "cli/complete_profile.rs"]
mod complete_profile;
#[path = "cli/configuration.rs"]
mod configuration;
#[path = "cli/git.rs"]
mod git;
#[path = "cli/git_metadata.rs"]
mod git_metadata;
#[path = "cli/help.rs"]
mod help;
#[path = "cli/jobs.rs"]
mod jobs;
#[path = "cli/reports.rs"]
mod reports;
#[path = "cli/scan.rs"]
mod scan;
