//! Source-adapter disposition rules.

use super::super::inventory::Record;
use super::super::model::{Attrs, attrs};

pub(super) fn annotation(record: &Record) -> Result<Attrs, String> {
    let name = record.name.as_str();
    let owner = record.owner.as_str();
    let kind = record.kind.as_str();
    if owner == "Fragment" || (kind == "type" && name == "Fragment") {
        let mut value = model(
            "sources.fragment-model",
            "rustleaks_core::Fragment",
            &["MODEL-001", "MODEL-002"],
        );
        value.design_evidence = "docs/ARCHITECTURE.md#sources".into();
        return Ok(value);
    }
    if owner == "CommitInfo" || (kind == "type" && name == "CommitInfo") {
        return Ok(commit(record));
    }
    if name == "InnerPathSeparator" {
        return Ok(attrs("equivalent-public-api", "sources.inner-path-separator", "rustleaks-sources", "path",
            "rustleaks_sources::INNER_PATH_SEPARATOR", "public",
            "The archive inner-path separator remains an exact downstream public constant used in observable paths.", "sources")
            .links(&["SRC-021"]).tested("crates/rustleaks-sources/src/path.rs; crates/rustleaks-sources/tests/source_corpus.rs"));
    }
    if owner == "ScanTarget" || name == "ScanTarget" || name == "DirectoryTargets" {
        return Ok(attrs("idiomatic-public-replacement", "sources.deprecated-directory-targets", "rustleaks-sources",
            "directory", "rustleaks_sources::DirectorySource", "public",
            "Deprecated ScanTarget traversal is finally omitted; public DirectorySource replaces channel/scheduler-shaped records without a Go-shaped compatibility type.", "sources")
            .links(&["FIX-ALL-001", "TM-ALL-001", "SRC-010", "SRC-028"])
            .tested("crates/rustleaks-sources/src/directory.rs; crates/rustleaks-sources/tests/native_sources.rs; cargo xtask source-check"));
    }
    if owner == "GitCmd"
        || name == "GitCmd"
        || [
            "NewGitLogCmd",
            "NewGitLogCmdContext",
            "NewGitDiffCmd",
            "NewGitDiffCmdContext",
        ]
        .contains(&name)
    {
        return Ok(attrs("compatibility-tooling-private-implementation", "sources.git-command-internal", "rustleaks-sources",
            "git", "rustleaks_sources::git::collect_command", "crate-private",
            "Git subprocess, channels, wait lifecycle, and blob readers stay private behind public GitSource/GitMode builders and structured diagnostics.", "sources")
            .links(&["FIX-ALL-001", "TM-ALL-001", "GIT-001", "GIT-002", "GIT-003", "GIT-004", "GIT-008", "GIT-009", "GIT-013", "GIT-014", "GIT-015", "GIT-020", "GIT-021", "GIT-022"])
            .tested("crates/rustleaks-sources/src/git.rs; crates/rustleaks-sources/tests/git_corpus.rs; crates/rustleaks-sources/tests/git_sources.rs"));
    }
    if owner == "RemoteInfo"
        || name == "RemoteInfo"
        || ["NewRemoteInfo", "NewRemoteInfoContext"].contains(&name)
    {
        return Ok(remote(
            "RemoteMetadata publicly preserves platform and URL; discovery is fallible and cancellation-aware rather than a mutable Go helper.",
            &["MODEL-002", "GIT-016", "GIT-017", "GIT-018", "GIT-019"],
        ));
    }
    if owner == "File" || name == "File" {
        return Ok(file(record));
    }
    if owner == "Files" || name == "Files" {
        return Ok(directory(record));
    }
    if owner == "Git" || name == "Git" {
        return Ok(git(record));
    }
    if name == "FragmentsFunc" || name == "Source" || owner == "Source" {
        return Ok(attrs("idiomatic-public-replacement", "sources.source-trait", "rustleaks-sources", "source",
            "rustleaks_sources::Source", "public",
            "A synchronous cancellation-aware Source trait with a fallible callback/iterator preserves fragment-plus-issue behavior without an async runtime.", "sources")
            .links(&["MODEL-001", "MODEL-002", "SRC-001", "SRC-009", "SRC-027", "SRC-030"])
            .tested("crates/rustleaks-sources/src/source.rs; crates/rustleaks-sources/tests/native_sources.rs"));
    }
    Err(format!("unclassified sources API: {}", record.key))
}

fn commit(record: &Record) -> Attrs {
    if record.owner == "CommitInfo" && record.name == "Remote" {
        return remote(
            "RemoteMetadata preserves remote platform and URL downstream; explicit composition replaces automatic attachment to core CommitMetadata as the final dependency-safe API.",
            &["MODEL-002", "GIT-016", "GIT-017", "GIT-018"],
        );
    }
    attrs("idiomatic-public-replacement", "sources.commit-metadata", "rustleaks-core", "model",
        "rustleaks_core::CommitMetadata", "public",
        "CommitMetadata implements byte-preserving SHA/author/email/date/message data; explicit downstream RemoteMetadata composition is the final replacement for the Go reverse dependency.", "sources")
        .links(&["MODEL-002"]).tested("crates/rustleaks-core/tests/model.rs; crates/rustleaks-sources/src/scm.rs; crates/rustleaks-sources/tests/git_scm.rs; cargo xtask git-check")
}

fn remote(justification: &str, links: &[&str]) -> Attrs {
    attrs(
        "idiomatic-public-replacement",
        "sources.remote-metadata",
        "rustleaks-sources",
        "scm",
        "rustleaks_sources::RemoteMetadata",
        "public",
        justification,
        "sources",
    )
    .links(links)
    .tested("crates/rustleaks-sources/src/scm.rs; crates/rustleaks-sources/tests/git_scm.rs")
}

fn file(record: &Record) -> Attrs {
    if record.owner == "File" && record.name == "Buffer" {
        return attrs("compatibility-tooling-private-implementation", "sources.file-buffer-internal", "rustleaks-sources",
            "file", "rustleaks_sources::file::buffer", "crate-private",
            "The mutable scratch buffer is internal implementation state; FileSource exposes content and options, not buffering internals.", "sources")
            .links(&["SRC-003", "SRC-004", "SRC-005", "SRC-006"])
            .tested("crates/rustleaks-sources/src/file.rs; crates/rustleaks-sources/tests/source_corpus.rs");
    }
    attrs("idiomatic-public-replacement", "sources.file-source", "rustleaks-sources", "file",
        "rustleaks_sources::FileSource", "public",
        "FileSource builder preserves content/path/symlink/config/depth behavior while hiding mutable fields and yielding fragments through Source; recognized unsupported codecs have final structured-error dispositions.", "sources")
        .links(&["MODEL-002", "SRC-001", "SRC-002", "SRC-003", "SRC-004", "SRC-005", "SRC-006", "SRC-007", "SRC-008", "SRC-017", "SRC-018", "SRC-019", "SRC-020", "SRC-021", "SRC-022", "SRC-023", "SRC-024", "SRC-025", "SRC-027", "SRC-029", "SRC-030"])
        .tested("crates/rustleaks-sources/src/file.rs; crates/rustleaks-sources/src/archive.rs; crates/rustleaks-sources/tests/source_corpus.rs; crates/rustleaks-sources/tests/archive_sources.rs; cargo xtask source-check")
}

fn directory(record: &Record) -> Attrs {
    if record.owner == "Files" && record.name == "Sema" {
        return attrs("compatibility-tooling-private-implementation", "sources.directory-scheduler-internal", "rustleaks-sources",
            "directory", "rustleaks_sources::directory::scheduler", "crate-private",
            "The semaphore is private traversal policy; concurrency limits are options, not an exposed scheduler object.", "sources")
            .links(&["SRC-026", "SRC-027", "SRC-028"])
            .tested("crates/rustleaks-sources/src/runner.rs; crates/rustleaks-sources/tests/native_sources.rs");
    }
    attrs("idiomatic-public-replacement", "sources.directory-source", "rustleaks-sources", "directory",
        "rustleaks_sources::DirectorySource", "public",
        "DirectorySource builder preserves path, size, symlink, archive, and config options while hiding mutable traversal state; native Linux/Windows runtime reruns remain nonblocking follow-ups.", "sources")
        .links(&["SRC-010", "SRC-011", "SRC-012", "SRC-013", "SRC-014", "SRC-015", "SRC-016", "SRC-017", "SRC-018", "SRC-022", "SRC-025", "SRC-026", "SRC-027", "SRC-028", "SRC-029", "SRC-030"])
        .tested("crates/rustleaks-sources/src/directory.rs; crates/rustleaks-sources/tests/native_sources.rs; crates/rustleaks-sources/tests/archive_sources.rs; crates/rustleaks-sources/tests/source_corpus.rs; cargo xtask source-check")
}

fn git(record: &Record) -> Attrs {
    if record.owner == "Git" && ["Cmd", "Sema"].contains(&record.name.as_str()) {
        let command = record.name == "Cmd";
        return attrs("compatibility-tooling-private-implementation", "sources.git-source-internals", "rustleaks-sources", "git",
            if command { "rustleaks_sources::git::collect_command" } else { "rustleaks_sources::GitSource" },
            if command { "crate-private" } else { "public" },
            if command { "The child command boundary is the real private collect_command function." }
            else { "GitSource is deliberately synchronous and has no semaphore field; the upstream scheduler field is finally excluded and concurrency remains caller-owned." }, "sources")
            .links(&["FIX-ALL-001", "GIT-012", "GIT-014", "GIT-015", "GIT-020", "GIT-021", "GIT-022"])
            .tested("crates/rustleaks-sources/src/git.rs; crates/rustleaks-sources/tests/git_corpus.rs; crates/rustleaks-sources/tests/git_sources.rs");
    }
    if record.owner == "Git" && record.name == "Remote" {
        return remote(
            "RemoteMetadata is discovered explicitly and can be composed with findings; this final explicit composition replaces automatic mutable attachment.",
            &["GIT-016", "GIT-017", "GIT-018", "GIT-019"],
        );
    }
    attrs("idiomatic-public-replacement", "sources.git-source", "rustleaks-sources", "git",
        "rustleaks_sources::GitSource", "public",
        "GitSource exposes explicit shell-free history/diff modes, checked limits, environment isolation, and optional archive expansion while subprocess and scheduling details stay private.", "sources")
        .links(&["FIX-ALL-001", "TM-ALL-001", "GIT-001", "GIT-002", "GIT-003", "GIT-004", "GIT-005", "GIT-006", "GIT-007", "GIT-008", "GIT-009", "GIT-010", "GIT-011", "GIT-012", "GIT-013", "GIT-014", "GIT-015", "GIT-020", "GIT-021", "GIT-022", "GIT-023"])
        .tested("crates/rustleaks-sources/src/git.rs; crates/rustleaks-sources/tests/git_corpus.rs; crates/rustleaks-sources/tests/git_sources.rs")
}

fn model(cluster: &str, path: &str, links: &[&str]) -> Attrs {
    attrs("equivalent-public-api", cluster, "rustleaks-core", "model", path, "public",
        "The byte-preserving Rust core model has the same observable data role, with validated builders and read-only access instead of mutable public fields.",
        "findings-and-reports").links(links).tested("crates/rustleaks-core/tests/model.rs")
}
