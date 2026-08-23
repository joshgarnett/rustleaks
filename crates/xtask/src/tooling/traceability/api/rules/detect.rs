//! Detector and codec disposition rules.

use super::super::inventory::Record;
use super::super::model::{Attrs, attrs};
use super::member;

pub(super) fn codec(record: &Record) -> Result<Attrs, String> {
    let (path, links): (&str, &[&str]) = match member(record).as_str() {
        "AdjustMatchIndex" => (
            "rustleaks_core::decoder::adjust_match_index",
            &["DEC-007", "DEC-008", "DEC-011"],
        ),
        "CurrentLine" => (
            "rustleaks_core::decoder::current_line",
            &["DEC-008", "DEC-012"],
        ),
        "NewDecoder" => (
            "rustleaks_core::decoder::Decoder::new",
            &["DEC-001", "DEC-009"],
        ),
        "SegmentsWithDecodedOverlap" => (
            "rustleaks_core::decoder::segments_with_decoded_overlap",
            &["DEC-008", "DEC-011"],
        ),
        "Tags" => ("rustleaks_core::decoder::tags", &["DEC-008", "DEC-011"]),
        "Decoder.Decode" => (
            "rustleaks_core::decoder::Decoder::decode",
            &[
                "DEC-001", "DEC-002", "DEC-003", "DEC-004", "DEC-005", "DEC-006", "DEC-007",
                "DEC-009", "DEC-010",
            ],
        ),
        "Decoder" => (
            "rustleaks_core::decoder::Decoder",
            &["DEC-001", "DEC-009", "DEC-010"],
        ),
        "EncodedSegment" => (
            "rustleaks_core::decoder::EncodedSegment",
            &["DEC-007", "DEC-008", "DEC-009", "DEC-011", "DEC-012"],
        ),
        value => return Err(format!("unmapped detect/codec identity: {value}")),
    };
    let mut all = vec!["TM-ALL-001"];
    all.extend_from_slice(links);
    Ok(attrs("compatibility-tooling-private-implementation", "detect.decoder-internals", "rustleaks-core",
        "decoder", path, "crate-private",
        "Decoder and encoded-segment internals remain private; exact segment, tag, line, and index behavior is exercised through decoder unit tests and complete detector corpus replay.",
        "detection-and-codec").links(&all)
        .tested("crates/rustleaks-core/src/decoder/mod.rs; crates/rustleaks-core/tests/detect_corpus.rs; crates/rustleaks-core/tests/engine.rs; cargo xtask decoder-check"))
}

pub(super) fn annotation(record: &Record) -> Result<Attrs, String> {
    let name = record.name.as_str();
    let kind = record.kind.as_str();
    let owner = record.owner.as_str();
    if name == "SlowWarningThreshold" {
        return Ok(attrs(
            "out-of-public-product-scope",
            "detect.slow-warning",
            "rustleaks-cli",
            "diagnostics",
            "rustleaks_cli::diagnostics::SLOW_WARNING_THRESHOLD",
            "binary-private",
            "The threshold is a CLI/adapter diagnostic default, not scanning semantics or core public API.",
            "detection-and-codec",
        ));
    }
    if name == "Fragment" && kind == "type" {
        return Ok(attrs("compatibility-shim", "detect.deprecated-fragment-alias", "rustleaks-compat", "detect",
            "rustleaks_compat::detect::Fragment", "compatibility-public",
            "The deprecated detect alias forwards to rustleaks_core::Fragment and never duplicates model storage or behavior.",
            "detection-and-codec").links(&["MODEL-001", "MODEL-002"]));
    }
    if name == "RemoteInfo" || name == "NewRemoteInfo" {
        return Ok(attrs("compatibility-shim", "detect.deprecated-remote-info", "rustleaks-compat", "detect",
            "rustleaks_compat::detect::RemoteInfo", "compatibility-public",
            "The deprecated detect facade forwards to downstream RemoteMetadata discovery without making sources a core dependency.",
            "detection-and-codec").links(&["MODEL-002"]));
    }
    if name == "Location" && kind == "type" {
        return Ok(attrs("idiomatic-public-replacement", "detect.location-model", "rustleaks-core", "model",
            "rustleaks_core::Location", "public",
            "The opaque Go calculator stays private, while its validated observable location result is an implemented public core model.",
            "detection-and-codec").links(&["MODEL-003"]).tested("crates/rustleaks-core/tests/model.rs"));
    }
    if name == "IsNew" && kind == "func" {
        return Ok(baseline("is_new"));
    }
    if name == "LoadBaseline" && kind == "func" {
        return Ok(attrs("idiomatic-public-replacement", "detect.baseline", "rustleaks-core", "session",
            "rustleaks_core::session::Baseline::load_go_json", "public",
            "The core replacement loads Go-compatible JSON baselines with structured portable I/O and parse errors; report-format dispatch and presentation text remain adapter concerns.",
            "detection-and-codec").links(&["MODEL-003", "SESSION-005", "SESSION-006"])
            .tested("crates/rustleaks-core/src/session.rs; crates/rustleaks-core/tests/session_corpus.rs; cargo xtask session-check"));
    }
    if owner == "Detector" || (kind == "type" && name == "Detector") {
        return Ok(detector(record));
    }
    if [
        "NewDetector",
        "NewDetectorContext",
        "NewDetectorDefaultConfig",
    ]
    .contains(&name)
    {
        return Ok(attrs("idiomatic-public-replacement", "detect.engine-construction", "rustleaks-core", "engine",
            "rustleaks_core::Engine::builder", "public",
            "Engine builders and ConfigLoader replace detector constructors; cancellation is passed per operation instead of stored globally.",
            "detection-and-codec").tested("crates/rustleaks-core/src/engine.rs; crates/rustleaks-core/tests/config.rs; crates/rustleaks-core/tests/engine.rs; cargo xtask detect-check"));
    }
    Err(format!("unclassified detect API: {}", record.key))
}

fn baseline(method: &str) -> Attrs {
    attrs("idiomatic-public-replacement", "detect.baseline", "rustleaks-core", "session",
        format!("rustleaks_core::session::Baseline::{method}"), "public",
        "Baseline newness is an immutable query over the public Finding model with the caller's redaction policy supplied explicitly.",
        "detection-and-codec").links(&["MODEL-003", "SESSION-006", "SESSION-007"])
        .tested("crates/rustleaks-core/src/session.rs; crates/rustleaks-core/tests/session_corpus.rs; cargo xtask session-check")
}

fn detector(record: &Record) -> Attrs {
    let name = record.name.as_str();
    let kind = record.kind.as_str();
    if kind == "method" && ["DetectReader", "StreamDetectReader", "DetectFiles"].contains(&name) {
        return attrs("idiomatic-public-replacement", "detect.deprecated-adapters", "rustleaks-sources", "source",
            if name == "DetectFiles" { "rustleaks_sources::DirectorySource" } else { "rustleaks_sources::FileSource" }, "public",
            "Safe synchronous FileSource and DirectorySource adapters replace deprecated channel-shaped reader/files methods; SourceRunner composes them with Engine and ScanSession.",
            "detection-and-codec").links(&["SRC-001", "SRC-009", "SRC-010", "SRC-028", "SRC-030"])
            .tested("crates/rustleaks-sources/src/file.rs; crates/rustleaks-sources/src/directory.rs; crates/rustleaks-sources/tests/source_corpus.rs; cargo xtask source-check");
    }
    if kind == "method" && name == "DetectGit" {
        return attrs("idiomatic-public-replacement", "detect.deprecated-adapters", "rustleaks-sources", "git",
            "rustleaks_sources::GitSource", "public",
            "The deprecated detector-owned Git entry point is finally replaced by public GitSource plus SourceRunner; no Go-shaped mutable compatibility method ships.",
            "detection-and-codec").links(&["TM-ALL-001", "GIT-001", "GIT-022", "GIT-023"])
            .tested("crates/rustleaks-sources/src/git.rs; crates/rustleaks-sources/src/runner.rs; crates/rustleaks-sources/tests/git_corpus.rs; cargo xtask git-check");
    }
    if kind == "method" && name == "DetectSource" {
        return attrs("idiomatic-public-replacement", "detect.source-runner", "rustleaks-sources", "runner",
            "rustleaks_sources::SourceRunner", "public",
            "Source execution lives downstream over the public Source trait so rustleaks-core never depends on source adapters.",
            "detection-and-codec").links(&["SRC-001", "SRC-026", "SRC-027", "SRC-028", "SRC-030"])
            .tested("crates/rustleaks-sources/src/runner.rs; crates/rustleaks-sources/tests/native_sources.rs; crates/rustleaks-sources/tests/source_corpus.rs");
    }
    if kind == "method"
        && ["DetectBytes", "DetectString", "Detect", "DetectContext"].contains(&name)
    {
        return attrs("idiomatic-public-replacement", "detect.direct-scan", "rustleaks-core", "engine",
            "rustleaks_core::Engine::scan_fragment", "public",
            "Direct mutable detector calls become immutable Engine scan_fragment operations; controlled cancellation and session/source policy are explicit completed layers.",
            "detection-and-codec").links(&["MODEL-001", "MODEL-002", "MODEL-003", "COMP-001", "COMP-002", "COMP-003", "COMP-004", "COMP-005", "COMP-006", "COMP-007", "COMP-008", "SUP-001", "RED-001", "RED-002", "RED-003"])
            .tested("crates/rustleaks-core/src/engine.rs; crates/rustleaks-core/tests/detect_corpus.rs; crates/rustleaks-core/tests/composite_corpus.rs; crates/rustleaks-sources/src/runner.rs; cargo xtask source-check");
    }
    if kind == "method" {
        if let Some(value) = session_method(name) {
            return value;
        }
    }
    if kind == "field" {
        return field(record);
    }
    attrs("idiomatic-public-replacement", "detect.engine-session", "rustleaks-core", "engine",
        "rustleaks_core::Engine", "public",
        "The mutable Detector surface is split into immutable Engine, per-call ScanOptions, and explicit ScanSession.",
        "detection-and-codec").tested("crates/rustleaks-core/src/engine.rs; crates/rustleaks-core/src/session.rs; cargo xtask session-check")
}

fn session_method(name: &str) -> Option<Attrs> {
    let value = match name {
        "AddGitleaksIgnore" => attrs("idiomatic-public-replacement", "detect.scan-session", "rustleaks-core", "session",
            "rustleaks_core::session::IgnoreSet::parse_go_compatible", "public",
            "The byte parser, normalization, scanner limit, malformed-line diagnostics, immutable policy installation, named-file loading, and host diagnostics are implemented across core and CLI layers.", "detection-and-codec")
            .links(&["MODEL-003", "SESSION-002", "SESSION-003", "SESSION-004"])
            .tested("crates/rustleaks-core/src/session.rs; crates/rustleaks-core/tests/session_corpus.rs; crates/rustleaks-cli/src/config.rs; crates/rustleaks-cli/tests/cli.rs; cargo xtask cli-check"),
        "AddBaseline" => attrs("idiomatic-public-replacement", "detect.scan-session", "rustleaks-core", "session",
            "rustleaks_core::session::SessionPolicyBuilder::baseline", "public",
            "Baseline parsing, equality, immutable policy installation, and native source-relative baseline exclusion are implemented; no hidden mutable reset API is retained.", "detection-and-codec")
            .links(&["MODEL-003", "SESSION-005", "SESSION-006", "SESSION-007"])
            .tested("crates/rustleaks-core/src/session.rs; crates/rustleaks-core/tests/session_corpus.rs; crates/rustleaks-cli/src/config.rs; crates/rustleaks-cli/tests/cli.rs; cargo xtask cli-check"),
        "AddFinding" => attrs("idiomatic-public-replacement", "detect.scan-session", "rustleaks-core", "session",
            "rustleaks_core::session::ScanSession::add_finding", "public",
            "Owned findings are fingerprinted, classified against immutable session policy, and either suppressed with an explicit reason or appended without hidden shared mutation.", "detection-and-codec")
            .links(&["MODEL-003", "SESSION-001", "SESSION-004", "SESSION-008"])
            .tested("crates/rustleaks-core/src/session.rs; crates/rustleaks-core/tests/session_corpus.rs; cargo xtask session-check"),
        "Findings" => attrs("idiomatic-public-replacement", "detect.scan-session", "rustleaks-core", "session",
            "rustleaks_core::session::ScanSession::findings", "public",
            "The explicit session exposes borrowed, cloned, or consuming snapshots while canonical ordering remains an opt-in portable helper.", "detection-and-codec")
            .links(&["MODEL-003", "SESSION-008", "SESSION-009", "SESSION-010"])
            .tested("crates/rustleaks-core/src/session.rs; crates/rustleaks-core/tests/session_corpus.rs; cargo xtask session-check"),
        _ => return None,
    };
    Some(value)
}

fn field(record: &Record) -> Attrs {
    let name = record.name.as_str();
    if ["Verbose", "NoColor", "ReportPath", "Reporter"].contains(&name) {
        return attrs(
            "out-of-public-product-scope",
            "detect.cli-report-options",
            "rustleaks-cli",
            "run",
            format!("rustleaks_cli::RunOptions::{name}"),
            "binary-private",
            "Verbosity, color, output path, and reporter selection are CLI/report orchestration rather than engine state.",
            "detection-and-codec",
        );
    }
    if name == "Sema" {
        return attrs(
            "compatibility-tooling-private-implementation",
            "detect.scheduler-internal",
            "rustleaks-sources",
            "scheduler",
            "rustleaks_sources::scheduler",
            "crate-private",
            "The Go semaphore is hidden scheduling policy; callers configure limits without receiving a semaphore object.",
            "detection-and-codec",
        );
    }
    if ["MaxArchiveDepth", "FollowSymlinks"].contains(&name) {
        return attrs("idiomatic-public-replacement", "detect.source-options", "rustleaks-sources", "options",
            if name == "MaxArchiveDepth" { "rustleaks_sources::ArchiveLimits::new" } else { "rustleaks_sources::DirectoryOptions::follow_symlinks" }, "public",
            "Archive depth and symlink following are source-adapter builder options, not mutable core detector fields.", "detection-and-codec")
            .links(&["SRC-014", "SRC-016", "SRC-019", "SRC-029", "SRC-030"])
            .tested("crates/rustleaks-sources/src/archive.rs; crates/rustleaks-sources/src/directory.rs; crates/rustleaks-sources/tests/source_corpus.rs");
    }
    if name == "TotalBytes" {
        return attrs("idiomatic-public-replacement", "detect.scan-statistics", "rustleaks-sources", "runner",
        "rustleaks_sources::SourceOutcome::scanned_bytes", "public",
        "A completed source outcome exposes checked scanned-byte statistics instead of a mutable public atomic counter on the engine.", "detection-and-codec")
        .links(&["SRC-028", "SRC-029"]).tested("crates/rustleaks-sources/src/runner.rs; crates/rustleaks-sources/tests/native_sources.rs; cargo xtask source-check");
    }
    if [
        "Redact",
        "MaxDecodeDepth",
        "MaxTargetMegaBytes",
        "IgnoreGitleaksAllow",
    ]
    .contains(&name)
    {
        let mut links = vec!["MODEL-003"];
        if name == "MaxDecodeDepth" {
            links.push("DEC-010");
        }
        if name == "Redact" {
            links.extend(["RED-001", "RED-002", "RED-003"]);
        }
        let evidence = if name == "MaxDecodeDepth" {
            "crates/rustleaks-core/tests/model.rs; crates/rustleaks-core/tests/detect_corpus.rs; cargo xtask decoder-check"
        } else if name == "Redact" {
            "crates/rustleaks-core/tests/model.rs; crates/rustleaks-core/tests/composite_corpus.rs; cargo xtask composite-check"
        } else {
            "crates/rustleaks-core/tests/model.rs"
        };
        return attrs("idiomatic-public-replacement", "detect.scan-options", "rustleaks-core", "model",
            "rustleaks_core::ScanOptions", "public",
            "Per-scan immutable options replace mutable detector flags; honor_gitleaks_allow uses non-inverted naming.", "detection-and-codec")
            .links(&links).tested(evidence);
    }
    attrs("idiomatic-public-replacement", "detect.engine-config", "rustleaks-core", "engine", "rustleaks_core::Engine", "public",
        "The engine owns immutable CompiledConfig rather than exposing mutable detector configuration.", "detection-and-codec")
        .tested("crates/rustleaks-core/src/engine.rs; crates/rustleaks-core/tests/engine.rs; cargo xtask detect-check")
}
