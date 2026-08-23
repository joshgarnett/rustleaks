//! Generator, CLI, SCM, regexp, logging, and version disposition rules.

use super::super::inventory::{Inventory, Record};
use super::super::model::{Attrs, attrs};
use super::member;

const GENERATOR_EVIDENCE: &str =
    "compat/generator-corpus; compat/extract_generator_samples.rb; cargo xtask generator-check";

pub(super) fn annotation(record: &Record, inventory: &Inventory) -> Result<Attrs, String> {
    let package = record.package.as_str();
    if package.ends_with("/cmd/generate/config/rules") {
        return generator_rules(record, inventory);
    }
    if package.ends_with("/cmd/generate/config/base") {
        return Ok(generator_base());
    }
    if package.ends_with("/cmd/generate/config/utils") {
        return Ok(generator_utils(record));
    }
    if package.ends_with("/cmd/generate/secrets") {
        return Ok(generator_secrets());
    }
    if package.ends_with("/cmd") {
        return Ok(command(record));
    }
    if package.ends_with("/cmd/scm") {
        return Ok(scm());
    }
    if package.ends_with("/regexp") {
        return Ok(regexp(record));
    }
    if package.ends_with("/logging") {
        return Ok(logging(record));
    }
    if package.ends_with("/version") {
        return Ok(version(record));
    }
    Err(format!("unclassified API record: {}", record.key))
}

fn generator_rules(record: &Record, inventory: &Inventory) -> Result<Attrs, String> {
    if record.kind == "func" {
        let id = inventory
            .generator_ids
            .get(&record.name)
            .ok_or_else(|| format!("missing generator ID for {}", record.name))?;
        return Ok(attrs(
            "compatibility-tooling-private-implementation", "generator.rule-constructors",
            "rustleaks-compat", "generator::rules",
            format!("rustleaks_compat::generator::rules::{}", record.name), "tooling-private",
            "The constructor is compatibility corpus input, not a 225-function runtime API; its selected rule becomes embedded default config and all samples remain oracle evidence.",
            "root-cli-generator-auxiliary-packages",
        ).links(&["GEN-ALL-001"]).manifests(&[id]).tested(GENERATOR_EVIDENCE));
    }
    Ok(attrs(
        "compatibility-tooling-private-implementation", "generator.default-stopwords",
        "rustleaks-compat", "generator::rules", "rustleaks_compat::generator::rules::DEFAULT_STOP_WORDS",
        "tooling-private", "Default stop words are embedded generation data with golden evidence, not mutable public runtime state.",
        "root-cli-generator-auxiliary-packages",
    ).links(&["GEN-ALL-001"]).tested(GENERATOR_EVIDENCE))
}

fn generator_base() -> Attrs {
    attrs(
        "compatibility-tooling-private-implementation", "generator.default-config-assembly",
        "rustleaks-compat", "generator::base", "rustleaks_compat::generator::base::create_global_config",
        "tooling-private", "Global-config assembly is a corpus/default-config producer and is intentionally absent from the runtime library surface.",
        "root-cli-generator-auxiliary-packages",
    ).links(&["GEN-ALL-001"]).tested(GENERATOR_EVIDENCE)
}

fn generator_utils(record: &Record) -> Attrs {
    let (cluster, path, justification) = if [
        "GenerateSemiGenericRegex",
        "GenerateUniqueTokenRegex",
        "MergeRegexps",
    ]
    .contains(&record.name.as_str())
    {
        (
            "generator.regex-construction",
            format!("rustleaks_compat::generator::regex::{}", record.name),
            "Generated-regex behavior stays private compatibility tooling and corpus evidence; it must not expose the Rust regex backend.",
        )
    } else if ["Validate", "ValidateWithPaths"].contains(&record.name.as_str()) {
        (
            "generator.rule-validation",
            format!("rustleaks_compat::generator::validate::{}", record.name),
            "Constructor validation is an oracle/corpus harness that preserves embedded assertions without becoming runtime API.",
        )
    } else {
        (
            "generator.sample-secrets",
            format!("rustleaks_compat::generator::samples::{}", record.name),
            "Synthetic sample generation is deterministic dev/test tooling, not a published runtime capability.",
        )
    };
    attrs(
        "compatibility-tooling-private-implementation",
        cluster,
        "rustleaks-compat",
        &cluster.replace('.', "::"),
        path,
        "tooling-private",
        justification,
        "root-cli-generator-auxiliary-packages",
    )
    .links(&["GEN-ALL-001"])
    .tested(GENERATOR_EVIDENCE)
}

fn generator_secrets() -> Attrs {
    attrs(
        "compatibility-tooling-private-implementation", "generator.secret-synthesis", "rustleaks-compat",
        "generator::secrets", "rustleaks_compat::generator::secrets::new_secret", "tooling-private",
        "Reggen-backed secret synthesis is test tooling; Rust replaces incidental panic control flow with a tooling error.",
        "root-cli-generator-auxiliary-packages",
    ).links(&["GEN-ALL-001"]).tested(GENERATOR_EVIDENCE)
}

fn command(record: &Record) -> Attrs {
    let name = record.name.as_str();
    if ["Config", "Detector"].contains(&name) && record.kind == "func" {
        return attrs(
            "out-of-public-product-scope", "cmd.legacy-assembly", "rustleaks-cli", "run",
            "rustleaks_cli::run_from", "binary-private",
            "The Go CLI assembly helper is implemented inside the thin injected runner through ConfigLoader, Engine, ScanOptions, source adapters, and ScanSession rather than exposed as an embedding API.",
            "root-cli-generator-auxiliary-packages",
        ).links(&["CLI-002", "CLI-003", "CLI-004", "CLI-005", "CLI-006", "CLI-SAFE-002", "CLI-SAFE-005"])
         .tested("crates/rustleaks-cli/src/config.rs; crates/rustleaks-cli/src/run.rs; crates/rustleaks-cli/src/source.rs; crates/rustleaks-cli/tests/cli.rs");
    }
    if name == "Execute" && record.kind == "func" {
        return attrs(
            "out-of-public-product-scope", "cmd.execution", "rustleaks-cli", "run",
            "rustleaks_cli::run_from", "binary-private",
            "Command execution belongs to the thin binary; the implemented injected runner preserves the declared CLI contract without becoming an engine API.",
            "root-cli-generator-auxiliary-packages",
        ).links(&["CLI-001", "CLI-007", "CLI-008", "CLI-009", "CLI-010", "CLI-011", "CLI-012", "CLI-013", "CLI-014", "CLI-015", "CLI-SAFE-001", "CLI-SAFE-002", "CLI-SAFE-003", "CLI-SAFE-004", "CLI-SAFE-005", "CLI-DEFER-001"])
         .tested("crates/rustleaks-cli/src/lib.rs; crates/rustleaks-cli/src/run.rs; crates/rustleaks-cli/tests/cli.rs");
    }
    if name == "FormatDuration" && record.kind == "func" {
        return attrs(
            "out-of-public-product-scope", "cmd.duration-formatting", "rustleaks-cli", "output",
            "rustleaks_cli::output::format_duration", "binary-private",
            "Human CLI duration formatting is implemented as private presentation behavior rather than core scanning API.",
            "root-cli-generator-auxiliary-packages",
        ).links(&["CLI-009"]).tested("crates/rustleaks-cli/src/output.rs; crates/rustleaks-cli/tests/cli.rs");
    }
    if ["BYTE", "KILOBYTE", "MEGABYTE", "GIGABYTE"].contains(&name) {
        return attrs(
            "out-of-public-product-scope", "cmd.byte-units", "rustleaks-cli", "output",
            "rustleaks_cli::output::human_bytes", "binary-private",
            "CLI byte units are implemented in private checked presentation and threshold mapping rather than exposed as public engine constants.",
            "root-cli-generator-auxiliary-packages",
        ).links(&["CLI-004", "CLI-009", "CLI-014", "CLI-SAFE-005"])
         .tested("crates/rustleaks-cli/src/output.rs; crates/rustleaks-cli/src/source.rs; crates/rustleaks-cli/tests/cli.rs");
    }
    attrs(
        "out-of-public-product-scope", "cmd.diagnostics", "rustleaks-cli", "diagnostics",
        format!("rustleaks_cli::diagnostics::{}", member(record)), "binary-private",
        "Process-global CPU, memory, trace, and HTTP diagnostics remain optional P2 CLI orchestration; no global profiler manager is exposed to embedders.",
        "root-cli-generator-auxiliary-packages",
    ).links(&["CLI-DEFER-001"])
}

fn scm() -> Attrs {
    attrs(
        "equivalent-public-api", "scm.platform", "rustleaks-sources", "scm",
        "rustleaks_sources::scm::ScmPlatform", "public",
        "A public ScmPlatform enum with Display and FromStr preserves unknown versus none, platform values, parsing, and display without Go integer mutability.",
        "scm-and-regexp",
    ).links(&["MODEL-002"]).tested("crates/rustleaks-sources/src/scm.rs; crates/rustleaks-sources/tests/git_scm.rs; cargo xtask git-check")
}

fn regexp(record: &Record) -> Attrs {
    let (cluster, path, justification) = match record.name.as_str() {
        "Version" => (
            "regexp.backend-metadata",
            "rustleaks_core::regex::backend_version",
            "Backend version is compatibility metadata only and must not make backend selection part of public API.",
        ),
        "Regexp" => (
            "regexp.backend-abstraction",
            "rustleaks_core::regex::GoRegex",
            "The build-selected backend alias is hidden behind private GoRegex so backend methods cannot leak into the public Rust contract.",
        ),
        _ => (
            "regexp.compilation",
            "rustleaks_core::regex::GoRegex::compile",
            "MustCompile becomes fallible private compilation for untrusted config; panic compatibility is limited to tooling tests.",
        ),
    };
    attrs(
        "compatibility-tooling-private-implementation",
        cluster,
        "rustleaks-core",
        "regex",
        path,
        "crate-private",
        justification,
        "scm-and-regexp",
    )
    .links(&["REGEX-GOREGEX-005"])
    .tested("crates/rustleaks-core/src/regex; cargo xtask regex-check")
}

fn logging(record: &Record) -> Attrs {
    let terminating = ["Fatal", "Panic"].contains(&record.name.as_str());
    attrs(
        "out-of-public-product-scope",
        if terminating {
            "logging.terminating-control-flow"
        } else {
            "logging.global-facade"
        },
        "rustleaks-cli",
        "logging",
        format!("rustleaks_cli::logging::{}", member(record)),
        "binary-private",
        if terminating {
            "Fatal and panic logging are never library control flow; core returns structured errors and only the CLI chooses termination policy."
        } else {
            "The mutable global logger facade is intentionally absent from core; libraries return structured diagnostics and callers select logging."
        },
        "root-cli-generator-auxiliary-packages",
    )
}

fn version(record: &Record) -> Attrs {
    attrs(
        "out-of-public-product-scope",
        "version.build-metadata",
        "rustleaks-cli",
        "version",
        format!("rustleaks_cli::version::{}", record.name),
        "binary-private",
        "Mutable build-process globals become immutable CLI build metadata; the exact display string is P2 compatibility data, not core API.",
        "root-cli-generator-auxiliary-packages",
    )
}
