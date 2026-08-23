//! Configuration disposition rules.

use super::super::inventory::Record;
use super::super::model::{Attrs, attrs};

pub(super) fn annotation(record: &Record) -> Result<Attrs, String> {
    let mut result = classify(record)?;
    let cluster = result.cluster.clone();
    if cluster == "config.compiled-allowlist-matching" {
        let links = match record.name.as_str() {
            "CommitAllowed" => &["AL-001", "AL-002", "AL-018"][..],
            "PathAllowed" => &["AL-001", "AL-003", "AL-018"],
            "RegexAllowed" => &["AL-001", "AL-004", "AL-018"],
            "ContainsStopWord" => &["AL-001", "AL-005", "AL-018"],
            _ => {
                return Err(format!(
                    "unmapped compiled allowlist method: {}",
                    record.name
                ));
            }
        };
        result = result
            .links(links)
            .tested("crates/rustleaks-core/tests/allowlist.rs; cargo xtask allowlist-check");
        return Ok(result);
    }
    let links: &[&str] = if cluster == "config.default-config" {
        &["CONFIG-DEFAULT-004"][..]
    } else if cluster == "config.extension-spec" {
        &["CONFIG-RAW-001", "CONFIG-EXTEND-003"]
    } else if cluster == "config.raw-translation" {
        &["CONFIG-RAW-001", "CONFIG-COMPILE-002", "CONFIG-EXTEND-003"]
    } else if cluster.starts_with("config.raw-") {
        &["CONFIG-RAW-001"]
    } else {
        &["CONFIG-COMPILE-002"]
    };
    let evidence = if ["config.raw-translation", "config.rule-compilation"]
        .contains(&cluster.as_str())
    {
        "crates/rustleaks-core/tests/config.rs; crates/rustleaks-core/src/regex; cargo xtask parity --scope regex"
    } else {
        "crates/rustleaks-core/tests/config.rs; cargo xtask config-check"
    };
    Ok(result.links(links).tested(evidence))
}

fn classify(record: &Record) -> Result<Attrs, String> {
    let name = record.name.as_str();
    let owner = record.owner.as_str();
    let kind = record.kind.as_str();
    if name == "DefaultConfig" && kind == "var" {
        return Ok(attrs("equivalent-public-api", "config.default-config", "rustleaks-core", "config::default",
            "rustleaks_core::config::DEFAULT_CONFIG", "public",
            "The mutable Go variable becomes immutable pinned default-config bytes plus revision/hash metadata.",
            "configuration").links(&["BOOT-001", "GEN-ALL-001"]));
    }
    if owner == "AllowlistMatchCondition" || name.starts_with("AllowlistMatch") {
        return Ok(attrs("equivalent-public-api", "config.allowlist-condition", "rustleaks-core", "config::allowlist",
            "rustleaks_core::config::AllowlistCondition", "public",
            "A public raw enum and Display preserve OR/AND identity and externally visible spelling while avoiding integerly typed state.",
            "configuration").links(&["TM-ALL-001"]));
    }
    if owner == "Allowlist" || (kind == "type" && name == "Allowlist") {
        return allowlist(record);
    }
    if owner == "ViperConfig"
        || owner.starts_with("ViperConfig.Rules")
        || owner.starts_with("viper")
        || (kind == "type" && name == "ViperConfig")
    {
        return Ok(viper(record));
    }
    if owner == "Config" || (kind == "type" && name == "Config") {
        return Ok(attrs("idiomatic-public-replacement", "config.compiled-config", "rustleaks-core", "config::compiled",
            "rustleaks_core::config::CompiledConfig", "public",
            "Mutable Config fields become immutable compiled state with read-only semantic access; regex/trie maps and ordering machinery remain private.",
            "configuration").links(&["TM-ALL-001"]));
    }
    if owner == "Extend" || (kind == "type" && name == "Extend") {
        return Ok(attrs("equivalent-public-api", "config.extension-spec", "rustleaks-core", "config::raw",
            "rustleaks_core::config::ConfigExtension", "public",
            "ConfigExtension preserves path, URL, default, and disabled-rule inputs while resolution moves behind an injected resolver.",
            "configuration").links(&["TM-ALL-001"]));
    }
    if owner == "Rule" || (kind == "type" && name == "Rule") {
        return Ok(rule(record));
    }
    if owner == "Required" || (kind == "type" && name == "Required") {
        return Ok(attrs("equivalent-public-api", "config.required-rule-spec", "rustleaks-core", "config::raw",
            "rustleaks_core::config::RequiredRuleSpec", "public",
            "RequiredRuleSpec directly preserves rule ID and optional line/column distances in a constructible public type.",
            "configuration").links(&["TM-ALL-001"]));
    }
    Err(format!("unclassified config API: {}", record.key))
}

fn allowlist(record: &Record) -> Result<Attrs, String> {
    if record.kind == "method" {
        if record.name == "Validate" {
            return Ok(attrs("idiomatic-public-replacement", "config.allowlist-compilation", "rustleaks-core", "config::allowlist",
                "rustleaks_core::config::ConfigLoader::compile", "public",
                "Mutable validate-in-place becomes fallible compilation from AllowlistSpec with structured errors.",
                "configuration").links(&["TM-ALL-001"]));
        }
        let method = match record.name.as_str() {
            "CommitAllowed" => "commit_allowed",
            "PathAllowed" => "path_allowed",
            "RegexAllowed" => "regex_allowed",
            "ContainsStopWord" => "contains_stop_word",
            _ => return Err(format!("unclassified Allowlist method: {}", record.name)),
        };
        return Ok(attrs("compatibility-tooling-private-implementation", "config.compiled-allowlist-matching",
            "rustleaks-core", "config::compiled", format!("rustleaks_core::config::CompiledAllowlist::{method}"),
            "crate-private", "Commit/path/regex/stop-word matching remains an internal pure operation over a compiled allowlist; backend regex objects are not public.",
            "configuration").links(&["TM-ALL-001"]));
    }
    let patterns = ["Paths", "Regexes", "RegexTarget"].contains(&record.name.as_str());
    Ok(attrs("idiomatic-public-replacement", if patterns { "config.allowlist-pattern-spec" } else { "config.allowlist-spec" },
        "rustleaks-core", "config::allowlist", "rustleaks_core::config::AllowlistSpec", "public",
        if patterns { "Public raw pattern strings live in AllowlistSpec while compiled regex values remain private behind the GoRegex compatibility gate." }
        else { "Constructible AllowlistSpec replaces mutable Go fields and compiles into an immutable CompiledAllowlist with semantic accessors." },
        "configuration").links(&["TM-ALL-001"]))
}

fn viper(record: &Record) -> Attrs {
    if record.kind == "method" && record.name == "Translate" {
        return attrs("idiomatic-public-replacement", "config.raw-translation", "rustleaks-core", "config::loader",
            "rustleaks_core::config::ConfigLoader::compile", "public",
            "Translate becomes fallible RawConfig compilation with structured ConfigError and injected extension resolution.",
            "configuration").links(&["TM-ALL-001"]);
    }
    let (path, cluster) = if record.owner.starts_with("ViperConfig.Rules") {
        ("rustleaks_core::config::RuleSpec", "config.raw-rule-spec")
    } else if record.owner == "viperRuleAllowlist" {
        (
            "rustleaks_core::config::RawAllowlist",
            "config.raw-allowlist",
        )
    } else if record.owner == "viperGlobalAllowlist" {
        (
            "rustleaks_core::config::RawGlobalAllowlist",
            "config.raw-global-allowlist",
        )
    } else if record.owner == "viperRequired" {
        (
            "rustleaks_core::config::RequiredRuleSpec",
            "config.raw-required-rule",
        )
    } else {
        ("rustleaks_core::config::RawConfig", "config.raw-config")
    };
    attrs("idiomatic-public-replacement", cluster, "rustleaks-core", "config::raw", path, "public",
        "The permissive public raw configuration shape uses named serde-friendly Rust structs and aliases instead of anonymous or unnameable Go element types.",
        "configuration").links(&["TM-ALL-001"])
}

fn rule(record: &Record) -> Attrs {
    if record.kind == "method" {
        return attrs("idiomatic-public-replacement", "config.rule-compilation", "rustleaks-core", "config::compiled",
            "rustleaks_core::config::ConfigLoader::compile", "public",
            "Mutable Rule.Validate becomes fallible RuleSpec compilation with structured errors and private compiled regexes.",
            "configuration").links(&["TM-ALL-001"]);
    }
    let patterns = ["Regex", "Path"].contains(&record.name.as_str());
    attrs("idiomatic-public-replacement", if patterns { "config.rule-pattern-spec" } else { "config.rule-spec" },
        "rustleaks-core", "config::raw", "rustleaks_core::config::RuleSpec", "public",
        if patterns { "RuleSpec exposes raw regex/path source text while compiled engines remain private and inspectable only semantically." }
        else { "Public RuleSpec preserves rule data/order/duplicates and compiles into an immutable CompiledRule." },
        "configuration").links(&["TM-ALL-001"])
}
