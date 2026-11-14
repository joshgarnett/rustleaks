//! Check six reviewed ASCII connection rules and MIT/Apache-2.0 provenance.
//! This is a fixed translation inventory, not a runtime pattern interpreter.

use std::path::Path;

const DIRECTORY: &str = "crates/rustleaks-core/default";

struct ReviewedRule {
    id: &'static str,
    upstream_id: &'static str,
    description: &'static str,
    source_pattern_sha256: &'static str,
    native_pattern_sha256: &'static str,
    unquoted_requirements: bool,
    source_line: u64,
}

const LITERAL_STOPWORDS: [&str; 27] = [
    "${",
    "$(",
    "#{",
    "{{",
    "$env:",
    "redacted",
    "masked",
    "filtered",
    "****",
    "xxxx",
    "placeholder",
    "your_password",
    "yourpassword",
    "your-password",
    "your password",
    "insert_password",
    "replace_password",
    "changeme",
    "change_me",
    "change-me",
    "change.me",
    "change me",
    "replaceme",
    "replace_me",
    "replace-me",
    "replace.me",
    "replace me",
];

const UNQUOTED_STOPWORDS: [&str; 43] = [
    "${",
    "$(",
    "#{",
    "{{",
    "$env:",
    "redacted",
    "masked",
    "filtered",
    "****",
    "xxxx",
    "placeholder",
    "your_password",
    "yourpassword",
    "your-password",
    "your password",
    "insert_password",
    "replace_password",
    "changeme",
    "change_me",
    "change-me",
    "change.me",
    "change me",
    "replaceme",
    "replace_me",
    "replace-me",
    "replace.me",
    "replace me",
    "db_password",
    "database_password",
    "process.env",
    "os.environ",
    "config.",
    "config[",
    "settings.",
    "settings[",
    "secret.",
    "secrets.",
    "secrets[",
    "credential.",
    "credentials.",
    "credentials[",
    "getpassword(",
    "getenv(",
];

const REVIEWED: [ReviewedRule; 5] = [
    ReviewedRule {
        id: "rustleaks.connection-string.password.double-quoted",
        upstream_id: "kingfisher.connection-string.password.double-quoted",
        description: "ASCII database connection password (double quoted)",
        source_pattern_sha256: "af11c3749b82660407fd16c14c35c96f277073a1eb45a8a8b8800537367d81e6",
        native_pattern_sha256: "cfddc90155c54c43645188c3ca9be81ecc7ee93de62fce1f52f551e685e10e55",
        unquoted_requirements: false,
        source_line: 24,
    },
    ReviewedRule {
        id: "rustleaks.connection-string.password.single-quoted",
        upstream_id: "kingfisher.connection-string.password.single-quoted",
        description: "ASCII database connection password (single quoted)",
        source_pattern_sha256: "140cb1b544c58910b7d2463036f5c652d20836ea69574c8c8867b408841124f1",
        native_pattern_sha256: "0019316c90fab431cf15a60ae3f9b2d93ef1ef1e45ef719546f3eb267430e43f",
        unquoted_requirements: false,
        source_line: 83,
    },
    ReviewedRule {
        id: "rustleaks.connection-string.password.odbc-braced",
        upstream_id: "kingfisher.connection-string.password.odbc-braced",
        description: "ASCII database connection password (odbc braced)",
        source_pattern_sha256: "0366f804bcf6d23ac694ae9790cef01fb710e56652d6ef797ea7c9c39986eb28",
        native_pattern_sha256: "9e29696a6df533022c8509b9dcf8f87b40aee20c461dd21ffaaf2c958f10ce29",
        unquoted_requirements: false,
        source_line: 104,
    },
    ReviewedRule {
        id: "rustleaks.connection-string.password.unquoted",
        upstream_id: "kingfisher.connection-string.password.unquoted",
        description: "ASCII database connection password (unquoted)",
        source_pattern_sha256: "a522f1cc289b0c02c41e633b0fbd0a5e5fa585a77f4e2da93a31295462ee8779",
        native_pattern_sha256: "ae4c6c866a23dd3bab61994f11db142a08a4a0b3189ed6b4e3f45efa38158011",
        unquoted_requirements: true,
        source_line: 129,
    },
    ReviewedRule {
        id: "rustleaks.connection-string.password.jdbc-query",
        upstream_id: "kingfisher.connection-string.password.jdbc-query",
        description: "ASCII database connection password (jdbc query)",
        source_pattern_sha256: "645a1e5f416034f5ecfcef43b8a13362b8004b78dcccb1bfa6c2fa7f60a7586e",
        native_pattern_sha256: "82b6e192756fc97db352af016b3d1499c89e8334dcfe8e1bf7da9b0ef2724ff7",
        unquoted_requirements: true,
        source_line: 209,
    },
];

const SOURCE_IDENTITY: &str = r#"{
  "repository": "https://github.com/mongodb/kingfisher",
  "revision": "01e7b817376fbf2272be8f162bd32309bf97ee1f",
  "path": "crates/kingfisher-rules/data/kingfisher-rules.yml",
  "url": "https://github.com/mongodb/kingfisher/blob/01e7b817376fbf2272be8f162bd32309bf97ee1f/crates/kingfisher-rules/data/kingfisher-rules.yml",
  "sha256": "12a5b53962fdcb8572a22d9b320531d6b7cec604f9c54cdca5239edcd833d192",
  "license": "Apache-2.0",
  "license_path": "crates/kingfisher-rules/LICENSE",
  "license_sha256": "43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1",
  "notice_path": "NOTICE",
  "notice_sha256": "72cb7ea966dc7bf6f3a0cc0895c07874c831bd900b92a493ae0f8ab7ae72806f",
  "documentation_sha256": "7ffd8806aeb174278fd14087898f09c09f0f86f789f6cf98b8623bf7f7174110",
  "tests_sha256": "4e44b4acd59a82f1807cfffbd6931b063d463c285c87b15fcadee27424358d38"
}"#;

const TRANSFORMATIONS: [&str; 6] = [
    "Namespace rule IDs and descriptions; preserve source order and capture 1.",
    "Remove reviewed extended-mode formatting; expand ASCII-insensitive literals and positive classes explicitly; preserve the case-sensitive JDBC password key.",
    "Intersect negated byte classes with ASCII using explicit positive byte ranges; preserve all bounds, greediness, alternatives, and consumed delimiters.",
    "Unroll the capture-free JDBC preceding-option repetition into sixteen sequential greedy optional groups; preserve 0 through 16 options without exceeding the existing nested-repeat product limit.",
    "Map the complete case-insensitive secret substring exclusions to rule-local secret stopwords; preserve absent keywords as an empty list and omit the zero entropy floor.",
    "Retain raw percent spelling and doubled ODBC braces; inherit unchanged Rustleaks source policy, global allowlists, finding geometry, decoding, and resource controls.",
];

pub(super) fn validate(root: &Path) -> Result<(), String> {
    let directory = root.join(DIRECTORY);
    let provenance =
        std::fs::read_to_string(directory.join("rustleaks-connections-v1.provenance.json"))
            .map_err(|error| format!("cannot read connection provenance: {error}"))?;
    let pack = std::fs::read_to_string(directory.join("rustleaks-connections-v1.toml"))
        .map_err(|error| format!("cannot read connection pack: {error}"))?;
    let license = super::sha256_file(&directory.join("LICENSE.kingfisher"))?;
    let uri_license = super::sha256_file(&directory.join("LICENSE.betterleaks"))?;
    validate_contents(&provenance, &pack, &license, &uri_license)
}

fn validate_contents(
    provenance: &str,
    pack: &str,
    license: &str,
    uri_license: &str,
) -> Result<(), String> {
    let provenance: serde_json::Value = serde_json::from_str(provenance)
        .map_err(|error| format!("invalid connection provenance: {error}"))?;
    let source: serde_json::Value = serde_json::from_str(SOURCE_IDENTITY)
        .map_err(|error| format!("invalid retained connection source identity: {error}"))?;
    if provenance.as_object().map(serde_json::Map::len) != Some(7)
        || provenance["schema_version"] != 1
        || provenance["pack_id"] != "rustleaks-connections-v1"
        || provenance["source"] != source
        || provenance["supported_domain"]
            != "ASCII match bytes; cross-tool comparison requires entirely ASCII raw input"
        || provenance["transformations"] != serde_json::json!(TRANSFORMATIONS)
        || source["license_sha256"] != license
    {
        return Err("connection source identity, license or scope differs".into());
    }
    let config: toml::Value =
        toml::from_str(pack).map_err(|error| format!("invalid connection pack: {error}"))?;
    let config = config.as_table().ok_or("connection pack must be a table")?;
    if config.len() != 2
        || config.get("title").and_then(toml::Value::as_str)
            != Some("Rustleaks connection rules v1")
    {
        return Err("connection pack contains an unreviewed field".into());
    }
    let rules = config
        .get("rules")
        .and_then(toml::Value::as_array)
        .ok_or("connection pack has no rules")?;
    let origins = provenance["rules"]
        .as_array()
        .ok_or("connection provenance has no rules")?;
    if rules.len() != REVIEWED.len() + 1 || origins.len() != REVIEWED.len() + 1 {
        return Err("connection rule inventory differs".into());
    }
    for ((rule, origin), reviewed) in rules.iter().zip(origins).zip(&REVIEWED) {
        validate_rule(rule, origin, reviewed)?;
    }
    validate_database_uri(
        &provenance["database_uri_source"],
        &origins[REVIEWED.len()],
        &rules[REVIEWED.len()],
        uri_license,
    )
}

// These hashes bind complete reviewed semantic objects, including absent and
// added fields, predicate targets, source filters, overlay disposition and order.
// serde_json's default object map serializes keys in lexical order.
fn reviewed_json_hash(value: &serde_json::Value) -> Result<String, String> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| format!("cannot encode reviewed URI metadata: {error}"))?;
    Ok(super::sha256_bytes(&encoded))
}

fn validate_database_uri(
    source: &serde_json::Value,
    origin: &serde_json::Value,
    rule: &toml::Value,
    license: &str,
) -> Result<(), String> {
    let rule = serde_json::to_value(rule)
        .map_err(|error| format!("cannot encode reviewed URI rule: {error}"))?;
    if reviewed_json_hash(source)?
        != "26c168a0ad4503d71a9cf53c10e7416c44192c41528621e782424bb85a17df78"
        || reviewed_json_hash(origin)?
            != "fa1f12e3390f44b516fcd791928ca3e8bf0b0c29d2180b270f79f46695751f26"
        || reviewed_json_hash(&rule)?
            != "d6cf57da2191b1a50355d0bd097dc4cf462b359b741f2df788d1f5db90cda6c3"
        || source["license_sha256"] != license
    {
        return Err("database URI source, predicates, native rule or license differs".into());
    }
    Ok(())
}

fn validate_rule(
    rule: &toml::Value,
    origin: &serde_json::Value,
    reviewed: &ReviewedRule,
) -> Result<(), String> {
    let stopwords: &[&str] = if reviewed.unquoted_requirements {
        &UNQUOTED_STOPWORDS
    } else {
        &LITERAL_STOPWORDS
    };
    let source_pattern = origin["source_pattern"]
        .as_str()
        .ok_or("connection source pattern is missing")?;
    let native_pattern = origin["native_pattern"]
        .as_str()
        .ok_or("connection native pattern is missing")?;
    if super::sha256_bytes(source_pattern.as_bytes()) != reviewed.source_pattern_sha256
        || super::sha256_bytes(native_pattern.as_bytes()) != reviewed.native_pattern_sha256
        || *origin
            != serde_json::json!({
                "id": reviewed.id,
                "upstream_id": reviewed.upstream_id,
                "source_line": reviewed.source_line,
                "source_pattern": source_pattern,
                "source_pattern_sha256": reviewed.source_pattern_sha256,
                "source_confidence": "medium",
                "source_min_entropy": 0,
                "source_keywords": [],
                "source_pattern_requirements": {"ignore_if_contains": stopwords},
                "source_validation": null,
                "source_revocation": null,
                "source_filter": null,
                "native_pattern": native_pattern,
                "secret_group": 1,
            })
    {
        return Err(format!(
            "connection source predicate differs for {}",
            reviewed.id
        ));
    }
    let rule = rule.as_table().ok_or("connection rule must be a table")?;
    let expected_stopwords = toml::Value::Array(
        stopwords
            .iter()
            .map(|word| toml::Value::String((*word).to_owned()))
            .collect(),
    );
    let allowlists = rule
        .get("allowlists")
        .and_then(toml::Value::as_array)
        .filter(|entries| entries.len() == 1)
        .and_then(|entries| entries[0].as_table())
        .ok_or("connection rule must have exactly one secret allowlist")?;
    if rule.len() != 6
        || rule.get("id").and_then(toml::Value::as_str) != Some(reviewed.id)
        || rule.get("description").and_then(toml::Value::as_str) != Some(reviewed.description)
        || rule.get("regex").and_then(toml::Value::as_str) != Some(native_pattern)
        || rule.get("secretGroup").and_then(toml::Value::as_integer) != Some(1)
        || rule
            .get("keywords")
            .and_then(toml::Value::as_array)
            .is_none_or(|items| !items.is_empty())
        || allowlists.len() != 3
        || allowlists.get("description").and_then(toml::Value::as_str)
            != Some("Source ignore-if-contains secret substrings")
        || allowlists.get("regexTarget").and_then(toml::Value::as_str) != Some("secret")
        || allowlists.get("stopwords") != Some(&expected_stopwords)
    {
        return Err(format!(
            "connection native rule differs for {}",
            reviewed.id
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_omitted_predicates_changed_patterns_and_added_fields() {
        let root = crate::workspace_root().unwrap();
        let directory = root.join(DIRECTORY);
        let provenance =
            std::fs::read_to_string(directory.join("rustleaks-connections-v1.provenance.json"))
                .unwrap();
        let pack =
            std::fs::read_to_string(directory.join("rustleaks-connections-v1.toml")).unwrap();
        let license = super::super::sha256_file(&directory.join("LICENSE.kingfisher")).unwrap();
        let uri_license =
            super::super::sha256_file(&directory.join("LICENSE.betterleaks")).unwrap();
        assert!(validate_contents(&provenance, &pack, &license, &uri_license).is_ok());
        for changed in [
            pack.replacen("    \"masked\",\n", "", 1),
            pack.replacen("{4,128}", "{1,128}", 1),
            pack.replacen("regexTarget = \"secret\"", "regexTarget = \"match\"", 1),
            pack.replacen("keywords = []", "keywords = ['jdbc']", 1),
            pack.replacen("secretGroup = 1", "secretGroup = 0", 1),
            pack.replacen("keywords = []", "entropy = 3.5\nkeywords = []", 1),
        ] {
            assert_ne!(changed, pack);
            assert!(validate_contents(&provenance, &changed, &license, &uri_license).is_err());
        }
        assert!(validate_contents(&provenance, &pack, &license, "wrong-license").is_err());
        let mut uri_changed: toml::Value = toml::from_str(&pack).unwrap();
        uri_changed["rules"][5]["allowlists"][0]["regexes"] = toml::Value::Array(Vec::new());
        assert!(
            validate_contents(
                &provenance,
                &toml::to_string(&uri_changed).unwrap(),
                &license,
                &uri_license
            )
            .is_err()
        );
        let mut uri_changed: toml::Value = toml::from_str(&pack).unwrap();
        uri_changed["rules"][5]["allowlists"][0]["regexes"][0] =
            toml::Value::String("(?i)^true|false|null$".to_owned());
        assert!(
            validate_contents(
                &provenance,
                &toml::to_string(&uri_changed).unwrap(),
                &license,
                &uri_license
            )
            .is_err()
        );
        let mut uri_changed: toml::Value = toml::from_str(&pack).unwrap();
        let predicate = uri_changed["rules"][5]["allowlists"][1]["regexes"][0]
            .as_str()
            .unwrap()
            .replace(r"\x09\x0a\x0c\x0d\x20", r"\x09-\x0d\x20");
        uri_changed["rules"][5]["allowlists"][1]["regexes"][0] = toml::Value::String(predicate);
        assert!(
            validate_contents(
                &provenance,
                &toml::to_string(&uri_changed).unwrap(),
                &license,
                &uri_license
            )
            .is_err()
        );
        let mut uri_changed: serde_json::Value = serde_json::from_str(&provenance).unwrap();
        uri_changed["rules"][5]["source_filter"] = serde_json::json!("false");
        assert!(
            validate_contents(&uri_changed.to_string(), &pack, &license, &uri_license).is_err()
        );
        let mut changed: serde_json::Value = serde_json::from_str(&provenance).unwrap();
        changed["rules"][0]["source_pattern_requirements"]["ignore_if_contains"] =
            serde_json::json!([]);
        assert!(validate_contents(&changed.to_string(), &pack, &license, &uri_license).is_err());
        assert!(validate_contents(&provenance, &pack, "wrong-license", &uri_license).is_err());
    }
}
