//! Generate and check packaged native identities and imported-rule provenance.

use std::path::Path;

const DIRECTORY: &str = "crates/rustleaks-core/default";
const PACKS: [&str; 3] = [
    "rustleaks-extra-v1",
    "rustleaks-providers-v1",
    "rustleaks-connections-v1",
];

pub(crate) fn generate(root: &Path, check: bool) -> Result<(), String> {
    validate_provider_provenance(root)?;
    super::connection_assets::validate(root)?;
    for name in PACKS {
        let pack = root.join(DIRECTORY).join(format!("{name}.toml"));
        let identity = root.join(DIRECTORY).join(format!("{name}.sha256"));
        let digest = super::sha256_file(&pack)?;
        if check {
            let retained = std::fs::read_to_string(&identity)
                .map_err(|error| format!("cannot read native pack identity: {error}"))?;
            if retained != digest {
                return Err(format!(
                    "{name} identity is stale; run xtask generate native-pack-identity"
                ));
            }
        } else {
            std::fs::write(identity, digest)
                .map_err(|error| format!("cannot write native pack identity: {error}"))?;
        }
    }
    Ok(())
}

fn validate_provider_provenance(root: &Path) -> Result<(), String> {
    let directory = root.join(DIRECTORY);
    let source = std::fs::read_to_string(directory.join("rustleaks-providers-v1.provenance.json"))
        .map_err(|error| format!("cannot read provider provenance: {error}"))?;
    let provenance: serde_json::Value = serde_json::from_str(&source)
        .map_err(|error| format!("invalid provider provenance: {error}"))?;
    if provenance["schema_version"] != 1
        || provenance["pack_id"] != "rustleaks-providers-v1"
        || provenance["source"]["revision"] != "8f376ff9c31ed5309ac448fe601c5dd21b376155"
        || provenance["source"]["sha256"]
            != "7c305ade42d5dbad4650b97cca0299f9c16d152ec555ae47bd6f321f049f82e5"
        || provenance["source"]["license"] != "MIT"
        || provenance["source"]["license_sha256"]
            != super::sha256_file(&directory.join("LICENSE.betterleaks"))?
    {
        return Err("provider provenance source identity or license differs".into());
    }
    let source = std::fs::read_to_string(directory.join("rustleaks-providers-v1.toml"))
        .map_err(|error| format!("cannot read provider pack: {error}"))?;
    let config: toml::Value =
        toml::from_str(&source).map_err(|error| format!("invalid provider pack: {error}"))?;
    let config = config.as_table().ok_or("provider pack must be a table")?;
    if config.len() != 2
        || config.get("title").and_then(toml::Value::as_str) != Some("Rustleaks provider rules v1")
    {
        return Err("provider pack contains an unreviewed configuration field".into());
    }
    let native_rules = config
        .get("rules")
        .and_then(toml::Value::as_array)
        .ok_or("provider pack has no rule list")?;
    let rules = provenance["rules"]
        .as_array()
        .ok_or("provider provenance has no rule list")?;
    let reviewed_ids = [
        "rustleaks.groq-api-key",
        "rustleaks.cerebras-api-key",
        "rustleaks.replicate-api-token",
        "rustleaks.nvidia-api-key",
        "rustleaks.anthropic-api-key-escaped",
        "rustleaks.anthropic-admin-api-key-escaped",
        "rustleaks.digitalocean-refresh-token-escaped",
        "rustleaks.openai-api-key-20-segment",
        "rustleaks.flyio-flyv1",
        "rustleaks.cloudsmith-api-key",
        "rustleaks.minimax-api-key",
        "rustleaks.posthog-personal-api-key",
        "rustleaks.figma-personal-access-token",
        "rustleaks.togetherai-api-key",
        "rustleaks.gcp-gemini-api",
    ];
    if rules.len() != reviewed_ids.len() + 89 || native_rules.len() != rules.len() {
        return Err("provider pack rule inventory differs".into());
    }
    super::provider_followup_assets::validate(root, &provenance, native_rules)?;
    super::provider_byte_entropy_assets::validate(&provenance, native_rules)?;
    super::shared_delimiter_assets::validate(&provenance, native_rules)?;
    super::contextual_delimiter_assets::validate(&provenance, native_rules)?;
    for ((rule, origin), reviewed_id) in native_rules.iter().zip(rules).zip(reviewed_ids) {
        if origin["id"] != reviewed_id {
            return Err("provider pack rule order or identity differs".into());
        }
        validate_provider_rule(rule, origin)?;
    }
    Ok(())
}

fn validate_provider_rule(rule: &toml::Value, origin: &serde_json::Value) -> Result<(), String> {
    let rule = rule.as_table().ok_or("provider rule must be a table")?;
    let fields = ["id", "description", "regex", "secretGroup", "keywords"];
    let has_entropy = !origin["entropy"].is_null();
    if rule.len() != fields.len() + usize::from(has_entropy)
        || fields.iter().any(|field| !rule.contains_key(*field))
        || rule.contains_key("entropy") != has_entropy
    {
        return Err("provider rule contains missing or unreviewed fields".into());
    }
    let id = rule["id"]
        .as_str()
        .ok_or("provider rule ID must be a string")?;
    let pattern = rule["regex"]
        .as_str()
        .ok_or("provider regex must be a string")?;
    let entropy = rule
        .get("entropy")
        .map(|value| value.as_float().ok_or("provider entropy must be a float"))
        .transpose()?;
    let secret_group = rule["secretGroup"]
        .as_integer()
        .ok_or("provider secret group must be an integer")?;
    rule["description"]
        .as_str()
        .ok_or("provider description must be a string")?;
    let keywords = rule["keywords"]
        .as_array()
        .ok_or("provider keywords must be an array")?
        .iter()
        .map(|keyword| keyword.as_str().ok_or("provider keyword must be a string"))
        .collect::<Result<Vec<_>, _>>()?;
    let filter = entropy.map(|value| format!("entropy(finding[\"secret\"]) <= {value:.1}\n"));
    let source_validation = if matches!(
        origin["upstream_id"].as_str(),
        Some("nvidia-api-key" | "digitalocean-refresh-token")
    ) {
        "absent"
    } else {
        "present; not imported"
    };
    if origin["id"] != id
        || origin["native_pattern"] != pattern
        || translated_provider_pattern(origin)? != pattern
        || secret_group != 1
        || origin["secret_group"] != secret_group
        || origin["entropy"].as_f64() != entropy
        || origin["source_filter"] != serde_json::json!(filter)
        || origin["source_keywords"] != serde_json::json!(keywords)
        || origin["source_validation"] != source_validation
    {
        return Err(format!(
            "provider rule {id} differs from its reviewed provenance"
        ));
    }
    Ok(())
}

fn translated_provider_pattern(origin: &serde_json::Value) -> Result<String, String> {
    if let Some(pattern) = translated_standalone_pattern(origin)? {
        return Ok(pattern);
    }
    if let Some(pattern) = translated_companion_pattern(origin)? {
        return Ok(pattern);
    }
    let (prefix, expanded, body, expanded_body) = match origin["upstream_id"].as_str() {
        Some("groq-api-key") => ("gsk_", "[gG][sS][kK]_", "[A-Z0-9]", "[A-Za-z0-9]"),
        Some("cerebras-api-key") => ("csk-", "[cC][sS][kK]-", "[a-z0-9]", "[A-Za-z0-9]"),
        Some("replicate-api-token") => ("r8_", "[rR]8_", "[A-Za-z0-9]", "[A-Za-z0-9]"),
        Some("nvidia-api-key") => (
            "nvapi-",
            "[nN][vV][aA][pP][iI]-",
            "[A-Z0-9_-]",
            "[A-Za-z0-9_-]",
        ),
        _ => return Err("unknown provider source rule".into()),
    };
    let pattern = origin["source_pattern"]
        .as_str()
        .and_then(|pattern| pattern.strip_prefix("(?i)\\b("))
        .and_then(|pattern| pattern.strip_prefix(prefix))
        .ok_or("provider source prefix differs from reviewed translation")?;
    Ok(format!(
        "\\b({expanded}{}",
        pattern
            .replace(body, expanded_body)
            .replace(r"[\s;]", r"[\x09-\x0d ;]")
            .replace(r"\\[nr]", r"\\[nNrR]")
    ))
}

fn translated_companion_pattern(origin: &serde_json::Value) -> Result<Option<String>, String> {
    let suffix = r#"(?:\\?['"\x60]|[\s;]|\\[nr]|$)"#;
    let (id, source, native, entropy) = match origin["upstream_id"].as_str() {
        Some("anthropic-api-key") => (
            "rustleaks.anthropic-api-key-escaped",
            format!(r"\b(sk-ant-api03-[a-zA-Z0-9_\-]{{93}}AA){suffix}"),
            r#"\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)\\['"\x60]"#.to_owned(),
            None,
        ),
        Some("anthropic-admin-api-key") => (
            "rustleaks.anthropic-admin-api-key-escaped",
            format!(r"\b(sk-ant-admin01-[a-zA-Z0-9_\-]{{93}}AA){suffix}"),
            r#"\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)\\['"\x60]"#.to_owned(),
            None,
        ),
        Some("digitalocean-refresh-token") => (
            "rustleaks.digitalocean-refresh-token-escaped",
            format!(r"(?i)\b(dor_v1_[a-f0-9]{{64}}){suffix}"),
            r#"\b([dD][oO][rR]_[vV]1_[a-fA-F0-9]{64})\\['"\x60]"#.to_owned(),
            None,
        ),
        Some("openai-api-key") => (
            "rustleaks.openai-api-key-20-segment",
            format!(
                r"\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{{74}}|[A-Za-z0-9_-]{{58}}|[A-Za-z0-9_-]{{20}})T3BlbkFJ(?:[A-Za-z0-9_-]{{74}}|[A-Za-z0-9_-]{{58}}|[A-Za-z0-9_-]{{20}})\b|sk-[a-zA-Z0-9]{{20}}T3BlbkFJ[a-zA-Z0-9]{{20}}){suffix}"
            ),
            format!(
                r"\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{{20}}T3BlbkFJ(?:[A-Za-z0-9_-]{{20}}|[A-Za-z0-9_-]{{58}}|[A-Za-z0-9_-]{{74}})|(?:[A-Za-z0-9_-]{{58}}|[A-Za-z0-9_-]{{74}})T3BlbkFJ[A-Za-z0-9_-]{{20}})\b){}",
                suffix.replace(r"[\s;]", r"[\x09-\x0d ;]")
            ),
            Some(3.0),
        ),
        Some("flyio-access-token") => (
            "rustleaks.flyio-flyv1",
            format!(r"\b(FlyV1\s[A-Za-z0-9=_\-,/+]{{100,}}){suffix}"),
            format!(
                r"\b(FlyV1[\x09-\x0d ][A-Za-z0-9=_\-,/+]{{100,}}){}",
                suffix.replace(r"[\s;]", r"[\x09-\x0d ;]")
            ),
            Some(4.0),
        ),
        _ => return Ok(None),
    };
    if origin["id"] != id
        || origin["source_pattern"] != source
        || origin["entropy"] != serde_json::json!(entropy)
        || origin["transformations"]
            .as_array()
            .is_none_or(Vec::is_empty)
    {
        return Err(format!(
            "provider companion {id} source or selection differs"
        ));
    }
    Ok(Some(native))
}

fn translated_standalone_pattern(origin: &serde_json::Value) -> Result<Option<String>, String> {
    let (source, native, entropy, keywords, analysis) = match origin["upstream_id"].as_str() {
        Some("cloudsmith-api-key") => (
            r#"\b(csa_[a-f0-9]{30}[A-Za-z0-9]{6})(?:\\?['"\x60]|[\s;]|\\[nr]|$)"#,
            r#"\b(csa_[a-f0-9]{30}[A-Za-z0-9]{6})(?:\\?['"\x60]|[\x09-\x0d ;]|\\[nr]|$)"#,
            None,
            vec!["csa_"],
            "absent",
        ),
        Some("minimax-api-key") => (
            r#"(?i)\b(sk-api-[A-Za-z0-9_-]{119})(?:\\?['"\x60]|[\s;]|\\[nr]|$)"#,
            r#"\b([sS][kK]-[aA][pP][iI]-[A-Za-z0-9_-]{119})(?:\\?['"\x60]|[\x09-\x0d ;]|\\[nNrR]|$)"#,
            Some(3.5),
            vec!["sk-api-", "minimax"],
            "absent",
        ),
        Some("posthog-personal-api-key") => (
            r#"(?i)\b(phx_[a-zA-Z0-9_\-]{41,49})(?:\\?['"\x60]|[\s;]|\\[nr]|$)"#,
            r#"\b([pP][hH][xX]_[a-zA-Z0-9_\-]{41,49})(?:\\?['"\x60]|[\x09-\x0d ;]|\\[nNrR]|$)"#,
            Some(3.0),
            vec!["phx_"],
            "absent",
        ),
        Some("figma-personal-access-token") => (
            r#"(?i)\b(figd_[A-Z0-9_-]{38,42})(?:\\?['"\x60]|[\s;]|\\[nr]|$)"#,
            r#"\b([fF][iI][gG][dD]_[A-Za-z0-9_-]{38,42})(?:\\?['"\x60]|[\x09-\x0d ;]|\\[nNrR]|$)"#,
            Some(3.5),
            vec!["figd_"],
            "present; not imported",
        ),
        Some("togetherai-api-key") => (
            r#"(?i)\b(tgp_v1_[A-Za-z0-9_-]{43})(?:\\?['"\x60]|[\s;]|\\[nr]|$)"#,
            r#"\b([tT][gG][pP]_[vV]1_[A-Za-z0-9_-]{43})(?:\\?['"\x60]|[\x09-\x0d ;]|\\[nNrR]|$)"#,
            Some(3.0),
            vec!["tgp_v1_"],
            "absent",
        ),
        Some("gcp-gemini-api") => (
            r#"\b(AQ\.Ab8RN6[A-Za-z0-9_-]{44})(?:\\?['"\x60]|[\s;]|\\[nr]|$)"#,
            r#"\b(AQ\.Ab8RN6[A-Za-z0-9_-]{44})(?:\\?['"\x60]|[\x09-\x0d ;]|\\[nr]|$)"#,
            Some(4.0),
            vec!["aq.ab8rn6"],
            "absent",
        ),
        _ => return Ok(None),
    };
    if origin["source_pattern"] != source
        || origin["entropy"] != serde_json::json!(entropy)
        || origin["source_keywords"] != serde_json::json!(keywords)
        || origin["source_analysis"] != analysis
        || origin["transformations"]
            .as_array()
            .is_none_or(Vec::is_empty)
    {
        return Err("standalone provider source or selection differs".into());
    }
    Ok(Some(native.to_owned()))
}
