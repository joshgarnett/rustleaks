use serde_json::Value;

use super::model::Inventory;
use super::{mechanical, traceability};

pub(super) fn run(
    inventory: &Inventory,
    generated: &str,
    candidate: &str,
    behavior: &str,
    api_jsonl: &str,
) -> Result<(), String> {
    reject_mechanical(
        inventory,
        "identity substitution",
        &generated.replacen(
            "go_name = \"TestConfigAllowlistPaths\"",
            "go_name = \"FabricatedIdentity\"",
            1,
        ),
    )?;
    reject_mechanical(
        inventory,
        "fixture hash substitution",
        &replace_first_hash(generated)?,
    )?;
    reject_mechanical(
        inventory,
        "fixture mode substitution",
        &generated.replacen("mode = \"100644\"", "mode = \"100755\"", 1),
    )?;
    reject_mechanical(
        inventory,
        "fixture consumer substitution",
        &replace_first_line(
            generated,
            "consumers = [",
            "consumers = [\"fabricated-consumer\"]",
        )?,
    )?;
    reject_mechanical(
        inventory,
        "fixture provenance substitution",
        &generated.replacen(
            "provenance = \"Gitleaks MIT; pinned upstream testdata\"",
            "provenance = \"fabricated provenance\"",
            1,
        ),
    )?;

    reject_traceability(
        "missing behavior",
        candidate,
        &behavior.replacen("id = \"TM-ALL-001\"", "id = \"TM-ALL-MISSING\"", 1),
        api_jsonl,
    )?;
    reject_traceability(
        "dangling case behavior",
        &candidate.replacen(
            "behavior_ids = [\"TM-ALL-001\"]",
            "behavior_ids = [\"DANGLING-BEHAVIOR\"]",
            1,
        ),
        behavior,
        api_jsonl,
    )?;
    let mut rows = parse_api(api_jsonl)?;
    rows[0]["manifest_links"] = serde_json::json!(["FABRICATED-MANIFEST-LINK"]);
    reject_traceability(
        "fabricated API manifest link",
        candidate,
        behavior,
        &jsonl(&rows),
    )?;
    reject_traceability(
        "unfinished manifest status",
        &candidate.replacen("status = \"implemented\"", "status = \"planned\"", 1),
        behavior,
        api_jsonl,
    )?;
    reject_traceability(
        "unfinished behavior status",
        candidate,
        &behavior.replacen(
            "status = \"traceability-complete\"",
            "status = \"partial\"",
            1,
        ),
        api_jsonl,
    )?;
    let mut rows = parse_api(api_jsonl)?;
    rows[0]["implementation_status"] = Value::String("planned".into());
    rows[0]["test_status"] = Value::String("planned".into());
    rows[0]["evidence_status"] = Value::String("design-only".into());
    reject_traceability("unfinished API status", candidate, behavior, &jsonl(&rows))
}

fn reject_mechanical(inventory: &Inventory, label: &str, mutated: &str) -> Result<(), String> {
    if mechanical::verify(inventory, mutated).is_ok() {
        return Err(format!("{label} negative self-test unexpectedly passed"));
    }
    Ok(())
}

fn reject_traceability(
    label: &str,
    manifest: &str,
    behavior: &str,
    api: &str,
) -> Result<(), String> {
    if traceability::verify(manifest, behavior, api).is_ok() {
        return Err(format!("{label} negative self-test unexpectedly passed"));
    }
    Ok(())
}

fn replace_first_hash(text: &str) -> Result<String, String> {
    let fixture = text
        .find("[[fixture]]")
        .ok_or_else(|| "generated manifest has no fixture row".to_owned())?;
    let start = fixture
        + text[fixture..]
            .find("\nsha256 = \"")
            .ok_or_else(|| "generated manifest has no fixture SHA-256".to_owned())?;
    let value = start + "\nsha256 = \"".len();
    let end = value + 64;
    if text.get(end..=end) != Some("\"") {
        return Err("first SHA-256 field is malformed".into());
    }
    let mut output = text.to_owned();
    output.replace_range(value..end, &"0".repeat(64));
    Ok(output)
}

fn replace_first_line(text: &str, prefix: &str, replacement: &str) -> Result<String, String> {
    let start = text
        .find(prefix)
        .ok_or_else(|| format!("generated manifest lacks {prefix}"))?;
    let end = start + text[start..].find('\n').unwrap_or(text.len() - start);
    let mut output = text.to_owned();
    output.replace_range(start..end, replacement);
    Ok(output)
}

fn parse_api(text: &str) -> Result<Vec<Value>, String> {
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line)
                .map_err(|error| format!("invalid API JSONL row {}: {error}", index + 1))
        })
        .collect()
}

fn jsonl(rows: &[Value]) -> String {
    let mut output = rows
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    output.push('\n');
    output
}
