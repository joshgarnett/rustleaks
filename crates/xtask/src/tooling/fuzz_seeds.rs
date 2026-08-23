//! Deterministic binary seed generation for the Go-regex fuzz target.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use base64::Engine as _;

use super::artifacts::GeneratedTree;

pub(crate) fn generate_regex_fuzz_seeds(
    requests_path: &Path,
    output_dir: &Path,
) -> Result<usize, String> {
    let requests = File::open(requests_path).map_err(|error| {
        format!(
            "cannot open regex requests {}: {error}",
            requests_path.display()
        )
    })?;
    let mut count = 0_usize;
    let mut generated = GeneratedTree::default();
    for (line_index, line) in BufReader::new(requests).lines().enumerate() {
        let line = line.map_err(|error| {
            format!(
                "cannot read line {} of {}: {error}",
                line_index + 1,
                requests_path.display()
            )
        })?;
        let request: serde_json::Value = serde_json::from_str(&line).map_err(|error| {
            format!(
                "invalid JSON on line {} of {}: {error}",
                line_index + 1,
                requests_path.display()
            )
        })?;
        let id = request
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("regex request line {} has no string id", line_index + 1))?;
        let pattern = decode_request_field(&request, "pattern_base64", id)?;
        let haystack = decode_request_field(&request, "input_base64", id)?;
        let pattern_len = u16::try_from(pattern.len())
            .map_err(|_| format!("pattern exceeds the u16 seed-frame limit: {id}"))?;
        let safe_id = id
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-') {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>();
        count += 1;
        let mut bytes = Vec::with_capacity(2 + pattern.len() + haystack.len());
        bytes.extend_from_slice(&pattern_len.to_le_bytes());
        bytes.extend_from_slice(&pattern);
        bytes.extend_from_slice(&haystack);
        generated.insert(format!("{count:04}-{safe_id}"), bytes)?;
    }
    generated.write_or_check(output_dir, false)?;
    Ok(count)
}

fn decode_request_field(
    request: &serde_json::Value,
    field: &str,
    id: &str,
) -> Result<Vec<u8>, String> {
    let encoded = request
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("regex request {id} has no string {field}"))?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| format!("regex request {id} has invalid {field}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::Engine as _;

    use super::generate_regex_fuzz_seeds;
    use crate::tooling::support::TempDir;

    #[test]
    fn preserves_binary_bytes_and_portable_names() {
        let temporary = TempDir::new("seed test ü").unwrap();
        let requests = temporary.path.join("requests ü.jsonl");
        let output = temporary.path.join("output dir ü");
        fs::write(
            &requests,
            concat!(
                "{\"id\":\"punctuation/id ü\",\"pattern_base64\":\"AP8=\",\"input_base64\":\"gEE=\"}\n",
                "{\"id\":\"plain\",\"pattern_base64\":\"YQ==\",\"input_base64\":\"Yg==\"}\n",
            ),
        )
        .unwrap();
        assert_eq!(generate_regex_fuzz_seeds(&requests, &output).unwrap(), 2);
        assert_eq!(
            fs::read(output.join("0001-punctuation_id__")).unwrap(),
            [2, 0, 0, 255, 128, 65]
        );
        assert_eq!(
            fs::read(output.join("0002-plain")).unwrap(),
            [1, 0, b'a', b'b']
        );
        assert_eq!(generate_regex_fuzz_seeds(&requests, &output).unwrap(), 2);
        fs::write(output.join("unexpected"), b"stale").unwrap();
        assert!(generate_regex_fuzz_seeds(&requests, &output).is_err());
    }

    #[test]
    fn rejects_malformed_and_oversized_inputs() {
        let temporary = TempDir::new("seed-negative").unwrap();
        let requests = temporary.path.join("requests.jsonl");
        let output = temporary.path.join("output");
        fs::write(
            &requests,
            "{\"id\":\"bad\",\"pattern_base64\":\"!\",\"input_base64\":\"\"}\n",
        )
        .unwrap();
        assert!(generate_regex_fuzz_seeds(&requests, &output).is_err());
        let oversized =
            base64::engine::general_purpose::STANDARD.encode(vec![0_u8; usize::from(u16::MAX) + 1]);
        fs::write(
            &requests,
            format!(
                "{{\"id\":\"large\",\"pattern_base64\":\"{oversized}\",\"input_base64\":\"\"}}\n"
            ),
        )
        .unwrap();
        assert!(generate_regex_fuzz_seeds(&requests, &output).is_err());
    }
}
