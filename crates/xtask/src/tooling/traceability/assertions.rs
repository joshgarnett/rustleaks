//! Validation of final frozen assertion dispositions.

pub(crate) fn validate_final_traceability(
    assertions: &str,
    benchmarks: &str,
    platform_skips: &str,
) -> Result<(), String> {
    fn rows(contents: &str, label: &str) -> Result<Vec<serde_json::Value>, String> {
        contents
            .lines()
            .enumerate()
            .map(|(index, line)| {
                serde_json::from_str(line)
                    .map_err(|error| format!("invalid {label} JSONL row {}: {error}", index + 1))
            })
            .collect()
    }

    let assertion_rows = rows(assertions, "assertion")?;
    if assertion_rows.len() != 283 {
        return Err(format!(
            "semantic assertion count mismatch: expected 283, got {}",
            assertion_rows.len()
        ));
    }
    for row in &assertion_rows {
        let id = row["id"].as_str().unwrap_or("<missing>");
        match row["status"].as_str() {
            Some("implemented") => {
                if row["rust_test"].as_str().is_none_or(str::is_empty)
                    || row["rust_evidence"].as_str().is_none_or(str::is_empty)
                {
                    return Err(format!("implemented assertion {id} lacks Rust evidence"));
                }
            }
            Some("final-disposition") => {
                if !row["rust_evidence"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("Final release disposition:"))
                {
                    return Err(format!("assertion {id} lacks a precise final disposition"));
                }
            }
            status => {
                return Err(format!(
                    "assertion {id} has non-final status {}",
                    status.unwrap_or("<missing>")
                ));
            }
        }
    }

    let benchmark_rows = rows(benchmarks, "benchmark assertion link")?;
    if benchmark_rows.len() != 6 {
        return Err(format!(
            "benchmark assertion-link count mismatch: expected 6, got {}",
            benchmark_rows.len()
        ));
    }
    for row in &benchmark_rows {
        let id = row["id"].as_str().unwrap_or("<missing>");
        if row["status"].as_str() != Some("implemented")
            || row["rust_test"].as_str().is_none_or(str::is_empty)
            || row["rust_evidence"].as_str().is_none_or(str::is_empty)
        {
            return Err(format!(
                "benchmark assertion link {id} lacks final Rust evidence"
            ));
        }
    }

    let platform_rows = rows(platform_skips, "platform branch")?;
    if platform_rows.len() != 2 {
        return Err(format!(
            "platform branch count mismatch: expected 2, got {}",
            platform_rows.len()
        ));
    }
    for row in &platform_rows {
        let id = row["id"].as_str().unwrap_or("<missing>");
        if row["status"].as_str() != Some("implemented")
            || row["rust_evidence"].as_str().is_none_or(str::is_empty)
        {
            return Err(format!("platform branch {id} lacks final Rust evidence"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod final_traceability_tests {
    use super::validate_final_traceability;

    #[test]
    fn pending_and_missing_evidence_fail_closed() {
        let assertion = serde_json::json!({"id":"AS-TEST","status":"implemented","rust_test":"tests::exact_case","rust_evidence":"tests/exact.rs"});
        let benchmark = serde_json::json!({"id":"AS-BM-TEST","status":"implemented","rust_test":"tests::exact_benchmark","rust_evidence":"tests/perf.rs"});
        let platform = serde_json::json!({"id":"SKIP-TEST","status":"implemented","rust_evidence":"tests/platform.rs"});
        let assertions = std::iter::repeat_n(format!("{assertion}\n"), 283).collect::<String>();
        let benchmarks = std::iter::repeat_n(format!("{benchmark}\n"), 6).collect::<String>();
        let platforms = std::iter::repeat_n(format!("{platform}\n"), 2).collect::<String>();
        validate_final_traceability(&assertions, &benchmarks, &platforms).unwrap();
        assert!(
            validate_final_traceability(
                &assertions.replacen("implemented", "pending", 1),
                &benchmarks,
                &platforms
            )
            .is_err()
        );
        assert!(
            validate_final_traceability(
                &assertions,
                &benchmarks.replacen("tests/perf.rs", "", 1),
                &platforms
            )
            .is_err()
        );
        assert!(
            validate_final_traceability(
                &assertions,
                &benchmarks,
                &platforms.replacen("tests/platform.rs", "", 1)
            )
            .is_err()
        );
    }
}
