//! Exact upstream test identities referenced by composite coverage.

pub(super) fn validate_test_manifest(bytes: &[u8]) -> Result<(), String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|error| format!("compat test manifest is not UTF-8: {error}"))?;
    let expected = [
        (
            "TM-0084",
            "detect",
            "TestDetect/fragment_level_composite",
            "detect/detect_test.go",
        ),
        ("TM-0241", "report", "TestMask", "report/finding_test.go"),
        (
            "TM-0242",
            "report",
            "TestMask/empty_secret",
            "report/finding_test.go",
        ),
        (
            "TM-0243",
            "report",
            "TestMask/normal_secret",
            "report/finding_test.go",
        ),
        (
            "TM-0244",
            "report",
            "TestMask/short_secret",
            "report/finding_test.go",
        ),
        (
            "TM-0245",
            "report",
            "TestMaskSecret",
            "report/finding_test.go",
        ),
        (
            "TM-0246",
            "report",
            "TestMaskSecret/high_masking",
            "report/finding_test.go",
        ),
        (
            "TM-0247",
            "report",
            "TestMaskSecret/invalid_masking",
            "report/finding_test.go",
        ),
        (
            "TM-0248",
            "report",
            "TestMaskSecret/low_masking",
            "report/finding_test.go",
        ),
        (
            "TM-0249",
            "report",
            "TestMaskSecret/normal_masking",
            "report/finding_test.go",
        ),
        ("TM-0250", "report", "TestRedact", "report/finding_test.go"),
    ];
    for (id, package, name, path) in expected {
        let block = source
            .split("[[case]]\n")
            .find(|block| block.starts_with(&format!("id = \"{id}\"\n")))
            .ok_or_else(|| format!("compat test manifest is missing {id}"))?;
        for field in [
            format!("package = \"{package}\"\n"),
            format!("go_name = \"{name}\"\n"),
            format!("source = \"{path}\"\n"),
        ] {
            if !block.contains(&field) {
                return Err(format!("compat test manifest identity changed for {id}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_test_manifest;

    #[test]
    fn incomplete_manifest_is_rejected() {
        assert!(validate_test_manifest(b"[[case]]\nid = \"TM-0084\"\n").is_err());
    }
}
