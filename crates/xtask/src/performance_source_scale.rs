//! Registration of the source, Git, archive, and CLI scale workloads.

/// Group selector accepted by `perf representative --workload`.
pub(super) const GROUP: &str = "source-scale";

const SOURCE_PHASES: &[&str] = &[
    "traversal-and-read",
    "runner-detection-and-session",
    "traversal-and-detection",
];
const GIT_PHASES: &[&str] = &["git-history-and-parse", "git-history-and-detection"];
const ARCHIVE_RATIO_PHASES: &[&str] = &["archive-expand-under-limit", "archive-expand-over-limit"];

/// Workload identifiers paired with the exact phase names each one reports.
const WORKLOADS: &[(&str, &[&str])] = &[
    ("source-default-config-1-workers", SOURCE_PHASES),
    ("source-default-config-4-workers", SOURCE_PHASES),
    ("source-default-config-8-workers", SOURCE_PHASES),
    ("source-blank-lines-12-mib", SOURCE_PHASES),
    ("source-no-blank-lines-12-mib", SOURCE_PHASES),
    ("source-single-line-64-mib", SOURCE_PHASES),
    ("source-many-tiny-50000", SOURCE_PHASES),
    ("source-deep-tree", SOURCE_PHASES),
    ("source-mostly-ignored", SOURCE_PHASES),
    ("source-binary-mix", SOURCE_PHASES),
    ("source-skewed-sizes", SOURCE_PHASES),
    ("git-many-tiny-commits", GIT_PHASES),
    ("git-wide-commit", GIT_PHASES),
    ("git-merge-and-rename", GIT_PHASES),
    ("git-archive-blobs", GIT_PHASES),
    ("archive-high-ratio-gzip", ARCHIVE_RATIO_PHASES),
    ("archive-high-ratio-zstd", ARCHIVE_RATIO_PHASES),
    ("archive-high-ratio-bzip2", ARCHIVE_RATIO_PHASES),
    ("archive-nested-depth-8", &["archive-expand-nested-layers"]),
    ("archive-nested-depth-9", &["archive-expand-nested-layers"]),
    ("archive-tar-10000-members", &["archive-expand-members"]),
    ("archive-tar-10001-members", &["archive-expand-members"]),
    ("archive-zstd-many-small", &["archive-expand-many-files"]),
    ("cli-many-issues", &["cold-cli-startup-config-scan-report"]),
    (
        "cli-stdin-chunked",
        &["cold-stdin-one-write", "cold-stdin-4-kib-writes"],
    ),
    (
        "cli-enable-rule-startup",
        &[
            "cold-default-config-empty-stdin",
            "cold-enable-rule-empty-stdin",
        ],
    ),
];

/// Returns the group members after checking that the runner lists each one.
pub(super) fn workloads(available: &[String]) -> Result<Vec<String>, String> {
    WORKLOADS
        .iter()
        .map(|(id, _)| {
            if available.iter().any(|known| known == id) {
                Ok((*id).to_owned())
            } else {
                Err(format!("representative runner does not list {id}"))
            }
        })
        .collect()
}

/// Returns the required phase names for one of this module's workloads.
pub(super) fn required_phases(workload: &str) -> Option<Vec<&'static str>> {
    WORKLOADS
        .iter()
        .find(|(id, _)| *id == workload)
        .map(|(_, phases)| phases.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_and_phase_table_is_consistent_and_rejects_unknown_runners() {
        let available = WORKLOADS
            .iter()
            .map(|(id, _)| (*id).to_owned())
            .collect::<Vec<_>>();
        assert_eq!(workloads(&available).unwrap().len(), 26);
        assert!(workloads(&available[..25]).is_err());
        for (id, phases) in WORKLOADS {
            assert_eq!(required_phases(id).unwrap(), *phases);
            assert!(!phases.is_empty(), "{id} needs phases");
        }
        assert!(required_phases("core-mixed-1-kib").is_none());
    }
}
