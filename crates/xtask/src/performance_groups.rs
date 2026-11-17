//! Registration of the pack, CLI matrix, dense, Git shape and filter workloads.

const CORE: &[&str] = &[
    "config-parse-and-compile",
    "engine-construction",
    "first-scan",
    "steady-scan",
];
const DENSE: &[&str] = &[
    "scan-25000-bytes",
    "scan-50000-bytes",
    "scan-100000-bytes",
    "scan-200000-bytes",
    "scan-400000-bytes",
];
const LONG_LINE: &[&str] = &["scan-1-mib", "scan-4-mib", "scan-16-mib"];
const GIT: &[&str] = &["git-history-and-parse", "git-history-and-detection"];

/// Workload identifiers paired with the exact phase names each one reports.
type Members = &'static [(&'static str, &'static [&'static str])];

/// Group selectors accepted by `perf representative --workload`.
const GROUPS: &[(&str, Members)] = &[
    (
        "packs",
        &[
            ("packs-startup-none", CORE),
            ("packs-startup-extra", CORE),
            ("packs-startup-providers", CORE),
            ("packs-startup-connections", CORE),
            ("packs-startup-all", CORE),
            ("packs-keywords-none", CORE),
            ("packs-keywords-all", CORE),
            ("packs-mixed-none", CORE),
            ("packs-mixed-all", CORE),
            ("packs-workers-all-1", CORE),
            ("packs-workers-all-4", CORE),
            ("packs-workers-all-8", CORE),
        ],
    ),
    (
        "cli-matrix",
        &[
            (
                "cli-matrix-startup-packs",
                &[
                    "cold-empty-stdin-packs-none",
                    "cold-empty-stdin-packs-extra",
                    "cold-empty-stdin-packs-providers",
                    "cold-empty-stdin-packs-connections",
                    "cold-empty-stdin-packs-all",
                ],
            ),
            (
                "cli-matrix-dir-decode-depth",
                &[
                    "cold-dir-decode-depth-0",
                    "cold-dir-decode-depth-5",
                    "cold-dir-decode-depth-8",
                ],
            ),
            (
                "cli-matrix-git-decode-depth",
                &[
                    "cold-git-decode-depth-0",
                    "cold-git-decode-depth-5",
                    "cold-git-decode-depth-8",
                ],
            ),
            (
                "cli-matrix-dir-archive-depth",
                &["cold-dir-archive-depth-0", "cold-dir-archive-depth-8"],
            ),
            (
                "cli-matrix-git-archive-depth",
                &["cold-git-archive-depth-0", "cold-git-archive-depth-8"],
            ),
            (
                "cli-matrix-dir-report",
                &["cold-dir-no-report", "cold-dir-json-report-file"],
            ),
            (
                "cli-matrix-git-report",
                &["cold-git-no-report", "cold-git-json-report-file"],
            ),
            (
                "cli-matrix-dir-packs-profile",
                &[
                    "cold-dir-packs-off-profile-off",
                    "cold-dir-packs-off-profile-on",
                    "cold-dir-packs-on-profile-off",
                    "cold-dir-packs-on-profile-on",
                ],
            ),
            (
                "cli-matrix-git-packs-profile",
                &[
                    "cold-git-packs-off-profile-off",
                    "cold-git-packs-off-profile-on",
                    "cold-git-packs-on-profile-off",
                    "cold-git-packs-on-profile-on",
                ],
            ),
            (
                "cli-matrix-dir-workers",
                &[
                    "cold-dir-profile-workers-1",
                    "cold-dir-profile-workers-4",
                    "cold-dir-profile-workers-8",
                ],
            ),
            (
                "cli-matrix-git-workers",
                &[
                    "cold-git-profile-workers-1",
                    "cold-git-profile-workers-4",
                    "cold-git-profile-workers-8",
                ],
            ),
            (
                "cli-matrix-dir-size-series",
                &[
                    "cold-dir-0-mib",
                    "cold-dir-1-mib",
                    "cold-dir-16-mib",
                    "cold-dir-128-mib",
                ],
            ),
            (
                "cli-matrix-dir-ignore-baseline",
                &[
                    "cold-dir-no-suppression",
                    "cold-dir-ignore-10000",
                    "cold-dir-baseline-10000",
                ],
            ),
        ],
    ),
    (
        "dense",
        &[
            ("dense-github-lines", DENSE),
            ("dense-github-one-line", DENSE),
            ("dense-filter-one-line", DENSE),
            ("dense-base64-uris", DENSE),
            ("dense-long-line-sparse", LONG_LINE),
            ("memory-many-findings-scan", &["scan"]),
            ("memory-many-findings-json", &["scan", "report-json-file"]),
        ],
    ),
    (
        "git-shapes",
        &[
            ("git-one-huge-hunk", GIT),
            ("git-many-small-files", GIT),
            ("git-many-branches", GIT),
            (
                "git-merges",
                &[
                    "git-history-and-parse-merges-off",
                    "git-history-and-detection-merges-off",
                    "git-history-and-parse-merges-on",
                    "git-history-and-detection-merges-on",
                ],
            ),
            (
                "git-renames",
                &[
                    "git-history-and-parse-renames-off",
                    "git-history-and-detection-renames-off",
                    "git-history-and-parse-renames-on",
                    "git-history-and-detection-renames-on",
                ],
            ),
        ],
    ),
    (
        "filters",
        &[
            (
                "filters-allowlist-build",
                &[
                    "compile-regex-allowlist-10",
                    "compile-regex-allowlist-100",
                    "compile-regex-allowlist-1000",
                    "compile-stopwords-10",
                    "compile-stopwords-100",
                    "compile-stopwords-1000",
                    "compile-shared-allowlist-100-rules",
                ],
            ),
            (
                "filters-match",
                &[
                    "stopwords-1000-hit",
                    "stopwords-1000-miss",
                    "regex-allowlist-100-hit",
                    "regex-allowlist-100-miss",
                    "path-allowlist-100-hit",
                    "path-allowlist-100-miss",
                ],
            ),
            (
                "filters-capture-groups",
                &["groups-0", "groups-1", "groups-2-named", "groups-6-named"],
            ),
            (
                "filters-composite-proximity",
                &["pairs-1", "pairs-10", "pairs-40"],
            ),
            (
                "filters-finding-construction",
                &[
                    "accepted-per-line",
                    "filtered-per-line",
                    "missing-component-per-line",
                    "accepted-one-line",
                    "filtered-one-line",
                    "missing-component-one-line",
                ],
            ),
        ],
    ),
];

/// Returns the members of a group selector after checking that the runner
/// lists each one, or `None` for a name that is not a group.
pub(super) fn workloads(group: &str, available: &[String]) -> Option<Result<Vec<String>, String>> {
    let (_, members) = GROUPS.iter().find(|(name, _)| *name == group)?;
    Some(
        members
            .iter()
            .map(|(id, _)| {
                if available.iter().any(|known| known == id) {
                    Ok((*id).to_owned())
                } else {
                    Err(format!("representative runner does not list {id}"))
                }
            })
            .collect(),
    )
}

/// Returns the required phase names for one of these workloads.
pub(super) fn required_phases(workload: &str) -> Option<Vec<&'static str>> {
    GROUPS
        .iter()
        .flat_map(|(_, members)| members.iter())
        .find(|(id, _)| *id == workload)
        .map(|(_, phases)| phases.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn groups_list_unique_workloads_and_phases() {
        let mut seen = BTreeSet::new();
        let mut available = Vec::new();
        for (_, members) in GROUPS {
            for (id, phases) in *members {
                assert!(seen.insert(*id), "{id} is listed twice");
                assert!(!phases.is_empty(), "{id} needs phases");
                let unique = phases.iter().collect::<BTreeSet<_>>();
                assert_eq!(unique.len(), phases.len(), "{id} repeats a phase");
                assert_eq!(required_phases(id).unwrap(), *phases);
                available.push((*id).to_owned());
            }
        }
        assert_eq!(seen.len(), 42);
        for (group, members) in GROUPS {
            assert_eq!(
                workloads(group, &available).unwrap().unwrap().len(),
                members.len()
            );
        }
        assert!(workloads("packs", &available[1..]).unwrap().is_err());
        assert!(workloads("unknown", &available).is_none());
        assert!(required_phases("core-mixed-1-kib").is_none());
    }
}
