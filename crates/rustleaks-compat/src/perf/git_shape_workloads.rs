//! Git reader shapes: one huge hunk, many small files, many branches, merge
//! diffs on and off, and renames on and off.
//!
//! The shapes adapt Betterleaks reader benchmark specifications (specs 7, 18,
//! 20, 21, 23 and 27 in the benchmark survey) to the Git subprocess reader.
//! Each plan lists the added lines of every hunk that `git log -p -U0` prints
//! for its log options, and the expected fragments and findings come from that
//! list. Variants of one shape import identical commits into separate
//! repositories, so commit IDs match across variants.

use super::Phase;
use super::source_scale_workloads::{
    GIT_LOG_NO_RENAMES, GitCommit, GitFile, GitPlan, KIB, SCALE, TOKEN, git_phases, import_plan,
    push_delete, push_inline_modify,
};
use super::suite_support::Result;

pub(super) const WORKLOADS: &[&str] = &[
    "git-one-huge-hunk",
    "git-many-small-files",
    "git-many-branches",
    "git-merges",
    "git-renames",
];

/// Merge commits print their diff against the first parent.
const GIT_LOG_FIRST_PARENT_MERGES: [&str; 6] = [
    "--all",
    "--full-history",
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
    "--diff-merges=first-parent",
];
const GIT_LOG_RENAMES: [&str; 5] = [
    "--all",
    "--full-history",
    "--no-ext-diff",
    "--no-textconv",
    "-M",
];

const HUGE_LINES: usize = 32 * KIB / SCALE;
const SMALL_FILES: usize = at_least(1_000 / SCALE, 8);
const BRANCHES: usize = at_least(1_000 / SCALE, 8);
const MERGES: usize = at_least(500 / SCALE, 8);
const RENAMES: usize = at_least(500 / SCALE, 8);
const RENAME_FILE_LINES: usize = 20;
const RENAME_EDIT_LINE: usize = 10;

const fn at_least(value: usize, minimum: usize) -> usize {
    if value < minimum { minimum } else { value }
}

pub(super) fn run(id: &str, iterations: usize) -> Result<Vec<Phase>> {
    if !(1..=1_000).contains(&iterations) {
        return Err("Git shape iterations outside 1..=1000".into());
    }
    let single = ["git-history-and-parse", "git-history-and-detection"];
    match id {
        "git-one-huge-hunk" => git_phases(&import_plan(&huge_hunk_plan())?, iterations, single),
        "git-many-small-files" => {
            git_phases(&import_plan(&small_files_plan())?, iterations, single)
        }
        "git-many-branches" => git_phases(&import_plan(&branches_plan())?, iterations, single),
        "git-merges" => {
            let mut phases = git_phases(
                &import_plan(&merges_plan(false))?,
                iterations,
                [
                    "git-history-and-parse-merges-off",
                    "git-history-and-detection-merges-off",
                ],
            )?;
            phases.extend(git_phases(
                &import_plan(&merges_plan(true))?,
                iterations,
                [
                    "git-history-and-parse-merges-on",
                    "git-history-and-detection-merges-on",
                ],
            )?);
            Ok(phases)
        }
        "git-renames" => {
            let mut phases = git_phases(
                &import_plan(&renames_plan(false))?,
                iterations,
                [
                    "git-history-and-parse-renames-off",
                    "git-history-and-detection-renames-off",
                ],
            )?;
            phases.extend(git_phases(
                &import_plan(&renames_plan(true))?,
                iterations,
                [
                    "git-history-and-parse-renames-on",
                    "git-history-and-detection-renames-on",
                ],
            )?);
            Ok(phases)
        }
        _ => Err(format!("unknown Git shape workload {id}").into()),
    }
}

fn token_text() -> String {
    String::from_utf8_lossy(TOKEN).into_owned()
}

fn commit(
    time_offset: usize,
    parents: Vec<usize>,
    reference: &str,
    message: &str,
    commands: Vec<u8>,
    files: Vec<GitFile>,
) -> GitCommit {
    GitCommit {
        time_offset: time_offset as u64,
        parents,
        reference: reference.to_owned(),
        message: message.as_bytes().to_vec(),
        commands,
        files,
    }
}

/// One file rewritten in full: no line of the second version equals a line of
/// the first, so `-U0` prints one hunk with every line removed and added.
fn huge_hunk_plan() -> GitPlan {
    let path = "huge/data.txt";
    let every = HUGE_LINES / 32;
    let mut first = Vec::with_capacity(HUGE_LINES * 16);
    let mut second = Vec::with_capacity(HUGE_LINES * 32);
    for line in 0..HUGE_LINES {
        first.extend_from_slice(format!("base row {line:06}\n").as_bytes());
        if line % every == every / 2 {
            second.extend_from_slice(format!("{} row {line:06}\n", token_text()).as_bytes());
        } else {
            second.extend_from_slice(format!("next row {line:06}\n").as_bytes());
        }
    }
    let mut first_commands = Vec::new();
    push_inline_modify(&mut first_commands, path, &first);
    let mut second_commands = Vec::new();
    push_inline_modify(&mut second_commands, path, &second);
    GitPlan {
        commits: vec![
            commit(
                0,
                vec![],
                "refs/heads/main",
                "add data",
                first_commands,
                vec![GitFile {
                    path: path.into(),
                    start_line: 1,
                    added: first,
                }],
            ),
            commit(
                1,
                vec![0],
                "refs/heads/main",
                "rewrite data",
                second_commands,
                vec![GitFile {
                    path: path.into(),
                    start_line: 1,
                    added: second,
                }],
            ),
        ],
        log_arguments: &GIT_LOG_NO_RENAMES,
        scope_notes: "one file of 32,768 lines replaced in one hunk",
    }
}

/// Many three-line files, then one commit that changes the middle line of each.
fn small_files_plan() -> GitPlan {
    let mut add_commands = Vec::new();
    let mut add_files = Vec::new();
    let mut edit_commands = Vec::new();
    let mut edit_files = Vec::new();
    for index in 0..SMALL_FILES {
        let path = format!("small/f{index:04}.txt");
        let first = format!("first {index:04}\nsecond {index:04}\nthird {index:04}\n");
        let changed = if index % 10 == 0 {
            format!("{} {index:04}\n", token_text())
        } else {
            format!("changed {index:04}\n")
        };
        let second = format!("first {index:04}\n{changed}third {index:04}\n");
        push_inline_modify(&mut add_commands, &path, first.as_bytes());
        push_inline_modify(&mut edit_commands, &path, second.as_bytes());
        add_files.push(GitFile {
            path: path.clone(),
            start_line: 1,
            added: first.into_bytes(),
        });
        edit_files.push(GitFile {
            path,
            start_line: 2,
            added: changed.into_bytes(),
        });
    }
    GitPlan {
        commits: vec![
            commit(
                0,
                vec![],
                "refs/heads/main",
                "add files",
                add_commands,
                add_files,
            ),
            commit(
                1,
                vec![0],
                "refs/heads/main",
                "edit files",
                edit_commands,
                edit_files,
            ),
        ],
        log_arguments: &GIT_LOG_NO_RENAMES,
        scope_notes: "1,000 one-line changes in one commit",
    }
}

/// One root commit, then one branch per topic, each adding one file.
fn branches_plan() -> GitPlan {
    let mut root_commands = Vec::new();
    push_inline_modify(&mut root_commands, "README.txt", b"root\n");
    let mut commits = vec![commit(
        0,
        vec![],
        "refs/heads/main",
        "root",
        root_commands,
        vec![GitFile {
            path: "README.txt".into(),
            start_line: 1,
            added: b"root\n".to_vec(),
        }],
    )];
    for index in 0..BRANCHES {
        let path = format!("topics/t{index:04}.txt");
        let content = if index % 10 == 0 {
            format!("{} topic {index:04}\n", token_text())
        } else {
            format!("topic {index:04}\n")
        };
        let mut commands = Vec::new();
        push_inline_modify(&mut commands, &path, content.as_bytes());
        commits.push(commit(
            index + 1,
            vec![0],
            &format!("refs/heads/topic-{index:04}"),
            "topic",
            commands,
            vec![GitFile {
                path,
                start_line: 1,
                added: content.into_bytes(),
            }],
        ));
    }
    GitPlan {
        commits,
        log_arguments: &GIT_LOG_NO_RENAMES,
        scope_notes: "1,000 branches from one root, one file each",
    }
}

/// A main line with one feature commit and one merge commit per step. Each
/// feature commit adds one file. With merge diffs on, each merge prints the
/// same added file against its first parent, so every plant is found twice.
fn merges_plan(merge_diffs: bool) -> GitPlan {
    let mut root_commands = Vec::new();
    push_inline_modify(&mut root_commands, "README.txt", b"root\n");
    let mut commits = vec![commit(
        0,
        vec![],
        "refs/heads/main",
        "root",
        root_commands,
        vec![GitFile {
            path: "README.txt".into(),
            start_line: 1,
            added: b"root\n".to_vec(),
        }],
    )];
    let mut main_tip = 0;
    for index in 0..MERGES {
        let path = format!("merged/m{index:04}.txt");
        let content = if index % 5 == 0 {
            format!("{} merged {index:04}\n", token_text())
        } else {
            format!("merged {index:04}\n")
        };
        let file = || GitFile {
            path: path.clone(),
            start_line: 1,
            added: content.clone().into_bytes(),
        };
        let mut commands = Vec::new();
        push_inline_modify(&mut commands, &path, content.as_bytes());
        let feature = commits.len();
        commits.push(commit(
            feature,
            vec![main_tip],
            "refs/heads/feature",
            "feature",
            commands.clone(),
            vec![file()],
        ));
        commits.push(commit(
            feature + 1,
            vec![main_tip, feature],
            "refs/heads/main",
            "merge feature",
            commands,
            if merge_diffs { vec![file()] } else { vec![] },
        ));
        main_tip = feature + 1;
    }
    GitPlan {
        commits,
        log_arguments: if merge_diffs {
            &GIT_LOG_FIRST_PARENT_MERGES
        } else {
            &GIT_LOG_NO_RENAMES
        },
        scope_notes: if merge_diffs {
            "500 merges; merge diffs against the first parent"
        } else {
            "500 merges; git log omits merge diffs"
        },
    }
}

fn rename_body(index: usize, edited: bool) -> Vec<u8> {
    let mut body = Vec::new();
    for line in 1..=RENAME_FILE_LINES {
        if edited && line == RENAME_EDIT_LINE {
            body.extend_from_slice(format!("renamed {index:04} {}\n", token_text()).as_bytes());
        } else {
            body.extend_from_slice(format!("unique row {index:04} {line:02}\n").as_bytes());
        }
    }
    body
}

/// Files moved to a new folder with one line edited. Without rename detection
/// each moved file is printed as a new file; with `-M` only the edited line is.
fn renames_plan(detect: bool) -> GitPlan {
    let mut add_commands = Vec::new();
    let mut add_files = Vec::new();
    let mut move_commands = Vec::new();
    let mut move_files = Vec::new();
    for index in 0..RENAMES {
        let old = format!("old/f{index:04}.txt");
        let new = format!("new/f{index:04}.txt");
        let original = rename_body(index, false);
        let edited = rename_body(index, true);
        push_inline_modify(&mut add_commands, &old, &original);
        push_delete(&mut move_commands, &old);
        push_inline_modify(&mut move_commands, &new, &edited);
        add_files.push(GitFile {
            path: old,
            start_line: 1,
            added: original,
        });
        move_files.push(if detect {
            let line_start = edited
                .split_inclusive(|byte| *byte == b'\n')
                .take(RENAME_EDIT_LINE - 1)
                .map(<[u8]>::len)
                .sum::<usize>();
            let line_end = line_start
                + edited[line_start..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(0, |offset| offset + 1);
            GitFile {
                path: new,
                start_line: RENAME_EDIT_LINE,
                added: edited[line_start..line_end].to_vec(),
            }
        } else {
            GitFile {
                path: new,
                start_line: 1,
                added: edited,
            }
        });
    }
    GitPlan {
        commits: vec![
            commit(
                0,
                vec![],
                "refs/heads/main",
                "add files",
                add_commands,
                add_files,
            ),
            commit(
                1,
                vec![0],
                "refs/heads/main",
                "move files",
                move_commands,
                move_files,
            ),
        ],
        log_arguments: if detect {
            &GIT_LOG_RENAMES
        } else {
            &GIT_LOG_NO_RENAMES
        },
        scope_notes: if detect {
            "500 renames with one edited line; -M"
        } else {
            "500 renames with one edited line; --no-renames"
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_shapes_have_exact_outcomes_at_test_scale() {
        for id in WORKLOADS {
            let phases = run(id, 1).unwrap_or_else(|error| panic!("{id}: {error}"));
            let expected = if *id == "git-merges" || *id == "git-renames" {
                4
            } else {
                2
            };
            assert_eq!(phases.len(), expected, "{id}");
        }
    }

    #[test]
    fn merge_and_rename_variants_change_only_the_expected_hunks() {
        let off = merges_plan(false);
        let on = merges_plan(true);
        let count = |plan: &GitPlan| plan.commits.iter().map(|c| c.files.len()).sum::<usize>();
        assert_eq!(count(&on), count(&off) + MERGES);
        let plain = renames_plan(false);
        let detected = renames_plan(true);
        assert_eq!(plain.commits[1].files[0].added, rename_body(0, true));
        assert_eq!(plain.commits[1].files[0].start_line, 1);
        let line = &detected.commits[1].files[0];
        assert_eq!(line.start_line, RENAME_EDIT_LINE);
        assert_eq!(
            line.added,
            format!("renamed 0000 {}\n", token_text()).into_bytes()
        );
    }
}
