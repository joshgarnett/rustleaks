//! Maintained documentation checks.
//!
//! The check covers prose style, local Markdown links, Rust documentation
//! comments, documented commands, and planning or tracker files that belong
//! outside the repository. Every documentation problem is reported before the
//! check fails. Workflow and I/O errors stop the check early.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::tooling::{FROZEN_DIRECTORIES, frozen_artifact_paths};

/// Upstream fixture Markdown files that are kept byte for byte.
const VERBATIM_UPSTREAM_FIXTURES: &[&str] = &[
    "compat/fixtures/upstream/testdata/expected/report/template_markdown.md",
    "compat/fixtures/upstream/testdata/repos/archives/README.md",
    "compat/fixtures/upstream/testdata/repos/small/README.md",
    "compat/fixtures/upstream/testdata/repos/staged/README.md",
];

/// Directory prefixes whose files are not maintained prose.
const UNCHECKED_DOCUMENT_DIRECTORIES: &[&str] = &["release/notice-inputs", "release/licenses"];

/// Marketing phrases that maintained prose must not use.
const BANNED_PHRASES: &[&str] = &[
    "100% safe",
    "blazing fast",
    "best-in-class",
    "production-quality",
    "world-class",
    "ultra-fast",
];

/// Planning and tracker paths that must not exist in the checkout.
///
/// Plans, progress notes, handoffs, and readiness trackers stay in the
/// ignored `.tmp/` directory. Committed documentation describes the current
/// repository, not work in progress.
const BANNED_TRACKER_DIRECTORIES: &[&str] = &["docs/plans", "docs/validation"];

/// File names that are banned anywhere in the checkout. See
/// [`BANNED_TRACKER_DIRECTORIES`] for the reason.
const BANNED_TRACKER_FILES: &[&str] = &[
    "BETA_READINESS.md",
    "HANDOFF.md",
    "PROGRESS.md",
    "ROADMAP.md",
];

/// Ignored local scratch directory for plans and investigation notes.
const SCRATCH_DIRECTORY: &str = ".tmp";

/// Fenced code block languages that are read as shell commands.
const SHELL_FENCE_LANGUAGES: &[&str] = &[
    "",
    "bash",
    "cmd",
    "console",
    "powershell",
    "ps1",
    "pwsh",
    "sh",
    "shell",
    "yaml",
    "yml",
    "zsh",
];

/// Runs every documentation check against the workspace at `root`.
pub(crate) fn run(root: &Path) -> Result<(), String> {
    crate::workflows::check(root)?;
    let justfile = fs::read_to_string(root.join("justfile"))
        .map_err(|error| format!("cannot read justfile: {error}"))?;
    let recipes = justfile_recipes(&justfile);
    let tree = walk(root)?;
    if tree.documents.is_empty() {
        return Err("documentation check found no maintained prose surfaces".into());
    }
    let mut problems = tracker_problems(&tree);
    let mut prose_files = 0_usize;
    let mut rust_doc_surfaces = 0_usize;
    for relative in &tree.documents {
        let contents = match fs::read_to_string(root.join(relative)) {
            Ok(contents) => contents,
            Err(error) => {
                problems.push(format!("{}: cannot read: {error}", display(relative)));
                continue;
            }
        };
        match check_document(root, relative, &contents, &recipes) {
            Checked::Empty => {}
            Checked::Prose(found) => {
                prose_files += 1;
                problems.extend(found);
            }
            Checked::RustDocs(found) => {
                rust_doc_surfaces += 1;
                problems.extend(found);
            }
        }
    }
    if !problems.is_empty() {
        for problem in &problems {
            eprintln!("{problem}");
        }
        return Err(format!(
            "documentation check found {} problem{}",
            problems.len(),
            if problems.len() == 1 { "" } else { "s" }
        ));
    }
    println!(
        "checked {prose_files} maintained prose files and {rust_doc_surfaces} Rust documentation surfaces for links, style, and commands"
    );
    Ok(())
}

/// The result of checking one file.
#[derive(Debug, PartialEq, Eq)]
enum Checked {
    /// The file has no prose to check.
    Empty,
    /// Problems found in a Markdown or YAML file.
    Prose(Vec<String>),
    /// Problems found in Rust documentation comments.
    RustDocs(Vec<String>),
}

/// Files found by one walk of the checkout, as paths relative to the root.
#[derive(Debug, Default)]
struct Tree {
    /// Sorted documentation files to check.
    documents: Vec<PathBuf>,
    /// Sorted banned tracker files and directories.
    trackers: Vec<PathBuf>,
}

/// Walks the checkout once, skipping build output, Git metadata, Bazel
/// convenience links, and the local scratch directory.
fn walk(root: &Path) -> Result<Tree, String> {
    let mut tree = Tree::default();
    walk_directory(root, root, &mut tree)?;
    tree.documents.sort();
    tree.trackers.sort();
    Ok(tree)
}

fn walk_directory(directory: &Path, root: &Path, tree: &mut Tree) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read directory {}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot read entry of {}: {error}", directory.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|error| format!("cannot relativize {}: {error}", path.display()))?
            .to_path_buf();
        if is_skipped_tree(&relative) {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if file_type.is_dir() {
            if BANNED_TRACKER_DIRECTORIES
                .iter()
                .any(|banned| relative == Path::new(banned))
            {
                tree.trackers.push(relative.clone());
            }
            walk_directory(&path, root, tree)?;
            continue;
        }
        if relative
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| BANNED_TRACKER_FILES.contains(&name))
        {
            tree.trackers.push(relative.clone());
        }
        if file_type.is_file() && is_document(&relative) {
            tree.documents.push(relative);
        }
    }
    Ok(())
}

/// Returns whether a top-level entry is outside the maintained checkout.
fn is_skipped_tree(relative: &Path) -> bool {
    let Some(Component::Normal(first)) = relative.components().next() else {
        return false;
    };
    let Some(first) = first.to_str() else {
        return false;
    };
    let top_level = relative.components().count() == 1
        && (matches!(first, ".git" | SCRATCH_DIRECTORY) || first.starts_with("bazel-"));
    // Cargo build output can appear at any depth, for example under fuzz crates.
    top_level || relative.file_name().is_some_and(|name| name == "target")
}

/// Returns whether a file is maintained prose that the style checks cover.
fn is_document(relative: &Path) -> bool {
    let checked_extension = relative
        .extension()
        .is_some_and(|value| matches!(value.to_str(), Some("md" | "rs" | "yml" | "yaml")));
    checked_extension
        && !UNCHECKED_DOCUMENT_DIRECTORIES
            .iter()
            .any(|directory| relative.starts_with(directory))
        && !VERBATIM_UPSTREAM_FIXTURES
            .iter()
            .any(|fixture| relative == Path::new(fixture))
}

fn tracker_problems(tree: &Tree) -> Vec<String> {
    tree.trackers
        .iter()
        .map(|path| {
            format!(
                "{}: planning and tracker files belong in the ignored .tmp/ directory, not the repository",
                display(path)
            )
        })
        .collect()
}

/// Returns whether documented commands in this file are exempt from command
/// validation. Frozen historical evidence and release notes may name retired
/// commands.
fn is_command_check_exempt(relative: &Path) -> bool {
    relative
        .file_name()
        .is_some_and(|name| name == "CHANGELOG.md")
        || FROZEN_DIRECTORIES
            .iter()
            .any(|directory| relative.starts_with(directory))
        || frozen_artifact_paths().any(|artifact| relative == Path::new(artifact))
}

/// Checks one file. `relative` is the path below `root`, which is used to
/// resolve local Markdown links.
fn check_document(
    root: &Path,
    relative: &Path,
    contents: &str,
    recipes: &BTreeSet<String>,
) -> Checked {
    let is_rust = relative.extension().is_some_and(|value| value == "rs");
    let prose = if is_rust {
        rust_documentation(contents)
    } else {
        contents.to_owned()
    };
    if prose.is_empty() {
        return Checked::Empty;
    }
    let mut messages = style_problems(&prose);
    if relative.extension().is_some_and(|value| value == "md") {
        messages.extend(link_problems(root, relative, contents));
        if !is_command_check_exempt(relative) {
            messages.extend(command_problems(contents, recipes));
        }
    }
    let problems = messages
        .into_iter()
        .map(|message| format!("{}: {message}", display(relative)))
        .collect();
    if is_rust {
        Checked::RustDocs(problems)
    } else {
        Checked::Prose(problems)
    }
}

fn style_problems(prose: &str) -> Vec<String> {
    let mut problems = Vec::new();
    if prose.contains('\u{2014}') {
        problems.push("contains an em dash".to_owned());
    }
    if prose.chars().any(|character| {
        ('\u{1f000}'..='\u{1faff}').contains(&character)
            || ('\u{2600}'..='\u{27bf}').contains(&character)
    }) {
        problems.push("contains an emoji".to_owned());
    }
    let lowercase = prose.to_ascii_lowercase();
    for phrase in BANNED_PHRASES {
        if lowercase.contains(phrase) {
            problems.push(format!("contains disallowed marketing phrase {phrase:?}"));
        }
    }
    problems
}

fn markdown_local_links(contents: &str) -> impl Iterator<Item = &str> {
    contents
        .split("](")
        .skip(1)
        .filter_map(|tail| tail.split_once(')').map(|(target, _)| target.trim()))
}

fn link_problems(root: &Path, relative: &Path, contents: &str) -> Vec<String> {
    let parent = relative.parent().unwrap_or(Path::new(""));
    let mut problems = Vec::new();
    for target in markdown_local_links(contents) {
        let target = target.trim_matches(['<', '>']);
        if target.is_empty()
            || target.starts_with('#')
            || target.starts_with("http://")
            || target.starts_with("https://")
            || target.starts_with("mailto:")
        {
            continue;
        }
        let target = target.split('#').next().unwrap_or(target);
        if target.starts_with(".tmp/")
            || normalize(&parent.join(target))
                .is_some_and(|path| path.starts_with(SCRATCH_DIRECTORY))
        {
            problems.push(format!(
                "links to local scratch path {target:?}; keep plans and notes out of committed documentation"
            ));
            continue;
        }
        if !root.join(parent).join(target).exists() {
            problems.push(format!("broken local documentation link {target:?}"));
        }
    }
    problems
}

/// Lexically resolves `.` and `..` components. Returns `None` for a path that
/// leaves the root.
fn normalize(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Normal(part) => normalized.push(part),
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn rust_documentation(contents: &str) -> String {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            line.strip_prefix("//!")
                .or_else(|| line.strip_prefix("///"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parses the recipe and alias names that `just` accepts from a justfile.
///
/// Recipe headers start at column 0. Comments, settings, imports, modules,
/// variable assignments, and attribute lines are not recipes. Recipes marked
/// `[private]` or named with a leading underscore are not part of the public
/// interface, so documentation must not name them.
pub(crate) fn justfile_recipes(justfile: &str) -> BTreeSet<String> {
    let mut recipes = BTreeSet::new();
    let mut private = false;
    for line in justfile.lines() {
        if line.is_empty() || line.starts_with(char::is_whitespace) || line.starts_with('#') {
            continue;
        }
        if let Some(attributes) = line.strip_prefix('[') {
            let attributes = attributes.trim_end().trim_end_matches(']');
            private |= attributes
                .split(',')
                .any(|attribute| attribute.trim() == "private");
            continue;
        }
        let first = line.split_whitespace().next().unwrap_or_default();
        if first == "alias" {
            if let Some((name, _)) = line["alias".len()..].split_once(":=") {
                let name = name.trim();
                if is_recipe_name(name) && !name.starts_with('_') && !private {
                    recipes.insert(name.to_owned());
                }
            }
            private = false;
            continue;
        }
        if matches!(
            first,
            "set" | "export" | "import" | "import?" | "mod" | "mod?"
        ) || line.contains(":=")
        {
            continue;
        }
        let Some((header, _)) = line.split_once(':') else {
            continue;
        };
        let name = header
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim_start_matches('@');
        if is_recipe_name(name) && !name.starts_with('_') && !private {
            recipes.insert(name.to_owned());
        }
        private = false;
    }
    recipes
}

fn is_recipe_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

/// Returns code from inline code spans and shell-like fenced code blocks.
/// Plain prose is not returned, so phrases such as "just as" are ignored.
fn code_snippets(contents: &str) -> Vec<String> {
    let mut snippets = Vec::new();
    let mut paragraph = String::new();
    let mut fence: Option<(char, usize, bool)> = None;
    for line in contents.lines() {
        let trimmed = line.trim_start();
        if let Some((marker, length, shell)) = fence {
            if is_fence_close(trimmed, marker, length) {
                fence = None;
            } else if shell {
                snippets.push(line.to_owned());
            }
            continue;
        }
        if let Some((marker, length, info)) = fence_open(trimmed) {
            snippets.extend(inline_code(&paragraph));
            paragraph.clear();
            let language = info
                .split(|character: char| character.is_whitespace() || character == ',')
                .next()
                .unwrap_or_default()
                .trim_start_matches('{')
                .trim_start_matches('.')
                .to_ascii_lowercase();
            fence = Some((
                marker,
                length,
                SHELL_FENCE_LANGUAGES.contains(&language.as_str()),
            ));
            continue;
        }
        if trimmed.is_empty() {
            snippets.extend(inline_code(&paragraph));
            paragraph.clear();
        } else {
            paragraph.push_str(line);
            paragraph.push('\n');
        }
    }
    snippets.extend(inline_code(&paragraph));
    snippets
}

/// Recognizes an opening code fence and returns its marker, length, and info
/// string.
fn fence_open(trimmed: &str) -> Option<(char, usize, &str)> {
    let marker = trimmed
        .chars()
        .next()
        .filter(|marker| matches!(marker, '`' | '~'))?;
    let length = trimmed
        .chars()
        .take_while(|character| *character == marker)
        .count();
    if length < 3 {
        return None;
    }
    let info = trimmed[length..].trim();
    if marker == '`' && info.contains('`') {
        return None;
    }
    Some((marker, length, info))
}

fn is_fence_close(trimmed: &str, marker: char, length: usize) -> bool {
    let run = trimmed
        .chars()
        .take_while(|character| *character == marker)
        .count();
    run >= length && trimmed[run..].trim().is_empty()
}

/// Extracts inline code spans from one paragraph. A span opens with a run of
/// backticks and closes with the next run of the same length.
fn inline_code(paragraph: &str) -> Vec<String> {
    let bytes = paragraph.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'`' {
            index += 1;
            continue;
        }
        let open_length = backtick_run(bytes, index);
        let content_start = index + open_length;
        let mut search = content_start;
        let mut closed = None;
        while search < bytes.len() {
            if bytes[search] == b'`' {
                let length = backtick_run(bytes, search);
                if length == open_length {
                    closed = Some(search);
                    break;
                }
                search += length;
            } else {
                search += 1;
            }
        }
        match closed {
            Some(close) => {
                spans.push(paragraph[content_start..close].replace('\n', " "));
                index = close + open_length;
            }
            None => index = content_start,
        }
    }
    spans
}

fn backtick_run(bytes: &[u8], start: usize) -> usize {
    bytes[start..]
        .iter()
        .take_while(|byte| **byte == b'`')
        .count()
}

/// Validates `just`, `cargo xtask`, and Bazel xtask commands found in code.
fn command_problems(contents: &str, recipes: &BTreeSet<String>) -> Vec<String> {
    let mut problems = Vec::new();
    for snippet in code_snippets(contents) {
        let tokens = command_tokens(&snippet);
        for (index, token) in tokens.iter().enumerate() {
            let rest = &tokens[index + 1..];
            match *token {
                "just" => {
                    if let Some(recipe) = rest.first().copied().filter(|word| is_literal(word))
                        && !recipes.contains(recipe)
                    {
                        problems.push(format!("names unknown just recipe `just {recipe}`"));
                    }
                }
                "cargo" if rest.first() == Some(&"xtask") => {
                    problems.extend(xtask_problems("cargo xtask", &rest[1..]));
                }
                "//crates/xtask:xtask" | "@//crates/xtask:xtask" if rest.first() == Some(&"--") => {
                    problems.extend(xtask_problems(
                        "bazelisk run //crates/xtask:xtask --",
                        &rest[1..],
                    ));
                }
                _ => {}
            }
        }
    }
    problems
}

/// Splits code into words, drops shell comments, and trims punctuation that
/// commonly surrounds a command in prose or scripts.
fn command_tokens(snippet: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    for line in snippet.lines() {
        for word in line.split_whitespace() {
            if word.starts_with('#') {
                break;
            }
            let word = word
                .trim_start_matches(['(', '"', '\'', '$'])
                .trim_end_matches([')', '"', '\'', ',', ';', '.', ':']);
            if !word.is_empty() {
                tokens.push(word);
            }
        }
    }
    tokens
}

/// Returns whether a token is a literal command word rather than a flag or a
/// placeholder such as `<recipe>`, `{name}`, or `[ARGS]`.
fn is_literal(word: &str) -> bool {
    let mut characters = word.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

fn xtask_problems(prefix: &str, arguments: &[&str]) -> Vec<String> {
    let Some(command) = arguments.first().copied().filter(|word| is_literal(word)) else {
        return Vec::new();
    };
    if !crate::XTASK_COMMANDS.contains(&command) {
        return vec![format!("names unknown xtask command `{prefix} {command}`")];
    }
    let Some(argument) = arguments.get(1).copied().filter(|word| is_literal(word)) else {
        return Vec::new();
    };
    let accepted = match command {
        "generate" => crate::tooling::GENERATE_TARGETS,
        "perf" => crate::PERF_SUBCOMMANDS,
        _ => return Vec::new(),
    };
    if accepted.contains(&argument) {
        Vec::new()
    } else {
        vec![format!(
            "names unknown xtask {command} target `{prefix} {command} {argument}`"
        )]
    }
}

/// Formats a relative path with forward slashes on every platform.
fn display(relative: &Path) -> String {
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;

    use super::{
        Checked, check_document, command_problems, is_command_check_exempt, justfile_recipes,
        tracker_problems, walk,
    };
    use crate::ScopedTempDir;

    fn recipes() -> BTreeSet<String> {
        ["check", "docs-check", "test"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    fn problems(relative: &str, contents: &str) -> Vec<String> {
        problems_in(
            Path::new("/nonexistent-docs-check-root"),
            relative,
            contents,
        )
    }

    fn problems_in(root: &Path, relative: &str, contents: &str) -> Vec<String> {
        match check_document(root, Path::new(relative), contents, &recipes()) {
            Checked::Empty => Vec::new(),
            Checked::Prose(found) | Checked::RustDocs(found) => found,
        }
    }

    #[test]
    fn reports_em_dash() {
        assert_eq!(
            problems("docs/A.md", "one \u{2014} two\n"),
            ["docs/A.md: contains an em dash"]
        );
    }

    #[test]
    fn reports_emoji() {
        assert_eq!(
            problems("docs/A.md", "done \u{1f680}\n"),
            ["docs/A.md: contains an emoji"]
        );
    }

    #[test]
    fn reports_banned_phrase() {
        assert_eq!(
            problems("docs/A.md", "A Blazing Fast scanner.\n"),
            ["docs/A.md: contains disallowed marketing phrase \"blazing fast\""]
        );
    }

    #[test]
    fn checks_rust_documentation_comments_only() {
        let source = "//! Module docs \u{2014} here.\nfn f() {} // blazing fast\n";
        assert_eq!(
            check_document(Path::new("."), Path::new("src/lib.rs"), source, &recipes()),
            Checked::RustDocs(vec!["src/lib.rs: contains an em dash".to_owned()])
        );
        assert_eq!(
            check_document(
                Path::new("."),
                Path::new("src/a.rs"),
                "fn f() {}\n",
                &recipes()
            ),
            Checked::Empty
        );
    }

    #[test]
    fn reports_broken_link_and_accepts_link_with_fragment() {
        let root = ScopedTempDir::new("docs-check-links").unwrap();
        fs::create_dir(root.path.join("docs")).unwrap();
        fs::write(root.path.join("docs/B.md"), "# B\n").unwrap();
        let contents =
            "[ok](B.md#section) [self](#top) [web](https://example.com) [gone](C.md#x)\n";
        assert_eq!(
            problems_in(&root.path, "docs/A.md", contents),
            ["docs/A.md: broken local documentation link \"C.md\""]
        );
    }

    #[test]
    fn reports_every_problem_in_one_run() {
        let found = problems("docs/A.md", "one \u{2014} two, world-class\n");
        assert_eq!(
            found,
            [
                "docs/A.md: contains an em dash",
                "docs/A.md: contains disallowed marketing phrase \"world-class\"",
            ]
        );
    }

    #[test]
    fn reports_links_into_local_scratch() {
        let found = problems(
            "docs/A.md",
            "[plan](../.tmp/plan/GOAL.md) [other](.tmp/x.md)\n",
        );
        assert_eq!(found.len(), 2);
        assert!(
            found
                .iter()
                .all(|problem| problem.contains("local scratch path"))
        );
    }

    #[test]
    fn parses_justfile_recipes() {
        let justfile = "set default-list\n\
            set windows-shell := [\"powershell.exe\"]\n\
            version := \"1\"\n\
            # Comment: not a recipe\n\
            alias t := test\n\
            \n\
            [unix]\n\
            doctor:\n    just --version\n\
            [windows]\n\
            doctor:\n    just --version\n\
            test:\n    echo test\n\
            check: docs-check\n    echo check\n\
            [positional-arguments]\n\
            perf-fixtures *arguments:\n    echo \"$@\"\n\
            build target='x':\n    echo\n\
            @quiet:\n    echo\n\
            [private]\n\
            hidden:\n    echo\n\
            [unix, private]\n\
            hidden-too:\n    echo\n\
            _helper:\n    echo\n";
        let parsed = justfile_recipes(justfile);
        let expected = [
            "build",
            "check",
            "doctor",
            "perf-fixtures",
            "quiet",
            "t",
            "test",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn parses_repository_justfile() {
        let root = crate::workspace_root().unwrap();
        let justfile = fs::read_to_string(root.join("justfile")).unwrap();
        let parsed = justfile_recipes(&justfile);
        for recipe in ["check", "docs-check", "doctor", "perf-fixtures", "test"] {
            assert!(parsed.contains(recipe), "missing {recipe}");
        }
        assert!(!parsed.contains("set"));
    }

    #[test]
    fn validates_just_commands_in_code_only() {
        let recipes = recipes();
        assert!(command_problems("Run `just check` and `just --list`.\n", &recipes).is_empty());
        assert!(command_problems("Use `just <recipe>` or `just {name}`.\n", &recipes).is_empty());
        assert!(
            command_problems("This works just as before, just the same.\n", &recipes).is_empty()
        );
        assert_eq!(
            command_problems("Run `just lint`.\n", &recipes),
            ["names unknown just recipe `just lint`"]
        );
        assert_eq!(
            command_problems(
                "```sh\njust test # just as before\njust lint\n```\n",
                &recipes
            ),
            ["names unknown just recipe `just lint`"]
        );
        assert!(command_problems("```rust\n// just lint\n```\n", &recipes).is_empty());
    }

    #[test]
    fn reads_inline_code_across_wrapped_lines() {
        let contents = "Run `bazelisk run\n//crates/xtask:xtask -- nope-check` now.\n";
        assert_eq!(
            command_problems(contents, &recipes()),
            ["names unknown xtask command `bazelisk run //crates/xtask:xtask -- nope-check`"]
        );
    }

    #[test]
    fn validates_cargo_xtask_commands() {
        let recipes = recipes();
        assert!(command_problems("`cargo xtask docs-check`\n", &recipes).is_empty());
        assert!(command_problems("`cargo xtask fuzz [ARGS]`\n", &recipes).is_empty());
        assert!(
            command_problems(
                "`bazelisk run //crates/xtask:xtask -- perf fixtures --check`\n",
                &recipes
            )
            .is_empty()
        );
        assert_eq!(
            command_problems("`cargo xtask oracle-check`\n", &recipes),
            ["names unknown xtask command `cargo xtask oracle-check`"]
        );
        assert_eq!(
            command_problems("`cargo xtask perf compare`\n", &recipes),
            ["names unknown xtask perf target `cargo xtask perf compare`"]
        );
    }

    #[test]
    fn validates_generate_targets() {
        let recipes = recipes();
        assert!(
            command_problems("`cargo xtask generate vet-inventory --check`\n", &recipes).is_empty()
        );
        assert!(command_problems("`cargo xtask generate <target>`\n", &recipes).is_empty());
        assert_eq!(
            command_problems("`cargo xtask generate oracle-corpus`\n", &recipes),
            ["names unknown xtask generate target `cargo xtask generate oracle-corpus`"]
        );
    }

    #[test]
    fn skips_command_checks_for_frozen_and_historical_files() {
        assert!(is_command_check_exempt(Path::new("CHANGELOG.md")));
        assert!(is_command_check_exempt(Path::new(
            "compat/allowlist-corpus/README.md"
        )));
        assert!(is_command_check_exempt(Path::new(
            "compat/fixtures/upstream/notes.md"
        )));
        assert!(!is_command_check_exempt(Path::new("docs/TESTING.md")));
        let retired = "Run `cargo xtask oracle-check`.\n";
        assert!(problems("compat/allowlist-corpus/README.md", retired).is_empty());
        assert!(problems("CHANGELOG.md", retired).is_empty());
        assert_eq!(problems("docs/TESTING.md", retired).len(), 1);
        assert_eq!(
            problems("CHANGELOG.md", "one \u{2014} two\n"),
            ["CHANGELOG.md: contains an em dash"]
        );
    }

    #[test]
    fn bans_tracker_paths_outside_scratch() {
        let root = ScopedTempDir::new("docs-check-trackers").unwrap();
        for directory in [
            "docs/plans",
            "docs/validation",
            "crates/a",
            ".tmp/work",
            "target",
        ] {
            fs::create_dir_all(root.path.join(directory)).unwrap();
        }
        for file in [
            "docs/ROADMAP.md",
            "docs/GUIDE.md",
            "crates/a/HANDOFF.md",
            "PROGRESS.md",
            "BETA_READINESS.md",
            ".tmp/work/PROGRESS.md",
            "target/ROADMAP.md",
        ] {
            fs::write(root.path.join(file), "# Note\n").unwrap();
        }
        let tree = walk(&root.path).unwrap();
        let found = tracker_problems(&tree);
        let paths = found
            .iter()
            .map(|problem| problem.split_once(':').unwrap().0)
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                "BETA_READINESS.md",
                "PROGRESS.md",
                "crates/a/HANDOFF.md",
                "docs/ROADMAP.md",
                "docs/plans",
                "docs/validation",
            ]
        );
        assert!(
            tree.documents
                .iter()
                .all(|path| !path.starts_with(".tmp") && !path.starts_with("target"))
        );
    }
}
