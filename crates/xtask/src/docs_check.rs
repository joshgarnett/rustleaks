//! Maintained documentation checks.
//!
//! The check covers prose style, local Markdown links, Rust documentation
//! comments, package descriptions, documented commands, and planning or
//! tracker files that belong outside the repository. Every documentation
//! problem is reported before the check fails. Long sentences are reported as
//! warnings and do not fail the check. Workflow and I/O errors stop the check
//! early.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::slice;

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

/// Filler and promotional words that maintained prose must not use.
///
/// They are matched as whole words, ignoring case, in Markdown and Rust
/// documentation prose outside code spans, code blocks, and link targets.
/// Frozen evidence and dependency audit records are exempt. A match that is
/// part of a [`BANNED_PHRASES`] match is reported only once, by that check.
const STYLE_PHRASES: &[&str] = &[
    "blazing",
    "comprehensive",
    "cutting-edge",
    "delve",
    "game-changer",
    "it is worth noting",
    "it's worth noting",
    "leverage",
    "leverages",
    "robust",
    "seamless",
    "seamlessly",
    "state-of-the-art",
    "supercharge",
    "utilize",
    "utilizes",
];

/// Sentences in Markdown prose longer than this many words are reported as
/// warnings.
const SENTENCE_WORD_LIMIT: usize = 40;

/// Dependency audit records, which keep reviewed wording as written.
const DEPENDENCY_AUDIT_DIRECTORY: &str = "docs/dependency-audits";

/// Directory that holds first-party crate manifests.
const CRATES_DIRECTORY: &str = "crates";

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
    let mut warnings = Vec::new();
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
                problems.extend(found.problems);
                warnings.extend(found.warnings);
            }
            Checked::RustDocs(found) => {
                rust_doc_surfaces += 1;
                problems.extend(found.problems);
                warnings.extend(found.warnings);
            }
        }
    }
    for relative in &tree.manifests {
        match fs::read_to_string(root.join(relative)) {
            Ok(contents) => problems.extend(manifest_problems(relative, &contents)),
            Err(error) => problems.push(format!("{}: cannot read: {error}", display(relative))),
        }
    }
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    let warning_summary = plural(warnings.len(), "sentence-length warning");
    if !problems.is_empty() {
        for problem in &problems {
            eprintln!("{problem}");
        }
        return Err(format!(
            "documentation check found {} and {warning_summary}",
            plural(problems.len(), "problem")
        ));
    }
    println!(
        "checked {prose_files} maintained prose files, {rust_doc_surfaces} Rust documentation surfaces, and {} package manifests for links, style, and commands; {warning_summary}",
        tree.manifests.len()
    );
    Ok(())
}

/// Formats a count with a noun that takes a plain `s` plural.
fn plural(count: usize, noun: &str) -> String {
    format!("{count} {noun}{}", if count == 1 { "" } else { "s" })
}

/// The result of checking one file.
#[derive(Debug, PartialEq, Eq)]
enum Checked {
    /// The file has no prose to check.
    Empty,
    /// Findings in a Markdown or YAML file.
    Prose(Findings),
    /// Findings in Rust documentation comments.
    RustDocs(Findings),
}

/// Problems and warnings found in one file, prefixed with its path.
#[derive(Debug, Default, PartialEq, Eq)]
struct Findings {
    /// Problems that fail the check.
    problems: Vec<String>,
    /// Advice that is printed but does not fail the check.
    warnings: Vec<String>,
}

/// Files found by one walk of the checkout, as paths relative to the root.
#[derive(Debug, Default)]
struct Tree {
    /// Sorted documentation files to check.
    documents: Vec<PathBuf>,
    /// Sorted first-party Cargo manifests whose descriptions are checked.
    manifests: Vec<PathBuf>,
    /// Sorted banned tracker files and directories.
    trackers: Vec<PathBuf>,
}

/// Walks the checkout once, skipping build output, Git metadata, Bazel
/// convenience links, and the local scratch directory.
fn walk(root: &Path) -> Result<Tree, String> {
    let mut tree = Tree::default();
    walk_directory(root, root, &mut tree)?;
    tree.documents.sort();
    tree.manifests.sort();
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
        if file_type.is_file() && is_manifest(&relative) {
            tree.manifests.push(relative);
        } else if file_type.is_file() && is_document(&relative) {
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

/// Returns whether a file is a first-party Cargo manifest: the workspace
/// manifest or a manifest below `crates/`, outside frozen evidence.
fn is_manifest(relative: &Path) -> bool {
    relative
        .file_name()
        .is_some_and(|name| name == "Cargo.toml")
        && (relative.components().count() == 1 || relative.starts_with(CRATES_DIRECTORY))
        && !is_frozen(relative)
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
        || is_frozen(relative)
}

/// Returns whether a file is frozen historical evidence that cannot be edited.
fn is_frozen(relative: &Path) -> bool {
    FROZEN_DIRECTORIES
        .iter()
        .any(|directory| relative.starts_with(directory))
        || frozen_artifact_paths().any(|artifact| relative == Path::new(artifact))
}

/// Returns whether a file is exempt from the [`STYLE_PHRASES`] and sentence
/// length checks. Frozen evidence cannot be edited, and dependency audit
/// records keep reviewed wording.
fn is_prose_style_exempt(relative: &Path) -> bool {
    is_frozen(relative) || relative.starts_with(DEPENDENCY_AUDIT_DIRECTORY)
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
    let is_markdown = relative.extension().is_some_and(|value| value == "md");
    let lines = if is_rust {
        rust_documentation_lines(contents)
    } else {
        contents
            .lines()
            .enumerate()
            .map(|(index, line)| (index + 1, line))
            .collect()
    };
    let prose = if is_rust {
        lines
            .iter()
            .map(|(_, line)| *line)
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        contents.to_owned()
    };
    if prose.is_empty() {
        return Checked::Empty;
    }
    let path = display(relative);
    let mut messages = style_problems(&prose);
    if is_markdown {
        messages.extend(link_problems(root, relative, contents));
        if !is_command_check_exempt(relative) {
            messages.extend(command_problems(contents, recipes));
        }
    }
    let mut findings = Findings {
        problems: messages
            .into_iter()
            .map(|message| format!("{path}: {message}"))
            .collect(),
        warnings: Vec::new(),
    };
    if (is_markdown || is_rust) && !is_prose_style_exempt(relative) {
        let blocks = prose_blocks(&lines, is_markdown);
        findings.problems.extend(
            phrase_problems(&blocks)
                .into_iter()
                .map(|(line, message)| format!("{path}:{line}: {message}")),
        );
        if is_markdown {
            findings.warnings = long_sentences(&blocks)
                .into_iter()
                .map(|(line, words)| {
                    format!(
                        "{path}:{line}: sentence has {words} words (limit {SENTENCE_WORD_LIMIT})"
                    )
                })
                .collect();
        }
    }
    if is_rust {
        Checked::RustDocs(findings)
    } else {
        Checked::Prose(findings)
    }
}

/// Checks the `package.description` of a Cargo manifest with the dash, emoji,
/// and phrase rules that apply to prose.
fn manifest_problems(relative: &Path, contents: &str) -> Vec<String> {
    let path = display(relative);
    let manifest: toml::Value = match toml::from_str(contents) {
        Ok(manifest) => manifest,
        Err(error) => return vec![format!("{path}: cannot parse manifest: {error}")],
    };
    // A manifest without a package, or one whose description is inherited
    // with `description.workspace = true`, has no text of its own to check.
    // The workspace manifest that holds the inherited text is checked on its
    // own when it has a `[package]` table.
    let Some(description) = manifest
        .get("package")
        .and_then(|package| package.get("description"))
        .and_then(toml::Value::as_str)
    else {
        return Vec::new();
    };
    let location =
        package_description_line(contents).map_or(path.clone(), |line| format!("{path}:{line}"));
    let block = Block {
        kind: BlockKind::Metadata,
        first_line: 1,
        text: mask_links(&mask_inline_code(description)),
    };
    style_problems(description)
        .into_iter()
        .chain(
            phrase_problems(slice::from_ref(&block))
                .into_iter()
                .map(|(_, message)| message),
        )
        .map(|message| format!("{location}: package description {message}"))
        .collect()
}

/// Returns the one-based line of the `description` key inside the `[package]`
/// table, ignoring keys with the same name in other tables.
fn package_description_line(contents: &str) -> Option<usize> {
    let mut in_package = false;
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim_start();
        if line.starts_with('[') {
            in_package = line
                .split('#')
                .next()
                .is_some_and(|header| header.trim_end() == "[package]");
            continue;
        }
        let Some(rest) = line.strip_prefix("description") else {
            continue;
        };
        if in_package && rest.trim_start().starts_with('=') {
            return Some(index + 1);
        }
    }
    None
}

/// Returns whether a character is an emoji or an emoji presentation selector.
///
/// The checked ranges are the emoji blocks from U+1F000 to U+1FAFF,
/// Miscellaneous Symbols and Dingbats (U+2600 to U+27BF), Miscellaneous
/// Symbols and Arrows (U+2B00 to U+2BFF), and U+FE0F. The U+2B00 block holds
/// emoji such as U+2B50 and decorative arrows such as U+2B05, so it is
/// rejected as a whole. The Arrows block (U+2190 to U+21FF), mathematical
/// operators, letterlike symbols, and box drawing characters are allowed
/// because technical prose uses them.
fn is_emoji(character: char) -> bool {
    ('\u{1f000}'..='\u{1faff}').contains(&character)
        || ('\u{2600}'..='\u{27bf}').contains(&character)
        || ('\u{2b00}'..='\u{2bff}').contains(&character)
        || character == '\u{fe0f}'
}

fn style_problems(prose: &str) -> Vec<String> {
    let mut problems = Vec::new();
    if prose.contains('\u{2014}') {
        problems.push("contains an em dash".to_owned());
    }
    if prose.contains('\u{2013}') {
        problems.push("contains an en dash".to_owned());
    }
    if prose.chars().any(is_emoji) {
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

/// The role of a block of Markdown prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    /// A paragraph or list item.
    Paragraph,
    /// A heading line.
    Heading,
    /// A table row.
    Table,
    /// A frontmatter or manifest description.
    Metadata,
}

/// Prose with code spans and link targets masked. Newlines are kept so that
/// a byte offset maps back to a source line.
#[derive(Debug)]
struct Block {
    kind: BlockKind,
    /// The 1-based source line of the first line of `text`.
    first_line: usize,
    text: String,
}

impl Block {
    fn new(kind: BlockKind, lines: &[(usize, &str)]) -> Option<Self> {
        let first_line = lines.first()?.0;
        let text = lines
            .iter()
            .map(|(_, line)| *line)
            .collect::<Vec<_>>()
            .join("\n");
        Some(Self {
            kind,
            first_line,
            text: mask_links(&mask_inline_code(&text)),
        })
    }

    /// Returns the source line that holds the byte at `offset` in `text`.
    fn line_at(&self, offset: usize) -> usize {
        self.first_line + self.text[..offset].matches('\n').count()
    }
}

/// The role of one Markdown line outside a fenced code block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineKind {
    /// A blank line, thematic break, HTML comment, or link reference
    /// definition. It ends the current paragraph and holds no prose.
    Boundary,
    Heading,
    Table,
    /// The first line of a list item, which starts a new paragraph.
    ListItem,
    Text,
}

fn line_kind(trimmed: &str) -> LineKind {
    let trimmed = trimmed.trim_end();
    if trimmed.is_empty()
        || trimmed.starts_with("<!--")
        || (trimmed.len() >= 3
            && trimmed
                .chars()
                .all(|character| matches!(character, '-' | '=' | '*' | '_' | ' ')))
        || is_link_definition(trimmed)
    {
        return LineKind::Boundary;
    }
    let hashes = trimmed
        .chars()
        .take_while(|character| *character == '#')
        .count();
    if (1..=6).contains(&hashes)
        && trimmed[hashes..]
            .chars()
            .next()
            .is_none_or(char::is_whitespace)
    {
        return LineKind::Heading;
    }
    if trimmed.starts_with('|') {
        return LineKind::Table;
    }
    let digits = trimmed.chars().take_while(char::is_ascii_digit).count();
    let marker = if digits > 0 {
        trimmed[digits..].strip_prefix(['.', ')'])
    } else {
        trimmed.strip_prefix(['-', '*', '+'])
    };
    if marker.is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace)) {
        return LineKind::ListItem;
    }
    LineKind::Text
}

/// Recognizes a link reference definition such as `[name]: target`.
fn is_link_definition(trimmed: &str) -> bool {
    trimmed.strip_prefix('[').is_some_and(|rest| {
        rest.split_once("]:")
            .is_some_and(|(label, _)| !label.is_empty() && !label.contains(']'))
    })
}

/// Splits Markdown into prose blocks, skipping fenced code blocks. `lines`
/// holds 1-based source line numbers; a gap in the numbering, such as code
/// between two Rust documentation comments, ends the current block. When
/// `frontmatter` is set, a leading `---` block contributes only its
/// `description` value.
fn prose_blocks(lines: &[(usize, &str)], frontmatter: bool) -> Vec<Block> {
    fn flush(paragraph: &mut Vec<(usize, &str)>, blocks: &mut Vec<Block>) {
        blocks.extend(Block::new(BlockKind::Paragraph, paragraph));
        paragraph.clear();
    }
    let mut blocks = Vec::new();
    let mut start = 0;
    if frontmatter
        && lines
            .first()
            .is_some_and(|(_, line)| line.trim_end() == "---")
        && let Some(close) = lines[1..]
            .iter()
            .position(|(_, line)| line.trim_end() == "---")
    {
        blocks.extend(frontmatter_description(&lines[1..=close]));
        start = close + 2;
    }
    let mut paragraph = Vec::new();
    let mut fence: Option<(char, usize)> = None;
    let mut previous: Option<usize> = None;
    for &(number, line) in &lines[start..] {
        if previous.is_some_and(|previous| number != previous + 1) {
            flush(&mut paragraph, &mut blocks);
            fence = None;
        }
        previous = Some(number);
        let trimmed = line.trim_start();
        if let Some((marker, length)) = fence {
            if is_fence_close(trimmed, marker, length) {
                fence = None;
            }
            continue;
        }
        if let Some((marker, length, _)) = fence_open(trimmed) {
            flush(&mut paragraph, &mut blocks);
            fence = Some((marker, length));
            continue;
        }
        match line_kind(trimmed) {
            LineKind::Boundary => flush(&mut paragraph, &mut blocks),
            LineKind::Heading => {
                flush(&mut paragraph, &mut blocks);
                blocks.extend(Block::new(BlockKind::Heading, &[(number, line)]));
            }
            LineKind::Table => {
                flush(&mut paragraph, &mut blocks);
                blocks.extend(Block::new(BlockKind::Table, &[(number, line)]));
            }
            LineKind::ListItem => {
                flush(&mut paragraph, &mut blocks);
                paragraph.push((number, line));
            }
            LineKind::Text => paragraph.push((number, line)),
        }
    }
    flush(&mut paragraph, &mut blocks);
    blocks
}

/// Returns the `description` value of a frontmatter block, including indented
/// continuation lines and block scalars.
fn frontmatter_description(lines: &[(usize, &str)]) -> Option<Block> {
    let index = lines
        .iter()
        .position(|(_, line)| line.starts_with("description:"))?;
    let (number, line) = lines[index];
    let value = line["description:".len()..].trim();
    let mut values = vec![(
        number,
        if value.starts_with(['>', '|']) {
            ""
        } else {
            value
        },
    )];
    values.extend(
        lines[index + 1..]
            .iter()
            .take_while(|(_, line)| {
                line.starts_with(char::is_whitespace) && !line.trim().is_empty()
            })
            .map(|(number, line)| (*number, line.trim())),
    );
    Block::new(BlockKind::Metadata, &values)
}

/// Replaces each closed inline code span with the word `code`, keeping any
/// newlines inside the span.
fn mask_inline_code(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut masked = String::with_capacity(text.len());
    let mut copied = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'`' {
            index += 1;
            continue;
        }
        let open_length = backtick_run(bytes, index);
        let content_start = index + open_length;
        match closing_backticks(bytes, content_start, open_length) {
            Some(close) => {
                masked.push_str(&text[copied..index]);
                masked.push_str("code");
                for _ in text[content_start..close].matches('\n') {
                    masked.push('\n');
                }
                index = close + open_length;
                copied = index;
            }
            None => index = content_start,
        }
    }
    masked.push_str(&text[copied..]);
    masked
}

/// Removes Markdown link targets and replaces bare URLs with the word `link`.
/// Link text is kept.
fn mask_links(text: &str) -> String {
    let mut masked = String::with_capacity(text.len());
    let mut index = 0;
    while let Some(rest) = text.get(index..).filter(|rest| !rest.is_empty()) {
        if let Some(target) = rest.strip_prefix("](") {
            let end = target.find([')', '\n']).unwrap_or(target.len());
            masked.push(']');
            index += 2 + end + usize::from(target[end..].starts_with(')'));
            continue;
        }
        if rest.starts_with("http://") || rest.starts_with("https://") {
            let end = rest
                .find(|character: char| {
                    character.is_whitespace() || matches!(character, ')' | '>' | ']')
                })
                .unwrap_or(rest.len());
            masked.push_str("link");
            index += end;
            continue;
        }
        let Some(character) = rest.chars().next() else {
            break;
        };
        masked.push(character);
        index += character.len_utf8();
    }
    masked
}

/// Returns maximal runs of characters accepted by `keep`, with byte offsets.
fn runs(text: &str, keep: impl Fn(char) -> bool) -> Vec<(usize, &str)> {
    let mut found = Vec::new();
    let mut start = None;
    for (index, character) in text.char_indices() {
        if keep(character) {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take() {
            found.push((begin, &text[begin..index]));
        }
    }
    if let Some(begin) = start {
        found.push((begin, &text[begin..]));
    }
    found
}

/// Splits prose into lowercase words with byte offsets. Hyphens,
/// underscores, and apostrophes inside a word are part of it, so
/// `non-robust` and `robust_name` are single words.
fn words(text: &str) -> Vec<(usize, String)> {
    const EDGES: &[char] = &['-', '_', '\'', '\u{2019}'];
    runs(text, |character| {
        character.is_alphanumeric() || EDGES.contains(&character)
    })
    .into_iter()
    .filter_map(|(offset, word)| {
        let trimmed = word.trim_start_matches(EDGES);
        let offset = offset + (word.len() - trimmed.len());
        let trimmed = trimmed.trim_end_matches(EDGES);
        (!trimmed.is_empty()).then(|| (offset, trimmed.to_lowercase().replace('\u{2019}', "'")))
    })
    .collect()
}

/// Reports [`STYLE_PHRASES`] used as whole words, with their source lines.
fn phrase_problems(blocks: &[Block]) -> Vec<(usize, String)> {
    let phrases = STYLE_PHRASES
        .iter()
        .map(|phrase| (*phrase, phrase.split(' ').collect::<Vec<_>>()))
        .collect::<Vec<_>>();
    let mut problems = Vec::new();
    for block in blocks {
        let mut text = block.text.to_ascii_lowercase();
        for phrase in BANNED_PHRASES {
            text = text.replace(phrase, &" ".repeat(phrase.len()));
        }
        let words = words(&text);
        for start in 0..words.len() {
            for (phrase, parts) in &phrases {
                let matches = words.len() - start >= parts.len()
                    && words[start..]
                        .iter()
                        .zip(parts)
                        .all(|((_, word), part)| word == part);
                if matches {
                    problems.push((
                        block.line_at(words[start].0),
                        format!("uses disallowed phrase {phrase:?}"),
                    ));
                }
            }
        }
    }
    problems
}

/// Returns the starting line and word count of each paragraph sentence that
/// is longer than [`SENTENCE_WORD_LIMIT`].
fn long_sentences(blocks: &[Block]) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    for block in blocks
        .iter()
        .filter(|block| block.kind == BlockKind::Paragraph)
    {
        let mut count = 0_usize;
        let mut first_line = block.first_line;
        for (offset, token) in runs(&block.text, |character| !character.is_whitespace()) {
            if token.chars().any(char::is_alphanumeric) {
                if count == 0 {
                    first_line = block.line_at(offset);
                }
                count += 1;
            }
            let end =
                token.trim_end_matches([')', '"', '\'', '*', '_', ']', '\u{2019}', '\u{201d}']);
            if end.ends_with(['.', '!', '?']) {
                if count > SENTENCE_WORD_LIMIT {
                    found.push((first_line, count));
                }
                count = 0;
            }
        }
        if count > SENTENCE_WORD_LIMIT {
            found.push((first_line, count));
        }
    }
    found
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

/// Returns the text of Rust documentation comments with 1-based line numbers.
fn rust_documentation_lines(contents: &str) -> Vec<(usize, &str)> {
    contents
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.trim_start();
            line.strip_prefix("//!")
                .or_else(|| line.strip_prefix("///"))
                .map(|text| (index + 1, text))
        })
        .collect()
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
        match closing_backticks(bytes, content_start, open_length) {
            Some(close) => {
                spans.push(paragraph[content_start..close].replace('\n', " "));
                index = close + open_length;
            }
            None => index = content_start,
        }
    }
    spans
}

/// Returns the offset of the next backtick run of exactly `length` at or
/// after `start`, which closes an inline code span.
fn closing_backticks(bytes: &[u8], start: usize, length: usize) -> Option<usize> {
    let mut search = start;
    while search < bytes.len() {
        if bytes[search] == b'`' {
            let run = backtick_run(bytes, search);
            if run == length {
                return Some(search);
            }
            search += run;
        } else {
            search += 1;
        }
    }
    None
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
        Checked, Findings, check_document, command_problems, is_command_check_exempt,
        justfile_recipes, manifest_problems, tracker_problems, walk,
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
        findings(root, relative, contents).problems
    }

    fn warnings(relative: &str, contents: &str) -> Vec<String> {
        findings(
            Path::new("/nonexistent-docs-check-root"),
            relative,
            contents,
        )
        .warnings
    }

    fn findings(root: &Path, relative: &str, contents: &str) -> Findings {
        match check_document(root, Path::new(relative), contents, &recipes()) {
            Checked::Empty => Findings::default(),
            Checked::Prose(found) | Checked::RustDocs(found) => found,
        }
    }

    /// Returns one sentence of `count` synthetic words.
    fn sentence(count: usize) -> String {
        let words = (1..=count)
            .map(|index| format!("w{index}"))
            .collect::<Vec<_>>();
        format!("{}.", words.join(" "))
    }

    #[test]
    fn reports_en_dash() {
        assert_eq!(
            problems("docs/A.md", "pages 1\u{2013}2\n"),
            ["docs/A.md: contains an en dash"]
        );
    }

    #[test]
    fn reports_star_and_emoji_presentation_selector() {
        assert_eq!(
            problems("docs/A.md", "rated \u{2b50}\n"),
            ["docs/A.md: contains an emoji"]
        );
        assert_eq!(
            problems("docs/A.md", "mark 1\u{fe0f}\n"),
            ["docs/A.md: contains an emoji"]
        );
    }

    #[test]
    fn reports_decorative_arrow_but_allows_arrows_block() {
        assert_eq!(
            problems("docs/A.md", "go \u{2b05}\n"),
            ["docs/A.md: contains an emoji"]
        );
        assert!(problems("docs/A.md", "a \u{2190} b \u{21d2} c\n").is_empty());
    }

    #[test]
    fn marketing_phrase_is_reported_once() {
        assert_eq!(
            problems("docs/A.md", "A best-in-class tool.\n"),
            ["docs/A.md: contains disallowed marketing phrase \"best-in-class\""]
        );
    }

    #[test]
    fn locates_package_description_line() {
        let manifest = "[features]\ndescription = []\n\n[package]\nname = \"demo\"\ndescriptions = 1\ndescription = \"A robust tool\"\n";
        assert_eq!(
            manifest_problems(Path::new("crates/demo/Cargo.toml"), manifest),
            ["crates/demo/Cargo.toml:7: package description uses disallowed phrase \"robust\""]
        );
        assert!(
            manifest_problems(
                Path::new("crates/demo/Cargo.toml"),
                "[package]\nname = \"demo\"\ndescription.workspace = true\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn allows_technical_symbols() {
        let symbols = "a \u{2192} b, x \u{2265} y, 5 \u{212a}, \u{a7}3, wait\u{2026}, \u{2502} \u{d7} \u{b5}s\n";
        assert!(problems("docs/A.md", symbols).is_empty());
    }

    #[test]
    fn reports_style_phrases_as_whole_words_with_lines() {
        let contents = "# Title\n\nA Robust design.\nIt\u{2019}s worth noting that it is\nworth noting twice.\n\n| col | We leverage it |\n";
        assert_eq!(
            problems("docs/A.md", contents),
            [
                "docs/A.md:3: uses disallowed phrase \"robust\"",
                "docs/A.md:4: uses disallowed phrase \"it's worth noting\"",
                "docs/A.md:4: uses disallowed phrase \"it is worth noting\"",
                "docs/A.md:7: uses disallowed phrase \"leverage\"",
            ]
        );
    }

    #[test]
    fn ignores_style_phrases_in_code_links_and_compound_words() {
        let contents = "Use `robust` and ``seamless``, a non-robust path, robustness, robust_name.\n\
            See [the guide](https://example.com/robust) and https://example.com/leverage.\n\
            [ref]: https://example.com/utilize\n\
            \n```toml\nrobust = true\n```\n\n    ~~~\n    utilize\n    ~~~\n";
        assert!(problems("docs/A.md", contents).is_empty());
    }

    #[test]
    fn reports_marketing_phrase_once() {
        assert_eq!(
            problems("docs/A.md", "A blazing fast tool, blazing ahead.\n"),
            [
                "docs/A.md: contains disallowed marketing phrase \"blazing fast\"",
                "docs/A.md:1: uses disallowed phrase \"blazing\"",
            ]
        );
    }

    #[test]
    fn checks_style_phrases_in_rust_documentation() {
        let source = "//! Module docs.\nfn f() {} // robust\n/// A seamless helper.\n///\n/// ```\n/// let robust = 1;\n/// ```\nfn g() {}\n";
        assert_eq!(
            check_document(Path::new("."), Path::new("src/lib.rs"), source, &recipes()),
            Checked::RustDocs(Findings {
                problems: vec!["src/lib.rs:3: uses disallowed phrase \"seamless\"".to_owned()],
                warnings: Vec::new(),
            })
        );
    }

    #[test]
    fn exempts_frozen_files_and_audits_from_style_phrases() {
        let contents = "A robust design.\n";
        assert!(problems("compat/allowlist-corpus/README.md", contents).is_empty());
        assert!(problems("docs/dependency-audits/crate.md", contents).is_empty());
        assert_eq!(
            problems("CHANGELOG.md", contents),
            ["CHANGELOG.md:1: uses disallowed phrase \"robust\""]
        );
        assert_eq!(
            problems("docs/dependency-audits/crate.md", "a \u{2013} b\n"),
            ["docs/dependency-audits/crate.md: contains an en dash"]
        );
    }

    #[test]
    fn checks_frontmatter_description() {
        let contents = "---\nname: robust-skill\ndescription: Seamless\n  sync of state.\n---\n\nUse it to leverage data.\n";
        assert_eq!(
            problems(".agents/skills/demo/SKILL.md", contents),
            [
                ".agents/skills/demo/SKILL.md:3: uses disallowed phrase \"seamless\"",
                ".agents/skills/demo/SKILL.md:7: uses disallowed phrase \"leverage\"",
            ]
        );
        assert_eq!(
            problems(
                ".agents/skills/demo/SKILL.md",
                "---\ndescription: >\n  A robust tool.\n---\n"
            ),
            [".agents/skills/demo/SKILL.md:3: uses disallowed phrase \"robust\""]
        );
        assert_eq!(
            problems(
                ".agents/skills/demo/SKILL.md",
                "---\ndescription: Sync \u{2014} state.\n---\n"
            ),
            [".agents/skills/demo/SKILL.md: contains an em dash"]
        );
    }

    #[test]
    fn warns_about_long_sentences_in_paragraphs_only() {
        let long = sentence(41);
        let limit = sentence(40);
        let contents = format!(
            "# {long}\n\n{limit} Short one.\n\nIntro line\n{long}\n\n| {long} |\n\n```text\n{long}\n```\n\n- {limit}\n- {limit}\n"
        );
        assert_eq!(
            warnings("docs/A.md", &contents),
            ["docs/A.md:5: sentence has 43 words (limit 40)"]
        );
        assert!(problems("docs/A.md", &contents).is_empty());
        let unterminated = format!("Start {}\n", sentence(40).trim_end_matches('.'));
        assert_eq!(
            warnings("docs/A.md", &unterminated),
            ["docs/A.md:1: sentence has 41 words (limit 40)"]
        );
    }

    #[test]
    fn exempts_frozen_files_audits_and_rust_from_sentence_warnings() {
        let contents = format!("{}\n", sentence(41));
        assert_eq!(warnings("docs/A.md", &contents).len(), 1);
        assert!(warnings("compat/allowlist-corpus/README.md", &contents).is_empty());
        assert!(warnings("docs/dependency-audits/crate.md", &contents).is_empty());
        assert!(warnings("src/lib.rs", &format!("/// {contents}")).is_empty());
    }

    #[test]
    fn checks_package_descriptions() {
        let manifest = "[package]\nname = \"demo\"\ndescription = \"A robust \u{2013} seamless tool \u{2b50}\"\n";
        assert_eq!(
            manifest_problems(Path::new("crates/demo/Cargo.toml"), manifest),
            [
                "crates/demo/Cargo.toml:3: package description contains an en dash",
                "crates/demo/Cargo.toml:3: package description contains an emoji",
                "crates/demo/Cargo.toml:3: package description uses disallowed phrase \"robust\"",
                "crates/demo/Cargo.toml:3: package description uses disallowed phrase \"seamless\"",
            ]
        );
        assert!(
            manifest_problems(
                Path::new("crates/demo/Cargo.toml"),
                "[package]\nname = \"demo\"\ndescription = \"Safe bounded decoder\"\n"
            )
            .is_empty()
        );
        assert!(
            manifest_problems(Path::new("Cargo.toml"), "[workspace]\nmembers = []\n").is_empty()
        );
        assert_eq!(
            manifest_problems(Path::new("Cargo.toml"), "[package\n").len(),
            1
        );
    }

    #[test]
    fn collects_first_party_manifests() {
        let root = ScopedTempDir::new("docs-check-manifests").unwrap();
        for directory in [
            "crates/a/fuzz",
            "crates/a/target",
            ".tmp/copy",
            "compat/allowlist-corpus",
            "vendor/b",
        ] {
            fs::create_dir_all(root.path.join(directory)).unwrap();
        }
        for file in [
            "Cargo.toml",
            "crates/a/Cargo.toml",
            "crates/a/fuzz/Cargo.toml",
            "crates/a/target/Cargo.toml",
            ".tmp/copy/Cargo.toml",
            "compat/allowlist-corpus/Cargo.toml",
            "vendor/b/Cargo.toml",
        ] {
            fs::write(root.path.join(file), "[workspace]\n").unwrap();
        }
        let tree = walk(&root.path).unwrap();
        let manifests = tree
            .manifests
            .iter()
            .map(|path| super::display(path))
            .collect::<Vec<_>>();
        assert_eq!(
            manifests,
            [
                "Cargo.toml",
                "crates/a/Cargo.toml",
                "crates/a/fuzz/Cargo.toml"
            ]
        );
        assert!(tree.documents.is_empty());
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
            Checked::RustDocs(Findings {
                problems: vec!["src/lib.rs: contains an em dash".to_owned()],
                warnings: Vec::new(),
            })
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
