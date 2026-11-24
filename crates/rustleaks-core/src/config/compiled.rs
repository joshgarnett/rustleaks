use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use aho_corasick::AhoCorasick;

use crate::go_unicode::lowercase_bytes as go_lowercase_bytes;
use crate::native::predicate::NativePredicate;
use crate::native::{NativeEntropy, NativeKeyword, NativeRequired};
use crate::regex::{GoRegex, NativeByteRegex};

use super::{Condition, ConfigExtension, ConfigOrigin, RegexTarget, RequiredRuleSpec};

/// A validated, normalized allowlist. Pattern strings remain inspectable while
/// executable matcher state is immutable and private.
#[derive(Clone)]
pub struct CompiledAllowlist {
    pub(crate) description: String,
    pub(crate) condition: Condition,
    pub(crate) commits: BTreeSet<String>,
    pub(crate) paths: Vec<String>,
    pub(crate) regex_target: RegexTarget,
    pub(crate) regexes: Vec<String>,
    pub(crate) stop_words: BTreeSet<String>,
    pub(crate) path_matcher: Option<GoRegex>,
    pub(crate) regex_matcher: Option<GoRegex>,
    pub(crate) stopword_matcher: Option<AhoCorasick>,
}

impl CompiledAllowlist {
    /// Returns the human-readable description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the normalized criterion combination condition.
    #[must_use]
    pub fn condition(&self) -> &Condition {
        &self.condition
    }

    /// Iterates normalized, deduplicated commit identifiers.
    #[must_use]
    pub fn commits(&self) -> impl ExactSizeIterator<Item = &str> {
        self.commits.iter().map(String::as_str)
    }

    /// Returns path pattern source strings.
    #[must_use]
    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    /// Returns the normalized content-pattern target.
    #[must_use]
    pub fn regex_target(&self) -> &RegexTarget {
        &self.regex_target
    }

    /// Returns content pattern source strings.
    #[must_use]
    pub fn regexes(&self) -> &[String] {
        &self.regexes
    }

    /// Iterates normalized, deduplicated stop words.
    #[must_use]
    pub fn stop_words(&self) -> impl ExactSizeIterator<Item = &str> {
        self.stop_words.iter().map(String::as_str)
    }

    pub(crate) fn commit_allowed(&self, commit: &[u8]) -> bool {
        if commit.is_empty() {
            return false;
        }
        let normalized = go_lowercase_bytes(commit);
        self.commits
            .iter()
            .any(|stored| stored.as_bytes() == normalized)
    }

    pub(crate) fn path_allowed(&self, path: &[u8]) -> bool {
        !path.is_empty()
            && self
                .path_matcher
                .as_ref()
                .is_some_and(|matcher| matcher.is_match(path))
    }

    // Retained as an unbudgeted reference for the controlled allowlist tests.
    #[cfg(test)]
    pub(crate) fn regex_allowed(&self, target: &[u8]) -> bool {
        !target.is_empty()
            && self
                .regex_matcher
                .as_ref()
                .is_some_and(|matcher| matcher.is_match(target))
    }

    pub(crate) fn contains_stop_word(&self, secret: &[u8]) -> bool {
        if secret.is_empty() {
            return false;
        }
        let Some(matcher) = self.stopword_matcher.as_ref() else {
            return false;
        };
        let normalized = go_lowercase_bytes(secret);
        matcher.is_match(&normalized)
    }
}

impl fmt::Debug for CompiledAllowlist {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledAllowlist")
            .field("description", &self.description)
            .field("condition", &self.condition)
            .field("commits", &self.commits)
            .field("paths", &self.paths)
            .field("regex_target", &self.regex_target)
            .field("regexes", &self.regexes)
            .field("stop_words", &self.stop_words)
            .finish_non_exhaustive()
    }
}

impl PartialEq for CompiledAllowlist {
    fn eq(&self, other: &Self) -> bool {
        self.description == other.description
            && self.condition == other.condition
            && self.commits == other.commits
            && self.paths == other.paths
            && self.regex_target == other.regex_target
            && self.regexes == other.regexes
            && self.stop_words == other.stop_words
    }
}

impl Eq for CompiledAllowlist {}

/// An immutable, configuration-validated rule with inspectable pattern text.
/// Executable regex dialects and native metadata remain private.
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledRule {
    pub(crate) id: String,
    pub(crate) description: String,
    pub(crate) path: Option<String>,
    pub(crate) regex: Option<String>,
    pub(crate) path_matcher: Option<GoRegex>,
    pub(crate) regex_matcher: Option<GoRegex>,
    pub(crate) secret_group: i64,
    pub(crate) entropy: f64,
    pub(crate) native_entropy: Option<NativeEntropy>,
    pub(crate) native_predicate: Option<NativePredicate>,
    pub(crate) native_required: Option<NativeRequired>,
    pub(crate) native_byte_matcher: Option<NativeByteRegex>,
    pub(crate) native_keywords: Option<Vec<NativeKeyword>>,
    pub(crate) keywords: Vec<String>,
    pub(crate) tags: Vec<String>,
    pub(crate) allowlists: Vec<CompiledAllowlist>,
    pub(crate) required: Vec<RequiredRuleSpec>,
    pub(crate) skip_report: bool,
    /// Whether the rule comes from a native rule pack.
    pub(crate) native_pack: bool,
    /// IDs of the rules whose finding replaces a finding of this rule with
    /// the same file, commit, secret and exact secret range. Set only from
    /// the reviewed `[[overlaps]]` entries of native rule packs.
    pub(crate) native_replaced_by: Vec<String>,
}

impl CompiledRule {
    /// Returns the stable rule ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the human-readable description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the optional path pattern source.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Returns the optional content pattern source.
    #[must_use]
    pub fn regex(&self) -> Option<&str> {
        self.regex.as_deref()
    }

    /// Returns the configured secret capture group.
    #[must_use]
    pub fn secret_group(&self) -> i64 {
        self.secret_group
    }

    /// Returns the configured scalar minimum entropy.
    ///
    /// This is zero for a native byte-entropy predicate. Inspect
    /// [`Self::native_entropy`] for that predicate's complete metadata.
    #[must_use]
    pub fn entropy(&self) -> f64 {
        self.entropy
    }

    /// Returns a native predicate's algorithm, rejection comparator and threshold.
    ///
    /// `byte-shannon-f64-v1` counts bytes in ascending order and divides each
    /// count by the byte length in binary64. `lt` rejects entropy below the
    /// threshold; `le` also rejects equality. Zero remains an active threshold.
    /// Native metadata survives cloning, rule selection and engine construction.
    #[must_use]
    pub fn native_entropy(&self) -> Option<(&'static str, &'static str, f64)> {
        self.native_entropy.map(NativeEntropy::metadata)
    }

    /// Returns the versioned bounded predicate algorithm, when configured.
    /// The complete descriptor remains part of the native policy's exact identity.
    #[must_use]
    pub fn native_predicate_algorithm(&self) -> Option<&'static str> {
        self.native_predicate
            .as_ref()
            .map(NativePredicate::algorithm)
    }

    /// Returns normalized pre-filter keywords in effective rule order.
    #[must_use]
    pub fn keywords(&self) -> &[String] {
        &self.keywords
    }

    /// Returns reporting tags in effective rule order.
    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Returns validated allowlist data.
    #[must_use]
    pub fn allowlists(&self) -> &[CompiledAllowlist] {
        &self.allowlists
    }

    /// Returns composite-rule dependencies.
    #[must_use]
    pub fn required_rules(&self) -> &[RequiredRuleSpec] {
        &self.required
    }

    /// Returns whether reporting is suppressed for this rule.
    #[must_use]
    pub fn skip_report(&self) -> bool {
        self.skip_report
    }

    /// IDs of the rules that this rule needs before it reports. The required
    /// rules also list the helpers of a `buffer-v1` relation.
    pub(crate) fn helper_ids(&self) -> impl Iterator<Item = &str> {
        self.required.iter().map(|required| required.id.as_str())
    }

    /// Makes a rule that is kept only for another rule a helper that does
    /// not report and keeps no overlaps.
    pub(crate) fn into_helper(mut self) -> Self {
        self.skip_report = true;
        self.native_replaced_by.clear();
        self
    }
}

/// Immutable, shareable effective configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct CompiledConfig {
    pub(crate) title: String,
    pub(crate) description: String,
    pub(crate) extension: ConfigExtension,
    pub(crate) origin: Option<ConfigOrigin>,
    pub(crate) rules: BTreeMap<String, CompiledRule>,
    pub(crate) ordered_rule_ids: Vec<String>,
    pub(crate) keywords: BTreeSet<String>,
    pub(crate) allowlists: Vec<CompiledAllowlist>,
    pub(crate) min_version: String,
    pub(crate) requires_newer_version: bool,
    pub(crate) targeted_allowlists: Vec<(Vec<String>, CompiledAllowlist)>,
}

impl CompiledConfig {
    /// Maximum ordered rule IDs accepted by one projected configuration.
    pub const MAX_SELECTED_RULES: usize = 4_096;
    /// Maximum inspectable source text copied into one rule projection.
    pub const MAX_SELECTED_BYTES: usize = 8 * 1_024 * 1_024;

    /// Returns the top-level title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the top-level description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the original top-level extension directive.
    #[must_use]
    pub fn extension(&self) -> &ConfigExtension {
        &self.extension
    }

    /// Returns the source origin, when supplied.
    #[must_use]
    pub fn origin(&self) -> Option<&ConfigOrigin> {
        self.origin.as_ref()
    }

    /// Returns final rules by ID. Duplicate source IDs use the last value.
    #[must_use]
    pub fn rules(&self) -> &BTreeMap<String, CompiledRule> {
        &self.rules
    }

    /// Looks up a final rule by ID.
    #[must_use]
    pub fn rule(&self, id: &str) -> Option<&CompiledRule> {
        self.rules.get(id)
    }

    /// IDs in Go-compatible report order. Duplicate IDs remain duplicate.
    #[must_use]
    pub fn ordered_rule_ids(&self) -> &[String] {
        &self.ordered_rule_ids
    }

    /// Rules in report order. As in Go, duplicate IDs resolve to the final
    /// map entry and therefore may yield the same rule more than once.
    #[must_use]
    pub fn ordered_rules(&self) -> impl ExactSizeIterator<Item = &CompiledRule> {
        self.ordered_rule_ids
            .iter()
            .map(|id| &self.rules[id.as_str()])
    }

    /// Returns an immutable configuration containing only the requested
    /// effective rules, preserving request order and duplicates for reports.
    ///
    /// The rules that a selected, reporting rule needs (required rules and
    /// `buffer-v1` helpers) stay in the projection as rules that do not
    /// report, even when they are not selected. They are not in
    /// [`Self::ordered_rule_ids`].
    ///
    /// # Errors
    ///
    /// Returns [`RuleSelectionError`] for the first unknown rule ID.
    pub fn select_rules<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, RuleSelectionError> {
        let mut selected_ids = Vec::new();
        for id in ids {
            if selected_ids.len() == Self::MAX_SELECTED_RULES {
                return Err(RuleSelectionError::limit(Self::MAX_SELECTED_RULES));
            }
            selected_ids
                .try_reserve(1)
                .map_err(|_| RuleSelectionError::allocation())?;
            selected_ids.push(try_copy_selection_string(id)?);
        }
        let helper_ids = self.selection_helpers(&selected_ids);
        self.validate_selection(&selected_ids, &helper_ids)?;
        let mut rules = BTreeMap::new();
        let mut keywords = BTreeSet::new();
        for id in &selected_ids {
            let Some(rule) = self.rules.get(id) else {
                return Err(RuleSelectionError::not_found(try_copy_selection_string(
                    id,
                )?));
            };
            let mut rule = rule.clone();
            // Like required rules, a reviewed overlap applies only within the
            // selected rules.
            rule.native_replaced_by
                .retain(|keeper| selected_ids.contains(keeper));
            for keyword in &rule.keywords {
                if keywords.len() == Self::MAX_SELECTED_RULES
                    && !keywords.contains(keyword.as_str())
                {
                    return Err(RuleSelectionError::limit(Self::MAX_SELECTED_RULES));
                }
                keywords.insert(try_copy_selection_string(keyword)?);
            }
            rules.insert(try_copy_selection_string(id)?, rule);
        }
        for id in helper_ids {
            let rule = self.rules[id].clone().into_helper();
            for keyword in &rule.keywords {
                if keywords.len() == Self::MAX_SELECTED_RULES
                    && !keywords.contains(keyword.as_str())
                {
                    return Err(RuleSelectionError::limit(Self::MAX_SELECTED_RULES));
                }
                keywords.insert(try_copy_selection_string(keyword)?);
            }
            rules.insert(try_copy_selection_string(id)?, rule);
        }
        let mut targeted_allowlists = Vec::new();
        for (targets, allowlist) in &self.targeted_allowlists {
            let mut selected = Vec::new();
            for target in targets
                .iter()
                .filter(|target| rules.contains_key(target.as_str()))
            {
                if selected.len() == Self::MAX_SELECTED_RULES {
                    return Err(RuleSelectionError::limit(Self::MAX_SELECTED_RULES));
                }
                selected
                    .try_reserve(1)
                    .map_err(|_| RuleSelectionError::allocation())?;
                selected.push(try_copy_selection_string(target)?);
            }
            if !selected.is_empty() {
                if targeted_allowlists.len() == Self::MAX_SELECTED_RULES {
                    return Err(RuleSelectionError::limit(Self::MAX_SELECTED_RULES));
                }
                targeted_allowlists
                    .try_reserve(1)
                    .map_err(|_| RuleSelectionError::allocation())?;
                targeted_allowlists.push((selected, allowlist.clone()));
            }
        }
        Ok(Self {
            title: self.title.clone(),
            description: self.description.clone(),
            min_version: self.min_version.clone(),
            requires_newer_version: self.requires_newer_version,
            origin: self.origin.clone(),
            rules,
            ordered_rule_ids: selected_ids,
            keywords,
            allowlists: self.allowlists.clone(),
            extension: self.extension.clone(),
            targeted_allowlists,
        })
    }

    /// IDs of the rules, not selected, that a selected reporting rule needs.
    fn selection_helpers(&self, selected_ids: &[String]) -> Vec<&str> {
        let selected = selected_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        selected
            .iter()
            .filter_map(|id| self.rules.get(*id))
            .filter(|rule| !rule.skip_report)
            .flat_map(CompiledRule::helper_ids)
            .filter(|id| !selected.contains(id) && self.rules.contains_key(*id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn validate_selection(
        &self,
        selected_ids: &[String],
        helper_ids: &[&str],
    ) -> Result<(), RuleSelectionError> {
        let mut selected_bytes = self
            .title
            .len()
            .checked_add(self.description.len())
            .and_then(|size| size.checked_add(self.min_version.len()))
            .ok_or_else(RuleSelectionError::size_limit)?;
        selected_bytes = checked_selection_size(selected_bytes, self.extension.path.len())?;
        selected_bytes = checked_selection_size(selected_bytes, self.extension.url.len())?;
        for id in &self.extension.disabled_rules {
            selected_bytes = checked_selection_size(selected_bytes, id.len())?;
        }
        if let Some(origin) = &self.origin {
            let length = match origin {
                ConfigOrigin::Path(path) => path.as_os_str().as_encoded_bytes().len(),
                ConfigOrigin::Virtual(value) => value.len(),
                ConfigOrigin::EmbeddedDefault => 0,
            };
            selected_bytes = checked_selection_size(selected_bytes, length)?;
        }
        for allowlist in &self.allowlists {
            selected_bytes = add_allowlist_size(selected_bytes, allowlist)?;
        }
        for id in selected_ids {
            let Some(rule) = self.rules.get(id) else {
                return Err(RuleSelectionError::not_found(try_copy_selection_string(
                    id,
                )?));
            };
            selected_bytes = add_rule_size(selected_bytes, rule)?;
        }
        for id in helper_ids {
            selected_bytes = add_rule_size(selected_bytes, &self.rules[*id])?;
        }
        for (targets, allowlist) in &self.targeted_allowlists {
            if targets
                .iter()
                .any(|target| selected_ids.iter().any(|id| id == target))
            {
                selected_bytes = add_allowlist_size(selected_bytes, allowlist)?;
                for target in targets {
                    selected_bytes = checked_selection_size(selected_bytes, target.len())?;
                }
            }
        }
        if selected_bytes > Self::MAX_SELECTED_BYTES {
            return Err(RuleSelectionError::size_limit());
        }
        Ok(())
    }

    /// Returns the normalized global keyword set.
    #[must_use]
    pub fn keywords(&self) -> &BTreeSet<String> {
        &self.keywords
    }

    /// Returns global allowlists not targeted to individual rules.
    #[must_use]
    pub fn allowlists(&self) -> &[CompiledAllowlist] {
        &self.allowlists
    }

    /// Returns whether an early source-adapter path check matches any global
    /// allowlist path expression.
    ///
    /// This deliberately tests only path expressions. The file walker uses
    /// this as an I/O pruning optimization before commit, content, and
    /// stop-word criteria exist, so an allowlist's combination condition does
    /// not participate. `windows_path` is the original native spelling used by
    /// Windows in addition to the slash-normalized logical path.
    #[must_use]
    pub fn source_path_allowed(&self, path: &[u8], windows_path: Option<&[u8]>) -> bool {
        self.allowlists.iter().any(|allowlist| {
            allowlist.path_allowed(path)
                || windows_path.is_some_and(|candidate| allowlist.path_allowed(candidate))
        })
    }

    /// Returns the source `minVersion` spelling.
    #[must_use]
    pub fn min_version(&self) -> &str {
        &self.min_version
    }

    /// Whether an explicitly configured current version is below minVersion.
    #[must_use]
    pub fn requires_newer_version(&self) -> bool {
        self.requires_newer_version
    }
}

/// An enabled-rule request named no effective configured rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleSelectionError {
    rule_id: String,
    kind: RuleSelectionErrorKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuleSelectionErrorKind {
    NotFound,
    Limit { maximum: usize },
    Allocation,
    SizeLimit,
}

impl RuleSelectionError {
    const fn not_found(rule_id: String) -> Self {
        Self {
            rule_id,
            kind: RuleSelectionErrorKind::NotFound,
        }
    }

    const fn limit(maximum: usize) -> Self {
        Self {
            rule_id: String::new(),
            kind: RuleSelectionErrorKind::Limit { maximum },
        }
    }

    const fn allocation() -> Self {
        Self {
            rule_id: String::new(),
            kind: RuleSelectionErrorKind::Allocation,
        }
    }

    const fn size_limit() -> Self {
        Self {
            rule_id: String::new(),
            kind: RuleSelectionErrorKind::SizeLimit,
        }
    }

    /// Returns the missing rule ID.
    #[must_use]
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }
}

impl std::fmt::Display for RuleSelectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            RuleSelectionErrorKind::NotFound => write!(
                formatter,
                "requested rule {} not found in rules",
                self.rule_id
            ),
            RuleSelectionErrorKind::Limit { maximum } => write!(
                formatter,
                "rule selection exceeds the {maximum}-item safety limit"
            ),
            RuleSelectionErrorKind::Allocation => {
                formatter.write_str("could not allocate projected rule selection")
            }
            RuleSelectionErrorKind::SizeLimit => write!(
                formatter,
                "rule selection exceeds the {}-byte safety limit",
                CompiledConfig::MAX_SELECTED_BYTES
            ),
        }
    }
}

impl std::error::Error for RuleSelectionError {}

fn try_copy_selection_string(value: &str) -> Result<String, RuleSelectionError> {
    let mut copied = String::new();
    copied
        .try_reserve_exact(value.len())
        .map_err(|_| RuleSelectionError::allocation())?;
    copied.push_str(value);
    Ok(copied)
}

fn checked_selection_size(current: usize, additional: usize) -> Result<usize, RuleSelectionError> {
    current
        .checked_add(additional)
        .filter(|size| *size <= CompiledConfig::MAX_SELECTED_BYTES)
        .ok_or_else(RuleSelectionError::size_limit)
}

fn add_rule_size(current: usize, rule: &CompiledRule) -> Result<usize, RuleSelectionError> {
    let mut size = checked_selection_size(current, rule.id.len())?;
    size = checked_selection_size(size, rule.description.len())?;
    for value in rule
        .path
        .iter()
        .chain(rule.regex.iter())
        .chain(rule.keywords.iter())
        .chain(rule.tags.iter())
        .chain(rule.required.iter().map(|required| &required.id))
    {
        size = checked_selection_size(size, value.len())?;
    }
    if rule.native_byte_matcher.is_some() {
        size = checked_selection_size(size, "bytes-v1".len())?;
    }
    if let Some(predicate) = &rule.native_predicate {
        size = checked_selection_size(size, predicate.retained_bytes())?;
    }
    if let Some(keywords) = &rule.native_keywords {
        for keyword in keywords {
            size = checked_selection_size(size, keyword.retained_bytes())?;
        }
    }
    for allowlist in &rule.allowlists {
        size = add_allowlist_size(size, allowlist)?;
    }
    Ok(size)
}

fn add_allowlist_size(
    current: usize,
    allowlist: &CompiledAllowlist,
) -> Result<usize, RuleSelectionError> {
    let mut size = checked_selection_size(current, allowlist.description.len())?;
    for value in allowlist
        .commits
        .iter()
        .chain(allowlist.paths.iter())
        .chain(allowlist.regexes.iter())
        .chain(allowlist.stop_words.iter())
    {
        size = checked_selection_size(size, value.len())?;
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::CompiledAllowlist;
    use crate::config::ConfigLoader;

    fn allowlist(specification: &str) -> CompiledAllowlist {
        let config = ConfigLoader::new()
            .load_toml(&format!(
                "[[rules]]\nid = \"probe\"\nregex = \".+\"\n\n[[allowlists]]\n{specification}\n"
            ))
            .unwrap();
        config.allowlists.into_iter().next().unwrap()
    }

    #[test]
    fn stopword_presence_handles_ascii_overlaps_and_empty_input() {
        let compiled = allowlist(r#"stopwords = ["he", "she", "FaKe"]"#);
        for (input, expected) in [
            (b"she".as_slice(), true),
            (b"SHE".as_slice(), true),
            (b"prefix FAKE suffix".as_slice(), true),
            (b"real".as_slice(), false),
            (b"".as_slice(), false),
        ] {
            assert_eq!(compiled.contains_stop_word(input), expected, "{input:?}");
        }

        let overlapping = allowlist(r#"stopwords = ["a", "aa", "aaa", "aaaa"]"#);
        assert!(overlapping.contains_stop_word(b"aaaaaaaaaaaaaaaa"));
        assert!(!overlapping.contains_stop_word(b"bbbbbbbbbbbbbbbb"));
    }

    #[test]
    fn absent_and_empty_stopword_matchers_never_match() {
        for specification in [r"paths = ['never']", r#"stopwords = [""]"#] {
            let compiled = allowlist(specification);
            assert!(compiled.stopword_matcher.is_none());
            for input in [
                b"".as_slice(),
                b"nonempty".as_slice(),
                b"\xff\x80".as_slice(),
            ] {
                assert!(!compiled.contains_stop_word(input), "{input:?}");
            }
        }
    }

    #[test]
    fn stopword_presence_uses_go_simple_lowercase_without_normalization() {
        let compiled = allowlist(r#"stopwords = ["IX", "ÉCOLE"]"#);
        for (input, expected) in [
            ("İX", true),
            ("ix", true),
            ("ÉCOLE", true),
            ("école", true),
            ("i\u{307}x", false),
            ("E\u{301}COLE", false),
            ("other", false),
        ] {
            assert_eq!(
                compiled.contains_stop_word(input.as_bytes()),
                expected,
                "{input:?}"
            );
        }
    }

    #[test]
    fn stopword_presence_preserves_each_invalid_byte_as_one_rune_error() {
        let compiled = allowlist(r#"stopwords = ["��"]"#);
        for (input, expected) in [
            (b"\xff\x80".as_slice(), true),
            (b"\xe2\x82".as_slice(), true),
            (b"\xff".as_slice(), false),
            ("�".as_bytes(), false),
            ("é".as_bytes(), false),
            (b"".as_slice(), false),
        ] {
            assert_eq!(compiled.contains_stop_word(input), expected, "{input:?}");
        }
    }
}
