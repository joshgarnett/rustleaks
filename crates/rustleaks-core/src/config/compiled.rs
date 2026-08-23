use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use aho_corasick::AhoCorasick;

use crate::go_unicode::lowercase_bytes as go_lowercase_bytes;
use crate::regex::GoRegex;

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

    pub(crate) fn regex_allowed(&self, target: &[u8]) -> bool {
        !target.is_empty()
            && self
                .regex_matcher
                .as_ref()
                .is_some_and(|matcher| matcher.is_match(target))
    }

    /// Returns the pinned trie's first matched lowercase input substring.
    ///
    /// The upstream walk selects the earliest ending match and, at a shared
    /// end position, the direct (longest) terminal before suffix links.
    pub(crate) fn matched_stop_word(&self, secret: &[u8]) -> Option<Vec<u8>> {
        if secret.is_empty() {
            return None;
        }
        let normalized = go_lowercase_bytes(secret);
        let matcher = self.stopword_matcher.as_ref()?;
        let selected = matcher
            .find_overlapping_iter(&normalized)
            .min_by(|left, right| {
                left.end()
                    .cmp(&right.end())
                    .then_with(|| right.len().cmp(&left.len()))
            })?;
        normalized
            .get(selected.start()..selected.end())
            .map(<[u8]>::to_vec)
    }

    pub(crate) fn contains_stop_word(&self, secret: &[u8]) -> bool {
        self.matched_stop_word(secret).is_some()
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
/// Full Go-regexp syntax certification remains the separate `GoRegex` gate.
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
    pub(crate) keywords: Vec<String>,
    pub(crate) tags: Vec<String>,
    pub(crate) allowlists: Vec<CompiledAllowlist>,
    pub(crate) required: Vec<RequiredRuleSpec>,
    pub(crate) skip_report: bool,
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

    /// Returns the configured minimum entropy.
    #[must_use]
    pub fn entropy(&self) -> f64 {
        self.entropy
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
    /// Required-rule references resolve only within the selected set, matching
    /// the upstream CLI's map replacement behavior.
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
        self.validate_selection(&selected_ids)?;
        let mut rules = BTreeMap::new();
        let mut keywords = BTreeSet::new();
        for id in &selected_ids {
            let Some(rule) = self.rules.get(id) else {
                return Err(RuleSelectionError::not_found(try_copy_selection_string(
                    id,
                )?));
            };
            let rule = rule.clone();
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

    fn validate_selection(&self, selected_ids: &[String]) -> Result<(), RuleSelectionError> {
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
    /// This deliberately tests only path expressions. The pinned file walker
    /// uses this as an I/O pruning optimization before commit, content, and
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
