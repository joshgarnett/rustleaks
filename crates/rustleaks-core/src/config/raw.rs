use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Raw Rustleaks TOML, including backward-compatible upstream fields.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RawConfig {
    /// Human-readable configuration title.
    pub title: String,
    /// Human-readable configuration description.
    pub description: String,
    /// Optional base configuration directive.
    pub extend: ConfigExtension,
    /// Rules in source order, including duplicate IDs.
    pub rules: Vec<RuleSpec>,
    /// Deprecated singular global allowlist spelling.
    #[serde(rename = "allowlist")]
    pub allowlist: Option<RawGlobalAllowlist>,
    /// Preferred plural global allowlist entries.
    pub allowlists: Vec<RawGlobalAllowlist>,
    /// Advisory minimum upstream version used for backward compatibility.
    #[serde(alias = "minversion")]
    pub min_version: String,
}

/// Raw extension directives.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ConfigExtension {
    /// Resolver-specific path to a base configuration.
    pub path: String,
    /// Reserved URL source. The pinned implementation retains but does not load it.
    pub url: String,
    /// Whether to extend the embedded default configuration.
    #[serde(alias = "usedefault")]
    pub use_default: bool,
    /// IDs to remove from the base configuration.
    #[serde(alias = "disabledrules")]
    pub disabled_rules: Vec<String>,
}

/// A constructible rule specification. Pattern values remain source strings.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RuleSpec {
    /// Stable rule identifier.
    pub id: String,
    /// Human-readable rule description.
    pub description: String,
    /// Go-regexp-compatible path pattern source.
    pub path: String,
    /// Go-regexp-compatible content pattern source.
    pub regex: String,
    /// Capture group used as the secret.
    #[serde(alias = "secretgroup")]
    pub secret_group: i64,
    /// Minimum Shannon entropy threshold.
    pub entropy: f64,
    /// Pre-filter terms, normalized to lowercase during compilation.
    pub keywords: Vec<String>,
    /// Reporting metadata tags.
    pub tags: Vec<String>,
    /// Deprecated singular rule allowlist spelling.
    #[serde(rename = "allowlist")]
    pub allowlist: Option<RawAllowlist>,
    /// Preferred plural rule allowlist entries.
    pub allowlists: Vec<RawAllowlist>,
    /// Composite-rule dependencies.
    pub required: Vec<RequiredRuleSpec>,
    /// Whether findings from this rule are omitted from reports.
    #[serde(alias = "skipreport")]
    pub skip_report: bool,
}

/// A dependency from a composite rule to another rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RequiredRuleSpec {
    /// ID of the required rule.
    pub id: String,
    /// Optional maximum line distance.
    #[serde(alias = "withinlines")]
    pub within_lines: Option<i64>,
    /// Optional maximum column distance.
    #[serde(alias = "withincolumns")]
    pub within_columns: Option<i64>,
}

/// A raw allowlist shared by rule-local and global allowlist entries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AllowlistSpec {
    /// Human-readable allowlist description.
    pub description: String,
    /// How populated criteria are combined.
    pub condition: Condition,
    /// Case-insensitive commit identifiers.
    pub commits: Vec<String>,
    /// Path pattern sources.
    pub paths: Vec<String>,
    /// Finding component targeted by `regexes`.
    #[serde(alias = "regextarget")]
    pub regex_target: RegexTarget,
    /// Content pattern sources.
    pub regexes: Vec<String>,
    /// Case-insensitive secret substrings.
    #[serde(alias = "stopwords")]
    pub stop_words: Vec<String>,
}

/// Rule-local raw allowlist.
pub type RawAllowlist = AllowlistSpec;

/// Global raw allowlist, optionally attached to selected rule IDs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RawGlobalAllowlist {
    /// Rule IDs that receive this allowlist; empty means globally applied.
    #[serde(alias = "targetrules")]
    pub target_rules: Vec<String>,
    /// Shared allowlist criteria.
    #[serde(flatten)]
    pub allowlist: AllowlistSpec,
}

/// Allowlist boolean combination condition.
///
/// `Unknown` is retained at the raw boundary so parsing remains permissive and
/// compilation can return a contextual, non-panicking validation error.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Condition {
    /// Every populated criterion must match.
    And,
    #[default]
    /// Any populated criterion may match.
    Or,
    /// Unrecognized raw value retained for contextual compilation errors.
    Unknown(String),
}

/// Compatibility-facing name used by the public API disposition table.
pub type AllowlistCondition = Condition;

impl Condition {
    pub(crate) fn parse(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "AND" | "&&" => Self::And,
            "" | "OR" | "||" => Self::Or,
            _ => Self::Unknown(value.to_owned()),
        }
    }

    fn source_value(&self) -> &str {
        match self {
            Self::And => "AND",
            Self::Or => "OR",
            Self::Unknown(value) => value,
        }
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.source_value())
    }
}

impl Serialize for Condition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.source_value())
    }
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self::parse(&value))
    }
}

/// Which portion of a finding an allowlist content pattern targets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RegexTarget {
    /// The extracted secret. This is represented by an empty string in Go.
    #[default]
    Secret,
    /// The full rule match.
    Match,
    /// The source line containing the match.
    Line,
    /// Unrecognized raw value retained for contextual compilation errors.
    Unknown(String),
}

impl RegexTarget {
    pub(crate) fn parse(value: &str) -> Self {
        match value {
            "" | "secret" => Self::Secret,
            "match" => Self::Match,
            "line" => Self::Line,
            _ => Self::Unknown(value.to_owned()),
        }
    }

    /// Returns the Go-compatible serialized spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Secret => "",
            Self::Match => "match",
            Self::Line => "line",
            Self::Unknown(value) => value,
        }
    }
}

impl fmt::Display for RegexTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for RegexTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RegexTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self::parse(&value))
    }
}
