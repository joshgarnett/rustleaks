//! Shared generators and checks for the built-in rule file, CLI matrix, dense,
//! Git shape and filter workload groups.
//!
//! Every helper builds synthetic input or checks a property of that input. None
//! of them runs the scanner, so expectations built from them stay independent
//! of the code under measurement.

use std::error::Error;

use rustleaks_core::config::CompiledConfig;
use rustleaks_core::native::{
    CONNECTION_RULES_V1, EXTRA_RULES_V1, NativePolicy, PROVIDER_RULES_V1,
};

use super::source_scale_workloads::github_token;

pub(super) type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// The Rustleaks rule files, in the order the built-in rules load them.
pub(super) const RULE_FILES: [(&str, &str); 3] = [
    ("rustleaks-extra-v1", EXTRA_RULES_V1),
    ("rustleaks-providers-v1", PROVIDER_RULES_V1),
    ("rustleaks-connections-v1", CONNECTION_RULES_V1),
];

/// Short lowercase words. The keyword census below rejects any input built
/// from them that contains a keyword of the selected configuration.
const WORDS: &[&str] = &[
    "river", "stone", "garden", "yellow", "window", "morning", "simple", "number", "orange",
    "bridge", "silver", "forest", "little", "quiet", "summer", "winter", "meadow", "candle",
    "pillow", "ladder", "mirror", "button", "pebble", "harbor", "lantern", "cotton", "copper",
    "marble", "thunder", "shadow", "rabbit", "turtle", "maple", "willow", "cedar", "birch",
    "clover", "tulip", "lemon", "mango", "peach", "plum", "olive", "walnut", "pepper", "bread",
    "apple", "grape", "melon", "carrot", "onion", "tomato", "radish", "wheat", "bean", "lentil",
];

/// A deterministic linear congruential generator for synthetic text.
pub(super) struct Lcg(u64);

impl Lcg {
    pub(super) const fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(super) fn next(&mut self, bound: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(self.0 >> 33).unwrap_or(0) % bound
    }

    pub(super) fn string(&mut self, alphabet: &[u8], length: usize) -> Vec<u8> {
        (0..length)
            .map(|_| alphabet[self.next(alphabet.len())])
            .collect()
    }
}

/// One line of 4 to 9 filler words, ending in a newline. No word is longer than
/// 7 bytes, so no run of letters can look like an encoded value.
pub(super) fn prose_line(rng: &mut Lcg) -> Vec<u8> {
    let count = 4 + rng.next(6);
    let mut line = Vec::with_capacity(count * 8);
    for index in 0..count {
        if index > 0 {
            line.push(b' ');
        }
        line.extend_from_slice(WORDS[rng.next(WORDS.len())].as_bytes());
    }
    line.push(b'\n');
    line
}

/// One filler line of exactly `length` bytes including its newline.
pub(super) fn prose_line_of(rng: &mut Lcg, length: usize) -> Vec<u8> {
    let mut line = Vec::with_capacity(length);
    while line.len() + 1 < length {
        if !line.is_empty() {
            line.push(b' ');
        }
        line.extend_from_slice(WORDS[rng.next(WORDS.len())].as_bytes());
    }
    line.truncate(length - 1);
    while line.last() == Some(&b' ') {
        line.pop();
    }
    line.resize(length - 1, b' ');
    line.push(b'\n');
    line
}

/// Fails when any keyword of `config` occurs in `filler`, ignoring ASCII case
/// as keyword admission does. Plants are checked separately by the caller.
pub(super) fn keyword_census(config: &CompiledConfig, filler: &[u8]) -> Result<()> {
    let lower = filler.to_ascii_lowercase();
    for keyword in config.keywords() {
        let keyword = keyword.to_ascii_lowercase();
        if !keyword.is_empty()
            && lower
                .windows(keyword.len())
                .any(|window| window == keyword.as_bytes())
        {
            return Err(format!("synthetic filler contains the keyword {keyword:?}").into());
        }
    }
    Ok(())
}

/// Shannon entropy as the engine reports it, summed in ascending symbol order.
/// The Go `shannonEntropy` iterates a map, so that order is the canonical
/// choice among Go's admissible results.
/// Every planted secret is ASCII, which makes bytes and runes equivalent.
pub(super) fn go_entropy(secret: &[u8]) -> Result<f64> {
    if !secret.is_ascii() {
        return Err("planted secret must be ASCII".into());
    }
    if secret.is_empty() {
        return Ok(0.0);
    }
    let mut counts = [0_u32; 128];
    for byte in secret {
        counts[usize::from(*byte)] += 1;
    }
    #[allow(clippy::cast_precision_loss)] // Secret lengths are far below 2^52.
    let inverse_length = 1.0 / secret.len() as f64;
    Ok(counts
        .iter()
        .filter(|count| **count > 0)
        .fold(0.0, |entropy, count| {
            let frequency = f64::from(*count) * inverse_length;
            entropy - frequency * frequency.log2()
        }))
}

/// A GitHub classic token from the shared generator, checked against the
/// `github-pat` entropy threshold with a wide margin.
pub(super) fn checked_github_token(index: usize) -> Result<Vec<u8>> {
    let token = github_token(index);
    if go_entropy(&token)? < 3.5 {
        return Err("synthetic GitHub token has too little entropy".into());
    }
    Ok(token)
}

/// A database URI whose password is planted for the connection rule file rule
/// `rustleaks.connection-string.password.database-uri`. The host is neither an
/// `example` host nor `example.invalid`, so the rule's allowlists do not apply.
pub(super) fn database_uri(index: usize) -> (Vec<u8>, Vec<u8>) {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = Lcg::new(0x7572_6900 ^ index as u64);
    let password = rng.string(ALPHABET, 24);
    let mut uri = b"postgres://svc:".to_vec();
    uri.extend_from_slice(&password);
    uri.extend_from_slice(format!("@db{index:04}.internal:5432/app").as_bytes());
    (uri, password)
}

/// Rule ID of the connection rule file rule that matches [`database_uri`].
pub(super) const DATABASE_URI_RULE: &str = "rustleaks.connection-string.password.database-uri";

/// Counts `[[rules]]` tables in packaged TOML, an input-side rule count.
pub(super) fn declared_rules(toml: &str) -> usize {
    toml.lines()
        .filter(|line| line.trim() == "[[rules]]")
        .count()
}

/// The named Rustleaks rule files with their text, the rule count that text
/// declares, and a byte identity for fingerprints. Nothing here compiles a rule.
pub(super) struct RuleFileSelection {
    pub(super) rule_files: Vec<(&'static str, &'static str)>,
    pub(super) rules: usize,
    pub(super) identity: Vec<u8>,
}

pub(super) fn rule_file_selection(ids: &[&str]) -> Result<RuleFileSelection> {
    let mut rule_files = Vec::with_capacity(ids.len());
    let mut rules = crate::GITLEAKS_RULES;
    let mut identity = b"default".to_vec();
    for id in ids {
        let (name, contents) = *RULE_FILES
            .iter()
            .find(|(name, _)| name == id)
            .ok_or("unknown native pack")?;
        rule_files.push((name, contents));
        rules += declared_rules(contents);
        identity.push(0);
        identity.extend_from_slice(name.as_bytes());
        identity.push(0);
        identity.extend_from_slice(contents.as_bytes());
    }
    Ok(RuleFileSelection {
        rule_files,
        rules,
        identity,
    })
}

/// Compiles the `gitleaks.toml` default rules plus the selected rule files
/// through the native policy, the way `ConfigLoader` builds the built-in rules.
pub(super) fn compile_rule_files(selection: &RuleFileSelection) -> Result<CompiledConfig> {
    let mut policy = NativePolicy::builder();
    for (id, contents) in &selection.rule_files {
        policy = policy.with_pack(id, contents)?;
    }
    Ok(policy.compile()?.0)
}

/// Fails unless the compiled rule count equals the count the rule file text
/// declares.
pub(super) fn check_rule_count(
    config: &CompiledConfig,
    selection: &RuleFileSelection,
) -> Result<()> {
    if config.rules().len() != selection.rules {
        return Err(format!(
            "native policy compiled {} rules, pack text declares {}",
            config.rules().len(),
            selection.rules
        )
        .into());
    }
    Ok(())
}

/// Selects, compiles and checks the named rule files in one step.
pub(super) fn rule_file_config(ids: &[&str]) -> Result<(CompiledConfig, usize, Vec<u8>)> {
    let selection = rule_file_selection(ids)?;
    let config = compile_rule_files(&selection)?;
    check_rule_count(&config, &selection)?;
    Ok((config, selection.rules, selection.identity))
}

/// Writes a POSIX ustar archive with one regular file per entry.
pub(super) fn tar(entries: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let mut archive = Vec::new();
    for (name, data) in entries {
        if name.len() >= 100 || name.is_empty() {
            return Err("synthetic tar member name must be 1 to 99 bytes".into());
        }
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        archive.extend_from_slice(&header);
        archive.extend_from_slice(data);
        archive.resize(archive.len().div_ceil(512) * 512, 0);
    }
    archive.resize(archive.len() + 1024, 0);
    Ok(archive)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generators_are_deterministic_and_bounded() {
        let mut first = Lcg::new(7);
        let mut second = Lcg::new(7);
        assert_eq!(prose_line(&mut first), prose_line(&mut second));
        for length in [2, 9, 41, 64, 200] {
            let line = prose_line_of(&mut first, length);
            assert_eq!(line.len(), length);
            assert_eq!(line.last(), Some(&b'\n'));
        }
        let (uri, password) = database_uri(3);
        assert!(uri.windows(password.len()).any(|window| window == password));
        assert_eq!(declared_rules("[[rules]]\nid = 'a'\n[[rules]]\n"), 2);
    }

    #[test]
    fn tar_headers_have_valid_checksums_and_ustar_magic() {
        let archive = tar(&[("a.txt", b"hello\n")]).unwrap();
        assert_eq!(archive.len(), 512 + 512 + 1024);
        assert_eq!(&archive[257..262], b"ustar");
        let mut header = archive[..512].to_vec();
        let stored = std::str::from_utf8(&header[148..154]).unwrap().to_owned();
        header[148..156].copy_from_slice(b"        ");
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        assert_eq!(u32::from_str_radix(&stored, 8).unwrap(), sum);
        assert_eq!(&archive[512..518], b"hello\n");
    }

    #[test]
    fn entropy_matches_known_values() {
        assert!((go_entropy(b"aaaa").unwrap() - 0.0).abs() < 1e-12);
        assert!((go_entropy(b"abcd").unwrap() - 2.0).abs() < 1e-12);
    }
}
