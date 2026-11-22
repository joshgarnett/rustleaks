//! Literal-anchored whole-match enumeration for keyword-template expressions.
//!
//! Many expressions start with bounded repetitions of one character class and
//! then a keyword. No literal prefix exists, so an ordinary search makes one
//! lazy-DFA pass over the whole haystack per admitted rule. This module proves
//! at compile time that an expression has that shape, then starts an anchored
//! search only at positions that a recorded keyword occurrence can reach.
//!
//! # Exactness
//!
//! Let `H` be a pure-ASCII haystack, and let the expression be the
//! concatenation `P L T`, where:
//!
//! - `P` is one or more repetitions, each with minimum 0 and a finite maximum,
//!   whose classes have the same set `C` of ASCII members. `N` is the sum of
//!   the maxima. Over ASCII input `P` matches exactly the strings of `C` of
//!   length at most `N`, whichever repetitions are greedy or lazy.
//! - `L` is a finite set of non-empty literals. Each literal position matches
//!   ASCII bytes with a single lowercase form, or a small enumerated set.
//! - `T` is arbitrary.
//!
//! `P` and `L` contain no look-around and no capture. Non-ASCII class members,
//! such as the folds U+212A of `k` and U+017F of `s`, are unreachable on `H`.
//!
//! An *occurrence* is a start offset `k` where the ASCII-lowercased haystack
//! has a member of `L`. Every member of `L` is required to be a keyword, and
//! ASCII lowercasing preserves offsets, so the keyword pass reports every
//! occurrence. A match with literal position `k` makes `k` an occurrence
//! because each matched literal byte lowercases to the enumerated byte.
//!
//! Fix a search position `p`. For an occurrence `k >= p` define `w(k)` as the
//! least `s` in `p..=k` with `H[s..k]` in `C*` and `k - s <= N`; this is what
//! the walk-back computes.
//!
//! 1. *Extension.* If a match starts at `s' >= p` and places its literal at
//!    `k`, then a match also starts at `w(k) <= s'`. `P` can consume
//!    `H[w(k)..k]`, and `L T` proceed identically from `k`. Look-around in `T`
//!    is evaluated on the unsliced haystack, so no context changes.
//! 2. *Monotonicity.* If `k1 < k2` then `w(k1) <= w(k2)`. If `w(k2) >= k1`
//!    this is immediate from `w(k1) <= k1`. Otherwise `H[w(k2)..k1]` is a
//!    prefix of a `C*` string, is shorter than `N`, and starts at or after
//!    `p`, so `w(k2)` is a candidate for `w(k1)`.
//! 3. *Leftmost start.* Let `m` be the least match start at or after `p`, with
//!    literal at `k*`. By (1) a match starts at `w(k*) <= m`, and `w(k*) >= p`,
//!    so `w(k*) = m` by minimality. Trying occurrences in ascending order
//!    tries nondecreasing starts by (2). Every start below `m` fails because
//!    no match starts there, and the attempt at `m` succeeds. A duplicate
//!    start is skipped only after that same start failed, and an anchored
//!    result depends only on its start, the span end and the haystack.
//! 4. *Same match.* An anchored search at `m` returns the highest-priority
//!    match starting at `m`. The unanchored search returns the same match:
//!    leftmost-first selects the least start, then priority within it.
//!    Unanchored threads from earlier starts cannot match, and those from
//!    later starts have lower priority.
//! 5. *Enumeration.* A match contains a non-empty literal, so it is non-empty
//!    and the empty-match progression never applies. The next position is the
//!    match end `e`. A later match has its literal at or after its start,
//!    which is at or after `e`, so occurrences below `e` are safely discarded.
//!
//! 6. *Skipped occurrences.* On an ASCII haystack, each choice may record a
//!    byte set `B` and a
//!    distance `D` such that every match of `T` has a byte of `B` within its
//!    first `D + 1` bytes. A match with its literal at `k` then has a byte of
//!    `B` in `H[k + l_min .. k + l_max + D + 1]`, where `l_min` and `l_max`
//!    are the shortest and longest literal lengths. An occurrence whose window
//!    has no such byte is the literal of no match. Dropping it leaves (3) and
//!    (5) unchanged: the leftmost match's own occurrence is kept, and the
//!    remaining attempts still run in nondecreasing start order.
//!
//! The argument never uses the greediness of `P`.
//!
//! # Other haystacks
//!
//! The argument holds unchanged on a valid UTF-8 haystack without U+017F and
//! U+212A when `P` and `L` match no other non-ASCII character. Those two are
//! the only non-ASCII characters that case-insensitive matching pairs with an
//! ASCII letter, so every match of `P L` is then ASCII and every byte the
//! walk-back and occurrence search read means what it does in ASCII. The
//! shape records whether `P` and `L` qualify. The caller then promises the
//! rest; the keyword pass checks it (`Lowered::same_offsets`). Priority only selects a path
//! within one start, and the same expression makes that choice. Greedy, lazy
//! and mixed leading repetitions are therefore all exact.
//!
//! # Cost
//!
//! An unbounded `T` can keep an attempt alive to the end of the input, so
//! occurrence density alone does not bound total attempt work. Before each
//! attempt the budget charges an upper bound on how far that attempt can scan.
//! The unbounded node consumes only its own bytes, so it stops at the first
//! other byte. When everything after it is bounded, the charge adds that bound
//! instead of scanning on. Enumeration abandons the anchored path when the
//! charges exceed the haystack length. Occurrences dropped by (6) are not
//! charged. Falling back affects only cost; both paths return the same matches.
//!
//! Analysis itself runs for every compiled expression, including allowlist
//! and path expressions. It keeps at most [`MAX_CANDIDATES`] choices, spends
//! at most [`MAX_ENUMERATION_STEPS`] on literal languages, and walks the
//! remainder after the literal node once for all choices. Stopping early only
//! drops longer choices; every retained choice remains exact.

use regex_automata::{Anchored, Input};
use regex_syntax::hir::{Class, Hir, HirKind};

use super::{ATTEMPT_COST_FLOOR, ByteSpan, GoRegex, NormalizedHaystack};

/// Maximum distinct literals considered for one expression.
const MAX_LITERALS: usize = 64;
/// Maximum bytes in one enumerated literal.
const MAX_LITERAL_LEN: usize = 64;
/// Recursion bound for walking literal nodes and tail byte sets.
const MAX_WALK_DEPTH: u32 = 32;
/// Maximum total leading characters accepted by the analysis.
const MAX_LEADING_CHARS: usize = 4_096;
/// Maximum literal-node choices retained for one expression.
///
/// The default rules need at most 12. Each choice retains at most
/// [`MAX_LITERALS`] literals of at most [`MAX_LITERAL_LEN`] bytes.
const MAX_CANDIDATES: usize = 32;
/// Work units for enumerating literal languages in one expression.
///
/// Each visited node costs one unit and each literal a cross product builds
/// costs one more. The default rules spend at most 168. The largest literal
/// set, 64 case-insensitive literals of 64 bytes, spends about 8,400.
const MAX_ENUMERATION_STEPS: usize = 1 << 14;
/// Membership by byte value. Entries for non-ASCII bytes are always false.
type ByteSet = [bool; 256];

/// Compile-time evidence that an expression begins `P L T`.
#[derive(Debug)]
pub(crate) struct LiteralAnchorShape {
    class: ByteSet,
    max_leading: usize,
    candidates: Vec<LiteralCandidate>,
    /// `P` and the longest `L` match no non-ASCII character except U+017F
    /// and U+212A, so the shape also serves the haystacks described above.
    non_ascii_haystacks: bool,
}

/// One choice of where the literal node ends, in ascending literal length.
#[derive(Debug)]
pub(crate) struct LiteralCandidate {
    literals: Vec<Box<[u8]>>,
    min_literal_len: usize,
    max_literal_len: usize,
    /// The remainder's bound on an ASCII haystack.
    tail: TailBound,
    /// The remainder's bound on any other haystack the shape serves.
    tail_any: TailBound,
    /// A byte that every match of the remainder has early on an ASCII
    /// haystack, if one is known.
    required: Option<RequiredByte>,
}

/// Every match of a remainder has a byte of `set` within its first
/// `within + 1` bytes.
#[derive(Debug)]
struct RequiredByte {
    set: Box<ByteSet>,
    within: usize,
}

#[derive(Debug)]
enum TailBound {
    /// The remainder after the literal consumes at most this many bytes.
    Finite(usize),
    /// The remainder has an unbounded node after `bounded_prefix` bytes. That
    /// node consumes only `run` bytes. With `after`, everything after it
    /// consumes at most that many bytes; without it, everything from the node
    /// onward consumes only `run` bytes.
    Unbounded {
        bounded_prefix: usize,
        run: Box<ByteSet>,
        after: Option<usize>,
    },
}

impl LiteralAnchorShape {
    /// Returns the shape of `hir`, or `None` if it is not eligible.
    pub(crate) fn analyze(hir: &Hir) -> Option<Self> {
        let HirKind::Concat(children) = hir.kind() else {
            return None;
        };
        let mut class = None;
        let mut max_leading = 0_usize;
        let mut leading = 0;
        for child in children {
            let HirKind::Repetition(repetition) = child.kind() else {
                break;
            };
            let (0, Some(maximum)) = (repetition.min, repetition.max) else {
                break;
            };
            let Some(members) = single_position_members(&repetition.sub) else {
                break;
            };
            // Only the ASCII projection is compared. A folded and an unfolded
            // spelling of one class differ only in unreachable members.
            if class.is_some_and(|current: ByteSet| current != members) {
                break;
            }
            class = Some(members);
            max_leading = max_leading.checked_add(usize::try_from(maximum).ok()?)?;
            leading += 1;
        }
        let class = class?;
        if max_leading > MAX_LEADING_CHARS {
            return None;
        }

        let rest = &children[leading..];
        let mut steps = MAX_ENUMERATION_STEPS;
        let mut current = vec![Vec::new()];
        // Each choice records the child where its literal node ends.
        let mut choices = Vec::new();
        for (index, child) in rest.iter().enumerate() {
            let Some(language) = literal_language(child, 0, &mut steps) else {
                break;
            };
            // A child that matches only the empty string leaves every literal
            // unchanged, so its choice would repeat the previous one.
            if only_empty(&language) {
                continue;
            }
            let Some(product) = cross_product(&current, &language, &mut steps) else {
                break;
            };
            current = product;
            if current.iter().all(|literal| !literal.is_empty()) {
                choices.push((index, current.clone()));
                if choices.len() == MAX_CANDIDATES {
                    break;
                }
            }
        }
        let &(last, _) = choices.last()?;
        // Every child through `last` has a finite language, so all choices
        // share the first unbounded node. One walk after the longest choice
        // serves every choice; a shorter one adds the children in between.
        let shared = TailBound::new(&rest[last + 1..], Haystack::Ascii);
        let shared_any = TailBound::new(&rest[last + 1..], Haystack::Any);
        let mut between = (0_usize, 0_usize);
        let mut end = last;
        let mut candidates = Vec::with_capacity(choices.len());
        for (index, literals) in choices.into_iter().rev() {
            between = rest[index + 1..=end]
                .iter()
                .fold(between, |(ascii, any), child| {
                    (
                        ascii.saturating_add(Haystack::Ascii.max_len(child).unwrap_or(usize::MAX)),
                        any.saturating_add(Haystack::Any.max_len(child).unwrap_or(usize::MAX)),
                    )
                });
            end = index;
            candidates.push(LiteralCandidate::new(
                &literals,
                [shared.after(between.0), shared_any.after(between.1)],
                RequiredByte::new(&rest[index + 1..]),
            ));
        }
        candidates.reverse();
        let non_ascii_haystacks = children[..leading + last + 1]
            .iter()
            .all(|child| matches_only_ascii_or_folds(child, 0));
        Some(Self {
            class,
            max_leading,
            candidates,
            non_ascii_haystacks,
        })
    }

    /// Returns literal-node choices in ascending length.
    pub(crate) fn candidates(&self) -> &[LiteralCandidate] {
        &self.candidates
    }

    /// Returns `N`, the most characters the leading repetitions can consume.
    pub(crate) fn max_leading(&self) -> usize {
        self.max_leading
    }

    /// Returns whether `byte` is an ASCII member of the leading class.
    #[cfg(test)]
    pub(crate) fn leading_contains(&self, byte: u8) -> bool {
        self.class[usize::from(byte)]
    }
}

impl LiteralCandidate {
    fn new(
        literals: &[Vec<u8>],
        [tail, tail_any]: [TailBound; 2],
        required: Option<RequiredByte>,
    ) -> Self {
        Self {
            literals: literals
                .iter()
                .map(|literal| literal.as_slice().into())
                .collect(),
            min_literal_len: literals.iter().map(Vec::len).min().unwrap_or(0),
            max_literal_len: literals.iter().map(Vec::len).max().unwrap_or(0),
            tail,
            tail_any,
            required,
        }
    }

    /// Returns whether a match can have its literal at `occurrence` (lemma 6).
    ///
    /// The bytes are an ASCII haystack. On other haystacks the remainder can
    /// match multi-byte characters, so no occurrence is ruled out there.
    fn can_place(&self, bytes: &[u8], occurrence: usize) -> bool {
        let Some(required) = &self.required else {
            return true;
        };
        let start = occurrence.saturating_add(self.min_literal_len);
        let end = occurrence
            .saturating_add(self.max_literal_len)
            .saturating_add(required.within)
            .saturating_add(1)
            .min(bytes.len());
        bytes
            .get(start..end)
            .is_some_and(|window| window.iter().any(|byte| required.set[usize::from(*byte)]))
    }

    /// Returns the sorted, deduplicated ASCII-lowercased literal set.
    pub(crate) fn literals(&self) -> &[Box<[u8]>] {
        &self.literals
    }
}

/// Which haystacks a length or byte bound must hold for.
#[derive(Clone, Copy)]
enum Haystack {
    Ascii,
    /// Any UTF-8 haystack, where a character can take up to four bytes.
    Any,
}

impl Haystack {
    fn max_len(self, hir: &Hir) -> Option<usize> {
        match self {
            Self::Ascii => ascii_max_len(hir, 0),
            Self::Any => hir.properties().maximum_len(),
        }
    }
}

impl TailBound {
    fn new(tail: &[Hir], haystack: Haystack) -> Self {
        let mut bounded_prefix = 0_usize;
        for (index, node) in tail.iter().enumerate() {
            let Some(maximum) = haystack.max_len(node) else {
                let mut run = Box::new([false; 256]);
                if matches!(haystack, Haystack::Any) {
                    // Any non-ASCII byte may belong to a character it consumes.
                    run[0x80..].fill(true);
                }
                // When everything after the unbounded node is bounded, the
                // node ends at the first byte it cannot consume and the rest
                // adds at most its maximum length.
                let after = tail[index + 1..].iter().try_fold(0_usize, |sum, later| {
                    sum.checked_add(haystack.max_len(later)?)
                });
                let consumed = if after.is_some() {
                    &tail[index..=index]
                } else {
                    &tail[index..]
                };
                for later in consumed {
                    collect_consumed_bytes(later, &mut run, 0);
                }
                return Self::Unbounded {
                    bounded_prefix,
                    run,
                    after,
                };
            };
            bounded_prefix = bounded_prefix.saturating_add(maximum);
        }
        Self::Finite(bounded_prefix)
    }

    /// Returns this bound for the same remainder after `bounded` more bytes.
    fn after(&self, bounded: usize) -> Self {
        match self {
            Self::Finite(maximum) => Self::Finite(maximum.saturating_add(bounded)),
            Self::Unbounded {
                bounded_prefix,
                run,
                after,
            } => Self::Unbounded {
                bounded_prefix: bounded_prefix.saturating_add(bounded),
                run: run.clone(),
                after: *after,
            },
        }
    }
}

impl RequiredByte {
    /// Finds the first node of `tail` that every match enters with a known
    /// byte, and how many bytes the nodes before it can consume.
    fn new(tail: &[Hir]) -> Option<Self> {
        let mut within = 0_usize;
        for node in tail {
            if node
                .properties()
                .minimum_len()
                .is_some_and(|minimum| minimum > 0)
                && let Some(set) = first_bytes(node, 0)
            {
                return Some(Self {
                    set: Box::new(set),
                    within,
                });
            }
            within = within.checked_add(Haystack::Ascii.max_len(node)?)?;
            if within > MAX_LEADING_CHARS {
                return None;
            }
        }
        None
    }
}

/// Returns the most bytes a match of `hir` can consume in an ASCII haystack,
/// or `None` if that is unbounded or the walk is too deep.
///
/// Anchored search runs only on ASCII haystacks, where every character that
/// can match is one byte. `Properties::maximum_len` counts the longest UTF-8
/// form instead, such as three bytes for the Kelvin sign that `(?i)k` adds.
fn ascii_max_len(hir: &Hir, depth: u32) -> Option<usize> {
    if depth >= MAX_WALK_DEPTH {
        return hir.properties().maximum_len();
    }
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Some(0),
        // A literal with a non-ASCII byte cannot match an ASCII haystack; its
        // byte length is still an upper bound.
        HirKind::Literal(literal) => Some(literal.0.len()),
        HirKind::Class(_) => Some(1),
        HirKind::Repetition(repetition) => {
            let maximum = usize::try_from(repetition.max?).ok()?;
            ascii_max_len(&repetition.sub, depth + 1)?.checked_mul(maximum)
        }
        HirKind::Capture(capture) => ascii_max_len(&capture.sub, depth + 1),
        HirKind::Concat(children) => children.iter().try_fold(0_usize, |sum, child| {
            sum.checked_add(ascii_max_len(child, depth + 1)?)
        }),
        HirKind::Alternation(children) => children.iter().try_fold(0_usize, |most, child| {
            Some(most.max(ascii_max_len(child, depth + 1)?))
        }),
    }
}

/// Returns the ASCII bytes that can start a non-empty match of `hir`, or
/// `None` when the walk is too deep. Non-ASCII bytes are left out: anchored
/// search runs only on ASCII haystacks.
fn first_bytes(hir: &Hir, depth: u32) -> Option<ByteSet> {
    if depth >= MAX_WALK_DEPTH {
        return None;
    }
    let mut set = [false; 256];
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => {}
        HirKind::Literal(literal) => {
            if let Some(&first) = literal.0.first()
                && first.is_ascii()
            {
                set[usize::from(first)] = true;
            }
        }
        HirKind::Class(class) => set = class_members(class),
        HirKind::Repetition(repetition) => {
            if repetition.max != Some(0) {
                set = first_bytes(&repetition.sub, depth + 1)?;
            }
        }
        HirKind::Capture(capture) => set = first_bytes(&capture.sub, depth + 1)?,
        HirKind::Concat(children) => {
            // A non-empty match starts in the first child that consumes a
            // byte, which can be any child up to the first non-empty one.
            for child in children {
                let child_set = first_bytes(child, depth + 1)?;
                for (slot, member) in set.iter_mut().zip(child_set) {
                    *slot |= member;
                }
                if child
                    .properties()
                    .minimum_len()
                    .is_some_and(|minimum| minimum > 0)
                {
                    break;
                }
            }
        }
        HirKind::Alternation(children) => {
            for child in children {
                let child_set = first_bytes(child, depth + 1)?;
                for (slot, member) in set.iter_mut().zip(child_set) {
                    *slot |= member;
                }
            }
        }
    }
    Some(set)
}

/// Returns whether `hir` can match no non-ASCII character except U+017F and
/// U+212A, which case-insensitive matching adds for `s` and `k`.
fn matches_only_ascii_or_folds(hir: &Hir, depth: u32) -> bool {
    if depth >= MAX_WALK_DEPTH {
        return false;
    }
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => true,
        HirKind::Literal(literal) => literal.0.is_ascii(),
        HirKind::Class(Class::Unicode(class)) => class.iter().all(|range| {
            let (start, end) = (range.start(), range.end());
            end <= '\x7f' || (start == end && matches!(start, '\u{17f}' | '\u{212a}'))
        }),
        HirKind::Class(Class::Bytes(class)) => class.iter().all(|range| range.end() <= 0x7f),
        HirKind::Repetition(repetition) => matches_only_ascii_or_folds(&repetition.sub, depth + 1),
        HirKind::Capture(capture) => matches_only_ascii_or_folds(&capture.sub, depth + 1),
        HirKind::Concat(children) | HirKind::Alternation(children) => children
            .iter()
            .all(|child| matches_only_ascii_or_folds(child, depth + 1)),
    }
}

fn class_members(class: &Class) -> ByteSet {
    let mut set = [false; 256];
    match class {
        Class::Unicode(class) => {
            for range in class.iter() {
                let (low, high) = (u32::from(range.start()), u32::from(range.end()));
                for value in low..=high.min(0x7F) {
                    set[value as usize] = true;
                }
            }
        }
        Class::Bytes(class) => {
            for range in class.iter() {
                for value in range.start()..=range.end().min(0x7F) {
                    set[usize::from(value)] = true;
                }
            }
        }
    }
    set
}

/// Returns the ASCII members of a node that consumes exactly one position.
fn single_position_members(hir: &Hir) -> Option<ByteSet> {
    match hir.kind() {
        HirKind::Class(class) => Some(class_members(class)),
        HirKind::Literal(literal) => match *literal.0 {
            [byte] if byte.is_ascii() => {
                let mut set = [false; 256];
                set[usize::from(byte)] = true;
                Some(set)
            }
            _ => None,
        },
        _ => None,
    }
}

/// Enumerates the ASCII-lowercased finite language of a literal node.
///
/// `None` means the node is not an eligible literal: it has look-around or a
/// capture, is unbounded, has no ASCII member, or exceeds the size or step
/// bounds.
fn literal_language(hir: &Hir, depth: u32, steps: &mut usize) -> Option<Vec<Vec<u8>>> {
    if depth >= MAX_WALK_DEPTH {
        return None;
    }
    spend(steps, 1)?;
    match hir.kind() {
        HirKind::Empty => Some(vec![Vec::new()]),
        HirKind::Literal(literal) => (literal.0.is_ascii() && literal.0.len() <= MAX_LITERAL_LEN)
            .then(|| vec![literal.0.to_ascii_lowercase()]),
        HirKind::Class(class) => {
            let members = class_members(class);
            let mut lowered = (0_u8..=0x7F)
                .filter(|byte| members[usize::from(*byte)])
                .map(|byte| byte.to_ascii_lowercase())
                .collect::<Vec<_>>();
            lowered.sort_unstable();
            lowered.dedup();
            (!lowered.is_empty() && lowered.len() <= MAX_LITERALS)
                .then(|| lowered.into_iter().map(|byte| vec![byte]).collect())
        }
        HirKind::Concat(children) => {
            let mut current = vec![Vec::new()];
            for child in children {
                let language = literal_language(child, depth + 1, steps)?;
                if !only_empty(&language) {
                    current = cross_product(&current, &language, steps)?;
                }
            }
            Some(current)
        }
        HirKind::Alternation(children) => {
            let mut union = Vec::new();
            for child in children {
                union.extend(literal_language(child, depth + 1, steps)?);
                if union.len() > MAX_LITERALS {
                    return None;
                }
            }
            union.sort_unstable();
            union.dedup();
            Some(union)
        }
        HirKind::Repetition(repetition) => {
            let maximum = repetition.max?;
            let unit = literal_language(&repetition.sub, depth + 1, steps)?;
            let mut union = Vec::new();
            let mut power = vec![Vec::new()];
            for count in 0..=maximum {
                if count >= repetition.min {
                    union.extend(power.iter().cloned());
                    if union.len() > MAX_LITERALS {
                        return None;
                    }
                }
                if count < maximum {
                    power = cross_product(&power, &unit, steps)?;
                }
            }
            union.sort_unstable();
            union.dedup();
            Some(union)
        }
        HirKind::Look(_) | HirKind::Capture(_) => None,
    }
}

/// Returns whether a language contains only the empty string.
fn only_empty(language: &[Vec<u8>]) -> bool {
    language.iter().all(Vec::is_empty)
}

/// Charges `units` against the enumeration budget.
fn spend(steps: &mut usize, units: usize) -> Option<()> {
    *steps = steps.checked_sub(units)?;
    Some(())
}

fn cross_product(
    prefixes: &[Vec<u8>],
    suffixes: &[Vec<u8>],
    steps: &mut usize,
) -> Option<Vec<Vec<u8>>> {
    let size = prefixes.len().checked_mul(suffixes.len())?;
    if size > MAX_LITERALS {
        return None;
    }
    spend(steps, size)?;
    let mut product = Vec::with_capacity(size);
    for prefix in prefixes {
        for suffix in suffixes {
            if prefix.len() + suffix.len() > MAX_LITERAL_LEN {
                return None;
            }
            product.push([prefix.as_slice(), suffix.as_slice()].concat());
        }
    }
    product.sort_unstable();
    product.dedup();
    Some(product)
}

/// Adds every ASCII byte `hir` can consume to `set`.
///
/// This is an estimate input only, so reaching the depth bound conservatively
/// admits every byte instead of failing analysis.
fn collect_consumed_bytes(hir: &Hir, set: &mut ByteSet, depth: u32) {
    if depth >= MAX_WALK_DEPTH {
        set[..0x80].fill(true);
        return;
    }
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => {}
        HirKind::Literal(literal) => {
            for byte in literal.0.iter().filter(|byte| byte.is_ascii()) {
                set[usize::from(*byte)] = true;
            }
        }
        HirKind::Class(class) => {
            let members = class_members(class);
            for (slot, member) in set.iter_mut().zip(members) {
                *slot |= member;
            }
        }
        HirKind::Repetition(repetition) => {
            collect_consumed_bytes(&repetition.sub, set, depth + 1);
        }
        HirKind::Capture(capture) => collect_consumed_bytes(&capture.sub, set, depth + 1),
        HirKind::Concat(children) | HirKind::Alternation(children) => {
            for child in children {
                collect_consumed_bytes(child, set, depth + 1);
            }
        }
    }
}

/// Charges upper bounds on anchored-attempt work against the haystack length.
struct AttemptBudget<'a> {
    bytes: &'a [u8],
    run: Option<&'a ByteSet>,
    /// Most bytes consumed after the unbounded node stops.
    after_run: usize,
    /// Distance from an attempt start to where the unbounded node may begin.
    reach_floor: usize,
    /// First byte at or after the latest floor that stops the unbounded node.
    run_end: usize,
    remaining: usize,
}

impl<'a> AttemptBudget<'a> {
    /// Returns `None` when the attempts cost more than a full search.
    fn new(
        shape: &LiteralAnchorShape,
        candidate: &'a LiteralCandidate,
        bytes: &'a [u8],
        ascii: bool,
        attempts: usize,
    ) -> Option<Self> {
        // `P` and `L` match only ASCII on every haystack the shape serves.
        let leading = shape.max_leading + candidate.max_literal_len;
        let tail = if ascii {
            &candidate.tail
        } else {
            &candidate.tail_any
        };
        let (minimum_tail, run, after_run) = match tail {
            TailBound::Finite(maximum) => (*maximum, None, 0),
            TailBound::Unbounded {
                bounded_prefix,
                run,
                after,
            } => (*bounded_prefix, Some(run.as_ref()), after.unwrap_or(0)),
        };
        let reach_floor = leading.saturating_add(minimum_tail);
        let attempt_floor = ATTEMPT_COST_FLOOR.saturating_add(reach_floor);
        if attempts.saturating_mul(attempt_floor) > bytes.len() {
            return None;
        }
        Some(Self {
            bytes,
            run,
            after_run,
            reach_floor,
            run_end: 0,
            remaining: bytes.len(),
        })
    }

    /// Charges an attempt at `start`, which must not decrease between calls.
    ///
    /// Run scanning is amortized: the cursor never moves backward. Every byte
    /// between one floor and `run_end` is a run byte, so a later floor at or
    /// below `run_end` stops exactly there.
    fn admit(&mut self, start: usize) -> bool {
        let Some(run) = self.run else {
            // A finite tail has a constant bound the constructor already checked.
            return true;
        };
        self.run_end = self.run_end.max(start.saturating_add(self.reach_floor));
        while self
            .bytes
            .get(self.run_end)
            .is_some_and(|byte| run[usize::from(*byte)])
        {
            self.run_end += 1;
        }
        let charge = ATTEMPT_COST_FLOOR
            .saturating_add(self.run_end.saturating_sub(start))
            .saturating_add(self.after_run);
        let Some(remaining) = self.remaining.checked_sub(charge) else {
            return false;
        };
        self.remaining = remaining;
        true
    }
}

impl GoRegex {
    /// Returns compile-time literal-anchor evidence, if the shape is eligible.
    pub(crate) fn literal_anchor(&self) -> Option<&LiteralAnchorShape> {
        self.literal_anchor.as_deref()
    }

    /// Returns every whole match using anchored searches at `occurrences`.
    ///
    /// `occurrences` must be sorted, deduplicated and complete for the chosen
    /// candidate's literals. The haystack must be pure ASCII, or valid UTF-8
    /// without U+017F and U+212A. `None` means the shape or the budget rejected
    /// this haystack; call [`Self::find_all_normalized`].
    pub(crate) fn find_all_literal_anchored(
        &self,
        normalized: &NormalizedHaystack<'_>,
        candidate: usize,
        occurrences: &[usize],
    ) -> Option<Vec<ByteSpan>> {
        self.find_all_literal_anchored_counted(normalized, candidate, occurrences)
            .0
    }

    /// Includes spans materialized by an optimization attempt that abandons.
    pub(crate) fn find_all_literal_anchored_counted(
        &self,
        normalized: &NormalizedHaystack<'_>,
        candidate: usize,
        occurrences: &[usize],
    ) -> (Option<Vec<ByteSpan>>, usize) {
        let mut collected = 0;
        let result = (|| {
            let shape = self.literal_anchor.as_deref()?;
            let bytes = normalized.bytes();
            let ascii = bytes.is_ascii();
            if !shape.non_ascii_haystacks && !ascii {
                return None;
            }
            let candidate = shape.candidates.get(candidate)?;
            let placed = placeable(candidate, bytes, ascii, occurrences);
            let budget = AttemptBudget::new(shape, candidate, bytes, ascii, placed.len())?;
            self.enumerate_anchored(bytes, shape, &placed, Some(budget), || collected += 1)
        })();
        (result, collected)
    }

    /// Runs the enumeration with no budget, for differential tests.
    ///
    /// The result is `None` only for an expression without a shape.
    #[cfg(test)]
    pub(crate) fn find_all_literal_anchored_unbudgeted(
        &self,
        normalized: &NormalizedHaystack<'_>,
        candidate: usize,
        occurrences: &[usize],
    ) -> Option<Vec<ByteSpan>> {
        let shape = self.literal_anchor.as_deref()?;
        let bytes = normalized.bytes();
        let placed = placeable(
            shape.candidates.get(candidate)?,
            bytes,
            bytes.is_ascii(),
            occurrences,
        );
        self.enumerate_anchored(normalized.bytes(), shape, &placed, None, || {})
    }

    /// Enumerates each candidate with naive occurrence discovery and no budget.
    ///
    /// Returns nothing for ineligible expressions and for haystacks the shape
    /// cannot serve. This is the oracle hook for tests and the regex fuzz
    /// target.
    pub(crate) fn literal_anchored_candidates(&self, haystack: &[u8]) -> Vec<Vec<ByteSpan>> {
        let Some(shape) = self.literal_anchor.as_deref() else {
            return Vec::new();
        };
        let served = haystack.is_ascii()
            || (shape.non_ascii_haystacks
                && std::str::from_utf8(haystack)
                    .is_ok_and(|text| !text.contains(['\u{17f}', '\u{212a}'])));
        if !served {
            return Vec::new();
        }
        let lowered = haystack.to_ascii_lowercase();
        shape
            .candidates
            .iter()
            .map(|candidate| {
                let occurrences = naive_occurrences(&lowered, candidate.literals());
                let placed = placeable(candidate, haystack, haystack.is_ascii(), &occurrences);
                self.enumerate_anchored(haystack, shape, &placed, None, || {})
                    .expect("enumeration without a budget cannot abandon")
            })
            .collect()
    }

    fn enumerate_anchored(
        &self,
        bytes: &[u8],
        shape: &LiteralAnchorShape,
        occurrences: &[usize],
        mut budget: Option<AttemptBudget<'_>>,
        mut collect_span: impl FnMut(),
    ) -> Option<Vec<ByteSpan>> {
        debug_assert!(bytes.is_ascii() || shape.non_ascii_haystacks);
        debug_assert!(occurrences.windows(2).all(|pair| pair[0] < pair[1]));
        let end = bytes.len();
        let mut position = 0;
        let mut previous_start = None;
        let mut results = Vec::new();
        for &occurrence in occurrences {
            if occurrence < position {
                continue;
            }
            let floor = position.max(occurrence.saturating_sub(shape.max_leading));
            let mut start = occurrence;
            while start > floor && shape.class[usize::from(bytes[start - 1])] {
                start -= 1;
            }
            if previous_start == Some(start) {
                continue;
            }
            previous_start = Some(start);
            if let Some(budget) = &mut budget
                && !budget.admit(start)
            {
                return None;
            }
            let input = Input::new(bytes).span(start..end).anchored(Anchored::Yes);
            if let Some(found) = self.backend.get().search(&input) {
                debug_assert_eq!(found.start(), start);
                debug_assert!(found.end() > found.start());
                collect_span();
                results.push(ByteSpan {
                    start: found.start(),
                    end: found.end(),
                });
                position = found.end();
            }
        }
        Some(results)
    }
}

/// Keeps the occurrences where a match can have its literal (lemma 6). Only
/// an ASCII haystack rules any out.
fn placeable(
    candidate: &LiteralCandidate,
    bytes: &[u8],
    ascii: bool,
    occurrences: &[usize],
) -> Vec<usize> {
    if !ascii {
        return occurrences.to_vec();
    }
    occurrences
        .iter()
        .copied()
        .filter(|&occurrence| candidate.can_place(bytes, occurrence))
        .collect()
}

/// Finds every literal start in `lowered`, sorted and deduplicated.
fn naive_occurrences(lowered: &[u8], literals: &[Box<[u8]>]) -> Vec<usize> {
    (0..lowered.len())
        .filter(|&offset| {
            literals
                .iter()
                .any(|literal| lowered[offset..].starts_with(literal))
        })
        .collect()
}

#[cfg(test)]
mod tests;
