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
//! The argument never uses the greediness of `P`. Priority only selects a path
//! within one start, and the same expression makes that choice. Greedy, lazy
//! and mixed leading repetitions are therefore all exact.
//!
//! # Cost
//!
//! An unbounded `T` can keep an attempt alive to the end of the input, so
//! occurrence density alone does not bound total attempt work. Before each
//! attempt the budget charges an upper bound on how far that attempt can scan.
//! Enumeration abandons the anchored path when the charges exceed the haystack
//! length. Falling back affects only cost; both paths return the same matches.
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
}

/// One choice of where the literal node ends, in ascending literal length.
#[derive(Debug)]
pub(crate) struct LiteralCandidate {
    literals: Vec<Box<[u8]>>,
    max_literal_len: usize,
    tail: TailBound,
}

#[derive(Debug)]
enum TailBound {
    /// The remainder after the literal consumes at most this many bytes.
    Finite(usize),
    /// The remainder has an unbounded node after `bounded_prefix` bytes, and
    /// everything from that node onward consumes only `run` bytes.
    Unbounded {
        bounded_prefix: usize,
        run: Box<ByteSet>,
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
        let shared = TailBound::new(&rest[last + 1..]);
        let mut between = 0_usize;
        let mut end = last;
        let mut candidates = Vec::with_capacity(choices.len());
        for (index, literals) in choices.into_iter().rev() {
            between = rest[index + 1..=end].iter().fold(between, |sum, child| {
                sum.saturating_add(child.properties().maximum_len().unwrap_or(usize::MAX))
            });
            end = index;
            candidates.push(LiteralCandidate::new(&literals, shared.after(between)));
        }
        candidates.reverse();
        Some(Self {
            class,
            max_leading,
            candidates,
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
    pub(crate) fn leading_contains(&self, byte: u8) -> bool {
        self.class[usize::from(byte)]
    }
}

impl LiteralCandidate {
    fn new(literals: &[Vec<u8>], tail: TailBound) -> Self {
        Self {
            literals: literals
                .iter()
                .map(|literal| literal.as_slice().into())
                .collect(),
            max_literal_len: literals.iter().map(Vec::len).max().unwrap_or(0),
            tail,
        }
    }

    /// Returns the sorted, deduplicated ASCII-lowercased literal set.
    pub(crate) fn literals(&self) -> &[Box<[u8]>] {
        &self.literals
    }
}

impl TailBound {
    fn new(tail: &[Hir]) -> Self {
        let mut bounded_prefix = 0_usize;
        for (index, node) in tail.iter().enumerate() {
            let Some(maximum) = node.properties().maximum_len() else {
                let mut run = Box::new([false; 256]);
                for later in &tail[index..] {
                    collect_consumed_bytes(later, &mut run, 0);
                }
                return Self::Unbounded {
                    bounded_prefix,
                    run,
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
            } => Self::Unbounded {
                bounded_prefix: bounded_prefix.saturating_add(bounded),
                run: run.clone(),
            },
        }
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
        attempts: usize,
    ) -> Option<Self> {
        let leading = shape.max_leading + candidate.max_literal_len;
        let (minimum_tail, run) = match &candidate.tail {
            TailBound::Finite(maximum) => (*maximum, None),
            TailBound::Unbounded {
                bounded_prefix,
                run,
            } => (*bounded_prefix, Some(run.as_ref())),
        };
        let reach_floor = leading.saturating_add(minimum_tail);
        let attempt_floor = ATTEMPT_COST_FLOOR.saturating_add(reach_floor);
        if attempts.saturating_mul(attempt_floor) > bytes.len() {
            return None;
        }
        Some(Self {
            bytes,
            run,
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
        let charge = ATTEMPT_COST_FLOOR.saturating_add(self.run_end.saturating_sub(start));
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
    /// candidate's literals, and the haystack must be pure ASCII. `None` means
    /// the budget rejected this haystack; call [`Self::find_all_normalized`].
    pub(crate) fn find_all_literal_anchored(
        &self,
        normalized: &NormalizedHaystack<'_>,
        candidate: usize,
        occurrences: &[usize],
    ) -> Option<Vec<ByteSpan>> {
        let shape = self.literal_anchor.as_deref()?;
        let bytes = normalized.bytes();
        let budget = AttemptBudget::new(
            shape,
            shape.candidates.get(candidate)?,
            bytes,
            occurrences.len(),
        )?;
        self.enumerate_anchored(bytes, shape, occurrences, Some(budget))
    }

    /// Runs the enumeration with no budget, for differential tests.
    ///
    /// The result is `None` only for an expression without a shape.
    pub(crate) fn find_all_literal_anchored_unbudgeted(
        &self,
        normalized: &NormalizedHaystack<'_>,
        occurrences: &[usize],
    ) -> Option<Vec<ByteSpan>> {
        let shape = self.literal_anchor.as_deref()?;
        self.enumerate_anchored(normalized.bytes(), shape, occurrences, None)
    }

    /// Enumerates each candidate with naive occurrence discovery and no budget.
    ///
    /// Returns nothing for ineligible expressions and non-ASCII haystacks. This
    /// is the oracle hook for tests and the regex fuzz target.
    pub(crate) fn literal_anchored_candidates(&self, haystack: &[u8]) -> Vec<Vec<ByteSpan>> {
        let Some(shape) = self.literal_anchor.as_deref() else {
            return Vec::new();
        };
        if !haystack.is_ascii() {
            return Vec::new();
        }
        let lowered = haystack.to_ascii_lowercase();
        shape
            .candidates
            .iter()
            .map(|candidate| {
                let occurrences = naive_occurrences(&lowered, candidate.literals());
                self.enumerate_anchored(haystack, shape, &occurrences, None)
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
    ) -> Option<Vec<ByteSpan>> {
        debug_assert!(bytes.is_ascii());
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
            if let Some(found) = self.backend.search(&input) {
                debug_assert_eq!(found.start(), start);
                debug_assert!(found.end() > found.start());
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
