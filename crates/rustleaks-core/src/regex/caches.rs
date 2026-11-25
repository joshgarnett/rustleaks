//! Search caches owned by one caller, such as one scan worker.
//!
//! A meta regex keeps its own pool of search caches. The pool never frees a
//! cache, so pool memory grows with the number of threads and has no limit.
//! [`RegexCaches`] holds one cache for each expression that its owner has
//! searched, and drops the least recently used caches when their estimated
//! size passes a limit. Searches with a cache from this store return the same
//! results as searches through the pool; only memory and speed differ.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

use regex_automata::meta::{Cache, Regex};

use super::LazyBackendState;

/// Search caches for one owner, keyed by expression.
pub(crate) struct RegexCaches {
    entries: HashMap<usize, CacheEntry, BuildHasherDefault<AddressHasher>>,
    /// Advances once per [`Self::end_unit`].
    clock: u64,
    /// Keys searched since estimates were last updated.
    touched: Vec<usize>,
    /// Sum of the entries' size estimates.
    estimated_bytes: usize,
    /// Size above which the least recently used caches are dropped.
    limit: usize,
}

struct CacheEntry {
    /// Keeps the expression alive, so that no other expression can reuse
    /// its address as a key while this entry exists.
    _owner: Arc<LazyBackendState>,
    cache: Cache,
    last_used: u64,
    /// Whether the key is in `touched`.
    listed: bool,
    /// Estimated heap of the cache, in bytes.
    ///
    /// `Cache::memory_usage` counts the states that a lazy DFA holds now,
    /// not the storage it has allocated, and a cleared lazy DFA keeps its
    /// storage. The estimate keeps the highest reading, scaled up for
    /// unused vector capacity.
    estimate: usize,
}

impl RegexCaches {
    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            entries: HashMap::default(),
            clock: 0,
            touched: Vec::new(),
            estimated_bytes: 0,
            limit,
        }
    }

    /// Returns the cache for `regex`, owned by `owner`, creating it if needed.
    pub(super) fn cache(&mut self, owner: &Arc<LazyBackendState>, regex: &Regex) -> &mut Cache {
        let key = Self::key_of(owner);
        let clock = self.clock;
        let entry = self.entries.entry(key).or_insert_with(|| CacheEntry {
            _owner: Arc::clone(owner),
            cache: regex.create_cache(),
            last_used: clock,
            listed: false,
            estimate: 0,
        });
        entry.last_used = clock;
        if !entry.listed {
            entry.listed = true;
            self.touched.push(key);
        }
        &mut entry.cache
    }

    fn key_of(owner: &Arc<LazyBackendState>) -> usize {
        Arc::as_ptr(owner) as usize
    }

    /// Units between updates of the size estimates.
    ///
    /// Reading a cache's size costs about as much as a short search, so it
    /// is not done after every fragment. Between updates the caches can
    /// grow past the limit by what this many units add.
    const UNITS_PER_UPDATE: u64 = 16;

    /// Ends one unit of work, such as one fragment, and applies the limit.
    pub(crate) fn end_unit(&mut self) {
        self.clock = self.clock.wrapping_add(1);
        if !self.clock.is_multiple_of(Self::UNITS_PER_UPDATE) {
            return;
        }
        for key in self.touched.drain(..) {
            let Some(entry) = self.entries.get_mut(&key) else {
                continue;
            };
            entry.listed = false;
            let reading = entry.cache.memory_usage();
            let estimate = reading.saturating_add(reading / 2);
            if estimate > entry.estimate {
                self.estimated_bytes = self
                    .estimated_bytes
                    .saturating_add(estimate - entry.estimate);
                entry.estimate = estimate;
            }
        }
        if self.estimated_bytes > self.limit {
            self.shrink();
        }
    }

    /// Drops least recently used caches until the estimate is at most three
    /// quarters of the limit, so that the next drop is not one update away.
    #[cold]
    fn shrink(&mut self) {
        let target = self.limit / 4 * 3;
        let mut order: Vec<(u64, usize)> = self
            .entries
            .iter()
            .map(|(key, entry)| (entry.last_used, *key))
            .collect();
        order.sort_unstable();
        for (_, key) in order {
            if self.estimated_bytes <= target {
                break;
            }
            if let Some(entry) = self.entries.remove(&key) {
                self.estimated_bytes = self.estimated_bytes.saturating_sub(entry.estimate);
            }
        }
    }

    /// Number of caches held, for tests.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Sum of the size estimates, for tests.
    #[cfg(test)]
    pub(crate) fn estimated_bytes(&self) -> usize {
        self.estimated_bytes
    }
}

/// Hashes a key that is already a unique heap address.
#[derive(Default)]
struct AddressHasher(u64);

impl Hasher for AddressHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0.rotate_left(8) ^ u64::from(*byte)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }

    fn write_usize(&mut self, value: usize) {
        // Heap addresses share their low alignment bits. The multiply moves
        // the varying bits up and the shift brings them back down, because
        // the table takes bucket bits from the low end and tag bits from the
        // high end.
        let mixed = (value as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.0 = mixed ^ (mixed >> 29);
    }
}

#[cfg(test)]
mod tests {
    use super::RegexCaches;
    use crate::regex::{ByteSpan, GoRegex, NormalizedHaystack};

    fn expressions() -> Vec<GoRegex> {
        [
            r"alpha=([a-z]+)",
            r"(?i)\bbeta\s*[:=]\s*(\w{4,})",
            r"gamma|delta",
        ]
        .iter()
        .map(|source| GoRegex::compile(source).unwrap())
        .collect()
    }

    fn search(regex: &GoRegex, haystack: &[u8], caches: &mut RegexCaches) -> Vec<ByteSpan> {
        regex.find_all_normalized(&NormalizedHaystack::new(haystack), Some(caches))
    }

    #[test]
    fn owned_caches_return_pool_results() {
        let haystack = b"alpha=abc BETA = wxyz1 delta gamma alpha=q";
        let mut caches = RegexCaches::with_limit(usize::MAX);
        for regex in expressions() {
            let expected = regex.find_all(haystack);
            for _ in 0..3 {
                assert_eq!(search(&regex, haystack, &mut caches), expected);
                caches.end_unit();
            }
            assert_eq!(
                regex.is_match_normalized(&NormalizedHaystack::new(haystack), Some(&mut caches)),
                regex.is_match(haystack)
            );
        }
        assert_eq!(caches.len(), 3);
    }

    #[test]
    fn caches_past_the_limit_are_dropped_and_rebuilt() {
        let haystack = b"alpha=abc beta: wxyz gamma";
        let regexes = expressions();
        let mut caches = RegexCaches::with_limit(1);
        for unit in 1..=RegexCaches::UNITS_PER_UPDATE * 2 {
            for regex in &regexes {
                assert_eq!(
                    search(regex, haystack, &mut caches),
                    regex.find_all(haystack)
                );
            }
            caches.end_unit();
            if unit % RegexCaches::UNITS_PER_UPDATE == 0 {
                // Every cache that holds memory is past a one-byte limit. A
                // cache that reports no memory, such as one for literals
                // alone, can stay.
                assert_eq!(caches.estimated_bytes(), 0);
                assert!(caches.len() < regexes.len());
            } else {
                assert_eq!(caches.len(), regexes.len());
            }
        }
    }

    #[test]
    fn least_recently_used_caches_are_dropped_first() {
        let regexes = expressions();
        let mut caches = RegexCaches::with_limit(usize::MAX);
        for regex in &regexes {
            search(regex, b"alpha=abc beta: wxyz gamma", &mut caches);
        }
        for _ in 0..RegexCaches::UNITS_PER_UPDATE {
            caches.end_unit();
        }
        let total = caches.estimated_bytes();
        assert!(total > 0);
        // Use only the last expression, then lower the limit so that one
        // cache must go: the two that were not used are dropped first.
        search(&regexes[2], b"gamma", &mut caches);
        caches.limit = total - 1;
        for _ in 0..RegexCaches::UNITS_PER_UPDATE {
            caches.end_unit();
        }
        let kept = RegexCaches::key_of(&regexes[2].backend.0);
        assert!(caches.entries.contains_key(&kept));
        assert!(caches.len() < regexes.len());
    }
}
