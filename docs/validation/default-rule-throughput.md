# Default-rule throughput

Measured on 2026-11-10 on Apple M1 Max, 32 GiB RAM, macOS 26.5.2 arm64, 10
logical CPUs, Rust 1.95.0, using optimized unstamped Bazel builds. The baseline
is `b84b3cc4f9c925d13c2eb150a1f4888918a64b16`: the previous branch state plus
frozen workload definitions, with no production change. The candidate is
`f8d06061cc19833fabf3422b7f767e3f0babe173`. Both report workload-definition
SHA-256 `174d2725bed4105fe8cbbfcf3693a1b0eb8e058cde721a42ae22271f42aed731`,
clean-source provenance and baseline eligibility. No dependency, feature,
toolchain, public API, copied configuration or Gitleaks pin changed. All inputs
are synthetic.

## Method

The `fragments`, `edges`, `workers`, `default-rules`, `decode-report` and
`source-scale` groups ran through `perf representative` with three fresh
processes and one steady iteration, except three iterations for `workers`.
Tables report the median of those processes. All 481 measured phases matched
the baseline in outcome fingerprint, finding count, work counts and input
identity; timing was the only difference. Elapsed time is a host observation,
not a portable guarantee. Background macOS services were active, and load
average was between 2 and 6 during collection.

One phase needed a repeat. `cli-many-issues` recorded 121.226 ms in the full
candidate run, which began right after a test build, with samples from 57.2 to
372.6 ms. A serial repeat at the same commit recorded 47.5, 48.6 and 49.0 ms.
The table reports that repeat.

Per-change effects compare each commit with its parent over its target
workloads. Those comparisons ran in the original order, before the rejected
changes below were removed, so they attribute an effect rather than restate
final totals.

Instruction counts come from `/usr/bin/time -l`, with five processes of five
iterations each. They cover the whole process, including fixture construction
and validation, so scan-only reductions are larger than those shown. Across
processes the largest count was at most 0.39% above the smallest.

## Cost before this change

Debug output from the compiled meta engines records the strategy each of the
221 default content rules receives. 105 have no prefilter (103 `Core`, 2
`ReverseInner`), 115 have one (`Core` or `ReverseInner` with Memmem, Memchr or
Teddy), and one is a pure literal search. All 96 rules beginning
`(?i)[\w.-]{0,50}?` are among those with no prefilter, so each admitted rule of
that shape made a forward lazy-DFA pass over the whole fragment.

Admitted-rule scaling confirms the cost model. Each input is 4 MiB of
keyword-free text with keywords only in its first 4 KiB and no candidates.

| Admitted rules | Baseline ms | Candidate ms |
| ---: | ---: | ---: |
| 2 | 13.772 | 7.287 |
| 17 | 71.273 | 30.610 |
| 65 | 183.760 | 44.038 |
| 167 | 546.653 | 102.214 |

## Literal-anchored enumeration

This supersedes the earlier statement in
[filtering and normalization measurements](core-edge-performance.md) that no
keyword-based search restriction or prefilter was added. It does not use fixed
windows and does not change results.

A rule qualifies when its parsed expression is one or more optional bounded
repetitions over one ASCII character class, followed by a finite set of
non-empty literals that are all among the rule's keywords, with no look-around
or capture before the literal. 93 default rules qualify. Rules whose literal is
not a keyword, such as `lob-api-key`, stay on the unanchored path, as do rules
with a top-level alternation, composite rules and every non-ASCII pass.

On a pure-ASCII pass, the existing keyword search records keyword start
offsets. For each occurrence at or after the current search position, the
matcher walks back at most the summed repetition limit through the class, then
runs the unchanged compiled regex anchored there, on the unsliced haystack, so
look-around sees the same context. The module documentation of
`crates/rustleaks-core/src/regex/literal_anchor.rs` holds the argument: a match
through an occurrence implies a match at its walk-back start, walk-back starts
are nondecreasing, so the first successful anchored attempt is the leftmost
match, and the anchored search returns the same highest-priority match.

Differential tests compare the two paths for all 93 rules over 6,770 frozen
rule samples, seeded adversarial inputs, exhaustive small-alphabet strings and
enumerated rule grammars, and a `go_regex` fuzz assertion checks span
equivalence. Dense occurrences and attempts that stay alive in an unbounded
tail fall back to the unanchored search, which returns the same matches.

## Results

Steady-scan medians, in milliseconds, default configuration, decode depth zero:

| Workload | Baseline | Candidate |
| --- | ---: | ---: |
| JSON, 4 MiB | 275.555 | 16.685 |
| JSON, 12 MiB / 16 KiB fragments | 812.718 | 57.355 |
| JSON, 12 MiB / 256 KiB fragments | 756.783 | 50.792 |
| Log, 4 MiB | 253.435 | 16.873 |
| Log, 12 MiB / 16 KiB fragments | 797.098 | 59.932 |
| Log, 12 MiB / 256 KiB fragments | 768.906 | 51.170 |
| Invalid UTF-8, 4 MiB | 263.458 | 260.537 |
| Invalid UTF-8, 12 MiB / 16 KiB fragments | 809.558 | 799.670 |
| Every rule admitted, 4 MiB | 764.203 | 115.016 |
| Prose dense in keywords, 1 MiB | 5.586 | 4.654 |
| Multi-language source, 256 KiB | 1.804 | 0.902 |
| `.env` content, 256 KiB | 2.607 | 1.931 |
| 100,000 fragments of 64 bytes | 1,390.216 | 190.467 |
| 100,000 fragments of 512 bytes | 1,640.431 | 371.577 |
| Shared engine, 8 workers, 12 MiB | 105.054 | 8.702 |
| Keyword repeated throughout, 1 MiB | 13.374 | 12.817 |
| CJK text with keywords, 4 MiB | 38.104 | 36.877 |

Invalid-UTF-8 and other non-ASCII passes keep the unanchored path, so they show
little change. The ordinary workload families plant provider keywords in fixed
records; broader text has fewer anchorable rules and gains less, as the prose
row shows.

Decoding, findings and reports:

| Workload | Baseline | Candidate |
| --- | ---: | ---: |
| 20,000 base64 lines, depth 1 | 357.884 | 23.373 |
| The same lines double-encoded, depth 2 | 1,009.435 | 30.374 |
| Long line, 10,000 tokens, findings allowlisted | 3,069.817 | 9.942 |
| Long line, 10,000 retained findings | 3,464.318 | 414.995 |
| Valid percent decoding, 4 MiB, depth 1 | 155.308 | 22.640 |
| Hex and unicode segments, 256 KiB | 14.660 | 5.394 |
| Base64-like lockfile, 4 MiB, depth 1 | 73.397 | 37.966 |
| 65,536 generic findings | 6,625.641 | 81.047 |
| Baseline classification, 10,000 x 10,000 | 132.923 | 4.343 |

JSON and SARIF report serialization were measured per change: JSON 10,000
findings went from 12.414 to 6.360 ms, and SARIF from 23.507 to 11.226 ms.

Sources, Git, archives and CLI, in milliseconds:

| Workload | Baseline | Candidate |
| --- | ---: | ---: |
| Default config, 12 MiB, 1 worker, traversal and detection | 50.645 | 27.748 |
| Default config, 12 MiB, 4 workers | 16.262 | 8.126 |
| Default config, 12 MiB, 8 workers | 16.423 | 8.415 |
| Directory with no blank lines, 12 MiB | 45.448 | 13.362 |
| Single line, 64 MiB | 234.979 | 63.822 |
| 20,000 commits, history and detection | 835.398 | 495.334 |
| 500 small zstd files | 355.022 | 53.865 |
| Gzip, 60 MiB of zeros | 749.534 | 96.821 |
| Bzip2, 60 MiB of zeros | 428.579 | 128.749 |
| Zstd, 60 MiB of zeros | 281.104 | 120.833 |
| CLI, 10,000 size-limit warnings | 382.222 | 48.6 |

Whole-process instructions retired, in millions:

| Workload | Baseline | Candidate |
| --- | ---: | ---: |
| JSON, 4 MiB | 9,661.4 | 2,442.0 |
| 150-keyword admission, 4 MiB | 22,461.7 | 9,011.6 |
| 100,000 fragments of 64 bytes | 112,078.1 | 19,164.2 |
| Every rule admitted, 4 MiB | 29,347.2 | 9,954.5 |
| Prose dense in keywords, 1 MiB | 2,216.9 | 2,107.1 |
| Invalid UTF-8, 4 MiB | 10,522.2 | 10,153.3 |
| 20,000 base64 lines, depth 1 | 23,040.5 | 2,719.8 |

## Per-change effects

Each row compares a commit with its parent.

| Change | Target workload | Before ms | After ms |
| --- | --- | ---: | ---: |
| Skip captures for groupless rules | 4,096 `ghp_` tokens | 11.610 | 10.718 |
| Per-rule keyword indexes | 64-byte fragments x 100,000 | 1,419.284 | 158.266 |
| Bucket generic suppression | 65,536 generic findings | 6,843.814 | 99.813 |
| Stack entropy histogram | Dense 16 KiB | 0.240 | 0.192 |
| JSON runs and indents | JSON 10,000 findings | 12.414 | 7.097 |
| Stack entropy formatting | JSON 10,000 findings | 7.097 | 6.360 |
| Baseline index | 10,000 x 10,000 classify | 135.113 | 4.385 |
| Decoded line bounds | Long allowlisted line | 3,047.254 | 13.606 |
| Whole-match decoder classification | Percent, 4 MiB, depth 1 | 144.836 | 22.782 |
| Decoder whole-buffer copies | Percent, 4 MiB, depth 1 | 22.782 | 22.625 |
| Bulk predecessor charge | 20,000 lines, depth 2 | 678.486 | 30.799 |
| Unique-commit index | 20,000 commits, detection | 844.350 | 507.529 |
| Single diagnostic write | 10,000 warnings | 394.514 | 49.319 |
| Table-driven CRC | Gzip, 60 MiB | 752.333 | 256.478 |
| Zstd history sizing | 500 small zstd files | 354.396 | 51.697 |
| Bulk read-ahead and buffer reuse | Single line, 64 MiB | 236.980 | 63.959 |
| Literal-anchored search | JSON, 4 MiB | 252.154 | 18.435 |
| Full keyword DFA | 2 admitted rules, 4 MiB | 13.932 | 7.281 |

The decoder whole-buffer change is wall-time neutral. It stays because it
removes a full-input copy on passes that decode nothing and lowers peak RSS on
the percent workload from 25.4 to 24.1 MiB.

The ordered merge has no speed target. Multi-worker runs now return findings in
producer order. Comparing it with its parent over the 4- and 8-worker and
many-file cases found no material change in complete-run elapsed time.

## Rejected changes

These were implemented and measured, then removed because they did not improve
their target workloads:

| Change | Observation | Disposition |
| --- | --- | --- |
| Bulk ASCII runs in Go lowercasing | CJK +4.5%, Cyrillic +6.1%, binary +14.2% | Removed |
| Base64 alphabet classification | Lookalike lockfile +5.7% | Removed |
| Blocking producer handoff | Runner phase +80.3% for 50,000 files, +70.1% for a deep tree | Removed |
| Allowlist memoization | One target +4.3%, one -7.2%, one unchanged | Removed |
| Borrowing tar members and gzip members | No change beyond sample overlap | Removed |

## Not implemented

- Native timing on Linux x86_64 or other targets. Teddy and memchr paths differ
  by architecture, so these results apply to macOS arm64.
- Merged-window matching for other bounded rules. No complete exactness proof
  exists, and `sourcegraph-access-token` has a branch with no required literal.
- Removing the duplicate NFA build or allowlist revalidation. The meta builder
  has no from-NFA entry point, and `a)|(?:b` and `\Qabc` show that pattern
  validation depends on context.
- Lazy-DFA capacity changes. No instrumented evidence of give-up was collected.
- Replacing the Git child poll with a reader join, which would prevent killing
  a hung child on cancellation.
- Streaming Git output, a CLI worker count or flag, and `git cat-file --batch`.
  These change observable behavior or policy. The bzip2 Huffman rewrite would
  widen the retained fork delta.
- Dependency changes, including a raised `regex-automata` floor and measurement
  crates. These need maintainer approval.

## Resource bounds for untrusted configuration

Configuration is untrusted, and the CLI loads `.gitleaks.toml` or
`.rustleaks.toml` from a scanned directory. Independent review found two
compile-time costs, which were reproduced and bounded before acceptance.

Shape analysis ran for every compiled expression. A 1 MiB pattern with 209,698
empty alternations took 72.1 s to analyze and retained about 1.26 GB. Children
that can only match the empty string now add no literal choice, and analysis is
capped at 32 choices and 16,384 enumeration steps. The same pattern analyzes in
about 1.05 ms and compiles in 0.86 s. The default rules need at most 12 choices
and 168 steps, and default eligibility is unchanged at 93 rules.

Forcing a full keyword DFA made build time quadratic in keyword depth. One
16,000-byte keyword plus 110 short keywords took 37.2 s. The DFA is now forced
only when keywords total at most 16 KiB and the summed lengths of all keyword
prefixes are at most 64 Ki bytes; otherwise the automatic choice applies and
the same set builds in 1.9 ms. The default set sums to 9,339 and builds its DFA
in 0.58 ms. These reproduction timings were collected while other builds ran
and are indicative only.

Sets of 100 or fewer keywords still receive aho-corasick's automatic DFA, as
before this change, and a hostile set of that size can still take tens of
seconds to build. That pre-existing cost is recorded in
[resource limits](../RESOURCE_LIMITS.md).

## Remaining limits

Bulk boundary read-ahead added runner-phase cost on sources that produce many
small fragments, and the ordered merge added a little more. Runner phases rose
from 11.941 to 14.422 ms for 50,000 files, 1.004 to 1.220 ms for a deep tree,
0.850 to 0.966 ms for a binary mix and 12.449 to 13.408 ms for skewed sizes.
Complete traversal elapsed time did not rise in those cases. The anchored path
setup adds about 0.15 ms to a 64 KiB invalid-UTF-8 empty-match case, from 2.026
to 2.175 ms. Keyword automaton construction adds about 0.3 ms per engine.

Commit-bearing sources retain a second copy of commit identifiers for the
unique-commit index. Scans with a cancellation signal keep the per-unit poll
loops in generic suppression and decoder predecessor charging, because signals
can observe poll counts, so those two improvements apply only without a signal.
File reads now poll cancellation once per buffered slice of at most 4,096
bytes. Non-ASCII input receives none of the anchored speedup. Accepted findings
still copy their full lines, and a long line with many retained findings holds
about 10 GiB in the 1 MiB, 10,000-finding case.

## Compatibility and security

Findings, spans, entropy bits, work units, budget termination, explanation
order, decoder cache contents, report bytes and baseline classification are
preserved; each change carries differential or reference tests against the
previous behavior, and mutation checks confirmed those tests fail when the
mechanism is broken. The anchored path is restricted to shapes proven at compile
time and to ASCII passes. Independent source reviews read every change. They
found no result difference; the two configuration costs above were their only
material findings. Archive CRC changes retain published check values and bitwise
differential tests.

The baseline index lives in private session policy data. `Baseline` keeps its
derived traits, and the core public API matches its snapshot byte for byte.

Multi-worker finding order is now deterministic for complete runs. Budget-stopped
runs keep their documented unspecified order, and the CLI still uses one worker.

## Validation

The code was gated at `dc46e03`, which adds Clippy-only syntax, the private
baseline index and the configuration bounds to the measured candidate.
Re-measuring the 4 MiB JSON, admission, all-admitted, keyword-run, 64-byte
fragment and baseline classification workloads there stayed within 1.6% of the
candidate, with identical outcomes.

- `just ci`: all 60 targets passed, including committed parity, format, lint,
  documentation and the eight-target compile matrix.
- `just security`: dependency policy, vetting, Miri, panic policy and
  owned-code safety checks passed.
- `cargo xtask qualify`: strict quality and MSRV, pinned Miri, frozen evidence
  and Rust regression replay, bounded resource controls, the public API
  snapshot, dependency advisories and licenses, and the 23 legacy performance
  workloads passed. Inherited M1 Max elapsed and RSS limits and every required
  1.5-second fragment median passed; 4 MiB JSON took 16.656 ms. All eight fuzz
  targets succeeded with zero artifacts, and `go_regex` replayed 3,386 corpus
  files.

Native measurements apply to macOS arm64. Hosted CI runs the native test suite
on the other required targets; compile-only checks are not runtime evidence.
