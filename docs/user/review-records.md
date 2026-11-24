# Review records

This guide is for Rust developers who use `rustleaks-core` and want to track
findings that a person has already reviewed. Read [Using
rustleaks-core](library.md) first.

The `rustleaks_core::triage` module labels each finding as `New` or
`Acknowledged`. It never removes a finding, changes detection, or marks a
credential as safe. An acknowledgement records a decision in your review
process. It is separate from ignore files and baselines, and you must turn
it on yourself.

```rust
use rustleaks_core::explanation::ExplanationOptions;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::native::NativePolicy;
use rustleaks_core::triage::{
    ReviewClassification, ReviewOccurrence, ReviewPolicy, ReviewReason, ReviewRecord,
    ReviewSource,
};
use rustleaks_core::ScanControl;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine = NativePolicy::builder().build()?;
    let policy = ReviewPolicy::for_builtin(engine.identity())?;
    let source = ReviewSource::caller_bound("snapshot-001")?;
    let scan = engine.scan_fragment_controlled(
        &Fragment::new(b"string AWSToken = \"AKIALALEMEL33243OLIB\";"), // rustleaks:allow
        &ScanOptions::default(),
        &ScanControl::unlimited(),
        ExplanationOptions::disabled(),
    );
    let record = ReviewRecord::new(
        policy.reference(),
        scan.options(),
        ReviewOccurrence::from_finding(source.clone(), &scan.scan().findings()[0], 0)?,
        ReviewReason::SyntheticFixture,
        1_800_000_000, // expires at this Unix time, in seconds
    )?;
    let review = policy.review(&scan, &source, &[record], 1_700_000_000)?;
    assert_eq!(
        review.classifications()[0],
        ReviewClassification::Acknowledged { record_index: 0 }
    );
    Ok(())
}
```

## Identifying the rules and the source

- `ReviewPolicy::for_builtin` works for the default rules and the built-in
  rule files. Its reference includes the package versions, the hashes of the
  selected rules and the enabled extensions.
- For your own rule files, use `ReviewPolicy::caller_bound` with a reference
  from your own store that is tied to the exact bytes of the rule file. A rule
  file name and version alone are not enough. Before each review, the
  library checks that the scan used the same rules as the policy.
- `ReviewSource::caller_bound` takes a reference to the exact bytes you
  scanned, and their source details, from your own store. When the bytes
  change, use a new reference, even if only one line was added or replaced at
  the same place. A file path or line number alone is not enough, because a
  reused reference can mark a new credential as already reviewed. The library
  cannot check your store between runs. Do not use an unsalted hash of a
  credential as a reference.
- Each record also stores the scan options: decode depth, target size,
  redaction and allow comments. A record does not match a scan with different
  options.

## What records contain

A record holds the policy and source references, the rule ID, numeric
locations and byte ranges, the finding index, a reason code and an expiry
time. It does not hold secrets, source text, paths, configuration or secret
hashes. Treat records as sensitive anyway, use references that reveal nothing,
and keep free-text notes in a separate system with access control.

`NativePolicyIdentity::sensitive_exact_bytes()` returns the full rule
configuration. Do not use it as a diagnostic value.

Reason codes are `AcceptedRisk`, `RemediationScheduled` and
`SyntheticFixture`.

## Stale records and partial scans

You pass the current time to `review`; the library never reads a clock. A
record expires when the current time is equal to or later than its expiry
time. The same records, input and time always give the same result.
`record_states()` reports each record as `Active`, `Expired`, `StalePolicy`,
`StaleOptions`, `StaleSource`, `StaleOccurrence` or
`UnobservedInPartialScan`. If several apply, the order of precedence is
policy, options, source, expiry, occurrence.

A finding that is missing from a partial scan was not seen in this scan. It is
not fixed. `ReviewResult::is_complete()` always comes from the scan, so a
review never turns a partial scan into a complete one. Acknowledged findings
stay in the finding list. The finding index tells repeated and decoded
findings apart. When the source changes, records are not moved to new line
numbers.

## Grouping findings for display

`PresentationGroups::for_scan` groups findings from one scan when different
rules found the same secret bytes at the same byte range. Every finding stays
in exactly one group. Findings in decoded text have no exact range, so each
one is in a group of its own. Equal secrets at different places stay in
different groups. Group numbers are for display only and are not stable
between scans. The groups keep the completion state of the scan, also for an
empty partial scan.

## Threads and limits in your program

The `rustleaks_core::triage` module documentation has compiled examples that
build an engine once, share it between scoped threads, set budgets, check
partial outcomes and read the numeric diagnostics. Your program decides the
number of threads, the source references, the clock, retries, storage and
output.

One review accepts at most 4,096 records and 100,000 findings. A policy
reference can be at most 1,024 bytes, a source reference 256 bytes and a rule
ID 128 bytes. References and rule IDs can use ASCII letters, digits and
`._-:/+=;|`. Policy references can also use `,`. A request over a limit fails
with an error instead of returning an incomplete review. These limits cover
review data only, so also set detection budgets before you scan.
