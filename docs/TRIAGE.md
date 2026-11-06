# Native review and embedding

Triage is opt-in and separate from legacy baseline and ignore behavior. It
classifies every original occurrence as new or acknowledged. An acknowledgement
records a workflow decision, never a statement that a credential is safe. It
does not delete a finding, change detection, or certify that a scan completed.

## Identity and persistence

`ReviewPolicy::for_builtin` uses the checked immutable built-in configuration
references, including policy/package versions, pinned upstream/default hashes,
the selected packaged rules hash, and enabled extensions. Custom packs require
`ReviewPolicy::caller_bound` with a persistent reference from an immutable
caller-controlled registry or an established keyed cryptographic construction.
The caller must bind that reference to every exact native identity byte. A
human pack name or version alone is insufficient. Core compares the actual
scan identity to the bound identity before each review.

`ReviewSource::caller_bound` requires a non-sensitive reference to exact source
bytes and source metadata in the caller's immutable store. Changed source,
including a line insertion or replacement at the same location, requires a new
reference. A file path or a line number alone is insufficient. Reusing a source
reference for changed bytes can incorrectly acknowledge a replacement
credential. Core cannot verify an external registry across restarts. Do not use
an unsalted hash of a credential as a reference. Actual decode, target-size,
redaction, and allow-marker options are stored in each record and compared
against the actual scan options independently of the source reference.

Version-one records retain policy/source references, rule IDs, numeric
locations, available exact byte ranges, original finding index, a finite reason
code and exclusive Unix-second expiry. They contain no copied credentials,
source text, paths, configuration, or secret hashes. These retained identifiers
are still metadata: use non-sensitive references, keep free-form notes in an
access-controlled review system, and access-control review artifacts. Native
identity's explicit sensitive-byte export contains configuration and is not a
diagnostic projection.

The unpublished report crate provides bounded JSON record readers/writers and
a separate projection containing only numeric locations and finite status
codes. Artifact readers reject unknown versions, unknown fields, invalid
metadata, duplicate records and resource-limit excess. Writing does not flush
or atomically replace a destination; the storage adapter owns that operation.

## Stale decisions and partial results

The caller supplies current Unix time. Records expire at `now >= expires_at`.
Classification is deterministic for equal records, inputs and time. Changed
policy, scan options, source reference, expired records and missing occurrences
receive separate statuses. For multiple applicable stale conditions, policy
takes precedence, followed by options, source, expiry and occurrence.

An absent occurrence in a partial scan is unobserved, not resolved. Acknowledged
findings remain in the original finding slice. The complete flag always comes
from the actual scan. Review state never upgrades a partial result to complete.
Finding indices disambiguate repeated and decoded occurrences. A source change
does not automatically remap records across line shifts.

## Presentation and embedding

`PresentationGroups::for_scan` groups related provider/generic detections only
when their exact secret byte ranges and secret bytes agree within one scan.
Keys remain process-local and are discarded after construction. Every original
finding and index remains accessible, with each index in exactly one group.
Different spans remain different occurrences even for equal credentials.
Decoded findings have unavailable exact byte ranges and remain singleton groups.
Group numbers are local presentation indices, not persistent identities.
Groups retain the original scan's completion and termination, including an
empty partial result.

The `rustleaks_core::triage` module contains compiled examples that construct an
engine once, reuse it on caller-managed scoped threads, set decoded-byte/work/
finding budgets, inspect actual partial outcomes, and project numeric
diagnostics. Applications own thread count, source identity, clocks, retries,
persistence and output destinations. Core starts no threads and performs no I/O.

## Limits

One operation accepts at most 4,096 review records and 100,000 findings. Policy
references are at most 1,024 bytes, source references 256 bytes and rule IDs 128
bytes. Identifier syntax is restricted to ASCII letters, digits and
`._-:/+=;|`. Reason codes are finite; arbitrary notes are excluded. JSON artifacts
are limited to 8 MiB. Over-limit operations fail explicitly rather than return
silently incomplete review state. These caps bound retained metadata; callers
should also apply detection and source budgets before constructing findings.
