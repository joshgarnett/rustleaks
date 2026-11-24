# Detect corpus

These cases cover detection on one fragment, with no decoding and no
redaction. They test keywords, path-only and path plus regex rules
(including Windows paths), `skipReport`, secret group selection and entropy
thresholds. They also test byte-based lines and columns, newline trimming,
the `gitleaks:allow` marker and the target size limit.

## Files

- `requests-v1.jsonl`: 84 cases. Each case scans `fragment` with `options`
  and the TOML in `config_base64`. `fragment.content_base64` is the scanned
  text. The other `fragment` fields hold the path, commit metadata and the
  remote. `options` sets `max_decode_depth` (always 0 here),
  `max_target_megabytes`, `redact_percent` and `ignore_allow_marker`.
- `outcomes-v1.jsonl`: the expected result of each case. `findings` lists
  every expected finding, with duplicates. `entropy_bits` is the entropy as
  the bits of a 32-bit float. `fingerprint_base64` is empty, because a scan
  of one fragment does not set fingerprints.
- `bootstrap-requests.jsonl` and `bootstrap-outcomes.jsonl`: four more cases
  in the same layout. `custom-basic` has full commit and remote metadata,
  `custom-invalid-utf8` has invalid UTF-8 content, `custom-allow-marker` has
  an allow marker, and `malformed-regex-panic` has an invalid regular
  expression. The tests list these IDs in this order.
- `matrix-coverage-v1.json`, `request-metadata-v1.jsonl` and
  `manifest-v1.json`: coverage notes, counts and hashes from when the cases
  were recorded. No test reads them.

## Tests

- `//crates/rustleaks-core:detect_corpus_test` replays `requests-v1.jsonl`
  and the first three bootstrap cases, and checks that
  `malformed-regex-panic` is a configuration error in Rustleaks.
- `//crates/rustleaks-sources:git_scm_test` builds the source link of
  `custom-basic` and compares it with the recorded `link_base64`.

## Origin and changes

The cases were recorded from Gitleaks at commit `b58d3f1` (MIT, see
[`NOTICE`](../../NOTICE)). See [Changing a case](../README.md#changing-a-case).
