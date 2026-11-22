# Decoder corpus

These cases cover the decoders and detection on decoded text. The decoders
are percent encoding, Unicode escapes, hex and base64 (standard and
URL-safe). The cases test the order in which overlapping candidates are
chosen, repeated decode passes, segment ranges and their mapping back to the
original text, tags, the current line, `MaxDecodeDepth`, and malformed or
non-UTF-8 input.

## Files

- `requests-v1.jsonl`: 263 cases. `operation` is `decode` (204 cases) or
  `detect` (59 cases).
  - A `decode` case runs the decoder on each input in `inputs_base64` for up
    to `pass_limit` passes. `decoder_scope` is `shared` (one decoder and its
    cache for all inputs) or `isolated`. `probe_ranges` lists extra ranges
    whose mapping is checked. Cases taken from the upstream `TestDecode`
    table also record `source_case`, `source_transform` and
    `expected_full_decode_base64`.
  - A `detect` case scans `fragment` with `options` and the configuration in
    `config_base64` or `config_fixture` (a file under
    `../fixtures/upstream/testdata/config/`).
- `outcomes-v1.jsonl`: the expected result of each case. For `decode`,
  `runs` holds one entry per input, and each entry lists its `passes`:
  input and output bytes, decoded `segments` with their ranges, tags, the
  current line and the probe results. For `detect`, `findings` lists the
  expected findings.
- `coverage-v1.json`, `request-metadata-v1.jsonl`,
  `negative-controls-v1.json` and `manifest-v1.json`: behavior notes, counts
  and hashes from when the cases were recorded. No test reads them.

## Tests

- `//crates/rustleaks-core:rustleaks_core_unit_test` replays the `decode`
  cases (in `src/decoder/mod.rs`) and checks that there are 204 of them.
- `//crates/rustleaks-core:detect_corpus_test` replays the `detect` cases.

## Origin and changes

The cases were recorded from Gitleaks at commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` (MIT, see the repository
[`NOTICE`](../../NOTICE)). The outcomes are the expected Rustleaks behavior.
To change a case, edit the JSONL by hand or with a small script in a
reviewed change, keep byte fields in base64, and write the expected value
from the intended behavior. See [Changing a case](../README.md#changing-a-case).
