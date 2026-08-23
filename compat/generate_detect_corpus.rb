#!/usr/bin/env ruby
# frozen_string_literal: true

# Freeze direct, undecoded detector and location behavior from the pinned Go
# checkout. This corpus deliberately stops before allowlists, decoding,
# composites, generic suppression, redaction, baselines, and sessions.

require "base64"
require "digest"
require "fileutils"
require "json"
require "open3"
require "pathname"
require "tmpdir"

ROOT = Pathname(__dir__).parent
UPSTREAM = ROOT.parent.join("gitleaks")
ORACLE = ROOT.join("crates/rustleaks-compat/oracle")
FIXTURES = ROOT.join("compat/fixtures/upstream/testdata/config")
OUTPUT_ROOT = ROOT.join("compat/detect-corpus")
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
DEFAULT_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
PROTOCOL_VERSION = 1
EXPECTED_UPSTREAM_STATUS = ""

CHECK = ARGV.delete("--check")
abort "usage: #{$PROGRAM_NAME} [--check]" unless ARGV.empty?

GO_ENV = {
  "GOCACHE" => ENV.fetch("GOCACHE", File.join(Dir.tmpdir, "rustleaks-m4-oracle-gocache")),
  "GOMODCACHE" => ENV.fetch("GOMODCACHE", File.join(Dir.tmpdir, "rustleaks-go-mod-cache"))
}.freeze

def capture(*command, chdir:, stdin_data: "")
  output, error, status = Open3.capture3(GO_ENV, *command, chdir: chdir.to_s, stdin_data: stdin_data)
  abort "#{command.join(' ')} failed in #{chdir}:\n#{error}\n#{output}" unless status.success?
  output
end

def sha(bytes)
  Digest::SHA256.hexdigest(bytes)
end

def b64(bytes)
  Base64.strict_encode64(bytes.b)
end

def jsonl(records)
  records.map { |record| JSON.generate(record) + "\n" }.join
end

def toml_string(value)
  JSON.generate(value)
end

def config_for(id:, regex: nil, path: nil, description: nil, keywords: [], tags: [], secret_group: 0, entropy: 0.0)
  lines = ["title = \"M4 direct detector corpus\"", "", "[[rules]]"]
  lines << "id = #{toml_string(id)}"
  lines << "description = #{toml_string(description || id)}"
  lines << "regex = #{toml_string(regex)}" if regex
  lines << "path = #{toml_string(path)}" if path
  lines << "secretGroup = #{secret_group}" unless secret_group.zero?
  lines << "entropy = #{entropy}" unless entropy.zero?
  lines << "keywords = [#{keywords.map { |value| toml_string(value) }.join(', ')}]"
  lines << "tags = [#{tags.map { |value| toml_string(value) }.join(', ')}]"
  lines.join("\n") + "\n"
end

def add_case(records, id:, behavior_ids:, config:, content:, test_case_ids: [], assertion_ids: [], file: "", windows_file: "",
             symlink_file: "", commit: "", start_line: 0, author: "", email: "", date: "", message: "",
             remote_url: "", remote_platform: "", inherited: false, max_target_megabytes: 0, ignore_allow_marker: false)
  records << {
    "protocol_version" => PROTOCOL_VERSION,
    "id" => id,
    "behavior_ids" => behavior_ids,
    "test_case_ids" => test_case_ids,
    "assertion_ids" => assertion_ids,
    "use_default" => false,
    "config_base64" => b64(config),
    "fragment" => {
      "content_base64" => b64(content),
      "file_base64" => b64(file),
      "windows_file_base64" => b64(windows_file),
      "symlink_file_base64" => b64(symlink_file),
      "commit_base64" => b64(commit),
      "start_line" => start_line,
      "author_base64" => b64(author),
      "email_base64" => b64(email),
      "date_base64" => b64(date),
      "message_base64" => b64(message),
      "remote_url_base64" => b64(remote_url),
      "remote_platform" => remote_platform,
      "inherited_from_finding" => inherited
    },
    "options" => {
      "max_decode_depth" => 0,
      "max_target_megabytes" => max_target_megabytes,
      "redact_percent" => 0,
      "ignore_allow_marker" => ignore_allow_marker
    }
  }
end

requests = []
token_config = config_for(id: "token", regex: "TOKEN=([A-Z0-9]{4})", keywords: ["ToKeN"], tags: ["raw", "token"])
no_keyword_config = config_for(id: "always", regex: "TOKEN=([A-Z0-9]{4})", tags: ["raw"])

add_case(requests, id: "keyword-case-insensitive-hit", behavior_ids: ["M4-KEYWORD-001", "M4-KW-002"],
         config: token_config, content: "prefix token TOKEN=AB12")
add_case(requests, id: "keyword-miss-skips-matching-regex", behavior_ids: ["M4-KEYWORD-002"],
         config: config_for(id: "miss", regex: "TOKEN=([A-Z0-9]{4})", keywords: ["absent"]), content: "TOKEN=AB12")
add_case(requests, id: "keyword-any-hit", behavior_ids: ["M4-KEYWORD-003"],
         config: config_for(id: "any", regex: "TOKEN=([A-Z0-9]{4})", keywords: ["absent", "token"]), content: "TOKEN=AB12")
add_case(requests, id: "keywordless-rule-always-runs", behavior_ids: ["M4-KEYWORD-004", "M4-KW-001"],
         config: no_keyword_config, content: "TOKEN=AB12")
add_case(requests, id: "keyword-unicode-lowercase", behavior_ids: ["M4-KEYWORD-005"],
         config: config_for(id: "unicode-keyword", regex: "TOKEN=([A-Z0-9]{4})", keywords: ["É"]), content: "é TOKEN=AB12")
add_case(requests, id: "keyword-empty-does-not-activate", behavior_ids: ["M4-KW-004"],
         config: config_for(id: "empty-keyword", regex: "MATCH", keywords: [""]), content: "MATCH")
add_case(requests, id: "keyword-malformed-byte-activates-replacement", behavior_ids: ["M4-KW-005"],
         config: config_for(id: "replacement-keyword", regex: ".", keywords: ["�"]), content: [0xff].pack("C"))

contained_keyword_config = <<~TOML
  [[rules]]
  id = "keyword-he"
  regex = "SHE"
  keywords = ["he"]
  [[rules]]
  id = "keyword-she"
  regex = "SHE"
  keywords = ["she"]
TOML
add_case(requests, id: "keyword-contained-overlap", behavior_ids: ["M4-KW-003"],
         config: contained_keyword_config, content: "SHE")

duplicate_id_config = <<~TOML
  [[rules]]
  id = "duplicate"
  description = "first source rule"
  regex = "first"
  [[rules]]
  id = "duplicate"
  description = "final source rule"
  regex = "second"
TOML
add_case(requests, id: "duplicate-id-final-map-once", behavior_ids: ["M4-DUP-001"],
         config: duplicate_id_config, content: "first second")

distinct_duplicate_config = <<~TOML
  [[rules]]
  id = "distinct-a"
  regex = "TOKEN"
  [[rules]]
  id = "distinct-b"
  regex = "TOKEN"
TOML
add_case(requests, id: "distinct-rules-preserve-duplicate-findings", behavior_ids: ["M4-DUP-002"],
         config: distinct_duplicate_config, content: "TOKEN TOKEN")

simple_config = FIXTURES.join("simple.toml").binread
add_case(requests, id: "upstream-aws-direct", behavior_ids: ["M4-UPSTREAM-DETECT-001", "M4-CAPTURE-002"],
         config: simple_config, content: 'awsToken := \"AKIALALEMEL33243OLIA\"', file: "tmp.go", test_case_ids: ["TM-0079"])
add_case(requests, id: "upstream-sidekiq-env-explicit-capture", behavior_ids: ["M4-UPSTREAM-DETECT-002", "M4-CAPTURE-005", "M4-KEYWORD-001"],
         config: simple_config, content: "export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;", file: "tmp.sh",
         test_case_ids: ["TM-0081"])
add_case(requests, id: "upstream-sidekiq-env-quoted", behavior_ids: ["M4-UPSTREAM-DETECT-003", "M4-CAPTURE-005", "M4-KEYWORD-001"],
         config: simple_config, content: 'echo hello1; export BUNDLE_ENTERPRISE__CONTRIBSYS__COM="cafebabe:deadbeef" && echo hello2',
         file: "tmp.sh", test_case_ids: ["TM-0082"])
add_case(requests, id: "upstream-sidekiq-url-explicit-capture", behavior_ids: ["M4-UPSTREAM-DETECT-004", "M4-CAPTURE-005", "M4-KEYWORD-001"],
         config: simple_config,
         content: 'url = "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1"',
         file: "tmp.sh", test_case_ids: ["TM-0083"])
add_case(requests, id: "upstream-valid-allow-comment", behavior_ids: ["M4-UPSTREAM-DETECT-005", "M4-ALLOW-MARKER-001"],
         config: simple_config, content: 'awsToken := \"AKIALALEMEL33243OKIA\ // gitleaks:allow"', file: "tmp.go",
         test_case_ids: ["TM-0096"])
add_case(requests, id: "upstream-invalid-allow-comment", behavior_ids: ["M4-UPSTREAM-DETECT-006", "M4-ALLOW-MARKER-003"],
         config: simple_config,
         content: "awsToken := \\\"AKIALALEMEL33243OKIA\\\"\n\n                        // gitleaks:allow\"\n",
         file: "tmp.go", test_case_ids: ["TM-0092"])

add_case(requests, id: "upstream-path-only-rule", behavior_ids: ["M4-UPSTREAM-DETECT-007", "M4-PATH-001"],
         config: FIXTURES.join("valid/rule_path_only.toml").binread,
         content: 'const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"',
         file: "tmp.py", test_case_ids: ["TM-0093"])
add_case(requests, id: "upstream-entropy-rule", behavior_ids: ["M4-UPSTREAM-DETECT-008", "M4-ENTROPY-006", "M4-CAPTURE-005"],
         config: FIXTURES.join("valid/rule_entropy_group.toml").binread,
         content: "const Discord_Public_Key = \"e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5\"\n" \
                  "//const Discord_Public_Key = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
         file: "tmp.go", test_case_ids: ["TM-0095"])

path_only_unix = config_for(id: "test-rule", description: "", path: '(^|/)\.m2/settings\.xml')
path_only_windows = config_for(id: "test-rule", description: "", path: '(^|\\\\)\.m2\\\\settings\.xml')
path_regex_unix = config_for(id: "test-rule", description: "", path: '(^|/)\.m2/settings\.xml', regex: '<password>(.+?)</password>')
path_regex_windows = config_for(id: "test-rule", description: "", path: '(^|\\\\)\.m2\\\\settings\.xml', regex: '<password>(.+?)</password>')
add_case(requests, id: "path-only-normalized", behavior_ids: ["M4-PATH-001"], config: path_only_unix,
         content: "", file: ".m2/settings.xml", test_case_ids: ["TM-0166"])
add_case(requests, id: "path-only-windows-fallback", behavior_ids: ["M4-PATH-002"], config: path_only_windows,
         content: "", file: ".m2/settings.xml", windows_file: '.m2\settings.xml', test_case_ids: ["TM-0170"])
add_case(requests, id: "path-only-windows-missing-original", behavior_ids: ["M4-PATH-WINDOWS-MISS-001"], config: path_only_windows,
         content: "", file: ".m2/settings.xml", test_case_ids: ["TM-0169"])
add_case(requests, id: "path-plus-regex-normalized", behavior_ids: ["M4-PATH-REGEX-001", "M4-PATH-003", "M4-CAPTURE-001"], config: path_regex_unix,
         content: "<password>s3cr3t</password>", file: ".m2/settings.xml", test_case_ids: ["TM-0165"])
add_case(requests, id: "path-plus-regex-windows-fallback", behavior_ids: ["M4-PATH-REGEX-WINDOWS-001", "M4-CAPTURE-001"], config: path_regex_windows,
         content: "<password>s3cr3t</password>", file: ".m2/settings.xml", windows_file: '.m2\settings.xml', test_case_ids: ["TM-0168"])
add_case(requests, id: "path-plus-regex-path-miss", behavior_ids: ["M4-PATH-006", "M4-PATH-003"], config: path_regex_unix,
         content: "<password>s3cr3t</password>", file: "settings.xml")
add_case(requests, id: "path-plus-regex-content-miss", behavior_ids: ["M4-PATH-007"], config: path_regex_unix,
         content: "<username>admin</username>", file: ".m2/settings.xml")
add_case(requests, id: "path-only-unmatched-keyword", behavior_ids: ["M4-PATH-004"],
         config: config_for(id: "path-keyword", path: '\.py$', keywords: ["required-keyword"]),
         content: "arbitrary", file: "a.py")
path_bypass_content = "gitleaks:allow\n" + ("x" * (2_000_000 - 16))
add_case(requests, id: "path-only-bypasses-size-and-marker", behavior_ids: ["M4-PATH-005"],
         config: config_for(id: "path-bypass", path: '\.py$'), content: path_bypass_content,
         file: "a.py", max_target_megabytes: 1)

skip_config = <<~TOML
  [[rules]]
  id = "skip-report"
  regex = "MATCH"
  skipReport = true
TOML
add_case(requests, id: "skip-report-ordinary", behavior_ids: ["M4-SKIP-001"],
         config: skip_config, content: "MATCH")
add_case(requests, id: "skip-report-inherited", behavior_ids: ["M4-SKIP-002"],
         config: skip_config, content: "MATCH", inherited: true)

add_case(requests, id: "capture-full-match", behavior_ids: ["M4-CAPTURE-002"],
         config: config_for(id: "full", regex: "TOKEN=[A-Z]+"), content: "x TOKEN=ALPHA y")
add_case(requests, id: "capture-first-nonempty", behavior_ids: ["M4-CAPTURE-003", "M4-CAP-001"],
         config: config_for(id: "implicit", regex: 'TOKEN=(?:([0-9]+)|([A-Z]+))'), content: "TOKEN=ALPHA")
add_case(requests, id: "capture-empty-falls-back-full", behavior_ids: ["M4-CAPTURE-004"],
         config: config_for(id: "empty", regex: "TOKEN()"), content: "TOKEN")
add_case(requests, id: "capture-explicit-third", behavior_ids: ["M4-CAPTURE-005"],
         config: config_for(id: "explicit", regex: '((TOKEN)=([A-Z]+))', secret_group: 3), content: "TOKEN=ALPHA")
add_case(requests, id: "capture-explicit-unmatched-is-empty", behavior_ids: ["M4-CAPTURE-006"],
         config: config_for(id: "explicit-empty", regex: '(?:TOKEN=([A-Z]+)|(OTHER))', secret_group: 2), content: "TOKEN=ALPHA")
add_case(requests, id: "capture-explicit-matched-empty", behavior_ids: ["M4-CAP-002"],
         config: config_for(id: "explicit-matched-empty", regex: 'TOKEN=()', secret_group: 1), content: "TOKEN=")
add_case(requests, id: "capture-negative-group-uses-implicit", behavior_ids: ["M4-CAP-003"],
         config: config_for(id: "negative-group", regex: 'TOKEN=(?:([0-9]+)|([A-Z]+))', secret_group: -1), content: "TOKEN=ALPHA")
add_case(requests, id: "capture-rerun-after-lf-trim-fails", behavior_ids: ["M4-CAP-004"],
         config: config_for(id: "capture-rerun", regex: '\n(a)(bc)\n'), content: "\nabc\n")
add_case(requests, id: "capture-invalid-utf8-bytes", behavior_ids: ["M4-CAPTURE-007", "M4-BYTES-001"],
         config: config_for(id: "invalid-capture", regex: "TOKEN=(....)"), content: "TOKEN=".b + [0xff, 0x80, 0xc3, 0x28].pack("C*"))

add_case(requests, id: "entropy-equal-threshold-rejected", behavior_ids: ["M4-ENTROPY-001", "M4-ENT-001"],
         config: config_for(id: "entropy-equal", regex: "TOKEN=([A-Z]{4})", entropy: 1.0), content: "TOKEN=ABAB")
add_case(requests, id: "entropy-strictly-above-accepted", behavior_ids: ["M4-ENTROPY-002"],
         config: config_for(id: "entropy-above", regex: "TOKEN=([A-Z]{4})", entropy: 0.999999), content: "TOKEN=ABAB")
add_case(requests, id: "entropy-below-threshold-rejected", behavior_ids: ["M4-ENTROPY-003"],
         config: config_for(id: "entropy-below", regex: "TOKEN=([A-Z]{4})", entropy: 1.000001), content: "TOKEN=ABAB")
add_case(requests, id: "entropy-zero-disables-filter", behavior_ids: ["M4-ENTROPY-004", "M4-ENT-002"],
         config: config_for(id: "entropy-disabled", regex: "TOKEN=([A-Z]{4})"), content: "TOKEN=AAAA")
add_case(requests, id: "entropy-negative-zero-disables-filter", behavior_ids: ["M4-ENT-002"],
         config: "[[rules]]\nid = \"negative-zero\"\nregex = \"TOKEN=([A-Z]{4})\"\nentropy = -0.0\n",
         content: "TOKEN=ABAB")
add_case(requests, id: "entropy-unicode-runes-byte-denominator", behavior_ids: ["M4-ENTROPY-005", "M4-BYTES-002", "M4-ENT-004"],
         config: config_for(id: "entropy-unicode", regex: "TOKEN=(éa)"), content: "TOKEN=éa")
add_case(requests, id: "entropy-single-and-repeated-multibyte-rune", behavior_ids: ["M4-ENT-003"],
         config: config_for(id: "entropy-multibyte", regex: "TOKEN=(é+)"), content: "TOKEN=é\nTOKEN=éé")
add_case(requests, id: "entropy-valid-and-malformed-replacement-runes", behavior_ids: ["M4-ENT-005"],
         config: config_for(id: "entropy-malformed", regex: "TOKEN=(...)"),
         content: "TOKEN=".b + [0xef, 0xbf, 0xbd, 0xff, 0xff].pack("C*"))
add_case(requests, id: "entropy-counts-one-two-three", behavior_ids: ["M4-ENT-007"],
         config: config_for(id: "entropy-counts", regex: "TOKEN=(abbccc)"), content: "TOKEN=abbccc")

{"nan" => "NaN", "positive-infinity" => "+Inf", "negative-infinity" => "-Inf"}.each do |name, threshold|
  add_case(requests, id: "entropy-threshold-#{name}", behavior_ids: ["M4-ENT-006"],
           config: "[[rules]]\nid = \"entropy-#{name}\"\nregex = \"TOKEN=([A-Z]{4})\"\nentropy = \"#{threshold}\"\n",
           content: "TOKEN=ABAB")
end

location_config = config_for(id: "location", regex: "TOKEN=([A-Z0-9]{4})")
add_case(requests, id: "location-no-newline-zero-base", behavior_ids: ["M4-LOCATION-001"],
         config: location_config, content: "xx TOKEN=AB12 yy", test_case_ids: ["TM-0138"], assertion_ids: ["AS-LOCATION-01"])
add_case(requests, id: "location-start-line-offset", behavior_ids: ["M4-LOCATION-002"],
         config: location_config, content: "xx TOKEN=AB12 yy", start_line: 41)
add_case(requests, id: "location-second-line-includes-boundary-newline", behavior_ids: ["M4-LOCATION-003"],
         config: location_config, content: "head\nxx TOKEN=AB12 tail", test_case_ids: ["TM-0138"], assertion_ids: ["AS-LOCATION-02"])
add_case(requests, id: "location-utf8-byte-columns", behavior_ids: ["M4-LOCATION-004", "M4-BYTES-003"],
         config: location_config, content: "é💩 TOKEN=AB12")
add_case(requests, id: "location-invalid-byte-columns", behavior_ids: ["M4-LOCATION-005", "M4-BYTES-004"],
         config: location_config, content: [0xff, 0x80].pack("C*") + " TOKEN=AB12")
add_case(requests, id: "location-multiline-match", behavior_ids: ["M4-LOCATION-006"],
         config: config_for(id: "multiline", regex: "BEGIN\\nmiddle\\nEND"), content: "prefix BEGIN\nmiddle\nEND suffix")
add_case(requests, id: "location-final-line-without-newline", behavior_ids: ["M4-LOCATION-007"],
         config: location_config, content: "head\nTOKEN=AB12")
add_case(requests, id: "location-crlf-byte-columns", behavior_ids: ["M4-LOCATION-008"],
         config: location_config, content: "head\r\nxx TOKEN=AB12 tail")
add_case(requests, id: "location-multiple-nonoverlapping", behavior_ids: ["M4-LOCATION-009"],
         config: location_config, content: "TOKEN=AB12\nTOKEN=CD34\nTOKEN=EF56")
add_case(requests, id: "location-exact-utf8-byte-column", behavior_ids: ["M4-LOC-001"],
         config: config_for(id: "loc-utf8", regex: "X"), content: "éX")
add_case(requests, id: "location-final-unterminated-prefix-line", behavior_ids: ["M4-LOC-002"],
         config: config_for(id: "loc-final", regex: "b"), content: "a\nb")
add_case(requests, id: "location-terminated-leading-lf-line", behavior_ids: ["M4-LOC-003"],
         config: config_for(id: "loc-terminated", regex: "b"), content: "a\nb\n")
add_case(requests, id: "location-crlf-retains-cr", behavior_ids: ["M4-LOC-004"],
         config: config_for(id: "loc-crlf", regex: "b"), content: "a\r\nb\r\n")
add_case(requests, id: "location-start-line-seven", behavior_ids: ["M4-LOC-005"],
         config: config_for(id: "loc-offset", regex: "b"), content: "a\nb\n", start_line: 7)
add_case(requests, id: "location-empty-input-empty-match", behavior_ids: ["M4-LOC-006"],
         config: config_for(id: "loc-empty", regex: "(?:)"), content: "")

add_case(requests, id: "newline-trim-trailing", behavior_ids: ["M4-NEWLINE-001", "M4-LOCATION-010"],
         config: config_for(id: "trim-trailing", regex: "TOKEN=AB12\\n"), content: "TOKEN=AB12\nnext")
add_case(requests, id: "newline-trim-leading-and-trailing", behavior_ids: ["M4-NEWLINE-002", "M4-LOCATION-011"],
         config: config_for(id: "trim-both", regex: "\\nTOKEN=AB12\\n"), content: "head\nTOKEN=AB12\ntail")
add_case(requests, id: "newline-only-match-trims-empty", behavior_ids: ["M4-NEWLINE-003", "M4-LOCATION-012"],
         config: config_for(id: "trim-empty", regex: "\\n+"), content: "head\n\ntail")
add_case(requests, id: "newline-trim-exact-trailing", behavior_ids: ["M4-TRIM-001"],
         config: config_for(id: "trim-exact-trailing", regex: "abc\\n"), content: "abc\n")
add_case(requests, id: "newline-trim-exact-leading-skew", behavior_ids: ["M4-TRIM-002"],
         config: config_for(id: "trim-exact-both", regex: "\\nabc\\n"), content: "\nabc\n")
add_case(requests, id: "newline-carriage-return-not-trimmed", behavior_ids: ["M4-TRIM-003"],
         config: config_for(id: "trim-cr", regex: "\\rabc\\r"), content: "\rabc\r")
add_case(requests, id: "newline-trim-exact-empty", behavior_ids: ["M4-TRIM-004"],
         config: config_for(id: "trim-exact-empty", regex: "\\n"), content: "\n")

add_case(requests, id: "allow-marker-same-line-suppressed", behavior_ids: ["M4-ALLOW-MARKER-001", "M4-ALLOW-001"],
         config: location_config, content: "TOKEN=AB12 # gitleaks:allow")
add_case(requests, id: "allow-marker-case-sensitive", behavior_ids: ["M4-ALLOW-MARKER-002", "M4-ALLOW-002"],
         config: location_config, content: "TOKEN=AB12 # GITLEAKS:ALLOW")
add_case(requests, id: "allow-marker-next-line-not-suppressed", behavior_ids: ["M4-ALLOW-MARKER-003"],
         config: location_config, content: "TOKEN=AB12\n# gitleaks:allow")
add_case(requests, id: "allow-marker-toggle-reports", behavior_ids: ["M4-ALLOW-MARKER-004", "M4-ALLOW-001"],
         config: location_config, content: "TOKEN=AB12 # gitleaks:allow", ignore_allow_marker: true)
marker_location_config = config_for(id: "marker-location", regex: "secret")
add_case(requests, id: "allow-marker-prefix-final-unterminated", behavior_ids: ["M4-ALLOW-003"],
         config: marker_location_config, content: "gitleaks:allow\nsecret")
add_case(requests, id: "allow-marker-prefix-terminated", behavior_ids: ["M4-ALLOW-004"],
         config: marker_location_config, content: "gitleaks:allow\nsecret\n")

near_limit = "TOKEN=AB12\n" + ("x" * (1_999_999 - 11))
over_limit = "TOKEN=AB12\n" + ("x" * (2_000_000 - 11))
one_megabyte = "TOKEN=AB12\n" + ("x" * (1_000_000 - 11))
add_case(requests, id: "max-target-one-megabyte-accepted", behavior_ids: ["M4-MAX-001"],
         config: location_config, content: one_megabyte, max_target_megabytes: 1)
add_case(requests, id: "max-target-truncated-megabyte-accepted", behavior_ids: ["M4-MAX-TARGET-001", "M4-MAX-001"],
         config: location_config, content: near_limit, max_target_megabytes: 1)
add_case(requests, id: "max-target-next-megabyte-skipped", behavior_ids: ["M4-MAX-TARGET-002", "M4-MAX-002"],
         config: location_config, content: over_limit, max_target_megabytes: 1)
add_case(requests, id: "max-target-zero-disabled", behavior_ids: ["M4-MAX-003"],
         config: location_config, content: over_limit, max_target_megabytes: 0)
add_case(requests, id: "max-target-negative-disabled", behavior_ids: ["M4-MAX-003"],
         config: location_config, content: over_limit, max_target_megabytes: -1)

metadata_content = [0xff].pack("C") + " TOKEN=AB12"
add_case(requests, id: "full-finding-byte-metadata", behavior_ids: ["M4-FINDING-001", "M4-BYTES-005"],
         config: location_config, content: metadata_content, file: "src/".b + [0xff].pack("C"),
         windows_file: "C:\\src\\".b + [0x80].pack("C"), symlink_file: "link/".b + [0xfe].pack("C"),
         commit: "abcdef1234567890", start_line: 7, author: "A".b + [0xff].pack("C"),
         email: "e".b + [0x80].pack("C") + "@example.test", date: "2026-08-22T00:00:00Z",
         message: "m".b + [0xfe].pack("C"), remote_platform: "none")

abort "duplicate detector request IDs" unless requests.map { |row| row.fetch("id") }.uniq.length == requests.length
abort "SCM metadata escaped the M4 direct-detector scope" unless requests.all? { |request|
  request.dig("fragment", "remote_url_base64").empty? && ["", "none"].include?(request.dig("fragment", "remote_platform"))
}

deterministic_matrix_ids = %w[
  M4-KW-001 M4-KW-002 M4-KW-003 M4-KW-004 M4-KW-005
  M4-DUP-001 M4-DUP-002
  M4-PATH-001 M4-PATH-002 M4-PATH-003 M4-PATH-004 M4-PATH-005
  M4-SKIP-001 M4-SKIP-002
  M4-MAX-001 M4-MAX-002 M4-MAX-003
  M4-TRIM-001 M4-TRIM-002 M4-TRIM-003 M4-TRIM-004
  M4-CAP-001 M4-CAP-002 M4-CAP-003 M4-CAP-004
  M4-ENT-001 M4-ENT-002 M4-ENT-003 M4-ENT-004 M4-ENT-005 M4-ENT-006 M4-ENT-007
  M4-LOC-001 M4-LOC-002 M4-LOC-003 M4-LOC-004 M4-LOC-005 M4-LOC-006
  M4-ALLOW-001 M4-ALLOW-002 M4-ALLOW-003 M4-ALLOW-004
].freeze
matrix_rows = deterministic_matrix_ids.map do |matrix_id|
  request_ids = requests.each_with_object([]) do |request, ids|
    ids << request.fetch("id") if request.fetch("behavior_ids").include?(matrix_id)
  end
  abort "uncovered deterministic semantic matrix row #{matrix_id}" if request_ids.empty?
  {"id" => matrix_id, "status" => "covered", "request_ids" => request_ids}
end
matrix_rows << {
  "id" => "M4-ENT-008",
  "status" => "outcome-set-resolved",
  "request_ids" => [],
  "evidence" => "go test ./... -run TestDirectDetectorEntropyThresholdOutcomeSet",
  "rust_evidence" => "cargo test -p rustleaks-core --lib engine::tests::canonical_entropy_is_one_proven_go_admissible_value",
  "decision" => "D-0012",
  "coordinator_decision_required" => false,
  "reason" => "Go map-order summation changes the threshold predicate while every accepted finding has identical f32 bits"
}
matrix_coverage = {
  "schema_version" => 1,
  "source" => "docs/COMPATIBILITY.md",
  "deterministic_row_count" => deterministic_matrix_ids.length,
  "covered_deterministic_row_count" => matrix_rows.count { |row| row.fetch("status") == "covered" },
  "decision_row_count" => 1,
  "rows" => matrix_rows
}

actual_revision = capture("git", "rev-parse", "HEAD", chdir: UPSTREAM).strip
abort "upstream revision changed: #{actual_revision}" unless actual_revision == REVISION
actual_status = capture("git", "status", "--porcelain", "--untracked-files=no", chdir: UPSTREAM)
abort "upstream status changed:\n#{actual_status}" unless actual_status == EXPECTED_UPSTREAM_STATUS
actual_default_sha = sha(UPSTREAM.join("config/gitleaks.toml").binread)
abort "default config hash changed: #{actual_default_sha}" unless actual_default_sha == DEFAULT_SHA256

capture("go", "test", "-count=1", "./...", chdir: ORACLE)
requests_bytes = jsonl(requests)
outcomes_bytes = capture("go", "run", ".", "--detect", chdir: ORACLE, stdin_data: requests_bytes)
outcomes = outcomes_bytes.lines(chomp: true).reject(&:empty?).map { |line| JSON.parse(line) }
abort "oracle returned #{outcomes.length} outcomes for #{requests.length} requests" unless outcomes.length == requests.length

requests.zip(outcomes).each do |request, outcome|
  abort "oracle response ID mismatch for #{request.fetch('id')}" unless outcome.fetch("id") == request.fetch("id")
  abort "oracle mode mismatch for #{request.fetch('id')}" unless outcome.fetch("oracle_mode") == "detect"
  abort "oracle revision mismatch for #{request.fetch('id')}" unless outcome.fetch("upstream_revision") == REVISION
  abort "oracle config pin mismatch for #{request.fetch('id')}" unless outcome.fetch("default_config_sha256") == DEFAULT_SHA256
  abort "oracle behavior IDs changed for #{request.fetch('id')}" unless outcome.fetch("behavior_ids") == request.fetch("behavior_ids")
  abort "oracle test IDs changed for #{request.fetch('id')}" unless outcome.fetch("test_case_ids") == request.fetch("test_case_ids")
  abort "oracle assertion IDs changed for #{request.fetch('id')}" unless outcome.fetch("assertion_ids") == request.fetch("assertion_ids")
  abort "oracle error for #{request.fetch('id')}: #{outcome['error']}" unless outcome["error"].nil?
  abort "SCM link escaped the M4 direct-detector scope for #{request.fetch('id')}" unless outcome.fetch("findings").all? { |finding| finding.fetch("link_base64").empty? }
  input = Base64.strict_decode64(request.dig("fragment", "content_base64"))
  config = Base64.strict_decode64(request.fetch("config_base64"))
  abort "oracle input hash changed for #{request.fetch('id')}" unless outcome.fetch("input_sha256") == sha(input)
  abort "oracle config hash changed for #{request.fetch('id')}" unless outcome.fetch("config_sha256") == sha(config)
  abort "oracle byte accounting changed for #{request.fetch('id')}" unless outcome.fetch("total_bytes") == input.bytesize
end

outcome_by_id = outcomes.each_with_object({}) { |outcome, index| index[outcome.fetch("id")] = outcome }
expected_finding_counts = {
  "keyword-empty-does-not-activate" => 0,
  "keyword-malformed-byte-activates-replacement" => 1,
  "keyword-contained-overlap" => 2,
  "duplicate-id-final-map-once" => 1,
  "distinct-rules-preserve-duplicate-findings" => 4,
  "path-only-unmatched-keyword" => 0,
  "path-only-bypasses-size-and-marker" => 1,
  "skip-report-ordinary" => 0,
  "skip-report-inherited" => 1,
  "capture-first-nonempty" => 1,
  "capture-explicit-matched-empty" => 1,
  "capture-negative-group-uses-implicit" => 1,
  "capture-rerun-after-lf-trim-fails" => 1,
  "entropy-equal-threshold-rejected" => 0,
  "entropy-zero-disables-filter" => 1,
  "entropy-negative-zero-disables-filter" => 1,
  "entropy-single-and-repeated-multibyte-rune" => 2,
  "entropy-valid-and-malformed-replacement-runes" => 1,
  "entropy-counts-one-two-three" => 1,
  "entropy-threshold-nan" => 1,
  "entropy-threshold-positive-infinity" => 0,
  "entropy-threshold-negative-infinity" => 1,
  "location-exact-utf8-byte-column" => 1,
  "location-final-unterminated-prefix-line" => 1,
  "location-terminated-leading-lf-line" => 1,
  "location-crlf-retains-cr" => 1,
  "location-start-line-seven" => 1,
  "location-empty-input-empty-match" => 1,
  "newline-trim-exact-trailing" => 1,
  "newline-trim-exact-leading-skew" => 1,
  "newline-carriage-return-not-trimmed" => 1,
  "newline-trim-exact-empty" => 1,
  "allow-marker-same-line-suppressed" => 0,
  "allow-marker-toggle-reports" => 1,
  "allow-marker-case-sensitive" => 1,
  "allow-marker-prefix-final-unterminated" => 0,
  "allow-marker-prefix-terminated" => 1,
  "max-target-one-megabyte-accepted" => 1,
  "max-target-truncated-megabyte-accepted" => 1,
  "max-target-next-megabyte-skipped" => 0,
  "max-target-zero-disabled" => 1,
  "max-target-negative-disabled" => 1
}
expected_finding_counts.each do |id, expected|
  actual = outcome_by_id.fetch(id).fetch("findings").length
  abort "#{id} finding count changed: got #{actual}, want #{expected}" unless actual == expected
end

def only_finding(outcome_by_id, id)
  outcome_by_id.fetch(id).fetch("findings").fetch(0)
end

expected_secrets = {
  "capture-first-nonempty" => "ALPHA",
  "capture-explicit-matched-empty" => "",
  "capture-negative-group-uses-implicit" => "ALPHA",
  "capture-rerun-after-lf-trim-fails" => "abc"
}
expected_secrets.each do |id, expected|
  actual = Base64.strict_decode64(only_finding(outcome_by_id, id).fetch("secret_base64"))
  abort "#{id} secret changed: got #{actual.inspect}, want #{expected.inspect}" unless actual == expected
end

expected_entropy_bits = {
  "entropy-unicode-runes-byte-denominator" => [0x3f874009],
  "entropy-single-and-repeated-multibyte-rune" => [0x3f000000, 0x3f000000],
  "entropy-counts-one-two-three" => [0x3fbac55c]
}
expected_entropy_bits.each do |id, expected|
  actual = outcome_by_id.fetch(id).fetch("findings").map { |finding| finding.fetch("entropy_bits") }
  abort "#{id} entropy bits changed: got #{actual.inspect}, want #{expected.inspect}" unless actual == expected
end

empty_location = only_finding(outcome_by_id, "location-empty-input-empty-match")
abort "empty location reversed columns changed" unless [empty_location.fetch("start_column"), empty_location.fetch("end_column")] == [1, 0]
cr_finding = only_finding(outcome_by_id, "newline-carriage-return-not-trimmed")
abort "CR was unexpectedly trimmed" unless Base64.strict_decode64(cr_finding.fetch("match_base64")) == "\rabc\r"
metadata_request = requests.find { |request| request.fetch("id") == "full-finding-byte-metadata" }
metadata_finding = only_finding(outcome_by_id, "full-finding-byte-metadata")
{
  "file_base64" => "file_base64",
  "symlink_file_base64" => "symlink_file_base64",
  "commit_base64" => "commit_base64",
  "author_base64" => "author_base64",
  "email_base64" => "email_base64",
  "date_base64" => "date_base64",
  "message_base64" => "message_base64"
}.each do |finding_field, request_field|
  expected = metadata_request.fetch("fragment").fetch(request_field)
  actual = metadata_finding.fetch(finding_field)
  abort "full metadata field #{finding_field} changed" unless actual == expected
end

metadata = requests.zip(outcomes).map do |request, outcome|
  request_line = JSON.generate(request) + "\n"
  outcome_line = JSON.generate(outcome) + "\n"
  {
    "schema_version" => 1,
    "id" => request.fetch("id"),
    "behavior_ids" => request.fetch("behavior_ids"),
    "test_case_ids" => request.fetch("test_case_ids"),
    "assertion_ids" => request.fetch("assertion_ids"),
    "content_bytes" => Base64.strict_decode64(request.dig("fragment", "content_base64")).bytesize,
    "request_sha256" => sha(request_line),
    "outcome_sha256" => sha(outcome_line),
    "finding_count" => outcome.fetch("findings").length
  }
end
metadata_bytes = jsonl(metadata)

files = {
  "requests-v1.jsonl" => requests_bytes,
  "outcomes-v1.jsonl" => outcomes_bytes,
  "request-metadata-v1.jsonl" => metadata_bytes,
  "matrix-coverage-v1.json" => JSON.pretty_generate(matrix_coverage) + "\n"
}
manifest = {
  "schema_version" => 1,
  "protocol_version" => PROTOCOL_VERSION,
  "oracle_mode" => "detect",
  "upstream_revision" => REVISION,
  "default_config_sha256" => DEFAULT_SHA256,
  "go_version" => outcomes.first.fetch("go_version"),
  "scope" => [
    "raw-direct-fragment", "effective-rule-map-and-duplicates", "keyword-prefilter",
    "path-only-and-path-plus-regex", "skip-report", "capture-selection", "entropy-threshold",
    "byte-location-and-line", "newline-trim", "gitleaks-allow-toggle", "max-target"
  ],
  "excluded" => ["allowlists", "decoding", "composites", "generic-suppression", "redaction", "baseline", "session"],
  "request_count" => requests.length,
  "finding_count" => outcomes.sum { |outcome| outcome.fetch("findings").length },
  "zero_finding_request_count" => outcomes.count { |outcome| outcome.fetch("findings").empty? },
  "behavior_id_count" => requests.flat_map { |request| request.fetch("behavior_ids") }.uniq.length,
  "linked_test_case_id_count" => requests.flat_map { |request| request.fetch("test_case_ids") }.uniq.length,
  "linked_assertion_id_count" => requests.flat_map { |request| request.fetch("assertion_ids") }.uniq.length,
  "deterministic_matrix_row_count" => deterministic_matrix_ids.length,
  "covered_deterministic_matrix_row_count" => matrix_rows.count { |row| row.fetch("status") == "covered" },
  "resolved_outcome_set_matrix_row_count" => 1,
  "maximum_content_bytes" => metadata.map { |row| row.fetch("content_bytes") }.max,
  "files" => files.transform_values { |bytes| { "sha256" => sha(bytes), "records" => bytes.lines.count } }
}
files["manifest-v1.json"] = JSON.pretty_generate(manifest) + "\n"

if CHECK
  files.each do |name, bytes|
    path = OUTPUT_ROOT.join(name)
    abort "missing generated detector corpus file #{path}" unless path.file?
    abort "generated detector corpus differs: #{path}" unless path.binread == bytes
  end
else
  FileUtils.mkdir_p(OUTPUT_ROOT)
  files.each { |name, bytes| OUTPUT_ROOT.join(name).binwrite(bytes) }
end

final_status = capture("git", "status", "--porcelain", "--untracked-files=no", chdir: UPSTREAM)
abort "upstream status changed during generation:\n#{final_status}" unless final_status == EXPECTED_UPSTREAM_STATUS

puts "#{CHECK ? 'checked' : 'wrote'} #{requests.length} detector requests (#{sha(outcomes_bytes)})"
