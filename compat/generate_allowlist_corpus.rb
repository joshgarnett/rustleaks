#!/usr/bin/env ruby
# frozen_string_literal: true

# Freeze compiled Allowlist method behavior and raw direct-detector allowlist
# behavior from the pinned ordinary Go build. Every request is executed by a
# fresh oracle process so package/global state cannot leak between records.

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
OUTPUT_ROOT = ROOT.join("compat/allowlist-corpus")
ASSERTION_CORPUS = ROOT.join("compat/assertion-corpus/assertions.jsonl")
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
DEFAULT_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
PROTOCOL_VERSION = 1
EXPECTED_UPSTREAM_STATUS = ""
AL_IDS = (1..18).map { |index| format("AL-%03d", index) }.freeze
ASSERTION_IDS = %w[
  AS-CFG-COMMIT-01 AS-CFG-COMMIT-02 AS-CFG-COMMIT-03
  AS-CFG-PATH-01 AS-CFG-PATH-02 AS-CFG-REGEX-01 AS-CFG-REGEX-02
  AS-CFG-VALIDATE-EMPTY AS-CFG-VALIDATE-DEDUP
].freeze
LEAF_TEST_CASE_IDS = (
  (74..77).map { |index| format("TM-%04d", index) } +
  (85..89).map { |index| format("TM-%04d", index) } +
  (102..115).map { |index| format("TM-%04d", index) } +
  (156..163).map { |index| format("TM-%04d", index) }
).freeze
AGGREGATOR_TEST_CASE_IDS = %w[TM-0028 TM-0032 TM-0033 TM-0072 TM-0101 TM-0155].freeze

CHECK = ARGV.delete("--check")
abort "usage: #{$PROGRAM_NAME} [--check]" unless ARGV.empty?

GO_ENV = {
  "GOCACHE" => ENV.fetch("GOCACHE", File.join(Dir.tmpdir, "rustleaks-m5-oracle-gocache")),
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

def method_case(records, id:, behaviors:, method:, input:, allowlist: {}, validate: false,
                validate_count: 0, nil_allowlist: false, base_global: false, assertions: [])
  encoded = {
    "description_base64" => b64(allowlist.fetch(:description, "")),
    "condition" => allowlist.fetch(:condition, ""),
    "commits_base64" => allowlist.fetch(:commits, []).map { |value| b64(value) },
    "paths_base64" => allowlist.fetch(:paths, []).map { |value| b64(value) },
    "regex_target" => allowlist.fetch(:regex_target, ""),
    "regexes_base64" => allowlist.fetch(:regexes, []).map { |value| b64(value) },
    "stopwords_base64" => allowlist.fetch(:stopwords, []).map { |value| b64(value) }
  }
  records << {
    "protocol_version" => PROTOCOL_VERSION,
    "id" => id,
    "behavior_ids" => behaviors,
    "test_case_ids" => [],
    "assertion_ids" => assertions,
    "operation" => "method",
    "method" => method,
    "validate" => validate,
    "validate_count" => validate_count,
    "nil_allowlist" => nil_allowlist,
    "base_global" => base_global,
    "allowlist" => encoded,
    "input_base64" => b64(input)
  }
end

def detect_case(records, id:, behaviors:, content:, test_case_ids: [], config: nil, fixture: nil,
                bundle: nil, entry: nil, file: "", windows_file: "", commit: "", ignore_allow_marker: false,
                inherited_from_finding: false)
  abort "#{id}: exactly one config source required" unless [config, fixture, bundle].compact.length == 1
  records << {
    "protocol_version" => PROTOCOL_VERSION,
    "id" => id,
    "behavior_ids" => behaviors,
    "test_case_ids" => test_case_ids,
    "assertion_ids" => [],
    "operation" => "detect",
    "use_default" => false,
    "config_base64" => config ? b64(config) : "",
    "config_fixture" => fixture || "",
    "config_entry" => entry || "",
    "config_files" => (bundle || {}).map { |path, content| { "path" => path, "content_base64" => b64(content) } },
    "fragment" => {
      "content_base64" => b64(content),
      "file_base64" => b64(file),
      "windows_file_base64" => b64(windows_file),
      "symlink_file_base64" => "",
      "commit_base64" => b64(commit),
      "start_line" => 0,
      "author_base64" => "",
      "email_base64" => "",
      "date_base64" => "",
      "message_base64" => "",
      "remote_url_base64" => "",
      "remote_platform" => "",
      "inherited_from_finding" => inherited_from_finding
    },
    "options" => {
      "max_decode_depth" => 0,
      "max_target_megabytes" => 0,
      "redact_percent" => 0,
      "ignore_allow_marker" => ignore_allow_marker
    }
  }
end

def simple_config(global_tables: "", rule_tables: "", regex: "TOKEN=([A-Za-z0-9_-]+)", id: "test", secret_group: 1)
  <<~TOML
    [[rules]]
    id = #{JSON.generate(id)}
    regex = #{JSON.generate(regex)}
    secretGroup = #{secret_group}
    #{rule_tables}
    #{global_tables}
  TOML
end

requests = []

# Public method and validation assertions. Top-level TM identities are
# aggregators, so requests link their AS-* leaves instead of claiming the root.
method_case(requests, id: "validate-empty", behaviors: ["AL-001", "AL-017"], method: "commit", input: "x",
            validate: true, assertions: ["AS-CFG-VALIDATE-EMPTY"])
method_case(requests, id: "validate-dedup-idempotent", behaviors: ["AL-001", "AL-018"], method: "stopword", input: "STOPWORDB",
            allowlist: { commits: %w[commitA commitB commitA], stopwords: %w[stopwordA stopwordB stopwordA] },
            validate_count: 2, assertions: ["AS-CFG-VALIDATE-DEDUP"])
method_case(requests, id: "commit-assert-hit-unvalidated", behaviors: ["AL-002"], method: "commit", input: "commitA",
            allowlist: { commits: ["commitA"] }, assertions: ["AS-CFG-COMMIT-01"])
method_case(requests, id: "commit-assert-miss-unvalidated", behaviors: ["AL-002"], method: "commit", input: "commitA",
            allowlist: { commits: ["commitB"] }, assertions: ["AS-CFG-COMMIT-02"])
method_case(requests, id: "commit-assert-empty-unvalidated", behaviors: ["AL-002", "AL-017"], method: "commit", input: "",
            allowlist: { commits: ["commitB"] }, assertions: ["AS-CFG-COMMIT-03"])
method_case(requests, id: "commit-validated-trim-case-hit-empty-payload", behaviors: ["AL-001", "AL-002", "AL-018"],
            method: "commit", input: "COMMITA", allowlist: { commits: [" CommitA "] }, validate: true)
method_case(requests, id: "commit-validated-query-not-trimmed", behaviors: ["AL-002", "AL-018"], method: "commit",
            input: " commita ", allowlist: { commits: [" CommitA "] }, validate: true)
method_case(requests, id: "commit-unvalidated-case-sensitive-payload", behaviors: ["AL-002", "AL-018"], method: "commit",
            input: "CommitA", allowlist: { commits: ["CommitA"] })
method_case(requests, id: "commit-unvalidated-case-miss", behaviors: ["AL-002"], method: "commit",
            input: "commita", allowlist: { commits: ["CommitA"] })

method_case(requests, id: "path-assert-hit", behaviors: ["AL-003"], method: "path", input: "a path",
            allowlist: { paths: ["path"] }, assertions: ["AS-CFG-PATH-01"])
method_case(requests, id: "path-assert-miss", behaviors: ["AL-003"], method: "path", input: "a ???",
            allowlist: { paths: ["path"] }, assertions: ["AS-CFG-PATH-02"])
method_case(requests, id: "path-combined-second-pattern", behaviors: ["AL-003"], method: "path", input: "second/path",
            allowlist: { paths: ["^first/", "^second/"] }, validate: true)
method_case(requests, id: "path-empty-pattern-validated", behaviors: ["AL-003", "AL-017"], method: "path", input: "nonempty",
            allowlist: { paths: [""] }, validate: true)
method_case(requests, id: "path-empty-pattern-unvalidated", behaviors: ["AL-003", "AL-017"], method: "path", input: "nonempty",
            allowlist: { paths: [""] })
method_case(requests, id: "path-empty-input", behaviors: ["AL-003", "AL-017"], method: "path", input: "",
            allowlist: { paths: [".*"] }, validate: true)

method_case(requests, id: "regex-assert-hit", behaviors: ["AL-004"], method: "regex", input: "a secret: matchthis, done",
            allowlist: { regexes: ["matchthis"] }, assertions: ["AS-CFG-REGEX-01"])
method_case(requests, id: "regex-assert-miss", behaviors: ["AL-004"], method: "regex", input: "a secret",
            allowlist: { regexes: ["matchthis"] }, assertions: ["AS-CFG-REGEX-02"])
method_case(requests, id: "regex-combined-inline-flag-scope", behaviors: ["AL-003", "AL-004"], method: "regex", input: "bar",
            allowlist: { regexes: ["(?i)foo", "BAR"] }, validate: true)
method_case(requests, id: "regex-empty-pattern-validated", behaviors: ["AL-004", "AL-017"], method: "regex", input: "nonempty",
            allowlist: { regexes: [""] }, validate: true)
method_case(requests, id: "regex-empty-pattern-unvalidated", behaviors: ["AL-004", "AL-017"], method: "regex", input: "nonempty",
            allowlist: { regexes: [""] })
method_case(requests, id: "regex-invalid-byte-dot", behaviors: ["AL-004", "AL-018"], method: "regex", input: [0xff].pack("C"),
            allowlist: { regexes: ["."] }, validate: true)

method_case(requests, id: "stopword-validated-case-hit-payload", behaviors: ["AL-005", "AL-018"], method: "stopword",
            input: "prefix FAKE suffix", allowlist: { stopwords: ["FaKe"] }, validate: true)
method_case(requests, id: "stopword-validated-miss", behaviors: ["AL-005"], method: "stopword",
            input: "real", allowlist: { stopwords: ["fake"] }, validate: true)
method_case(requests, id: "stopword-empty-validated", behaviors: ["AL-005", "AL-017"], method: "stopword",
            input: "nonempty", allowlist: { stopwords: [""] }, validate: true)
method_case(requests, id: "stopword-empty-unvalidated", behaviors: ["AL-005", "AL-017"], method: "stopword",
            input: "nonempty", allowlist: { stopwords: [""] })
method_case(requests, id: "stopword-invalid-byte-replacement", behaviors: ["AL-005", "AL-018"], method: "stopword",
            input: [0xff].pack("C"), allowlist: { stopwords: ["�"] }, validate: true)
method_case(requests, id: "stopword-nonascii-simple-lower", behaviors: ["AL-005", "AL-018"], method: "stopword",
            input: "prefix ÉCOLE suffix", allowlist: { stopwords: ["ÉCOLE"] }, validate: true)
method_case(requests, id: "stopword-overlap-direct-before-suffix", behaviors: ["AL-005", "AL-018"], method: "stopword",
            input: "she", allowlist: { stopwords: %w[he she] }, validate: true)
method_case(requests, id: "stopword-unvalidated-config-order", behaviors: ["AL-005", "AL-017"], method: "stopword",
            input: "early then later", allowlist: { stopwords: %w[later early] })
method_case(requests, id: "commit-invalid-byte-collapse", behaviors: ["AL-001", "AL-002", "AL-018"], method: "commit",
            input: [0x80].pack("C"), allowlist: { commits: [[0xff].pack("C")] }, validate: true)
method_case(requests, id: "path-invalid-byte-dot", behaviors: ["AL-003", "AL-018"], method: "path",
            input: [0xff].pack("C"), allowlist: { paths: ["."] }, validate: true)
%w[commit path regex stopword].each do |method|
  method_case(requests, id: "nil-receiver-#{method}", behaviors: ["AL-017"], method: method,
              input: "nonempty", nil_allowlist: true)
end

# The upstream generator's one programmatic, deliberately unvalidated global
# allowlist has 92 extracted sample leaves. Keep them as related evidence:
# their parent TM identities are aggregators, and none is relabeled as one of
# this packet's assigned nested detector leaves.
base_assertions = ASSERTION_CORPUS.readlines.map { |line| JSON.parse(line) }.select do |row|
  %w[config-global-allowlist-regex config-global-allowlist-path].include?(row.fetch("domain"))
end
abort "base allowlist assertion count changed: #{base_assertions.length}" unless base_assertions.length == 92
base_assertions.each do |row|
  method = row.fetch("domain").end_with?("regex") ? "regex" : "path"
  sample = Base64.strict_decode64(row.dig("input", "sample", "data"))
  behaviors = [method == "regex" ? "AL-004" : "AL-003", "AL-018"]
  method_case(requests, id: "base-#{row.fetch('id')}", behaviors: behaviors,
              method: method, input: sample, base_global: true, assertions: [row.fetch("id")])
end

# Upstream TestDetect fixture leaves.
aws = 'awsToken := \"AKIALALEMEL33243OLIA\"'
detect_case(requests, id: "fixture-rule-commit", behaviors: ["AL-006", "AL-016"], content: aws,
            file: "tmp.go", commit: "allowthiscommit", fixture: "valid/allowlist_rule_commit.toml", test_case_ids: ["TM-0074"])
detect_case(requests, id: "fixture-rule-path", behaviors: ["AL-006", "AL-013"], content: aws,
            file: "tmp.go", fixture: "valid/allowlist_rule_path.toml", test_case_ids: ["TM-0075"])
detect_case(requests, id: "fixture-rule-extend-default", behaviors: ["AL-016"],
            content: 'token = "aebfab88-7596-481d-82e8-c60c8f7de0c0"', file: "path/to/your/problematic/file.js",
            fixture: "valid/allowlist_rule_extend_default.toml", test_case_ids: ["TM-0076"])
detect_case(requests, id: "fixture-rule-regex", behaviors: ["AL-007"], content: aws,
            file: "tmp.go", fixture: "valid/allowlist_rule_regex.toml", test_case_ids: ["TM-0077"])
detect_case(requests, id: "fixture-global-and-partial", behaviors: ["AL-008", "AL-009"],
            content: "\nconst token = \"mockSecret\";\n// const token = \"changeit\";", file: "config.txt",
            fixture: "valid/allowlist_global_multiple.toml", test_case_ids: ["TM-0085"])
detect_case(requests, id: "fixture-global-and-path-partial", behaviors: ["AL-008", "AL-009"],
            content: 'var token = "fakeSecret";', file: "node_modules/config.txt",
            fixture: "valid/allowlist_global_multiple.toml", test_case_ids: ["TM-0086"])
detect_case(requests, id: "fixture-global-and-all", behaviors: ["AL-008", "AL-009"],
            content: 'token := "mockSecret";', file: "node_modules/config.txt",
            fixture: "valid/allowlist_global_multiple.toml", test_case_ids: ["TM-0087"])
detect_case(requests, id: "fixture-global-regex", behaviors: ["AL-007", "AL-009"], content: aws,
            file: "tmp.go", fixture: "valid/allowlist_global_regex.toml", test_case_ids: ["TM-0088"])
detect_case(requests, id: "fixture-generic-rule-regex", behaviors: ["AL-004", "AL-007", "AL-012"],
            content: 'const Discord_Public_Key = "load2523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"',
            file: "tmp.py", fixture: "generic_with_py_path.toml", test_case_ids: ["TM-0089"])

# Exact TestDetectRuleAllowlist leaves use translated configs with the same
# rule, content, metadata, and allowlist criteria as the private detectRule test.
raw = "let username = 'james@mail.com';\nlet password = 'Summer2024!';"
commit_a = "41edf1f7f612199f401ccfc3144c2ebd0d7aeb48"
commit_b = "a060c9d2d5e90c992763f1bd4c3cd2a6f121241b"
rule_cases = [
  ["commit-and-path-not", "TM-0102", ["AL-006", "AL-008", "AL-018"], "AND", [commit_a], ["package-lock.json"], [], [], "package.json", commit_a],
  ["commit-and-path-regex-not", "TM-0103", ["AL-008", "AL-018"], "AND", [commit_a], ["package-lock.json"], ["password"], [], "package-lock.json", commit_a],
  ["commit-and-path-allowed", "TM-0104", ["AL-006", "AL-008", "AL-018"], "AND", [commit_a], ["package-lock.json"], [], [], "package-lock.json", commit_a],
  ["commit-or-path-allowed", "TM-0105", ["AL-006", "AL-018"], "OR", ["704178e7dca77ff143778a31cff0fc192d59b030"], ["package-lock.json"], [], [], "package-lock.json", commit_a],
  ["commit-allowed", "TM-0106", ["AL-006", "AL-018"], "OR", [commit_a], [], [], [], "", commit_a],
  ["path-allowed", "TM-0107", ["AL-006", "AL-018"], "OR", [], ["package-lock.json"], [], [], "package-lock.json", ""],
  ["regex-and-stop-not", "TM-0108", ["AL-008", "AL-018"], "AND", [], [], ["(?i)winter.+"], ["2024"], "", ""],
  ["regex-stop-nongit-other", "TM-0109", ["AL-008", "AL-018"], "AND", [commit_a], ["config.js"], ["(?i)summer.+"], ["2024"], "config.js", ""],
  ["regex-stop-wrong-other", "TM-0110", ["AL-008", "AL-018"], "AND", [commit_a], ["package-lock.json"], ["(?i)winter.+"], ["2024"], "config.js", commit_b],
  ["regex-and-stop-allowed", "TM-0111", ["AL-008", "AL-018"], "AND", [], [], ["(?i)summer.+"], ["2024"], "", ""],
  ["all-criteria-allowed", "TM-0112", ["AL-008", "AL-018"], "AND", [commit_a], ["config.js"], ["(?i)summer.+"], ["2024"], "config.js", commit_a],
  ["regex-or-stop-allowed", "TM-0113", ["AL-007", "AL-018"], "OR", [], [], ["(?i)summer.+"], ["winter"], "", ""],
  ["regex-allowed", "TM-0114", ["AL-007", "AL-018"], "OR", [], [], ["(?i)summer.+"], [], "", ""],
  ["stopword-allowed", "TM-0115", ["AL-007", "AL-018"], "OR", [], [], [], ["summer"], "", ""]
]
rule_cases.each do |name, tm, behaviors, condition, commits, paths, regexes, stopwords, file, commit|
  fields = []
  fields << "condition = #{JSON.generate(condition)}"
  fields << "commits = #{JSON.generate(commits)}" unless commits.empty?
  fields << "paths = #{JSON.generate(paths)}" unless paths.empty?
  fields << "regexes = #{JSON.generate(regexes)}" unless regexes.empty?
  fields << "stopwords = #{JSON.generate(stopwords)}" unless stopwords.empty?
  table = "[[rules.allowlists]]\n" + fields.join("\n")
  config = simple_config(rule_tables: table, regex: "Summer2024!", id: "test-rule", secret_group: 0)
  detect_case(requests, id: name, behaviors: behaviors,
              content: raw, file: file, commit: commit, config: config, test_case_ids: [tm])
end

# Windows dual-path leaf matrix.
windows_cases = [
  ["unix-unix-and", "TM-0156", "unix-rule", ["AL-008", "AL-011", "AL-018"], 'value: "f4k3s3cr3t"', "ignoreme/unix.txt", "", "AND", '(^|/)ignoreme(/.*)?$', ["f4k3"]],
  ["unix-unix-or", "TM-0157", "unix-rule", ["AL-006", "AL-011", "AL-018"], 'value: "s3cr3t"', "ignoreme/unix.txt", "", "OR", '(^|/)ignoreme(/.*)?$', []],
  ["unix-windows-and", "TM-0158", "windows-rule", ["AL-008", "AL-011", "AL-018"], 'value: "f4k3s3cr3t"', "ignoreme/unix.txt", "", "AND", '(^|\\\\)ignoreme(\\\\.*)?$', ["f4k3"]],
  ["unix-windows-or", "TM-0159", "windows-rule", ["AL-006", "AL-011", "AL-018"], 'value: "s3cr3t"', "ignoreme/unix.txt", "", "OR", '(^|\\\\)ignoreme(\\\\.*)?$', []],
  ["windows-unix-and", "TM-0160", "unix-rule", ["AL-008", "AL-011", "AL-018"], 'value: "f4k3s3cr3t"', "ignoreme/unix.txt", 'ignoreme\windows.txt', "AND", '(^|/)ignoreme(/.*)?$', ["f4k3"]],
  ["windows-unix-or", "TM-0161", "unix-rule", ["AL-006", "AL-011", "AL-018"], 'value: "s3cr3t"', "ignoreme/windows.txt", 'ignoreme\windows.txt', "OR", '(^|/)ignoreme(/.*)?$', []],
  ["windows-windows-and", "TM-0162", "windows-rule", ["AL-008", "AL-011", "AL-018"], 'value: "f4k3s3cr3t"', "ignoreme/unix.txt", 'ignoreme\windows.txt', "AND", '(^|\\\\)ignoreme(\\\\.*)?$', ["f4k3"]],
  ["windows-windows-or", "TM-0163", "windows-rule", ["AL-006", "AL-011", "AL-018"], 'value: "s3cr3t"', "ignoreme/windows.txt", 'ignoreme\windows.txt', "OR", '(^|\\\\)ignoreme(\\\\.*)?$', []]
]
windows_cases.each do |name, tm, rule_id, behaviors, content, file, windows, condition, path, stopwords|
  fields = ["condition = #{JSON.generate(condition)}", "paths = #{JSON.generate([path])}"]
  fields << "stopwords = #{JSON.generate(stopwords)}" unless stopwords.empty?
  regex = condition == "OR" ? "s3cr3t" : 'value: "[^"]+"'
  config = simple_config(rule_tables: "[[rules.allowlists]]\n#{fields.join("\n")}", regex: regex, id: rule_id, secret_group: 0)
  detect_case(requests, id: name, behaviors: behaviors, content: content,
              file: file, windows_file: windows, config: config, test_case_ids: [tm])
end

# Focused staging, targets, ordering, path-only, and extension cases.
%w[secret match line].each do |target|
  table = <<~TOML
    [[rules.allowlists]]
    regexTarget = #{JSON.generate(target)}
    regexes = [#{JSON.generate(target == "secret" ? '^VALUE$' : target == "match" ? '^TOKEN=VALUE$' : '^prefix TOKEN=VALUE suffix$')}]
  TOML
  detect_case(requests, id: "regex-target-#{target}", behaviors: ["AL-004", target == "line" ? "AL-015" : "AL-007"],
              content: "prefix TOKEN=VALUE suffix", config: simple_config(rule_tables: table))
end

targeted = <<~TOML
  [[rules]]
  id = "targeted-a"
  regex = "TOKEN=([A-Z]+)"
  [[rules]]
  id = "targeted-b"
  regex = "TOKEN=([A-Z]+)"
  [[rules]]
  id = "untargeted"
  regex = "TOKEN=([A-Z]+)"
  [[allowlists]]
  targetRules = ["targeted-a", "targeted-b"]
  regexes = ["^VALUE$"]
TOML
detect_case(requests, id: "targeted-global-two-of-three-rules", behaviors: ["AL-009", "AL-010"],
            content: "TOKEN=VALUE", config: targeted)

multi = <<~TOML
  [[rules]]
  id = "multi"
  regex = "TOKEN=([A-Z]+)"
  [[rules.allowlists]]
  regexes = ["^MISS$"]
  [[rules.allowlists]]
  stopwords = ["value"]
TOML
detect_case(requests, id: "multiple-allowlists-or-of-tables", behaviors: ["AL-009"], content: "TOKEN=VALUE", config: multi)

precedence = <<~TOML
  [[rules]]
  id = "global"
  regex = "GLOBAL=([A-Z]+)"
  [[rules]]
  id = "targeted"
  regex = "TARGETED=([A-Z]+)"
  [[rules]]
  id = "rule"
  regex = "RULE=([A-Z]+)"
  [[rules.allowlists]]
  stopwords = ["rulevalue"]
  [[rules]]
  id = "survivor"
  regex = "SURVIVOR=([A-Z]+)"
  [[allowlists]]
  regexes = ["^GLOBALVALUE$"]
  [[allowlists]]
  targetRules = ["targeted"]
  regexes = ["^TARGETEDVALUE$"]
TOML
detect_case(requests, id: "global-targeted-rule-precedence", behaviors: ["AL-009", "AL-010"],
            content: "GLOBAL=GLOBALVALUE TARGETED=TARGETEDVALUE RULE=RULEVALUE SURVIVOR=KEPT", config: precedence)

path_only_or = <<~TOML
  [[rules]]
  id = "path-only"
  path = "ignoreme"
  [[rules.allowlists]]
  paths = ["ignoreme"]
TOML
detect_case(requests, id: "path-only-or-path-suppressed", behaviors: ["AL-006", "AL-013"],
            content: "", file: "ignoreme.txt", config: path_only_or)
path_only_and_deferred = <<~TOML
  [[rules]]
  id = "path-only"
  path = "ignoreme"
  [[rules.allowlists]]
  condition = "AND"
  paths = ["ignoreme"]
  stopwords = ["never-reached"]
TOML
detect_case(requests, id: "path-only-and-finding-criterion-reports", behaviors: ["AL-008", "AL-013"],
            content: "", file: "ignoreme.txt", config: path_only_and_deferred)

marker_table = <<~TOML
  [[rules.allowlists]]
  stopwords = ["value"]
TOML
detect_case(requests, id: "allow-marker-before-finding-allowlist", behaviors: ["AL-012"],
            content: "TOKEN=VALUE # gitleaks:allow", config: simple_config(rule_tables: marker_table))
detect_case(requests, id: "allow-marker-disabled-then-rule-allowlist", behaviors: ["AL-012"],
            content: "TOKEN=VALUE # gitleaks:allow", config: simple_config(rule_tables: marker_table), ignore_allow_marker: true)

detect_case(requests, id: "or-commit-miss-regex-hit", behaviors: ["AL-006", "AL-007"], content: "TOKEN=VALUE",
            commit: "other", config: simple_config(rule_tables: "[[rules.allowlists]]\ncommits = [\"wanted\"]\nregexes = [\"^VALUE$\"]"))
detect_case(requests, id: "or-path-miss-stopword-hit", behaviors: ["AL-006", "AL-007"], content: "TOKEN=VALUE",
            file: "other.txt", config: simple_config(rule_tables: "[[rules.allowlists]]\npaths = [\"wanted\\\\.txt\"]\nstopwords = [\"value\"]"))
windows_only_pattern = %q{(^|\\\\)ignoreme(\\\\.*)?$}
detect_case(requests, id: "windows-only-path-early-guard", behaviors: ["AL-006", "AL-011"], content: "TOKEN=VALUE",
            file: "", windows_file: 'ignoreme\windows.txt',
            config: simple_config(rule_tables: "[[rules.allowlists]]\npaths = [#{JSON.generate(windows_only_pattern)}]"))

%w[secret match line].each do |target|
  wrong_pattern = target == "secret" ? '^TOKEN=VALUE$' : target == "match" ? '^VALUE$' : '^VALUE$'
  table = "[[rules.allowlists]]\nregexTarget = #{JSON.generate(target)}\nregexes = [#{JSON.generate(wrong_pattern)}]"
  detect_case(requests, id: "regex-target-#{target}-negative", behaviors: ["AL-004", "AL-012"],
              content: "prefix TOKEN=VALUE suffix", config: simple_config(rule_tables: table))
end
detect_case(requests, id: "line-target-raw-multiline", behaviors: ["AL-012", "AL-015"],
            content: "head\nprefix TOKEN=VALUE suffix\ntail",
            config: simple_config(rule_tables: "[[rules.allowlists]]\nregexTarget = \"line\"\nregexes = [\"prefix TOKEN=VALUE suffix\"]"))
detect_case(requests, id: "stopword-ignores-regex-target", behaviors: ["AL-005", "AL-012"], content: "TOKEN=VALUE",
            config: simple_config(rule_tables: "[[rules.allowlists]]\nregexTarget = \"line\"\nregexes = [\"never\"]\nstopwords = [\"value\"]"))

detect_case(requests, id: "path-only-or-regex-reports", behaviors: ["AL-007", "AL-013"], content: "", file: "report.txt",
            config: "[[rules]]\nid = \"path-only\"\npath = \"report\"\n[[rules.allowlists]]\nregexes = [\".*\"]\n")
detect_case(requests, id: "path-only-and-path-only-suppressed", behaviors: ["AL-008", "AL-013"], content: "", file: "ignoreme.txt",
            config: "[[rules]]\nid = \"path-only\"\npath = \"ignoreme\"\n[[rules.allowlists]]\ncondition = \"AND\"\npaths = [\"ignoreme\"]\n")
detect_case(requests, id: "path-plus-regex-and-path-stopword", behaviors: ["AL-008", "AL-013"], content: "TOKEN=VALUE", file: "ignoreme.txt",
            config: "[[rules]]\nid = \"path-regex\"\npath = \"ignoreme\"\nregex = \"TOKEN=([A-Z]+)\"\nsecretGroup = 1\n[[rules.allowlists]]\ncondition = \"AND\"\npaths = [\"ignoreme\"]\nstopwords = [\"value\"]\n")
detect_case(requests, id: "entropy-before-allowlist", behaviors: ["AL-012", "AL-013"], content: "TOKEN=AAAA",
            config: "[[rules]]\nid = \"entropy\"\nregex = \"TOKEN=([A-Z]+)\"\nsecretGroup = 1\nentropy = 1.0\n[[rules.allowlists]]\nstopwords = [\"aaaa\"]\n")

composite_primary_allowlisted = <<~TOML
  [[rules]]
  id = "primary"
  regex = "PRIMARY=([A-Z]+)"
  [[rules.required]]
  id = "aux"
  [[rules.allowlists]]
  stopwords = ["primaryvalue"]
  [[rules]]
  id = "aux"
  regex = "AUX=([A-Z]+)"
  skipReport = true
TOML
detect_case(requests, id: "composite-primary-allowlisted-future", behaviors: ["AL-014"],
            content: "PRIMARY=PRIMARYVALUE AUX=AUXVALUE", config: composite_primary_allowlisted)
composite_aux_allowlisted = <<~TOML
  [[rules]]
  id = "primary"
  regex = "PRIMARY=([A-Z]+)"
  [[rules.required]]
  id = "aux"
  [[rules]]
  id = "aux"
  regex = "AUX=([A-Z]+)"
  skipReport = true
  [[rules.allowlists]]
  stopwords = ["auxvalue"]
TOML
detect_case(requests, id: "composite-aux-allowlisted-future", behaviors: ["AL-014"],
            content: "PRIMARY=PRIMARYVALUE AUX=AUXVALUE", config: composite_aux_allowlisted)
detect_case(requests, id: "composite-inherited-primary-bypasses-projection", behaviors: ["AL-014"],
            content: "PRIMARY=PRIMARYVALUE", config: composite_aux_allowlisted, inherited_from_finding: true)

base_rule = "[[rules]]\nid = \"base\"\nregex = \"TOKEN=([A-Z]+)\"\nsecretGroup = 1\n"
base_target = base_rule + "[[allowlists]]\ntargetRules = [\"base\"]\nregexes = [\"^VALUE$\"]\n"
child_only_extend = "[extend]\npath = \"base.toml\"\n"
child_outer_target = child_only_extend + "[[allowlists]]\ntargetRules = [\"base\"]\nregexes = [\"^VALUE$\"]\n"
detect_case(requests, id: "extended-base-targeted-global-discarded", behaviors: ["AL-010", "AL-016"],
            content: "TOKEN=VALUE", bundle: { "entry.toml" => child_only_extend, "base.toml" => base_target }, entry: "entry.toml")
detect_case(requests, id: "outer-target-attaches-to-base-rule", behaviors: ["AL-010", "AL-016"],
            content: "TOKEN=VALUE", bundle: { "entry.toml" => child_outer_target, "base.toml" => base_rule }, entry: "entry.toml")
detect_case(requests, id: "duplicate-matches-preserved", behaviors: ["AL-009", "AL-018"],
            content: "TOKEN=VALUE TOKEN=VALUE", config: simple_config(rule_tables: "[[rules.allowlists]]\nregexes = [\"^MISS$\"]"))

extend_content = "fake aws_thing=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd"
%w[valid/extend_rule_allowlist_or.toml valid/extend_rule_allowlist_and.toml].each do |fixture|
  detect_case(requests, id: "fixture-#{File.basename(fixture, '.toml')}", behaviors: ["AL-008", "AL-016"],
              content: extend_content, file: "ignore.xaml", commit: "abcdefg1", fixture: fixture)
end

abort "duplicate request IDs" unless requests.map { |request| request.fetch("id") }.uniq.length == requests.length
observed_al = requests.flat_map { |request| request.fetch("behavior_ids") }.grep(/^AL-/).uniq.sort
abort "AL coverage changed: #{observed_al.inspect}" unless observed_al == AL_IDS
AL_IDS.each do |id|
  abort "#{id}: no request evidence" unless requests.any? { |request| request.fetch("behavior_ids").include?(id) }
end
observed_assertions = requests.flat_map { |request| request.fetch("assertion_ids") }.uniq.sort
base_assertion_ids = base_assertions.map { |row| row.fetch("id") }.sort
all_assertion_ids = (ASSERTION_IDS + base_assertion_ids).sort
abort "assertion coverage changed: #{observed_assertions.inspect}" unless observed_assertions == all_assertion_ids
all_assertion_ids.each do |id|
  count = requests.count { |request| request.fetch("assertion_ids").include?(id) }
  abort "#{id}: expected exactly one request, got #{count}" unless count == 1
end
observed_leaf_tests = requests.flat_map { |request| request.fetch("test_case_ids") }.uniq.sort
abort "leaf test coverage changed: #{observed_leaf_tests.inspect}" unless observed_leaf_tests == LEAF_TEST_CASE_IDS.sort
LEAF_TEST_CASE_IDS.each do |id|
  count = requests.count { |request| request.fetch("test_case_ids").include?(id) }
  abort "#{id}: expected exactly one request, got #{count}" unless count == 1
end
abort "aggregator linked as request leaf" unless (observed_leaf_tests & AGGREGATOR_TEST_CASE_IDS).empty?

# Guard the exact programmatic-rule translations behind the 22 nested detector
# identities. These assertions are intentionally independent of the tables
# above so a convenient substitute config cannot silently retain the TM link.
requests_by_tm = requests.each_with_object({}) do |request, index|
  request.fetch("test_case_ids").each { |id| index[id] = request }
end
(102..115).each do |index|
  id = format("TM-%04d", index)
  config = Base64.strict_decode64(requests_by_tm.fetch(id).fetch("config_base64"))
  abort "#{id}: translated rule ID changed" unless config.include?(%{id = "test-rule"})
  abort "#{id}: translated rule regex changed" unless config.include?(%{regex = "Summer2024!"})
end
windows_exact = {
  "TM-0156" => ["unix-rule", "AND", 'value: "[^"]+"', "AL-008"],
  "TM-0157" => ["unix-rule", "OR", "s3cr3t", "AL-006"],
  "TM-0158" => ["windows-rule", "AND", 'value: "[^"]+"', "AL-008"],
  "TM-0159" => ["windows-rule", "OR", "s3cr3t", "AL-006"],
  "TM-0160" => ["unix-rule", "AND", 'value: "[^"]+"', "AL-008"],
  "TM-0161" => ["unix-rule", "OR", "s3cr3t", "AL-006"],
  "TM-0162" => ["windows-rule", "AND", 'value: "[^"]+"', "AL-008"],
  "TM-0163" => ["windows-rule", "OR", "s3cr3t", "AL-006"]
}
windows_exact.each do |id, (rule_id, condition, regex, behavior)|
  request = requests_by_tm.fetch(id)
  config = Base64.strict_decode64(request.fetch("config_base64"))
  abort "#{id}: translated rule ID changed" unless config.include?(%{id = #{JSON.generate(rule_id)}})
  abort "#{id}: translated regex changed" unless config.include?(%{regex = #{JSON.generate(regex)}})
  abort "#{id}: translated condition changed" unless config.include?(%{condition = #{JSON.generate(condition)}})
  abort "#{id}: behavior link changed" unless request.fetch("behavior_ids").include?(behavior)
  wrong = behavior == "AL-006" ? "AL-008" : "AL-006"
  abort "#{id}: contradictory behavior link" if request.fetch("behavior_ids").include?(wrong)
end
abort "decoding escaped M5 gate" unless requests.select { |request| request["operation"] == "detect" }.all? { |request| request.dig("options", "max_decode_depth") == 0 }

revision = capture("git", "rev-parse", "HEAD", chdir: UPSTREAM).strip
abort "upstream revision changed: #{revision}" unless revision == REVISION
default_sha = sha(UPSTREAM.join("config/gitleaks.toml").binread)
abort "default config hash changed: #{default_sha}" unless default_sha == DEFAULT_SHA256
status = capture("git", "status", "--short", "--untracked-files=no", chdir: UPSTREAM)
abort "upstream status changed:\n#{status}" unless status == EXPECTED_UPSTREAM_STATUS

requests_bytes = jsonl(requests)
generated = {}
Dir.mktmpdir("rustleaks-m5-allowlist") do |temporary|
  binary = File.join(temporary, "allowlist-oracle")
  capture("go", "test", "./...", chdir: ORACLE)
  capture("go", "build", "-o", binary, ".", chdir: ORACLE)
  outcomes = requests.map do |request|
    output = capture(binary, "--allowlist", chdir: ORACLE, stdin_data: JSON.generate(request) + "\n")
    lines = output.lines
    abort "#{request.fetch('id')}: oracle emitted #{lines.length} lines" unless lines.length == 1
    parsed = JSON.parse(lines.first)
    abort "#{request.fetch('id')}: oracle ID changed" unless parsed.fetch("id") == request.fetch("id")
    abort "#{request.fetch('id')}: pin changed" unless parsed.fetch("upstream_revision") == REVISION && parsed.fetch("default_config_sha256") == DEFAULT_SHA256
    abort "#{request.fetch('id')}: oracle error #{parsed['error'].inspect}" unless parsed["error"].nil?
    parsed
  end

  by_id = outcomes.to_h { |outcome| [outcome.fetch("id"), outcome] }
  expected_allowed = %w[
    validate-dedup-idempotent commit-assert-hit-unvalidated
    commit-validated-trim-case-hit-empty-payload commit-unvalidated-case-sensitive-payload
    path-assert-hit path-combined-second-pattern path-empty-pattern-validated
    regex-assert-hit regex-combined-inline-flag-scope regex-empty-pattern-validated regex-invalid-byte-dot
    stopword-validated-case-hit-payload stopword-empty-unvalidated stopword-invalid-byte-replacement
    stopword-nonascii-simple-lower stopword-overlap-direct-before-suffix stopword-unvalidated-config-order
    commit-invalid-byte-collapse path-invalid-byte-dot
  ].to_h { |id| [id, true] }
  requests.select { |request| request.fetch("operation") == "method" && !request.fetch("base_global") }.each do |request|
    actual = by_id.fetch(request.fetch("id")).fetch("method_result").fetch("allowed")
    expected = expected_allowed.fetch(request.fetch("id"), false)
    abort "#{request.fetch('id')}: method invariant #{actual} != #{expected}" unless actual == expected
  end
  {
    "validate-dedup-idempotent" => "stopwordb",
    "commit-assert-hit-unvalidated" => "commitA",
    "commit-unvalidated-case-sensitive-payload" => "CommitA",
    "stopword-validated-case-hit-payload" => "fake",
    "stopword-invalid-byte-replacement" => "�",
    "stopword-nonascii-simple-lower" => "école",
    "stopword-overlap-direct-before-suffix" => "she",
    "stopword-unvalidated-config-order" => "later"
  }.each do |id, expected|
    actual = Base64.strict_decode64(by_id.fetch(id).fetch("method_result").fetch("matched_value_base64"))
    abort "#{id}: matched payload changed" unless actual == expected.b
  end
  abort "validated commit unexpectedly returned text" unless by_id.fetch("commit-validated-trim-case-hit-empty-payload").dig("method_result", "matched_value_base64") == ""
  empty_validation = by_id.fetch("validate-empty").fetch("validation")
  abort "empty validation invariant changed" unless !empty_validation.fetch("success") && empty_validation.fetch("error") == "must contain at least one check for: commits, paths, regexes, or stopwords"
  dedup = by_id.fetch("validate-dedup-idempotent")
  abort "validate idempotence count changed" unless dedup.dig("validation", "success") && dedup.dig("validation", "attempted_count") == 2
  abort "commit normalization changed" unless dedup.dig("normalized", "commits").sort == %w[commita commitb]
  abort "stopword normalization changed" unless dedup.dig("normalized", "stop_words").sort == %w[stopworda stopwordb]

  base_assertions.each do |row|
    id = "base-#{row.fetch('id')}"
    actual = by_id.fetch(id).fetch("method_result").fetch("allowed")
    expected = row.dig("expected", "value")
    abort "#{id}: extracted assertion changed #{actual} != #{expected}" unless actual == expected
  end

  expected_nonzero_findings = {
    "fixture-global-and-partial" => 1, "fixture-global-and-path-partial" => 1,
    "commit-and-path-not" => 1, "commit-and-path-regex-not" => 1,
    "regex-and-stop-not" => 1, "regex-stop-nongit-other" => 1, "regex-stop-wrong-other" => 1,
    "unix-windows-and" => 1, "unix-windows-or" => 1,
    "targeted-global-two-of-three-rules" => 1, "global-targeted-rule-precedence" => 1,
    "path-only-and-finding-criterion-reports" => 1, "fixture-extend_rule_allowlist_and" => 1,
    "windows-only-path-early-guard" => 1,
    "regex-target-secret-negative" => 1, "regex-target-match-negative" => 1, "regex-target-line-negative" => 1,
    "path-only-or-regex-reports" => 1, "extended-base-targeted-global-discarded" => 1,
    "duplicate-matches-preserved" => 2, "composite-inherited-primary-bypasses-projection" => 1
  }
  requests.select { |request| request.fetch("operation") == "detect" }.each do |request|
    actual = by_id.fetch(request.fetch("id")).fetch("findings").length
    expected = expected_nonzero_findings.fetch(request.fetch("id"), 0)
    abort "#{request.fetch('id')}: finding-count invariant #{actual} != #{expected}" unless actual == expected
  end
  expected_rule_ids = {
    "targeted-global-two-of-three-rules" => ["untargeted"],
    "global-targeted-rule-precedence" => ["survivor"],
    "path-only-and-finding-criterion-reports" => ["path-only"],
    "fixture-extend_rule_allowlist_and" => ["aws-secret-key-again-again"],
    "extended-base-targeted-global-discarded" => ["base"],
    "composite-inherited-primary-bypasses-projection" => ["primary"],
    "duplicate-matches-preserved" => ["test", "test"]
  }
  expected_rule_ids.each do |id, expected|
    actual = by_id.fetch(id).fetch("findings").map { |finding| finding.fetch("rule_id") }
    abort "#{id}: rule-scope invariant #{actual.inspect} != #{expected.inspect}" unless actual == expected
  end
  complete_finding_keys = %w[
    rule_id description_base64 start_line end_line start_column end_column line_base64 match_base64
    secret_base64 file_base64 symlink_file_base64 commit_base64 link_base64 entropy_bits author_base64
    email_base64 date_base64 message_base64 tags_base64 fingerprint_base64 fragment required_findings
  ].sort
  outcomes.flat_map { |outcome| outcome.fetch("findings") }.each do |finding|
    abort "complete finding projection changed" unless finding.keys.sort == complete_finding_keys
  end
  outcomes_bytes = jsonl(outcomes)
  metadata = requests.zip(outcomes).map do |request, outcome|
    {
      "id" => request.fetch("id"), "operation" => request.fetch("operation"),
      "behavior_ids" => request.fetch("behavior_ids"), "test_case_ids" => request.fetch("test_case_ids"),
      "assertion_ids" => request.fetch("assertion_ids"), "input_sha256" => outcome.fetch("input_sha256"),
      "config_sha256" => outcome.fetch("config_sha256"), "finding_count" => outcome.fetch("findings").length
    }
  end
  metadata_bytes = jsonl(metadata)
  coverage = {
    "schema_version" => 1,
    "behavior_ids" => AL_IDS.map do |id|
      linked = requests.select { |request| request.fetch("behavior_ids").include?(id) }.map { |request| request.fetch("id") }
      status = case id
               when "AL-014" then "future-m7-ordering-cases-frozen-no-positive-composite-claim"
               when "AL-015" then "raw-line-observed-decoded-line-deferred-m6"
               else "observed"
               end
      { "id" => id, "status" => status, "request_ids" => linked }
    end,
    "assertion_ids" => ASSERTION_IDS.sort.map do |id|
      { "id" => id, "kind" => "leaf", "request_ids" => requests.select { |request| request.fetch("assertion_ids").include?(id) }.map { |request| request.fetch("id") } }
    end,
    "related_assertion_ids" => base_assertion_ids.map do |id|
      { "id" => id, "kind" => "related-base-allowlist-leaf", "request_ids" => requests.select { |request| request.fetch("assertion_ids").include?(id) }.map { |request| request.fetch("id") } }
    end,
    "test_cases" => (
      AGGREGATOR_TEST_CASE_IDS.map do |id|
        child_kind = %w[TM-0028 TM-0032 TM-0033 TM-0072].include?(id) ? "assertion-leaf-aggregator" : "nested-test-aggregator"
        { "id" => id, "kind" => child_kind, "direct_request_ids" => [] }
      end + LEAF_TEST_CASE_IDS.sort.map do |id|
        { "id" => id, "kind" => "nested-test-leaf", "direct_request_ids" => requests.select { |request| request.fetch("test_case_ids").include?(id) }.map { |request| request.fetch("id") } }
      end
    )
  }
  coverage_bytes = JSON.pretty_generate(coverage) + "\n"
  go_version = outcomes.first.fetch("go_version")
  manifest = {
    "schema_version" => 1, "protocol_version" => PROTOCOL_VERSION, "oracle_mode" => "allowlist",
    "upstream_revision" => REVISION, "default_config_sha256" => DEFAULT_SHA256, "go_version" => go_version,
    "scope" => ["compiled-allowlist-methods", "raw-direct-fragment-allowlists", "translated-config-fixtures", "complete-canonical-findings"],
    "excluded" => ["decoded-target-lines-m6", "composite-required-rules", "source-session-baseline-ignore"],
    "request_count" => requests.length,
    "method_request_count" => requests.count { |request| request.fetch("operation") == "method" },
    "detect_request_count" => requests.count { |request| request.fetch("operation") == "detect" },
    "finding_count" => outcomes.sum { |outcome| outcome.fetch("findings").length },
    "zero_finding_detect_request_count" => outcomes.count { |outcome| outcome.fetch("operation") == "detect" && outcome.fetch("findings").empty? },
    "finding_bearing_detect_request_count" => outcomes.count { |outcome| outcome.fetch("operation") == "detect" && !outcome.fetch("findings").empty? },
    "behavior_id_count" => AL_IDS.length, "assertion_leaf_count" => ASSERTION_IDS.length,
    "related_base_assertion_leaf_count" => base_assertion_ids.length,
    "linked_nested_test_leaf_count" => LEAF_TEST_CASE_IDS.length,
    "aggregator_test_case_count" => AGGREGATOR_TEST_CASE_IDS.length,
    "fresh_process_per_request" => true,
    "files" => {
      "requests-v1.jsonl" => { "sha256" => sha(requests_bytes), "records" => requests.length },
      "outcomes-v1.jsonl" => { "sha256" => sha(outcomes_bytes), "records" => outcomes.length },
      "request-metadata-v1.jsonl" => { "sha256" => sha(metadata_bytes), "records" => metadata.length },
      "coverage-v1.json" => { "sha256" => sha(coverage_bytes), "records" => AL_IDS.length + all_assertion_ids.length + AGGREGATOR_TEST_CASE_IDS.length + LEAF_TEST_CASE_IDS.length }
    }
  }
  generated["requests-v1.jsonl"] = requests_bytes
  generated["outcomes-v1.jsonl"] = outcomes_bytes
  generated["request-metadata-v1.jsonl"] = metadata_bytes
  generated["coverage-v1.json"] = coverage_bytes
  generated["manifest-v1.json"] = JSON.pretty_generate(manifest) + "\n"
end

final_status = capture("git", "status", "--short", "--untracked-files=no", chdir: UPSTREAM)
abort "upstream status changed during generation:\n#{final_status}" unless final_status == EXPECTED_UPSTREAM_STATUS

if CHECK
  generated.each do |name, bytes|
    path = OUTPUT_ROOT.join(name)
    abort "missing #{path}" unless path.file?
    unless path.binread == bytes.b
      abort "#{path} differs from fresh pinned-Go generation: committed=#{sha(path.binread)} fresh=#{sha(bytes)}"
    end
  end
else
  FileUtils.mkdir_p(OUTPUT_ROOT)
  generated.each { |name, bytes| OUTPUT_ROOT.join(name).binwrite(bytes) }
end

puts "allowlist corpus #{CHECK ? 'verified' : 'generated'}: #{requests.length} fresh processes, outcomes #{sha(generated.fetch('outcomes-v1.jsonl'))}"
