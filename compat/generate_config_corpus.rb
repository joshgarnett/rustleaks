#!/usr/bin/env ruby
# frozen_string_literal: true

# Generates the canonical configuration corpus. Every request is
# evaluated by a fresh oracle process in its own temporary fixture tree because
# the pinned Go implementation keeps extension depth in process-global state.

require "base64"
require "digest"
require "fileutils"
require "json"
require "open3"
require "pathname"
require "tmpdir"

ROOT = Pathname(__dir__).parent
ORACLE = ROOT.parent.join("gitleaks")
ORACLE_MODULE = ROOT.join("crates/rustleaks-compat/oracle")
FIXTURE_ROOT = ROOT.join("compat/fixtures/upstream/testdata/config")
OUTPUT_ROOT = ROOT.join("compat/config-corpus")
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
DEFAULT_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
PROTOCOL_VERSION = 1

CHECK = ARGV.delete("--check")
abort "usage: #{$PROGRAM_NAME} [--check]" unless ARGV.empty?

def capture(*command, chdir:, env: {}, stdin_data: "")
  output, error, status = Open3.capture3(env, *command, chdir: chdir.to_s, stdin_data: stdin_data)
  abort "#{command.join(' ')} failed in #{chdir}:\n#{error}\n#{output}" unless status.success?
  output
end

def json_line(value)
  JSON.generate(value) + "\n"
end

def sha(bytes)
  Digest::SHA256.hexdigest(bytes)
end

def fixture_manifest_ids(relative)
  exact = {
    "generic.toml" => %w[TM-0034 TM-0035],
    "invalid/rule_bad_entropy_group.toml" => ["TM-0036"],
    "invalid/rule_missing_id.toml" => ["TM-0037"],
    "invalid/rule_no_regex_or_path.toml" => ["TM-0038"],
    "valid/rule_entropy_group.toml" => ["TM-0039"],
    "valid/rule_path_only.toml" => ["TM-0040"],
    "valid/rule_regex_escaped_character_group.toml" => ["TM-0041"],
    "invalid/allowlist_global_empty.toml" => ["TM-0043"],
    "invalid/allowlist_global_old_and_new.toml" => ["TM-0044"],
    "invalid/allowlist_global_regextarget.toml" => ["TM-0045"],
    "invalid/allowlist_global_target_rule_id.toml" => ["TM-0046"],
    "invalid/allowlist_rule_empty.toml" => ["TM-0047"],
    "invalid/allowlist_rule_old_and_new.toml" => ["TM-0048"],
    "invalid/allowlist_rule_regextarget.toml" => ["TM-0049"],
    "valid/allowlist_global_multiple.toml" => %w[TM-0042 TM-0050],
    "valid/allowlist_global_old_compat.toml" => ["TM-0051"],
    "valid/allowlist_global_regex.toml" => ["TM-0052"],
    "valid/allowlist_global_target_rules.toml" => ["TM-0053"],
    "valid/allowlist_rule_commit.toml" => ["TM-0054"],
    "valid/allowlist_rule_old_compat.toml" => ["TM-0055"],
    "valid/allowlist_rule_path.toml" => ["TM-0056"],
    "valid/allowlist_rule_regex.toml" => ["TM-0057"],
    "invalid/extend_invalid_ruleid.toml" => ["TM-0059"],
    "valid/extend.toml" => %w[TM-0058 TM-0060],
    "valid/extend_disabled.toml" => ["TM-0061"],
    "valid/extend_rule_allowlist_and.toml" => ["TM-0062"],
    "valid/extend_rule_allowlist_or.toml" => ["TM-0063"],
    "valid/extend_rule_no_regexpath.toml" => ["TM-0064"],
    "valid/extend_rule_override_description.toml" => ["TM-0065"],
    "valid/extend_rule_override_entropy.toml" => ["TM-0066"],
    "valid/extend_rule_override_keywords.toml" => ["TM-0067"],
    "valid/extend_rule_override_path.toml" => ["TM-0068"],
    "valid/extend_rule_override_regex.toml" => ["TM-0069"],
    "valid/extend_rule_override_secret_group.toml" => ["TM-0070"],
    "valid/extend_rule_override_tags.toml" => ["TM-0071"],
    "valid/extend_base_rule_including_keywords_with_attribute.toml" => %w[TM-0029 TM-0030],
    "valid/extend_rule_new.toml" => %w[TM-0029 TM-0031]
  }
  exact.fetch(relative, [])
end

FOCUSED_FILES = {
  "focused/reentrant.toml" => <<~TOML,
    title = "reentrant"
    [extend]
    path = "../testdata/config/focused/reentrant-base.toml"
    [[rules]]
    id = "child"
    regex = "child"
  TOML
  "focused/reentrant-base.toml" => <<~TOML,
    title = "reentrant base"
    [[rules]]
    id = "base"
    regex = "base"
  TOML
  "focused/depth-root.toml" => <<~TOML,
    [extend]
    path = "../testdata/config/focused/depth-1.toml"
    [[rules]]
    id = "depth-root"
    regex = "root"
  TOML
  "focused/depth-1.toml" => <<~TOML,
    [extend]
    path = "../testdata/config/focused/depth-2.toml"
    [[rules]]
    id = "depth-1"
    regex = "one"
  TOML
  "focused/depth-2.toml" => <<~TOML,
    [extend]
    path = "../testdata/config/focused/depth-3.toml"
    [[rules]]
    id = "depth-2"
    regex = "two"
  TOML
  "focused/depth-3.toml" => <<~TOML,
    [[rules]]
    id = "depth-3-must-not-load"
    regex = "three"
  TOML
  "focused/disabled-unknown.toml" => <<~TOML,
    [extend]
    path = "../testdata/config/focused/reentrant-base.toml"
    disabledRules = ["missing-rule"]
    [[rules]]
    id = "child"
    regex = "child"
  TOML
  "focused/targeted-existing-root.toml" => <<~TOML,
    [extend]
    path = "../testdata/config/focused/targeted-existing-base.toml"
    [[rules]]
    id = "child"
    regex = "child"
  TOML
  "focused/targeted-existing-base.toml" => <<~TOML,
    [[rules]]
    id = "base"
    regex = "base"
    [[allowlists]]
    targetRules = ["base"]
    regexes = ["discarded"]
  TOML
  "focused/targeted-missing-root.toml" => <<~TOML,
    [extend]
    path = "../testdata/config/focused/targeted-missing-base.toml"
    [[rules]]
    id = "child"
    regex = "child"
  TOML
  "focused/targeted-missing-base.toml" => <<~TOML,
    [[rules]]
    id = "base"
    regex = "base"
    [[allowlists]]
    targetRules = ["absent"]
    regexes = ["discarded"]
  TOML
  "focused/targeted-depth-root.toml" => <<~TOML,
    [extend]
    path = "../testdata/config/focused/targeted-depth-1.toml"
    [[rules]]
    id = "root"
    regex = "root"
  TOML
  "focused/targeted-depth-1.toml" => <<~TOML,
    [extend]
    path = "../testdata/config/focused/targeted-depth-2.toml"
    [[rules]]
    id = "middle"
    regex = "middle"
  TOML
  "focused/targeted-depth-2.toml" => <<~TOML,
    [[rules]]
    id = "deep"
    regex = "deep"
    [[allowlists]]
    targetRules = ["deep"]
    regexes = ["discarded"]
  TOML
  "focused/required-disabled-root.toml" => <<~TOML,
    [extend]
    path = "../testdata/config/focused/required-disabled-base.toml"
    disabledRules = ["secondary"]
  TOML
  "focused/required-disabled-base.toml" => <<~TOML,
    [[rules]]
    id = "primary"
    regex = "primary"
    [[rules.required]]
    id = "secondary"
    [[rules]]
    id = "secondary"
    regex = "secondary"
  TOML
}.freeze

FOCUSED_INLINE = {
  "permissive-fields" => <<~TOML,
    TiTlE = "mixed field casing"
    UnknownTopLevel = "ignored"
    [[rules]]
    ID = "mixed"
    DeScRiPtIoN = "mixed rule fields"
    ReGeX = "mixed"
    KeYwOrDs = ["MiXeD"]
    TaGs = ["One"]
    UnknownRuleField = 42
  TOML
  "permissive-table-casing" => <<~TOML,
    [[RuLeS]]
    ID = "upper-table"
    REGEX = "upper"
  TOML
  "duplicate-rule-ids" => <<~TOML,
    [[rules]]
    id = "duplicate"
    regex = "first"
    keywords = ["first"]
    [[rules]]
    id = "duplicate"
    regex = "second"
    keywords = ["second"]
  TOML
  "required-valid" => <<~TOML,
    [[rules]]
    id = "primary"
    regex = "primary"
    [[rules.required]]
    id = "secondary"
    withinLines = 0
    withinColumns = 2
    [[rules]]
    id = "secondary"
    regex = "secondary"
    skipReport = true
  TOML
  "required-missing" => <<~TOML,
    [[rules]]
    id = "primary"
    regex = "primary"
    [[rules.required]]
    id = "absent"
  TOML
  "required-empty" => <<~TOML,
    [[rules]]
    id = "primary"
    regex = "primary"
    [[rules.required]]
  TOML
  "deprecated-rule-alias" => <<~TOML,
    [[rules]]
    id = "alias"
    regex = "alias"
    [rules.allowlist]
    regexes = ["allowed"]
  TOML
  "conditions-and-targets" => <<~TOML,
    [[rules]]
    id = "targets"
    regex = "targets"
    [[rules.allowlists]]
    condition = "&&"
    regexTarget = "secret"
    commits = [" ABC ", "abc"]
    paths = ["one", "two"]
    regexes = ["first", "second"]
    stopWords = ["STOP", "stop"]
    [[allowlists]]
    condition = "||"
    regexTarget = "line"
    targetRules = ["targets"]
    paths = ["targeted"]
  TOML
  "allowlist-set-normalization" => <<~TOML,
    [[rules]]
    id = "sets"
    regex = "sets"
    [[rules.allowlists]]
    commits = [" B ", "a", "b"]
    stopWords = ["Z", "z", "a"]
  TOML
  "extend-default-path-conflict" => <<~TOML,
    [extend]
    useDefault = true
    path = "somewhere.toml"
    [[rules]]
    id = "local"
    regex = "local"
  TOML
  "extend-url-noop" => <<~TOML,
    [extend]
    url = "https://example.invalid/config.toml"
    [[rules]]
    id = "local"
    regex = "local"
  TOML
  "invalid-min-version-dev-build" => <<~TOML,
    minVersion = "not-semver"
    [[rules]]
    id = "versioned"
    regex = "versioned"
  TOML
  "negative-secret-group" => <<~TOML,
    [[rules]]
    id = "negative-group"
    regex = "(secret)"
    secretGroup = -1
  TOML
  "unicode-simple-lowercase" => <<~TOML,
    [[rules]]
    id = "unicode-lower"
    regex = "unicode"
    keywords = ["İ", "I", "ẞ"]
    [[rules.allowlists]]
    commits = [" İ ", "ẞ"]
    stopWords = ["İ", "ẞ"]
  TOML
  "weak-scalars-to-string-and-list" => <<~TOML,
    title = 123
    description = true
    minVersion = 1.25
    [extend]
    url = false
    disabledRules = "A,B"
    [[rules]]
    id = 456
    description = 2.5
    regex = 789
    keywords = 12
    tags = true
    [[rules.allowlists]]
    description = 99
    commits = false
    paths = 7
    regexes = 42
    stopWords = 2.5
  TOML
  "weak-string-list-hook-and-mixed-array" => <<~TOML,
    [extend]
    disabledRules = ""
    [[rules]]
    id = "comma"
    regex = "comma"
    keywords = "ONE,TWO"
    tags = ""
    [[rules.allowlists]]
    commits = "A,B"
    regexes = "first,second"
    stopWords = "X,Y"
    [[rules]]
    id = "mixed"
    regex = "mixed"
    keywords = [1, true, 2.5, "X"]
    tags = [false, 9]
  TOML
  "weak-numeric-and-pointer-fields" => <<~TOML,
    [[rules]]
    id = "primary"
    regex = "(a)(b)"
    secretGroup = 1.9
    entropy = "2.5"
    skipReport = "1"
    [[rules.required]]
    id = 123
    withinLines = true
    withinColumns = "0x2"
    [[rules]]
    id = 123
    regex = 123
  TOML
  "weak-empty-string-numerics" => <<~TOML,
    [[rules]]
    id = "x"
    regex = "(x)"
    secretGroup = ""
    entropy = ""
    skipReport = ""
    [[rules.required]]
    id = "y"
    withinLines = ""
    withinColumns = ""
    [[rules]]
    id = "y"
    regex = "y"
  TOML
  "weak-int-lower-bound" => <<~TOML,
    [[rules]]
    id = "int-min"
    regex = "(x)"
    secretGroup = "-9223372036854775808"
  TOML
  "weak-int-positive-overflow" => <<~TOML,
    [[rules]]
    id = "int-overflow"
    regex = "(x)"
    secretGroup = "9223372036854775808"
  TOML
  "weak-float-overflow" => <<~TOML,
    [[rules]]
    id = "float-overflow"
    regex = "x"
    entropy = "1e999"
  TOML
  "weak-float-underflow" => <<~TOML,
    [[rules]]
    id = "float-underflow"
    regex = "x"
    entropy = "1e-999"
  TOML
  "weak-nonfinite-string-and-list" => <<~TOML,
    title = inf
    description = -inf
    minVersion = nan
    [extend]
    disabledRules = [inf, -inf, nan]
    [[rules]]
    id = "nonfinite-strings"
    regex = "x"
    tags = [inf, -inf, nan]
  TOML
  "weak-nonfinite-entropy" => <<~TOML,
    [[rules]]
    id = "negative-infinity"
    regex = "x"
    entropy = -inf
    [[rules]]
    id = "not-a-number"
    regex = "x"
    entropy = nan
    [[rules]]
    id = "positive-infinity"
    regex = "x"
    entropy = inf
  TOML
  "weak-special-string-floats" => <<~TOML,
    [[rules]]
    id = "negative-infinity"
    regex = "x"
    entropy = "-inFiNiTy"
    [[rules]]
    id = "not-a-number"
    regex = "x"
    entropy = "NaN"
    [[rules]]
    id = "positive-infinity"
    regex = "x"
    entropy = "+INF"
  TOML
  "weak-hex-float-boundaries" => <<~TOML,
    [[rules]]
    id = "minimum-subnormal"
    regex = "x"
    entropy = "0x1p-1074"
    [[rules]]
    id = "round-above-halfway"
    regex = "x"
    entropy = "0x1.0000000000000800000000000001p0"
    [[rules]]
    id = "zero-huge-exponent"
    regex = "x"
    entropy = "0x0p999999999999999999999999"
    [[rules]]
    id = "mantissa-sixteen-digits"
    regex = "x"
    entropy = "0x1000000000000000p-60"
    [[rules]]
    id = "mantissa-seventeen-digits"
    regex = "x"
    entropy = "0x10000000000000000p-64"
    [[rules]]
    id = "mantissa-discarded-tail"
    regex = "x"
    entropy = "0x10000000000000001p-64"
  TOML
  "weak-decimal-scanner-below-bound" => <<~TOML,
    [[rules]]
    id = "decimal-below"
    regex = "x"
    entropy = "1#{'0' * 799}e-799"
  TOML
  "weak-decimal-scanner-at-bound" => <<~TOML,
    [[rules]]
    id = "decimal-at"
    regex = "x"
    entropy = "1#{'0' * 800}e-800"
  TOML
  "weak-decimal-scanner-above-bound" => <<~TOML,
    [[rules]]
    id = "decimal-above"
    regex = "x"
    entropy = "1#{'0' * 801}e-801"
  TOML
  "weak-decimal-scanner-discarded-tail" => <<~TOML,
    [[rules]]
    id = "decimal-tail"
    regex = "x"
    entropy = "1#{'0' * 799}5e-800"
  TOML
  "weak-decimal-fast-path-boundaries" => <<~TOML,
    [[rules]]
    id = "fast-path-799"
    regex = "x"
    entropy = "#{'1' * 799}e-798"
    [[rules]]
    id = "fast-path-800"
    regex = "x"
    entropy = "#{'1' * 800}e-799"
    [[rules]]
    id = "fast-path-801"
    regex = "x"
    entropy = "#{'1' * 801}e-800"
  TOML
  "weak-hex-exponent-cap-overflow" => <<~TOML,
    [[rules]]
    id = "capped-overflow"
    regex = "x"
    entropy = "0x1#{'0' * 25_000}p-100000"
  TOML
  "weak-hex-exponent-cap-underflow" => <<~TOML,
    [[rules]]
    id = "capped-underflow"
    regex = "x"
    entropy = "0x0.#{'0' * 24_999}1p100000"
  TOML
  "weak-single-table-lifts" => <<~TOML,
    allowlists = { targetRules = "x", paths = "targeted" }
    rules = [
      { id = "x", regex = "x", allowlists = { regexes = "allow" }, required = { id = "y" } },
      { id = "y", regex = "y" }
    ]
  TOML
  "weak-empty-map-to-lists" => <<~TOML,
    rules = {}
    allowlists = {}
  TOML
  "weak-use-default-bool" => <<~TOML,
    [extend]
    useDefault = 1
    [[rules]]
    id = "local"
    regex = "local"
  TOML
  "weak-condition-after-conversion" => <<~TOML,
    [[rules]]
    id = "condition"
    regex = "condition"
    [[rules.allowlists]]
    condition = false
    commits = "abc"
  TOML
  "weak-regex-target-after-conversion" => <<~TOML,
    [[rules]]
    id = "target"
    regex = "target"
    [[rules.allowlists]]
    regexTarget = 1
    commits = "abc"
  TOML
  "weak-invalid-secret-group" => <<~TOML,
    [[rules]]
    id = "invalid-secret-group"
    regex = "x"
    secretGroup = "no"
  TOML
  "weak-invalid-entropy" => <<~TOML,
    [[rules]]
    id = "invalid-entropy"
    regex = "x"
    entropy = "no"
  TOML
  "weak-invalid-skip-report" => <<~TOML,
    [[rules]]
    id = "invalid-skip-report"
    regex = "x"
    skipReport = "yes"
  TOML
  "weak-invalid-title-shape" => <<~TOML,
    title = { nested = 1 }
  TOML
  "weak-invalid-rules-shape" => <<~TOML,
    rules = 1
  TOML
  "weak-invalid-extend-shape" => <<~TOML,
    extend = []
  TOML
  "weak-invalid-keywords-shape" => <<~TOML,
    [[rules]]
    id = "invalid-keywords"
    regex = "x"
    keywords = { a = 1 }
  TOML
  "origin-aware-metadata" => <<~TOML,
    title = "origin source"
    [[rules]]
    id = "origin"
    regex = "origin"
  TOML
  "malformed-toml" => "[[rules]\nid = \"broken\"\n",
  "invalid-regex-panic" => <<~TOML,
    [[rules]]
    id = "panic"
    regex = "("
  TOML
  "invalid-regex-leading-repeat" => <<~TOML,
    [[rules]]
    id = "panic-leading-repeat"
    regex = "*"
  TOML
  "invalid-regex-reverse-repeat" => <<~TOML,
    [[rules]]
    id = "panic-reverse-repeat"
    regex = "a{2,1}"
  TOML
  "invalid-regex-escape" => <<~'TOML',
    [[rules]]
    id = "panic-escape"
    regex = '''\q'''
  TOML
  "invalid-regex-class-range" => <<~TOML,
    [[rules]]
    id = "panic-class-range"
    regex = "[z-a]"
  TOML
  "invalid-regex-lookahead" => <<~TOML,
    [[rules]]
    id = "panic-lookahead"
    regex = "(?=x)"
  TOML
}.freeze

revision = capture("git", "rev-parse", "HEAD", chdir: ORACLE).strip
abort "upstream revision mismatch: #{revision}" unless revision == REVISION
oracle_status_before = capture("git", "status", "--porcelain=v1", "--untracked-files=all", chdir: ORACLE)
default_config = capture("git", "show", "#{REVISION}:config/gitleaks.toml", chdir: ORACLE)
abort "default config hash mismatch" unless sha(default_config) == DEFAULT_SHA256

fixture_paths = FIXTURE_ROOT.glob("**/*.toml").sort
abort "expected 50 copied config fixtures, got #{fixture_paths.length}" unless fixture_paths.length == 50

fixture_inputs = fixture_paths.map do |path|
  relative = path.relative_path_from(FIXTURE_ROOT).to_s
  raw = path.binread
  {
    "kind" => "upstream-fixture", "path" => relative, "sha256" => sha(raw),
    "config_base64" => Base64.strict_encode64(raw)
  }
end
focused_inputs = FOCUSED_FILES.sort.map do |path, raw|
  {
    "kind" => "focused-auxiliary", "path" => path, "sha256" => sha(raw),
    "config_base64" => Base64.strict_encode64(raw)
  }
end
inputs = fixture_inputs + focused_inputs

cases = fixture_inputs.map do |input|
  relative = input.fetch("path")
  {
    "id" => "fixture/#{relative.delete_suffix('.toml')}",
    "category" => "upstream-fixture",
    "manifest_ids" => fixture_manifest_ids(relative),
    "source" => {
      "kind" => "path", "path" => "../testdata/config/#{relative}",
      "config_base64" => input.fetch("config_base64")
    }
  }
end
cases << {
  "id" => "default/pinned", "category" => "default", "manifest_ids" => [],
  "source" => {"kind" => "default", "config_base64" => Base64.strict_encode64(default_config)}
}
FOCUSED_INLINE.each do |name, raw|
  kind = name == "origin-aware-metadata" ? "origin" : "inline"
  source = {"kind" => kind, "config_base64" => Base64.strict_encode64(raw)}
  source["origin"] = "virtual/config.toml" if kind == "origin"
  cases << {
    "id" => "focused/#{name}", "category" => "focused",
    "manifest_ids" => (name == "allowlist-set-normalization" ? ["TM-0072"] : []),
    "source" => source
  }
end
%w[reentrant-a reentrant-b].each do |name|
  raw = FOCUSED_FILES.fetch("focused/reentrant.toml")
  cases << {
    "id" => "focused/#{name}", "category" => "extension-reentrant", "manifest_ids" => [],
    "source" => {
      "kind" => "path", "path" => "../testdata/config/focused/reentrant.toml",
      "config_base64" => Base64.strict_encode64(raw)
    }
  }
end
{
  "depth-limit" => "focused/depth-root.toml",
  "disabled-unknown-diagnostic" => "focused/disabled-unknown.toml",
  "extended-targeted-existing-is-dropped" => "focused/targeted-existing-root.toml",
  "extended-targeted-missing-is-dropped" => "focused/targeted-missing-root.toml",
  "depth-two-targeted-is-dropped" => "focused/targeted-depth-root.toml",
  "disabled-required-dependency-remains-dangling" => "focused/required-disabled-root.toml"
}.each do |name, relative|
  raw = FOCUSED_FILES.fetch(relative)
  cases << {
    "id" => "focused/#{name}", "category" => "extension-focused", "manifest_ids" => [],
    "source" => {
      "kind" => "path", "path" => "../testdata/config/#{relative}",
      "config_base64" => Base64.strict_encode64(raw)
    }
  }
end
cases.sort_by! { |item| item.fetch("id") }
abort "duplicate case IDs" unless cases.map { |item| item.fetch("id") }.uniq.length == cases.length

go_env = {
  "GOCACHE" => ENV.fetch("GOCACHE", File.join(Dir.tmpdir, "rustleaks-go-cache")),
  "GOMODCACHE" => ENV.fetch("GOMODCACHE", File.join(Dir.tmpdir, "rustleaks-go-mod-cache"))
}

requests = []
outcomes = []
Dir.mktmpdir("rustleaks-config-oracle-") do |build_directory|
  binary = File.join(build_directory, "config-oracle")
  capture("go", "build", "-o", binary, ".", chdir: ORACLE_MODULE, env: go_env)
  cases.each do |item|
    request = {
      "protocol_version" => PROTOCOL_VERSION,
      "id" => item.fetch("id"),
      "category" => item.fetch("category"),
      "manifest_ids" => item.fetch("manifest_ids"),
      "input_sha256" => sha(Base64.strict_decode64(item.fetch("source").fetch("config_base64"))),
      "source" => item.fetch("source")
    }
    requests << request
    Dir.mktmpdir("rustleaks-config-case-") do |case_directory|
      case_root = Pathname(case_directory)
      FileUtils.mkdir_p(case_root.join("config"))
      FileUtils.mkdir_p(case_root.join("testdata/config"))
      fixture_inputs.each do |input|
        destination = case_root.join("testdata/config", input.fetch("path"))
        FileUtils.mkdir_p(destination.dirname)
        destination.binwrite(Base64.strict_decode64(input.fetch("config_base64")))
      end
      FOCUSED_FILES.each do |relative, raw|
        destination = case_root.join("testdata/config", relative)
        FileUtils.mkdir_p(destination.dirname)
        destination.binwrite(raw)
      end
      output = capture(binary, "--config-one", chdir: case_root.join("config"), stdin_data: json_line(request))
      parsed = JSON.parse(output)
      abort "oracle returned wrong ID for #{item.fetch('id')}" unless parsed.fetch("id") == item.fetch("id")
      abort "oracle returned wrong revision" unless parsed.fetch("upstream_revision") == REVISION
      abort "oracle returned wrong default hash" unless parsed.fetch("default_config_sha256") == DEFAULT_SHA256
      outcomes << parsed
    end
  end
end

first_reentrant = outcomes.find { |item| item.fetch("id") == "focused/reentrant-a" }
second_reentrant = outcomes.find { |item| item.fetch("id") == "focused/reentrant-b" }
normalize_id = ->(item) { item.reject { |key, _value| key == "id" } }
abort "fresh-process reentrant outcomes differ" unless normalize_id.call(first_reentrant) == normalize_id.call(second_reentrant)

covered_manifest_ids = ((29..31).to_a + (34..72).to_a).map { |number| format("TM-%04d", number) }
deferred_manifest_ids = %w[TM-0028 TM-0032 TM-0033]
mapped_manifest_ids = cases.flat_map { |item| item.fetch("manifest_ids") }.uniq.sort
abort "manifest coverage mapping mismatch" unless mapped_manifest_ids == covered_manifest_ids.sort
default_outcome = outcomes.find { |item| item.fetch("id") == "default/pinned" }
abort "default config did not compile" unless default_outcome["error"].nil?
abort "default config rule count changed" unless default_outcome.dig("effective", "rules")&.length == 222
abort "default ordered-rule count changed" unless default_outcome.dig("effective", "ordered_rule_ids")&.length == 222
simple_outcome = outcomes.find { |item| item.fetch("id") == "fixture/simple" }
abort "simple duplicate bookkeeping changed" unless simple_outcome.dig("effective", "rules")&.length == 36 &&
                                                   simple_outcome.dig("effective", "ordered_rule_ids")&.length == 37 &&
                                                   simple_outcome.dig("effective", "duplicate_rule_ids")&.length == 1
depth_outcome = outcomes.find { |item| item.fetch("id") == "focused/depth-limit" }
depth_ids = depth_outcome.dig("effective", "rules")&.map { |rule| rule.fetch("id") }
abort "extension depth semantics changed" unless depth_ids == %w[depth-1 depth-2 depth-root]
outcomes.zip(requests).each do |outcome, request|
  abort "config input hash mismatch for #{request.fetch('id')}" unless outcome.fetch("config_sha256") == request.fetch("input_sha256")
end
successful = outcomes.count { |item| item["error"].nil? }
failed = outcomes.length - successful
source_schema = {
  "schema_version" => 1,
  "request" => %w[protocol_version id category manifest_ids input_sha256 source],
  "source_kinds" => %w[default inline origin path],
  "response" => %w[protocol_version oracle_mode id upstream_revision default_config_sha256 go_version source config_sha256 effective diagnostics error],
  "canonicalization" => {
    "rules" => "sorted by rule ID because Config.Rules is a Go map",
    "normalized_keywords" => "sorted because Config.Keywords is a Go map set",
    "allowlist_commits_stop_words" => "sorted because Allowlist.Validate rebuilds these values from Go maps",
    "non_finite_entropy" => "finite entropy is a JSON number; NaN and infinities use NaN, +Inf, or -Inf strings while entropy_bits remains exact",
    "all_other_lists" => "preserved exactly, including ordered-rule duplicates"
  }
}

schema_bytes = JSON.pretty_generate(source_schema) + "\n"
inputs_bytes = inputs.sort_by { |item| [item.fetch("kind"), item.fetch("path")] }.map { |item| json_line(item) }.join
requests_bytes = requests.map { |item| json_line(item) }.join
outcomes_bytes = outcomes.map { |item| json_line(item) }.join
config_tree_records = fixture_inputs.map { |item| "#{item.fetch('path')}\t#{item.fetch('sha256')}\n" }.join
manifest = {
  "schema_version" => 1,
  "protocol_version" => PROTOCOL_VERSION,
  "upstream_revision" => REVISION,
  "default_config_sha256" => DEFAULT_SHA256,
  "schema_sha256" => sha(schema_bytes),
  "oracle_main_sha256" => sha(ORACLE_MODULE.join("main.go").binread),
  "oracle_test_sha256" => sha(ORACLE_MODULE.join("main_test.go").binread),
  "copied_config_tree_sha256" => sha(config_tree_records),
  "inputs_sha256" => sha(inputs_bytes),
  "requests_sha256" => sha(requests_bytes),
  "outcomes_sha256" => sha(outcomes_bytes),
  "case_totals" => {
    "all" => cases.length, "upstream_fixtures" => fixture_inputs.length,
    "default" => 1, "focused" => cases.length - fixture_inputs.length - 1,
    "successful" => successful, "errors" => failed
  },
  "covered_manifest_ids" => covered_manifest_ids,
  "deferred_manifest_ids" => deferred_manifest_ids,
  "deferred_reason" => "CommitAllowed, PathAllowed, and RegexAllowed are execution semantics for later allowlist/GoRegex gates, not configuration construction.",
  "fresh_process_per_case" => true,
  "isolated_fixture_tree_per_case" => true
}
manifest_bytes = JSON.pretty_generate(manifest) + "\n"
readme = <<~MARKDOWN
  # Canonical Go configuration corpus

  Generated by `compat/generate_config_corpus.rb` from pinned upstream
  `#{REVISION}`. Every one of the #{cases.length} cases runs in a fresh Go
  process and a separate temporary copy of the configuration fixture tree, so
  upstream's process-global extension-depth counter cannot leak between cases.

  The corpus contains all #{fixture_inputs.length} copied `testdata/config`
  TOMLs, the byte-exact pinned default TOML, and #{cases.length - fixture_inputs.length - 1}
  focused permissiveness, validation, alias, required-rule, diagnostic, and
  extension cases. `outcomes-v1.jsonl` has #{successful} successful effective
  configurations and #{failed} structured errors/panics.

  Canonicalization is deliberately narrow: rule-map keys and the global keyword
  set are sorted; commits and stop words are sorted only because upstream
  rebuilds those semantic sets from Go maps. Ordered rules, duplicates, tags,
  keywords, required rules, patterns, target rules, and allowlist order remain
  observable and unchanged.

  `TM-0029..TM-0031` and `TM-0034..TM-0072` cover configuration construction.
  `TM-0028`, `TM-0032`, and `TM-0033` are covered by the allowlist and GoRegex
  execution corpora instead.

  Regenerate with:

  ```sh
  ruby compat/generate_config_corpus.rb
  ruby compat/generate_config_corpus.rb --check
  ```
MARKDOWN

files = {
  "README.md" => readme,
  "schema-v1.json" => schema_bytes,
  "manifest-v1.json" => manifest_bytes,
  "inputs-v1.jsonl" => inputs_bytes,
  "requests-v1.jsonl" => requests_bytes,
  "outcomes-v1.jsonl" => outcomes_bytes,
  "default-gitleaks.toml" => default_config
}

if CHECK
  extras = OUTPUT_ROOT.exist? ? OUTPUT_ROOT.children.map(&:basename).map(&:to_s) - files.keys : []
  abort "unexpected config corpus files: #{extras.join(', ')}" unless extras.empty?
  files.each do |name, expected|
    path = OUTPUT_ROOT.join(name)
    abort "missing #{path}" unless path.file?
    actual = path.binread
    abort "#{path} differs (expected #{sha(expected)}, got #{sha(actual)})" unless actual == expected.b
  end
else
  FileUtils.mkdir_p(OUTPUT_ROOT)
  files.each { |name, contents| OUTPUT_ROOT.join(name).binwrite(contents) }
end

abort "config corpus generation changed sibling oracle status" unless capture(
  "git", "status", "--porcelain=v1", "--untracked-files=all", chdir: ORACLE
) == oracle_status_before
abort "config corpus generation changed sibling revision" unless capture(
  "git", "rev-parse", "HEAD", chdir: ORACLE
).strip == REVISION

puts "config corpus: #{cases.length} cases (#{successful} effective, #{failed} errors), outcomes #{sha(outcomes_bytes)}"
