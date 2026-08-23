#!/usr/bin/env ruby
# frozen_string_literal: true

# Regenerates the mechanical upstream inventory portion of test-manifest.toml.
# Behavioral mappings and assertion rows remain coordinator-owned additions.
# Only the explicitly certified config and M4-M7 case identities below are emitted
# as implemented; every other mechanical identity remains inventoried.

require "digest"
require "find"
require "json"
require "open3"
require "pathname"
require "tmpdir"

ROOT = Pathname(__dir__).parent
ORACLE = ROOT.parent.join("gitleaks")
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
MODULE = "github.com/zricethezav/gitleaks/v8"
BEHAVIOR_MATRIX = ROOT.join("compat/behavior-matrix.toml")
API_DISPOSITIONS = ROOT.join("compat/api-dispositions-v1.jsonl")
FINAL_BEHAVIOR_STATUSES = %w[
  traceability-complete
  explicit-cli-polish-follow-up
  implemented
  implemented-native-linux-windows-runtime-follow-up
  implemented-normalized-diagnostics
  implemented-pending-native-ci
  implemented-pending-native-windows
  implemented-raw
  implemented-safe-boundary
  implemented-safe-disclosure-disposition
  implemented-safe-error-disposition
  implemented-safe-error-dispositions
  implemented-safe-filesystem-disposition
  implemented-safe-in-memory-spool
  implemented-safe-numeric-disposition
  implemented-safe-overflow-disposition
  implemented-safe-process-disposition
  implemented-safe-profile
  implemented-timeout-ctrl-c-follow-up
].freeze
M4_DETECT_CASE_IDS = %w[
  TM-0079 TM-0081 TM-0082 TM-0083 TM-0092 TM-0093 TM-0095 TM-0096
  TM-0138 TM-0165 TM-0166 TM-0168 TM-0169 TM-0170
].freeze
M4_LINKED_CORPUS_CASE_IDS = ROOT.join("compat/detect-corpus/requests-v1.jsonl")
  .each_line
  .flat_map { |line| JSON.parse(line).fetch("test_case_ids") }
  .uniq
  .sort
  .freeze
abort "M4 linked detector identities changed" unless M4_LINKED_CORPUS_CASE_IDS == M4_DETECT_CASE_IDS.sort
M5_ALLOWLIST_CASE_IDS = [
  *%w[TM-0074 TM-0075 TM-0076 TM-0077],
  *%w[TM-0085 TM-0086 TM-0087 TM-0088 TM-0089],
  *(102..115).map { |number| format("TM-%04d", number) },
  *(156..163).map { |number| format("TM-%04d", number) }
].freeze
M5_ALLOWLIST_REQUESTS = ROOT.join("compat/allowlist-corpus/requests-v1.jsonl")
  .each_line
  .map { |line| JSON.parse(line) }
  .freeze
M5_LINKED_CORPUS_CASE_IDS = M5_ALLOWLIST_REQUESTS
  .flat_map { |request| request.fetch("test_case_ids") }
  .uniq
  .sort
  .freeze
abort "M5 linked allowlist identities changed" unless M5_LINKED_CORPUS_CASE_IDS == M5_ALLOWLIST_CASE_IDS.sort
M5_CASE_BEHAVIOR_IDS = M5_ALLOWLIST_REQUESTS.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |request, mapping|
  request.fetch("test_case_ids").each do |case_id|
    mapping[case_id].concat(request.fetch("behavior_ids"))
    mapping[case_id].uniq!
  end
end.freeze
M6_DECODER_CASE_IDS = ["TM-0078", *(186..240).map { |number| format("TM-%04d", number) }].freeze
M6_DECODER_REQUESTS = ROOT.join("compat/decoder-corpus/requests-v1.jsonl")
  .each_line
  .map { |line| JSON.parse(line) }
  .freeze
M6_LINKED_CORPUS_CASE_IDS = M6_DECODER_REQUESTS
  .flat_map { |request| request.fetch("test_case_ids") }
  .uniq
  .sort
  .freeze
expected_m6_links = ["TM-0078", *(187..240).map { |number| format("TM-%04d", number) }].sort
abort "M6 linked decoder identities changed" unless M6_LINKED_CORPUS_CASE_IDS == expected_m6_links
M6_CASE_BEHAVIOR_IDS = M6_DECODER_REQUESTS.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |request, mapping|
  request.fetch("test_case_ids").each do |case_id|
    mapping[case_id].concat(request.fetch("behavior_ids"))
    mapping[case_id].uniq!
  end
end
M6_CASE_BEHAVIOR_IDS["TM-0186"] = %w[DEC-001 DEC-002 DEC-003 DEC-004 DEC-005]
M6_CASE_BEHAVIOR_IDS.freeze
M7_COMPOSITE_REQUESTS = ROOT.join("compat/composite-corpus/requests-v1.jsonl")
  .each_line
  .map { |line| JSON.parse(line) }
  .freeze
M7_LINKED_CORPUS_CASE_IDS = M7_COMPOSITE_REQUESTS
  .flat_map { |request| request.fetch("test_case_ids") }
  .uniq
  .sort
  .freeze
expected_m7_links = %w[TM-0084 TM-0242 TM-0243 TM-0244 TM-0246 TM-0247 TM-0248 TM-0249 TM-0250]
abort "M7 linked composite identities changed" unless M7_LINKED_CORPUS_CASE_IDS == expected_m7_links
M7_COMPOSITE_CASE_IDS = ["TM-0084", *(241..250).map { |number| format("TM-%04d", number) }].freeze
M7_CASE_BEHAVIOR_IDS = M7_COMPOSITE_REQUESTS.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |request, mapping|
  request.fetch("test_case_ids").each do |case_id|
    mapping[case_id].concat(request.fetch("behavior_ids"))
    mapping[case_id].uniq!
  end
end
M7_CASE_BEHAVIOR_IDS["TM-0084"].unshift("COMP-001")
M7_CASE_BEHAVIOR_IDS["TM-0241"] = %w[RED-001 RED-002]
M7_CASE_BEHAVIOR_IDS["TM-0245"] = %w[RED-001]
M7_CASE_BEHAVIOR_IDS["TM-0250"] << "RED-003"
M7_CASE_BEHAVIOR_IDS.freeze
M9_SOURCE_ROOT = ROOT.join("compat/source-corpus")
M9_SOURCE_MANIFEST_PATH = M9_SOURCE_ROOT.join("manifest-v1.json")
M9_SOURCE_MANIFEST = JSON.parse(M9_SOURCE_MANIFEST_PATH.read).freeze
M9_SOURCE_REQUESTS = M9_SOURCE_ROOT.join("requests-v1.jsonl")
  .each_line
  .map { |line| JSON.parse(line) }
  .freeze
M9_SOURCE_CASE_IDS = %w[
  TM-0098 TM-0099 TM-0100 TM-0116 TM-0117 TM-0118 TM-0119 TM-0120 TM-0121
  TM-0122 TM-0123 TM-0124 TM-0125 TM-0126 TM-0128 TM-0129 TM-0130 TM-0131
  TM-0132 TM-0147 TM-0148 TM-0149 TM-0150 TM-0151 TM-0152 TM-0153 TM-0154
  TM-0269 TM-0270 TM-0271 TM-0272 TM-0273 TM-0274 TM-0275
].freeze
M9_READER_CASE_IDS = %w[
  TM-0098 TM-0099 TM-0100 TM-0147 TM-0148 TM-0149 TM-0150 TM-0151 TM-0152
  TM-0153 TM-0154
].freeze
M9_LINKED_CORPUS_CASE_IDS = M9_SOURCE_REQUESTS
  .flat_map { |request| request.fetch("test_case_ids") }
  .uniq
  .sort
  .freeze
abort "M9 linked source identities changed" unless M9_LINKED_CORPUS_CASE_IDS == M9_SOURCE_CASE_IDS.sort
M9_CASE_BEHAVIOR_IDS = M9_SOURCE_REQUESTS.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |request, mapping|
  request.fetch("test_case_ids").each do |case_id|
    mapping[case_id].concat(request.fetch("behavior_ids"))
    mapping[case_id].uniq!
  end
end.freeze
M9_RUST_TEST = "crates/rustleaks-sources/tests/source_corpus.rs::complete_source_corpus_matches_frozen_go_outcomes_or_exact_safe_dispositions"
source_test_path, source_test_name = M9_RUST_TEST.split("::", 2)
source_test_text = ROOT.join(source_test_path).read
abort "M9 Rust source replay test disappeared" unless source_test_text.match?(/fn\s+#{Regexp.escape(source_test_name)}\s*\(/)
M10_GIT_ROOT = ROOT.join("compat/git-corpus")
M10_GIT_MANIFEST_PATH = M10_GIT_ROOT.join("manifest-v1.json")
M10_GIT_MANIFEST = JSON.parse(M10_GIT_MANIFEST_PATH.read).freeze
M10_GIT_REQUESTS = M10_GIT_ROOT.join("requests-v1.jsonl")
  .each_line
  .map { |line| JSON.parse(line) }
  .freeze
M10_GIT_LEAF_CASE_IDS = %w[TM-0134 TM-0135 TM-0136 TM-0137].freeze
M10_GIT_CASE_IDS = ["TM-0133", *M10_GIT_LEAF_CASE_IDS].freeze
M10_LINKED_CORPUS_CASE_IDS = M10_GIT_REQUESTS
  .flat_map { |request| request.fetch("test_case_ids") }
  .uniq
  .sort
  .freeze
abort "M10 linked Git identities changed" unless M10_LINKED_CORPUS_CASE_IDS == M10_GIT_LEAF_CASE_IDS.sort
M10_CASE_BEHAVIOR_IDS = M10_GIT_REQUESTS.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |request, mapping|
  request.fetch("test_case_ids").each do |case_id|
    mapping[case_id].concat(request.fetch("behavior_ids"))
    mapping[case_id].uniq!
  end
end
M10_CASE_BEHAVIOR_IDS["TM-0133"] = %w[GIT-022 GIT-023]
M10_CASE_BEHAVIOR_IDS.freeze
M10_GIT_INTENTION_CASES = M10_GIT_REQUESTS
  .select { |request| !request.fetch("git_intention_ids").empty? }
  .each_with_object({}) do |request, mapping|
    request.fetch("git_intention_ids").each { |id| mapping[id] = request.fetch("id") }
  end
  .freeze
M10_RUST_TEST = "crates/rustleaks-sources/tests/git_corpus.rs::valid_git_corpus_fragments_match_and_failures_have_safe_dispositions"
git_test_path, git_test_name = M10_RUST_TEST.split("::", 2)
git_test_text = ROOT.join(git_test_path).read
abort "M10 Rust Git replay test disappeared" unless git_test_text.match?(/fn\s+#{Regexp.escape(git_test_name)}\s*\(/)
M11_REPORT_ROOT = ROOT.join("compat/report-corpus")
M11_REPORT_COVERAGE_PATH = M11_REPORT_ROOT.join("coverage-v1.json")
M11_REPORT_COVERAGE = JSON.parse(M11_REPORT_COVERAGE_PATH.read).freeze
M11_REPORT_CASE_IDS = (251..268).map { |number| format("TM-%04d", number) }.freeze
abort "M11 report identity coverage changed" unless M11_REPORT_COVERAGE.fetch("required_report_test_case_ids") == M11_REPORT_CASE_IDS
M11_REPORT_CASE_BEHAVIOR_IDS = M11_REPORT_CASE_IDS.to_h do |case_id|
  number = case_id.delete_prefix("TM-").to_i
  behaviors = case number
              when 251..255 then %w[REPORT-010]
              when 256..258 then %w[REPORT-001 REPORT-004 REPORT-005]
              when 259..261 then %w[REPORT-001 REPORT-002 REPORT-003]
              when 262 then %w[REPORT-001 REPORT-006 REPORT-007]
              when 263..264 then %w[REPORT-001 REPORT-008 REPORT-009]
              when 265 then %w[REPORT-001 REPORT-002]
              when 266..268 then %w[REPORT-010 REPORT-011]
              end
  [case_id, behaviors]
end.freeze
M11_REPORT_RUST_TEST = "crates/rustleaks-report/tests/report_corpus.rs::every_representable_builtin_report_case_replays_exact_oracle_bytes; crates/rustleaks-report/tests/template.rs::every_template_oracle_case_has_an_exact_replay_or_named_safe_profile_disposition"
M11_CLI_ROOT = ROOT.join("compat/cli-corpus")
M11_CLI_MANIFEST_PATH = M11_CLI_ROOT.join("manifest-v1.json")
M11_CLI_MANIFEST = JSON.parse(M11_CLI_MANIFEST_PATH.read).freeze
abort "M11 CLI case coverage changed" unless M11_CLI_MANIFEST.fetch("case_count") == 34
abort "M11 CLI variant coverage changed" unless M11_CLI_MANIFEST.fetch("variant_count") == 119
abort "M11 CLI mutation coverage changed" unless M11_CLI_MANIFEST.fetch("mutation_control_count") == 20

def capture(*command, chdir: ORACLE, env: {})
  output, error, status = Open3.capture3(env, *command, chdir: chdir.to_s)
  abort "#{command.join(' ')} failed: #{error}" unless status.success?
  output
end

def with_archived_oracle
  Dir.mktmpdir("rustleaks-inventory-") do |directory|
    archive, error, status = Open3.capture3("git", "archive", "--format=tar", REVISION, chdir: ORACLE.to_s)
    abort "git archive failed: #{error}" unless status.success?
    _output, extract_error, extract_status = Open3.capture3(
      "tar", "-xf", "-", chdir: directory, stdin_data: archive
    )
    abort "extracting isolated oracle archive failed: #{extract_error}" unless extract_status.success?
    isolated = Pathname(directory)
    abort "isolated oracle unexpectedly aliases the sibling checkout" if isolated.realpath == ORACLE.realpath

    probe = isolated.join("testdata/.rustleaks-isolation-probe")
    probe.binwrite("temporary isolated write\n")
    abort "isolated write escaped into sibling oracle" if ORACLE.join("testdata/.rustleaks-isolation-probe").exist?
    probe.delete
    yield isolated
  end
end

abort "upstream revision mismatch" unless capture("git", "rev-parse", "HEAD").strip == REVISION

go_env = {
  "GOCACHE" => ENV.fetch("GOCACHE", File.join(Dir.tmpdir, "rustleaks-go-cache")),
  "GOMODCACHE" => ENV.fetch("GOMODCACHE", File.join(Dir.tmpdir, "rustleaks-go-mod-cache"))
}

test_files = ORACLE.glob("**/*_test.go").reject { |path| path.to_s.include?("/.git/") }.sort
root_source = {}
benchmark_source = {}
test_files.each do |path|
  relative = path.relative_path_from(ORACLE).to_s
  path.each_line.with_index(1) do |line, number|
    root_source[Regexp.last_match(1)] = [relative, number] if line =~ /^func (Test[A-Za-z0-9_]+)\(/
    benchmark_source[Regexp.last_match(1)] = [relative, number] if line =~ /^func (Benchmark[A-Za-z0-9_]+)\(/
  end
end

oracle_status_before = capture("git", "status", "--porcelain=v1", "--untracked-files=all")
oracle_index_before = capture("git", "ls-files", "-s", "--", "testdata")
test_events = with_archived_oracle do |isolated|
  capture("go", "test", "-json", "./...", chdir: isolated, env: go_env)
end
abort "dynamic discovery changed sibling oracle status" unless capture("git", "status", "--porcelain=v1", "--untracked-files=all") == oracle_status_before
abort "dynamic discovery changed sibling oracle fixture index" unless capture("git", "ls-files", "-s", "--", "testdata") == oracle_index_before

events = test_events.lines.each_with_object([]) do |line, found|
  event = JSON.parse(line)
  next unless event["Action"] == "pass" && event["Test"]
  found << [event.fetch("Package").sub(%r{\A#{Regexp.escape(MODULE)}/?}, ""), event.fetch("Test")]
end.uniq.sort

rule_files = ORACLE.glob("cmd/generate/config/rules/*.go").sort
constructors = rule_files.flat_map do |path|
  source = path.read
  matches = source.enum_for(:scan, /^func ([A-Z][A-Za-z0-9_]*)\(\) \*config\.Rule/m).map { Regexp.last_match }
  matches.each_with_index.map do |match, index|
    body_end = index + 1 < matches.length ? matches[index + 1].begin(0) : source.length
    body = source[match.begin(0)...body_end]
    helper = if body.include?("utils.ValidateWithPaths(")
               "validate_with_paths"
             elsif body.include?("utils.Validate(")
               "validate"
             else
               "none"
             end
    rule_id = body[/\bRuleID:\s*"([^"]+)"/, 1]
    abort "#{match[1]} has no literal RuleID" unless rule_id
    [match[1], path.relative_path_from(ORACLE).to_s, source[0...match.begin(0)].count("\n") + 1, helper, rule_id]
  end
end.sort_by(&:first)

main_source = ORACLE.join("cmd/generate/config/main.go").read
selected_in_order = main_source.lines.each_with_object([]) do |line, selected|
  next if line.lstrip.start_with?("//")
  match = line.match(/^\s*rules\.([A-Z][A-Za-z0-9_]*)\(\),/)
  selected << match[1] if match
end
rule_ids = ORACLE.join("config/gitleaks.toml").read.scan(/^id = "([^"]+)"$/).flatten
abort "selected/default rule count mismatch" unless selected_in_order.length == 222 && rule_ids.length == 222
constructors_by_name = constructors.to_h { |name, _path, _line, _helper, rule_id| [name, rule_id] }
selected_rule_ids = selected_in_order.to_h { |name| [name, constructors_by_name.fetch(name)] }
abort "selected constructor IDs differ from default TOML" unless selected_rule_ids.values.sort == rule_ids.sort

git_modes = capture("git", "ls-files", "-s", "--", "testdata").lines.to_h do |line|
  metadata, path = line.chomp.split("\t", 2)
  [path, metadata.split.first]
end

fixtures = []
Find.find(ORACLE.join("testdata").to_s) do |entry|
  path = Pathname(entry)
  next if path.directory?
  relative = path.relative_path_from(ORACLE).to_s
  mode = git_modes.fetch(relative)
  if path.symlink?
    fixtures << [relative, "symlink", mode, nil, nil, path.readlink.to_s]
  elsif path.file?
    fixtures << [relative, "regular", mode, path.size, Digest::SHA256.file(path).hexdigest, nil]
  end
end
fixtures.sort_by!(&:first)

git_intentions = [
  ["GIT-INT-001", "", "sources/TestGitLog/default-small", "sources/git_test.go", 10,
   "commented-out-flaky", "all", ["testdata/repos/small", "testdata/expected/git/small.txt"],
   "isolated copy; rename copied dotGit to .git", ["git", "-C", "<repo>", "log", "-p", "-U0", "--full-history", "--all", "--diff-filter=tuxdb"],
   "ordered-added-fragment-bytes", "testdata/expected/git/small.txt"],
  ["GIT-INT-002", "", "sources/TestGitLog/all-foo", "sources/git_test.go", 10,
   "commented-out-flaky", "all", ["testdata/repos/small", "testdata/expected/git/small-branch-foo.txt"],
   "isolated copy; rename copied dotGit to .git", ["git", "-C", "<repo>", "log", "-p", "-U0", "--all", "foo..."],
   "ordered-added-fragment-bytes", "testdata/expected/git/small-branch-foo.txt"],
  ["GIT-INT-003", "", "sources/TestGitDiff/working-tree", "sources/git_test.go", 66,
   "commented-out-flaky", "all", ["testdata/repos/small"],
   "isolated copy; rename copied dotGit to .git; replace copied main.go", ["git", "-C", "<repo>", "diff", "-U0", "--no-ext-diff", "."],
   "ordered-added-fragment-bytes", "inline:this line is added\\nand another one"],
  ["GIT-INT-004", "TM-0135", "detect/TestFromGit/simple-default", "detect/detect_test.go", 850,
   "active-not-windows", "not-windows", ["testdata/repos/small", "testdata/config/simple.toml"],
   "isolated copy; rename copied dotGit to .git; load .gitleaksignore", ["git", "-C", "<repo>", "log", "-p", "-U0", "--full-history", "--all", "--diff-filter=tuxdb"],
   "complete-finding-multiset-preserve-duplicates", "upstream expected Finding structs"],
  ["GIT-INT-005", "TM-0136", "detect/TestFromGit/simple-all-foo", "detect/detect_test.go", 850,
   "active-not-windows", "not-windows", ["testdata/repos/small", "testdata/config/simple.toml"],
   "isolated copy; rename copied dotGit to .git; load .gitleaksignore", ["git", "-C", "<repo>", "log", "-p", "-U0", "--all", "foo..."],
   "complete-finding-multiset-preserve-duplicates", "upstream expected Finding structs"],
  ["GIT-INT-006", "TM-0134", "detect/TestFromGit/archives", "detect/detect_test.go", 850,
   "active-not-windows", "not-windows", ["testdata/repos/archives", "testdata/config/archives.toml"],
   "isolated copy; rename copied dotGit to .git; archive depth 8", ["git", "-C", "<repo>", "log", "-p", "-U0", "--full-history", "--all", "--diff-filter=tuxdb"],
   "complete-finding-multiset-preserve-duplicates", "upstream expected Finding structs"],
  ["GIT-INT-007", "TM-0137", "detect/TestFromGitStaged", "detect/detect_test.go", 1328,
   "active", "all", ["testdata/repos/staged", "testdata/config/simple.toml"],
   "isolated copy; rename copied dotGit to .git; preserve staged index", ["git", "-C", "<repo>", "diff", "-U0", "--no-ext-diff", "--staged", "."],
   "complete-finding-multiset-preserve-duplicates", "upstream expected Finding structs"]
]

packages = capture("go", "list", "./...", env: go_env).lines.map(&:strip).sort
benchmarks = benchmark_source.keys.sort

expected = {
  packages: 16, test_files: 19, roots: 41, events: 275,
  benchmarks: 8, constructors: 225, selected: 222, fixtures: 215
}
actual = {
  packages: packages.length, test_files: test_files.length,
  roots: root_source.length, events: events.length, benchmarks: benchmarks.length,
  constructors: constructors.length, selected: selected_in_order.length,
  fixtures: fixtures.length
}
abort "inventory total mismatch: expected #{expected}, got #{actual}" unless actual == expected

regular_fixture_records = fixtures.select { |record| record[1] == "regular" }.map do |path, _kind, mode, size, digest, _target|
  host_equivalent_mode = mode == "100755" ? "755" : "644"
  "#{path}\t#{digest}\t#{host_equivalent_mode}\t#{size}\n"
end.join
fixture_record_sha256 = Digest::SHA256.hexdigest(regular_fixture_records)
expected_fixture_record_sha256 = "a29bcb807fc5466fb38bba0134fe6d5f41364e9efeae4980225cc21524fd4ed1"
abort "fixture record digest mismatch" unless fixture_record_sha256 == expected_fixture_record_sha256

def fixture_consumers(path)
  case path
  when %r{\Atestdata/archives/} then ["detect/TestDetectWithArchives", "source/archive"]
  when %r{\Atestdata/baseline/} then ["detect/TestFileLoadBaseline", "detect/TestIgnoreIssuesInBaseline"]
  when %r{\Atestdata/config/} then ["config tests", "detect custom-config tests", "regex corpus"]
  when %r{\Atestdata/expected/git/} then ["detect/TestFromGit", "sources disabled Git intentions"]
  when %r{\Atestdata/expected/report/} then ["report golden tests"]
  when %r{\Atestdata/gitleaksignore/} then ["detect/TestNormalizeGitleaksIgnorePaths"]
  when %r{\Atestdata/report/} then ["report/TestWriteTemplate"]
  when %r{\Atestdata/repos/archives/} then ["detect/TestFromGit archives"]
  when %r{\Atestdata/repos/nogit/} then ["detect/TestFromFiles"]
  when %r{\Atestdata/repos/small/} then ["detect/TestFromGit", "sources disabled Git intentions"]
  when %r{\Atestdata/repos/staged/} then ["detect/TestFromGitStaged"]
  when %r{\Atestdata/repos/symlinks/} then ["detect/TestDetectWithSymlinks"]
  else ["inventory review required"]
  end
end

quote = ->(value) { JSON.generate(value) }
lines = []
lines << "# Generated by compat/generate_inventory.rb; coordinator annotations may follow."
lines << "schema_version = 1"
lines << "upstream_revision = #{quote.call(REVISION)}"
lines << "status = \"understanding-complete\""
lines << ""
lines << "[expected_totals]"
lines << "packages = 16"
lines << "exported_api_identities = 607"
lines << "test_files = 19"
lines << "active_top_level_tests = 41"
lines << "nested_test_identities = 234"
lines << "macos_test_identities = 275"
lines << "benchmarks = 8"
lines << "exported_rule_constructors = 225"
lines << "default_rules = 222"
lines << "selected_helper_validations = 220"
lines << "generator_sample_cases = 6770"
lines << "generator_string_true_positive_cases = 6368"
lines << "generator_string_false_positive_cases = 342"
lines << "generator_path_true_positive_cases = 28"
lines << "generator_path_false_positive_cases = 32"
lines << "non_t_run_assertion_cases = 283"
lines << "benchmark_correctness_assertions = 6"
lines << "platform_skip_branches = 2"
lines << "deterministic_git_intentions = 7"
lines << "testdata_files = 214"
lines << "testdata_symlinks = 1"
lines << ""
lines << "[fixture_set]"
lines << "regular_record_stream_sha256 = #{quote.call(fixture_record_sha256)}"
lines << "regular_git_mode_100644 = 210"
lines << "regular_git_mode_100755 = 4"
lines << "symlink_git_mode_120000 = 1"
lines << "symlink_target = \"../source_file/id_ed25519\""
lines << "copy_root = \"compat/fixtures/upstream\""
lines << "tracked_entries = 215"
lines << "ascii_paths = 215"
lines << "invalid_utf8_regular_payloads = 67"
lines << ""
lines << "[traceability_corpora]"
lines << "api_inventory = \"compat/api-inventory-v1.json\""
lines << "api_inventory_sha256 = \"958ddaa92c5cce6afb21ef8209ce5689ff907cb2d9f152951bb75c795362125a\""
lines << "api_identity_set_sha256 = \"de2e917190f3fdcc24c3db77e3e0a5c7fdd09aff97805b066273f4a7b6e96e6b\""
lines << "api_dispositions = \"compat/api-dispositions-v1.jsonl\""
lines << "api_dispositions_sha256 = \"#{Digest::SHA256.file(API_DISPOSITIONS).hexdigest}\""
lines << "assertions = \"compat/assertion-corpus/assertions.jsonl\""
lines << "assertions_sha256 = \"13f1603e6cf32073262bb67d736b158b45a6149dddcb08b36667fab23e64b8c5\""
lines << "benchmark_links = \"compat/assertion-corpus/benchmark-links.jsonl\""
lines << "benchmark_links_sha256 = \"81aade22fd568a0cd6658fba5ff52563dc2ac3df3148a2cff368d75caa9cb1b5\""
lines << "platform_skips = \"compat/assertion-corpus/platform-skips.jsonl\""
lines << "platform_skips_sha256 = \"73bdf8c0d2b5b721ade1d519d29b43bc4a2aa81d3eeaf212e7c0bf91d9eb3a76\""
lines << "generator_constructors = \"compat/generator-corpus/constructors-v1.jsonl\""
lines << "generator_constructors_sha256 = \"b7f69ca6317157c7ca8015ec897ec82371e6e362067c6c799c61f0c4819cd7c1\""
lines << "generator_samples = \"compat/generator-corpus/samples-v1.jsonl\""
lines << "generator_samples_sha256 = \"b0d1e24c04f88ec3c875bcbd08a6e0cafbabd7f7cf8757af5e385eb83259b750\""
lines << "config_requests = \"compat/config-corpus/requests-v1.jsonl\""
lines << "config_requests_sha256 = \"91efa888f8fb2a875892f61629b561ceeb52c82bd503fdf6d25de59b5b6373bb\""
lines << "config_outcomes = \"compat/config-corpus/outcomes-v1.jsonl\""
lines << "config_outcomes_sha256 = \"1548a91af225e4e28523804590e81629c24cfa3a28270c84decd2bbeceecb6e4\""
lines << "config_cases = 112"
lines << "config_effective = 75"
lines << "config_errors = 37"
lines << "regex_expression_occurrences = 436"
lines << "regex_unique_patterns = 390"
lines << "regex_requests = 3618"
lines << "regex_compile_successes = 3581"
lines << "regex_compile_errors = 37"
lines << "regex_matching_requests = 879"
lines << "regex_adversarial_cases = 252"
lines << "regex_expressions = \"compat/regex-corpus/expressions-v1.jsonl\""
lines << "regex_expressions_sha256 = \"0811469d53321dd86de9c5c7577682028042864ff998ba328d33c57810e74824\""
lines << "regex_requests_path = \"compat/regex-corpus/requests-v1.jsonl\""
lines << "regex_requests_sha256 = \"99917c10d3dddc3bb2645029b474d6987d3fb44607acd5f8d6fdaadcc05a6577\""
lines << "regex_request_metadata = \"compat/regex-corpus/request-metadata-v1.jsonl\""
lines << "regex_request_metadata_sha256 = \"424276b289ee0e451ac145aa957ccd6ce29715834992a500dc7e57d8912173a3\""
lines << "regex_outcomes = \"compat/regex-corpus/outcomes-v1.jsonl\""
lines << "regex_outcomes_sha256 = \"a8e3ca94a0d1a7210b9260d738b35a623bad9b98f521688770dbce1130a0c394\""
lines << "regex_manifest_sha256 = \"380ff1fd219179bdf07b3830beedd416bca2494aae0071c4b04848207a9b8e24\""
lines << "detect_requests_sha256 = \"e2b77263b65d31b36639ff4da43776f634d321d9a6d133673b3527f0f07f8707\""
lines << "detect_outcomes_sha256 = \"a06329c834e7784484261c4f324ee7e49bdb21a9348f32860a3035fb8858771c\""
lines << "detect_cases = 84"
lines << "allowlist_requests_sha256 = \"779e9c5b71e215c2b159528ccef94f71b8b7e7e182e91d59dd1d2f7360b5a26d\""
lines << "allowlist_outcomes_sha256 = \"9cb2cf7bb909e137d9802f569dccd7f004610decfa2cf7e43d0676e5b14e72a3\""
lines << "allowlist_request_metadata_sha256 = \"c42cb275883a9eb50f49893343d238361a0652339f92eb521f9abbc0673435ad\""
lines << "allowlist_coverage_sha256 = \"45f3a08b36849f3eb507a029079ae7e2fe36482b31043c3cc6e7d8bbf0845182\""
lines << "allowlist_cases = 188"
lines << "allowlist_method_cases = 127"
lines << "allowlist_detect_cases = 61"
lines << "decoder_requests_sha256 = \"9b5ee04e0bc49b4b852b3f427ff44f58a8d3c463097c1022dac8a13799b8fed7\""
lines << "decoder_outcomes_sha256 = \"428d8e37112f9b26d65156a0a075a8cfd15897f2b0bc02d7cee7aae17cd9a8b3\""
lines << "decoder_request_metadata_sha256 = \"c8fe20631eead7ddf515d500051c468a115a09a6ec1f0f652e11ab3ea8bb5c9b\""
lines << "decoder_coverage_sha256 = \"c46d32a1b1e340ae1e6b41539ddf812ef2090bd582766fc79813a656512268c2\""
lines << "decoder_cases = 263"
lines << "decoder_decode_cases = 204"
lines << "decoder_detect_cases = 59"
lines << "composite_requests_sha256 = \"be01978f45cbeb6b180e4a28b3fa909c672f2690c8a3861e5088b4b09b5a531f\""
lines << "composite_outcomes_sha256 = \"a39ba5ae9c7228ee2a19a9c16e11892c1bd9afa5d97f1a6ab9ab5ce1d52ad601\""
lines << "composite_coverage_sha256 = \"e0d3b738854524c3b9ce620022c286728c08d807a9ff1e4a11f30401a99c2149\""
lines << "composite_negative_controls_sha256 = \"69dc393a8dea2fec2b88211e5bdcd4dcfb0e916eb4a05647dc47fac690fba0da\""
lines << "composite_cases = 182"
lines << "composite_findings = 275"
lines << "composite_required_findings = 1623"
lines << "session_requests_sha256 = \"d13327151d12bc208786350e42b3c04d722b392cc6f7d9acfa050dd32bc93898\""
lines << "session_outcomes_sha256 = \"026cd026ef68dce45672a6c80bd0850219382217ad0a091434cb303d439779fc\""
lines << "session_coverage_sha256 = \"a92e8bd8b57cac5ad832d4d4fd7f0e44ac20ba114a34cb5e1e8242c266b2d5ed\""
lines << "session_negative_controls_sha256 = \"6a6c4962409a55ce91fd29a30166533eb17ac5a14708280172ef2f3027d8ab95\""
lines << "session_cases = 45"
lines << "session_input_findings = 42"
lines << "session_collected_findings = 29"
lines << "session_baseline_findings = 33"
source_files = M9_SOURCE_MANIFEST.fetch("files")
lines << "source_generator_sha256 = \"#{Digest::SHA256.file(ROOT.join("compat/generate_source_corpus.rb")).hexdigest}\""
lines << "source_requests_sha256 = \"#{source_files.fetch("requests-v1.jsonl").fetch("sha256")}\""
lines << "source_outcomes_sha256 = \"#{source_files.fetch("outcomes-v1.jsonl").fetch("sha256")}\""
lines << "source_coverage_sha256 = \"#{source_files.fetch("coverage-v1.json").fetch("sha256")}\""
lines << "source_negative_controls_sha256 = \"#{source_files.fetch("negative-controls-v1.json").fetch("sha256")}\""
lines << "source_manifest_sha256 = \"#{Digest::SHA256.file(M9_SOURCE_MANIFEST_PATH).hexdigest}\""
lines << "source_readme_sha256 = \"#{source_files.fetch("README.md").fetch("sha256")}\""
lines << "source_cases = #{M9_SOURCE_MANIFEST.fetch("request_count")}"
lines << "source_fragments = #{M9_SOURCE_MANIFEST.fetch("fragment_count")}"
lines << "source_findings = #{M9_SOURCE_MANIFEST.fetch("finding_count")}"
lines << "source_issues = #{M9_SOURCE_MANIFEST.fetch("issue_count")}"
lines << "source_behaviors = #{M9_SOURCE_MANIFEST.fetch("behavior_count")}"
lines << "source_upstream_identities = #{M9_SOURCE_MANIFEST.fetch("upstream_identity_count")}"
lines.push("source_material_assertions = #{M9_SOURCE_MANIFEST.fetch("material_assertion_count")}")
git_files = M10_GIT_MANIFEST.fetch("files")
lines << "git_generator_sha256 = \"#{Digest::SHA256.file(ROOT.join("compat/generate_git_corpus.rb")).hexdigest}\""
lines << "git_requests_sha256 = \"#{git_files.fetch("requests-v1.jsonl").fetch("sha256")}\""
lines << "git_outcomes_sha256 = \"#{git_files.fetch("outcomes-v1.jsonl").fetch("sha256")}\""
lines << "git_coverage_sha256 = \"#{git_files.fetch("coverage-v1.json").fetch("sha256")}\""
lines << "git_negative_controls_sha256 = \"#{git_files.fetch("negative-controls-v1.json").fetch("sha256")}\""
lines << "git_manifest_sha256 = \"#{Digest::SHA256.file(M10_GIT_MANIFEST_PATH).hexdigest}\""
lines << "git_readme_sha256 = \"#{git_files.fetch("README.md").fetch("sha256")}\""
lines << "git_cases = #{M10_GIT_MANIFEST.fetch("request_count")}"
lines << "report_generator_sha256 = \"#{Digest::SHA256.file(ROOT.join("compat/generate_report_corpus.rb")).hexdigest}\""
lines << "report_requests_sha256 = \"#{Digest::SHA256.file(M11_REPORT_ROOT.join("requests-v1.jsonl")).hexdigest}\""
lines << "report_outcomes_sha256 = \"#{Digest::SHA256.file(M11_REPORT_ROOT.join("outcomes-v1.jsonl")).hexdigest}\""
lines << "report_coverage_sha256 = \"#{Digest::SHA256.file(M11_REPORT_COVERAGE_PATH).hexdigest}\""
lines << "report_readme_sha256 = \"#{Digest::SHA256.file(M11_REPORT_ROOT.join("README.md")).hexdigest}\""
lines << "report_cases = #{M11_REPORT_COVERAGE.fetch("case_count")}"
lines << "report_output_bytes = #{M11_REPORT_COVERAGE.fetch("output_byte_count")}"
lines << "report_error_cases = #{M11_REPORT_COVERAGE.fetch("error_case_count")}"
lines.push("report_behaviors = #{M11_REPORT_COVERAGE.fetch("behavior_ids").length}")
lines << "cli_generator_sha256 = \"#{Digest::SHA256.file(ROOT.join("compat/generate_cli_corpus.rb")).hexdigest}\""
lines << "cli_requests_sha256 = \"#{Digest::SHA256.file(M11_CLI_ROOT.join("requests-v1.jsonl")).hexdigest}\""
lines << "cli_outcomes_sha256 = \"#{Digest::SHA256.file(M11_CLI_ROOT.join("outcomes-v1.jsonl")).hexdigest}\""
lines << "cli_negative_controls_sha256 = \"#{Digest::SHA256.file(M11_CLI_ROOT.join("negative-controls-v1.json")).hexdigest}\""
lines << "cli_manifest_sha256 = \"#{Digest::SHA256.file(M11_CLI_MANIFEST_PATH).hexdigest}\""
lines << "cli_readme_sha256 = \"#{Digest::SHA256.file(M11_CLI_ROOT.join("README.md")).hexdigest}\""
lines << "cli_cases = #{M11_CLI_MANIFEST.fetch("case_count")}"
lines << "cli_variants = #{M11_CLI_MANIFEST.fetch("variant_count")}"
lines << "cli_fresh_processes = #{M11_CLI_MANIFEST.fetch("fresh_cli_process_count")}"
lines << "cli_exact_variants = #{M11_CLI_MANIFEST.fetch("exact_variant_count")}"
lines << "cli_disposition_variants = #{M11_CLI_MANIFEST.fetch("versioned_disposition_variant_count")}"
lines << "cli_findings_both = #{M11_CLI_MANIFEST.fetch("complete_duplicate_preserving_finding_count_both_implementations")}"
lines << "cli_report_bytes_both = #{M11_CLI_MANIFEST.fetch("raw_report_byte_count_both_implementations")}"
lines << "cli_parser_usage_bytes_both = #{M11_CLI_MANIFEST.fetch("parser_usage_byte_count_both_implementations")}"
lines << "cli_stderr_events_both = #{M11_CLI_MANIFEST.fetch("stderr_event_count_both_implementations")}"
lines.push("cli_mutation_controls = #{M11_CLI_MANIFEST.fetch("mutation_control_count")}")

packages.each do |package|
  lines << ""
  lines << "[[api_package]]"
  lines << "name = #{quote.call(package)}"
  lines << "status = \"implemented\""
  lines << "mapping_id = \"API-ALL-001\""
end

test_files.each do |path|
  relative = path.relative_path_from(ORACLE).to_s
  roots = root_source.select { |_name, source| source[0] == relative }.keys.sort
  file_benchmarks = benchmark_source.select { |_name, source| source[0] == relative }.keys.sort
  lines << ""
  lines << "[[test_file]]"
  lines << "path = #{quote.call(relative)}"
  lines << "active_top_level = #{roots.length}"
  lines << "top_level_names = #{quote.call(roots)}"
  lines << "benchmark_names = #{quote.call(file_benchmarks)}"
  lines << "status = \"final-disposition\""
end

events.each_with_index do |(package, name), index|
  case_id = format('TM-%04d', index + 1)
  root = name.split("/", 2).first
  source_path, source_line = root_source.fetch(root)
  platform = %w[TestFromGit TestDetectWithSymlinks].include?(root) ? "not-windows" : "all"
  lines << ""
  lines << "[[case]]"
  lines << "id = #{quote.call(case_id)}"
  lines << "package = #{quote.call(package)}"
  lines << "go_name = #{quote.call(name)}"
  lines << "source = #{quote.call(source_path)}"
  lines << "source_line = #{source_line}"
  lines << "top_level = #{name == root}"
  lines << "platform = #{quote.call(platform)}"
  if name == root && root == "TestFromGit"
    lines << "platform_skip_reason = #{quote.call('TODO: this fails on Windows: [git] fatal: bad object refs/remotes/origin/main?')}"
  elsif name == root && root == "TestDetectWithSymlinks"
    lines << "platform_skip_reason = #{quote.call("TODO: this returns no results on windows, I'm not sure why.")}"
  end
  behavior_ids = ["TM-ALL-001"]
  if source_path == "config/allowlist_test.go" && root == "TestValidate"
    behavior_ids << "CONFIG-COMPILE-002"
  elsif source_path == "config/config_test.go"
    behavior_ids.concat(["CONFIG-RAW-001", "CONFIG-COMPILE-002"])
    if %w[TestTranslateExtend TestExtendedRuleKeywordsAreDowncase].include?(root)
      behavior_ids << "CONFIG-EXTEND-003"
    end
  end
  config_construction = (source_path == "config/allowlist_test.go" && root == "TestValidate") ||
                        source_path == "config/config_test.go"
  m4_direct = M4_DETECT_CASE_IDS.include?(case_id)
  m5_allowlist = M5_ALLOWLIST_CASE_IDS.include?(case_id)
  m6_decoder = M6_DECODER_CASE_IDS.include?(case_id)
  m7_composite = M7_COMPOSITE_CASE_IDS.include?(case_id)
  m9_source = M9_SOURCE_CASE_IDS.include?(case_id)
  m10_git = M10_GIT_CASE_IDS.include?(case_id)
  m11_report = M11_REPORT_CASE_IDS.include?(case_id)
  assertion_allowlist = source_path == "cmd/generate/config/base/config_test.go" ||
                        (source_path == "config/allowlist_test.go" && %w[TestCommitAllowed TestPathAllowed TestRegexAllowed].include?(root))
  generator_helper = source_path == "cmd/generate/config/utils/generate_test.go"
  session_remaining = source_path == "detect/baseline_test.go" || root == "TestNormalizeGitleaksIgnorePaths"
  engine_remaining = %w[TM-0080 TM-0090 TM-0091 TM-0094 TM-0097 TM-0101 TM-0155 TM-0164 TM-0167].include?(case_id)
  scm_remaining = source_path == "detect/utils_test.go" && root == "Test_createScmLink"
  aggregate_only = case_id == "TM-0073"
  behavior_ids << "DETECT-RAW-006" if m4_direct
  behavior_ids.concat(M5_CASE_BEHAVIOR_IDS.fetch(case_id)) if m5_allowlist
  behavior_ids.concat(M6_CASE_BEHAVIOR_IDS.fetch(case_id)) if m6_decoder
  behavior_ids.concat(M7_CASE_BEHAVIOR_IDS.fetch(case_id)) if m7_composite
  behavior_ids.concat(M9_CASE_BEHAVIOR_IDS.fetch(case_id)) if m9_source
  behavior_ids.concat(M10_CASE_BEHAVIOR_IDS.fetch(case_id)) if m10_git
  behavior_ids.concat(M11_REPORT_CASE_BEHAVIOR_IDS.fetch(case_id)) if m11_report
  comparison = if config_construction
                 "canonical-effective-config-or-structured-error"
               elsif assertion_allowlist
                 "exact-semantic-assertion-replay"
               elsif generator_helper
                 "not-applicable-go-only-default-construction-helper"
               elsif session_remaining
                 "complete-session-baseline-or-ignore-outcome"
               elsif engine_remaining
                 "complete-canonical-finding-or-exact-path-policy"
               elsif scm_remaining
                 "exact-scm-link-bytes"
               elsif aggregate_only
                 "aggregate-container-with-every-child-mapped-separately"
               elsif m5_allowlist
                 "complete-canonical-finding-multiset"
               elsif m4_direct
                 "complete-canonical-finding-multiset-or-exact-location-helper"
               elsif m6_decoder && case_id == "TM-0078"
                 "complete-canonical-finding-multiset"
               elsif m6_decoder
                 "complete-codec-pass-segment-probe-and-full-decode"
               elsif case_id == "TM-0084"
                 "complete-canonical-finding-multiset-with-exact-required-vectors"
               elsif case_id == "TM-0241"
                 "aggregate-of-exact-redaction-leaves"
               elsif case_id == "TM-0245"
                 "aggregate-of-exact-private-helper-leaves"
               elsif (242..244).map { |number| format("TM-%04d", number) }.include?(case_id) || case_id == "TM-0250"
                 "complete-canonical-finding-before-and-after"
               elsif (246..249).map { |number| format("TM-%04d", number) }.include?(case_id)
                 "exact-private-mask-bytes"
               elsif m9_source && M9_READER_CASE_IDS.include?(case_id)
                 "complete-reader-findings-errors-and-explicit-unobservable-fragment-disposition"
               elsif m9_source
                 "complete-ordered-source-events-and-canonical-finding-multiset"
               elsif case_id == "TM-0133"
                 "aggregate-of-complete-git-intention-leaves"
               elsif m10_git
                 "complete-git-fragments-findings-metadata-links-and-safe-dispositions"
               elsif m11_report
                 "exact-report-bytes-or-named-safe-template-and-writer-disposition"
               else
                 "behavioral-assertions"
               end
  rust_test = if config_construction
                "crates/rustleaks-core/tests/config.rs::canonical_config_corpus_matches_all_112_fresh_go_outcomes"
              elsif assertion_allowlist
                "crates/rustleaks-core/tests/allowlist.rs::frozen_allowlist_corpus_matches_go"
              elsif generator_helper
                ""
              elsif session_remaining
                "crates/rustleaks-core/tests/session_corpus.rs::session_corpus_matches_every_frozen_oracle_outcome"
              elsif engine_remaining
                "crates/rustleaks-core/tests/engine.rs::path_only_and_path_plus_content_rules_check_both_path_spellings; crates/rustleaks-core/tests/allowlist.rs::frozen_allowlist_corpus_matches_go; crates/rustleaks-core/tests/detect_corpus.rs::frozen_direct_detector_corpus_matches_go"
              elsif scm_remaining
                "crates/rustleaks-sources/tests/git_scm.rs::matrix_m_link_templates_are_exact"
              elsif aggregate_only
                ""
              elsif case_id == "TM-0138"
                "crates/rustleaks-core/src/engine.rs::tests::upstream_location_matches_pinned_helper_assertions"
              elsif m5_allowlist
                "crates/rustleaks-core/tests/allowlist.rs::frozen_allowlist_corpus_matches_go"
              elsif m4_direct
                "crates/rustleaks-core/tests/detect_corpus.rs::frozen_direct_detector_corpus_matches_go"
              elsif m6_decoder && case_id == "TM-0078"
                "crates/rustleaks-core/tests/detect_corpus.rs::frozen_decoder_detector_corpus_matches_go"
              elsif m6_decoder
                "crates/rustleaks-core/src/decoder/mod.rs::tests::canonical_decoder_pass_corpus_matches_go"
              elsif ["TM-0245", *%w[TM-0246 TM-0247 TM-0248 TM-0249]].include?(case_id)
                "crates/rustleaks-core/src/model.rs::redaction_tests::private_mask_helper_replays_every_frozen_oracle_row"
              elsif m7_composite
                "crates/rustleaks-core/tests/composite_corpus.rs::frozen_composite_and_redaction_corpus_matches_go"
              elsif m9_source
                M9_RUST_TEST
              elsif m10_git
                M10_RUST_TEST
              elsif m11_report
                M11_REPORT_RUST_TEST
              else
                ""
              end
  evidence = if config_construction
               "cargo xtask config-check"
             elsif assertion_allowlist
               "cargo xtask allowlist-check"
             elsif session_remaining
               "cargo xtask session-check"
             elsif engine_remaining
               "cargo xtask detect-check; cargo xtask allowlist-check"
             elsif scm_remaining
               "cargo xtask git-check"
             elsif m4_direct
               "cargo xtask detect-check"
             elsif m5_allowlist
               "cargo xtask allowlist-check"
             elsif m6_decoder
               "cargo xtask decoder-check"
             elsif m7_composite
               "cargo xtask composite-check"
             elsif m9_source
               "cargo xtask source-check"
             elsif m10_git
               "cargo xtask git-check"
             elsif m11_report
               "cargo xtask report-check"
             else
               "go test -json ./..."
             end
  lines << "behavior_ids = #{quote.call(behavior_ids)}"
  lines << "comparison = #{quote.call(comparison)}"
  lines << "rust_test = #{quote.call(rust_test)}"
  implemented = config_construction || assertion_allowlist || session_remaining || engine_remaining || scm_remaining ||
                m4_direct || m5_allowlist || m6_decoder || m7_composite || m9_source || m10_git || m11_report
  lines << "status = #{quote.call(implemented ? 'implemented' : 'final-disposition')}"
  final_evidence = if implemented
                     evidence
                   elsif generator_helper
                     "final release disposition: this upstream Go-only default-construction helper is not part of the Rustleaks API; the byte-exact packaged configuration and all 6,770 emitted default-rule samples are enforced by crates/rustleaks-core/tests/default_rule_corpus.rs"
                   elsif aggregate_only
                     "final release disposition: this top-level Go table-test function is only a container; every active child identity has an explicit Rust mapping below"
                   else
                     raise "unmapped final case #{case_id} #{go_name}"
                   end
  lines << "evidence = #{quote.call(final_evidence)}"
end

benchmarks.each_with_index do |name, index|
  source_path, source_line = benchmark_source.fetch(name)
  lines << ""
  lines << "[[benchmark]]"
  lines << "id = #{quote.call(format('BM-%04d', index + 1))}"
  lines << "go_name = #{quote.call(name)}"
  lines << "source = #{quote.call(source_path)}"
  lines << "source_line = #{source_line}"
  lines << "disposition = \"port-workload-record-separate-go-baseline\""
  lines << "status = \"implemented\""
  lines << "evidence = \"cargo test -p rustleaks-compat --bin rustleaks-perf --offline exact_upstream_benchmark_inputs_and_outcomes_run; cargo run -p rustleaks-compat --bin rustleaks-perf --release --offline -- --workload #{format('bm-%04d', index + 1)} --iterations 1\""
end

git_intentions.each do |id, parent_case, go_name, source, source_line, upstream_state, platform, fixture_roots, setup, git_argv, comparison, golden|
  lines << ""
  lines << "[[git_intention]]"
  lines << "id = #{quote.call(id)}"
  lines << "parent_case = #{quote.call(parent_case)}"
  lines << "go_name = #{quote.call(go_name)}"
  lines << "source = #{quote.call(source)}"
  lines << "source_line = #{source_line}"
  lines << "upstream_state = #{quote.call(upstream_state)}"
  lines << "platform = #{quote.call(platform)}"
  lines << "fixture_roots = #{quote.call(fixture_roots)}"
  lines << "setup = #{quote.call(setup)}"
  lines << "git_argv = #{quote.call(git_argv)}"
  lines << "comparison = #{quote.call(comparison)}"
  lines << "golden = #{quote.call(golden)}"
  lines << "rust_test = #{quote.call(M10_RUST_TEST)}"
  lines << "oracle_case = #{quote.call(M10_GIT_INTENTION_CASES.fetch(id))}"
  lines << "status = \"implemented\""
  lines << "evidence = \"cargo xtask git-check\""
end

constructors.each_with_index do |(name, source_path, source_line, helper, rule_id), index|
  selected = selected_rule_ids.key?(name)
  lines << ""
  lines << "[[generator_constructor]]"
  lines << "id = #{quote.call(format('GEN-%04d', index + 1))}"
  lines << "name = #{quote.call(name)}"
  lines << "source = #{quote.call(source_path)}"
  lines << "source_line = #{source_line}"
  lines << "disposition = #{quote.call(selected ? 'selected-default' : 'excluded-by-upstream-default')}"
  lines << "helper = #{quote.call(helper)}"
  lines << "rule_id = #{quote.call(rule_id)}"
  lines << "sample_inventory = \"compat/generator-corpus/constructors-v1.jsonl\""
  lines << "rust_evidence = \"cargo xtask generator-check\""
  lines << "status = \"implemented\""
end

fixtures.each_with_index do |(path, kind, mode, size, digest, target), index|
  lines << ""
  lines << "[[fixture]]"
  lines << "id = #{quote.call(format('FIX-%04d', index + 1))}"
  lines << "source = #{quote.call(path)}"
  lines << "kind = #{quote.call(kind)}"
  lines << "mode = #{quote.call(mode)}"
  lines << "size = #{size}" if size
  lines << "sha256 = #{quote.call(digest)}" if digest
  lines << "symlink_target = #{quote.call(target)}" if target
  lines << "consumers = #{quote.call(fixture_consumers(path))}"
  lines << "rust_location = #{quote.call("compat/fixtures/upstream/#{path}")}"
  lines << "provenance = \"Gitleaks MIT; pinned upstream testdata\""
  lines << "asset_status = \"copied-verified\""
  lines << "verification = \"cargo xtask fixture-check\""
  lines << "status = \"implemented\""
end

generated = lines.join("\n") + "\n"
manifest_path = ROOT.join("compat/test-manifest.toml")

def section_records(text, section)
  records = []
  current = nil
  text.each_line do |line|
    if line.strip == "[[#{section}]]"
      current = {}
      records << current
    elsif line.start_with?("[[") || line.start_with?("[")
      current = nil
    elsif current && (match = line.match(/^([a-z0-9_]+) = (.+)$/))
      current[match[1]] = match[2].strip
    end
  end
  records
end

def identity_signatures(text, section, keys)
  section_records(text, section).map do |record|
    keys.map { |key| "#{key}=#{record.fetch(key, '<missing>')}" }.join("\t")
  end.sort
end

class InventoryMismatch < StandardError; end
class TraceabilityMismatch < StandardError; end

def verify_mechanical_inventory(expected, actual)
  stable_keys = {
    "api_package" => %w[name mapping_id],
    "test_file" => %w[path active_top_level top_level_names benchmark_names],
    "case" => %w[id package go_name source source_line top_level platform platform_skip_reason behavior_ids],
    "benchmark" => %w[id go_name source source_line disposition],
    "git_intention" => %w[id parent_case go_name source source_line upstream_state platform fixture_roots git_argv comparison golden],
    "generator_constructor" => %w[id name source source_line disposition helper rule_id sample_inventory],
    "fixture" => %w[id source kind mode size sha256 symlink_target consumers rust_location provenance asset_status verification]
  }
  stable_keys.each do |section, keys|
    expected_signatures = identity_signatures(expected, section, keys)
    actual_signatures = identity_signatures(actual, section, keys)
    next if expected_signatures == actual_signatures

    missing = expected_signatures - actual_signatures
    unexpected = actual_signatures - expected_signatures
    raise InventoryMismatch, "#{section} identity mismatch\nmissing: #{missing.first || '<none>'}\nunexpected: #{unexpected.first || '<none>'}"
  end

  %w[expected_totals fixture_set traceability_corpora].each do |table|
    expected_table = expected[/^\[#{table}\]\n(.*?)(?=^\[|\z)/m, 1]
    actual_table = actual[/^\[#{table}\]\n(.*?)(?=^\[|\z)/m, 1]
    raise InventoryMismatch, "#{table} mismatch" unless expected_table == actual_table
  end
end

def json_field(record, key, context)
  JSON.parse(record.fetch(key))
rescue JSON::ParserError, KeyError => error
  raise TraceabilityMismatch, "#{context} has invalid #{key}: #{error.message}"
end

def verify_traceability_links(manifest, behavior_matrix, api_dispositions)
  behavior_records = section_records(behavior_matrix, "behavior")
  behavior_ids = behavior_records.map { |record| json_field(record, "id", "behavior row") }
  raise TraceabilityMismatch, "behavior IDs are empty or duplicated" if behavior_ids.empty? || behavior_ids.uniq.length != behavior_ids.length
  behavior_set = behavior_ids.to_h { |id| [id, true] }

  behavior_records.each do |record|
    id = json_field(record, "id", "behavior row")
    status = json_field(record, "status", "behavior #{id}")
    final = FINAL_BEHAVIOR_STATUSES.include?(status)
    raise TraceabilityMismatch, "behavior #{id} has non-final status #{status}" unless final
  end

  required_manifest_sections = %w[api_package test_file case benchmark git_intention generator_constructor fixture]
  required_manifest_sections.each do |section|
    section_records(manifest, section).each do |record|
      identity_key = %w[id name path].find { |key| record[key] }
      raise TraceabilityMismatch, "#{section} row has no identity field" unless identity_key
      identity = json_field(record, identity_key, section)
      status = json_field(record, "status", "#{section} #{identity}")
      unless %w[implemented final-disposition].include?(status)
        raise TraceabilityMismatch, "#{section} #{identity} has non-final status #{status}"
      end
    end
  end

  section_ids = %w[case benchmark git_intention generator_constructor fixture].flat_map do |section|
    section_records(manifest, section).map { |record| json_field(record, "id", section) }
  end
  manifest_namespace = (behavior_ids + section_ids).to_h { |id| [id, true] }

  section_records(manifest, "api_package").each do |record|
    mapping_id = json_field(record, "mapping_id", "api_package")
    raise TraceabilityMismatch, "api_package has dangling mapping_id #{mapping_id}" unless behavior_set[mapping_id]
  end
  section_records(manifest, "case").each do |record|
    id = json_field(record, "id", "case")
    links = json_field(record, "behavior_ids", "case #{id}")
    raise TraceabilityMismatch, "case #{id} has no behavior_ids" unless links.is_a?(Array) && !links.empty?
    links.each do |link|
      raise TraceabilityMismatch, "case #{id} has dangling behavior_id #{link}" unless behavior_set[link]
    end
  end

  raise TraceabilityMismatch, "API disposition count mismatch" unless api_dispositions.length == 607
  api_dispositions.each do |row|
    source_key = row.fetch("source_key")
    behavior_links = row.fetch("behavior_links")
    manifest_links = row.fetch("manifest_links")
    implementation_status = row.fetch("implementation_status")
    test_status = row.fetch("test_status")
    evidence_status = row.fetch("evidence_status")
    final_api_status = (implementation_status == "implemented" && test_status == "passing" && evidence_status == "rust-tested") ||
                       (implementation_status == "not-applicable" && test_status == "not-applicable" && evidence_status == "go-inventoried")
    unless final_api_status
      raise TraceabilityMismatch,
            "API #{source_key} has non-final status #{implementation_status}/#{test_status}/#{evidence_status}"
    end
    raise TraceabilityMismatch, "API #{source_key} has no behavior links" unless behavior_links.is_a?(Array) && !behavior_links.empty?
    raise TraceabilityMismatch, "API #{source_key} has no manifest links" unless manifest_links.is_a?(Array) && !manifest_links.empty?
    behavior_links.each do |link|
      raise TraceabilityMismatch, "API #{source_key} has dangling behavior link #{link}" unless behavior_set[link]
    end
    manifest_links.each do |link|
      raise TraceabilityMismatch, "API #{source_key} has dangling manifest link #{link}" unless manifest_namespace[link]
    end
  rescue KeyError => error
    raise TraceabilityMismatch, "API disposition row is malformed: #{error.message}"
  end
end

def require_traceability_rejection(label)
  begin
    yield
  rescue TraceabilityMismatch
    return
  end
  raise TraceabilityMismatch, "#{label} negative self-test unexpectedly passed"
end

if (check_index = ARGV.index("--check"))
  candidate = ARGV[check_index + 1] ? Pathname(ARGV[check_index + 1]).expand_path : manifest_path
  candidate_text = candidate.read
  begin
    verify_mechanical_inventory(generated, candidate_text)
  rescue InventoryMismatch => error
    abort error.message
  end
  behavior_text = BEHAVIOR_MATRIX.read
  api_rows = API_DISPOSITIONS.each_line.map { |line| JSON.parse(line) }
  begin
    verify_traceability_links(candidate_text, behavior_text, api_rows)
  rescue TraceabilityMismatch => error
    abort error.message
  end
  mutated = generated.sub('go_name = "TestConfigAllowlistPaths"', 'go_name = "FabricatedIdentity"')
  begin
    verify_mechanical_inventory(generated, mutated)
    abort "negative identity-substitution self-test unexpectedly passed"
  rescue InventoryMismatch
    # Expected: an identity substitution must fail without changing totals.
  end
  mutated_hash = generated.sub(
    /sha256 = "[0-9a-f]{64}"/,
    'sha256 = "0000000000000000000000000000000000000000000000000000000000000000"'
  )
  begin
    verify_mechanical_inventory(generated, mutated_hash)
    abort "negative fixture-hash-substitution self-test unexpectedly passed"
  rescue InventoryMismatch
    # Expected: digit-bearing TOML keys must participate in exact identities.
  end
  mutated_mode = generated.sub('mode = "100644"', 'mode = "100755"')
  begin
    verify_mechanical_inventory(generated, mutated_mode)
    abort "negative fixture-mode-substitution self-test unexpectedly passed"
  rescue InventoryMismatch
    # Expected: same-count fixture mode substitutions must fail.
  end
  mutated_consumer = generated.sub(/consumers = \[[^\n]+\]/, 'consumers = ["fabricated-consumer"]')
  begin
    verify_mechanical_inventory(generated, mutated_consumer)
    abort "negative fixture-consumer-substitution self-test unexpectedly passed"
  rescue InventoryMismatch
    # Expected: nonempty fabricated prose must not replace reviewed consumers.
  end
  mutated_provenance = generated.sub(
    'provenance = "Gitleaks MIT; pinned upstream testdata"',
    'provenance = "fabricated provenance"'
  )
  begin
    verify_mechanical_inventory(generated, mutated_provenance)
    abort "negative fixture-provenance-substitution self-test unexpectedly passed"
  rescue InventoryMismatch
    # Expected: provenance is stable evidence, not an unchecked annotation.
  end
  require_traceability_rejection("missing behavior") do
    verify_traceability_links(
      candidate_text,
      behavior_text.sub('id = "TM-ALL-001"', 'id = "TM-ALL-MISSING"'),
      api_rows
    )
  end
  require_traceability_rejection("dangling case behavior") do
    verify_traceability_links(
      candidate_text.sub('behavior_ids = ["TM-ALL-001"]', 'behavior_ids = ["DANGLING-BEHAVIOR"]'),
      behavior_text,
      api_rows
    )
  end
  fabricated_api_rows = api_rows.map(&:dup)
  fabricated_api_rows[0] = fabricated_api_rows[0].merge("manifest_links" => ["FABRICATED-MANIFEST-LINK"])
  require_traceability_rejection("fabricated API manifest link") do
    verify_traceability_links(candidate_text, behavior_text, fabricated_api_rows)
  end
  require_traceability_rejection("unfinished manifest status") do
    verify_traceability_links(
      candidate_text.sub('status = "implemented"', 'status = "planned"'),
      behavior_text,
      api_rows
    )
  end
  require_traceability_rejection("unfinished behavior status") do
    verify_traceability_links(
      candidate_text,
      behavior_text.sub('status = "traceability-complete"', 'status = "partial"'),
      api_rows
    )
  end
  unfinished_api_rows = api_rows.map(&:dup)
  unfinished_api_rows[0] = unfinished_api_rows[0].merge(
    "implementation_status" => "planned",
    "test_status" => "planned",
    "evidence_status" => "design-only"
  )
  require_traceability_rejection("unfinished API status") do
    verify_traceability_links(candidate_text, behavior_text, unfinished_api_rows)
  end
  warn "verified exact mechanical identities and negative substitution: #{events.length} cases, #{benchmarks.length} benchmarks, #{constructors.length} constructors, #{fixtures.length} fixtures"
else
  manifest_path.write(generated)
  warn "wrote #{events.length} cases, #{benchmarks.length} benchmarks, #{constructors.length} constructors, #{fixtures.length} fixtures"
end
