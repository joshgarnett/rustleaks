#!/usr/bin/env ruby
# frozen_string_literal: true

# Freeze pinned-Go ScanSession behavior. Every request is executed in a fresh,
# deadline-bounded oracle process so detector state cannot cross case boundaries.

require "base64"
require "digest"
require "fileutils"
require "json"
require "open3"
require "pathname"
require "timeout"
require "tmpdir"

ROOT = Pathname(__dir__).parent
UPSTREAM = ROOT.parent.join("gitleaks")
ORACLE = ROOT.join("crates/rustleaks-compat/oracle")
OUTPUT_ROOT = ROOT.join("compat/session-corpus")
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
DEFAULT_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
PROTOCOL_VERSION = 1
EXPECTED_UPSTREAM_STATUS = ""
BEHAVIORS = (1..10).map { |number| format("SESSION-%03d", number) }.freeze
UPSTREAM_IDENTITIES = {
  "TM-0127" => "TestFileLoadBaseline",
  "TM-0139" => "TestIgnoreIssuesInBaseline",
  "TM-0140" => "TestIsNew",
  "TM-0141" => "TestIsNew/new_-_commit_doesn't_match_baseline",
  "TM-0142" => "TestIsNew/new_-_redacted,_different_baseline",
  "TM-0143" => "TestIsNew/not_new_-_commit+author_matches",
  "TM-0144" => "TestIsNew/not_new_-_commit+author_matches,_tags_ignored",
  "TM-0145" => "TestIsNew/not_new_-_redacted,_everything_else_matches",
  "TM-0146" => "TestNormalizeGitleaksIgnorePaths",
  "TM-0250" => "TestRedact"
}.freeze
SOURCE_HASHES = {
  "detect/baseline.go" => "23d043ab3bf70d0a4ff560598a22b8507f38054b038acd3e6e684abf5c663e93",
  "detect/detect.go" => "2bac563a09f22ff76c56b200c3b9b5dc865c1de699eb0ba2a27cca741fa9bd13",
  "report/finding.go" => "a1ecd3837f6d89b8ddf95f2b0a6c301103b8d3e67f84e1b3520ffc6f7d7751a6",
  "detect/baseline_test.go" => "4e6e40bae1d71f14acf66f8ebeb1f328607e1ca01b675c28a8447284f5068895",
  "detect/detect_test.go" => "191e7178827d790ae7c72f7b17824e3d368fe66b263fb12a9b8f3ede225124d3",
  "report/finding_test.go" => "60f6950823fd227c77d65c630b540fdb3dba46b947bda5bf98f5a72d9d513874"
}.freeze

CHECK = ARGV.delete("--check")
abort "usage: #{$PROGRAM_NAME} [--check]" unless ARGV.empty?

GO_ENV = {
  "GOCACHE" => ENV.fetch("GOCACHE", File.join(Dir.tmpdir, "rustleaks-m8-oracle-gocache")),
  "GOMODCACHE" => ENV.fetch("GOMODCACHE", File.join(Dir.tmpdir, "rustleaks-go-mod-cache")),
  "GOMEMLIMIT" => ENV.fetch("GOMEMLIMIT", "512MiB"),
  "GOMAXPROCS" => ENV.fetch("GOMAXPROCS", "2")
}.freeze

def sha(bytes)
  Digest::SHA256.hexdigest(bytes)
end

def b64(bytes)
  Base64.strict_encode64(bytes.b)
end

def jsonl(records)
  records.map { |record| JSON.generate(record) + "\n" }.join
end

def capture(*command, chdir:, stdin_data: "")
  output, error, status = Open3.capture3(GO_ENV, *command, chdir: chdir.to_s, stdin_data: stdin_data)
  abort "#{command.join(' ')} failed in #{chdir}:\n#{error}\n#{output}" unless status.success?
  output
end

def bounded_oracle(binary, request)
  output = "".b
  error = "".b
  status = nil
  Open3.popen3(GO_ENV, binary, "--session", chdir: ORACLE.to_s, pgroup: true) do |stdin, stdout, stderr, wait|
    stdin.write(JSON.generate(request) + "\n")
    stdin.close
    begin
      Timeout.timeout(10) do
        readers = [stdout, stderr]
        until readers.empty?
          ready = IO.select(readers, nil, nil, 0.25)
          next if ready.nil?
          ready.first.each do |stream|
            begin
              chunk = stream.read_nonblock(16 * 1024)
              target = stream.equal?(stdout) ? output : error
              target << chunk
              raise "oracle output exceeded 4 MiB" if target.bytesize > 4 * 1024 * 1024
            rescue IO::WaitReadable
              next
            rescue EOFError
              readers.delete(stream)
            end
          end
        end
        status = wait.value
      end
    rescue Timeout::Error, RuntimeError => e
      Process.kill("KILL", -wait.pid) rescue nil
      wait.value rescue nil
      abort "#{request.fetch('id')}: bounded oracle failed: #{e.message}"
    end
  end
  abort "#{request.fetch('id')}: oracle failed: #{error}" unless status && status.success?
  lines = output.lines
  abort "#{request.fetch('id')}: oracle emitted #{lines.length} lines" unless lines.length == 1
  JSON.parse(lines.first)
end

def deep_copy(value)
  JSON.parse(JSON.generate(value))
end

def finding(rule: "rule", file: "src/secret.txt", commit: "commit-a", line: 7, fingerprint: "caller-stale",
            description: "description", match: "MATCH=secret", secret: "secret", source_line: "line MATCH=secret",
            entropy: 3.25, tags: ["tag-a", "tag-b"], symlink: "link.txt", link: "https://example.invalid/link",
            author: "author", email: "email@example.invalid", date: "2025-01-02", message: "message")
  {
    "rule_id" => rule, "description_base64" => b64(description),
    "start_line" => line, "end_line" => line + 1, "start_column" => 3, "end_column" => 15,
    "line_base64" => b64(source_line), "match_base64" => b64(match), "secret_base64" => b64(secret),
    "file_base64" => b64(file), "symlink_file_base64" => b64(symlink), "commit_base64" => b64(commit),
    "link_base64" => b64(link), "entropy_bits" => [entropy].pack("g").unpack1("N"),
    "author_base64" => b64(author), "email_base64" => b64(email), "date_base64" => b64(date),
    "message_base64" => b64(message), "tags_base64" => tags.map { |tag| b64(tag) },
    "fingerprint_base64" => b64(fingerprint), "required_findings" => []
  }
end

def go_finding(input)
  decode = ->(key) { Base64.strict_decode64(input.fetch(key)) }
  result = {
    "RuleID" => input.fetch("rule_id"), "Description" => decode.call("description_base64"),
    "StartLine" => input.fetch("start_line"), "EndLine" => input.fetch("end_line"),
    "StartColumn" => input.fetch("start_column"), "EndColumn" => input.fetch("end_column"),
    "Match" => decode.call("match_base64"), "Secret" => decode.call("secret_base64"),
    "File" => decode.call("file_base64"), "SymlinkFile" => decode.call("symlink_file_base64"),
    "Commit" => decode.call("commit_base64"), "Link" => decode.call("link_base64"),
    "Entropy" => [input.fetch("entropy_bits")].pack("N").unpack1("g"),
    "Author" => decode.call("author_base64"), "Email" => decode.call("email_base64"),
    "Date" => decode.call("date_base64"), "Message" => decode.call("message_base64"),
    "Tags" => input.fetch("tags_base64").map { |value| Base64.strict_decode64(value) },
    "Fingerprint" => decode.call("fingerprint_base64")
  }
  if input["fragment"]
    fragment = input.fetch("fragment")
    result["Fragment"] = {
      "Raw" => Base64.strict_decode64(fragment.fetch("raw_base64")),
      "Bytes" => fragment.fetch("bytes_base64"),
      "FilePath" => Base64.strict_decode64(fragment.fetch("file_base64")),
      "SymlinkFile" => Base64.strict_decode64(fragment.fetch("symlink_file_base64")),
      "CommitSHA" => Base64.strict_decode64(fragment.fetch("commit_base64")),
      "StartLine" => fragment.fetch("start_line"), "CommitInfo" => nil,
      "InheritedFromFinding" => fragment.fetch("inherited_from_finding")
    }
  end
  result
end

def baseline_bytes(findings)
  JSON.generate(findings.map { |entry| go_finding(entry) })
end

def request(id, behaviors:, findings: [], test_ids: [], ignore: nil, ignore_missing: false,
            baseline: nil, baseline_missing: false, baseline_name: "baseline.json", redact: 0)
  value = {
    "protocol_version" => PROTOCOL_VERSION, "id" => id, "behavior_ids" => behaviors,
    "test_case_ids" => test_ids, "operation" => "session", "redact_percent" => redact,
    "ignore_file" => nil, "baseline_file" => nil, "findings" => findings
  }
  value["ignore_file"] = {"name" => ".gitleaksignore", "content_base64" => b64(ignore || ""), "missing" => ignore_missing} if ignore || ignore_missing
  value["baseline_file"] = {"name" => baseline_name, "content_base64" => b64(baseline || ""), "missing" => baseline_missing} if baseline || baseline_missing
  value
end

abort "upstream revision changed" unless capture("git", "rev-parse", "HEAD", chdir: UPSTREAM).strip == REVISION
abort "default config changed" unless sha(UPSTREAM.join("config/gitleaks.toml").binread) == DEFAULT_SHA256
abort "upstream status changed" unless capture("git", "status", "--short", "--untracked-files=no", chdir: UPSTREAM) == EXPECTED_UPSTREAM_STATUS
SOURCE_HASHES.each do |path, expected|
  abort "#{path} changed" unless sha(UPSTREAM.join(path).binread) == expected
end
window_paths = UPSTREAM.join("testdata/gitleaksignore/.windowspaths").binread
abort "window-path fixture changed" unless sha(window_paths) == "5426aeccb90cd6495f01a2ff078a008108615697f2fe5ff98d0baa1a1738add3"
baseline_fixture = UPSTREAM.join("testdata/baseline/baseline.json").binread
abort "baseline fixture changed" unless sha(baseline_fixture) == "02b42cf04e716d178e4fc2c98783646e3133a5b14a47f15f7305074b376676f7"
manifest_text = ROOT.join("compat/test-manifest.toml").binread
UPSTREAM_IDENTITIES.each do |id, name|
  identity = /\[\[case\]\]\nid = #{Regexp.escape(id.to_json)}\npackage = "[^"]+"\ngo_name = #{Regexp.escape(name.to_json)}\n/
  abort "manifest identity changed for #{id}:#{name}" unless manifest_text.match?(identity)
end

requests = []
requests << request("upstream-normalize-window-paths", behaviors: %w[SESSION-002 SESSION-003],
                    test_ids: ["TM-0146"], ignore: window_paths)
requests << request("ignore-comments-invalid-duplicates", behaviors: %w[SESSION-002 SESSION-003],
                    ignore: "  foo\\bar.txt:rule:7  \n\n  # comment\ninvalid\ntoo:many:colon:fields:here\nfoo/bar.txt:rule:7\n")
requests << request("ignore-missing", behaviors: ["SESSION-003"], ignore_missing: true)

global = finding(file: "dir/file.txt", commit: "commit-a", line: 7)
uncommitted = finding(file: "dir/file.txt", commit: "", line: 7)
commit_other = finding(file: "dir/file.txt", commit: "commit-b", line: 7)
requests << request("fingerprints-global-and-commit", behaviors: %w[SESSION-001 SESSION-009],
                    findings: [global, uncommitted, commit_other])
requests << request("ignore-global-before-commit", behaviors: %w[SESSION-001 SESSION-004],
                    ignore: "dir/file.txt:rule:7\ncommit-a:dir/file.txt:rule:7\n",
                    baseline: baseline_bytes([global]), findings: [global])
requests << request("ignore-commit-exact-and-near-misses", behaviors: %w[SESSION-001 SESSION-004],
                    ignore: "commit-a:dir/file.txt:rule:7\n", baseline: baseline_bytes([global]),
                    findings: [global, uncommitted, commit_other])
requests << request("ignore-slash-positive-backslash-negative", behaviors: %w[SESSION-002 SESSION-004],
                    ignore: "dir\\file.txt:rule:7\n", findings: [global, finding(file: "dir\\file.txt", commit: "commit-a", line: 7)])
requests << request("ignore-explicit-drive-colon-bytes", behaviors: %w[SESSION-002 SESSION-004],
                    ignore: "C:\\dir\\file.txt:rule:7\n", findings: [finding(file: "C:/dir/file.txt", commit: "", line: 7)])

base = finding
baseline = baseline_bytes([base])
requests << request("baseline-valid-empty", behaviors: ["SESSION-005"], baseline: "[]")
requests << request("baseline-valid-null", behaviors: ["SESSION-005"], baseline: "null")
requests << request("baseline-upstream-json-fixture", behaviors: ["SESSION-005"], test_ids: ["TM-0127"], baseline: baseline_fixture)
requests << request("baseline-preserves-duplicates-order", behaviors: %w[SESSION-005 SESSION-008], baseline: baseline_bytes([base, base]))
requests << request("baseline-invalid-csv", behaviors: ["SESSION-005"], test_ids: ["TM-0127"], baseline: "a,b,c\n", baseline_name: "baseline.csv")
requests << request("baseline-invalid-sarif", behaviors: ["SESSION-005"], test_ids: ["TM-0127"], baseline: '{"version":"2.1.0"}', baseline_name: "baseline.sarif")
requests << request("baseline-float32-overflow", behaviors: ["SESSION-005"],
                    baseline: '[{"Entropy":3.4028236e38}]')
requests << request("baseline-unicode-folded-keys", behaviors: ["SESSION-005"],
                    baseline: '[{"Deſcription":"folded","LinK":"kelvin"}]')
requests << request("baseline-missing", behaviors: ["SESSION-005"], test_ids: ["TM-0127"], baseline_missing: true, baseline_name: "notfound.json")

requests << request("baseline-equal", behaviors: ["SESSION-006"], test_ids: ["TM-0143"], baseline: baseline, findings: [base])

compared = {
  "rule-id" => ["rule_id", "other-rule"], "description" => ["description_base64", b64("other")],
  "start-line" => ["start_line", 8], "end-line" => ["end_line", 10],
  "start-column" => ["start_column", 4], "end-column" => ["end_column", 16],
  "match" => ["match_base64", b64("other match")], "secret" => ["secret_base64", b64("other secret")],
  "file" => ["file_base64", b64("other.txt")], "commit" => ["commit_base64", b64("commit-b")],
  "author" => ["author_base64", b64("other author")], "email" => ["email_base64", b64("other email")],
  "date" => ["date_base64", b64("other date")], "message" => ["message_base64", b64("other message")],
  "entropy" => ["entropy_bits", [4.5].pack("g").unpack1("N")]
}
compared.each do |name, mutation|
  candidate = deep_copy(base)
  candidate[mutation[0]] = mutation[1]
  ids = name == "commit" ? ["TM-0141"] : []
  requests << request("baseline-compared-#{name}", behaviors: ["SESSION-006"], test_ids: ids,
                      baseline: baseline, findings: [candidate])
end

ignored = {
  "line" => lambda { |candidate| candidate["line_base64"] = b64("other line") },
  "symlink" => lambda { |candidate| candidate["symlink_file_base64"] = b64("other-link") },
  "link" => lambda { |candidate| candidate["link_base64"] = b64("other URL") },
  "tags" => lambda { |candidate| candidate["tags_base64"] = [b64("other-tag")] },
  "fingerprint" => lambda { |candidate| candidate["fingerprint_base64"] = b64("other-fingerprint") },
  "fragment" => lambda do |candidate|
    candidate["fragment"] = {"raw_base64" => b64("raw"), "bytes_base64" => b64("bytes"),
      "file_base64" => b64("fragment-file"), "windows_file_base64" => b64("C:\\fragment-file"),
      "symlink_file_base64" => b64("fragment-link"), "commit_base64" => b64("fragment-commit"),
      "start_line" => 41, "inherited_from_finding" => true}
  end,
  "required-findings" => lambda do |candidate|
    candidate["required_findings"] = [{"rule_id" => "required", "start_line" => 1, "end_line" => 1,
      "start_column" => 2, "end_column" => 3, "line_base64" => b64("required line"),
      "match_base64" => b64("required match"), "secret_base64" => b64("required secret")}]
  end
}
ignored.each do |name, mutation|
  candidate = deep_copy(base)
  mutation.call(candidate)
  ids = []
  ids << "TM-0144" if name == "tags"
  ids << "TM-0139" if name == "fingerprint"
  requests << request("baseline-ignored-#{name}", behaviors: ["SESSION-006"], test_ids: ids,
                      baseline: baseline, findings: [candidate])
end

redacted = deep_copy(base)
redacted["match_base64"] = b64("REDACTED")
redacted["secret_base64"] = b64("REDACTED")
requests << request("baseline-redaction-disabled-near-negative", behaviors: %w[SESSION-006 SESSION-007],
                    baseline: baseline, findings: [redacted])
requests << request("baseline-redaction-enabled", behaviors: %w[SESSION-006 SESSION-007],
                    test_ids: %w[TM-0145 TM-0250], baseline: baseline, findings: [redacted], redact: 100)
redacted_different = deep_copy(redacted)
redacted_different["commit_base64"] = b64("different-commit")
requests << request("upstream-redacted-different-baseline", behaviors: %w[SESSION-006 SESSION-007],
                    test_ids: ["TM-0142"], baseline: baseline, findings: [redacted_different], redact: 100)

z = finding(rule: "z-rule", file: "z.txt", commit: "", line: 9)
a = finding(rule: "a-rule", file: "a.txt", commit: "", line: 1)
requests << request("collection-order-duplicates-canonical", behaviors: %w[SESSION-008 SESSION-009 SESSION-010],
                    findings: [z, a, deep_copy(a), finding(rule: "m-rule", file: "m.txt", commit: "", line: 5)])
sort_z = finding(rule: "same-rule", file: "z.txt", commit: "", line: 4)
sort_a = finding(rule: "same-rule", file: "a.txt", commit: "", line: 4)
requests << request("canonical-sort-full-projection-inputs", behaviors: ["SESSION-010"], findings: [sort_z, sort_a])

abort "duplicate request IDs" unless requests.map { |entry| entry.fetch("id") }.uniq.length == requests.length

generated = {}
Dir.mktmpdir("rustleaks-m8-session-") do |temporary|
  binary = File.join(temporary, "session-oracle")
  capture("go", "test", "./...", chdir: ORACLE)
  capture("go", "build", "-o", binary, ".", chdir: ORACLE)
  outcomes = requests.map do |entry|
    outcome = bounded_oracle(binary, entry)
    abort "#{entry.fetch('id')}: identity changed" unless outcome.fetch("id") == entry.fetch("id")
    abort "#{entry.fetch('id')}: pin changed" unless outcome.fetch("upstream_revision") == REVISION && outcome.fetch("default_config_sha256") == DEFAULT_SHA256
    outcome
  end
  by_id = outcomes.each_with_object({}) { |entry, memo| memo[entry.fetch("id")] = entry }

  expected_errors = {
    "ignore-missing" => ["ignore-open", "could not open .gitleaksignore"],
    "baseline-invalid-csv" => ["baseline-format", "the format of the file baseline.csv is not supported"],
    "baseline-invalid-sarif" => ["baseline-format", "the format of the file baseline.sarif is not supported"],
    "baseline-float32-overflow" => ["baseline-format", "the format of the file baseline.json is not supported"],
    "baseline-missing" => ["baseline-open", "could not open notfound.json"]
  }
  outcomes.each do |outcome|
    expected = expected_errors[outcome.fetch("id")]
    if expected
      abort "#{outcome.fetch('id')}: error changed" unless outcome.fetch("error").values_at("class", "message") == expected
    else
      abort "#{outcome.fetch('id')}: unexpected error #{outcome['error'].inspect}" unless outcome["error"].nil?
    end
  end

  material = {}
  verify = lambda do |number, name, condition|
    abort "material assertion #{number} (#{name}) failed" unless condition
    material[number] ||= []
    material[number] << name
  end
  decode_entries = lambda { |id| by_id.fetch(id).dig("ignore", "entries_base64").map { |value| Base64.strict_decode64(value) } }
  decisions = lambda { |id| by_id.fetch(id).fetch("decisions").map { |entry| entry.fetch("disposition") } }
  verify.call(1, "exact-global-and-commit-fingerprints",
              by_id.fetch("fingerprints-global-and-commit").fetch("collected_findings").map { |entry| Base64.strict_decode64(entry.fetch("fingerprint_base64")) } ==
                ["commit-a:dir/file.txt:rule:7", "dir/file.txt:rule:7", "commit-b:dir/file.txt:rule:7"])
  verify.call(2, "exact-upstream-windows-normalization",
              decode_entries.call("upstream-normalize-window-paths") == [
                "b55d88dc151f7022901cda41a03d43e0e508f2b7:test_data/test_local_repo_three_leaks.json:aws-access-token:73",
                "foo/bar/gitleaks-false-positive.yaml:aws-access-token:4",
                "foo/bar/gitleaks-false-positive.yaml:aws-access-token:5"])
  verify.call(3, "comments-blanks-invalid-and-duplicates",
              decode_entries.call("ignore-comments-invalid-duplicates") == ["foo/bar.txt:rule:7", "invalid", "too:many:colon:fields:here"])
  verify.call(4, "ignore-precedence-and-near-misses",
              decisions.call("ignore-global-before-commit") == ["ignored-global"] &&
                !by_id.fetch("ignore-global-before-commit").dig("decisions", 0, "baseline_is_new") &&
                decisions.call("ignore-commit-exact-and-near-misses") == ["ignored-commit", "accepted", "accepted"] &&
                !by_id.fetch("ignore-commit-exact-and-near-misses").dig("decisions", 0, "baseline_is_new") &&
                decisions.call("ignore-slash-positive-backslash-negative") == ["ignored-global", "accepted"] &&
                decisions.call("ignore-explicit-drive-colon-bytes") == ["ignored-global"])
  verify.call(5, "baseline-load-and-error-classes",
              by_id.fetch("baseline-valid-empty").dig("baseline", "loaded") && by_id.fetch("baseline-valid-null").dig("baseline", "loaded") &&
                by_id.fetch("baseline-upstream-json-fixture").dig("baseline", "findings").length == 2 &&
                by_id.fetch("baseline-preserves-duplicates-order").dig("baseline", "findings").length == 2 && expected_errors.length == 5)
  folded = by_id.fetch("baseline-unicode-folded-keys").dig("baseline", "findings", 0)
  verify.call(5, "baseline-unicode-simple-fold-keys",
              Base64.strict_decode64(folded.fetch("description_base64")) == "folded" &&
                Base64.strict_decode64(folded.fetch("link_base64")) == "kelvin")
  verify.call(5, "baseline-float32-overflow-rejected",
              by_id.fetch("baseline-float32-overflow").dig("error", "class") == "baseline-format")
  compared.keys.each do |name|
    verify.call(6, "compared-field-#{name}", decisions.call("baseline-compared-#{name}") == ["accepted"])
  end
  verify.call(6, "exact-equality-suppresses", decisions.call("baseline-equal") == ["ignored-baseline"])
  ignored.keys.each do |name|
    verify.call(7, "ignored-field-#{name}", decisions.call("baseline-ignored-#{name}") == ["ignored-baseline"])
  end
  verify.call(8, "redaction-match-secret-only",
              decisions.call("baseline-redaction-disabled-near-negative") == ["accepted"] &&
                decisions.call("baseline-redaction-enabled") == ["ignored-baseline"] &&
                decisions.call("upstream-redacted-different-baseline") == ["accepted"])
  ordered = by_id.fetch("collection-order-duplicates-canonical")
  verify.call(9, "collection-order-and-duplicates",
              ordered.fetch("collected_findings").map { |entry| entry.fetch("rule_id") } == %w[z-rule a-rule a-rule m-rule] &&
                ordered.fetch("collected_findings")[1] == ordered.fetch("collected_findings")[2])
  verify.call(10, "canonical-sort-and-fingerprint-mutation",
              ordered.fetch("canonical_findings").map { |entry| entry.fetch("rule_id") } == %w[a-rule a-rule m-rule z-rule] &&
                Base64.strict_decode64(ordered.dig("input_findings", 0, "fingerprint_base64")) == "caller-stale" &&
                Base64.strict_decode64(ordered.dig("collected_findings", 0, "fingerprint_base64")) == "z.txt:z-rule:9" &&
                by_id.fetch("canonical-sort-full-projection-inputs").fetch("canonical_findings").map { |entry| Base64.strict_decode64(entry.fetch("file_base64")) } == %w[a.txt z.txt])

  complete_keys = %w[rule_id description_base64 start_line end_line start_column end_column line_base64 match_base64 secret_base64 file_base64 symlink_file_base64 commit_base64 link_base64 entropy_bits author_base64 email_base64 date_base64 message_base64 tags_base64 fingerprint_base64 fragment required_findings].sort
  outcomes.flat_map { |entry| entry.fetch("input_findings") + entry.fetch("collected_findings") + entry.fetch("canonical_findings") }.each do |entry|
    abort "complete finding projection changed" unless entry.keys.sort == complete_keys
  end
  abort "material assertion group inventory changed" unless material.keys.sort == (1..10).to_a
  abort "material assertion names not unique" unless material.values.all? { |names| names == names.uniq && !names.empty? }

  request_bytes = jsonl(requests)
  outcome_bytes = jsonl(outcomes)
  coverage = {
    "schema_version" => 1, "protocol_version" => PROTOCOL_VERSION, "upstream_revision" => REVISION,
    "default_config_sha256" => DEFAULT_SHA256,
    "behavior_ids" => BEHAVIORS.map { |id| {"id" => id, "request_ids" => requests.select { |entry| entry.fetch("behavior_ids").include?(id) }.map { |entry| entry.fetch("id") }} },
    "upstream" => UPSTREAM_IDENTITIES.map { |id, name| {"test_case_id" => id, "go_name" => name, "classification" => %w[TM-0127 TM-0139 TM-0140 TM-0250].include?(id) ? "aggregator" : "leaf", "request_ids" => requests.select { |entry| entry.fetch("test_case_ids").include?(id) }.map { |entry| entry.fetch("id") }} },
    "baseline_compared_fields" => compared.keys,
    "baseline_ignored_fields" => ignored.keys,
    "material_assertions" => material.sort.map { |number, names| {"number" => number, "assertions" => names} },
    "source_hashes" => SOURCE_HASHES,
    "cross_platform_contract" => "all path cases are explicit request bytes; no host path conversion determines an expectation",
    "canonical_sort_key" => "stable ascending byte comparison of each complete canonical finding's compact JSON projection",
    "excluded" => ["production safety/unsafe design", "Rust session implementation", "file/archive/Git scheduling"]
  }
  coverage_bytes = JSON.pretty_generate(coverage) + "\n"
  negative_controls = {
    "pairs" => [
      {"positive" => "ignore-slash-positive-backslash-negative[0]", "negative" => "ignore-slash-positive-backslash-negative[1]"},
      {"positive" => "ignore-commit-exact-and-near-misses[0]", "negative" => "ignore-commit-exact-and-near-misses[2]"},
      {"positive" => "baseline-redaction-enabled", "negative" => "baseline-redaction-disabled-near-negative"},
      {"positive" => "baseline-equal", "negative" => "baseline-compared-description"}
    ]
  }
  negative_bytes = JSON.pretty_generate(negative_controls) + "\n"
  readme = <<~MARKDOWN
    # Session oracle corpus v1

    This corpus freezes pinned Gitleaks `#{REVISION}` session behavior. The generator
    runs every one of its #{requests.length} requests in a fresh Go child with a
    10-second deadline, 4 MiB per-stream output ceiling, 512 MiB Go memory limit,
    and explicit input bytes for cross-platform path cases.

    `outcomes-v1.jsonl` preserves every Finding field, duplicates, original collection
    order, fingerprint mutation, and a separate stable canonical-sort view. Baseline
    comparisons mutate each compared and ignored field individually; ignore cases
    cover global and commit forms, slash normalization, comments, blanks, malformed
    entries, duplicate collapse, and precedence.

    Regenerate or verify from the repository root:

    ```sh
    ruby compat/generate_session_corpus.rb
    ruby compat/generate_session_corpus.rb --check
    ```

    Production safety/unsafe design and Rust implementation claims are outside this packet.
  MARKDOWN
  manifest = {
    "schema_version" => 1, "protocol_version" => PROTOCOL_VERSION, "oracle_mode" => "session",
    "upstream_revision" => REVISION, "default_config_sha256" => DEFAULT_SHA256,
    "go_version" => outcomes.reject { |entry| entry["go_version"].nil? }.first.fetch("go_version"),
    "fresh_process_per_request" => true, "deadline_seconds" => 10, "stream_limit_bytes" => 4 * 1024 * 1024,
    "request_count" => requests.length, "outcome_count" => outcomes.length,
    "input_finding_count" => outcomes.sum { |entry| entry.fetch("input_findings").length },
    "collected_finding_count" => outcomes.sum { |entry| entry.fetch("collected_findings").length },
    "baseline_finding_count" => outcomes.sum { |entry| entry.dig("baseline", "findings").length },
    "behavior_count" => BEHAVIORS.length, "upstream_identity_count" => UPSTREAM_IDENTITIES.length,
    "material_assertion_count" => material.values.sum(&:length),
    "files" => {
      "requests-v1.jsonl" => {"sha256" => sha(request_bytes), "records" => requests.length},
      "outcomes-v1.jsonl" => {"sha256" => sha(outcome_bytes), "records" => outcomes.length},
      "coverage-v1.json" => {"sha256" => sha(coverage_bytes)},
      "negative-controls-v1.json" => {"sha256" => sha(negative_bytes)},
      "README.md" => {"sha256" => sha(readme)}
    }
  }
  generated = {"requests-v1.jsonl" => request_bytes, "outcomes-v1.jsonl" => outcome_bytes,
               "coverage-v1.json" => coverage_bytes, "negative-controls-v1.json" => negative_bytes,
               "README.md" => readme, "manifest-v1.json" => JSON.pretty_generate(manifest) + "\n"}
end

abort "upstream status changed during generation" unless capture("git", "status", "--short", "--untracked-files=no", chdir: UPSTREAM) == EXPECTED_UPSTREAM_STATUS
if CHECK
  generated.each do |name, bytes|
    path = OUTPUT_ROOT.join(name)
    abort "missing #{path}" unless path.file?
    abort "#{path} differs: committed=#{sha(path.binread)} fresh=#{sha(bytes)}" unless path.binread == bytes.b
  end
  extras = OUTPUT_ROOT.children.select(&:file?).map { |path| path.basename.to_s } - generated.keys
  abort "unexpected corpus files: #{extras.join(', ')}" unless extras.empty?
else
  FileUtils.mkdir_p(OUTPUT_ROOT)
  generated.each { |name, bytes| OUTPUT_ROOT.join(name).binwrite(bytes) }
end

puts JSON.pretty_generate(JSON.parse(generated.fetch("manifest-v1.json")))
