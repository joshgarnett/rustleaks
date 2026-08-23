#!/usr/bin/env ruby
# frozen_string_literal: true

# Freeze exact report bytes from the pinned Go implementation. Every request
# runs in a fresh bounded oracle process; no report state is shared between
# cases and no sibling-checkout file is modified.

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
OUTPUT_ROOT = Pathname(ENV.fetch("RUSTLEAKS_REPORT_CORPUS_OUTPUT", ROOT.join("compat/report-corpus").to_s))
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
DEFAULT_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
PROTOCOL_VERSION = 1
BEHAVIORS = {
  "RPT-001" => "Report format selection is explicit and unknown formats fail structurally.",
  "RPT-002" => "JSON output preserves the pinned field order, indentation, omission, escaping, and terminal newline.",
  "RPT-003" => "CSV output preserves columns, quoting, raw bytes, tags, first-finding Link selection, and empty behavior.",
  "RPT-004" => "JUnit output preserves XML shape, messages, embedded finding JSON, escaping, and empty behavior.",
  "RPT-005" => "SARIF output preserves ordered rules, findings, metadata, symlink locations, constants, and empty arrays.",
  "RPT-006" => "Templates preserve pinned finding fields and deterministic allowed Sprig helpers.",
  "RPT-007" => "Templates reject env, expandenv, and getHostByName while parse-allowing pinned benign helpers.",
  "RPT-008" => "Report redaction mutates Line, Match, and Secret with pinned byte-length and RoundToEven semantics.",
  "RPT-009" => "Unicode, invalid UTF-8, controls, HTML, CSV, JSON, XML, and template byte boundaries are explicit.",
  "RPT-010" => "Writer, JSON value, template path/read/parse/execute, request, and format failures are observable.",
  "RPT-011" => "Empty JSON, CSV, JUnit, SARIF, and template reports retain format-specific exact bytes.",
  "RPT-012" => "Link and symlink fields retain their format-specific inclusion and precedence.",
  "RPT-013" => "Report bytes are deterministic for deterministic findings, rules, and templates."
}.freeze
SOURCE_HASHES = {
  "report/constants.go" => "7b340a90e47a2bdb55fed6a80644b7e8682f12d4706d20efdabccd43043e4ba4",
  "report/csv.go" => "c51f7575fcf542de8b3a897fa98093aaed697b28e0af44f4bec19a66ef9d4b91",
  "report/csv_test.go" => "2585824350ac030e0751aeb8af0a1103654d9ee14821358caa96410c76784f9e",
  "report/finding.go" => "a1ecd3837f6d89b8ddf95f2b0a6c301103b8d3e67f84e1b3520ffc6f7d7751a6",
  "report/finding_test.go" => "60f6950823fd227c77d65c630b540fdb3dba46b947bda5bf98f5a72d9d513874",
  "report/json.go" => "7cce5d031a4b6fde50e52bd9cd551781a0f00f9a0de79852cfa10ac3385ff733",
  "report/json_test.go" => "7f4172d7ff38ef224f88fdaf103187d68a8dd43eaefcd0e2bcbd933849ee2367",
  "report/junit.go" => "de628ab9afb6ab5aee6a36e172485ca84f9f9625eeedaa7fa39c62a9754ab4b1",
  "report/junit_test.go" => "dc298993221456d5b023b6af4d200e6ade47bab1272b92d441d29f27124da558",
  "report/report.go" => "109c5fc946faa5af35ac784815644b4fe5b1ec7b27e3f1f2540c6306a2876f30",
  "report/report_test.go" => "16763fa5d4794ce1bb11292a2d4d47a90c6fa1fd661d9b621230b25d53835d89",
  "report/sarif.go" => "703eff736c567fb14133dd24cb814bca8f2626fb63d6b969c1fd967ff58e01ed",
  "report/sarif_test.go" => "94dc9b2c5745bbcf705721310ff0be680f606458f6bf7d438fde804c263ae28e",
  "report/template.go" => "0e324cc75ffeff1ccd3210dc4df88daa72bc5458c49a945db68ade53b80a0a13",
  "report/template_test.go" => "d2df3b6b51dfd6d2970b0348cd36c318d0147a6bfa5fc5e761798d20f3102e3c"
}.freeze
FIXTURE_HASHES = {
  "testdata/expected/report/csv_simple.csv" => "5de23941d15e7a24937cd469aaad57a980639dba613cd2f8e300b027a7b710c6",
  "testdata/expected/report/empty.json" => "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570",
  "testdata/expected/report/json_simple.json" => "009af704252257862ee56642a9711189b6f70ec039a3531255d154664968b7ba",
  "testdata/expected/report/junit_empty.xml" => "05219f7bf8d7624e2c21f8e17fe1bbda6d83c915b2716aaaeb0bd6c1d92ac5b3",
  "testdata/expected/report/junit_simple.xml" => "02fa6b90965f73a02ecc1fb015317ba4785742bea7460086c7d6b143322e58f3",
  "testdata/expected/report/sarif_simple.sarif" => "501d60363f7f8963e44eb976785818282898a5f4c46fa454ff6f9b47572ed083",
  "testdata/expected/report/template_jsonextra.json" => "bfd4437153905ab8ce814e7aa38cfed6d385bbffaa5829b8bc8fc6c58104acda",
  "testdata/expected/report/template_markdown.md" => "0badcf1d17d701a9693d5daf93dab64e07b685814815eec6ed36944686c430aa",
  "testdata/report/jsonextra.tmpl" => "5510863d4e65c22344ef54a06be93411282e9ab4630efab54cd38da68816c67d",
  "testdata/report/markdown.tmpl" => "de9fc3354c93675f1cc2ce72ccbe5197f785879e6490f1a9b1fe2e2cf8940d29"
}.freeze
REPORT_TEST_IDS = (251..268).map { |number| format("TM-%04d", number) }.freeze

CHECK = ARGV.delete("--check")
abort "usage: #{$PROGRAM_NAME} [--check]" unless ARGV.empty?

GO_ENV = {
  "GOCACHE" => ENV.fetch("GOCACHE", File.join(Dir.tmpdir, "rustleaks-m11-oracle-gocache")),
  "GOMODCACHE" => ENV.fetch("GOMODCACHE", File.join(Dir.tmpdir, "rustleaks-go-mod-cache")),
  "GOMEMLIMIT" => ENV.fetch("GOMEMLIMIT", "768MiB"),
  "GOMAXPROCS" => ENV.fetch("GOMAXPROCS", "2"),
  "LC_ALL" => "C", "TZ" => "UTC"
}.freeze

def sha(bytes)
  Digest::SHA256.hexdigest(bytes)
end

def b64(bytes)
  Base64.strict_encode64(bytes.b)
end

def decode64(value)
  Base64.strict_decode64(value).b
end

def capture(*command, chdir:, stdin_data: "")
  output, error, status = Open3.capture3(GO_ENV, *command, chdir: chdir.to_s, stdin_data: stdin_data)
  abort "#{command.join(' ')} failed in #{chdir}:\n#{error}\n#{output}" unless status.success?
  output
end

selected_runtime = capture("go", "env", "GOVERSION", "GOOS", "GOARCH", chdir: ORACLE).lines.map(&:strip)
abort "selected Go runtime provenance was incomplete" unless selected_runtime.length == 3
EXPECTED_GO_VERSION = selected_runtime.fetch(0).freeze
EXPECTED_PLATFORM = "#{selected_runtime.fetch(1)}/#{selected_runtime.fetch(2)}".freeze
abort "selected Go toolchain is not pinned to Go 1.25" unless EXPECTED_GO_VERSION.match?(/\Ago1\.25(?:\.\d+)?\z/)
abort "selected Go platform is malformed" unless EXPECTED_PLATFORM.match?(%r{\A[a-z0-9]+/[a-z0-9]+\z})

def bounded_oracle(binary, request)
  output = +"".b
  error = +"".b
  status = nil
  Open3.popen3(GO_ENV, binary, "--report", chdir: ORACLE.to_s, pgroup: true) do |stdin, stdout, stderr, wait|
    stdin.write(JSON.generate(request) + "\n")
    stdin.close
    begin
      Timeout.timeout(20) do
        readers = [stdout, stderr]
        until readers.empty?
          ready = IO.select(readers, nil, nil, 0.25)
          next if ready.nil?
          ready.first.each do |stream|
            begin
              chunk = stream.read_nonblock(64 * 1024)
              target = stream.equal?(stdout) ? output : error
              target << chunk
              raise "oracle output exceeded 8 MiB" if target.bytesize > 8 * 1024 * 1024
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
  abort "#{request.fetch('id')}: oracle failed: #{error}" unless status&.success?
  lines = output.lines
  abort "#{request.fetch('id')}: oracle emitted #{lines.length} lines: #{output.inspect}" unless lines.length == 1
  JSON.parse(lines.first)
end

def request(id, format:, behaviors:, tests: [], findings: [], **fields)
  {
    "protocol_version" => PROTOCOL_VERSION, "id" => id, "behavior_ids" => behaviors,
    "test_case_ids" => tests, "format" => format, "findings" => findings
  }.merge(fields.transform_keys(&:to_s))
end

def finding(**overrides)
  values = {
    rule_id_base64: b64("test-rule"), description_base64: b64("Test Rule"),
    start_line: 1, end_line: 2, start_column: 1, end_column: 2,
    line_base64: b64("whole line containing secret"), match_base64: b64("line containing secret"), secret_base64: b64("a secret"),
    file_base64: b64("auth.py"), symlink_file_base64: b64(""), commit_base64: b64("0000000000000000"), link_base64: b64(""),
    entropy_bits: 0, author_base64: b64("John Doe"), email_base64: b64("johndoe@gmail.com"),
    date_base64: b64("10-19-2003"), message_base64: b64("opps"), tags_base64: [], fingerprint_base64: b64("")
  }.merge(overrides)
  values.transform_keys(&:to_s)
end

def rule(id, description)
  { "id_base64" => b64(id), "description_base64" => b64(description) }
end

def output(outcome)
  decode64(outcome.fetch("output_base64"))
end

def runtime_provenance_valid?(outcome)
  outcome["go_version"] == EXPECTED_GO_VERSION && outcome["platform"] == EXPECTED_PLATFORM
end

def assert_runtime_provenance_negative_control!(outcome)
  %w[go_version platform].each do |field|
    mutated = outcome.merge(field => "invalid-provenance")
    abort "runtime provenance negative control accepted mutated #{field}" if runtime_provenance_valid?(mutated)
  end
end

def assert_envelope!(entry, outcome)
  id = entry.fetch("id")
  abort "#{id}: id changed" unless outcome["id"] == id
  abort "#{id}: protocol changed" unless outcome["protocol_version"] == PROTOCOL_VERSION
  abort "#{id}: mode changed" unless outcome["oracle_mode"] == "report"
  abort "#{id}: revision changed" unless outcome["upstream_revision"] == REVISION
  abort "#{id}: config hash changed" unless outcome["default_config_sha256"] == DEFAULT_SHA256
  abort "#{id}: runtime provenance differs from selected Go toolchain" unless runtime_provenance_valid?(outcome)
  bytes = output(outcome)
  abort "#{id}: output length mismatch" unless outcome["output_bytes"] == bytes.bytesize
  abort "#{id}: output hash mismatch" unless outcome["output_sha256"] == sha(bytes)
  abort "#{id}: redacted projection missing" unless outcome["redacted_findings"].is_a?(Array)
end

abort "upstream revision changed" unless capture("git", "rev-parse", "HEAD", chdir: UPSTREAM).strip == REVISION
abort "default config changed" unless sha(UPSTREAM.join("config/gitleaks.toml").binread) == DEFAULT_SHA256
SOURCE_HASHES.merge(FIXTURE_HASHES).each do |path, expected|
  abort "#{path} changed" unless sha(UPSTREAM.join(path).binread) == expected
end
upstream_before = capture("git", "status", "--short", chdir: UPSTREAM)

simple_json = finding(description_base64: b64(""), line_base64: b64(""))
junit_second = finding(start_line: 2, end_line: 3, message_base64: b64(""), commit_base64: b64(""),
                       author_base64: b64(""), email_base64: b64(""), date_base64: b64(""))
markdown_template = UPSTREAM.join("testdata/report/markdown.tmpl").binread
jsonextra_template = UPSTREAM.join("testdata/report/jsonextra.tmpl").binread

requests = []
requests << request("json-empty", format: "json", behaviors: %w[RPT-002 RPT-011 RPT-013], tests: %w[TM-0259 TM-0260])
requests << request("json-upstream-simple", format: "json", behaviors: %w[RPT-002 RPT-013], tests: %w[TM-0259 TM-0261 TM-0265], findings: [simple_json])
requests << request("json-link-symlink-tags-nil", format: "json", behaviors: %w[RPT-002 RPT-009 RPT-012], findings: [finding(
  rule_id_base64: b64("规则<&"), description_base64: b64("desc\n\t\x00"), file_base64: b64("real/é.txt"),
  symlink_file_base64: b64("link/💩.txt"), link_base64: b64("https://example.test/?a=<x>&b=1"), tags_nil: true,
  secret_base64: b64("\xff<&\u2028\u2029".b), match_base64: b64("prefix\xff<&\u2028\u2029".b), entropy_bits: 0x40600000
)])
requests << request("json-redact-75-repeated", format: "json", behaviors: %w[RPT-002 RPT-008], tests: %w[TM-0241 TM-0243 TM-0250], redact_percent: 75,
                    findings: [finding(secret_base64: b64("secret"), line_base64: b64("secret/secret"), match_base64: b64("secret+secret"))])
requests << request("json-redact-100", format: "json", behaviors: %w[RPT-002 RPT-008], tests: %w[TM-0247 TM-0250], redact_percent: 100,
                    findings: [finding(secret_base64: b64("secret"), line_base64: b64("secret"), match_base64: b64("secret"))])
requests << request("json-redact-zero", format: "json", behaviors: %w[RPT-002 RPT-008], redact_percent: 0,
                    findings: [finding(secret_base64: b64("abc"), line_base64: b64("abc"), match_base64: b64("abc"))])
requests << request("json-redact-round-even", format: "json", behaviors: %w[RPT-002 RPT-008], redact_percent: 50,
                    findings: [finding(secret_base64: b64("abcde"), line_base64: b64("abcde"), match_base64: b64("abcde"))])
requests << request("json-redact-unicode-byte-split", format: "json", behaviors: %w[RPT-002 RPT-008 RPT-009], redact_percent: 50,
                    findings: [finding(secret_base64: b64("ééé"), line_base64: b64("ééé"), match_base64: b64("ééé"))])
requests << request("json-nan-error", format: "json", behaviors: %w[RPT-002 RPT-010], findings: [finding(entropy_bits: 0x7fc00000)])
requests << request("json-writer-error", format: "json", behaviors: %w[RPT-002 RPT-010], findings: [simple_json], fail_after_bytes: 17)

requests << request("csv-empty", format: "csv", behaviors: %w[RPT-003 RPT-011 RPT-013], tests: %w[TM-0256 TM-0257])
requests << request("csv-upstream-simple", format: "csv", behaviors: %w[RPT-003 RPT-013], tests: %w[TM-0256 TM-0258],
                    findings: [finding(fingerprint_base64: b64("fingerprint"), tags_base64: %w[tag1 tag2 tag3].map { |tag| b64(tag) })])
requests << request("csv-first-link-present", format: "csv", behaviors: %w[RPT-003 RPT-009 RPT-012], findings: [
  finding(link_base64: b64("https://first.example/a,b"), file_base64: b64("a,\"b\n💩\xff".b), tags_base64: [b64("one two"), b64("三")]),
  finding(link_base64: b64("https://second.example"), secret_base64: b64("second"))
])
requests << request("csv-first-link-absent", format: "csv", behaviors: %w[RPT-003 RPT-012], findings: [finding, finding(link_base64: b64("https://omitted.example"))])
requests << request("csv-unicode-leading-space-backslash-dot", format: "csv", behaviors: %w[RPT-003 RPT-009], findings: [finding(
  rule_id_base64: b64("\u00a0leading"), file_base64: b64('\\.'), secret_base64: b64("\u2003é💩"),
  match_base64: b64("prefix \\. suffix"), tags_base64: [b64(" leading-tag"), b64("三")]
)])
requests << request("csv-redacted", format: "csv", behaviors: %w[RPT-003 RPT-008], redact_percent: 90,
                    findings: [finding(secret_base64: b64("secret"), line_base64: b64("secret"), match_base64: b64("secret"))])
requests << request("csv-writer-error", format: "csv", behaviors: %w[RPT-003 RPT-010], findings: [finding], fail_after_bytes: 1)

requests << request("junit-empty", format: "junit", behaviors: %w[RPT-004 RPT-011 RPT-013], tests: ["TM-0262"])
requests << request("junit-upstream-simple", format: "junit", behaviors: %w[RPT-004 RPT-013], tests: ["TM-0262"], findings: [finding, junit_second])
requests << request("junit-unicode-escaping", format: "junit", behaviors: %w[RPT-004 RPT-009 RPT-012], findings: [finding(
  description_base64: b64("规则<&\""), rule_id_base64: b64("id<&"), file_base64: b64("é<&.txt"),
  secret_base64: b64("s<&\n\t\u2028\u2029"), match_base64: b64("m<&"), link_base64: b64("https://example.test/<&"), entropy_bits: 0x40600000
)])
requests << request("junit-invalid-byte-replacement", format: "junit", behaviors: %w[RPT-004 RPT-009], findings: [finding(
  description_base64: b64("desc\xff".b), file_base64: b64("file\xff.txt".b), secret_base64: b64("secret\xff".b), entropy_bits: 0x3f000000
)])
requests << request("junit-control-replacement", format: "junit", behaviors: %w[RPT-004 RPT-009], findings: [finding(description_base64: b64("bad\x01control"))])
requests << request("junit-writer-error", format: "junit", behaviors: %w[RPT-004 RPT-010], findings: [finding], fail_after_bytes: 0)

ordered_rules = [rule("aws-access-key", "AWS Access Key"), rule("pypi", "PyPI upload token")]
requests << request("sarif-empty", format: "sarif", behaviors: %w[RPT-005 RPT-011 RPT-013], ordered_rules: [])
requests << request("sarif-upstream-simple", format: "sarif", behaviors: %w[RPT-005 RPT-013], tests: %w[TM-0263 TM-0264], findings: [finding(
  description_base64: b64("A test rule"), tags_base64: %w[tag1 tag2 tag3].map { |tag| b64(tag) }
)], ordered_rules: ordered_rules)
requests << request("sarif-rule-order-duplicates", format: "sarif", behaviors: %w[RPT-005 RPT-013], ordered_rules: [rule("z", "last"), rule("a", "first"), rule("z", "again")])
requests << request("sarif-symlink-no-commit", format: "sarif", behaviors: %w[RPT-005 RPT-009 RPT-012], findings: [finding(
  file_base64: b64("real/<&.txt"), symlink_file_base64: b64("link/💩.txt"), commit_base64: b64(""), secret_base64: b64("秘密<&"),
  tags_base64: [b64("tag<&"), b64("三")]
)], ordered_rules: [rule("test-rule", "规则<&")])
requests << request("sarif-invalid-byte-message", format: "sarif", behaviors: %w[RPT-005 RPT-009], findings: [finding(
  file_base64: b64("bad\xff<&.txt".b), secret_base64: b64("s\xff\u2028\u2029".b), author_base64: b64("a\xff".b)
)], ordered_rules: [rule("test-rule", "description")])
requests << request("sarif-writer-error", format: "sarif", behaviors: %w[RPT-005 RPT-010], findings: [finding], ordered_rules: ordered_rules, fail_after_bytes: 19)

requests << request("template-markdown", format: "template", behaviors: %w[RPT-006 RPT-013], tests: %w[TM-0266 TM-0268], findings: [finding], template_base64: b64(markdown_template))
requests << request("template-jsonextra", format: "template", behaviors: %w[RPT-006 RPT-013], tests: %w[TM-0266 TM-0267], findings: [finding(
  description_base64: b64("A test rule"), tags_base64: %w[tag1 tag2 tag3].map { |tag| b64(tag) }
)], template_base64: b64(jsonextra_template))
requests << request("template-empty", format: "template", behaviors: %w[RPT-006 RPT-011], template_base64: b64(""))
requests << request("template-safe-helpers", format: "template", behaviors: %w[RPT-006 RPT-007], findings: [finding],
                    template_base64: b64('{{ upper (index . 0).RuleID }}|{{ quote (index . 0).Secret }}|{{ sha256sum "x" }}|{{ default "fallback" "" }}'))
requests << request("template-raw-bytes", format: "template", behaviors: %w[RPT-006 RPT-009], findings: [finding(secret_base64: b64("\x00\xff<&💩".b))],
                    template_base64: b64("{{ (index . 0).Secret }}"))
{
  "template-block-env" => ["env", "TM-0252"],
  "template-block-expandenv" => ["expandenv", "TM-0253"],
  "template-block-host" => ["getHostByName", "TM-0254"]
}.each do |id, (function, test_id)|
  requests << request(id, format: "template", behaviors: %w[RPT-007 RPT-010], tests: %W[TM-0251 #{test_id}],
                      template_mode: "validate", template_base64: b64(%({{ #{function} "value" }})))
end
requests << request("template-allow-now-parse", format: "template", behaviors: ["RPT-007"], tests: %w[TM-0251 TM-0255],
                    template_mode: "validate", template_base64: b64('{{ now | date "2006-01-02" }}'))
requests << request("template-allow-random-parse", format: "template", behaviors: ["RPT-007"], template_mode: "validate", template_base64: b64("{{ randAlphaNum 8 }}"))
requests << request("template-parse-error", format: "template", behaviors: ["RPT-010"], template_mode: "validate", template_base64: b64("{{"))
requests << request("template-execute-error", format: "template", behaviors: ["RPT-010"], findings: [finding], template_base64: b64("{{ index . 99 }}"))
requests << request("template-empty-path", format: "template", behaviors: ["RPT-010"], template_mode: "empty-path")
requests << request("template-missing-path", format: "template", behaviors: ["RPT-010"], template_mode: "missing")
requests << request("template-writer-error", format: "template", behaviors: %w[RPT-006 RPT-010], findings: [finding],
                    template_base64: b64("prefix {{ (index . 0).Secret }} suffix"), fail_after_bytes: 4)

requests << request("unknown-format", format: "yaml", behaviors: %w[RPT-001 RPT-010])
requests << request("bad-finding-base64", format: "json", behaviors: ["RPT-010"], findings: [finding(secret_base64: "***")])
requests << request("bad-rule-base64", format: "sarif", behaviors: ["RPT-010"], ordered_rules: [{ "id_base64" => "***", "description_base64" => b64("") }])
requests << request("negative-writer-limit", format: "json", behaviors: ["RPT-010"], fail_after_bytes: -1)
wrong_version = request("wrong-protocol", format: "json", behaviors: ["RPT-010"])
wrong_version["protocol_version"] = PROTOCOL_VERSION + 1
requests << wrong_version

Dir.mktmpdir("rustleaks-report-corpus-") do |temporary|
  binary = File.join(temporary, "oracle")
  capture("go", "build", "-trimpath", "-o", binary, ".", chdir: ORACLE)
  outcomes = requests.map.with_index do |entry, index|
    outcome = bounded_oracle(binary, entry)
    assert_envelope!(entry, outcome)
    assert_runtime_provenance_negative_control!(outcome) if index.zero?
    # Runtime provenance is validated above but omitted from committed exact
    # outcomes so identical behavior regenerates byte-for-byte on every host.
    outcome.delete("go_version")
    outcome.delete("platform")
    outcome
  end
  by_id = outcomes.to_h { |outcome| [outcome.fetch("id"), outcome] }

  # Exact pinned upstream fixture relations. These compare report bytes, not a
  # parsed/normalized representation.
  {
    "json-empty" => "testdata/expected/report/empty.json",
    "json-upstream-simple" => "testdata/expected/report/json_simple.json",
    "csv-upstream-simple" => "testdata/expected/report/csv_simple.csv",
    "junit-empty" => "testdata/expected/report/junit_empty.xml",
    "junit-upstream-simple" => "testdata/expected/report/junit_simple.xml",
    "sarif-upstream-simple" => "testdata/expected/report/sarif_simple.sarif",
    "template-markdown" => "testdata/expected/report/template_markdown.md",
    "template-jsonextra" => "testdata/expected/report/template_jsonextra.json"
  }.each do |id, fixture|
    abort "#{id}: upstream fixture bytes changed" unless output(by_id.fetch(id)) == UPSTREAM.join(fixture).binread
  end

  abort "empty CSV emitted bytes" unless output(by_id.fetch("csv-empty")).empty?
  abort "empty SARIF lost explicit arrays" unless JSON.parse(output(by_id.fetch("sarif-empty"))).dig("runs", 0, "tool", "driver", "rules") == [] &&
                                                  JSON.parse(output(by_id.fetch("sarif-empty"))).dig("runs", 0, "results") == []
  json_edge = JSON.parse(output(by_id.fetch("json-link-symlink-tags-nil"))).first
  abort "JSON Link omitted or changed" unless json_edge["Link"] == "https://example.test/?a=<x>&b=1"
  abort "JSON nil tags changed" unless json_edge.key?("Tags") && json_edge["Tags"].nil?
  abort "JSON Line leaked" if json_edge.key?("Line")
  json_edge_bytes = output(by_id.fetch("json-link-symlink-tags-nil"))
  abort "JSON invalid UTF-8/HTML escaping changed" unless json_edge_bytes.include?(%q{"Secret": "\ufffd\u003c\u0026})
  abort "JSON U+2028/U+2029 escaping changed" unless json_edge_bytes.include?("\\u2028\\u2029".b)
  abort "JSON float32 rendering changed" unless json_edge["Entropy"] == 3.5
  redacted = by_id.fetch("json-redact-75-repeated").fetch("redacted_findings").first
  abort "redaction did not replace all Line occurrences" unless decode64(redacted.fetch("line_base64")) == "se.../se..."
  abort "redaction did not replace all Match occurrences" unless decode64(redacted.fetch("match_base64")) == "se...+se..."
  abort "100% redaction changed" unless decode64(by_id.fetch("json-redact-100").dig("redacted_findings", 0, "secret_base64")) == "REDACTED"
  abort "0% redaction quirk changed" unless decode64(by_id.fetch("json-redact-zero").dig("redacted_findings", 0, "secret_base64")) == "abc..."
  abort "RoundToEven redaction changed" unless decode64(by_id.fetch("json-redact-round-even").dig("redacted_findings", 0, "secret_base64")) == "ab..."
  abort "Unicode byte-split redaction stopped producing replacement on JSON encoding" unless output(by_id.fetch("json-redact-unicode-byte-split")).include?("\\ufffd...".b)
  abort "NaN JSON did not fail" unless by_id.fetch("json-nan-error").dig("error", "class") == "writer" && by_id.fetch("json-nan-error").dig("error", "message").include?("unsupported value")

  csv_without_link = output(by_id.fetch("csv-first-link-absent"))
  abort "CSV first-finding Link quirk changed" if csv_without_link.include?("Link") || csv_without_link.include?("omitted.example")
  csv_with_link = output(by_id.fetch("csv-first-link-present"))
  abort "CSV Link column missing" unless csv_with_link.lines.first.end_with?("Tags,Link\n") && csv_with_link.include?("second.example")
  abort "CSV stopped preserving invalid bytes" unless csv_with_link.include?("\xff".b)
  csv_plain = output(by_id.fetch("csv-unicode-leading-space-backslash-dot"))
  abort "CSV Unicode-leading-space/backslash-dot quoting changed" unless csv_plain.lines[1].start_with?("\"\u00a0leading\",".b) && csv_plain.include?(',"\\.",'.b) && csv_plain.include?("\"\u2003é💩\"".b)
  junit_control = output(by_id.fetch("junit-control-replacement"))
  abort "JUnit XML-invalid-control replacement changed" unless by_id.fetch("junit-control-replacement")["error"].nil? && junit_control.include?("bad�control".b)
  junit_unicode = output(by_id.fetch("junit-unicode-escaping"))
  abort "JUnit embedded float32/HTML/U+2028/U+2029 changed" unless junit_unicode.include?("&#34;Entropy&#34;: 3.5".b) && junit_unicode.include?("\\u003c\\u0026".b) && junit_unicode.include?("\\u2028\\u2029".b)
  junit_invalid = output(by_id.fetch("junit-invalid-byte-replacement"))
  abort "JUnit invalid-byte replacement changed" unless by_id.fetch("junit-invalid-byte-replacement")["error"].nil? && junit_invalid.include?("�".b)
  sarif_order = JSON.parse(output(by_id.fetch("sarif-rule-order-duplicates"))).dig("runs", 0, "tool", "driver", "rules").map { |item| item.fetch("id") }
  abort "SARIF ordered rules changed" unless sarif_order == %w[z a z]
  sarif_symlink = JSON.parse(output(by_id.fetch("sarif-symlink-no-commit")))
  abort "SARIF symlink URI changed" unless sarif_symlink.dig("runs", 0, "results", 0, "locations", 0, "physicalLocation", "artifactLocation", "uri") == "link/💩.txt"
  abort "SARIF no-commit message changed" unless sarif_symlink.dig("runs", 0, "results", 0, "message", "text") == "test-rule has detected secret for file real/<&.txt."
  sarif_invalid = output(by_id.fetch("sarif-invalid-byte-message"))
  abort "SARIF invalid-byte/HTML/U+2028/U+2029 escaping changed" unless sarif_invalid.include?("\\ufffd\\u003c\\u0026".b) && sarif_invalid.include?("\\u2028\\u2029".b)
  abort "template raw bytes changed" unless output(by_id.fetch("template-raw-bytes")) == "\x00\xff<&💩".b
  abort "safe helpers changed" unless output(by_id.fetch("template-safe-helpers")).start_with?('TEST-RULE|"a secret"|2d711642b726b044')
  %w[template-block-env template-block-expandenv template-block-host].each do |id|
    abort "#{id}: dangerous helper accepted" unless by_id.fetch(id).dig("error", "class") == "template-parse" && by_id.fetch(id).dig("error", "message").include?("not defined")
  end
  %w[template-allow-now-parse template-allow-random-parse].each do |id|
    abort "#{id}: allowed helper rejected or executed" unless by_id.fetch(id)["error"].nil? && output(by_id.fetch(id)).empty?
  end
  expected_errors = {
    "json-writer-error" => "writer", "csv-writer-error" => "writer", "junit-writer-error" => "writer",
    "sarif-writer-error" => "writer", "template-writer-error" => "writer", "template-parse-error" => "template-parse",
    "template-execute-error" => "template-execute", "template-empty-path" => "template-path",
    "template-missing-path" => "template-read", "unknown-format" => "format", "bad-finding-base64" => "request",
    "bad-rule-base64" => "request", "negative-writer-limit" => "request", "wrong-protocol" => "protocol"
  }
  expected_errors.each do |id, class_name|
    abort "#{id}: expected #{class_name}, got #{by_id.fetch(id)['error'].inspect}" unless by_id.fetch(id).dig("error", "class") == class_name
  end
  serialized = JSON.generate(outcomes)
  abort "temporary template path leaked" if serialized.include?("rustleaks-report-template-")

  request_bytes = requests.map { |entry| JSON.generate(entry) + "\n" }.join
  outcome_bytes = outcomes.map { |entry| JSON.generate(entry) + "\n" }.join
  coverage = {
    "protocol_version" => PROTOCOL_VERSION,
    "upstream_revision" => REVISION,
    "default_config_sha256" => DEFAULT_SHA256,
    "case_count" => requests.length,
    "output_byte_count" => outcomes.sum { |item| item.fetch("output_bytes") },
    "format_counts" => requests.group_by { |item| item.fetch("format") }.transform_values(&:length).sort.to_h,
    "error_case_count" => outcomes.count { |item| !item["error"].nil? },
    "test_case_ids" => requests.flat_map { |item| item.fetch("test_case_ids") }.uniq.sort,
    "required_report_test_case_ids" => REPORT_TEST_IDS,
    "behavior_ids" => BEHAVIORS.keys,
    "behavior_definitions" => BEHAVIORS,
    "source_sha256" => SOURCE_HASHES,
    "fixture_sha256" => FIXTURE_HASHES,
    "requests_sha256" => sha(request_bytes),
    "outcomes_sha256" => sha(outcome_bytes)
  }
  abort "report test identity coverage incomplete" unless (REPORT_TEST_IDS - coverage.fetch("test_case_ids")).empty?
  coverage_bytes = JSON.pretty_generate(coverage) + "\n"
  readme = <<~README
    # Report compatibility corpus v1

    Generated by `ruby compat/generate_report_corpus.rb` from pinned Go revision
    `#{REVISION}`. Every JSONL request executes in its own bounded oracle process.
    Byte-bearing finding, template, and output fields use base64, so invalid UTF-8
    and control bytes remain observable.

    Runtime Go version and host platform are validated during generation but
    omitted from outcomes so the committed corpus is host-independent.

    The corpus freezes exact JSON, CSV, JUnit, SARIF, and template bytes; all
    pinned upstream report fixtures; report-test identities `TM-0251..TM-0268`;
    redaction; ordered SARIF rules; Link/symlink behavior; deterministic safe
    template helpers; the three explicitly blocked Sprig helpers; and structured
    writer/template/format/request failures. Parse-only cases retain allowed
    nondeterministic helpers without executing them.

    Regenerate with `ruby compat/generate_report_corpus.rb`; verify exact
    determinism with `ruby compat/generate_report_corpus.rb --check`.
  README
  artifacts = {
    "requests-v1.jsonl" => request_bytes,
    "outcomes-v1.jsonl" => outcome_bytes,
    "coverage-v1.json" => coverage_bytes,
    "README.md" => readme
  }

  if CHECK
    artifacts.each do |name, expected|
      path = OUTPUT_ROOT.join(name)
      abort "missing #{path}" unless path.file?
      actual = path.binread
      unless actual == expected.b
        differing = [actual.bytesize, expected.bytesize].min.times.find { |index| actual.getbyte(index) != expected.getbyte(index) }
        abort "#{path} differs at byte #{differing || 'length'} (committed #{sha(actual)}, generated #{sha(expected)})"
      end
    end
    unexpected = OUTPUT_ROOT.children.map(&:basename).map(&:to_s).sort - artifacts.keys.sort
    abort "unexpected report corpus artifacts: #{unexpected.join(', ')}" unless unexpected.empty?
  else
    FileUtils.mkdir_p(OUTPUT_ROOT)
    artifacts.each { |name, bytes| OUTPUT_ROOT.join(name).binwrite(bytes) }
  end

  puts "report corpus: #{requests.length} fresh processes, #{coverage.fetch('output_byte_count')} output bytes, #{coverage.fetch('error_case_count')} errors"
  puts "requests sha256: #{coverage.fetch('requests_sha256')}"
  puts "outcomes sha256: #{coverage.fetch('outcomes_sha256')}"
end

abort "upstream checkout changed during report generation" unless capture("git", "status", "--short", chdir: UPSTREAM) == upstream_before
