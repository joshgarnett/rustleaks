#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "digest"
require "fileutils"
require "json"
require "open3"
require "pathname"
require "tmpdir"
require "timeout"

ROOT = Pathname(__dir__).parent
UPSTREAM = ROOT.parent.join("gitleaks")
ORACLE = ROOT.join("crates/rustleaks-compat/oracle")
OUTPUT_ROOT = ROOT.join("compat/composite-corpus")
MANIFEST = ROOT.join("compat/test-manifest.toml")
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
DEFAULT_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
EXPECTED_UPSTREAM_STATUS = ""
PROTOCOL_VERSION = 1
BEHAVIORS = %w[COMP-001 COMP-002 COMP-003 COMP-004 COMP-005 COMP-006 COMP-007 COMP-008 SUP-001 RED-001 RED-002 RED-003].freeze
LEAF_IDS = %w[TM-0084 TM-0242 TM-0243 TM-0244 TM-0246 TM-0247 TM-0248 TM-0249 TM-0250].freeze
ROOT_IDS = %w[TM-0241 TM-0245].freeze
CHECK = ARGV.delete("--check")
abort "usage: #{$PROGRAM_NAME} [--check]" unless ARGV.empty?

GO_ENV = {
  "GOCACHE" => ENV.fetch("GOCACHE", File.join(Dir.tmpdir, "rustleaks-composite-oracle-gocache")),
  "GOMODCACHE" => ENV.fetch("GOMODCACHE", File.join(Dir.tmpdir, "rustleaks-go-mod-cache"))
}.freeze

def capture(*command, chdir:, stdin_data: "", env: {}, timeout_seconds: 60, output_limit: 64 * 1024 * 1024,
            allocation_limit: nil, request_id: nil)
  label = request_id || command.join(" ")
  spawn_options = {chdir: chdir.to_s}
  child_env = GO_ENV.merge(env)
  child_env["GOMEMLIMIT"] = "#{allocation_limit}B" if allocation_limit
  output = +"".b
  error = +"".b
  status = nil
  Open3.popen3(child_env, *command, spawn_options) do |stdin, stdout, stderr, wait_thread|
    stdin.binmode
    stdin.write(stdin_data)
    stdin.close
    readers = [[stdout, output, "stdout"], [stderr, error, "stderr"]].map do |io, buffer, stream|
      Thread.new do
        loop do
          chunk = io.readpartial(16 * 1024)
          buffer << chunk
          if buffer.bytesize > output_limit
            Process.kill("KILL", wait_thread.pid) rescue nil
            raise "#{label}: #{stream} exceeded #{output_limit} bytes"
          end
        end
      rescue EOFError
        nil
      end
    end
    begin
      Timeout.timeout(timeout_seconds) { status = wait_thread.value }
      readers.each(&:value)
    rescue Timeout::Error
      Process.kill("KILL", wait_thread.pid) rescue nil
      wait_thread.value rescue nil
      abort "#{label}: exceeded deterministic #{timeout_seconds}s deadline"
    rescue StandardError => e
      Process.kill("KILL", wait_thread.pid) rescue nil
      wait_thread.value rescue nil
      abort e.message
    ensure
      stdout.close rescue nil
      stderr.close rescue nil
    end
  end
  abort "#{label} failed in #{chdir}:\n#{error}\n#{output}" unless status&.success?
  output
end

def b64(bytes)
  Base64.strict_encode64(bytes.b)
end

def sha(bytes)
  Digest::SHA256.hexdigest(bytes.b)
end

def jsonl(rows)
  rows.map { |row| JSON.generate(row) + "\n" }.join
end

def fragment(content, start_line: 0, file: "tmp.go", commit: "", inherited: false)
  {
    "content_base64" => b64(content), "file_base64" => b64(file),
    "windows_file_base64" => "", "symlink_file_base64" => "", "commit_base64" => b64(commit),
    "start_line" => start_line, "author_base64" => "", "email_base64" => "", "date_base64" => "",
    "message_base64" => "", "remote_url_base64" => "", "remote_platform" => "",
    "inherited_from_finding" => inherited
  }
end

def options(depth: 0, redact: 0, ignore_marker: false, max_mb: 0)
  {"max_decode_depth" => depth, "max_target_megabytes" => max_mb,
   "redact_percent" => redact, "ignore_allow_marker" => ignore_marker}
end

def detect_request(id, behaviors, content, config: nil, fixture: nil, config_files: nil, config_entry: nil, config_workdir: nil, test_ids: [], start_line: 0,
                   inherited: false, depth: 0, redact: 0, ignore_marker: false, file: "tmp.go", commit: "")
  sources = [config, fixture, config_files].compact
  abort "#{id}: exactly one config source required" unless sources.length == 1
  {
    "protocol_version" => PROTOCOL_VERSION, "id" => id, "behavior_ids" => behaviors,
    "test_case_ids" => test_ids, "operation" => "detect", "use_default" => false,
    "config_base64" => config ? b64(config) : "", "config_fixture" => fixture || "",
    "config_entry" => config_entry || "", "config_files" => (config_files || {}).map { |path, bytes| {"path" => path, "content_base64" => b64(bytes)} },
    "config_working_directory" => config_workdir || "",
    "fragment" => fragment(content, start_line: start_line, file: file, commit: commit, inherited: inherited),
    "options" => options(depth: depth, redact: redact, ignore_marker: ignore_marker)
  }
end

def probe_request(id, content)
  {"protocol_version" => PROTOCOL_VERSION, "id" => id, "behavior_ids" => ["COMP-001"],
   "test_case_ids" => [], "operation" => "probe_missing_required", "fragment" => fragment(content),
   "options" => options}
end

def finding_input(secret:, match: nil, line: nil, rule_id: "redact-rule", entropy: 3.25, tags: ["tag"])
  match ||= secret
  line ||= match
  {
    "rule_id" => rule_id, "description_base64" => b64("Redaction fixture"),
    "start_line" => 7, "end_line" => 8, "start_column" => 3, "end_column" => 19,
    "line_base64" => b64(line), "match_base64" => b64(match), "secret_base64" => b64(secret),
    "file_base64" => b64("src/secret.bin"), "symlink_file_base64" => b64("link.bin"),
    "commit_base64" => b64("abcdef1234567"), "link_base64" => b64("https://example.invalid/link"),
    "entropy_bits" => [entropy].pack("g").unpack1("L>"), "author_base64" => b64("Author"),
    "email_base64" => b64("a@example.invalid"), "date_base64" => b64("2025-01-02"),
    "message_base64" => b64("message"), "tags_base64" => tags.map { |tag| b64(tag) },
    "fingerprint_base64" => b64("fingerprint")
  }
end

def redact_request(id, percent, secret: "", match: nil, line: nil, input: nil, test_ids: [], behaviors: %w[RED-001 RED-002])
  {"protocol_version" => PROTOCOL_VERSION, "id" => id, "behavior_ids" => behaviors,
   "test_case_ids" => test_ids, "operation" => "redact", "redaction" => (input || finding_input(secret: secret, match: match, line: line)),
   "redact_percent" => percent}
end

def mask_request(id, percent, secret, test_id)
  {"protocol_version" => PROTOCOL_VERSION, "id" => id, "behavior_ids" => ["RED-001"],
   "test_case_ids" => [test_id], "operation" => "mask_secret",
   "redaction" => finding_input(secret: secret), "redact_percent" => percent}
end

def filter_request(id, inputs, redact: 0)
  {"protocol_version" => PROTOCOL_VERSION, "id" => id, "behavior_ids" => ["SUP-001"],
   "test_case_ids" => [], "operation" => "filter_probe", "filter_inputs" => inputs,
   "redact_percent" => redact}
end

def required(id, lines: :unset, columns: :unset)
  text = "[[rules.required]]\nid = #{id.to_json}\n"
  text += "withinLines = #{lines}\n" unless lines == :unset
  text += "withinColumns = #{columns}\n" unless columns == :unset
  text
end

def rule(id:, regex:, description: nil, required: [], skip: false, keywords: nil, secret_group: nil,
         entropy: nil, tags: nil, allowlist: nil, path: nil)
  text = "[[rules]]\nid = #{id.to_json}\ndescription = #{(description || id).to_json}\n"
  text += "regex = #{regex.to_json}\n" if regex
  text += "path = #{path.to_json}\n" if path
  text += "secretGroup = #{secret_group}\n" if secret_group
  text += "entropy = #{entropy}\n" if entropy
  text += "keywords = #{keywords.to_json}\n" if keywords
  text += "tags = #{tags.to_json}\n" if tags
  text += "skipReport = true\n" if skip
  required.each { |entry| text += entry }
  text += allowlist if allowlist
  text
end

def rule_allowlist(stopword: nil, regex: nil, target: nil, commit: nil, path: nil)
  text = "[[rules.allowlists]]\n"
  text += "stopwords = #{[stopword].to_json}\n" if stopword
  text += "regexTarget = #{target.to_json}\n" if target
  text += "regexes = #{[regex].to_json}\n" if regex
  text += "commits = #{[commit].to_json}\n" if commit
  text += "paths = #{[path].to_json}\n" if path
  text
end

def global_allowlist(stopword:, targets: nil)
  text = "[[allowlists]]\nstopwords = #{[stopword].to_json}\n"
  text += "targetRules = #{targets.to_json}\n" if targets
  text
end

def composite_config(required_specs: [required("aux")], primary_regex: 'PRIMARY=([A-Z]+)',
                     aux_regex: 'AUX=([a-z]+)', aux_skip: true, primary_id: "primary", aux_id: "aux",
                     aux_keywords: nil, aux_secret_group: nil, aux_entropy: nil, aux_tags: nil,
                     aux_allowlist: nil, suffix: "")
  rule(id: primary_id, regex: primary_regex, required: required_specs) +
    rule(id: aux_id, regex: aux_regex, skip: aux_skip, keywords: aux_keywords,
         secret_group: aux_secret_group, entropy: aux_entropy, tags: aux_tags, allowlist: aux_allowlist) + suffix
end

manifest_rows = MANIFEST.read.scan(/\[\[case\]\]\nid = "(TM-\d+)"\npackage = "([^"]+)"\ngo_name = "([^"]+)"\nsource = "([^"]+)"/)
manifest_by_name = manifest_rows.to_h { |id, package, name, source| ["#{package}:#{name}", [id, source]] }
expected_names = {
  "detect:TestDetect/fragment_level_composite" => "TM-0084",
  "report:TestMask" => "TM-0241", "report:TestMask/empty_secret" => "TM-0242",
  "report:TestMask/normal_secret" => "TM-0243", "report:TestMask/short_secret" => "TM-0244",
  "report:TestMaskSecret" => "TM-0245", "report:TestMaskSecret/high_masking" => "TM-0246",
  "report:TestMaskSecret/invalid_masking" => "TM-0247", "report:TestMaskSecret/low_masking" => "TM-0248",
  "report:TestMaskSecret/normal_masking" => "TM-0249", "report:TestRedact" => "TM-0250"
}
expected_names.each do |name, id|
  abort "manifest identity changed for #{name}" unless manifest_by_name.fetch(name).first == id
end

detect_source = UPSTREAM.join("detect/detect_test.go").binread
multili = detect_source[/var multili = `([^`]*)`/, 1]
abort "pinned multili source missing" unless multili == "\nusername = \"admin\"\n\n\n\n\t\t\tpassword = \"secret123\"\n"
fixture = UPSTREAM.join("testdata/config/composite.toml").binread
abort "composite fixture changed" unless sha(fixture) == "ee72a01e0dbcfea872a9cae97e87096340903e6c7fb115dcffe69a2f49595bdf"
detect_implementation = UPSTREAM.join("detect/detect.go").binread
abort "detect implementation identity changed" unless sha(detect_implementation) == "2bac563a09f22ff76c56b200c3b9b5dc865c1de699eb0ba2a27cca741fa9bd13"
detect_lines = detect_implementation.lines
entropy_source_line = detect_lines.index { |line| line.include?("entropy := shannonEntropy") }.to_i + 1
global_allow_source_line = detect_lines.index { |line| line.include?("checkFindingAllowed(logger, finding, fragment, currentLine, d.Config.Allowlists)") }.to_i + 1
rule_allow_source_line = detect_lines.index { |line| line.include?("checkFindingAllowed(logger, finding, fragment, currentLine, r.Allowlists)") }.to_i + 1
abort "capture/entropy/allowlist source order changed" unless [entropy_source_line, global_allow_source_line, rule_allow_source_line] == [543, 557, 563]
source_order_evidence = {"group" => 12, "classification" => "source-order-only",
                         "source" => "detect/detect.go", "source_sha256" => sha(detect_implementation),
                         "entropy_line" => entropy_source_line, "global_allowlist_line" => global_allow_source_line,
                         "rule_allowlist_line" => rule_allow_source_line}

requests = []
expect = {}
add = lambda do |request, count:, required_count: nil, error: nil|
  abort "duplicate request #{request['id']}" if expect.key?(request["id"])
  requests << request
  expect[request["id"]] = {count: count, required_count: required_count, error: error}
end

# Exact upstream detector leaf and complete private auxiliary projection.
add.call(detect_request("upstream-tm-0084-fragment-level-composite", %w[COMP-002 COMP-005], multili,
                        fixture: "composite.toml", test_ids: ["TM-0084"]), count: 1, required_count: 1)

base = composite_config
encoded_both = Base64.strict_encode64("AUX=one PRIMARY=VALUE")
encoded_primary = Base64.strict_encode64("PRIMARY=VALUE")
encoded_aux = Base64.strict_encode64("AUX=one")
add.call(detect_request("required-raw-raw", %w[COMP-001 COMP-005 COMP-006], "AUX=one PRIMARY=VALUE", config: base), count: 1, required_count: 1)
add.call(detect_request("required-absent", ["COMP-001"], "PRIMARY=VALUE", config: base), count: 0)
add.call(probe_request("required-runtime-missing-fail-closed", "PRIMARY=VALUE"), count: 0)
disabled_root = <<~TOML
  [extend]
  path = "../testdata/config/focused/required-disabled-base.toml"
  disabledRules = ["secondary"]
TOML
disabled_base = <<~TOML
  [[rules]]
  id = "primary"
  regex = "primary"
  [[rules.required]]
  id = "secondary"
  [[rules]]
  id = "secondary"
  regex = "secondary"
TOML
abort "extension root identity changed" unless sha(disabled_root) == "50cbe78501cf4585751b8364e6c462c65023c865bfb3e1e674325367366bc3a8"
disabled_files = {"testdata/config/focused/required-disabled-root.toml" => disabled_root,
                  "testdata/config/focused/required-disabled-base.toml" => disabled_base}
add.call(detect_request("required-extension-disabled-dependency-fail-closed", ["COMP-001"], "primary",
                        config_files: disabled_files, config_entry: "testdata/config/focused/required-disabled-root.toml",
                        config_workdir: "config"), count: 0)
valid_missing_root = "[extend]\npath = \"../testdata/config/focused/valid-missing-base.toml\"\ndisabledRules = [\"third\"]\n"
valid_missing_base = rule(id: "primary", regex: 'primary', required: [required("secondary"), required("third")]) +
                     rule(id: "secondary", regex: 'secondary', skip: true) + rule(id: "third", regex: 'third', skip: true)
valid_missing_files = {"testdata/config/focused/valid-missing-root.toml" => valid_missing_root,
                       "testdata/config/focused/valid-missing-base.toml" => valid_missing_base}
add.call(detect_request("required-extension-valid-plus-missing-fail-closed", ["COMP-001"], "primary secondary",
                        config_files: valid_missing_files, config_entry: "testdata/config/focused/valid-missing-root.toml",
                        config_workdir: "config"), count: 0)
missing = rule(id: "primary", regex: 'PRIMARY=([A-Z]+)', required: [required("missing")])
add.call(detect_request("required-config-missing-id", ["COMP-001"], "PRIMARY=VALUE", config: missing), count: 0, error: "config")
empty = rule(id: "primary", regex: 'PRIMARY=([A-Z]+)', required: [required("")])
add.call(detect_request("required-config-empty-id", ["COMP-001"], "PRIMARY=VALUE", config: empty), count: 0, error: "config")
duplicate_specs = composite_config(required_specs: [required("aux"), required("aux")], aux_regex: 'AUX=([a-z]+)')
add.call(detect_request("required-duplicate-specs", %w[COMP-001 COMP-005], "AUX=one AUX=two PRIMARY=VALUE", config: duplicate_specs), count: 1, required_count: 4)
duplicate_ids = rule(id: "primary", regex: 'NEVER', required: [required("aux")]) +
                rule(id: "primary", regex: 'PRIMARY=([A-Z]+)', required: [required("aux")]) +
                rule(id: "aux", regex: 'AUX=([a-z]+)', skip: true)
add.call(detect_request("required-duplicate-config-id-last-wins", ["COMP-001"], "AUX=one PRIMARY=VALUE", config: duplicate_ids), count: 1, required_count: 1)
duplicate_aux_last = rule(id: "primary", regex: 'PRIMARY=([A-Z]+)', required: [required("aux")]) +
                     rule(id: "aux", regex: 'NEVER', skip: true) + rule(id: "aux", regex: 'AUX=([a-z]+)', skip: true)
duplicate_aux_wrong_last = rule(id: "primary", regex: 'PRIMARY=([A-Z]+)', required: [required("aux")]) +
                           rule(id: "aux", regex: 'AUX=([a-z]+)', skip: true) + rule(id: "aux", regex: 'NEVER', skip: true)
add.call(detect_request("required-duplicate-aux-last-wins-positive", ["COMP-001"], "AUX=one PRIMARY=VALUE", config: duplicate_aux_last), count: 1, required_count: 1)
add.call(detect_request("required-duplicate-aux-last-wins-negative", ["COMP-001"], "AUX=one PRIMARY=VALUE", config: duplicate_aux_wrong_last), count: 0)
two_required_one_present = rule(id: "primary", regex: 'PRIMARY=([A-Z]+)', required: [required("aux-a"), required("aux-b")]) +
                           rule(id: "aux-a", regex: 'A=([a-z]+)', skip: true) + rule(id: "aux-b", regex: 'B=([a-z]+)', skip: true)
add.call(detect_request("required-two-ids-one-present", ["COMP-001"], "A=one PRIMARY=VALUE", config: two_required_one_present), count: 0)
self_config = rule(id: "self", regex: 'SELF=([A-Z]+)', required: [required("self")])
add.call(detect_request("required-self-cycle", %w[COMP-002 COMP-008], "SELF=VALUE", config: self_config), count: 1, required_count: 1)
cycle_config = rule(id: "a", regex: 'A=([A-Z]+)', required: [required("b")]) +
               rule(id: "b", regex: 'B=([A-Z]+)', required: [required("a")], skip: true)
add.call(detect_request("required-two-rule-cycle", %w[COMP-002 COMP-008], "A=ONE B=TWO", config: cycle_config), count: 1, required_count: 1)
nested_config = rule(id: "primary", regex: 'PRIMARY=([A-Z]+)', required: [required("aux")]) +
                rule(id: "aux", regex: 'AUX=([a-z]+)', required: [required("nested")], skip: true) +
                rule(id: "nested", regex: 'NESTED=([0-9]+)', skip: true)
add.call(detect_request("required-nested-ignored", ["COMP-002"], "AUX=one PRIMARY=VALUE", config: nested_config), count: 1, required_count: 1)
add.call(detect_request("required-inherited-primary-bypass", ["COMP-002"], "PRIMARY=VALUE", config: base, inherited: true), count: 1, required_count: 0)

# Auxiliary visibility and every observable scan gate.
add.call(detect_request("aux-skipreport-bypassed", ["COMP-002"], "AUX=one PRIMARY=VALUE", config: base), count: 1, required_count: 1)
non_skip = composite_config(aux_skip: false)
add.call(detect_request("aux-nonskip-top-level-visible", %w[COMP-002 COMP-008], "AUX=one PRIMARY=VALUE", config: non_skip), count: 2)
keyword = composite_config(aux_keywords: ["keyword-not-present"])
add.call(detect_request("aux-keyword-prefilter-bypassed", ["COMP-003"], "AUX=one PRIMARY=VALUE", config: keyword), count: 1, required_count: 1)
ordinary_keyword_rule = rule(id: "aux", regex: 'AUX=([a-z]+)', keywords: ["required-keyword"])
add.call(detect_request("aux-keyword-ordinary-top-level-rejected", ["COMP-003"], "AUX=one", config: ordinary_keyword_rule), count: 0)
add.call(detect_request("aux-keyword-ordinary-top-level-control", ["COMP-003"], "required-keyword AUX=one", config: ordinary_keyword_rule), count: 1)
marker_content = "AUX=one gitleaks:allow PRIMARY=VALUE"
add.call(detect_request("aux-marker-reject", ["COMP-003"], marker_content, config: base), count: 0)
add.call(detect_request("aux-marker-ignore-option", ["COMP-003"], marker_content, config: base, ignore_marker: true), count: 1, required_count: 1)
capture = composite_config(aux_regex: 'AUX=prefix-([A-Z0-9]+)', aux_secret_group: 1, aux_tags: ["aux-tag"])
add.call(detect_request("aux-capture-tags", ["COMP-003"], "AUX=prefix-A1B2 PRIMARY=VALUE", config: capture), count: 1, required_count: 1)
entropy_reject = composite_config(aux_regex: 'AUX=([a-z]+)', aux_entropy: 3.0)
add.call(detect_request("aux-entropy-reject", ["COMP-003"], "AUX=aaaa PRIMARY=VALUE", config: entropy_reject), count: 0)
entropy_pass = composite_config(aux_regex: 'AUX=([A-Za-z0-9]+)', aux_entropy: 1.9)
add.call(detect_request("aux-entropy-pass", ["COMP-003"], "AUX=a1B2 PRIMARY=VALUE", config: entropy_pass), count: 1, required_count: 1)
entropy_equal = composite_config(aux_regex: 'AUX=([A-Za-z0-9]+)', aux_entropy: 2.0)
entropy_above = composite_config(aux_regex: 'AUX=([A-Za-z0-9]+)', aux_entropy: 2.1)
add.call(detect_request("aux-entropy-equal-reject", ["COMP-003"], "AUX=a1B2 PRIMARY=VALUE", config: entropy_equal), count: 0)
add.call(detect_request("aux-entropy-above-reject", ["COMP-003"], "AUX=a1B2 PRIMARY=VALUE", config: entropy_above), count: 0)
entropy_visible = composite_config(aux_regex: 'AUX=([A-Za-z0-9]+)', aux_entropy: 1.9, aux_skip: false)
add.call(detect_request("aux-entropy-below-visible", ["COMP-003"], "AUX=a1B2 PRIMARY=VALUE", config: entropy_visible), count: 2)
allow_stop = composite_config(aux_allowlist: rule_allowlist(stopword: "one"))
add.call(detect_request("aux-rule-allowlist-reject", ["COMP-003"], "AUX=one PRIMARY=VALUE", config: allow_stop), count: 0)
global_stop = composite_config(suffix: global_allowlist(stopword: "one", targets: ["aux"]))
add.call(detect_request("aux-global-allowlist-reject", ["COMP-003"], "AUX=one PRIMARY=VALUE", config: global_stop), count: 0)
commit_gate = composite_config(aux_allowlist: rule_allowlist(commit: "abcdef1234567"))
add.call(detect_request("aux-commit-early-reject", %w[COMP-003 COMP-007], "AUX=one PRIMARY=VALUE", config: commit_gate, commit: "abcdef1234567"), count: 0)
path_gate = composite_config(aux_allowlist: rule_allowlist(path: 'blocked\\.go'))
add.call(detect_request("aux-path-early-reject", %w[COMP-003 COMP-007], "AUX=one PRIMARY=VALUE", config: path_gate, file: "blocked.go"), count: 0)
primary_keyword = rule(id: "primary", regex: 'PRIMARY=([A-Z]+)', required: [required("aux")], keywords: ["primary"]) + rule(id: "aux", regex: 'AUX=([a-z]+)', skip: true)
add.call(detect_request("primary-keyword-raw", %w[COMP-003 COMP-007], "AUX=one PRIMARY=VALUE", config: primary_keyword), count: 1, required_count: 1)
primary_keyword_absent = rule(id: "primary", regex: 'PRIMARY=([A-Z]+)', required: [required("aux")], keywords: ["withheld-keyword"]) + rule(id: "aux", regex: 'AUX=([a-z]+)', skip: true)
add.call(detect_request("primary-keyword-absent", %w[COMP-003 COMP-007], "AUX=one PRIMARY=VALUE", config: primary_keyword_absent), count: 0)
unicode_keyword = rule(id: "primary", regex: 'SECRÉT=([A-Z]+)', required: [required("aux")], keywords: ["secrét"]) + rule(id: "aux", regex: 'AUX=([a-z]+)', skip: true)
add.call(detect_request("primary-keyword-unicode-case", ["COMP-003"], "AUX=one SECRÉT=VALUE", config: unicode_keyword), count: 1, required_count: 1)
add.call(detect_request("primary-keyword-decoded", %w[COMP-003 COMP-006], Base64.strict_encode64("AUX=one PRIMARY=VALUE"), config: primary_keyword, depth: 1), count: 1, required_count: 1)
global_early = composite_config(suffix: "[[allowlists]]\ncommits = [\"blockedcommit\"]\n")
add.call(detect_request("global-early-all-passes", ["COMP-007"], Base64.strict_encode64("AUX=one PRIMARY=VALUE"), config: global_early, depth: 2, commit: "blockedcommit"), count: 0)
global_finding = composite_config(suffix: global_allowlist(stopword: "one"))
global_target_other = composite_config(suffix: rule(id: "other-rule", regex: 'NEVER') + global_allowlist(stopword: "one", targets: ["other-rule"]))
add.call(detect_request("aux-global-finding-untargeted-reject", %w[COMP-003 COMP-007], "AUX=one PRIMARY=VALUE", config: global_finding), count: 0)
add.call(detect_request("aux-global-finding-targeted-control", %w[COMP-003 COMP-007], "AUX=one PRIMARY=VALUE", config: global_target_other), count: 1, required_count: 1)
%w[secret match line].each do |target|
  allow = rule_allowlist(regex: target == "secret" ? '^one$' : 'AUX=one', target: target)
  cfg = composite_config(aux_allowlist: allow)
  add.call(detect_request("aux-allow-target-#{target}-raw", ["COMP-003"], "AUX=one PRIMARY=VALUE", config: cfg), count: 0)
end
decoded_line_allow = composite_config(aux_allowlist: rule_allowlist(regex: 'AUX=one PRIMARY=VALUE', target: "line"))
add.call(detect_request("aux-allow-target-line-decoded", %w[COMP-003 COMP-006], encoded_both, config: decoded_line_allow, depth: 1), count: 0)
nested_line_allow = composite_config(aux_allowlist: rule_allowlist(regex: '^AUX=one PRIMARY=VALUE$', target: "line"))
nested_line_control = composite_config(aux_allowlist: rule_allowlist(regex: '^wrong$', target: "line"))
add.call(detect_request("aux-allow-target-line-nested-decoded", %w[COMP-003 COMP-006], Base64.strict_encode64(encoded_both), config: nested_line_allow, depth: 2), count: 0)
add.call(detect_request("aux-line-nested-original-line-control", %w[COMP-003 COMP-006], Base64.strict_encode64(encoded_both), config: nested_line_control, depth: 2), count: 1, required_count: 1)
multi_segment_line = "#{Base64.strict_encode64('AUXILIARY-5678')} #{Base64.strict_encode64('PRIMARY-1234')}"
multi_line_allow = composite_config(primary_regex: 'PRIMARY-1234', aux_regex: 'AUXILIARY-5678', aux_allowlist: rule_allowlist(regex: '^AUXILIARY-5678 PRIMARY-1234$', target: "line"))
multi_line_control = composite_config(primary_regex: 'PRIMARY-1234', aux_regex: 'AUXILIARY-5678', aux_allowlist: rule_allowlist(regex: '^wrong$', target: "line"))
add.call(detect_request("aux-allow-target-line-multisegment", %w[COMP-003 COMP-006], multi_segment_line, config: multi_line_allow, depth: 1), count: 0)
add.call(detect_request("aux-line-multisegment-original-line-control", %w[COMP-003 COMP-006], multi_segment_line, config: multi_line_control, depth: 1), count: 1, required_count: 1)
capture_match_allow = composite_config(aux_regex: 'AUX=prefix-([A-Z0-9]+)', aux_secret_group: 1,
                                       aux_allowlist: rule_allowlist(regex: '^AUX=prefix-A1B2$', target: "match"))
capture_secret_control = composite_config(aux_regex: 'AUX=prefix-([A-Z0-9]+)', aux_secret_group: 1,
                                          aux_allowlist: rule_allowlist(regex: '^AUX=prefix-A1B2$', target: "secret"))
add.call(detect_request("aux-capture-match-allowlist-reject", ["COMP-003"], "AUX=prefix-A1B2 PRIMARY=VALUE", config: capture_match_allow), count: 0)
add.call(detect_request("aux-capture-secret-target-control", ["COMP-003"], "AUX=prefix-A1B2 PRIMARY=VALUE", config: capture_secret_control), count: 1, required_count: 1)
combined_stage_control = composite_config(aux_regex: 'AUX=prefix-([A-Z0-9]+)', aux_secret_group: 1,
                                          aux_entropy: 1.9, aux_skip: false,
                                          aux_allowlist: rule_allowlist(regex: '^NEVER$', target: "secret"))
combined_stage_allow_reject = composite_config(aux_regex: 'AUX=prefix-([A-Z0-9]+)', aux_secret_group: 1,
                                               aux_entropy: 1.9, aux_skip: false,
                                               aux_allowlist: rule_allowlist(regex: '^A1B2$', target: "secret"))
combined_stage_entropy_reject = composite_config(aux_regex: 'AUX=prefix-([A-Z0-9]+)', aux_secret_group: 1,
                                                 aux_entropy: 2.0, aux_skip: false,
                                                 aux_allowlist: rule_allowlist(regex: '^NEVER$', target: "secret"))
add.call(detect_request("aux-capture-entropy-allowlist-control", ["COMP-003"], "AUX=prefix-A1B2 PRIMARY=VALUE", config: combined_stage_control), count: 2)
add.call(detect_request("aux-capture-entropy-allowlist-reject", ["COMP-003"], "AUX=prefix-A1B2 PRIMARY=VALUE", config: combined_stage_allow_reject), count: 0)
add.call(detect_request("aux-capture-entropy-before-allowlist-source-boundary", ["COMP-003"], "AUX=prefix-A1B2 PRIMARY=VALUE", config: combined_stage_entropy_reject), count: 0)
primary_marker = "AUX=one PRIMARY=VALUE gitleaks:allow"
add.call(detect_request("primary-marker-original-line", ["COMP-003"], primary_marker, config: base), count: 0)
add.call(detect_request("primary-marker-isolated-line", ["COMP-003"], "AUX=one\nPRIMARY=VALUE gitleaks:allow", config: base), count: 0)
add.call(detect_request("aux-marker-isolated-line", ["COMP-003"], "AUX=one gitleaks:allow\nPRIMARY=VALUE", config: base), count: 0)
decoded_marker = Base64.strict_encode64("AUX=one PRIMARY=VALUE gitleaks:allow")
add.call(detect_request("marker-decoded-only-does-not-suppress", %w[COMP-003 COMP-006], decoded_marker, config: base, depth: 1), count: 1, required_count: 1)
mapped_neighbor_marker = "#{decoded_marker} gitleaks:allow"
abort "mapped marker neighbor identity changed" unless sha(mapped_neighbor_marker) == "9f994cd8f5fa43faca2427bea8a0e0cf85b5e2fa0bcbeec2cfdaf2fcf08fc8d0"
add.call(detect_request("marker-neighbor-outside-encoded-token", %w[COMP-003 COMP-006], mapped_neighbor_marker, config: base, depth: 1), count: 0)
path_only = rule(id: "primary", regex: 'PRIMARY=([A-Z]+)', required: [required("aux")]) + rule(id: "aux", regex: nil, path: 'tmp\\.go', skip: true)
add.call(detect_request("aux-path-only-raw", ["COMP-003"], "PRIMARY=VALUE", config: path_only), count: 1, required_count: 1)
add.call(detect_request("aux-path-only-decoded-negative", %w[COMP-003 COMP-006], encoded_primary, config: path_only, depth: 1), count: 0)
path_regex = rule(id: "primary", regex: 'PRIMARY=([A-Z]+)', required: [required("aux")]) +
             rule(id: "aux", regex: 'AUX=([a-z]+)', path: 'tmp\\.go', skip: true)
add.call(detect_request("aux-path-regex-positive", ["COMP-003"], "AUX=one PRIMARY=VALUE", config: path_regex, file: "tmp.go"), count: 1, required_count: 1)
add.call(detect_request("aux-path-regex-negative", ["COMP-003"], "AUX=one PRIMARY=VALUE", config: path_regex, file: "other.go"), count: 0)

# Same-pass decoding and mapped coordinates.
abort "encoded same-pass candidate fails likelihood" unless encoded_both.match?(/[0-9+\/=\-_]/)
add.call(detect_request("pass-both-encoded-same", ["COMP-006"], encoded_both, config: base, depth: 1), count: 1, required_count: 1)
abort "encoded candidates fail likelihood" unless [encoded_primary, encoded_aux].all? { |value| value.match?(/[0-9+\/=\-_]/) }
add.call(detect_request("pass-primary-encoded-aux-raw", ["COMP-006"], "AUX=one #{encoded_primary}", config: base, depth: 1), count: 0)
add.call(detect_request("pass-primary-raw-aux-encoded", ["COMP-006"], "PRIMARY=VALUE #{encoded_aux}", config: base, depth: 1), count: 0)
nested = Base64.strict_encode64(encoded_both)
add.call(detect_request("pass-both-nested-same-depth", ["COMP-006"], nested, config: base, depth: 2), count: 1, required_count: 1)
nested_primary = Base64.strict_encode64(encoded_primary)
add.call(detect_request("pass-different-decoded-depth", ["COMP-006"], "#{encoded_aux} #{nested_primary}", config: base, depth: 2), count: 0)
separate_line_encoded = "#{Base64.strict_encode64('PRIMARY-1234')}\n#{Base64.strict_encode64('AUXILIARY-5678')}"
primary_wrong_line = rule(id: "primary", regex: 'PRIMARY-1234', required: [required("aux")],
                          allowlist: rule_allowlist(regex: '^NEVER$', target: "line")) +
                     rule(id: "aux", regex: 'AUXILIARY-5678', skip: true)
primary_own_line = rule(id: "primary", regex: 'PRIMARY-1234', required: [required("aux")],
                        allowlist: rule_allowlist(regex: '.*', target: "line")) +
                   rule(id: "aux", regex: 'AUXILIARY-5678', skip: true)
aux_wrong_line = rule(id: "primary", regex: 'PRIMARY-1234', required: [required("aux")]) +
                 rule(id: "aux", regex: 'AUXILIARY-5678', skip: true,
                      allowlist: rule_allowlist(regex: '^NEVER$', target: "line"))
aux_own_line = rule(id: "primary", regex: 'PRIMARY-1234', required: [required("aux")]) +
               rule(id: "aux", regex: 'AUXILIARY-5678', skip: true,
                    allowlist: rule_allowlist(regex: '.*', target: "line"))
add.call(detect_request("decoded-line-primary-wrong-line-control", %w[COMP-003 COMP-006], separate_line_encoded, config: primary_wrong_line, depth: 1), count: 1, required_count: 1)
add.call(detect_request("decoded-line-primary-own-line-reject", %w[COMP-003 COMP-006], separate_line_encoded, config: primary_own_line, depth: 1), count: 0)
add.call(detect_request("decoded-line-aux-wrong-line-control", %w[COMP-003 COMP-006], separate_line_encoded, config: aux_wrong_line, depth: 1), count: 1, required_count: 1)
add.call(detect_request("decoded-line-aux-own-line-reject", %w[COMP-003 COMP-006], separate_line_encoded, config: aux_own_line, depth: 1), count: 0)
mapped = "#{Base64.strict_encode64('PRIMARY-1234')} #{Base64.strict_encode64('AUXILIARY-5678')}"
mapped_out = composite_config(required_specs: [required("aux", columns: 1)], primary_regex: 'PRIMARY-1234', aux_regex: 'AUXILIARY-5678')
mapped_in = composite_config(required_specs: [required("aux", columns: 100)], primary_regex: 'PRIMARY-1234', aux_regex: 'AUXILIARY-5678')
add.call(detect_request("proximity-mapped-outside", %w[COMP-004 COMP-006], mapped, config: mapped_out, depth: 1), count: 0)
add.call(detect_request("proximity-mapped-inside", %w[COMP-004 COMP-006], mapped, config: mapped_in, depth: 1), count: 1, required_count: 1)
mapped_exact = composite_config(required_specs: [required("aux", columns: 17)], primary_regex: 'PRIMARY-1234', aux_regex: 'AUXILIARY-5678')
mapped_just_out = composite_config(required_specs: [required("aux", columns: 16)], primary_regex: 'PRIMARY-1234', aux_regex: 'AUXILIARY-5678')
add.call(detect_request("proximity-mapped-column-exact", %w[COMP-004 COMP-006], mapped, config: mapped_exact, depth: 1), count: 1, required_count: 1)
add.call(detect_request("proximity-mapped-column-just-outside", %w[COMP-004 COMP-006], mapped, config: mapped_just_out, depth: 1), count: 0)
mapped_lines = "#{Base64.strict_encode64('PRIMARY-1234')}\n#{Base64.strict_encode64('AUXILIARY-5678')}"
mapped_line_exact = composite_config(required_specs: [required("aux", lines: 1)], primary_regex: 'PRIMARY-1234', aux_regex: 'AUXILIARY-5678')
mapped_line_out = composite_config(required_specs: [required("aux", lines: 0)], primary_regex: 'PRIMARY-1234', aux_regex: 'AUXILIARY-5678')
add.call(detect_request("proximity-mapped-line-exact", %w[COMP-004 COMP-006], mapped_lines, config: mapped_line_exact, depth: 1), count: 1, required_count: 1)
add.call(detect_request("proximity-mapped-line-outside", %w[COMP-004 COMP-006], mapped_lines, config: mapped_line_out, depth: 1), count: 0)
mapped_reverse = "#{Base64.strict_encode64('AUXILIARY-5678')} #{Base64.strict_encode64('PRIMARY-1234')}"
add.call(detect_request("proximity-mapped-reverse-shift", %w[COMP-004 COMP-006], mapped_reverse, config: mapped_in, depth: 1), count: 1, required_count: 1)
raw_and_decoded = "AUX=one PRIMARY=VALUE #{encoded_both}"
add.call(detect_request("pass-raw-and-decoded-composite-duplicates", %w[COMP-006 COMP-008], raw_and_decoded, config: base, depth: 1), count: 2, required_count: 1)

# Line/column proximity uses absolute start geometry and inclusive signed bounds.
line_content = "AUX=one\nmid\nPRIMARY=VALUE"
[["line-boundary", 2, 1], ["line-outside", 1, 0], ["line-zero", 0, 0], ["line-negative", -1, 0]].each do |name, bound, count|
  cfg = composite_config(required_specs: [required("aux", lines: bound)])
  add.call(detect_request("proximity-#{name}", ["COMP-004"], line_content, config: cfg, start_line: 11), count: count, required_count: count == 1 ? 1 : nil)
end
line_loose = composite_config(required_specs: [required("aux", lines: 3)])
add.call(detect_request("proximity-line-distance-plus-one", ["COMP-004"], line_content, config: line_loose), count: 1, required_count: 1)
reverse_line = "PRIMARY=VALUE\nmid\nAUX=one"
cfg_line = composite_config(required_specs: [required("aux", lines: 2)])
add.call(detect_request("proximity-line-reverse", ["COMP-004"], reverse_line, config: cfg_line), count: 1, required_count: 1)
column_content = "AUX=one.....PRIMARY=VALUE"
[["column-boundary", 12, 1], ["column-outside", 11, 0], ["column-zero", 0, 0], ["column-negative", -1, 0]].each do |name, bound, count|
  cfg = composite_config(required_specs: [required("aux", columns: bound)])
  add.call(detect_request("proximity-#{name}", ["COMP-004"], column_content, config: cfg), count: count, required_count: count == 1 ? 1 : nil)
end
column_loose = composite_config(required_specs: [required("aux", columns: 13)])
add.call(detect_request("proximity-column-distance-plus-one", ["COMP-004"], column_content, config: column_loose), count: 1, required_count: 1)
zero_equal_config = composite_config(required_specs: [required("aux", columns: 0)], primary_regex: 'TOKEN=([A-Z]+)', aux_regex: 'TOKEN=([A-Z]+)')
add.call(detect_request("proximity-zero-equal-start", ["COMP-004"], "TOKEN=VALUE", config: zero_equal_config), count: 1, required_count: 1)
both_content = "AUX=one\nmid\n............PRIMARY=VALUE"
both_fail = composite_config(required_specs: [required("aux", lines: 2, columns: 11)])
both_pass = composite_config(required_specs: [required("aux", lines: 2, columns: 100)])
add.call(detect_request("proximity-both-conjunctive-fail", ["COMP-004"], both_content, config: both_fail), count: 0)
add.call(detect_request("proximity-both-conjunctive-pass", ["COMP-004"], both_content, config: both_pass), count: 1, required_count: 1)
max_bound = (2**63) - 1
min_bound = -(2**63)
add.call(detect_request("proximity-max-signed", %w[COMP-004 COMP-008], line_content, config: composite_config(required_specs: [required("aux", lines: max_bound)])), count: 1, required_count: 1)
add.call(detect_request("proximity-min-signed", %w[COMP-004 COMP-008], line_content, config: composite_config(required_specs: [required("aux", lines: min_bound)])), count: 0)
add.call(detect_request("proximity-negative-fragment-start", ["COMP-004"], line_content, config: cfg_line, start_line: -20), count: 1, required_count: 1)
capture_geometry = composite_config(required_specs: [required("aux", columns: 12)], primary_regex: 'PRIMARY=prefix-([A-Z]+)', aux_regex: 'AUX=([a-z]+)')
add.call(detect_request("proximity-match-start-not-capture", ["COMP-004"], "AUX=one.....PRIMARY=prefix-VALUE", config: capture_geometry), count: 1, required_count: 1)
same_start_end_geometry = composite_config(required_specs: [required("aux", columns: 0)], primary_regex: 'TOKEN=([A-Z]+)-TAIL', aux_regex: 'TOKEN=([A-Z]+)')
add.call(detect_request("proximity-same-start-different-ends", ["COMP-004"], "TOKEN=VALUE-TAIL", config: same_start_end_geometry), count: 1, required_count: 1)
overlap_geometry_out = composite_config(required_specs: [required("aux", columns: 3)], primary_regex: 'BEGIN-OVERLAP-END', aux_regex: 'N-OVERLAP')
overlap_geometry_in = composite_config(required_specs: [required("aux", columns: 4)], primary_regex: 'BEGIN-OVERLAP-END', aux_regex: 'N-OVERLAP')
add.call(detect_request("proximity-overlapping-spans-start-outside", ["COMP-004"], "BEGIN-OVERLAP-END", config: overlap_geometry_out), count: 0)
add.call(detect_request("proximity-overlapping-spans-start-exact", ["COMP-004"], "BEGIN-OVERLAP-END", config: overlap_geometry_in), count: 1, required_count: 1)

# Projection ordering and multiplicity.
multi_aux = composite_config(aux_regex: 'AUX=([a-z]+)')
add.call(detect_request("projection-aux-regex-order", ["COMP-005"], "AUX=one AUX=two PRIMARY=VALUE", config: multi_aux), count: 1, required_count: 2)
two_required = rule(id: "primary", regex: 'PRIMARY=([A-Z]+)', required: [required("aux-b"), required("aux-a")]) +
               rule(id: "aux-a", regex: 'A=([a-z]+)', skip: true) + rule(id: "aux-b", regex: 'B=([a-z]+)', skip: true)
add.call(detect_request("projection-required-spec-order", ["COMP-005"], "A=one B=two PRIMARY=VALUE", config: two_required), count: 1, required_count: 2)
add.call(detect_request("projection-primary-multiplicity", %w[COMP-005 COMP-008], "AUX=one PRIMARY=ONE PRIMARY=TWO", config: base), count: 2, required_count: 1)
small_matrix = "AUX=one AUX=two PRIMARY=ONE PRIMARY=TWO"
add.call(detect_request("projection-primary-aux-cartesian-2x2", ["COMP-005"], small_matrix, config: base), count: 2, required_count: 2)
duplicate_matrix_config = composite_config(required_specs: [required("aux"), required("aux")])
add.call(detect_request("projection-duplicate-pass-and-requirements", %w[COMP-005 COMP-006 COMP-008], "AUX=one PRIMARY=VALUE #{encoded_both}", config: duplicate_matrix_config, depth: 1), count: 2, required_count: 2)
metadata_visible = composite_config(aux_skip: false, aux_tags: ["aux-metadata"])
add.call(detect_request("projection-decoded-aux-metadata-visible", %w[COMP-005 COMP-006], encoded_both, config: metadata_visible, depth: 1), count: 2)
arbitrary = "AUX=".b + [0xff, 0xfe].pack("C*") + " PRIMARY=VALUE".b
arbitrary_cfg = composite_config(aux_regex: 'AUX=(..)')
add.call(detect_request("projection-arbitrary-bytes", ["COMP-008"], arbitrary, config: arbitrary_cfg), count: 1, required_count: 1)
malformed_cfg = composite_config(aux_regex: 'AUX=(one)')
{"before" => "\xFFAUX=one PRIMARY=VALUE".b, "inside" => "AUX=one \xFF PRIMARY=VALUE".b,
 "after" => "AUX=one PRIMARY=VALUE\xFF".b}.each do |position, content|
  add.call(detect_request("malformed-composite-#{position}", ["COMP-008"], content, config: malformed_cfg), count: 1, required_count: 1)
end
invalid_keyword_cfg = rule(id: "primary", regex: 'PRIMARY=([A-Z]+)', required: [required("aux")], keywords: ["primary"]) + rule(id: "aux", regex: 'AUX=([a-z]+)', skip: true)
add.call(detect_request("malformed-adjacent-keyword", ["COMP-008"], "\xFFPRIMARY=VALUE AUX=one".b, config: invalid_keyword_cfg), count: 1, required_count: 1)
unicode_invalid_keyword_cfg = rule(id: "primary", regex: 'SECRÉT=([A-Z]+)', required: [required("aux")], keywords: ["secrét"]) + rule(id: "aux", regex: 'AUX=([a-z]+)', skip: true)
add.call(detect_request("malformed-adjacent-unicode-keyword", ["COMP-008"], "\xFFSECRÉT=VALUE AUX=one".b, config: unicode_invalid_keyword_cfg), count: 1, required_count: 1)
malformed_inside_config = composite_config(primary_regex: 'PRIMARY=(.VALUE)', aux_regex: 'AUX=(.one)')
malformed_inside_content = "\xFFAUX=\xFEone middle PRIMARY=\x80VALUE\xFF".b
add.call(detect_request("malformed-primary-aux-inside-secrets", ["COMP-008"], malformed_inside_content, config: malformed_inside_config), count: 1, required_count: 1)

# Generic suppression predicate and interactions.
def generic_config(generic_id: "generic", specific_id: "specific", generic_regex: 'TOKEN=([A-Z]+)', specific_regex: 'TOKEN=([A-Z]+)')
  rule(id: generic_id, regex: generic_regex) + rule(id: specific_id, regex: specific_regex)
end
add.call(detect_request("generic-shadow-contained", %w[SUP-001 COMP-007], "TOKEN=VALUE", config: generic_config), count: 1)
add.call(detect_request("generic-alone-retained", ["SUP-001"], "TOKEN=VALUE", config: rule(id: "generic-alone", regex: 'TOKEN=([A-Z]+)')), count: 1)
add.call(detect_request("generic-case-insensitive-substring", ["SUP-001"], "TOKEN=VALUE", config: generic_config(generic_id: "preGeNeRiCpost")), count: 1)
add.call(detect_request("generic-both-generic-survive", ["SUP-001"], "TOKEN=VALUE", config: generic_config(specific_id: "also-generic")), count: 2)
noncontained = generic_config(generic_regex: 'TOKEN=(VAL)', specific_regex: 'TOKEN=VAL(UE)')
add.call(detect_request("generic-noncontained-survives", ["SUP-001"], "TOKEN=VALUE", config: noncontained), count: 2)
different_lines = generic_config(generic_regex: 'GEN=([A-Z]+)', specific_regex: 'SPEC=([A-Z]+)')
add.call(detect_request("generic-different-lines-survive", ["SUP-001"], "GEN=VALUE\nSPEC=VALUE", config: different_lines), count: 2)
reversed = generic_config(generic_regex: 'TOKEN=([A-Z]+)', specific_regex: 'TOKEN=(VAL)')
add.call(detect_request("generic-reversed-containment-survives", ["SUP-001"], "TOKEN=VALUE", config: reversed), count: 2)
case_diff = generic_config(generic_regex: 'TOKEN=(VALUE)', specific_regex: 'TOKEN=(value)')
add.call(detect_request("generic-case-different-survives", ["SUP-001"], "TOKEN=VALUE TOKEN=value", config: case_diff), count: 2)
add.call(detect_request("generic-same-line-different-file-ignored", ["SUP-001"], "TOKEN=VALUE", config: generic_config, file: "one.go", commit: "samecommit"), count: 1)
filter_generic = finding_input(secret: "GEN", match: "g=GEN", line: "generic line", rule_id: "generic-adapter").merge(
  "start_line" => 9, "end_line" => 50, "start_column" => 1, "end_column" => 3,
  "file_base64" => b64("generic.go"), "commit_base64" => b64("same"))
filter_specific = finding_input(secret: "XGENX", match: "s=XGENX", line: "specific line", rule_id: "specific-adapter").merge(
  "start_line" => 9, "end_line" => 9, "start_column" => 99, "end_column" => 120,
  "file_base64" => b64("specific.go"), "commit_base64" => b64("same"))
add.call(filter_request("generic-filter-adapter-ignores-file-column-end", [filter_generic, filter_specific]), count: 1)
different_commit_specific = filter_specific.merge("commit_base64" => b64("different"))
add.call(filter_request("generic-filter-adapter-different-commit", [filter_generic, different_commit_specific]), count: 2)
same_rule_specific = filter_specific.merge("rule_id" => "generic-adapter")
add.call(filter_request("generic-filter-adapter-same-rule-id", [filter_generic, same_rule_specific]), count: 2)
duplicate_required_vector = [
  {"rule_id" => "required-duplicate", "start_line" => 4, "end_line" => 4, "start_column" => 2, "end_column" => 8,
   "line_base64" => b64("required line"), "match_base64" => b64("required match"), "secret_base64" => b64("required secret")},
  {"rule_id" => "required-duplicate", "start_line" => 4, "end_line" => 4, "start_column" => 2, "end_column" => 8,
   "line_base64" => b64("required line"), "match_base64" => b64("required match"), "secret_base64" => b64("required secret")}
]
duplicate_primary = finding_input(secret: "primary-secret", match: "primary-match", line: "primary line",
                                  rule_id: "specific-duplicate-primary").merge("required_findings" => duplicate_required_vector)
add.call(filter_request("filter-exact-duplicate-primaries-required", [duplicate_primary, Marshal.load(Marshal.dump(duplicate_primary))]), count: 2)
empty_generic = rule(id: "generic", regex: 'TOKEN=()', secret_group: 1) + rule(id: "specific", regex: 'TOKEN=([A-Z]+)')
add.call(detect_request("generic-empty-secret-suppressed", %w[SUP-001 RED-003], "TOKEN=VALUE", config: empty_generic, redact: 100), count: 1)
empty_generic_alone = rule(id: "generic-empty", regex: 'TOKEN=()', secret_group: 1)
add.call(detect_request("generic-empty-secret-alone-retained", ["SUP-001"], "TOKEN=VALUE", config: empty_generic_alone), count: 1)
add.call(detect_request("generic-suppression-before-redaction", %w[SUP-001 RED-003], "TOKEN=VALUE", config: generic_config, redact: 50), count: 1)
terminal_generic = generic_config(generic_regex: 'TOKEN=(abc)', specific_regex: 'TOKEN=(XabcY)')
add.call(detect_request("generic-terminal-redaction-discriminator", %w[SUP-001 RED-003], "TOKEN=abc TOKEN=XabcY", config: terminal_generic, redact: 50), count: 1)
order_bookend_start = finding_input(secret: "start", match: "bookend-start", line: "bookend start", rule_id: "bookend-start").merge(
  "start_line" => 1, "end_line" => 1, "commit_base64" => b64("bookend"))
order_generic = finding_input(secret: "abc", match: "generic duplicate", line: "shared", rule_id: "generic-duplicate").merge(
  "start_line" => 9, "end_line" => 9, "commit_base64" => b64("same"))
order_specific = finding_input(secret: "XabcY", match: "specific duplicate", line: "shared", rule_id: "specific-duplicate").merge(
  "start_line" => 9, "end_line" => 9, "commit_base64" => b64("same"))
order_bookend_end = finding_input(secret: "end", match: "bookend-end", line: "bookend end", rule_id: "bookend-end").merge(
  "start_line" => 20, "end_line" => 20, "commit_base64" => b64("bookend"))
order_inputs = [order_bookend_start, order_generic, Marshal.load(Marshal.dump(order_generic)),
                order_specific, Marshal.load(Marshal.dump(order_specific)), order_bookend_end]
add.call(filter_request("generic-filter-duplicate-order", order_inputs), count: 4)
raw_generic_decoded_specific = rule(id: "generic-raw", regex: 'GEN=(abc)') + rule(id: "specific-decoded", regex: 'SPECIFIC-(XabcY)-1234')
add.call(detect_request("generic-raw-shadowed-decoded-specific", ["SUP-001"], "GEN=abc #{Base64.strict_encode64('SPECIFIC-XabcY-1234')}", config: raw_generic_decoded_specific, depth: 1), count: 1)
decoded_generic_composite = rule(id: "generic-decoded", regex: 'GENERIC-(abc)-1234') +
                            rule(id: "specific-composite", regex: 'SPEC=(XabcY)', required: [required("aux")]) +
                            rule(id: "aux", regex: 'AUX=([a-z]+)', skip: true)
add.call(detect_request("generic-decoded-shadowed-composite-specific", %w[SUP-001 COMP-005], "SPEC=XabcY AUX=one #{Base64.strict_encode64('GENERIC-abc-1234')}", config: decoded_generic_composite, depth: 1), count: 1, required_count: 1)
attachment_only = rule(id: "generic", regex: 'GEN=(abc)') +
                  rule(id: "primary", regex: 'PRIMARY=(VALUE)', required: [required("aux")]) +
                  rule(id: "aux", regex: 'AUX=(XabcY)', skip: true)
attachment_visible = rule(id: "generic", regex: 'GEN=(abc)') +
                     rule(id: "primary", regex: 'PRIMARY=(VALUE)', required: [required("aux")]) +
                     rule(id: "aux", regex: 'AUX=(XabcY)')
add.call(detect_request("generic-attachment-alone-cannot-suppress", %w[SUP-001 COMP-005], "GEN=abc AUX=XabcY PRIMARY=VALUE", config: attachment_only), count: 2)
add.call(detect_request("generic-visible-aux-can-suppress", %w[SUP-001 COMP-005], "GEN=abc AUX=XabcY PRIMARY=VALUE", config: attachment_visible), count: 2)

# Exact upstream redaction leaves. Private maskSecret leaves are evaluated by
# an overlay test compiled into the pinned upstream package below.
add.call(redact_request("upstream-tm-0242-empty-secret", 75, secret: "", match: "line containing", test_ids: ["TM-0242"]), count: 0)
add.call(redact_request("upstream-tm-0243-normal-secret", 75, secret: "secret", match: "line containing secret", test_ids: ["TM-0243"]), count: 0)
add.call(redact_request("upstream-tm-0244-short-secret", 75, secret: "ss", match: "line containing", test_ids: ["TM-0244"]), count: 0)
add.call(mask_request("upstream-tm-0246-high-masking", 90, "secret", "TM-0246"), count: 0)
add.call(mask_request("upstream-tm-0247-invalid-masking", 1000, "secret", "TM-0247"), count: 0)
add.call(mask_request("upstream-tm-0248-low-masking", 10, "secret", "TM-0248"), count: 0)
add.call(mask_request("upstream-tm-0249-normal-masking", 75, "secret", "TM-0249"), count: 0)
add.call(redact_request("upstream-tm-0250-redact", 100, secret: "secret", match: "line containing secret", test_ids: ["TM-0250"]), count: 0)

# Redaction boundaries, ties, replacements, malformed bytes, and terminal
# composite interactions. Direct Redact(0) intentionally differs from detector option 0.
[[0, "redact-direct-zero"], [1, "redact-one"], [10, "redact-ten"], [25, "redact-tie-25"],
 [50, "redact-tie-50"], [75, "redact-tie-75"], [90, "redact-ninety"], [99, "redact-ninety-nine"],
 [100, "redact-hundred"], [101, "redact-over-hundred"]].each do |percent, id|
  add.call(redact_request(id, percent, secret: "secret", match: "secret/secret", line: "xsecret-secretx",
                          behaviors: %w[RED-001 RED-002 RED-003]), count: 0)
end
add.call(redact_request("redact-max-uint", (2**64) - 1, secret: "secret", match: "secret", line: "secret"), count: 0)
add.call(redact_request("redact-empty-partial", 75, secret: "", match: "Aé\xFFB".b, line: "Aé\xFFB".b), count: 0)
add.call(redact_request("redact-empty-full-utf8-invalid", 100, secret: "", match: "Aé\xFFB".b, line: "Aé\xFFB".b), count: 0)
add.call(redact_request("redact-utf8-byte-split", 50, secret: "éX", match: "éX", line: "prefix éX suffix"), count: 0)
add.call(redact_request("redact-utf8-mid-rune-75", 75, secret: "éX", match: "match éX end", line: "line éX end"), count: 0)
add.call(redact_request("redact-malformed-byte-slice", 50, secret: [0xff, 0xfe, 0x41].pack("C*"), match: [0xff, 0xfe, 0x41].pack("C*")), count: 0)
add.call(redact_request("redact-secret-absent", 50, secret: "secret", match: "nothing", line: "nothing"), count: 0)
add.call(redact_request("redact-secret-one-occurrence", 50, secret: "secret", match: "one secret", line: "one secret"), count: 0)
add.call(redact_request("redact-five-byte-half-even", 50, secret: "abcde", match: "abcde", line: "abcde"), count: 0)
add.call(redact_request("redact-five-byte-one-percent", 1, secret: "abcde", match: "abcde", line: "abcde"), count: 0)
add.call(redact_request("redact-overlapping-replaceall", 50, secret: "aa", match: "aaaaa", line: "aaaaa"), count: 0)
all_boundary_bytes = [0x00, 0x09, 0x7f, 0x80, 0xff].pack("C*")
add.call(redact_request("redact-required-arbitrary-byte-set", 50, secret: all_boundary_bytes, match: all_boundary_bytes, line: "x".b + all_boundary_bytes + "y".b), count: 0)
empty_over_input = "Aé\xFFB".b
add.call(redact_request("redact-empty-over-hundred-rune-boundaries", 101, secret: "", match: empty_over_input, line: empty_over_input), count: 0)
full_invariant_input = finding_input(secret: "secret", match: "match secret", line: "line secret").merge(
  "fragment" => {"raw_base64" => b64("fragment raw secret"), "bytes_base64" => "", "file_base64" => b64("fragment.go"),
                 "windows_file_base64" => b64("C:\\fragment.go"), "symlink_file_base64" => b64("fragment-link"),
                 "commit_base64" => b64("fragmentcommit"), "start_line" => 41, "inherited_from_finding" => true},
  "required_findings" => [{"rule_id" => "required", "start_line" => 2, "end_line" => 3,
                            "start_column" => 4, "end_column" => 9, "line_base64" => b64("required line"),
                            "match_base64" => b64("required match"), "secret_base64" => b64("required secret")}]
)
add.call(redact_request("redact-full-invariant-state", 75, input: full_invariant_input, behaviors: %w[RED-002 RED-003]), count: 0)
redacted_composite = composite_config(aux_regex: 'AUX=([a-z]+)')
add.call(detect_request("redact-composite-aux-unredacted", %w[RED-003 COMP-005], "AUX=one PRIMARY=VALUE", config: redacted_composite, redact: 100), count: 1, required_count: 1)
add.call(detect_request("redact-detector-option-zero", ["RED-001"], "AUX=one PRIMARY=VALUE", config: redacted_composite, redact: 0), count: 1, required_count: 1)
add.call(detect_request("redact-detector-partial", %w[RED-001 RED-003], "AUX=one PRIMARY=VALUE", config: redacted_composite, redact: 50), count: 1, required_count: 1)
add.call(detect_request("redact-decoded-composite", %w[RED-003 COMP-006], encoded_both, config: redacted_composite, depth: 1, redact: 50), count: 1, required_count: 1)
ordinary_redact_config = rule(id: "ordinary", regex: 'SECRET=([A-Z]+)', tags: ["ordinary-tag"])
add.call(detect_request("redact-ordinary-raw-top-level", %w[RED-001 RED-003], "SECRET=VALUE", config: ordinary_redact_config, redact: 50), count: 1)
ordinary_encoded = Base64.strict_encode64("SECRET=VALUE")
add.call(detect_request("redact-ordinary-decoded-top-level", %w[RED-001 RED-003], ordinary_encoded, config: ordinary_redact_config, depth: 1, redact: 50), count: 1)

# Bounded recursion/multiplicity probes.
many_aux = Array.new(256) { |index| "AUX=v#{index}" }.join(" ") + " PRIMARY=VALUE"
resource_cfg = composite_config(aux_regex: 'AUX=(v[0-9]+)')
add.call(detect_request("resource-many-auxiliaries", %w[COMP-005 COMP-008], many_aux, config: resource_cfg), count: 1, required_count: 256)
many_self = Array.new(16) { "SELF=VALUE" }.join(" ")
add.call(detect_request("resource-self-cycle-bounded", %w[COMP-002 COMP-008], many_self, config: self_config), count: 16, required_count: 16)
many_matrix = Array.new(32) { |index| "AUX=v#{index}" }.join(" ") + " " + Array.new(16) { |index| "PRIMARY=V#{index}" }.join(" ")
many_matrix_cfg = composite_config(required_specs: [required("aux"), required("aux")], primary_regex: 'PRIMARY=(V[0-9]+)', aux_regex: 'AUX=(v[0-9]+)')
add.call(detect_request("resource-primary-aux-duplicate-cartesian", %w[COMP-005 COMP-008], many_matrix, config: many_matrix_cfg), count: 16, required_count: 64)
many_generic_content = Array.new(128) { |index| "TOKEN=V#{index}" }.join(" ")
many_generic_cfg = generic_config(generic_regex: 'TOKEN=(V[0-9]+)', specific_regex: 'TOKEN=(V[0-9]+)')
add.call(detect_request("resource-many-generics", %w[SUP-001 COMP-008], many_generic_content, config: many_generic_cfg), count: 128)
long_malformed = ("A\xFFé".b * 512)
add.call(redact_request("resource-empty-full-long-malformed", 100, secret: "", match: long_malformed, line: long_malformed, behaviors: %w[RED-002 COMP-008]), count: 0)
deep_graph = +""
64.times do |index|
  required_rules = index == 63 ? [] : [required("graph-#{index + 1}")]
  deep_graph << rule(id: "graph-#{index}", regex: "NODE#{index}=VALUE", required: required_rules, skip: index != 0)
end
deep_graph_content = 64.times.map { |index| "NODE#{index}=VALUE" }.join(" ")
add.call(detect_request("resource-deep-required-graph", %w[COMP-002 COMP-008], deep_graph_content, config: deep_graph), count: 1, required_count: 1)
deep_graph_missing_tail = 63.times.map { |index| "NODE#{index}=VALUE" }.join(" ")
add.call(detect_request("resource-deep-required-graph-missing-tail", %w[COMP-002 COMP-008], deep_graph_missing_tail, config: deep_graph), count: 1, required_count: 1)
deep_cycle = +""
64.times do |index|
  deep_cycle << rule(id: "cycle-#{index}", regex: "CYCLE#{index}=VALUE",
                     required: [required("cycle-#{(index + 1) % 64}")], skip: index != 0)
end
deep_cycle_content = 64.times.map { |index| "CYCLE#{index}=VALUE" }.join(" ")
add.call(detect_request("resource-deep-required-cycle", %w[COMP-002 COMP-008], deep_cycle_content, config: deep_cycle), count: 1, required_count: 1)

abort "behavior coverage changed" unless requests.flat_map { |row| row["behavior_ids"] }.uniq.sort == BEHAVIORS.sort
ids = requests.map { |row| row["id"] }
abort "request IDs are not unique" unless ids.uniq.length == ids.length
abort "request assertion inventory changed" unless ids.sort == expect.keys.sort
mandatory_cases = {
  1 => %w[required-raw-raw required-config-empty-id required-config-missing-id],
  2 => %w[required-extension-disabled-dependency-fail-closed required-extension-valid-plus-missing-fail-closed required-runtime-missing-fail-closed],
  3 => %w[required-duplicate-aux-last-wins-positive required-duplicate-aux-last-wins-negative], 4 => %w[required-duplicate-specs],
  5 => %w[required-two-ids-one-present], 6 => %w[required-self-cycle required-two-rule-cycle required-nested-ignored],
  7 => %w[aux-skipreport-bypassed aux-nonskip-top-level-visible], 8 => %w[required-inherited-primary-bypass],
  9 => %w[primary-keyword-raw primary-keyword-decoded primary-keyword-unicode-case primary-keyword-absent required-raw-raw],
  10 => %w[aux-keyword-prefilter-bypassed aux-keyword-ordinary-top-level-rejected aux-keyword-ordinary-top-level-control],
  11 => %w[global-early-all-passes aux-commit-early-reject aux-rule-allowlist-reject aux-global-allowlist-reject aux-global-finding-untargeted-reject aux-global-finding-targeted-control],
  12 => %w[aux-capture-entropy-allowlist-control aux-capture-entropy-allowlist-reject aux-capture-entropy-before-allowlist-source-boundary],
  13 => %w[aux-allow-target-line-nested-decoded aux-line-nested-original-line-control aux-allow-target-line-multisegment aux-line-multisegment-original-line-control],
  14 => %w[marker-neighbor-outside-encoded-token marker-decoded-only-does-not-suppress],
  15 => %w[aux-capture-tags aux-entropy-below-visible aux-entropy-equal-reject aux-entropy-above-reject],
  16 => %w[aux-path-only-raw aux-path-only-decoded-negative aux-path-regex-positive aux-path-regex-negative],
  17 => %w[required-raw-raw proximity-line-boundary proximity-column-boundary proximity-both-conjunctive-pass],
  18 => %w[proximity-line-outside proximity-line-boundary proximity-line-distance-plus-one proximity-column-outside proximity-column-boundary proximity-column-distance-plus-one],
  19 => %w[proximity-zero-equal-start proximity-line-zero proximity-column-zero proximity-line-negative proximity-min-signed proximity-max-signed],
  20 => %w[proximity-same-start-different-ends proximity-overlapping-spans-start-outside proximity-overlapping-spans-start-exact], 21 => %w[proximity-match-start-not-capture],
  22 => %w[proximity-line-boundary proximity-negative-fragment-start],
  23 => %w[projection-primary-aux-cartesian-2x2], 24 => %w[projection-required-spec-order],
  25 => %w[filter-exact-duplicate-primaries-required projection-duplicate-pass-and-requirements], 26 => %w[projection-decoded-aux-metadata-visible],
  27 => %w[required-raw-raw], 28 => %w[pass-primary-raw-aux-encoded pass-primary-encoded-aux-raw],
  29 => %w[pass-both-encoded-same proximity-mapped-inside], 30 => %w[pass-both-nested-same-depth pass-different-decoded-depth],
  31 => %w[proximity-mapped-column-just-outside proximity-mapped-column-exact proximity-mapped-inside proximity-mapped-line-outside proximity-mapped-line-exact proximity-mapped-reverse-shift],
  32 => %w[decoded-line-primary-wrong-line-control decoded-line-primary-own-line-reject decoded-line-aux-wrong-line-control decoded-line-aux-own-line-reject],
  33 => %w[pass-raw-and-decoded-composite-duplicates], 34 => %w[generic-alone-retained generic-case-insensitive-substring],
  35 => %w[generic-shadow-contained], 36 => %w[generic-different-lines-survive generic-reversed-containment-survives generic-case-different-survives generic-filter-adapter-different-commit generic-filter-adapter-same-rule-id],
  37 => %w[generic-both-generic-survive], 38 => %w[generic-filter-adapter-ignores-file-column-end],
  39 => %w[generic-empty-secret-suppressed generic-empty-secret-alone-retained], 40 => %w[generic-filter-duplicate-order],
  41 => %w[generic-raw-shadowed-decoded-specific generic-decoded-shadowed-composite-specific],
  42 => %w[generic-attachment-alone-cannot-suppress generic-visible-aux-can-suppress],
  43 => %w[generic-terminal-redaction-discriminator], 44 => %w[redact-detector-option-zero redact-direct-zero],
  45 => %w[redact-one redact-ten redact-tie-25 redact-tie-50 redact-tie-75 redact-ninety redact-ninety-nine redact-hundred redact-over-hundred redact-max-uint],
  46 => %w[upstream-tm-0243-normal-secret upstream-tm-0244-short-secret redact-five-byte-half-even redact-five-byte-one-percent],
  47 => %w[redact-secret-absent redact-secret-one-occurrence redact-overlapping-replaceall redact-ten],
  48 => %w[redact-utf8-byte-split redact-utf8-mid-rune-75 redact-malformed-byte-slice redact-required-arbitrary-byte-set],
  49 => %w[redact-empty-partial redact-empty-full-utf8-invalid redact-empty-over-hundred-rune-boundaries],
  50 => %w[redact-full-invariant-state], 51 => %w[redact-composite-aux-unredacted],
  52 => %w[redact-ordinary-raw-top-level redact-ordinary-decoded-top-level redact-decoded-composite],
  53 => %w[malformed-composite-before malformed-composite-inside malformed-composite-after malformed-primary-aux-inside-secrets],
  54 => %w[malformed-adjacent-keyword malformed-adjacent-unicode-keyword], 55 => %w[resource-primary-aux-duplicate-cartesian],
  56 => %w[resource-many-generics], 57 => %w[resource-empty-full-long-malformed],
  58 => %w[resource-deep-required-graph resource-deep-required-graph-missing-tail resource-deep-required-cycle]
}.freeze
abort "mandatory semantic numbering changed" unless mandatory_cases.keys == (1..58).to_a
mandatory_cases.each do |number, request_ids|
  missing_ids = request_ids - ids
  abort "mandatory semantic case #{number} missing request IDs #{missing_ids.inspect}" unless missing_ids.empty?
end
resource_contracts = {
  "resource-primary-aux-duplicate-cartesian" => {"case" => 55, "deadline_seconds" => 10, "output_bytes" => 8 * 1024 * 1024, "allocation_bytes" => 1024 * 1024 * 1024},
  "resource-many-generics" => {"case" => 56, "deadline_seconds" => 10, "output_bytes" => 4 * 1024 * 1024, "allocation_bytes" => 1024 * 1024 * 1024},
  "resource-empty-full-long-malformed" => {"case" => 57, "deadline_seconds" => 10, "output_bytes" => 4 * 1024 * 1024, "allocation_bytes" => 1024 * 1024 * 1024},
  "resource-deep-required-graph" => {"case" => 58, "deadline_seconds" => 10, "output_bytes" => 4 * 1024 * 1024, "allocation_bytes" => 1024 * 1024 * 1024},
  "resource-deep-required-graph-missing-tail" => {"case" => 58, "deadline_seconds" => 10, "output_bytes" => 4 * 1024 * 1024, "allocation_bytes" => 1024 * 1024 * 1024},
  "resource-deep-required-cycle" => {"case" => 58, "deadline_seconds" => 10, "output_bytes" => 4 * 1024 * 1024, "allocation_bytes" => 1024 * 1024 * 1024}
}.freeze
abort "resource case ownership changed" unless resource_contracts.keys.sort == %w[resource-deep-required-cycle resource-deep-required-graph resource-deep-required-graph-missing-tail resource-empty-full-long-malformed resource-many-generics resource-primary-aux-duplicate-cartesian] &&
                                                resource_contracts.values.map { |value| value["case"] }.uniq.sort == (55..58).to_a
seen_leaf_ids = requests.flat_map { |row| row["test_case_ids"] }.uniq.sort
abort "leaf identity coverage changed: #{seen_leaf_ids.inspect}" unless seen_leaf_ids == LEAF_IDS.sort

revision = capture("git", "rev-parse", "HEAD", chdir: UPSTREAM).strip
abort "upstream revision changed: #{revision}" unless revision == REVISION
status = capture("git", "status", "--short", "--untracked-files=no", chdir: UPSTREAM)
abort "upstream status changed:\n#{status}" unless status == EXPECTED_UPSTREAM_STATUS
default_config = UPSTREAM.join("config/gitleaks.toml").binread
abort "default config hash changed" unless sha(default_config) == DEFAULT_SHA256

outcomes = []
Dir.mktmpdir("rustleaks-composite-oracle-") do |temporary|
  binary = File.join(temporary, "oracle")
  capture("go", "build", "-o", binary, ".", chdir: ORACLE)

  mask_source = File.join(temporary, "m7_mask_oracle_test.go")
  File.write(mask_source, <<~GO)
    package report
    import ("encoding/base64"; "fmt"; "os"; "strconv"; "testing")
    func TestM7MaskOracle(t *testing.T) {
      raw, err := base64.StdEncoding.DecodeString(os.Getenv("M7_SECRET")); if err != nil { t.Fatal(err) }
      percent, err := strconv.ParseUint(os.Getenv("M7_PERCENT"), 10, 64); if err != nil { t.Fatal(err) }
      fmt.Println("M7MASK:" + base64.StdEncoding.EncodeToString([]byte(maskSecret(string(raw), uint(percent)))))
    }
  GO
  overlay = File.join(temporary, "overlay.json")
  target = UPSTREAM.join("report/m7_mask_oracle_test.go").to_s
  File.write(overlay, JSON.generate({"Replace" => {target => mask_source}}))
  mask_binary = File.join(temporary, "mask.test")
  capture("go", "test", "-c", "-overlay", overlay, "-o", mask_binary, "./report", chdir: UPSTREAM)

  filter_source = File.join(temporary, "m7_filter_oracle_test.go")
  File.write(filter_source, <<~'GO')
    package detect
    import ("encoding/base64"; "encoding/json"; "fmt"; "math"; "os"; "testing"; "github.com/zricethezav/gitleaks/v8/report")
    type m7Req struct { RuleID string `json:"rule_id"`; StartLine int `json:"start_line"`; EndLine int `json:"end_line"`; StartColumn int `json:"start_column"`; EndColumn int `json:"end_column"`; Line string `json:"line_base64"`; Match string `json:"match_base64"`; Secret string `json:"secret_base64"` }
    type m7In struct { RuleID string `json:"rule_id"`; Description string `json:"description_base64"`; StartLine int `json:"start_line"`; EndLine int `json:"end_line"`; StartColumn int `json:"start_column"`; EndColumn int `json:"end_column"`; Line string `json:"line_base64"`; Match string `json:"match_base64"`; Secret string `json:"secret_base64"`; File string `json:"file_base64"`; Symlink string `json:"symlink_file_base64"`; Commit string `json:"commit_base64"`; Link string `json:"link_base64"`; Entropy uint32 `json:"entropy_bits"`; Author string `json:"author_base64"`; Email string `json:"email_base64"`; Date string `json:"date_base64"`; Message string `json:"message_base64"`; Tags []string `json:"tags_base64"`; Fingerprint string `json:"fingerprint_base64"`; Required []m7Req `json:"required_findings"` }
    type m7Out struct { RuleID string `json:"rule_id"`; Description string `json:"description_base64"`; StartLine int `json:"start_line"`; EndLine int `json:"end_line"`; StartColumn int `json:"start_column"`; EndColumn int `json:"end_column"`; Line string `json:"line_base64"`; Match string `json:"match_base64"`; Secret string `json:"secret_base64"`; File string `json:"file_base64"`; Symlink string `json:"symlink_file_base64"`; Commit string `json:"commit_base64"`; Link string `json:"link_base64"`; Entropy uint32 `json:"entropy_bits"`; Author string `json:"author_base64"`; Email string `json:"email_base64"`; Date string `json:"date_base64"`; Message string `json:"message_base64"`; Tags []string `json:"tags_base64"`; Fingerprint string `json:"fingerprint_base64"`; Fragment any `json:"fragment"`; Required []m7Req `json:"required_findings"` }
    func dec(v string) string { b,e:=base64.StdEncoding.DecodeString(v); if e!=nil { panic(e) }; return string(b) }
    func enc(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }
    func TestM7FilterOracle(t *testing.T) { var in []m7In; if e:=json.Unmarshal([]byte(os.Getenv("M7_FILTER")),&in);e!=nil{t.Fatal(e)}; fs:=make([]report.Finding,0,len(in)); for _,v:=range in { tags:=make([]string,len(v.Tags));for i,x:=range v.Tags{tags[i]=dec(x)}; f:=report.Finding{RuleID:v.RuleID,Description:dec(v.Description),StartLine:v.StartLine,EndLine:v.EndLine,StartColumn:v.StartColumn,EndColumn:v.EndColumn,Line:dec(v.Line),Match:dec(v.Match),Secret:dec(v.Secret),File:dec(v.File),SymlinkFile:dec(v.Symlink),Commit:dec(v.Commit),Link:dec(v.Link),Entropy:math.Float32frombits(v.Entropy),Author:dec(v.Author),Email:dec(v.Email),Date:dec(v.Date),Message:dec(v.Message),Tags:tags,Fingerprint:dec(v.Fingerprint)}; req:=make([]*report.RequiredFinding,0,len(v.Required));for _,r:=range v.Required{req=append(req,&report.RequiredFinding{RuleID:r.RuleID,StartLine:r.StartLine,EndLine:r.EndLine,StartColumn:r.StartColumn,EndColumn:r.EndColumn,Line:dec(r.Line),Match:dec(r.Match),Secret:dec(r.Secret)})};f.AddRequiredFindings(req);fs=append(fs,f)}; got:=filter(fs,0); out:=make([]m7Out,0,len(got));for _,f:=range got{tags:=make([]string,len(f.Tags));for i,x:=range f.Tags{tags[i]=enc(x)};req:=make([]m7Req,0);for _,r:=range report.M7RequiredFindings(f){req=append(req,m7Req{r.RuleID,r.StartLine,r.EndLine,r.StartColumn,r.EndColumn,enc(r.Line),enc(r.Match),enc(r.Secret)})};out=append(out,m7Out{f.RuleID,enc(f.Description),f.StartLine,f.EndLine,f.StartColumn,f.EndColumn,enc(f.Line),enc(f.Match),enc(f.Secret),enc(f.File),enc(f.SymlinkFile),enc(f.Commit),enc(f.Link),math.Float32bits(f.Entropy),enc(f.Author),enc(f.Email),enc(f.Date),enc(f.Message),tags,enc(f.Fingerprint),nil,req})}; raw,_:=json.Marshal(out);fmt.Println("M7FILTER:"+base64.StdEncoding.EncodeToString(raw)) }
  GO
  report_export_source = File.join(temporary, "finding.go")
  File.binwrite(report_export_source, UPSTREAM.join("report/finding.go").binread + "\nfunc M7RequiredFindings(f Finding) []*RequiredFinding { return f.requiredFindings }\n")
  filter_overlay = File.join(temporary, "filter-overlay.json")
  filter_target = UPSTREAM.join("detect/m7_filter_oracle_test.go").to_s
  report_target = UPSTREAM.join("report/finding.go").to_s
  File.write(filter_overlay, JSON.generate({"Replace" => {filter_target => filter_source, report_target => report_export_source}}))
  filter_binary = File.join(temporary, "filter.test")
  capture("go", "test", "-c", "-overlay", filter_overlay, "-o", filter_binary, "./detect", chdir: UPSTREAM)

  template = nil
  requests.each do |request|
    if request["operation"] == "mask_secret"
      abort "mask template unavailable" unless template
      secret = Base64.strict_decode64(request.fetch("redaction").fetch("secret_base64"))
      output = capture(mask_binary, "-test.run", "^TestM7MaskOracle$", "-test.v", chdir: UPSTREAM,
                       env: {"M7_SECRET" => b64(secret), "M7_PERCENT" => request.fetch("redact_percent").to_s})
      encoded = output[/M7MASK:([^\s]+)/, 1] or abort "mask probe marker missing: #{output}"
      outcome = template.merge(
        "id" => request["id"], "behavior_ids" => request["behavior_ids"], "test_case_ids" => request["test_case_ids"],
        "operation" => "mask_secret", "input_sha256" => sha(secret), "config_sha256" => "",
        "redact_percent" => request["redact_percent"], "findings" => [], "original" => nil, "redacted" => nil,
        "mask_secret_base64" => encoded, "error" => nil
      )
    elsif request["operation"] == "filter_probe"
      abort "filter template unavailable" unless template
      input = JSON.generate(request.fetch("filter_inputs"))
      output = capture(filter_binary, "-test.run", "^TestM7FilterOracle$", "-test.v", chdir: UPSTREAM, env: {"M7_FILTER" => input})
      encoded = output[/M7FILTER:([^\s]+)/, 1] or abort "filter probe marker missing: #{output}"
      findings = JSON.parse(Base64.strict_decode64(encoded))
      outcome = template.merge("id" => request["id"], "behavior_ids" => request["behavior_ids"], "test_case_ids" => [],
                               "operation" => "filter_probe", "input_sha256" => sha(input), "config_sha256" => "",
                               "redact_percent" => request["redact_percent"], "findings" => findings,
                               "original" => nil, "redacted" => nil, "mask_secret_base64" => "", "error" => nil)
    else
      contract = resource_contracts[request["id"]]
      raw = capture(binary, "--composite", chdir: ORACLE, stdin_data: JSON.generate(request) + "\n",
                    timeout_seconds: contract ? contract["deadline_seconds"] : 20,
                    output_limit: contract ? contract["output_bytes"] : 64 * 1024 * 1024,
                    allocation_limit: contract && contract["allocation_bytes"], request_id: request["id"])
      lines = raw.lines
      abort "#{request['id']}: oracle returned #{lines.length} rows" unless lines.length == 1
      outcome = JSON.parse(lines.first)
      template ||= outcome
    end
    outcomes << outcome
  end
end

outcomes.each do |outcome|
  request = requests.fetch(outcomes.index(outcome))
  id = request.fetch("id")
  assertion = expect.fetch(id)
  abort "#{id}: response identity changed" unless outcome["id"] == id && outcome["behavior_ids"] == request["behavior_ids"] && outcome["test_case_ids"] == request["test_case_ids"]
  abort "#{id}: pin changed" unless outcome["upstream_revision"] == REVISION && outcome["default_config_sha256"] == DEFAULT_SHA256
  if assertion[:error]
    abort "#{id}: expected #{assertion[:error]} error" unless outcome.dig("error", "class") == assertion[:error]
    next
  end
  abort "#{id}: unexpected error #{outcome['error'].inspect}" unless outcome["error"].nil?
  findings = outcome.fetch("findings")
  abort "#{id}: finding count #{findings.length} != #{assertion[:count]}" unless findings.length == assertion[:count]
  next if assertion[:required_count].nil?
  abort "#{id}: no primary finding for required assertion" if findings.empty?
  counts = findings.select { |finding| finding["rule_id"] != "aux" }.map { |finding| finding.fetch("required_findings").length }
  abort "#{id}: required counts #{counts.inspect}" unless counts.all? { |count| count == assertion[:required_count] }
end

by_id = outcomes.to_h { |row| [row.fetch("id"), row] }
expected_finding_keys = %w[rule_id description_base64 start_line end_line start_column end_column line_base64 match_base64 secret_base64 file_base64 symlink_file_base64 commit_base64 link_base64 entropy_bits author_base64 email_base64 date_base64 message_base64 tags_base64 fingerprint_base64 fragment required_findings].sort
expected_required_keys = %w[rule_id start_line end_line start_column end_column line_base64 match_base64 secret_base64].sort
outcomes.each do |outcome|
  outcome.fetch("findings").each do |finding|
    abort "#{outcome['id']}: incomplete finding schema" unless finding.keys.sort == expected_finding_keys
    finding.fetch("required_findings").each do |required_finding|
      abort "#{outcome['id']}: incomplete required finding schema" unless required_finding.keys.sort == expected_required_keys
    end
  end
end
extension = by_id.fetch("required-extension-disabled-dependency-fail-closed")
abort "extension dangling identity changed" unless extension["config_sha256"] == "50cbe78501cf4585751b8364e6c462c65023c865bfb3e1e674325367366bc3a8" && extension["error"].nil? && extension["findings"].empty?
tm = by_id.fetch("upstream-tm-0084-fragment-level-composite").fetch("findings").first
abort "TM-0084 primary geometry changed" unless tm.values_at("rule_id", "start_line", "end_line", "start_column", "end_column") == ["primary-rule", 5, 5, 5, 26]
aux = tm.fetch("required_findings").first
abort "TM-0084 auxiliary changed: #{aux.inspect}" unless aux.values_at("rule_id", "start_line", "start_column") == ["username-rule", 1, 2] && Base64.strict_decode64(aux.fetch("secret_base64")) == "admin"

dup = by_id.fetch("required-duplicate-specs").dig("findings", 0, "required_findings")
abort "duplicate required order changed" unless dup.map { |row| Base64.strict_decode64(row.fetch("secret_base64")) } == %w[one two one two]
order = by_id.fetch("projection-required-spec-order").dig("findings", 0, "required_findings").map { |row| row["rule_id"] }
abort "required spec order changed" unless order == %w[aux-b aux-a]
mapped_finding = by_id.fetch("proximity-mapped-inside").fetch("findings").first
abort "mapped proximity did not preserve distinct original columns" unless mapped_finding["start_column"] < mapped_finding.dig("required_findings", 0, "start_column")

abort "generic shadow predicate changed" unless by_id.fetch("generic-shadow-contained").fetch("findings").map { |f| f["rule_id"] } == ["specific"]
adapter_request = requests.find { |row| row["id"] == "generic-filter-adapter-ignores-file-column-end" }
abort "filter adapter inputs do not discriminate ignored geometry" unless adapter_request.fetch("filter_inputs").map { |input| [input["file_base64"], input["start_column"], input["end_line"], input["end_column"]] }.uniq.length == 2
adapter = by_id.fetch("generic-filter-adapter-ignores-file-column-end").fetch("findings")
abort "filter adapter predicate changed" unless adapter.length == 1 && adapter.first["rule_id"] == "specific-adapter" && Base64.strict_decode64(adapter.first["file_base64"]) == "specific.go"
redacted_generic = by_id.fetch("generic-suppression-before-redaction").fetch("findings").first
abort "suppression/redaction ordering changed" unless redacted_generic["rule_id"] == "specific" && Base64.strict_decode64(redacted_generic["secret_base64"]).end_with?("...")

expected_masks = {"upstream-tm-0246-high-masking" => "s...", "upstream-tm-0247-invalid-masking" => "...",
                  "upstream-tm-0248-low-masking" => "secre...", "upstream-tm-0249-normal-masking" => "se..."}
expected_masks.each do |id, value|
  abort "#{id}: private mask changed" unless Base64.strict_decode64(by_id.fetch(id).fetch("mask_secret_base64")) == value
end
empty_partial = by_id.fetch("redact-empty-partial").fetch("redacted")
abort "empty partial redaction changed" unless empty_partial["line_base64"] == by_id.fetch("redact-empty-partial").dig("original", "line_base64")
empty_full = Base64.strict_decode64(by_id.fetch("redact-empty-full-utf8-invalid").dig("redacted", "line_base64"))
abort "empty full redaction rune boundaries changed" unless empty_full.b.scan("REDACTED".b).length == 5 && empty_full.b.include?("é".b) && empty_full.b.include?("\xFF".b)
direct_zero = Base64.strict_decode64(by_id.fetch("redact-direct-zero").dig("redacted", "secret_base64"))
detector_zero = Base64.strict_decode64(by_id.fetch("redact-detector-option-zero").dig("findings", 0, "secret_base64"))
abort "Redact(0)/detector option 0 boundary changed" unless direct_zero == "secret..." && detector_zero == "VALUE"
composite_redacted = by_id.fetch("redact-composite-aux-unredacted").fetch("findings").first
abort "required attachment was redacted" unless Base64.strict_decode64(composite_redacted.dig("required_findings", 0, "secret_base64")) == "one"
invariant = by_id.fetch("redact-ten")
unchanged = expected_finding_keys - %w[line_base64 match_base64 secret_base64]
abort "redaction changed invariant finding fields" unless unchanged.all? { |key| invariant.dig("original", key) == invariant.dig("redacted", key) }

# The review acceptance gate is semantic, not an ID inventory. Every repaired
# group below has named material properties over request geometry and exact Go
# outcomes. Coverage serializes this inventory and generation fails unless all
# properties execute successfully.
request_by_id = requests.to_h { |row| [row.fetch("id"), row] }
material_assertions = Hash.new { |hash, key| hash[key] = [] }
verify = lambda do |group, assertion_id, condition|
  abort "mandatory semantic group #{group} failed #{assertion_id}" unless condition
  material_assertions[group] << assertion_id
end
decoded_config = lambda { |id| Base64.strict_decode64(request_by_id.fetch(id).fetch("config_base64")) }
decoded_content = lambda { |id| Base64.strict_decode64(request_by_id.fetch(id).dig("fragment", "content_base64")) }
finding_ids = lambda { |id| by_id.fetch(id).fetch("findings").map { |finding| finding["rule_id"] } }

verify.call(3, "duplicate-aux-last-definition-controls-projection",
            decoded_config.call("required-duplicate-aux-last-wins-positive").scan("[[rules]]\nid = \"aux\"").length == 2 &&
            by_id.fetch("required-duplicate-aux-last-wins-positive").dig("findings", 0, "required_findings", 0, "secret_base64") == b64("one") &&
            by_id.fetch("required-duplicate-aux-last-wins-negative").fetch("findings").empty?)
verify.call(5, "two-distinct-required-ids-one-match-fails-closed",
            decoded_config.call("required-two-ids-one-present").include?('id = "aux-a"') &&
            decoded_config.call("required-two-ids-one-present").include?('id = "aux-b"') &&
            by_id.fetch("required-two-ids-one-present").fetch("findings").empty?)
verify.call(9, "keyword-absent-retains-regex-candidate",
            decoded_content.call("primary-keyword-absent").include?("PRIMARY=VALUE") &&
            decoded_config.call("primary-keyword-absent").include?("withheld-keyword") &&
            by_id.fetch("primary-keyword-absent").fetch("findings").empty?)
verify.call(10, "aux-keyword-bypass-versus-ordinary-gate",
            by_id.fetch("aux-keyword-prefilter-bypassed").fetch("findings").length == 1 &&
            by_id.fetch("aux-keyword-ordinary-top-level-rejected").fetch("findings").empty? &&
            finding_ids.call("aux-keyword-ordinary-top-level-control") == ["aux"])
verify.call(11, "global-finding-target-isolated-from-early-and-rule-gates",
            by_id.fetch("aux-global-finding-untargeted-reject").fetch("findings").empty? &&
            by_id.fetch("aux-global-finding-targeted-control").fetch("findings").length == 1 &&
            by_id.fetch("global-early-all-passes").fetch("findings").empty?)
combined_config = decoded_config.call("aux-capture-entropy-allowlist-control")
combined_aux = by_id.fetch("aux-capture-entropy-allowlist-control").fetch("findings").find { |finding| finding["rule_id"] == "aux" }
verify.call(12, "combined-capture-entropy-allowlist-pairs-and-source-order-boundary",
            combined_config == combined_stage_control &&
            decoded_config.call("aux-capture-entropy-allowlist-reject") == combined_stage_allow_reject &&
            decoded_config.call("aux-capture-entropy-before-allowlist-source-boundary") == combined_stage_entropy_reject &&
            %w[aux-capture-entropy-allowlist-control aux-capture-entropy-allowlist-reject aux-capture-entropy-before-allowlist-source-boundary].all? { |id|
              decoded_content.call(id) == "AUX=prefix-A1B2 PRIMARY=VALUE"
            } &&
            combined_config.include?('secretGroup = 1') && combined_config.include?('entropy = 1.9') &&
            combined_config.include?('regexTarget = "secret"') && combined_config.include?('regexes = ["^NEVER$"]') &&
            combined_aux["secret_base64"] == b64("A1B2") && combined_aux["entropy_bits"] == 1_073_741_824 &&
            by_id.fetch("aux-capture-entropy-allowlist-reject").fetch("findings").empty? &&
            by_id.fetch("aux-capture-entropy-before-allowlist-source-boundary").fetch("findings").empty? &&
            source_order_evidence["classification"] == "source-order-only" &&
            source_order_evidence["source_sha256"] == "2bac563a09f22ff76c56b200c3b9b5dc865c1de699eb0ba2a27cca741fa9bd13" &&
            source_order_evidence.values_at("entropy_line", "global_allowlist_line", "rule_allowlist_line") == [543, 557, 563])
verify.call(13, "nested-and-multisegment-current-line-with-original-projection",
            by_id.fetch("aux-allow-target-line-nested-decoded").fetch("findings").empty? &&
            by_id.fetch("aux-allow-target-line-multisegment").fetch("findings").empty? &&
            Base64.strict_decode64(by_id.fetch("aux-line-nested-original-line-control").dig("findings", 0, "required_findings", 0, "line_base64")) == Base64.strict_encode64(encoded_both) &&
            Base64.strict_decode64(by_id.fetch("aux-line-multisegment-original-line-control").dig("findings", 0, "required_findings", 0, "line_base64")) == multi_segment_line)
verify.call(14, "mapped-original-line-neighbor-marker-versus-decoded-only",
            decoded_content.call("marker-neighbor-outside-encoded-token") == mapped_neighbor_marker &&
            sha(decoded_content.call("marker-neighbor-outside-encoded-token")) == "9f994cd8f5fa43faca2427bea8a0e0cf85b5e2fa0bcbeec2cfdaf2fcf08fc8d0" &&
            by_id.fetch("marker-neighbor-outside-encoded-token").fetch("findings").empty? &&
            by_id.fetch("marker-decoded-only-does-not-suppress").fetch("findings").length == 1 &&
            by_id.fetch("marker-decoded-only-does-not-suppress").dig("findings", 0, "required_findings").length == 1)
visible_entropy = by_id.fetch("aux-entropy-below-visible").fetch("findings").find { |finding| finding["rule_id"] == "aux" }
verify.call(15, "capture-entropy-below-equal-above-f32",
            visible_entropy && visible_entropy["secret_base64"] == b64("a1B2") && visible_entropy["entropy_bits"] == 1_073_741_824 &&
            by_id.fetch("aux-entropy-equal-reject").fetch("findings").empty? && by_id.fetch("aux-entropy-above-reject").fetch("findings").empty?)
verify.call(16, "path-regex-positive-negative-and-path-only-pass-boundary",
            decoded_config.call("aux-path-regex-positive").include?('path = "tmp\\\\.go"') &&
            by_id.fetch("aux-path-regex-positive").fetch("findings").length == 1 &&
            by_id.fetch("aux-path-regex-negative").fetch("findings").empty? &&
            by_id.fetch("aux-path-only-decoded-negative").fetch("findings").empty?)
verify.call(18, "line-column-distance-minus-exact-plus",
            %w[proximity-line-outside proximity-column-outside].all? { |id| by_id.fetch(id).fetch("findings").empty? } &&
            %w[proximity-line-boundary proximity-line-distance-plus-one proximity-column-boundary proximity-column-distance-plus-one].all? { |id| by_id.fetch(id).fetch("findings").length == 1 })
zero_equal = by_id.fetch("proximity-zero-equal-start").fetch("findings").first
verify.call(19, "zero-equal-positive-zero-unequal-negative-signed-extremes",
            zero_equal["start_column"] == zero_equal.dig("required_findings", 0, "start_column") &&
            by_id.fetch("proximity-column-zero").fetch("findings").empty? &&
            by_id.fetch("proximity-min-signed").fetch("findings").empty? && by_id.fetch("proximity-max-signed").fetch("findings").length == 1)
same_start = by_id.fetch("proximity-same-start-different-ends").fetch("findings").first
verify.call(20, "end-geometry-ignored-overlap-start-controls",
            same_start["start_column"] == same_start.dig("required_findings", 0, "start_column") && same_start["end_column"] != same_start.dig("required_findings", 0, "end_column") &&
            by_id.fetch("proximity-overlapping-spans-start-outside").fetch("findings").empty? && by_id.fetch("proximity-overlapping-spans-start-exact").fetch("findings").length == 1)
verify.call(22, "fragment-start-shift-and-negative-domain-explicit",
            request_by_id.fetch("proximity-line-boundary").dig("fragment", "start_line") == 11 &&
            by_id.fetch("proximity-line-boundary").dig("findings", 0, "start_line") == 13 &&
            by_id.fetch("proximity-line-boundary").dig("findings", 0, "required_findings", 0, "start_line") == 11 &&
            (by_id.fetch("proximity-line-boundary").dig("findings", 0, "start_line") -
             by_id.fetch("proximity-line-boundary").dig("findings", 0, "required_findings", 0, "start_line")).abs == 2 &&
            request_by_id.fetch("proximity-negative-fragment-start").dig("fragment", "start_line") == -20 &&
            by_id.fetch("proximity-negative-fragment-start").dig("findings", 0, "start_line") == -18)
cartesian = by_id.fetch("projection-primary-aux-cartesian-2x2").fetch("findings")
verify.call(23, "two-primary-by-two-aux-cartesian",
            cartesian.length == 2 && cartesian.all? { |finding| finding["required_findings"].map { |required| Base64.strict_decode64(required["secret_base64"]) } == %w[one two] })
duplicate_projection = by_id.fetch("projection-duplicate-pass-and-requirements").fetch("findings")
duplicate_filter_inputs = request_by_id.fetch("filter-exact-duplicate-primaries-required").fetch("filter_inputs")
duplicate_filter_findings = by_id.fetch("filter-exact-duplicate-primaries-required").fetch("findings")
verify.call(25, "byte-identical-primary-and-required-vector-preservation",
            duplicate_filter_inputs.length == 2 && JSON.generate(duplicate_filter_inputs[0]) == JSON.generate(duplicate_filter_inputs[1]) &&
            duplicate_filter_inputs.all? { |finding| finding.fetch("required_findings").length == 2 &&
              JSON.generate(finding.fetch("required_findings")[0]) == JSON.generate(finding.fetch("required_findings")[1]) } &&
            duplicate_filter_findings.length == 2 && JSON.generate(duplicate_filter_findings[0]) == JSON.generate(duplicate_filter_findings[1]) &&
            duplicate_filter_findings.all? { |finding| finding.fetch("rule_id") == "specific-duplicate-primary" &&
              finding.fetch("required_findings").length == 2 &&
              JSON.generate(finding.fetch("required_findings")[0]) == JSON.generate(finding.fetch("required_findings")[1]) } &&
            duplicate_projection.length == 2 && duplicate_projection.all? { |finding| finding["required_findings"].length == 2 } &&
            duplicate_projection.map { |finding| finding["tags_base64"] }.any?(&:empty?) &&
            duplicate_projection.map { |finding| finding["tags_base64"] }.any? { |tags| !tags.empty? })
metadata_rows = by_id.fetch("projection-decoded-aux-metadata-visible").fetch("findings")
visible_aux = metadata_rows.find { |finding| finding["rule_id"] == "aux" }
metadata_primary = metadata_rows.find { |finding| finding["rule_id"] == "primary" }
verify.call(26, "visible-aux-metadata-dropped-from-eight-field-attachment",
            visible_aux["tags_base64"].map { |tag| Base64.strict_decode64(tag) } == ["aux-metadata", "decoded:base64", "decode-depth:1"] &&
            metadata_primary["required_findings"].first.keys.sort == expected_required_keys)
mapped_exact_finding = by_id.fetch("proximity-mapped-column-exact").fetch("findings").first
mapped_exact_required = mapped_exact_finding.fetch("required_findings").first
mapped_reverse_finding = by_id.fetch("proximity-mapped-reverse-shift").fetch("findings").first
mapped_reverse_required = mapped_reverse_finding.fetch("required_findings").first
verify.call(31, "mapped-expanded-spans-and-cumulative-shrink-shifts",
            mapped_exact_finding.values_at("start_line", "end_line", "start_column", "end_column") == [0, 0, 1, 16] &&
            mapped_exact_required.values_at("start_line", "end_line", "start_column", "end_column") == [0, 0, 18, 37] &&
            mapped_reverse_finding.values_at("start_line", "end_line", "start_column", "end_column") == [0, 0, 22, 37] &&
            mapped_reverse_required.values_at("start_line", "end_line", "start_column", "end_column") == [0, 0, 1, 20] &&
            Base64.strict_decode64(mapped_exact_finding.fetch("secret_base64")).bytesize == 12 &&
            Base64.strict_decode64(mapped_exact_required.fetch("secret_base64")).bytesize == 14 &&
            Base64.strict_decode64(mapped_reverse_finding.fetch("secret_base64")).bytesize == 12 &&
            Base64.strict_decode64(mapped_reverse_required.fetch("secret_base64")).bytesize == 14 &&
            mapped_exact_required.fetch("start_column") - (mapped_exact_finding.fetch("start_column") + 12 + 1) == 4 &&
            mapped_reverse_finding.fetch("start_column") - (mapped_reverse_required.fetch("start_column") + 14 + 1) == 6 &&
            by_id.fetch("proximity-mapped-column-just-outside").fetch("findings").empty? &&
            by_id.fetch("proximity-mapped-line-exact").fetch("findings").length == 1 && by_id.fetch("proximity-mapped-line-outside").fetch("findings").empty? &&
            by_id.fetch("proximity-mapped-reverse-shift").fetch("findings").length == 1)
verify.call(32, "primary-aux-decoded-line-gates-isolated",
            by_id.fetch("decoded-line-primary-wrong-line-control").fetch("findings").length == 1 && by_id.fetch("decoded-line-primary-own-line-reject").fetch("findings").empty? &&
            by_id.fetch("decoded-line-aux-wrong-line-control").fetch("findings").length == 1 && by_id.fetch("decoded-line-aux-own-line-reject").fetch("findings").empty?)
raw_decoded = by_id.fetch("pass-raw-and-decoded-composite-duplicates").fetch("findings")
verify.call(33, "raw-decoded-genuinely-new-composites-retain-vectors",
            raw_decoded.length == 2 && raw_decoded.all? { |finding| finding["required_findings"].length == 1 } &&
            raw_decoded.count { |finding| finding["tags_base64"].empty? } == 1 && raw_decoded.count { |finding| !finding["tags_base64"].empty? } == 1)
verify.call(36, "different-commit-and-same-rule-id-filter-controls",
            by_id.fetch("generic-filter-adapter-different-commit").fetch("findings").length == 2 &&
            by_id.fetch("generic-filter-adapter-same-rule-id").fetch("findings").length == 2)
verify.call(39, "empty-generic-suppressed-and-alone-retained",
            finding_ids.call("generic-empty-secret-suppressed") == ["specific"] &&
            by_id.fetch("generic-empty-secret-alone-retained").dig("findings", 0, "secret_base64") == "")
duplicate_order_inputs = request_by_id.fetch("generic-filter-duplicate-order").fetch("filter_inputs")
duplicate_order_findings = by_id.fetch("generic-filter-duplicate-order").fetch("findings")
verify.call(40, "true-generic-specific-duplicates-and-stable-bookend-order",
            duplicate_order_inputs.length == 6 &&
            JSON.generate(duplicate_order_inputs[1]) == JSON.generate(duplicate_order_inputs[2]) &&
            JSON.generate(duplicate_order_inputs[3]) == JSON.generate(duplicate_order_inputs[4]) &&
            duplicate_order_inputs.group_by { |finding| JSON.generate(finding) }.values.map(&:length).sort == [1, 1, 2, 2] &&
            duplicate_order_inputs.map { |finding| finding.values_at("start_line", "end_line") } == [[1, 1], [9, 9], [9, 9], [9, 9], [9, 9], [20, 20]] &&
            duplicate_order_inputs.values_at(0, 5).map { |finding| finding.fetch("rule_id") } == %w[bookend-start bookend-end] &&
            finding_ids.call("generic-filter-duplicate-order") == %w[bookend-start specific-duplicate specific-duplicate bookend-end] &&
            duplicate_order_findings.length == 4 && JSON.generate(duplicate_order_findings[1]) == JSON.generate(duplicate_order_findings[2]) &&
            duplicate_order_findings.none? { |finding| finding.fetch("rule_id").include?("generic") })
verify.call(41, "cross-pass-and-composite-specific-suppression",
            finding_ids.call("generic-raw-shadowed-decoded-specific") == ["specific-decoded"] &&
            finding_ids.call("generic-decoded-shadowed-composite-specific") == ["specific-composite"])
verify.call(42, "attachment-alone-versus-visible-aux-suppression",
            finding_ids.call("generic-attachment-alone-cannot-suppress").include?("generic") &&
            !finding_ids.call("generic-visible-aux-can-suppress").include?("generic") && finding_ids.call("generic-visible-aux-can-suppress").include?("aux"))
verify.call(43, "suppression-uses-original-before-noncontaining-masks",
            finding_ids.call("generic-terminal-redaction-discriminator") == ["specific"] &&
            Base64.strict_decode64(by_id.fetch("generic-terminal-redaction-discriminator").dig("findings", 0, "secret_base64")) == "Xa...")
verify.call(45, "public-redact-max-uint-full-mask",
            Base64.strict_decode64(by_id.fetch("redact-max-uint").dig("redacted", "secret_base64")) == "REDACTED")
verify.call(47, "zero-one-repeated-overlap-replacement",
            Base64.strict_decode64(by_id.fetch("redact-secret-absent").dig("redacted", "line_base64")) == "nothing" &&
            Base64.strict_decode64(by_id.fetch("redact-secret-one-occurrence").dig("redacted", "line_base64")) == "one sec..." &&
            Base64.strict_decode64(by_id.fetch("redact-overlapping-replaceall").dig("redacted", "line_base64")) == "a...a...a")
boundary_redacted = Base64.strict_decode64(by_id.fetch("redact-required-arbitrary-byte-set").dig("redacted", "secret_base64"))
utf8_boundary = by_id.fetch("redact-utf8-byte-split").fetch("redacted")
utf8_mid_rune = by_id.fetch("redact-utf8-mid-rune-75").fetch("redacted")
verify.call(48, "required-control-byte-set-and-mid-rune-slice",
            all_boundary_bytes.bytes == [0, 9, 127, 128, 255] && boundary_redacted.bytes == [0, 9, 46, 46, 46] &&
            Base64.strict_decode64(utf8_boundary.fetch("secret_base64")).bytes == [0xc3, 0xa9, 46, 46, 46] &&
            Base64.strict_decode64(utf8_mid_rune.fetch("secret_base64")).bytes == [0xc3, 46, 46, 46] &&
            Base64.strict_decode64(utf8_mid_rune.fetch("match_base64")).bytes == "match ".bytes + [0xc3, 46, 46, 46] + " end".bytes &&
            Base64.strict_decode64(utf8_mid_rune.fetch("line_base64")).bytes == "line ".bytes + [0xc3, 46, 46, 46] + " end".bytes)
verify.call(49, "empty-secret-partial-full-over-rune-boundaries",
            by_id.fetch("redact-empty-partial").dig("original", "line_base64") == by_id.fetch("redact-empty-partial").dig("redacted", "line_base64") &&
            by_id.fetch("redact-empty-full-utf8-invalid").dig("redacted", "line_base64") == by_id.fetch("redact-empty-over-hundred-rune-boundaries").dig("redacted", "line_base64"))
full_invariant = by_id.fetch("redact-full-invariant-state")
verify.call(50, "all-public-fields-fragment-required-invariant",
            full_invariant.dig("original", "fragment", "raw_base64") == b64("fragment raw secret") && full_invariant.dig("original", "fragment", "bytes_base64") == "" &&
            full_invariant.dig("original", "required_findings").length == 1 &&
            unchanged.all? { |key| full_invariant.dig("original", key) == full_invariant.dig("redacted", key) })
raw_top = by_id.fetch("redact-ordinary-raw-top-level").fetch("findings").first
decoded_top = by_id.fetch("redact-ordinary-decoded-top-level").fetch("findings").first
verify.call(52, "ordinary-raw-decoded-and-composite-terminal-redaction",
            raw_top["tags_base64"] == [b64("ordinary-tag")] && decoded_top["tags_base64"].map { |tag| Base64.strict_decode64(tag) } == ["ordinary-tag", "decoded:base64", "decode-depth:1"] &&
            decoded_top["line_base64"] == b64(ordinary_encoded) && by_id.fetch("redact-decoded-composite").fetch("findings").length == 1)
malformed_projection = by_id.fetch("malformed-primary-aux-inside-secrets").fetch("findings").first
verify.call(53, "malformed-before-inside-after-primary-aux-exact-slices",
            Base64.strict_decode64(malformed_projection["secret_base64"]).bytes == [128] + "VALUE".bytes &&
            Base64.strict_decode64(malformed_projection.dig("required_findings", 0, "secret_base64")).bytes == [254] + "one".bytes &&
            Base64.strict_decode64(malformed_projection["line_base64"]).bytes.first == 255 && Base64.strict_decode64(malformed_projection["line_base64"]).bytes.last == 255)
verify.call(54, "invalid-byte-ascii-and-unicode-keyword-adjacency",
            decoded_content.call("malformed-adjacent-keyword").bytes.first == 255 && decoded_content.call("malformed-adjacent-unicode-keyword").bytes.first == 255 &&
            by_id.fetch("malformed-adjacent-unicode-keyword").fetch("findings").length == 1)
verify.call(55, "bounded-cartesian-count-and-vector",
            by_id.fetch("resource-primary-aux-duplicate-cartesian").fetch("findings").length == 16 &&
            by_id.fetch("resource-primary-aux-duplicate-cartesian").fetch("findings").all? { |finding| finding["required_findings"].length == 64 })
verify.call(56, "bounded-quadratic-generic-result",
            by_id.fetch("resource-many-generics").fetch("findings").length == 128)
resource_empty = Base64.strict_decode64(by_id.fetch("resource-empty-full-long-malformed").dig("redacted", "line_base64"))
verify.call(57, "bounded-empty-secret-expansion-bytes",
            resource_empty.bytesize < resource_contracts.fetch("resource-empty-full-long-malformed").fetch("output_bytes") && resource_empty.scan("REDACTED".b).length == (512 * 3) + 1)
deep = by_id.fetch("resource-deep-required-graph").fetch("findings").first
deep_missing = by_id.fetch("resource-deep-required-graph-missing-tail").fetch("findings").first
deep_cycle_finding = by_id.fetch("resource-deep-required-cycle").fetch("findings").first
verify.call(58, "deep-missing-tail-and-closed-cycle-under-external-contracts",
            decoded_config.call("resource-deep-required-graph").scan("[[rules]]").length == 64 &&
            decoded_config.call("resource-deep-required-graph-missing-tail").scan("[[rules]]").length == 64 &&
            !decoded_content.call("resource-deep-required-graph-missing-tail").include?("NODE63=VALUE") &&
            decoded_content.call("resource-deep-required-graph-missing-tail").include?("NODE62=VALUE") &&
            deep["rule_id"] == "graph-0" && deep["required_findings"].map { |required| required["rule_id"] } == ["graph-1"] &&
            deep_missing["rule_id"] == "graph-0" && deep_missing["required_findings"].map { |required| required["rule_id"] } == ["graph-1"] &&
            decoded_config.call("resource-deep-required-cycle").scan("[[rules]]").length == 64 &&
            decoded_config.call("resource-deep-required-cycle") == deep_cycle &&
            decoded_config.call("resource-deep-required-cycle").end_with?("[[rules.required]]\nid = \"cycle-0\"\n") &&
            decoded_content.call("resource-deep-required-cycle") == deep_cycle_content &&
            deep_cycle_finding["rule_id"] == "cycle-0" &&
            deep_cycle_finding["required_findings"].map { |required| required["rule_id"] } == ["cycle-1"] &&
            %w[resource-deep-required-graph resource-deep-required-graph-missing-tail resource-deep-required-cycle].all? { |id|
              resource_contracts.fetch(id).values_at("case", "deadline_seconds", "output_bytes", "allocation_bytes") == [58, 10, 4 * 1024 * 1024, 1024 * 1024 * 1024]
            })

reviewed_groups = [3, 5, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20, 22, 23, 25, 26, 31, 32, 33, 36, 39, 40, 41, 42, 43, 45, 47, 48, 49, 50, 52, 53, 54, 55, 56, 57, 58]
abort "material assertion group inventory changed" unless material_assertions.keys.sort == reviewed_groups
abort "material assertion was not unique" unless material_assertions.values.all? { |values| values.length == values.uniq.length && !values.empty? }

all_findings = outcomes.flat_map { |row| row["findings"] }
required_findings = all_findings.flat_map { |row| row["required_findings"] }
coverage = {
  "protocol_version" => PROTOCOL_VERSION, "upstream_revision" => REVISION,
  "default_config_sha256" => DEFAULT_SHA256,
  "behavior_ids" => BEHAVIORS,
  "upstream" => expected_names.map { |name, id| {"test_case_id" => id, "go_name" => name.split(":", 2).last, "classification" => ROOT_IDS.include?(id) ? "aggregator" : "leaf"} },
  "request_ids" => ids,
  "mandatory_cases" => mandatory_cases.map { |number, request_ids| {"number" => number, "request_ids" => request_ids} },
  "material_assertions" => material_assertions.sort.map { |group, assertion_ids| {"number" => group, "assertion_ids" => assertion_ids} },
  "source_order_evidence" => [source_order_evidence],
  "domain_observations" => [{"group" => 22, "classification" => "Go-only-negative-Fragment.StartLine",
                              "request_id" => "proximity-negative-fragment-start", "request_start_line" => -20,
                              "primary_start_line" => -18}],
  "resource_contracts" => resource_contracts.map { |request_id, contract| contract.merge("request_id" => request_id) },
  "exclusions" => ["session ignore/baseline behavior", "report/CLI presentation", "SARIF/JSON/CSV/JUnit rendering", "Rust implementation claims"]
}
negative_controls = {
  "same_count_substitutions" => [
    {"positive" => "pass-both-encoded-same", "negative" => "pass-primary-encoded-aux-raw"},
    {"positive" => "proximity-line-boundary", "negative" => "proximity-line-outside"},
    {"positive" => "proximity-column-boundary", "negative" => "proximity-column-outside"},
    {"positive" => "generic-both-generic-survive", "negative" => "generic-shadow-contained"},
    {"positive" => "aux-marker-ignore-option", "negative" => "aux-marker-reject"}
  ]
}

request_bytes = jsonl(requests)
outcome_bytes = jsonl(outcomes)
coverage_bytes = JSON.pretty_generate(coverage) + "\n"
negative_bytes = JSON.pretty_generate(negative_controls) + "\n"
readme_bytes = <<~MARKDOWN
  # Composite oracle corpus v1

  This directory freezes ordinary-Go observations from Gitleaks
  `#{REVISION}` for required/composite evaluation, generic suppression, and
  redaction. The generator invokes a fresh pinned-Go process
  for each request, verifies exact request identities and semantic branch
  outcomes before writing, and byte-compares fresh results in `--check` mode.

  The corpus contains #{requests.length} requests, #{all_findings.length}
  canonical findings, and #{required_findings.length} required-finding
  attachments. `coverage-v1.json` maps all 58 mandatory semantic groups to
  exact request IDs and records the material assertion executed for each
  reviewed group. Group 12's otherwise unobservable internal stage order is
  explicitly classified as source-order-only against the pinned source hash
  and lines. Group 22's negative `Fragment.StartLine` is an exact Go-only
  domain observation.

  ## Files

  - `requests-v1.jsonl`: versioned detector, redaction, missing-reference, and
    private final-filter probe requests.
  - `outcomes-v1.jsonl`: complete canonical findings, ordered required vectors,
    full locations/byte fields, fragments, and redacted outcomes.
  - `coverage-v1.json`: behavior IDs, exact upstream identities, mandatory
    groups, material assertions, source/domain classifications, and resource
    contracts.
  - `negative-controls-v1.json`: paired same-count substitutions.
  - `manifest-v1.json`: pins, counts, and artifact SHA-256 hashes.

  Group 58 has three separately bounded requests: the all-present 64-node
  chain, a missing-tail counterfactual that still returns `graph-0` with one
  `graph-1` attachment, and a closed 64-node cycle. Each pinned-Go child has a
  10-second deadline, 4 MiB combined per-stream ceiling, and 1 GiB
  `GOMEMLIMIT`; any timeout, overflow, or nonzero exit fails with the request
  ID.

  ## Regeneration

  From the Rust repository root:

  ```sh
  env GOCACHE=/private/tmp/rustleaks-composite-oracle-gocache \
    GOMODCACHE=/private/tmp/rustleaks-go-mod-cache \
    ruby compat/generate_composite_corpus.rb --check
  ```

  The generator refuses a changed upstream revision, default-config hash, or
  sibling status. Ignore/baseline behavior and report/CLI presentation are
  out of scope; the corpus makes no Rust implementation claim.
MARKDOWN
manifest = {
  "protocol_version" => PROTOCOL_VERSION, "upstream_revision" => REVISION, "default_config_sha256" => DEFAULT_SHA256,
  "request_count" => requests.length, "outcome_count" => outcomes.length,
  "finding_count" => all_findings.length, "required_finding_count" => required_findings.length,
  "behavior_count" => BEHAVIORS.length, "leaf_identity_count" => LEAF_IDS.length, "aggregator_identity_count" => ROOT_IDS.length,
  "files" => {
    "requests-v1.jsonl" => sha(request_bytes), "outcomes-v1.jsonl" => sha(outcome_bytes),
    "coverage-v1.json" => sha(coverage_bytes), "negative-controls-v1.json" => sha(negative_bytes),
    "README.md" => sha(readme_bytes)
  }
}
manifest_bytes = JSON.pretty_generate(manifest) + "\n"
files = {"requests-v1.jsonl" => request_bytes, "outcomes-v1.jsonl" => outcome_bytes,
         "coverage-v1.json" => coverage_bytes, "negative-controls-v1.json" => negative_bytes,
         "README.md" => readme_bytes, "manifest-v1.json" => manifest_bytes}

if CHECK
  files.each do |name, bytes|
    path = OUTPUT_ROOT.join(name)
    abort "missing #{path}" unless path.file?
    abort "#{path} differs from fresh Go outcomes" unless path.binread == bytes
  end
  extras = OUTPUT_ROOT.children.select(&:file?).map(&:basename).map(&:to_s) - files.keys
  abort "unexpected corpus files: #{extras.join(', ')}" unless extras.empty?
else
  FileUtils.mkdir_p(OUTPUT_ROOT)
  files.each { |name, bytes| OUTPUT_ROOT.join(name).binwrite(bytes) }
end

puts JSON.pretty_generate(manifest)
