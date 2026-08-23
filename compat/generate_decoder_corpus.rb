#!/usr/bin/env ruby
# frozen_string_literal: true

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
OUTPUT_ROOT = ROOT.join("compat/decoder-corpus")
MANIFEST = ROOT.join("compat/test-manifest.toml")
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
DEFAULT_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
EXPECTED_UPSTREAM_STATUS = ""
PROTOCOL_VERSION = 1
BEHAVIOR_IDS = ((1..13).map { |index| format("DEC-%03d", index) } +
  %w[COMP-003 COMP-004 COMP-005 COMP-006]).sort.freeze
LEAF_IDS = (187..240).map { |index| format("TM-%04d", index) }.freeze
ROOT_ID = "TM-0186"
DETECT_ID = "TM-0078"
CHECK = ARGV.delete("--check")
abort "usage: #{$PROGRAM_NAME} [--check]" unless ARGV.empty?

GO_ENV = {
  "GOCACHE" => ENV.fetch("GOCACHE", File.join(Dir.tmpdir, "rustleaks-m6-oracle-gocache")),
  "GOMODCACHE" => ENV.fetch("GOMODCACHE", File.join(Dir.tmpdir, "rustleaks-go-mod-cache"))
}.freeze

TESTS = [
  ["only b64 chunk", "bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=", "longer-encoded-secret-test"],
  ["mixed content", "token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=", "token: longer-encoded-secret-test"],
  ["no chunk", "", ""],
  ["env var (looks like all b64 decodable but has `=` in the middle)", "some-encoded-secret=dGVzdC1zZWNyZXQtdmFsdWU=", "some-encoded-secret=test-secret-value"],
  ["has longer b64 inside", 'some-encoded-secret="bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q="', 'some-encoded-secret="longer-encoded-secret-test"'],
  ["many possible i := 0substrings", "Many substrings in this slack message could be base64 decoded\n\t\t\t\tbut only dGhpcyBlbmNhcHN1bGF0ZWQgc2VjcmV0 should be decoded.", "Many substrings in this slack message could be base64 decoded\n\t\t\t\tbut only this encapsulated secret should be decoded."],
  ["b64-url-safe: only b64 chunk", "bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q", "longer-encoded-secret-test"],
  ["b64-url-safe: mixed content", "token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q", "token: longer-encoded-secret-test"],
  ["b64-url-safe: env var (looks like all b64 decodable but has `=` in the middle)", "some-encoded-secret=dGVzdC1zZWNyZXQtdmFsdWU=", "some-encoded-secret=test-secret-value"],
  ["b64-url-safe: has longer b64 inside", 'some-encoded-secret="bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q"', 'some-encoded-secret="longer-encoded-secret-test"'],
  ["b64-url-safe: hyphen url b64", "Z2l0bGVha3M-PmZpbmRzLXNlY3JldHM", "gitleaks>>finds-secrets"],
  ["b64-url-safe: underscore url b64", "YjY0dXJsc2FmZS10ZXN0LXNlY3JldC11bmRlcnNjb3Jlcz8_", "b64urlsafe-test-secret-underscores??"],
  ["invalid base64 string", "a3d3fa7c2bb99e469ba55e5834ce79ee4853a8a3", "a3d3fa7c2bb99e469ba55e5834ce79ee4853a8a3"],
  ["url encoded value", "secret%3D%22q%24%21%40%23%24%25%5E%26%2A%28%20asdf%22", 'secret="q$!@#$%^&*( asdf"'],
  ["hex encoded value", 'secret="466973684D617048756E6B79212121363334"', 'secret="FishMapHunky!!!634"'],
  ["unicode encoded value", "secret=U+0061 U+0062 U+0063 U+0064 U+0065 U+0066", "secret=abcdef"],
  ["unicode encoded value backslashed", 'secret=\\\\u0068\\\\u0065\\\\u006c\\\\u006c\\\\u006f\\\\u0020\\\\u0077\\\\u006f\\\\u0072\\\\u006c\\\\u0064\\\\u0020\\\\u0064\\\\u0075\\\\u0064\\\\u0065', "secret=hello world dude"],
  ["unicode encoded value backslashed mixed w/ hex", 'secret=\\u0068\\u0065\\u006c\\u006c\\u006f\\u0020\\u0077\\u006f\\u0072\\u006c\\u0064 6C6F76656C792070656F706C65206F66206561727468', "secret=hello world lovely people of earth"]
].freeze

def capture(*command, chdir:, stdin_data: "")
  output, error, status = Open3.capture3(GO_ENV, *command, chdir: chdir.to_s, stdin_data: stdin_data)
  abort "#{command.join(' ')} failed in #{chdir}:\n#{error}\n#{output}" unless status.success?
  output
end

def sha(bytes)
  Digest::SHA256.hexdigest(bytes.b)
end

def b64(bytes)
  Base64.strict_encode64(bytes.b)
end

def jsonl(rows)
  rows.map { |row| JSON.generate(row) + "\n" }.join
end

# Exact net/url.PathEscape encodePathSegment rules used by TestDecode.
def path_escape(value)
  safe = /[A-Za-z0-9\-_.~$&+:=@]/
  value.b.bytes.map do |byte|
    character = byte.chr
    character.match?(safe) ? character : format("%%%02X", byte)
  end.join
end

def noncanonical_trailing_bits(encoded, urlsafe: false)
  alphabet = urlsafe ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" :
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  padding = encoded.end_with?("==") ? 2 : (encoded.end_with?("=") ? 1 : 0)
  index = encoded.length - padding - 1
  value = alphabet.index(encoded[index])
  abort "trailing-bit fixture is not base64" unless value
  unused_bits = if padding == 2 || (padding == 0 && encoded.length % 4 == 2)
                  4
                elsif padding == 1 || (padding == 0 && encoded.length % 4 == 3)
                  2
                else
                  abort "fixture has no trailing pad bits"
                end
  abort "fixture is already noncanonical" unless (value & ((1 << unused_bits) - 1)).zero?
  mutated = encoded.dup
  mutated[index] = alphabet[value + 1]
  mutated
end

def base64_with_likelihood_character(character)
  urlsafe = %w[- _].include?(character)
  (0x20..0x7e).each do |left|
    (0x20..0x7e).each do |right|
      source = ([left, right].pack("C*") * 6).b
      encoded = urlsafe ? Base64.urlsafe_encode64(source, padding: false) : Base64.strict_encode64(source)
      return encoded if encoded.include?(character)
    end
  end
  abort "could not construct base64 likelihood fixture for #{character.inspect}"
end

def decode_request(id:, behaviors:, input: nil, inputs: nil, test_ids: [], probes: [], pass_limit: 64,
                   decoder_scope: "shared", carry_predecessors: false)
  {
    "protocol_version" => PROTOCOL_VERSION,
    "id" => id,
    "behavior_ids" => behaviors,
    "test_case_ids" => test_ids,
    "operation" => "decode",
    "inputs_base64" => (inputs || [input]).map { |value| b64(value) },
    "decoder_scope" => decoder_scope,
    "carry_predecessors_across_inputs" => carry_predecessors,
    "pass_limit" => pass_limit,
    "probe_ranges" => probes
  }
end

def detect_request(id:, behaviors:, content:, depth:, test_ids: [], fixture: nil, config: nil,
                   file: "tmp.go", commit: "", repeat_count: 1, inherited: false)
  abort "#{id}: one config source required" unless [fixture, config].compact.length == 1
  {
    "protocol_version" => PROTOCOL_VERSION,
    "id" => id,
    "behavior_ids" => behaviors,
    "test_case_ids" => test_ids,
    "operation" => "detect",
    "config_fixture" => fixture || "",
    "config_base64" => config ? b64(config) : "",
    "fragment" => {
      "content_base64" => b64(content), "file_base64" => b64(file),
      "windows_file_base64" => "", "symlink_file_base64" => "", "commit_base64" => b64(commit),
      "start_line" => 0, "author_base64" => "", "email_base64" => "", "date_base64" => "",
      "message_base64" => "", "remote_url_base64" => "", "remote_platform" => "",
      "inherited_from_finding" => inherited
    },
    "options" => {
      "max_decode_depth" => depth, "max_target_megabytes" => 0,
      "redact_percent" => 0, "ignore_allow_marker" => false
    },
    "detect_repeat_count" => repeat_count
  }
end

def simple_rule_config(id:, regex:, secret_group: 0, keywords: nil, tags: nil, entropy: nil,
                       rule_allowlist: nil, global_allowlist: nil, required: nil, skip_report: false)
  lines = ["[[rules]]", "id = #{JSON.generate(id)}", "regex = #{JSON.generate(regex)}"]
  lines << "secretGroup = #{secret_group}" unless secret_group.zero?
  lines << "keywords = #{JSON.generate(keywords)}" unless keywords.nil?
  lines << "tags = #{JSON.generate(tags)}" unless tags.nil?
  lines << "entropy = #{entropy}" unless entropy.nil?
  lines << "skipReport = true" if skip_report
  lines << required unless required.nil?
  lines << rule_allowlist unless rule_allowlist.nil?
  lines << global_allowlist unless global_allowlist.nil?
  lines.join("\n") + "\n"
end

manifest_cases = MANIFEST.read.scan(/\[\[case\]\]\nid = "(TM-\d+)"\npackage = "detect\/codec"\ngo_name = "(TestDecode[^"]*)"/).to_h { |id, name| [name, id] }
abort "decoder manifest identity count changed: #{manifest_cases.length}" unless manifest_cases.length == 55
abort "decoder root identity changed" unless manifest_cases.fetch("TestDecode") == ROOT_ID

requests = []
TESTS.each do |name, input, expected|
  manifest_name = name.tr(" ", "_")
  case_behaviors = if name.include?("unicode")
                     %w[DEC-001 DEC-003]
                   elsif name.include?("hex encoded")
                     %w[DEC-001 DEC-004]
                   elsif name.include?("url encoded")
                     %w[DEC-001 DEC-002]
                   elsif name == "no chunk"
                     %w[DEC-001]
                   elsif name.include?("invalid base64")
                     %w[DEC-001 DEC-004 DEC-005 DEC-009]
                   else
                     %w[DEC-001 DEC-005]
                   end
  variants = [
    ["direct", input, "TestDecode/#{manifest_name}"],
    ["path-escape", path_escape(input), "TestDecode/#{manifest_name}#01"],
    ["hex", input.b.unpack1("H*"), "TestDecode/#{manifest_name}#02"]
  ]
  variants.each do |variant, transformed, go_name|
    tm = manifest_cases.fetch(go_name)
    requests << decode_request(
      id: "upstream-#{tm.downcase}-#{variant}",
      behaviors: (case_behaviors + (variant == "path-escape" ? ["DEC-002"] : []) + (variant == "hex" ? ["DEC-004"] : [])).uniq,
      input: transformed, test_ids: [tm]
    ).merge(
      "source_case" => name, "source_variant" => variant,
      "source_base64" => b64(input), "source_transform" => variant,
      "expected_full_decode_base64" => b64(expected)
    )
  end
end

# Cache reuse is observable through identical semantic results, including the
# cached empty decode for a rejected candidate, all within one Decoder object.
requests << decode_request(id: "cache-repeat-success", behaviors: ["DEC-001"],
                           inputs: ["dGhpcy1pcy1hLXNlY3JldA=="] * 3)
requests << decode_request(id: "cache-repeat-empty", behaviors: ["DEC-001", "DEC-005", "DEC-009"],
                           inputs: ["AAAAAAAAAAAAAAAA"] * 3)
requests << decode_request(id: "cache-empty-input", behaviors: ["DEC-001", "DEC-009"], inputs: [""] * 2)

focused = {
  # Percent grammar, partial/scattered decoding, malformed and byte boundaries.
  "percent-single" => ["%41", %w[DEC-002]],
  "percent-min-minus-one" => ["%4", %w[DEC-002]],
  "percent-min-plus-one" => ["x%41", %w[DEC-002]],
  "percent-scattered" => ["x%41y%42z", %w[DEC-002 DEC-007]],
  "percent-lowercase" => ["%7e", %w[DEC-002]],
  "percent-tab-printable" => ["%09", %w[DEC-002 DEC-009]],
  "percent-del-printability-reject" => ["%7f", %w[DEC-002 DEC-009]],
  "percent-control-reject" => ["%08", %w[DEC-002 DEC-009]],
  "percent-malformed-short" => ["%4", %w[DEC-002 DEC-009]],
  "percent-malformed-nonhex" => ["%GG", %w[DEC-002 DEC-009]],
  "percent-invalid-utf8-literal" => [[0xff, 0x25, 0x34, 0x31].pack("C*"), %w[DEC-002 DEC-009]],
  "percent-copied-invalid-byte-inside" => [[0x25, 0x34, 0x31, 0xff, 0x25, 0x34, 0x32].pack("C*"), %w[DEC-002 DEC-009]],
  "percent-broad-reject-blocks-base64" => ["%7fdGhpcy1pcy0xMjM=%41", %w[DEC-002 DEC-005 DEC-006 DEC-009]],
  "percent-greedy-same-line" => ["%41middle%zztail%42", %w[DEC-002]],
  "percent-does-not-cross-lf" => ["%41\n%42", %w[DEC-002 DEC-008]],
  "percent-incomplete-copied-inside" => ["%41%4%42", %w[DEC-002 DEC-009]],
  "percent-lf-printable" => ["%0a", %w[DEC-002 DEC-009]],
  "percent-tilde-printable" => ["%7e", %w[DEC-002 DEC-009]],
  "percent-wrap-base64-success" => ["%64Ghpcy1pcy0xMjM%30", %w[DEC-001 DEC-002 DEC-005 DEC-006]],
  "percent-wrap-hex-success" => ["%33" + "031323334353637383961626364656" + "%36", %w[DEC-001 DEC-002 DEC-004 DEC-006]],
  # Unicode code-point/escape forms, mixed forms, case, whitespace, and
  # non-ASCII/control output (Unicode deliberately has no printable guard).
  "unicode-codepoint" => ["U+0041", %w[DEC-003]],
  "unicode-min-minus-one" => ["U+061", %w[DEC-003 DEC-009]],
  "unicode-min-plus-one" => ["xU+0061", %w[DEC-003]],
  "unicode-eof" => ["U+0061", %w[DEC-003]],
  "unicode-space" => ["U+0061 ", %w[DEC-003]],
  "unicode-tab" => ["U+0061\t", %w[DEC-003 DEC-008]],
  "unicode-lf" => ["U+0061\n", %w[DEC-003 DEC-008]],
  "unicode-two-spaces" => ["U+0061  ", %w[DEC-003 DEC-008]],
  "unicode-lowercase-codepoint-rejected" => ["u+0061", %w[DEC-003 DEC-009]],
  "unicode-codepoint-fifth-digit" => ["U+00610", %w[DEC-003 DEC-009]],
  "unicode-codepoint-sequence" => ["U+0041 U+0042 U+0043", %w[DEC-003 DEC-007]],
  "unicode-single-slash" => ['\\u0041\\u0042', %w[DEC-003]],
  "unicode-double-slash" => ['\\\\u0041\\\\u0042', %w[DEC-003]],
  "unicode-case-insensitive-u" => ['\\U0041', %w[DEC-003]],
  "unicode-mixed-forms" => ['U+0041 \\u0042', %w[DEC-003]],
  "unicode-nonascii" => ['\\u00e9', %w[DEC-003 DEC-009]],
  "unicode-nul" => ['\\u0000', %w[DEC-003 DEC-009]],
  "unicode-surrogate" => ['\\ud800', %w[DEC-003 DEC-009]],
  "unicode-surrogate-pair-not-combined" => ['\\ud83d\\ude00', %w[DEC-003 DEC-009]],
  "unicode-three-backslashes" => ['\\\\\\u0041', %w[DEC-003]],
  "unicode-four-backslashes" => ['\\\\\\\\u0041', %w[DEC-003]],
  "unicode-escape-trailing-ascii" => ['\\u0061Z', %w[DEC-003]],
  "unicode-escapes-separated" => ['\\u0061 \\u0062', %w[DEC-003 DEC-008]],
  "unicode-escapes-contiguous" => ['\\u0061\\u0062', %w[DEC-003]],
  "unicode-codepoint-u0008" => ["U+0008", %w[DEC-003 DEC-009]],
  "unicode-codepoint-u0009" => ["U+0009", %w[DEC-003 DEC-009]],
  "unicode-codepoint-u007e" => ["U+007e", %w[DEC-003 DEC-009]],
  "unicode-codepoint-u007f" => ["U+007f", %w[DEC-003 DEC-009]],
  "unicode-codepoint-u00e9" => ["U+00e9", %w[DEC-003 DEC-009]],
  "unicode-codepoint-ud800" => ["U+d800", %w[DEC-003 DEC-009]],
  "unicode-codepoint-udfff" => ["U+dfff", %w[DEC-003 DEC-009]],
  "unicode-fifth-hex-digit" => ['\\u00411', %w[DEC-003 DEC-009]],
  "unicode-malformed-width" => ['\\u041', %w[DEC-003 DEC-009]],
  # Hex threshold, digit heuristic, odd length, printability, and case.
  "hex-minimum" => ["30313233343536373839616263646566", %w[DEC-004]],
  "hex-under-minimum" => ["3031323334353637383961626364656", %w[DEC-004]],
  "hex-uppercase" => ["4142434445464748494A4B4C4D4E4F50", %w[DEC-004]],
  "hex-no-digit-heuristic" => ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", %w[DEC-004]],
  "hex-odd-length" => ["303132333435363738396162636465666", %w[DEC-004 DEC-009]],
  "hex-length-34" => ["3031323334353637383961626364656667", %w[DEC-004]],
  "hex-lowercase-pairs" => ["6162636465666768696a6b6c6d6e6f70", %w[DEC-004]],
  "hex-one-digit-likelihood" => ["61616161616161616161616161616161", %w[DEC-004]],
  "hex-nonprint-first" => ["08" + "61" * 15, %w[DEC-004 DEC-009]],
  "hex-nonprint-middle" => ["61" * 7 + "08" + "61" * 8, %w[DEC-004 DEC-009]],
  "hex-nonprint-last" => ["61" * 15 + "08", %w[DEC-004 DEC-009]],
  "hex-lf-printable" => ["0a" * 16, %w[DEC-004 DEC-009]],
  "hex-tilde-printable" => ["7e" * 16, %w[DEC-004 DEC-009]],
  "hex-tab-printable" => ["09090909090909090909090909090909", %w[DEC-004 DEC-009]],
  "hex-control-reject" => ["08080808080808080808080808080808", %w[DEC-004 DEC-009]],
  "hex-del-reject" => ["7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", %w[DEC-004 DEC-009]],
  # Base64 threshold/alphabets/padding/heuristic/printability.
  "base64-minimum-padded" => ["dGhpcy1pcy0xMjM=", %w[DEC-005]],
  "base64-under-minimum" => ["dGhpcy1pcy0xMjM", %w[DEC-005]],
  "base64-length-16" => ["dGhpcy1pcy0xMjM0", %w[DEC-005]],
  "base64-length-17" => ["dGhpcy1pcy0xMjM0N", %w[DEC-005 DEC-009]],
  "base64-standard" => [Base64.strict_encode64("printable+123/456"), %w[DEC-005]],
  "base64-raw-url" => [Base64.urlsafe_encode64("printable-123_456", padding: false), %w[DEC-005]],
  "base64-no-likely-byte" => ["QUJDREVGR0hJSktM", %w[DEC-005]],
  "base64-bad-padding" => ["dGhpcy1pcy0xMjM===", %w[DEC-005 DEC-009]],
  "base64-tab-printable" => [Base64.strict_encode64("\t" * 9 + "-14"), %w[DEC-005 DEC-009]],
  "base64-control-reject" => [Base64.strict_encode64("\b" * 9 + "-14"), %w[DEC-005 DEC-009]],
  "base64-del-reject" => [Base64.strict_encode64("\x7f" * 9 + "-0"), %w[DEC-005 DEC-009]],
  "base64-lf-printable" => [Base64.strict_encode64("\n" * 9 + "-14"), %w[DEC-005 DEC-009]],
  "base64-tilde-printable" => [Base64.strict_encode64("~" * 9 + "123"), %w[DEC-005 DEC-009]],
  "base64-standard-pad2-canonical" => [Base64.strict_encode64("this-is-12345"), %w[DEC-005]],
  "base64-standard-pad2-noncanonical" => [noncanonical_trailing_bits(Base64.strict_encode64("this-is-12345")), %w[DEC-005]],
  "base64-standard-pad1-canonical" => [Base64.strict_encode64("this-is-123456"), %w[DEC-005]],
  "base64-standard-pad1-noncanonical" => [noncanonical_trailing_bits(Base64.strict_encode64("this-is-123456")), %w[DEC-005]],
  "base64-raw-url-pad2-canonical" => [Base64.urlsafe_encode64("this-is-12345", padding: false), %w[DEC-005]],
  "base64-raw-url-pad2-noncanonical" => [noncanonical_trailing_bits(Base64.urlsafe_encode64("this-is-12345", padding: false), urlsafe: true), %w[DEC-005]],
  "base64-raw-url-pad1-canonical" => [Base64.urlsafe_encode64("this-is-123456", padding: false), %w[DEC-005]],
  "base64-raw-url-pad1-noncanonical" => [noncanonical_trailing_bits(Base64.urlsafe_encode64("this-is-123456", padding: false), urlsafe: true), %w[DEC-005]],
  "base64-unpadded-standard-plus-rejected" => ["QUFBQUFBQUFBQUF+LQ", %w[DEC-005 DEC-009]],
  "base64-padded-url-rejected" => ["YjY0dXJsc2FmZS0xMjM_==", %w[DEC-005 DEC-009]],
  "base64-mixed-alphabet-rejected" => ["QUFBQUFBQUFBQUF+LQ_", %w[DEC-005 DEC-009]],
  # Combined-regex precedence and inclusive overlap/touching behavior.
  "precedence-percent-over-base64" => ["ZGVjb2%52lZC1zZWNyZXQtdmFsdWU=", %w[DEC-006 DEC-007]],
  "precedence-percent-over-hex" => ["6465636F%36%34%36%35%36%34", %w[DEC-006 DEC-007]],
  "touch-percent-hex" => ["%4130313233343536373839616263646566", %w[DEC-006 DEC-007]],
  "touch-percent-before-base64" => ["%41dGhpcy1pcy0xMjM0", %w[DEC-006]],
  "touch-base64-before-percent" => ["dGhpcy1pcy0xMjM0%41", %w[DEC-006]],
  "touch-unicode-before-hex" => ["U+0041 30313233343536373839616263646566", %w[DEC-003 DEC-004 DEC-006]],
  "touch-equal-base64" => ["dGhpcy1pcy0xMjM=dGhhdC1pcy00NTY=", %w[DEC-005 DEC-006]],
  "touch-three-precedence-neighbors" => ["%41U+0042 dGhpcy1pcy0xMjM=", %w[DEC-002 DEC-003 DEC-005 DEC-006 DEC-007]],
  "touch-two-percent-segments" => ["%41%42", %w[DEC-006 DEC-007]],
  "adjacent-base64-values" => ["dGhpcy1pcy0xMjM= dGhhdC1pcy00NTY=", %w[DEC-006 DEC-007 DEC-008]],
  "multiline-current-line" => ["before\nkey=dGhpcy1pcy0xMjM=\nafter", %w[DEC-007 DEC-008]],
  "multi-line-spanning-percent" => ["before%0Aafter%09tail", %w[DEC-002 DEC-007 DEC-008]],
  "arbitrary-bytes" => [[0x00, 0xff, 0x80, 0x25, 0x34, 0x31].pack("C*"), %w[DEC-009]],
  "nested-base64" => [Base64.strict_encode64(Base64.strict_encode64("decoded-secret-123")), %w[DEC-001 DEC-005 DEC-007 DEC-008]],
  "nested-percent-base64" => [path_escape(Base64.strict_encode64("decoded-secret-123")), %w[DEC-001 DEC-002 DEC-005 DEC-007 DEC-008]]
}.freeze
focused.each do |id, (input, behaviors)|
  requests << decode_request(id: id, behaviors: behaviors, input: input,
                             probes: [[0, input.bytesize], [0, 0], [input.bytesize, input.bytesize]])
end

%w[0 1 2 3 4 5 6 7 8 9 + / - _].each do |character|
  requests << decode_request(id: "base64-likelihood-#{character.ord}", behaviors: %w[DEC-005],
                             input: base64_with_likelihood_character(character))
end

# Same-start alternation ownership: the hex branch wins before base64 even when
# its decoder later rejects the maximal candidate.
requests << decode_request(id: "same-start-hex-base64-success", behaviors: %w[DEC-004 DEC-005 DEC-006],
                           input: "30313233343536373839616263646566")
requests << decode_request(id: "same-start-hex-base64-likelihood-failure", behaviors: %w[DEC-004 DEC-005 DEC-006],
                           input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
requests << decode_request(id: "same-start-hex-base64-odd-failure", behaviors: %w[DEC-004 DEC-005 DEC-006],
                           input: "303132333435363738396162636465666")
requests << decode_request(id: "same-start-hex-base64-printability-failure", behaviors: %w[DEC-004 DEC-005 DEC-006 DEC-009],
                           input: "08" + "61" * 15)

# Cache and ownership observations use the extended oracle projection rather
# than timing. The deeper reappearance has the exact first-pass key both before
# and after pass two. Isolated scope constructs a fresh Decoder per run.
cache_key = "dGhpcy1pcy0xMjM0"
requests << decode_request(id: "cache-two-successes-one-pass", behaviors: %w[DEC-001 DEC-007],
                           input: "#{cache_key} #{cache_key}")
requests << decode_request(id: "cache-two-failures-one-pass", behaviors: %w[DEC-001 DEC-005],
                           input: "AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA")
requests << decode_request(id: "cache-key-reappears-deeper", behaviors: %w[DEC-001 DEC-007],
                           input: "#{cache_key} #{Base64.strict_encode64(cache_key)}")
requests << decode_request(id: "cache-shared-instance", behaviors: %w[DEC-001],
                           inputs: [cache_key, cache_key], decoder_scope: "shared")
requests << decode_request(id: "cache-isolated-instances", behaviors: %w[DEC-001],
                           inputs: [cache_key, cache_key], decoder_scope: "isolated")
requests << decode_request(id: "cache-carried-unrelated-global-depth", behaviors: %w[DEC-001 DEC-007 DEC-008],
                           inputs: [("x" * 32) + "%41", cache_key], pass_limit: 1,
                           decoder_scope: "shared", carry_predecessors: true)

# Explicit public mapping geometry. Colons are outside every candidate grammar,
# so the first decoded output is "pre:this-is-1234:post" with its segment at
# [4,16) and cannot be swallowed by adjacent base64 letters.
mapping_input = "pre:#{cache_key}:post"
mapping_probes = [[6, 10], [2, 6], [14, 18], [2, 18], [0, 2], [0, 4], [16, 21]]
requests << decode_request(id: "mapping-contained-left-right-both-none-touch", behaviors: %w[DEC-007 DEC-008],
                           input: mapping_input, probes: mapping_probes)
second_cache_key = Base64.urlsafe_encode64("that-is-4567", padding: false)
two_mapping_input = "A:#{cache_key}:MID:#{second_cache_key}:Z"
requests << decode_request(id: "mapping-two-segments-shift-span", behaviors: %w[DEC-007 DEC-008],
                           input: two_mapping_input, probes: [[2, 24]])
requests << decode_request(id: "mapping-success-failure-success-shifts", behaviors: %w[DEC-001 DEC-007],
                           input: "A:#{cache_key}: AAAAAAAAAAAAAAAA :30313233343536373839616263646566:Z")

# CurrentLine geometry uses the public helper on every pass.
requests << decode_request(id: "line-segment-at-byte-zero", behaviors: %w[DEC-008], input: cache_key)
requests << decode_request(id: "line-segment-after-lf", behaviors: %w[DEC-008], input: "before\n#{cache_key}:after")
requests << decode_request(id: "line-segment-before-lf", behaviors: %w[DEC-008], input: "#{cache_key}\nafter")
requests << decode_request(id: "line-segment-decodes-to-lf", behaviors: %w[DEC-002 DEC-008], input: "before%0Aafter")
requests << decode_request(id: "line-selected-segments-separate-lines", behaviors: %w[DEC-008],
                           input: "#{cache_key}\nmiddle\n#{second_cache_key}")

# A later pass receives an unrelated predecessor slice explicitly through the
# public Decode argument, proving pass-global depth with no encoding-bit union.
requests << decode_request(id: "outer-all-letter-likelihood-stops-recursion", behaviors: %w[DEC-001 DEC-005],
                           input: "ZENRbGVtcDRSMVpJWUhnNQ==")

# Bounded adversarial strings keep corpus generation safe while freezing the
# asymptotic surfaces of greedy percent and long candidate regexes.
requests << decode_request(id: "resource-percent-4096", behaviors: %w[DEC-002 DEC-013], input: "%41" * 4096)
requests << decode_request(id: "resource-hex-16384", behaviors: %w[DEC-004 DEC-013], input: "41" * 8192)
requests << decode_request(id: "resource-base64-16384", behaviors: %w[DEC-005 DEC-013],
                           input: Base64.strict_encode64("this-is-1234" * 1024))

detect_source = UPSTREAM.join("detect/detect_test.go").binread
encoded_match = detect_source.match(/const encodedTestValues = `(?<value>.*?)`\n\nvar multili/m)
abort "pinned encodedTestValues constant not found" unless encoded_match
encoded_values = encoded_match[:value]
encoded_config = UPSTREAM.join("testdata/config/encoded.toml").binread

(0..8).each do |depth|
  requests << detect_request(
    id: "detect-encoded-depth-#{depth}", behaviors: %w[DEC-010 DEC-011],
    content: encoded_values, depth: depth, fixture: "encoded.toml",
    test_ids: depth == 8 ? [DETECT_ID] : []
  ).merge("source_constant_sha256" => sha(encoded_values), "source_config_sha256" => sha(encoded_config))
end
requests << detect_request(
  id: "detect-encoded-depth-negative-one", behaviors: %w[DEC-001 DEC-010 DEC-011],
  content: encoded_values, depth: -1, fixture: "encoded.toml"
).merge("rust_depth_adapter_expected" => 0)

exhaustion_config = simple_rule_config(id: "exhaustion", regex: "decoded-secret-123")
requests << detect_request(id: "detect-exhaustion-before-huge-depth", behaviors: %w[DEC-001 DEC-010],
                           content: Base64.strict_encode64("decoded-secret-123"), depth: 127,
                           config: exhaustion_config)

line_config = lambda do |allowed|
  pattern = allowed ? "^prefix TOKEN=VALUE! suffix$" : "^does-not-match$"
  <<~TOML
    [[rules]]
    id = "decoded-line"
    regex = '''TOKEN=(VALUE!)'''
    secretGroup = 1
      [[rules.allowlists]]
      regexTarget = "line"
      regexes = [#{JSON.generate(pattern)}]
  TOML
end
decoded_line_input = "prefix VE9LRU49VkFMVUUh suffix"
requests << detect_request(id: "decoded-line-allowlist-positive", behaviors: %w[DEC-010 DEC-012],
                           content: decoded_line_input, depth: 1, config: line_config.call(true))
requests << detect_request(id: "decoded-line-allowlist-negative", behaviors: %w[DEC-010 DEC-012],
                           content: decoded_line_input, depth: 1, config: line_config.call(false))

duplicate_config = <<~TOML
  [[rules]]
  id = "duplicate-pass"
  regex = '''small-secret'''
TOML
requests << detect_request(id: "duplicates-across-passes", behaviors: %w[DEC-010 DEC-011],
                           content: "small-secret c21hbGwtc2VjcmV0", depth: 1, config: duplicate_config)

touch_duplicate_config = <<~TOML
  [[rules]]
  id = "inclusive-touch-duplicate"
  regex = '''token='''
TOML
requests << detect_request(id: "inclusive-touch-unchanged-duplicate", behaviors: %w[DEC-006 DEC-008 DEC-010 DEC-011],
                           content: "token=QUFBQUFBQUFBQUF0", depth: 1, config: touch_duplicate_config)

touch_after_config = simple_rule_config(id: "inclusive-touch-after", regex: "suffix")
requests << detect_request(id: "inclusive-touch-after-duplicate", behaviors: %w[DEC-006 DEC-008 DEC-010 DEC-011],
                           content: "#{cache_key}suffix", depth: 1, config: touch_after_config)

all_tags_input = "%54 \\u004f 30313233343536373839616263646566 #{cache_key} END"
all_tags_regex = "T O 0123456789abcdef this-is-1234 END"
all_tags_config = simple_rule_config(id: "all-tags", regex: all_tags_regex, tags: ["rule-tag"])
requests << detect_request(id: "finding-all-four-encoding-tags", behaviors: %w[DEC-003 DEC-004 DEC-005 DEC-008 DEC-011],
                           content: all_tags_input, depth: 1, config: all_tags_config)
requests << detect_request(id: "rule-tags-state-reuse", behaviors: %w[DEC-008 DEC-011],
                           content: all_tags_input, depth: 1, config: all_tags_config, repeat_count: 3)

# Per-pass keyword matrix.
decoded_keyword_config = simple_rule_config(id: "keyword-decoded", regex: "decoded-secret-123",
                                            keywords: ["decoded"])
requests << detect_request(id: "keyword-absent-raw-present-decoded", behaviors: %w[DEC-010 DEC-011],
                           content: Base64.strict_encode64("decoded-secret-123"), depth: 1,
                           config: decoded_keyword_config)
raw_keyword_config = simple_rule_config(id: "keyword-raw", regex: cache_key, keywords: ["dghp"])
requests << detect_request(id: "keyword-present-raw-absent-decoded", behaviors: %w[DEC-010 DEC-011],
                           content: cache_key, depth: 1, config: raw_keyword_config)
unicode_keyword = "ÉCOLE"
unicode_keyword_input = unicode_keyword.each_codepoint.map { |codepoint| format("\\u%04x", codepoint) }.join
unicode_keyword_config = simple_rule_config(id: "keyword-unicode-fold", regex: unicode_keyword,
                                            keywords: ["école"])
requests << detect_request(id: "keyword-unicode-case-folded", behaviors: %w[DEC-003 DEC-010 DEC-011],
                           content: unicode_keyword_input, depth: 1, config: unicode_keyword_config)
no_keyword_config = simple_rule_config(id: "no-keywords-every-pass", regex: "token=")
requests << detect_request(id: "keyword-none-every-pass", behaviors: %w[DEC-010 DEC-011],
                           content: "token=QUFBQUFBQUFBQUF0", depth: 1, config: no_keyword_config)

# Original-line marker matrix.
marker_config = simple_rule_config(id: "marker", regex: "SECRET-VALUE")
marker_encoded = Base64.strict_encode64("SECRET-VALUE")
requests << detect_request(id: "marker-original-same-line", behaviors: %w[DEC-010 DEC-011],
                           content: "#{marker_encoded} gitleaks:allow", depth: 1, config: marker_config)
requests << detect_request(id: "marker-decoded-only", behaviors: %w[DEC-010 DEC-011],
                           content: Base64.strict_encode64("SECRET-VALUE gitleaks:allow"), depth: 1,
                           config: marker_config)
requests << detect_request(id: "marker-neighboring-original-line", behaviors: %w[DEC-010 DEC-011],
                           content: "#{marker_encoded}\ngitleaks:allow", depth: 1, config: marker_config)
requests << detect_request(id: "marker-previous-line-currentline-quirk", behaviors: %w[DEC-008 DEC-010 DEC-011],
                           content: "gitleaks:allow\n#{marker_encoded}", depth: 1, config: marker_config)

# Capture selection and strict entropy ordering on a decoded secret whose
# Shannon entropy is exactly 3.0.
entropy_payload = "prefix TOKEN=ABCD1234 suffix"
entropy_encoded = Base64.strict_encode64(entropy_payload)
entropy_equal_config = simple_rule_config(id: "entropy-equal", regex: "prefix TOKEN=([A-Za-z0-9]+) suffix",
                                          secret_group: 1, entropy: 3.0)
entropy_below_config = simple_rule_config(id: "entropy-below", regex: "prefix TOKEN=([A-Za-z0-9]+) suffix",
                                          secret_group: 1, entropy: 2.99)
requests << detect_request(id: "decoded-capture-entropy-equal-reject", behaviors: %w[DEC-010 DEC-011],
                           content: entropy_encoded, depth: 1, config: entropy_equal_config)
requests << detect_request(id: "decoded-capture-entropy-below-report", behaviors: %w[DEC-010 DEC-011],
                           content: entropy_encoded, depth: 1, config: entropy_below_config)

# Decoded secret/match/line versus original-line allowlist target matrix.
allowlist_rule = lambda do |target, pattern|
  table = "[[rules.allowlists]]\nregexTarget = #{JSON.generate(target)}\nregexes = [#{JSON.generate(pattern)}]"
  simple_rule_config(id: "allow-#{target}", regex: "prefix TOKEN=([A-Za-z0-9]+) suffix",
                     secret_group: 1, rule_allowlist: table)
end
requests << detect_request(id: "allow-target-decoded-secret", behaviors: %w[DEC-010 DEC-012],
                           content: entropy_encoded, depth: 1,
                           config: allowlist_rule.call("secret", "^ABCD1234$"))
requests << detect_request(id: "allow-target-decoded-match", behaviors: %w[DEC-010 DEC-012],
                           content: entropy_encoded, depth: 1,
                           config: allowlist_rule.call("match", "^prefix TOKEN=ABCD1234 suffix$"))
requests << detect_request(id: "allow-target-decoded-line", behaviors: %w[DEC-010 DEC-012],
                           content: entropy_encoded, depth: 1,
                           config: allowlist_rule.call("line", "^prefix TOKEN=ABCD1234 suffix$"))
requests << detect_request(id: "allow-target-original-line-not-decoded", behaviors: %w[DEC-010 DEC-012],
                           content: entropy_encoded, depth: 1,
                           config: allowlist_rule.call("line", "^#{Regexp.escape(entropy_encoded)}$"))
nested_entropy = Base64.strict_encode64(entropy_encoded)
requests << detect_request(id: "allow-target-nested-decoded-line", behaviors: %w[DEC-010 DEC-012],
                           content: nested_entropy, depth: 2,
                           config: allowlist_rule.call("line", "^prefix TOKEN=ABCD1234 suffix$"))
multi_segment_line = "#{Base64.strict_encode64('prefix TOKEN=')}#{Base64.strict_encode64('ABCD1234 suffix')}"
requests << detect_request(id: "allow-target-multisegment-decoded-line", behaviors: %w[DEC-008 DEC-010 DEC-012],
                           content: multi_segment_line, depth: 1,
                           config: allowlist_rule.call("line", "^prefix TOKEN=ABCD1234 suffix$"))

# Global/rule early path gates and an ungated control.
early_regex = "decoded-secret-123"
early_encoded = Base64.strict_encode64(early_regex)
early_two_pass_input = "#{early_regex} #{early_encoded}"
global_early = "[[allowlists]]\npaths = [\"^blocked/\"]"
rule_early = "[[rules.allowlists]]\npaths = [\"^blocked/\"]"
requests << detect_request(id: "early-global-fragment-gate-once", behaviors: %w[DEC-010 DEC-012],
                           content: early_two_pass_input, depth: 2, file: "blocked/file.txt",
                           config: simple_rule_config(id: "early-global", regex: early_regex,
                                                      global_allowlist: global_early))
requests << detect_request(id: "early-rule-gate-each-pass", behaviors: %w[DEC-010 DEC-012],
                           content: early_two_pass_input, depth: 2, file: "blocked/file.txt",
                           config: simple_rule_config(id: "early-rule", regex: early_regex,
                                                      rule_allowlist: rule_early))
requests << detect_request(id: "early-gate-control", behaviors: %w[DEC-010 DEC-012],
                           content: early_two_pass_input, depth: 2, file: "allowed/file.txt",
                           config: simple_rule_config(id: "early-control", regex: early_regex,
                                                      rule_allowlist: rule_early))

# These decoder/composite intersections are fully replayed after M7. The two
# opposite-pass arrangements remain zero because the unchanged required match
# has no current-segment overlap; same-pass and mapped-proximity rows retain
# their exact required projections.
required_config = <<~TOML
  [[rules]]
  id = "primary"
  regex = '''PRIMARY-VALUE'''
    [[rules.required]]
    id = "auxiliary"
  [[rules]]
  id = "auxiliary"
  regex = '''AUXILIARY-VALUE'''
  skipReport = true
TOML
requests << detect_request(id: "required-primary-raw-aux-encoded-different-pass", behaviors: %w[DEC-010 DEC-011 COMP-006],
                           content: "PRIMARY-VALUE %41UXILIARY-VALUE", depth: 1,
                           config: required_config).merge("scope_disposition" => "m7-integrated-opposite-pass-zero")
requests << detect_request(id: "required-primary-encoded-aux-raw-different-pass", behaviors: %w[DEC-010 DEC-011 COMP-006],
                           content: "%50RIMARY-VALUE AUXILIARY-VALUE", depth: 1,
                           config: required_config).merge("scope_disposition" => "m7-integrated-opposite-pass-zero")
requests << detect_request(id: "required-aux-encoded-candidate-control", behaviors: %w[DEC-002 DEC-010 DEC-011],
                           content: "PRIMARY-VALUE %41UXILIARY-VALUE", depth: 1,
                           config: simple_rule_config(id: "aux-control", regex: "AUXILIARY-VALUE"))
requests << detect_request(id: "required-primary-encoded-candidate-control", behaviors: %w[DEC-002 DEC-010 DEC-011],
                           content: "%50RIMARY-VALUE AUXILIARY-VALUE", depth: 1,
                           config: simple_rule_config(id: "primary-control", regex: "PRIMARY-VALUE"))

required_same_pass = Base64.strict_encode64("PRIMARY-VALUE AUXILIARY-VALUE")
requests << detect_request(id: "required-both-encoded-same-pass", behaviors: %w[DEC-010 DEC-011 COMP-005 COMP-006],
                           content: required_same_pass, depth: 1,
                           config: required_config).merge("scope_disposition" => "m7-integrated-positive-projection")
required_allowlisted_config = required_config + <<~TOML
    [[rules.allowlists]]
    regexTarget = "match"
    regexes = ['''^AUXILIARY-VALUE$''']
TOML
requests << detect_request(id: "required-auxiliary-allowlisted-same-pass", behaviors: %w[DEC-010 DEC-011 DEC-012 COMP-003 COMP-006],
                           content: required_same_pass, depth: 1,
                           config: required_allowlisted_config).merge("scope_disposition" => "m7-integrated-negative")

required_proximity = lambda do |columns|
  <<~TOML
    [[rules]]
    id = "primary"
    regex = '''PRIMARY-1234'''
      [[rules.required]]
      id = "auxiliary"
      withinColumns = #{columns}
    [[rules]]
    id = "auxiliary"
    regex = '''AUXILIARY-5678'''
    skipReport = true
  TOML
end
required_split_encoded = "#{Base64.strict_encode64('PRIMARY-1234')} #{Base64.strict_encode64('AUXILIARY-5678')}"
requests << detect_request(id: "required-mapped-proximity-outside", behaviors: %w[DEC-007 DEC-010 DEC-011 COMP-004 COMP-006],
                           content: required_split_encoded, depth: 1,
                           config: required_proximity.call(1)).merge("scope_disposition" => "m7-integrated-proximity")
requests << detect_request(id: "required-mapped-proximity-inside", behaviors: %w[DEC-007 DEC-010 DEC-011 COMP-004 COMP-005 COMP-006],
                           content: required_split_encoded, depth: 1,
                           config: required_proximity.call(100)).merge("scope_disposition" => "m7-integrated-proximity")

# Direct inherited scans are the M6-owned context boundary: inherited mode
# bypasses skipReport while retaining the decoded segment context, mapping and
# finding allowlist. These do not claim composite projection.
inherited_skip_config = simple_rule_config(id: "inherited-skip", regex: "decoded-secret-123", skip_report: true)
requests << detect_request(id: "inherited-decoded-skipreport-context", behaviors: %w[DEC-007 DEC-010 DEC-011],
                           content: Base64.strict_encode64("decoded-secret-123"), depth: 1,
                           config: inherited_skip_config, inherited: true)
inherited_allowlist = "[[rules.allowlists]]\nregexTarget = \"match\"\nregexes = ['''^decoded-secret-123$''']"
requests << detect_request(id: "inherited-decoded-skipreport-allowlisted", behaviors: %w[DEC-007 DEC-010 DEC-011 DEC-012],
                           content: Base64.strict_encode64("decoded-secret-123"), depth: 1,
                           config: simple_rule_config(id: "inherited-skip-allow", regex: "decoded-secret-123",
                                                      skip_report: true, rule_allowlist: inherited_allowlist),
                           inherited: true)

# Malformed UTF-8 before, between, and after candidates for every codec. The
# complete finding spans BEGIN..END so the invalid byte is part of the match
# and all byte offsets remain observable in the canonical projection.
malformed_payload = "TOKEN=VALUE!XXXX"
malformed_candidates = {
  "percent" => malformed_payload.bytes.map { |byte| format("%%%02X", byte) }.join,
  "unicode" => malformed_payload.each_codepoint.map { |codepoint| format("\\u%04x", codepoint) }.join,
  "hex" => malformed_payload.unpack1("H*"),
  "base64" => Base64.strict_encode64(malformed_payload)
}
malformed_config = simple_rule_config(id: "malformed-offset", regex: "BEGIN:.*TOKEN=VALUE!XXXX.*:END")
malformed_candidates.each do |kind, candidate|
  {
    "before" => "BEGIN:".b + "\xff".b + candidate.b + ":END".b,
    "inside" => "BEGIN:".b + candidate.b + "\xff".b + candidate.b + ":END".b,
    "after" => "BEGIN:".b + candidate.b + "\xff".b + ":END".b
  }.each do |position, content|
    requests << detect_request(id: "malformed-utf8-#{kind}-#{position}", behaviors: %w[DEC-009 DEC-010 DEC-011],
                               content: content, depth: 1, config: malformed_config)
  end
end

# Bounded fan-out/depth resource probes complement the long single candidates.
distinct_failures = ("A".."Z").map.with_index { |letter, index| letter * (16 + index) }.join(" ")
requests << decode_request(id: "resource-many-distinct-failures", behaviors: %w[DEC-001 DEC-013],
                           input: distinct_failures)
many_successes = Array.new(64, cache_key).join(" ")
requests << decode_request(id: "resource-many-successful-segments", behaviors: %w[DEC-001 DEC-007 DEC-013],
                           input: many_successes)
nested_resource = "decoded-secret-123"
6.times { nested_resource = Base64.strict_encode64(nested_resource) }
requests << decode_request(id: "resource-nested-depth-six", behaviors: %w[DEC-001 DEC-007 DEC-013],
                           input: nested_resource, pass_limit: 16)

# Exact request ownership for the mandatory 1..31 audit matrix in
# M6-DECODER-SEMANTICS-001. This is deliberately independent of the broader
# DEC category labels: deleting or substituting any named row fails closed.
mandatory_cases = {
  1 => %w[percent-min-minus-one percent-single percent-min-plus-one unicode-min-minus-one unicode-eof unicode-min-plus-one hex-under-minimum hex-minimum hex-odd-length hex-length-34 base64-under-minimum base64-length-16 base64-length-17],
  2 => %w[same-start-hex-base64-success same-start-hex-base64-likelihood-failure same-start-hex-base64-odd-failure same-start-hex-base64-printability-failure],
  3 => %w[percent-wrap-base64-success percent-wrap-hex-success percent-broad-reject-blocks-base64],
  4 => %w[touch-percent-before-base64 touch-base64-before-percent touch-unicode-before-hex touch-equal-base64 touch-three-precedence-neighbors],
  5 => %w[percent-greedy-same-line percent-does-not-cross-lf percent-malformed-nonhex percent-malformed-short percent-incomplete-copied-inside],
  6 => %w[percent-control-reject percent-tab-printable percent-lf-printable percent-tilde-printable percent-del-printability-reject unicode-codepoint-u0008 unicode-codepoint-u0009 unicode-codepoint-u007e unicode-codepoint-u007f hex-control-reject hex-tab-printable hex-lf-printable hex-tilde-printable hex-del-reject base64-control-reject base64-tab-printable base64-lf-printable base64-tilde-printable base64-del-reject],
  7 => %w[percent-copied-invalid-byte-inside percent-invalid-utf8-literal],
  8 => %w[hex-under-minimum hex-minimum hex-odd-length hex-length-34 hex-no-digit-heuristic hex-one-digit-likelihood hex-uppercase hex-lowercase-pairs hex-nonprint-first hex-nonprint-middle hex-nonprint-last],
  9 => %w[base64-likelihood-48 base64-likelihood-49 base64-likelihood-50 base64-likelihood-51 base64-likelihood-52 base64-likelihood-53 base64-likelihood-54 base64-likelihood-55 base64-likelihood-56 base64-likelihood-57 base64-likelihood-43 base64-likelihood-47 base64-likelihood-45 base64-likelihood-95 base64-standard base64-raw-url base64-bad-padding base64-unpadded-standard-plus-rejected base64-padded-url-rejected base64-mixed-alphabet-rejected base64-standard-pad2-canonical base64-standard-pad2-noncanonical base64-standard-pad1-canonical base64-standard-pad1-noncanonical base64-raw-url-pad2-canonical base64-raw-url-pad2-noncanonical base64-raw-url-pad1-canonical base64-raw-url-pad1-noncanonical],
  10 => %w[unicode-eof unicode-space unicode-tab unicode-lf unicode-two-spaces unicode-codepoint unicode-lowercase-codepoint-rejected unicode-single-slash unicode-double-slash unicode-three-backslashes unicode-four-backslashes unicode-case-insensitive-u unicode-escape-trailing-ascii unicode-escapes-separated unicode-escapes-contiguous unicode-codepoint-fifth-digit unicode-fifth-hex-digit],
  11 => %w[unicode-nul unicode-codepoint-u0008 unicode-codepoint-u0009 unicode-codepoint-u007e unicode-codepoint-u007f unicode-codepoint-u00e9 unicode-codepoint-ud800 unicode-codepoint-udfff unicode-surrogate-pair-not-combined],
  12 => %w[cache-two-successes-one-pass cache-two-failures-one-pass],
  13 => %w[cache-key-reappears-deeper],
  14 => %w[cache-shared-instance cache-isolated-instances],
  15 => %w[detect-encoded-depth-negative-one detect-encoded-depth-0 detect-encoded-depth-1 detect-encoded-depth-7 detect-encoded-depth-8 detect-exhaustion-before-huge-depth],
  16 => %w[outer-all-letter-likelihood-stops-recursion],
  17 => %w[mapping-two-segments-shift-span mapping-success-failure-success-shifts],
  18 => %w[mapping-contained-left-right-both-none-touch mapping-two-segments-shift-span],
  19 => %w[inclusive-touch-unchanged-duplicate inclusive-touch-after-duplicate],
  20 => %w[line-segment-at-byte-zero line-segment-after-lf line-segment-before-lf line-segment-decodes-to-lf line-selected-segments-separate-lines],
  21 => %w[finding-all-four-encoding-tags cache-carried-unrelated-global-depth],
  22 => %w[rule-tags-state-reuse],
  23 => %w[duplicates-across-passes],
  24 => %w[keyword-absent-raw-present-decoded keyword-present-raw-absent-decoded keyword-unicode-case-folded keyword-none-every-pass],
  25 => %w[marker-original-same-line marker-decoded-only marker-neighboring-original-line marker-previous-line-currentline-quirk],
  26 => %w[decoded-capture-entropy-equal-reject decoded-capture-entropy-below-report],
  27 => %w[allow-target-decoded-secret allow-target-decoded-match allow-target-decoded-line allow-target-original-line-not-decoded allow-target-nested-decoded-line allow-target-multisegment-decoded-line],
  28 => %w[early-global-fragment-gate-once early-rule-gate-each-pass early-gate-control],
  29 => %w[required-primary-raw-aux-encoded-different-pass required-primary-encoded-aux-raw-different-pass required-aux-encoded-candidate-control required-primary-encoded-candidate-control required-both-encoded-same-pass required-auxiliary-allowlisted-same-pass required-mapped-proximity-outside required-mapped-proximity-inside inherited-decoded-skipreport-context inherited-decoded-skipreport-allowlisted],
  30 => malformed_candidates.keys.product(%w[before inside after]).map { |kind, position| "malformed-utf8-#{kind}-#{position}" },
  31 => %w[resource-percent-4096 resource-hex-16384 resource-base64-16384 resource-many-distinct-failures resource-many-successful-segments resource-nested-depth-six]
}.freeze

abort "duplicate request IDs" unless requests.map { |request| request.fetch("id") }.uniq.length == requests.length
abort "mandatory case numbering changed" unless mandatory_cases.keys == (1..31).to_a
request_ids = requests.map { |request| request.fetch("id") }
mandatory_cases.each do |number, ids|
  abort "mandatory case #{number}: empty request ownership" if ids.empty?
  missing = ids - request_ids
  abort "mandatory case #{number}: missing exact request IDs #{missing.inspect}" unless missing.empty?
end
linked_leaves = requests.flat_map { |request| request.fetch("test_case_ids") }
actual_decoder_leaves = linked_leaves & LEAF_IDS
abort "decoder leaf identity coverage changed" unless actual_decoder_leaves.sort == LEAF_IDS
LEAF_IDS.each { |id| abort "#{id}: expected one request" unless actual_decoder_leaves.count(id) == 1 }
abort "decoder root incorrectly linked as leaf" if linked_leaves.include?(ROOT_ID)
abort "detect_encoded identity count changed" unless linked_leaves.count(DETECT_ID) == 1
observed_behaviors = requests.flat_map { |request| request.fetch("behavior_ids") }.uniq.sort
abort "decoder/composite coverage changed: #{observed_behaviors.inspect}" unless observed_behaviors == BEHAVIOR_IDS

revision = capture("git", "rev-parse", "HEAD", chdir: UPSTREAM).strip
abort "upstream revision changed: #{revision}" unless revision == REVISION
abort "default config hash changed" unless sha(UPSTREAM.join("config/gitleaks.toml").binread) == DEFAULT_SHA256
status = capture("git", "status", "--short", "--untracked-files=no", chdir: UPSTREAM)
abort "upstream status changed:\n#{status}" unless status == EXPECTED_UPSTREAM_STATUS

generated = {}
Dir.mktmpdir("rustleaks-m6-decoder") do |temporary|
  binary = File.join(temporary, "decoder-oracle")
  capture("go", "test", "./...", chdir: ORACLE)
  capture("go", "build", "-o", binary, ".", chdir: ORACLE)
  outcomes = requests.map do |request|
    output = capture(binary, "--decoder", chdir: ORACLE, stdin_data: JSON.generate(request) + "\n")
    lines = output.lines
    abort "#{request.fetch('id')}: oracle emitted #{lines.length} lines" unless lines.length == 1
    parsed = JSON.parse(lines.first)
    abort "#{request.fetch('id')}: identity changed" unless parsed.fetch("id") == request.fetch("id")
    abort "#{request.fetch('id')}: pin changed" unless parsed.fetch("upstream_revision") == REVISION && parsed.fetch("default_config_sha256") == DEFAULT_SHA256
    abort "#{request.fetch('id')}: oracle error #{parsed['error'].inspect}" unless parsed["error"].nil?
    parsed
  end
  by_id = outcomes.to_h { |outcome| [outcome.fetch("id"), outcome] }
  request_by_id = requests.to_h { |request| [request.fetch("id"), request] }
  first_run = ->(id) { by_id.fetch(id).fetch("runs").fetch(0) }
  first_pass = ->(id) { first_run.call(id).fetch("passes").fetch(0) }
  segment_count = lambda do |id|
    first_pass.call(id).fetch("segments").length
  end
  finding_count = ->(id) { by_id.fetch(id).fetch("findings").length }

  # Mandatory codec branches are asserted by exact request ID and accepted
  # segment count. A successful oracle invocation with the wrong branch is not
  # sufficient to update the corpus.
  codec_segment_counts = {
    "percent-min-minus-one" => 0, "percent-single" => 1, "percent-min-plus-one" => 1,
    "unicode-min-minus-one" => 0, "unicode-eof" => 1, "unicode-min-plus-one" => 1,
    "hex-under-minimum" => 0, "hex-minimum" => 1, "hex-odd-length" => 0, "hex-length-34" => 1,
    "base64-under-minimum" => 0, "base64-length-16" => 1, "base64-length-17" => 0,
    "percent-control-reject" => 0, "percent-tab-printable" => 1, "percent-lf-printable" => 1,
    "percent-tilde-printable" => 1, "percent-del-printability-reject" => 0,
    "percent-greedy-same-line" => 1, "percent-does-not-cross-lf" => 2,
    "percent-malformed-short" => 0, "percent-malformed-nonhex" => 0,
    "percent-incomplete-copied-inside" => 1,
    "hex-control-reject" => 0, "hex-tab-printable" => 1, "hex-lf-printable" => 1,
    "hex-tilde-printable" => 1, "hex-del-reject" => 0,
    "base64-control-reject" => 0, "base64-tab-printable" => 1, "base64-lf-printable" => 1,
    "base64-tilde-printable" => 1, "base64-del-reject" => 0,
    "hex-no-digit-heuristic" => 0, "hex-one-digit-likelihood" => 1,
    "hex-uppercase" => 1, "hex-lowercase-pairs" => 1,
    "hex-nonprint-first" => 0, "hex-nonprint-middle" => 0, "hex-nonprint-last" => 0,
    "base64-bad-padding" => 0, "base64-unpadded-standard-plus-rejected" => 0,
    "base64-padded-url-rejected" => 0, "base64-mixed-alphabet-rejected" => 0,
    "unicode-space" => 1, "unicode-tab" => 1, "unicode-lf" => 1, "unicode-two-spaces" => 1,
    "unicode-lowercase-codepoint-rejected" => 0, "unicode-codepoint-fifth-digit" => 0,
    "unicode-single-slash" => 1, "unicode-double-slash" => 1,
    "unicode-three-backslashes" => 1, "unicode-four-backslashes" => 1,
    "unicode-case-insensitive-u" => 1, "unicode-escape-trailing-ascii" => 1,
    "unicode-escapes-separated" => 2, "unicode-escapes-contiguous" => 1,
    "unicode-fifth-hex-digit" => 1, "unicode-malformed-width" => 0,
    "unicode-nul" => 1, "unicode-codepoint-u0008" => 1, "unicode-codepoint-u0009" => 1,
    "unicode-codepoint-u007e" => 1, "unicode-codepoint-u007f" => 1,
    "unicode-codepoint-u00e9" => 1, "unicode-codepoint-ud800" => 1,
    "unicode-codepoint-udfff" => 1, "unicode-surrogate-pair-not-combined" => 1
  }
  codec_segment_counts.each do |id, expected|
    actual = segment_count.call(id)
    abort "#{id}: accepted segment count #{actual} != #{expected}" unless actual == expected
  end
  %w[0 1 2 3 4 5 6 7 8 9 + / - _].each do |character|
    id = "base64-likelihood-#{character.ord}"
    segments = first_pass.call(id).fetch("segments")
    abort "#{id}: likelihood branch changed" unless segments.length == 1 && segments.fetch(0).fetch("encoding_kinds") == ["base64"]
  end
  unicode_outputs = {
    "unicode-nul" => "\x00".b, "unicode-codepoint-u0008" => "\x08".b,
    "unicode-codepoint-u0009" => "\t".b, "unicode-codepoint-u007e" => "~".b,
    "unicode-codepoint-u007f" => "\x7f".b, "unicode-codepoint-u00e9" => "\u00e9".encode("UTF-8"),
    "unicode-codepoint-ud800" => "\ufffd".encode("UTF-8"),
    "unicode-codepoint-udfff" => "\ufffd".encode("UTF-8"),
    "unicode-surrogate-pair-not-combined" => "\ufffd\ufffd".encode("UTF-8")
  }
  unicode_outputs.each do |id, expected|
    abort "#{id}: decoded bytes changed" unless first_run.call(id).fetch("full_decode_base64") == b64(expected)
  end

  same_start = {
    "same-start-hex-base64-success" => ["hex"],
    "same-start-hex-base64-likelihood-failure" => [],
    "same-start-hex-base64-odd-failure" => [],
    "same-start-hex-base64-printability-failure" => []
  }
  same_start.each do |id, expected|
    actual = first_pass.call(id).fetch("segments").flat_map { |segment| segment.fetch("encoding_kinds") }
    abort "#{id}: same-start ownership changed: #{actual.inspect}" unless actual == expected
  end
  touch_ownership = {
    "precedence-percent-over-base64" => [["percent"]],
    "precedence-percent-over-hex" => [["percent"]],
    "touch-percent-hex" => [["percent"]],
    "touch-percent-before-base64" => [["percent"]],
    "touch-base64-before-percent" => [["percent"]],
    "touch-unicode-before-hex" => [["unicode"]],
    "touch-equal-base64" => [],
    "touch-three-precedence-neighbors" => [["percent"]],
    "touch-two-percent-segments" => [["percent"]]
  }
  touch_ownership.each do |id, expected|
    actual = first_pass.call(id).fetch("segments").map { |segment| segment.fetch("encoding_kinds") }
    abort "#{id}: precedence/touch ownership changed: #{actual.inspect}" unless actual == expected
  end
  {
    "percent-wrap-base64-success" => [["percent"], %w[percent base64]],
    "percent-wrap-hex-success" => [["percent"], %w[percent hex]]
  }.each do |id, expected|
    kinds = first_run.call(id).fetch("passes").map do |pass|
      segment = pass.fetch("segments").fetch(0, nil)
      segment&.fetch("encoding_kinds")
    end.compact
    abort "#{id}: nested exposure changed: #{kinds.inspect}" unless kinds == expected
  end
  abort "outer all-letter likelihood gate changed" unless segment_count.call("outer-all-letter-likelihood-stops-recursion").zero?
  abort "greedy percent failure no longer blocks base64" unless segment_count.call("percent-broad-reject-blocks-base64").zero?

  # Cache observations distinguish repeated hits, cached empty failures,
  # same-key reappearance on a later pass, shared scope, and isolated scope.
  success_entry = { "encoded_base64" => b64(cache_key), "decoded_base64" => b64("this-is-1234") }
  success_pass = first_pass.call("cache-two-successes-one-pass")
  abort "cache success duplicate branch changed" unless success_pass.fetch("segments").length == 2 &&
                                                        success_pass.fetch("cache_before").empty? &&
                                                        success_pass.fetch("cache_after") == [success_entry]
  failure_entry = { "encoded_base64" => b64("AAAAAAAAAAAAAAAA"), "decoded_base64" => "" }
  failure_pass = first_pass.call("cache-two-failures-one-pass")
  abort "cache empty-result branch changed" unless failure_pass.fetch("segments").empty? &&
                                                     failure_pass.fetch("cache_before").empty? &&
                                                     failure_pass.fetch("cache_after") == [failure_entry]
  deeper_passes = first_run.call("cache-key-reappears-deeper").fetch("passes")
  abort "cache key not present before deeper reappearance" unless deeper_passes.fetch(1).fetch("cache_before").include?(success_entry)
  abort "deeper cache hit mutated cache" unless deeper_passes.fetch(1).fetch("cache_before") == deeper_passes.fetch(1).fetch("cache_after")
  deeper_segment = deeper_passes.fetch(1).fetch("segments").fetch(0)
  abort "deeper cache segment metadata changed" unless deeper_segment.fetch("depth") == 2 &&
                                                       deeper_segment.fetch("predecessor_indices") == [0, 1]
  shared_runs = by_id.fetch("cache-shared-instance").fetch("runs")
  isolated_runs = by_id.fetch("cache-isolated-instances").fetch("runs")
  abort "shared Decoder cache did not reappear" unless shared_runs.fetch(0).fetch("cache_before").empty? &&
                                                        shared_runs.fetch(1).fetch("cache_before") == [success_entry]
  abort "isolated Decoder cache leaked" unless isolated_runs.all? { |run| run.fetch("cache_before").empty? }
  carried = by_id.fetch("cache-carried-unrelated-global-depth").fetch("runs")
  carried_segment = carried.fetch(1).fetch("passes").fetch(0).fetch("segments").fetch(0)
  abort "global depth/unrelated predecessor changed" unless carried_segment.fetch("depth") == 2 &&
                                                        carried_segment.fetch("encoding_kinds") == ["base64"] &&
                                                        carried_segment.fetch("predecessor_indices") == [0]

  # Signed range mapping, endpoint touching and two-segment shift geometry.
  mapping_pass = first_pass.call("mapping-contained-left-right-both-none-touch")
  mapping_segment = mapping_pass.fetch("segments").fetch(0)
  abort "mapping segment geometry changed" unless mapping_segment.values_at("original", "encoded", "decoded") == [[4, 20], [4, 20], [4, 16]]
  expected_mapping_probes = {
    [6, 10] => [[4, 20], [0]], [2, 6] => [[2, 20], [0]], [14, 18] => [[4, 22], [0]],
    [2, 18] => [[2, 22], [0]], [0, 2] => [[0, 2], []], [0, 4] => [[0, 20], [0]],
    [16, 21] => [[4, 25], [0]]
  }
  expected_mapping_probes.each do |range, (adjusted, overlaps)|
    probe = mapping_pass.fetch("probes").find { |candidate| candidate.fetch("range") == range }
    abort "mapping probe #{range.inspect} missing" unless probe
    abort "mapping probe #{range.inspect} changed" unless probe.fetch("adjusted") == adjusted &&
                                                          probe.fetch("overlap_segment_indices") == overlaps
  end
  two_mapping = first_pass.call("mapping-two-segments-shift-span")
  abort "two-segment mapping geometry changed" unless two_mapping.fetch("segments").map { |segment| segment.values_at("original", "decoded") } ==
                                                       [[[2, 18], [2, 14]], [[23, 39], [19, 31]]]
  spanning_probe = two_mapping.fetch("probes").find { |probe| probe.fetch("range") == [2, 24] }
  abort "two-segment spanning adjustment changed" unless spanning_probe &&
                                                        spanning_probe.fetch("adjusted") == [2, 39] &&
                                                        spanning_probe.fetch("overlap_segment_indices") == [0, 1]
  shifted = first_pass.call("mapping-success-failure-success-shifts").fetch("segments")
  abort "success/failure/success shifts changed" unless shifted.map { |segment| segment.values_at("original", "decoded", "encoding_kinds") } ==
                                                       [[[2, 18], [2, 14], ["base64"]], [[38, 70], [34, 50], ["hex"]]]

  current_lines = {
    "line-segment-at-byte-zero" => "this-is-1234",
    "line-segment-after-lf" => "\nthis-is-1234:after",
    "line-segment-before-lf" => "this-is-1234",
    "line-segment-decodes-to-lf" => "\nafter",
    "line-selected-segments-separate-lines" => "this-is-1234\nmiddle\nthat-is-4567"
  }
  current_lines.each do |id, expected|
    abort "#{id}: CurrentLine changed" unless first_pass.call(id).fetch("current_line_base64") == b64(expected)
  end

  all_tags = %w[rule-tag decoded:percent decoded:unicode decoded:hex decoded:base64 decode-depth:1].map { |tag| b64(tag) }
  abort "all encoding tags/order changed" unless by_id.fetch("finding-all-four-encoding-tags").fetch("findings").fetch(0).fetch("tags_base64") == all_tags
  repeated = by_id.fetch("rule-tags-state-reuse")
  abort "rule tag state was reused/mutated" unless repeated.fetch("finding_runs").length == 3 &&
                                                  repeated.fetch("finding_runs").all? { |run| run.length == 1 && run.fetch(0).fetch("tags_base64") == all_tags } &&
                                                  repeated.fetch("finding_runs").uniq.length == 1

  detector_counts = {
    "keyword-absent-raw-present-decoded" => 1, "keyword-present-raw-absent-decoded" => 1,
    "keyword-unicode-case-folded" => 1, "keyword-none-every-pass" => 2,
    "marker-original-same-line" => 0, "marker-decoded-only" => 1, "marker-neighboring-original-line" => 1,
    "marker-previous-line-currentline-quirk" => 0,
    "decoded-capture-entropy-equal-reject" => 0, "decoded-capture-entropy-below-report" => 1,
    "allow-target-decoded-secret" => 0, "allow-target-decoded-match" => 0,
    "allow-target-decoded-line" => 0, "allow-target-original-line-not-decoded" => 1,
    "allow-target-nested-decoded-line" => 0, "allow-target-multisegment-decoded-line" => 0,
    "early-global-fragment-gate-once" => 0, "early-rule-gate-each-pass" => 0, "early-gate-control" => 2,
    "required-primary-raw-aux-encoded-different-pass" => 0,
    "required-primary-encoded-aux-raw-different-pass" => 0,
    "required-aux-encoded-candidate-control" => 1, "required-primary-encoded-candidate-control" => 1,
    "required-both-encoded-same-pass" => 1, "required-auxiliary-allowlisted-same-pass" => 0,
    "required-mapped-proximity-outside" => 0, "required-mapped-proximity-inside" => 1,
    "inherited-decoded-skipreport-context" => 1, "inherited-decoded-skipreport-allowlisted" => 0
  }
  detector_counts.each do |id, expected|
    actual = finding_count.call(id)
    abort "#{id}: finding count #{actual} != #{expected}" unless actual == expected
  end
  same_pass_required = by_id.fetch("required-both-encoded-same-pass").fetch("findings").fetch(0)
  same_pass_projection = {
    "rule_id" => "auxiliary", "start_line" => 0, "end_line" => 0,
    "start_column" => 1, "end_column" => 40,
    "line_base64" => b64(required_same_pass),
    "match_base64" => b64("AUXILIARY-VALUE"),
    "secret_base64" => b64("AUXILIARY-VALUE")
  }
  abort "required same-pass projection fields changed" unless same_pass_required.fetch("rule_id") == "primary" &&
                                                        same_pass_required.values_at("start_line", "end_line", "start_column", "end_column") == [0, 0, 1, 40] &&
                                                        same_pass_required.fetch("line_base64") == b64(required_same_pass) &&
                                                        same_pass_required.fetch("match_base64") == b64("PRIMARY-VALUE") &&
                                                        same_pass_required.fetch("secret_base64") == b64("PRIMARY-VALUE") &&
                                                        same_pass_required.fetch("tags_base64") == [b64("decoded:base64"), b64("decode-depth:1")] &&
                                                        same_pass_required.fetch("required_findings") == [same_pass_projection]
  proximity_required = by_id.fetch("required-mapped-proximity-inside").fetch("findings").fetch(0)
  abort "required mapped-proximity projection fields changed" unless proximity_required.fetch("rule_id") == "primary" &&
                                                                  proximity_required.values_at("start_column", "end_column") == [1, 16] &&
                                                                  proximity_required.fetch("line_base64") == b64(required_split_encoded) &&
                                                                  proximity_required.fetch("match_base64") == b64("PRIMARY-1234") &&
                                                                  proximity_required.fetch("tags_base64") == [b64("decoded:base64"), b64("decode-depth:1")] &&
                                                                  proximity_required.fetch("required_findings") == [{
                                                                    "rule_id" => "auxiliary", "start_line" => 0, "end_line" => 0,
                                                                    "start_column" => 18, "end_column" => 37,
                                                                    "line_base64" => b64(required_split_encoded),
                                                                    "match_base64" => b64("AUXILIARY-5678"),
                                                                    "secret_base64" => b64("AUXILIARY-5678")
                                                                  }]
  neighboring_marker = by_id.fetch("marker-neighboring-original-line").fetch("findings").fetch(0)
  abort "neighboring following-line marker boundary changed" unless neighboring_marker.values_at("start_line", "end_line", "start_column", "end_column") == [0, 0, 1, 16] &&
                                                            neighboring_marker.fetch("line_base64") == b64(marker_encoded) &&
                                                            neighboring_marker.fetch("match_base64") == b64("SECRET-VALUE") &&
                                                            neighboring_marker.fetch("secret_base64") == b64("SECRET-VALUE") &&
                                                            neighboring_marker.fetch("tags_base64") == [b64("decoded:base64"), b64("decode-depth:1")]
  %w[required-aux-encoded-candidate-control required-primary-encoded-candidate-control inherited-decoded-skipreport-context].each do |id|
    tags = by_id.fetch(id).fetch("findings").fetch(0).fetch("tags_base64")
    abort "#{id}: intended decoded-pass control did not decode" unless tags.any? { |tag| Base64.strict_decode64(tag).start_with?("decoded:") }
  end

  # Every malformed row must produce one complete decoded finding. The raw
  # line stays byte-exact, the match/secret use decoded bytes, and columns map
  # across the entire original candidate span.
  malformed_candidates.each_key do |kind|
    %w[before inside after].each do |position|
      id = "malformed-utf8-#{kind}-#{position}"
      request = request_by_id.fetch(id)
      raw = Base64.strict_decode64(request.fetch("fragment").fetch("content_base64"))
      decoded = case position
                when "before" then "BEGIN:".b + "\xff".b + malformed_payload.b + ":END".b
                when "inside" then "BEGIN:".b + malformed_payload.b + "\xff".b + malformed_payload.b + ":END".b
                when "after" then "BEGIN:".b + malformed_payload.b + "\xff".b + ":END".b
                end
      findings = by_id.fetch(id).fetch("findings")
      abort "#{id}: expected one complete finding" unless findings.length == 1
      finding = findings.fetch(0)
      expected_tags = [b64("decoded:#{kind}"), b64("decode-depth:1")]
      abort "#{id}: exact malformed finding changed" unless finding.fetch("rule_id") == "malformed-offset" &&
                                                            finding.values_at("start_line", "end_line", "start_column", "end_column") == [0, 0, 1, raw.bytesize] &&
                                                            finding.fetch("line_base64") == b64(raw) &&
                                                            finding.fetch("match_base64") == b64(decoded) &&
                                                            finding.fetch("secret_base64") == b64(decoded) &&
                                                            finding.fetch("file_base64") == b64("tmp.go") &&
                                                            finding.fetch("tags_base64") == expected_tags
    end
  end

  resource_segments = {
    "resource-percent-4096" => 1, "resource-hex-16384" => 1, "resource-base64-16384" => 1,
    "resource-many-distinct-failures" => 0, "resource-many-successful-segments" => 64,
    "resource-nested-depth-six" => 6
  }
  resource_segments.each do |id, expected|
    run = first_run.call(id)
    count = run.fetch("passes").sum { |pass| pass.fetch("segments").length }
    abort "#{id}: bounded resource segment count #{count} != #{expected}" unless count == expected
    abort "#{id}: bounded resource probe did not terminate" unless run.fetch("terminated")
  end

  # Every upstream leaf carries its exact full-decode expectation independently
  # of the Go test's assertion, preventing a same-count or substituted-case pass.
  requests.select { |request| request.key?("expected_full_decode_base64") }.each do |request|
    outcome = by_id.fetch(request.fetch("id"))
    actual = outcome.fetch("runs").fetch(0).fetch("full_decode_base64")
    expected = request.fetch("expected_full_decode_base64")
    abort "#{request.fetch('id')}: full decode #{actual} != #{expected}" unless actual == expected
    abort "#{request.fetch('id')}: did not terminate" unless outcome.fetch("runs").fetch(0).fetch("terminated")
  end

  # Cache success/empty repetitions must remain byte-for-byte semantic repeats.
  %w[cache-repeat-success cache-repeat-empty cache-empty-input].each do |id|
    runs = by_id.fetch(id).fetch("runs")
    signatures = runs.map do |run|
      semantic = run.reject { |key, _| %w[input_sha256 cache_before cache_after].include?(key) }
      semantic = semantic.merge("passes" => semantic.fetch("passes").map do |pass|
        pass.reject { |key, _| %w[cache_before cache_after].include?(key) }
      end)
      JSON.generate(semantic)
    end.uniq
    abort "#{id}: cache repeats diverged" unless signatures.length == 1
  end

  {
    "base64-standard-pad2" => "this-is-12345",
    "base64-standard-pad1" => "this-is-123456",
    "base64-raw-url-pad2" => "this-is-12345",
    "base64-raw-url-pad1" => "this-is-123456"
  }.each do |prefix, expected|
    canonical = by_id.fetch("#{prefix}-canonical").fetch("runs").fetch(0)
    noncanonical = by_id.fetch("#{prefix}-noncanonical").fetch("runs").fetch(0)
    expected_base64 = b64(expected)
    abort "#{prefix}: canonical trailing-bit decode changed" unless canonical.fetch("full_decode_base64") == expected_base64
    abort "#{prefix}: noncanonical trailing bits rejected" unless noncanonical.fetch("full_decode_base64") == expected_base64
    abort "#{prefix}: noncanonical request produced no accepted segment" if noncanonical.fetch("passes").fetch(0).fetch("segments").empty?
  end
  copied_invalid = by_id.fetch("percent-copied-invalid-byte-inside").fetch("runs").fetch(0)
  abort "percent copied-byte qualification changed" unless copied_invalid.fetch("full_decode_base64") == b64([0x41, 0xff, 0x42].pack("C*"))
  blocked = by_id.fetch("percent-broad-reject-blocks-base64").fetch("runs").fetch(0)
  abort "failed broad percent no longer blocks nested candidate" unless blocked.fetch("passes").fetch(0).fetch("segments").empty?
  three_touch = by_id.fetch("touch-three-precedence-neighbors").fetch("runs").fetch(0).fetch("passes").fetch(0)
  abort "three-neighbor precedence changed" unless three_touch.fetch("segments").map { |segment| segment.fetch("encoding_kinds") } == [["percent"]]
  %w[base64-unpadded-standard-plus-rejected base64-padded-url-rejected base64-mixed-alphabet-rejected].each do |id|
    pass = by_id.fetch(id).fetch("runs").fetch(0).fetch("passes").fetch(0)
    abort "#{id}: unsupported base64 form unexpectedly decoded" unless pass.fetch("segments").empty?
  end

  depth_counts = (0..8).to_h do |depth|
    [depth.to_s, by_id.fetch("detect-encoded-depth-#{depth}").fetch("findings").length]
  end
  abort "decode depth counts are not monotone: #{depth_counts}" unless depth_counts.values.each_cons(2).all? { |a, b| b >= a }
  negative_depth = by_id.fetch("detect-encoded-depth-negative-one")
  zero_depth = by_id.fetch("detect-encoded-depth-0")
  abort "negative Go depth / Rust adapter boundary changed" unless negative_depth.fetch("requested_max_decode_depth") == -1 &&
                                                                  negative_depth.fetch("rust_adapter_max_decode_depth") == 0 &&
                                                                  negative_depth.fetch("findings") == zero_depth.fetch("findings")
  depth8 = by_id.fetch("detect-encoded-depth-8")
  abort "TM-0078 exact replay lost findings" if depth8.fetch("findings").empty?
  complete_finding_keys = %w[
    rule_id description_base64 start_line end_line start_column end_column line_base64 match_base64
    secret_base64 file_base64 symlink_file_base64 commit_base64 link_base64 entropy_bits author_base64
    email_base64 date_base64 message_base64 tags_base64 fingerprint_base64 fragment required_findings
  ].sort
  outcomes.flat_map { |outcome| outcome.fetch("findings") }.each do |finding|
    abort "complete finding projection changed" unless finding.keys.sort == complete_finding_keys
  end
  abort "decoded line positive was not suppressed" unless by_id.fetch("decoded-line-allowlist-positive").fetch("findings").empty?
  negative_line_findings = by_id.fetch("decoded-line-allowlist-negative").fetch("findings")
  abort "decoded line negative did not report: #{negative_line_findings.inspect}" unless negative_line_findings.length == 1
  abort "duplicate pass multiplicity changed" unless by_id.fetch("duplicates-across-passes").fetch("findings").length == 2
  touch_findings = by_id.fetch("inclusive-touch-unchanged-duplicate").fetch("findings")
  abort "inclusive-touch duplicate multiplicity changed" unless touch_findings.length == 2
  touch_tags = touch_findings.map { |finding| finding.fetch("tags_base64") }
  abort "inclusive-touch duplicate lacks raw and decoded forms" unless touch_tags.any?(&:empty?) && touch_tags.any? { |tags| !tags.empty? }

  # Negative controls prove comparisons are schema/content sensitive even when
  # record and finding counts are unchanged.
  substituted_pass = Marshal.load(Marshal.dump(by_id.fetch("nested-base64")))
  substituted_pass.fetch("runs").fetch(0).fetch("passes").fetch(0).fetch("segments").fetch(0)["depth"] += 1
  abort "pass substitution changed record counts" unless substituted_pass.fetch("runs").length == by_id.fetch("nested-base64").fetch("runs").length &&
                                                    substituted_pass.fetch("runs").fetch(0).fetch("passes").length == by_id.fetch("nested-base64").fetch("runs").fetch(0).fetch("passes").length
  abort "pass substitution negative control ineffective" if sha(JSON.generate(substituted_pass)) == sha(JSON.generate(by_id.fetch("nested-base64")))
  substituted_finding = Marshal.load(Marshal.dump(depth8))
  substituted_finding.fetch("findings").fetch(0)["rule_id"] += "-substituted"
  abort "finding substitution changed finding count" unless substituted_finding.fetch("findings").length == depth8.fetch("findings").length
  abort "finding substitution negative control ineffective" if sha(JSON.generate(substituted_finding)) == sha(JSON.generate(depth8))
  negative_controls = {
    "schema_version" => 1,
    "same_count_pass_original_sha256" => sha(JSON.generate(by_id.fetch("nested-base64"))),
    "same_count_pass_substituted_sha256" => sha(JSON.generate(substituted_pass)),
    "same_count_finding_original_sha256" => sha(JSON.generate(depth8)),
    "same_count_finding_substituted_sha256" => sha(JSON.generate(substituted_finding)),
    "assertion" => "original and substituted hashes must differ while array counts remain equal"
  }
  negative_bytes = JSON.pretty_generate(negative_controls) + "\n"

  requests_bytes = jsonl(requests)
  outcomes_bytes = jsonl(outcomes)
  metadata = requests.zip(outcomes).map do |request, outcome|
    {
      "id" => request.fetch("id"), "operation" => request.fetch("operation"),
      "behavior_ids" => request.fetch("behavior_ids"), "test_case_ids" => request.fetch("test_case_ids"),
      "input_sha256" => outcome.fetch("input_sha256"), "config_sha256" => outcome.fetch("config_sha256"),
      "run_count" => outcome.fetch("runs").length, "finding_count" => outcome.fetch("findings").length
    }
  end
  metadata_bytes = jsonl(metadata)
  coverage = {
    "schema_version" => 1,
    "behavior_ids" => BEHAVIOR_IDS.map do |id|
      { "id" => id, "request_ids" => requests.select { |request| request.fetch("behavior_ids").include?(id) }.map { |request| request.fetch("id") } }
    end,
    "test_cases" => [
      { "id" => ROOT_ID, "kind" => "top-level-aggregator", "direct_request_ids" => [], "child_ids" => LEAF_IDS },
      { "id" => DETECT_ID, "kind" => "nested-detector-leaf", "direct_request_ids" => ["detect-encoded-depth-8"] }
    ] + LEAF_IDS.map do |id|
      { "id" => id, "kind" => "nested-codec-leaf", "direct_request_ids" => requests.select { |request| request.fetch("test_case_ids").include?(id) }.map { |request| request.fetch("id") } }
    end,
    "mandatory_cases" => mandatory_cases.map do |number, ids|
      {
        "case" => number,
        "request_ids" => ids,
        "scope" => number == 29 ? "M6 decoder context plus M7-integrated composite/proximity projection" : "M6"
      }
    end,
    "depth_finding_counts" => depth_counts
  }
  coverage_bytes = JSON.pretty_generate(coverage) + "\n"
  manifest = {
    "schema_version" => 1, "protocol_version" => PROTOCOL_VERSION, "oracle_mode" => "decoder",
    "upstream_revision" => REVISION, "default_config_sha256" => DEFAULT_SHA256,
    "go_version" => outcomes.first.fetch("go_version"),
    "scope" => ["codec-pass-output", "complete-segment-metadata", "full-decode", "direct-decoded-detector", "decoded-line-allowlist"],
    "excluded" => ["rust-implementation", "session-baseline-ignore", "source-adapters", "cli"],
    "request_count" => requests.length,
    "decode_request_count" => requests.count { |request| request.fetch("operation") == "decode" },
    "detect_request_count" => requests.count { |request| request.fetch("operation") == "detect" },
    "run_count" => outcomes.sum { |outcome| outcome.fetch("runs").length },
    "pass_count" => outcomes.sum { |outcome| outcome.fetch("runs").sum { |run| run.fetch("passes").length } },
    "segment_count" => outcomes.sum { |outcome| outcome.fetch("runs").sum { |run| run.fetch("passes").sum { |pass| pass.fetch("segments").length } } },
    "finding_count" => outcomes.sum { |outcome| outcome.fetch("findings").length },
    "behavior_id_count" => BEHAVIOR_IDS.length, "linked_decoder_leaf_count" => LEAF_IDS.length,
    "top_level_aggregator_count" => 1, "linked_detect_leaf_count" => 1,
    "fresh_process_per_request" => true, "depth_finding_counts" => depth_counts,
    "files" => {
      "requests-v1.jsonl" => { "sha256" => sha(requests_bytes), "records" => requests.length },
      "outcomes-v1.jsonl" => { "sha256" => sha(outcomes_bytes), "records" => outcomes.length },
      "request-metadata-v1.jsonl" => { "sha256" => sha(metadata_bytes), "records" => metadata.length },
      "coverage-v1.json" => { "sha256" => sha(coverage_bytes), "records" => BEHAVIOR_IDS.length + LEAF_IDS.length + 2 + mandatory_cases.length },
      "negative-controls-v1.json" => { "sha256" => sha(negative_bytes), "records" => 2 }
    }
  }
  generated["requests-v1.jsonl"] = requests_bytes
  generated["outcomes-v1.jsonl"] = outcomes_bytes
  generated["request-metadata-v1.jsonl"] = metadata_bytes
  generated["coverage-v1.json"] = coverage_bytes
  generated["negative-controls-v1.json"] = negative_bytes
  generated["manifest-v1.json"] = JSON.pretty_generate(manifest) + "\n"
end

final_status = capture("git", "status", "--short", "--untracked-files=no", chdir: UPSTREAM)
abort "upstream status changed during generation:\n#{final_status}" unless final_status == EXPECTED_UPSTREAM_STATUS

if CHECK
  generated.each do |name, bytes|
    path = OUTPUT_ROOT.join(name)
    abort "missing #{path}" unless path.file?
    committed = path.binread
    abort "#{path} differs: committed=#{sha(committed)} fresh=#{sha(bytes)}" unless committed == bytes.b
  end
else
  FileUtils.mkdir_p(OUTPUT_ROOT)
  generated.each { |name, bytes| OUTPUT_ROOT.join(name).binwrite(bytes) }
end

puts "decoder corpus #{CHECK ? 'verified' : 'generated'}: #{requests.length} fresh processes, outcomes #{sha(generated.fetch('outcomes-v1.jsonl'))}"
