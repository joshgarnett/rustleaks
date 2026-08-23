#!/usr/bin/env ruby
# frozen_string_literal: true

# Generate the frozen Go regexp compatibility corpus. The observations are
# always produced by a fresh invocation of the pinned Go oracle; --check never
# trusts the checked-in outcomes.

require "base64"
require "digest"
require "fileutils"
require "json"
require "open3"
require "pathname"
require "tempfile"

ROOT = Pathname(__dir__).parent
UPSTREAM = ROOT.parent.join("gitleaks")
ORACLE_MODULE = ROOT.join("crates/rustleaks-compat/oracle")
CONFIG_OUTCOMES = ROOT.join("compat/config-corpus/outcomes-v1.jsonl")
FIXTURES = ROOT.join("compat/fixtures/upstream/testdata/config")
GENERATOR_SAMPLES = ROOT.join("compat/generator-corpus/samples-v1.jsonl")
OUTPUT_ROOT = ROOT.join("compat/regex-corpus")
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
DEFAULT_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
PROTOCOL_VERSION = 1

CHECK = ARGV.delete("--check")
abort "usage: #{$PROGRAM_NAME} [--check]" unless ARGV.empty?

def capture(*command, chdir:, stdin_data: "")
  output, error, status = Open3.capture3(*command, chdir: chdir.to_s, stdin_data: stdin_data)
  abort "#{command.join(' ')} failed in #{chdir}:\n#{error}\n#{output}" unless status.success?
  output
end

def sha(bytes)
  Digest::SHA256.hexdigest(bytes)
end

def jsonl(records)
  records.map { |record| JSON.generate(record) + "\n" }.join
end

def b64(bytes)
  Base64.strict_encode64(bytes)
end

def load_jsonl(path)
  File.foreach(path, chomp: true).reject(&:empty?).map { |line| JSON.parse(line) }
end

def add_expression(records, source_kind:, source_path:, location:, expression_kind:, pattern:, line: nil)
  occurrence = format("RE-%04d", records.length + 1)
  records << {
    "schema_version" => 1,
    "occurrence_id" => occurrence,
    "source_kind" => source_kind,
    "source_path" => source_path,
    "source_line" => line,
    "location" => location,
    "expression_kind" => expression_kind,
    "pattern_base64" => b64(pattern.b),
    "pattern_sha256" => sha(pattern.b)
  }
end

def expressions_from_effective(records, effective)
  effective.fetch("rules").each do |rule|
    id = rule.fetch("id")
    add_expression(records, source_kind: "default", source_path: "config/gitleaks.toml",
                   location: "rules/#{id}/regex", expression_kind: "rule_regex", pattern: rule["regex"]) if rule["regex"]
    add_expression(records, source_kind: "default", source_path: "config/gitleaks.toml",
                   location: "rules/#{id}/path", expression_kind: "rule_path", pattern: rule["path"]) if rule["path"]
    rule.fetch("allowlists").each_with_index do |allowlist, allowlist_index|
      allowlist.fetch("regexes").each_with_index do |pattern, index|
        add_expression(records, source_kind: "default", source_path: "config/gitleaks.toml",
                       location: "rules/#{id}/allowlists/#{allowlist_index}/regexes/#{index}",
                       expression_kind: "rule_allowlist_regex", pattern: pattern)
      end
      allowlist.fetch("paths").each_with_index do |pattern, index|
        add_expression(records, source_kind: "default", source_path: "config/gitleaks.toml",
                       location: "rules/#{id}/allowlists/#{allowlist_index}/paths/#{index}",
                       expression_kind: "rule_allowlist_path", pattern: pattern)
      end
    end
  end
  effective.fetch("global_allowlists").each_with_index do |allowlist, allowlist_index|
    allowlist.fetch("regexes").each_with_index do |pattern, index|
      add_expression(records, source_kind: "default", source_path: "config/gitleaks.toml",
                     location: "global_allowlists/#{allowlist_index}/regexes/#{index}",
                     expression_kind: "global_allowlist_regex", pattern: pattern)
    end
    allowlist.fetch("paths").each_with_index do |pattern, index|
      add_expression(records, source_kind: "default", source_path: "config/gitleaks.toml",
                     location: "global_allowlists/#{allowlist_index}/paths/#{index}",
                     expression_kind: "global_allowlist_path", pattern: pattern)
    end
  end
end

# This fail-closed reader implements precisely the TOML string forms used by
# the pinned copied fixtures: basic/literal strings, multiline variants, and
# arrays containing those strings. It is intentionally not a general TOML
# parser. Unknown syntax aborts corpus generation instead of being omitted.
class FixtureTomlStrings
  def initialize(source)
    @source = source
    @index = 0
  end

  def parse
    whitespace
    return array if peek == "["
    [string]
  end

  private

  def peek(length = 1)
    @source[@index, length]
  end

  def whitespace
    loop do
      @index += 1 while peek && peek.match?(/[ \t\r\n]/)
      if peek == "#"
        @index += 1 until peek.nil? || peek == "\n"
      else
        break
      end
    end
  end

  def array
    @index += 1
    values = []
    loop do
      whitespace
      return values.tap { @index += 1 } if peek == "]"
      values << string
      whitespace
      if peek == ","
        @index += 1
      elsif peek != "]"
        raise "expected comma or array terminator near #{@source[@index, 24].inspect}"
      end
    end
  end

  def string
    case peek(3)
    when "'''" then literal_string("'''", true)
    when '\"\"\"' then basic_string("\"\"\"", true)
    else
      case peek
      when "'" then literal_string("'", false)
      when '"' then basic_string('"', false)
      else raise "expected TOML string near #{@source[@index, 24].inspect}"
      end
    end
  end

  def literal_string(delimiter, multiline)
    @index += delimiter.length
    finish = @source.index(delimiter, @index)
    raise "unterminated TOML literal string" unless finish
    value = @source[@index...finish]
    value = value.sub(/\A\r?\n/, "") if multiline
    @index = finish + delimiter.length
    value
  end

  def basic_string(delimiter, multiline)
    @index += delimiter.length
    value = +""
    value.force_encoding(Encoding::BINARY)
    value.sub!(/\A\r?\n/, "") if multiline
    loop do
      raise "unterminated TOML basic string" unless peek
      if peek(delimiter.length) == delimiter
        @index += delimiter.length
        return value.force_encoding(Encoding::UTF_8)
      end
      char = peek
      @index += 1
      if char != "\\"
        value << char
        next
      end
      escaped = peek
      @index += 1
      mapping = { "b" => "\b", "t" => "\t", "n" => "\n", "f" => "\f", "r" => "\r", '"' => '"', "\\" => "\\" }
      if mapping.key?(escaped)
        value << mapping.fetch(escaped)
      elsif multiline && escaped == "\n"
        @index += 1 while peek && peek.match?(/[ \t\r\n]/)
      elsif escaped == "u" || escaped == "U"
        digits = escaped == "u" ? 4 : 8
        hex = @source[@index, digits]
        raise "invalid TOML Unicode escape" unless hex && hex.match?(/\A[0-9a-fA-F]{#{digits}}\z/)
        value << [hex.to_i(16)].pack("U")
        @index += digits
      else
        raise "unsupported TOML escape \\#{escaped}"
      end
    end
  end
end

def expressions_from_fixtures(records)
  Dir.glob(FIXTURES.join("**/*.toml")).sort.each do |path_string|
    path = Pathname(path_string)
    relative = path.relative_path_from(FIXTURES).to_s
    lines = File.binread(path).force_encoding(Encoding::UTF_8).lines
    section = "root"
    section_ordinal = Hash.new(0)
    lines.each_with_index do |line, index|
      if (header = line.match(/^\s*(\[\[?[^#]+?\]\]?)\s*(?:#.*)?$/))
        section = header[1].gsub(/[\[\]\s]/, "")
        section_ordinal[section] += 1
        next
      end
      assignment = line.match(/^\s*(regex|path|regexes|paths)\s*=\s*(.*)$/)
      next unless assignment
      next if section == "extend"

      key = assignment[1]
      source = assignment[2] + lines[(index + 1)..-1].to_a.join
      values = FixtureTomlStrings.new(source).parse
      kind = case key
             when "regex" then "rule_regex"
             when "path" then section.include?("allowlist") ? "allowlist_path" : "rule_path"
             when "regexes" then "allowlist_regex"
             when "paths" then "allowlist_path"
             end
      values.each_with_index do |pattern, value_index|
        add_expression(records, source_kind: "fixture", source_path: relative,
                       location: "#{section}[#{section_ordinal[section]}]/#{key}/#{value_index}",
                       expression_kind: kind, pattern: pattern, line: index + 1)
      end
    end
  end
end

upstream_head = capture("git", "rev-parse", "HEAD", chdir: UPSTREAM).strip
abort "upstream revision changed: #{upstream_head}" unless upstream_head == REVISION
default_bytes = File.binread(ROOT.join("compat/config-corpus/default-gitleaks.toml"))
abort "default config hash changed" unless sha(default_bytes) == DEFAULT_SHA256

config_outcomes = load_jsonl(CONFIG_OUTCOMES)
default_outcome = config_outcomes.find { |record| record["id"] == "default/pinned" }
abort "missing effective pinned default configuration" unless default_outcome && default_outcome["effective"]

expressions = []
expressions_from_effective(expressions, default_outcome.fetch("effective"))
default_expression_count = expressions.length
expressions_from_fixtures(expressions)
fixture_expression_count = expressions.length - default_expression_count

base_inputs = {
  "empty" => "".b,
  "ascii-boundaries" => "Aa0_ \t\n{}$xyz".b,
  "all-bytes" => (0..255).to_a.pack("C*"),
  "valid-utf8" => "AéKİſΣσς中文🙂\n".encode(Encoding::UTF_8).b,
  "malformed-utf8" => [0xf0, 0x28, 0x8c, 0x28, 0xc0, 0xaf, 0xe2, 0x82, 0xff, 0x61, 0x80].pack("C*")
}.freeze

requests = []
request_metadata = []
add_request = lambda do |id, pattern, input, category, provenance|
  requests << {
    "protocol_version" => PROTOCOL_VERSION,
    "id" => id,
    "pattern_base64" => b64(pattern.b),
    "input_base64" => b64(input.b)
  }
  request_metadata << { "id" => id, "category" => category, "provenance" => provenance }
end

expressions.each do |expression|
  pattern = Base64.strict_decode64(expression.fetch("pattern_base64"))
  base_inputs.each do |name, input|
    add_request.call("#{expression.fetch('occurrence_id')}/#{name}", pattern, input,
                     "expression-matrix", expression.fetch("occurrence_id"))
  end
end

default_rules = default_outcome.fetch("effective").fetch("rules").each_with_object({}) do |rule, result|
  result[rule.fetch("id")] = rule
end
samples_by_rule = Hash.new { |hash, key| hash[key] = [] }
File.foreach(GENERATOR_SAMPLES) do |line|
  sample = JSON.parse(line)
  samples_by_rule[sample.fetch("rule_id")] << sample
end

sampled_rule_regexes = 0
sampled_rule_paths = 0
default_rules.keys.sort.each do |rule_id|
  rule = default_rules.fetch(rule_id)
  samples = samples_by_rule.fetch(rule_id, [])
  if rule["regex"]
    positives = samples.select { |sample| sample.fetch("oracle_observed_count") > 0 && sample["input_base64"] }
    negatives = samples.select { |sample| sample.fetch("oracle_observed_count") == 0 && sample["input_base64"] }
    unless positives.empty?
      sample = positives.min_by { |item| Base64.strict_decode64(item.fetch("input_base64")).bytesize }
      input = Base64.strict_decode64(sample.fetch("input_base64"))
      mutations = {
        "generated" => input,
        "drop-first" => input.byteslice(1..-1).to_s.b,
        "drop-last" => input.byteslice(0, [input.bytesize - 1, 0].max).to_s.b,
        "prefix-nul" => "\0".b + input,
        "suffix-invalid" => input + "\xff".b
      }
      mutations.each do |name, value|
        add_request.call("sample/regex/#{rule_id}/#{name}", rule.fetch("regex"), value,
                         "generated-regex", sample.fetch("case_id"))
      end
      sampled_rule_regexes += 1
    end
    unless negatives.empty?
      sample = negatives.min_by { |item| Base64.strict_decode64(item.fetch("input_base64")).bytesize }
      add_request.call("sample/regex/#{rule_id}/generated-negative", rule.fetch("regex"),
                       Base64.strict_decode64(sample.fetch("input_base64")), "generated-regex-negative",
                       sample.fetch("case_id"))
    end
  end
  if rule["path"]
    positives = samples.select { |sample| sample["path_present"] && sample.fetch("oracle_observed_count") > 0 }
    unless positives.empty?
      sample = positives.min_by { |item| Base64.strict_decode64(item.fetch("path_base64")).bytesize }
      input = Base64.strict_decode64(sample.fetch("path_base64"))
      add_request.call("sample/path/#{rule_id}/generated", rule.fetch("path"), input,
                       "generated-path", sample.fetch("case_id"))
      add_request.call("sample/path/#{rule_id}/drop-last", rule.fetch("path"),
                       input.byteslice(0, [input.bytesize - 1, 0].max).to_s.b,
                       "generated-path", sample.fetch("case_id"))
      sampled_rule_paths += 1
    end
  end
end

adversarial = [
  ["empty-pattern", "", "é"], ["empty-iteration", "a*", "ba"],
  ["alternation-leftmost-first", "(a|ab)(b)?", "ab a"],
  ["named-capture-p", "(?P<first>a)?(?P<second>b)", "b ab"],
  ["named-capture-angle", "(?<word>[[:alpha:]]+)", "abc 123"],
  ["duplicate-capture-names", "(?P<x>a)|(?P<x>b)", "ab"],
  ["nested-flags", "(?i:a(?-i:B)c)", "aBc abc ABC"],
  ["multiline-anchors", "(?m)^a$", "x\na\ny"], ["text-anchors", "\\A(?:a|b)\\z", "a\nb"],
  ["ascii-perl-d", "\\d+", "1١２"], ["ascii-perl-s", "\\s+", " \t\n\u00a0"],
  ["ascii-perl-w", "\\w+", "az_09é中"], ["ascii-word-boundary", "\\b\\w+\\b", "éabc中"],
  ["ascii-non-boundary", "a\\B", "a_ a中 a"], ["posix-alpha", "[[:alpha:]]+", "abcéXYZ"],
  ["posix-not-space", "[[:^space:]]+", "a b\té"],
  ["case-fold-kelvin", "(?i)k", "kKK"], ["case-fold-long-s", "(?i)s", "sSſ"],
  ["case-fold-sigma", "(?i)σ", "Σσς"], ["valid-max-repeat", "a{1000}", "a" * 1000],
  ["invalid-max-repeat", "a{1001}", "aaa"], ["valid-repeat-range", "a{0,1000}", "aaa"],
  ["invalid-repeat-range", "a{2,1}", "aaa"], ["literal-brace-template", "{{[^}]+}}", "{{value}}"],
  ["literal-brace-import", "import[ \\t]+{[ \\t\\w,]+}", "import { a, b }"],
  ["literal-brace-shell", "^\\$(?:\\d+|{\\d+})$", "${12}"],
  ["literal-brace-env", "^\\${(?:[A-Z_]+|[a-z_]+)}$", "${HOME}"],
  ["malformed-lookahead", "a(?=b)", "ab"], ["malformed-backreference", "(a)\\1", "aa"],
  ["malformed-class", "[z-a]", "z"], ["malformed-repeat", "a++", "aaa"],
  ["malformed-escape", "\\C", "C"], ["invalid-pattern-utf8", [0xff].pack("C"), "x"],
  ["dot-all-bytes", "(?s).+", base_inputs.fetch("all-bytes")],
  ["dot-malformed-utf8", ".", base_inputs.fetch("malformed-utf8")],
  ["rune-error-malformed-utf8", "\\x{FFFD}+", base_inputs.fetch("malformed-utf8")],
  ["unicode-class", "[\\p{Greek}]+", "abcΣσς"], ["ungreedy", "(?U)a+", "aaaa"],
  ["greedy-vs-ungreedy", "(a+?)(a*)", "aaaa"], ["begin-end-empty", "^|$", "a\n"]
]

adversarial.concat([
  # Go treats braces as repetition only when the complete body is valid. These
  # cases distinguish literals, malformed repetitions, and the leading-zero
  # form from a blanket brace-escaping translation.
  ["repeat-literal-open", "a{", "a{"],
  ["repeat-literal-alpha", "a{b}", "a{b}"],
  ["repeat-literal-missing-close", "a{1", "a{1"],
  ["repeat-literal-missing-close-comma", "a{1,", "a{1,"],
  ["repeat-literal-missing-min", "a{,1}", "a{,1}"],
  ["repeat-literal-alpha-max", "a{1,x}", "a{1,x}"],
  ["repeat-leading-zero", "a{01}", "a{01} a"],
  ["repeat-leading-token", "{1}", "{1}"],
  ["class-literal-intersection", "[a&&b]+", "a&b"],
  ["class-literal-symmetric-difference", "[a~~b]+", "a~b"],
  ["class-invalid-double-range", "[a--b]", "a-b"],
  ["class-literal-open", "[[]", "x[y"],
  ["class-literal-open-with-tail", "[[a]]", "[a]a"],
  ["class-range-from-open", "[[-a]+", "[\\]^_`ab"],
  ["class-nested-looking", "[[a-z]]", "[a]z]"],
  ["class-invalid-posix", "[[:bogus:]]", "a"],
  ["class-backspace-escape-rejected", "[\\b]", "\b"],
  ["class-uppercase-boundary-escape-rejected", "[\\B]", "B"],
  ["class-nonascii-escape-e-acute-rejected", "[\\é]", "é"],
  ["class-nonascii-escape-cjk-rejected", "[\\中]", "中"],
  ["class-nonascii-escape-emoji-rejected", "[\\😀]", "😀"],
  ["class-nonascii-escape-nbsp-rejected", "[\\ ]", " "],
  ["quoted-class-and-repeat", "\\Q[a&&b]{01}\\E", "[a&&b]{01}"],

  # Perl shorthands and boundaries are ASCII-only in Go.
  ["ascii-digit-arabic", "\\d+", "١"],
  ["ascii-not-digit-arabic", "\\D+", "١"],
  ["ascii-space-nbsp", "\\s+", "\u00a0"],
  ["ascii-not-space-nbsp", "\\S+", "\u00a0"],
  ["ascii-word-e-acute", "\\w+", "é"],
  ["ascii-not-word-e-acute", "\\W+", "é"],
  ["ascii-boundary-arabic", "\\b.", "١"],
  ["ascii-non-boundary-arabic", "\\B.", "١"],
  ["ascii-word-between-unicode", "\\ba\\b", "١aé"],
  ["ascii-word-fold-global", "(?i)\\w+", "KkS sKſ"],
  ["ascii-not-word-fold-global", "(?i)\\W+", "KkS sKſ!"],
  ["ascii-word-fold-scoped", "(?i:\\w+)", "KkS sKſ"],
  ["ascii-word-fold-class-scoped", "(?i:[\\w]+)", "KkS sKſ"],
  ["ascii-word-fold-ungreedy", "(?iU)\\w+", "KkS sKſ"],

  # The pinned toolchain uses Unicode 15 tables. Todhri U+105C0 was added
  # later, so the generic letter class does not match it and the script name is
  # unknown. Go exposes general categories/scripts, not derived Age or
  # Alphabetic properties.
  ["unicode15-u105c0-letter", "\\pL", "\u{105C0}"],
  ["unicode15-u105c0-not-letter", "\\PL", "\u{105C0}"],
  ["unicode-reject-todhri", "\\p{Todhri}", "\u{105C0}"],
  ["unicode-reject-age", "\\p{Age=15.0}", "A"],
  ["unicode-reject-alphabetic", "\\p{Alphabetic}", "A"],
  # Go canonicalizes property spellings before table lookup. General-category
  # aliases have a separately canonicalized map, but multiword unicode.Scripts
  # keys retain underscores and are therefore operationally unresolvable.
  ["unicode-script-canonical-valid", "\\p{latin}", "A"],
  ["unicode-category-alias-canonical-valid", "\\p{upper case-let ter}", "A"],
  ["unicode-script-multiword-key-rejected", "\\p{Old_Italic}", "\u{10300}"],
  ["unicode-script-multiword-canonical-rejected", "\\p{OldItalic}", "\u{10300}"],
  ["unicode-category-surrogate", "\\p{Cs}+", [0xed, 0xa0, 0x80].pack("C*")],
  ["unicode-category-not-surrogate", "\\P{Cs}+", [0xed, 0xa0, 0x80].pack("C*")],
  ["unicode-surrogate-name", "\\p{Surrogate}", [0xed, 0xa0, 0x80].pack("C*")],
  ["unicode-not-surrogate-name", "\\P{Surrogate}", [0xed, 0xa0, 0x80].pack("C*")],
  ["replacement-literal-valid-e-acute", "�", "é"],
  ["replacement-literal-actual", "�", "�"],

  # Empty-match advancement is by decoded rune, while indexes remain bytes.
  ["empty-pattern-e-acute", "", "é"],
  ["empty-pattern-poop", "", "💩"],
  ["empty-alternative-unicode", "(?:)|.", "é💩"],
  ["optional-dot-unicode", ".?", "é💩"],

  # Go permits ASCII digit-first and duplicate names, but rejects non-ASCII
  # names. The full SubexpNames vector is part of the outcome.
  ["capture-name-digit-first", "(?P<1>a)", "a"],
  ["capture-name-digit-first-duplicate", "(?P<1>a)(?P<1>b)?", "ab a"],
  ["capture-name-unicode", "(?P<é>a)", "a"],
  ["capture-zero-repeat", "(a){0}", "a"],
  ["capture-zero-repeat-before-live", "(a){0}(b)", "b"],
  ["capture-zero-repeat-named", "(?P<gone>a){0}(?P<live>b)", "b"],
  ["capture-zero-repeat-duplicate-name", "(?P<x>a){0}(?P<x>b)", "b"],

  # Go's $ anchor is strict at text end unless m is active, and m recognizes
  # only the LF boundary (so CR remains part of a CRLF line).
  ["anchor-crlf-no-strip", "(?m)^b$", "a\r\nb\r\n"],
  ["anchor-crlf-explicit-cr", "(?m)^b\\r$", "a\r\nb\r\n"],
  ["anchor-final-newline-strict", "x$", "x\n"],
  ["anchor-final-newline-multiline", "(?m)x$", "x\n"],
  ["anchor-final-newline-z-fail", "x\\z", "x\n"],
  ["anchor-final-newline-z-exact", "x\\n\\z", "x\n"],
  ["anchor-empty-multiline-crlf", "(?m)^|$", "\r\n"],

  # Syntax accepted by Rust regex but not Go, plus Rust's extended word
  # boundary forms. The latter are intentionally observed rather than assumed
  # to fail because Go may parse the brace suffix literally.
  ["rust-only-unicode-flag", "(?u:\\w+)", "é"],
  ["rust-only-crlf-flag", "(?R:^.$)", "\r\n"],
  ["rust-only-verbose-flag", "(?x:a # comment\n)", "a"],
  ["rust-only-unicode-escape", "\\u{41}", "A"],
  ["hex-long-leading-zero", "\\x{000000000041}", "A"],
  ["hex-surrogate-literal", "\\x{D800}", "A\u{FFFD}"],
  ["hex-surrogate-class", "[\\x{D800}]", "A\u{FFFD}"],
  ["hex-surrogate-class-complement", "[^\\x{D800}]", "A\u{FFFD}"],
  ["hex-surrogate-upper-range-end", "[\\x{D7FF}-\\x{D800}]", "\u{D7FF}\u{E000}"],
  ["hex-surrogate-lower-range-end", "[\\x{DFFF}-\\x{E000}]", "\u{D7FF}\u{E000}"],
  ["hex-surrogate-full-range", "[\\x{D800}-\\x{DFFF}]", "A\u{FFFD}"],
  ["hex-surrogate-spanning-range", "[\\x{D7FF}-\\x{E000}]", "\u{D7FF}\u{E000}"],
  ["hex-surrogate-spanning-range-negated", "[^\\x{D7FF}-\\x{E000}]", "A\u{D7FF}\u{E000}"],
  ["rust-only-uppercase-end-anchor", "x\\Z", "x"],
  ["rust-word-boundary-start", "\\b{start}a", "{start}a a"],
  ["rust-word-boundary-end", "a\\b{end}", "a{end} a"],
  ["rust-word-boundary-start-half", "\\b{start-half}a", "{start-half}a a"],
  ["rust-word-boundary-end-half", "a\\b{end-half}", "a{end-half} a"]
])

adversarial.concat([
  ["empty-flag-group", "(?)", "éa"],
  ["empty-flag-group-between-literals", "a(?)b", "ab a(?)b"],
  ["empty-flag-group-star-rejected", "(?)*", "a"],
  ["empty-flag-group-question-rejected", "(?)?", "a"],
  ["empty-flag-group-plus-rejected", "(?)+", "a"],
  ["empty-flag-group-repeat-rejected", "(?){1}", "a"],
  ["flag-directive-star-rejected", "(?i)*", "a"],
  ["flag-directive-question-rejected", "(?i)?", "a"],
  ["flag-directive-plus-rejected", "(?i)+", "a"],
  ["flag-directive-adjacent-repeat-accepted", "b(?i){1,2}", "bb"],
  ["flag-scoped-empty-repeatable", "(?i:)*", "a"],
  ["directive-after-star-plus", "a*(?i)+", "aaaA"],
  ["directive-after-star-repeat", "\\s*(?i){1,2}", "  \tA"],
  ["empty-directive-after-lazy-question", "$+?(?)?", "a"],
  ["empty-directive-after-class-repeat", "[\\w]*(?){1,2}", "abc!"],
  ["empty-directive-after-plus-star", "a+(?)*", "aaa"],
  ["empty-directive-after-counted-repeat", "a{2}(?){3}", "aaaaaa"],
  ["ungreedy-directive-before-star", "a(?U)*a", "aaa"],
  ["ungreedy-directive-before-plus", "a(?U)+a", "aaa"],
  ["ungreedy-directive-before-repeat", "a(?U){1,2}a", "aaaa"],
  ["greedy-directive-before-star", "(?U)a(?-U)*a", "aaa"],
  ["ungreedy-directive-lazy-reversal", "a(?U)*?a", "aaaa"],
  ["escaped-less-than-literal", "\\<", "Aa_<>!q123"],
  ["escaped-greater-than-literal", "\\>", "Aa_<>!q123"],
  ["escaped-angle-pair-literal", "\\<\\>", "Aa_<>!q123"]
])

adversarial.concat([
  ["flags-overlap-scoped", "(?i-i:a)", "Aa"],
  ["flags-overlap-unscoped", "(?i-i)a", "Aa"],
  ["flags-overlap-multiple", "(?im-im:^a$)", "A\na"],
  ["flags-duplicate-enable", "(?ii:a)", "Aa"],
  ["flags-duplicate-disable", "(?i)(?-ii:a)", "Aa"],
  ["flags-mixed-overlap", "(?im-mi:^a$)", "A\na"],
  ["flags-second-hyphen-rejected", "(?-i-i:a)", "a"]
])

adversarial.concat([
  ["nesting-capture-999", "(" * 999 + "a" + ")" * 999, "a"],
  ["nesting-capture-1000", "(" * 1000 + "a" + ")" * 1000, "a"],
  ["nesting-noncapture-999", "(?:" * 999 + "a" + ")" * 999, "a"],
  ["nesting-noncapture-1000", "(?:" * 1000 + "a" + ")" * 1000, "a"]
])

# Every malformed byte is decoded by Go as a width-one RuneError. The matrix
# freezes both repeated matching and the original-byte capture coordinates,
# including a.b cases where more than one invalid byte prevents the match.
malformed_inputs = {
  "isolated-ff" => [0xff],
  "isolated-continuation" => [0x80],
  "truncated-two" => [0xc2],
  "truncated-three" => [0xe2, 0x82],
  "truncated-four" => [0xf0, 0x9f, 0x92],
  "invalid-continuation-three" => [0xe2, 0x28, 0xa1],
  "overlong" => [0xc0, 0xaf],
  "surrogate-encoding" => [0xed, 0xa0, 0x80],
  "out-of-range" => [0xf4, 0x90, 0x80, 0x80],
  "adjacent-invalid" => [0xff, 0x80]
}.transform_values { |bytes| bytes.pack("C*") }

malformed_inputs.each do |name, input|
  adversarial.concat([
    ["malformed-#{name}-dot", ".", input],
    ["malformed-#{name}-any", "\\p{Any}", input],
    ["malformed-#{name}-negated-class", "[^a]", input],
    ["malformed-#{name}-wrapped-dot", "a.b", "a".b + input + "b".b],
    ["malformed-#{name}-capture", "(�)(.)?", input],
    ["malformed-#{name}-replacement-literal", "�", input]
  ])
end

# Go exposes these named ASCII POSIX classes. Exercise every positive and
# negated form over one byte-diverse input so translator mistakes cannot hide
# behind a single alpha/space example.
posix_input = "Az09_ \t\n!~\x00é".b
%w[alnum alpha ascii blank cntrl digit graph lower print punct space upper word xdigit].each do |name|
  adversarial << ["posix-matrix-#{name}", "[[:#{name}:]]+", posix_input]
  adversarial << ["posix-matrix-not-#{name}", "[[:^#{name}:]]+", posix_input]
end

adversarial_ids = adversarial.map(&:first)
duplicate_adversarial_ids = adversarial_ids.group_by(&:itself).select { |_id, values| values.length > 1 }.keys
abort "duplicate adversarial IDs: #{duplicate_adversarial_ids.join(', ')}" unless duplicate_adversarial_ids.empty?
adversarial.each do |name, pattern, input|
  add_request.call("adversarial/#{name}", pattern.b, input.b, "adversarial", name)
end

request_ids = requests.map { |request| request.fetch("id") }
duplicate_request_ids = request_ids.group_by(&:itself).select { |_id, values| values.length > 1 }.keys
abort "duplicate regex request IDs: #{duplicate_request_ids.join(', ')}" unless duplicate_request_ids.empty?

request_bytes = jsonl(requests)
outcome_bytes = capture("go", "run", ".", "--regex", chdir: ORACLE_MODULE, stdin_data: request_bytes)
outcomes = outcome_bytes.each_line.map { |line| JSON.parse(line) }
abort "oracle returned #{outcomes.length} outcomes for #{requests.length} requests" unless outcomes.length == requests.length
requests.each_with_index do |request, index|
  outcome = outcomes[index]
  abort "oracle response order changed at #{index}" unless outcome.fetch("id") == request.fetch("id")
  abort "oracle response revision changed" unless outcome.fetch("upstream_revision") == REVISION
  abort "oracle response default hash changed" unless outcome.fetch("default_config_sha256") == DEFAULT_SHA256
  abort "oracle response mode changed" unless outcome.fetch("oracle_mode") == "regex"
  abort "oracle request failed: #{outcome.inspect}" if outcome["error"]
  request_metadata[index]["request_sha256"] = sha(JSON.generate(request) + "\n")
  request_metadata[index]["outcome_sha256"] = sha(JSON.generate(outcome) + "\n")
end

expression_bytes = jsonl(expressions)
metadata_bytes = jsonl(request_metadata)
compile_successes = outcomes.count { |outcome| outcome.fetch("compile").fetch("success") }
compile_errors = outcomes.length - compile_successes
matching = outcomes.count { |outcome| outcome.fetch("match_exists") }
manifest = {
  "schema_version" => 1,
  "protocol_version" => PROTOCOL_VERSION,
  "upstream_revision" => REVISION,
  "default_config_sha256" => DEFAULT_SHA256,
  "go_version" => outcomes.first.fetch("go_version"),
  "unicode_version" => outcomes.first.fetch("unicode_version"),
  "expression_occurrence_count" => expressions.length,
  "default_expression_occurrence_count" => default_expression_count,
  "fixture_expression_occurrence_count" => fixture_expression_count,
  "unique_pattern_count" => expressions.map { |item| item.fetch("pattern_sha256") }.uniq.length,
  "base_input_count" => base_inputs.length,
  "sampled_default_rule_regex_count" => sampled_rule_regexes,
  "sampled_default_rule_path_count" => sampled_rule_paths,
  "adversarial_case_count" => adversarial.length,
  "request_count" => requests.length,
  "compile_success_count" => compile_successes,
  "compile_error_count" => compile_errors,
  "matching_request_count" => matching,
  "files" => {
    "expressions-v1.jsonl" => { "sha256" => sha(expression_bytes), "records" => expressions.length },
    "requests-v1.jsonl" => { "sha256" => sha(request_bytes), "records" => requests.length },
    "request-metadata-v1.jsonl" => { "sha256" => sha(metadata_bytes), "records" => request_metadata.length },
    "outcomes-v1.jsonl" => { "sha256" => sha(outcome_bytes), "records" => outcomes.length }
  }
}
manifest_bytes = JSON.pretty_generate(manifest) + "\n"
readme = <<~MARKDOWN
  # Go regexp compatibility corpus

  This directory is generated by `ruby compat/generate_regex_corpus.rb` from
  pinned Gitleaks revision `#{REVISION}`. `--check` reruns every request through
  a fresh Go process and byte-compares all generated artifacts.

  Patterns and inputs use base64 so arbitrary bytes survive JSON. Go's `regexp`
  API receives a string: each malformed UTF-8 byte is observed as a width-one
  `utf8.RuneError`, while match and capture indexes remain byte offsets in the
  original string. Capture index zero is the full match; unmatched captures are
  explicitly `[-1,-1]`. `FindAllStringSubmatchIndex(..., -1)` defines empty-
  match suppression and non-overlapping iteration.

  `expressions-v1.jsonl` preserves every expression occurrence from the exact
  compiled default plus every `regex`, `path`, `regexes`, and `paths` value in
  the copied pinned `testdata/config` tree (extension paths are not regexes).
  The fixture reader is intentionally limited to the basic/literal strings and
  string arrays present in that pinned tree and fails generation on any unknown
  form. Generated samples select the shortest available positive (and negative,
  when present) upstream generator sample per default rule; rules without an
  upstream generated positive remain covered by the five-input byte matrix.

  Counts and SHA-256 digests are frozen in `manifest-v1.json`.
  `request-metadata-v1.jsonl` also hashes each request and outcome line
  individually.
MARKDOWN

generated = {
  "expressions-v1.jsonl" => expression_bytes,
  "requests-v1.jsonl" => request_bytes,
  "request-metadata-v1.jsonl" => metadata_bytes,
  "outcomes-v1.jsonl" => outcome_bytes,
  "manifest-v1.json" => manifest_bytes,
  "README.md" => readme
}

if CHECK
  generated.each do |name, bytes|
    path = OUTPUT_ROOT.join(name)
    abort "missing generated file #{path}" unless path.file?
    actual = File.binread(path)
    next if actual == bytes.b
    expected_lines = bytes.b.lines
    actual_lines = actual.lines
    difference = (0...[expected_lines.length, actual_lines.length].max).find do |index|
      expected_lines[index] != actual_lines[index]
    end
    expected_line = expected_lines[difference].to_s.b
    actual_line = actual_lines[difference].to_s.b
    abort "generated file differs at line #{difference + 1}: #{path} " \
          "(expected #{sha(expected_line)}, actual #{sha(actual_line)})"
  end
  puts "regex corpus is current (#{requests.length} requests, #{sha(outcome_bytes)})"
else
  FileUtils.mkdir_p(OUTPUT_ROOT)
  generated.each { |name, bytes| File.binwrite(OUTPUT_ROOT.join(name), bytes) }
  puts "wrote #{requests.length} regex requests (#{sha(outcome_bytes)})"
end
