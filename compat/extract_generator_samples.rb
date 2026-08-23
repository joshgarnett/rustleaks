#!/usr/bin/env ruby
# frozen_string_literal: true

# Extracts the validation cases embedded in the pinned upstream default-rule
# constructors. The upstream checkout is never edited: a git archive is made in
# a temporary directory and only that copy is instrumented.

require "base64"
require "digest"
require "fileutils"
require "json"
require "open3"
require "pathname"
require "tmpdir"

ROOT = Pathname(__dir__).parent
ORACLE = ROOT.parent.join("gitleaks")
CORPUS = ROOT.join("compat/generator-corpus")
SAMPLES = CORPUS.join("samples-v1.jsonl")
CONSTRUCTORS = CORPUS.join("constructors-v1.jsonl")

REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
CONFIG_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
FROZEN_CONSTRUCTORS_SHA256 = "b7f69ca6317157c7ca8015ec897ec82371e6e362067c6c799c61f0c4819cd7c1"
FROZEN_SAMPLES_SHA256 = "b0d1e24c04f88ec3c875bcbd08a6e0cafbabd7f7cf8757af5e385eb83259b750"
SCHEMA_VERSION = 1

EXPECTED_SAMPLE_TOTALS = {
  "ordinary_true" => 6_368,
  "ordinary_false" => 342,
  "path_true" => 28,
  "path_false" => 32
}.freeze

EXPECTED_EXCLUSIONS = {
  "GCPServiceAccount" => "excluded-default; helper fails: escaped keyword does not occur in positive sample",
  "SquareSecret" => "excluded-default; helper passes when invoked independently",
  "TrelloAccessToken" => "excluded-default; helper passes when invoked independently"
}.freeze

EXPECTED_GAPS = {
  "DropBoxLongLivedAPIToken" => "selected-default; validate TODO returns rule without helper",
  "DropBoxShortLivedAPIToken" => "selected-default; validate TODO returns rule without helper"
}.freeze

class CorpusError < StandardError; end

def fail_corpus(message)
  raise CorpusError, message
end

def capture(*command, chdir: ROOT, env: {})
  output, error, status = Open3.capture3(env, *command, chdir: chdir.to_s)
  fail_corpus("#{command.join(' ')} failed: #{error}") unless status.success?
  output
end

def verify_upstream!
  fail_corpus("missing upstream checkout: #{ORACLE}") unless ORACLE.directory?
  actual_revision = capture("git", "rev-parse", "HEAD", chdir: ORACLE).strip
  fail_corpus("upstream revision mismatch: expected #{REVISION}, got #{actual_revision}") unless actual_revision == REVISION

  config = ORACLE.join("config/gitleaks.toml")
  actual_hash = Digest::SHA256.file(config).hexdigest
  fail_corpus("upstream config hash mismatch: expected #{CONFIG_SHA256}, got #{actual_hash}") unless actual_hash == CONFIG_SHA256

  relevant = capture(
    "git", "status", "--porcelain", "--untracked-files=no", "--",
    "cmd/generate", "config/gitleaks.toml", chdir: ORACLE
  )
  fail_corpus("tracked generator/config changes exist in read-only upstream checkout") unless relevant.empty?
end

def line_number(source, byte_offset)
  source.byteslice(0, byte_offset).count("\n") + 1
end

def constructor_inventory
  records = ORACLE.glob("cmd/generate/config/rules/*.go").sort.flat_map do |path|
    source = path.binread
    matches = source.enum_for(:scan, /^func ([A-Z][A-Za-z0-9_]*)\(\) \*config\.Rule/m).map { Regexp.last_match }
    matches.each_with_index.map do |match, index|
      body_end = index + 1 < matches.length ? matches[index + 1].begin(0) : source.bytesize
      body = source.byteslice(match.begin(0)...body_end)
      helper_match = body.match(/return\s+utils\.(ValidateWithPaths|Validate)\s*\(/m)
      helper = case helper_match&.[](1)
               when "ValidateWithPaths" then "validate_with_paths"
               when "Validate" then "validate"
               else "none"
               end
      rule_id = body[/\bRuleID:\s*"([^"]+)"/, 1]
      fail_corpus("#{match[1]} has no literal RuleID") unless rule_id

      relative = path.relative_path_from(ORACLE).to_s
      constructor_line = line_number(source, match.begin(0))
      helper_line = helper_match && constructor_line + body.byteslice(0, helper_match.begin(0)).count("\n")
      {
        "schema_version" => SCHEMA_VERSION,
        "record_type" => "generator_constructor",
        "upstream_revision" => REVISION,
        "constructor" => match[1],
        "rule_id" => rule_id,
        "source_file" => relative,
        "constructor_line" => constructor_line,
        "helper_line" => helper_line,
        "helper" => helper,
        "constructor_source_sha256" => Digest::SHA256.hexdigest(body)
      }
    end
  end

  main = ORACLE.join("cmd/generate/config/main.go").read
  selected = main.lines.each_with_object([]) do |line, found|
    next if line.lstrip.start_with?("//")
    name = line[/^\s*rules\.([A-Z][A-Za-z0-9_]*)\(\),/, 1]
    found << name if name
  end
  fail_corpus("expected 222 selected constructors, got #{selected.length}") unless selected.length == 222
  fail_corpus("selected constructor names are not unique") unless selected.uniq.length == selected.length

  by_name = records.to_h { |record| [record.fetch("constructor"), record] }
  missing = selected - by_name.keys
  fail_corpus("selected constructors missing from source inventory: #{missing.join(', ')}") unless missing.empty?

  selected_ids = selected.map { |name| by_name.fetch(name).fetch("rule_id") }
  config_ids = ORACLE.join("config/gitleaks.toml").read.scan(/^id = "([^"]+)"$/).flatten
  fail_corpus("expected 222 generated config RuleIDs, got #{config_ids.length}") unless config_ids.length == 222
  fail_corpus("selected constructor RuleIDs differ from generated config") unless selected_ids.sort == config_ids.sort

  records.each do |record|
    name = record.fetch("constructor")
    is_selected = selected.include?(name)
    record["selected_default"] = is_selected
    record["helper_covered"] = is_selected && record.fetch("helper") != "none"
    if EXPECTED_EXCLUSIONS.key?(name)
      record["disposition"] = "excluded_default"
      record["exception"] = EXPECTED_EXCLUSIONS.fetch(name)
    elsif EXPECTED_GAPS.key?(name)
      record["disposition"] = "selected_gap"
      record["exception"] = EXPECTED_GAPS.fetch(name)
    else
      record["disposition"] = is_selected ? "selected_helper" : "unexpected_exclusion"
      record["exception"] = nil
    end
  end
  records.sort_by { |record| record.fetch("constructor") }
end

OBSERVER_VALIDATE_GO = <<~'GO'
  // Generated only inside a temporary git archive by extract_generator_samples.rb.
  package utils

  import (
      "encoding/base64"
      "encoding/json"
      "os"
      "runtime"
      "sort"
      "strings"

      "github.com/zricethezav/gitleaks/v8/cmd/generate/config/base"
      "github.com/zricethezav/gitleaks/v8/config"
      "github.com/zricethezav/gitleaks/v8/detect"
      "github.com/zricethezav/gitleaks/v8/logging"
      "github.com/zricethezav/gitleaks/v8/report"
  )

  type sampleOrigin struct {
      TemplateKey string
      SourceFile  string
      SourceLine  int
  }

  type loggedFinding struct {
      MatchBase64  string `json:"match_base64"`
      SecretBase64 string `json:"secret_base64"`
  }

  type loggedDependencies struct {
      Entropy            float64  `json:"entropy"`
      KeywordBase64      []string `json:"keyword_base64"`
      RuleAllowlistCount int      `json:"rule_allowlist_count"`
      HasPath            bool     `json:"has_path"`
      SecretGroup        int      `json:"secret_group"`
      GlobalAllowlist    bool     `json:"global_allowlist"`
  }

  type loggedRecord struct {
      Constructor     string             `json:"constructor"`
      RuleID          string             `json:"rule_id"`
      Helper          string             `json:"helper"`
      Polarity        string             `json:"polarity"`
      Ordinal         int                `json:"ordinal"`
      Contract        string             `json:"contract"`
      HelperSource    string             `json:"helper_source_file"`
      HelperLine      int                `json:"helper_line"`
      OriginKind      string             `json:"origin_kind"`
      OriginSource    string             `json:"origin_source_file"`
      OriginLine      int                `json:"origin_line"`
      TemplateKey     *string            `json:"template_key"`
      InputBase64     string             `json:"input_base64"`
      PathPresent     bool               `json:"path_present"`
      PathBase64      *string            `json:"path_base64"`
      Findings        []loggedFinding    `json:"findings"`
      Dependencies    loggedDependencies `json:"dependencies"`
  }

  var sampleOrigins = map[string][]sampleOrigin{}
  var observationFile *os.File

  func relativeSource(path string) string {
      marker := "/cmd/generate/"
      if index := strings.Index(path, marker); index >= 0 {
          return path[index+1:]
      }
      return path
  }

  func registerSampleOrigin(value string, templateKey string, sourceFile string, sourceLine int) {
      sampleOrigins[value] = append(sampleOrigins[value], sampleOrigin{
          TemplateKey: templateKey,
          SourceFile: relativeSource(sourceFile),
          SourceLine: sourceLine,
      })
  }

  func consumeSampleOrigin(value string) (sampleOrigin, bool) {
      origins := sampleOrigins[value]
      if len(origins) == 0 {
          return sampleOrigin{}, false
      }
      origin := origins[0]
      if len(origins) == 1 {
          delete(sampleOrigins, value)
      } else {
          sampleOrigins[value] = origins[1:]
      }
      return origin, true
  }

  func caller() (string, string, int) {
      pc, file, line, ok := runtime.Caller(3)
      if !ok {
          return "unknown", "unknown", 0
      }
      name := runtime.FuncForPC(pc).Name()
      if index := strings.LastIndex(name, "."); index >= 0 {
          name = name[index+1:]
      }
      return name, relativeSource(file), line
  }

  func encode(value string) string {
      return base64.StdEncoding.EncodeToString([]byte(value))
  }

  func dependencies(rule *config.Rule) loggedDependencies {
      keywords := make([]string, len(rule.Keywords))
      for index, keyword := range rule.Keywords {
          keywords[index] = encode(keyword)
      }
      return loggedDependencies{
          Entropy: rule.Entropy,
          KeywordBase64: keywords,
          RuleAllowlistCount: len(rule.Allowlists),
          HasPath: rule.Path != nil,
          SecretGroup: rule.SecretGroup,
          GlobalAllowlist: true,
      }
  }

  func writeObservation(record loggedRecord) {
      if observationFile == nil {
          path := os.Getenv("RUSTLEAKS_GENERATOR_SAMPLE_LOG")
          if path == "" {
              panic("RUSTLEAKS_GENERATOR_SAMPLE_LOG is unset")
          }
          file, err := os.Create(path)
          if err != nil {
              panic(err)
          }
          observationFile = file
      }
      if err := json.NewEncoder(observationFile).Encode(record); err != nil {
          panic(err)
      }
  }

  func logCase(rule *config.Rule, helper string, polarity string, ordinal int, contract string, input string, path *string, findings []report.Finding) {
      constructor, helperSource, helperLine := caller()
      origin, generated := consumeSampleOrigin(input)
      originKind := "direct"
      originSource := helperSource
      originLine := helperLine
      var templateKey *string
      if generated {
          originKind = "generated_template"
          originSource = origin.SourceFile
          originLine = origin.SourceLine
          key := origin.TemplateKey
          templateKey = &key
      }
      loggedFindings := make([]loggedFinding, 0, len(findings))
      for _, finding := range findings {
          loggedFindings = append(loggedFindings, loggedFinding{
              MatchBase64: encode(finding.Match),
              SecretBase64: encode(finding.Secret),
          })
      }
      var pathBase64 *string
      if path != nil {
          encoded := encode(*path)
          pathBase64 = &encoded
      }
      writeObservation(loggedRecord{
          Constructor: constructor,
          RuleID: rule.RuleID,
          Helper: helper,
          Polarity: polarity,
          Ordinal: ordinal,
          Contract: contract,
          HelperSource: helperSource,
          HelperLine: helperLine,
          OriginKind: originKind,
          OriginSource: originSource,
          OriginLine: originLine,
          TemplateKey: templateKey,
          InputBase64: encode(input),
          PathPresent: path != nil,
          PathBase64: pathBase64,
          Findings: loggedFindings,
          Dependencies: dependencies(rule),
      })
  }

  func Validate(rule config.Rule, truePositives []string, falsePositives []string) *config.Rule {
      r := &rule
      d := createSingleRuleDetector(r)
      for ordinal, tp := range truePositives {
          findings := d.DetectString(tp)
          logCase(r, "validate", "ordinary_true", ordinal, "at_least_one", tp, nil, findings)
          if len(findings) < 1 {
              logging.Fatal().Str("rule", r.RuleID).Str("value", tp).Str("regex", r.Regex.String()).Msg("Failed to Validate. True positive was not detected by regex.")
          }
      }
      for ordinal, fp := range falsePositives {
          findings := d.DetectString(fp)
          logCase(r, "validate", "ordinary_false", ordinal, "zero", fp, nil, findings)
          if len(findings) != 0 {
              logging.Fatal().Str("rule", r.RuleID).Str("value", fp).Str("regex", r.Regex.String()).Msg("Failed to Validate. False positive was detected by regex.")
          }
      }
      return r
  }

  func sortedPaths(samples map[string]string) []string {
      paths := make([]string, 0, len(samples))
      for path := range samples {
          paths = append(paths, path)
      }
      sort.Strings(paths)
      return paths
  }

  func ValidateWithPaths(rule config.Rule, truePositives map[string]string, falsePositives map[string]string) *config.Rule {
      r := &rule
      d := createSingleRuleDetector(r)
      for ordinal, path := range sortedPaths(truePositives) {
          tp := truePositives[path]
          fragment := detect.Fragment{Raw: tp, FilePath: path}
          findings := d.Detect(fragment)
          logCase(r, "validate_with_paths", "path_true", ordinal, "exactly_one", tp, &path, findings)
          if len(findings) != 1 {
              logging.Fatal().Str("rule", r.RuleID).Str("value", tp).Str("regex", r.Regex.String()).Str("path", r.Path.String()).Msg("Failed to Validate. True positive was not detected by regex and/or path.")
          }
      }
      for ordinal, path := range sortedPaths(falsePositives) {
          fp := falsePositives[path]
          fragment := detect.Fragment{Raw: fp, FilePath: path}
          findings := d.Detect(fragment)
          logCase(r, "validate_with_paths", "path_false", ordinal, "zero", fp, &path, findings)
          if len(findings) != 0 {
              logging.Fatal().Str("rule", r.RuleID).Str("value", fp).Str("regex", r.Regex.String()).Str("path", r.Path.String()).Msg("Failed to Validate. False positive was detected by regex and/or path.")
          }
      }
      return r
  }

  func createSingleRuleDetector(r *config.Rule) *detect.Detector {
      uniqueKeywords := make(map[string]struct{})
      var keywords []string
      for _, keyword := range r.Keywords {
          normalized := strings.ToLower(keyword)
          if _, ok := uniqueKeywords[normalized]; ok {
              continue
          }
          keywords = append(keywords, normalized)
          uniqueKeywords[normalized] = struct{}{}
      }
      r.Keywords = keywords
      rules := map[string]config.Rule{r.RuleID: *r}
      cfg := base.CreateGlobalConfig()
      cfg.Rules = rules
      cfg.Keywords = uniqueKeywords
      for _, allowlist := range cfg.Allowlists {
          if err := allowlist.Validate(); err != nil {
              logging.Fatal().Err(err).Msg("invalid global allowlist")
          }
      }
      return detect.NewDetector(cfg)
  }
GO

def instrument_generate_helpers!(path)
  source = path.read
  import_change = source.sub!(%Q{\t"fmt"\n\t"strings"\n}, %Q{\t"fmt"\n\t"runtime"\n\t"sort"\n\t"strings"\n})
  single_change = source.sub!(
    /func GenerateSampleSecret\(identifier string, secret string\) string \{.*?^\}/m,
    <<~'GO'.chomp
      func GenerateSampleSecret(identifier string, secret string) string {
          sample := fmt.Sprintf("%s_api_token = \"%s\"", identifier, secret)
          _, file, line, _ := runtime.Caller(1)
          registerSampleOrigin(sample, "single - api token assignment", file, line)
          return sample
      }
    GO
  )
  new_loop = [
    "\tkeys := make([]string, 0, len(samples))",
    "\tfor key := range samples {",
    "\t\tkeys = append(keys, key)",
    "\t}",
    "\tsort.Strings(keys)",
    "\t_, file, line, _ := runtime.Caller(1)",
    "\tcases := make([]string, 0, len(samples))",
    "\tfor _, key := range keys {",
    "\t\tsample := replacer.Replace(samples[key])",
    "\t\tregisterSampleOrigin(sample, key, file, line)",
    "\t\tcases = append(cases, sample)",
    "\t}",
    "\treturn cases"
  ].join("\n")
  loop_change = source.sub!(
    /\tcases := make\(\[\]string, 0, len\(samples\)\)\n\tfor _, v := range samples \{\n\t\tcases = append\(cases, replacer\.Replace\(v\)\)\n\t\}\n\treturn cases/,
    new_loop
  )
  fail_corpus("failed to instrument generate.go imports") unless import_change
  fail_corpus("failed to instrument GenerateSampleSecret") unless single_change
  fail_corpus("failed to instrument GenerateSampleSecrets") unless loop_change
  path.write(source)
end

def instrument_secret_generator!(path)
  source = path.read
  changed = source.sub!(
    /func NewSecret\(regex string\) string \{.*?^\}/m,
    <<~'GO'.chomp
      func deterministicSeed(regex string) int64 {
          hash := uint64(14695981039346656037)
          for index := 0; index < len(regex); index++ {
              hash ^= uint64(regex[index])
              hash *= 1099511628211
          }
          return int64(hash)
      }

      func concentrationScore(value string) int {
          counts := [256]int{}
          for index := 0; index < len(value); index++ {
              counts[value[index]]++
          }
          score := 0
          for _, count := range counts {
              score += count * count
          }
          return score
      }

      func NewSecret(regex string) string {
          g, err := reggen.NewGenerator(regex)
          if err != nil {
              panic(err)
          }
          baseSeed := deterministicSeed(regex)
          best := ""
          bestScore := 0
          for offset := int64(0); offset < 128; offset++ {
              g.SetSeed(baseSeed + offset)
              candidate := g.Generate(1)
              score := concentrationScore(candidate)
              if offset == 0 || score < bestScore || (score == bestScore && candidate < best) {
                  best = candidate
                  bestScore = score
              }
          }
          return best
      }
    GO
  )
  fail_corpus("failed to instrument deterministic secret generation") unless changed
  path.write(source)
end

def archive_upstream!(destination)
  commands = [
    ["git", "-C", ORACLE.to_s, "archive", "--format=tar", REVISION],
    ["tar", "-x", "-C", destination.to_s]
  ]
  statuses = Open3.pipeline(*commands, out: File::NULL)
  fail_corpus("git archive extraction failed") unless statuses.all?(&:success?)
end

def extract_observations(inventory)
  by_name = inventory.to_h { |record| [record.fetch("constructor"), record] }
  raw_records = nil

  Dir.mktmpdir("gitleaks-generator-corpus") do |directory|
    temporary = Pathname(directory)
    archive_upstream!(temporary)
    temporary.join("cmd/generate/config/utils/validate.go").write(OBSERVER_VALIDATE_GO)
    instrument_generate_helpers!(temporary.join("cmd/generate/config/utils/generate.go"))
    instrument_secret_generator!(temporary.join("cmd/generate/secrets/regen.go"))

    log = temporary.join("observations.jsonl")
    generated_config = temporary.join("generated.toml")
    go_env = {
      "GOCACHE" => ENV.fetch("GOCACHE", File.join(Dir.tmpdir, "rustleaks-go-cache")),
      "GOMODCACHE" => ENV.fetch("GOMODCACHE", File.join(Dir.tmpdir, "rustleaks-go-mod-cache")),
      "RUSTLEAKS_GENERATOR_SAMPLE_LOG" => log.to_s
    }
    capture("go", "run", ".", generated_config.to_s, chdir: temporary.join("cmd/generate/config"), env: go_env)
    generated_hash = Digest::SHA256.file(generated_config).hexdigest
    fail_corpus("instrumentation changed generated config: #{generated_hash}") unless generated_hash == CONFIG_SHA256
    raw_records = log.each_line.with_index(1).map do |line, line_index|
      JSON.parse(line)
    rescue JSON::ParserError => error
      fail_corpus("invalid observer JSON at line #{line_index}: #{error.message}")
    end
  end

  records = raw_records.map do |raw|
    constructor = by_name[raw.fetch("constructor")]
    fail_corpus("observer emitted unknown constructor #{raw.fetch('constructor')}") unless constructor
    fail_corpus("observer emitted unselected constructor #{raw.fetch('constructor')}") unless constructor.fetch("selected_default")
    fail_corpus("observer RuleID mismatch for #{raw.fetch('constructor')}") unless raw.fetch("rule_id") == constructor.fetch("rule_id")
    fail_corpus("observer helper mismatch for #{raw.fetch('constructor')}") unless raw.fetch("helper") == constructor.fetch("helper")
    fail_corpus("observer helper source mismatch for #{raw.fetch('constructor')}") unless raw.fetch("helper_source_file") == constructor.fetch("source_file")
    fail_corpus("observer helper line mismatch for #{raw.fetch('constructor')}") unless raw.fetch("helper_line") == constructor.fetch("helper_line")

    polarity = raw.fetch("polarity")
    ordinal = raw.fetch("ordinal")
    source_occurrence = "#{constructor.fetch('source_file')}:#{constructor.fetch('helper_line')}:#{polarity}:#{format('%04d', ordinal)}"
    case_id = "GEN/#{constructor.fetch('constructor')}/#{polarity}/#{format('%04d', ordinal)}"
    input = Base64.strict_decode64(raw.fetch("input_base64"))
    path_encoded = raw["path_base64"]
    path = path_encoded.nil? ? nil : Base64.strict_decode64(path_encoded)
    {
      "schema_version" => SCHEMA_VERSION,
      "record_type" => "generator_sample",
      "upstream_revision" => REVISION,
      "case_id" => case_id,
      "constructor" => constructor.fetch("constructor"),
      "rule_id" => constructor.fetch("rule_id"),
      "selected_default" => true,
      "helper" => raw.fetch("helper"),
      "polarity" => polarity,
      "ordinal" => ordinal,
      "contract" => raw.fetch("contract"),
      "source_file" => constructor.fetch("source_file"),
      "constructor_line" => constructor.fetch("constructor_line"),
      "helper_line" => constructor.fetch("helper_line"),
      "source_occurrence" => source_occurrence,
      "constructor_source_sha256" => constructor.fetch("constructor_source_sha256"),
      "origin_kind" => raw.fetch("origin_kind"),
      "origin_source_file" => raw.fetch("origin_source_file"),
      "origin_line" => raw.fetch("origin_line"),
      "template_key" => raw["template_key"],
      "duplicate_ordinal" => nil,
      "input_base64" => raw.fetch("input_base64"),
      "input_sha256" => Digest::SHA256.hexdigest(input),
      "path_present" => raw.fetch("path_present"),
      "path_base64" => path_encoded,
      "path_sha256" => path && Digest::SHA256.hexdigest(path),
      "upstream_expected_count" => raw.fetch("contract") == "at_least_one" ? nil : (raw.fetch("contract") == "exactly_one" ? 1 : 0),
      "oracle_observed_count" => raw.fetch("findings").length,
      "findings" => raw.fetch("findings"),
      "dependencies" => raw.fetch("dependencies")
    }
  end

  records.sort_by! { |record| record.fetch("case_id") }
  seen_duplicates = Hash.new(0)
  records.each do |record|
    duplicate_key = [
      record.fetch("rule_id"), record.fetch("polarity"), record.fetch("path_present"),
      record["path_base64"], record.fetch("input_base64")
    ]
    record["duplicate_ordinal"] = seen_duplicates[duplicate_key]
    seen_duplicates[duplicate_key] += 1
    record["identity_sha256"] = Digest::SHA256.hexdigest(JSON.generate(identity_projection(record)))
  end
  records
end

def identity_projection(record)
  {
    "case_id" => record.fetch("case_id"),
    "constructor" => record.fetch("constructor"),
    "rule_id" => record.fetch("rule_id"),
    "selected_default" => record.fetch("selected_default"),
    "helper" => record.fetch("helper"),
    "polarity" => record.fetch("polarity"),
    "ordinal" => record.fetch("ordinal"),
    "contract" => record.fetch("contract"),
    "source_file" => record.fetch("source_file"),
    "constructor_line" => record.fetch("constructor_line"),
    "helper_line" => record.fetch("helper_line"),
    "source_occurrence" => record.fetch("source_occurrence"),
    "constructor_source_sha256" => record.fetch("constructor_source_sha256"),
    "origin_kind" => record.fetch("origin_kind"),
    "origin_source_file" => record.fetch("origin_source_file"),
    "origin_line" => record.fetch("origin_line"),
    "template_key" => record["template_key"],
    "path_present" => record.fetch("path_present"),
    "path_base64" => record["path_base64"],
    "dependencies" => record.fetch("dependencies")
  }
end

def strict_base64!(value, label)
  fail_corpus("#{label} must be a base64 string") unless value.is_a?(String)
  decoded = Base64.strict_decode64(value)
  fail_corpus("#{label} is not canonical base64") unless Base64.strict_encode64(decoded) == value
  decoded
rescue ArgumentError
  fail_corpus("#{label} is invalid base64")
end

def validate_inventory!(records)
  fail_corpus("expected 225 constructor records, got #{records.length}") unless records.length == 225
  fail_corpus("constructor identities are not unique") unless records.map { |record| record.fetch("constructor") }.uniq.length == 225
  fail_corpus("constructor RuleIDs are not unique") unless records.map { |record| record.fetch("rule_id") }.uniq.length == 225
  records.each do |record|
    fail_corpus("invalid constructor schema") unless record.fetch("schema_version") == SCHEMA_VERSION && record.fetch("record_type") == "generator_constructor"
    fail_corpus("constructor revision mismatch") unless record.fetch("upstream_revision") == REVISION
    fail_corpus("invalid constructor source digest") unless record.fetch("constructor_source_sha256").match?(/\A[0-9a-f]{64}\z/)
  end

  selected = records.select { |record| record.fetch("selected_default") }
  covered = records.select { |record| record.fetch("helper_covered") }
  gaps = records.select { |record| record.fetch("disposition") == "selected_gap" }
  exclusions = records.select { |record| record.fetch("disposition") == "excluded_default" }
  fail_corpus("expected 222 selected constructors, got #{selected.length}") unless selected.length == 222
  fail_corpus("expected 220 helper-covered selected constructors, got #{covered.length}") unless covered.length == 220
  selected_helpers = selected.group_by { |record| record.fetch("helper") }.transform_values(&:length)
  expected_helpers = { "validate" => 215, "validate_with_paths" => 5, "none" => 2 }
  fail_corpus("selected helper split mismatch: #{selected_helpers}") unless selected_helpers == expected_helpers
  fail_corpus("gap constructor set mismatch") unless gaps.to_h { |record| [record.fetch("constructor"), record.fetch("exception")] } == EXPECTED_GAPS
  fail_corpus("excluded constructor set mismatch") unless exclusions.to_h { |record| [record.fetch("constructor"), record.fetch("exception")] } == EXPECTED_EXCLUSIONS
  unexpected = records.select { |record| record.fetch("disposition") == "unexpected_exclusion" }
  fail_corpus("unexpected excluded constructors: #{unexpected.map { |record| record.fetch('constructor') }.join(', ')}") unless unexpected.empty?
end

def validate_samples!(records, inventory)
  fail_corpus("expected 6770 sample records, got #{records.length}") unless records.length == 6_770
  ids = records.map { |record| record.fetch("case_id") }
  fail_corpus("sample case IDs are not unique") unless ids.uniq.length == ids.length

  totals = records.group_by { |record| record.fetch("polarity") }.transform_values(&:length)
  fail_corpus("sample polarity totals mismatch: #{totals}") unless totals == EXPECTED_SAMPLE_TOTALS

  inventory_by_name = inventory.to_h { |record| [record.fetch("constructor"), record] }
  records.each do |record|
    id = record.fetch("case_id")
    fail_corpus("#{id}: invalid schema") unless record.fetch("schema_version") == SCHEMA_VERSION && record.fetch("record_type") == "generator_sample"
    fail_corpus("#{id}: revision mismatch") unless record.fetch("upstream_revision") == REVISION
    constructor = inventory_by_name[record.fetch("constructor")]
    fail_corpus("#{id}: unknown constructor") unless constructor
    fail_corpus("#{id}: constructor is not selected/helper-covered") unless constructor.fetch("selected_default") && constructor.fetch("helper_covered")
    fail_corpus("#{id}: RuleID mismatch") unless record.fetch("rule_id") == constructor.fetch("rule_id")
    fail_corpus("#{id}: helper mismatch") unless record.fetch("helper") == constructor.fetch("helper")
    fail_corpus("#{id}: source digest mismatch") unless record.fetch("constructor_source_sha256") == constructor.fetch("constructor_source_sha256")

    expected_id = "GEN/#{record.fetch('constructor')}/#{record.fetch('polarity')}/#{format('%04d', record.fetch('ordinal'))}"
    fail_corpus("#{id}: ID is not derived from source occurrence") unless id == expected_id
    expected_occurrence = "#{record.fetch('source_file')}:#{record.fetch('helper_line')}:#{record.fetch('polarity')}:#{format('%04d', record.fetch('ordinal'))}"
    fail_corpus("#{id}: source occurrence mismatch") unless record.fetch("source_occurrence") == expected_occurrence

    input = strict_base64!(record.fetch("input_base64"), "#{id} input")
    fail_corpus("#{id}: input digest mismatch") unless Digest::SHA256.hexdigest(input) == record.fetch("input_sha256")
    if record.fetch("path_present")
      path = strict_base64!(record.fetch("path_base64"), "#{id} path")
      fail_corpus("#{id}: path digest mismatch") unless Digest::SHA256.hexdigest(path) == record.fetch("path_sha256")
    else
      fail_corpus("#{id}: absent path must be JSON null") unless record["path_base64"].nil? && record["path_sha256"].nil?
    end

    findings = record.fetch("findings")
    fail_corpus("#{id}: findings must be an array") unless findings.is_a?(Array)
    findings.each_with_index do |finding, index|
      strict_base64!(finding.fetch("match_base64"), "#{id} finding #{index} match")
      strict_base64!(finding.fetch("secret_base64"), "#{id} finding #{index} secret")
    end
    fail_corpus("#{id}: observed count mismatch") unless record.fetch("oracle_observed_count") == findings.length

    case record.fetch("contract")
    when "at_least_one"
      fail_corpus("#{id}: at-least-one contract has an exact upstream count") unless record["upstream_expected_count"].nil?
      fail_corpus("#{id}: positive observation is empty") unless findings.length >= 1
    when "exactly_one"
      fail_corpus("#{id}: exactly-one contract mismatch") unless record.fetch("upstream_expected_count") == 1 && findings.length == 1
    when "zero"
      fail_corpus("#{id}: zero contract mismatch") unless record.fetch("upstream_expected_count") == 0 && findings.empty?
    else
      fail_corpus("#{id}: unknown helper contract")
    end

    if record.fetch("polarity").start_with?("ordinary_")
      fail_corpus("#{id}: ordinary case uses wrong helper/path shape") unless record.fetch("helper") == "validate" && !record.fetch("path_present")
    elsif record.fetch("polarity").start_with?("path_")
      fail_corpus("#{id}: path case uses wrong helper/path shape") unless record.fetch("helper") == "validate_with_paths" && record.fetch("path_present")
    else
      fail_corpus("#{id}: unknown polarity")
    end

    dependencies = record.fetch("dependencies")
    fail_corpus("#{id}: global allowlist dependency missing") unless dependencies.fetch("global_allowlist") == true
    keywords = dependencies.fetch("keyword_base64")
    fail_corpus("#{id}: keywords must be an array") unless keywords.is_a?(Array)
    keywords.each_with_index { |keyword, index| strict_base64!(keyword, "#{id} keyword #{index}") }
    fail_corpus("#{id}: invalid rule allowlist count") unless dependencies.fetch("rule_allowlist_count").is_a?(Integer) && dependencies.fetch("rule_allowlist_count") >= 0
    fail_corpus("#{id}: helper/path dependency mismatch") unless dependencies.fetch("has_path") == record.fetch("path_present") || record.fetch("helper") == "validate"
    fail_corpus("#{id}: invalid origin kind") unless %w[direct generated_template].include?(record.fetch("origin_kind"))
    if record.fetch("origin_kind") == "generated_template"
      fail_corpus("#{id}: generated sample lacks template key") unless record["template_key"].is_a?(String) && !record["template_key"].empty?
    else
      fail_corpus("#{id}: direct sample has template key") unless record["template_key"].nil?
    end

    expected_identity = Digest::SHA256.hexdigest(JSON.generate(identity_projection(record)))
    fail_corpus("#{id}: identity digest mismatch") unless record.fetch("identity_sha256") == expected_identity
  end

  grouped = records.group_by { |record| [record.fetch("constructor"), record.fetch("polarity")] }
  grouped.each do |(constructor, polarity), cases|
    ordinals = cases.map { |record| record.fetch("ordinal") }.sort
    fail_corpus("#{constructor}/#{polarity}: non-contiguous source ordinals") unless ordinals == (0...ordinals.length).to_a
  end

  covered_names = inventory.select { |record| record.fetch("helper_covered") }.map { |record| record.fetch("constructor") }.sort
  observed_names = records.map { |record| record.fetch("constructor") }.uniq.sort
  fail_corpus("helper-covered/sample constructor set mismatch") unless observed_names == covered_names

  seen_duplicates = Hash.new(0)
  records.sort_by { |record| record.fetch("case_id") }.each do |record|
    key = [record.fetch("rule_id"), record.fetch("polarity"), record.fetch("path_present"), record["path_base64"], record.fetch("input_base64")]
    fail_corpus("#{record.fetch('case_id')}: duplicate ordinal mismatch") unless record.fetch("duplicate_ordinal") == seen_duplicates[key]
    seen_duplicates[key] += 1
  end
end

def read_jsonl(path)
  fail_corpus("missing corpus file: #{path}") unless path.file?
  path.each_line.with_index(1).map do |line, number|
    fail_corpus("#{path}:#{number}: blank JSONL record") if line.strip.empty?
    JSON.parse(line)
  rescue JSON::ParserError => error
    fail_corpus("#{path}:#{number}: #{error.message}")
  end
end

def write_jsonl(path, records)
  path.dirname.mkpath
  path.write(records.map { |record| JSON.generate(record) }.join("\n") + "\n")
end

def assert_same_identities!(expected, actual)
  expected_projection = expected.map { |record| identity_projection(record) }.sort_by { |record| record.fetch("case_id") }
  actual_projection = actual.map { |record| identity_projection(record) }.sort_by { |record| record.fetch("case_id") }
  return if expected_projection == actual_projection

  expected_by_id = expected_projection.to_h { |record| [record.fetch("case_id"), record] }
  actual_by_id = actual_projection.to_h { |record| [record.fetch("case_id"), record] }
  missing = expected_by_id.keys - actual_by_id.keys
  extra = actual_by_id.keys - expected_by_id.keys
  changed = (expected_by_id.keys & actual_by_id.keys).find { |id| expected_by_id.fetch(id) != actual_by_id.fetch(id) }
  fail_corpus("stable generator identity drift: missing=#{missing.first || '<none>'}; extra=#{extra.first || '<none>'}; changed=#{changed || '<none>'}")
end

def negative_identity_self_test!(records)
  substituted = records.map(&:dup)
  substituted[0]["case_id"] = "#{substituted[0].fetch('case_id')}-SUBSTITUTED"
  begin
    assert_same_identities!(records, substituted)
  rescue CorpusError
    return
  end
  fail_corpus("same-count identity-substitution negative self-test unexpectedly passed")
end

def check!
  verify_upstream!
  actual_constructor_hash = Digest::SHA256.file(CONSTRUCTORS).hexdigest if CONSTRUCTORS.file?
  actual_sample_hash = Digest::SHA256.file(SAMPLES).hexdigest if SAMPLES.file?
  fail_corpus("frozen constructor corpus digest mismatch: #{actual_constructor_hash || '<missing>'}") unless actual_constructor_hash == FROZEN_CONSTRUCTORS_SHA256
  fail_corpus("frozen sample corpus digest mismatch: #{actual_sample_hash || '<missing>'}") unless actual_sample_hash == FROZEN_SAMPLES_SHA256
  frozen_inventory = read_jsonl(CONSTRUCTORS)
  frozen_samples = read_jsonl(SAMPLES)
  validate_inventory!(frozen_inventory)
  validate_samples!(frozen_samples, frozen_inventory)
  negative_identity_self_test!(frozen_samples)

  current_inventory = constructor_inventory
  validate_inventory!(current_inventory)
  fail_corpus("constructor inventory/source drift") unless current_inventory == frozen_inventory
  current_samples = extract_observations(current_inventory)
  validate_samples!(current_samples, current_inventory)
  assert_same_identities!(frozen_samples, current_samples)

  frozen_by_id = frozen_samples.to_h { |record| [record.fetch("case_id"), record] }
  changed_observations = current_samples.count do |record|
    frozen = frozen_by_id.fetch(record.fetch("case_id"))
    [record.fetch("input_base64"), record["path_base64"], record.fetch("findings")] !=
      [frozen.fetch("input_base64"), frozen["path_base64"], frozen.fetch("findings")]
  end

  warn "verified #{frozen_samples.length} frozen generator samples, 222 selected constructors, 220 helper-covered constructors at #{REVISION}; #{changed_observations} fresh observations differed while stable identities matched"
end

def regenerate!
  verify_upstream!
  inventory = constructor_inventory
  validate_inventory!(inventory)
  samples = extract_observations(inventory)
  validate_samples!(samples, inventory)
  negative_identity_self_test!(samples)
  write_jsonl(CONSTRUCTORS, inventory)
  write_jsonl(SAMPLES, samples)
  warn "regenerated #{samples.length} generator samples; deterministic observations frozen in #{SAMPLES}"
  warn "review and update FROZEN_CONSTRUCTORS_SHA256=#{Digest::SHA256.file(CONSTRUCTORS).hexdigest}"
  warn "review and update FROZEN_SAMPLES_SHA256=#{Digest::SHA256.file(SAMPLES).hexdigest}"
end

begin
  case ARGV
  when ["--check"] then check!
  when ["--regenerate"] then regenerate!
  else
    warn "usage: ruby compat/extract_generator_samples.rb --check|--regenerate"
    exit 2
  end
rescue CorpusError, KeyError, TypeError => error
  warn "generator corpus error: #{error.message}"
  exit 1
end
