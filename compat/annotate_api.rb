#!/usr/bin/env ruby
# frozen_string_literal: true

# Generates and checks the explicit Rust disposition joined to every pinned Go
# API identity. Uses only the Ruby standard library.

require "digest"
require "json"
require "pathname"
require "stringio"

ROOT = Pathname(__dir__).parent
INVENTORY_PATH = ROOT.join("compat/api-inventory-v1.json")
DISPOSITIONS_PATH = ROOT.join("compat/api-dispositions-v1.jsonl")
MANIFEST_PATH = ROOT.join("compat/test-manifest.toml")
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
INVENTORY_IDENTITY_COUNT = 607
INVENTORY_IDENTITY_SHA256 = "de2e917190f3fdcc24c3db77e3e0a5c7fdd09aff97805b066273f4a7b6e96e6b"
EXPECTED_DISPOSITIONS_SHA256 = "00b0968df34b279f93fc69b9d064c80e0ae6ee00a2710230ecea65abffce4062"

DISPOSITIONS = %w[
  equivalent-public-api
  idiomatic-public-replacement
  compatibility-shim
  compatibility-tooling-private-implementation
  out-of-public-product-scope
].freeze

PUBLICITIES = %w[
  public
  compatibility-public
  crate-private
  binary-private
  tooling-private
  none
].freeze

IMPLEMENTATION_STATUSES = %w[implemented not-applicable].freeze
TEST_STATUSES = %w[passing not-applicable].freeze
EVIDENCE_STATUSES = %w[rust-tested go-inventoried].freeze

REQUIRED_FIELDS = %w[
  schema_version
  upstream_revision
  inventory_identity_set_sha256
  source_key
  source_identity
  source_identity_sha256
  source_package
  source_kind
  disposition
  disposition_cluster
  rust_crate
  rust_module
  rust_path
  rust_publicity
  contract_justification
  behavior_links
  manifest_links
  implementation_status
  test_status
  evidence_status
  implementation_evidence
  design_evidence
].freeze

DOC = "docs/ARCHITECTURE.md"

def inventory
  @inventory ||= JSON.parse(INVENTORY_PATH.read)
end

def validate_inventory!
  inv = inventory
  abort "inventory revision mismatch" unless inv.fetch("upstream_revision") == REVISION
  abort "inventory identity count mismatch" unless inv.fetch("identity_count") == INVENTORY_IDENTITY_COUNT
  abort "inventory record count mismatch" unless inv.fetch("records").length == INVENTORY_IDENTITY_COUNT
  abort "inventory identity SHA mismatch" unless inv.fetch("identity_set_sha256") == INVENTORY_IDENTITY_SHA256

  identities = inv.fetch("identities")
  calculated = Digest::SHA256.hexdigest(identities.sort.map { |identity| "#{identity}\n" }.join)
  abort "inventory identity stream digest mismatch" unless calculated == INVENTORY_IDENTITY_SHA256
  abort "duplicate inventory key" unless inv.fetch("records").map { |record| record.fetch("key") }.uniq.length == INVENTORY_IDENTITY_COUNT
  abort "duplicate inventory identity" unless identities.uniq.length == INVENTORY_IDENTITY_COUNT
end

def constructor_manifest_ids
  constructors = inventory.fetch("records").select do |record|
    record.fetch("package").end_with?("/cmd/generate/config/rules") && record.fetch("kind") == "func"
  end.sort_by { |record| record.fetch("name") }
  abort "expected 225 rule constructors" unless constructors.length == 225
  expected = constructors.each_with_index.to_h { |record, index| [record.fetch("name"), format("GEN-%04d", index + 1)] }

  manifest = MANIFEST_PATH.read
  actual = manifest.scan(/^\[\[generator_constructor\]\]\n(.*?)(?=^\[\[|\z)/m).to_h do |(body)|
    id = body[/^id = "([^"]+)"$/, 1]
    name = body[/^name = "([^"]+)"$/, 1]
    abort "malformed generator_constructor manifest block" unless id && name
    [name, id]
  end
  abort "generator manifest constructor count mismatch" unless actual.length == 225
  abort "generator manifest IDs differ from API constructor set" unless actual == expected
  actual
end

def row(record, attrs)
  behavior_links = ["API-ALL-001", *Array(attrs.fetch(:behavior_links, []))].uniq
  manifest_links = ["API-ALL-001", *Array(attrs.fetch(:manifest_links, []))].uniq
  {
    "schema_version" => 1,
    "upstream_revision" => REVISION,
    "inventory_identity_set_sha256" => INVENTORY_IDENTITY_SHA256,
    "source_key" => record.fetch("key"),
    "source_identity" => record.fetch("identity"),
    "source_identity_sha256" => record.fetch("identity_sha256"),
    "source_package" => record.fetch("package"),
    "source_kind" => record.fetch("kind"),
    "disposition" => attrs.fetch(:disposition),
    "disposition_cluster" => attrs.fetch(:cluster),
    "rust_crate" => attrs.fetch(:crate),
    "rust_module" => attrs.fetch(:module),
    "rust_path" => attrs.fetch(:path),
    "rust_publicity" => attrs.fetch(:publicity),
    "contract_justification" => attrs.fetch(:justification),
    "behavior_links" => behavior_links,
    "manifest_links" => manifest_links,
    "implementation_status" => attrs.fetch(:implementation_status, "not-applicable"),
    "test_status" => attrs.fetch(:test_status, "not-applicable"),
    "evidence_status" => attrs.fetch(:evidence_status, "go-inventoried"),
    "implementation_evidence" => attrs.fetch(:implementation_evidence, "Final release disposition: the Go-shaped identity is not shipped; its declared idiomatic replacement, tooling role, or product-scope exclusion is final."),
    "design_evidence" => attrs.fetch(:design_evidence)
  }
end

def attrs(disposition:, cluster:, crate:, module_name:, path:, publicity:, justification:, section:,
          behavior_links: [], manifest_links: [], implementation_status: "not-applicable", test_status: "not-applicable",
          evidence_status: "go-inventoried", implementation_evidence: "Final release disposition: the Go-shaped identity is not shipped; its declared idiomatic replacement, tooling role, or product-scope exclusion is final.")
  {
    disposition: disposition,
    cluster: cluster,
    crate: crate,
    module: module_name,
    path: path,
    publicity: publicity,
    justification: justification,
    design_evidence: "#{DOC}##{section}",
    behavior_links: behavior_links,
    manifest_links: manifest_links,
    implementation_status: implementation_status,
    test_status: test_status,
    evidence_status: evidence_status,
    implementation_evidence: implementation_evidence
  }
end

def owner(record)
  record["owner"].to_s
end

def member(record)
  owner(record).empty? ? record.fetch("name") : "#{owner(record)}.#{record.fetch('name')}"
end

def implemented_model_attrs(cluster:, path:, behavior_links:, evidence: "crates/rustleaks-core/tests/model.rs")
  attrs(
    disposition: "equivalent-public-api", cluster: cluster, crate: "rustleaks-core",
    module_name: "model", path: path, publicity: "public",
    justification: "The byte-preserving Rust core model has the same observable data role, with validated builders and read-only access instead of mutable public fields.",
    section: "findings-and-reports", behavior_links: behavior_links,
    implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
    implementation_evidence: evidence
  )
end

def annotation_for(record, generator_ids)
  package = record.fetch("package")
  name = record.fetch("name")
  kind = record.fetch("kind")
  generator_tested = {
    implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
    implementation_evidence: "compat/generator-corpus; compat/extract_generator_samples.rb; cargo xtask generator-check"
  }

  case package
  when %r{/cmd/generate/config/rules\z}
    if kind == "func"
      gen_id = generator_ids.fetch(name)
      return attrs(
        disposition: "compatibility-tooling-private-implementation", cluster: "generator.rule-constructors",
        crate: "rustleaks-compat", module_name: "generator::rules", path: "rustleaks_compat::generator::rules::#{name}",
        publicity: "tooling-private",
        justification: "The constructor is compatibility corpus input, not a 225-function runtime API; its selected rule becomes embedded default config and all samples remain oracle evidence.",
        section: "root-cli-generator-auxiliary-packages", behavior_links: ["GEN-ALL-001"], manifest_links: [gen_id],
        **generator_tested
      )
    end
    return attrs(
      disposition: "compatibility-tooling-private-implementation", cluster: "generator.default-stopwords",
      crate: "rustleaks-compat", module_name: "generator::rules", path: "rustleaks_compat::generator::rules::DEFAULT_STOP_WORDS",
      publicity: "tooling-private",
      justification: "Default stop words are embedded generation data with golden evidence, not mutable public runtime state.",
      section: "root-cli-generator-auxiliary-packages", behavior_links: ["GEN-ALL-001"], **generator_tested
    )
  when %r{/cmd/generate/config/base\z}
    return attrs(
      disposition: "compatibility-tooling-private-implementation", cluster: "generator.default-config-assembly",
      crate: "rustleaks-compat", module_name: "generator::base", path: "rustleaks_compat::generator::base::create_global_config",
      publicity: "tooling-private",
      justification: "Global-config assembly is a corpus/default-config producer and is intentionally absent from the runtime library surface.",
      section: "root-cli-generator-auxiliary-packages", behavior_links: ["GEN-ALL-001"], **generator_tested
    )
  when %r{/cmd/generate/config/utils\z}
    regex_helpers = %w[GenerateSemiGenericRegex GenerateUniqueTokenRegex MergeRegexps]
    validators = %w[Validate ValidateWithPaths]
    cluster, path, justification = if regex_helpers.include?(name)
      ["generator.regex-construction", "rustleaks_compat::generator::regex::#{name}", "Generated-regex behavior stays private compatibility tooling and corpus evidence; it must not expose the Rust regex backend."]
    elsif validators.include?(name)
      ["generator.rule-validation", "rustleaks_compat::generator::validate::#{name}", "Constructor validation is an oracle/corpus harness that preserves embedded assertions without becoming runtime API."]
    else
      ["generator.sample-secrets", "rustleaks_compat::generator::samples::#{name}", "Synthetic sample generation is deterministic dev/test tooling, not a published runtime capability."]
    end
    return attrs(
      disposition: "compatibility-tooling-private-implementation", cluster: cluster,
      crate: "rustleaks-compat", module_name: cluster.gsub(".", "::"), path: path,
      publicity: "tooling-private", justification: justification,
      section: "root-cli-generator-auxiliary-packages", behavior_links: ["GEN-ALL-001"], **generator_tested
    )
  when %r{/cmd/generate/secrets\z}
    return attrs(
      disposition: "compatibility-tooling-private-implementation", cluster: "generator.secret-synthesis",
      crate: "rustleaks-compat", module_name: "generator::secrets", path: "rustleaks_compat::generator::secrets::new_secret",
      publicity: "tooling-private",
      justification: "Reggen-backed secret synthesis is test tooling; Rust replaces incidental panic control flow with a tooling error.",
      section: "root-cli-generator-auxiliary-packages", behavior_links: ["GEN-ALL-001"], **generator_tested
    )
  when %r{/cmd\z}
    if %w[Config Detector].include?(name) && kind == "func"
      return attrs(
        disposition: "out-of-public-product-scope", cluster: "cmd.legacy-assembly",
        crate: "rustleaks-cli", module_name: "run", path: "rustleaks_cli::run_from", publicity: "binary-private",
        justification: "The Go CLI assembly helper is implemented inside the thin injected runner through ConfigLoader, Engine, ScanOptions, source adapters, and ScanSession rather than exposed as an embedding API.",
        section: "root-cli-generator-auxiliary-packages", behavior_links: %w[CLI-002 CLI-003 CLI-004 CLI-005 CLI-006 CLI-SAFE-002 CLI-SAFE-005],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-cli/src/config.rs; crates/rustleaks-cli/src/run.rs; crates/rustleaks-cli/src/source.rs; crates/rustleaks-cli/tests/cli.rs"
      )
    end
    if name == "Execute" && kind == "func"
      return attrs(
        disposition: "out-of-public-product-scope", cluster: "cmd.execution",
        crate: "rustleaks-cli", module_name: "run", path: "rustleaks_cli::run_from", publicity: "binary-private",
        justification: "Command execution belongs to the thin binary; the implemented injected runner preserves the declared CLI contract without becoming an engine API.",
        section: "root-cli-generator-auxiliary-packages", behavior_links: %w[CLI-001 CLI-007 CLI-008 CLI-009 CLI-010 CLI-011 CLI-012 CLI-013 CLI-014 CLI-015 CLI-SAFE-001 CLI-SAFE-002 CLI-SAFE-003 CLI-SAFE-004 CLI-SAFE-005 CLI-DEFER-001],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-cli/src/lib.rs; crates/rustleaks-cli/src/run.rs; crates/rustleaks-cli/tests/cli.rs"
      )
    end
    if name == "FormatDuration" && kind == "func"
      return attrs(
        disposition: "out-of-public-product-scope", cluster: "cmd.duration-formatting",
        crate: "rustleaks-cli", module_name: "output", path: "rustleaks_cli::output::format_duration", publicity: "binary-private",
        justification: "Human CLI duration formatting is implemented as private presentation behavior rather than core scanning API.",
        section: "root-cli-generator-auxiliary-packages", behavior_links: ["CLI-009"],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-cli/src/output.rs; crates/rustleaks-cli/tests/cli.rs"
      )
    end
    if %w[BYTE KILOBYTE MEGABYTE GIGABYTE].include?(name)
      return attrs(
        disposition: "out-of-public-product-scope", cluster: "cmd.byte-units",
        crate: "rustleaks-cli", module_name: "output", path: "rustleaks_cli::output::human_bytes", publicity: "binary-private",
        justification: "CLI byte units are implemented in private checked presentation and threshold mapping rather than exposed as public engine constants.",
        section: "root-cli-generator-auxiliary-packages", behavior_links: %w[CLI-004 CLI-009 CLI-014 CLI-SAFE-005],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-cli/src/output.rs; crates/rustleaks-cli/src/source.rs; crates/rustleaks-cli/tests/cli.rs"
      )
    end
    return attrs(
      disposition: "out-of-public-product-scope", cluster: "cmd.diagnostics",
      crate: "rustleaks-cli", module_name: "diagnostics", path: "rustleaks_cli::diagnostics::#{member(record)}", publicity: "binary-private",
      justification: "Process-global CPU, memory, trace, and HTTP diagnostics remain optional P2 CLI orchestration; no global profiler manager is exposed to embedders.",
      section: "root-cli-generator-auxiliary-packages", behavior_links: ["CLI-DEFER-001"]
    )
  when %r{/cmd/scm\z}
    return attrs(
      disposition: "equivalent-public-api", cluster: "scm.platform",
      crate: "rustleaks-sources", module_name: "scm", path: "rustleaks_sources::scm::ScmPlatform", publicity: "public",
      justification: "A public ScmPlatform enum with Display and FromStr preserves unknown versus none, platform values, parsing, and display without Go integer mutability.",
      section: "scm-and-regexp", behavior_links: ["MODEL-002"],
      implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
      implementation_evidence: "crates/rustleaks-sources/src/scm.rs; crates/rustleaks-sources/tests/git_scm.rs; cargo xtask git-check"
    )
  when %r{/regexp\z}
    cluster, path, justification = case name
    when "Version"
      ["regexp.backend-metadata", "rustleaks_core::regex::backend_version", "Backend version is compatibility metadata only and must not make backend selection part of public API."]
    when "Regexp"
      ["regexp.backend-abstraction", "rustleaks_core::regex::GoRegex", "The build-selected backend alias is hidden behind private GoRegex so backend methods cannot leak into the public Rust contract."]
    else
      ["regexp.compilation", "rustleaks_core::regex::GoRegex::compile", "MustCompile becomes fallible private compilation for untrusted config; panic compatibility is limited to tooling tests."]
    end
    return attrs(
      disposition: "compatibility-tooling-private-implementation", cluster: cluster,
      crate: "rustleaks-core", module_name: "regex", path: path, publicity: "crate-private",
      justification: justification, section: "scm-and-regexp",
      behavior_links: ["REGEX-GOREGEX-005"], implementation_status: "implemented",
      test_status: "passing", evidence_status: "rust-tested",
      implementation_evidence: "crates/rustleaks-core/src/regex; cargo xtask regex-check"
    )
  when %r{/config\z}
    annotation = config_annotation(record)
    if annotation.fetch(:cluster) == "config.compiled-allowlist-matching"
      allowlist_behaviors = {
        "CommitAllowed" => %w[AL-001 AL-002 AL-018],
        "PathAllowed" => %w[AL-001 AL-003 AL-018],
        "RegexAllowed" => %w[AL-001 AL-004 AL-018],
        "ContainsStopWord" => %w[AL-001 AL-005 AL-018]
      }.fetch(name)
      return annotation.merge(
        behavior_links: (annotation.fetch(:behavior_links) + allowlist_behaviors).uniq,
        implementation_status: "implemented", test_status: "passing",
        evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-core/tests/allowlist.rs; cargo xtask allowlist-check"
      )
    end

    config_behaviors = case annotation.fetch(:cluster)
                       when "config.default-config" then ["CONFIG-DEFAULT-004"]
                       when "config.extension-spec" then ["CONFIG-RAW-001", "CONFIG-EXTEND-003"]
                       when "config.raw-translation" then ["CONFIG-RAW-001", "CONFIG-COMPILE-002", "CONFIG-EXTEND-003"]
                       when /^config\.raw-/ then ["CONFIG-RAW-001"]
                       else ["CONFIG-COMPILE-002"]
                       end
    regex_gate_completed = %w[config.raw-translation config.rule-compilation].include?(annotation.fetch(:cluster))
    return annotation.merge(
      behavior_links: (annotation.fetch(:behavior_links) + config_behaviors).uniq,
      implementation_status: "implemented", test_status: "passing",
      evidence_status: "rust-tested",
      implementation_evidence: regex_gate_completed ?
        "crates/rustleaks-core/tests/config.rs; crates/rustleaks-core/src/regex; cargo xtask parity --scope regex" :
        "crates/rustleaks-core/tests/config.rs; cargo xtask config-check"
    )
  when %r{/detect/codec\z}
    codec_annotations = {
      "AdjustMatchIndex" => ["rustleaks_core::decoder::adjust_match_index", %w[DEC-007 DEC-008 DEC-011]],
      "CurrentLine" => ["rustleaks_core::decoder::current_line", %w[DEC-008 DEC-012]],
      "NewDecoder" => ["rustleaks_core::decoder::Decoder::new", %w[DEC-001 DEC-009]],
      "SegmentsWithDecodedOverlap" => ["rustleaks_core::decoder::segments_with_decoded_overlap", %w[DEC-008 DEC-011]],
      "Tags" => ["rustleaks_core::decoder::tags", %w[DEC-008 DEC-011]],
      "Decoder.Decode" => ["rustleaks_core::decoder::Decoder::decode", %w[DEC-001 DEC-002 DEC-003 DEC-004 DEC-005 DEC-006 DEC-007 DEC-009 DEC-010]],
      "Decoder" => ["rustleaks_core::decoder::Decoder", %w[DEC-001 DEC-009 DEC-010]],
      "EncodedSegment" => ["rustleaks_core::decoder::EncodedSegment", %w[DEC-007 DEC-008 DEC-009 DEC-011 DEC-012]]
    }
    codec_member = member(record)
    codec_rust_path, codec_behaviors = codec_annotations.fetch(codec_member) do
      abort "unmapped detect/codec identity: #{codec_member}"
    end
    return attrs(
      disposition: "compatibility-tooling-private-implementation", cluster: "detect.decoder-internals",
      crate: "rustleaks-core", module_name: "decoder", path: codec_rust_path, publicity: "crate-private",
      justification: "Decoder and encoded-segment internals remain private; exact segment, tag, line, and index behavior is exercised through decoder unit tests and complete detector corpus replay.",
      section: "detection-and-codec", behavior_links: ["TM-ALL-001", *codec_behaviors],
      implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
      implementation_evidence: "crates/rustleaks-core/src/decoder/mod.rs; crates/rustleaks-core/tests/detect_corpus.rs; crates/rustleaks-core/tests/engine.rs; cargo xtask decoder-check"
    )
  when %r{/detect\z}
    return detect_annotation(record)
  when %r{/report\z}
    return report_annotation(record)
  when %r{/sources\z}
    return sources_annotation(record)
  when %r{/logging\z}
    terminating = %w[Fatal Panic].include?(name)
    return attrs(
      disposition: "out-of-public-product-scope", cluster: terminating ? "logging.terminating-control-flow" : "logging.global-facade",
      crate: "rustleaks-cli", module_name: "logging", path: "rustleaks_cli::logging::#{member(record)}", publicity: "binary-private",
      justification: terminating ?
        "Fatal and panic logging are never library control flow; core returns structured errors and only the CLI chooses termination policy." :
        "The mutable global logger facade is intentionally absent from core; libraries return structured diagnostics and callers select logging.",
      section: "root-cli-generator-auxiliary-packages"
    )
  when %r{/version\z}
    return attrs(
      disposition: "out-of-public-product-scope", cluster: "version.build-metadata",
      crate: "rustleaks-cli", module_name: "version", path: "rustleaks_cli::version::#{name}", publicity: "binary-private",
      justification: "Mutable build-process globals become immutable CLI build metadata; the exact display string is P2 compatibility data, not core API.",
      section: "root-cli-generator-auxiliary-packages"
    )
  end

  abort "unclassified API record: #{record.fetch('key')}"
end

def config_annotation(record)
  name = record.fetch("name")
  kind = record.fetch("kind")
  owning_type = owner(record)

  if name == "DefaultConfig" && kind == "var"
    return attrs(
      disposition: "equivalent-public-api", cluster: "config.default-config",
      crate: "rustleaks-core", module_name: "config::default", path: "rustleaks_core::config::DEFAULT_CONFIG", publicity: "public",
      justification: "The mutable Go variable becomes immutable pinned default-config bytes plus revision/hash metadata.",
      section: "configuration", behavior_links: ["BOOT-001", "GEN-ALL-001"]
    )
  end
  if owning_type == "AllowlistMatchCondition" || name.start_with?("AllowlistMatch")
    return attrs(
      disposition: "equivalent-public-api", cluster: "config.allowlist-condition",
      crate: "rustleaks-core", module_name: "config::allowlist", path: "rustleaks_core::config::AllowlistCondition", publicity: "public",
      justification: "A public raw enum and Display preserve OR/AND identity and externally visible spelling while avoiding integerly typed state.",
      section: "configuration", behavior_links: ["TM-ALL-001"]
    )
  end
  if owning_type == "Allowlist" || (kind == "type" && name == "Allowlist")
    if kind == "method"
      if name == "Validate"
        return attrs(
          disposition: "idiomatic-public-replacement", cluster: "config.allowlist-compilation",
          crate: "rustleaks-core", module_name: "config::allowlist", path: "rustleaks_core::config::ConfigLoader::compile", publicity: "public",
          justification: "Mutable validate-in-place becomes fallible compilation from AllowlistSpec with structured errors.",
          section: "configuration", behavior_links: ["TM-ALL-001"]
        )
      end
      rust_method = {
        "CommitAllowed" => "commit_allowed",
        "PathAllowed" => "path_allowed",
        "RegexAllowed" => "regex_allowed",
        "ContainsStopWord" => "contains_stop_word"
      }.fetch(name)
      return attrs(
        disposition: "compatibility-tooling-private-implementation", cluster: "config.compiled-allowlist-matching",
        crate: "rustleaks-core", module_name: "config::compiled", path: "rustleaks_core::config::CompiledAllowlist::#{rust_method}", publicity: "crate-private",
        justification: "Commit/path/regex/stop-word matching remains an internal pure operation over a compiled allowlist; backend regex objects are not public.",
        section: "configuration", behavior_links: ["TM-ALL-001"]
      )
    end
    patterns = %w[Paths Regexes RegexTarget].include?(name)
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: patterns ? "config.allowlist-pattern-spec" : "config.allowlist-spec",
      crate: "rustleaks-core", module_name: "config::allowlist", path: "rustleaks_core::config::AllowlistSpec", publicity: "public",
      justification: patterns ?
        "Public raw pattern strings live in AllowlistSpec while compiled regex values remain private behind the GoRegex compatibility gate." :
        "Constructible AllowlistSpec replaces mutable Go fields and compiles into an immutable CompiledAllowlist with semantic accessors.",
      section: "configuration", behavior_links: ["TM-ALL-001"]
    )
  end
  if owning_type == "ViperConfig" || owning_type.start_with?("ViperConfig.Rules") || owning_type.start_with?("viper") || (kind == "type" && name == "ViperConfig")
    if kind == "method" && name == "Translate"
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "config.raw-translation",
        crate: "rustleaks-core", module_name: "config::loader", path: "rustleaks_core::config::ConfigLoader::compile", publicity: "public",
        justification: "Translate becomes fallible RawConfig compilation with structured ConfigError and injected extension resolution.",
        section: "configuration", behavior_links: ["TM-ALL-001"]
      )
    end
    path, cluster = if owning_type.start_with?("ViperConfig.Rules")
      ["rustleaks_core::config::RuleSpec", "config.raw-rule-spec"]
    elsif owning_type == "viperRuleAllowlist"
      ["rustleaks_core::config::RawAllowlist", "config.raw-allowlist"]
    elsif owning_type == "viperGlobalAllowlist"
      ["rustleaks_core::config::RawGlobalAllowlist", "config.raw-global-allowlist"]
    elsif owning_type == "viperRequired"
      ["rustleaks_core::config::RequiredRuleSpec", "config.raw-required-rule"]
    else
      ["rustleaks_core::config::RawConfig", "config.raw-config"]
    end
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: cluster,
      crate: "rustleaks-core", module_name: "config::raw", path: path, publicity: "public",
      justification: "The permissive public raw configuration shape uses named serde-friendly Rust structs and aliases instead of anonymous or unnameable Go element types.",
      section: "configuration", behavior_links: ["TM-ALL-001"]
    )
  end
  if owning_type == "Config" || (kind == "type" && name == "Config")
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "config.compiled-config",
      crate: "rustleaks-core", module_name: "config::compiled", path: "rustleaks_core::config::CompiledConfig", publicity: "public",
      justification: "Mutable Config fields become immutable compiled state with read-only semantic access; regex/trie maps and ordering machinery remain private.",
      section: "configuration", behavior_links: ["TM-ALL-001"]
    )
  end
  if owning_type == "Extend" || (kind == "type" && name == "Extend")
    return attrs(
      disposition: "equivalent-public-api", cluster: "config.extension-spec",
      crate: "rustleaks-core", module_name: "config::raw", path: "rustleaks_core::config::ConfigExtension", publicity: "public",
      justification: "ConfigExtension preserves path, URL, default, and disabled-rule inputs while resolution moves behind an injected resolver.",
      section: "configuration", behavior_links: ["TM-ALL-001"]
    )
  end
  if owning_type == "Rule" || (kind == "type" && name == "Rule")
    if kind == "method"
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "config.rule-compilation",
        crate: "rustleaks-core", module_name: "config::compiled", path: "rustleaks_core::config::ConfigLoader::compile", publicity: "public",
        justification: "Mutable Rule.Validate becomes fallible RuleSpec compilation with structured errors and private compiled regexes.",
        section: "configuration", behavior_links: ["TM-ALL-001"]
      )
    end
    patterns = %w[Regex Path].include?(name)
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: patterns ? "config.rule-pattern-spec" : "config.rule-spec",
      crate: "rustleaks-core", module_name: "config::raw", path: "rustleaks_core::config::RuleSpec", publicity: "public",
      justification: patterns ?
        "RuleSpec exposes raw regex/path source text while compiled engines remain private and inspectable only semantically." :
        "Public RuleSpec preserves rule data/order/duplicates and compiles into an immutable CompiledRule.",
      section: "configuration", behavior_links: ["TM-ALL-001"]
    )
  end
  if owning_type == "Required" || (kind == "type" && name == "Required")
    return attrs(
      disposition: "equivalent-public-api", cluster: "config.required-rule-spec",
      crate: "rustleaks-core", module_name: "config::raw", path: "rustleaks_core::config::RequiredRuleSpec", publicity: "public",
      justification: "RequiredRuleSpec directly preserves rule ID and optional line/column distances in a constructible public type.",
      section: "configuration", behavior_links: ["TM-ALL-001"]
    )
  end
  abort "unclassified config API: #{record.fetch('key')}"
end

def detect_annotation(record)
  name = record.fetch("name")
  kind = record.fetch("kind")
  owning_type = owner(record)

  if name == "SlowWarningThreshold"
    return attrs(
      disposition: "out-of-public-product-scope", cluster: "detect.slow-warning",
      crate: "rustleaks-cli", module_name: "diagnostics", path: "rustleaks_cli::diagnostics::SLOW_WARNING_THRESHOLD", publicity: "binary-private",
      justification: "The threshold is a CLI/adapter diagnostic default, not scanning semantics or core public API.", section: "detection-and-codec"
    )
  end
  if name == "Fragment" && kind == "type"
    return attrs(
      disposition: "compatibility-shim", cluster: "detect.deprecated-fragment-alias",
      crate: "rustleaks-compat", module_name: "detect", path: "rustleaks_compat::detect::Fragment", publicity: "compatibility-public",
      justification: "The deprecated detect alias forwards to rustleaks_core::Fragment and never duplicates model storage or behavior.",
      section: "detection-and-codec", behavior_links: %w[MODEL-001 MODEL-002]
    )
  end
  if name == "RemoteInfo" || name == "NewRemoteInfo"
    return attrs(
      disposition: "compatibility-shim", cluster: "detect.deprecated-remote-info",
      crate: "rustleaks-compat", module_name: "detect", path: "rustleaks_compat::detect::RemoteInfo", publicity: "compatibility-public",
      justification: "The deprecated detect facade forwards to downstream RemoteMetadata discovery without making sources a core dependency.",
      section: "detection-and-codec", behavior_links: ["MODEL-002"]
    )
  end
  if name == "Location" && kind == "type"
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "detect.location-model",
      crate: "rustleaks-core", module_name: "model", path: "rustleaks_core::Location", publicity: "public",
      justification: "The opaque Go calculator stays private, while its validated observable location result is an implemented public core model.",
      section: "detection-and-codec", behavior_links: ["MODEL-003"], implementation_status: "implemented",
      test_status: "passing", evidence_status: "rust-tested", implementation_evidence: "crates/rustleaks-core/tests/model.rs"
    )
  end
  if name == "IsNew" && kind == "func"
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "detect.baseline",
      crate: "rustleaks-core", module_name: "session", path: "rustleaks_core::session::Baseline::is_new", publicity: "public",
      justification: "Baseline newness is an immutable query over the public Finding model with the caller's redaction policy supplied explicitly.",
      section: "detection-and-codec", behavior_links: %w[MODEL-003 SESSION-006 SESSION-007],
      implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
      implementation_evidence: "crates/rustleaks-core/src/session.rs; crates/rustleaks-core/tests/session_corpus.rs; cargo xtask session-check"
    )
  end
  if name == "LoadBaseline" && kind == "func"
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "detect.baseline",
      crate: "rustleaks-core", module_name: "session", path: "rustleaks_core::session::Baseline::load_go_json", publicity: "public",
      justification: "The core replacement loads Go-compatible JSON baselines with structured portable I/O and parse errors; report-format dispatch and presentation text remain adapter concerns.",
      section: "detection-and-codec", behavior_links: %w[MODEL-003 SESSION-005 SESSION-006],
      implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
      implementation_evidence: "crates/rustleaks-core/src/session.rs; crates/rustleaks-core/tests/session_corpus.rs; cargo xtask session-check"
    )
  end
  if owning_type == "Detector" || (kind == "type" && name == "Detector")
    if kind == "method" && %w[DetectReader StreamDetectReader DetectFiles].include?(name)
      path = name == "DetectFiles" ? "rustleaks_sources::DirectorySource" : "rustleaks_sources::FileSource"
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "detect.deprecated-adapters",
        crate: "rustleaks-sources", module_name: "source", path: path, publicity: "public",
        justification: "Safe synchronous FileSource and DirectorySource adapters replace deprecated channel-shaped reader/files methods; SourceRunner composes them with Engine and ScanSession.",
        section: "detection-and-codec", behavior_links: %w[SRC-001 SRC-009 SRC-010 SRC-028 SRC-030],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-sources/src/file.rs; crates/rustleaks-sources/src/directory.rs; crates/rustleaks-sources/tests/source_corpus.rs; cargo xtask source-check"
      )
    end
    if kind == "method" && name == "DetectGit"
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "detect.deprecated-adapters",
        crate: "rustleaks-sources", module_name: "git", path: "rustleaks_sources::GitSource", publicity: "public",
        justification: "The deprecated detector-owned Git entry point is finally replaced by public GitSource plus SourceRunner; no Go-shaped mutable compatibility method ships.",
        section: "detection-and-codec", behavior_links: %w[TM-ALL-001 GIT-001 GIT-022 GIT-023],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-sources/src/git.rs; crates/rustleaks-sources/src/runner.rs; crates/rustleaks-sources/tests/git_corpus.rs; cargo xtask git-check"
      )
    end
    if kind == "method" && name == "DetectSource"
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "detect.source-runner",
        crate: "rustleaks-sources", module_name: "runner", path: "rustleaks_sources::SourceRunner", publicity: "public",
        justification: "Source execution lives downstream over the public Source trait so rustleaks-core never depends on source adapters.",
        section: "detection-and-codec", behavior_links: %w[SRC-001 SRC-026 SRC-027 SRC-028 SRC-030],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-sources/src/runner.rs; crates/rustleaks-sources/tests/native_sources.rs; crates/rustleaks-sources/tests/source_corpus.rs"
      )
    end
    if kind == "method" && %w[DetectBytes DetectString Detect DetectContext].include?(name)
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "detect.direct-scan",
        crate: "rustleaks-core", module_name: "engine", path: "rustleaks_core::Engine::scan_fragment", publicity: "public",
        justification: "Direct mutable detector calls become immutable Engine scan_fragment operations; controlled cancellation and session/source policy are explicit completed layers.",
        section: "detection-and-codec", behavior_links: %w[MODEL-001 MODEL-002 MODEL-003 COMP-001 COMP-002 COMP-003 COMP-004 COMP-005 COMP-006 COMP-007 COMP-008 SUP-001 RED-001 RED-002 RED-003],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-core/src/engine.rs; crates/rustleaks-core/tests/detect_corpus.rs; crates/rustleaks-core/tests/composite_corpus.rs; crates/rustleaks-sources/src/runner.rs; cargo xtask source-check"
      )
    end
    if kind == "method" && name == "AddGitleaksIgnore"
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "detect.scan-session",
        crate: "rustleaks-core", module_name: "session", path: "rustleaks_core::session::IgnoreSet::parse_go_compatible", publicity: "public",
        justification: "The byte parser, normalization, scanner limit, malformed-line diagnostics, immutable policy installation, named-file loading, and host diagnostics are implemented across core and CLI layers.",
        section: "detection-and-codec", behavior_links: %w[MODEL-003 SESSION-002 SESSION-003 SESSION-004],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-core/src/session.rs; crates/rustleaks-core/tests/session_corpus.rs; crates/rustleaks-cli/src/config.rs; crates/rustleaks-cli/tests/cli.rs; cargo xtask cli-check"
      )
    end
    if kind == "method" && name == "AddBaseline"
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "detect.scan-session",
        crate: "rustleaks-core", module_name: "session", path: "rustleaks_core::session::SessionPolicyBuilder::baseline", publicity: "public",
        justification: "Baseline parsing, equality, immutable policy installation, and native source-relative baseline exclusion are implemented; no hidden mutable reset API is retained.",
        section: "detection-and-codec", behavior_links: %w[MODEL-003 SESSION-005 SESSION-006 SESSION-007],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-core/src/session.rs; crates/rustleaks-core/tests/session_corpus.rs; crates/rustleaks-cli/src/config.rs; crates/rustleaks-cli/tests/cli.rs; cargo xtask cli-check"
      )
    end
    if kind == "method" && name == "AddFinding"
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "detect.scan-session",
        crate: "rustleaks-core", module_name: "session", path: "rustleaks_core::session::ScanSession::add_finding", publicity: "public",
        justification: "Owned findings are fingerprinted, classified against immutable session policy, and either suppressed with an explicit reason or appended without hidden shared mutation.",
        section: "detection-and-codec", behavior_links: %w[MODEL-003 SESSION-001 SESSION-004 SESSION-008],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-core/src/session.rs; crates/rustleaks-core/tests/session_corpus.rs; cargo xtask session-check"
      )
    end
    if kind == "method" && name == "Findings"
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "detect.scan-session",
        crate: "rustleaks-core", module_name: "session", path: "rustleaks_core::session::ScanSession::findings", publicity: "public",
        justification: "The explicit session exposes borrowed, cloned, or consuming snapshots while canonical ordering remains an opt-in portable helper.",
        section: "detection-and-codec", behavior_links: %w[MODEL-003 SESSION-008 SESSION-009 SESSION-010],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-core/src/session.rs; crates/rustleaks-core/tests/session_corpus.rs; cargo xtask session-check"
      )
    end
    if kind == "field"
      if %w[Verbose NoColor ReportPath Reporter].include?(name)
        return attrs(
          disposition: "out-of-public-product-scope", cluster: "detect.cli-report-options",
          crate: "rustleaks-cli", module_name: "run", path: "rustleaks_cli::RunOptions::#{name}", publicity: "binary-private",
          justification: "Verbosity, color, output path, and reporter selection are CLI/report orchestration rather than engine state.",
          section: "detection-and-codec"
        )
      end
      if name == "Sema"
        return attrs(
          disposition: "compatibility-tooling-private-implementation", cluster: "detect.scheduler-internal",
          crate: "rustleaks-sources", module_name: "scheduler", path: "rustleaks_sources::scheduler", publicity: "crate-private",
          justification: "The Go semaphore is hidden scheduling policy; callers configure limits without receiving a semaphore object.",
          section: "detection-and-codec"
        )
      end
      if %w[MaxArchiveDepth FollowSymlinks].include?(name)
        path = name == "MaxArchiveDepth" ? "rustleaks_sources::ArchiveLimits::new" : "rustleaks_sources::DirectoryOptions::follow_symlinks"
        return attrs(
          disposition: "idiomatic-public-replacement", cluster: "detect.source-options",
          crate: "rustleaks-sources", module_name: "options", path: path, publicity: "public",
          justification: "Archive depth and symlink following are source-adapter builder options, not mutable core detector fields.",
          section: "detection-and-codec", behavior_links: %w[SRC-014 SRC-016 SRC-019 SRC-029 SRC-030],
          implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
          implementation_evidence: "crates/rustleaks-sources/src/archive.rs; crates/rustleaks-sources/src/directory.rs; crates/rustleaks-sources/tests/source_corpus.rs"
        )
      end
      if name == "TotalBytes"
        return attrs(
          disposition: "idiomatic-public-replacement", cluster: "detect.scan-statistics",
          crate: "rustleaks-sources", module_name: "runner", path: "rustleaks_sources::SourceOutcome::scanned_bytes", publicity: "public",
          justification: "A completed source outcome exposes checked scanned-byte statistics instead of a mutable public atomic counter on the engine.",
          section: "detection-and-codec", behavior_links: %w[SRC-028 SRC-029],
          implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
          implementation_evidence: "crates/rustleaks-sources/src/runner.rs; crates/rustleaks-sources/tests/native_sources.rs; cargo xtask source-check"
        )
      end
      if %w[Redact MaxDecodeDepth MaxTargetMegaBytes IgnoreGitleaksAllow].include?(name)
        scan_option_behaviors = ["MODEL-003"]
        scan_option_behaviors << "DEC-010" if name == "MaxDecodeDepth"
        scan_option_behaviors.concat(%w[RED-001 RED-002 RED-003]) if name == "Redact"
        return attrs(
          disposition: "idiomatic-public-replacement", cluster: "detect.scan-options",
          crate: "rustleaks-core", module_name: "model", path: "rustleaks_core::ScanOptions", publicity: "public",
          justification: "Per-scan immutable options replace mutable detector flags; honor_gitleaks_allow uses non-inverted naming.",
          section: "detection-and-codec", behavior_links: scan_option_behaviors, implementation_status: "implemented",
          test_status: "passing", evidence_status: "rust-tested", implementation_evidence: name == "MaxDecodeDepth" ?
            "crates/rustleaks-core/tests/model.rs; crates/rustleaks-core/tests/detect_corpus.rs; cargo xtask decoder-check" :
            (name == "Redact" ? "crates/rustleaks-core/tests/model.rs; crates/rustleaks-core/tests/composite_corpus.rs; cargo xtask composite-check" : "crates/rustleaks-core/tests/model.rs")
        )
      end
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "detect.engine-config",
        crate: "rustleaks-core", module_name: "engine", path: "rustleaks_core::Engine", publicity: "public",
        justification: "The engine owns immutable CompiledConfig rather than exposing mutable detector configuration.",
        section: "detection-and-codec", implementation_status: "implemented", test_status: "passing",
        evidence_status: "rust-tested", implementation_evidence: "crates/rustleaks-core/src/engine.rs; crates/rustleaks-core/tests/engine.rs; cargo xtask detect-check"
      )
    end
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "detect.engine-session",
      crate: "rustleaks-core", module_name: "engine", path: "rustleaks_core::Engine", publicity: "public",
      justification: "The mutable Detector surface is split into immutable Engine, per-call ScanOptions, and explicit ScanSession.",
      section: "detection-and-codec", implementation_status: "implemented", test_status: "passing",
      evidence_status: "rust-tested", implementation_evidence: "crates/rustleaks-core/src/engine.rs; crates/rustleaks-core/src/session.rs; cargo xtask session-check"
    )
  end
  if %w[NewDetector NewDetectorContext NewDetectorDefaultConfig].include?(name)
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "detect.engine-construction",
      crate: "rustleaks-core", module_name: "engine", path: "rustleaks_core::Engine::builder", publicity: "public",
      justification: "Engine builders and ConfigLoader replace detector constructors; cancellation is passed per operation instead of stored globally.",
      section: "detection-and-codec", implementation_status: "implemented", test_status: "passing",
      evidence_status: "rust-tested", implementation_evidence: "crates/rustleaks-core/src/engine.rs; crates/rustleaks-core/tests/config.rs; crates/rustleaks-core/tests/engine.rs; cargo xtask detect-check"
    )
  end
  abort "unclassified detect API: #{record.fetch('key')}"
end

def report_annotation(record)
  name = record.fetch("name")
  kind = record.fetch("kind")
  owning_type = owner(record)
  report_tested = {
    implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
    implementation_evidence: "crates/rustleaks-report/src; crates/rustleaks-report/tests; compat/report-corpus; cargo xtask report-check"
  }

  if owning_type == "Finding" || (kind == "type" && name == "Finding")
    if kind == "method"
      if name == "PrintRequiredFindings"
        return attrs(
          disposition: "out-of-public-product-scope", cluster: "report.finding-printing",
          crate: "rustleaks-cli", module_name: "finding", path: "rustleaks_cli::finding::print_required", publicity: "binary-private",
          justification: "Printing required findings belongs to CLI/report presentation; core exposes queryable required-finding data.",
          section: "findings-and-reports", behavior_links: ["MODEL-003"]
        )
      end
      if name == "Redact"
        return attrs(
          disposition: "idiomatic-public-replacement", cluster: "report.finding-redaction",
          crate: "rustleaks-core", module_name: "model", path: "rustleaks_core::Finding::redacted", publicity: "public",
          justification: "Redaction is a consuming transformation that preserves immutable caller state and reproduces the pinned byte-oriented mutation result.",
          section: "findings-and-reports", behavior_links: %w[MODEL-003 RED-001 RED-002 RED-003],
          implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
          implementation_evidence: "crates/rustleaks-core/src/model.rs; crates/rustleaks-core/tests/model.rs; crates/rustleaks-core/tests/composite_corpus.rs; cargo xtask composite-check"
        )
      end
      if name == "AddRequiredFindings"
        return attrs(
          disposition: "idiomatic-public-replacement", cluster: "report.finding-required",
          crate: "rustleaks-core", module_name: "model", path: "rustleaks_core::Finding::add_required_findings", publicity: "public",
          justification: "Required findings are appended through builders/transformations while order and duplicates remain observable.",
          section: "findings-and-reports", behavior_links: %w[MODEL-003 COMP-005],
          implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
          implementation_evidence: "crates/rustleaks-core/src/model.rs; crates/rustleaks-core/tests/model.rs; crates/rustleaks-core/tests/composite_corpus.rs; cargo xtask composite-check"
        )
      end
      abort "unclassified Finding method: #{record.fetch('key')}"
    end
    return implemented_model_attrs(cluster: "report.finding-model", path: "rustleaks_core::Finding", behavior_links: %w[MODEL-001 MODEL-003])
  end
  if owning_type == "RequiredFinding" || (kind == "type" && name == "RequiredFinding")
    return implemented_model_attrs(cluster: "report.required-finding-model", path: "rustleaks_core::RequiredFinding", behavior_links: %w[MODEL-001 MODEL-003])
  end
  if %w[CWE CWE_DESCRIPTION].include?(name)
    return attrs(
      disposition: "equivalent-public-api", cluster: "report.cwe-metadata",
      crate: "rustleaks-report", module_name: "lib", path: "rustleaks_report::#{name}", publicity: "public",
      justification: "Reporter consumers may use the same stable CWE metadata constants; they do not belong in core.",
      section: "findings-and-reports", behavior_links: %w[TM-ALL-001 REPORT-008], **report_tested
    )
  end
  if name == "StdoutReportPath"
    return attrs(
      disposition: "out-of-public-product-scope", cluster: "report.stdout-routing",
      crate: "rustleaks-cli", module_name: "report", path: "rustleaks_cli::report::OutputTarget::Stdout", publicity: "binary-private",
      justification: "Stdout routing is a CLI output-target choice, not a core or reusable reporter constant.",
      section: "findings-and-reports"
    )
  end
  junit_types = %w[TestSuites TestSuite TestCase Failure]
  sarif_types = %w[PartialFingerPrints Sarif ShortDescription FullDescription Rules Driver Tool Message ArtifactLocation Region Snippet PhysicalLocation Locations Properties Results Runs]
  if junit_types.include?(name) || junit_types.include?(owning_type)
    return attrs(
      disposition: "compatibility-tooling-private-implementation", cluster: "report.junit-dto",
      crate: "rustleaks-report", module_name: "junit::dto", path: "rustleaks_report::junit::dto::#{member(record)}", publicity: "crate-private",
      justification: "JUnit DTO layout is private serialization machinery; exact XML bytes/shape are the public compatibility contract.",
      section: "findings-and-reports", behavior_links: %w[TM-ALL-001 REPORT-006 REPORT-007], **report_tested
    )
  end
  if sarif_types.include?(name) || sarif_types.include?(owning_type)
    return attrs(
      disposition: "compatibility-tooling-private-implementation", cluster: "report.sarif-dto",
      crate: "rustleaks-report", module_name: "sarif::dto", path: "rustleaks_report::sarif::dto::#{member(record)}", publicity: "crate-private",
      justification: "SARIF DTO names/fields remain private serialization machinery; exact JSON keys and output shape are golden behavior.",
      section: "findings-and-reports", behavior_links: %w[TM-ALL-001 REPORT-008 REPORT-009], **report_tested
    )
  end
  if owning_type == "TemplateReporter" || name == "TemplateReporter" || name == "NewTemplateReporter"
    return attrs(
      disposition: "compatibility-shim", cluster: "report.template-reporter",
      crate: "rustleaks-report", module_name: "template", path: "rustleaks_report::TemplateReporter", publicity: "compatibility-public",
      justification: "The template reporter is public only as a restricted compatibility feature after Go-template semantics and safety pass.",
      section: "findings-and-reports", behavior_links: %w[TM-ALL-001 REPORT-010 REPORT-011], **report_tested
    )
  end
  if owning_type == "Reporter" || name == "Reporter"
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "report.reporter-trait",
      crate: "rustleaks-report", module_name: "lib", path: "rustleaks_report::Reporter", publicity: "public",
      justification: "A public Reporter trait writes to std::io::Write and returns ReportError while caller retains closing ownership.",
      section: "findings-and-reports", behavior_links: %w[TM-ALL-001 REPORT-001], **report_tested
    )
  end
  public_reporters = %w[CsvReporter JsonReporter JunitReporter SarifReporter]
  if public_reporters.include?(name) || public_reporters.include?(owning_type)
    if kind == "method" || (owning_type == "SarifReporter" && name == "OrderedRules")
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "report.public-reporters",
        crate: "rustleaks-report", module_name: "lib", path: "rustleaks_report::#{owning_type.empty? ? name : owning_type}", publicity: "public",
        justification: "Reusable reporters stay public, but Write uses Rust writer ownership/errors and SARIF receives ordered rule metadata at construction.",
        section: "findings-and-reports", behavior_links: %w[TM-ALL-001 REPORT-001 REPORT-002 REPORT-004 REPORT-006 REPORT-008], **report_tested
      )
    end
    return attrs(
      disposition: "equivalent-public-api", cluster: "report.public-reporters",
      crate: "rustleaks-report", module_name: "lib", path: "rustleaks_report::#{name}", publicity: "public",
      justification: "The reusable reporter type keeps the same role while serialization details remain private.",
      section: "findings-and-reports", behavior_links: %w[TM-ALL-001 REPORT-001 REPORT-002 REPORT-004 REPORT-006 REPORT-008], **report_tested
    )
  end
  abort "unclassified report API: #{record.fetch('key')}"
end

def sources_annotation(record)
  name = record.fetch("name")
  kind = record.fetch("kind")
  owning_type = owner(record)

  if owning_type == "Fragment" || (kind == "type" && name == "Fragment")
    model = implemented_model_attrs(cluster: "sources.fragment-model", path: "rustleaks_core::Fragment", behavior_links: %w[MODEL-001 MODEL-002])
    return model.merge(design_evidence: "#{DOC}#sources")
  end
  if owning_type == "CommitInfo" || (kind == "type" && name == "CommitInfo")
    remote_field = owning_type == "CommitInfo" && name == "Remote"
    if remote_field
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "sources.remote-metadata",
        crate: "rustleaks-sources", module_name: "scm", path: "rustleaks_sources::RemoteMetadata", publicity: "public",
        justification: "RemoteMetadata preserves remote platform and URL downstream; explicit composition replaces automatic attachment to core CommitMetadata as the final dependency-safe API.",
        section: "sources", behavior_links: %w[MODEL-002 GIT-016 GIT-017 GIT-018], implementation_status: "implemented", test_status: "passing",
        evidence_status: "rust-tested", implementation_evidence: "crates/rustleaks-sources/src/scm.rs; crates/rustleaks-sources/tests/git_scm.rs"
      )
    end
    implementation_status = "implemented"
    test_status = "passing"
    evidence_status = "rust-tested"
    implementation_evidence = "crates/rustleaks-core/tests/model.rs; crates/rustleaks-sources/src/scm.rs; crates/rustleaks-sources/tests/git_scm.rs; cargo xtask git-check"
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "sources.commit-metadata",
      crate: "rustleaks-core", module_name: "model", path: "rustleaks_core::CommitMetadata", publicity: "public",
      justification: "CommitMetadata implements byte-preserving SHA/author/email/date/message data; explicit downstream RemoteMetadata composition is the final replacement for the Go reverse dependency.",
      section: "sources", behavior_links: ["MODEL-002"], implementation_status: implementation_status, test_status: test_status,
      evidence_status: evidence_status, implementation_evidence: implementation_evidence
    )
  end
  if name == "InnerPathSeparator"
    return attrs(
      disposition: "equivalent-public-api", cluster: "sources.inner-path-separator",
      crate: "rustleaks-sources", module_name: "path", path: "rustleaks_sources::INNER_PATH_SEPARATOR", publicity: "public",
      justification: "The archive inner-path separator remains an exact downstream public constant used in observable paths.",
      section: "sources", behavior_links: ["SRC-021"], implementation_status: "implemented",
      test_status: "passing", evidence_status: "rust-tested",
      implementation_evidence: "crates/rustleaks-sources/src/path.rs; crates/rustleaks-sources/tests/source_corpus.rs"
    )
  end
  if owning_type == "ScanTarget" || name == "ScanTarget" || name == "DirectoryTargets"
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "sources.deprecated-directory-targets",
      crate: "rustleaks-sources", module_name: "directory", path: "rustleaks_sources::DirectorySource", publicity: "public",
      justification: "Deprecated ScanTarget traversal is finally omitted; public DirectorySource replaces channel/scheduler-shaped records without a Go-shaped compatibility type.",
      section: "sources", behavior_links: %w[FIX-ALL-001 TM-ALL-001 SRC-010 SRC-028],
      implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
      implementation_evidence: "crates/rustleaks-sources/src/directory.rs; crates/rustleaks-sources/tests/native_sources.rs; cargo xtask source-check"
    )
  end
  if owning_type == "GitCmd" || name == "GitCmd" || %w[NewGitLogCmd NewGitLogCmdContext NewGitDiffCmd NewGitDiffCmdContext].include?(name)
    return attrs(
      disposition: "compatibility-tooling-private-implementation", cluster: "sources.git-command-internal",
      crate: "rustleaks-sources", module_name: "git", path: "rustleaks_sources::git::collect_command", publicity: "crate-private",
      justification: "Git subprocess, channels, wait lifecycle, and blob readers stay private behind public GitSource/GitMode builders and structured diagnostics.",
      section: "sources", behavior_links: %w[FIX-ALL-001 TM-ALL-001 GIT-001 GIT-002 GIT-003 GIT-004 GIT-008 GIT-009 GIT-013 GIT-014 GIT-015 GIT-020 GIT-021 GIT-022],
      implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
      implementation_evidence: "crates/rustleaks-sources/src/git.rs; crates/rustleaks-sources/tests/git_corpus.rs; crates/rustleaks-sources/tests/git_sources.rs"
    )
  end
  if owning_type == "RemoteInfo" || name == "RemoteInfo" || %w[NewRemoteInfo NewRemoteInfoContext].include?(name)
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "sources.remote-metadata",
      crate: "rustleaks-sources", module_name: "scm", path: "rustleaks_sources::RemoteMetadata", publicity: "public",
      justification: "RemoteMetadata publicly preserves platform and URL; discovery is fallible and cancellation-aware rather than a mutable Go helper.",
      section: "sources", behavior_links: %w[MODEL-002 GIT-016 GIT-017 GIT-018 GIT-019],
      implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
      implementation_evidence: "crates/rustleaks-sources/src/scm.rs; crates/rustleaks-sources/tests/git_scm.rs"
    )
  end
  if owning_type == "File" || name == "File"
    if owning_type == "File" && name == "Buffer"
      return attrs(
        disposition: "compatibility-tooling-private-implementation", cluster: "sources.file-buffer-internal",
        crate: "rustleaks-sources", module_name: "file", path: "rustleaks_sources::file::buffer", publicity: "crate-private",
        justification: "The mutable scratch buffer is internal implementation state; FileSource exposes content and options, not buffering internals.",
        section: "sources", behavior_links: %w[SRC-003 SRC-004 SRC-005 SRC-006], implementation_status: "implemented",
        test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-sources/src/file.rs; crates/rustleaks-sources/tests/source_corpus.rs"
      )
    end
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "sources.file-source",
      crate: "rustleaks-sources", module_name: "file", path: "rustleaks_sources::FileSource", publicity: "public",
      justification: "FileSource builder preserves content/path/symlink/config/depth behavior while hiding mutable fields and yielding fragments through Source; recognized unsupported codecs have final structured-error dispositions.",
      section: "sources", behavior_links: %w[MODEL-002 SRC-001 SRC-002 SRC-003 SRC-004 SRC-005 SRC-006 SRC-007 SRC-008 SRC-017 SRC-018 SRC-019 SRC-020 SRC-021 SRC-022 SRC-023 SRC-024 SRC-025 SRC-027 SRC-029 SRC-030],
      implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
      implementation_evidence: "crates/rustleaks-sources/src/file.rs; crates/rustleaks-sources/src/archive.rs; crates/rustleaks-sources/tests/source_corpus.rs; crates/rustleaks-sources/tests/archive_sources.rs; cargo xtask source-check"
    )
  end
  if owning_type == "Files" || name == "Files"
    if owning_type == "Files" && name == "Sema"
      return attrs(
        disposition: "compatibility-tooling-private-implementation", cluster: "sources.directory-scheduler-internal",
        crate: "rustleaks-sources", module_name: "directory", path: "rustleaks_sources::directory::scheduler", publicity: "crate-private",
        justification: "The semaphore is private traversal policy; concurrency limits are options, not an exposed scheduler object.",
        section: "sources", behavior_links: %w[SRC-026 SRC-027 SRC-028], implementation_status: "implemented",
        test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-sources/src/runner.rs; crates/rustleaks-sources/tests/native_sources.rs"
      )
    end
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "sources.directory-source",
      crate: "rustleaks-sources", module_name: "directory", path: "rustleaks_sources::DirectorySource", publicity: "public",
      justification: "DirectorySource builder preserves path, size, symlink, archive, and config options while hiding mutable traversal state; native Linux/Windows runtime reruns remain nonblocking follow-ups.",
      section: "sources", behavior_links: %w[SRC-010 SRC-011 SRC-012 SRC-013 SRC-014 SRC-015 SRC-016 SRC-017 SRC-018 SRC-022 SRC-025 SRC-026 SRC-027 SRC-028 SRC-029 SRC-030],
      implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
      implementation_evidence: "crates/rustleaks-sources/src/directory.rs; crates/rustleaks-sources/tests/native_sources.rs; crates/rustleaks-sources/tests/archive_sources.rs; crates/rustleaks-sources/tests/source_corpus.rs; cargo xtask source-check"
    )
  end
  if owning_type == "Git" || name == "Git"
    if owning_type == "Git" && %w[Cmd Sema].include?(name)
      command_field = name == "Cmd"
      return attrs(
        disposition: "compatibility-tooling-private-implementation", cluster: "sources.git-source-internals",
        crate: "rustleaks-sources", module_name: "git", path: command_field ? "rustleaks_sources::git::collect_command" : "rustleaks_sources::GitSource", publicity: command_field ? "crate-private" : "public",
        justification: command_field ? "The child command boundary is the real private collect_command function." : "GitSource is deliberately synchronous and has no semaphore field; the upstream scheduler field is finally excluded and concurrency remains caller-owned.",
        section: "sources", behavior_links: %w[FIX-ALL-001 GIT-012 GIT-014 GIT-015 GIT-020 GIT-021 GIT-022],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-sources/src/git.rs; crates/rustleaks-sources/tests/git_corpus.rs; crates/rustleaks-sources/tests/git_sources.rs"
      )
    end
    if owning_type == "Git" && name == "Remote"
      return attrs(
        disposition: "idiomatic-public-replacement", cluster: "sources.remote-metadata",
        crate: "rustleaks-sources", module_name: "scm", path: "rustleaks_sources::RemoteMetadata", publicity: "public",
        justification: "RemoteMetadata is discovered explicitly and can be composed with findings; this final explicit composition replaces automatic mutable attachment.",
        section: "sources", behavior_links: %w[GIT-016 GIT-017 GIT-018 GIT-019],
        implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
        implementation_evidence: "crates/rustleaks-sources/src/scm.rs; crates/rustleaks-sources/tests/git_scm.rs"
      )
    end
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "sources.git-source",
      crate: "rustleaks-sources", module_name: "git", path: "rustleaks_sources::GitSource", publicity: "public",
      justification: "GitSource exposes explicit shell-free history/diff modes, checked limits, environment isolation, and optional archive expansion while subprocess and scheduling details stay private.",
      section: "sources", behavior_links: %w[FIX-ALL-001 TM-ALL-001 GIT-001 GIT-002 GIT-003 GIT-004 GIT-005 GIT-006 GIT-007 GIT-008 GIT-009 GIT-010 GIT-011 GIT-012 GIT-013 GIT-014 GIT-015 GIT-020 GIT-021 GIT-022 GIT-023],
      implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
      implementation_evidence: "crates/rustleaks-sources/src/git.rs; crates/rustleaks-sources/tests/git_corpus.rs; crates/rustleaks-sources/tests/git_sources.rs"
    )
  end
  if name == "FragmentsFunc" || name == "Source" || owning_type == "Source"
    return attrs(
      disposition: "idiomatic-public-replacement", cluster: "sources.source-trait",
      crate: "rustleaks-sources", module_name: "source", path: "rustleaks_sources::Source", publicity: "public",
      justification: "A synchronous cancellation-aware Source trait with a fallible callback/iterator preserves fragment-plus-issue behavior without an async runtime.",
      section: "sources", behavior_links: %w[MODEL-001 MODEL-002 SRC-001 SRC-009 SRC-027 SRC-030],
      implementation_status: "implemented", test_status: "passing", evidence_status: "rust-tested",
      implementation_evidence: "crates/rustleaks-sources/src/source.rs; crates/rustleaks-sources/tests/native_sources.rs"
    )
  end
  abort "unclassified sources API: #{record.fetch('key')}"
end

def expected_rows
  generator_ids = constructor_manifest_ids
  inventory.fetch("records").map do |record|
    row(record, annotation_for(record, generator_ids))
  end.sort_by { |entry| entry.fetch("source_key") }
end

def jsonl(rows)
  rows.map { |entry| JSON.generate(entry) }.join("\n") + "\n"
end

def load_rows(path = DISPOSITIONS_PATH)
  if path == DISPOSITIONS_PATH
    digest = Digest::SHA256.file(path).hexdigest
    abort "disposition JSONL file digest mismatch: got #{digest}, want #{EXPECTED_DISPOSITIONS_SHA256}" unless digest == EXPECTED_DISPOSITIONS_SHA256
  end
  path.each_line.with_index(1).map do |line, index|
    abort "blank JSONL line #{index}" if line.strip.empty?
    JSON.parse(line)
  rescue JSON::ParserError => error
    abort "invalid JSONL line #{index}: #{error.message}"
  end
end

def validate_rows!(rows, expected: expected_rows, check_digest: true)
  abort "disposition row count mismatch" unless rows.length == INVENTORY_IDENTITY_COUNT
  keys = rows.map { |entry| entry["source_key"] }
  abort "disposition keys are not sorted" unless keys == keys.sort
  abort "duplicate disposition key" unless keys.uniq.length == keys.length

  rows.each_with_index do |entry, index|
    missing = REQUIRED_FIELDS - entry.keys
    extra = entry.keys - REQUIRED_FIELDS
    abort "row #{index + 1} missing fields: #{missing.join(', ')}" unless missing.empty?
    abort "row #{index + 1} has unknown fields: #{extra.join(', ')}" unless extra.empty?
    abort "row #{index + 1} bad schema" unless entry["schema_version"] == 1
    abort "row #{index + 1} bad revision" unless entry["upstream_revision"] == REVISION
    abort "row #{index + 1} bad inventory digest" unless entry["inventory_identity_set_sha256"] == INVENTORY_IDENTITY_SHA256
    abort "row #{index + 1} invalid disposition" unless DISPOSITIONS.include?(entry["disposition"])
    abort "row #{index + 1} invalid publicity" unless PUBLICITIES.include?(entry["rust_publicity"])
    abort "row #{index + 1} invalid implementation status" unless IMPLEMENTATION_STATUSES.include?(entry["implementation_status"])
    abort "row #{index + 1} invalid test status" unless TEST_STATUSES.include?(entry["test_status"])
    abort "row #{index + 1} invalid evidence status" unless EVIDENCE_STATUSES.include?(entry["evidence_status"])
    final_status = (entry["implementation_status"] == "implemented" && entry["test_status"] == "passing" && entry["evidence_status"] == "rust-tested") ||
                   (entry["implementation_status"] == "not-applicable" && entry["test_status"] == "not-applicable" && entry["evidence_status"] == "go-inventoried")
    abort "row #{index + 1} has inconsistent final status" unless final_status
    %w[source_key source_identity source_identity_sha256 source_package source_kind disposition_cluster rust_crate rust_module rust_path contract_justification implementation_evidence design_evidence].each do |field|
      abort "row #{index + 1} empty #{field}" unless entry[field].is_a?(String) && !entry[field].empty?
    end
    abort "row #{index + 1} short justification" unless entry["contract_justification"].length >= 40
    if entry["implementation_status"] == "not-applicable"
      abort "row #{index + 1} lacks a precise final release disposition" unless entry["implementation_evidence"].start_with?("Final release disposition:")
    end
    abort "row #{index + 1} bad design evidence" unless entry["design_evidence"].start_with?(DOC + "#")
    %w[behavior_links manifest_links].each do |field|
      values = entry[field]
      abort "row #{index + 1} empty #{field}" unless values.is_a?(Array) && !values.empty? && values.all? { |value| value.is_a?(String) && !value.empty? }
    end
  end

  expected_by_key = expected.to_h { |entry| [entry.fetch("source_key"), entry] }
  actual_by_key = rows.to_h { |entry| [entry.fetch("source_key"), entry] }
  missing = expected_by_key.keys - actual_by_key.keys
  unexpected = actual_by_key.keys - expected_by_key.keys
  abort "disposition key-set mismatch missing=#{missing.inspect} unexpected=#{unexpected.inspect}" unless missing.empty? && unexpected.empty?
  expected.each do |wanted|
    key = wanted.fetch("source_key")
    abort "disposition row differs for #{key}" unless actual_by_key.fetch(key) == wanted
  end

  stale_source_paths = rows.each_with_object([]) do |entry, paths|
    next unless entry["implementation_status"] == "implemented"
    next unless entry["rust_crate"] == "rustleaks-sources"
    paths << entry["rust_path"] if entry["rust_path"].include?("SourceOptions") || entry["rust_path"].end_with?("::run_source")
  end
  abort "implemented source dispositions reference stale Rust paths: #{stale_source_paths.inspect}" unless stale_source_paths.empty?

  source_root = ROOT.join("crates/rustleaks-sources/src")
  required_symbols = {
    "rustleaks_sources::FileSource" => ["file.rs", /pub struct FileSource/],
    "rustleaks_sources::DirectorySource" => ["directory.rs", /pub struct DirectorySource/],
    "rustleaks_sources::SourceRunner" => ["runner.rs", /pub struct SourceRunner/],
    "rustleaks_sources::ArchiveLimits::new" => ["archive.rs", /pub fn new\(/],
    "rustleaks_sources::DirectoryOptions::follow_symlinks" => ["directory.rs", /pub const fn follow_symlinks\(/]
  }
  implemented_paths = rows.select { |entry| entry["implementation_status"] == "implemented" }.map { |entry| entry["rust_path"] }
  required_symbols.each do |path, (file, pattern)|
    next unless implemented_paths.include?(path)
    abort "implemented source symbol disappeared: #{path}" unless source_root.join(file).read.match?(pattern)
  end

  return unless check_digest

  digest = Digest::SHA256.hexdigest(jsonl(rows))
  abort "disposition JSONL digest mismatch: got #{digest}, want #{EXPECTED_DISPOSITIONS_SHA256}" unless digest == EXPECTED_DISPOSITIONS_SHA256
end

def summary(rows)
  by_disposition = rows.group_by { |entry| entry.fetch("disposition") }.transform_values(&:length).sort.to_h
  by_cluster = rows.group_by { |entry| entry.fetch("disposition_cluster") }.transform_values(&:length).sort.to_h
  {
    "upstream_revision" => REVISION,
    "inventory_identity_set_sha256" => INVENTORY_IDENTITY_SHA256,
    "dispositions_sha256" => Digest::SHA256.hexdigest(jsonl(rows)),
    "rows" => rows.length,
    "by_disposition" => by_disposition,
    "by_cluster" => by_cluster
  }
end

def prove_same_count_substitutions!(rows)
  key_mutation = Marshal.load(Marshal.dump(rows))
  key_mutation[0]["source_key"] = key_mutation[0]["source_key"] + "#substituted"
  abort "key self-test changed count" unless key_mutation.length == rows.length
  abort "same-count key substitution was accepted" unless validation_rejected?(key_mutation)

  disposition_mutation = Marshal.load(Marshal.dump(rows))
  current = disposition_mutation[0].fetch("disposition")
  disposition_mutation[0]["disposition"] = (DISPOSITIONS - [current]).first
  abort "disposition self-test changed count" unless disposition_mutation.length == rows.length
  abort "same-count disposition substitution was accepted" unless validation_rejected?(disposition_mutation)

  status_mutation = Marshal.load(Marshal.dump(rows))
  status_mutation[0]["implementation_status"] = "partial"
  abort "status self-test changed count" unless status_mutation.length == rows.length
  abort "unfinished implementation status was accepted" unless validation_rejected?(status_mutation)
end

def validation_rejected?(rows)
  original_stderr = $stderr
  $stderr = StringIO.new
  begin
    validate_rows!(rows, check_digest: false)
    false
  rescue SystemExit
    true
  ensure
    $stderr = original_stderr
  end
end

validate_inventory!
command = ARGV.shift || "check"
abort "unexpected arguments: #{ARGV.inspect}" unless ARGV.empty?

case command
when "write"
  rows = expected_rows
  DISPOSITIONS_PATH.write(jsonl(rows))
  puts JSON.pretty_generate(summary(rows))
when "check"
  rows = load_rows
  validate_rows!(rows)
  puts JSON.pretty_generate(summary(rows).merge("status" => "ok"))
when "self-test"
  rows = load_rows
  validate_rows!(rows)
  prove_same_count_substitutions!(rows)
  puts JSON.pretty_generate(summary(rows).merge("status" => "ok", "same_count_key_substitution" => "rejected", "same_count_disposition_substitution" => "rejected", "unfinished_status_substitution" => "rejected"))
when "summary"
  rows = load_rows
  validate_rows!(rows)
  puts JSON.pretty_generate(summary(rows))
else
  abort "usage: ruby compat/annotate_api.rb [write|check|self-test|summary]"
end
