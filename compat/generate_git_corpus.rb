#!/usr/bin/env ruby
# frozen_string_literal: true

# Freeze pinned-Go Git-source behavior. Every request runs in a fresh process
# and every repository operation uses an isolated copy of a committed fixture.

require "base64"
require "digest"
require "fileutils"
require "find"
require "json"
require "open3"
require "pathname"
require "timeout"
require "tmpdir"

ROOT = Pathname(__dir__).parent
UPSTREAM = ROOT.parent.join("gitleaks")
ORACLE = ROOT.join("crates/rustleaks-compat/oracle")
OUTPUT_ROOT = Pathname(ENV.fetch("RUSTLEAKS_GIT_CORPUS_OUTPUT", ROOT.join("compat/git-corpus").to_s))
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
DEFAULT_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
PROTOCOL_VERSION = 1
INTENTIONS = (1..7).map { |number| format("GIT-INT-%03d", number) }.freeze
BEHAVIORS = {
  "GIT-001" => "Default history argv is exact and shell-free.",
  "GIT-002" => "Nonempty raw log options use literal ASCII-space splitting, including empty and quoted tokens.",
  "GIT-003" => "Working-tree/staged argv and final dot pathspec are exact; untracked files are absent.",
  "GIT-004" => "stdout is parsed as bytes into ordered files/hunks; asynchronous parse truncation needs a safe disposition.",
  "GIT-005" => "Raw contains only compacted added-line bytes and StartLine is hunk NewPosition.",
  "GIT-006" => "No-newline, hunk deletion, and whole-file deletion distinctions remain exact.",
  "GIT-007" => "Git logical paths remain byte preserving.",
  "GIT-008" => "Nonarchive binaries skip and filename-recognized binary archives scan the selected blob.",
  "GIT-009" => "History uses commit:path and empty-commit diff archives use index :path.",
  "GIT-010" => "History metadata and diff-only zero metadata are exact.",
  "GIT-011" => "The source-level commit allowlist attempt is a no-op.",
  "GIT-013" => "stderr whitelist and one-generic-issue behavior have an explicit safe overflow disposition.",
  "GIT-014" => "Rust must not silently lose child exit, parser, kill, wait, or reap outcomes.",
  "GIT-015" => "Cancellation stops process/blob/archive work and joins helpers before return.",
  "GIT-016" => "Remote discovery argv, directory, and no-platform behavior are exact.",
  "GIT-017" => "Remote normalization, userinfo removal, no-remote errors, and first-remote selection are exact.",
  "GIT-018" => "Platform parsing and host inference use the closed pinned mapping.",
  "GIT-019" => "SCM links preserve pinned template/path/anchor behavior.",
  "GIT-023" => "GIT-INT-001..007 use isolated complete copies and preserve shared fixture bytes."
}.freeze
SOURCE_HASHES = {
  "sources/git.go" => "1fb86062416b83f756be89165e4ef1244f038a6e59c6ab5c014d330909de8e8f",
  "sources/git_test.go" => "8f94704954737adb4be6225cc01a0d2c64ac322ae50a2f020d9fced9485faddb",
  "detect/git.go" => "1126fc5149daac5b06d0b61e1575796496c7102a41e990a42a60bc813a616266",
  "detect/detect_test.go" => "191e7178827d790ae7c72f7b17824e3d368fe66b263fb12a9b8f3ede225124d3",
  "cmd/scm/scm.go" => "9d3783fb042e2047b467a79138799f82b6256fc15bbae0f81a5ca8d51c23814e",
  "config/allowlist.go" => "5fac823414a97a873e25016e4bc76a0d1aa898c0a6f57b248bdc067d69fd6d7f"
}.freeze
FIXTURE_INDEX_HASHES = {
  "small" => "0225d0ccae1b6703377c9485a0a8f465188a35a1339a2bdb1d40742168f05ac2",
  "staged" => "c81406d3e48089b14a5efaaed17ebba84bd7ffadd5fbad6819194a6946fc3c36",
  "archives" => "ddc2d463377afd84c184a1ba581ddec81d6f89569fecff178718cd9e0fa3dc77"
}.freeze

CHECK = ARGV.delete("--check")
abort "usage: #{$PROGRAM_NAME} [--check]" unless ARGV.empty?

GO_ENV = {
  "GOCACHE" => ENV.fetch("GOCACHE", File.join(Dir.tmpdir, "rustleaks-m10-oracle-gocache")),
  "GOMODCACHE" => ENV.fetch("GOMODCACHE", File.join(Dir.tmpdir, "rustleaks-go-mod-cache")),
  "GOMEMLIMIT" => ENV.fetch("GOMEMLIMIT", "768MiB"),
  "GOMAXPROCS" => ENV.fetch("GOMAXPROCS", "2"),
  "GIT_CONFIG_GLOBAL" => File::NULL, "GIT_CONFIG_SYSTEM" => File::NULL,
  "LC_ALL" => "C", "TZ" => "UTC"
}.freeze

def sha(bytes)
  Digest::SHA256.hexdigest(bytes)
end

def b64decode(value)
  Base64.strict_decode64(value)
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
  output = +"".b
  error = +"".b
  status = nil
  Open3.popen3(GO_ENV, binary, "--git", chdir: ORACLE.to_s, pgroup: true) do |stdin, stdout, stderr, wait|
    stdin.write(JSON.generate(request) + "\n")
    stdin.close
    begin
      Timeout.timeout(45) do
        readers = [stdout, stderr]
        until readers.empty?
          ready = IO.select(readers, nil, nil, 0.25)
          next if ready.nil?
          ready.first.each do |stream|
            begin
              chunk = stream.read_nonblock(64 * 1024)
              target = stream.equal?(stdout) ? output : error
              target << chunk
              raise "oracle output exceeded 64 MiB" if target.bytesize > 64 * 1024 * 1024
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
  abort "#{request.fetch('id')}: oracle emitted #{lines.length} lines" unless lines.length == 1
  JSON.parse(lines.first)
end

def request(id, operation:, repository:, behaviors:, intentions: [], tests: [], **fields)
  {
    "protocol_version" => PROTOCOL_VERSION, "id" => id,
    "behavior_ids" => behaviors, "test_case_ids" => tests,
    "git_intention_ids" => intentions, "operation" => operation,
    "repository" => repository
  }.merge(fields.transform_keys(&:to_s))
end

def fragment_bytes(outcome)
  outcome.fetch("fragments").map { |fragment| b64decode(fragment.fetch("raw_base64")) }.join
end

def assert_outcome!(request, outcome)
  abort "#{request['id']}: response id changed" unless outcome["id"] == request["id"]
  abort "#{request['id']}: protocol changed" unless outcome["protocol_version"] == PROTOCOL_VERSION
  abort "#{request['id']}: revision changed" unless outcome["upstream_revision"] == REVISION
  abort "#{request['id']}: default config changed" unless outcome["default_config_sha256"] == DEFAULT_SHA256
  %w[arguments_base64 fragments canonical_fragments findings issues].each do |field|
    abort "#{request['id']}: missing #{field}" unless outcome[field].is_a?(Array)
  end
  serialized = JSON.generate(outcome)
  abort "#{request['id']}: temporary path leaked" if serialized.include?("gitleaks git Ω oracle-")
end

def tree_fingerprint(root)
  records = root.find.map do |path|
    next if path == root
    relative = path.relative_path_from(root).to_s
    stat = path.lstat
    payload = if stat.symlink?
                "link:#{path.readlink}"
              elsif stat.file?
                "file:#{sha(path.binread)}"
              else
                "dir"
              end
    [relative, stat.mode & 0o7777, payload]
  end.compact.sort
  sha(JSON.generate(records))
end

abort "upstream revision changed" unless capture("git", "rev-parse", "HEAD", chdir: UPSTREAM).strip == REVISION
abort "default config changed" unless sha(UPSTREAM.join("config/gitleaks.toml").binread) == DEFAULT_SHA256
SOURCE_HASHES.each { |path, expected| abort "#{path} changed" unless sha(UPSTREAM.join(path).binread) == expected }
FIXTURE_INDEX_HASHES.each do |repository, expected|
  compat = ROOT.join("compat/fixtures/upstream/testdata/repos", repository, "dotGit/index")
  sibling = UPSTREAM.join("testdata/repos", repository, "dotGit/index")
  abort "#{repository} compat index changed" unless sha(compat.binread) == expected
  abort "#{repository} sibling index changed" unless sha(sibling.binread) == expected
end
fixture_root = ROOT.join("compat/fixtures/upstream/testdata/repos")
fixture_before = tree_fingerprint(fixture_root)
upstream_before = capture("git", "status", "--short", chdir: UPSTREAM)
repo_before = capture("git", "status", "--short", "--", "compat/fixtures/upstream/testdata/repos", chdir: ROOT)

requests = []
requests << request("int-default-log", operation: "log", repository: "small",
                    behaviors: %w[GIT-001 GIT-004 GIT-005 GIT-006 GIT-007 GIT-010 GIT-023], intentions: ["GIT-INT-001"])
requests << request("int-all-foo-log", operation: "log", repository: "small",
                    behaviors: %w[GIT-002 GIT-004 GIT-005 GIT-006 GIT-007 GIT-010 GIT-023], intentions: ["GIT-INT-002"], log_options: "--all foo...")
requests << request("int-working-tree-diff", operation: "diff", repository: "small",
                    behaviors: %w[GIT-003 GIT-005 GIT-006 GIT-010 GIT-023], intentions: ["GIT-INT-003"], mutation: "working-additions")
requests << request("int-default-findings", operation: "log", repository: "small",
                    behaviors: %w[GIT-001 GIT-004 GIT-005 GIT-006 GIT-007 GIT-010 GIT-016 GIT-017 GIT-018 GIT-019 GIT-023], intentions: ["GIT-INT-004"], tests: ["TM-0135"],
                    detect: true, config_fixture: "simple.toml", load_ignore: true)
requests << request("int-all-foo-findings", operation: "log", repository: "small",
                    behaviors: %w[GIT-002 GIT-004 GIT-005 GIT-006 GIT-007 GIT-010 GIT-016 GIT-017 GIT-018 GIT-019 GIT-023], intentions: ["GIT-INT-005"], tests: ["TM-0136"],
                    log_options: "--all foo...", detect: true, config_fixture: "simple.toml", load_ignore: true)
requests << request("int-archive-findings", operation: "log", repository: "archives",
                    behaviors: %w[GIT-001 GIT-004 GIT-008 GIT-009 GIT-010 GIT-015 GIT-016 GIT-017 GIT-018 GIT-019 GIT-023], intentions: ["GIT-INT-006"], tests: ["TM-0134"],
                    detect: true, config_fixture: "archives.toml", load_ignore: true, max_archive_depth: 8)
requests << request("int-staged-findings", operation: "diff", repository: "staged",
                    behaviors: %w[GIT-003 GIT-004 GIT-005 GIT-006 GIT-010 GIT-023], intentions: ["GIT-INT-007"], tests: ["TM-0137"],
                    staged: true, detect: true, config_fixture: "simple.toml", load_ignore: true)

requests << request("log-options-double-space", operation: "log", repository: "small", behaviors: %w[GIT-002 GIT-013], log_options: "--all  foo...")
requests << request("log-options-leading-trailing-space", operation: "log", repository: "small", behaviors: %w[GIT-002 GIT-013], log_options: " --all ")
requests << request("log-options-literal-quotes", operation: "log", repository: "small", behaviors: %w[GIT-002 GIT-013], log_options: "'--all' foo...")
requests << request("log-options-literal-double-quotes", operation: "log", repository: "small", behaviors: %w[GIT-002 GIT-013], log_options: '"--all" foo...')
requests << request("log-options-tab-not-split", operation: "log", repository: "small", behaviors: %w[GIT-002 GIT-013], log_options: "--all\tfoo...")
requests << request("log-options-shell-metacharacters-literal", operation: "log", repository: "small", behaviors: %w[GIT-002 GIT-013], log_options: '--all $(touch proof)')
requests << request("delete-skip", operation: "diff", repository: "small", behaviors: %w[GIT-006 GIT-008], mutation: "delete-main")
requests << request("binary-skip", operation: "diff", repository: "small", behaviors: ["GIT-008"], mutation: "binary-main")
requests << request("pure-rename-skip", operation: "diff", repository: "small", behaviors: %w[GIT-003 GIT-007], mutation: "staged-rename", staged: true)
requests << request("ineffective-commit-allowlist", operation: "log", repository: "small", behaviors: ["GIT-011"],
                    log_options: "-1 1b6da43b82b22e4eaa10bcf8ee591e91abbfc587",
                    allow_commits: ["1B6DA43B82B22E4EAA10BCF8EE591E91ABBFC587"])
requests << request("unstaged-archive-reads-index", operation: "diff", repository: "archives", behaviors: %w[GIT-008 GIT-009 GIT-014],
                    mutation: "binary-archive-worktree", detect: true, config_fixture: "archives.toml", max_archive_depth: 8)
requests << request("staged-malformed-archive-worker-error", operation: "diff", repository: "small", behaviors: %w[GIT-008 GIT-009 GIT-014],
                    mutation: "staged-bad-archive", staged: true, max_archive_depth: 8)
requests << request("malformed-not-a-repository", operation: "log", repository: "empty", behaviors: %w[GIT-013 GIT-014])
requests << request("cancel-after-start", operation: "log", repository: "small", behaviors: %w[GIT-014 GIT-015 GIT-023], cancel_after_start: true)
requests << request("remote-explicit-none", operation: "remote", repository: "small", behaviors: ["GIT-016"], platform: "none")
requests << request("remote-ssh-port-github", operation: "remote", repository: "small", behaviors: %w[GIT-017 GIT-018], remote_url: "git@github.com:2222/org/repo.git")
requests << request("remote-userinfo-gitlab", operation: "remote", repository: "small", behaviors: %w[GIT-017 GIT-018], remote_url: "https://user:pass@gitlab.com/org/repo.git")
requests << request("remote-unknown-host", operation: "remote", repository: "small", behaviors: %w[GIT-017 GIT-018], remote_url: "https://example.invalid/org/repo.git")
requests << request("remote-malformed-url", operation: "remote", repository: "small", behaviors: %w[GIT-013 GIT-017 GIT-018], remote_url: "%")
{
  "remote-azure" => ["https://dev.azure.com/org/repo.git", "azuredevops"],
  "remote-visualstudio" => ["https://visualstudio.com/org/repo.git", "azuredevops"],
  "remote-gitea" => ["https://gitea.com/org/repo.git", "gitea"],
  "remote-forgejo" => ["https://code.forgejo.org/org/repo.git", "gitea"],
  "remote-codeberg" => ["https://codeberg.org/org/repo.git", "gitea"],
  "remote-bitbucket" => ["https://bitbucket.org/org/repo.git", "bitbucket"],
  "remote-uppercase-host-suffix" => ["https://GITHUB.COM/org/repo.GIT", "github"],
  "remote-ssh-url" => ["ssh://git@github.com/org/repo.git", "github"]
}.each do |id, (remote_url, expected_platform)|
  requests << request(id, operation: "remote", repository: "small", behaviors: %w[GIT-017 GIT-018],
                      remote_url: remote_url, expected_platform: expected_platform)
end

Dir.mktmpdir("rustleaks-git-corpus-") do |temporary|
  binary = File.join(temporary, "oracle")
  capture("go", "build", "-trimpath", "-o", binary, ".", chdir: ORACLE)
  outcomes = requests.map do |entry|
    outcome = bounded_oracle(binary, entry)
    assert_outcome!(entry, outcome)
    outcome
  end

  by_id = outcomes.to_h { |outcome| [outcome.fetch("id"), outcome] }
  expected_default = ROOT.join("compat/fixtures/upstream/testdata/expected/git/small.txt").binread
  expected_foo = ROOT.join("compat/fixtures/upstream/testdata/expected/git/small-branch-foo.txt").binread
  default_outcome = by_id.fetch("int-default-log")
  observed_default = fragment_bytes(default_outcome)
  legacy_default = default_outcome.fetch("fragments").reject do |fragment|
    b64decode(fragment.fetch("commit_base64")) == "53cd7a3c6eb4937f413e3c25e4a9f39289afa69e"
  end.map { |fragment| b64decode(fragment.fetch("raw_base64")) }.join
  abort "pinned default Git additions changed" unless observed_default.bytesize == 1477
  abort "legacy default Git golden relation changed" unless legacy_default == expected_default
  foo_outcome = by_id.fetch("int-all-foo-log")
  observed_foo = fragment_bytes(foo_outcome)
  legacy_foo = foo_outcome.fetch("fragments").reject do |fragment|
    b64decode(fragment.fetch("commit_base64")) == "53cd7a3c6eb4937f413e3c25e4a9f39289afa69e"
  end.map { |fragment| b64decode(fragment.fetch("raw_base64")) }.join
  abort "pinned foo Git additions changed" unless observed_foo.bytesize == 786
  abort "legacy foo Git golden relation changed" unless legacy_foo == expected_foo
  abort "working diff additions changed" unless fragment_bytes(by_id.fetch("int-working-tree-diff")) == "this line is added\nand another one"
  abort "small finding multiset changed" unless by_id.fetch("int-default-findings").fetch("findings").length == 2
  abort "foo finding multiset changed" unless by_id.fetch("int-all-foo-findings").fetch("findings").length == 1
  abort "archive finding multiset changed" unless by_id.fetch("int-archive-findings").fetch("findings").length == 16
  abort "staged finding multiset changed" unless by_id.fetch("int-staged-findings").fetch("findings").length == 1
  %w[delete-skip binary-skip pure-rename-skip].each do |id|
    abort "#{id} emitted fragments" unless by_id.fetch(id).fetch("fragments").empty?
  end
  abort "commit allowlist unexpectedly pruned" unless by_id.fetch("ineffective-commit-allowlist").fetch("fragments").length == 1
  bad_archive = by_id.fetch("staged-malformed-archive-worker-error")
  abort "worker error became observable" unless bad_archive.fetch("fragments").empty? && bad_archive.fetch("issues").empty? && bad_archive["error"].nil?
  unstaged_archive = by_id.fetch("unstaged-archive-reads-index")
  abort "unstaged archive did not read index blob" unless unstaged_archive.fetch("findings").length == 1
  malformed = by_id.fetch("malformed-not-a-repository")
  abort "stderr classification changed" unless malformed.fetch("issues").map { |issue| issue.fetch("class") } == ["stderr"]
  canceled = by_id.fetch("cancel-after-start")
  abort "cancellation classification changed" unless canceled.dig("error", "class") == "canceled"
  double_space_args = by_id.fetch("log-options-double-space").fetch("arguments_base64").map { |value| b64decode(value) }
  abort "empty log option token lost" unless double_space_args[-3, 3] == ["--all", "", "foo..."]
  tab_args = by_id.fetch("log-options-tab-not-split").fetch("arguments_base64").map { |value| b64decode(value) }
  abort "tab log option unexpectedly split" unless tab_args.last == "--all\tfoo..."
  boundary_args = by_id.fetch("log-options-leading-trailing-space").fetch("arguments_base64").map { |value| b64decode(value) }
  abort "leading/trailing empty log tokens lost" unless boundary_args[-3, 3] == ["", "--all", ""]
  shell_args = by_id.fetch("log-options-shell-metacharacters-literal").fetch("arguments_base64").map { |value| b64decode(value) }
  abort "shell metacharacters were transformed" unless shell_args[-3, 3] == ["$(touch", "proof)"] || shell_args[-3, 3] == ["--all", "$(touch", "proof)"]
  abort "explicit no-platform changed" unless by_id.fetch("remote-explicit-none").fetch("remote") == {"platform" => "none", "url_base64" => ""}
  abort "SSH remote normalization changed" unless b64decode(by_id.fetch("remote-ssh-port-github").dig("remote", "url_base64")) == "https://github.com/org/repo"
  abort "userinfo remote normalization changed" unless b64decode(by_id.fetch("remote-userinfo-gitlab").dig("remote", "url_base64")) == "https://gitlab.com/org/repo"
  abort "unknown remote mapping changed" unless by_id.fetch("remote-unknown-host").dig("remote", "platform") == "unknown"
  abort "malformed remote handling changed" unless by_id.fetch("remote-malformed-url").fetch("remote") == {"platform" => "unknown", "url_base64" => ""}
  requests.select { |entry| entry.key?("expected_platform") }.each do |entry|
    actual = by_id.fetch(entry.fetch("id")).dig("remote", "platform")
    abort "#{entry.fetch('id')} platform changed: #{actual}" unless actual == entry.fetch("expected_platform")
  end

  covered_intentions = requests.flat_map { |entry| entry.fetch("git_intention_ids") }.uniq.sort
  covered_behaviors = requests.flat_map { |entry| entry.fetch("behavior_ids") }.uniq.sort
  coverage = {
    "protocol_version" => PROTOCOL_VERSION, "upstream_revision" => REVISION,
    "fixture_tree_sha256" => fixture_before,
    "git_intention_ids" => covered_intentions, "behavior_ids" => covered_behaviors,
    "behavior_definitions" => BEHAVIORS,
    "cases" => requests.map { |entry| {"id" => entry.fetch("id"), "git_intention_ids" => entry.fetch("git_intention_ids"), "behavior_ids" => entry.fetch("behavior_ids")} },
    "gaps" => [
      "The disabled low-level default-log golden is stale: pinned behavior emits 1,477 bytes; removing commit 53cd7a3c... yields its 907 bytes exactly.",
      "The disabled --all foo... golden is likewise stale: pinned behavior emits 786 bytes; removing commit 53cd7a3c... yields its 216 bytes exactly.",
      "The earlier archive estimate counted 15 findings; the pinned source, configuration, and fixture produce 16, which this corpus freezes.",
      "go-gitdiff asynchronous parse-error truncation has no deterministic real-Git fixture; source hash and semantics audit pin it until a safe byte-stream seam exists.",
      "Allowed rename/gc stderr warnings require large or timing-sensitive repositories and remain source-hash evidence rather than corpus cases.",
      "Native Linux and Windows runtime evidence is not available locally; the corpus records local GOOS/GOARCH.",
      "GIT-012 and GIT-020..022 are implementation, scheduler, limit, and platform contracts not fully certifiable by this real-Git oracle corpus."
    ]
  }
  abort "Git intentions incomplete" unless covered_intentions == INTENTIONS
  abort "Git behaviors incomplete" unless covered_behaviors == BEHAVIORS.keys.sort

  negative_controls = {
    "protocol_version" => PROTOCOL_VERSION,
    "controls" => [
      {"id" => "shared-fixture-mutation", "rejected" => true, "reason" => "all repository operations occur only after a recursive temporary copy"},
      {"id" => "shell-log-options", "rejected" => true, "reason" => "custom options are literal space-split argv, never shell parsed"},
      {"id" => "native-git-reimplementation", "rejected" => true, "reason" => "the corpus first freezes exact external Git behavior"},
      {"id" => "silent-stderr-normalization", "rejected" => true, "reason" => "unexpected stderr remains one generic structured issue"},
      {"id" => "force-stale-default-golden", "rejected" => true, "reason" => "live pinned output is 1,477 bytes; the 907-byte file predates commit 53cd7a3c"},
      {"id" => "force-stale-foo-golden", "rejected" => true, "reason" => "live pinned output is 786 bytes; the 216-byte file predates commit 53cd7a3c"},
      {"id" => "force-stale-archive-count", "rejected" => true, "reason" => "live pinned archive detection returns 16 findings, not the earlier estimate of 15"}
    ]
  }
  readme = <<~README
    # Git compatibility corpus v1

    Generated by `ruby compat/generate_git_corpus.rb` from pinned Go revision
    `#{REVISION}`. Each JSONL request is executed in a fresh bounded oracle
    process. The oracle recursively copies only the committed `small`, `staged`,
    or `archives` fixture into a private temporary directory and renames only
    that copy's `dotGit`; committed fixtures and `../gitleaks` stay read-only.

    `requests-v1.jsonl` is declarative input. `outcomes-v1.jsonl` records exact
    argv tokens, normalized command text, ordered fragments, canonical fragment
    and finding multisets, commit metadata, remotes, and structured issues.
    Byte-bearing fields are base64. Behavior IDs use the stable `GIT-001..023`
    mapping recorded in `coverage-v1.json`.

    Regenerate with `ruby compat/generate_git_corpus.rb`; verify with
    `ruby compat/generate_git_corpus.rb --check`.
  README
  files = {
    "README.md" => readme,
    "requests-v1.jsonl" => jsonl(requests),
    "outcomes-v1.jsonl" => jsonl(outcomes),
    "coverage-v1.json" => JSON.pretty_generate(coverage) + "\n",
    "negative-controls-v1.json" => JSON.pretty_generate(negative_controls) + "\n"
  }
  manifest = {
    "protocol_version" => PROTOCOL_VERSION, "upstream_revision" => REVISION,
    "default_config_sha256" => DEFAULT_SHA256, "request_count" => requests.length,
    "outcome_count" => outcomes.length,
    "files" => files.transform_values { |content| {"sha256" => sha(content.b), "bytes" => content.bytesize} }
  }
  files["manifest-v1.json"] = JSON.pretty_generate(manifest) + "\n"

  if CHECK
    files.each do |name, content|
      path = OUTPUT_ROOT.join(name)
      abort "missing #{path}" unless path.file?
      abort "#{path} differs" unless path.binread == content.b
    end
    extras = OUTPUT_ROOT.children.map(&:basename).map(&:to_s).sort - files.keys.sort
    abort "unexpected Git corpus files: #{extras.join(', ')}" unless extras.empty?
  else
    FileUtils.mkdir_p(OUTPUT_ROOT)
    files.each { |name, content| OUTPUT_ROOT.join(name).binwrite(content.b) }
  end
end

abort "compat Git fixtures changed during generation" unless tree_fingerprint(fixture_root) == fixture_before
abort "compat Git fixture status changed" unless capture("git", "status", "--short", "--", "compat/fixtures/upstream/testdata/repos", chdir: ROOT) == repo_before
abort "upstream worktree changed" unless capture("git", "status", "--short", chdir: UPSTREAM) == upstream_before

puts "Git corpus #{CHECK ? 'verified' : 'generated'}: #{requests.length} fresh-process cases, #{INTENTIONS.length} intentions, #{BEHAVIORS.length} stable behaviors"
