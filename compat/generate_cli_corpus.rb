#!/usr/bin/env ruby
# frozen_string_literal: true

# Generate the CLI black-box corpus. The pinned Go command and
# the current Rust command are built once, then every observation is made by a
# new, bounded process in a new fixture directory.  The sibling checkout is
# read-only and its complete status is checked before and after generation.

require "base64"
require "digest"
require "fileutils"
require "json"
require "open3"
require "pathname"
require "rubygems/package"
require "stringio"
require "tempfile"
require "tmpdir"
require "zlib"

ROOT = Pathname(__dir__).parent
UPSTREAM = ROOT.parent.join("gitleaks")
OUTPUT_ROOT = Pathname(ENV.fetch("RUSTLEAKS_CLI_CORPUS_OUTPUT", ROOT.join("compat/cli-corpus").to_s))
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
DEFAULT_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
PROTOCOL_VERSION = 1
CORPUS_VERSION = "rustleaks-cli-corpus-v1"
BUILD_VERSION = "0.1.0-alpha.1"
PROCESS_TIMEOUT = Integer(ENV.fetch("RUSTLEAKS_CLI_CASE_TIMEOUT", "15"), 10)
MAX_OUTPUT_BYTES = 8 * 1024 * 1024

GO_SOURCE_HASHES = {
  "cmd/root.go" => "275516f78724a075530898e6354e096f2b33ef78de8856f9a5f1b68b9552d994",
  "cmd/git.go" => "8df69d800458de6b3140d2c6742e03aa9cb4aea0ac3c4cbfab2bb601222e93bc",
  "cmd/directory.go" => "dfc5947ac5237ea67886515fcf1199b4b89a2ecf6f622a51e323b4d75b0db988",
  "cmd/stdin.go" => "cfab0777788db0ae1cd8d9c1d614bf05992fc1c6ac2f25cc1e423b2f0677d267",
  "cmd/detect.go" => "1da20509fc6f172dca5ade289f394e053ab771f202a4edd46aa05a573d11237c",
  "cmd/protect.go" => "f694cd5f7d4b27c1ffc1f9b9a86a7bed302479763eb94d3a652f8eccf31cded9",
  "main.go" => "09053475a95ad638804d38161dd470c7baadee958a50a50b2a038f6ec3474223",
  "logging/log.go" => "1b7a94f24c71fdc8600066c4ea619adc8f62e8e6d730867f12ed238ffdfd2282",
  "sources/git.go" => "1fb86062416b83f756be89165e4ef1244f038a6e59c6ab5c014d330909de8e8f",
  "detect/detect.go" => "2bac563a09f22ff76c56b200c3b9b5dc865c1de699eb0ba2a27cca741fa9bd13",
  "detect/baseline.go" => "23d043ab3bf70d0a4ff560598a22b8507f38054b038acd3e6e684abf5c663e93",
  "detect/files.go" => "dbf6443db44cb962e0193698f1f2f11206e7e9c8621bad9873aacc0cb421b0af",
  "detect/utils.go" => "9bc4ef65bee3afdf0c4b51cd7e9f3d7ec8c4acf72a04905d1bb1e9ce0a6c55db",
  "sources/file.go" => "c9d1d8be4e5bbac08c0df774882f33060572ed8d720e7f34360f0a5164c822fa",
  "cmd/scm/scm.go" => "9d3783fb042e2047b467a79138799f82b6256fc15bbae0f81a5ca8d51c23814e",
  "report/constants.go" => "7b340a90e47a2bdb55fed6a80644b7e8682f12d4706d20efdabccd43043e4ba4",
  "report/csv.go" => "c51f7575fcf542de8b3a897fa98093aaed697b28e0af44f4bec19a66ef9d4b91",
  "report/finding.go" => "a1ecd3837f6d89b8ddf95f2b0a6c301103b8d3e67f84e1b3520ffc6f7d7751a6",
  "report/json.go" => "7cce5d031a4b6fde50e52bd9cd551781a0f00f9a0de79852cfa10ac3385ff733",
  "report/junit.go" => "de628ab9afb6ab5aee6a36e172485ca84f9f9625eeedaa7fa39c62a9754ab4b1",
  "report/report.go" => "109c5fc946faa5af35ac784815644b4fe5b1ec7b27e3f1f2540c6306a2876f30",
  "report/sarif.go" => "703eff736c567fb14133dd24cb814bca8f2626fb63d6b969c1fd967ff58e01ed",
  "report/template.go" => "0e324cc75ffeff1ccd3210dc4df88daa72bc5458c49a945db68ade53b80a0a13",
  "go.mod" => "4a13d81b74eb0092dd5fc0fdad5cae91450b3843b2ac6b576e329daf9d4526af",
  "go.sum" => "4bab2153d86f2a4f6b7a1146720f82e374fbd84931fe95798009be31c90d4162"
}.freeze

GO_TREE_HASHES = {
  "cmd" => "f41361d996a5fad3f001c21832d1ac33d1e709102dda3aab78963c2029410a51",
  "logging" => "fe61734f8a76de8a3115749396c7fd6ca51d7563f00b77454cdeddc89a8c912b",
  "sources" => "c94801ce1b7807a06b423d5b808e088572094201efeb04d4ff360e5d9bd63ee9",
  "detect" => "21eb15368a2daa8b9dcee0ddc658c28de072bc69bf6b082779138c19d1a55402",
  "report" => "0081532e37aaebe6fcd550b1076f496425908fdcf7355878e0ecb1dc2bb660a7",
  "config" => "2eb01c48aad5adc5ff5c1be2139e2673ef36e1102ae2be63af5b04abbaf48344"
}.freeze

# Updated only after the concurrent CLI repair is integrated.  --check and
# ordinary generation both reject a changed Rust implementation before a
# corpus can be accepted.
RUST_SOURCE_HASHES = {
  "Cargo.toml" => "28dfef5b687b972d90a205f4c36435cbc3a3bb0ae28374445b2e44c2f3edc07c",
  "Cargo.lock" => "c27f70ea157cdacf5f493de0a68a30e737f44b1d7051bdf53a07a4ea440ad008",
  "crates/rustleaks-cli/Cargo.toml" => "234894cd76d39c099b3894a8a056d1c59e977615eddab9473616a4bc9e57eb95",
  "crates/rustleaks-cli/src/args.rs" => "efc406db5eb453e2e0fb16ea90e7f90f3ddb94f880e51fa03bdb6a73488fdbe2",
  "crates/rustleaks-cli/src/config.rs" => "adfc1656cb7b1b625c8e9de92424b3a71100338c4db83351089e9441700ed984",
  "crates/rustleaks-cli/src/lib.rs" => "0c0a81f49066b19343765d6076593384b50a5c97e04315115f398daf64a651f2",
  "crates/rustleaks-cli/src/main.rs" => "459bd190f5258177fa7099afbd2238e3b082f11b0e0c7b15d55bad4c87af415d",
  "crates/rustleaks-cli/src/output.rs" => "800a1c3350f56b4f7af25193e6c5d1a54e3cb44d8273ecdebd5f4bbb45b000ba",
  "crates/rustleaks-cli/src/run.rs" => "ab7393a1020f67cc6c1790912126b429994cbce1b9c84acd1177b646c4943971",
  "crates/rustleaks-cli/src/source.rs" => "2803d6bde7c68504ac7f3f04ec7bbca5c70f7a95da27bed12b61e91c3351625e"
}.freeze

# Aggregate every regular file in each transitive local runtime crate.  The
# per-file CLI hashes above make implementation changes easy to review; these
# tree pins also fail closed if a core, source, report, or archive dependency
# changes without touching the CLI facade or Cargo.lock.
RUST_TREE_HASHES = {
  "crates/rustleaks-cli" => "c175d8ecdafddb9676df724db36a61ecde033bca37b37497ea7ece18a9c306ae",
  "crates/rustleaks-core" => "f35c35413025ee78af5ca9a0a8227e723f3572a1a7092f80989153f49b7d0891",
  "crates/rustleaks-report" => "6a4ebf0277309b3e8bbf6e52b3d04be8fee323014ab7a341e816532d12da0d8c",
  "crates/rustleaks-sources" => "1ee2c977617b6a3adb02f7989b32646189f33ca0c3cfd3b4028645268ca2ef57",
  "crates/rustleaks-bzip2" => "eff6fa1410ebf53eebe2052cb48ca1f42e72e16230407490b86f171fac9e6d32",
  "crates/rustleaks-compcol" => "244e1c88bc0eaa9866f92f5c851781d5273cd911d7fd6218a7d6f79a03fcdaf6",
  "crates/rustleaks-rar-codec" => "188596cdee2d5b251ac88c6a7d55d3f9ebb6c95d21c5f99abecbf8e50d7e9586",
  "crates/rustleaks-sevenz" => "4fde1e7cc679c93d6cad1714da6961b4d20e0215854b0b1016a9fea721ba33ce"
}.freeze

SAFE_DISPOSITIONS = {
  "CLI-SAFE-001" => "Rust rejects surplus dir/stdin positionals before setup; Go scans or ignores them.",
  "CLI-SAFE-002" => "Rust never discloses inline configuration contents in diagnostics.",
  "CLI-SAFE-003" => "Rust makes terminal Git/source failure partial and exit 1 after writing the report.",
  "CLI-SAFE-004" => "Rust does not create, remove, or truncate a report target before final report writing.",
  "CLI-SAFE-005" => "Rust rejects arithmetic and process-exit values outside its checked portable domain before side effects."
}.freeze

OTHER_DISPOSITIONS = {
  "CLI-DEFER-001" => "Cobra-only commands and diagnostics stay omitted; Rustleaks-native names are added while legacy spellings remain backward-compatible aliases.",
  "REPORT-SAFE-001" => "Rust uses the reviewed deterministic capability-free safe-template profile; Go helpers outside that profile are not reproduced.",
  "FOLLOWUP-NATIVE-M11-001" => "Native Linux and Windows runtime replay is unavailable and nonblocking; cross-compilation is not runtime evidence."
}.freeze

CHECK = ARGV.delete("--check")
abort "usage: #{$PROGRAM_NAME} [--check]" unless ARGV.empty?

MATCHING_CONFIG = <<~TOML.freeze
  title='fixture'
  [[rules]]
  id='fixture-token'
  description='fixture token'
  regex='''token=([A-Z0-9]{4})'''
  secretGroup=1
  keywords=['token']
TOML
NO_MATCH_CONFIG = <<~TOML.freeze
  title='fixture'
  [[rules]]
  id='never'
  description='never'
  regex='''NEVER_MATCH_THIS_VALUE'''
TOML
TWO_RULE_CONFIG = <<~TOML.freeze
  title='fixture'
  [[rules]]
  id='alpha'
  description='alpha'
  regex='''alpha=([A-Z0-9]{4})'''
  secretGroup=1
  [[rules]]
  id='beta'
  description='beta'
  regex='''beta=([A-Z0-9]{4})'''
  secretGroup=1
TOML
COMPOSITE_CONFIG = <<~TOML.freeze
  title='fixture'
  [[rules]]
  id='primary-rule'
  description='primary'
  regex='''password\\s*=\\s*"([^"]+)"'''
  [[rules.required]]
  id='username-rule'
  [[rules]]
  id='username-rule'
  description='username'
  regex='''username\\s*=\\s*"([^"]+)"'''
  skipReport=true
TOML
TEMPLATE = "{{ range . }}{{ .RuleID }}:{{ .Secret }}\\n{{ end }}".freeze
MARKER = "CLI_CORPUS_DISCLOSURE_MARKER_8F20C3".freeze

def sha(bytes)
  Digest::SHA256.hexdigest(bytes.b)
end

def b64(bytes)
  Base64.strict_encode64(bytes.b)
end

def tree_sha256_at(root, relative)
  digest = Digest::SHA256.new
  files = root.join(relative).glob("**/*", File::FNM_DOTMATCH).select(&:file?).reject do |path|
    name = path.relative_path_from(root).to_s
    name.match?(%r{/fuzz(?:/|\z)})
  end
  files.sort_by do |path|
    path.relative_path_from(root).to_s.b
  end.each do |path|
    name = path.relative_path_from(root).to_s.b
    bytes = path.binread
    digest.update([name.bytesize].pack("Q>"))
    digest.update(name)
    digest.update([bytes.bytesize].pack("Q>"))
    digest.update(bytes)
  end
  digest.hexdigest
end


def tree_sha256(relative)
  tree_sha256_at(ROOT, relative)
end

def deep_copy(value)
  Marshal.load(Marshal.dump(value))
end

def command_capture(*command, chdir:, env: {}, timeout: 120, max_bytes: MAX_OUTPUT_BYTES)
  result = bounded_process(command, chdir: chdir, env: env, stdin_bytes: "", timeout: timeout, max_bytes: max_bytes)
  abort "#{command.join(' ')} failed in #{chdir}: exit=#{result.fetch('exit')} stderr=#{result.fetch('stderr').inspect}" unless result.fetch("exit") == 0
  result.fetch("stdout")
end

def bounded_process(command, chdir:, env:, stdin_bytes:, timeout: PROCESS_TIMEOUT, max_bytes: MAX_OUTPUT_BYTES)
  input = Tempfile.new("rustleaks-cli-input")
  stdout = Tempfile.new("rustleaks-cli-stdout")
  stderr = Tempfile.new("rustleaks-cli-stderr")
  input.binmode
  stdout.binmode
  stderr.binmode
  input.write(stdin_bytes.b)
  input.rewind
  process_env = {
    "GITLEAKS_CONFIG" => nil,
    "GITLEAKS_CONFIG_TOML" => nil,
    "LC_ALL" => "C",
    "TZ" => "UTC",
    "NO_COLOR" => "1",
    "GIT_CONFIG_NOSYSTEM" => "1"
  }.merge(env)
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  spawn_options = { chdir: chdir.to_s, in: input, out: stdout, err: stderr, close_others: true }
  spawn_options[:pgroup] = true unless Gem.win_platform?
  pid = Process.spawn(process_env, *command, **spawn_options)
  status = nil
  failure = nil
  loop do
    waited = Process.waitpid2(pid, Process::WNOHANG)
    if waited
      status = waited.last
      break
    end
    if stdout.size > max_bytes || stderr.size > max_bytes
      failure = "output exceeded #{max_bytes} bytes"
      break
    end
    if Process.clock_gettime(Process::CLOCK_MONOTONIC) - started > timeout
      failure = "exceeded #{timeout}s"
      break
    end
    sleep 0.02
  end
  if failure
    kill_process_tree(pid)
    bounded_reap(pid)
    raise "#{command.first}: bounded process #{failure}"
  end
  stdout.rewind
  stderr.rewind
  out = (stdout.read(max_bytes + 1) || "").b
  err = (stderr.read(max_bytes + 1) || "").b
  raise "#{command.first}: output bound bypassed" if out.bytesize > max_bytes || err.bytesize > max_bytes
  exit_value = status.exited? ? status.exitstatus : { "signal" => status.termsig }
  { "exit" => exit_value, "stdout" => out, "stderr" => err }
ensure
  [input, stdout, stderr].compact.each(&:close!)
end

def bounded_reap(pid)
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
  loop do
    return if Process.waitpid(pid, Process::WNOHANG)
    break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
    sleep 0.02
  end
  Process.kill("KILL", pid) rescue nil
  grace = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1
  loop do
    return if Process.waitpid(pid, Process::WNOHANG)
    break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= grace
    sleep 0.02
  end
  raise "failed to reap process #{pid} after bounded cleanup"
rescue Errno::ECHILD, Errno::ESRCH
  nil
end

def kill_process_tree(pid)
  if Gem.win_platform?
    # Ruby has no portable Windows Job Object API. taskkill /T is the native
    # tree-cleanup primitive and is itself bounded so a failed cleanup cannot
    # strand the generator. This path is generator-only; it is not CLI runtime
    # evidence and does not alter the D-0019 follow-up.
    task = Process.spawn("taskkill", "/PID", pid.to_s, "/T", "/F", out: File::NULL, err: File::NULL)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    loop do
      break if Process.waitpid(task, Process::WNOHANG)
      if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        Process.kill("KILL", task) rescue nil
        Process.waitpid(task) rescue nil
        break
      end
      sleep 0.02
    end
  else
    Process.kill("KILL", -pid)
  end
rescue Errno::ESRCH, Errno::ECHILD
  nil
end

def write_file(root, relative, bytes, mode: nil)
  path = root.join(relative)
  FileUtils.mkdir_p(path.dirname)
  path.binwrite(bytes.b)
  File.chmod(mode, path) if mode
end

def tar_bytes(entries)
  io = StringIO.new("".b)
  Gem::Package::TarWriter.new(io) do |tar|
    entries.each do |name, bytes|
      tar.add_file_simple(name, 0o644, bytes.bytesize) { |file| file.write(bytes) }
    end
  end
  io.string.b
end

def gzip_bytes(bytes)
  io = StringIO.new("".b)
  Zlib::GzipWriter.wrap(io) { |writer| writer.write(bytes) }
  io.string.b
end

def git!(root, *arguments)
  env = {
    "GIT_AUTHOR_NAME" => "CLI Corpus",
    "GIT_AUTHOR_EMAIL" => "cli@example.invalid",
    "GIT_COMMITTER_NAME" => "CLI Corpus",
    "GIT_COMMITTER_EMAIL" => "cli@example.invalid",
    "GIT_AUTHOR_DATE" => "2001-02-03T04:05:06Z",
    "GIT_COMMITTER_DATE" => "2001-02-03T04:05:06Z",
    "LC_ALL" => "C", "TZ" => "UTC", "GIT_CONFIG_NOSYSTEM" => "1"
  }
  command_capture("git", *arguments, chdir: root, env: env, timeout: 30)
end

def init_git(root, content: "token=AB12\n", remote: nil)
  git!(root, "init", "--quiet")
  git!(root, "config", "user.name", "CLI Corpus")
  git!(root, "config", "user.email", "cli@example.invalid")
  write_file(root, "secret.txt", content)
  git!(root, "add", "secret.txt")
  git!(root, "commit", "--quiet", "-m", "initial")
  git!(root, "remote", "add", "origin", remote) if remote
end

def fixture_setup(root, kind)
  write_file(root, "config.toml", MATCHING_CONFIG)
  write_file(root, "never.toml", NO_MATCH_CONFIG)
  write_file(root, "template.tmpl", TEMPLATE)
  case kind
  when "empty"
    nil
  when "secret-file"
    write_file(root, "secret.txt", "token=AB12\n")
  when "aliases"
    write_file(root, "scan/secret.txt", "token=AB12\n")
  when "two-rules"
    write_file(root, "two.toml", TWO_RULE_CONFIG)
    write_file(root, "secret.txt", "alpha=AB12\nbeta=CD34\n")
  when "composite"
    write_file(root, "composite.toml", COMPOSITE_CONFIG)
    write_file(root, "secret.txt", "username=\"alice\" password=\"AB12\"\n")
  when "local-config"
    write_file(root, ".gitleaks.toml", MATCHING_CONFIG)
    write_file(root, "secret.txt", "token=AB12\n")
  when "ignores"
    write_file(root, "scan/a.txt", "token=AB12\n")
    write_file(root, "scan/b.txt", "token=CD34\n")
    write_file(root, "scan/.gitleaksignore", "scan/a.txt:fixture-token:1\n")
    write_file(root, "named.ignore", "scan/b.txt:fixture-token:1\nmalformed\n")
  when "baseline"
    write_file(root, "secret.txt", "token=AB12\n")
  when "encoded"
    # The decoder requires at least 16 non-padding base64 bytes.  Keep the
    # decoded rule match short while making the encoded candidate eligible.
    write_file(root, "encoded.txt", "dG9rZW49QUIxMnh4eHg=\n")
  when "archives"
    nested = tar_bytes("nested.txt" => "token=CD34\n")
    outer = tar_bytes("direct.txt" => "token=AB12\n", "nested.tar" => nested)
    write_file(root, "scan/archive.tar", outer)
    write_file(root, "scan/corrupt.gz", "\x1f\x8bcorrupt".b)
  when "allow-comment"
    write_file(root, "secret.txt", "token=AB12 # gitleaks:allow\n")
  when "git"
    init_git(root)
  when "git-remote"
    init_git(root, remote: "https://github.com/acme/repo.git")
  when "git-unknown-remote"
    init_git(root, remote: "https://example.invalid/acme/repo.git")
  when "git-malformed-remote"
    init_git(root, remote: "not a remote")
  when "issues"
    write_file(root, "scan/secret.txt", "token=AB12\n")
    write_file(root, "scan/bad.gz", "\x1f\x8bbad".b)
    File.symlink("missing-target", root.join("scan/broken-link"))
  when "paths"
    write_file(root, "config file.toml", MATCHING_CONFIG)
    write_file(root, "source dir ü/secret file.txt", "token=AB12\n")
    write_file(root, "source dir ü/C:\\repo\\secret.txt", "token=CD34\n")
  else
    raise "unknown fixture setup #{kind.inspect}"
  end
end

def report_args(path = "report.json", format = "json")
  ["-r", path, "-f", format]
end

def variant(id, setup:, args:, stdin: "", env: {}, report: nil, disposition: nil, finding_source: nil,
            prepare: nil, expected: {})
  {
    "id" => id, "setup" => setup, "args" => args, "stdin_base64" => b64(stdin),
    "env" => env.transform_values { |value| b64(value) }, "report_path" => report,
    "disposition" => disposition, "finding_source" => finding_source,
    "prepare" => prepare, "expected" => expected
  }
end

def scan_args(command, source = nil, config: "config.toml", extra: [], report: "report.json", format: "json")
  args = [command]
  args << source unless source.nil?
  args.concat(["--no-banner", "--no-color", "-c", config]) unless config.nil?
  args.concat(extra)
  args.concat(report_args(report, format)) if report
  args
end

def case_row(number, title, variants)
  { "id" => format("CLI-BB-%03d", number), "title" => title, "variants" => variants }
end

CASES = [
  case_row(1, "root help and the two version forms", [
    variant("root", setup: "empty", args: [], disposition: "CLI-DEFER-001", expected: { "exit" => 0 }),
    variant("help", setup: "empty", args: ["--help"], disposition: "CLI-DEFER-001", expected: { "exit" => 0 }),
    variant("version-command", setup: "empty", args: ["version"], expected: { "exit" => 0 }),
    variant("version-flag", setup: "empty", args: ["--version"], expected: { "exit" => 0 }),
    variant("version-persistent-flag", setup: "empty", args: ["version", "--no-banner"], expected: { "exit" => 0 })
  ]),
  case_row(2, "directory aliases", %w[dir file directory].map do |name|
    variant(name, setup: "aliases", args: scan_args(name, "scan", extra: ["--exit-code", "7"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 7, "findings" => 1 })
  end),
  case_row(3, "Git default, explicit repository, and surplus argument grammar", [
    variant("default-dot", setup: "git", args: scan_args("git", nil, extra: ["--platform", "none"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 1, "findings" => 1 }),
    variant("explicit-dot", setup: "git", args: scan_args("git", ".", extra: ["--platform", "none"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 1, "findings" => 1 }),
    variant("surplus", setup: "git", args: scan_args("git", ".", extra: ["second", "--platform", "none"]),
            report: "report.json", expected: { "exit" => 1, "report" => "absent" })
  ]),
  case_row(4, "safe directory and stdin arity", [
    variant("dir-surplus", setup: "secret-file",
            args: ["dir", "secret.txt", "ignored", "--no-banner", "--no-color", "-c", "config.toml", *report_args],
            report: "report.json", disposition: "CLI-SAFE-001", expected: { "rust_exit" => 1, "rust_report" => "absent" }),
    variant("stdin-surplus", setup: "empty",
            args: ["stdin", "ignored", "--no-banner", "--no-color", "-c", "config.toml", *report_args],
            stdin: "token=AB12\n", report: "report.json", disposition: "CLI-SAFE-001",
            expected: { "rust_exit" => 1, "rust_report" => "absent" })
  ]),
  case_row(5, "explicit config wins over both environment forms", [
    variant("explicit-over-env", setup: "secret-file", args: scan_args("dir", "secret.txt", config: "never.toml"),
            env: { "GITLEAKS_CONFIG" => "config.toml", "GITLEAKS_CONFIG_TOML" => MATCHING_CONFIG },
            report: "report.json", finding_source: "report", expected: { "exit" => 0, "findings" => 0 })
  ]),
  case_row(6, "environment path wins over inline TOML", [
    variant("env-path-over-inline", setup: "secret-file", args: scan_args("dir", "secret.txt", config: nil),
            env: { "GITLEAKS_CONFIG" => "never.toml", "GITLEAKS_CONFIG_TOML" => MATCHING_CONFIG },
            report: "report.json", finding_source: "report", expected: { "exit" => 0, "findings" => 0 })
  ]),
  case_row(7, "inline, target-local, file, and embedded config selection", [
    variant("inline", setup: "secret-file", args: scan_args("dir", "secret.txt", config: nil),
            env: { "GITLEAKS_CONFIG_TOML" => MATCHING_CONFIG }, report: "report.json", finding_source: "report",
            expected: { "exit" => 1, "findings" => 1 }),
    variant("target-local", setup: "local-config", args: scan_args("dir", ".", config: nil),
            report: "report.json", finding_source: "report", expected: { "exit" => 1, "findings" => 1 }),
    variant("file-embedded", setup: "empty", prepare: "embedded-secret",
            args: ["dir", "aws.txt", "--no-banner", "--no-color", *report_args], report: "report.json",
            finding_source: "report", expected: { "exit" => 1, "minimum_findings" => 1 }),
    variant("directory-embedded-empty", setup: "empty", args: ["dir", ".", "--no-banner", "--no-color", *report_args],
            report: "report.json", finding_source: "report", expected: { "exit" => 0, "findings" => 0 })
  ]),
  case_row(8, "missing source at config selection versus source execution", [
    variant("missing-no-higher-config", setup: "empty", args: ["dir", "missing", "--no-banner", "--no-color", *report_args],
            report: "report.json", expected: { "exit" => 1, "report" => "absent", "event" => "config.source-stat-error" }),
    variant("missing-with-higher-config", setup: "empty", args: scan_args("dir", "missing", config: "never.toml"),
            report: "report.json", finding_source: "report", expected: { "exit" => 0, "findings" => 0, "event" => "source.issue" })
  ]),
  case_row(9, "inline config disclosure", [
    variant("malformed-inline-marker", setup: "empty", args: ["stdin", "--no-banner", "--no-color"],
            env: { "GITLEAKS_CONFIG_TOML" => "invalid=[#{MARKER}" }, disposition: "CLI-SAFE-002",
            expected: { "go_discloses" => true, "rust_discloses" => false, "rust_exit" => 1 })
  ]),
  case_row(10, "enabled-rule projection and grammar", [
    variant("single", setup: "two-rules", args: scan_args("dir", "secret.txt", config: "two.toml", extra: ["--enable-rule", "alpha"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 1, "rule_ids" => ["alpha"] }),
    variant("repeated-csv", setup: "two-rules", args: scan_args("dir", "secret.txt", config: "two.toml",
            extra: ["--enable-rule", "alpha,alpha", "--enable-rule", "alpha"]), report: "report.json",
            finding_source: "report", expected: { "exit" => 1, "rule_ids" => ["alpha"] }),
    variant("invalid", setup: "two-rules", args: scan_args("dir", "secret.txt", config: "two.toml", extra: ["--enable-rule", "absent"]),
            report: "report.json", expected: { "exit" => 1, "report" => "absent" }),
    variant("selected-composite-missing-required", setup: "composite",
            args: scan_args("dir", "secret.txt", config: "composite.toml", extra: ["--enable-rule", "primary-rule"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 0, "findings" => 0 })
  ]),
  case_row(11, "default, named, and source-local ignore union", [
    variant("source-local", setup: "ignores", args: scan_args("dir", "scan"), report: "report.json",
            finding_source: "report", expected: { "exit" => 1, "findings" => 1 }),
    variant("named-plus-source", setup: "ignores", args: scan_args("dir", "scan", extra: ["-i", "named.ignore"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 0, "findings" => 0 }),
    variant("stdin-named-plus-local", setup: "empty", prepare: "stdin-ignore-union",
            args: scan_args("stdin", nil, extra: ["-i", "named.ignore"]), stdin: "token=AB12\n",
            report: "report.json", finding_source: "report", expected: { "exit" => 0, "findings" => 0 })
  ]),
  case_row(12, "valid, missing, and malformed baselines", [
    variant("valid", setup: "baseline", prepare: "valid-baseline", args: scan_args("dir", "secret.txt", extra: ["-b", "baseline.json"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 0, "findings" => 0 }),
    variant("missing", setup: "baseline", args: scan_args("dir", "secret.txt", extra: ["-b", "missing.json"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 1, "findings" => 1, "event" => "baseline.error" }),
    variant("malformed", setup: "baseline", prepare: "malformed-baseline", args: scan_args("dir", "secret.txt", extra: ["-b", "baseline.json"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 1, "findings" => 1, "event" => "baseline.error" })
  ]),
  case_row(13, "exact config and baseline logical-path exclusions", [
    variant("relative-config", setup: "empty", prepare: "config-self-secret", args: scan_args("dir", ".", config: "scan/config.toml"),
            report: "report.json", finding_source: "report", expected: { "exit" => 0, "findings" => 0 }),
    variant("dot-config-spelling", setup: "empty", prepare: "config-self-secret", args: scan_args("dir", ".", config: "./scan/../scan/config.toml"),
            report: "report.json", finding_source: "report"),
    variant("outside-baseline", setup: "baseline", prepare: "outside-baseline-secret",
            args: scan_args("dir", ".", extra: ["-b", "other/baseline.json"]), report: "report.json", finding_source: "report",
            expected: { "exit" => 1, "findings" => 1 }),
    variant("git-logical-config", setup: "git", prepare: "git-config-self-secret",
            args: scan_args("git", ".", config: "config.toml", extra: ["--platform", "none"]), report: "report.json", finding_source: "report",
            expected: {}),
    variant("windows-drive-unc-spellings", setup: "empty", prepare: "windows-logical-exclusions",
            args: scan_args("dir", ".", config: "C:\\fixture\\config.toml"), report: "report.json", finding_source: "report",
            expected: { "unix_only" => true, "exit" => 0, "findings" => 0 })
  ]),
  case_row(14, "raw, positive, and negative decode depth", [
    variant("raw-zero", setup: "encoded", args: scan_args("dir", "encoded.txt", extra: ["--max-decode-depth", "0"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 0, "findings" => 0 }),
    variant("depth-one", setup: "encoded", args: scan_args("dir", "encoded.txt", extra: ["--max-decode-depth", "1"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 1, "findings" => 1 }),
    variant("negative", setup: "encoded", args: scan_args("dir", "encoded.txt", extra: ["--max-decode-depth", "-1"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 0, "findings" => 0 })
  ]),
  case_row(15, "archive depth and corruption", [
    variant("depth-zero", setup: "archives", args: scan_args("dir", "scan/archive.tar", extra: ["--max-archive-depth", "0"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 0, "findings" => 0 }),
    variant("depth-one", setup: "archives", args: scan_args("dir", "scan/archive.tar", extra: ["--max-archive-depth", "1"]),
            report: "report.json", finding_source: "report", expected: { "minimum_findings" => 1 }),
    variant("depth-two", setup: "archives", args: scan_args("dir", "scan/archive.tar", extra: ["--max-archive-depth", "2"]),
            report: "report.json", finding_source: "report", expected: { "minimum_findings" => 2 }),
    variant("corrupt", setup: "archives", args: scan_args("dir", "scan/corrupt.gz", extra: ["--max-archive-depth", "1"]),
            report: "report.json", finding_source: "report",
            expected: { "exit" => 0, "findings" => 0, "event" => "source.issue" })
  ]),
  case_row(16, "source and engine size thresholds", [
    variant("source-inclusive", setup: "empty", prepare: "sized:1000000", args: scan_args("dir", "sized.txt", extra: ["--max-target-megabytes", "1"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 1, "findings" => 1 }),
    variant("source-plus-one", setup: "empty", prepare: "sized:1000001", args: scan_args("dir", "sized.txt", extra: ["--max-target-megabytes", "1"]),
            report: "report.json", finding_source: "report",
            expected: { "exit" => 0, "findings" => 0 }),
    variant("engine-inclusive", setup: "git", prepare: "git-sized:1999999", args: scan_args("git", ".", extra: ["--max-target-megabytes", "1"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 1, "findings" => 1 }),
    variant("engine-plus-one", setup: "git", prepare: "git-sized:2000000", args: scan_args("git", ".", extra: ["--max-target-megabytes", "1"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 0, "findings" => 0 }),
    variant("overflow", setup: "secret-file", args: scan_args("dir", "secret.txt", extra: ["--max-target-megabytes", "9223372036854775807"]),
            report: "report.json", disposition: "CLI-SAFE-005", expected: { "rust_exit" => 1, "rust_report" => "absent" })
  ]),
  case_row(17, "gitleaks allow-comment policy", [
    variant("honor", setup: "allow-comment", args: scan_args("dir", "secret.txt"), report: "report.json", finding_source: "report",
            expected: { "exit" => 0, "findings" => 0 }),
    variant("ignore-marker", setup: "allow-comment", args: scan_args("dir", "secret.txt", extra: ["--ignore-gitleaks-allow"]),
            report: "report.json", finding_source: "report", expected: { "exit" => 1, "findings" => 1 })
  ]),
  case_row(18, "redaction optional-value grammar", [
    variant("bare", setup: "empty", args: scan_args("stdin", nil, extra: ["--redact"]), stdin: "token=AB12\n",
            report: "report.json", finding_source: "report", expected: { "secret" => "REDACTED" }),
    variant("attached-20", setup: "empty", args: scan_args("stdin", nil, extra: ["--redact=20"]), stdin: "token=AB12\n",
            report: "report.json", finding_source: "report", expected: { "secret" => "AB1..." }),
    variant("attached-zero", setup: "empty", args: scan_args("stdin", nil, extra: ["--redact=0"]), stdin: "token=AB12\n",
            report: "report.json", finding_source: "report", expected: { "secret" => "AB12" }),
    variant("following-positional", setup: "empty", args: scan_args("stdin", nil, extra: ["--redact", "20"]), stdin: "token=AB12\n",
            report: "report.json", disposition: "CLI-SAFE-001", expected: { "rust_exit" => 1, "rust_report" => "absent" })
  ]),
  case_row(19, "finding and configured process exits", [
    variant("no-finding", setup: "empty", args: scan_args("stdin", nil, config: "never.toml"), report: "report.json", finding_source: "report", expected: { "exit" => 0 }),
    variant("default", setup: "empty", args: scan_args("stdin"), stdin: "token=AB12\n", report: "report.json", finding_source: "report", expected: { "exit" => 1 }),
    variant("zero", setup: "empty", args: scan_args("stdin", nil, extra: ["--exit-code", "0"]), stdin: "token=AB12\n", report: "report.json", finding_source: "report", expected: { "exit" => 0 }),
    variant("seven", setup: "empty", args: scan_args("stdin", nil, extra: ["--exit-code", "7"]), stdin: "token=AB12\n", report: "report.json", finding_source: "report", expected: { "exit" => 7 }),
    variant("negative-one-native", setup: "empty", args: scan_args("stdin", nil, extra: ["--exit-code", "-1"]), stdin: "token=AB12\n", report: "report.json", finding_source: "report", expected: { "native_negative_one" => true }),
    variant("outside-i32", setup: "empty", args: scan_args("stdin", nil, extra: ["--exit-code", "2147483648"]), stdin: "token=AB12\n", report: "report.json",
            disposition: "CLI-SAFE-005", expected: { "rust_exit" => 1, "rust_report" => "absent" })
  ]),
  case_row(20, "dormant report flags without a path", [
    variant("format-only", setup: "empty", args: scan_args("stdin", nil, config: "never.toml", extra: ["--report-format", "not-a-format"], report: nil),
            expected: { "exit" => 0, "stdout_bytes" => 0 }),
    variant("template-only", setup: "empty", args: scan_args("stdin", nil, config: "never.toml", extra: ["--report-template", "missing.tmpl"], report: nil),
            expected: { "exit" => 0, "stdout_bytes" => 0 })
  ]),
  case_row(21, "stdout report format selection", [
    variant("missing-format", setup: "empty", args: scan_args("stdin", nil, config: "never.toml", report: nil) + ["-r", "-"],
            expected: { "exit" => 1, "stdout_bytes" => 0 }),
    *%w[json csv junit sarif template].map do |format|
      extra = format == "template" ? ["--report-template", "template.tmpl"] : []
      variant(format, setup: "empty", args: scan_args("stdin", nil, extra: extra, report: "-", format: format), stdin: "token=AB12\n",
              finding_source: (format == "json" ? "stdout" : nil), expected: { "exit" => 1, "stdout_nonempty" => true })
    end
  ]),
  case_row(22, "report extension inference and explicit mismatch", [
    *["result.json", "result.CSV", "result.sarif"].map do |path|
      variant(path, setup: "empty", args: scan_args("stdin", nil, config: "never.toml", report: nil) + ["-r", path], report: path,
              expected: { "exit" => 0, "report" => "present" })
    end,
    variant("xml-rejected", setup: "empty", args: scan_args("stdin", nil, config: "never.toml", report: nil) + ["-r", "result.xml"], report: "result.xml",
            expected: { "exit" => 1, "report" => "absent" }),
    variant("extensionless-rejected", setup: "empty", args: scan_args("stdin", nil, config: "never.toml", report: nil) + ["-r", "result"], report: "result",
            expected: { "exit" => 1, "report" => "absent" }),
    variant("explicit-mismatch", setup: "empty", args: scan_args("stdin", nil, config: "never.toml", report: "result.csv", format: "json"), report: "result.csv", finding_source: "report", expected: { "exit" => 0, "findings" => 0 })
  ]),
  case_row(23, "template construction and safe profile", [
    variant("valid", setup: "empty", args: scan_args("stdin", nil, extra: ["--report-template", "template.tmpl"], report: "report.tmpl", format: "template"),
            stdin: "token=AB12\n", report: "report.tmpl", expected: { "exit" => 1, "report" => "present" }),
    variant("missing", setup: "empty", args: scan_args("stdin", nil, extra: ["--report-template", "missing.tmpl"], report: "report.tmpl", format: "template"),
            report: "report.tmpl", expected: { "exit" => 1, "report" => "absent" }),
    variant("dangerous-helper", setup: "empty", prepare: "dangerous-template",
            args: scan_args("stdin", nil, config: "never.toml", extra: ["--report-template", "dangerous.tmpl"], report: "report.tmpl", format: "template"),
            env: { "CLI_CORPUS_TEMPLATE_VALUE" => "synthetic-template-value" }, report: "report.tmpl", disposition: "REPORT-SAFE-001",
            expected: { "go_report_contains" => "SYNTHETIC-TEMPLATE-VALUE", "rust_report" => "absent" }),
    variant("raw-uppercase", setup: "empty", args: scan_args("stdin", nil, config: "never.toml", extra: ["--report-template", "template.tmpl"], report: "report.tmpl", format: "TEMPLATE"),
            report: "report.tmpl", expected: { "exit" => 1, "report" => "absent" })
  ]),
  case_row(24, "safe report target preflight", [
    variant("preexisting-later-setup-failure", setup: "empty", prepare: "preexisting-report",
            args: scan_args("stdin", nil, config: "config.toml", extra: ["--report-template", "missing.tmpl"], report: "report.json", format: "template"),
            report: "report.json",
            disposition: "CLI-SAFE-004", expected: { "go_report" => "absent", "rust_report_sha256" => sha("preserve-this-report") }),
    variant("report-open-directory", setup: "empty", prepare: "report-directory",
            args: scan_args("stdin", nil, config: "never.toml", report: "report-dir", format: "json"),
            report: "report-dir", disposition: "CLI-SAFE-004",
            expected: { "exit" => 1, "report" => "absent", "event" => "report.error", "open_failure" => true })
  ]),
  case_row(25, "no-color verbose bytes and stdout interleaving", [
    variant("verbose", setup: "secret-file", args: scan_args("dir", "secret.txt", extra: ["--verbose"], report: nil), expected: { "exit" => 1, "stdout_nonempty" => true }),
    variant("verbose-stdout-json", setup: "empty", args: scan_args("stdin", nil, extra: ["--verbose"], report: "-", format: "json"),
            stdin: "token=AB12\n", expected: { "exit" => 1, "stdout_prefix" => "Finding:" })
  ]),
  case_row(26, "Git history, worktree, staged, and staged precedence", [
    variant("history", setup: "git", args: scan_args("git", ".", extra: ["--platform", "none"]), report: "report.json", finding_source: "report", expected: { "findings" => 1 }),
    *[["worktree", ["--pre-commit"]], ["staged", ["--staged"]], ["both", ["--pre-commit", "--staged"]]].map do |id, flags|
      variant(id, setup: "git", prepare: "git-change:#{id}", args: scan_args("git", ".", extra: flags), report: "report.json", finding_source: "report", expected: { "findings" => 1 })
    end
  ]),
  case_row(27, "SCM platforms, remotes, and links", [
    *%w[unknown none github gitlab azuredevops gitea bitbucket].map do |platform|
      variant(platform, setup: "git-remote", args: scan_args("git", ".", extra: ["--platform", platform]), report: "report.json", finding_source: "report", expected: { "findings" => 1 })
    end,
    variant("unknown-host", setup: "git-unknown-remote", args: scan_args("git", "."), report: "report.json", finding_source: "report", expected: { "findings" => 1 }),
    variant("no-remote", setup: "git", args: scan_args("git", "."), report: "report.json", finding_source: "report", expected: { "findings" => 1 }),
    variant("malformed-remote", setup: "git-malformed-remote", args: scan_args("git", "."), report: "report.json", finding_source: "report", expected: { "findings" => 1 })
  ]),
  case_row(28, "quoted and empty-space log options", [
    variant("quoted", setup: "git", args: scan_args("git", ".", extra: ["--platform", "none", "--log-opts", "'--all'"]),
            report: "report.json", finding_source: "report", disposition: "CLI-SAFE-003", expected: { "rust_exit" => 1, "rust_report" => "present" }),
    variant("empty-space", setup: "git", args: scan_args("git", ".", extra: ["--platform", "none", "--log-opts", "  "]),
            report: "report.json", finding_source: "report", disposition: "CLI-SAFE-003", expected: { "rust_exit" => 1, "rust_report" => "present" })
  ]),
  case_row(29, "terminal Git child and parser failures", [
    variant("invalid-repository", setup: "empty", args: scan_args("git", "missing", config: "never.toml", extra: ["--platform", "none", "--exit-code", "7"]),
            report: "report.json", finding_source: "report", disposition: "CLI-SAFE-003",
            expected: { "go_exit" => 0, "rust_exit" => 1, "rust_findings" => 0, "rust_report" => "present" }),
    variant("malformed-patch", setup: "empty", prepare: "fake-git:malformed", args: scan_args("git", ".", config: "never.toml", extra: ["--platform", "none", "--exit-code", "7"]),
            report: "report.json", finding_source: "report", disposition: "CLI-SAFE-003", expected: { "rust_exit" => 1, "rust_report" => "present" }),
    variant("child-stderr-output-limit", setup: "empty", prepare: "fake-git:output-limit", args: scan_args("git", ".", config: "never.toml", extra: ["--platform", "none", "--exit-code", "7"]),
            report: "report.json", finding_source: "report", disposition: "CLI-SAFE-003",
            expected: { "rust_exit" => 1, "rust_report" => "present", "child_reaped" => true, "output_limit" => true })
  ]),
  case_row(30, "recoverable directory issues remain completed", [
    variant("corrupt-archive-and-broken-symlink", setup: "issues", args: scan_args("dir", "scan", extra: ["--max-archive-depth", "1", "--follow-symlinks"]),
            report: "report.json", finding_source: "report",
            expected: { "exit" => 1, "findings" => 1, "event" => "source.issue" })
  ]),
  case_row(31, "timeout before and during Git source with cleanup", [
    variant("remote-timeout", setup: "empty", prepare: "fake-git:timeout-remote", args: scan_args("git", ".", config: "never.toml", extra: ["--timeout", "1"]),
            report: "report.json", finding_source: "report", disposition: "CLI-SAFE-003", expected: { "rust_exit" => 1, "rust_report" => "present", "child_reaped" => true }),
    variant("source-timeout", setup: "empty", prepare: "fake-git:timeout-source", args: scan_args("git", ".", config: "never.toml", extra: ["--platform", "none", "--timeout", "1", "--exit-code", "7"]),
            report: "report.json", finding_source: "report", disposition: "CLI-SAFE-003", expected: { "rust_exit" => 1, "rust_report" => "present", "child_reaped" => true })
  ]),
  case_row(32, "parser failures and side-effect freedom", [
    variant("unknown-long", setup: "empty", prepare: "preexisting-report", args: ["stdin", "--unknown", *report_args], report: "report.json", expected: { "exit" => 126, "report_sha256" => sha("preserve-this-report") }),
    variant("unknown-short", setup: "empty", prepare: "preexisting-report", args: ["stdin", "-x", *report_args], report: "report.json", expected: { "exit" => 1, "report_sha256" => sha("preserve-this-report") }),
    variant("bad-integer", setup: "empty", prepare: "preexisting-report", args: ["stdin", "--exit-code", "nope", *report_args], report: "report.json", expected: { "exit" => 1, "report_sha256" => sha("preserve-this-report") }),
    variant("unknown-command", setup: "empty", prepare: "preexisting-report", args: ["unknown", *report_args], report: "report.json", expected: { "exit" => 1, "report_sha256" => sha("preserve-this-report") }),
    variant("short-attached-config", setup: "empty", args: ["stdin", "--no-banner", "--no-color", "-c=config.toml", *report_args], stdin: "token=AB12\n",
            report: "report.json", finding_source: "report", expected: { "exit" => 1, "findings" => 1 })
  ]),
  case_row(33, "spaces, Unicode, Windows spellings, report case, and native bytes", [
    variant("spaces-unicode", setup: "paths", args: scan_args("dir", "source dir ü/secret file.txt", config: "config file.toml", report: "Report.JSON", format: "json"),
            report: "Report.JSON", finding_source: "report", expected: { "exit" => 1, "findings" => 1 }),
    variant("windows-logical-name", setup: "paths", args: scan_args("dir", "source dir ü/C:\\repo\\secret.txt", config: "config file.toml"),
            report: "report.json", finding_source: "report", expected: { "exit" => 1, "findings" => 1 }),
    variant("leading-dash", setup: "empty", prepare: "leading-dash", args: ["dir", "--no-banner", "--no-color", "-c", "config.toml", *report_args, "--", "-source"],
            report: "report.json", finding_source: "report", expected: { "exit" => 1, "findings" => 1 }),
    variant("native-non-utf8", setup: "empty", prepare: "native-non-utf8", args: ["dir", "__NATIVE_PATH__", "--no-banner", "--no-color", "-c", "config.toml", *report_args],
            report: "report.json", finding_source: "report", expected: { "linux_only" => true, "exit" => 1, "findings" => 1 })
  ]),
  case_row(34, "empty findings in every report format", %w[json csv junit sarif template].map do |format|
    extra = format == "template" ? ["--report-template", "template.tmpl"] : []
    variant(format, setup: "empty", args: scan_args("stdin", nil, config: "never.toml", extra: extra, report: "empty.#{format}", format: format),
            report: "empty.#{format}", finding_source: (format == "json" ? "report" : nil), expected: { "exit" => 0, "report" => "present" })
  end)
].freeze

abort "CLI matrix must contain exactly 34 rows" unless CASES.map { |row| row.fetch("id") } == (1..34).map { |n| format("CLI-BB-%03d", n) }
CASES.each do |row|
  ids = row.fetch("variants").map { |variant| variant.fetch("id") }
  abort "duplicate variant ID in #{row.fetch('id')}" unless ids.uniq.length == ids.length
end
abort "CLI variant matrix changed from 119 variants" unless CASES.sum { |row| row.fetch("variants").length } == 119

def prepare_fixture(root, preparation, go_binary)
  return {} if preparation.nil?
  case preparation
  when "embedded-secret"
    write_file(root, "aws.txt", "aws_access_key_id=AKIALALEMEL33243OLIA\n")
  when "stdin-ignore-union"
    write_file(root, ".gitleaksignore", ":fixture-token:1\n")
    write_file(root, "named.ignore", "malformed\n")
  when "valid-baseline"
    result = bounded_process([go_binary, "dir", "secret.txt", "--no-banner", "--no-color", "-c", "config.toml", "-r", "baseline.json", "-f", "json"],
                             chdir: root, env: {}, stdin_bytes: "")
    raise "baseline seed did not find exactly one secret" unless result.fetch("exit") == 1
    findings = JSON.parse(root.join("baseline.json").binread)
    raise "baseline seed finding count changed" unless findings.length == 1
  when "malformed-baseline"
    write_file(root, "baseline.json", "[{broken")
  when "config-self-secret"
    write_file(root, "scan/config.toml", MATCHING_CONFIG + "# token=AB12\n")
  when "outside-baseline-secret"
    FileUtils.mkdir_p(root.join("scan"))
    write_file(root, "scan/clean.txt", "clean\n")
    write_file(root, "other/baseline.json", "[{\"Extra\":\"token=AB12\"}]\n")
  when "git-config-self-secret"
    write_file(root, "config.toml", MATCHING_CONFIG + "# token=AB12\n")
    git!(root, "add", "config.toml")
    git!(root, "commit", "--quiet", "--amend", "--no-edit")
  when "windows-logical-exclusions"
    write_file(root, "C:\\fixture\\config.toml", MATCHING_CONFIG + "# token=AB12\n")
    write_file(root, "scan/clean.txt", "clean\n")
  when /\Asized:(\d+)\z/
    size = Regexp.last_match(1).to_i
    prefix = "token=AB12\n".b
    raise "invalid sized fixture" if size < prefix.bytesize
    write_file(root, "sized.txt", prefix + ("x".b * (size - prefix.bytesize)))
  when /\Astdin-sized:(\d+)\z/
    size = Regexp.last_match(1).to_i
    prefix = "token=AB12\n".b
    raise "invalid stdin fixture" if size < prefix.bytesize
    return { "stdin" => prefix + ("x".b * (size - prefix.bytesize)) }
  when /\Agit-sized:(\d+)\z/
    size = Regexp.last_match(1).to_i
    suffix = "token=AB12".b
    raise "invalid Git-sized fixture" if size < suffix.bytesize
    write_file(root, "secret.txt", ("x".b * (size - suffix.bytesize)) + suffix)
    git!(root, "add", "secret.txt")
    git!(root, "commit", "--quiet", "--amend", "--no-edit")
  when "dangerous-template"
    write_file(root, "dangerous.tmpl", '{{ upper "synthetic-template-value" }}')
  when "preexisting-report"
    write_file(root, "report.json", "preserve-this-report")
  when "report-directory"
    FileUtils.mkdir_p(root.join("report-dir"))
  when /\Agit-change:(worktree|staged|both)\z/
    mode = Regexp.last_match(1)
    write_file(root, "secret.txt", "token=CD34\n")
    git!(root, "add", "secret.txt") if %w[staged both].include?(mode)
  when /\Afake-git:(malformed|output-limit|timeout-remote|timeout-source)\z/
    mode = Regexp.last_match(1)
    script = <<~RUBY
      #!/usr/bin/env ruby
      File.write(File.join(Dir.pwd, "fake-git.pid"), Process.pid.to_s)
      args = ARGV.join(" ")
      mode = #{mode.inspect}
      if mode == "malformed"
        STDOUT.write("malformed patch bytes\\n")
        exit 0
      end
      if mode == "output-limit"
        # Stay below Go's per-line bufio.Scanner ceiling while crossing the
        # Rust Git runner's cumulative 1 MiB stderr retention limit.
        STDERR.write((("x" * 32_767) + "\\n") * 33)
        STDERR.flush
        sleep 2
        exit 0
      end
      remote = args.include?("ls-remote")
      should_sleep = mode == "timeout-remote" ? remote : !remote
      if should_sleep
        sleep 30
      elsif remote
        exit 1
      else
        STDOUT.write("")
      end
    RUBY
    write_file(root, "fake-bin/git", script, mode: 0o755)
    return { "env" => { "PATH" => "#{root.join('fake-bin')}#{File::PATH_SEPARATOR}#{ENV.fetch('PATH')}" }, "child_pid_file" => "fake-git.pid" }
  when "leading-dash"
    write_file(root, "-source/secret.txt", "token=AB12\n")
  when "native-non-utf8"
    if RUBY_PLATFORM.include?("linux")
      native = "native-\xff.txt".b
      write_file(root, native, "token=AB12\n")
      return { "native_path" => native }
    end
  else
    raise "unknown fixture preparation #{preparation.inspect}"
  end
  {}
end

ANSI_RE = /\e\[[0-?]*[ -\/]*[@-~]/.freeze
GO_LEVELS = { "TRC" => "trace", "DBG" => "debug", "INF" => "info", "WRN" => "warn", "ERR" => "error", "FTL" => "fatal" }.freeze

def normalize_bytes(bytes, root:, executable_names: [])
  value = bytes.b.dup
  if RUBY_PLATFORM.include?("darwin") && root.to_s.start_with?("/var/")
    value.gsub!("/private#{root}".b, "<TMP>".b)
  end
  value.gsub!(root.to_s.b, "<TMP>".b)
  value.gsub!("<TMP>\\".b, "<TMP>/".b) if Gem.win_platform?
  executable_names.sort_by { |item| -item.bytesize }.each do |name|
    value.gsub!(name.b, "gitleaks".b)
    value.gsub!(name.capitalize.b, "Gitleaks".b)
  end
  value.gsub!(ANSI_RE, "")
  value
end

def event_for(line)
  text = line.strip
  severity = "error"
  if (match = text.match(/\A(?:\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?\s+)?(TRC|DBG|INF|WRN|ERR|FTL)\s+(.*)\z/i))
    severity = GO_LEVELS.fetch(match[1].upcase)
    text = match[2]
  elsif (match = text.match(/\A(trace|debug|info|warn|error|fatal)\s+(.*)\z/i))
    severity = match[1].downcase
    text = match[2]
  end
  text = text.gsub(/\b(?:\d+(?:\.\d+)?(?:ns|µs|us|ms|s|m|h))+\b/, "<DURATION>")
  text = text.gsub(/(?:No such file or directory|The system cannot find the (?:file|path) specified\.?)/i, "<os:not-found>")
  fields = {}
  class_name = case text
               when /scanned ~([0-9]+) bytes \(([^)]+)\)(?: in <DURATION>)?/
                 fields = { "bytes" => Regexp.last_match(1).to_i, "human" => Regexp.last_match(2) }
                 "summary.scanned"
               when /partial scan completed(?: in <DURATION>)?/
                 "summary.partial"
               when /(?:leaks found: ([0-9]+)|([0-9]+) leaks found in partial scan)/
                 fields = { "count" => (Regexp.last_match(1) || Regexp.last_match(2)).to_i }
                 text.include?("partial") ? "summary.partial-findings" : "summary.findings"
               when /no leaks found in partial scan/
                 "summary.partial-empty"
               when /no leaks found/
                 "summary.empty"
               when /([0-9]+) commits scanned/
                 fields = { "count" => Regexp.last_match(1).to_i }
                 "git.commits"
               when /unknown shorthand/i then "parser.unknown-short"
               when /unknown flag/i then "parser.unknown-long"
               when /unknown command/i then "parser.unknown-command"
               when /accepts? (?:at most|no)|argument/i then "parser.arity"
               when /invalid value|requires a value|out of range|overflow/i then "parser.value"
               when /baseline/i then "baseline.error"
               when /gitleaksignore|ignore file/i then "ignore.warning"
               when /git standard (?:error|output).*byte ceiling|git.*output limit/i then "source.git-error"
               when /\Astat\s|during config selection/i then "config.source-stat-error"
               when /config|toml/i then "config.error"
               when /report format|report path|report template|template report|(?:open|write|flush)\b.*\breport\b|\breport\b.*\b(?:open|write|flush)\b|template/i then "report.error"
               when /quoted|quote characters|log-opts/i then "git.log-options"
               when /enable|custom regex|rule/i then "rules.selection"
               when /unknown scm|unknown host|remote/i then "scm.event"
               when /partial|cancel|timeout|timed out/i then "source.partial"
               when /git|repository|revision|patch|child/i then "source.git-error"
               when /skipping|source Metadata/i then "source.issue"
               when /archive|symlink|read|decode|corrupt/i then "source.issue"
               when /source|directory|walk|stat/i then "source.error"
               else
                 fields = { "message_sha256" => sha(text) }
                 "diagnostic.other"
               end
  { "severity" => severity, "class" => class_name, "fields" => fields,
    "normalized_message_base64" => b64(text) }
end

def rendered_log_line?(line)
  line.match?(/\A(?:(?:\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?\s+)?(?:TRC|DBG|INF|WRN|ERR|FTL)\s|(?:trace|debug|info|warn|error|fatal)\s)/i)
end

def versioned_usage_line?(line)
  line.match?(/\A(?:completion|help)\s{2,}/) ||
    line.include?("Generate the autocompletion script") ||
    line.match?(/\A--diagnostics(?:-dir)?(?:\s|\z)/) ||
    line.include?("--gitleaks-ignore-path") ||
    line.include?("--ignore-gitleaks-allow") ||
    line.match?(/\A(?:order of precedence:|[1-6]\. |If none of the four options|Otherwise Gitleaks)/)
end

def normalize_events(bytes, root:, executable_names: [])
  normalized = normalize_bytes(bytes, root: root, executable_names: executable_names)
  normalized.force_encoding(Encoding::UTF_8)
  normalized = normalized.scrub("�")
  in_usage = false
  normalized.lines.each_with_object([]) do |line, events|
    stripped = line.strip
    next if stripped.empty?
    in_usage = true if stripped == "Usage:"
    in_usage = false if in_usage && stripped != "Usage:" && rendered_log_line?(stripped)
    # The same narrowly versioned CLI-DEFER-001 rows can be embedded in
    # parser-failure usage on stderr. Do not suppress surrounding usage,
    # diagnostics, or arbitrary matching prose.
    next if in_usage && versioned_usage_line?(stripped)
    events << event_for(stripped)
  end
end

def normalized_usage(bytes, root:, executable_names: [])
  normalized = normalize_bytes(bytes, root: root, executable_names: executable_names)
  normalized.force_encoding(Encoding::UTF_8)
  lines = normalized.scrub("�").lines
  start = lines.index { |line| line.strip == "Usage:" }
  return nil unless start
  usage = []
  lines.drop(start).each do |line|
    stripped = line.strip
    break if !usage.empty? && rendered_log_line?(stripped)
    next if versioned_usage_line?(stripped)
    usage << line
  end
  usage.join.sub(/\s+\z/, "\n").gsub("Gitleaks", "gitleaks").b
end

def canonical_findings(bytes)
  parsed = JSON.parse(bytes)
  raise "JSON report is not a finding array" unless parsed.is_a?(Array)
  parsed.sort_by { |finding| JSON.generate(finding) }
end

def report_observation(root, report_path)
  return nil if report_path.nil? || report_path == "-"
  path = root.join(report_path)
  return { "state" => "absent" } unless path.file?
  bytes = path.binread
  { "state" => "present", "bytes_base64" => b64(bytes), "bytes" => bytes.bytesize, "sha256" => sha(bytes) }
end

def process_alive?(pid)
  Process.kill(0, pid)
  true
rescue Errno::ESRCH
  false
rescue Errno::EPERM
  true
end

def observe(binary, implementation, row, spec, go_binary)
  Dir.mktmpdir("rustleaks-cli-#{row.fetch('id').downcase}-") do |directory|
    root = Pathname(directory)
    fixture_setup(root, spec.fetch("setup"))
    prepared = prepare_fixture(root, spec["prepare"], go_binary)
    args = spec.fetch("args").map do |argument|
      argument == "__NATIVE_PATH__" ? prepared.fetch("native_path", argument) : argument
    end
    env = spec.fetch("env").transform_values { |value| Base64.strict_decode64(value) }.merge(prepared.fetch("env", {}))
    stdin_bytes = Base64.strict_decode64(spec.fetch("stdin_base64"))
    stdin_bytes = prepared.fetch("stdin") if stdin_bytes == "__GENERATED__"
    result = bounded_process([binary, *args], chdir: root, env: env, stdin_bytes: stdin_bytes)
    report = report_observation(root, spec["report_path"])
    stable_stdout = normalize_bytes(result.fetch("stdout"), root: root,
                                    executable_names: [File.basename(binary), "rustleaks", "gitleaks"])
    finding_bytes = case spec["finding_source"]
                    when "report"
                      report && report["state"] == "present" ? Base64.strict_decode64(report.fetch("bytes_base64")) : nil
                    when "stdout" then result.fetch("stdout")
                    end
    findings = finding_bytes ? canonical_findings(finding_bytes) : nil
    child_reaped = nil
    if prepared["child_pid_file"] && root.join(prepared.fetch("child_pid_file")).file?
      child_pid = Integer(root.join(prepared.fetch("child_pid_file")).read, 10)
      child_reaped = !process_alive?(child_pid)
      kill_process_tree(child_pid) unless child_reaped
    end
    if spec.dig("expected", "native_negative_one")
      allowed = Gem.win_platform? ? [255, 4_294_967_295] : [255]
      raise "#{row.fetch('id')}/#{spec.fetch('id')}: native -1 status #{result.fetch('exit').inspect} not in #{allowed.inspect}" unless allowed.include?(result.fetch("exit"))
    end
    exit_value = spec.dig("expected", "native_negative_one") ? "native-negative-one" : result.fetch("exit")
    {
      "implementation" => implementation,
      "exit" => exit_value,
      "stdout_base64" => b64(stable_stdout),
      "stdout_bytes" => stable_stdout.bytesize,
      "stdout_sha256" => sha(stable_stdout),
      "stderr_events" => normalize_events(result.fetch("stderr"), root: root,
                                           executable_names: [File.basename(binary), "rustleaks", "gitleaks"]),
      "stderr_usage" => begin
        usage = normalized_usage(result.fetch("stderr"), root: root,
                                 executable_names: [File.basename(binary), "rustleaks", "gitleaks"])
        usage && { "bytes_base64" => b64(usage), "bytes" => usage.bytesize, "sha256" => sha(usage) }
      end,
      "stderr_contains_disclosure_marker" => result.fetch("stderr").include?(MARKER),
      "report" => report,
      "findings" => findings,
      "finding_count" => findings&.length,
      "child_reaped" => child_reaped
    }
  end
end

def report_bytes(observation)
  report = observation["report"]
  return nil unless report && report["state"] == "present"
  Base64.strict_decode64(report.fetch("bytes_base64"))
end

def stdout_bytes(observation)
  Base64.strict_decode64(observation.fetch("stdout_base64"))
end

def axis_equal(go, rust, key)
  go[key] == rust[key]
end

def comparison_axes(go, rust)
  event_projection = lambda do |observation|
    observation.fetch("stderr_events").map { |event| event.reject { |key, _value| key == "normalized_message_base64" } }
  end
  {
    "exit" => axis_equal(go, rust, "exit"),
    "stdout" => axis_equal(go, rust, "stdout_base64"),
    "stderr_events" => event_projection.call(go) == event_projection.call(rust),
    "stderr_usage" => axis_equal(go, rust, "stderr_usage"),
    "report" => axis_equal(go, rust, "report"),
    "findings" => axis_equal(go, rust, "findings"),
    "child_cleanup" => axis_equal(go, rust, "child_reaped")
  }
end

def require_condition(condition, message)
  raise message unless condition
end

def validate_expected!(case_id, spec, go, rust)
  label = "#{case_id}/#{spec.fetch('id')}"
  expected = spec.fetch("expected")
  [go, rust].each do |observation|
    implementation = observation.fetch("implementation")
    require_condition(observation["exit"] == expected["exit"], "#{label}/#{implementation}: exit changed") if expected.key?("exit")
    require_condition(observation["finding_count"] == expected["findings"], "#{label}/#{implementation}: finding count changed") if expected.key?("findings")
    if expected.key?("minimum_findings")
      require_condition(observation["finding_count"] && observation["finding_count"] >= expected["minimum_findings"], "#{label}/#{implementation}: minimum finding count changed")
    end
    if expected.key?("report")
      state = observation["report"]&.fetch("state", "absent") || "absent"
      require_condition(state == expected["report"], "#{label}/#{implementation}: report state changed")
    end
    require_condition(observation["stdout_bytes"] == expected["stdout_bytes"], "#{label}/#{implementation}: stdout length changed") if expected.key?("stdout_bytes")
    require_condition(observation["stdout_bytes"].positive? == expected["stdout_nonempty"], "#{label}/#{implementation}: stdout presence changed") if expected.key?("stdout_nonempty")
    if expected.key?("stdout_prefix")
      require_condition(stdout_bytes(observation).start_with?(expected["stdout_prefix"]), "#{label}/#{implementation}: stdout prefix changed")
    end
    if expected.key?("event")
      classes = observation.fetch("stderr_events").map { |event| event.fetch("class") }
      require_condition(classes.include?(expected["event"]), "#{label}/#{implementation}: missing event #{expected['event']}; observed #{observation.fetch('stderr_events').inspect}")
    end
    if expected.key?("rule_ids")
      actual = observation.fetch("findings").map { |finding| finding.fetch("RuleID") }.uniq.sort
      require_condition(actual == expected["rule_ids"].uniq.sort, "#{label}/#{implementation}: rule IDs changed")
    end
    if expected.key?("secret")
      actual = observation.fetch("findings").map { |finding| finding.fetch("Secret") }
      require_condition(actual == [expected["secret"]], "#{label}/#{implementation}: redacted secret changed")
    end
    if expected.key?("report_sha256")
      require_condition(observation.dig("report", "sha256") == expected["report_sha256"], "#{label}/#{implementation}: preserved report changed")
    end
  end
  require_condition(go["exit"] == expected["go_exit"], "#{label}/go: disposition exit changed") if expected.key?("go_exit")
  require_condition(rust["exit"] == expected["rust_exit"], "#{label}/rust: disposition exit changed: expected #{expected['rust_exit'].inspect}, got #{rust['exit'].inspect}") if expected.key?("rust_exit")
  require_condition(rust["finding_count"] == expected["rust_findings"], "#{label}/rust: disposition findings changed") if expected.key?("rust_findings")
  if expected.key?("rust_report")
    state = rust["report"]&.fetch("state", "absent") || "absent"
    require_condition(state == expected["rust_report"], "#{label}/rust: disposition report state changed")
  end
  if expected.key?("go_report")
    state = go["report"]&.fetch("state", "absent") || "absent"
    require_condition(state == expected["go_report"], "#{label}/go: disposition report state changed")
  end
  if expected.key?("rust_report_sha256")
    require_condition(rust.dig("report", "sha256") == expected["rust_report_sha256"], "#{label}/rust: preserved report bytes changed")
  end
  if expected.key?("go_report_contains")
    require_condition(report_bytes(go)&.include?(expected["go_report_contains"]), "#{label}/go: expected template capability observation missing")
  end
  if expected.key?("go_discloses")
    require_condition(go["stderr_contains_disclosure_marker"] == expected["go_discloses"], "#{label}/go: disclosure observation changed")
  end
  if expected.key?("rust_discloses")
    require_condition(rust["stderr_contains_disclosure_marker"] == expected["rust_discloses"], "#{label}/rust: disclosure disposition changed")
  end
  if expected["child_reaped"]
    require_condition(rust["child_reaped"] == true, "#{label}/rust: source child was not reaped")
  end
end

def strip_versioned_help_differences(bytes)
  bytes.lines.reject { |line| versioned_usage_line?(line.strip) }
       .join.gsub("Gitleaks", "gitleaks").b
end

def validate_disposition!(case_id, spec, go, rust, axes)
  label = "#{case_id}/#{spec.fetch('id')}"
  disposition = spec["disposition"]
  if disposition.nil?
    differences = axes.reject { |_axis, equal| equal }.keys
    unless differences.empty?
      details = differences.to_h do |axis|
        key = axis == "stderr_events" ? "stderr_events" : axis
        [axis, { "go" => go[key], "rust" => rust[key] }]
      end
      raise "#{label}: unexplained Go/Rust differences: #{differences.join(', ')} #{JSON.generate(details)}"
    end
    return
  end
  raise "#{label}: unknown disposition #{disposition}" unless SAFE_DISPOSITIONS.key?(disposition) || OTHER_DISPOSITIONS.key?(disposition)
  case disposition
  when "CLI-DEFER-001"
    require_condition(go["exit"] == 0 && rust["exit"] == 0, "#{label}: help disposition exit changed")
    require_condition(stdout_bytes(go).include?("completion") && !stdout_bytes(rust).include?("completion"), "#{label}: Cobra omission changed")
    require_condition(stdout_bytes(go).include?("--diagnostics") && !stdout_bytes(rust).include?("--diagnostics"), "#{label}: diagnostics omission changed")
    require_condition(stdout_bytes(rust).include?("RUSTLEAKS_CONFIG") && !stdout_bytes(go).include?("RUSTLEAKS_CONFIG"), "#{label}: native config help changed")
    require_condition(stdout_bytes(rust).lines.count { |line| line.match?(/^\s+(?:-i, )?--gitleaks-ignore-path/) } == 2, "#{label}: native and legacy ignore-path help changed")
    require_condition(stdout_bytes(rust).lines.count { |line| line.match?(/^\s+--ignore-gitleaks-allow/) } == 2, "#{label}: native and legacy allow-marker help changed")
    require_condition(strip_versioned_help_differences(stdout_bytes(go)) == strip_versioned_help_differences(stdout_bytes(rust)), "#{label}: help differs beyond reviewed branding, native aliases, and Cobra omissions")
    require_condition(axes.reject { |axis, equal| equal || axis == "stdout" }.empty?, "#{label}: completion disposition hid another axis")
  when "CLI-SAFE-001"
    require_condition(rust["exit"] == 1, "#{label}: safe arity must exit 1")
    require_condition(rust.dig("report", "state") != "present", "#{label}: safe arity reached report writing")
    require_condition(rust["stderr_events"].any? { |event| event["class"] == "parser.arity" }, "#{label}: safe arity class missing")
  when "CLI-SAFE-002"
    require_condition(go["stderr_contains_disclosure_marker"] && !rust["stderr_contains_disclosure_marker"], "#{label}: disclosure disposition changed")
    require_condition(go["exit"] == 1 && rust["exit"] == 1, "#{label}: disclosure error exit changed")
  when "CLI-SAFE-003"
    require_condition(rust["exit"] == 1, "#{label}: terminal Rust source failure must exit 1")
    require_condition(rust.dig("report", "state") == "present", "#{label}: terminal Rust source failure must write report")
    require_condition(rust["stderr_events"].any? { |event| event["class"].start_with?("summary.partial") || event["class"] == "source.partial" }, "#{label}: terminal Rust partial class missing")
    if spec.dig("expected", "output_limit")
      limit_event = rust["stderr_events"].any? do |event|
        event["class"] == "source.git-error" &&
          Base64.strict_decode64(event.fetch("normalized_message_base64")).match?(/limit|ceiling/i)
      end
      require_condition(limit_event, "#{label}: terminal Rust output-limit diagnostic missing")
      require_condition(rust["child_reaped"] == true, "#{label}: output-limited Git child was not killed and waited")
    end
  when "CLI-SAFE-004"
    if spec.dig("expected", "open_failure")
      require_condition(go["exit"] == 1 && rust["exit"] == 1, "#{label}: report-open failure exit changed")
      require_condition(go.dig("report", "state") == "absent" && rust.dig("report", "state") == "absent", "#{label}: report-open failure created a report file")
      require_condition(go["stderr_events"].any? { |event| event["class"] == "report.error" && event["severity"] == "fatal" }, "#{label}: pinned Go report-open fatal changed")
      require_condition(rust["stderr_events"].any? { |event| event["class"] == "report.error" && event["severity"] == "error" }, "#{label}: Rust report-open error changed")
      require_condition(axes.reject { |axis, equal| equal || axis == "stderr_events" }.empty?, "#{label}: report-open disposition hid another axis")
    else
      require_condition(go.dig("report", "state") == "absent", "#{label}: pinned destructive observation changed")
      require_condition(rust.dig("report", "sha256") == sha("preserve-this-report"), "#{label}: Rust truncated pre-existing report")
    end
  when "CLI-SAFE-005"
    require_condition(rust["exit"] == 1, "#{label}: checked numeric refusal must exit 1")
    require_condition(rust.dig("report", "state") != "present", "#{label}: checked numeric refusal reached report writing")
  when "REPORT-SAFE-001"
    require_condition(report_bytes(go)&.include?("SYNTHETIC-TEMPLATE-VALUE"), "#{label}: Go helper observation changed")
    require_condition(rust.dig("report", "state") != "present" && rust["exit"] == 1, "#{label}: Rust safe-template refusal changed")
  else
    raise "#{label}: disposition lacks validator"
  end
end

def validate_variant!(case_id, spec, go, rust)
  validate_expected!(case_id, spec, go, rust)
  axes = comparison_axes(go, rust)
  validate_disposition!(case_id, spec, go, rust, axes)
  {
    "axes" => axes.transform_values { |equal| equal ? "equal" : "different" },
    "status" => spec["disposition"] ? "accepted-versioned-disposition" : "exact",
    "disposition" => spec["disposition"]
  }
end

def verify_hashes!
  revision = command_capture("git", "rev-parse", "HEAD", chdir: UPSTREAM).strip
  abort "upstream revision changed: #{revision}" unless revision == REVISION
  abort "default config changed" unless sha(UPSTREAM.join("config/gitleaks.toml").binread) == DEFAULT_SHA256
  GO_SOURCE_HASHES.each do |relative, expected|
    actual = sha(UPSTREAM.join(relative).binread)
    abort "upstream source #{relative} changed: expected #{expected}, got #{actual}" unless actual == expected
  end
  GO_TREE_HASHES.each do |relative, expected|
    actual = tree_sha256_at(UPSTREAM, relative)
    abort "upstream runtime tree #{relative} changed: expected #{expected}, got #{actual}" unless actual == expected
  end
  abort "Rust source pin set is empty" if RUST_SOURCE_HASHES.empty?
  RUST_SOURCE_HASHES.each do |relative, expected|
    actual = sha(ROOT.join(relative).binread)
    abort "Rust CLI source #{relative} changed: expected #{expected}, got #{actual}" unless actual == expected
  end
  RUST_TREE_HASHES.each do |relative, expected|
    actual = tree_sha256(relative)
    abort "Rust runtime tree #{relative} changed: expected #{expected}, got #{actual}" unless actual == expected
  end
end

def selected_runtime_provenance
  go = command_capture("go", "env", "GOVERSION", "GOOS", "GOARCH", chdir: UPSTREAM).lines.map(&:strip)
  abort "selected Go provenance incomplete" unless go.length == 3
  abort "selected Go toolchain is outside the pinned 1.25 family" unless go[0].match?(/\Ago1\.25(?:\.\d+)?\z/)
  rust = command_capture("rustc", "-vV", chdir: ROOT)
  rust_host = rust.lines.find { |line| line.start_with?("host: ") }&.sub("host: ", "")&.strip
  abort "selected Rust host provenance incomplete" unless rust_host&.match?(/\A[a-zA-Z0-9_.-]+\z/)
  {
    "go_version" => go[0], "go_platform" => "#{go[1]}/#{go[2]}",
    "rust_host" => rust_host, "ruby_platform" => RUBY_PLATFORM,
    "cleanup_strategy" => Gem.win_platform? ? "bounded-taskkill-tree" : "bounded-process-group"
  }
end

def runtime_provenance_valid?(candidate, selected)
  candidate == selected &&
    candidate.fetch("go_version").match?(/\Ago1\.25(?:\.\d+)?\z/) &&
    candidate.fetch("go_platform").match?(%r{\A[a-z0-9]+/[a-z0-9]+\z}) &&
    candidate.fetch("rust_host").match?(/\A[a-zA-Z0-9_.-]+\z/) &&
    %w[bounded-taskkill-tree bounded-process-group].include?(candidate.fetch("cleanup_strategy"))
end

def runtime_provenance_negative_controls!(selected)
  selected.each_key do |field|
    mutated = selected.merge(field => "invalid-provenance")
    abort "runtime provenance mutation accepted for #{field}" if runtime_provenance_valid?(mutated, selected)
  end
end

def build_binaries!(directory, provenance)
  go_binary = File.join(directory, Gem.win_platform? ? "gitleaks-go.exe" : "gitleaks-go")
  rust_target = File.join(directory, "rust-target")
  rust_binary = File.join(rust_target, "debug", Gem.win_platform? ? "rustleaks.exe" : "rustleaks")
  go_env = {
    "GOCACHE" => ENV.fetch("GOCACHE", File.join(Dir.tmpdir, "rustleaks-m11-cli-gocache")),
    "GOMODCACHE" => ENV.fetch("GOMODCACHE", File.join(Dir.tmpdir, "rustleaks-go-mod-cache")),
    "GOMEMLIMIT" => ENV.fetch("GOMEMLIMIT", "768MiB"), "GOMAXPROCS" => ENV.fetch("GOMAXPROCS", "2")
  }
  command_capture("go", "build", "-trimpath", "-buildvcs=true", "-ldflags",
                  "-X github.com/zricethezav/gitleaks/v8/version.Version=#{BUILD_VERSION}", "-o", go_binary, ".",
                  chdir: UPSTREAM, env: go_env, timeout: 300)
  command_capture("cargo", "build", "--locked", "--offline", "-p", "rustleaks-cli", chdir: ROOT,
                  env: { "CARGO_TARGET_DIR" => rust_target, "CARGO_TERM_COLOR" => "never" }, timeout: 900,
                  max_bytes: 32 * 1024 * 1024)
  [go_binary, rust_binary].each { |path| abort "missing built CLI #{path}" unless File.file?(path) }
  go_version = bounded_process([go_binary, "version"], chdir: directory, env: {}, stdin_bytes: "")
  rust_version = bounded_process([rust_binary, "version"], chdir: directory, env: {}, stdin_bytes: "")
  abort "Go build version mismatch" unless go_version["exit"] == 0 && go_version["stdout"] == "#{BUILD_VERSION}\n"
  abort "Rust build version mismatch" unless rust_version["exit"] == 0 && rust_version["stdout"] == "#{BUILD_VERSION}\n"
  module_info = command_capture("go", "version", "-m", go_binary, chdir: ROOT)
  abort "built Go binary lacks pinned VCS revision" unless module_info.include?("vcs.revision=#{REVISION}")
  current_provenance = selected_runtime_provenance
  abort "runtime provenance changed during build" unless runtime_provenance_valid?(current_provenance, provenance)
  [go_binary, rust_binary]
end

def outcome_lookup(outcomes, case_id, variant_id)
  row = outcomes.find { |candidate| candidate.fetch("id") == case_id } or raise "missing outcome #{case_id}"
  variant = row.fetch("variants").find { |candidate| candidate.fetch("id") == variant_id } or raise "missing outcome #{case_id}/#{variant_id}"
  [row, variant]
end

def spec_lookup(case_id, variant_id)
  row = CASES.find { |candidate| candidate.fetch("id") == case_id } or raise "missing request #{case_id}"
  variant = row.fetch("variants").find { |candidate| candidate.fetch("id") == variant_id } or raise "missing request #{case_id}/#{variant_id}"
  [row, variant]
end

def run_mutation_controls!(outcomes)
  controls = []
  apply = lambda do |id, case_id, variant_id, failure_class, &mutation|
    mutated = deep_copy(outcomes)
    _row, variant = outcome_lookup(mutated, case_id, variant_id)
    mutation.call(variant)
    _request_row, spec = spec_lookup(case_id, variant_id)
    begin
      validate_variant!(case_id, spec, variant.fetch("go"), variant.fetch("rust"))
    rescue RuntimeError => error
      controls << { "id" => id, "case_id" => case_id, "variant_id" => variant_id,
                    "expected_failure_class" => failure_class, "observed_rejection_sha256" => sha(error.message) }
      next
    end
    abort "mutation control #{id} was accepted"
  end

  apply.call("MUT-CLI-CONFIG-LEVEL-1-2-SWAP", "CLI-BB-005", "explicit-over-env", "selected-findings") do |variant|
    variant["rust"]["findings"] = [{ "RuleID" => "fixture-token" }]
    variant["rust"]["finding_count"] = 1
  end
  apply.call("MUT-CLI-REDACT-FOLLOWING-CONSUMED", "CLI-BB-018", "following-positional", "safe-arity") do |variant|
    _row, source = outcome_lookup(outcomes, "CLI-BB-018", "attached-20")
    variant["rust"] = deep_copy(source.fetch("rust"))
  end
  apply.call("MUT-CLI-DIR-SURPLUS-REACHES-SOURCE", "CLI-BB-004", "dir-surplus", "safe-arity") do |variant|
    variant["rust"]["report"] = deep_copy(variant.fetch("go").fetch("report"))
  end
  apply.call("MUT-CLI-FORMAT-ONLY-WRITES", "CLI-BB-020", "format-only", "dormant-report") do |variant|
    bytes = "[]\n"
    variant["rust"]["stdout_base64"] = b64(bytes)
    variant["rust"]["stdout_bytes"] = bytes.bytesize
    variant["rust"]["stdout_sha256"] = sha(bytes)
  end
  apply.call("MUT-CLI-STDOUT-INFERS-JSON", "CLI-BB-021", "missing-format", "stdout-format") do |variant|
    variant["rust"]["exit"] = 0
    bytes = "[]\n"
    variant["rust"]["stdout_base64"] = b64(bytes)
    variant["rust"]["stdout_bytes"] = bytes.bytesize
  end
  apply.call("MUT-CLI-TERMINAL-USES-LEAK-CODE", "CLI-BB-029", "invalid-repository", "terminal-exit") do |variant|
    variant["rust"]["exit"] = 7
  end
  apply.call("MUT-CLI-REPORT-AFTER-EXIT-SELECTION", "CLI-BB-029", "invalid-repository", "report-before-exit") do |variant|
    variant["rust"]["report"] = { "state" => "absent" }
  end
  apply.call("MUT-CLI-CONFIG-DISCLOSURE", "CLI-BB-009", "malformed-inline-marker", "non-disclosure") do |variant|
    variant["rust"]["stderr_contains_disclosure_marker"] = true
  end
  apply.call("MUT-CLI-FAILED-SETUP-TRUNCATES", "CLI-BB-024", "preexisting-later-setup-failure", "safe-preflight") do |variant|
    variant["rust"]["report"] = { "state" => "present", "bytes_base64" => b64(""), "bytes" => 0, "sha256" => sha("") }
  end
  apply.call("MUT-CLI-REPORT-OPEN-FAILURE-SUCCEEDS", "CLI-BB-024", "report-open-directory", "report-open-failure") do |variant|
    variant["rust"]["exit"] = 0
  end
  apply.call("MUT-CLI-HELP-FLAG-GRAMMAR-DROP", "CLI-BB-001", "help", "help-golden") do |variant|
    bytes = stdout_bytes(variant.fetch("rust")).lines.reject { |line| line.include?("--config") }.join
    variant["rust"]["stdout_base64"] = b64(bytes)
  end
  apply.call("MUT-CLI-VERSION-PERSISTENT-REJECT", "CLI-BB-001", "version-persistent-flag", "persistent-grammar") do |variant|
    variant["rust"]["exit"] = 1
  end
  apply.call("MUT-CLI-SHORT-ATTACHED-CONFIG-REJECT", "CLI-BB-032", "short-attached-config", "shorthand-grammar") do |variant|
    variant["rust"]["exit"] = 1
    variant["rust"]["report"] = { "state" => "absent" }
    variant["rust"]["findings"] = nil
    variant["rust"]["finding_count"] = nil
  end
  apply.call("MUT-CLI-UPPERCASE-TEMPLATE-ACCEPT", "CLI-BB-023", "raw-uppercase", "raw-template-grammar") do |variant|
    variant["rust"]["exit"] = 0
    variant["rust"]["report"] = { "state" => "present", "bytes_base64" => b64(""), "bytes" => 0, "sha256" => sha("") }
  end
  apply.call("MUT-CLI-REPORT-BYTE-FLIP", "CLI-BB-002", "dir", "report-bytes") do |variant|
    report = variant["rust"].fetch("report")
    bytes = Base64.strict_decode64(report.fetch("bytes_base64"))
    bytes.setbyte(0, bytes.getbyte(0) ^ 1)
    report["bytes_base64"] = b64(bytes)
    report["sha256"] = sha(bytes)
  end
  apply.call("MUT-CLI-COMPLETE-FINDING-DROP", "CLI-BB-033", "spaces-unicode", "complete-findings") do |variant|
    variant["rust"]["findings"].pop
    variant["rust"]["finding_count"] -= 1
  end
  apply.call("MUT-CLI-EXIT-NO-FINDING", "CLI-BB-019", "no-finding", "exit") do |variant|
    variant["rust"]["exit"] = 1
  end
  apply.call("MUT-CLI-STDERR-SEVERITY", "CLI-BB-019", "default", "stderr-severity") do |variant|
    event = variant["rust"]["stderr_events"].first or raise "missing stderr event for mutation"
    event["severity"] = event["severity"] == "warn" ? "info" : "warn"
  end
  apply.call("MUT-CLI-TIMEOUT-CHILD-NOT-REAPED", "CLI-BB-031", "source-timeout", "process-cleanup") do |variant|
    variant["rust"]["child_reaped"] = false
  end
  apply.call("MUT-CLI-OUTPUT-LIMIT-CHILD-NOT-REAPED", "CLI-BB-029", "child-stderr-output-limit", "process-cleanup") do |variant|
    variant["rust"]["child_reaped"] = false
  end
  controls
end

verify_hashes!
selected_provenance = selected_runtime_provenance
abort "selected runtime provenance invalid" unless runtime_provenance_valid?(selected_provenance, selected_provenance)
runtime_provenance_negative_controls!(selected_provenance)
upstream_before = command_capture("git", "status", "--porcelain=v1", "--untracked-files=all", chdir: UPSTREAM)

Dir.mktmpdir("rustleaks-cli-corpus-build-") do |build_directory|
  go_binary, rust_binary = build_binaries!(build_directory, selected_provenance)
  outcomes = CASES.map do |row|
    variants = row.fetch("variants").map do |spec|
      if (spec.dig("expected", "unix_only") && Gem.win_platform?) ||
         (spec.dig("expected", "linux_only") && !RUBY_PLATFORM.include?("linux"))
        next {
          "id" => spec.fetch("id"), "status" => "native-runtime-followup",
          "disposition" => "FOLLOWUP-NATIVE-M11-001"
        }
      end
      go = observe(go_binary, "go", row, spec, go_binary)
      rust = observe(rust_binary, "rust", row, spec, go_binary)
      comparison = validate_variant!(row.fetch("id"), spec, go, rust)
      { "id" => spec.fetch("id"), "go" => go, "rust" => rust, "comparison" => comparison }
    end
    { "protocol_version" => PROTOCOL_VERSION, "id" => row.fetch("id"), "title" => row.fetch("title"), "variants" => variants }
  end

  negative_controls = run_mutation_controls!(outcomes)
  abort "mutation-control accounting changed: #{negative_controls.length}" unless negative_controls.length == 20
  request_rows = CASES.map do |row|
    {
      "protocol_version" => PROTOCOL_VERSION, "id" => row.fetch("id"), "title" => row.fetch("title"),
      "variants" => row.fetch("variants").map { |spec| spec.reject { |key, _value| key == "expected" }.merge("expectation" => spec.fetch("expected")) }
    }
  end
  request_bytes = request_rows.map { |row| JSON.generate(row) + "\n" }.join
  outcome_bytes = outcomes.map { |row| JSON.generate(row) + "\n" }.join
  control_bytes = JSON.pretty_generate({ "controls" => negative_controls }) + "\n"
  variant_count = CASES.sum { |row| row.fetch("variants").length }
  exact_count = outcomes.sum { |row| row.fetch("variants").count { |variant| variant.dig("comparison", "status") == "exact" } }
  followup_count = outcomes.sum { |row| row.fetch("variants").count { |variant| variant["status"] == "native-runtime-followup" } }
  disposition_counts = CASES.flat_map { |row| row.fetch("variants") }.each_with_object(Hash.new(0)) do |variant, counts|
    counts[variant["disposition"]] += 1 if variant["disposition"]
  end
  disposition_counts["FOLLOWUP-NATIVE-M11-001"] += followup_count
  disposition_counts = disposition_counts.sort.to_h
  abort "variant accounting mismatch" unless exact_count + disposition_counts.values.sum == variant_count
  baseline_seed_processes = CASES.sum { |row| row.fetch("variants").count { |variant| variant["prepare"] == "valid-baseline" } } * 2
  build_probe_processes = 2
  paired_variants = variant_count - followup_count
  paired_processes = paired_variants * 2
  total_cli_processes = paired_processes + baseline_seed_processes + build_probe_processes
  finding_count = outcomes.sum do |row|
    row.fetch("variants").sum { |variant| (variant.dig("go", "finding_count") || 0) + (variant.dig("rust", "finding_count") || 0) }
  end
  report_byte_count = outcomes.sum do |row|
    row.fetch("variants").sum { |variant| (variant.dig("go", "report", "bytes") || 0) + (variant.dig("rust", "report", "bytes") || 0) }
  end
  manifest = {
    "corpus_version" => CORPUS_VERSION,
    "protocol_version" => PROTOCOL_VERSION,
    "upstream_revision" => REVISION,
    "default_config_sha256" => DEFAULT_SHA256,
    "build_version" => BUILD_VERSION,
    "case_count" => CASES.length,
    "variant_count" => variant_count,
    "paired_observation_pair_count" => paired_variants,
    "paired_observation_process_count" => paired_processes,
    "auxiliary_cli_process_count" => baseline_seed_processes + build_probe_processes,
    "fresh_cli_process_count" => total_cli_processes,
    "exact_variant_count" => exact_count,
    "versioned_disposition_variant_count" => disposition_counts.values.sum,
    "disposition_counts" => disposition_counts,
    "safe_dispositions" => SAFE_DISPOSITIONS,
    "other_dispositions" => OTHER_DISPOSITIONS,
    "complete_duplicate_preserving_finding_count_both_implementations" => finding_count,
    "raw_report_byte_count_both_implementations" => report_byte_count,
    "parser_usage_byte_count_both_implementations" => outcomes.sum do |row|
      row.fetch("variants").sum do |variant|
        (variant.dig("go", "stderr_usage", "bytes") || 0) +
          (variant.dig("rust", "stderr_usage", "bytes") || 0)
      end
    end,
    "stderr_event_count_both_implementations" => outcomes.sum { |row| row.fetch("variants").sum { |variant| (variant.dig("go", "stderr_events") || []).length + (variant.dig("rust", "stderr_events") || []).length } },
    "mutation_control_count" => negative_controls.length,
    "generator_sha256" => sha(ROOT.join("compat/generate_cli_corpus.rb").binread),
    "go_source_sha256" => GO_SOURCE_HASHES,
    "go_runtime_tree_sha256" => GO_TREE_HASHES,
    "rust_source_sha256" => RUST_SOURCE_HASHES,
    "rust_runtime_tree_sha256" => RUST_TREE_HASHES,
    "requests_sha256" => sha(request_bytes),
    "outcomes_sha256" => sha(outcome_bytes),
    "negative_controls_sha256" => sha(control_bytes),
    "runtime_provenance_policy" => "independently-validated-then-omitted",
    "native_runtime_evidence" => {
      "generation_host" => "validated-but-omitted",
      "linux" => "FOLLOWUP-NATIVE-M11-001",
      "windows" => "FOLLOWUP-NATIVE-M11-001"
    }
  }
  manifest_bytes = JSON.pretty_generate(manifest) + "\n"
  readme = <<~README
    # CLI compatibility corpus v1

    Generated by `ruby compat/generate_cli_corpus.rb` from pinned Go revision
    `#{REVISION}` and the Rust CLI source hashes in `manifest-v1.json`.

    The 34 JSONL rows map one-to-one to `CLI-BB-001..034`; their #{variant_count}
    variants include #{paired_variants} fresh Go/Rust observation pairs
    (#{paired_processes} bounded, isolated observation processes and #{total_cli_processes} CLI processes
    including build-version and baseline-seed probes). Stable stdout and raw report bytes are retained
    as base64. Stderr is reduced only to severity-preserving event classes and
    required counts/fields after ANSI, executable, duration, temporary-root,
    native-separator, and OS-error normalization. JSON reports additionally
    retain complete findings sorted canonically without deduplication.

    `CLI-SAFE-001..005` are explicit versioned dispositions. Completion omission
    and the reviewed safe-template capability boundary are separately versioned;
    no unexplained axis difference is accepted. Material mutation controls cover
    precedence swaps, redact grammar, surplus-argument source entry, dormant
    report flags, stdout inference, terminal exit/report ordering, disclosure,
    truncation and report-open failure, help/persistent/shorthand/template
    grammar, report bytes, duplicate-preserving findings, exit selection,
    stderr severity, and timeout/output-limit child cleanup.

    Selected Go version/platform, Rust host, Ruby platform, and cleanup strategy
    are independently queried and mutation-tested before being omitted from exact
    outcomes. This keeps committed artifacts host-independent. The generator has
    a bounded Windows `taskkill /T` cleanup path, but no native Linux or Windows
    runtime was available for this packet; those lanes remain the explicit
    nonblocking `FOLLOWUP-NATIVE-M11-001`.

    Regenerate with `ruby compat/generate_cli_corpus.rb`; verify byte-for-byte
    determinism with `ruby compat/generate_cli_corpus.rb --check`.
  README
  artifacts = {
    "requests-v1.jsonl" => request_bytes,
    "outcomes-v1.jsonl" => outcome_bytes,
    "negative-controls-v1.json" => control_bytes,
    "manifest-v1.json" => manifest_bytes,
    "README.md" => readme
  }

  # Catch a concurrently changed Rust/Go source tree before either write mode
  # or --check can accept observations built from a mixed implementation.
  verify_hashes!
  final_provenance = selected_runtime_provenance
  abort "runtime provenance changed during generation" unless runtime_provenance_valid?(final_provenance, selected_provenance)

  if OUTPUT_ROOT.directory?
    unexpected = OUTPUT_ROOT.children.map { |path| path.basename.to_s }.sort - artifacts.keys.sort
    abort "unexpected CLI corpus artifacts: #{unexpected.join(', ')}" unless unexpected.empty?
  end

  if CHECK
    artifacts.each do |name, expected|
      path = OUTPUT_ROOT.join(name)
      abort "missing #{path}" unless path.file?
      actual = path.binread
      next if actual == expected.b
      differing = [actual.bytesize, expected.bytesize].min.times.find { |index| actual.getbyte(index) != expected.getbyte(index) }
      abort "#{path} differs at byte #{differing || 'length'} (committed #{sha(actual)}, generated #{sha(expected)})"
    end
  else
    FileUtils.mkdir_p(OUTPUT_ROOT)
    artifacts.each { |name, bytes| OUTPUT_ROOT.join(name).binwrite(bytes) }
  end
  unexpected = OUTPUT_ROOT.children.map { |path| path.basename.to_s }.sort - artifacts.keys.sort
  abort "unexpected CLI corpus artifacts: #{unexpected.join(', ')}" unless unexpected.empty?

  puts "cli corpus: #{CASES.length} cases, #{variant_count} variants, #{total_cli_processes} fresh CLI processes (#{paired_variants} pairs/#{paired_processes} observation processes)"
  puts "accounting: #{exact_count} exact, #{disposition_counts.values.sum} versioned dispositions, #{negative_controls.length} mutation controls"
  puts "payload: #{finding_count} complete findings, #{report_byte_count} raw report bytes"
  puts "requests sha256: #{manifest.fetch('requests_sha256')}"
  puts "outcomes sha256: #{manifest.fetch('outcomes_sha256')}"
  puts "negative controls sha256: #{manifest.fetch('negative_controls_sha256')}"
  puts "manifest sha256: #{sha(manifest_bytes)}"
  puts "README sha256: #{sha(readme)}"
end

upstream_after = command_capture("git", "status", "--porcelain=v1", "--untracked-files=all", chdir: UPSTREAM)
abort "upstream checkout changed during CLI corpus generation" unless upstream_after == upstream_before
