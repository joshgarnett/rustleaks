#!/usr/bin/env ruby
# frozen_string_literal: true

# Verifies the committed, independent copy of the pinned upstream testdata.

require "digest"
require "find"
require "open3"
require "pathname"
require "tmpdir"

ROOT = Pathname(__dir__).parent
ORACLE = ROOT.parent.join("gitleaks")
SOURCE = ORACLE.join("testdata")
COPY = ROOT.join("compat/fixtures/upstream/testdata")
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
RECORD_SHA256 = "a29bcb807fc5466fb38bba0134fe6d5f41364e9efeae4980225cc21524fd4ed1"

class FixtureMismatch < StandardError; end

def capture(*command, chdir: ROOT)
  output, error, status = Open3.capture3(*command, chdir: chdir.to_s)
  abort "#{command.join(' ')} failed: #{error}" unless status.success?
  output
end

def entries(root)
  found = []
  Find.find(root.to_s) do |entry|
    path = Pathname(entry)
    next if path.directory?
    found << path.relative_path_from(root).to_s
  end
  found.sort
end

def symlink_target(path, label)
  raise FixtureMismatch, "#{label} symlink is flattened: #{path}" unless path.symlink?
  path.readlink.to_s
end

Dir.mktmpdir("rustleaks-fixture-self-test") do |directory|
  flattened = Pathname(directory).join("flattened-link")
  flattened.binwrite("../target")
  begin
    symlink_target(flattened, "negative self-test")
    abort "flattened-symlink negative self-test unexpectedly passed"
  rescue FixtureMismatch
    # Expected: link text in an ordinary file is not a symlink.
  end
end

abort "upstream revision mismatch" unless capture("git", "rev-parse", "HEAD", chdir: ORACLE).strip == REVISION
abort "fixture copy is missing: #{COPY}" unless COPY.directory?

source_paths = entries(SOURCE)
copy_paths = entries(COPY)
unless source_paths == copy_paths
  missing = source_paths - copy_paths
  extra = copy_paths - source_paths
  abort "fixture path mismatch; missing=#{missing.first || '<none>'}; extra=#{extra.first || '<none>'}"
end

git_modes = capture("git", "ls-files", "-s", "--", "testdata", chdir: ORACLE).lines.to_h do |line|
  metadata, path = line.chomp.split("\t", 2)
  [path.delete_prefix("testdata/"), metadata.split.first]
end
copy_git_modes = capture("git", "ls-files", "-s", "--", "compat/fixtures/upstream/testdata").lines.to_h do |line|
  metadata, path = line.chomp.split("\t", 2)
  [path.delete_prefix("compat/fixtures/upstream/testdata/"), metadata.split.first]
end
abort "fixture copy is not completely tracked in Git" unless copy_git_modes.keys.sort == copy_paths

regular_records = []
regular_count = 0
symlink_count = 0

source_paths.each do |relative|
  source = SOURCE.join(relative)
  copy = COPY.join(relative)
  mode = git_modes.fetch(relative)
  copy_mode = copy_git_modes.fetch(relative)
  abort "fixture Git mode mismatch for #{relative}: expected #{mode}, got #{copy_mode}" unless copy_mode == mode

  if mode == "120000"
    symlink_count += 1
    begin
      expected_target = symlink_target(source, "upstream")
      actual_target = symlink_target(copy, "copied")
    rescue FixtureMismatch => error
      abort error.message
    end
    abort "symlink target mismatch for #{relative}" unless actual_target == expected_target
    next
  end

  regular_count += 1
  expected_size = source.size
  actual_size = copy.size
  abort "fixture size mismatch for #{relative}" unless actual_size == expected_size

  expected_hash = Digest::SHA256.file(source).hexdigest
  actual_hash = Digest::SHA256.file(copy).hexdigest
  abort "fixture content mismatch for #{relative}" unless actual_hash == expected_hash

  expected_permissions = mode == "100755" ? 0o755 : 0o644
  unless Gem.win_platform?
    actual_permissions = copy.stat.mode & 0o777
    abort "fixture mode mismatch for #{relative}: expected #{expected_permissions.to_s(8)}, got #{actual_permissions.to_s(8)}" unless actual_permissions == expected_permissions
  end

  regular_records << "testdata/#{relative}\t#{expected_hash}\t#{expected_permissions.to_s(8)}\t#{expected_size}\n"
end

abort "expected 214 regular fixtures, got #{regular_count}" unless regular_count == 214
abort "expected one symlink fixture, got #{symlink_count}" unless symlink_count == 1

record_hash = Digest::SHA256.hexdigest(regular_records.join)
abort "fixture record digest mismatch: expected #{RECORD_SHA256}, got #{record_hash}" unless record_hash == RECORD_SHA256

warn "verified #{regular_count} regular fixtures and #{symlink_count} symlink at upstream #{REVISION}"
