#!/usr/bin/env ruby
# frozen_string_literal: true

# Freeze pinned-Go reader, file, directory, symlink, and archive behavior. Each
# request runs in a fresh, deadline-bounded oracle process.

require "base64"
require "digest"
require "fileutils"
require "json"
require "open3"
require "pathname"
require "rubygems/package"
require "stringio"
require "timeout"
require "tmpdir"
require "zlib"

ROOT = Pathname(__dir__).parent
UPSTREAM = ROOT.parent.join("gitleaks")
ORACLE = ROOT.join("crates/rustleaks-compat/oracle")
OUTPUT_ROOT = Pathname(ENV.fetch("RUSTLEAKS_SOURCE_CORPUS_OUTPUT", ROOT.join("compat/source-corpus").to_s))
REVISION = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
DEFAULT_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
PROTOCOL_VERSION = 1
BEHAVIORS = (1..30).map { |number| format("SRC-%03d", number) }.freeze
BEHAVIOR_DEFINITIONS = {
  "SRC-001" => "A synchronous source visits fragment-or-issue events; callback stop/errors and terminal source errors remain distinct.",
  "SRC-002" => "File fragments own exact bytes and metadata; they never expose the Go reusable-buffer alias.",
  "SRC-003" => "Nil file buffers select 100,000 bytes; custom positive sizes are exact; the compatibility shim preserves the zero-buffer empty-success quirk.",
  "SRC-004" => "A suffix already containing two LFs separated only by SP/TAB/CR/LF ends a chunk without read-ahead.",
  "SRC-005" => "Unsafe boundaries append bytewise through the second LF or exactly 25,000 bytes, with no byte pushback.",
  "SRC-006" => "EOF, n>0+EOF, n>0+nil, n>0+error, n==0+error, and read-ahead errors preserve the pinned fragment/error outcomes.",
  "SRC-007" => "File fragments start at one plus prior LF count; only byte 0x0a advances the next start line.",
  "SRC-008" => "MIME matching uses the original read before extension whenever prior LF count is zero and skips only h2non/filetype-v1.1.3 application/*.",
  "SRC-009" => "Reader compatibility adapters preserve count/error/finalization outcomes without requiring channels, goroutines, or an async runtime.",
  "SRC-010" => "Directory discovery follows host WalkDir lexical traversal semantics for root file, root directory, and nested entries.",
  "SRC-011" => "Empty files are skipped; positive maximum file size is an exact strict-greater-than byte gate and equality is scanned.",
  "SRC-012" => "Missing, unreadable, and metadata-failing paths are skipped/diagnosed at the pinned stage; untrusted filesystem states never panic.",
  "SRC-013" => "Global path allowlists prune directories early and skip discovered files/aliases, with Windows raw-plus-slash checks.",
  "SRC-014" => "Symlink entries are skipped when following is disabled and directory symlinks are never traversed.",
  "SRC-015" => "Followed file symlinks scan the resolved target while reporting target FilePath and discovered alias SymlinkFile.",
  "SRC-016" => "Chained, dangling, looping, and escaping symlinks terminate safely as scan issues; no target is scanned twice by implicit directory following.",
  "SRC-017" => "Physical paths stay as PathBuf; logical fragment paths reproduce host Go cleaning and Windows slash/original dual fields without Unicode normalization.",
  "SRC-018" => "Archive identification is case-insensitive name-only with the pinned format/substring profile; magic alone does not activate archive handling.",
  "SRC-019" => "Each recognized extractor/decompressor layer consumes one depth; zero disables, and a compressed tar is one layer.",
  "SRC-020" => "Extractors ignore directories, preserve backend entry order, clean entry names with host filepath semantics, and recurse synchronously.",
  "SRC-021" => "Observable inner paths are slash-normalized outer layers joined to the current entry with literal !; fingerprints use that full path.",
  "SRC-022" => "Registered single-stream decompressors retain the outer filename while scanning decoded bytes; compressed TARs consume one archive layer.",
  "SRC-023" => "First-level inner allowlist checks use the cleaned inner name; nested child config non-propagation and later full-path engine checks are frozen.",
  "SRC-024" => "Zip/7z work from seekable files and bounded safe spool storage for non-seekable nested streams; temporary artifacts are always reclaimed.",
  "SRC-025" => "Corrupt/member-open/decompress/read errors preserve direct-file versus directory outcome classes while Rust surfaces structured issues.",
  "SRC-026" => "Directory parallelism is caller-selected and bounded; result order is unspecified but the complete finding multiset and duplicates are invariant.",
  "SRC-027" => "Cancellation is checked during traversal, scheduling, chunk loops, archive enumeration/decoding, and runner detection; cancellation never leaves unjoined workers.",
  "SRC-028" => "Source running scans each successful fragment through immutable Engine, then policy-binds and merges owned ScanSession batches so fingerprints/ignore/baseline behavior is unchanged.",
  "SRC-029" => "All lengths, line counts, depths, entry counts, expansion totals, and spool sizes use checked arithmetic and configurable limits with structured limit outcomes.",
  "SRC-030" => "rustleaks-sources and its archive feature are safe, synchronous, native macOS/Linux/Windows Rust and keep all source/archive/scheduler dependencies out of rustleaks-core."
}.freeze
UPSTREAM_IDENTITIES = {
  "TM-0098" => "TestDetectReader",
  "TM-0099" => "TestDetectReader/Test_case_-_Reader_returns_n_>_0_bytes_and_io.EOF_error",
  "TM-0100" => "TestDetectReader/Test_case_-_Reader_returns_n_>_0_bytes_and_nil_error",
  "TM-0116" => "TestDetectWithArchives",
  "TM-0117" => "TestDetectWithArchives/archives_-_../testdata/archives/files",
  "TM-0118" => "TestDetectWithArchives/archives_-_../testdata/archives/files.7z",
  "TM-0119" => "TestDetectWithArchives/archives_-_../testdata/archives/files.tar",
  "TM-0120" => "TestDetectWithArchives/archives_-_../testdata/archives/files.tar.xz",
  "TM-0121" => "TestDetectWithArchives/archives_-_../testdata/archives/files.tar.zst",
  "TM-0122" => "TestDetectWithArchives/archives_-_../testdata/archives/files.zip",
  "TM-0123" => "TestDetectWithArchives/archives_-_../testdata/archives/nested.tar.gz",
  "TM-0124" => "TestDetectWithArchives/archives_-_../testdata/archives/nested.tar.gz#01",
  "TM-0125" => "TestDetectWithArchives/archives_-_../testdata/archives/this-path-does-not-exist",
  "TM-0126" => "TestDetectWithSymlinks",
  "TM-0128" => "TestFromFiles",
  "TM-0129" => "TestFromFiles/generic_-_../testdata/repos/nogit/.env.prod",
  "TM-0130" => "TestFromFiles/simple_-_../testdata/repos/nogit",
  "TM-0131" => "TestFromFiles/simple_-_../testdata/repos/nogit/api.go",
  "TM-0132" => "TestFromFiles/simple_-_../testdata/repos/nogit/main.go",
  "TM-0147" => "TestStreamDetectReader",
  "TM-0148" => "TestStreamDetectReader/Empty_reader",
  "TM-0149" => "TestStreamDetectReader/Mock_reader_with_EOF",
  "TM-0150" => "TestStreamDetectReader/Multiple_secrets_with_larger_buffer",
  "TM-0151" => "TestStreamDetectReader/Reader_returns_error",
  "TM-0152" => "TestStreamDetectReader/Reader_returns_error_after_first_read",
  "TM-0153" => "TestStreamDetectReader/Secret_split_across_boundary",
  "TM-0154" => "TestStreamDetectReader/Single_secret_streaming",
  "TM-0269" => "Test_readUntilSafeBoundary",
  "TM-0270" => "Test_readUntilSafeBoundary/no_safe_split",
  "TM-0271" => "Test_readUntilSafeBoundary/safe_original_split_-_CRLF",
  "TM-0272" => "Test_readUntilSafeBoundary/safe_original_split_-_LF",
  "TM-0273" => "Test_readUntilSafeBoundary/safe_split_-_CRLF",
  "TM-0274" => "Test_readUntilSafeBoundary/safe_split_-_LF",
  "TM-0275" => "Test_readUntilSafeBoundary/safe_split_-_blank_line"
}.freeze
SOURCE_HASHES = {
  "sources/common.go" => "eb0d687e7d7565058b9320cf372b2250e9de774ed78be7b2f166077901704147",
  "sources/common_test.go" => "e51ccb8147787134c8d5576a83e06d2e146e0fa28b606e1d4ec9d9d1d4bb0dac",
  "sources/source.go" => "c8d049dbe91f539102f4f31e734c2dd8947e5b478762fd6f7003796c18370b62",
  "sources/fragment.go" => "cc691fcc9fbf7af6eaeafece9e6c3e7467204ab9c760648a490a6a922a21de0b",
  "sources/file.go" => "c9d1d8be4e5bbac08c0df774882f33060572ed8d720e7f34360f0a5164c822fa",
  "sources/files.go" => "fab6f4357a87cd67490707f37ac85746938a88d9c1c3601a91270eb85e4c5a4d",
  "detect/reader.go" => "369875f6b8828f1647005740fd6c762e0f7700113a5dcdf049c48b3030854234",
  "detect/reader_test.go" => "e53b2f25936c532b01d6abaa2906469cc4cec75d2f26c74759195fff66a04831",
  "detect/files.go" => "dbf6443db44cb962e0193698f1f2f11206e7e9c8621bad9873aacc0cb421b0af",
  "detect/detect_test.go" => "191e7178827d790ae7c72f7b17824e3d368fe66b263fb12a9b8f3ede225124d3"
}.freeze

CHECK = ARGV.delete("--check")
abort "usage: #{$PROGRAM_NAME} [--check]" unless ARGV.empty?

GO_ENV = {
  "GOCACHE" => ENV.fetch("GOCACHE", File.join(Dir.tmpdir, "rustleaks-m9-oracle-gocache")),
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
  output = +"".b
  error = +"".b
  status = nil
  Open3.popen3(GO_ENV, binary, "--source", chdir: ORACLE.to_s, pgroup: true) do |stdin, stdout, stderr, wait|
    stdin.write(JSON.generate(request) + "\n")
    stdin.close
    begin
      Timeout.timeout(15) do
        readers = [stdout, stderr]
        until readers.empty?
          ready = IO.select(readers, nil, nil, 0.25)
          next if ready.nil?
          ready.first.each do |stream|
            begin
              chunk = stream.read_nonblock(16 * 1024)
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
  abort "#{request.fetch('id')}: oracle emitted #{lines.length} lines" unless lines.length == 1
  JSON.parse(lines.first)
end

def request(id, operation:, behaviors:, tests: [], **fields)
  {"protocol_version" => PROTOCOL_VERSION, "id" => id, "behavior_ids" => behaviors,
   "test_case_ids" => tests, "operation" => operation}.merge(fields.transform_keys(&:to_s))
end

def tar_bytes(entries)
  output = StringIO.new("".b)
  original_epoch = ENV["SOURCE_DATE_EPOCH"]
  ENV["SOURCE_DATE_EPOCH"] = "0"
  begin
    Gem::Package::TarWriter.new(output) do |tar|
      entries.each do |name, content|
        tar.add_file_simple(name, 0o644, content.bytesize) { |file| file.write(content) }
      end
    end
  ensure
    original_epoch.nil? ? ENV.delete("SOURCE_DATE_EPOCH") : ENV["SOURCE_DATE_EPOCH"] = original_epoch
  end
  output.string
end

def rar_vint(value)
  output = +"".b
  loop do
    byte = value & 0x7f
    value >>= 7
    byte |= 0x80 unless value.zero?
    output << byte
    return output if value.zero?
  end
end

def rar5_block(kind, flags, data, payload = "".b)
  header = rar_vint(kind) + rar_vint(flags)
  header << rar_vint(payload.bytesize) unless (flags & 2).zero?
  header << data.b
  checked = rar_vint(header.bytesize) + header
  [Zlib.crc32(checked)].pack("V") + checked + payload.b
end

def rar5_archive(name, packed, unpacked, compression)
  file = rar_vint(4) + rar_vint(unpacked.bytesize) + rar_vint(0)
  file << [Zlib.crc32(unpacked)].pack("V")
  file << rar_vint(compression) << rar_vint(1) << rar_vint(name.bytesize) << name.b
  "Rar!\x1a\x07\x01\x00".b + rar5_block(1, 0, "\x00".b) +
    rar5_block(2, 2, file, packed) + rar5_block(5, 0, "\x00".b)
end

def rar15_block(kind, flags, data, payload = "".b)
  header = [kind, flags, 7 + data.bytesize].pack("Cvv") + data.b
  [Zlib.crc32(header) & 0xffff].pack("v") + header + payload.b
end

def rar2_archive(name, packed, unpacked)
  main = rar15_block(0x73, 0, [0, 0].pack("vV"))
  file = [packed.bytesize, unpacked.bytesize, 3, Zlib.crc32(unpacked), 0, 20, 0x33,
          name.bytesize, 0x20].pack("VVCVVC2vV") + name.b
  "Rar!\x1a\x07\x00".b + main + rar15_block(0x74, 0x8000, file, packed)
end

abort "upstream revision changed" unless capture("git", "rev-parse", "HEAD", chdir: UPSTREAM).strip == REVISION
abort "default config changed" unless sha(UPSTREAM.join("config/gitleaks.toml").binread) == DEFAULT_SHA256
upstream_status_before = capture("git", "status", "--short", chdir: UPSTREAM)
abort "upstream has tracked changes" unless upstream_status_before.lines.all? { |line| line.start_with?("?? ") }
SOURCE_HASHES.each { |path, expected| abort "#{path} changed" unless sha(UPSTREAM.join(path).binread) == expected }
manifest_text = ROOT.join("compat/test-manifest.toml").binread
UPSTREAM_IDENTITIES.each do |id, name|
  identity = /\[\[case\]\]\nid = #{Regexp.escape(id.to_json)}\npackage = "[^"]+"\ngo_name = #{Regexp.escape(name.to_json)}\n/
  abort "manifest identity changed for #{id}:#{name}" unless manifest_text.match?(identity)
end

fixtures = %w[files.7z files.tar files.tar.xz files.tar.zst files.zip nested.tar.gz]
fixture_hashes = fixtures.to_h { |name| ["testdata/archives/#{name}", sha(ROOT.join("compat/fixtures/upstream/testdata/archives", name).binread)] }
sevenzip_fixture_names = %w[copy delta lzma deflate bzip2 brotli lz4 zstd bcj bcj2 arm ppc sparc]
sevenzip_fixture_root = ROOT.join("compat/fixtures/oracle/bodgit-sevenzip-v1.6.1")
sevenzip_fixture_names.each do |name|
  fixture_hashes["bodgit-sevenzip-v1.6.1/#{name}.7z"] = sha(sevenzip_fixture_root.join("#{name}.7z").binread)
end
rar_fixture_names = %w[
  testfile.rar3.rar
  testfile.rar3.solid.rar
  testfile.rar3.cbr
  testfile.rar3.solid.cbr
  testfile.rar5.rar
  testfile.rar5.solid.rar
  testfile.rar5.cbr
  testfile.rar5.solid.cbr
].freeze
rar_expected_names = %w[testfile.txt testfile.jpg testfile.png].freeze
rar_fixture_root = ROOT.join("compat/fixtures/oracle/rar-test-files-16b785c")
rar_fixture_names.each do |name|
  fixture_hashes["rar-test-files-16b785c/#{name}"] = sha(rar_fixture_root.join(name).binread)
end
rar_expected_names.each do |name|
  fixture_hashes["rar-test-files-16b785c/expected/#{name}"] = sha(rar_fixture_root.join("expected", name).binread)
end
multivolume_rar_root = ROOT.join("compat/fixtures/oracle/mholt-archives-v0.1.5")
%w[test.part01.rar test.part02.rar].each do |name|
  fixture_hashes["mholt-archives-v0.1.5/#{name}"] = sha(multivolume_rar_root.join(name).binread)
end

requests = []
boundary_cases = [
  ["boundary-original-lf", "abc\n\ndefghijklmnop\n\nqrstuvwxyz", "TM-0272"],
  ["boundary-original-crlf", "a\r\n\r\nbcdefghijklmnop\n", "TM-0271"],
  ["boundary-lf", "abcdefg\nhijklmnop\n\nqrstuvwxyz", "TM-0274"],
  ["boundary-crlf", "abcdefg\r\nhijklmnop\r\n\r\nqrstuvwxyz", "TM-0273"],
  ["boundary-blank", "abcdefg\nhijklmnop\n\t  \t\nqrstuvwxyz", "TM-0275"],
  ["boundary-none", "abcdefg\nhijklmnopqrstuvwxyz", "TM-0270"]
]
boundary_cases.each do |id, content, test|
  behaviors = if %w[boundary-original-lf boundary-original-crlf].include?(id)
                %w[SRC-004]
              elsif id == "boundary-none"
                %w[SRC-005]
              else
                %w[SRC-004 SRC-005]
              end
  requests << request(id, operation: "boundary", behaviors: behaviors, tests: ["TM-0269", test],
                      content_base64: b64(content), buffer_size: 5, max_peek_size: 20)
end
requests << request("boundary-empty", operation: "boundary", behaviors: %w[SRC-005], content_base64: b64(""), buffer_size: 0, max_peek_size: 25_000)
requests << request("boundary-25000-ceiling", operation: "boundary", behaviors: %w[SRC-005],
                    content_base64: b64("a" * 100_000 + "b" * 25_001), buffer_size: 100_000, max_peek_size: 25_000)

secret = "AKIAIRYLJVKMPEGZMPJS"
requests << request("detect-reader-nil", operation: "reader", behaviors: %w[SRC-003 SRC-006 SRC-009], tests: %w[TM-0098 TM-0100],
                    content_base64: b64(secret), buffer_size: 10)
requests << request("detect-reader-eof", operation: "reader", behaviors: %w[SRC-003 SRC-006 SRC-009], tests: %w[TM-0098 TM-0099],
                    reader_schedule: [{"data_base64" => b64(secret), "error" => "eof"}], buffer_size: 10)
stream_cases = [
  ["stream-single", [{"data_base64" => b64(secret)}], 10, "TM-0154"],
  ["stream-empty", [], 10, "TM-0148"],
  ["stream-error", [{"data_base64" => b64(""), "error" => "error"}], 10, "TM-0151"],
  ["stream-multiple", [{"data_base64" => b64(secret + "\n" + secret)}], 20, "TM-0150"],
  ["stream-eof", [{"data_base64" => b64(secret), "error" => "eof"}], 10, "TM-0149"],
  ["stream-split", [{"data_base64" => b64(secret[0, 10])}, {"data_base64" => b64(secret[10..])}], 1, "TM-0153"],
  ["stream-late-error", [{"data_base64" => b64("blah" * 1000 + secret), "error" => "error"}], 1, "TM-0152"]
]
stream_cases.each do |id, schedule, size, test|
  behaviors = %w[SRC-003 SRC-006 SRC-009]
  behaviors << "SRC-007" if id == "stream-multiple"
  behaviors << "SRC-005" if id == "stream-late-error"
  requests << request(id, operation: "reader", behaviors: behaviors, tests: ["TM-0147", test],
                      reader_schedule: schedule, buffer_size: size, stream: true)
end

requests << request("file-invalid-bytes", operation: "file", behaviors: %w[SRC-002 SRC-007 SRC-017],
                    content_base64: b64("\xffalpha\n\xffbeta"), path_base64: b64("src/\xff.bin"), buffer_size: 7)
requests << request("file-data-plus-error", operation: "file", behaviors: %w[SRC-006],
                    reader_schedule: [{"data_base64" => b64("visible"), "error" => "error"}], logical_path: "error.txt", buffer_size: 100)
requests << request("file-empty", operation: "file", behaviors: %w[SRC-006 SRC-011], content_base64: b64(""), logical_path: "empty.txt")
requests << request("file-path-nfc", operation: "file", behaviors: %w[SRC-017 SRC-030],
                    content_base64: b64("nfc"), logical_path: "paths/caf\u00e9.txt")
requests << request("file-path-nfd", operation: "file", behaviors: %w[SRC-017 SRC-030],
                    content_base64: b64("nfd"), logical_path: "paths/cafe\u0301.txt")
requests << request("file-path-windows-mixed-drive", operation: "file", behaviors: %w[SRC-017 SRC-030],
                    content_base64: b64("mixed"), logical_path: "C:\\work/mixed\\secret.txt")
requests << request("file-path-windows-unc", operation: "file", behaviors: %w[SRC-017 SRC-030],
                    content_base64: b64("unc"), logical_path: "\\\\server\\share\\dir\\secret.txt")
requests << request("file-path-windows-extended", operation: "file", behaviors: %w[SRC-017 SRC-030],
                    content_base64: b64("extended"), logical_path: "\\\\?\\C:\\very\\long\\secret.txt")
requests << request("file-mime-skip", operation: "file", behaviors: %w[SRC-008], content_base64: b64("%PDF-1.4\n%synthetic\n"), logical_path: "document.pdf")
requests << request("file-canceled", operation: "file", behaviors: %w[SRC-027], content_base64: b64("content"), logical_path: "cancel.txt", cancel_before: true)
requests << request("file-yield-error", operation: "file", behaviors: %w[SRC-001], content_base64: b64("one\n\ntwo"),
                    logical_path: "yield.txt", buffer_size: 3, yield_error_after: 1)
requests << request("file-malformed-archive", operation: "file", behaviors: %w[SRC-018 SRC-025], content_base64: b64("not really an archive"), logical_path: "broken.zip")
requests << request("file-default-buffer", operation: "file", behaviors: %w[SRC-003 SRC-005 SRC-007],
                    content_base64: b64("a" * 100_000 + "\n\nb"), logical_path: "default.txt")
requests << request("file-custom-buffer", operation: "file", behaviors: %w[SRC-003 SRC-004 SRC-007],
                    content_base64: b64("abc\n\ndef"), logical_path: "custom.txt", buffer_size: 5)
requests << request("file-lf-line-count", operation: "file", behaviors: %w[SRC-007],
                    content_base64: b64("a\r\n\nb"), logical_path: "lines.txt", buffer_size: 4)
requests << request("file-repeat-mime-before-first-lf", operation: "file", behaviors: %w[SRC-008],
                    content_base64: b64("a" * 125_000 + "%PDF-1.4\n%synthetic\n"), logical_path: "late.bin", buffer_size: 100_000)

archive_tests = {"files.7z" => "TM-0118", "files.tar" => "TM-0119", "files.tar.xz" => "TM-0120", "files.tar.zst" => "TM-0121", "files.zip" => "TM-0122"}
archive_tests.each do |name, test|
  behaviors = %w[SRC-018 SRC-019 SRC-020 SRC-021]
  behaviors << "SRC-022" if name.include?(".xz") || name.include?(".zst")
  behaviors << "SRC-024" if name.end_with?(".zip") || name.end_with?(".7z")
  requests << request("archive-#{name.tr('.', '-')}", operation: "file", behaviors: behaviors, tests: ["TM-0116", test],
                      fixture_path: "testdata/archives/#{name}", logical_path: "../testdata/archives/#{name}", config_fixture: "archives.toml",
                      max_archive_depth: 8, detect: true)
end
requests << request("archive-uppercase-name", operation: "file", behaviors: %w[SRC-018 SRC-020 SRC-021],
                    fixture_path: "testdata/archives/files.zip", logical_path: "archives/FILES.ZIP", max_archive_depth: 8)
requests << request("archive-substring-name", operation: "file", behaviors: %w[SRC-018 SRC-020 SRC-021],
                    fixture_path: "testdata/archives/files.zip", logical_path: "archives/files.zip.backup", max_archive_depth: 8)
requests << request("archive-windows-outer-path", operation: "file", behaviors: %w[SRC-017 SRC-021 SRC-030],
                    fixture_path: "testdata/archives/files.zip", logical_path: "C:\\work/mixed\\files.zip", max_archive_depth: 8)
requests << request("archive-magic-without-name", operation: "file", behaviors: %w[SRC-008 SRC-018],
                    fixture_path: "testdata/archives/files.zip", logical_path: "archives/blob", max_archive_depth: 8)
%w[main.go.gz main.go.xz main.go.zst].each do |name|
  requests << request("decompress-#{name.tr('.', '-')}", operation: "file", behaviors: %w[SRC-018 SRC-019 SRC-022],
                      fixture_path: "testdata/archives/files/#{name}", logical_path: "archives/files/#{name}", config_fixture: "archives.toml",
                      max_archive_depth: 8, detect: true)
end
safe_codec_streams = {
  "br" => "iw2AcG9ydGFibGUgc2FmZSBjb2RlYyBwYXlsb2FkCgM=",
  "bz2" => "QlpoNjFBWSZTWV+QhkgAAAvRgAAQQAA/BNwgIAAkH7VP2lR/lPJCmAABmcijINDrVvbaMVafC7kinChIL8hDJAA=",
  "lz4" => "BCJNGGRwuRwAAIBwb3J0YWJsZSBzYWZlIGNvZGVjIHBheWxvYWQKAAAAAOHkpaM=",
  "mz" => "/wYAAE1pbkx6CwEgAACuxSMacG9ydGFibGUgc2FmZSBjb2RlYyBwYXlsb2FkCiABAAAc",
  "s2" => "/wYAAFMyc1R3TwEgAACuxSMacG9ydGFibGUgc2FmZSBjb2RlYyBwYXlsb2FkCg==",
  "sz" => "/wYAAHNOYVBwWQEgAACuxSMacG9ydGFibGUgc2FmZSBjb2RlYyBwYXlsb2FkCg=="
}.freeze
safe_codec_tars = {
  "br" => "i/8DAICqqqrqH89+Oenh5MAGZu5+O6ubqZ8MwAzM1Bzc/++qf8+91T2juryN4a54sbCwsLGxqpcZ1cGHDz8Gg8E4zmRVDQaDwWAwmEOdEakojcJhoZ1k7wnufOt6tXv/dZuHdNMkeU7TMeQk7kJOxvsj+5kNQx4vJdl6SNdsptfZ6yHpfSRlvy3gT+Hmm/bt6PW9tnLWTyvztrS57PW/bnW5FeOnz/12z2Y=",
  "bz2" => "QlpoNjFBWSZTWQ/P/nYAAEZbkcqQQAFvhACAfwTfYAQAAgAACCAAahEpTyaVVP/1VQ//0qqMf/qqn/tVUP/1VQH/hUY1NVR/71VUD/9Aqp/6qj/1U/9NVT/aVS+5+9S9gTvdsQnXPAkHymtQriLWC5pmLqOiYreP1/fLaRYb0Zvkm1wS8eWRNiEJsh8DdqMr8LuSKcKEgH5/87A=",
  "lz4" => "BCJNGGRwuZUAAACvdmFsdWUudHh0AAEAR/IBMDAwMDY0NAAwMDAwMDAwAAcABQgARjAwMzQMAM8wMAAwMTEwNTcAIDCTAEcGAgCFdXN0YXIAMDARAA8CACQDwQAEyQAPRQAjDwIAX/8NcG9ydGFibGUgc2FmZSBjb2RlYyBwYXlsb2FkCo0AXg8CAP//////VgACALAAAAAAAAAAAAAAAAAAAABUNE6+",
  "mz" => "/wYAAE1pbkx6CwJnAABvPTLTgBBIdmFsdWUudHh0AOw8ADAUEDYwMMUBADCMGDAwMzTZAsEFODExMDQ3ACAwuRI9AEAwdXN0YXIAMP0aLzE3PQCV4HBvcnRhYmxlIHNhZmUgY29kZWMgcGF5bG9hZAoA9MUFIAIAAIAQ",
  "s2" => "/wYAAFMyc1R3TwCJAABvPTLTgBAkdmFsdWUudHh0ABEBFQBKIDAwMDA2MDAAMAkAAAAJBxUQEDAwMzQACRM4MDAwMDAAMDExMDQ3ACAwEZMVAEoZWhh1c3RhcgAwEWwVADEVvQkJGWERChUAjmxwb3J0YWJsZSBzYWZlIGNvZGVjIHBheWxvYWQKEbsVAI8RnRkAOAQAAA==",
  "sz" => "/wYAAHNOYVBwWQDSAABvPTLTgBAkdmFsdWUudHh0AO4BAHYBACAwMDAwNjAwADAJAQAACQcVEBAwMDM0AAkTODAwMDAwADAxMTA0NwAgMO6TAHaTABlaGHVzdGFyADDubAAFbBW9CQkZYe4KAO4KAJYKAGxwb3J0YWJsZSBzYWZlIGNvZGVjIHBheWxvYWQK7rsA7rsAmrsA7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0A7p0Abp0AAAA="
}.freeze
safe_codec_streams.each do |extension, content|
  requests << request("decompress-safe-#{extension}", operation: "file", behaviors: %w[SRC-018 SRC-019 SRC-022 SRC-030],
                      content_base64: content, logical_path: "portable.#{extension}", max_archive_depth: 1)
  requests << request("decompress-safe-tar-#{extension}", operation: "file", behaviors: %w[SRC-018 SRC-019 SRC-020 SRC-022 SRC-030],
                      content_base64: safe_codec_tars.fetch(extension), logical_path: "portable.tar.#{extension}", max_archive_depth: 1)
end
sevenzip_fixture_names.each do |name|
  requests << request("archive-7z-#{name}", operation: "file",
                      behaviors: %w[SRC-018 SRC-019 SRC-020 SRC-021 SRC-022 SRC-030],
                      content_base64: b64(sevenzip_fixture_root.join("#{name}.7z").binread),
                      logical_path: "portable-#{name}.7z", max_archive_depth: 1)
end
rar_stored_payload = "portable safe RAR payload\n".b
rar_stored = rar5_archive("value.txt", rar_stored_payload, rar_stored_payload, 0)
rar_compressed_payload = ("A" * 200 + "\n").b
rar_compressed = rar5_archive(
  "compressed.txt",
  [0xc0, 0x97, 0x0d, 0x02, 0x3f, 0xd3, 0x1f, 0xf1, 0x5e, 0x7f, 0x49, 0x81, 0xa9, 0xbf, 0x15, 0x00].pack("C*"),
  rar_compressed_payload,
  3 << 7
)
requests << request("archive-rar5-stored", operation: "file", behaviors: %w[SRC-018 SRC-019 SRC-020 SRC-021 SRC-022 SRC-030],
                    content_base64: b64(rar_stored), logical_path: "portable-stored.rar", max_archive_depth: 1)
requests << request("archive-rar5-compressed", operation: "file", behaviors: %w[SRC-018 SRC-019 SRC-020 SRC-021 SRC-022 SRC-030],
                    content_base64: b64(rar_compressed), logical_path: "portable-compressed.rar", max_archive_depth: 1)
rar2_compressed = [
  "0d5554890000000000d2f74579bf234163598d2d0d44740b30fb02413ec0245df9",
  "9466246846974672bef74d739a3ef2738fd0525481b1c1cbaeac58d88a321228c8",
  "1e7c6c2ef108b370b2f87ff859560d7952302e1d9bf8227a4cceea52fad37da13e",
  "eef1cb80"
].join.then { |hex| [hex].pack("H*") }
rar2_plain = "Hello, RAR2 world!\nThis is a test of the RAR 2.x decoder.\nLine three with some repetition: ABCABCABCABC.\n".b
rar2 = rar2_archive("hello.txt", rar2_compressed, rar2_plain)
requests << request("archive-rar2-compressed", operation: "file",
                    behaviors: %w[SRC-018 SRC-019 SRC-020 SRC-021 SRC-022 SRC-030],
                    content_base64: b64(rar2), logical_path: "portable-rar2.rar", max_archive_depth: 1)
rar_fixture_names.each do |name|
  label = name.include?("rar3") ? "rar3" : "rar5"
  label = "#{label}-solid" if name.include?(".solid.")
  label = "#{label}-multi" if name.end_with?(".cbr")
  requests << request("archive-rar-#{label}", operation: "file",
                      behaviors: %w[SRC-018 SRC-019 SRC-020 SRC-021 SRC-022 SRC-025 SRC-030],
                      content_base64: b64(rar_fixture_root.join(name).binread),
                      logical_path: "portable-#{label}.rar", max_archive_depth: 1)
end
rar5_encrypted_headers = "Rar!\x1a\x07\x01\x00".b + rar5_block(4, 0, "".b)
requests << request("archive-rar5-encrypted-headers", operation: "file",
                    behaviors: %w[SRC-018 SRC-022 SRC-025 SRC-030],
                    content_base64: b64(rar5_encrypted_headers), logical_path: "portable-encrypted.rar",
                    max_archive_depth: 1)
requests << request("archive-rar5-multivolume", operation: "file",
                    behaviors: %w[SRC-018 SRC-022 SRC-025 SRC-030],
                    content_base64: b64(multivolume_rar_root.join("test.part01.rar").binread),
                    logical_path: "portable-volume.part01.rar", max_archive_depth: 1)
[0, 1, 2, 8].each do |depth|
  tests = depth == 8 ? %w[TM-0116 TM-0123] : []
  behaviors = depth == 0 ? %w[SRC-018 SRC-019] : %w[SRC-018 SRC-019 SRC-020 SRC-021]
  behaviors += %w[SRC-022 SRC-023 SRC-024] if depth >= 2
  requests << request("nested-depth-#{depth}", operation: "file", behaviors: behaviors, tests: tests,
                      fixture_path: "testdata/archives/nested.tar.gz", logical_path: "../testdata/archives/nested.tar.gz",
                      config_fixture: "archives.toml", max_archive_depth: depth, detect: true)
end
requests << request("nested-canceled", operation: "file", behaviors: %w[SRC-027], tests: %w[TM-0116 TM-0124],
                    fixture_path: "testdata/archives/nested.tar.gz", logical_path: "../testdata/archives/nested.tar.gz",
                    config_fixture: "archives.toml", max_archive_depth: 8, detect: true, cancel_before: true)
inner_allowlist_tar = tar_bytes([["skip/deep.txt", "deep"]])
outer_allowlist_tar = tar_bytes([["skip/first.txt", "first"], ["nested.tar", inner_allowlist_tar]])
requests << request("archive-inner-allowlist-scope", operation: "file", behaviors: %w[SRC-013 SRC-019 SRC-020 SRC-023],
                    content_base64: b64(outer_allowlist_tar), logical_path: "outer.tar", max_archive_depth: 2,
                    skip_paths_base64: [b64("(?:^|/)skip(?:/|$)")])
requests << request("archive-direct-corrupt-tar", operation: "file", behaviors: %w[SRC-018 SRC-025],
                    content_base64: b64("short tar"), logical_path: "broken.tar", max_archive_depth: 1)
%w[zip 7z br bz2 gz lz4 mz s2 sz xz zst lz zz].each do |extension|
  requests << request("archive-direct-corrupt-#{extension}", operation: "file", behaviors: %w[SRC-018 SRC-025],
                      content_base64: b64("not a valid #{extension} stream"), logical_path: "broken.#{extension}", max_archive_depth: 1)
end

requests << request("files-upstream-directory", operation: "files", behaviors: %w[SRC-010 SRC-013 SRC-018 SRC-022 SRC-026 SRC-028], tests: %w[TM-0116 TM-0117],
                    fixture_path: "testdata/archives/files", logical_path: "../testdata/archives/files", config_fixture: "archives.toml",
                    max_archive_depth: 8, detect: true, worker_limit: 1)
requests << request("files-nogit-directory", operation: "files", behaviors: %w[SRC-010 SRC-026 SRC-028], tests: %w[TM-0128 TM-0130],
                    fixture_path: "testdata/repos/nogit", logical_path: "../testdata/repos/nogit", config_fixture: "simple.toml",
                    ignore_fixture: "testdata/repos/nogit/.gitleaksignore", detect: true, worker_limit: 1)
requests << request("files-nogit-main", operation: "files", behaviors: %w[SRC-007 SRC-010 SRC-028], tests: %w[TM-0128 TM-0132],
                    fixture_path: "testdata/repos/nogit", root_subpath: "main.go", logical_path: "../testdata/repos/nogit/main.go",
                    config_fixture: "simple.toml", ignore_fixture: "testdata/repos/nogit/.gitleaksignore", detect: true, worker_limit: 1)
requests << request("files-nogit-api", operation: "files", behaviors: %w[SRC-010 SRC-028], tests: %w[TM-0128 TM-0131],
                    fixture_path: "testdata/repos/nogit", root_subpath: "api.go", logical_path: "../testdata/repos/nogit/api.go",
                    config_fixture: "simple.toml", ignore_fixture: "testdata/repos/nogit/.gitleaksignore", detect: true, worker_limit: 1)
requests << request("files-nogit-env", operation: "files", behaviors: %w[SRC-007 SRC-010 SRC-028], tests: %w[TM-0128 TM-0129],
                    fixture_path: "testdata/repos/nogit", root_subpath: ".env.prod", logical_path: "../testdata/repos/nogit/.env.prod",
                    config_fixture: "generic.toml", ignore_fixture: "testdata/repos/nogit/.gitleaksignore", detect: true, worker_limit: 1)
requests << request("files-symlink-disabled", operation: "files", behaviors: %w[SRC-014 SRC-017 SRC-030], fixture_path: "testdata/repos/symlinks",
                    root_subpath: "file_symlink", logical_path: "../testdata/repos/symlinks/file_symlink", worker_limit: 1)
requests << request("files-symlink-enabled", operation: "files", behaviors: %w[SRC-014 SRC-015 SRC-016 SRC-017 SRC-028 SRC-030], tests: ["TM-0126"],
                    fixture_path: "testdata/repos/symlinks", root_subpath: "file_symlink", logical_path: "../testdata/repos/symlinks/file_symlink",
                    config_fixture: "simple.toml", follow_symlinks: true, detect: true, worker_limit: 1)
requests << request("files-directory-symlink", operation: "files", behaviors: %w[SRC-014 SRC-016], logical_path: "tree", follow_symlinks: true,
                    entries: [{"path" => "real", "kind" => "dir"}, {"path" => "real/value.txt", "kind" => "file", "content_base64" => b64("value")},
                              {"path" => "dir-link", "kind" => "symlink", "target" => "real"}], worker_limit: 1)
requests << request("files-chained-symlink", operation: "files", behaviors: %w[SRC-015 SRC-016], logical_path: "tree/scan", root_subpath: "scan",
                    follow_symlinks: true, entries: [{"path" => "target", "kind" => "file", "content_base64" => b64("value")},
                    {"path" => "second", "kind" => "symlink", "target" => "target"}, {"path" => "scan/link", "kind" => "symlink", "target" => "../second"}], worker_limit: 1)
requests << request("files-symlink-alias-size-skip", operation: "files", behaviors: %w[SRC-011 SRC-015], logical_path: "tree/scan", root_subpath: "scan",
                    follow_symlinks: true, max_file_size: 5, entries: [{"path" => "very-long-target-name", "kind" => "file", "content_base64" => b64("x")},
                    {"path" => "scan/link", "kind" => "symlink", "target" => "../very-long-target-name"}], worker_limit: 1)
requests << request("files-symlink-target-size-bypass", operation: "files", behaviors: %w[SRC-011 SRC-015], logical_path: "tree/scan", root_subpath: "scan",
                    follow_symlinks: true, max_file_size: 5, entries: [{"path" => "x", "kind" => "file", "content_base64" => b64("1234567890")},
                    {"path" => "scan/link", "kind" => "symlink", "target" => "../x"}], worker_limit: 1)
requests << request("files-dangling-symlink", operation: "files", behaviors: %w[SRC-012 SRC-016], logical_path: "tree", follow_symlinks: true,
                    entries: [{"path" => "dangling", "kind" => "symlink", "target" => "absent"}], worker_limit: 1)
requests << request("files-looping-symlink", operation: "files", behaviors: %w[SRC-012 SRC-016], logical_path: "tree", follow_symlinks: true,
                    entries: [{"path" => "a", "kind" => "symlink", "target" => "b"}, {"path" => "b", "kind" => "symlink", "target" => "a"}], worker_limit: 1)
requests << request("files-corrupt-tar", operation: "files", behaviors: %w[SRC-018 SRC-025 SRC-026], logical_path: "tree", max_archive_depth: 1,
                    entries: [{"path" => "broken.tar", "kind" => "file", "content_base64" => b64("short tar")}], worker_limit: 1)
requests << request("files-corrupt-archive-matrix", operation: "files", behaviors: %w[SRC-018 SRC-025 SRC-026], logical_path: "tree", max_archive_depth: 1,
                    entries: %w[zip 7z br bz2 gz lz4 mz s2 sz xz zst lz zz].map { |extension|
                      {"path" => "broken.#{extension}", "kind" => "file", "content_base64" => b64("not a valid #{extension} stream")}
                    }, worker_limit: 1)
requests << request("files-size-boundary", operation: "files", behaviors: %w[SRC-011 SRC-029], logical_path: "tree", max_file_size: 5,
                    entries: [{"path" => "empty", "kind" => "file", "content_base64" => b64("")},
                              {"path" => "equal", "kind" => "file", "content_base64" => b64("12345")},
                              {"path" => "over", "kind" => "file", "content_base64" => b64("123456")}], worker_limit: 1)
requests << request("files-permission-denied", operation: "files", behaviors: %w[SRC-012 SRC-030], logical_path: "tree",
                    entries: [{"path" => "unreadable", "kind" => "file", "content_base64" => b64("unreadable"), "mode" => 0}],
                    worker_limit: 1)
requests << request("files-prune-directory", operation: "files", behaviors: %w[SRC-010 SRC-013], logical_path: "tree",
                    skip_paths_base64: [b64("(?:^|/)skip(?:/|$)")], entries: [{"path" => "keep/value", "kind" => "file", "content_base64" => b64("keep")},
                    {"path" => "skip/nested/value", "kind" => "file", "content_base64" => b64("skip")}], worker_limit: 1)
requests << request("files-missing", operation: "files", behaviors: %w[SRC-012], tests: %w[TM-0116 TM-0125], logical_path: "missing", missing_root: true)
requests << request("files-canceled", operation: "files", behaviors: %w[SRC-027], logical_path: "tree", cancel_before: true,
                    entries: [{"path" => "value", "kind" => "file", "content_base64" => b64("value")}], worker_limit: 1)
requests << request("files-bounded-order", operation: "files", behaviors: %w[SRC-026 SRC-029], logical_path: "tree", worker_limit: 1,
                    entries: [{"path" => "a", "kind" => "file", "content_base64" => b64("same")},
                              {"path" => "b", "kind" => "file", "content_base64" => b64("same")}])

abort "duplicate request IDs" unless requests.map { |entry| entry.fetch("id") }.uniq.length == requests.length
abort "behavior coverage missing" unless requests.flat_map { |entry| entry.fetch("behavior_ids") }.uniq.sort == BEHAVIORS

generated = {}
Dir.mktmpdir("rustleaks-m9-source-") do |temporary|
  binary = File.join(temporary, "source-oracle")
  capture("go", "test", "./...", chdir: ORACLE)
  capture("go", "build", "-o", binary, ".", chdir: ORACLE)
  outcomes = requests.map { |entry| bounded_oracle(binary, entry) }
  by_id = outcomes.to_h { |entry| [entry.fetch("id"), entry] }
  outcomes.each do |outcome|
    abort "#{outcome.fetch('id')}: pin changed" unless outcome.fetch("upstream_revision") == REVISION && outcome.fetch("default_config_sha256") == DEFAULT_SHA256
    abort "#{outcome.fetch('id')}: platform missing" if outcome.fetch("platform").empty?
  end

  decode = ->(value) { Base64.strict_decode64(value) }
  fragment_bytes = ->(id) { by_id.fetch(id).fetch("fragments").map { |entry| decode.call(entry.fetch("raw_base64")) } }
  finding_files = ->(id) { by_id.fetch(id).fetch("findings").map { |entry| decode.call(entry.fetch("file_base64")) } }
  fragment_paths = ->(id) { by_id.fetch(id).fetch("fragments").map { |entry| decode.call(entry.fetch("file_base64")) } }
  windows_paths = ->(id) { by_id.fetch(id).fetch("fragments").map { |entry| decode.call(entry.fetch("windows_file_base64")) } }
  windows = outcomes.first.fetch("platform").start_with?("windows/")
  material = {}
  verify = lambda do |behavior, name, condition|
    abort "#{behavior} material assertion #{name} failed" unless condition
    material[behavior] ||= []
    material[behavior] << name
  end

  expected_boundaries = ["abc\n\n", "a\r\n\r\n", "abcdefg\nhijklmnop\n\n", "abcdefg\r\nhijklmnop\r\n\r\n",
                         "abcdefg\nhijklmnop\n\t  \t\n", "abcdefg\nhijklmnopqrstuvwx"]
  boundary_cases.first(2).each_with_index { |(id), index| verify.call("SRC-004", "#{id}-safe-suffix", fragment_bytes.call(id).first == expected_boundaries[index]) }
  boundary_cases.drop(2).each_with_index { |(id), index| verify.call("SRC-005", "#{id}-lookahead", fragment_bytes.call(id).first == expected_boundaries[index + 2]) }
  verify.call("SRC-001", "callback-yield-error-propagates", by_id.fetch("file-yield-error").dig("error", "class") == "yield" &&
              by_id.fetch("file-yield-error").fetch("fragments").length == 1)
  verify.call("SRC-002", "owned-raw-and-bytes-projections", by_id.fetch("file-invalid-bytes").fetch("fragments").all? { |entry|
    entry.fetch("raw_base64") == entry.fetch("bytes_base64") && !entry.fetch("bytes_nil") })
  verify.call("SRC-003", "default-and-custom-buffer-sizes", fragment_bytes.call("file-default-buffer").map(&:bytesize) == [100_002, 1] &&
              fragment_bytes.call("file-custom-buffer") == ["abc\n\n", "def"])
  verify.call("SRC-004", "custom-file-safe-suffix-no-read-ahead", fragment_bytes.call("file-custom-buffer").first == "abc\n\n")
  verify.call("SRC-005", "lookahead-ceiling-is-exact", fragment_bytes.call("boundary-25000-ceiling").first.bytesize == 125_000)
  expected_stream_counts = {"stream-single" => 1, "stream-empty" => 0, "stream-error" => 0, "stream-multiple" => 2,
                            "stream-eof" => 1, "stream-split" => 1, "stream-late-error" => 0}
  verify.call("SRC-006", "reader-error-and-eof-matrix", by_id.fetch("detect-reader-eof").fetch("findings").length == 1 &&
              %w[stream-error stream-late-error].all? { |id| by_id.fetch(id).fetch("issues").length == 1 } &&
              by_id.fetch("file-data-plus-error").fetch("issues").length == 1)
  verify.call("SRC-007", "lf-only-start-line-accounting", by_id.fetch("file-lf-line-count").fetch("fragments").map { |entry| entry.fetch("start_line") } == [1, 3])
  verify.call("SRC-008", "mime-before-extension-and-repeat", by_id.fetch("file-mime-skip").fetch("fragments").empty? &&
              fragment_bytes.call("file-repeat-mime-before-first-lf").map(&:bytesize) == [125_000] &&
              by_id.fetch("archive-magic-without-name").fetch("fragments").empty?)
  expected_stream_counts.each { |id, count| verify.call("SRC-009", "#{id}-adapter-outcome", by_id.fetch(id).fetch("findings").length == count) }
  invalid = by_id.fetch("file-invalid-bytes").fetch("fragments")
  verify.call("SRC-010", "root-file-directory-and-lexical-nested-discovery", by_id.fetch("files-nogit-main").fetch("fragments").length == 1 &&
              by_id.fetch("files-nogit-directory").fetch("fragments").map { |entry| decode.call(entry.fetch("file_base64")) }.sort ==
                by_id.fetch("files-nogit-directory").fetch("fragments").map { |entry| decode.call(entry.fetch("file_base64")) })
  verify.call("SRC-011", "empty-and-over-limit-skip-equal-retained", by_id.fetch("file-empty").fetch("fragments").empty? &&
              fragment_bytes.call("files-size-boundary") == ["12345"])
  verify.call("SRC-011", "symlink-alias-size-precedes-target-size", fragment_bytes.call("files-symlink-alias-size-skip").empty? &&
              fragment_bytes.call("files-symlink-target-size-bypass") == ["1234567890"])
  verify.call("SRC-012", "missing-and-invalid-symlink-stages", by_id.fetch("files-missing").fetch("error").nil? &&
              by_id.fetch("files-missing").fetch("fragments").empty? &&
              %w[files-dangling-symlink files-looping-symlink].all? { |id| by_id.fetch(id).fetch("fragments").empty? })
  verify.call("SRC-012", "native-unreadable-file-is-skipped", windows || by_id.fetch("files-permission-denied").fetch("fragments").empty?)
  verify.call("SRC-013", "directory-and-inner-path-allowlists", by_id.fetch("files-prune-directory").fetch("fragments").length == 1 &&
              fragment_bytes.call("archive-inner-allowlist-scope") == ["deep"])
  verify.call("SRC-014", "disabled-and-directory-symlinks-skip", by_id.fetch("files-symlink-disabled").fetch("fragments").empty? &&
              by_id.fetch("files-directory-symlink").fetch("fragments").length == 1)
  verify.call("SRC-015", "followed-and-chained-file-symlinks", by_id.fetch("files-symlink-enabled").fetch("findings").length == 1 &&
              by_id.fetch("files-chained-symlink").fetch("fragments").length == 1)
  verify.call("SRC-016", "invalid-symlinks-terminate", %w[files-dangling-symlink files-looping-symlink].all? { |id|
    by_id.fetch(id).fetch("error").nil? || %w[panic source].include?(by_id.fetch(id).dig("error", "class")) })
  verify.call("SRC-017", "invalid-bytes-and-logical-paths-preserved", decode.call(invalid.first.fetch("file_base64")) == "src/\xff.bin".b &&
              decode.call(by_id.fetch("files-symlink-enabled").dig("fragments", 0, "symlink_file_base64")).include?("file_symlink/"))
  verify.call("SRC-017", "unicode-normalization-is-not-applied", fragment_paths.call("file-path-nfc") == ["paths/caf\u00e9.txt".b] &&
              fragment_paths.call("file-path-nfd") == ["paths/cafe\u0301.txt".b] &&
              fragment_paths.call("file-path-nfc") != fragment_paths.call("file-path-nfd"))
  windows_path_ids = %w[file-path-windows-mixed-drive file-path-windows-unc file-path-windows-extended]
  verify.call("SRC-017", "native-windows-dual-path-projection", windows ?
              windows_path_ids.all? { |id| windows_paths.call(id).all? { |path| !path.empty? } && fragment_paths.call(id) != windows_paths.call(id) } :
              windows_path_ids.all? { |id| windows_paths.call(id) == [""] })
  verify.call("SRC-018", "name-only-case-insensitive-substring-identification", by_id.fetch("archive-uppercase-name").fetch("fragments").length == 4 &&
              by_id.fetch("archive-substring-name").fetch("fragments").length == 4 && by_id.fetch("archive-magic-without-name").fetch("fragments").empty?)
  verify.call("SRC-019", "each-archive-layer-consumes-depth", by_id.fetch("nested-depth-0").fetch("findings").empty? &&
              by_id.fetch("nested-depth-1").fetch("findings").length == 2 && by_id.fetch("nested-depth-2").fetch("findings").length == 15)
  zip_paths = by_id.fetch("archive-files-zip").fetch("fragments").map { |entry| decode.call(entry.fetch("file_base64")) }
  verify.call("SRC-020", "extractor-entry-order-and-cleaning", zip_paths == ["../testdata/archives/files.zip!files/.gitleaksignore",
              "../testdata/archives/files.zip!files/api.go", "../testdata/archives/files.zip!files/main.go"])
  verify.call("SRC-021", "inner-paths-and-fingerprints-use-bang", finding_files.call("archive-files-zip").all? { |path| path.include?("!") } &&
              by_id.fetch("archive-files-zip").fetch("findings").all? { |finding| decode.call(finding.fetch("fingerprint_base64")).include?("!") })
  verify.call("SRC-021", "native-windows-archive-outer-path", fragment_paths.call("archive-windows-outer-path").all? { |path| path.include?("!") } &&
              (windows ? windows_paths.call("archive-windows-outer-path").all? { |path| !path.empty? } : windows_paths.call("archive-windows-outer-path").all?(&:empty?)))
  verify.call("SRC-022", "gzip-xz-zstd-retain-outer-name", %w[main.go.gz main.go.xz main.go.zst].all? { |name|
    finding_files.call("decompress-#{name.tr('.', '-')}") == ["archives/files/#{name}"] })
  verify.call("SRC-022", "safe-native-stream-codecs-retain-outer-name", safe_codec_streams.keys.all? { |extension|
    id = "decompress-safe-#{extension}"
    fragment_bytes.call(id) == ["portable safe codec payload\n"] &&
      fragment_paths.call(id) == ["portable.#{extension}".b]
  })
  verify.call("SRC-022", "safe-native-compressed-tars-extract-members", safe_codec_tars.keys.all? { |extension|
    id = "decompress-safe-tar-#{extension}"
    fragment_bytes.call(id) == ["portable safe codec payload\n"] &&
      fragment_paths.call(id) == ["portable.tar.#{extension}!value.txt".b]
  })
  verify.call("SRC-022", "safe-native-7z-codec-profile", sevenzip_fixture_names.all? { |name|
    outcome = by_id.fetch("archive-7z-#{name}")
    outcome.fetch("error").nil? && outcome.fetch("issues").empty?
  })
  verify.call("SRC-022", "safe-native-rar-container-and-compression", fragment_bytes.call("archive-rar5-stored") == [rar_stored_payload] &&
              fragment_paths.call("archive-rar5-stored") == ["portable-stored.rar!value.txt".b] &&
              fragment_bytes.call("archive-rar5-compressed") == [rar_compressed_payload] &&
              fragment_paths.call("archive-rar5-compressed") == ["portable-compressed.rar!compressed.txt".b])
  rar_text = rar_fixture_root.join("expected/testfile.txt").binread
  rar_jpeg = rar_fixture_root.join("expected/testfile.jpg").binread
  rar_png = rar_fixture_root.join("expected/testfile.png").binread
  rar_single_ids = %w[archive-rar-rar3 archive-rar-rar3-solid archive-rar-rar5 archive-rar-rar5-solid]
  rar_multi_expected = {
    "archive-rar-rar3-multi" => [rar_jpeg, rar_png],
    "archive-rar-rar3-solid-multi" => [rar_png, rar_jpeg],
    "archive-rar-rar5-multi" => [rar_jpeg, rar_png],
    "archive-rar-rar5-solid-multi" => [rar_jpeg, rar_png]
  }
  verify.call("SRC-020", "rar-backend-entry-order", rar_multi_expected.all? { |id, bytes|
    fragment_bytes.call(id) == bytes
  })
  verify.call("SRC-022", "rar3-rar5-ordinary-and-solid-members", rar_single_ids.all? { |id|
    fragment_bytes.call(id) == [rar_text] && by_id.fetch(id).fetch("error").nil? && by_id.fetch(id).fetch("issues").empty?
  } && rar_multi_expected.all? { |id, bytes|
    fragment_bytes.call(id) == bytes && by_id.fetch(id).fetch("error").nil? && by_id.fetch(id).fetch("issues").empty?
  })
  verify.call("SRC-022", "rar2-compressed-member", fragment_bytes.call("archive-rar2-compressed") == [rar2_plain] &&
              fragment_paths.call("archive-rar2-compressed") == ["portable-rar2.rar!hello.txt".b] &&
              by_id.fetch("archive-rar2-compressed").fetch("error").nil? && by_id.fetch("archive-rar2-compressed").fetch("issues").empty?)
  verify.call("SRC-025", "rar-password-and-unnamed-volume-failures", by_id.fetch("archive-rar5-encrypted-headers").dig("error", "class") == "source" &&
              by_id.fetch("archive-rar5-encrypted-headers").dig("error", "message") == "rardecode: archive encrypted, password required" &&
              by_id.fetch("archive-rar5-multivolume").dig("error", "class") == "panic" &&
              %w[archive-rar5-encrypted-headers archive-rar5-multivolume].all? { |id|
                by_id.fetch(id).fetch("fragments").empty? && by_id.fetch(id).fetch("issues").empty?
              })
  verify.call("SRC-023", "first-level-allowlist-not-propagated-to-child", fragment_bytes.call("archive-inner-allowlist-scope") == ["deep"] &&
              decode.call(by_id.fetch("archive-inner-allowlist-scope").dig("fragments", 0, "file_base64")) == "outer.tar!nested.tar!skip/deep.txt")
  verify.call("SRC-024", "nested-zip-and-7z-nonseekable-members-scan", finding_files.call("nested-depth-8").any? { |path| path.include?("files.zip!") } &&
              finding_files.call("nested-depth-8").any? { |path| path.include?("files.7z!") })
  verify.call("SRC-025", "corrupt-direct-and-directory-outcomes-frozen", fragment_bytes.call("file-malformed-archive").empty? &&
              by_id.fetch("file-malformed-archive").fetch("error").nil? &&
              by_id.fetch("archive-direct-corrupt-tar").dig("error", "message") == "unexpected EOF" &&
              by_id.fetch("files-corrupt-tar").fetch("error").nil? && by_id.fetch("files-corrupt-tar").fetch("fragments").empty?)
  verify.call("SRC-025", "supported-codec-corruption-matrix", %w[zip 7z].all? { |extension|
                by_id.fetch("archive-direct-corrupt-#{extension}").dig("error", "class") == "source"
              } && %w[gz xz lz zz].all? { |extension|
                by_id.fetch("archive-direct-corrupt-#{extension}").fetch("error").nil? &&
                  by_id.fetch("archive-direct-corrupt-#{extension}").fetch("fragments").empty?
              } && %w[br bz2 lz4 mz s2 sz].all? { |extension|
                by_id.fetch("archive-direct-corrupt-#{extension}").fetch("error").nil? &&
                  fragment_paths.call("archive-direct-corrupt-#{extension}") == ["broken.#{extension}".b] &&
                  by_id.fetch("archive-direct-corrupt-#{extension}").fetch("issues").length == 1
              } && fragment_paths.call("archive-direct-corrupt-zst") == ["broken.zst"] &&
              fragment_paths.call("files-corrupt-archive-matrix").length == 7)
  verify.call("SRC-026", "bounded-order-independent-duplicates", by_id.fetch("files-bounded-order").fetch("max_concurrent_callbacks") == 1 &&
              fragment_bytes.call("files-bounded-order").sort == %w[same same])
  verify.call("SRC-027", "pre-cancel-is-terminal-and-joined", %w[file-canceled files-canceled nested-canceled].all? { |id|
    by_id.fetch(id).dig("error", "class") == "canceled" })
  verify.call("SRC-028", "engine-session-fingerprints-and-ignore", by_id.fetch("files-nogit-directory").fetch("findings").length == 1 &&
              by_id.fetch("files-nogit-api").fetch("findings").empty? &&
              decode.call(by_id.fetch("files-nogit-main").dig("findings", 0, "fingerprint_base64")).end_with?("main.go:aws-access-key:20"))
  verify.call("SRC-029", "configured-size-depth-and-entry-limits", fragment_bytes.call("files-size-boundary") == ["12345"] &&
              by_id.fetch("nested-depth-0").fetch("findings").empty? && by_id.fetch("files-bounded-order").fetch("fragments").length == 2)
  verify.call("SRC-030", "native-platform-recorded-without-emulation", outcomes.all? { |entry| entry.fetch("platform").include?("/") } &&
              %w[file-path-nfc file-path-nfd file-path-windows-mixed-drive file-path-windows-unc file-path-windows-extended
                 archive-windows-outer-path files-permission-denied].all? { |id| by_id.fetch(id).fetch("platform") == outcomes.first.fetch("platform") })

  complete_fragment_keys = %w[raw_base64 bytes_base64 bytes_nil file_base64 windows_file_base64 symlink_file_base64 commit_base64 start_line inherited_from_finding].sort
  outcomes.flat_map { |entry| entry.fetch("fragments") + entry.fetch("canonical_fragments") }.each do |fragment|
    abort "complete fragment projection changed" unless fragment.keys.sort == complete_fragment_keys
  end
  abort "material behavior inventory incomplete" unless material.keys.sort == BEHAVIORS

  request_bytes = jsonl(requests)
  outcome_bytes = jsonl(outcomes)
  coverage = {
    "schema_version" => 1, "protocol_version" => PROTOCOL_VERSION, "upstream_revision" => REVISION,
    "default_config_sha256" => DEFAULT_SHA256,
    "behavior_ids" => BEHAVIORS.map { |id| {"id" => id, "definition" => BEHAVIOR_DEFINITIONS.fetch(id),
                                                  "request_ids" => requests.select { |entry| entry.fetch("behavior_ids").include?(id) }.map { |entry| entry.fetch("id") },
                                                  "material_assertions" => material.fetch(id, [])} },
    "upstream" => UPSTREAM_IDENTITIES.map { |id, name| {"test_case_id" => id, "go_name" => name,
      "classification" => %w[TM-0098 TM-0116 TM-0128 TM-0147 TM-0269].include?(id) ? "aggregator" : "leaf",
      "request_ids" => requests.select { |entry| entry.fetch("test_case_ids").include?(id) }.map { |entry| entry.fetch("id") }} },
    "source_hashes" => SOURCE_HASHES, "fixture_hashes" => fixture_hashes,
    "platform_contract" => "host GOOS/GOARCH is recorded; Windows symlink creation/metadata remains a native CI lane obligation",
    "ordering_contract" => "file callbacks preserve emission order; concurrent directory cases use worker_limit=1 and also include canonical_fragments",
    "known_gaps" => {
      "SRC-003" => "the current Go adapter protocol cannot distinguish an omitted buffer from an explicit non-nil zero-length buffer",
      "SRC-012" => "native Unix permission denial is covered; metadata TOCTOU still requires deterministic filesystem fault injection",
      "SRC-013" => "Windows raw-plus-slash allowlist fallback requires native Windows",
      "SRC-016" => "chained, dangling, and looping links are covered; an escaping-but-valid target requires a separately controlled parent fixture",
      "SRC-017" => "NFC/NFD and Windows drive/UNC/extended/mixed spellings are generated natively; Windows evidence requires the declared native workflow to run",
      "SRC-018" => "ambiguous multi-format registered-map iteration and formats absent from assigned fixtures remain unfrozen",
      "SRC-022" => "The pinned non-encrypted 7z codec profile plus Brotli, bzip2, gzip, LZ4, MinLZ, Snappy/S2, XZ, and Zstandard streams and compressed TARs are covered; RAR3/RAR5 ordinary and solid members are covered while password support is intentionally outside the source API",
      "SRC-024" => "nested zip/7z exercises non-seekable spooling, but temporary-file reclamation and spool ceilings are not externally observable here",
      "SRC-025" => "direct and directory corruption is frozen for TAR, ZIP, 7z, Brotli, bzip2, gzip, LZ4, MinLZ, Snappy/S2, XZ, Zstandard, LZIP, and zlib; encrypted RAR and unnamed-stream multi-volume failures are frozen while malformed RAR remains excluded because the pinned Go backend hangs",
      "SRC-026" => "worker-one bounded order is frozen; worker counts above one intentionally expose no stable emission order",
      "SRC-027" => "pre-cancellation matches the assigned upstream assertion; deterministic mid-flight cancellation needs an injectable cancellation probe",
      "SRC-028" => "source fingerprints and ignore merging are covered; baseline equivalence remains in the M8 session corpus",
      "SRC-029" => "Go size/depth gates are covered; Rust checked-overflow, expansion, entry, and spool limits are implementation obligations",
      "SRC-030" => "native path and permission overlays carry platform provenance; safe Rust crate boundaries and dependency audits are implementation evidence"
    },
    "excluded" => ["Git source semantics", "Rust implementation", "metadata TOCTOU fault injection"]
  }
  coverage_bytes = JSON.pretty_generate(coverage) + "\n"
  negative_controls = {"pairs" => [
    {"positive" => "detect-reader-eof", "negative" => "stream-error", "dimension" => "EOF-versus-error"},
    {"positive" => "files-size-boundary/equal", "negative" => "files-size-boundary/over", "dimension" => "strict-size-limit"},
    {"positive" => "files-symlink-enabled", "negative" => "files-symlink-disabled", "dimension" => "follow-symlinks"},
    {"positive" => "nested-depth-8", "negative" => "nested-depth-1", "dimension" => "archive-depth"},
    {"positive" => "files-prune-directory/keep", "negative" => "files-prune-directory/skip", "dimension" => "directory-pruning"}
  ]}
  negative_bytes = JSON.pretty_generate(negative_controls) + "\n"
  readme = <<~MARKDOWN
    # Source oracle corpus v1

    This corpus freezes reader, file, directory, symlink, and archive behavior from
    pinned Gitleaks `#{REVISION}`. Each of its #{requests.length} requests runs in a
    fresh Go child with a 15-second deadline, an 8 MiB per-stream ceiling, a 512 MiB
    Go memory limit, and at most two Go scheduler threads.

    Byte-bearing fragment and finding fields are base64 encoded. Both emission-order
    and canonical fragment views preserve duplicates; `bytes_nil` distinguishes nil
    from empty byte slices. Archive requests use provenance-tracked copies under
    `compat/fixtures/upstream`, whose hashes are frozen in `coverage-v1.json`.
    `coverage-v1.json` embeds the authoritative definition for every `SRC-001`
    through `SRC-030`, material assertions aligned to those definitions, and an
    explicit per-ID gap list where native or Rust implementation evidence is still
    mandatory.

    Regenerate or verify from the repository root:

    ```sh
    ruby compat/generate_source_corpus.rb
    ruby compat/generate_source_corpus.rb --check
    ```

    Outcomes record the generating GOOS/GOARCH. Windows symlink behavior and native
    separator metadata require native Windows CI confirmation rather than emulation.
  MARKDOWN
  manifest = {
    "schema_version" => 1, "protocol_version" => PROTOCOL_VERSION, "oracle_mode" => "source",
    "upstream_revision" => REVISION, "default_config_sha256" => DEFAULT_SHA256,
    "go_version" => outcomes.first.fetch("go_version"), "platform" => outcomes.first.fetch("platform"),
    "fresh_process_per_request" => true, "deadline_seconds" => 15, "stream_limit_bytes" => 8 * 1024 * 1024,
    "request_count" => requests.length, "outcome_count" => outcomes.length,
    "fragment_count" => outcomes.sum { |entry| entry.fetch("fragments").length },
    "finding_count" => outcomes.sum { |entry| entry.fetch("findings").length },
    "issue_count" => outcomes.sum { |entry| entry.fetch("issues").length },
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

abort "upstream status changed during generation" unless capture("git", "status", "--short", chdir: UPSTREAM) == upstream_status_before
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
