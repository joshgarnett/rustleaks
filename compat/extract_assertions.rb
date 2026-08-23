#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "open3"
require "pathname"

PIN = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
SCHEMA = 1
ROOT = Pathname(__dir__).parent
UPSTREAM = ROOT.parent.join("gitleaks")
OUT = ROOT.join("compat/assertion-corpus")
MANIFEST = ROOT.join("compat/test-manifest.toml")

SOURCE_HASHES = {
  "cmd/generate/config/base/config_test.go" => "c5e88dcf113ac382043cf037643b142e52d7ccb7523754c8e61aa52bd4bf739f",
  "cmd/generate/config/utils/generate_test.go" => "2188f0d2ade645f6996273991a70b1c95e265dd1f0136adaf3e2bdb7affdc077",
  "config/allowlist_test.go" => "5cfabc25ece05a39268ba81ca4209d98dc85df828acadfd4927b231f49fe2e7c",
  "detect/baseline_test.go" => "4e6e40bae1d71f14acf66f8ebeb1f328607e1ca01b675c28a8447284f5068895",
  "detect/location_test.go" => "e04b3bf5d7ca6807b28e2f246d2dc9e52c089d893064782afded9c1202006597",
  "detect/detect_test.go" => "191e7178827d790ae7c72f7b17824e3d368fe66b263fb12a9b8f3ede225124d3",
  "report/finding_test.go" => "60f6950823fd227c77d65c630b540fdb3dba46b947bda5bf98f5a72d9d513874",
  "report/junit_test.go" => "dc298993221456d5b023b6af4d200e6ade47bab1272b92d441d29f27124da558",
  "report/report_test.go" => "16763fa5d4794ce1bb11292a2d4d47a90c6fa1fd661d9b621230b25d53835d89"
}.freeze

def b64(value)
  Base64.strict_encode64(value.b)
end

def bytes(value)
  {"encoding" => "base64", "data" => b64(value)}
end

def deep_bytes(value)
  case value
  when String then bytes(value)
  when Array then value.map { |v| deep_bytes(v) }
  when Hash then value.transform_values { |v| deep_bytes(v) }
  else value
  end
end

def record(id:, parent:, source:, line:, occurrence:, domain:, observation:, input:, expected:, fixtures: [])
  {
    "schema_version" => SCHEMA,
    "id" => id,
    "parent_case_id" => parent,
    "upstream_revision" => PIN,
    "mapping_id" => "M1-ASSERTIONS-002",
    "source_file" => source,
    "source_line" => line,
    "source_occurrence" => occurrence,
    "domain" => domain,
    "observation" => observation,
    "comparison" => "exact",
    "input" => deep_bytes(input),
    "expected" => deep_bytes(expected),
    "fixture_ids" => fixtures,
    "rust_test" => nil,
    "rust_evidence" => nil,
    "status" => "pending"
  }
end

# Narrow Go lexer used only to recover exact decoded string-literal bytes and
# their source lines. It deliberately skips comments so commented-out samples
# cannot silently enter the corpus.
def go_string_tokens(path, first_line, last_line)
  source = UPSTREAM.join(path).binread
  tokens = []
  i = 0
  line = 1
  while i < source.bytesize
    if source.byteslice(i, 2) == "//"
      eol = source.index("\n", i) || source.bytesize
      line += source.byteslice(i, eol - i).count("\n")
      i = eol
    elsif source.byteslice(i, 2) == "/*"
      finish = source.index("*/", i + 2) or raise "unterminated comment in #{path}"
      line += source.byteslice(i, finish + 2 - i).count("\n")
      i = finish + 2
    elsif source.getbyte(i) == 96 # raw string
      start_line = line
      finish = source.index("`", i + 1) or raise "unterminated raw string in #{path}"
      raw = source.byteslice(i + 1, finish - i - 1)
      tokens << [raw, start_line] if start_line.between?(first_line, last_line)
      line += raw.count("\n")
      i = finish + 1
    elsif source.getbyte(i) == 34 # interpreted string
      start_line = line
      j = i + 1
      j += 2 while j < source.bytesize && source.getbyte(j) == 92
      loop do
        c = source.getbyte(j) or raise "unterminated string in #{path}"
        if c == 92
          j += 2
        elsif c == 34
          break
        else
          j += 1
        end
      end
      literal = source.byteslice(i, j - i + 1)
      decoded = JSON.parse(literal)
      tokens << [decoded.b, start_line] if start_line.between?(first_line, last_line)
      i = j + 1
    else
      line += 1 if source.getbyte(i) == 10
      i += 1
    end
  end
  tokens
end

def source_lines(path, range, values)
  remaining = go_string_tokens(path, range.begin, range.end)
  values.map do |value|
    index = remaining.index { |token, _line| token == value.b }
    raise "source literal not found in #{path}:#{range}: #{value.inspect}" unless index
    _token, line = remaining[index]
    remaining = remaining.drop(index + 1)
    line
  end
end

def add_sample_group(rows, prefix:, parent:, source:, range:, domain:, operation:, setup:, flags:, matches:, nonmatches:)
  samples = matches + nonmatches
  lines = source_lines(source, range, samples)
  sample_rows = matches.each_with_index.map { |v, i| ["M", i + 1, v, lines[i], "validStrings[#{i}]"] } +
                nonmatches.each_with_index.map { |v, i| ["N", i + 1, v, lines[matches.length + i], "invalidStrings[#{i}]"] }
  flags.each_with_index do |flag, flag_index|
    sample_rows.each do |kind, ordinal, sample, line, occurrence|
      id = format("%s-CI%s-%s-%02d", prefix, flag ? "T" : "F", kind, ordinal)
      rows << record(id: id, parent: parent, source: source, line: line,
                     occurrence: "#{occurrence};isCaseInsensitive[#{flag_index}]",
                     domain: domain, observation: "public-api",
                     input: setup.merge("operation" => operation, "case_insensitive" => flag, "sample" => sample),
                     expected: {"kind" => "bool", "value" => kind == "M"})
    end
  end
end

def build_assertions
  rows = []
  base_source = "cmd/generate/config/base/config_test.go"
  regex_groups = [
    ["general-placeholders", "TM-0006", 11..15, %w[true True false False null NULL], []],
    ["repeated-characters", "TM-0007", 16..21,
     ["aaaaaaaaaaaaaaaaa", "BBBBBBBBBBbBBBBBBBbBB", "********************"],
     ["aaaaaaaaaaaaaaaaaaabaa", "pas*************d"]],
    ["environment-variables", "TM-0005", 22..25,
     ["$2", "$GIT_PASSWORD", "${GIT_PASSWORD}", "$password"],
     ["$yP@R.@=ibxI", "$2a6WCust9aE", "${not_complete1"]],
    ["ansible", "TM-0008", 26..31,
     ["{{ x }}", "{{ password }}", "{{password}}", "{{ data.proxy_password }}",
      "{{ dict1 | ansible.builtin.combine(dict2) }}"], []],
    ["github-actions", "TM-0009", 32..45,
     ["${{ env.First_Name }}", "${{ env.DAY_OF_WEEK == 'Monday' }}", "${{env.JAVA_VERSION}}",
      "${{ github.event.issue.title }}", "${{ github.repository == \"Gattocrucco/lsqfitgp\" }}",
      "${{ github.event.pull_request.number || github.ref }}",
      "${{ github.event_name == 'pull_request' && github.event.action == 'unassigned' }}",
      "${{ secrets.SuperSecret }}", "${{ vars.JOB_NAME }}", "${{ vars.USE_VARIABLES == 'true' }}"], []],
    ["nuget", "TM-0010", 46..50, ["%MY_PASSWORD%", "%password%"], []],
    ["go-fmt", "TM-0011", 51..55,
     ["%b", "%c", "%d", "% d", "%e", "%E", "%f", "%F", "%g", "%G", "%o", "%O", "%p",
      "%q", "%-s", "%s", "%t", "%T", "%U", "%#U", "%+v", "%#v", "%v", "%x", "%X"], []],
    ["python-fmt", "TM-0012", 56..60, ["{}", "{0}", "{10}"], []],
    ["ucd", "TM-0013", 61..64, ["@password@", "@LDAP_PASS@"], ["@username@mastodon.example"]],
    ["file-paths", "TM-0014", 65..73,
     ["/Users/james/Projects/SwiftCode/build/Release", "/tmp/screen-exchange"], []]
  ]
  regex_groups.each do |slug, parent, range, allowed, not_allowed|
    lines = source_lines(base_source, range, allowed + not_allowed)
    [["A", allowed, true, "invalid"], ["N", not_allowed, false, "valid"]].each do |kind, values, expected, source_class|
      offset = kind == "A" ? 0 : allowed.length
      values.each_with_index do |sample, i|
        rows << record(id: format("AS-BASE-RX-%s-%s-%02d", slug, kind, i + 1), parent: parent,
                       source: base_source, line: lines[offset + i], occurrence: "#{source_class}[#{i}]",
                       domain: "config-global-allowlist-regex", observation: "public-api",
                       input: {"operation" => "RegexAllowed", "sample" => sample, "source_class" => source_class},
                       expected: {"kind" => "bool", "value" => expected})
      end
    end
  end

  path_groups = [
    ["javascript", "TM-0002", 124..136,
     ["tests/e2e/nuget/wwwroot/lib/bootstrap/dist/js/bootstrap.esm.min.js",
      "src/main/static/lib/angular.1.2.16.min.js",
      "src/main/resources/static/jquery-ui-1.12.1/jquery-ui-min.js",
      "src/main/resources/static/js/jquery-ui-1.10.4.min.js", "src-static/js/plotly.min.js",
      "swagger/swaggerui/swagger-ui-bundle.js.map", "swagger/swaggerui/swagger-ui-es-bundle.js.map",
      "src/main/static/swagger-ui.min.js", "swagger/swaggerui/swagger-ui.js"]],
    ["python", "TM-0003", 137..158,
     ["Pipfile.lock", "poetry.lock", "env/lib/python3.7/site-packages/urllib3/util/url.py",
      "venv/Lib/site-packages/regex-2018.08.29.dist-info/DESCRIPTION.rst",
      "venv/lib64/python3.5/site-packages/pynvml.py",
      "python/python3/virtualenv/Lib/site-packages/pyphonetics/utils.py",
      "virtualenv/lib64/python3.7/base64.py", "cde-root/usr/lib64/python2.4/site-packages/Numeric.pth",
      "lib/python3.9/site-packages/setuptools/_distutils/msvccompiler.py",
      "lib/python3.8/site-packages/botocore/data/alexaforbusiness/2017-11-09/service-2.json",
      "code/python/3.7.4/Lib/site-packages/dask/bytes/tests/test_bytes_utils.py",
      "python/3.7.4/Lib/site-packages/fsspec/utils.py",
      "python/2.7.16.32/Lib/bsddb/test/test_dbenv.py",
      "python/lib/python3.8/site-packages/boto3/data/ec2/2016-04-01/resources-1.json",
      "libs/PyX-0.15.dist-info/AUTHORS"]]
  ]
  path_groups.each do |slug, parent, range, values|
    source_lines(base_source, range, values).zip(values).each_with_index do |(line, sample), i|
      rows << record(id: format("AS-BASE-PATH-%s-A-%02d", slug, i + 1), parent: parent,
                     source: base_source, line: line, occurrence: "invalid[#{i}]",
                     domain: "config-global-allowlist-path", observation: "public-api",
                     input: {"operation" => "PathAllowed", "sample" => sample, "source_class" => "invalid"},
                     expected: {"kind" => "bool", "value" => true})
    end
  end

  gen = "cmd/generate/config/utils/generate_test.go"
  semi = [
    ["G01", "TM-0022", 16..23, [false], ["api_key=xxx"], ["api_key=XXX", "api_key=xXx"], ["api_key"]],
    ["G02", "TM-0021", 24..31, [true], ["api_key=xxx", "api_key=XXX", "api_key=xXx"], ["api_key=x!x"], ["api_key"]],
    ["G03", "TM-0019", 32..39, [true, false], ["api_key=xxx", "ApI_KeY=xxx", "aPi_kEy=xxx", "API_KEY=xxx"], ["api!key=xxx"], ["api_key"]],
    ["G04", "TM-0017", 40..47, [true, false], ["apikey=xxx", "ApiKey=xxx", "Apikey=xxx", "APIKEY=xxx", "api_key=xxx"], ["ApIKeY=xxx", "aPikEy=xxx"], ["(?-i:[Aa]pi_?[Kk]ey|API_?KEY)"]],
    ["G05", "TM-0018", 48..55, [true, false], ["mykey=xxx", "keys=xxx", "key1=xxx", "keystore=xxx", "monkey=xxx"], [], ["key"]],
    ["G06", "TM-0020", 56..80, [true, false],
     ["api_key-----=xxx", "api_key.....=xxx", "api_key_____=xxx", "'''api_key'''=xxx", "\"\"\"api_key\"\"\"=xxx",
      "api_key          =xxx", "api_key\t\t\t\t\t=xxx", "api_key\n\n\n=xxx", "api_key\r\n=xxx"],
     ["api_key&=xxx", "$api_key$=xxx", "%api_key%=xxx", "api_key[0]=xxx", "api_key/*REMOVE*/=xxx"], ["api_key"]],
    ["G07", "TM-0016", 81..106, [true, false],
     ["api_key=xxx", "api_key: xxx", "<api_key>xxx", "api_key:=xxx", "api_key:::=xxx", "api_key => xxx", "api_key ?= xxx", "api_key, xxx"],
     ["api_keyxxx", "api_key\txxx", "api_key; xxx", "api_key<xxx>", "api_key&xxx", "api_key = true ? 'xxx' : 'yyy'"], ["api_key"]],
    ["G08", "TM-0023", 107..139, [true, false],
     ["api_key=    xxx ", "api_key=xxx\n", "api_key=xxx\r\n", "api_key=\n\n\n\n\nxxx", "api_key=\r\n\r\nxxx",
      "api_key=\t\t\t\txxx\t", "api_key======xxx;", "api_key='''xxx'''", "api_key=\"\"\"xxx\"\"\"",
      "api_key=```xxx```", "api_key=\"xxx'", "api_key=\"don't do it!\"", "api_key=\"xxx;notpartofthematch\""],
     ["api_key=_xxx", "api_key=xxx_", "api_key=$xxx", "api_key=%xxx%", "api_key=[xxx]", "api_key=(xxx)",
      "api_key=<xxx>", "api_key={xxx}", "<api_key>xxx</api_key>", "example.com?api_key=xxx&other=yyy"], ["api_key"]]
  ]
  semi.each do |group, parent, range, flags, matches, nonmatches, identifiers|
    add_sample_group(rows, prefix: "AS-GEN-SG-#{group}", parent: parent, source: gen, range: range,
                     domain: "regex-generator-semi-generic", operation: "GenerateSemiGenericRegex",
                     setup: {"identifiers" => identifiers, "secret_regex" => "[a-z]{3}"},
                     flags: flags, matches: matches, nonmatches: nonmatches)
  end

  unique = [
    ["G01", "TM-0027", 173..179, false, ["abc"], ["ABC", "Abc"]],
    ["G02", "TM-0026", 180..186, true, ["abc", "ABC", "Abc"], ["123"]],
    ["G03", "TM-0025", 187..213, false,
     ["abc", " abc ", "\nabc\n", "\r\nabc\r\n", "\tabc\t", "'abc'", "\"abc\"", "```abc```", "my abc's", ".com?abc"],
     ["abcabc", "_abc_", ".com?abc&def", "/*abc*/", "<abc>", "<str>abc</str>", "{{{abc}}}", "abc, d"]]
  ]
  unique.each do |group, parent, range, flag, matches, nonmatches|
    add_sample_group(rows, prefix: "AS-GEN-UT-#{group}", parent: parent, source: gen, range: range,
                     domain: "regex-generator-unique-token", operation: "GenerateUniqueTokenRegex",
                     setup: {"secret_regex" => "[a-c]{3}"}, flags: [flag], matches: matches, nonmatches: nonmatches)
  end

  add_direct_rows(rows)
  rows
end

def add_direct_rows(rows)
  source = "config/allowlist_test.go"
  [["AS-CFG-COMMIT-01", 20, ["commitA"], "commitA", true],
   ["AS-CFG-COMMIT-02", 27, ["commitB"], "commitA", false],
   ["AS-CFG-COMMIT-03", 34, ["commitB"], "", false]].each_with_index do |(id, line, commits, query, value), i|
    rows << record(id: id, parent: "TM-0028", source: source, line: line, occurrence: "tests[#{i}]",
                   domain: "config-allowlist", observation: "public-api",
                   input: {"operation" => "CommitAllowed", "commits" => commits, "query" => query},
                   expected: {"kind" => "bool", "value" => value})
  end
  [["AS-CFG-REGEX-01", 54, "a secret: matchthis, done", true], ["AS-CFG-REGEX-02", 61, "a secret", false]].each_with_index do |(id, line, secret, value), i|
    rows << record(id: id, parent: "TM-0033", source: source, line: line, occurrence: "tests[#{i}]",
                   domain: "config-allowlist", observation: "public-api",
                   input: {"operation" => "RegexAllowed", "regex" => "matchthis", "secret" => secret},
                   expected: {"kind" => "bool", "value" => value})
  end
  [["AS-CFG-PATH-01", 80, "a path", true], ["AS-CFG-PATH-02", 87, "a ???", false]].each_with_index do |(id, line, path, value), i|
    rows << record(id: id, parent: "TM-0032", source: source, line: line, occurrence: "tests[#{i}]",
                   domain: "config-allowlist", observation: "public-api",
                   input: {"operation" => "PathAllowed", "regex" => "path", "path" => path},
                   expected: {"kind" => "bool", "value" => value})
  end
  rows << record(id: "AS-CFG-VALIDATE-EMPTY", parent: "TM-0072", source: source, line: 106,
                 occurrence: "tests[empty conditions]", domain: "config-allowlist-validation", observation: "public-api",
                 input: {"allowlist" => {}},
                 expected: {"kind" => "exact-error-and-state", "error" => "must contain at least one check for: commits, paths, regexes, or stopwords", "allowlist" => {}}).merge(
                   "rust_test" => "config_compile_002_validates_and_normalizes_rules",
                   "rust_evidence" => "crates/rustleaks-core/tests/config.rs", "status" => "implemented"
                 )
  rows << record(id: "AS-CFG-VALIDATE-DEDUP", parent: "TM-0072", source: source, line: 110,
                 occurrence: "tests[deduplicated commits and stopwords]", domain: "config-allowlist-validation", observation: "public-api",
                 input: {"commits" => %w[commitA commitB commitA], "stopwords" => %w[stopwordA stopwordB stopwordA]},
                 expected: {"kind" => "no-error-normalized-sets", "error" => nil, "commits_unordered" => %w[commita commitb], "stopwords_unordered" => %w[stopworda stopwordb]}).merge(
                   "rust_test" => "config_compile_002_validates_and_normalizes_rules",
                   "rust_evidence" => "crates/rustleaks-core/tests/config.rs", "status" => "implemented"
                 )

  baseline = "detect/baseline_test.go"
  [["AS-BASELINE-LOAD-CSV", 162, "../testdata/baseline/baseline.csv", "the format of the file ../testdata/baseline/baseline.csv is not supported", ["FIX-0014"]],
   ["AS-BASELINE-LOAD-SARIF", 166, "../testdata/baseline/baseline.sarif", "the format of the file ../testdata/baseline/baseline.sarif is not supported", ["FIX-0016"]],
   ["AS-BASELINE-LOAD-MISSING", 170, "../testdata/baseline/notfound.json", "could not open ../testdata/baseline/notfound.json", []]].each_with_index do |(id, line, path, error, fixtures), i|
    rows << record(id: id, parent: "TM-0127", source: baseline, line: line, occurrence: "tests[#{i}]",
                   domain: "baseline-load", observation: "public-api", input: {"path" => path},
                   expected: {"kind" => "exact-error", "error" => error}, fixtures: fixtures)
  end
  [["AS-BASELINE-IGNORE-01", 189, {"author" => "a", "commit" => "5"}, {"author" => "a", "commit" => "5"}],
   ["AS-BASELINE-IGNORE-FINGERPRINT", 204, {"author" => "a", "commit" => "5", "fingerprint" => "a"}, {"author" => "a", "commit" => "5", "fingerprint" => "b"}]].each_with_index do |(id, line, finding, base), i|
    rows << record(id: id, parent: "TM-0139", source: baseline, line: line, occurrence: "tests[#{i}]",
                   domain: "baseline-suppression", observation: "oracle-adapter-or-public-e2e",
                   input: {"finding" => finding, "baseline" => [base]}, expected: {"kind" => "count", "value" => 0})
  end
  location = "detect/location_test.go"
  [["AS-LOCATION-01", 17, [35, 38], [1, 36, 1, 38, 0, 40]], ["AS-LOCATION-02", 34, [40, 44], [2, 1, 2, 4, 40, 56]]].each_with_index do |(id, line, span, fields), i|
    rows << record(id: id, parent: "TM-0138", source: location, line: line, occurrence: "tests[#{i}]",
                   domain: "detector-location", observation: "oracle-adapter",
                   input: {"line_pairs" => [[0, 39], [40, 55], [56, 57]], "span" => span, "fragment" => ""},
                   expected: {"kind" => "location", "field_order" => %w[start_line start_column end_line end_column start_line_index end_line_index], "values" => fields})
                   .merge("rust_test" => "engine::tests::upstream_location_matches_pinned_helper_assertions",
                          "rust_evidence" => "crates/rustleaks-core/src/engine.rs", "status" => "implemented")
  end

  finding = {"rule_id" => "aws-access-key", "description" => "AWS Access Key", "start_line" => 7, "end_line" => 7,
             "start_column" => 18, "end_column" => 37, "line" => "\n\taws_token2 := \"AKIALALEMEL33243OLIA\" // this one is not",
             "match" => "AKIALALEMEL33243OLIA", "secret" => "AKIALALEMEL33243OLIA", "file" => "api/api.go",
             "symlink_file" => "", "commit" => "", "entropy" => 3.0841837, "author" => "", "email" => "",
             "date" => "0001-01-01T00:00:00Z", "message" => "", "tags" => ["key", "AWS"],
             "fingerprint" => "api/api.go:aws-access-key:7", "link" => ""}
  staged_fixtures = ["FIX-0034"] + (161..213).map { |n| format("FIX-%04d", n) }
  rows << record(id: "AS-DETECT-STAGED-01", parent: "TM-0137", source: "detect/detect_test.go", line: 1328,
                 occurrence: "tests[0]", domain: "source-git-staged", observation: "public-integration",
                 input: {"config" => "simple", "source" => "../testdata/repos/staged", "git_metadata_name" => "dotGit", "isolated_copy_required" => true},
                 expected: {"kind" => "finding-multiset", "count" => 1, "findings" => [finding]}, fixtures: staged_fixtures)
  symlink_finding = {"rule_id" => "apkey", "description" => "Asymmetric Private Key", "start_line" => 1, "end_line" => 1,
                     "start_column" => 1, "end_column" => 35, "match" => "-----BEGIN OPENSSH PRIVATE KEY-----",
                     "secret" => "-----BEGIN OPENSSH PRIVATE KEY-----", "line" => "-----BEGIN OPENSSH PRIVATE KEY-----",
                     "file" => "../testdata/repos/symlinks/source_file/id_ed25519",
                     "symlink_file" => "../testdata/repos/symlinks/file_symlink/symlinked_id_ed25519",
                     "commit" => "", "entropy" => 3.587164, "author" => "", "email" => "", "date" => "", "message" => "",
                     "tags" => ["key", "AsymmetricPrivateKey"],
                     "fingerprint" => "../testdata/repos/symlinks/source_file/id_ed25519:apkey:1", "link" => ""}
  rows << record(id: "AS-DETECT-SYMLINK-01", parent: "TM-0126", source: "detect/detect_test.go", line: 2127,
                 occurrence: "tests[0]", domain: "source-symlink", observation: "public-integration",
                 input: {"config" => "simple", "source" => "../testdata/repos/symlinks/file_symlink", "follow_symlinks" => true},
                 expected: {"kind" => "finding-multiset", "count" => 1, "findings" => [symlink_finding]}, fixtures: ["FIX-0034", "FIX-0214", "FIX-0215"])
  rows << record(id: "AS-IGNORE-NORMALIZE-01", parent: "TM-0146", source: "detect/detect_test.go", line: 2461,
                 occurrence: "single-test", domain: "ignore-normalization", observation: "oracle-adapter",
                 input: {"path" => "../testdata/gitleaksignore/.windowspaths"},
                 expected: {"kind" => "unordered-exact-set", "count" => 3,
                            "values" => ["foo/bar/gitleaks-false-positive.yaml:aws-access-token:4",
                                         "foo/bar/gitleaks-false-positive.yaml:aws-access-token:5",
                                         "b55d88dc151f7022901cda41a03d43e0e508f2b7:test_data/test_local_repo_three_leaks.json:aws-access-token:73"]},
                 fixtures: ["FIX-0077"])

  rows << record(id: "AS-REPORT-REDACT-01", parent: "TM-0250", source: "report/finding_test.go", line: 14,
                 occurrence: "tests[0]", domain: "report-finding-redaction", observation: "public-api",
                 input: {"finding" => {"match" => "line containing secret", "secret" => "secret"}, "redact_percent" => 100},
                 expected: {"kind" => "finding-fields", "secret" => "REDACTED", "match" => "line containing REDACTED"})
                 .merge("rust_test" => "frozen_composite_and_redaction_corpus_matches_go",
                        "rust_evidence" => "crates/rustleaks-core/tests/composite_corpus.rs; cargo xtask composite-check",
                        "status" => "implemented")
  junit_findings = [{"description" => "Test Rule", "rule_id" => "test-rule", "match" => "line containing secret", "secret" => "a secret",
                     "start_line" => 1, "end_line" => 2, "start_column" => 1, "end_column" => 2, "message" => "opps", "file" => "auth.py",
                     "commit" => "0000000000000000", "author" => "John Doe", "email" => "johndoe@gmail.com", "date" => "10-19-2003", "tags" => []},
                    {"description" => "Test Rule", "rule_id" => "test-rule", "match" => "line containing secret", "secret" => "a secret",
                     "start_line" => 2, "end_line" => 3, "start_column" => 1, "end_column" => 2, "message" => "", "file" => "auth.py",
                     "commit" => "", "author" => "", "email" => "", "date" => "", "tags" => []}]
  rows << record(id: "AS-REPORT-JUNIT-SIMPLE", parent: "TM-0262", source: "report/junit_test.go", line: 19,
                 occurrence: "tests[0]", domain: "report-junit", observation: "public-api",
                 input: {"findings" => junit_findings}, expected: {"kind" => "golden", "normalization" => "upstream-lineEndingReplacer", "fixture_id" => "FIX-0073"}, fixtures: ["FIX-0073"])
  rows << record(id: "AS-REPORT-JUNIT-EMPTY", parent: "TM-0262", source: "report/junit_test.go", line: 61,
                 occurrence: "tests[1]", domain: "report-junit", observation: "public-api",
                 input: {"findings" => []}, expected: {"kind" => "golden", "normalization" => "upstream-lineEndingReplacer", "fixture_id" => "FIX-0072"}, fixtures: ["FIX-0072"])
  rows << record(id: "AS-REPORT-STDOUT-01", parent: "TM-0265", source: "report/report_test.go", line: 15,
                 occurrence: "single-test", domain: "report-json", observation: "public-api",
                 input: {"findings" => [{"rule_id" => "test-rule"}], "writer" => "closable-buffer"},
                 expected: {"kind" => "no-error-and-nonempty-bytes", "error" => nil, "nonempty" => true})
end

def build_benchmarks
  source = "config/allowlist_test.go"
  specs = [
    ["AS-BM-0001-ASSERT", "BM-0001", 269, "CommitAllowed", "d0dbe09bb150bbd5bb4b85adc273df87350e7e6c", true, nil],
    ["AS-BM-0002-ASSERT", "BM-0002", 276, "CommitAllowed", "5fe58bf0b0be1735ad27aa6053b56323a905c223", false, nil],
    ["AS-BM-0007-ASSERT", "BM-0007", 318, "RegexAllowed", "environment {\n\tCREDENTIALS_ID = \"K8S_CRED\"\n}", true, nil],
    ["AS-BM-0008-ASSERT", "BM-0008", 327, "RegexAllowed", "\"credentials\" : \"0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506\"", false, nil],
    ["AS-BM-0005-ASSERT", "BM-0005", 368, "PathAllowed", "src/main/resources/static/js/jquery-ui-1.10.4.min.js", true, "AS-BASE-PATH-javascript-A-04"],
    ["AS-BM-0006-ASSERT", "BM-0006", 375, "PathAllowed", "azure_scale_templates/sub_modules/vpc_template/inputs.auto.tfvars.json_backup", false, nil]
  ]
  specs.map do |id, benchmark, line, operation, sample, value, overlap|
    {"schema_version" => SCHEMA, "id" => id, "benchmark_id" => benchmark, "upstream_revision" => PIN,
     "mapping_id" => "M1-ASSERTIONS-002", "source_file" => source, "source_line" => line,
     "source_occurrence" => benchmark, "observation" => "public-api", "comparison" => "exact",
     "input" => deep_bytes({"operation" => operation, "sample" => sample}),
     "expected" => deep_bytes({"kind" => "bool", "value" => value}), "semantic_overlap_assertion_id" => overlap,
     "rust_test" => "tests::exact_upstream_benchmark_inputs_and_outcomes_run",
     "rust_evidence" => "crates/rustleaks-compat/src/bin/rustleaks-perf.rs; cargo xtask perf check",
     "status" => "implemented"}
  end
end

def build_skips
  [{"id" => "SKIP-TM-0133-WINDOWS", "parent_case_id" => "TM-0133", "child_case_ids" => %w[TM-0134 TM-0135 TM-0136],
    "source_line" => 850, "reason" => "TODO: this fails on Windows: [git] fatal: bad object refs/remotes/origin/main?"},
   {"id" => "SKIP-TM-0126-WINDOWS", "parent_case_id" => "TM-0126", "child_case_ids" => [], "source_line" => 2127,
    "reason" => "TODO: this returns no results on windows, I'm not sure why."}].map do |row|
    evidence = row["id"] == "SKIP-TM-0133-WINDOWS" ?
      "crates/rustleaks-sources/tests/git_corpus.rs::matrix_n_isolated_platform_fixtures_use_distinct_private_copies; portable Git corpus replaces the upstream Windows skip" :
      "crates/rustleaks-sources/tests/source_corpus.rs::complete_source_corpus_matches_frozen_go_outcomes_or_exact_safe_dispositions; portable source corpus replaces the upstream Windows skip"
    {"schema_version" => SCHEMA, "upstream_revision" => PIN, "mapping_id" => "M1-ASSERTIONS-002",
     "source_file" => "detect/detect_test.go", "platform" => "windows", "effect" => "skip",
     "rust_evidence" => evidence, "status" => "implemented"}.merge(row).transform_values { |v| v.is_a?(String) && v.start_with?("TODO:") ? bytes(v) : v }
  end
end

def finalize_assertion(row)
  return row unless row["status"] == "pending"

  test, evidence = case row.fetch("domain")
                   when "config-global-allowlist-path", "config-global-allowlist-regex", "config-allowlist"
                     ["frozen_allowlist_corpus_matches_go",
                      "crates/rustleaks-core/tests/allowlist.rs; cargo xtask allowlist-check"]
                   when "baseline-load", "baseline-suppression", "ignore-normalization"
                     ["session_corpus_matches_every_frozen_oracle_outcome",
                      "crates/rustleaks-core/tests/session_corpus.rs; cargo xtask session-check"]
                   when "report-junit", "report-json"
                     ["every_representable_builtin_report_case_replays_exact_oracle_bytes",
                      "crates/rustleaks-report/tests/report_corpus.rs; cargo xtask report-check"]
                   when "source-git-staged"
                     ["valid_git_corpus_fragments_match_and_failures_have_safe_dispositions",
                      "crates/rustleaks-sources/tests/git_corpus.rs; cargo xtask git-check"]
                   when "source-symlink"
                     ["complete_source_corpus_matches_frozen_go_outcomes_or_exact_safe_dispositions",
                      "crates/rustleaks-sources/tests/source_corpus.rs; cargo xtask source-check"]
                   when "regex-generator-semi-generic", "regex-generator-unique-token"
                     return row.merge(
                       "rust_evidence" => "Final release disposition: this upstream Go-only default-construction helper is not part of the Rustleaks API; the byte-exact packaged configuration and every emitted default-rule sample are replayed by crates/rustleaks-core/tests/default_rule_corpus.rs",
                       "status" => "final-disposition"
                     )
                   else
                     raise "unmapped assertion domain #{row.fetch('domain')} for #{row.fetch('id')}"
                   end
  row.merge("rust_test" => test, "rust_evidence" => evidence, "status" => "implemented")
end

def jsonl(rows)
  rows.map { |row| JSON.generate(row) }.join("\n") + "\n"
end

def manifest_ids(section)
  marker = "[[#{section}]]"
  ids = MANIFEST.read.split(marker).drop(1).map { |block| block[/^id = "([^"]+)"/, 1] }.compact
  ids.each_with_object({}) { |id, out| out[id] = true }
end

def verify_environment!(assertions, benchmarks, skips)
  head, status = Open3.capture2("git", "-C", UPSTREAM.to_s, "rev-parse", "HEAD")
  raise "cannot read upstream revision" unless status.success?
  raise "upstream revision #{head.strip} != #{PIN}" unless head.strip == PIN
  SOURCE_HASHES.each do |path, expected|
    actual = Digest::SHA256.file(UPSTREAM.join(path)).hexdigest
    raise "source drift #{path}: #{actual} != #{expected}" unless actual == expected
  end
  raise "assertion count #{assertions.length} != 283" unless assertions.length == 283
  raise "benchmark link count #{benchmarks.length} != 6" unless benchmarks.length == 6
  raise "platform skip count #{skips.length} != 2" unless skips.length == 2
  ids = assertions.map { |row| row["id"] }
  raise "duplicate assertion identities" unless ids.uniq.length == ids.length
  cases = manifest_ids("case")
  benchmark_ids = manifest_ids("benchmark")
  fixtures = manifest_ids("fixture")
  assertions.each do |row|
    raise "missing manifest parent #{row['parent_case_id']}" unless cases[row["parent_case_id"]]
    row["fixture_ids"].each { |id| raise "missing manifest fixture #{id}" unless fixtures[id] }
  end
  benchmarks.each { |row| raise "missing manifest benchmark #{row['benchmark_id']}" unless benchmark_ids[row["benchmark_id"]] }
  skips.each do |row|
    ([row["parent_case_id"]] + row["child_case_ids"]).each { |id| raise "missing skip case #{id}" unless cases[id] }
  end
  assertions.each do |row|
    status = row["status"]
    if status == "implemented"
      raise "implemented assertion #{row['id']} lacks Rust test" if row["rust_test"].to_s.empty?
      raise "implemented assertion #{row['id']} lacks Rust evidence" if row["rust_evidence"].to_s.empty?
    elsif status == "final-disposition"
      unless row["rust_evidence"].to_s.start_with?("Final release disposition:")
        raise "assertion #{row['id']} lacks a precise final disposition"
      end
    else
      raise "assertion #{row['id']} has non-final status #{status}"
    end
  end
  benchmarks.each do |row|
    raise "benchmark link #{row['id']} is not implemented" unless row["status"] == "implemented"
    raise "benchmark link #{row['id']} lacks Rust test" if row["rust_test"].to_s.empty?
    raise "benchmark link #{row['id']} lacks Rust evidence" if row["rust_evidence"].to_s.empty?
  end
  skips.each do |row|
    raise "platform branch #{row['id']} is not implemented" unless row["status"] == "implemented"
    raise "platform branch #{row['id']} lacks Rust evidence" if row["rust_evidence"].to_s.empty?
  end
  # Explicit negative control: equal row count with one substituted identity
  # must not compare equal to the canonical serialization.
  original = jsonl(assertions)
  substituted = assertions.map(&:dup)
  substituted[0] = substituted[0].merge("id" => "AS-SAME-COUNT-SUBSTITUTION")
  raise "same-count identity substitution was not rejected" if jsonl(substituted) == original
end

assertions = build_assertions.map { |row| finalize_assertion(row) }
benchmarks = build_benchmarks
skips = build_skips
verify_environment!(assertions, benchmarks, skips)
outputs = {"assertions.jsonl" => jsonl(assertions), "benchmark-links.jsonl" => jsonl(benchmarks), "platform-skips.jsonl" => jsonl(skips)}

case ARGV.first
when "--write"
  raise "--write takes no additional arguments" unless ARGV.length == 1
  OUT.mkpath
  outputs.each { |name, content| OUT.join(name).binwrite(content) }
  puts "wrote assertions=283 benchmark_links=6 platform_skips=2"
when "--check"
  raise "--check accepts at most one corpus directory" if ARGV.length > 2
  check_dir = ARGV[1] ? Pathname(ARGV[1]).expand_path : OUT
  outputs.each do |name, expected|
    path = check_dir.join(name)
    raise "missing #{path}" unless path.file?
    actual = path.binread
    raise "identity/content substitution in #{name}" unless actual == expected
  end
  puts "ok assertions=283 benchmark_links=6 platform_skips=2 revision=#{PIN}"
else
  warn "usage: ruby compat/extract_assertions.rb --write|--check"
  exit 2
end
