# Comparison harness: synthetic self-test. No real scanner, network or secret
# is used. Fake scanners written below emulate each family's command line and
# report format well enough to drive the whole harness.

FAKE_SCANNER = r'''#!%(python)s -I
import json, os, re, subprocess, sys
FAMILY = %(family)r
PATTERN = re.compile(r'SYNTHA[0-9A-Z]{16}')
args = sys.argv[1:]
if args[:1] in (['version'], ['--version']):
    print('fake-' + FAMILY + ' 0.0.0')
    sys.exit(0)
if args[:2] == ['dir', '--help']:
    print('--native-pack --complete-profile' if FAMILY == 'rustleaks' else 'help')
    sys.exit(0)
if args[:3] == ['config', 'show', 'ids']:
    print('rule-a\nrule-b')
    sys.exit(0)
if args[:2] == ['config', 'hash']:
    print('0' * 64)
    sys.exit(0)
if '-v' in args or '--validate' in args or '--validation' in args:
    sys.exit(97)
mode, target = args[0], args[1]
def value_after(names):
    for index, arg in enumerate(args):
        if arg in names:
            return args[index + 1]
    return None
report = value_after(('--report-path', '-o'))
if mode == 'git' and FAMILY != 'kingfisher':
    subprocess.run(['git', 'log', '-p'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
found = []
for directory, names, files in os.walk(target):
    names[:] = sorted(name for name in names if name != '.git')
    for name in sorted(files):
        path = os.path.join(directory, name)
        with open(path, encoding='utf-8', errors='replace') as handle:
            for number, line in enumerate(handle, 1):
                for match in PATTERN.finditer(line):
                    found.append((path, number, match.start(), match.group(0)))
if FAMILY == 'kingfisher':
    rules_path = value_after(('--rules-path',))
    applied = open(rules_path).read().count('[[rules]]') if rules_path else 3
    rows = [{'rule': {'id': 'kingfisher.synth'}, 'finding': {'snippet': secret, 'line': line,
             'column_start': column, 'column_end': column + len(secret) - 1, 'path': path}}
            for path, line, column, secret in found]
    with open(report, 'w') as handle:
        handle.write(json.dumps({'findings': rows, 'metadata': {'summary': {'rules_applied': applied}}}) + '\n')
        handle.write(json.dumps({'findings': len(rows), 'rules_applied': applied, 'bytes_scanned': 1,
                                 'successful_validations': 0, 'failed_validations': 0}) + '\n')
    sys.exit(200 if rows else 0)
if FAMILY == 'betterleaks-v2':
    rows = [{'rule_id': 'synth', 'match': {'value': secret, 'full': secret},
             'location': {'path': path, 'start_line': line, 'end_line': line,
                          'start_column': column + 1, 'end_column': column + len(secret)}}
            for path, line, column, secret in found]
    rows += [dict(rows[0], rule_id='synth-twin')] if rows else []
    with open(report, 'w') as handle:
        json.dump({'schema_version': '1', 'findings': rows, 'scan': {'state': 'complete', 'bytes_scanned': 1}}, handle)
    sys.exit(1 if rows else 0)
rows = [{'RuleID': 'synth', 'File': path, 'StartLine': line, 'EndLine': line, 'StartColumn': column + 1,
         'EndColumn': column + len(secret), 'Secret': secret, 'Match': 'key=' + secret, 'Commit': '', 'Tags': []}
        for path, line, column, secret in found]
with open(report, 'w') as handle:
    json.dump(rows, handle)
if '--complete-profile' in args:
    sys.stderr.write('rustleaks_scan_status version=1 status=complete reason=complete findings=%%d\n' %% len(rows))
sys.exit(1 if rows else 0)
'''

FAKE_GIT = r'''#!%(python)s -I
import sys
if sys.argv[1:] == ['--version']:
    print('git version 0.0-fake')
sys.exit(0)
'''


def selftest_check(condition, message):
    if not condition:
        raise AssertionError(message)


def selftest_units():
    with tempfile.TemporaryDirectory() as folder:
        manifest = os.path.join(folder, 'w.json')
        with open(manifest, 'w') as handle:
            json.dump({'schema': SCHEMA_WORKLOADS, 'set': 's', 'workloads': [
                {'id': 'a', 'family': 'synthetic', 'modes': ['stdin'], 'path': 'a'},
                {'id': 'b', 'family': 'synthetic', 'modes': ['dir', 'stdin'], 'path': 'b'}]}, handle)
        loaded, sources = manifest_load_workloads([manifest], folder)
        selftest_check([workload['id'] for workload in loaded] == ['b'] and loaded[0]['modes'] == ['dir']
                       and [item['id'] for item in sources[0]['skipped_workloads']] == ['a', 'b'],
                       'unsupported modes are dropped and listed')
    split = {'target': '/cache/repos/x', 'targets': {'dir': '/cache/repos/x/tree', 'git': '/cache/repos/x/repo'}}
    selftest_check(workload_target(split, 'dir') == '/cache/repos/x/tree'
                   and workload_target(split, 'git') == '/cache/repos/x/repo', 'per-mode paths pick the mode target')
    selftest_check(workload_target({'target': '/cache/y', 'targets': {}}, 'git') == '/cache/y',
                   'a workload without per-mode paths uses its path')
    selftest_check(stats_median([3, 1, 2]) == 2 and stats_median([1, 2, 3, 4]) == 2.5, 'median')
    selftest_check(stats_mad([1, 2, 3, 4, 100]) == 1, 'MAD')
    selftest_check(stats_bimodal([10] * 6 + [20] * 6)['flag'], 'two groups are flagged')
    selftest_check(not stats_bimodal([10, 10.1, 10.2, 10.3, 10.1, 10.2, 10.0, 10.3, 10.2])['flag'], 'one group is not flagged')
    first = stats_ratio_interval([2, 2.1, 1.9, 2.0] * 3, [1, 1.05, 0.95, 1.0] * 3, 7)
    second = stats_ratio_interval([2, 2.1, 1.9, 2.0] * 3, [1, 1.05, 0.95, 1.0] * 3, 7)
    selftest_check(first == second and abs(first['ratio'] - 2) < 1e-9 and first['low'] <= 2 <= first['high'],
                   'bootstrap interval is seeded and contains the ratio')

    def item(path, line, secret, rule='r', end=None, commit=''):
        return adapter_finding(rule, path, commit, line, end, secret)

    selftest_check(score_texts_match('abcdef', 'xxabcdefyy', score_overlap('abcdef', 'xxabcdefyy')), 'containment matches')
    selftest_check(score_texts_match('abcdWXYZ', 'abcdQRST', score_overlap('abcdWXYZ', 'abcdQRST')), 'half overlap matches')
    selftest_check(not score_texts_match('abcWXYZQ', 'abcRSTUV', score_overlap('abcWXYZQ', 'abcRSTUV')), 'small overlap does not match')
    left = [item('a', 1, 'SECRETVALUE1234'), item('a', 5, 'OTHERVALUE99999'), item('b', 1, 'LONELYVALUE0000')]
    right = [item('a', 1, 'SECRETVALUE1234', 'x'), item('a', 1, 'SECRETVALUE1234', 'y'),
             item('a', 9, 'OTHERVALUE99999'), item('c', 1, 'LONELYVALUE0000')]
    result = score_compare(left, right, 'l', 'r')
    selftest_check(result['matched'] == 1, 'one-to-one: only one partner per item')
    hints = {row['secret_sha256']: row['hint'] for row in result['only_right']}
    selftest_check(hints[sha256_text('SECRETVALUE1234')] == 'duplicate', 'second rule on the same value is a duplicate')
    selftest_check(hints[sha256_text('OTHERVALUE99999')] == 'no-counterpart', 'far lines have no counterpart')
    left_hints = {row['secret_sha256']: row['hint'] for row in result['only_left']}
    selftest_check(left_hints[sha256_text('OTHERVALUE99999')] == 'no-counterpart', 'four lines away is not near')
    near = score_compare([item('a', 3, 'NEARVALUE123456')], [item('a', 4, 'NEARVALUE123456')], 'l', 'r')
    selftest_check(near['only_left'][0]['hint'] == 'span-difference', 'same text on a near line is a span difference')
    multi = score_compare([item('a', 2, 'line1\nline2\nline3')], [item('a', 4, 'line3')], 'l', 'r')
    selftest_check(multi['matched'] == 1, 'multi-line end line comes from the text')
    text = json.dumps(result)
    selftest_check('SECRETVALUE1234' not in text and 'OTHERVALUE' not in text, 'score output carries no secret text')
    gitleaks_report = json_bytes([{'RuleID': 'r', 'File': '/t/x/f.txt', 'StartLine': 2, 'EndLine': 2,
                                   'Secret': 'abc', 'Commit': '', 'Tags': ['decoded:base64']}])
    kingfisher_report = (json_bytes({'findings': [{'rule': {'id': 'k'}, 'finding': {
        'snippet': 'abc', 'line': 2, 'path': '/t/x/f.txt', 'encoding': 'base64'}}]}) + b'\n' +
        json_bytes({'findings': 1, 'rules_applied': 9, 'successful_validations': 0, 'failed_validations': 0}))
    v2_report = json_bytes({'findings': [{'rule_id': 'r', 'match': {'value': 'abc'}, 'encodings': ['base64'],
                                          'attributes': {'git.sha': 'c' * 40},
                                          'location': {'path': '/t/x/f.txt', 'start_line': 2, 'end_line': 2}}],
                            'scan': {'state': 'complete'}})
    directory = tempfile.mkdtemp(prefix='compare-units-')
    try:
        for adapter, data in (('gitleaks', gitleaks_report), ('kingfisher', kingfisher_report), ('betterleaks-v2', v2_report)):
            path = os.path.join(directory, adapter + '.json')
            write_private(path, data)
            findings, meta = adapter_parse(adapter, path, '/t/x', 'dir')
            selftest_check(len(findings) == 1 and findings[0]['path'] == 'f.txt' and findings[0]['start_line'] == 2,
                           adapter + ' report parses with the target prefix removed')
            if adapter == 'kingfisher':
                selftest_check(meta['rules_applied'] == 9 and findings[0]['decoded'], 'Kingfisher summary and encoding')
            if adapter == 'betterleaks-v2':
                selftest_check(findings[0]['commit'] == 'c' * 40 and findings[0]['decoded'], 'Betterleaks v2 commit and encoding')
        labels_root = os.path.join(directory, 'labels-root')
        os.makedirs(labels_root)
        write_private(os.path.join(labels_root, 'f.txt'), b'line one\nkey = SYNTHAAAAABBBBBCCCCCDD\n')
        secret = b'SYNTHAAAAABBBBBCCCCCDD'
        start = 15
        labels_path = os.path.join(directory, 'labels.jsonl')
        write_private(labels_path, json_bytes({'workload': 'w', 'path': 'f.txt', 'commit': None, 'start': start,
                                               'end': start + len(secret), 'line': 2,
                                               'secret_sha256': sha256_bytes(secret), 'category': 'synthetic',
                                               'label': 'secret', 'source': 'constructed'}) + b'\n' +
                      json_bytes({'workload': 'w', 'path': 'f.txt', 'commit': None, 'start': 0, 'end': 4,
                                  'line': 1, 'secret_sha256': '0' * 64, 'category': 'synthetic',
                                  'label': 'not-secret', 'source': 'constructed'}) + b'\n')
        labels, problems = score_load_labels(labels_path, 'w', labels_root)
        selftest_check(len(labels) == 1 and problems == {'text does not match secret_sha256': 1}, 'labels are checked by hash')
        quality = score_quality([item('f.txt', 2, secret.decode()), item('f.txt', 1, 'line one is not')], labels)
        selftest_check(quality['overall']['true_positive'] == 1 and quality['overall']['unlabeled_findings'] == 1,
                       'quality counts true positives and unlabeled findings')
        negative = dict(labels[0], label='not-secret', category='placeholder')
        quality = score_quality([], [negative])
        selftest_check(quality['missed_labels'] == [] and quality['overall']['true_negative'] == 1,
                       'an unmatched not-secret label is a true negative, not a missed label')
        quality = score_quality([item('f.txt', 2, secret.decode())], [negative])
        selftest_check(len(quality['findings_on_negatives']) == 1
                       and quality['overall']['false_positive_on_negative'] == 1, 'a finding on a not-secret label is listed')
        selftest_partial_and_line_labels(directory, labels_root, secret)
    finally:
        shutil.rmtree(directory)
    profile = adapter_profile_text(4)
    selftest_check(len([line for line in profile.splitlines() if '=' in line]) == 33 and 'workers=4' in profile,
                   'generated profile has all 33 keys')
    selftest_check(adapter_shared_rules_toml().count('[[rules]]') == len(SHARED_RULES), 'shared rules file')


def selftest_partial_and_line_labels(directory, root, secret):
    """Overlapping labels form one group, line labels match by line only
    when marked, partial labels make unmatched findings unknown, ambiguous
    labels are excluded, and results split by source and by test paths."""
    os.makedirs(os.path.join(root, 'tests'))
    other = b'alpha line\nbeta line\ngamma\n'
    write_private(os.path.join(root, 'tests', 'g.txt'), other)
    data = open(os.path.join(root, 'f.txt'), 'rb').read()
    line_start = data.index(b'key =')
    line_end = data.index(b'\n', line_start)
    value_start = data.index(secret)

    def label(path, start, end, blob, source, category, **extra):
        row = {'workload': 'w', 'path': path, 'commit': None, 'start': start, 'end': end, 'line': None,
               'secret_sha256': sha256_bytes(blob[start:end]), 'category': category, 'label': 'secret',
               'source': source, 'unknown_field': 1}
        row.update(extra)
        return json_bytes(row) + b'\n'

    path = os.path.join(directory, 'groups.jsonl')
    write_private(path, label('f.txt', line_start, line_end, data, 'credData', 'credata-token', span='line')
                  + label('tests/g.txt', other.index(b'gamma'), len(other) - 1, other, 'credData', 'credata-maybe',
                          label='ambiguous', span='line')
                  + label('f.txt', value_start, value_start + len(secret), data, 'credData', 'credata-token')
                  + label('tests/g.txt', 0, other.index(b'gamma'), other, 'constructed', 'multi-line', span='line'))
    labels, problems = score_load_labels(path, 'w', root)
    selftest_check(len(labels) == 4 and not problems, 'line, multi-line and ambiguous labels load: %s' % problems)
    selftest_check(sum(1 for row in labels if row['kind'] == 'line') == 3, 'span line makes a line-level label')
    selftest_check(len(score_label_groups([row for row in labels if row['label'] == 'secret'])) == 2,
                   'a line label and a value label on it form one group')
    findings = [adapter_finding('r', 'f.txt', '', 2, 2, secret.decode()),
                adapter_finding('r', 'tests/g.txt', '', 2, 2, 'some-other-value'),
                adapter_finding('r', 'f.txt', '', 1, 1, 'line one'),
                adapter_finding('r', 'tests/g.txt', '', 3, 3, 'gamma')]
    for complete in (True, False):
        quality = score_quality(findings, labels, complete)
        overall = quality['overall']
        selftest_check(overall['true_positive'] == 2 and overall['false_negative'] == 0,
                       'one finding satisfies a label group and a line label matches by line')
        selftest_check((overall['unlabeled_findings'], overall['unknown_findings']) == ((1, 0) if complete else (0, 1)),
                       'partial labels count unmatched findings as unknown')
        selftest_check(overall['excluded_labels'] == 1 and overall['excluded_findings'] == 1
                       and overall['precision_strict'] == (2 / 3 if complete else 1.0),
                       'an ambiguous label and its finding are left out of precision and recall')
        selftest_check(quality['by_scope']['test paths']['true_positive'] == 1
                       and quality['by_source']['credData']['true_positive'] == 1
                       and quality['by_source']['constructed']['true_positive'] == 1
                       and quality['by_category']['credata-token']['precision_strict'] is None,
                       'results split by test paths and by label source; category rows have no strict precision')
    selftest_check(score_test_scope('a/fixtures/b.txt') and not score_test_scope('src/test.py'),
                   'test scope looks at folders, not file names')
    whole = os.path.join(directory, 'whole.jsonl')
    write_private(whole, label('f.txt', line_start, line_end, data, 'constructed', 'value'))
    labels, _ = score_load_labels(whole, 'w', root)
    selftest_check(labels[0]['kind'] == 'text', 'a whole-line label without span line stays a value label')
    quality = score_quality([adapter_finding('r', 'f.txt', '', 2, 2, 'other-text-here')], labels)
    selftest_check(quality['overall']['true_positive'] == 0, 'a value label needs matching text')
    selftest_fixture_labels(directory, root)


def selftest_fixture_labels(directory, root):
    """Case, encoded, expected and scope-difference labels from fixture sets."""
    case = b'token: one\ntoken: two\n'
    write_private(os.path.join(root, 'case.txt'), case)
    write_private(os.path.join(root, 'none.txt'), case)
    write_private(os.path.join(root, 'count.txt'), case)
    write_private(os.path.join(root, 'scope.txt'), case)
    encoded = b'blob: QUJDREVGR0hJSktMTU5PUA==\n'
    write_private(os.path.join(root, 'enc.txt'), encoded)
    decoded = 'ABCDEFGHIJKLMNOP'

    def row(path, blob, **extra):
        value = {'workload': 'w', 'path': path, 'commit': None, 'start': 0, 'end': len(blob), 'line': 1,
                 'secret_sha256': sha256_bytes(blob), 'category': 'gitleaks:rule', 'label': 'secret',
                 'source': 'fixture', 'home_tool': 'gitleaks', 'span': 'case'}
        value.update(extra)
        return json_bytes(value) + b'\n'

    path = os.path.join(directory, 'fixtures.jsonl')
    write_private(path, row('case.txt', case, expected='exactly_one') + row('none.txt', case, expected='none')
                  + row('count.txt', case, expected='count', expected_count=2)
                  + row('enc.txt', encoded, span=None, encoding='base64', secret_sha256=sha256_text(decoded),
                        start=6, end=len(encoded) - 1)
                  + row('scope.txt', case, span=None, start=0, end=10, secret_sha256=sha256_bytes(case[:10]),
                        reachable_from_head=False, in_binary=True))
    labels, problems = score_load_labels(path, 'w', root)
    selftest_check(len(labels) == 5, 'fixture labels load: %s' % problems)
    findings = [adapter_finding('r', 'case.txt', '', 1, 1, 'one'), adapter_finding('r', 'scope.txt', '', 1, 1, 'token: one'),
                adapter_finding('r', 'none.txt', '', 1, 1, 'one'), adapter_finding('r', 'none.txt', '', 2, 2, 'two'),
                adapter_finding('r', 'count.txt', '', 1, 1, 'one'), adapter_finding('r', 'count.txt', '', 2, 2, 'two'),
                adapter_finding('r', 'enc.txt', '', 1, 1, decoded), adapter_finding('r', 'other.txt', '', 1, 1, decoded)]
    quality = score_quality(findings, labels)
    overall = quality['overall']
    selftest_check(overall['false_positive_on_negative'] == 2, 'every finding in an expected-none case is a false positive')
    selftest_check(overall['over_reported_findings'] == 0 and overall['true_positive'] == 4,
                   'case and count labels take their expected findings and the base64 label matches by hash: %s' % overall)
    selftest_check(overall['scope_difference_found'] == 1 and overall['false_negative'] == 0,
                   'a scope-difference label is its own row, not a miss')
    selftest_check(overall['duplicate_findings'] == 1, 'a labeled secret found at another path is a duplicate')
    selftest_check(quality['by_home_tool']['gitleaks']['true_positive'] >= 4, 'results split by home tool')
    extra = findings + [adapter_finding('r', 'case.txt', '', 2, 2, 'three')]
    selftest_check(score_quality(extra, labels)['overall']['over_reported_findings'] == 1,
                   'an extra finding in an exactly-one case is over-reporting')


def selftest_adapters():
    """Scan ranges, thread rules, root configuration files and report checks."""
    inputs = {'shared_rules': '/r.toml', 'profile': lambda workers: '/p%d' % workers}
    git_range = {'git_base': 'a' * 40, 'git_head': 'b' * 40}
    for adapter, expected in (('gitleaks', '--log-opts=' + 'a' * 40 + '..' + 'b' * 40),
                              ('betterleaks-v2', 'a' * 40 + '..' + 'b' * 40), ('kingfisher', '--since-commit')):
        tool = {'adapter': adapter, 'binary': '/bin/x', 'probe': {}}
        argv = adapter_invocation(tool, 'git', '/t', '/r.json', {'git_range': git_range}, inputs)['argv']
        selftest_check(expected in argv, adapter + ' uses the workload scan range')
    only_options = adapter_invocation({'adapter': 'kingfisher', 'binary': '/bin/x', 'probe': {}}, 'git', '/t', '/r.json',
                                      {'git_range': {'git_log_options': '--all'}}, inputs)
    selftest_check(only_options['unsupported'], 'a range given only as git log options is unsupported for Kingfisher')
    rustleaks = {'adapter': 'rustleaks', 'binary': '/bin/x', 'probe': {'capabilities': ['complete-profile']}}
    one = adapter_invocation(rustleaks, 'dir', '/t', '/r.json', {'threads': 1}, inputs)['argv']
    four = adapter_invocation(rustleaks, 'dir', '/t', '/r.json', {'threads': 4}, inputs)['argv']
    selftest_check('--complete-profile' not in one and '/p4' in four, 'Rustleaks uses a profile only above 1 thread')
    rustleaks['probe']['capabilities'].append('jobs')
    one = ' '.join(adapter_invocation(rustleaks, 'dir', '/t', '/r.json', {'threads': 1}, inputs)['argv'])
    four = ' '.join(adapter_invocation(rustleaks, 'dir', '/t', '/r.json', {'threads': 4}, inputs)['argv'])
    default = ' '.join(adapter_invocation(rustleaks, 'dir', '/t', '/r.json', {}, inputs)['argv'])
    selftest_check('--jobs 1' in one and '--jobs 4' in four and '--complete-profile' not in four
                   and '--jobs' not in default, 'Rustleaks builds with --jobs set threads with --jobs')
    selftest_check(adapter_auto_loaded('gitleaks', ['.gitleaks.toml', '.gitleaksignore'], True) == ['.gitleaksignore']
                   and adapter_auto_loaded('betterleaks-v2', ['.gitleaks.toml'], False) == [],
                   'root configuration files are matched to the tools that load them')
    directory = tempfile.mkdtemp(prefix='compare-adapters-')
    try:
        path = os.path.join(directory, 'v2.json')
        write_private(path, json_bytes({'findings': [], 'scan': {'state': 'complete',
                                                                 'status_counts': {'valid': 1, 'none': 0}}}))
        selftest_check(adapter_parse('betterleaks-v2', path, '/t', 'dir')[1]['validations'] == 1,
                       'a Betterleaks v2 validation status is detected')
        path = os.path.join(directory, 'kf.json')
        write_private(path, json_bytes({'findings': [{'rule': {'id': 'k'}, 'finding': {
            'snippet': 'abcdef', 'line': 1, 'path': '/t/a.txt'}}]}))
        selftest_check(adapter_parse('kingfisher', path, '/t', 'git')[1]['non_history_findings'] == 1,
                       'Kingfisher git findings without a commit are counted')
        workload = {'target': directory}
        write_private(os.path.join(directory, '.gitleaksignore'), b'')
        selftest_check(manifest_target_config(workload) == ['.gitleaksignore'], 'root ignore files are found')
    finally:
        shutil.rmtree(directory)


def selftest_matching():
    """Maximum matching, the minimum shared length, and commit-agnostic matching."""

    def item(path, line, secret, commit=''):
        return adapter_finding('r', path, commit, line, line, secret)

    # Greedy by overlap would pair the long left value with the long right
    # value and leave one item unmatched on each side; the maximum matching
    # pairs both.
    left = [item('a', 1, 'ABCDEFGHIJKLMNOP'), item('a', 1, 'ABCDEFGH')]
    right = [item('a', 1, 'ABCDEFGHIJKLMNOPQRST'), item('a', 1, 'ZZZZABCDEFGHIJKLMNOP')]
    selftest_check(score_compare(left, right, 'l', 'r')['matched'] == 2, 'matching is maximum, not greedy')
    left = [item('a', 1, 'ABCDEFGHIJKL'), item('a', 1, 'ABCDEFGHIJKL')]
    right = [item('a', 1, 'ABCDEFGHIJKL'), item('a', 1, 'zABCz')]
    selftest_check(score_compare(left, right, 'l', 'r')['matched'] == 1, 'a short shared part does not match')
    selftest_check(not score_texts_match('AB', 'xxxxABxxxxxxxxxx', score_overlap('AB', 'xxxxABxxxxxxxxxx')),
                   'a 2-character text inside a 16-character text does not match')
    selftest_check(score_texts_match('9', '9', 1), 'equal short texts match')
    patch = [item('a', 3, 'SECRETVALUE1234', 'c' * 40)]
    blob = [item('a', 7, 'SECRETVALUE1234', 'd' * 40)]
    selftest_check(score_compare(patch, blob, 'l', 'r')['matched'] == 0
                   and score_commit_agnostic(patch, blob)['matched'] == 1,
                   'commit-agnostic matching pairs a value found at different commits')


def selftest_tool(directory, family, adapter, version):
    path = os.path.join(directory, 'fake-' + adapter)
    write_private(path, (FAKE_SCANNER % {'python': sys.executable, 'family': adapter}).encode())
    os.chmod(path, 0o700)
    tool = {'id': 'fake-' + adapter, 'family': family, 'version': version, 'binary': path,
            'sha256': sha256_file(path), 'build': 'synthetic', 'regex_engine': 'python-re', 'notes': 'self-test'}
    if adapter == 'rustleaks':
        tool['rule_count'] = 2
    return tool


def selftest_options(base, **overrides):
    arguments = ['run', '--tools', base['tools'], '--workloads', base['workloads'], '--cache-root', base['cache'],
                 '--output', overrides.pop('output'), '--git', base['git']]
    for key, value in overrides.items():
        arguments += ['--' + key.replace('_', '-'), value]
    options = main_parser().parse_args(arguments)
    main_normalize(options)
    return options


def selftest_end_to_end():
    directory = tempfile.mkdtemp(prefix='compare-e2e-')
    secrets = ['SYNTHA' + ''.join(random.Random(index).choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567') for _ in range(16))
               for index in range(3)]
    try:
        bins = private_dir(os.path.join(directory, 'tools'))
        tools = [selftest_tool(bins, 'rustleaks', 'rustleaks', '0.0.0'),
                 selftest_tool(bins, 'gitleaks', 'gitleaks', '8.0.0'),
                 selftest_tool(bins, 'betterleaks', 'betterleaks-v1', '1.0.0'),
                 selftest_tool(bins, 'betterleaks', 'betterleaks-v2', '2.0.0'),
                 selftest_tool(bins, 'kingfisher', 'kingfisher', '2.0.0')]
        git = os.path.join(bins, 'git')
        write_private(git, (FAKE_GIT % {'python': sys.executable}).encode())
        os.chmod(git, 0o700)
        cache = private_dir(os.path.join(directory, 'cache'))
        tree = os.path.join(cache, 'synthetic', 'tree')
        os.makedirs(os.path.join(tree, 'src'))
        os.makedirs(os.path.join(tree, '.git'))
        content = 'first = "%s"\n\nsecond = "%s"\nthird: %s\n' % tuple(secrets)
        write_private(os.path.join(tree, 'src', 'config.txt'), content.encode())
        write_private(os.path.join(tree, '.git', 'config'), ('token = %s\n' % secrets[0]).encode())
        offsets = [content.index(secret) for secret in secrets]
        labels = os.path.join(cache, 'synthetic', 'labels.jsonl')
        write_private(labels, b''.join(json_bytes({
            'workload': 'tiny', 'path': 'src/config.txt', 'commit': None, 'start': offset, 'end': offset + len(secret),
            'line': content.count('\n', 0, offset) + 1, 'secret_sha256': sha256_text(secret),
            'category': 'synthetic-token', 'label': 'secret', 'source': 'constructed'}) + b'\n'
            for offset, secret in zip(offsets, secrets)))
        base = {'tools': os.path.join(directory, 'tools.json'), 'workloads': os.path.join(directory, 'workloads.json'),
                'cache': cache, 'git': git}
        write_json(base['tools'], {'schema': SCHEMA_TOOLS, 'tools': tools})
        write_json(base['workloads'], {'schema': SCHEMA_WORKLOADS, 'set': 'self-test', 'workloads': [{
            'id': 'tiny', 'family': 'synthetic', 'modes': ['dir', 'git'],
            'source': {'kind': 'generated', 'generator': 'self-test', 'params': {}, 'seed': '1'},
            'path': 'synthetic/tree', 'size': {'bytes': len(content), 'files': 1, 'commits': 0},
            'labels': 'synthetic/labels.jsonl', 'tuned': True}]})
        output = os.path.join(directory, 'run-dir')
        options = selftest_options(base, output=output, lanes='defaults,threads,features,shared-rules,rustleaks-2x2',
                                   modes='dir', threads='1,2', shared_threads='1', warmups='1', runs='2')
        selftest_check(run_command(options) == 0, 'dir run completes')
        run = read_json(os.path.join(output, 'run.json'))
        statuses = collections.Counter(cell['status'] for cell in run['cells'])
        selftest_check(statuses.get('failed', 0) == 0 and statuses.get('dropped', 0) == 0, 'no cell fails: %s' % statuses)
        selftest_check(run['protocol_deviations'], 'run count override is recorded as a deviation')
        for cell in run['cells']:
            argv = cell.get('argv') or []
            if cell['adapter'] == 'betterleaks-v2':
                selftest_check('-v' not in argv and '--validate=false' in argv, 'Betterleaks v2 never gets -v')
            if cell['adapter'] == 'kingfisher':
                selftest_check('--no-validate' in argv and ('--git-history' in argv) == (cell['mode'] == 'dir'),
                               'Kingfisher validation off and history off in dir mode')
            for flag in cell.get('flags') or []:
                selftest_check(flag['reason'], 'every flag has a reason')
        samples = read_jsonl(os.path.join(output, 'samples.jsonl'))
        cold = [row for row in samples if row['cell_id'].endswith('/cold')]
        selftest_check(cold and all(row['phase'] == 'measured' for row in cold), 'cold cells have no warmups')
        selftest_check(all(row['status'] == 'ok' for row in samples), 'every sample is ok')
        report = open(os.path.join(output, 'report.md'), encoding='utf-8').read()
        for heading in ('## Host', '## Tools', '## Lane: defaults', '## Lane: rustleaks-2x2', '## Disclosure',
                        '### Flags that are not tool defaults', '## Identity agreement', '## Quality against labels'):
            selftest_check(heading in report, 'report has ' + heading)
        selftest_check('page cache is not purged' in report, 'report states the page cache limit')
        summary = read_json(os.path.join(output, 'summary.json'))
        selftest_check(any(cell['ratios'].get('wall_ns') for cell in summary['cells']), 'ratios are computed')
        score = read_json(os.path.join(output, 'score.json'))
        recalls = {row['tool']: row['overall']['recall'] for row in score['quality'] if row['lane'] == 'defaults'}
        selftest_check(recalls and all(value == 1.0 for value in recalls.values()), 'every fake tool finds every label')
        twins = [row for row in score['comparisons'] if 'betterleaks-v2' in row['right'] or 'betterleaks-v2' in row['left']]
        selftest_check(any(sum(row['only_left_by_hint'].values()) + sum(row['only_right_by_hint'].values()) for row in twins),
                       'duplicate reporting shows up as unmatched items')
        for name in ('run.json', 'samples.jsonl', 'summary.json', 'score.json', 'score.md', 'report.md'):
            text = open(os.path.join(output, name), encoding='utf-8').read()
            selftest_check(not any(secret in text for secret in secrets), name + ' carries no secret text')
            selftest_check(directory not in text or name in ('run.json',), name + ' carries no private paths')
        selftest_check(stat.S_IMODE(os.stat(output).st_mode) == 0o700, 'run folder is private')
        git_output = os.path.join(directory, 'run-git')
        options = selftest_options(base, output=git_output, lanes='defaults', modes='git', cache='warm',
                                   warmups='0', runs='1')
        selftest_check(run_command(options) == 0, 'git run completes')
        run = read_json(os.path.join(git_output, 'run.json'))
        children = {cell['adapter']: cell.get('children') for cell in run['cells']}
        selftest_check(children['gitleaks']['processes'] == 1 and children['kingfisher']['processes'] == 0,
                       'the git shim counts git processes per tool: %s' % children)
        dry = os.path.join(directory, 'run-dry')
        options = selftest_options(base, output=dry, lanes='threads', modes='dir', threads='1,2')
        options.dry_run = True
        plan = io.StringIO()
        with contextlib.redirect_stdout(plan):
            code = run_command(options)
        selftest_check(plan.getvalue().count('planned ') == 10, 'dry run prints the plan')
        selftest_check(code == 0 and not os.path.exists(os.path.join(dry, 'samples.jsonl')),
                       'dry run plans without running tools')
        write_private(os.path.join(tree, '.gitleaksignore'), b'')
        dry = os.path.join(directory, 'run-dry-ignore')
        options = selftest_options(base, output=dry, lanes='defaults', modes='dir', cache='warm')
        options.dry_run = True
        with contextlib.redirect_stdout(io.StringIO()):
            run_command(options)
        statuses = {cell['adapter']: cell['status'] for cell in read_json(os.path.join(dry, 'run.json'))['cells']}
        selftest_check(statuses == {'rustleaks': 'skipped', 'gitleaks': 'skipped', 'betterleaks-v1': 'skipped',
                                    'betterleaks-v2': 'planned', 'kingfisher': 'planned'},
                       'cells whose tool loads a root ignore file are skipped: %s' % statuses)
        os.remove(os.path.join(tree, '.gitleaksignore'))
        tools[0]['sha256'] = '0' * 64
        write_json(base['tools'], {'schema': SCHEMA_TOOLS, 'tools': tools}, exclusive=False)
        try:
            manifest_load_tools(base['tools'])
            selftest_check(False, 'a wrong binary hash is rejected')
        except HarnessError:
            pass
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def selftest_main():
    selftest_units()
    selftest_matching()
    selftest_adapters()
    selftest_end_to_end()
    print('comparison self-test passed')
    return 0
