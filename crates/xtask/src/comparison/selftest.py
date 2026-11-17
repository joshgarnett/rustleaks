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
    rows = [{'rule': {'id': 'kingfisher.synth'}, 'finding': {'snippet': secret, 'line': line,
             'column_start': column, 'column_end': column + len(secret) - 1, 'path': path}}
            for path, line, column, secret in found]
    with open(report, 'w') as handle:
        handle.write(json.dumps({'findings': rows, 'metadata': {'summary': {'rules_applied': 3}}}) + '\n')
        handle.write(json.dumps({'findings': len(rows), 'rules_applied': 3, 'bytes_scanned': 1,
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
    finally:
        shutil.rmtree(directory)
    profile = adapter_profile_text(4)
    selftest_check(len([line for line in profile.splitlines() if '=' in line]) == 33 and 'workers=4' in profile,
                   'generated profile has all 33 keys')
    selftest_check(adapter_shared_rules_toml().count('[[rules]]') == len(SHARED_RULES), 'shared rules file')


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
    selftest_end_to_end()
    print('comparison self-test passed')
    return 0
