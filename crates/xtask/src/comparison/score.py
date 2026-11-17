# Comparison harness: one-to-one matching, quality against labels and
# identity agreement between tools.
#
# Two items match when they have the same path and commit, their line ranges
# intersect, and their secret texts overlap: one contains the other, or a
# common substring covers at least half of the shorter text. Matching is
# greedy by the largest overlap, then by the smallest line distance, and each
# item is used at most once. Secret texts stay in memory; outputs carry only
# a SHA-256 and a length.

SCORE_NEAR_LINES = 3
SCORE_MIN_SHARED = 8


def score_overlap(left, right):
    if not left or not right:
        return 0
    if left in right or right in left:
        return min(len(left), len(right))
    matcher = difflib.SequenceMatcher(None, left, right, autojunk=False)
    return matcher.find_longest_match(0, len(left), 0, len(right)).size


def score_texts_match(left, right, overlap):
    return overlap > 0 and 2 * overlap >= min(len(left), len(right))


def score_lines_intersect(left, right):
    if left['start_line'] == 0 or right['start_line'] == 0:
        return left['start_line'] == right['start_line'] == 0
    return left['start_line'] <= right['end_line'] and right['start_line'] <= left['end_line']


def score_line_distance(left, right):
    if score_lines_intersect(left, right):
        return 0
    return min(abs(left['start_line'] - right['end_line']), abs(right['start_line'] - left['end_line']))


def score_index(items):
    index = collections.defaultdict(list)
    for position, item in enumerate(items):
        index[(item['path'], item['commit'] or '')].append(position)
    return index


def score_match(left, right):
    """Return (pairs, unmatched left positions, unmatched right positions)."""
    right_index = score_index(right)
    candidates = []
    for i, item in enumerate(left):
        for j in right_index.get((item['path'], item['commit'] or ''), ()):
            other = right[j]
            if not score_lines_intersect(item, other):
                continue
            overlap = score_overlap(item['secret'], other['secret'])
            if score_texts_match(item['secret'], other['secret'], overlap):
                candidates.append((-overlap, abs(item['start_line'] - other['start_line']), i, j))
    candidates.sort()
    used_left, used_right, pairs = set(), set(), []
    for negative, _, i, j in candidates:
        if i in used_left or j in used_right:
            continue
        used_left.add(i)
        used_right.add(j)
        pairs.append((i, j, -negative))
    return (pairs, [i for i in range(len(left)) if i not in used_left],
            [j for j in range(len(right)) if j not in used_right])


def score_public(item):
    row = {'path': item['path'], 'commit': item['commit'] or None, 'start_line': item['start_line'],
           'end_line': item['end_line'], 'rule': item['rule'], 'secret_sha256': item['secret_sha256'],
           'secret_length': item['secret_length']}
    if 'label' in item:
        row['label'] = item['label']
    return row


def score_relation(item, other):
    overlap = score_overlap(item['secret'], other['secret'])
    if item['secret'] == other['secret']:
        text = 'same text'
    elif item['secret'] and item['secret'] in other['secret']:
        text = 'text inside counterpart'
    elif other['secret'] and other['secret'] in item['secret']:
        text = 'counterpart text inside this text'
    elif overlap:
        text = 'texts share %d characters' % overlap
    else:
        text = 'texts disjoint'
    lines = 'lines intersect' if score_lines_intersect(item, other) else 'lines differ by %d' % score_line_distance(item, other)
    return overlap, text, lines


def score_hint(position, items, matched_same, others):
    """Explain why an item has no partner, from the closest candidates."""
    item = items[position]
    same_index = [k for k in matched_same if k != position
                  and items[k]['path'] == item['path'] and (items[k]['commit'] or '') == (item['commit'] or '')]
    for k in same_index:
        twin = items[k]
        if score_lines_intersect(item, twin) and score_texts_match(
                item['secret'], twin['secret'], score_overlap(item['secret'], twin['secret'])):
            return {'hint': 'duplicate', 'detail': 'same value already matched under rule ' + twin['rule'],
                    'counterpart': score_public(twin)}
    best = None
    for other in others:
        if other['path'] != item['path'] or (other['commit'] or '') != (item['commit'] or ''):
            continue
        distance = score_line_distance(item, other)
        overlap = score_overlap(item['secret'], other['secret'])
        key = (-(overlap >= SCORE_MIN_SHARED or score_texts_match(item['secret'], other['secret'], overlap)),
               distance, -overlap)
        if best is None or key < best[0]:
            best = (key, other, overlap, distance)
    if best is None:
        return {'hint': 'no-counterpart', 'detail': 'no item from the other side in this file', 'counterpart': None}
    _, other, overlap, distance = best
    _, text, lines = score_relation(item, other)
    shares = overlap >= SCORE_MIN_SHARED or score_texts_match(item['secret'], other['secret'], overlap)
    if shares and distance <= SCORE_NEAR_LINES:
        hint = 'span-difference'
    elif distance == 0:
        hint = 'same-lines-other-value'
    elif distance <= SCORE_NEAR_LINES:
        hint = 'nearby-other-value'
    else:
        hint = 'no-counterpart'
    return {'hint': hint, 'detail': text + '; ' + lines, 'counterpart': score_public(other)}


def score_compare(left, right, left_name, right_name):
    pairs, unmatched_left, unmatched_right = score_match(left, right)
    matched_left = [i for i, _, _ in pairs]
    matched_right = [j for _, j, _ in pairs]

    def listing(positions, items, matched, others):
        rows = []
        for position in positions:
            row = score_public(items[position])
            row.update(score_hint(position, items, matched, others))
            rows.append(row)
        rows.sort(key=lambda row: (row['path'], row['commit'] or '', row['start_line'], row['rule'], row['secret_sha256']))
        return rows

    only_left = listing(unmatched_left, left, matched_left, right)
    only_right = listing(unmatched_right, right, matched_right, left)
    total = len(pairs) + len(only_left) + len(only_right)
    return {'left': left_name, 'right': right_name, 'left_items': len(left), 'right_items': len(right),
            'matched': len(pairs), 'only_left': only_left, 'only_right': only_right,
            'agreement': (len(pairs) / total) if total else 1.0,
            'only_left_by_hint': dict(collections.Counter(row['hint'] for row in only_left)),
            'only_right_by_hint': dict(collections.Counter(row['hint'] for row in only_right))}


def score_read_blob(root, commit, path, git):
    if not commit:
        with open(os.path.join(root, path), 'rb') as handle:
            return handle.read()
    if not git:
        raise HarnessError('labels with a commit need git')
    completed = subprocess.run([git, '-C', root, 'show', '%s:%s' % (commit, path)], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env={'PATH': SYSTEM_PATH, 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
                                    'GIT_CONFIG_GLOBAL': '/dev/null', 'HOME': '/nonexistent'})
    if completed.returncode != 0:
        raise OSError('git show failed')
    return completed.stdout


SCORE_TEST_FOLDERS = frozenset(('test', 'tests', 'spec', 'fixtures', 'examples'))


def score_test_scope(path):
    """True when a folder in the path is test, tests, spec, fixtures or examples."""
    folders = path.replace('\\', '/').split('/')[:-1]
    return any(folder.lower() in SCORE_TEST_FOLDERS for folder in folders)


def score_load_labels(path, workload_id, root, git=None, mode=None):
    """Load labels for one workload. Each label's text is read from the input
    and checked against its SHA-256; a label that does not check is reported
    and left out. Labels without a commit apply to dir mode, labels with a
    commit to git mode.

    A label is line-level when it has "span": "line", or when its byte range
    starts at the start of a line and ends at the end of a line. A line-level
    label matches any finding whose line range intersects its lines.

    A label value other than secret and not-secret, such as ambiguous, is
    kept: scoring excludes it from precision and recall and counts it."""
    labels, problems = [], collections.Counter()
    cache = {}
    for row in read_jsonl(path):
        if workload_id is not None and row.get('workload') != workload_id:
            continue
        if mode is not None and bool(row.get('commit')) != (mode == 'git'):
            continue
        if not isinstance(row.get('label'), str) or not row['label']:
            problems['label value missing'] += 1
            continue
        key = (row.get('commit') or '', row.get('path'))
        try:
            if key not in cache:
                cache[key] = score_read_blob(root, key[0], key[1], git)
            data = cache[key]
        except (OSError, TypeError):
            problems['file not readable'] += 1
            continue
        start, end = row.get('start'), row.get('end')
        if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start < end <= len(data):
            problems['offsets outside the file'] += 1
            continue
        segment = data[start:end]
        if sha256_bytes(segment) != row.get('secret_sha256'):
            problems['text does not match secret_sha256'] += 1
            continue
        line = data.count(b'\n', 0, start) + 1
        if row.get('line') not in (None, line):
            problems['line differs from byte offset (offset used)'] += 1
        body = segment[:-1] if segment.endswith(b'\n') else segment
        whole_lines = ((start == 0 or data[start - 1:start] == b'\n')
                       and (end == len(data) or data[end:end + 1] in (b'\n', b'\r') or segment.endswith(b'\n')))
        line_level = row.get('span') == 'line' or (row.get('span') is None and whole_lines)
        text = segment.decode('utf-8', 'replace')
        category = row.get('category') or 'uncategorized'
        labels.append({'rule': category, 'path': row['path'], 'commit': row.get('commit') or '',
                       'start_line': line, 'end_line': line + body.count(b'\n'), 'secret': text,
                       'secret_sha256': row['secret_sha256'], 'secret_length': len(text),
                       'label': row['label'], 'category': category, 'source': row.get('source') or 'unknown',
                       'start': start, 'end': end, 'line_level': line_level})
    return labels, dict(problems)


def score_label_groups(labels):
    """Merge labels with the same path and commit whose byte spans overlap.

    A group is one unit for scoring: a finding that matches any member
    satisfies the group. The group is a secret when any member is one; its
    category and source come from its narrowest secret member (or narrowest
    member when none is a secret)."""
    ordered = sorted(labels, key=lambda label: (label['path'], label['commit'], label['start'], label['end']))
    groups = []
    for label in ordered:
        last = groups[-1] if groups else None
        if (last is not None and last['path'] == label['path'] and last['commit'] == label['commit']
                and label['start'] < last['end']):
            last['members'].append(label)
            last['end'] = max(last['end'], label['end'])
            last['start_line'] = min(last['start_line'], label['start_line'])
            last['end_line'] = max(last['end_line'], label['end_line'])
        else:
            groups.append({'path': label['path'], 'commit': label['commit'], 'start': label['start'],
                           'end': label['end'], 'start_line': label['start_line'],
                           'end_line': label['end_line'], 'members': [label]})
    for group in groups:
        secrets = [member for member in group['members'] if member['label'] == 'secret']
        pool = secrets or group['members']
        primary = min(pool, key=lambda member: (member['end'] - member['start'], member['start']))
        group.update({'label': 'secret' if secrets else 'not-secret', 'primary': primary,
                      'category': primary['category'], 'source': primary['source']})
    return groups


def score_group_overlap(finding, group):
    """Return a match score for a finding and a label group, or None.

    Text matches score by the shared length. A line-level match scores 0, so
    a value-span match is always preferred."""
    best = None
    for member in group['members']:
        if not score_lines_intersect(member, finding):
            continue
        if member['line_level']:
            score = 0
        else:
            overlap = score_overlap(member['secret'], finding['secret'])
            if not score_texts_match(member['secret'], finding['secret'], overlap):
                continue
            score = overlap
        best = score if best is None else max(best, score)
    return best


def score_quality(findings, labels, labels_complete=True):
    """Precision, recall and F1 from one-to-one matching of label groups and
    findings, by category, by label source and by test or other paths.

    With complete labels, a finding that matches no label is a false
    positive. With partial labels it is counted as unknown instead."""
    excluded_labels = [label for label in labels if label['label'] not in ('secret', 'not-secret')]
    groups = score_label_groups([label for label in labels if label['label'] in ('secret', 'not-secret')])
    excluded_groups = score_label_groups(excluded_labels)
    excluded_index = score_index(excluded_groups)
    index = score_index(groups)
    candidates = []
    for j, finding in enumerate(findings):
        for g in index.get((finding['path'], finding['commit'] or ''), ()):
            score = score_group_overlap(finding, groups[g])
            if score is not None:
                candidates.append((-score, abs(groups[g]['start_line'] - finding['start_line']), g, j))
    candidates.sort()
    used_groups, used_findings, pairs = set(), set(), []
    for _, _, g, j in candidates:
        if g in used_groups or j in used_findings:
            continue
        used_groups.add(g)
        used_findings.add(j)
        pairs.append((g, j))

    def bucket():
        return {'true_positive': 0, 'false_negative': 0, 'false_positive_on_negative': 0, 'true_negative': 0,
                'unlabeled_findings': 0, 'unknown_findings': 0, 'duplicate_findings': 0, 'excluded_findings': 0}

    dimensions = {'category': collections.defaultdict(bucket), 'source': collections.defaultdict(bucket),
                  'scope': collections.defaultdict(bucket)}
    total = bucket()

    def add(group_or_path, key, source=None, category=None):
        scope = 'test paths' if score_test_scope(group_or_path) else 'other paths'
        for dimension, name in (('category', category), ('source', source), ('scope', scope)):
            if name is not None:
                dimensions[dimension][name][key] += 1
        total[key] += 1

    on_negatives = []
    for g, j in pairs:
        group = groups[g]
        key = 'true_positive' if group['label'] == 'secret' else 'false_positive_on_negative'
        add(group['path'], key, group['source'], group['category'])
        if key == 'false_positive_on_negative':
            row = score_public(findings[j])
            row.update({'hint': 'finding on a not-secret label', 'detail': 'category ' + group['category'],
                        'counterpart': score_public(group['primary'])})
            on_negatives.append(row)
    missed = []
    for g, group in enumerate(groups):
        if g in used_groups:
            continue
        key = 'false_negative' if group['label'] == 'secret' else 'true_negative'
        add(group['path'], key, group['source'], group['category'])
        if key == 'false_negative':
            row = score_public(group['primary'])
            row.update(score_hint(0, [group['primary']], [], findings))
            row['group_members'] = len(group['members'])
            missed.append(row)
    unmatched = []
    for j, finding in enumerate(findings):
        if j in used_findings:
            continue
        row = score_public(finding)
        twin = next((groups[g] for g in index.get((finding['path'], finding['commit'] or ''), ())
                     if g in used_groups and score_group_overlap(finding, groups[g]) is not None), None)
        excluded = next((group for group in (excluded_groups[g] for g in
                                             excluded_index.get((finding['path'], finding['commit'] or ''), ()))
                         if score_group_overlap(finding, group) is not None), None)
        if twin is not None:
            key = 'duplicate_findings'
            row.update({'hint': 'duplicate', 'detail': 'its label group already matched another finding',
                        'counterpart': score_public(twin['primary'])})
        elif excluded is not None:
            key = 'excluded_findings'
            row.update({'hint': 'excluded', 'detail': 'matches a label with the value ' + excluded['primary']['label'],
                        'counterpart': score_public(excluded['primary'])})
        else:
            key = 'unlabeled_findings' if labels_complete else 'unknown_findings'
            members = [member for g in index.get((finding['path'], finding['commit'] or ''), ())
                       for member in groups[g]['members']]
            row.update(score_hint(0, [finding], [], members))
            row['hint'] = ('unlabeled: ' if labels_complete else 'unknown: ') + row['hint']
        add(finding['path'], key)
        unmatched.append(row)

    def rates(counts):
        tp, fn = counts['true_positive'], counts['false_negative']
        labeled_fp = counts['false_positive_on_negative']
        strict_fp = labeled_fp + counts['unlabeled_findings'] + counts['duplicate_findings']

        def f1(precision, recall):
            if precision is None or recall is None:
                return None
            return 2 * precision * recall / (precision + recall) if precision + recall else 0.0

        precision = tp / (tp + strict_fp) if tp + strict_fp else None
        labeled = tp / (tp + labeled_fp) if tp + labeled_fp else None
        recall = tp / (tp + fn) if tp + fn else None
        result = dict(counts)
        result.update({'precision_strict': precision, 'precision_labeled_only': labeled, 'recall': recall,
                       'f1_strict': f1(precision, recall), 'f1_labeled_only': f1(labeled, recall)})
        return result

    overall = rates(total)
    overall.update({'findings': len(findings), 'labels': len(labels), 'label_groups': len(groups),
                    'excluded_labels': len(excluded_labels),
                    'excluded_label_values': dict(collections.Counter(label['label'] for label in excluded_labels)),
                    'labels_complete': bool(labels_complete)})
    return {'overall': overall, 'labels_complete': bool(labels_complete),
            'by_category': {name: rates(counts) for name, counts in sorted(dimensions['category'].items())},
            'by_source': {name: rates(counts) for name, counts in sorted(dimensions['source'].items())},
            'by_scope': {name: rates(counts) for name, counts in sorted(dimensions['scope'].items())},
            'missed_labels': sorted(missed, key=lambda row: (row['path'], row['start_line'])),
            'findings_on_negatives': on_negatives,
            'unmatched_findings': sorted(unmatched, key=lambda row: (row['path'], row['start_line'], row['rule']))}


def score_spec(text):
    """Parse ADAPTER=PATH for ad hoc scoring."""
    adapter, separator, path = text.partition('=')
    allowed = ('rustleaks', 'gitleaks', 'betterleaks-v1', 'betterleaks-v2', 'kingfisher')
    if not separator or adapter not in allowed or not path:
        raise HarnessError('expected ADAPTER=REPORT with ADAPTER one of %s' % ', '.join(allowed))
    return adapter, path


def score_adhoc(args):
    target = os.path.abspath(args.target)
    sides = []
    for spec in (args.left, args.right):
        if spec is None:
            continue
        adapter, path = score_spec(spec)
        findings, _ = adapter_parse(adapter, path, target, args.mode)
        sides.append(('%s:%s' % (adapter, os.path.basename(path)), findings, path))
    result = {'schema': SCHEMA_SCORE, 'kind': 'ad hoc', 'target': target, 'mode': args.mode,
              'reports': [{'name': name, 'sha256': sha256_file(path), 'findings': len(findings)}
                          for name, findings, path in sides],
              'comparisons': [], 'quality': []}
    if len(sides) == 2:
        result['comparisons'].append(score_compare(sides[0][1], sides[1][1], sides[0][0], sides[1][0]))
    if args.labels:
        git = resolve_git(args.git)
        labels, problems = score_load_labels(args.labels, args.workload, target, git and git['path'], args.mode)
        for name, findings, _ in sides:
            quality = score_quality(findings, labels, not args.labels_partial)
            quality.update({'name': name, 'label_problems': problems, 'labels': len(labels)})
            result['quality'].append(quality)
    return result


def score_run(run_dir, seed):
    """Score every kept report in a run: identity agreement within each
    comparable group, and quality for workloads with labels."""
    run = read_json(os.path.join(run_dir, 'run.json'))
    cells = [cell for cell in run['cells'] if cell.get('kept_report') and cell.get('cache') == 'warm']
    if not cells:
        cells = [cell for cell in run['cells'] if cell.get('kept_report')]
    workloads = {workload['id']: workload for workload in run['workloads']}
    git = run.get('git') and run['git'].get('path')
    loaded = {}
    for cell in cells:
        try:
            findings, _ = adapter_parse(cell['adapter'], os.path.join(run_dir, cell['kept_report']),
                                        workloads[cell['workload']]['target'], cell['mode'])
            loaded[cell['cell_id']] = findings
        except (OSError, ValueError) as error:
            loaded[cell['cell_id']] = None
            cell['score_error'] = str(error)[:200]
    groups = collections.defaultdict(list)
    for cell in cells:
        if loaded.get(cell['cell_id']) is not None:
            groups[(cell['group'], cell['cache'])].append(cell)
    comparisons = []
    for (group, cache), members in sorted(groups.items()):
        members.sort(key=lambda cell: cell['cell_id'])
        for a in range(len(members)):
            for b in range(a + 1, len(members)):
                left, right = members[a], members[b]
                result = score_compare(loaded[left['cell_id']], loaded[right['cell_id']],
                                       left['cell_id'], right['cell_id'])
                result.update({'group': group, 'cache': cache})
                comparisons.append(result)
    quality, label_cache = [], {}
    for cell in cells:
        workload = workloads[cell['workload']]
        if not workload.get('labels_path') or loaded.get(cell['cell_id']) is None:
            continue
        key = (workload['id'], cell['mode'])
        if key not in label_cache:
            if not os.path.isfile(workload['labels_path']):
                label_cache[key] = None
            else:
                label_cache[key] = score_load_labels(workload['labels_path'], workload['id'],
                                                     workload['target'], git, cell['mode'])
        if label_cache[key] is None or not label_cache[key][0]:
            continue
        labels, problems = label_cache[key]
        result = score_quality(loaded[cell['cell_id']], labels, workload.get('labels_complete', True) is not False)
        result.update({'name': cell['cell_id'], 'label_problems': problems, 'labels': len(labels),
                       'workload': workload['id'], 'lane': cell['lane'], 'tool': cell['tool']})
        quality.append(result)
    return {'schema': SCHEMA_SCORE, 'kind': 'run', 'run_id': run['run_id'], 'comparisons': comparisons,
            'quality': quality,
            'score_errors': [{'cell': cell['cell_id'], 'error': cell['score_error']}
                             for cell in cells if cell.get('score_error')]}


def score_rate_table(title, rows):
    lines = ['| %s | TP | FN | FP on negatives | TN | Unlabeled | Unknown | Duplicates | Excluded | '
             'Precision (strict) | Precision (labeled only) | Recall | F1 (strict) |' % title,
             '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for name, row in rows.items():
        lines.append('| %s | %d | %d | %d | %d | %d | %d | %d | %d | %s | %s | %s | %s |' % (
            name, row['true_positive'], row['false_negative'], row['false_positive_on_negative'],
            row['true_negative'], row['unlabeled_findings'], row['unknown_findings'], row['duplicate_findings'],
            row['excluded_findings'],
            report_rate(row['precision_strict']), report_rate(row['precision_labeled_only']),
            report_rate(row['recall']), report_rate(row['f1_strict'])))
    return lines + ['']


def score_markdown(result):
    lines = ['# Comparison score', '',
             'Matching is one-to-one: same path and commit, intersecting line ranges, and secret',
             'texts where one contains the other or a common substring covers at least half of',
             'the shorter. Secrets appear only as SHA-256 and length.', '']
    for comparison in result['comparisons']:
        lines += ['## %s versus %s' % (comparison['left'], comparison['right']), '']
        if comparison.get('group'):
            lines += ['Group: `%s` (%s cache).' % (comparison['group'], comparison['cache']), '']
        lines += ['| Items left | Items right | Matched | Only left | Only right | Agreement |',
                  '| ---: | ---: | ---: | ---: | ---: | ---: |',
                  '| %d | %d | %d | %d | %d | %.4f |' % (
                      comparison['left_items'], comparison['right_items'], comparison['matched'],
                      len(comparison['only_left']), len(comparison['only_right']), comparison['agreement']), '']
        for side, key in (('left', 'only_left'), ('right', 'only_right')):
            rows = comparison[key]
            if not rows:
                continue
            hints = comparison[key + '_by_hint']
            lines += ['Only %s, by hint: %s.' % (side, ', '.join('%s %d' % item for item in sorted(hints.items()))), '',
                      '| Path | Commit | Lines | Rule | Secret SHA-256 | Length | Hint | Detail | Counterpart |',
                      '| --- | --- | --- | --- | --- | ---: | --- | --- | --- |']
            for row in rows:
                other = row['counterpart']
                lines.append('| `%s` | %s | %d-%d | `%s` | `%s` | %d | %s | %s | %s |' % (
                    row['path'], (row['commit'] or '')[:12], row['start_line'], row['end_line'], row['rule'],
                    row['secret_sha256'][:16], row['secret_length'], row['hint'], row['detail'],
                    '' if other is None else '`%s` %d-%d `%s`' % (other['rule'], other['start_line'],
                                                                  other['end_line'], other['secret_sha256'][:16])))
            lines.append('')
    for quality in result['quality']:
        overall = quality['overall']
        lines += ['## Quality: %s' % quality['name'], '',
                  'Labels used: %d in %d groups, plus %d excluded labels (%s) (%s). Label problems: %s.' % (
                      quality['labels'] - overall['excluded_labels'], overall['label_groups'], overall['excluded_labels'],
                      ', '.join('%s %d' % item for item in sorted(overall['excluded_label_values'].items())) or 'none',
                      'complete labels: findings with no label are false positives' if quality['labels_complete']
                      else 'partial labels: findings with no label are unknown',
                      ', '.join('%s %d' % item for item in sorted(quality['label_problems'].items())) or 'none'), '']
        lines += score_rate_table('Overall', {'all': overall})
        for title, key in (('Category', 'by_category'), ('Label source', 'by_source'), ('Path scope', 'by_scope')):
            lines += score_rate_table(title, quality[key])
        for title, rows in (('Missed secret labels', quality['missed_labels']),
                            ('Findings on not-secret labels', quality.get('findings_on_negatives', [])),
                            ('Findings with no label of their own', quality['unmatched_findings'])):
            if not rows:
                continue
            lines += [title + ':', '', '| Path | Lines | Rule or category | Secret SHA-256 | Length | Hint |',
                      '| --- | --- | --- | --- | ---: | --- |']
            for row in rows:
                lines.append('| `%s` | %d-%d | `%s` | `%s` | %d | %s |' % (
                    row['path'], row['start_line'], row['end_line'], row['rule'], row['secret_sha256'][:16],
                    row['secret_length'], row['hint']))
            lines.append('')
    if result.get('score_errors'):
        lines += ['## Reports that could not be scored', '']
        lines += ['- `%s`: %s' % (row['cell'], row['error']) for row in result['score_errors']]
        lines.append('')
    return '\n'.join(lines)
