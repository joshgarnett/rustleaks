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


def score_load_labels(path, workload_id, root, git=None, mode=None):
    """Load labels for one workload. Each label's text is read from the input
    and checked against its SHA-256; a label that does not check is reported
    and left out. Labels without a commit apply to dir mode, labels with a
    commit to git mode."""
    labels, problems = [], collections.Counter()
    cache = {}
    for row in read_jsonl(path):
        if workload_id is not None and row.get('workload') != workload_id:
            continue
        if mode is not None and bool(row.get('commit')) != (mode == 'git'):
            continue
        if row.get('label') not in ('secret', 'not-secret'):
            problems['unknown label value'] += 1
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
        text = segment.decode('utf-8', 'replace')
        labels.append({'rule': row.get('category') or 'uncategorized', 'path': row['path'],
                       'commit': row.get('commit') or '', 'start_line': line,
                       'end_line': line + segment.count(b'\n'), 'secret': text,
                       'secret_sha256': row['secret_sha256'], 'secret_length': len(text),
                       'label': row['label'], 'category': row.get('category') or 'uncategorized',
                       'source': row.get('source')})
    return labels, dict(problems)


def score_quality(findings, labels):
    """Precision, recall and F1 by category from one-to-one matching."""
    pairs, unmatched_labels, unmatched_findings = score_match(labels, findings)
    categories = collections.defaultdict(lambda: {'true_positive': 0, 'false_negative': 0,
                                                  'false_positive_on_negative': 0, 'true_negative': 0})
    for i, _, _ in pairs:
        label = labels[i]
        bucket = categories[label['category']]
        bucket['true_positive' if label['label'] == 'secret' else 'false_positive_on_negative'] += 1
    for i in unmatched_labels:
        label = labels[i]
        bucket = categories[label['category']]
        bucket['false_negative' if label['label'] == 'secret' else 'true_negative'] += 1
    comparison = score_compare(labels, findings, 'labels', 'findings')
    unlabeled = [row for row in comparison['only_right'] if row['hint'] != 'duplicate']
    duplicates = [row for row in comparison['only_right'] if row['hint'] == 'duplicate']

    def rates(tp, fp, fn):
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = (2 * precision * recall / (precision + recall)) if precision and recall else (0.0 if precision == 0 or recall == 0 else None)
        return {'precision': precision, 'recall': recall, 'f1': f1}

    by_category = {}
    for name, bucket in sorted(categories.items()):
        row = dict(bucket)
        row.update(rates(bucket['true_positive'], bucket['false_positive_on_negative'], bucket['false_negative']))
        by_category[name] = row
    tp = sum(bucket['true_positive'] for bucket in categories.values())
    fp_negative = sum(bucket['false_positive_on_negative'] for bucket in categories.values())
    fn = sum(bucket['false_negative'] for bucket in categories.values())
    overall = {'true_positive': tp, 'false_negative': fn, 'false_positive_on_negative': fp_negative,
               'true_negative': sum(bucket['true_negative'] for bucket in categories.values()),
               'unlabeled_findings': len(unlabeled), 'duplicate_findings': len(duplicates),
               'findings': len(findings)}
    strict = rates(tp, fp_negative + len(unlabeled) + len(duplicates), fn)
    labeled = rates(tp, fp_negative, fn)
    overall.update({'precision_strict': strict['precision'], 'recall': strict['recall'], 'f1_strict': strict['f1'],
                    'precision_labeled_only': labeled['precision'], 'f1_labeled_only': labeled['f1']})
    on_negatives = []
    for i, j, _ in pairs:
        if labels[i]['label'] != 'secret':
            row = score_public(findings[j])
            row.update({'hint': 'finding on a not-secret label', 'detail': 'category ' + labels[i]['category'],
                        'counterpart': score_public(labels[i])})
            on_negatives.append(row)
    return {'overall': overall, 'by_category': by_category,
            'missed_labels': [row for row in comparison['only_left'] if row.get('label') == 'secret'],
            'findings_on_negatives': on_negatives, 'unmatched_findings': comparison['only_right']}


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
            quality = score_quality(findings, labels)
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
        result = score_quality(loaded[cell['cell_id']], labels)
        result.update({'name': cell['cell_id'], 'label_problems': problems, 'labels': len(labels),
                       'workload': workload['id'], 'lane': cell['lane'], 'tool': cell['tool']})
        quality.append(result)
    return {'schema': SCHEMA_SCORE, 'kind': 'run', 'run_id': run['run_id'], 'comparisons': comparisons,
            'quality': quality,
            'score_errors': [{'cell': cell['cell_id'], 'error': cell['score_error']}
                             for cell in cells if cell.get('score_error')]}


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
                  'Labels used: %d. Label problems: %s.' % (
                      quality['labels'], ', '.join('%s %d' % item for item in sorted(quality['label_problems'].items())) or 'none'), '',
                  '| Findings | TP | FN | FP on negatives | Unlabeled | Duplicates | Precision (strict) | Precision (labeled only) | Recall | F1 (strict) |',
                  '| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
                  '| %d | %d | %d | %d | %d | %d | %s | %s | %s | %s |' % (
                      overall['findings'], overall['true_positive'], overall['false_negative'],
                      overall['false_positive_on_negative'], overall['unlabeled_findings'],
                      overall['duplicate_findings'], report_rate(overall['precision_strict']),
                      report_rate(overall['precision_labeled_only']), report_rate(overall['recall']),
                      report_rate(overall['f1_strict'])), '',
                  '| Category | TP | FN | FP on negatives | TN | Precision | Recall | F1 |',
                  '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
        for name, row in quality['by_category'].items():
            lines.append('| %s | %d | %d | %d | %d | %s | %s | %s |' % (
                name, row['true_positive'], row['false_negative'], row['false_positive_on_negative'],
                row['true_negative'], report_rate(row['precision']), report_rate(row['recall']), report_rate(row['f1'])))
        lines.append('')
        for title, rows in (('Missed secret labels', quality['missed_labels']),
                            ('Findings on not-secret labels', quality.get('findings_on_negatives', [])),
                            ('Findings with no label', quality['unmatched_findings'])):
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
