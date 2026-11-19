# Comparison harness: one-to-one matching, quality against labels and
# identity agreement between tools.
#
# Two items match when they have the same path and commit, their line ranges
# intersect, and their secret texts match: the texts are equal, or they share
# at least SCORE_MIN_SHARED characters (as a containment or a common
# substring) and the shared part covers at least half of the shorter text.
# The pairing is a maximum one-to-one matching: no other pairing matches
# more items. Among maximum pairings, larger overlaps are preferred. Secret
# texts stay in memory; outputs carry only a SHA-256 and a length.

SCORE_NEAR_LINES = 3
SCORE_MIN_SHARED = 4
SCORE_MAX_CANDIDATES = 64
SCORE_WINDOW = 256
SCORE_MAX_HINTS = 5000
SCORE_MARKDOWN_ROWS = 1000
# Pairs of texts whose lengths multiply to more than this are compared by
# equality and containment only (difflib is quadratic in the lengths).
SCORE_MAX_WORK = 4096 * 4096
SCORE_OVERLAP_MEMO_LIMIT = 1000000
SCORE_DEFAULT_HOURS = 12
SCORE_GIT_SECONDS = 600
SCORE_LIMIT = {'deadline': None, 'hours': None}
SCORE_OVERLAP_MEMO = {}


class ScoreTimeLimit(Exception):
    """Scoring passed its time limit (--score-hours)."""


def score_check():
    deadline = SCORE_LIMIT['deadline']
    if deadline is not None and time.monotonic() > deadline:
        raise ScoreTimeLimit('scoring time limit of %s hours reached' % SCORE_LIMIT['hours'])
SCORE_TEST_FOLDERS = frozenset(('test', 'tests', 'spec', 'fixtures', 'examples'))


def score_overlap(left, right):
    """Length of the longest text the two secrets share."""
    if not left or not right:
        return 0
    if left == right:
        return len(left)
    if left in right or right in left:
        return min(len(left), len(right))
    if len(left) * len(right) > SCORE_MAX_WORK:
        # Long values (such as private keys) are compared by containment only.
        return 0
    key = (left, right)
    size = SCORE_OVERLAP_MEMO.get(key)
    if size is None:
        matcher = difflib.SequenceMatcher(None, left, right, autojunk=False)
        size = matcher.find_longest_match(0, len(left), 0, len(right)).size
        if len(SCORE_OVERLAP_MEMO) >= SCORE_OVERLAP_MEMO_LIMIT:
            SCORE_OVERLAP_MEMO.clear()
        SCORE_OVERLAP_MEMO[key] = size
    return size


def score_could_match(left, right):
    """False only when the texts cannot match (see score_texts_match).

    A match needs a shared run of `need` characters. Any such run in the
    shorter text contains one of its aligned blocks of need // 2 characters,
    so when no block occurs in the longer text there is no match."""
    short, long_ = (left, right) if len(left) <= len(right) else (right, left)
    if short in long_:
        return True
    need = max(SCORE_MIN_SHARED, (len(short) + 1) // 2)
    size = max(1, need // 2)
    return any(short[start:start + size] in long_ for start in range(0, len(short) - size + 1, size))


def score_text_overlap(left, right):
    """The overlap when two secret texts match, otherwise None."""
    if not left or not right:
        return None
    if left == right:
        return len(left)
    if not score_could_match(left, right):
        return None
    overlap = score_overlap(left, right)
    return overlap if score_texts_match(left, right, overlap) else None


def score_texts_match(left, right, overlap):
    if left and left == right:
        return True
    return overlap >= SCORE_MIN_SHARED and 2 * overlap >= min(len(left), len(right))


def score_lines_intersect(left, right):
    if left['start_line'] == 0 or right['start_line'] == 0:
        return left['start_line'] == right['start_line'] == 0
    return left['start_line'] <= right['end_line'] and right['start_line'] <= left['end_line']


def score_line_distance(left, right):
    if score_lines_intersect(left, right):
        return 0
    return min(abs(left['start_line'] - right['end_line']), abs(right['start_line'] - left['end_line']))


def score_keys(item, ignore_commit=False):
    if ignore_commit:
        return [(item['path'],)]
    commits = item.get('commits') or {item['commit'] or ''}
    return [(item['path'], commit) for commit in sorted(commits)]


def score_column(item):
    """Start column of an item, or 0 when the tool gave none (cached)."""
    value = item.get('_column')
    if value is None:
        columns = item.get('columns') or ()
        value = columns[0] if columns else None
        value = value if isinstance(value, int) and value > 0 else 0
        item['_column'] = value
    return value


def score_nearness(item, other):
    """Sort key for candidates: line distance, then column distance."""
    return (score_line_distance(item, other), abs(score_column(item) - score_column(other)))


class ScoreNeighbours(object):
    """Items indexed by path (and commit), sorted by line and column, for
    bounded lookups.

    A lookup never looks at more than SCORE_WINDOW items per key, so a file
    with many findings on one line (minified or generated files) stays cheap:
    when the line window is larger than that, only the items nearest by line
    and column are considered."""

    def __init__(self, items, ignore_commit=False):
        self.items = items
        self.by_key = collections.defaultdict(list)
        self.by_text = collections.defaultdict(list)
        self.span = collections.defaultdict(int)
        for position, item in enumerate(items):
            for key in score_keys(item, ignore_commit):
                self.by_key[key].append(position)
                self.by_text[key + (item['secret_sha256'],)].append(position)
                self.span[key] = max(self.span[key], item['end_line'] - item['start_line'])

        def order(position):
            return (items[position]['start_line'], score_column(items[position]), position)

        self.starts, self.orders = {}, {}
        for key, positions in self.by_key.items():
            positions.sort(key=order)
            self.starts[key] = [items[position]['start_line'] for position in positions]
            self.orders[key] = [order(position) for position in positions]
        self.text_orders = {}
        for key, positions in self.by_text.items():
            positions.sort(key=order)
            self.text_orders[key] = [order(position) for position in positions]
        self.ignore_commit = ignore_commit

    def has_key(self, item):
        return any(key in self.by_key for key in score_keys(item, self.ignore_commit))

    def near(self, item, radius, same_text=True):
        """Positions within `radius` lines, plus the nearest items with the
        same text, nearest first by line and then by column.

        At most SCORE_MAX_CANDIDATES positions."""
        found = set()
        probe = (item['start_line'], score_column(item), -1)
        for key in score_keys(item, self.ignore_commit):
            positions = self.by_key.get(key)
            if not positions:
                continue
            starts = self.starts[key]
            low = bisect.bisect_left(starts, item['start_line'] - radius - self.span[key])
            high = bisect.bisect_right(starts, item['end_line'] + radius)
            if high - low > SCORE_WINDOW:
                middle = bisect.bisect_left(self.orders[key], probe, low, high)
                low, high = max(low, middle - SCORE_WINDOW // 2), min(high, middle + SCORE_WINDOW // 2)
            for position in positions[low:high]:
                if score_line_distance(item, self.items[position]) <= radius:
                    found.add(position)
            if same_text:
                text_key = key + (item['secret_sha256'],)
                same = self.by_text.get(text_key)
                if same:
                    middle = bisect.bisect_left(self.text_orders[text_key], probe)
                    found.update(same[max(0, middle - SCORE_MAX_CANDIDATES):middle + SCORE_MAX_CANDIDATES])
        sha = item['secret_sha256']

        def order(position):
            other = self.items[position]
            return (score_line_distance(item, other), other['secret_sha256'] != sha,
                    abs(score_column(item) - score_column(other)), position)

        return sorted(found, key=order)[:SCORE_MAX_CANDIDATES]

    def path_items(self, item, limit=SCORE_MAX_CANDIDATES * 64):
        """Items in the same file in line order, for line-free matching
        (at most `limit`)."""
        found = []
        for key in score_keys(item, self.ignore_commit):
            found.extend(self.by_key.get(key, ())[:limit - len(found)])
            if len(found) >= limit:
                break
        return found

    def same_text_window(self, item, rank):
        """Items in the same file with the same text, around the rank-th one.

        Items with the same path and text are interchangeable for line-free
        matching, so pairing by rank keeps the matching maximum while each
        item gets at most 2 * SCORE_MAX_CANDIDATES candidates."""
        found = []
        for key in score_keys(item, self.ignore_commit):
            same = self.by_text.get(key + (item['secret_sha256'],), ())
            found.extend(same[max(0, rank - SCORE_MAX_CANDIDATES):rank + SCORE_MAX_CANDIDATES])
        return found


def score_assign(edges):
    """Maximum one-to-one matching of (score, distance, left, right) edges.

    A greedy pass by score takes the best pairs first. Augmenting paths then
    add pairs until no unmatched left item can be matched, which makes the
    matching maximum (Berge). Returns (left, right, score) triples."""
    edges = sorted(edges, key=lambda edge: (-edge[0], edge[1], edge[2], edge[3]))
    adjacency = collections.OrderedDict()
    weight = {}
    for score, _, left, right in edges:
        adjacency.setdefault(left, []).append(right)
        weight.setdefault((left, right), score)
    match_left, match_right = {}, {}
    for score, _, left, right in edges:
        if left not in match_left and right not in match_right:
            match_left[left] = right
            match_right[right] = left
    # Left nodes seen by a search that found no free right node cannot reach
    # one until the matching changes, so later searches skip them. This
    # does not change which path a search finds.
    dead = set()
    for count, start in enumerate(adjacency):
        if count % 256 == 0:
            score_check()
        if start in match_left:
            continue
        parent = {}
        queue = collections.deque([start])
        visited = {start}
        free = None
        while queue and free is None:
            node = queue.popleft()
            for right in adjacency[node]:
                if right in parent:
                    continue
                parent[right] = node
                if right not in match_right:
                    free = right
                    break
                partner = match_right[right]
                if partner not in visited and partner not in dead:
                    visited.add(partner)
                    queue.append(partner)
        if free is None:
            dead |= visited
            continue
        dead.clear()
        right = free
        while right is not None:
            node = parent[right]
            previous = match_left.get(node)
            match_left[node] = right
            match_right[right] = node
            right = previous if node != start else None
    return [(left, right, weight[(left, right)]) for left, right in match_left.items()]


def score_text_edges(left, right, ignore_commit=False, ignore_lines=False, index=None):
    index = index if index is not None else ScoreNeighbours(right, ignore_commit)
    edges = []
    # Items with the same path and text are paired by rank in line and
    # column order, so repeated values reach their partners while each item
    # gets a bounded number of candidates.
    ranks, counter = {}, collections.Counter()
    for i in sorted(range(len(left)), key=lambda i: (left[i]['start_line'], score_column(left[i]), i)):
        rank_key = (tuple(score_keys(left[i], ignore_commit)), left[i]['secret_sha256'])
        ranks[i] = counter[rank_key]
        counter[rank_key] += 1
    for i, item in enumerate(left):
        if i % 256 == 0:
            score_check()
        positions = set(index.same_text_window(item, ranks[i]))
        if ignore_lines:
            positions.update(position for position in index.path_items(item)
                             if right[position]['secret_sha256'] != item['secret_sha256'])
        else:
            positions.update(index.near(item, 0, same_text=False))
        for j in sorted(positions):
            other = right[j]
            if not ignore_lines and not score_lines_intersect(item, other):
                continue
            overlap = score_text_overlap(item['secret'], other['secret'])
            if overlap is not None:
                edges.append((overlap, score_nearness(item, other), i, j))
    return edges


def score_match(left, right, ignore_commit=False, ignore_lines=False, index=None):
    """Return (pairs, unmatched left positions, unmatched right positions)."""
    pairs = score_assign(score_text_edges(left, right, ignore_commit, ignore_lines, index))
    used_left = {i for i, _, _ in pairs}
    used_right = {j for _, j, _ in pairs}
    return (sorted(pairs), [i for i in range(len(left)) if i not in used_left],
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


def score_hint(item, own, own_matched, others):
    """Explain why an item has no partner, from nearby candidates only.

    `own` and `others` are ScoreNeighbours over each side; `own_matched` is
    the set of matched positions on the item's own side."""
    if own is not None:
        for position in own.near(item, 0, same_text=False):
            twin = own.items[position]
            if position in own_matched and twin is not item and score_lines_intersect(item, twin) and \
                    score_text_overlap(item['secret'], twin['secret']) is not None:
                return {'hint': 'duplicate', 'detail': 'same value already matched under rule ' + twin['rule'],
                        'counterpart': score_public(twin)}
    best = None
    for position in others.near(item, SCORE_NEAR_LINES):
        other = others.items[position]
        distance = score_line_distance(item, other)
        overlap = score_overlap(item['secret'], other['secret'])
        shares = score_texts_match(item['secret'], other['secret'], overlap)
        key = (not shares, distance, -overlap)
        if best is None or key < best[0]:
            best = (key, other, shares, distance)
    if best is None:
        detail = ('no item from the other side within %d lines' % SCORE_NEAR_LINES if others.has_key(item)
                  else 'no item from the other side in this file')
        return {'hint': 'no-counterpart', 'detail': detail, 'counterpart': None}
    _, other, shares, distance = best
    _, text, lines = score_relation(item, other)
    if shares and distance <= SCORE_NEAR_LINES:
        hint = 'span-difference'
    elif distance == 0:
        hint = 'same-lines-other-value'
    elif distance <= SCORE_NEAR_LINES:
        hint = 'nearby-other-value'
    else:
        hint = 'no-counterpart'
    return {'hint': hint, 'detail': text + '; ' + lines, 'counterpart': score_public(other)}


def score_compare(left, right, left_name, right_name, ignore_commit=False):
    left_index, right_index = ScoreNeighbours(left, ignore_commit), ScoreNeighbours(right, ignore_commit)
    pairs, unmatched_left, unmatched_right = score_match(left, right, ignore_commit, index=right_index)
    matched_left = {i for i, _, _ in pairs}
    matched_right = {j for _, j, _ in pairs}

    def listing(positions, items, own, matched, others):
        rows = []
        for count, position in enumerate(positions):
            if count % 256 == 0:
                score_check()
            row = score_public(items[position])
            if count < SCORE_MAX_HINTS:
                row.update(score_hint(items[position], own, matched, others))
            else:
                row.update({'hint': 'not-examined', 'counterpart': None,
                            'detail': 'hints are computed for the first %d unmatched items only' % SCORE_MAX_HINTS})
            rows.append(row)
        rows.sort(key=lambda row: (row['path'], row['commit'] or '', row['start_line'], row['rule'], row['secret_sha256']))
        return rows

    only_left = listing(unmatched_left, left, left_index, matched_left, right_index)
    only_right = listing(unmatched_right, right, right_index, matched_right, left_index)
    total = len(pairs) + len(only_left) + len(only_right)
    return {'left': left_name, 'right': right_name, 'left_items': len(left), 'right_items': len(right),
            'matched': len(pairs), 'only_left': only_left, 'only_right': only_right,
            'agreement': (len(pairs) / total) if total else 1.0,
            'only_left_by_hint': dict(collections.Counter(row['hint'] for row in only_left)),
            'only_right_by_hint': dict(collections.Counter(row['hint'] for row in only_right))}


def score_commit_agnostic(left, right):
    """Counts for a match on path and secret text only, for git mode, where
    patch-based and blob-based tools attribute values to different commits."""
    pairs, only_left, only_right = score_match(left, right, ignore_commit=True, ignore_lines=True)
    total = len(pairs) + len(only_left) + len(only_right)
    return {'matched': len(pairs), 'only_left': len(only_left), 'only_right': len(only_right),
            'agreement': (len(pairs) / total) if total else 1.0}


def score_test_scope(path):
    """True when a folder in the path is test, tests, spec, fixtures or examples."""
    folders = path.replace('\\', '/').split('/')[:-1]
    return any(folder.lower() in SCORE_TEST_FOLDERS for folder in folders)


SCORE_HEX_COMMIT = re.compile(r'^[0-9a-f]{7,64}$')
SCORE_STAGED = ':staged'


def score_read_blob(root, commit, path, git):
    """Read a file from the input folder, a commit, or the Git index."""
    if not commit:
        with open(os.path.join(root, path), 'rb') as handle:
            return handle.read()
    if not git:
        raise HarnessError('labels with a commit need git')
    spec = ':' + path if commit == SCORE_STAGED else '%s:%s' % (commit, path)
    completed = subprocess.run([git, '-C', root, 'show', spec], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=SCORE_GIT_SECONDS,
                               env={'PATH': SYSTEM_PATH, 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
                                    'GIT_CONFIG_GLOBAL': '/dev/null', 'HOME': '/nonexistent'})
    if completed.returncode != 0:
        raise OSError('git show failed')
    return completed.stdout


def score_outer_path(path):
    """The archive path of an archive member path such as `a.zst!member`."""
    return path.split('!', 1)[0]


def score_load_labels(path, workload_id, root, git=None, mode=None, home_tool=None):
    """Load labels for one workload. Unknown fields are ignored.

    Labels hold no secret text. The text is read from the input at the byte
    offsets and checked against secret_sha256. Kinds of label:

    - text (default): matches a finding on intersecting lines with matching
      text;
    - "span": "line": matches any finding on intersecting lines;
    - "span": "case": matches any finding in the same file; the SHA-256 is
      of the whole case;
    - "encoding": "base64" or "zstd": matches a finding in the same file (or
      archive) whose secret has the label's SHA-256, wherever it is. The
      bytes at the offsets are encoded, so the hash is not checked against
      them.

    A label belongs to git mode when it has a commit, a commit in
    introduced_by, or "staged": true (read from the Git index), and to dir
    mode otherwise. Label values other than secret and not-secret, such as
    ambiguous, are kept so scoring can exclude them."""
    labels, problems = [], collections.Counter()
    cache, newlines = {}, {}
    for row in read_jsonl(path):
        if workload_id is not None and row.get('workload') != workload_id:
            continue
        introduced = row.get('introduced_by')
        introduced = introduced if isinstance(introduced, str) and SCORE_HEX_COMMIT.match(introduced) else None
        staged = bool(row.get('staged')) or row.get('encoding') == 'staged'
        commit = row.get('commit') or introduced or (SCORE_STAGED if staged else '')
        if mode is not None and bool(commit) != (mode == 'git'):
            continue
        if not isinstance(row.get('label'), str) or not row['label'] or not isinstance(row.get('path'), str):
            problems['label value or path missing'] += 1
            continue
        encoding = row.get('encoding') if row.get('encoding') in ('base64', 'zstd') else None
        span = row.get('span')
        kind = 'hash' if encoding else 'case' if span == 'case' else 'line' if span == 'line' else 'text'
        key = (commit, row['path'])
        try:
            if key not in cache:
                cache[key] = score_read_blob(root, key[0], key[1], git)
                newlines[key] = [match.start() for match in re.finditer(b'\n', cache[key])]
            data = cache[key]
        except (OSError, TypeError, subprocess.TimeoutExpired):
            problems['file not readable'] += 1
            continue
        start, end = row.get('start'), row.get('end')
        if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start < end <= len(data):
            problems['offsets outside the file'] += 1
            continue
        segment = data[start:end]
        if kind == 'hash':
            problems['encoded label (hash not checked against the encoded bytes)'] += 1
        elif sha256_bytes(segment) != row.get('secret_sha256'):
            problems['text does not match secret_sha256'] += 1
            continue
        if not isinstance(row.get('secret_sha256'), str) or not HEX64.match(row['secret_sha256']):
            problems['secret_sha256 missing'] += 1
            continue
        line = bisect.bisect_left(newlines[key], start) + 1
        column = start - (newlines[key][line - 2] + 1 if line > 1 else 0) + 1
        if row.get('line') not in (None, line):
            problems['line differs from byte offset (offset used)'] += 1
        body = segment[:-1] if segment.endswith(b'\n') else segment
        text = '' if kind == 'hash' else segment.decode('utf-8', 'replace')
        category = row.get('category') or 'uncategorized'
        source = row.get('source') or 'unknown'
        expected = row.get('expected') if row.get('expected') in ('exactly_one', 'none', 'count') else None
        count = row.get('expected_count') if isinstance(row.get('expected_count'), int) else None
        reachable = row.get('reachable_from_head')
        scope = []
        if reachable is False:
            scope.append('not reachable from HEAD')
        if row.get('introduced_by') == 'merge':
            scope.append('introduced by a merge')
        if row.get('in_binary'):
            scope.append('in a binary file')
        home = (row.get('home_tool') or home_tool
                or (row['path'].split('/', 1)[0] if source == 'fixture' else 'not a fixture'))
        labels.append({'rule': category, 'path': row['path'], 'commit': commit,
                       'commits': {value for value in (row.get('commit'), introduced) if value} or {commit},
                       'start_line': line, 'end_line': line + body.count(b'\n'), 'secret': text,
                       'columns': [column, None],
                       'secret_sha256': row['secret_sha256'], 'secret_length': len(text),
                       'label': 'not-secret' if expected == 'none' else row['label'], 'category': category,
                       'source': source, 'start': start, 'end': end, 'kind': kind, 'encoding': encoding,
                       'expected': expected, 'capacity': max(1, count or 1) if expected == 'count' else 1,
                       'scope_difference': ', '.join(scope) or None, 'home_tool': home,
                       'reachable': 'unspecified' if reachable is None else
                       'reachable from HEAD' if reachable else 'not reachable from HEAD',
                       'binary': 'in binary file' if row.get('in_binary') else 'text file'})
    return labels, dict(problems)


def score_label_groups(labels):
    """Merge labels with the same path and commit whose byte spans overlap.

    A group is one unit for scoring: a finding that matches any member
    satisfies the group. The group is a secret when any member is one; its
    category and source come from its narrowest secret member (or narrowest
    member when none is a secret). Encoded labels are never merged, because
    one encoded run can hold many secrets."""
    ordered = sorted(labels, key=lambda label: (label['path'], label['commit'], label['start'], label['end']))
    groups = []
    for label in ordered:
        last = groups[-1] if groups else None
        if (last is not None and label['kind'] != 'hash' and last['members'][0]['kind'] != 'hash'
                and last['path'] == label['path'] and last['commit'] == label['commit'] and label['start'] < last['end']):
            last['members'].append(label)
            last['end'] = max(last['end'], label['end'])
            last['start_line'] = min(last['start_line'], label['start_line'])
            last['end_line'] = max(last['end_line'], label['end_line'])
            last['commits'] = last['commits'] | label['commits']
        else:
            groups.append({'path': label['path'], 'commit': label['commit'], 'commits': set(label['commits']),
                           'start': label['start'], 'end': label['end'], 'start_line': label['start_line'],
                           'columns': label['columns'],
                           'end_line': label['end_line'], 'members': [label]})
    for group in groups:
        members = group['members']
        secrets = [member for member in members if member['label'] == 'secret']
        pool = secrets or members
        primary = min(pool, key=lambda member: (member['end'] - member['start'], member['start']))
        expected = next((member['expected'] for member in members if member['expected']), None)
        group.update({'label': 'secret' if secrets else 'not-secret', 'primary': primary,
                      'category': primary['category'], 'source': primary['source'],
                      'reachable': primary['reachable'], 'binary': primary['binary'],
                      'home_tool': primary['home_tool'], 'expected': expected,
                      'capacity': max(member['capacity'] for member in members),
                      'scope_difference': next((member['scope_difference'] for member in members
                                                if member['scope_difference']), None),
                      'path_wide': any(member['kind'] in ('case', 'hash') for member in members),
                      'rule': primary['rule'], 'secret': primary['secret'],
                      'secret_sha256': primary['secret_sha256'], 'secret_length': primary['secret_length']})
    return groups


def score_group_overlap(finding, group, ignore_commit=False):
    """Return a match score for a finding and a label group, or None.

    Text matches score by the shared length and encoded matches by the
    secret length, so value matches are preferred. Line-level and case
    matches score 0. With ignore_commit (git mode, commit-agnostic), text
    members match on path and text alone."""
    best = None
    for member in group['members']:
        kind = member['kind']
        if kind == 'hash':
            if score_outer_path(finding['path']) != member['path'] or finding['secret_sha256'] != member['secret_sha256']:
                continue
            score = finding['secret_length']
        elif finding['path'] != member['path']:
            continue
        elif kind == 'case':
            score = 0
        elif kind == 'line':
            if not score_lines_intersect(member, finding):
                continue
            score = 0
        else:
            if not ignore_commit and not score_lines_intersect(member, finding):
                continue
            score = score_text_overlap(member['secret'], finding['secret'])
            if score is None:
                continue
        best = score if best is None else max(best, score)
    return best


class ScoreGroupIndex(object):
    """Candidate label groups for a finding: nearby groups by line, plus
    groups that match anywhere in a file (case and encoded labels)."""

    def __init__(self, groups, ignore_commit):
        self.groups = groups
        self.ignore_commit = ignore_commit
        self.near_index = ScoreNeighbours(groups, ignore_commit)
        # Case groups match any finding in the file. Encoded (hash) groups
        # are never merged and match only a finding with their SHA-256, so
        # they are indexed by it.
        self.case_wide = collections.defaultdict(list)
        self.hash_wide = collections.defaultdict(list)
        for position, group in enumerate(groups):
            if not group['path_wide']:
                continue
            hashes = {member['secret_sha256'] for member in group['members'] if member['kind'] == 'hash'}
            for key in score_keys(group, ignore_commit):
                if any(member['kind'] == 'case' for member in group['members']):
                    self.case_wide[key].append(position)
                for value in hashes:
                    self.hash_wide[key + (value,)].append(position)

    def candidates(self, finding):
        found = set(self.near_index.path_items(finding) if self.ignore_commit
                    else self.near_index.near(finding, 0, same_text=True))
        probe = dict(finding, path=score_outer_path(finding['path']))
        for item in (finding, probe):
            for key in score_keys(item, self.ignore_commit):
                found.update(self.case_wide.get(key, ()))
                found.update(self.hash_wide.get(key + (finding['secret_sha256'],), ()))
        return sorted(found)


QUALITY_DIMENSIONS = (('category', 'by_category'), ('source', 'by_source'), ('scope', 'by_scope'),
                      ('reachable', 'by_reachability'), ('binary', 'by_binary'), ('home_tool', 'by_home_tool'),
                      ('scope_difference', 'by_scope_difference'))


def score_quality(findings, labels, labels_complete=True, ignore_commit=False):
    """Precision, recall and F1 from a maximum one-to-one matching of label
    groups and findings, overall and split by category, label source, test
    or other paths, reachability, file kind, home tool and scope difference.

    - With complete labels, a finding that matches no label is a false
      positive; with partial labels it is unknown.
    - Labels other than secret and not-secret are excluded, and so are
      findings on them.
    - A label with "expected": "none" makes every finding on it a false
      positive. "expected": "count" lets expected_count findings match.
      Extra findings on an exactly_one or count label are over-reporting.
    - A finding whose secret has the SHA-256 of a secret label elsewhere (a
      re-found value at another commit or path) is a duplicate.
    - Labels not reachable from HEAD, introduced by a merge, or in a binary
      file are scope differences. They are reported in their own rows and
      left out of the overall recall."""
    excluded_labels = [label for label in labels if label['label'] not in ('secret', 'not-secret')]
    groups = score_label_groups([label for label in labels if label['label'] in ('secret', 'not-secret')])
    excluded_groups = score_label_groups(excluded_labels)
    index = ScoreGroupIndex(groups, ignore_commit)
    excluded_index = ScoreGroupIndex(excluded_groups, ignore_commit)
    secret_hashes = {member['secret_sha256'] for group in groups if group['label'] == 'secret'
                     for member in group['members'] if member['label'] == 'secret'}
    edges, on_none = [], {}
    for j, finding in enumerate(findings):
        if j % 256 == 0:
            score_check()
        for g in index.candidates(finding):
            score = score_group_overlap(finding, groups[g], ignore_commit)
            if score is None:
                continue
            if groups[g]['expected'] == 'none':
                on_none.setdefault(j, g)
                continue
            for copy in range(groups[g]['capacity']):
                edges.append((score, score_line_distance(groups[g], finding), (g, copy), j))
    edges = [edge for edge in edges if edge[3] not in on_none]
    pairs = score_assign(edges)
    filled = collections.Counter(node[0] for node, _, _ in pairs)
    used_findings = {j for _, j, _ in pairs} | set(on_none)

    def bucket():
        return {'true_positive': 0, 'false_negative': 0, 'false_positive_on_negative': 0, 'true_negative': 0,
                'unlabeled_findings': 0, 'unknown_findings': 0, 'duplicate_findings': 0,
                'over_reported_findings': 0, 'excluded_findings': 0, 'scope_difference_found': 0,
                'scope_difference_missed': 0}

    dimensions = {name: collections.defaultdict(bucket) for name, _ in QUALITY_DIMENSIONS}
    total = bucket()

    def add(key, path, group=None, count=1):
        dimensions['scope']['test paths' if score_test_scope(path) else 'other paths'][key] += count
        overall_key = key
        if group is not None:
            for name in ('category', 'source', 'reachable', 'binary', 'home_tool'):
                dimensions[name][group[name]][key] += count
            if group['scope_difference']:
                dimensions['scope_difference'][group['scope_difference']][key] += count
                overall_key = {'true_positive': 'scope_difference_found',
                               'false_negative': 'scope_difference_missed'}.get(key, key)
        total[overall_key] += count

    on_negatives = []
    for j, g in sorted(on_none.items()):
        row = score_public(findings[j])
        row.update({'hint': 'finding on an expected-none case', 'detail': 'category ' + groups[g]['category'],
                    'counterpart': score_public(groups[g]['primary'])})
        on_negatives.append(row)
        add('false_positive_on_negative', groups[g]['path'], groups[g])
    for (g, _), j, _ in sorted(pairs):
        group = groups[g]
        key = 'true_positive' if group['label'] == 'secret' else 'false_positive_on_negative'
        add(key, group['path'], group)
        if key == 'false_positive_on_negative':
            row = score_public(findings[j])
            row.update({'hint': 'finding on a not-secret label', 'detail': 'category ' + group['category'],
                        'counterpart': score_public(group['primary'])})
            on_negatives.append(row)
    finding_index = ScoreNeighbours(findings, ignore_commit)
    hit_none = set(on_none.values())
    missed = []
    for g, group in enumerate(groups):
        if group['expected'] == 'none':
            if g not in hit_none:
                add('true_negative', group['path'], group)
            continue
        empty = group['capacity'] - filled.get(g, 0)
        if empty <= 0:
            continue
        key = 'false_negative' if group['label'] == 'secret' else 'true_negative'
        add(key, group['path'], group, empty)
        if key == 'false_negative':
            row = score_public(group['primary'])
            if len(missed) < SCORE_MAX_HINTS:
                row.update(score_hint(group['primary'], None, set(), finding_index))
            else:
                row.update({'hint': 'not-examined', 'counterpart': None,
                            'detail': 'hints are computed for the first %d missed labels only' % SCORE_MAX_HINTS})
            row.update({'group_members': len(group['members']), 'unfilled': empty,
                        'scope_difference': group['scope_difference']})
            missed.append(row)
    unmatched = []
    hinted = 0
    for j, finding in enumerate(findings):
        if j % 256 == 0:
            score_check()
        if j in used_findings:
            continue
        row = score_public(finding)
        twin = next((groups[g] for g in index.candidates(finding)
                     if filled.get(g) and score_group_overlap(finding, groups[g], ignore_commit) is not None), None)
        excluded = next((excluded_groups[g] for g in excluded_index.candidates(finding)
                         if score_group_overlap(finding, excluded_groups[g], ignore_commit) is not None), None)
        if twin is not None and twin['expected'] in ('exactly_one', 'count'):
            key = 'over_reported_findings'
            row.update({'hint': 'over-reported', 'detail': 'more findings than the case expects',
                        'counterpart': score_public(twin['primary'])})
        elif twin is not None:
            key = 'duplicate_findings'
            row.update({'hint': 'duplicate', 'detail': 'its label group already matched another finding',
                        'counterpart': score_public(twin['primary'])})
        elif excluded is not None:
            key = 'excluded_findings'
            row.update({'hint': 'excluded', 'detail': 'matches a label with the value ' + excluded['primary']['label'],
                        'counterpart': score_public(excluded['primary'])})
        elif finding['secret_sha256'] in secret_hashes:
            key = 'duplicate_findings'
            row.update({'hint': 'duplicate', 'detail': 'a labeled secret found again at another commit or path',
                        'counterpart': None})
        else:
            key = 'unlabeled_findings' if labels_complete else 'unknown_findings'
            hinted += 1
            if hinted <= SCORE_MAX_HINTS:
                row.update(score_hint(finding, None, set(), index.near_index))
            else:
                row.update({'hint': 'not-examined', 'counterpart': None,
                            'detail': 'hints are computed for the first %d such findings only' % SCORE_MAX_HINTS})
            row['hint'] = ('unlabeled: ' if labels_complete else 'unknown: ') + row['hint']
        add(key, finding['path'])
        unmatched.append(row)

    def rates(counts, strict=True):
        tp, fn = counts['true_positive'], counts['false_negative']
        labeled_fp = counts['false_positive_on_negative']
        strict_fp = (labeled_fp + counts['unlabeled_findings'] + counts['duplicate_findings']
                     + counts['over_reported_findings'])

        def f1(precision, recall):
            if precision is None or recall is None:
                return None
            return 2 * precision * recall / (precision + recall) if precision + recall else 0.0

        precision = tp / (tp + strict_fp) if strict and tp + strict_fp else None
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
                    'labels_complete': bool(labels_complete), 'commit_agnostic': bool(ignore_commit)})
    result = {'overall': overall, 'labels_complete': bool(labels_complete), 'commit_agnostic': bool(ignore_commit),
              'missed_labels': sorted(missed, key=lambda row: (row['path'], row['start_line'])),
              'findings_on_negatives': on_negatives,
              'unmatched_findings': sorted(unmatched, key=lambda row: (row['path'], row['start_line'], row['rule']))}
    for name, key in QUALITY_DIMENSIONS:
        # Findings with no label have no category, source or other label
        # attribute, so strict precision is only given overall and by scope.
        result[key] = {value: rates(counts, strict=name == 'scope')
                       for value, counts in sorted(dimensions[name].items())}
    return result


def score_spec(text):
    """Parse ADAPTER=PATH for ad hoc scoring."""
    adapter, separator, path = text.partition('=')
    allowed = ('rustleaks', 'gitleaks', 'betterleaks-v1', 'betterleaks-v2', 'kingfisher')
    if not separator or adapter not in allowed or not path:
        raise HarnessError('expected ADAPTER=REPORT with ADAPTER one of %s' % ', '.join(allowed))
    return adapter, path


def score_quality_both(findings, labels, complete, mode):
    """Quality with the strict rule and, in git mode, the commit-agnostic rule."""
    quality = score_quality(findings, labels, complete)
    if mode == 'git':
        agnostic = score_quality(findings, labels, complete, ignore_commit=True)
        quality['commit_agnostic_overall'] = agnostic['overall']
    return quality


def score_adhoc(args):
    score_limit_start(getattr(args, 'score_hours', None))
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
              'comparisons': [], 'quality': [], 'label_errors': []}
    if len(sides) == 2:
        comparison = score_compare(sides[0][1], sides[1][1], sides[0][0], sides[1][0])
        if args.mode == 'git':
            comparison['commit_agnostic'] = score_commit_agnostic(sides[0][1], sides[1][1])
        result['comparisons'].append(comparison)
    if args.labels:
        if not os.path.isfile(args.labels):
            raise HarnessError('labels file not found: %s' % args.labels)
        git = resolve_git(args.git)
        labels, problems = score_load_labels(args.labels, args.workload, target, git and git['path'], args.mode)
        for name, findings, _ in sides:
            quality = score_quality_both(findings, labels, not args.labels_partial, args.mode)
            quality.update({'name': name, 'label_problems': problems, 'labels': len(labels)})
            result['quality'].append(quality)
    return result


def score_limit_start(hours):
    """Start the scoring time limit. Work after it is listed as not scored."""
    hours = SCORE_DEFAULT_HOURS if hours is None else hours
    if hours <= 0:
        raise HarnessError('--score-hours must be positive')
    SCORE_LIMIT.update({'deadline': time.monotonic() + hours * 3600, 'hours': hours})


def score_run(run_dir, seed, hours=None):
    """Score every kept report in a run: identity agreement within each
    comparable group, and quality for workloads with labels.

    Scoring stops after `hours` (default SCORE_DEFAULT_HOURS); comparisons
    and quality rows not finished by then are listed in `not_scored`."""
    score_limit_start(hours)
    not_scored = []
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
                                        workload_target(workloads[cell['workload']], cell['mode']), cell['mode'])
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
                try:
                    result = score_compare(loaded[left['cell_id']], loaded[right['cell_id']],
                                           left['cell_id'], right['cell_id'])
                    if left['mode'] == 'git':
                        result['commit_agnostic'] = score_commit_agnostic(loaded[left['cell_id']],
                                                                          loaded[right['cell_id']])
                except ScoreTimeLimit as error:
                    not_scored.append({'kind': 'agreement', 'left': left['cell_id'], 'right': right['cell_id'],
                                       'reason': str(error)})
                    continue
                result.update({'group': group, 'cache': cache})
                comparisons.append(result)
    quality, label_cache, label_errors = [], {}, []
    for cell in cells:
        workload = workloads[cell['workload']]
        if not workload.get('labels_path') or loaded.get(cell['cell_id']) is None:
            continue
        key = (workload['id'], cell['mode'])
        if key not in label_cache:
            if not os.path.isfile(workload['labels_path']):
                label_cache[key] = None
                message = 'labels file for workload %s is missing; quality not scored' % workload['id']
                label_errors.append(message)
                print('compare: WARNING: ' + message, file=sys.stderr)
            else:
                label_cache[key] = score_load_labels(workload['labels_path'], workload['id'],
                                                     workload_target(workload, cell['mode']), git, cell['mode'],
                                                     workload.get('home_tool'))
        if label_cache[key] is None or not label_cache[key][0]:
            continue
        labels, problems = label_cache[key]
        try:
            result = score_quality_both(loaded[cell['cell_id']], labels,
                                        workload.get('labels_complete', True) is not False, cell['mode'])
        except ScoreTimeLimit as error:
            not_scored.append({'kind': 'quality', 'left': cell['cell_id'], 'right': None, 'reason': str(error)})
            continue
        result.update({'name': cell['cell_id'], 'label_problems': problems, 'labels': len(labels),
                       'workload': workload['id'], 'lane': cell['lane'], 'tool': cell['tool'], 'mode': cell['mode']})
        quality.append(result)
    return {'schema': SCHEMA_SCORE, 'kind': 'run', 'run_id': run['run_id'], 'comparisons': comparisons,
            'quality': quality, 'label_errors': sorted(set(label_errors)), 'not_scored': not_scored,
            'score_hours': SCORE_LIMIT['hours'],
            'score_errors': [{'cell': cell['cell_id'], 'error': cell['score_error']}
                             for cell in cells if cell.get('score_error')]}


def score_rate_table(title, rows):
    lines = ['| %s | TP | FN | FP on negatives | TN | Unlabeled | Unknown | Duplicates | Over-reported | Excluded | '
             'Scope difference found / missed | Precision (strict) | Precision (labeled only) | Recall | F1 (strict) |'
             % title,
             '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for name, row in rows.items():
        lines.append('| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d / %d | %s | %s | %s | %s |' % (
            name, row['true_positive'], row['false_negative'], row['false_positive_on_negative'],
            row['true_negative'], row['unlabeled_findings'], row['unknown_findings'], row['duplicate_findings'],
            row['over_reported_findings'], row['excluded_findings'], row['scope_difference_found'],
            row['scope_difference_missed'],
            report_rate(row['precision_strict']), report_rate(row['precision_labeled_only']),
            report_rate(row['recall']), report_rate(row['f1_strict'])))
    return lines + ['']


SCORE_MARKDOWN_HEADER = [
    '# Comparison score', '',
    'Matching is a maximum one-to-one matching: same path and commit, intersecting line ranges,',
    'and secret texts that are equal or share at least %d characters covering at least half of' % SCORE_MIN_SHARED,
    'the shorter text. In git mode, a second count ignores commits and lines and matches on path',
    'and text only, because patch-based and blob-based tools attribute a value to different',
    'commits.', '',
    'Secrets appear only as SHA-256 and length. A SHA-256 of a short or guessable secret can be',
    'recovered by brute force, so review this file before you share it.', '']


def score_markdown(result):
    lines = list(SCORE_MARKDOWN_HEADER)
    for message in result.get('label_errors', []):
        lines += ['WARNING: ' + message, '']
    for row in result.get('not_scored', []):
        lines += ['NOT SCORED (%s): %s%s: %s' % (row['kind'], row['left'], ' versus ' + row['right'] if row['right'] else '',
                                                 row['reason']), '']
    for comparison in result['comparisons']:
        lines += ['## %s versus %s' % (comparison['left'], comparison['right']), '']
        if comparison.get('group'):
            lines += ['Group: `%s` (%s cache).' % (comparison['group'], comparison['cache']), '']
        lines += ['| Items left | Items right | Matched | Only left | Only right | Agreement |',
                  '| ---: | ---: | ---: | ---: | ---: | ---: |',
                  '| %d | %d | %d | %d | %d | %.4f |' % (
                      comparison['left_items'], comparison['right_items'], comparison['matched'],
                      len(comparison['only_left']), len(comparison['only_right']), comparison['agreement']), '']
        agnostic = comparison.get('commit_agnostic')
        if agnostic:
            lines += ['Commit-agnostic (path and text only): matched %d, only left %d, only right %d, '
                      'agreement %.4f.' % (agnostic['matched'], agnostic['only_left'], agnostic['only_right'],
                                           agnostic['agreement']), '']
        for side, key in (('left', 'only_left'), ('right', 'only_right')):
            rows = comparison[key]
            if not rows:
                continue
            hints = comparison[key + '_by_hint']
            lines += ['Only %s, by hint: %s.' % (side, ', '.join('%s %d' % item for item in sorted(hints.items()))), '',
                      '| Path | Commit | Lines | Rule | Secret SHA-256 | Length | Hint | Detail | Counterpart |',
                      '| --- | --- | --- | --- | --- | ---: | --- | --- | --- |']
            if len(rows) > SCORE_MARKDOWN_ROWS:
                lines.insert(len(lines) - 2, 'Only the first %d of %d rows are listed; score.json has all of them.'
                             % (SCORE_MARKDOWN_ROWS, len(rows)))
                lines.insert(len(lines) - 2, '')
            for row in rows[:SCORE_MARKDOWN_ROWS]:
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
        rows = {'all (strict)': overall}
        if quality.get('commit_agnostic_overall'):
            rows['all (commit-agnostic)'] = quality['commit_agnostic_overall']
        lines += score_rate_table('Overall', rows)
        lines += ['Strict precision needs every finding to have a category, so it is given only overall and by '
                  'path scope.', '']
        for title, key in (('Category', 'by_category'), ('Label source', 'by_source'), ('Path scope', 'by_scope'),
                           ('Reachability', 'by_reachability'), ('File kind', 'by_binary'),
                           ('Home tool', 'by_home_tool'), ('Scope difference', 'by_scope_difference')):
            if not quality.get(key):
                continue
            lines += score_rate_table(title, quality[key])
        for title, rows in (('Missed secret labels', quality['missed_labels']),
                            ('Findings on not-secret labels', quality.get('findings_on_negatives', [])),
                            ('Findings with no label of their own', quality['unmatched_findings'])):
            if not rows:
                continue
            lines += [title + ':', '']
            if len(rows) > SCORE_MARKDOWN_ROWS:
                lines += ['Only the first %d of %d rows are listed; score.json has all of them.'
                          % (SCORE_MARKDOWN_ROWS, len(rows)), '']
            lines += ['| Path | Lines | Rule or category | Secret SHA-256 | Length | Hint |',
                      '| --- | --- | --- | --- | ---: | --- |']
            for row in rows[:SCORE_MARKDOWN_ROWS]:
                lines.append('| `%s` | %d-%d | `%s` | `%s` | %d | %s |' % (
                    row['path'], row['start_line'], row['end_line'], row['rule'], row['secret_sha256'][:16],
                    row['secret_length'], row['hint']))
            lines.append('')
    if result.get('score_errors'):
        lines += ['## Reports that could not be scored', '']
        lines += ['- `%s`: %s' % (row['cell'], row['error']) for row in result['score_errors']]
        lines.append('')
    return '\n'.join(lines)
