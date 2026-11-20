# Constructed labeled corpus: plan items, place them in files, write labels.

CORPUS_ID = 'constructed-v1'
DEFAULT_SEED = 'rustleaks-quality-constructed-v1'
DEFAULT_SCALE = 2.0
CORPUS_DIRECTORY = 'quality/' + CORPUS_ID
GENERATOR_COMMAND = 'cargo xtask compare-quality generate'
COMMITTED_MANIFEST = 'benchmarks/comparison/quality/labeled.json'
COMMITTED_EXPECTED = 'benchmarks/comparison/quality/constructed-v1.expected.json'
WORDS = ('orders', 'billing', 'payments', 'search', 'auth', 'gateway', 'reports', 'ingest', 'notify',
         'inventory', 'profile', 'scheduler', 'exports', 'ledger', 'mailer', 'catalog')
TEST_SHARE = (3, 20)
CLEAN_FILES = 60


def scaled(weight, scale):
    return max(1, int(round(weight * scale)))


def plan_items(rng, scale):
    items = []
    for kind in KINDS:
        for _ in range(scaled(kind.weight, scale)):
            entries = kind.build(rng)
            if kind.scopes == ('test',):
                scope = 'test'
            elif 'test' in kind.scopes and rng.chance(*TEST_SHARE):
                scope = 'test'
            else:
                scope = 'main'
            candidates = [name for name in kind.contexts if supports(CONTEXTS[name], entries)]
            if not candidates:
                raise QualityError(f'no context can hold a {kind.identifier} value')
            items.append((kind, entries, scope, rng.choice(candidates)))
    return items


def fill_path(template, word, index):
    return template.replace('{w}', f'{word}-{index}').replace('{W}', f'{word.title()}{index}')


def place_files(rng, items, scale):
    buckets = {}
    for item in items:
        buckets.setdefault((item[3], item[2]), []).append(item)
    groups = []
    for (context_name, scope), bucket in buckets.items():
        rng.shuffle(bucket)
        context = CONTEXTS[context_name]
        while bucket:
            take = rng.between(1, max_entries(context))
            groups.append((context, scope, bucket[:take]))
            bucket = bucket[take:]
    clean_contexts = [context for context in LINE_CONTEXTS] + [CONTEXTS['markdown'], CONTEXTS['json']]
    for _ in range(scaled(CLEAN_FILES, scale)):
        groups.append((rng.choice(clean_contexts), 'main', []))
    rng.shuffle(groups)
    projects = max(2, len(groups) // 25)
    used = set()
    files = []
    for index, (context, scope, members) in enumerate(groups):
        entries = [entry for member in members for entry in member[1]]
        template = pem_path(entries) if context.name == 'pem' else rng.choice(context.paths)
        if scope == 'test':
            template = rng.choice(context.test_paths) + template.rsplit('/', 1)[-1]
        project = f'project-{rng.below(projects):02d}'
        word = rng.choice(WORDS)
        path = project + '/' + fill_path(template, word, index)
        if path in used:
            path = project + f'/services/{word}-{index}/' + fill_path(template, word, index)
        used.add(path)
        files.append((path, context, entries, [member[0].identifier for member in members]))
    return files


def build_corpus(seed, scale):
    """Returns (files, labels, kind_counts). files maps path to bytes."""
    plan_rng = Drbg(seed, 'items')
    place_rng = Drbg(seed, 'placement')
    render_rng = Drbg(seed, 'render')
    items = plan_items(plan_rng, scale)
    placed = place_files(place_rng, items, scale)
    files = {}
    labels = []
    kind_counts = {}
    for path, context, entries, kinds in placed:
        for identifier in kinds:
            kind_counts[identifier] = kind_counts.get(identifier, 0) + 1
        doc = render(context, render_rng, entries)
        data = doc.data()
        files[path] = data
        for start, end, label, category in doc.spans:
            labels.append({
                'workload': CORPUS_ID, 'path': path, 'commit': None, 'start': start, 'end': end,
                'line': line_of(data, start), 'secret_sha256': sha256_bytes(data[start:end]),
                'category': category, 'label': label, 'source': 'constructed',
            })
    labels.sort(key=lambda record: (record['path'], record['start']))
    return files, labels, dict(sorted(kind_counts.items()))


def label_counts(labels):
    counts = {}
    for record in labels:
        bucket = counts.setdefault(record['category'], {'secret': 0, 'not-secret': 0})
        bucket[record['label']] += 1
    return dict(sorted(counts.items()))


def workload_manifest(seed, scale, size):
    return {
        'schema': WORKLOADS_SCHEMA,
        'set': 'labeled',
        'workloads': [{
            'id': CORPUS_ID,
            'family': 'labeled',
            'modes': ['dir'],
            'source': {'kind': 'generated', 'generator': GENERATOR_COMMAND,
                       'params': {'corpus': CORPUS_ID, 'scale': scale}, 'seed': seed},
            'path': CORPUS_DIRECTORY + '/tree',
            'size': size,
            'labels': CORPUS_DIRECTORY + '/labels.jsonl',
            'tuned': False,
        }],
    }


def write_corpus(cache_root, seed, scale, force):
    target = cache_root / CORPUS_DIRECTORY
    reset_directory(target, force)
    files, labels, kind_counts = build_corpus(seed, scale)
    tree = target / 'tree'
    tree.mkdir()
    for path, data in sorted(files.items()):
        write_bytes(tree / path, data)
    labels_bytes = ''.join(label_line(record) + '\n' for record in labels).encode('ascii')
    write_bytes(target / 'labels.jsonl', labels_bytes)
    digest, file_count, total = tree_digest(tree)
    size = {'bytes': total, 'files': file_count, 'commits': 0}
    summary = {
        'schema': EXPECTED_SCHEMA,
        'corpus': CORPUS_ID,
        'generator_sha256': QUALITY_GENERATOR_SHA256,
        'seed': seed,
        'scale': scale,
        'tree_sha256': digest,
        'labels_sha256': sha256_bytes(labels_bytes),
        'size': size,
        'labels': {'total': len(labels),
                   'secret': sum(1 for record in labels if record['label'] == 'secret'),
                   'not-secret': sum(1 for record in labels if record['label'] == 'not-secret')},
        'categories': label_counts(labels),
        'kinds': kind_counts,
    }
    write_bytes(target / 'summary.json', json_bytes(summary))
    write_bytes(target / 'workload.json', json_bytes(workload_manifest(seed, scale, size)))
    return target, summary


def check_corpus(target):
    """Check structure and every label of a corpus folder. Returns its summary."""
    summary = json.loads((target / 'summary.json').read_text(encoding='ascii'))
    records = check_labels_against_tree(target / 'labels.jsonl', target / 'tree')
    digest, file_count, total = tree_digest(target / 'tree')
    if digest != summary['tree_sha256'] or file_count != summary['size']['files'] or total != summary['size']['bytes']:
        raise QualityError(f'{target}: the tree does not match its summary')
    if sha256_bytes((target / 'labels.jsonl').read_bytes()) != summary['labels_sha256']:
        raise QualityError(f'{target}: labels.jsonl does not match its summary')
    previous = None
    for record in records:
        if record['workload'] != CORPUS_ID or record['source'] != 'constructed' or record['commit'] is not None:
            raise QualityError(f'{target}: unexpected label identity fields')
        if record['category'] not in CATEGORIES:
            raise QualityError(f'{target}: unknown category {record["category"]}')
        key = (record['path'], record['start'])
        if previous is not None:
            if key < (previous['path'], previous['start']):
                raise QualityError(f'{target}: labels are not sorted')
            if record['path'] == previous['path'] and record['start'] < previous['end']:
                raise QualityError(f'{target}: labels overlap in {record["path"]}')
        previous = record
    secrets = [record['secret_sha256'] for record in records if record['label'] == 'secret']
    if len(secrets) != len(set(secrets)):
        raise QualityError(f'{target}: a secret value repeats')
    if label_counts(records) != summary['categories']:
        raise QualityError(f'{target}: category counts do not match the summary')
    return summary


def compare_with_committed(source_root, target, summary):
    root = Path(source_root)
    expected = json.loads((root / COMMITTED_EXPECTED).read_text(encoding='ascii'))
    manifest = json.loads((root / COMMITTED_MANIFEST).read_text(encoding='ascii'))
    problems = []
    for field in ('generator_sha256', 'seed', 'scale', 'tree_sha256', 'labels_sha256', 'size', 'labels',
                  'categories', 'kinds'):
        if expected.get(field) != summary.get(field):
            problems.append(f'{field} differs from {COMMITTED_EXPECTED}')
    generated = json.loads((target / 'workload.json').read_text(encoding='ascii'))
    if generated != manifest:
        problems.append(f'workload manifest differs from {COMMITTED_MANIFEST}')
    if problems:
        raise QualityError('; '.join(problems) + '; regenerate with `generate` and review the change')
