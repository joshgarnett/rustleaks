# Samsung CredData adapter: converts CredData metadata into the shared labels
# format. It reads a local CredData checkout after its own download script has
# built `data/`. It never downloads anything and never copies data files.

import csv

CREDDATA_URL = 'https://github.com/Samsung/CredData'
CREDDATA_COMMIT = '01e3d135a90f46c9a7965683b24a05d12e136b33'
CREDDATA_META_FIELDS = ('Id', 'FileID', 'Domain', 'RepoName', 'FilePath', 'LineStart', 'LineEnd', 'GroundTruth',
                        'ValueStart', 'ValueEnd', 'CryptographyKey', 'PredefinedPattern', 'Category')
CREDDATA_WORKLOAD = 'credata'
CREDDATA_LABELS = {'T': 'secret', 'F': 'not-secret', 'X': 'not-secret'}


def creddata_category(category):
    slug = ''.join(character.lower() if character.isalnum() else '-' for character in category)
    while '--' in slug:
        slug = slug.replace('--', '-')
    return 'credata-' + slug.strip('-')


def meta_integer(value):
    value = value.strip()
    return int(value) if value else -1


def read_meta_rows(meta_directory):
    rows = []
    for path in sorted(Path(meta_directory).glob('*.csv')):
        with open(path, newline='', encoding='utf-8') as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != CREDDATA_META_FIELDS:
                raise QualityError(f'{path}: unexpected CredData metadata columns')
            for row in reader:
                rows.append((path.name, row))
    return rows


def line_offsets(text):
    offsets = [0]
    for index, character in enumerate(text):
        if character == '\n':
            offsets.append(index + 1)
    return offsets


def char_to_byte(text, index):
    return len(text[:index].encode('utf-8'))


def convert_row(row, text, offsets):
    """Return (start, end, line) byte offsets for one metadata row, or raise ValueError."""
    line_start = meta_integer(row['LineStart'])
    line_end = meta_integer(row['LineEnd'])
    value_start = meta_integer(row['ValueStart'])
    value_end = meta_integer(row['ValueEnd'])
    lines = len(offsets)
    if not 1 <= line_start <= line_end <= lines:
        raise ValueError('line numbers are outside the file')
    first = offsets[line_start - 1]
    last_begin = offsets[line_end - 1]
    last_end = offsets[line_end] - 1 if line_end < lines else len(text)
    first_end = offsets[line_start] - 1 if line_start < lines else len(text)
    start = first + value_start if value_start >= 0 else first
    end = last_begin + value_end if value_end >= 0 else last_end
    if line_start == line_end and value_start >= 0 and start > first_end:
        raise ValueError('value start is past the end of the line')
    if end > last_end or end <= start:
        raise ValueError('value span is empty or past the end of the line')
    return start, end, line_start


def convert_creddata(checkout, max_problems):
    """Returns (labels, problems, counts)."""
    meta = checkout / 'meta'
    data = checkout / 'data'
    if not meta.is_dir():
        raise QualityError(f'{meta} is missing; check out CredData at {CREDDATA_COMMIT}')
    if not data.is_dir():
        raise QualityError(f'{data} is missing; run CredData download_data.py first (see docs/dev/comparison-quality.md)')
    texts = {}
    labels = []
    problems = []
    seen = set()
    for meta_name, row in read_meta_rows(meta):
        where = f'meta/{meta_name} Id {row["Id"]}'
        file_path = row['FilePath']
        if not file_path.startswith('data/') or '..' in file_path.split('/') or '\\' in file_path:
            problems.append(f'{where}: unexpected FilePath')
            continue
        relative = file_path[len('data/'):]
        if relative not in texts:
            try:
                raw = (data / relative).read_bytes()
                text = raw.decode('utf-8')
                if '\r' in text:
                    raise ValueError('carriage return in a normalized file')
                texts[relative] = (raw, text, line_offsets(text))
            except (OSError, ValueError) as error:
                texts[relative] = error
        entry = texts[relative]
        if isinstance(entry, Exception):
            problems.append(f'{where}: cannot read {relative}: {entry}')
            continue
        raw, text, offsets = entry
        label = CREDDATA_LABELS.get(row['GroundTruth'])
        if label is None:
            problems.append(f'{where}: unknown GroundTruth {row["GroundTruth"]!r}')
            continue
        try:
            start_char, end_char, line = convert_row(row, text, offsets)
        except ValueError as error:
            problems.append(f'{where}: {error}')
            continue
        start = char_to_byte(text, start_char)
        end = char_to_byte(text, end_char)
        key = (relative, start, end, label)
        if key in seen:
            continue
        seen.add(key)
        labels.append({
            'workload': CREDDATA_WORKLOAD, 'path': relative, 'commit': None, 'start': start, 'end': end,
            'line': line, 'secret_sha256': sha256_hex(raw[start:end]),
            'category': creddata_category(row['Category']), 'label': label, 'source': 'credData',
        })
    labels.sort(key=lambda record: (record['path'], record['start'], record['end']))
    if len(problems) > max_problems:
        shown = '\n  '.join(problems[:20])
        raise QualityError(f'{len(problems)} CredData rows could not be converted (limit {max_problems}):\n  {shown}')
    return labels, problems


def write_creddata(cache_root, checkout, max_problems, force):
    try:
        data_relative = (checkout / 'data').relative_to(cache_root).as_posix()
    except ValueError:
        raise QualityError(f'the CredData checkout {checkout} must be inside the cache folder {cache_root}')
    labels, problems = convert_creddata(checkout, max_problems)
    target = cache_root / CREDDATA_WORKLOAD
    target.mkdir(parents=True, exist_ok=True)
    output = target / 'labels.jsonl'
    if output.exists() and not force:
        raise QualityError(f'{output} already exists; pass --force to replace it')
    labels_bytes = ''.join(label_line(record) + '\n' for record in labels).encode('ascii')
    write_bytes(output, labels_bytes)
    digest, file_count, total = tree_digest(checkout / 'data')
    manifest = {
        'schema': WORKLOADS_SCHEMA,
        'set': 'credata',
        'workloads': [{
            'id': CREDDATA_WORKLOAD,
            'family': 'labeled',
            'modes': ['dir'],
            'source': {'kind': 'git', 'url': CREDDATA_URL, 'commit': CREDDATA_COMMIT, 'refs': 'HEAD'},
            'path': data_relative,
            'size': {'bytes': total, 'files': file_count, 'commits': 0},
            'labels': CREDDATA_WORKLOAD + '/labels.jsonl',
            'tuned': False,
        }],
    }
    summary = {
        'commit': CREDDATA_COMMIT,
        'data_tree_sha256': digest,
        'labels_sha256': sha256_hex(labels_bytes),
        'labels': {'total': len(labels),
                   'secret': sum(1 for record in labels if record['label'] == 'secret'),
                   'not-secret': sum(1 for record in labels if record['label'] == 'not-secret')},
        'categories': label_counts(labels),
        'problems': problems,
    }
    write_bytes(target / 'workload.json', json_bytes(manifest))
    write_bytes(target / 'summary.json', json_bytes(summary))
    return target, summary
