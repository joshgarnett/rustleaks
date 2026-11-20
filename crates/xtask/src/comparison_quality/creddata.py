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


class CredDataFile:
    """One data file, split into lines the way CredData's obfuscate_creds.py
    reads it: `\r\n` and a lone `\r` are line breaks, like `\n`. Offsets
    always point into the raw bytes, which are never changed."""

    def __init__(self, raw):
        self.raw = raw
        self.text = raw.decode('utf-8')
        self.char_lines = self.split(self.text, '\r\n', '\r', '\n')
        self.byte_lines = self.split(raw, b'\r\n', b'\r', b'\n')

    @staticmethod
    def split(data, pair, carriage, feed):
        """Return (start, end) of each line's content, without its line break."""
        lines = []
        start = 0
        index = 0
        size = len(data)
        while index < size:
            if data[index:index + 2] == pair:
                lines.append((start, index))
                index += 2
                start = index
            elif data[index:index + 1] in (carriage, feed):
                lines.append((start, index))
                index += 1
                start = index
            else:
                index += 1
        lines.append((start, size))
        return lines

    def offset(self, line, value, at_end):
        """Byte offset of a character position on a one-based line. A negative
        position means the start of the line, or its end when `at_end`."""
        char_start, char_end = self.char_lines[line - 1]
        byte_start, byte_end = self.byte_lines[line - 1]
        if value < 0:
            return byte_end if at_end else byte_start
        if value > char_end - char_start:
            raise ValueError(f'value position {value} is past the end of line {line}')
        return byte_start + len(self.text[char_start:char_start + value].encode('utf-8'))


def convert_row(row, document):
    """Return (start, end, line) byte offsets for one metadata row, or raise ValueError."""
    line_start = meta_integer(row['LineStart'])
    line_end = meta_integer(row['LineEnd'])
    if not 1 <= line_start <= line_end <= len(document.char_lines):
        raise ValueError('line numbers are outside the file')
    start = document.offset(line_start, meta_integer(row['ValueStart']), False)
    end = document.offset(line_end, meta_integer(row['ValueEnd']), True)
    if end <= start:
        raise ValueError('value span is empty')
    return start, end, line_start


def convert_creddata(checkout, max_problems):
    """Returns (labels, problems, conflicts)."""
    meta = checkout / 'meta'
    data = checkout / 'data'
    if not meta.is_dir():
        raise QualityError(f'{meta} is missing; check out CredData at {CREDDATA_COMMIT}')
    if not data.is_dir():
        raise QualityError(f'{data} is missing; run CredData download_data.py first (see docs/dev/comparison-quality.md)')
    documents = {}
    spans = {}
    problems = []
    for meta_name, row in read_meta_rows(meta):
        where = f'meta/{meta_name} Id {row["Id"]}'
        file_path = row['FilePath']
        if not file_path.startswith('data/') or '..' in file_path.split('/') or '\\' in file_path:
            problems.append(f'{where}: unexpected FilePath')
            continue
        relative = file_path[len('data/'):]
        if relative not in documents:
            try:
                documents[relative] = CredDataFile((data / relative).read_bytes())
            except (OSError, ValueError) as error:
                documents[relative] = error
        document = documents[relative]
        if isinstance(document, Exception):
            problems.append(f'{where}: cannot read {relative}: {document}')
            continue
        label = CREDDATA_LABELS.get(row['GroundTruth'])
        if label is None:
            problems.append(f'{where}: unknown GroundTruth {row["GroundTruth"]!r}')
            continue
        try:
            start, end, line = convert_row(row, document)
        except ValueError as error:
            problems.append(f'{where}: {error}')
            continue
        # Rows without value positions mark whole lines; the scorer matches
        # those by line, not by byte overlap.
        whole_line = meta_integer(row['ValueStart']) < 0 and meta_integer(row['ValueEnd']) < 0
        found = spans.setdefault((relative, start, end), [])
        found.append((label, line, creddata_category(row['Category']), where, whole_line))
    labels = []
    conflicts = []
    for (relative, start, end), found in spans.items():
        if len({label for label, _, _, _, _ in found}) > 1:
            # The same bytes are labeled both secret and not secret. Leave the
            # span out rather than count it both ways.
            conflicts.append(f'{relative} bytes {start}-{end}: ' +
                             ', '.join(f'{where} {label}' for label, _, _, where, _ in found))
            continue
        label, _, category, _, _ = found[0]
        record = {
            'workload': CREDDATA_WORKLOAD, 'path': relative, 'commit': None, 'start': start, 'end': end,
            'line': line_of(documents[relative].raw, start),
            'secret_sha256': sha256_bytes(documents[relative].raw[start:end]),
            'category': category, 'label': label, 'source': 'credData',
        }
        if all(entry[4] for entry in found):
            record['span'] = 'line'
        labels.append(record)
    labels.sort(key=lambda record: (record['path'], record['start'], record['end']))
    if len(problems) > max_problems:
        shown = '\n  '.join(problems[:20])
        raise QualityError(f'{len(problems)} CredData rows could not be converted (limit {max_problems}):\n  {shown}')
    return labels, problems, sorted(conflicts)


def write_creddata(cache_root, checkout, max_problems, force):
    try:
        data_relative = (checkout / 'data').relative_to(cache_root).as_posix()
    except ValueError:
        raise QualityError(f'the CredData checkout {checkout} must be inside the cache folder {cache_root}')
    labels, problems, conflicts = convert_creddata(checkout, max_problems)
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
            # CredData labels only the lines its source tools reported, so a
            # finding on an unlabeled line is unknown, not a false positive.
            'labels_complete': False,
            'tuned': False,
        }],
    }
    summary = {
        'commit': CREDDATA_COMMIT,
        'data_tree_sha256': digest,
        'labels_sha256': sha256_bytes(labels_bytes),
        'labels': {'total': len(labels),
                   'secret': sum(1 for record in labels if record['label'] == 'secret'),
                   'not-secret': sum(1 for record in labels if record['label'] == 'not-secret')},
        'categories': label_counts(labels),
        'problems': problems,
        'conflicts': conflicts,
    }
    write_bytes(target / 'workload.json', json_bytes(manifest))
    write_bytes(target / 'summary.json', json_bytes(summary))
    return target, summary
