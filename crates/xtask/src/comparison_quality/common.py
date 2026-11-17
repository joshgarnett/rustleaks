# Shared helpers for the comparison quality tools.
#
# Python 3.9 standard library only. xtask embeds these files with
# include_str! and runs them with `python3 -I -c`, so the files are
# concatenated into one script in a fixed order: common, formats, contexts,
# generator, creddata, main.

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import zlib

WORKLOADS_SCHEMA = 'rustleaks-comparison-workloads-v1'
EXPECTED_SCHEMA = 'rustleaks-comparison-quality-expected-v1'
LABEL_FIELDS = ('workload', 'path', 'commit', 'start', 'end', 'line',
                'secret_sha256', 'category', 'label', 'source')
LABEL_VALUES = ('secret', 'not-secret')


class QualityError(Exception):
    """A failure that is reported to the user without a traceback."""


class Drbg:
    """Deterministic byte stream: SHA-256 over a seed, a stream name and a counter.

    The output depends only on the seed and stream strings, never on the
    Python version, the platform or hash randomization.
    """

    def __init__(self, seed, stream):
        self.key = hashlib.sha256(
            ('rustleaks-quality\0' + seed + '\0' + stream).encode('utf-8')).digest()
        self.counter = 0
        self.buffer = b''

    def bytes(self, count):
        while len(self.buffer) < count:
            self.buffer += hashlib.sha256(self.key + self.counter.to_bytes(8, 'big')).digest()
            self.counter += 1
        result, self.buffer = self.buffer[:count], self.buffer[count:]
        return result

    def below(self, bound):
        if bound <= 0:
            raise ValueError('bound must be positive')
        bits = (bound - 1).bit_length()
        if bits == 0:
            return 0
        width = (bits + 7) // 8
        mask = (1 << bits) - 1
        while True:
            value = int.from_bytes(self.bytes(width), 'big') & mask
            if value < bound:
                return value

    def between(self, low, high):
        return low + self.below(high - low + 1)

    def choice(self, items):
        return items[self.below(len(items))]

    def chance(self, numerator, denominator):
        return self.below(denominator) < numerator

    def chars(self, alphabet, count):
        return ''.join(alphabet[self.below(len(alphabet))] for _ in range(count))

    def shuffle(self, items):
        for index in range(len(items) - 1, 0, -1):
            other = self.below(index + 1)
            items[index], items[other] = items[other], items[index]
        return items


UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
LOWER = 'abcdefghijklmnopqrstuvwxyz'
DIGITS = '0123456789'
HEX = '0123456789abcdef'
ALNUM = UPPER + LOWER + DIGITS
BASE62 = DIGITS + UPPER + LOWER
BASE64 = UPPER + LOWER + DIGITS + '+/'
BASE64URL = UPPER + LOWER + DIGITS + '-_'
BASE32 = UPPER + '234567'


def b64(data):
    return base64.b64encode(data).decode('ascii')


def b64url(data):
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def crc32(data):
    return zlib.crc32(data) & 0xffffffff


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=False, ensure_ascii=True) + '\n').encode('ascii')


def label_line(record):
    ordered = {field: record[field] for field in LABEL_FIELDS}
    return json.dumps(ordered, separators=(',', ':'), ensure_ascii=True)


def write_bytes(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'wb') as handle:
        handle.write(data)


def tree_digest(root):
    """Digest of every regular file below root: sorted relative paths and contents."""
    entries = []
    total = 0
    for directory, names, files in os.walk(root):
        names.sort()
        for name in sorted(files):
            full = Path(directory) / name
            if full.is_symlink() or not full.is_file():
                raise QualityError(f'unexpected non-regular file {full}')
            data = full.read_bytes()
            total += len(data)
            relative = full.relative_to(root).as_posix()
            entries.append(f'{relative}\0{sha256_hex(data)}\n')
    entries.sort()
    return sha256_hex(''.join(entries).encode('utf-8')), len(entries), total


def resolve_outside(path, source_root, what):
    """Resolve path and refuse locations inside the source checkout."""
    resolved = Path(path).expanduser().resolve()
    if source_root is not None:
        root = Path(source_root).resolve()
        if resolved == root or root in resolved.parents:
            raise QualityError(f'{what} {resolved} is inside the source checkout; '
                               'use a cache folder outside the repository')
    return resolved


def reset_directory(path, force):
    if path.exists():
        if not force:
            raise QualityError(f'{path} already exists; pass --force to replace it')
        shutil.rmtree(path)
    path.mkdir(parents=True)


def check_label_record(record, where):
    if list(record.keys()) != list(LABEL_FIELDS):
        raise QualityError(f'{where}: label fields must be exactly {", ".join(LABEL_FIELDS)}')
    if record['label'] not in LABEL_VALUES:
        raise QualityError(f'{where}: label must be secret or not-secret')
    if not (isinstance(record['start'], int) and isinstance(record['end'], int)
            and 0 <= record['start'] < record['end']):
        raise QualityError(f'{where}: start and end must be increasing byte offsets')
    if not (isinstance(record['line'], int) and record['line'] >= 1):
        raise QualityError(f'{where}: line must be a positive integer')
    path = record['path']
    if path.startswith('/') or '\\' in path or '..' in path.split('/'):
        raise QualityError(f'{where}: path must be relative with forward slashes')


def line_number(data, offset):
    """One-based line of a byte offset. `\r\n`, `\r` and `\n` each end a line."""
    before = data[:offset]
    return before.count(b'\n') + before.count(b'\r') - before.count(b'\r\n') + 1


def check_labels_against_tree(labels_path, tree_root):
    """Check every label against the bytes it points at. Returns the records."""
    records = []
    cache = {}
    with open(labels_path, 'r', encoding='ascii') as handle:
        for number, line in enumerate(handle, 1):
            where = f'{labels_path}:{number}'
            record = json.loads(line)
            check_label_record(record, where)
            path = record['path']
            if path not in cache:
                cache[path] = (Path(tree_root) / path).read_bytes()
            data = cache[path]
            if record['end'] > len(data):
                raise QualityError(f'{where}: span ends after the file')
            span = data[record['start']:record['end']]
            if sha256_hex(span) != record['secret_sha256']:
                raise QualityError(f'{where}: secret_sha256 does not match the span')
            if line_number(data, record['start']) != record['line']:
                raise QualityError(f'{where}: line does not match the start offset')
            records.append(record)
    return records
