# Command line entry point: cargo xtask compare-quality <credata|generate|verify|self-test>.

import argparse
import sys
import tempfile

CREDDATA_STEPS = '''CredData is not downloaded by this command. Prepare it once:
  1. mkdir -p CACHE/credata
  2. git clone https://github.com/Samsung/CredData CACHE/credata/CredData
  3. git -C CACHE/credata/CredData checkout {commit}
  4. cd CACHE/credata/CredData && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
  5. .venv/bin/python download_data.py --data_dir data --jobs 8
Then run: cargo xtask compare-quality credata --cache CACHE'''


def command_generate(arguments):
    cache = resolve_outside(arguments.out, arguments.source_root, 'output folder')
    target, summary = write_corpus(cache, arguments.seed, arguments.scale, arguments.force)
    check_corpus(target)
    print(f'wrote {summary["size"]["files"]} files and {summary["labels"]["total"]} labels '
          f'({summary["labels"]["secret"]} secret, {summary["labels"]["not-secret"]} not-secret) to {target}')


def command_verify(arguments):
    if arguments.out is not None:
        cache = resolve_outside(arguments.out, arguments.source_root, 'output folder')
        target = cache / CORPUS_DIRECTORY
        summary = check_corpus(target)
        compare_with_committed(arguments.source_root, target, summary)
        print(f'{target} matches its labels and {COMMITTED_EXPECTED}')
        return
    with tempfile.TemporaryDirectory(prefix='rustleaks-quality-') as temporary:
        cache = Path(temporary)
        expected = json.loads((Path(arguments.source_root) / COMMITTED_EXPECTED).read_text(encoding='ascii'))
        target, summary = write_corpus(cache, expected['seed'], expected['scale'], False)
        check_corpus(target)
        compare_with_committed(arguments.source_root, target, summary)
    print(f'regenerated corpus matches {COMMITTED_EXPECTED} and {COMMITTED_MANIFEST}')


def command_credata(arguments):
    cache = resolve_outside(arguments.cache, arguments.source_root, 'cache folder')
    checkout = (resolve_outside(arguments.checkout, arguments.source_root, 'CredData checkout')
                if arguments.checkout else cache / 'credata' / 'CredData')
    if not (checkout / 'meta').is_dir():
        raise QualityError(f'no CredData checkout at {checkout}.\n' +
                           CREDDATA_STEPS.format(commit=CREDDATA_COMMIT).replace('CACHE', str(cache)))
    target, summary = write_creddata(cache, checkout, arguments.max_problems, arguments.force)
    print(f'wrote {summary["labels"]["total"]} CredData labels ({summary["labels"]["secret"]} secret) to {target}')
    if summary['problems'] or summary['conflicts']:
        print(f'{len(summary["problems"])} rows were skipped and {len(summary["conflicts"])} conflicting spans '
              f'were left out; see {target / "summary.json"}')


def self_test_creddata(root):
    checkout = root / 'credata' / 'CredData'
    meta = checkout / 'meta'
    data = checkout / 'data' / 'abcd1234' / 'src'
    meta.mkdir(parents=True)
    data.mkdir(parents=True)
    # Synthetic CredData-shaped files. Values are drawn at run time. A line
    # holds a two-byte character before its value, so character and byte
    # offsets differ. The file mixes `\r\n`, `\r` and `\n` line breaks.
    rng = Drbg('self-test', 'credata')
    first_value, second_value = rng.chars(ALNUM, 24), rng.chars(ALNUM, 21)
    lines = ['# café settings', 'api_key = "' + first_value + '"', 'password = getPass()',
             '-----BEGIN SYNTHETIC BLOCK-----', 'QUJDREVGR0hJSktMTU5PUA==', '-----END SYNTHETIC BLOCK-----',
             'note = "ünicode" value="' + second_value + '"']
    breaks = ['\r\n', '\n', '\r', '\r\n', '\r\n', '\n']
    text = ''.join(line + separator for line, separator in zip(lines, breaks + ['']))
    (data / 'f0000001.py').write_bytes(text.encode('utf-8'))
    header = ','.join(CREDDATA_META_FIELDS)
    path = 'data/abcd1234/src/f0000001.py'
    first_at = lines[1].index(first_value)
    second_at = lines[6].index(second_value)
    rows = [
        f'1,f0000001,GitHub,abcd1234,{path},2,2,T,{first_at},{first_at + 24},,,Key',
        f'2,f0000001,GitHub,abcd1234,{path},3,3,F,,,,,Password',
        f'3,f0000001,GitHub,abcd1234,{path},4,6,T,0,{len(lines[5])},,,PEM Private Key',
        f'4,f0000001,GitHub,abcd1234,{path},7,7,X,{second_at},{second_at + 21},,,Secret:Token',
    ]
    (meta / 'abcd1234.csv').write_text(header + '\n' + '\n'.join(rows) + '\n', encoding='utf-8')
    cache = root
    target, summary = write_creddata(cache, checkout, 0, False)
    records = check_labels_against_tree(target / 'labels.jsonl', checkout / 'data')
    raw = (data / 'f0000001.py').read_bytes()
    spans = [(record['label'], record['category'], raw[record['start']:record['end']].decode('utf-8'), record['line'])
             for record in records]
    expected = [
        ('secret', 'credata-key', first_value, 2),
        ('not-secret', 'credata-password', 'password = getPass()', 3),
        ('secret', 'credata-pem-private-key', '\r\n'.join(lines[3:6]), 4),
        ('not-secret', 'credata-secret-token', second_value, 7),
    ]
    if spans != expected:
        raise QualityError(f'CredData conversion self-test failed: {spans!r}')
    if any(record['path'] != 'abcd1234/src/f0000001.py' or record['source'] != 'credData' for record in records):
        raise QualityError('CredData conversion self-test produced wrong paths or sources')
    manifest = json.loads((target / 'workload.json').read_text(encoding='ascii'))
    workload = manifest['workloads'][0]
    if workload['path'] != 'credata/CredData/data' or workload['labels'] != 'credata/labels.jsonl':
        raise QualityError('CredData manifest paths are wrong')
    # Rows past the end of a line or the file are problems, not silent
    # labels, and a span labeled both ways is left out and reported.
    bad_rows = [
        rows[0],
        f'5,f0000001,GitHub,abcd1234,{path},2,2,F,{first_at},{first_at + 24},,,Key',
        f'6,f0000001,GitHub,abcd1234,{path},4,6,T,0,{len(lines[5]) + 1},,,PEM Private Key',
        f'7,f0000001,GitHub,abcd1234,{path},99,99,T,0,4,,,Key',
    ]
    (meta / 'abcd1234.csv').write_text(header + '\n' + '\n'.join(bad_rows) + '\n', encoding='utf-8')
    try:
        write_creddata(cache, checkout, 0, True)
    except QualityError:
        pass
    else:
        raise QualityError('CredData conversion accepted rows past the end of a line or file')
    labels, problems, conflicts = convert_creddata(checkout, 2)
    if labels or len(problems) != 2 or len(conflicts) != 1:
        raise QualityError(f'CredData conversion did not report bad rows and conflicts: {problems!r} {conflicts!r}')


def self_test_generator(root, source_root):
    first, summary = write_corpus(root / 'one', 'self-test', 0.05, False)
    check_corpus(first)
    second, again = write_corpus(root / 'two', 'self-test', 0.05, False)
    check_corpus(second)
    if (summary['tree_sha256'], summary['labels_sha256']) != (again['tree_sha256'], again['labels_sha256']):
        raise QualityError('the generator is not deterministic')
    other, different = write_corpus(root / 'three', 'self-test-other', 0.05, False)
    if different['tree_sha256'] == summary['tree_sha256']:
        raise QualityError('the seed does not change the corpus')
    unsourced = [kind.identifier for kind in KINDS if kind.identifier not in SOURCES]
    if unsourced or len(SOURCES) != len(KINDS):
        raise QualityError(f'kinds and format sources differ: {", ".join(unsourced) or "extra sources"}')
    missing = [kind.identifier for kind in KINDS if kind.identifier not in summary['kinds']]
    if missing:
        raise QualityError(f'kinds without items: {", ".join(missing)}')
    for category in CATEGORIES:
        if category not in summary['categories']:
            raise QualityError(f'category without labels: {category}')
    labels = summary['labels']
    if labels['secret'] == 0 or labels['not-secret'] == 0:
        raise QualityError('the corpus needs both secret and not-secret labels')
    manifest = json.loads((first / 'workload.json').read_text(encoding='ascii'))
    workload = manifest['workloads'][0]
    if manifest['schema'] != WORKLOADS_SCHEMA or workload['family'] != 'labeled' or workload['tuned']:
        raise QualityError('the workload manifest is wrong')
    try:
        write_corpus(root / 'one', 'self-test', 0.05, False)
    except QualityError:
        pass
    else:
        raise QualityError('the generator replaced an existing corpus without --force')
    if source_root is not None:
        try:
            resolve_outside(Path(source_root) / 'cache', source_root, 'output folder')
        except QualityError:
            pass
        else:
            raise QualityError('an output folder inside the source checkout was accepted')
    # A changed byte must fail the label check.
    path = next((first / 'tree').rglob('*.env'), None) or next(p for p in (first / 'tree').rglob('*') if p.is_file())
    data = bytearray(path.read_bytes())
    data[0] = ord('#') if data[0] != ord('#') else ord('!')
    path.write_bytes(bytes(data))
    try:
        check_corpus(first)
    except QualityError:
        pass
    else:
        raise QualityError('a modified corpus file passed the check')
    # A span that the generator could break by quoting must stay exact.
    doc = Doc()
    doc.add('key = "')
    doc.fragment(transform(whole('a\nb', SECRET, 'private-key'), escape_newlines))
    doc.line('"')
    if doc.spans != [(7, 11, SECRET, 'private-key')] or doc.data()[7:11] != b'a\\nb':
        raise QualityError('escaped span offsets are wrong')
    try:
        transform(inner('x', 'y\n', 'z', SECRET, 'password'), escape_newlines)
    except QualityError:
        pass
    else:
        raise QualityError('a partial span passed through an escaping transform')
    # GitHub-style checksum: the last six characters encode CRC32 of the body.
    token = github_classic(Drbg('self-test', 'github'), 'ghp_')
    if len(token) != 40 or base62_fixed(crc32(token[4:34].encode('ascii')), 6) != token[34:]:
        raise QualityError('the token checksum layout is wrong')
    routable = gitlab_routable(Drbg('self-test', 'gitlab'))
    body, length = routable[len('glpat-'):].split('.01.')
    if (int(length[:2], 36) != len(body) or
            int(routable[-7:], 36) != crc32(routable[:-7].encode('ascii'))):
        raise QualityError('the routable token layout is wrong')
    if crc24(b'') != 0xB704CE:
        raise QualityError('the armor checksum is wrong')


def command_self_test(arguments):
    with tempfile.TemporaryDirectory(prefix='rustleaks-quality-self-test-') as temporary:
        root = Path(temporary)
        self_test_generator(root / 'generator', arguments.source_root)
        self_test_creddata(root / 'creddata')
    print('comparison quality self-test passed')


def parse(argv):
    parser = argparse.ArgumentParser(prog='cargo xtask compare-quality')
    parser.add_argument('--source-root', default=None, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest='command', required=True)
    generate = commands.add_parser('generate', help='write the constructed labeled corpus to a cache folder')
    generate.add_argument('--out', required=True, help='cache folder outside the repository')
    generate.add_argument('--seed', default=DEFAULT_SEED)
    generate.add_argument('--scale', type=float, default=DEFAULT_SCALE)
    generate.add_argument('--force', action='store_true', help='replace an existing corpus folder')
    verify = commands.add_parser('verify', help='check a corpus against its labels and the committed digests')
    verify.add_argument('--out', default=None, help='cache folder that holds a generated corpus')
    credata = commands.add_parser('credata', help='convert CredData metadata into labels')
    credata.add_argument('--cache', required=True, help='cache folder outside the repository')
    credata.add_argument('--checkout', default=None, help='CredData checkout inside the cache folder')
    credata.add_argument('--max-problems', type=int, default=0)
    credata.add_argument('--force', action='store_true')
    commands.add_parser('self-test', help='run the generator and adapter checks on tiny data')
    return parser.parse_args(argv)


def main(argv):
    arguments = parse(argv)
    handlers = {'generate': command_generate, 'verify': command_verify, 'credata': command_credata,
                'self-test': command_self_test}
    try:
        handlers[arguments.command](arguments)
    except QualityError as error:
        print(f'compare-quality: {error}', file=sys.stderr)
        return 1
    return 0


sys.exit(main(sys.argv[1:]))
