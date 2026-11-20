# Realistic synthetic workloads (recipe rustleaks-synthetic-v2). Every value
# is generated from a fixed seed. Labels come from construction: a `secret`
# label marks each planted credential-shaped value, and a `not-secret` label
# marks each planted hard negative. Every other byte is non-secret filler by
# construction, so a finding outside a `secret` label is a false positive.

SYNTHETIC_VERSION = 'rustleaks-synthetic-v2'
SYNTHETIC_SEED = 'rustleaks-comparison-workloads-2026-11-17'
LOWER = 'abcdefghijklmnopqrstuvwxyz'
UPPER = LOWER.upper()
DIGITS = '0123456789'
ALNUM = LOWER + UPPER + DIGITS
HEX = DIGITS + 'abcdef'
BASE32 = UPPER + '234567'
MIB = 1024 * 1024
SIZE_SERIES = (1, 16, 128, 1024)
DENSE_SIZES = (25000, 50000, 100000, 200000, 400000)
MAIN_SHAPES = ('keyword-dense', 'entropy-negatives', 'mixed-source', 'minified', 'binary-mix')
DENSE_CASES = ('dense-github-pat-lines', 'dense-github-pat-single-line', 'dense-generic-single-line',
               'dense-planetscale-pairs', 'dense-base64-uris')
GIT_SHAPES = ('git-many-branches', 'git-merges', 'git-huge-hunk', 'git-many-small-files', 'git-renames')
# Fragments that would make a generated value look like a placeholder.
AVOID = ('test', 'exam', 'sampl', 'dumm', 'fake', 'xxx', 'pass', 'secr', 'toke', 'key', 'chang',
         'place', 'demo', 'abc', '123', 'aaa', 'redact', 'mask', 'todo', 'fixme', 'null', 'none')


def entropy(text):
    counts = {}
    for character in text:
        counts[character] = counts.get(character, 0) + 1
    total = float(len(text))
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def random_value(stream, alphabet, length, classes=(LOWER, UPPER, DIGITS), minimum_entropy=3.5):
    classes = [group for group in classes if any(character in alphabet for character in group)]
    while True:
        value = stream.text(alphabet, length)
        lowered = value.lower()
        if any(fragment in lowered for fragment in AVOID):
            continue
        if re.search(r'(.)\1\1', value):
            continue
        if not all(any(character in group for character in value) for group in classes):
            continue
        if length >= 16 and entropy(value) < minimum_entropy:
            continue
        return value


def b64(stream, count):
    return base64.b64encode(stream.raw(count)).decode('ascii')


def pem_block(stream):
    body = base64.b64encode(stream.raw(1190)).decode('ascii')
    lines = [body[index:index + 64] for index in range(0, len(body), 64)]
    dash = '-' * 5
    return dash + 'BEGIN RSA PRIVATE KEY' + dash + '\n' + '\n'.join(lines) + '\n' + dash + 'END RSA PRIVATE KEY' + dash


# Positive kinds: (category, assignment name, value maker). The value maker
# returns (text, secret_start, secret_end) within the text. The source of
# each shape, and where it coincides with a Gitleaks rule's bounds, is listed
# in docs/dev/comparison-workloads.md.
def _token(prefix, alphabet, length, classes=(LOWER, UPPER, DIGITS)):
    def make(stream):
        value = prefix + random_value(stream, alphabet, length, classes)
        return value, 0, len(value)
    return make


BASE62 = DIGITS + UPPER + LOWER


def checksum_token(prefix):
    # GitHub and npm tokens end in 6 base62 characters of the CRC32 of the
    # 30 random characters before them. The base62 alphabet is 0-9, A-Z,
    # a-z, left padded with 0. Published examples in the Kingfisher 1.113.0
    # rules (github.yml, npm.yml) reproduce with this reading.
    def make(stream):
        body = random_value(stream, ALNUM, 30)
        value = zlib.crc32(body.encode('ascii')) & 0xffffffff
        check = ''
        while value:
            value, digit = divmod(value, 62)
            check = BASE62[digit] + check
        token = prefix + body + check.rjust(6, '0')
        return token, 0, len(token)
    return make


def _slack(stream):
    first = random_value(stream, DIGITS, 12, (DIGITS,), 0)
    second = random_value(stream, DIGITS, 12, (DIGITS,), 0)
    value = 'xoxb-' + first + '-' + second + '-' + random_value(stream, ALNUM, 24)
    return value, 0, len(value)


def _sendgrid(stream):
    value = 'SG.' + random_value(stream, ALNUM + '-_', 22) + '.' + random_value(stream, ALNUM + '-_', 43)
    return value, 0, len(value)


def _pem(stream):
    value = pem_block(stream)
    return value, 0, len(value)


def _password(stream):
    value = random_value(stream, ALNUM + '!#%+=', 20)
    return value, 0, len(value)


def _uri(stream):
    password = random_value(stream, ALNUM, 18)
    prefix = 'postgres://app_user:'
    value = prefix + password + '@db.internal.invalid:5432/app'
    return value, len(prefix), len(prefix) + len(password)


POSITIVE_KINDS = {
    'github-pat': ('vcs-token', 'GITHUB_TOKEN', checksum_token('ghp_')),
    'gitlab-pat': ('vcs-token', 'GITLAB_TOKEN', _token('glpat-', ALNUM, 20)),
    'aws-access-key': ('cloud-key', 'AWS_ACCESS_KEY_ID', _token('AKIA', BASE32, 16, (UPPER, '234567'))),
    'slack-bot-token': ('chat-token', 'SLACK_BOT_TOKEN', _slack),
    'stripe-secret-key': ('payment-key', 'STRIPE_API_KEY', _token('sk_live_', ALNUM, 24)),
    'npm-token': ('package-token', 'NPM_TOKEN', checksum_token('npm_')),
    'pypi-token': ('package-token', 'PYPI_TOKEN', _token('pypi-AgEIcHlwaS5vcmc', ALNUM + '-_', 70)),
    'sendgrid-key': ('email-api-key', 'SENDGRID_API_KEY', _sendgrid),
    'shopify-token': ('commerce-token', 'SHOPIFY_ACCESS_TOKEN', _token('shpat_', HEX, 32, (DIGITS, 'abcdef'))),
    'private-key': ('private-key', 'PRIVATE_KEY', _pem),
    'generic-password': ('generic-password', 'DB_PASSWORD', _password),
    'credential-uri': ('credential-uri', 'DATABASE_URL', _uri),
}
POSITIVE_ORDER = tuple(POSITIVE_KINDS)


def _negative(prefix, maker):
    def make(stream):
        value = prefix + maker(stream)
        return value, 0, len(value)
    return make


def _uuid(stream):
    text = stream.text(HEX, 32)
    return '%s-%s-4%s-%s%s-%s' % (text[:8], text[8:12], text[13:16], stream.choice('89ab'), text[17:20], text[20:])


NEGATIVE_KINDS = {
    'sha256-hex': ('hash', 'checksum', _negative('', lambda s: s.text(HEX, 64))),
    'sha1-hex': ('hash', 'commit', _negative('', lambda s: s.text(HEX, 40))),
    'uuid': ('uuid', 'request_id', _negative('', _uuid)),
    'sri-integrity': ('integrity', 'integrity', _negative('sha512-', lambda s: b64(s, 64))),
    'go-sum': ('checksum', 'h1', _negative('h1:', lambda s: b64(s, 32))),
    'example-aws-key': ('example-key', 'aws_access_key_id',
                        _negative('AKIA', lambda s: s.text(BASE32, 9) + 'EXAMPLE')),
    'placeholder-token': ('placeholder', 'GITHUB_TOKEN', _negative('ghp_', lambda s: 'x' * 36)),
    'env-reference': ('placeholder', 'api_token', _negative('', lambda s: '${' + s.choice(
        ('API_TOKEN', 'DB_PASSWORD', 'SERVICE_SECRET', 'AUTH_TOKEN')) + '}')),
    'template-placeholder': ('placeholder', 'api_key', _negative('', lambda s: s.choice(
        ('<your-api-key>', '<YOUR_TOKEN_HERE>', '{{ api_token }}', 'REPLACE_WITH_REAL_KEY')))),
    'base64-data': ('encoded-data', 'payload', _negative('', lambda s: b64(s, 48))),
    'masked-value': ('placeholder', 'password', _negative('', lambda s: '*' * s.between(8, 16))),
}
NEGATIVE_ORDER = tuple(NEGATIVE_KINDS)

# Line templates by file style. `{n}` is the name, `{v}` the value.
STYLES = {
    'env': '{N}={v}', 'ini': '{n} = {v}', 'yaml': '{n}: {v}', 'toml': '{n} = "{v}"',
    'properties': '{n}={v}', 'json': '  "{n}": "{v}",', 'txt': 'The {n} value is {v} for this host.',
    'py': '{N} = "{v}"', 'js': 'const {c} = "{v}";', 'ts': 'export const {c}: string = "{v}";',
    'go': '\t{c} := "{v}"', 'rs': 'const {N}: &str = "{v}";', 'java': '    String {c} = "{v}";',
    'rb': '{n} = "{v}"', 'php': '${c} = \'{v}\';', 'c': 'static const char *{n} = "{v}";',
    'cs': '        var {c} = "{v}";', 'kt': '    val {c} = "{v}"', 'sh': 'export {N}="{v}"',
    'minjs': '{c}:"{v}",', 'mincss': '/*{v}*/', 'lock': '    "{n}": "{v}",',
}


def camel(name):
    parts = name.lower().split('_')
    return parts[0] + ''.join(part.title() for part in parts[1:])


def render(style, name, text, start, end):
    # Returns the rendered bytes and the value span inside them. PEM blocks
    # stay on their own lines, as they would in a real file.
    if '\n' in text:
        template = '{v}' if style not in ('minjs', 'mincss') else STYLES[style]
    else:
        template = STYLES[style]
    if style in ('minjs', 'mincss') and '\n' in text:
        text = text.replace('\n', '\\n')
        end = len(text)
    line = template.replace('{N}', name).replace('{n}', name.lower()).replace('{c}', camel(name))
    offset = line.index('{v}')
    line = line.replace('{v}', text)
    data = line.encode('utf-8')
    prefix = len(line[:offset].encode('utf-8'))
    return data, prefix + start, prefix + end


def plant(stream, kind, style, positive):
    table = POSITIVE_KINDS if positive else NEGATIVE_KINDS
    category, name, maker = table[kind]
    text, start, end = maker(stream)
    data, start, end = render(style, name, text, start, end)
    return data, (start, end, category, 'secret' if positive else 'not-secret', kind)


# Filler pools. Pool entries are single lines ending in a newline, or
# fragments without a newline for minified files.
WORDS = ('the', 'service', 'request', 'returns', 'value', 'when', 'cache', 'is', 'enabled', 'for', 'each',
         'user', 'account', 'session', 'handler', 'config', 'default', 'timeout', 'retry', 'limit', 'queue',
         'worker', 'record', 'table', 'index', 'query', 'result', 'error', 'message', 'client', 'server',
         'route', 'module', 'package', 'version', 'build', 'release', 'deploy', 'region', 'cluster', 'node',
         'metric', 'event', 'stream', 'buffer', 'file', 'path', 'option', 'flag', 'field', 'schema', 'model',
         'view', 'template', 'render', 'update', 'create', 'delete', 'read', 'write', 'open', 'close',
         'start', 'stop', 'check', 'parse', 'format', 'encode', 'decode', 'load', 'store', 'fetch', 'send')
KEYWORD_NAMES = ('api_key', 'token', 'password', 'secret', 'auth_token', 'access_key', 'client_secret',
                 'db_password', 'session_secret', 'key', 'apikey', 'authorization', 'private_key_path',
                 'secret_key_base', 'refresh_token', 'bearer', 'credentials', 'passwd', 'pwd', 'auth')
SAFE_VALUES = ('${API_TOKEN}', '${DB_PASSWORD}', 'os.environ["APP_TOKEN"]', 'process.env.API_KEY',
               '<placeholder>', 'changeme', 'true', 'false', 'null', '""', '********', '/etc/app/token.txt',
               'vault:secret/data/app#token', 'none', '30', '3600', 'v2', 'disabled', 'from-env',
               'see docs/setup.md', 'arn:aws:secretsmanager:region:account:secret:app', '${{ secrets.TOKEN }}')
LANGUAGES = ('py', 'js', 'ts', 'go', 'rs', 'java', 'rb', 'php', 'c', 'cs', 'kt', 'sh')
COMMENT = {'py': '#', 'rb': '#', 'sh': '#', 'js': '//', 'ts': '//', 'go': '//', 'rs': '//', 'java': '//',
           'php': '//', 'c': '//', 'cs': '//', 'kt': '//', 'yaml': '#', 'toml': '#', 'ini': ';',
           'env': '#', 'properties': '#', 'txt': '', 'json': '', 'lock': ''}


def prose(stream, words):
    return ' '.join(stream.choice(WORDS) for _ in range(words))


def ident(stream):
    return stream.choice(WORDS) + '_' + stream.choice(WORDS)


def pool_keyword(stream, style, size=4096):
    pool = []
    comment = COMMENT[style]
    for index in range(size):
        roll = stream.below(100)
        name = stream.choice(KEYWORD_NAMES)
        if roll < 45:
            line = render(style if style != 'txt' else 'ini', name.upper(), stream.choice(SAFE_VALUES), 0, 0)[0]
            line = line.decode('utf-8')
        elif roll < 60:
            line = (comment + ' ' if comment else '') + 'Rotate the %s every %d days; %s.' % (
                name.replace('_', ' '), stream.between(7, 365), prose(stream, stream.between(3, 30)))
        elif roll < 75:
            line = '%s_%s = %s' % (stream.choice(WORDS), stream.choice(WORDS), stream.choice(
                ('true', 'false', str(stream.between(0, 99999)), '"' + prose(stream, 2) + '"')))
        elif roll < 85:
            line = '[%s.%s]' % (stream.choice(WORDS), stream.choice(WORDS)) if style in ('ini', 'toml') else (
                comment + ' ' + prose(stream, stream.between(2, 12)) if comment else prose(stream, 8))
        elif roll < 95:
            line = '%s %s' % ('password' if stream.below(2) else 'token', prose(stream, stream.between(5, 60)))
        else:
            line = ''
        pool.append((line + '\n').encode('utf-8'))
    return pool


def code_line(stream, language):
    roll = stream.below(100)
    name = ident(stream)
    comment = COMMENT[language]
    if roll < 12:
        return comment + ' ' + prose(stream, stream.between(2, 18))
    if roll < 22:
        # Keyword use without a credential value.
        templates = {
            'py': 'token = request.headers.get("Authorization")',
            'js': 'const token = req.headers["authorization"];',
            'ts': 'const password: string | undefined = process.env.DB_PASSWORD;',
            'go': '\tsecret := os.Getenv("APP_SECRET")',
            'rs': '    let api_key = std::env::var("API_KEY")?;',
            'java': '        String password = config.getPassword();',
            'rb': 'api_key = ENV.fetch("API_KEY")',
            'php': '$token = getenv("API_TOKEN");',
            'c': '    const char *password = getenv("DB_PASSWORD");',
            'cs': '        var secret = Configuration["Auth:Secret"];',
            'kt': '    val token = System.getenv("TOKEN")',
            'sh': 'TOKEN="${TOKEN:-}"',
        }
        return templates[language]
    if roll < 24:
        # Long lines: data tables and generated strings.
        count = stream.between(40, 600)
        return '%s = [%s]' % (name, ', '.join(str(stream.below(65536)) for _ in range(count)))
    if roll < 30:
        return ''
    indent = ' ' * (4 * stream.below(4))
    body = {
        'py': 'def %s(%s):' % (name, ident(stream)), 'js': 'function %s(%s) {' % (name, ident(stream)),
        'ts': 'export function %s(%s: number): number {' % (name, ident(stream)),
        'go': 'func %s(%s int) error {' % (name, ident(stream)), 'rs': 'fn %s(%s: usize) -> usize {' % (name, ident(stream)),
        'java': 'public int %s(int %s) {' % (name, ident(stream)), 'rb': 'def %s(%s)' % (name, ident(stream)),
        'php': 'function %s($%s) {' % (name, ident(stream)), 'c': 'int %s(int %s) {' % (name, ident(stream)),
        'cs': 'public int %s(int %s) {' % (name, ident(stream)), 'kt': 'fun %s(%s: Int): Int {' % (name, ident(stream)),
        'sh': '%s() {' % name,
    }[language]
    if roll < 60:
        return indent + body
    return indent + '%s = %s(%s, %d)%s' % (name, ident(stream), ident(stream), stream.below(1000),
                                          ';' if language in ('js', 'ts', 'java', 'php', 'c', 'cs', 'rs') else '')


def pool_code(stream, language, size=4096):
    return [(code_line(stream, language) + '\n').encode('utf-8') for _ in range(size)]


def pool_lock(stream, kind, size=4096):
    pool = []
    for index in range(size):
        name = '%s-%s' % (stream.choice(WORDS), stream.choice(WORDS))
        version = '%d.%d.%d' % (stream.below(20), stream.below(40), stream.below(100))
        if kind == 'json':
            line = ('    "node_modules/%s": {"version": "%s", "resolved": "https://registry.npmjs.invalid/%s/-/%s-%s.tgz", '
                    '"integrity": "sha512-%s"},' % (name, version, name, name, version, b64(stream, 64)))
        elif kind == 'yarn':
            line = '"%s@^%s":\n  version "%s"\n  integrity sha512-%s' % (name, version, version, b64(stream, 64))
        elif kind == 'gosum':
            line = 'example.invalid/%s v%s h1:%s' % (name, version, b64(stream, 32))
        elif kind == 'sums':
            line = '%s  %s-%s.tar.gz' % (stream.text(HEX, 64), name, version)
        elif kind == 'cargo':
            line = '[[package]]\nname = "%s"\nversion = "%s"\nchecksum = "%s"\n' % (name, version, stream.text(HEX, 64))
        else:
            line = '%s,%s,%s,%d' % (_uuid(stream), name, stream.text(HEX, 40), stream.below(10 ** 9))
        pool.append((line + '\n').encode('ascii'))
    return pool


def pool_minified(stream, css, size=4096):
    pool = []
    for _ in range(size):
        if css:
            roll = stream.below(10)
            if roll == 0:
                pool.append(('.%s{background:url(data:image/png;base64,%s)}' % (ident(stream), b64(stream, 96))).encode('ascii'))
            else:
                pool.append(('.%s-%s{margin:%dpx %dpx;color:#%s;display:%s}' % (
                    stream.choice(WORDS), stream.choice(WORDS), stream.below(64), stream.below(64),
                    stream.text(HEX, 6), stream.choice(('flex', 'block', 'none', 'grid')))).encode('ascii'))
        else:
            a, b = stream.choice(LOWER), stream.choice(LOWER)
            roll = stream.below(10)
            if roll < 4:
                text = 'function %s%s(%s,%s){return %s.%s(%s)+%d}' % (a, b, a, b, a, stream.choice(WORDS), b, stream.below(999))
            elif roll < 7:
                text = 'var %s=%s.%s("%s"),%s=%d;' % (a, b, stream.choice(WORDS), prose(stream, 3), b, stream.below(99999))
            elif roll < 9:
                text = '%s.%s=function(){return"%s"};' % (a, stream.choice(WORDS), prose(stream, stream.between(1, 12)))
            else:
                text = '%s={%s:%d,%s:"%s",%s:!0};' % (a, stream.choice(WORDS), stream.below(9999), stream.choice(WORDS),
                                                   stream.text(ALNUM, stream.between(4, 16)), stream.choice(WORDS))
            pool.append(text.encode('ascii'))
    return pool


POOLS = {}


def cached_pool(key, make):
    # Pools depend only on their key, so each is built once per process.
    if key not in POOLS:
        POOLS[key] = make(Stream(SYNTHETIC_SEED + ':pool:' + key))
    return POOLS[key]


class Builder:
    def __init__(self, workload, path):
        self.workload = workload
        self.path = path
        self.parts = []
        self.size = 0
        self.newlines = 0
        self.pending = []

    def add(self, data, newlines):
        self.parts.append(data)
        self.size += len(data)
        self.newlines += newlines

    def add_span(self, data, span, **extra):
        # Counts lines as `line_of` does; the running count avoids rescanning
        # the whole file for every span.
        start, end, category, label, kind = span
        line = self.newlines + 1 + data.count(b'\n', 0, start)
        end_line = self.newlines + 1 + data.count(b'\n', 0, max(start, end - 1))
        self.pending.append((self.size + start, self.size + end, line, end_line, category, label, kind, extra))
        self.add(data, data.count(b'\n'))

    def finish(self, labels):
        data = b''.join(self.parts)
        for start, end, line, end_line, category, label, kind, extra in self.pending:
            record = {'workload': self.workload, 'path': self.path, 'commit': None, 'start': start,
                      'end': end, 'line': line, 'end_line': end_line,
                      'secret_sha256': extra.pop('secret_sha256', None) or sha256_bytes(data[start:end]),
                      'category': category, 'label': label, 'source': 'constructed', 'kind': kind}
            record.update(extra)
            labels.append(record)
        return data


def scheduled(stream, size, every):
    # Deterministic count with the given mean spacing, at sorted offsets.
    count = size // every + (1 if stream.below(every) < size % every else 0)
    return sorted(stream.below(max(1, size)) for _ in range(count))


def fill_lines(builder, stream, target, pool, short, plants, newline=True):
    # Fills to exactly `target` bytes. `plants` holds (offset, data, span)
    # tuples. Pool lines are chosen by the stream until the next one would
    # overflow; short lines and a final space pad make the size exact.
    plants = sorted(plants, key=lambda item: item[0])
    reserve = sum(len(item[1]) + (1 if newline else 0) for item in plants)
    budget = target - reserve - (1 if not newline else 0)
    if budget < 0:
        fail('planted values exceed the file size of %s' % builder.path)
    index = 0
    count = len(pool)
    used = 0
    add = builder.add
    while True:
        while index < len(plants) and plants[index][0] <= used:
            _, data, span = plants[index]
            builder.add_span(data + (b'\n' if newline else b''), span)
            index += 1
        line = pool[stream.u32() % count]
        if used + len(line) > budget:
            break
        add(line, line.count(b'\n'))
        used += len(line)
    for _, data, span in plants[index:]:
        builder.add_span(data + (b'\n' if newline else b''), span)
    for _ in range(64):
        line = short[stream.u32() % len(short)]
        if used + len(line) <= budget:
            add(line, line.count(b'\n'))
            used += len(line)
    remaining = budget - used
    if newline:
        if remaining:
            add(b' ' * (remaining - 1) + b'\n', 1)
    else:
        add(b' ' * remaining + b'\n', 1)


def plan_files(stream, total, low, high):
    sizes = []
    remaining = total
    while remaining:
        size = stream.between(low, high)
        if remaining - size < low:
            size = remaining
        sizes.append(size)
        remaining -= size
    return sizes


def make_plants(stream, size, positive_every, negative_every, style, positives=POSITIVE_ORDER,
                negatives=NEGATIVE_ORDER):
    plants = []
    for offset in scheduled(stream, size, positive_every):
        data, span = plant(stream, stream.choice(positives), style, True)
        plants.append((offset, data, span))
    for offset in scheduled(stream, size, negative_every):
        data, span = plant(stream, stream.choice(negatives), style, False)
        plants.append((offset, data, span))
    # Keep the plants within the file: large plants only fit in large files.
    while plants and sum(len(item[1]) + 1 for item in plants) > size // 2:
        plants.pop()
    return plants


class ShapeContext:
    def __init__(self, root, identity, seed):
        self.root = pathlib.Path(root)
        self.identity = identity
        self.seed = seed
        self.labels = []
        self.files = 0
        self.bytes = 0
        self.executables = []

    def write(self, relative, data, mode=0o644):
        write_file(self.root, relative, data, mode)
        if mode & 0o100:
            self.executables.append(relative)
        self.files += 1
        self.bytes += len(data)


def shape_keyword_dense(context, total):
    stream = Stream(context.seed + ':files')
    pools = {style: cached_pool('keyword:' + style, lambda stream, style=style: pool_keyword(stream, style))
             for style in ('env', 'yaml', 'ini', 'properties', 'txt', 'toml')}
    short = [line for line in pools['ini'] if len(line) <= 48] or [b'\n']
    styles = tuple(pools)
    for index, size in enumerate(plan_files(stream, total, 16 * 1024, 256 * 1024)):
        style = styles[index % len(styles)]
        path = 'config/group-%03d/service-%05d.%s' % (index // 100, index, style)
        builder = Builder(context.identity, path)
        plants = make_plants(stream, size, 48 * 1024, 12 * 1024, style)
        fill_lines(builder, stream, size, pools[style], short, plants)
        context.write(path, builder.finish(context.labels))


LOCK_FILES = (('json', 'package-lock.json', 'lock'), ('yarn', 'yarn.lock', 'yaml'),
              ('gosum', 'go.sum', 'txt'), ('sums', 'SHA256SUMS', 'txt'), ('cargo', 'Cargo.lock', 'toml'),
              ('csv', 'ids.csv', 'txt'))


def shape_entropy_negatives(context, total):
    stream = Stream(context.seed + ':files')
    pools = {kind: cached_pool('lock:' + kind, lambda stream, kind=kind: pool_lock(stream, kind))
             for kind, _, _ in LOCK_FILES}
    short = [b'\n']
    negatives = ('sha256-hex', 'sha1-hex', 'uuid', 'sri-integrity', 'go-sum', 'base64-data', 'example-aws-key')
    positives = ('npm-token', 'credential-uri', 'github-pat')
    for index, size in enumerate(plan_files(stream, total, 64 * 1024, 1024 * 1024)):
        kind, name, style = LOCK_FILES[index % len(LOCK_FILES)]
        path = 'deps/group-%03d/%05d-%s' % (index // 100, index, name)
        builder = Builder(context.identity, path)
        plants = make_plants(stream, size, 256 * 1024, 8 * 1024, style, positives, negatives)
        fill_lines(builder, stream, size, pools[kind], short, plants)
        context.write(path, builder.finish(context.labels))


def source_file(context, stream, pools, shorts, index, size):
    language = LANGUAGES[stream.below(len(LANGUAGES))]
    path = 'src/%s/pkg-%03d/file-%05d.%s' % (language, index // 64, index, language)
    builder = Builder(context.identity, path)
    plants = make_plants(stream, size, 64 * 1024, 16 * 1024, language)
    fill_lines(builder, stream, size, pools[language], shorts[language], plants)
    context.write(path, builder.finish(context.labels), 0o755 if language == 'sh' else 0o644)


def code_pools():
    pools = {language: cached_pool('code:' + language, lambda stream, language=language: pool_code(stream, language))
             for language in LANGUAGES}
    shorts = {language: [line for line in pool if len(line) <= 40] or [b'\n'] for language, pool in pools.items()}
    return pools, shorts


def shape_mixed_source(context, total):
    stream = Stream(context.seed + ':files')
    pools, shorts = code_pools()
    for index, size in enumerate(plan_files(stream, total, 1024, 48 * 1024)):
        source_file(context, stream, pools, shorts, index, size)


def shape_minified(context, total):
    stream = Stream(context.seed + ':files')
    pools = {False: cached_pool('min:js', lambda stream: pool_minified(stream, False)),
             True: cached_pool('min:css', lambda stream: pool_minified(stream, True))}
    shorts = {False: [b';'], True: [b' ']}
    for index, size in enumerate(plan_files(stream, total, 128 * 1024, 2 * 1024 * 1024)):
        css = index % 10 >= 7
        path = 'assets/chunk-%04d.min.%s' % (index, 'css' if css else 'js')
        builder = Builder(context.identity, path)
        style = 'mincss' if css else 'minjs'
        plants = make_plants(stream, size, 512 * 1024, 64 * 1024, style,
                             negatives=('base64-data', 'sri-integrity', 'uuid', 'sha256-hex'))
        fill_lines(builder, stream, size, pools[css], shorts[css], plants, newline=False)
        context.write(path, builder.finish(context.labels))


def png_bytes(seed, size):
    # Chunk structure with valid CRCs; the image data is not decodable.
    def chunk(kind, payload):
        return struct_u32(len(payload)) + kind + payload + struct_u32(zlib.crc32(kind + payload) & 0xffffffff)
    header = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct_u32(256) + struct_u32(256) + b'\x08\x06\x00\x00\x00')
    tail = chunk(b'IEND', b'')
    payload = size - len(header) - len(tail) - 12
    if payload < 0:
        return hashlib.shake_256(seed.encode('utf-8')).digest(size)
    return header + chunk(b'IDAT', hashlib.shake_256(seed.encode('utf-8')).digest(payload)) + tail


def struct_u32(value):
    return value.to_bytes(4, 'big')


def zip_bytes(stream, seed, size):
    # A stored (uncompressed) archive of exactly `size` bytes. The archive
    # comment absorbs the final gap, so the size never depends on zlib.
    buffer = io.BytesIO()
    archive = zipfile.ZipFile(buffer, 'w', zipfile.ZIP_STORED)
    central = 22
    index = 0
    while True:
        name = 'com/example/%s/Class%04d.class' % (stream.choice(WORDS), index)
        length = min(stream.between(512, 8192), size // 4)
        entry = 30 + len(name) + length
        if buffer.tell() + entry + central + 46 + len(name) > size:
            break
        info = zipfile.ZipInfo(name, date_time=(2000, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.external_attr = 0o100644 << 16
        archive.writestr(info, b'\xca\xfe\xba\xbe' + hashlib.shake_256(
            ('%s:%d' % (seed, index)).encode('utf-8')).digest(length - 4))
        central += 46 + len(name)
        index += 1
    gap = size - buffer.tell() - central
    if gap < 0 or gap > 65535:
        fail('cannot size a stored archive to %d bytes' % size)
    archive.comment = b' ' * gap
    archive.close()
    data = buffer.getvalue()
    if len(data) != size:
        fail('stored archive has %d bytes, expected %d' % (len(data), size))
    return data


def shape_binary_mix(context, total):
    stream = Stream(context.seed + ':files')
    pools, shorts = code_pools()
    remaining = total
    index = 0
    while remaining:
        roll = stream.below(10)
        if roll < 4:
            size = min(remaining, stream.between(4 * 1024, 48 * 1024))
            if remaining - size < 4096:
                size = remaining
            source_file(context, stream, pools, shorts, index, size)
        else:
            size = min(remaining, stream.between(16 * 1024, 2 * 1024 * 1024))
            if remaining - size < 4096:
                size = remaining
            seed = '%s:binary:%d' % (context.seed, index)
            if roll < 6:
                path = 'static/img-%05d.png' % index
                data = png_bytes(seed, size)
            elif roll < 8:
                path = 'lib/native-%05d.so' % index
                data = bytearray(b'\x7fELF\x02\x01\x01' + hashlib.shake_256(seed.encode('utf-8')).digest(size - 7))
                for offset in range(4096, size, 4096):
                    data[offset:offset + 64] = b'\0' * min(64, size - offset)
                pending = []
                if size >= 256 * 1024:
                    # A credential embedded in a binary, as in a compiled string table.
                    text, start, end = POSITIVE_KINDS['github-pat'][2](stream)
                    value = b'\0' + text.encode('ascii') + b'\0'
                    offset = stream.between(1024, size - 1024 - len(value))
                    data[offset:offset + len(value)] = value
                    pending.append((offset + 1, offset + 1 + len(text)))
                data = bytes(data)
                for start, end in pending:
                    context.labels.append(make_label(context.identity, path, data, start, end, 'vcs-token',
                                                     'secret', kind='github-pat', in_binary=True))
            elif roll < 9 and size >= 4096:
                path = 'vendor/bundle-%05d.jar' % index
                data = zip_bytes(Stream(seed), seed, size)
            else:
                path = 'fonts/face-%05d.woff2' % index
                data = b'wOF2' + hashlib.shake_256(seed.encode('utf-8')).digest(size - 4)
            if len(data) != size:
                fail('binary file size mismatch for %s' % path)
            context.write(path, data)
        remaining -= size
        index += 1


SHAPES = {'keyword-dense': shape_keyword_dense, 'entropy-negatives': shape_entropy_negatives,
          'mixed-source': shape_mixed_source, 'minified': shape_minified, 'binary-mix': shape_binary_mix}


# Dense finding shapes after Kingfisher's dense findings benchmark, at 25 KB to
# 400 KB, doubling. Each workload is one file.

def dense_file(case, size, seed):
    stream = Stream(seed)
    identity = '%s-%dk' % (case, size // 1000)
    builder = Builder(identity, 'dense.txt')
    labels = []
    if case == 'dense-base64-uris':
        plain = bytearray()
        spans = []
        while len(plain) < size * 3 // 4:
            password = random_value(stream, ALNUM, 24).encode('ascii')
            entry = b'mysql://user:' + password + b'@db.invalid/test '
            spans.append((len(plain) + 13, len(plain) + 13 + len(password), password))
            plain += entry
        encoded = base64.b64encode(bytes(plain))
        data = encoded + b'\n'
        for start, end, password in spans:
            labels.append({'workload': identity, 'path': 'dense.txt', 'commit': None,
                           'start': 4 * (start // 3), 'end': 4 * ((end + 2) // 3), 'line': 1, 'end_line': 1,
                           'secret_sha256': sha256_bytes(password), 'category': 'credential-uri',
                           'label': 'secret', 'source': 'constructed', 'kind': 'credential-uri',
                           'encoding': 'base64', 'decoded_start': start, 'decoded_end': end})
        return identity, data, labels
    single = case in ('dense-github-pat-single-line', 'dense-generic-single-line')
    separator = b' ' if single else b'\n'
    while True:
        if case in ('dense-github-pat-lines', 'dense-github-pat-single-line'):
            text, start, end = POSITIVE_KINDS['github-pat'][2](stream)
            piece = text.encode('ascii')
            span = (start, end, 'vcs-token', 'secret', 'github-pat')
        elif case == 'dense-generic-single-line':
            value = random_value(stream, ALNUM, 40)
            piece = ("api_key = '%s'" % value).encode('ascii')
            span = (11, 11 + len(value), 'generic-password', 'secret', 'generic-assignment')
        else:
            identifier = random_value(stream, LOWER + DIGITS, 12, (LOWER, DIGITS), 0)
            value = random_value(stream, ALNUM, 32)
            first = ('PLANETSCALE_DATABASE_ID=%s' % identifier).encode('ascii')
            piece = first + b'\n' + ('PLANETSCALE_TOKEN=pscale_tkn_%s' % value).encode('ascii')
            offset = len(first) + 1 + len('PLANETSCALE_TOKEN=')
            span = (offset, offset + 11 + len(value), 'database-token', 'secret', 'planetscale-token')
        if builder.size + len(piece) + 2 > size:
            break
        builder.add_span(piece + separator, span)
    builder.add(b' ' * (size - builder.size - 1) + b'\n', 1)
    return identity, builder.finish(labels), labels


def long_line_file(seed, size, identity):
    stream = Stream(seed)
    pool = cached_pool('min:js', lambda stream: pool_minified(stream, False))
    builder = Builder(identity, 'bundle.min.js')
    plants = []
    for index in range(8):
        offset = (size - 4096) * index // 7
        data, span = plant(stream, POSITIVE_ORDER[index % 9], 'minjs', True)
        plants.append((offset, data, span))
    fill_lines(builder, stream, size, pool, [b';'], plants, newline=False)
    labels = []
    return builder.finish(labels), labels


# Git history shapes. Built with `git fast-import` and fixed dates, so commit
# IDs are the same on every run.

class FastImport:
    def __init__(self):
        self.parts = []
        self.mark = 0
        self.clock = 946684800
        self.secrets = []

    def commit(self, ref, message, parent=None, merges=(), changes=()):
        self.mark += 1
        self.clock += 60
        message = message.encode('utf-8')
        self.parts.append(('commit %s\nmark :%d\nauthor Synthetic Benchmark <benchmark@example.invalid> %d +0000\n'
                           'committer Synthetic Benchmark <benchmark@example.invalid> %d +0000\ndata %d\n'
                           % (ref, self.mark, self.clock, self.clock, len(message))).encode('ascii') + message + b'\n')
        if parent is not None:
            self.parts.append(b'from :%d\n' % parent)
        for merge in merges:
            self.parts.append(b'merge :%d\n' % merge)
        for change in changes:
            if change[0] == 'M':
                _, path, data = change[:3]
                self.parts.append(('M 100644 inline %s\ndata %d\n' % (path, len(data))).encode('utf-8') + data + b'\n')
                for start, end, category, label, kind, extra in (change[3] if len(change) > 3 else ()):
                    self.secrets.append((self.mark, path, data, start, end, category, label, kind, extra))
            elif change[0] == 'D':
                self.parts.append(('D %s\n' % change[1]).encode('utf-8'))
            elif change[0] == 'R':
                self.parts.append(('R %s %s\n' % (change[1], change[2])).encode('utf-8'))
        return self.mark

    def run(self, git, repository, environment, control):
        stream_path = pathlib.Path(control) / 'import.fi'
        marks_path = pathlib.Path(control) / 'marks.txt'
        stream_path.write_bytes(b''.join(self.parts) + b'done\n')
        with open(stream_path, 'rb') as stdin:
            git_run(git, repository, environment, ['fast-import', '--quiet', '--date-format=raw',
                                                   '--export-marks=' + str(marks_path)], stdin=stdin)
        marks = {}
        for line in marks_path.read_text(encoding='ascii').splitlines():
            mark, oid = line.split()
            marks[int(mark[1:])] = oid
        stream_path.unlink()
        marks_path.unlink()
        return marks


def secret_line(stream, kind, style='env'):
    data, span = plant(stream, kind, style, True)
    return data, span


def git_text_file(stream, lines, plants=()):
    # `plants` maps a line index to (data, span). Returns bytes and spans.
    out = bytearray()
    spans = []
    for index in range(lines):
        if index in plants:
            data, (start, end, category, label, kind) = plants[index]
            spans.append((len(out) + start, len(out) + end, category, label, kind, {}))
            out += data + b'\n'
        else:
            out += ('%s %05d %s\n' % (stream.choice(WORDS), index, prose(stream, stream.between(1, 9)))).encode('ascii')
    return bytes(out), spans


def git_shape(name, importer, stream, scale):
    full = scale == 'full'
    if name == 'git-many-branches':
        count, trunk = (1000, 50) if full else (12, 5)
        main = []
        parent = None
        for index in range(trunk):
            plants = {1: secret_line(stream, POSITIVE_ORDER[index % 9])} if index % 10 == 3 else {}
            data, spans = git_text_file(stream, 4, plants)
            parent = importer.commit('refs/heads/main', 'main %d' % index, parent,
                                     changes=[('M', 'main.txt', data, spans)])
            main.append(parent)
        for index in range(count):
            ref = 'refs/heads/feature/b-%04d' % index
            path = 'branches/b-%04d.txt' % index
            data, spans = git_text_file(stream, 3)
            tip = importer.commit(ref, 'branch %d start' % index, main[index % trunk], changes=[('M', path, data, spans)])
            plants = {2: secret_line(stream, POSITIVE_ORDER[index % 9])} if index % 50 == 7 else {}
            data, spans = git_text_file(stream, 4, plants)
            importer.commit(ref, 'branch %d update' % index, tip, changes=[('M', path, data, spans)])
        return {'branches': count + 1, 'head_reaches_all_commits': False}
    if name == 'git-merges':
        count = 200 if full else 12
        data, spans = git_text_file(stream, 3)
        main = importer.commit('refs/heads/main', 'root', changes=[('M', 'README.txt', data, spans)])
        for index in range(count):
            ref = 'refs/heads/topic/m-%03d' % index
            path = 'topics/m-%03d.txt' % index
            data, spans = git_text_file(stream, 3)
            tip = importer.commit(ref, 'topic %d start' % index, main, changes=[('M', path, data, spans)])
            plants = {1: secret_line(stream, POSITIVE_ORDER[index % 9])} if index % 20 == 5 else {}
            final, spans = git_text_file(stream, 4, plants)
            tip = importer.commit(ref, 'topic %d update' % index, tip, changes=[('M', path, final, spans)])
            changes = [('M', path, final, ())]
            if index % 20 == 10:
                # A change made only by the merge commit (an "evil merge").
                extra, spans = git_text_file(stream, 3, {1: secret_line(stream, POSITIVE_ORDER[(index + 4) % 9])})
                spans = [span[:5] + ({'introduced_by': 'merge'},) for span in spans]
                changes.append(('M', 'merges/m-%03d.txt' % index, extra, spans))
            main = importer.commit('refs/heads/main', 'merge topic %d' % index, main, merges=(tip,), changes=changes)
        return {'merges': count, 'head_reaches_all_commits': True}
    if name == 'git-huge-hunk':
        lines = 32768 if full else 64
        data, spans = git_text_file(stream, lines)
        first = importer.commit('refs/heads/main', 'add table', changes=[('M', 'data/table.txt', data, spans)])
        plants = {index * lines // 8 + 3: secret_line(stream, POSITIVE_ORDER[index % 9]) for index in range(8)}
        data, spans = git_text_file(stream, lines, plants)
        importer.commit('refs/heads/main', 'replace table', first, changes=[('M', 'data/table.txt', data, spans)])
        return {'hunk_lines_removed': lines, 'hunk_lines_added': lines, 'head_reaches_all_commits': True}
    if name == 'git-many-small-files':
        count = 10000 if full else 20
        changes = []
        for index in range(count):
            data, spans = git_text_file(stream, 2)
            changes.append(('M', 'small/%02d/f-%05d.txt' % (index // 1000, index), data, spans))
        first = importer.commit('refs/heads/main', 'add files', changes=changes)
        changes = []
        for index in range(count):
            plants = {1: secret_line(stream, POSITIVE_ORDER[index % 9])} if index % 500 == 11 else {}
            data, spans = git_text_file(stream, 2, plants)
            changes.append(('M', 'small/%02d/f-%05d.txt' % (index // 1000, index), data, spans))
        importer.commit('refs/heads/main', 'change every file', first, changes=changes)
        return {'changed_files': count, 'head_reaches_all_commits': True}
    if name == 'git-renames':
        count, modified = (100, 1000) if full else (10, 20)
        changes = []
        contents = {}
        for index in range(count):
            plants = {1: secret_line(stream, POSITIVE_ORDER[index % 9])} if index % 10 == 0 else {}
            data, spans = git_text_file(stream, 3, plants)
            contents[index] = data
            changes.append(('M', 'renames/a/file-%03d.txt' % index, data, spans))
        for index in range(modified):
            data, spans = git_text_file(stream, 2)
            changes.append(('M', 'renames/m/mod-%04d.txt' % index, data, spans))
        head = importer.commit('refs/heads/main', 'add files', changes=changes)
        head = importer.commit('refs/heads/main', 'pure renames', head, changes=[
            ('R', 'renames/a/file-%03d.txt' % index, 'renames/b/file-%03d.txt' % index) for index in range(count)])
        changes = []
        for index in range(count // 2):
            changes.append(('D', 'renames/b/file-%03d.txt' % index))
            plants = {0: secret_line(stream, POSITIVE_ORDER[(index + 2) % 9])} if index % 10 == 5 else {}
            line, spans = git_text_file(stream, 1, plants)
            data = contents[index] + line
            spans = [(start + len(contents[index]), end + len(contents[index]), *rest) for start, end, *rest in spans]
            changes.append(('M', 'renames/c/file-%03d.txt' % index, data, spans))
        head = importer.commit('refs/heads/main', 'rename and modify', head, changes=changes)
        changes = [('R', 'renames/b/file-%03d.txt' % (count - 1), 'renames/d/file-%03d.txt' % (count - 1))]
        for index in range(modified):
            data, spans = git_text_file(stream, 2)
            changes.append(('M', 'renames/m/mod-%04d.txt' % index, data, spans))
        importer.commit('refs/heads/main', 'one rename among many modifications', head, changes=changes)
        return {'renamed_files': count, 'modified_files': modified, 'head_reaches_all_commits': True}
    fail('unknown Git shape %s' % name)


def generate_git_shape(root, git, identity, scale, seed):
    repository = fresh_directory(pathlib.Path(root) / 'synthetic' / identity)
    control = fresh_directory(pathlib.Path(root) / ('.control-' + identity))
    environment = git_environment(control / 'home')
    git_run(git, None, environment, ['init', '--quiet', '--object-format=sha1', str(repository)])
    importer = FastImport()
    details = git_shape(identity, importer, Stream(seed), scale)
    marks = importer.run(git, repository, environment, control)
    git_run(git, repository, environment, ['reset', '--hard', '--quiet', 'refs/heads/main'])
    git_run(git, repository, environment, ['gc', '--quiet', '--prune=now'])
    head_commits = set(git_text(git, repository, environment, ['rev-list', 'HEAD']).split())
    labels = []
    for mark, path, data, start, end, category, label, kind, extra in importer.secrets:
        commit = marks[mark]
        record = make_label(identity, path, data, start, end, category, label, commit=commit, kind=kind,
                            reachable_from_head=commit in head_commits)
        record.update(extra)
        labels.append(record)
    remove_tree(control)
    details['commits'] = len(marks)
    return labels, details


# Workload catalog. The manifest is generated from this list, so ids, seeds
# and parameters are defined in one place.

def synthetic_catalog():
    entries = []
    for identity in TUNED_IDS:
        entries.append({'id': identity, 'generator': COMPARISON_FIXTURE_VERSION, 'tuned': True})
    for shape in MAIN_SHAPES:
        for size in SIZE_SERIES:
            entries.append({'id': '%s-%dmib' % (shape, size), 'generator': SYNTHETIC_VERSION, 'tuned': False,
                            'shape': shape, 'params': {'bytes': size * MIB}})
    for case in DENSE_CASES:
        for size in DENSE_SIZES:
            entries.append({'id': '%s-%dk' % (case, size // 1000), 'generator': SYNTHETIC_VERSION,
                            'tuned': False, 'shape': case, 'params': {'bytes': size}})
    entries.append({'id': 'long-line-16mib', 'generator': SYNTHETIC_VERSION, 'tuned': False,
                    'shape': 'long-line', 'params': {'bytes': 16 * MIB}})
    entries.append({'id': 'base64-uris-4mib', 'generator': SYNTHETIC_VERSION, 'tuned': False,
                    'shape': 'dense-base64-uris', 'params': {'bytes': 4 * MIB}})
    for shape in GIT_SHAPES:
        entries.append({'id': shape, 'generator': SYNTHETIC_VERSION, 'tuned': False, 'shape': shape,
                        'params': {}})
    for entry in entries:
        entry['seed'] = (COMPARISON_FIXTURE_SEED if entry['generator'] == COMPARISON_FIXTURE_VERSION
                         else '%s:%s' % (SYNTHETIC_SEED, entry['id']))
    return entries


def smoke_bytes(entry):
    # Smoke scale keeps every shape but shrinks it for self-tests.
    return {'bytes': min(entry['params']['bytes'], 48 * 1024 if entry['shape'] in MAIN_SHAPES else 64 * 1024)}


def generate_entry(root, git, entry, scale):
    identity = entry['id']
    target = pathlib.Path(root) / 'synthetic' / identity
    shape = entry['shape']
    params = entry['params'] if scale == 'full' else smoke_bytes(entry) if entry['params'] else {}
    seed = entry['seed'] + ('' if scale == 'full' else ':smoke')
    if shape in GIT_SHAPES:
        return generate_git_shape(root, git, identity, scale, seed)
    fresh_directory(target)
    context = ShapeContext(target, identity, seed)
    if shape in SHAPES:
        SHAPES[shape](context, params['bytes'])
        return context.labels, {'executable_paths': sorted(context.executables)}
    if shape in DENSE_CASES:
        _, data, labels = dense_file(shape, params['bytes'], seed)
        for record in labels:
            record['workload'] = identity
        context.write('dense.txt', data)
        return labels, {}
    if shape == 'long-line':
        data, labels = long_line_file(seed, params['bytes'], identity)
        context.write('bundle.min.js', data)
        return labels, {}
    fail('unknown shape %s' % shape)
