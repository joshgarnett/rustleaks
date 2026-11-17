# Credential formats and hard negatives for the constructed corpus.
#
# Every format here is written from the public vendor or standards
# description named in SOURCES, never from a scanner rule. Values are random
# and synthetic. A value that a format requires to carry a checksum gets a
# checksum computed from the published description. Labels come only from
# how a value is built.


class Fragment:
    """Text to place in a file, with labeled spans relative to the text."""

    def __init__(self, text, spans):
        self.text = text
        self.spans = spans  # list of (start, end, label, category)


class Entry:
    """One named value. `header` entries render as HTTP header lines."""

    def __init__(self, name, fragment, header=False):
        self.name = name  # tuple of lowercase words
        self.fragment = fragment
        self.header = header


def whole(text, label, category):
    return Fragment(text, [(0, len(text), label, category)])


def inner(prefix, value, suffix, label, category):
    text = prefix + value + suffix
    return Fragment(text, [(len(prefix), len(prefix) + len(value), label, category)])


def plain(text):
    return Fragment(text, [])


SECRET = 'secret'
NOT_SECRET = 'not-secret'

# Public format sources. Keys are kind identifiers; docs/dev/comparison-quality.md
# repeats this table for review.
SOURCES = {
    'aws-access-key': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes '
                      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
    'google-api-key': 'https://docs.cloud.google.com/docs/authentication/api-keys',
    'gcp-service-account-key': 'https://docs.cloud.google.com/iam/docs/keys-create-delete',
    'github-token': 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/'
                    'about-authentication-to-github#githubs-token-formats '
                    'https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/',
    'github-fine-grained-token': 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/'
                                 'about-authentication-to-github#githubs-token-formats',
    'gitlab-token': 'https://docs.gitlab.com/security/tokens/#token-prefixes '
                    'https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/cells/'
                    'routable_tokens/',
    'slack-bot-token': 'https://docs.slack.dev/authentication/tokens/',
    'slack-user-token': 'https://docs.slack.dev/authentication/tokens/',
    'slack-webhook-url': 'https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/',
    'discord-bot-token': 'https://docs.discord.com/developers/reference#authentication',
    'telegram-bot-token': 'https://core.telegram.org/bots/api#authorizing-your-bot',
    'stripe-secret-key': 'https://docs.stripe.com/keys',
    'database-uri': 'https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING-URIS '
                    'https://www.mongodb.com/docs/manual/reference/connection-string/ '
                    'https://www.rabbitmq.com/docs/uri-spec',
    'connection-string': 'https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string '
                         'https://learn.microsoft.com/en-us/dotnet/framework/data/adonet/connection-string-syntax '
                         'https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas '
                         'https://jdbc.postgresql.org/documentation/use/',
    'private-key': 'https://www.rfc-editor.org/rfc/rfc7468 https://www.rfc-editor.org/rfc/rfc4880#section-6 '
                   'https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key',
    'jwt': 'https://www.rfc-editor.org/rfc/rfc7519',
    'http-auth': 'https://www.rfc-editor.org/rfc/rfc7617 https://www.rfc-editor.org/rfc/rfc6750',
    'generic-api-key': 'none: a random value assigned to a credential name',
    'password': 'none: a random password assigned to a password name',
    'hash': 'https://git-scm.com/docs/gitglossary#def_object_name '
            'https://github.com/opencontainers/image-spec/blob/main/descriptor.md#digests',
    'go-sum-hash': 'https://go.dev/ref/mod#go-sum-files',
    'checksum-file': 'https://www.gnu.org/software/coreutils/manual/html_node/sha2-utilities.html',
    'uuid': 'https://www.rfc-editor.org/rfc/rfc9562',
    'subresource-integrity': 'https://www.w3.org/TR/SRI/',
    'config-integrity': 'https://www.w3.org/TR/SRI/',
    'package-lock-integrity': 'https://docs.npmjs.com/cli/configuring-npm/package-lock-json',
    'vendor-example-key': 'the vendor pages above that publish each example value',
    'placeholder': 'none: placeholder and reference shapes',
    'test-fixture': 'none: values marked fake in test paths',
    'ssh-public-key': 'https://www.rfc-editor.org/rfc/rfc4253#section-6.6',
    'pem-public-key': 'https://www.rfc-editor.org/rfc/rfc7468',
    'stripe-publishable-key': 'https://docs.stripe.com/keys',
    'identifier': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html',
    'high-entropy-data': 'https://www.rfc-editor.org/rfc/rfc2397',
    'near-miss': 'the formats above with a wrong length, alphabet or structure',
}


def base62_fixed(number, width):
    digits = []
    while number:
        number, remainder = divmod(number, 62)
        digits.append(BASE62[remainder])
    return ''.join(reversed(digits)).rjust(width, '0')


def snowflake(rng):
    return str(rng.between(10 ** 16, 10 ** 19 - 1))


# Credential value builders. Each returns the bare value text.

def aws_access_key_id(rng):
    return 'AKIA' + rng.chars(BASE32, 16)


def aws_secret_access_key(rng):
    return rng.chars(BASE64, 40)


def google_api_key(rng):
    return 'AIza' + rng.chars(BASE64URL, 35)


def github_classic(rng, prefix):
    # Prefix, 30 random Base62 characters, then a CRC32 of the random part in
    # 6 Base62 digits. GitHub does not publish the alphabet order or the
    # hashed portion; see docs/dev/comparison-quality.md.
    body = rng.chars(BASE62, 30)
    return prefix + body + base62_fixed(crc32(body.encode('ascii')), 6)


def github_fine_grained(rng):
    return 'github_pat_' + rng.chars(ALNUM, 22) + '_' + rng.chars(ALNUM, 59)


def base36_fixed(number, width):
    digits = []
    while number:
        number, remainder = divmod(number, 36)
        digits.append((DIGITS + LOWER)[remainder])
    return ''.join(reversed(digits)).rjust(width, '0')


def gitlab_legacy(rng):
    # Prefix from the GitLab token prefix table; the 20-character body is
    # taken from public examples, as GitLab does not publish it.
    return rng.choice(('glpat-', 'gldt-')) + rng.chars(ALNUM + '-_', 20)


def gitlab_routable(rng):
    # GitLab routable token design document: <prefix><base64url payload>.
    # <2-digit base36 version>.<2-digit base36 payload length><7-digit base36
    # CRC32 of everything before it>. The payload is random bytes, a
    # line-delimited routing payload and a one-byte routing payload length.
    routing = 'o:' + base36_fixed(rng.between(1, 10 ** 6), 1)
    if rng.chance(1, 2):
        routing += '\nu:' + base36_fixed(rng.between(1, 10 ** 8), 1)
    payload = b64url(rng.bytes(16) + routing.encode('ascii') + bytes([len(routing)]))
    token = 'glpat-' + payload + '.01.' + base36_fixed(len(payload), 2)
    return token + base36_fixed(crc32(token.encode('ascii')), 7)


def gitlab_token(rng):
    return gitlab_routable(rng) if rng.chance(1, 2) else gitlab_legacy(rng)


def slack_digits(rng):
    # Slack documents no length for the numeric groups. Its own examples use
    # three digits (xoxp-111-222-333-...), so lengths run from 3 to 14.
    return rng.chars('123456789', 1) + rng.chars(DIGITS, rng.between(2, 13))


def slack_bot(rng):
    return 'xoxb-' + slack_digits(rng) + '-' + slack_digits(rng) + '-' + rng.chars(ALNUM, 24)


def slack_user(rng):
    return 'xoxp-' + '-'.join(slack_digits(rng) for _ in range(3)) + '-' + rng.chars(HEX, 32)


def slack_webhook(rng):
    return 'https://hooks.slack.com/services/T' + rng.chars(UPPER + DIGITS, rng.between(8, 10)) + '/B' + \
        rng.chars(UPPER + DIGITS, rng.between(8, 10)) + '/' + rng.chars(ALNUM, 24)


def discord_bot(rng):
    return b64url(snowflake(rng).encode('ascii')) + '.' + rng.chars(BASE64URL, 6) + '.' + \
        rng.chars(BASE64URL, 27)


def telegram_bot(rng):
    return rng.choice('123456789') + rng.chars(DIGITS, rng.between(7, 9)) + ':' + \
        'AA' + rng.chars(BASE64URL, 33)


def stripe_secret(rng):
    return rng.choice(('sk_live_', 'rk_live_')) + rng.chars(ALNUM, rng.choice((24, 34, 99)))


def password_value(rng):
    if rng.chance(1, 3):
        words = ('copper', 'lantern', 'ridge', 'harbor', 'violet', 'summit', 'meadow',
                 'falcon', 'quartz', 'timber', 'orbit', 'saddle', 'glacier', 'ember')
        return rng.choice(words).title() + rng.chars(DIGITS, 2) + rng.choice('!%*+?') + \
            rng.choice(words).title() + '-' + rng.choice(words)
    return rng.chars(ALNUM + '!%*+-_.?=', rng.between(14, 24))


def generic_key_value(rng):
    shape = rng.below(5)
    if shape == 0:
        return rng.chars(ALNUM, 32)
    if shape == 1:
        return rng.chars(HEX, rng.choice((32, 40, 64)))
    if shape == 2:
        return b64(rng.bytes(32))
    if shape == 3:
        return rng.chars(ALNUM, 40)
    return rng.chars(BASE64URL, 43)


def jwt_value(rng):
    header = {'alg': 'HS256', 'typ': 'JWT'}
    issued = rng.between(1700000000, 1790000000)
    payload = {'sub': rng.chars(DIGITS, 10), 'iss': rng.choice(('auth.internal', 'login.app', 'sso.service')),
               'scope': rng.choice(('read write', 'admin', 'deploy')), 'iat': issued, 'exp': issued + 3600}
    signing_input = (b64url(json.dumps(header, separators=(',', ':')).encode()) + '.' +
                     b64url(json.dumps(payload, separators=(',', ':')).encode()))
    signature = hmac.new(rng.bytes(32), signing_input.encode('ascii'), hashlib.sha256).digest()
    return signing_input + '.' + b64url(signature)


# DER-shaped private and public key bodies. Only the outer structure follows
# the standards; key material is random bytes and is not a usable key.

def der_length(count):
    if count < 0x80:
        return bytes([count])
    if count < 0x100:
        return bytes([0x81, count])
    return bytes([0x82, count >> 8, count & 0xff])


def der_sequence(content):
    return b'\x30' + der_length(len(content)) + content


RSA_OID = bytes.fromhex('300d06092a864886f70d0101010500')


def pem_block(label, body, width=64):
    encoded = b64(body)
    lines = [encoded[index:index + width] for index in range(0, len(encoded), width)]
    return '-----BEGIN ' + label + '-----\n' + '\n'.join(lines) + '\n-----END ' + label + '-----'


def ssh_string(data):
    return len(data).to_bytes(4, 'big') + data


def rsa_private(rng):
    body = der_sequence(b'\x02\x01\x00' + b'\x02\x82\x01\x01\x00' + rng.bytes(256) + rng.bytes(rng.between(880, 920)))
    return pem_block('RSA ' + 'PRIVATE KEY', body)


def pkcs8_private(rng):
    inner_key = der_sequence(b'\x02\x01\x00' + b'\x02\x82\x01\x01\x00' + rng.bytes(256) + rng.bytes(900))
    body = der_sequence(b'\x02\x01\x00' + RSA_OID + b'\x04' + der_length(len(inner_key)) + inner_key)
    return pem_block('PRIVATE ' + 'KEY', body)


def ec_private(rng):
    body = der_sequence(b'\x02\x01\x01\x04\x20' + rng.bytes(32) +
                        bytes.fromhex('a00a06082a8648ce3d030107a144034200') + b'\x04' + rng.bytes(64))
    return pem_block('EC ' + 'PRIVATE KEY', body)


def openssh_private(rng):
    public = ssh_string(b'ssh-ed25519') + ssh_string(rng.bytes(32))
    check = rng.bytes(4)
    private = (check + check + ssh_string(b'ssh-ed25519') + ssh_string(rng.bytes(32)) +
               ssh_string(rng.bytes(64)) + ssh_string(b'deploy@build-host'))
    private += bytes(range(1, 1 + (8 - len(private) % 8) % 8))
    body = (b'openssh-key-v1\x00' + ssh_string(b'none') + ssh_string(b'none') + ssh_string(b'') +
            (1).to_bytes(4, 'big') + ssh_string(public) + ssh_string(private))
    return pem_block('OPENSSH ' + 'PRIVATE KEY', body, 70)


def crc24(data):
    # RFC 4880 section 6.1.
    value = 0xB704CE
    for byte in data:
        value ^= byte << 16
        for _ in range(8):
            value <<= 1
            if value & 0x1000000:
                value ^= 0x1864CFB
    return value & 0xFFFFFF


def pgp_private(rng):
    packet_body = b'\x04' + rng.bytes(4) + b'\x16' + rng.bytes(rng.between(90, 140))
    packet = b'\x95' + len(packet_body).to_bytes(2, 'big') + packet_body
    encoded = b64(packet)
    lines = [encoded[index:index + 64] for index in range(0, len(encoded), 64)]
    label = 'PGP ' + 'PRIVATE KEY BLOCK'
    return ('-----BEGIN ' + label + '-----\n\n' + '\n'.join(lines) + '\n=' +
            b64(crc24(packet).to_bytes(3, 'big')) + '\n-----END ' + label + '-----')


def private_key(rng):
    return rng.choice((rsa_private, pkcs8_private, ec_private, openssh_private, pgp_private))(rng)


def spki_public(rng):
    key = b'\x00' + der_sequence(b'\x02\x82\x01\x01\x00' + rng.bytes(256) + b'\x02\x03\x01\x00\x01')
    body = der_sequence(RSA_OID + b'\x03' + der_length(len(key)) + key)
    return pem_block('PUBLIC KEY', body)


def certificate(rng):
    body = der_sequence(der_sequence(b'\xa0\x03\x02\x01\x02\x02\x10' + rng.bytes(16) + rng.bytes(rng.between(700, 900))))
    return pem_block('CERTIFICATE', body)


def ssh_public_line(rng):
    if rng.chance(1, 2):
        blob = ssh_string(b'ssh-ed25519') + ssh_string(rng.bytes(32))
        kind = 'ssh-ed25519'
    else:
        blob = ssh_string(b'ssh-rsa') + ssh_string(b'\x01\x00\x01') + ssh_string(b'\x00' + rng.bytes(256))
        kind = 'ssh-rsa'
    user = rng.choice(('deploy', 'ci', 'ops', 'release'))
    return kind + ' ' + b64(blob) + ' ' + user + '@' + rng.choice(('build-01', 'bastion', 'laptop'))


# Negative value builders.

def uuid4(rng):
    raw = bytearray(rng.bytes(16))
    raw[6] = (raw[6] & 0x0f) | 0x40
    raw[8] = (raw[8] & 0x3f) | 0x80
    text = raw.hex()
    return f'{text[:8]}-{text[8:12]}-{text[12:16]}-{text[16:20]}-{text[20:]}'


def png_data_uri(rng):
    data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' + rng.bytes(rng.between(60, 160))
    return 'data:image/png;base64,' + b64(data)


# Published documentation examples, listed in docs/dev/comparison-quality.md.
# Each value is stored in six-character pieces, apart from its name, so that
# this source file does not itself hold a credential-shaped string.
VENDOR_EXAMPLE_NAMES = (
    'aws_access_key_id',
    'aws_secret_access_key',
    'azurite_account_key',
    'discord_bot_token',
    'telegram_bot_token',
    'slack_token',
    'google_api_key',
)
VENDOR_EXAMPLE_PIECES = (
    (
        'AKIAIO', 'SFODNN', '7EXAMP', 'LE',
    ),
    (
        'wJalrX', 'UtnFEM', 'I/K7MD', 'ENG/bP', 'xRfiCY', 'EXAMPL', 'EKEY',
    ),
    (
        'Eby8vd', 'M02xNO', 'cqFlqU', 'wJPLlm', 'EtlCDX', 'J1OUzF', 'T50uSR', 'Z6IFsu',
        'Fq2UVE', 'rCz4I6', 'tq/K1S', 'ZFPTOt', 'r/KBHB', 'eksoGM', 'Gw==',
    ),
    (
        'MTk4Nj', 'IyNDgz', 'NDcxOT', 'I1MjQ4', '.Cl2FM', 'Q.ZnCj', 'm1XVW7', 'vRze4b',
        '7Cq4se', '7kKWs',
    ),
    (
        '123456', ':ABC-D', 'EF1234', 'ghIkl-', 'zyx57W', '2v1u12', '3ew11',
    ),
    (
        'xoxp-1', '11-222', '-333-d', '6bc768', '406e5c', '2e6958', 'cfc399', 'b43800',
        '4',
    ),
    (
        'AIzaSy', 'DaGmWK', 'a4JsXZ', '-HjGw7', 'ISLn_3', 'namBGe', 'wQe',
    ),
)


def vendor_examples():
    return tuple(zip(VENDOR_EXAMPLE_NAMES, (''.join(pieces) for pieces in VENDOR_EXAMPLE_PIECES)))


PLACEHOLDERS = (
    '<YOUR_API_KEY>', '${API_TOKEN}', '{{ secrets.DEPLOY_TOKEN }}', 'changeme', 'REPLACE_ME',
    'your-api-key-here', 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', '********', '%(password)s',
    '<insert-token>', 'TODO', 'none', '${{ secrets.API_KEY }}', '$(cat /run/secrets/api_key)',
)


def placeholder_value(rng):
    shape = rng.below(5)
    if shape == 0:
        return 'ghp_' + 'x' * 36
    if shape == 1:
        return 'AKIA' + 'X' * 16
    if shape == 2:
        return 'sk_live_' + 'X' * 24
    return rng.choice(PLACEHOLDERS)


FIXTURE_VALUES = (
    'test-password', 'dummy-api-key', 'fake-token-0000', 'not-a-real-secret', 'testtesttest',
    'fixture-secret-value', 'example-password-123', 'dummy_token_for_tests', 'fake-client-secret',
)


def near_miss_value(rng):
    shape = rng.below(6)
    if shape == 0:
        return 'ghp_' + rng.chars(ALNUM, 35)
    if shape == 1:
        return 'AKIA' + rng.chars(LOWER + '0189', 16)
    if shape == 2:
        return 'xoxb-' + rng.chars(DIGITS, 12)
    if shape == 3:
        return 'glpat-' + rng.chars(ALNUM, 8)
    if shape == 4:
        return 'AIza' + rng.chars(BASE64URL, 20)
    return 'github_pat_' + rng.chars(ALNUM, 30)


CREDENTIAL_NAMES = (
    ('api', 'key'), ('apikey',), ('client', 'secret'), ('secret', 'key'), ('access', 'token'),
    ('auth', 'token'), ('app', 'secret'), ('signing', 'secret'), ('webhook', 'secret'),
    ('encryption', 'key'), ('service', 'token'), ('private', 'token'),
)
PASSWORD_NAMES = (
    ('password',), ('db', 'password'), ('admin', 'password'), ('smtp', 'password'), ('passwd',),
    ('redis', 'password'), ('ldap', 'bind', 'password'),
)
TOKEN_NAMES = (('token',), ('api', 'token'), ('secret',), ('api', 'key'), ('password',))
# Near misses sit under names that do not claim a credential, so a random
# value under a credential name is always a generic secret.
NEUTRAL_NAMES = (('build', 'ref'), ('release', 'tag'), ('sample', 'value'), ('doc', 'reference'),
                 ('legacy', 'id'), ('ticket', 'ref'), ('fixture', 'name'))


class Kind:
    def __init__(self, identifier, label, category, weight, contexts, build, scopes=('main',)):
        self.identifier = identifier
        self.label = label
        self.category = category
        self.weight = weight
        self.contexts = contexts
        self.build = build  # rng -> list of Entry
        self.scopes = scopes


ASSIGN = ('env', 'yaml', 'json', 'properties', 'ini', 'toml', 'python', 'javascript', 'typescript',
          'go', 'java', 'ruby', 'php', 'csharp', 'rust', 'shell', 'terraform', 'dockerfile',
          'markdown', 'log', 'compose', 'workflow', 'batch', 'powershell')
CODE = ('python', 'javascript', 'typescript', 'go', 'java', 'ruby', 'php', 'csharp', 'rust')
CONFIG = ('env', 'yaml', 'json', 'properties', 'ini', 'toml', 'compose', 'workflow', 'terraform')
MULTILINE = ('pem', 'env', 'json', 'yaml', 'python', 'go', 'javascript', 'java', 'rust')


def one(name, fragment, header=False):
    return [Entry(name, fragment, header)]


def build_aws(rng):
    entries = one(('aws', 'access', 'key', 'id'), whole(aws_access_key_id(rng), SECRET, 'cloud-key'))
    if rng.chance(7, 10):
        entries += one(('aws', 'secret', 'access', 'key'), whole(aws_secret_access_key(rng), SECRET, 'cloud-key'))
    return entries


def build_database_uri(rng):
    password = rng.chars(ALNUM, rng.between(16, 32))
    user = rng.choice(('app', 'svc_orders', 'reporting', 'admin', 'worker'))
    host = rng.choice(('db.internal', 'pg-primary.prod', '10.20.3.14', 'mysql.billing.svc'))
    shape = rng.below(5)
    if shape == 0:
        prefix, suffix, name = f'postgresql://{user}:', f'@{host}:5432/orders', ('database', 'url')
    elif shape == 1:
        prefix, suffix, name = f'mysql://{user}:', f'@{host}:3306/billing', ('mysql', 'url')
    elif shape == 2:
        cluster = 'cluster0.' + rng.chars(LOWER + DIGITS, 5) + '.mongodb.net'
        prefix, suffix, name = f'mongodb+srv://{user}:', f'@{cluster}/app?retryWrites=true', ('mongo', 'uri')
    elif shape == 3:
        prefix, suffix, name = 'redis://default:', f'@{host}:6379/0', ('redis', 'url')
    else:
        prefix, suffix, name = f'amqp://{user}:', f'@{host}:5672/jobs', ('broker', 'url')
    return one(name, inner(prefix, password, suffix, SECRET, 'database-uri'))


def build_connection_string(rng):
    shape = rng.below(4)
    if shape == 0:
        password = rng.chars(ALNUM, rng.between(16, 28))
        return one(('connection', 'string'), inner(
            'Server=tcp:sql-' + rng.chars(LOWER, 6) + '.database.windows.net,1433;Database=orders;User ID=app;Password=',
            password, ';Encrypt=True;', SECRET, 'connection-string'))
    if shape == 1:
        return one(('storage', 'connection', 'string'), inner(
            'DefaultEndpointsProtocol=https;AccountName=st' + rng.chars(LOWER + DIGITS, 10) + ';AccountKey=',
            b64(rng.bytes(64)), ';EndpointSuffix=core.windows.net', SECRET, 'connection-string'))
    if shape == 2:
        return one(('servicebus', 'connection', 'string'), inner(
            'Endpoint=sb://ns-' + rng.chars(LOWER, 8) +
            '.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=',
            b64(rng.bytes(32)), '', SECRET, 'connection-string'))
    password = rng.chars(ALNUM, rng.between(16, 28))
    return one(('jdbc', 'url'), inner('jdbc:postgresql://db.internal:5432/orders?user=app&password=',
                                      password, '&ssl=true', SECRET, 'connection-string'))


def build_service_account(rng):
    project = rng.choice(('orders', 'billing', 'ingest')) + '-' + rng.chars(DIGITS, 6)
    key = pkcs8_private(rng)
    key_id = rng.chars(HEX, 40)
    return [Entry(('type',), plain('service_account')),
            Entry(('project', 'id'), plain(project)),
            Entry(('private', 'key', 'id'), whole(key_id, NOT_SECRET, 'identifier')),
            Entry(('private', 'key'), whole(key + '\n', SECRET, 'private-key')),
            Entry(('client', 'email'), plain('deployer@' + project + '.iam.gserviceaccount.com')),
            Entry(('token', 'uri'), plain('https://oauth2.googleapis.com/token'))]


def build_http_auth(rng):
    if rng.chance(1, 2):
        user = rng.choice(('deploy', 'svc-reports', 'admin', 'jenkins'))
        secret = b64((user + ':' + rng.chars(ALNUM, rng.between(16, 24))).encode('ascii'))
        return one(('authorization',), inner('Basic ', secret, '', SECRET, 'http-auth'), header=True)
    return one(('authorization',), inner('Bearer ', rng.chars(BASE64URL, rng.between(32, 48)), '',
                                         SECRET, 'http-auth'), header=True)


def build_jwt(rng):
    if rng.chance(1, 3):
        return one(('authorization',), inner('Bearer ', jwt_value(rng), '', SECRET, 'jwt'), header=True)
    return one(rng.choice((('access', 'token'), ('id', 'token'), ('session', 'jwt'), ('auth', 'token'))),
               whole(jwt_value(rng), SECRET, 'jwt'))


def build_generic(rng):
    return one(rng.choice(CREDENTIAL_NAMES), whole(generic_key_value(rng), SECRET, 'generic-api-key'))


def build_password(rng):
    return one(rng.choice(PASSWORD_NAMES), whole(password_value(rng), SECRET, 'password'))


def build_example(rng):
    name, value = rng.choice(vendor_examples())
    return one(tuple(name.split('_')), whole(value, NOT_SECRET, 'example-key'))


def build_placeholder(rng):
    return one(rng.choice(TOKEN_NAMES + CREDENTIAL_NAMES[:4]), whole(placeholder_value(rng), NOT_SECRET, 'placeholder'))


def build_fixture(rng):
    return one(rng.choice(TOKEN_NAMES + PASSWORD_NAMES[:2]),
               whole(rng.choice(FIXTURE_VALUES), NOT_SECRET, 'test-fixture'))


def build_identifier(rng):
    shape = rng.below(4)
    if shape == 0:
        return one(('aws', 'account', 'id'), whole(rng.chars('123456789', 1) + rng.chars(DIGITS, 11),
                                                   NOT_SECRET, 'identifier'))
    if shape == 1:
        account = rng.chars('123456789', 1) + rng.chars(DIGITS, 11)
        if rng.chance(1, 2):
            arn = 'arn:aws:iam::' + account + ':role/deploy-' + rng.chars(LOWER, 6)
            return one(('role', 'arn'), whole(arn, NOT_SECRET, 'identifier'))
        arn = ('arn:aws:secretsmanager:eu-west-1:' + account + ':secret:db-password-' +
               rng.chars(ALNUM, 6))
        return one(rng.choice((('db', 'secret', 'arn'), ('api', 'key', 'secret', 'arn'))),
                   whole(arn, NOT_SECRET, 'identifier'))
    if shape == 2:
        return one(('google', 'client', 'id'), whole(
            rng.chars(DIGITS, 12) + '-' + rng.chars(LOWER + DIGITS, 32) + '.apps.googleusercontent.com',
            NOT_SECRET, 'identifier'))
    return one(('twilio', 'account', 'sid'), whole('AC' + rng.chars(HEX, 32), NOT_SECRET, 'identifier'))


def build_high_entropy(rng):
    shape = rng.below(3)
    if shape == 0:
        return one(rng.choice((('logo',), ('icon', 'data'), ('placeholder', 'image'))),
                   whole(png_data_uri(rng), NOT_SECRET, 'high-entropy'))
    if shape == 1:
        return one(rng.choice((('bundle',), ('main', 'script'), ('asset',))),
                   whole('/static/js/main.' + rng.chars(HEX, 20) + '.js', NOT_SECRET, 'high-entropy'))
    return one(rng.choice((('csp', 'nonce'), ('request', 'nonce'), ('cache', 'buster'))),
               whole(b64(rng.bytes(rng.choice((16, 24, 32)))), NOT_SECRET, 'high-entropy'))


def build_hash(rng):
    shape = rng.below(4)
    if shape == 0:
        return one(rng.choice((('commit',), ('git', 'sha'), ('revision',), ('source', 'version'),
                               ('secret', 'version'), ('token', 'commit'))),
                   whole(rng.chars(HEX, 40), NOT_SECRET, 'hash'))
    if shape == 1:
        return one(rng.choice((('sha256',), ('checksum',), ('artifact', 'digest'), ('fingerprint',),
                               ('token', 'sha256'), ('api', 'key', 'fingerprint'), ('secret', 'digest'))),
                   whole(rng.chars(HEX, 64), NOT_SECRET, 'hash'))
    if shape == 2:
        return one(rng.choice((('md5',), ('etag',), ('content', 'md5'), ('key', 'checksum'), ('token', 'md5'))),
                   whole(rng.chars(HEX, 32), NOT_SECRET, 'hash'))
    return one(('image',), inner('registry.internal/' + rng.choice(('api', 'worker', 'web')) + '@sha256:',
                                 rng.chars(HEX, 64), '', NOT_SECRET, 'hash'))


def build_uuid(rng):
    return one(rng.choice((('request', 'id'), ('trace', 'id'), ('tenant', 'id'), ('correlation', 'id'),
                           ('installation', 'id'), ('workspace', 'id'), ('id',), ('client', 'id'),
                           ('token', 'id'), ('api', 'key', 'id'), ('secret', 'version', 'id'))),
               whole(uuid4(rng), NOT_SECRET, 'uuid'))


def build_publishable(rng):
    return one(rng.choice((('stripe', 'publishable', 'key'), ('publishable', 'key'), ('stripe', 'pk'))),
               whole('pk_live_' + rng.chars(ALNUM, rng.choice((24, 34, 99))), NOT_SECRET, 'publishable-key'))


def build_near_miss(rng):
    return one(rng.choice(NEUTRAL_NAMES), whole(near_miss_value(rng), NOT_SECRET, 'near-miss'))


def build_go_sum(rng):
    module = rng.choice(('github.com/acme', 'golang.org/x', 'example.org/lib')) + '/' + rng.choice(
        ('net', 'text', 'sync', 'yaml', 'retry', 'metrics'))
    version = f'v{rng.below(3)}.{rng.below(20)}.{rng.below(10)}'
    suffix = rng.choice(('', '/go.mod'))
    return one(('module',), inner(f'{module} {version}{suffix} h1:', b64(rng.bytes(32)), '', NOT_SECRET, 'hash'))


def build_checksum_line(rng):
    name = rng.choice(('app', 'agent', 'cli')) + f'-1.{rng.below(9)}.{rng.below(9)}-' + rng.choice(
        ('linux-amd64.tar.gz', 'darwin-arm64.tar.gz', 'windows-amd64.zip'))
    return one(('file',), inner('', rng.chars(HEX, 64), '  ' + name, NOT_SECRET, 'hash'))


def build_sri(rng):
    size = rng.choice((32, 48, 64))
    algorithm = {32: 'sha256-', 48: 'sha384-', 64: 'sha512-'}[size]
    return one(('integrity',), whole(algorithm + b64(rng.bytes(size)), NOT_SECRET, 'integrity'))


def build_config_integrity(rng):
    size = rng.choice((32, 48, 64))
    algorithm = {32: 'sha256-', 48: 'sha384-', 64: 'sha512-'}[size]
    return one(rng.choice((('auth', 'sdk', 'integrity'), ('token', 'client', 'integrity'),
                           ('secrets', 'loader', 'integrity'), ('api', 'key', 'widget', 'integrity'))),
               whole(algorithm + b64(rng.bytes(size)), NOT_SECRET, 'integrity'))


def build_lock_integrity(rng):
    return one(('integrity',), whole('sha512-' + b64(rng.bytes(64)), NOT_SECRET, 'integrity'))


def build_ssh_public(rng):
    return one(('ssh', 'public', 'key'), whole(ssh_public_line(rng), NOT_SECRET, 'public-key'))


def build_pem_public(rng):
    value = spki_public(rng) if rng.chance(1, 2) else certificate(rng)
    return one(('public', 'key') if 'PUBLIC' in value else ('ca', 'certificate'),
               whole(value, NOT_SECRET, 'public-key'))


def single(name, builder, label, category):
    return lambda rng: one(name if isinstance(name[0], str) else rng.choice(name),
                           whole(builder(rng), label, category))


KINDS = (
    # Secrets.
    Kind('aws-access-key', SECRET, 'cloud-key', 40, ASSIGN, build_aws, ('main', 'test')),
    Kind('google-api-key', SECRET, 'cloud-key', 25,
         ASSIGN, single((('google', 'api', 'key'), ('gcp', 'api', 'key'), ('youtube', 'api', 'key')),
                        google_api_key, SECRET, 'cloud-key')),
    Kind('gcp-service-account-key', SECRET, 'private-key', 8, ('service-account',), build_service_account),
    Kind('github-token', SECRET, 'vcs-token', 40, ASSIGN,
         single((('github', 'token'), ('gh', 'token'), ('github', 'pat'), ('token',)),
                lambda rng: github_classic(rng, rng.choice(('ghp_', 'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_'))),
                SECRET, 'vcs-token'), ('main', 'test')),
    Kind('github-fine-grained-token', SECRET, 'vcs-token', 15, ASSIGN,
         single((('github', 'token'), ('gh', 'pat')), github_fine_grained, SECRET, 'vcs-token')),
    Kind('gitlab-token', SECRET, 'vcs-token', 25, ASSIGN,
         single((('gitlab', 'token'), ('ci', 'job', 'token'), ('gitlab', 'pat')), gitlab_token, SECRET, 'vcs-token')),
    Kind('slack-bot-token', SECRET, 'chat-token', 20, ASSIGN,
         single((('slack', 'bot', 'token'), ('slack', 'token')), slack_bot, SECRET, 'chat-token')),
    Kind('slack-user-token', SECRET, 'chat-token', 10, ASSIGN,
         single((('slack', 'user', 'token'), ('slack', 'token')), slack_user, SECRET, 'chat-token')),
    Kind('slack-webhook-url', SECRET, 'chat-token', 15, ASSIGN,
         single((('slack', 'webhook', 'url'), ('alerts', 'webhook')), slack_webhook, SECRET, 'chat-token')),
    Kind('discord-bot-token', SECRET, 'chat-token', 15, ASSIGN,
         single((('discord', 'bot', 'token'), ('discord', 'token')), discord_bot, SECRET, 'chat-token')),
    Kind('telegram-bot-token', SECRET, 'chat-token', 15, ASSIGN,
         single((('telegram', 'bot', 'token'), ('telegram', 'token')), telegram_bot, SECRET, 'chat-token')),
    Kind('stripe-secret-key', SECRET, 'payment-key', 25, ASSIGN,
         single((('stripe', 'secret', 'key'), ('stripe', 'api', 'key'), ('stripe', 'key')),
                stripe_secret, SECRET, 'payment-key')),
    Kind('database-uri', SECRET, 'database-uri', 40, ASSIGN, build_database_uri, ('main', 'test')),
    Kind('connection-string', SECRET, 'connection-string', 30, ASSIGN, build_connection_string),
    Kind('private-key', SECRET, 'private-key', 30, MULTILINE + ('markdown',),
         single((('private', 'key'), ('ssh', 'private', 'key'), ('tls', 'key'), ('signing', 'key')),
                private_key, SECRET, 'private-key')),
    Kind('jwt', SECRET, 'jwt', 30, ('log', 'shell', 'markdown') + CONFIG + CODE, build_jwt),
    Kind('http-auth', SECRET, 'http-auth', 25, ('log', 'shell', 'markdown'), build_http_auth),
    Kind('generic-api-key', SECRET, 'generic-api-key', 60, ASSIGN, build_generic, ('main', 'test')),
    Kind('password', SECRET, 'password', 50, ASSIGN, build_password, ('main', 'test')),
    # Hard negatives.
    Kind('hash', NOT_SECRET, 'hash', 50, ASSIGN, build_hash),
    Kind('go-sum-hash', NOT_SECRET, 'hash', 20, ('gosum',), build_go_sum),
    Kind('checksum-file', NOT_SECRET, 'hash', 15, ('sums',), build_checksum_line),
    Kind('uuid', NOT_SECRET, 'uuid', 40, ASSIGN, build_uuid),
    Kind('subresource-integrity', NOT_SECRET, 'integrity', 20, ('html',), build_sri),
    Kind('config-integrity', NOT_SECRET, 'integrity', 15, ('json', 'yaml', 'javascript', 'typescript'),
         build_config_integrity),
    Kind('package-lock-integrity', NOT_SECRET, 'integrity', 20, ('package-lock',), build_lock_integrity),
    Kind('vendor-example-key', NOT_SECRET, 'example-key', 35, CONFIG + CODE + ('markdown',), build_example),
    Kind('placeholder', NOT_SECRET, 'placeholder', 50, ASSIGN, build_placeholder),
    Kind('test-fixture', NOT_SECRET, 'test-fixture', 30, CONFIG + CODE, build_fixture, ('test',)),
    Kind('ssh-public-key', NOT_SECRET, 'public-key', 15, ('authorized-keys', 'pem', 'yaml', 'markdown'),
         build_ssh_public),
    Kind('pem-public-key', NOT_SECRET, 'public-key', 15, ('pem', 'yaml', 'markdown'), build_pem_public),
    Kind('stripe-publishable-key', NOT_SECRET, 'publishable-key', 20,
         ('javascript', 'typescript', 'env', 'yaml', 'json', 'html'), build_publishable),
    Kind('identifier', NOT_SECRET, 'identifier', 35, ASSIGN, build_identifier),
    Kind('high-entropy-data', NOT_SECRET, 'high-entropy', 30,
         ('json', 'javascript', 'typescript', 'yaml', 'python', 'go', 'log'), build_high_entropy),
    Kind('near-miss', NOT_SECRET, 'near-miss', 35, ASSIGN, build_near_miss),
)

CATEGORIES = tuple(sorted({kind.category for kind in KINDS}))
