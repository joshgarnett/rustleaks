# File contexts for the constructed corpus: where values are placed and the
# realistic text around them. Filler is keyword-dense on purpose (key, token,
# secret, password) but never holds a credential value.


class Doc:
    """Accumulates file bytes and labeled spans with exact byte offsets."""

    def __init__(self, newline='\n'):
        self.newline = newline
        self.chunks = []
        self.size = 0
        self.spans = []  # (start, end, label, category)

    def add(self, text):
        data = text.encode('utf-8')
        self.chunks.append(data)
        self.size += len(data)

    def line(self, text=''):
        self.add(text + self.newline)

    def fragment(self, fragment):
        base = self.size
        for start, end, label, category in fragment.spans:
            self.spans.append((base + start, base + end, label, category))
        self.add(fragment.text)

    def data(self):
        return b''.join(self.chunks)


def transform(fragment, function):
    """Apply a text transform. Partial spans survive only unchanged text."""
    text = function(fragment.text)
    if text == fragment.text:
        return fragment
    spans = []
    for start, end, label, category in fragment.spans:
        if (start, end) != (0, len(fragment.text)):
            raise QualityError('a partial span cannot pass through a text transform')
        spans.append((0, len(text), label, category))
    return Fragment(text, spans)


def escape_newlines(text):
    return text.replace('\n', '\\n')


def style_name(words, style):
    if style == 'upper':
        return '_'.join(word.upper() for word in words)
    if style == 'snake':
        return '_'.join(words)
    if style == 'camel':
        return words[0] + ''.join(word.title() for word in words[1:])
    if style == 'pascal':
        return ''.join(word.title() for word in words)
    if style == 'dotted':
        return '.'.join(words)
    if style == 'kebab':
        return '-'.join(words)
    raise ValueError(style)


def header_name(words):
    return '-'.join(word.title() for word in words)


def timestamp(rng):
    return (f'2026-{rng.between(1, 12):02d}-{rng.between(1, 28):02d}T{rng.between(0, 23):02d}:'
            f'{rng.between(0, 59):02d}:{rng.between(0, 59):02d}.{rng.between(0, 999):03d}Z')


COMMENTS = (
    'Rotate the API key every 90 days and keep the old token for one hour.',
    'The password must come from the secret store in production.',
    'Token refresh happens in the background worker.',
    'Keep these settings in sync with the staging environment.',
    'Do not log the secret value; log only its key name.',
    'Café ordering service settings.',
    'Default timeouts are in seconds.',
    'Credentials below are loaded at start-up and cached.',
    'The signing key id is public; the key itself is not.',
    'See docs/operations.md for the rotation procedure.',
    'naïve retry policy, replace with exponential backoff',
    'Auth settings for the reporting job (日本語 locale enabled).',
)

FILLER = {
    'env': ('APP_ENV=production', 'LOG_LEVEL=info', 'PORT=8080', 'REGION=eu-west-1', 'FEATURE_FLAGS=search,exports',
            'TOKEN_TTL_SECONDS=3600', 'PASSWORD_MIN_LENGTH=12', 'SECRET_ROTATION_DAYS=90', 'WORKERS=4'),
    'yaml': ('  timeout: 30', '  retries: 3', '  region: eu-west-1', '  token_ttl: 3600', '  log_level: info',
             '  password_policy: strict', '  key_rotation_days: 90', '  enabled: true'),
    'properties': ('server.port=8080', 'spring.jpa.open-in-view=false', 'logging.level.root=INFO',
                   'auth.token.ttl=3600', 'security.password.min-length=12', 'cache.key.prefix=orders'),
    'ini': ('timeout = 30', 'retries = 3', 'token_ttl = 3600', 'password_policy = strict', 'log_level = info'),
    'toml': ('timeout = 30', 'retries = 3', 'token_ttl = 3600', 'password_min_length = 12', 'region = "eu-west-1"'),
    'python': ('import os', 'import logging', 'logger = logging.getLogger(__name__)',
               'TOKEN_TTL = 3600', 'def get_token(session):', '    return session.headers.get("Authorization")',
               'if not password:', '    raise ValueError("password is required")',
               'logger.info("token refreshed for user %s", user_id)', 'API_BASE_URL = "https://api.internal/v1"'),
    'javascript': ('const express = require("express");', 'const TOKEN_TTL = 3600;',
                   'function getToken(req) { return req.headers.authorization; }',
                   'if (!password) { throw new Error("password is required"); }',
                   'logger.info("api key loaded", { keyName: "primary" });', 'module.exports = config;'),
    'typescript': ('import { Config } from "./types";', 'export const TOKEN_TTL = 3600;',
                   'export function getToken(req: Request): string | null { return req.headers.get("authorization"); }',
                   'if (!password) { throw new Error("password is required"); }'),
    'go': ('import "os"', 'var tokenTTL = 3600', 'func getToken(r *http.Request) string { return r.Header.Get("Authorization") }',
           'if password == "" { return errors.New("password is required") }', 'log.Printf("api key loaded: %s", keyName)'),
    'java': ('    private static final int TOKEN_TTL = 3600;', '    private final TokenStore tokenStore;',
             '    private static final Logger log = LoggerFactory.getLogger(Settings.class);',
             '    public String token() { return tokenStore.current(); }',
             '    public void requirePassword(String password) { Objects.requireNonNull(password, "password is required"); }'),
    'ruby': ('require "json"', 'TOKEN_TTL = 3600', 'raise ArgumentError, "password is required" if password.nil?',
             'Rails.logger.info("api key loaded")'),
    'php': ("'timeout' => 30,", "'token_ttl' => 3600,", "'password_policy' => 'strict',", "'log_level' => 'info',"),
    'csharp': ('    private const int TokenTtl = 3600;', '    public static string KeyVaultName => "app-vault";',
               '    public static bool RequirePassword => true;',
               '    public static TimeSpan TokenLifetime => TimeSpan.FromHours(1);'),
    'rust': ('use std::env;', 'const TOKEN_TTL: u64 = 3600;',
             'let password = env::var("DB_PASSWORD").expect("password is required");'),
    'shell': ('set -euo pipefail', 'echo "loading api key from vault"', 'TOKEN_TTL=3600',
              'if [ -z "${PASSWORD:-}" ]; then echo "password is required" >&2; exit 1; fi'),
    'terraform': ('  region = "eu-west-1"', '  token_ttl = 3600', '  tags = { team = "platform" }'),
    'dockerfile': ('FROM debian:bookworm-slim', 'WORKDIR /app', 'COPY . .', 'RUN make build',
                   'EXPOSE 8080', 'USER app'),
    'batch': ('@echo off', 'setlocal', 'set LOG_LEVEL=info', 'set TOKEN_TTL=3600',
              'if "%PASSWORD%"=="" echo password is required & exit /b 1', 'call build.cmd'),
    'powershell': ('$ErrorActionPreference = "Stop"', '$TokenTtl = 3600',
                   'if (-not $env:DB_PASSWORD) { throw "password is required" }',
                   'Write-Host "loading api key from vault"'),
    'log': ('INFO  server listening on :8080', 'DEBUG cache miss for key orders:42', 'WARN  token expires in 300s',
            'INFO  password policy check passed for user 1042', 'INFO  api key rotation scheduled',
            'ERROR upstream returned 401 Unauthorized, refreshing token'),
}


def comment_lines(rng, prefix, count):
    return [prefix + rng.choice(COMMENTS) for _ in range(count)]


def filler_lines(rng, family, count):
    pool = FILLER[family]
    return [rng.choice(pool) for _ in range(count)]


class LineContext:
    """A context where each entry is one assignment line."""

    def __init__(self, name, paths, style, singles, comment, family, header=(), footer=(), indent='',
                 multiline=None, header_line=None, test_paths=None, newline='\n'):
        self.name = name
        self.paths = paths
        self.style = style
        self.singles = singles  # (prefix, suffix) templates with {name}
        self.comment = comment
        self.family = family
        self.header = header
        self.footer = footer
        self.indent = indent
        self.multiline = multiline  # (mode, prefix, suffix) or None
        self.header_line = header_line  # (prefix, suffix) for HTTP header entries
        self.test_paths = test_paths or ('tests/fixtures/',)
        self.newline = newline

    def render(self, rng, entries):
        doc = Doc(self.newline)
        for line in self.header:
            doc.line(line)
        if self.comment is not None:
            for line in comment_lines(rng, self.comment, rng.between(0, 2)):
                doc.line(line)
        for line in filler_lines(rng, self.family, rng.between(4, 20)):
            doc.line(self.indent + line.lstrip() if self.indent else line)
        for entry in entries:
            if self.comment is not None and rng.chance(1, 2):
                doc.line(self.indent + self.comment + rng.choice(COMMENTS))
            self.render_entry(rng, doc, entry)
            if rng.chance(1, 3):
                for line in filler_lines(rng, self.family, rng.between(1, 3)):
                    doc.line(self.indent + line.lstrip() if self.indent else line)
        for line in filler_lines(rng, self.family, rng.between(2, 16)):
            doc.line(self.indent + line.lstrip() if self.indent else line)
        for line in self.footer:
            doc.line(line)
        return doc

    def render_entry(self, rng, doc, entry):
        fragment = entry.fragment
        if entry.header:
            prefix, suffix = self.header_line
            doc.add(prefix.format(name=header_name(entry.name), ts=timestamp(rng)))
            doc.fragment(fragment)
            doc.line(suffix)
            return
        name = style_name(entry.name, self.style)
        if '\n' in fragment.text:
            mode, prefix, suffix = self.multiline
            if mode == 'escape':
                fragment = transform(fragment, escape_newlines)
            elif mode == 'indent':
                pad = self.indent + '  '
                fragment = transform(fragment, lambda text: text.replace('\n', '\n' + pad))
                prefix = prefix + pad
            doc.add(self.indent + prefix.format(name=name))
            doc.fragment(fragment)
            doc.line(suffix)
            return
        prefix, suffix = rng.choice(self.singles)
        doc.add(self.indent + prefix.format(name=name, ts=timestamp(rng)))
        doc.fragment(fragment)
        doc.line(suffix)


LINE_CONTEXTS = (
    LineContext('env', ('.env', '.env.production', 'deploy/{w}.env', 'config/{w}.env'), 'upper',
                (('{name}=', ''), ('{name}="', '"'), ('export {name}=', '')), '# ', 'env',
                multiline=('escape', '{name}="', '"')),
    LineContext('yaml', ('config/{w}.yaml', 'config/{w}.yml', 'helm/{w}/values.yaml'), 'snake',
                (('{name}: ', ''), ('{name}: "', '"'), ("{name}: '", "'")), '# ', 'yaml',
                header=('service:',), indent='  ', multiline=('indent', '{name}: |\n', '')),
    LineContext('compose', ('docker-compose.yml', 'deploy/compose.{w}.yml'), 'upper',
                (('- {name}=', ''),), '# ', 'env',
                header=('services:', '  app:', '    image: registry.internal/app:1.4.2', '    environment:'),
                indent='      '),
    LineContext('workflow', ('.github/workflows/{w}.yml',), 'upper', (('{name}: ', ''), ("{name}: '", "'")), '# ', 'env',
                header=('name: deploy', 'on: [push]', 'env:'), indent='  ',
                footer=('jobs:', '  deploy:', '    runs-on: ubuntu-24.04', '    steps:', '      - run: make deploy')),
    LineContext('properties', ('src/main/resources/application.properties', 'config/{w}.properties'), 'dotted',
                (('{name}=', ''),), '# ', 'properties'),
    LineContext('ini', ('config/{w}.ini', 'setup.cfg', 'config/{w}.cfg'), 'snake', (('{name} = ', ''),), '; ', 'ini',
                header=('[default]',)),
    LineContext('toml', ('config/{w}.toml',), 'snake', (('{name} = "', '"'),), '# ', 'toml', header=('[service]',)),
    LineContext('python', ('app/{w}.py', 'src/{w}/settings.py', 'scripts/{w}.py'), 'upper',
                (('{name} = "', '"'), ("{name} = '", "'"), ('settings["{name}"] = "', '"')), '# ', 'python',
                multiline=('raw', '{name} = """', '"""'), test_paths=('tests/', 'tests/fixtures/')),
    LineContext('javascript', ('src/{w}.js', 'lib/{w}.js', 'config/{w}.config.js'), 'camel',
                (('const {name} = "', '";'), ("const {name} = '", "';"), ('  {name}: "', '",')), '// ', 'javascript',
                multiline=('raw', 'const {name} = `', '`;'), test_paths=('test/', '__tests__/')),
    LineContext('typescript', ('src/{w}.ts', 'src/config/{w}.ts'), 'upper',
                (('export const {name} = "', '";'), ("export const {name}: string = '", "';")), '// ', 'typescript',
                test_paths=('test/', 'src/__tests__/')),
    LineContext('go', ('internal/{w}/config.go', 'cmd/{w}/main.go'), 'camel',
                (('const {name} = "', '"'), ('var {name} = "', '"')), '// ', 'go', header=('package main', ''),
                multiline=('raw', 'const {name} = `', '`'), test_paths=('internal/testdata/',)),
    LineContext('java', ('src/main/java/com/example/{W}Config.java',), 'upper',
                (('    private static final String {name} = "', '";'),), '    // ', 'java',
                header=('package com.example;', '', 'public final class Settings {'), footer=('}',),
                multiline=('raw', '    private static final String {name} = """\n', '""";'),
                test_paths=('src/test/java/com/example/',)),
    LineContext('ruby', ('config/initializers/{w}.rb', 'lib/{w}.rb'), 'snake',
                (("config.{name} = '", "'"), ('{name} = "', '"')), '# ', 'ruby', test_paths=('spec/fixtures/',)),
    LineContext('php', ('config/{w}.php',), 'snake', (("    '{name}' => '", "',"),), '    // ', 'php',
                header=('<?php', '', 'return ['), footer=('];',)),
    LineContext('csharp', ('src/{W}/Settings.cs',), 'pascal', (('    private const string {name} = "', '";'),),
                '    // ', 'csharp', header=('namespace App;', '', 'public static class Settings', '{'),
                footer=('}',), test_paths=('tests/{W}.Tests/',)),
    LineContext('rust', ('src/{w}.rs', 'src/config/{w}.rs'), 'upper', (('const {name}: &str = "', '";'),), '// ', 'rust',
                multiline=('raw', 'const {name}: &str = r#"', '"#;'), test_paths=('tests/',)),
    LineContext('shell', ('scripts/{w}.sh', 'deploy/{w}.sh'), 'upper',
                (('export {name}="', '"'), ('{name}=', '')), '# ', 'shell', header=('#!/usr/bin/env bash',),
                header_line=('curl -sS -H "{name}: ', '" https://api.internal/v1/status')),
    LineContext('batch', ('scripts/{w}.bat', 'tools/{w}.cmd'), 'upper', (('set {name}=', ''), ('set "{name}=', '"')),
                'REM ', 'batch', newline='\r\n'),
    LineContext('powershell', ('scripts/{w}.ps1', 'deploy/{w}.ps1'), 'upper', (('$env:{name} = "', '"'),
                                                                             ("${name} = '", "'")),
                '# ', 'powershell', newline='\r\n'),
    LineContext('terraform', ('infra/{w}.tf', 'infra/modules/{w}/main.tf'), 'snake', (('  {name} = "', '"'),), '  # ',
                'terraform', header=('provider "service" {',), footer=('}',)),
    LineContext('dockerfile', ('Dockerfile', 'docker/{w}.Dockerfile'), 'upper', (('ENV {name}=', ''), ('ARG {name}=', '')),
                '# ', 'dockerfile'),
    LineContext('log', ('logs/{w}.log', 'var/log/{w}.log'), 'snake',
                (('{ts} INFO  config loaded {name}=', ''), ('{ts} DEBUG settings {name}="', '"')), None, 'log',
                header_line=('{ts} DEBUG http.client > {name}: ', '')),
)


def render_markdown(rng, entries):
    doc = Doc()
    doc.line('# ' + rng.choice(('Deployment notes', 'Local setup', 'Service configuration', 'Runbook')))
    doc.line('')
    doc.line(rng.choice(COMMENTS))
    doc.line('')
    for entry in entries:
        doc.line(rng.choice(('Set the value before you start the service:', 'Example request:',
                             'The current configuration is:', 'Use this key for the integration:')))
        doc.line('')
        doc.line('```sh')
        if entry.header:
            doc.add('curl -H "' + header_name(entry.name) + ': ')
            doc.fragment(entry.fragment)
            doc.line('" https://api.internal/v1/me')
        elif '\n' in entry.fragment.text:
            doc.fragment(entry.fragment)
            doc.line('')
        else:
            doc.add(style_name(entry.name, 'upper') + '=')
            doc.fragment(entry.fragment)
            doc.line('')
        doc.line('```')
        doc.line('')
        doc.line(rng.choice(COMMENTS))
        doc.line('')
    return doc


JSON_FILLER = ('"timeout": 30', '"retries": 3', '"region": "eu-west-1"', '"enabled": true', '"tokenTtl": 3600',
               '"passwordPolicy": "strict"', '"keyRotationDays": 90')


def render_json(rng, entries, style=None, filler=True):
    doc = Doc()
    style = style or rng.choice(('snake', 'camel'))
    items = []
    for entry in entries:
        if filler:
            items.extend(('filler', rng.choice(JSON_FILLER)) for _ in range(rng.below(3)))
        items.append(('entry', entry))
    if filler:
        items.extend(('filler', rng.choice(JSON_FILLER)) for _ in range(rng.between(1, 3)))
    doc.line('{')
    for index, (kind, value) in enumerate(items):
        comma = ',' if index + 1 < len(items) else ''
        if kind == 'filler':
            doc.line('  ' + value + comma)
            continue
        doc.add('  "' + style_name(value.name, style) + '": "')
        doc.fragment(transform(value.fragment, escape_newlines))
        doc.line('"' + comma)
    doc.line('}')
    return doc


def render_service_account(rng, entries):
    return render_json(rng, entries, style='snake', filler=False)


def render_html(rng, entries):
    doc = Doc()
    doc.line('<!doctype html>')
    doc.line('<html lang="en">')
    doc.line('<head>')
    doc.line('  <meta charset="utf-8">')
    doc.line('  <title>' + rng.choice(('Checkout', 'Dashboard', 'Account')) + '</title>')
    for entry in entries:
        if entry.name == ('integrity',):
            library = rng.choice(('react', 'chart', 'search', 'analytics'))
            doc.add(f'  <script src="https://cdn.static.example/{library}-1.{rng.below(9)}.{rng.below(9)}.min.js" '
                    'integrity="')
            doc.fragment(entry.fragment)
            doc.line('" crossorigin="anonymous"></script>')
        else:
            doc.add('  <script>window.' + style_name(entry.name, 'camel') + ' = "')
            doc.fragment(entry.fragment)
            doc.line('";</script>')
    doc.line('</head>')
    doc.line('<body><main id="app"></main></body>')
    doc.line('</html>')
    return doc


def render_package_lock(rng, entries):
    doc = Doc()
    doc.line('{')
    doc.line('  "name": "web",')
    doc.line('  "lockfileVersion": 3,')
    doc.line('  "packages": {')
    for index, entry in enumerate(entries):
        name = rng.choice(('left-pad', 'lodash', 'chalk', 'ms', 'debug', 'semver')) + f'-{index}'
        doc.line(f'    "node_modules/{name}": {{')
        doc.line(f'      "version": "1.{rng.below(20)}.{rng.below(10)}",')
        doc.line(f'      "resolved": "https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz",')
        doc.add('      "integrity": "')
        doc.fragment(entry.fragment)
        doc.line('"')
        doc.line('    }' + (',' if index + 1 < len(entries) else ''))
    doc.line('  }')
    doc.line('}')
    return doc


def render_lines(rng, entries):
    doc = Doc()
    for entry in entries:
        doc.fragment(entry.fragment)
        doc.line('')
    return doc


def render_pem(rng, entries):
    doc = Doc()
    for entry in entries:
        doc.fragment(entry.fragment)
        doc.line('')
    return doc


def pem_path(entries):
    text = entries[0].fragment.text
    if text.startswith('ssh-'):
        return 'keys/{w}.pub'
    if 'CERTIFICATE' in text:
        return 'certs/{w}.crt'
    if 'PUBLIC' in text:
        return 'keys/{w}.pub.pem'
    if 'OPENSSH' in text:
        return 'keys/id_{w}'
    if 'PGP' in text:
        return 'keys/{w}.asc'
    return 'keys/{w}.key'


class SpecialContext:
    def __init__(self, name, paths, render, max_entries, test_paths=('tests/fixtures/',)):
        self.name = name
        self.paths = paths
        self.render = render
        self.max_entries = max_entries
        self.test_paths = test_paths


SPECIAL_CONTEXTS = (
    SpecialContext('markdown', ('docs/{w}.md', 'README.md', 'docs/runbooks/{w}.md'), render_markdown, 4),
    SpecialContext('json', ('config/{w}.json', 'appsettings.json', 'config/{w}.settings.json'), render_json, 6),
    SpecialContext('service-account', ('credentials/{w}-sa.json', 'deploy/{w}-service-account.json'),
                   render_service_account, 6),
    SpecialContext('html', ('public/{w}.html', 'templates/{w}.html'), render_html, 6),
    SpecialContext('package-lock', ('package-lock.json', 'web/package-lock.json'), render_package_lock, 12),
    SpecialContext('gosum', ('go.sum',), render_lines, 20),
    SpecialContext('sums', ('dist/SHA256SUMS', 'release/{w}.sha256'), render_lines, 8),
    SpecialContext('authorized-keys', ('deploy/authorized_keys', 'ops/{w}_authorized_keys'), render_lines, 6),
    SpecialContext('pem', (None,), render_pem, 1),
)

CONTEXTS = {context.name: context for context in LINE_CONTEXTS + SPECIAL_CONTEXTS}


def max_entries(context):
    return getattr(context, 'max_entries', 6)


def supports(context, entries):
    """Whether a context can hold these entries without changing their meaning."""
    for entry in entries:
        multiline = '\n' in entry.fragment.text
        if isinstance(context, LineContext):
            if entry.header and context.header_line is None:
                return False
            if multiline and context.multiline is None:
                return False
        elif context.name in ('json', 'html') and entry.header:
            return False
    return True


def render(context, rng, entries):
    return context.render(rng, entries)
