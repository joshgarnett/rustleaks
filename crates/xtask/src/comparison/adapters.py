# Comparison harness: tool adapters.
#
# An adapter turns lane settings into argv and environment for one tool family,
# records every flag that is not the tool's default with a reason, and parses
# the tool's report into findings with the same fields for every family.

RUSTLEAKS_PACKS = ('rustleaks-extra-v1', 'rustleaks-providers-v1', 'rustleaks-connections-v1')

# Synthetic shapes only. No capture groups, so the secret is the whole match
# for every tool. ASCII only, so every regex engine reads them the same way.
SHARED_RULES = [
    ('shared-github-pat', 'GitHub personal access token shape', 'ghp_[0-9A-Za-z]{36}', 'ghp_'),
    ('shared-aws-access-key-id', 'AWS access key ID shape', 'AKIA[A-Z2-7]{16}', 'akia'),
    ('shared-slack-bot-token', 'Slack bot token shape', 'xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}', 'xoxb-'),
    ('shared-stripe-live-key', 'Stripe live secret key shape', 'sk_live_[0-9A-Za-z]{24,64}', 'sk_live_'),
    ('shared-npm-token', 'npm access token shape', 'npm_[0-9A-Za-z]{36}', 'npm_'),
]

# Complete-profile limits that do not bind on the comparison workloads. They
# are not the documented example profile; only `workers` is a lane setting.
PROFILE_LIMITS = [
    ('version', 1), ('target_bytes', 1 << 32), ('operation_original_bytes', 1 << 42),
    ('operation_fragments', 1 << 32), ('operation_issues', 1 << 20), ('workers', None),
    ('queue_capacity', 1024), ('fragment_decoded_bytes', 1 << 32),
    ('operation_decoded_bytes', 1 << 42), ('fragment_work_units', 1 << 50),
    ('operation_work_units', 1 << 56), ('fragment_finding_records', 1 << 26),
    ('operation_finding_records', 1 << 30), ('fragment_finding_payload_bytes', 1 << 34),
    ('operation_finding_payload_bytes', 1 << 38), ('fragment_collected_spans', 1 << 30),
    ('operation_collected_spans', 1 << 34), ('fragment_normalization_bytes', 1 << 34),
    ('operation_normalization_bytes', 1 << 40), ('archive_entries', 1 << 24),
    ('archive_member_bytes', 1 << 32), ('archive_total_bytes', 1 << 36),
    ('archive_spool_bytes', 1 << 36), ('git_patch_bytes', 1 << 42), ('git_patch_lines', 1 << 34),
    ('git_stderr_bytes', 1 << 20), ('git_blob_bytes', 1 << 32), ('git_metadata_bytes', 1 << 30),
    ('git_path_bytes', 65536), ('git_files', 1 << 30), ('git_hunks', 1 << 32),
    ('scm_link_bytes', 1 << 22), ('operation_scm_link_bytes', 1 << 34),
]

ADAPTER_FACTS = {
    'rustleaks': {
        'defaults': {'threads': 'one detection thread per CPU the process may use; 1 worker in builds without --jobs',
                     'decode_depth': 5, 'archive_depth': 0, 'dedup': 'none'},
        'scope': [
            'dir mode skips .git folders, like Gitleaks.',
            'git mode runs the system git log -p and scans added lines of each patch.',
            'Files are read in pieces of about 100,000 bytes unless --complete-profile is set; with a profile each file is read whole.',
            'Native rule packs and --complete-profile exist only in builds after 0.1.0-alpha.9.',
            'The native packs are ported from rule sources that Kingfisher also bundles, most of them Betterleaks-derived, so pack results and Kingfisher results are not independent.',
            'Threads: builds with --jobs get --jobs N in every thread cell. In older builds, cells with 1 thread run the default runner with no profile, and cells with more threads use a generated profile.',
        ]},
    'gitleaks': {
        'defaults': {'threads': 'fixed 40 detection goroutines; Go uses GOMAXPROCS OS threads',
                     'decode_depth': 5, 'archive_depth': 0, 'dedup': 'none'},
        'scope': [
            'dir mode skips .git folders and files whose first bytes look like application/* MIME types.',
            'git mode runs the system git log -p -U0 and scans added lines; merge commit diffs are not scanned.',
            'Files are read in 100 KB pieces, extended by up to 25 KB to a blank line.',
            'Release binaries use go-re2 (WebAssembly RE2); go install and Homebrew builds use Go regexp.',
        ]},
    'betterleaks-v1': {
        'defaults': {'threads': 'Go runtime default (GOMAXPROCS = logical CPUs)',
                     'decode_depth': 5, 'archive_depth': 8, 'dedup': 'none'},
        'scope': [
            'Gitleaks-derived; dir mode skips .git folders.',
            'git mode runs the system git log -p.',
            'Archive depth 8 by default, where Gitleaks and Rustleaks use 0.',
            'Its AWS access key rule reports a key ID only with a nearby secret key. A lone key ID is not reported by design, so it is a policy difference, not a miss.',
        ]},
    'betterleaks-v2': {
        'defaults': {'threads': '-j 0 = 4 x GOMAXPROCS detection workers',
                     'decode_depth': 5, 'archive_depth': 8, 'dedup': 'none'},
        'scope': [
            'fs mode scans .git contents and binary files (no MIME skip).',
            'git mode reads history in process (go-git and own readers), HEAD and all non-note refs, without merge patches; blobs over 64 MiB are skipped.',
            'All confidence levels are reported by default.',
            'The harness fails a cell when a report shows a validation status other than none.',
            '-v means --validate in v2, so the harness never passes it; validation and analysis are set to false explicitly.',
        ]},
    'kingfisher': {
        'defaults': {'threads': '--jobs = logical CPUs',
                     'decode_depth': 'Base64 decoding on, no numeric depth',
                     'archive_depth': 2, 'dedup': 'on'},
        'scope': [
            'dir mode needs --git-history none to scan only the working tree; files under .git are still scanned.',
            'A checkout path scans the working tree and history together; the harness passes <target>/.git in git mode so only history is scanned.',
            'git mode scans each unique blob of all fetched objects once, not patches per commit.',
            'Archive extraction (depth 2) also covers SQLite, Python bytecode and PDF text.',
            'Reports medium confidence and above by default; findings are deduplicated by default.',
            'Compiled Vectorscan rules are cached under HOME; cold cells start without that cache.',
            'Its built-in catalog takes 472 of 503 rules from Betterleaks v2.0.0-rc.7.',
            'The harness counts git-mode findings without a commit and flags the cell, and fails a shared-rules cell when the number of rules applied is not the number of shared rules.',
        ]},
}


TARGET_CONFIG_FILES = ('.gitleaks.toml', '.gitleaksignore', '.rustleaks.toml', '.rustleaksignore',
                       '.betterleaks.toml', '.betterleaksignore')

# Files at the scan root that each tool loads by itself: (configuration, ignore).
AUTO_LOADED = {
    'rustleaks': (('.rustleaks.toml', '.gitleaks.toml'), ('.rustleaksignore', '.gitleaksignore')),
    'gitleaks': (('.gitleaks.toml',), ('.gitleaksignore',)),
    'betterleaks-v1': ((), ('.betterleaksignore', '.gitleaksignore')),
    'betterleaks-v2': ((), ()),
    'kingfisher': ((), ()),
}


def adapter_auto_loaded(adapter, present, shared_rules):
    """Files present at the scan root that this tool would load itself.

    An explicit --config in the shared rules lane replaces a configuration
    file, but ignore files are still loaded."""
    configs, ignores = AUTO_LOADED.get(adapter, ((), ()))
    return sorted(name for name in present if name in ignores or (name in configs and not shared_rules))


def adapter_name(tool):
    family = tool['family']
    if family == 'betterleaks':
        explicit = tool.get('adapter')
        if explicit in ('betterleaks-v1', 'betterleaks-v2'):
            return explicit
        return 'betterleaks-v1' if tool['version'].lstrip('v').startswith('1.') else 'betterleaks-v2'
    return family


def adapter_shared_rules_toml():
    lines = ['# Synthetic shared rules for the cross-tool comparison.',
             'title = "rustleaks comparison shared rules"', '']
    for rule_id, description, regex, keyword in SHARED_RULES:
        lines += ['[[rules]]', 'id = "%s"' % rule_id, 'description = "%s"' % description,
                  "regex = '''%s'''" % regex, 'keywords = ["%s"]' % keyword, '']
    return '\n'.join(lines)


def adapter_profile_text(workers):
    lines = ['# Generated by the comparison harness. Limits are set high so they do not bind.']
    for key, value in PROFILE_LIMITS:
        lines.append('%s=%d' % (key, workers if value is None else value))
    return '\n'.join(lines) + '\n'


def adapter_probe(tool, env):
    """Probe version text and optional capabilities. Probes never scan."""
    name = tool['adapter']
    binary = tool['binary']
    probe = {'capabilities': [], 'version_text': None, 'rule_count_probed': None}
    if name in ('rustleaks', 'gitleaks', 'betterleaks-v1'):
        code, out, err = run_text([binary, 'version'], env=env)
        probe['version_text'] = (out or err).strip()[:200] if code == 0 else None
        if name == 'rustleaks':
            code, out, err = run_text([binary, 'dir', '--help'], env=env)
            text = out + err
            if '--native-pack' in text:
                probe['capabilities'].append('native-packs')
            if '--complete-profile' in text:
                probe['capabilities'].append('complete-profile')
            if '--jobs' in text:
                probe['capabilities'].append('jobs')
    elif name == 'betterleaks-v2':
        code, out, err = run_text([binary, 'version'], env=env)
        probe['version_text'] = (out or err).strip()[:200] if code == 0 else None
        code, out, _ = run_text([binary, 'config', 'show', 'ids'], env=env)
        if code == 0:
            probe['rule_count_probed'] = len([line for line in out.splitlines() if line.strip()])
            probe['rule_count_source'] = 'betterleaks config show ids'
        code, out, _ = run_text([binary, 'config', 'hash'], env=env)
        if code == 0:
            probe['config_hash'] = out.strip()[:80]
    elif name == 'kingfisher':
        code, out, err = run_text([binary, '--version'], env=env)
        probe['version_text'] = (out or err).strip()[:200] if code == 0 else None
    return probe


def adapter_invocation(tool, mode, target, report, settings, inputs):
    """Build argv and extra environment for one sample.

    Returns a dict with argv, env (extra variables), flags (each with its
    reason and kind) and unsupported (None or the reason the cell cannot run).
    """
    name = tool['adapter']
    flags = []
    env = {}
    argv = [tool['binary']]

    def flag(values, reason, kind):
        argv.extend(values)
        flags.append({'flag': ' '.join(values), 'reason': reason, 'kind': kind})

    threads = settings.get('threads')
    decode = settings.get('decode')
    archive = settings.get('archive')
    shared = settings.get('rules') == 'shared'
    path_reason = 'scan target'
    if name in ('rustleaks', 'gitleaks', 'betterleaks-v1'):
        argv += [mode, target]
        flags.append({'flag': mode + ' <target>', 'reason': path_reason, 'kind': 'input'})
        git_range = settings.get('git_range') if mode == 'git' else None
        if git_range:
            options = git_range.get('git_log_options') or adapter_range_text(git_range)
            flag(['--log-opts=' + options], 'workload scan range', 'input')
        flag(['--no-banner'], 'keep the banner out of logs', 'output')
        flag(['--no-color'], 'plain logs', 'output')
        flag(['--report-format', 'json', '--report-path', report], 'write a JSON report to a private file', 'output')
        if name == 'betterleaks-v1':
            flag(['--validation=false'], 'keep live validation off', 'safety')
        if shared:
            flag(['--config', inputs['shared_rules']], 'shared rules lane: load only the common synthetic rules', 'lane')
        if decode is not None:
            flag(['--max-decode-depth', str(decode)], 'explicit decode depth for this lane', 'lane')
        if archive is not None:
            flag(['--max-archive-depth', str(archive)], 'explicit archive depth for this lane', 'lane')
        if name == 'rustleaks':
            capabilities = tool.get('probe', {}).get('capabilities', [])
            if settings.get('packs'):
                if 'native-packs' not in capabilities:
                    return {'unsupported': 'binary has no --native-pack option'}
                for pack in RUSTLEAKS_PACKS:
                    flag(['--native-pack', pack], 'Rustleaks 2x2 lane: packs on', 'lane')
            workers = None
            if settings.get('profile'):
                workers = threads or 1
            elif threads is not None and 'jobs' in capabilities:
                flag(['--jobs', str(threads)], 'threads lane: detection threads', 'lane')
            elif threads == 1:
                flags.append({'flag': '(none)', 'kind': 'lane',
                              'reason': 'threads=1: the default runner uses 1 worker, so no profile is used for any build'})
            elif threads is not None:
                if 'complete-profile' not in capabilities:
                    return {'unsupported': 'binary has no --complete-profile option, the only way to set more than 1 worker'}
                workers = threads
            if workers is not None:
                if 'complete-profile' not in capabilities:
                    return {'unsupported': 'binary has no --complete-profile option'}
                if workers > 64:
                    return {'unsupported': '--complete-profile allows at most 64 workers'}
                reason = ('Rustleaks 2x2 lane: complete profile on' if settings.get('profile')
                          else 'threads lane: workers=%d through a generated profile' % workers)
                flag(['--complete-profile', inputs['profile'](workers)],
                     reason + '; the profile also reads each file whole and sets high limits', 'lane')
        elif threads is not None:
            env['GOMAXPROCS'] = str(threads)
            flags.append({'flag': 'GOMAXPROCS=%d' % threads, 'kind': 'lane',
                          'reason': 'threads lane: bounds Go OS threads; the tool has no worker flag'})
    elif name == 'betterleaks-v2':
        argv += ['fs' if mode == 'dir' else 'git', target]
        flags.append({'flag': ('fs' if mode == 'dir' else 'git') + ' <target>', 'reason': path_reason, 'kind': 'input'})
        git_range = settings.get('git_range') if mode == 'git' else None
        if git_range:
            if not git_range.get('git_head'):
                return {'unsupported': 'the workload scan range is given only as git log options'}
            flag(['--revision', adapter_range_text(git_range)], 'workload scan range', 'input')
        flag(['-s'], 'do not print findings to the terminal', 'output')
        flag(['--no-banner'], 'keep the banner out of logs', 'output')
        flag(['--no-color'], 'plain logs', 'output')
        flag(['-o', report], 'write a JSON report to a private file', 'output')
        flag(['--validate=false', '--analyze=false'], 'keep live validation and analysis off', 'safety')
        if shared:
            flag(['--config', inputs['shared_rules']], 'shared rules lane: load only the common synthetic rules', 'lane')
        if decode is not None:
            flag(['--max-decode-depth=%d' % decode], 'explicit decode depth for this lane', 'lane')
        if archive is not None:
            flag(['--max-archive-depth=%d' % archive], 'explicit archive depth for this lane', 'lane')
        if threads is not None:
            env['GOMAXPROCS'] = str(threads)
            flags.append({'flag': 'GOMAXPROCS=%d' % threads, 'kind': 'lane',
                          'reason': 'threads lane: -j stays 0, which means 4 x GOMAXPROCS detection workers'})
    elif name == 'kingfisher':
        if mode == 'git':
            argv += ['scan', os.path.join(target, '.git')]
            flags.append({'flag': 'scan <target>/.git', 'kind': 'input',
                          'reason': 'git mode: history only, like the other tools; a checkout path also scans the working tree'})
        else:
            argv += ['scan', target]
            flags.append({'flag': 'scan <target>', 'reason': path_reason, 'kind': 'input'})
        flag(['--no-validate'], 'keep live validation off', 'safety')
        flag(['--no-update-check'], 'no network update check', 'safety')
        flag(['--format', 'json', '-o', report], 'write a JSON report to a private file', 'output')
        if mode == 'dir':
            flag(['--git-history', 'none'], 'dir mode: scan the working tree only, not Git history', 'input')
        git_range = settings.get('git_range') if mode == 'git' else None
        if git_range:
            if not git_range.get('git_head'):
                return {'unsupported': 'the workload scan range is given only as git log options'}
            flag(['--branch', git_range['git_head']], 'workload scan range', 'input')
            if git_range.get('git_base'):
                flag(['--since-commit', git_range['git_base']], 'workload scan range', 'input')
        if shared:
            flag(['--rules-path', inputs['shared_rules'], '--load-builtins=false'],
                 'shared rules lane: load only the common synthetic rules (Betterleaks TOML)', 'lane')
        if threads is not None:
            flag(['--jobs', str(threads)], 'threads lane: scan threads', 'lane')
        if decode is not None:
            if decode == 0:
                flag(['--no-base64'], 'decode depth 0: Base64 decoding off', 'lane')
            else:
                flags.append({'flag': '(default)', 'kind': 'lane',
                              'reason': 'decode depth %d requested; Kingfisher has no numeric depth, Base64 decoding stays on' % decode})
        if archive is not None:
            if archive == 0:
                flag(['--no-extract-archives'], 'archive depth 0: extraction off (also SQLite, bytecode and PDF)', 'lane')
            else:
                flag(['--extraction-depth', str(archive)], 'explicit archive depth for this lane', 'lane')
        if settings.get('dedup') is False:
            flag(['--no-dedup'], 'report every occurrence instead of deduplicated findings', 'lane')
    else:
        return {'unsupported': 'no adapter for %s' % name}
    return {'unsupported': None, 'argv': argv, 'env': env, 'flags': flags}


def adapter_range_text(git_range):
    head = git_range.get('git_head') or 'HEAD'
    return '%s..%s' % (git_range['git_base'], head) if git_range.get('git_base') else head


def adapter_leak_exit_code(tool):
    return 200 if tool['adapter'] == 'kingfisher' else 1


def adapter_strip(path, target):
    """Remove only an exact input prefix. Nothing else is changed."""
    if not isinstance(path, str):
        return ''
    for prefix in (target, os.path.realpath(target)):
        prefix = prefix.rstrip('/')
        if path == prefix:
            return os.path.basename(prefix)
        if path.startswith(prefix + '/'):
            return path[len(prefix) + 1:]
    return path


def adapter_json_documents(raw):
    text = raw.decode('utf-8', 'replace')
    decoder = json.JSONDecoder()
    position, documents = 0, []
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text):
            break
        value, position = decoder.raw_decode(text, position)
        documents.append(value)
    return documents


def adapter_finding(rule, path, commit, start_line, end_line, secret, decoded=False, columns=None):
    secret = secret if isinstance(secret, str) else ''
    start_line = start_line if isinstance(start_line, int) and start_line > 0 else 0
    if not isinstance(end_line, int) or end_line < start_line:
        end_line = start_line + secret.count('\n')
    return {'rule': rule if isinstance(rule, str) else '', 'path': path, 'commit': commit or '',
            'start_line': start_line, 'end_line': end_line, 'secret': secret,
            'secret_sha256': sha256_text(secret), 'secret_length': len(secret),
            'decoded': bool(decoded), 'columns': columns}


def adapter_parse(adapter, report, target, mode):
    """Parse a report into findings. Returns (findings, meta).

    Findings keep the secret text in memory for matching. Callers must never
    write it out; only its SHA-256 and length leave this process.
    """
    with open(report, 'rb') as handle:
        raw = handle.read()
    meta = {}
    findings = []
    if adapter in ('rustleaks', 'gitleaks', 'betterleaks-v1'):
        values = json.loads(raw.decode('utf-8')) if raw.strip() else []
        if not isinstance(values, list):
            raise ValueError('report is not a JSON list')
        for value in values:
            if not isinstance(value, dict):
                raise ValueError('finding is not an object')
            tags = value.get('Tags') or []
            findings.append(adapter_finding(
                value.get('RuleID'), adapter_strip(value.get('File'), target), value.get('Commit'),
                value.get('StartLine'), value.get('EndLine'), value.get('Secret'),
                any(isinstance(tag, str) and tag.startswith('decoded:') for tag in tags),
                [value.get('StartColumn'), value.get('EndColumn')]))
    elif adapter == 'betterleaks-v2':
        documents = adapter_json_documents(raw)
        for document in documents:
            rows = document if isinstance(document, list) else (
                document.get('findings') if isinstance(document, dict) and isinstance(document.get('findings'), list)
                else [document] if isinstance(document, dict) and 'rule_id' in document else [])
            if isinstance(document, dict) and isinstance(document.get('scan'), dict):
                scan = document['scan']
                meta['state'] = scan.get('state')
                meta['tool_bytes_scanned'] = scan.get('bytes_scanned')
                counts = scan.get('status_counts') or {}
                meta['validations'] = meta.get('validations', 0) + sum(
                    value for key, value in counts.items() if key != 'none' and isinstance(value, int))
            for value in rows:
                location = value.get('location') or {}
                match = value.get('match') or {}
                attributes = value.get('attributes') or {}
                validation = value.get('validation') or value.get('status')
                status = validation.get('status') if isinstance(validation, dict) else validation
                if status not in (None, '', 'none'):
                    meta['validations'] = meta.get('validations', 0) + 1
                findings.append(adapter_finding(
                    value.get('rule_id'), adapter_strip(location.get('path'), target), attributes.get('git.sha'),
                    location.get('start_line'), location.get('end_line'), match.get('value'),
                    bool(value.get('encodings')) or bool(value.get('decode_depth')),
                    [location.get('start_column'), location.get('end_column')]))
    elif adapter == 'kingfisher':
        for document in adapter_json_documents(raw):
            if not isinstance(document, dict):
                continue
            if isinstance(document.get('findings'), int):
                meta['terminal_findings'] = document['findings']
                meta['rules_applied'] = document.get('rules_applied')
                meta['tool_bytes_scanned'] = document.get('bytes_scanned')
                meta['validations'] = (document.get('successful_validations', 0) or 0) + (document.get('failed_validations', 0) or 0)
                continue
            summary = (document.get('metadata') or {}).get('summary') or {}
            if summary.get('rules_applied') is not None:
                meta['rules_applied'] = summary.get('rules_applied')
            for value in document.get('findings') or []:
                rule = (value.get('rule') or {}).get('id')
                finding = value.get('finding') or {}
                path = finding.get('path')
                commit = ''
                git = finding.get('git_metadata')
                if isinstance(git, dict):
                    commit = (git.get('commit') or {}).get('id') or ''
                    path = (git.get('file') or {}).get('path') or path
                snippet = finding.get('snippet')
                line = finding.get('line')
                if mode == 'git' and not commit:
                    meta['non_history_findings'] = meta.get('non_history_findings', 0) + 1
                findings.append(adapter_finding(
                    rule, adapter_strip(path, target), commit, line, None, snippet,
                    finding.get('encoding') not in (None, ''),
                    [finding.get('column_start'), finding.get('column_end')]))
    else:
        raise ValueError('no parser for adapter %s' % adapter)
    return findings, meta


def adapter_status_line(stderr_text):
    """Return the fields of the last Rustleaks complete-profile status line."""
    lines = [line for line in stderr_text.splitlines() if line.startswith('rustleaks_scan_status ')]
    if not lines:
        return None
    fields = {}
    for part in lines[-1].split()[1:]:
        key, _, value = part.partition('=')
        fields[key] = value
    return fields


def adapter_identity_digest(findings):
    rows = sorted((row['rule'], row['path'], row['commit'], row['start_line'], row['end_line'],
                   row['secret_sha256']) for row in findings)
    return sha256_bytes(json_bytes(rows))
