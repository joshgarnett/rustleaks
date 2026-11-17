# Comparison harness: tools and workload manifests.

TOOL_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
WORKLOAD_FAMILIES = ('real-repo', 'labeled', 'fixtures-matrix', 'synthetic')


def manifest_load_tools(path):
    """Load and check a tools manifest. Every binary hash is verified."""
    data = read_json(path)
    if not isinstance(data, dict) or data.get('schema') != SCHEMA_TOOLS:
        raise HarnessError('%s: schema must be %s' % (path, SCHEMA_TOOLS))
    entries = data.get('tools')
    if not isinstance(entries, list) or not entries:
        raise HarnessError('%s: "tools" must be a non-empty list' % path)
    tools, seen = [], set()
    for index, entry in enumerate(entries):
        where = '%s: tools[%d]' % (path, index)
        if not isinstance(entry, dict):
            raise HarnessError(where + ' must be an object')
        for key in ('id', 'family', 'version', 'binary', 'sha256', 'build'):
            if not isinstance(entry.get(key), str) or not entry[key]:
                raise HarnessError('%s: "%s" must be a non-empty string' % (where, key))
        if not TOOL_ID.match(entry['id']) or entry['id'] in seen:
            raise HarnessError('%s: id %r is invalid or repeated' % (where, entry['id']))
        seen.add(entry['id'])
        if entry['family'] not in FAMILIES:
            raise HarnessError('%s: family must be one of %s' % (where, ', '.join(FAMILIES)))
        if not HEX64.match(entry['sha256']):
            raise HarnessError(where + ': sha256 must be 64 lowercase hex digits')
        binary = entry['binary']
        if not os.path.isabs(binary) or not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            raise HarnessError(where + ': binary must be an absolute path to an executable file')
        actual = sha256_file(binary)
        if actual != entry['sha256']:
            raise HarnessError('%s: binary SHA-256 is %s, manifest says %s' % (where, actual, entry['sha256']))
        tool = dict(entry)
        tool.setdefault('regex_engine', None)
        tool.setdefault('notes', '')
        tool['adapter'] = adapter_name(tool)
        tools.append(tool)
    return {'path': os.path.abspath(path), 'sha256': sha256_file(path), 'tools': tools}


def manifest_verify_hashes(tools):
    """Return a map of tool id to the SHA-256 of its binary now."""
    return {tool['id']: sha256_file(tool['binary']) for tool in tools}


def manifest_load_workloads(paths, cache_root):
    """Load one or more workload manifests and resolve paths under the cache root."""
    workloads, seen, sources = [], set(), []
    for path in paths:
        data = read_json(path)
        if not isinstance(data, dict) or data.get('schema') != SCHEMA_WORKLOADS:
            raise HarnessError('%s: schema must be %s' % (path, SCHEMA_WORKLOADS))
        entries = data.get('workloads')
        if not isinstance(entries, list):
            raise HarnessError('%s: "workloads" must be a list' % path)
        sources.append({'path': os.path.abspath(path), 'sha256': sha256_file(path), 'set': data.get('set')})
        for index, entry in enumerate(entries):
            where = '%s: workloads[%d]' % (path, index)
            if not isinstance(entry, dict) or not isinstance(entry.get('id'), str) or not TOOL_ID.match(entry['id']):
                raise HarnessError(where + ': needs an "id" made of letters, digits, ".", "_" or "-"')
            if entry['id'] in seen:
                raise HarnessError(where + ': id %r is repeated' % entry['id'])
            seen.add(entry['id'])
            modes = entry.get('modes')
            if not isinstance(modes, list) or not modes or any(mode not in MODES for mode in modes):
                raise HarnessError(where + ': "modes" must list dir and/or git')
            relative = entry.get('path')
            if not isinstance(relative, str) or not relative or os.path.isabs(relative) or '..' in relative.split('/'):
                raise HarnessError(where + ': "path" must be relative to the cache root')
            workload = dict(entry)
            workload['set'] = data.get('set')
            workload['manifest'] = os.path.abspath(path)
            workload['target'] = os.path.join(cache_root, relative)
            workload['tuned'] = bool(entry.get('tuned', False))
            size = entry.get('size') if isinstance(entry.get('size'), dict) else {}
            workload['size'] = {key: size.get(key) for key in ('bytes', 'files', 'commits', 'git_bytes')}
            source = entry.get('source') if isinstance(entry.get('source'), dict) else {}
            # A fixtures-matrix workload holds one tool's own rule examples.
            workload['home_tool'] = source.get('tool') if isinstance(source.get('tool'), str) else None
            params = source.get('params') if isinstance(source.get('params'), dict) else {}
            git_range = {key: params[key] for key in ('git_base', 'git_head', 'git_log_options')
                         if isinstance(params.get(key), str) and params[key]}
            workload['git_range'] = git_range or None
            labels = entry.get('labels')
            workload['labels_path'] = None
            workload['labels_missing'] = False
            if isinstance(labels, str) and labels:
                for base in (cache_root, os.path.dirname(os.path.abspath(path))):
                    candidate = labels if os.path.isabs(labels) else os.path.join(base, labels)
                    if os.path.isfile(candidate):
                        workload['labels_path'] = candidate
                        break
                else:
                    workload['labels_path'] = os.path.join(cache_root, labels)
                    workload['labels_missing'] = True
            workloads.append(workload)
    return workloads, sources


def manifest_input_bytes(workload):
    """Input bytes come from the workload manifest, never from a tool."""
    declared = workload['size'].get('bytes')
    if isinstance(declared, int) and declared > 0:
        return declared, 'manifest'
    total = 0
    for directory, names, files in os.walk(workload['target']):
        names[:] = [name for name in names if name != '.git']
        for name in files:
            try:
                metadata = os.lstat(os.path.join(directory, name))
            except OSError:
                continue
            if stat.S_ISREG(metadata.st_mode):
                total += metadata.st_size
    return total, 'harness walk of regular files, excluding .git'


def manifest_git_bytes(workload):
    """Bytes for git-mode throughput, only when the manifest gives them."""
    value = workload['size'].get('git_bytes')
    return value if isinstance(value, int) and value > 0 else None


def manifest_target_config(workload):
    """Configuration and ignore files at the scan root that tools may load."""
    target = workload['target']
    if not os.path.isdir(target):
        return []
    return [name for name in TARGET_CONFIG_FILES if os.path.lexists(os.path.join(target, name))]


def manifest_check_target(workload, mode):
    target = workload['target']
    if not os.path.isdir(target) and not os.path.isfile(target):
        return 'input path does not exist under the cache root'
    if mode == 'git' and not os.path.exists(os.path.join(target, '.git')):
        return 'git mode needs a repository with a .git folder'
    return None
