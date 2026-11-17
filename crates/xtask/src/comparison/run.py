# Comparison harness: the `run` command.


class RunContext(object):
    def __init__(self, options, output, tools, workloads, git):
        self.options = options
        self.output = output
        self.tools = {tool['id']: tool for tool in tools}
        self.workloads = {workload['id']: workload for workload in workloads}
        self.git = git
        self.rng = random.Random(options.seed)
        self.samples_path = os.path.join(output, 'samples.jsonl')
        self.cwd = private_dir(os.path.join(output, 'cwd'))
        self.bin_dir = None
        if git:
            self.bin_dir = os.path.join(output, 'bin')
            measure_git_link(self.bin_dir, git['path'])
        self.inputs_dir = private_dir(os.path.join(output, 'inputs'))
        self.shared_rules = os.path.join(self.inputs_dir, 'shared-rules.toml')
        write_private(self.shared_rules, adapter_shared_rules_toml().encode())
        self.profiles = {}
        self.counter = 0

    def profile(self, workers):
        if workers not in self.profiles:
            path = os.path.join(self.inputs_dir, 'rustleaks-profile-w%d.limits' % workers)
            write_private(path, adapter_profile_text(workers).encode())
            self.profiles[workers] = path
        return self.profiles[workers]

    def inputs(self):
        return {'shared_rules': self.shared_rules, 'profile': self.profile}

    def public(self, text, tool, workload):
        replacements = [(tool['binary'], '<binary>'), (workload['target'], '<target>'),
                        (self.inputs_dir + '/', '<inputs>/'), (self.output + '/', '<run>/')]
        for old, new in replacements:
            text = text.replace(old, new)
        return text


def run_home(ctx, cell, sample_id):
    if cell['cache'] == 'cold':
        home = os.path.join(ctx.output, 'homes', 'cold-' + sample_id)
        if os.path.exists(home):
            shutil.rmtree(home)
    else:
        home = os.path.join(ctx.output, 'homes', 'warm-' + slug(cell['tool']))
    private_dir(home)
    tmp = private_dir(os.path.join(home, 'tmp'))
    return home, tmp


def run_sample(ctx, cell, phase, repetition):
    tool = ctx.tools[cell['tool']]
    workload = ctx.workloads[cell['workload']]
    ctx.counter += 1
    sample_id = '%06d' % ctx.counter
    report = os.path.join(ctx.output, 'reports', sample_id + '.json')
    stdout_path = os.path.join(ctx.output, 'logs', sample_id + '.stdout')
    stderr_path = os.path.join(ctx.output, 'logs', sample_id + '.stderr')
    home, tmp = run_home(ctx, cell, sample_id)
    bin_dir = ctx.bin_dir
    child_log = None
    if phase == 'instrumented':
        bin_dir = os.path.join(ctx.output, 'instrument', sample_id)
        child_log = os.path.join(ctx.output, 'instrument', sample_id + '.jsonl')
        measure_git_shim(bin_dir, ctx.git['path'], child_log)
    invocation = adapter_invocation(tool, cell['mode'], workload['target'], report, cell['settings'], ctx.inputs())
    env = measure_environment(home, tmp, bin_dir, invocation['env'])
    if phase == 'measured' and repetition == 0:
        cell['thermal_before'] = thermal_state()
    record = {'schema': SCHEMA_SAMPLE, 'sample': sample_id, 'cell_id': cell['cell_id'], 'phase': phase,
              'repetition': repetition, 'started_at': utc_now(), 'load_before': load_average()}
    result = measure_execute(invocation['argv'], env, ctx.cwd, stdout_path, stderr_path,
                             ctx.options.timeout, watch_paths=[report])
    record['load_after'] = load_average()
    if phase == 'measured' and repetition + 1 >= cell.get('runs_planned', 0):
        cell['thermal_after'] = thermal_state()
    record.update(result)
    status = result['status']
    findings = None
    if status == 'exited':
        status = 'ok'
        if not os.path.exists(report):
            status = 'no-report'
        elif os.path.getsize(report) > RUN_PARSE_LIMIT and cell.get('parsed_once') and phase != 'instrumented':
            # Large reports are parsed once per cell; later samples keep only
            # the exit code check.
            record['report_bytes'] = os.path.getsize(report)
            record['findings_checked'] = False
            if result['exit_code'] not in (0, adapter_leak_exit_code(tool)):
                status = 'unexpected-exit-code'
        else:
            try:
                findings, meta = adapter_parse(tool['adapter'], report, workload['target'], cell['mode'])
                cell['parsed_once'] = True
                record['tool_meta'] = {key: value for key, value in meta.items()
                                       if key in ('state', 'rules_applied', 'tool_bytes_scanned', 'validations',
                                                  'terminal_findings', 'non_history_findings')}
            except (OSError, ValueError) as error:
                status = 'invalid-report'
                record['error'] = str(error)[:200]
        if findings is not None:
            count = len(findings)
            record['findings'] = count
            record['findings_digest'] = adapter_identity_digest(findings)
            expected = adapter_leak_exit_code(tool) if count else 0
            if result['exit_code'] != expected:
                status = 'unexpected-exit-code'
            if tool['adapter'] == 'rustleaks' and '--complete-profile' in invocation['argv']:
                with open(stderr_path, encoding='utf-8', errors='replace') as handle:
                    line = adapter_status_line(handle.read())
                record['rustleaks_status'] = None if line is None else {
                    key: line.get(key) for key in ('status', 'reason', 'findings', 'original_bytes', 'fragments')}
                if line is None or line.get('status') != 'complete':
                    status = 'incomplete-scan'
            meta = record.get('tool_meta', {})
            if tool['adapter'] in ('kingfisher', 'betterleaks-v2') and meta.get('validations'):
                status = 'validation-ran'
            if (tool['adapter'] == 'kingfisher' and cell['settings'].get('rules') == 'shared'
                    and meta.get('rules_applied') != len(SHARED_RULES)):
                status = 'rules-mismatch'
                record['error'] = 'Kingfisher applied %s rules, not the %d shared rules' % (
                    meta.get('rules_applied'), len(SHARED_RULES))
            if meta.get('non_history_findings'):
                cell['non_history_findings'] = max(cell.get('non_history_findings', 0), meta['non_history_findings'])
            if tool['adapter'] == 'betterleaks-v2' and record.get('tool_meta', {}).get('state') not in (None, 'complete'):
                status = 'incomplete-scan'
    record['status'] = status
    if child_log is not None:
        record['children'] = measure_child_summary(child_log)
    keep = status == 'ok' and phase == 'measured' and not cell.get('kept_report')
    if keep:
        kept = os.path.join('reports', '%s-%s.json' % (slug(cell['cell_id']), sha256_text(cell['cell_id'])[:8]))
        os.replace(report, os.path.join(ctx.output, kept))
        cell['kept_report'] = kept
        cell['kept_logs'] = [os.path.relpath(stdout_path, ctx.output), os.path.relpath(stderr_path, ctx.output)]
    else:
        if os.path.exists(report):
            os.remove(report)
        if status == 'ok':
            for path in (stdout_path, stderr_path):
                os.remove(path)
        else:
            record['logs'] = [os.path.relpath(stdout_path, ctx.output), os.path.relpath(stderr_path, ctx.output)]
    if cell['cache'] == 'cold':
        shutil.rmtree(home, ignore_errors=True)
    append_jsonl(ctx.samples_path, record)
    return record


RUN_PARSE_LIMIT = 64 << 20


def run_count(options, warm_median):
    if options.runs:
        return options.runs, 'override: --runs %d (not the protocol count)' % options.runs
    if warm_median is None:
        return options.runs_slow, 'no warmup timing; used the count for cells of 1 s or more'
    seconds = warm_median / 1e9
    if seconds >= options.long_seconds:
        return options.long_runs, 'multi-minute cell (warmup median %.0f s): %d runs' % (seconds, options.long_runs)
    if seconds < 1:
        return options.runs_fast, 'warmup median under 1 s'
    return options.runs_slow, 'warmup median 1 s or more'


def run_block(ctx, cells):
    """Run every cell of one workload and mode, interleaved in random order."""
    warm = [cell for cell in cells if cell['cache'] == 'warm']
    warmups = collections.defaultdict(list)
    for repetition in range(ctx.options.warmups):
        order = [cell for cell in warm if cell['status'] == 'planned']
        ctx.rng.shuffle(order)
        for cell in order:
            record = run_sample(ctx, cell, 'warmup', repetition)
            if record['status'] != 'ok':
                cell['status'] = 'dropped'
                cell['reason'] = 'warmup failed: %s' % record['status']
            else:
                warmups[cell['cell_id']].append(record['wall_ns'])
    sibling = {}
    for cell in warm:
        key = (cell['lane'], cell['variant'], cell['sub'], cell['tool'])
        sibling[key] = stats_median(warmups[cell['cell_id']]) if warmups[cell['cell_id']] else None
    for cell in cells:
        if cell['status'] != 'planned':
            continue
        median = sibling.get((cell['lane'], cell['variant'], cell['sub'], cell['tool']))
        cell['runs_planned'], cell['runs_reason'] = run_count(ctx.options, median)
        cell['warmups'] = len(warmups.get(cell['cell_id'], []))
    done = collections.Counter()
    while True:
        order = [cell for cell in cells if cell['status'] == 'planned' and done[cell['cell_id']] < cell['runs_planned']]
        if not order:
            break
        ctx.rng.shuffle(order)
        for cell in order:
            record = run_sample(ctx, cell, 'measured', done[cell['cell_id']])
            done[cell['cell_id']] += 1
            if record['status'] != 'ok':
                cell.setdefault('failed_samples', 0)
                cell['failed_samples'] += 1
            if (cell['cache'] == 'cold' and done[cell['cell_id']] == 1 and cell['runs_reason'].startswith('no warmup')
                    and record['status'] == 'ok' and not ctx.options.runs):
                cell['runs_planned'], cell['runs_reason'] = run_count(ctx.options, record['wall_ns'])
    for cell in cells:
        if cell['status'] != 'planned':
            continue
        cell['status'] = 'partial' if cell.get('failed_samples') else 'ok'
        if cell.get('failed_samples') == done[cell['cell_id']]:
            cell['status'] = 'failed'
            cell['reason'] = 'every measured sample failed'
        if (cell['mode'] == 'git' and ctx.git and not ctx.options.no_child_instrumentation
                and cell['cache'] == 'warm' and cell['status'] != 'failed'):
            record = run_sample(ctx, cell, 'instrumented', 0)
            cell['children'] = record.get('children')
            cell['instrumented_status'] = record['status']


def run_command(options):
    os.umask(0o077)
    output = os.path.abspath(options.output)
    if os.path.exists(output):
        raise HarnessError('output folder already exists: %s' % output)
    cache_root = os.path.abspath(options.cache_root)
    tools_manifest = manifest_load_tools(options.tools)
    tools = tools_manifest['tools']
    if options.tool:
        tools = [tool for tool in tools if tool['id'] in options.tool]
        missing = set(options.tool) - {tool['id'] for tool in tools}
        if missing:
            raise HarnessError('unknown tool id: %s' % ', '.join(sorted(missing)))
    workloads, workload_sources = manifest_load_workloads(options.workloads, cache_root)
    if options.workload:
        missing = set(options.workload) - {workload['id'] for workload in workloads}
        if missing:
            raise HarnessError('unknown workload id: %s' % ', '.join(sorted(missing)))
        workloads = [workload for workload in workloads if workload['id'] in options.workload]
    if not workloads:
        raise HarnessError('no workloads selected')
    git = resolve_git(options.git)
    private_dir(output)
    for name in ('reports', 'logs', 'homes', 'instrument'):
        private_dir(os.path.join(output, name))
    probe_home = private_dir(os.path.join(output, 'homes', 'probe'))
    probe_env = measure_environment(probe_home, private_dir(os.path.join(probe_home, 'tmp')), None, {})
    for tool in tools:
        tool['probe'] = adapter_probe(tool, probe_env)
    ctx = RunContext(options, output, tools, workloads, git)
    for workload in workloads:
        workload['input_bytes'], workload['input_bytes_source'] = manifest_input_bytes(workload) \
            if os.path.exists(workload['target']) else (workload['size'].get('bytes'), 'manifest')
        workload['git_bytes'] = manifest_git_bytes(workload)
        workload['target_config_files'] = manifest_target_config(workload)
        if workload['labels_missing']:
            print('compare: WARNING: labels file for workload %s is missing; quality will not be scored'
                  % workload['id'], file=sys.stderr)
    cells = lanes_plan(tools, workloads, options)
    for cell in cells:
        cell['status'] = 'planned'
        workload = ctx.workloads[cell['workload']]
        tool = ctx.tools[cell['tool']]
        problem = manifest_check_target(workload, cell['mode'])
        if problem:
            cell['status'], cell['reason'] = 'skipped', problem
            continue
        if cell['mode'] == 'git' and tool['adapter'] in ('rustleaks', 'gitleaks', 'betterleaks-v1') and not git:
            cell['status'], cell['reason'] = 'skipped', 'git mode needs a git executable on this host'
            continue
        if cell['mode'] == 'git' and workload.get('git_range'):
            cell['settings'] = dict(cell['settings'], git_range=workload['git_range'])
        loaded = adapter_auto_loaded(tool['adapter'], workload['target_config_files'],
                                     cell['settings'].get('rules') == 'shared')
        if loaded:
            cell['target_config_loaded'] = loaded
            if options.target_config == 'skip':
                cell['status'] = 'skipped'
                cell['reason'] = ('the scan root holds %s, which this tool loads by itself; '
                                  'use --target-config run to run it anyway' % ', '.join(loaded))
                continue
        invocation = adapter_invocation(tool, cell['mode'], workload['target'],
                                        os.path.join(output, 'reports', '<report>.json'), cell['settings'], ctx.inputs())
        if invocation['unsupported']:
            cell['status'], cell['reason'] = 'skipped', invocation['unsupported']
            continue
        cell['argv'] = [ctx.public(arg, tool, workload) for arg in invocation['argv']]
        cell['flags'] = [dict(item, flag=ctx.public(item['flag'], tool, workload)) for item in invocation['flags']]
        cell['env'] = invocation['env']
    deviations = []
    if any(cell.get('target_config_loaded') and cell['status'] == 'planned' for cell in cells):
        deviations.append('some cells run with configuration or ignore files from the scan root (--target-config run)')
    if options.runs:
        deviations.append('--runs %d overrides the protocol run counts' % options.runs)
    if options.warmups < 3:
        deviations.append('--warmups %d is below the protocol minimum of 3' % options.warmups)
    run = {'schema': SCHEMA_RUN, 'run_id': datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ') + '-%04x' % random.getrandbits(16),
           'harness_sha256': HARNESS_SHA256, 'started_at': utc_now(), 'command': 'run',
           'settings': {key: value for key, value in vars(options).items() if key not in ('func',)},
           'protocol_deviations': deviations, 'host': host_details(), 'thermal_before': thermal_state(),
           'load_before': load_average(), 'background_builds_before': background_builds(),
           'git': git, 'tools_manifest': {key: tools_manifest[key] for key in ('path', 'sha256')},
           'tools': tools, 'workload_manifests': workload_sources, 'workloads': workloads, 'cells': cells,
           'source': run_source_state()}
    planned = [cell for cell in cells if cell['status'] == 'planned']
    print('planned %d cells (%d skipped) over %d workloads' % (
        len(planned), len(cells) - len(planned), len(workloads)), file=sys.stderr)
    if options.dry_run:
        for cell in cells:
            print('%-8s %s%s' % (cell['status'], cell['cell_id'],
                                 '' if cell['status'] == 'planned' else '  (%s)' % cell['reason']))
        run['finished_at'] = utc_now()
        run['dry_run'] = True
        write_json(os.path.join(output, 'run.json'), run)
        return 0
    blocks = collections.defaultdict(list)
    for cell in planned:
        blocks[(cell['workload'], cell['mode'])].append(cell)
    order = sorted(blocks)
    ctx.rng.shuffle(order)
    run['block_order'] = ['%s/%s' % key for key in order]
    run['blocks'] = []
    for key in order:
        block = {'block': '%s/%s' % key, 'load_before': load_average(), 'background_builds_before': background_builds(),
                 'thermal_before': thermal_state(), 'started_at': utc_now()}
        print('running %s/%s: %d cells' % (key[0], key[1], len(blocks[key])), file=sys.stderr)
        run_block(ctx, blocks[key])
        block.update({'load_after': load_average(), 'background_builds_after': background_builds(),
                      'thermal_after': thermal_state(), 'finished_at': utc_now()})
        run['blocks'].append(block)
    after = manifest_verify_hashes(tools)
    for tool in tools:
        tool['sha256_after'] = after[tool['id']]
        tool['sha256_verified'] = after[tool['id']] == tool['sha256']
    if git:
        git['sha256_after'] = sha256_file(git['path'])
        git['sha256_verified'] = git['sha256_after'] == git['sha256']
    run.update({'finished_at': utc_now(), 'thermal_after': thermal_state(), 'load_after': load_average(),
                'background_builds_after': background_builds()})
    shutil.rmtree(os.path.join(output, 'homes'), ignore_errors=True)
    write_json(os.path.join(output, 'run.json'), run)
    if not options.no_score:
        result = score_run(output, options.seed)
        write_json(os.path.join(output, 'score.json'), result)
        write_private(os.path.join(output, 'score.md'), score_markdown(result).encode())
    report_write(output, options.seed)
    print('wrote %s' % os.path.join(output, 'report.md'), file=sys.stderr)
    bad = [tool['id'] for tool in tools if not tool['sha256_verified']]
    if git and not git['sha256_verified']:
        bad.append('git')
    if bad:
        raise HarnessError('binary changed during the run: %s' % ', '.join(bad))
    return 0


def run_source_state():
    """Record the harness source commit when the checkout is available."""
    root = os.environ.get('RUSTLEAKS_COMPARISON_SOURCE_ROOT')
    if not root or not os.path.isdir(os.path.join(root, '.git')) and not os.path.isfile(os.path.join(root, '.git')):
        return None
    git = resolve_git()
    if not git:
        return None
    env = {'PATH': SYSTEM_PATH, 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'HOME': '/nonexistent'}
    code, head, _ = run_text([git['path'], '-C', root, 'rev-parse', 'HEAD'], env=env)
    code2, status, _ = run_text([git['path'], '-C', root, 'status', '--porcelain'], env=env)
    if code != 0:
        return None
    return {'commit': head.strip(), 'dirty': bool(status.strip()) if code2 == 0 else None}
