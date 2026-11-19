# Comparison harness: summary JSON and the Markdown report.

REPORT_METRICS = ('wall_ns', 'cpu_user_ns', 'cpu_system_ns', 'cpu_total_ns', 'peak_rss_bytes')

REPORT_MEASURED = [
    'Wall time: from spawn to the return of wait4 for the scanner process, measured by the harness. It includes process start, rule loading, scanning and writing the report file.',
    'User and system CPU time: from the wait4 rusage of the scanner. On macOS and Linux this includes every descendant the scanner waited for, such as git.',
    'Peak RSS: ru_maxrss from the same rusage. It is the largest single process among the scanner and its waited-for descendants, not the sum of processes that ran at the same time.',
    'Child processes: in git mode, one extra untimed run per warm cell puts a git shim on PATH that records wall time, CPU time and peak RSS of each git process. Only git is shimmed. Tools that read Git in process (Kingfisher, Betterleaks v2) show no git children; their Git work is part of the scanner figures. The same run samples the resident size of the scanner process alone every 10 ms, because the peak RSS of a cell is the largest single process and can be a git child.',
    'Not measured: the combined RSS of processes that run at the same time, memory of helper processes other than git, GPU or I/O wait time, and disk bytes read.',
    'Input bytes come from the workload manifest (or a harness walk of regular files outside .git when the manifest has none), never from a tool. Throughput is input bytes divided by the median wall time.',
    'Findings are counted from the parsed report, every record, with no deduplication by the harness.',
]

REPORT_LIMITS = [
    'Cold cells start each sample with an empty HOME, TMPDIR and tool cache folders. The operating system page cache is not purged, because that needs root; cold cells are cold for tool caches only.',
    'Warm cells share one HOME per tool across all lanes of the run, so tool caches (such as compiled rule caches) are filled by the warmups.',
    'Results apply only to this host, these tool builds and these inputs.',
    'Thermal state is recorded before the first and after the last measured run of each cell, and for each workload block.',
    'Rustleaks and Gitleaks load .gitleaks.toml, .gitleaksignore (and the Rustleaks names) from the scan root by themselves, and Betterleaks 1 loads ignore files. Cells where that would happen are skipped unless the run used --target-config run; the workloads table lists such files.',
    'Throughput in git mode is given only when the workload manifest gives Git bytes, because the tools read different Git data.',
    'Each tool uses its own mechanism for threads (Rustleaks workers through a generated --complete-profile, GOMAXPROCS for Go tools, --jobs for Kingfisher). These are not identical mechanisms: Gitleaks keeps 40 goroutines, Betterleaks v2 starts 4 x GOMAXPROCS workers, and the Rustleaks profile also switches to whole-file reading.',
    'The same rule text in the shared rules lane does not guarantee the same regex semantics in every engine. Identity agreement shows whether the tools found the same items.',
]


def report_rate(value):
    return '-' if value is None else '%.3f' % value


def report_ms(value):
    return '-' if value is None else '%.1f' % (value / 1e6)


def report_mib(value):
    return '-' if value is None else '%.1f' % (value / 1048576.0)


def report_summary(run_dir, seed):
    run = read_json(os.path.join(run_dir, 'run.json'))
    samples_path = os.path.join(run_dir, 'samples.jsonl')
    samples = read_jsonl(samples_path) if os.path.exists(samples_path) else []
    by_cell = collections.defaultdict(list)
    for sample in samples:
        if 'cpu_user_ns' in sample:
            sample['cpu_total_ns'] = sample['cpu_user_ns'] + sample['cpu_system_ns']
        by_cell[sample['cell_id']].append(sample)
    workloads = {workload['id']: workload for workload in run['workloads']}
    cells = []
    for cell in run['cells']:
        rows = by_cell.get(cell['cell_id'], [])
        measured = [row for row in rows if row['phase'] == 'measured']
        good = [row for row in measured if row['status'] == 'ok']
        digests = sorted({row.get('findings_digest') for row in good})
        summary = {key: cell.get(key) for key in ('cell_id', 'lane', 'variant', 'sub', 'tool', 'family', 'adapter',
                                                  'workload', 'mode', 'cache', 'group', 'status', 'reason',
                                                  'runs_planned', 'runs_reason', 'warmups', 'children',
                                                  'baseline_key', 'settings', 'thermal_before', 'thermal_after',
                                                  'non_history_findings', 'target_config_loaded')}
        summary['measured'] = len(measured)
        summary['failed_samples'] = len(measured) - len(good)
        summary['statuses'] = dict(collections.Counter(row['status'] for row in rows))
        summary['metrics'] = {metric: stats_summary([row.get(metric) for row in good]) for metric in REPORT_METRICS}
        summary['samples'] = {metric: [row.get(metric) for row in good] for metric in REPORT_METRICS}
        summary['findings'] = sorted({row.get('findings') for row in good if row.get('findings') is not None})
        summary['findings_stable'] = len(digests) <= 1
        summary['exit_codes'] = sorted({row.get('exit_code') for row in measured if row.get('exit_code') is not None})
        loads = [row['load_before'][0] for row in rows if row.get('load_before')] + \
                [row['load_after'][0] for row in rows if row.get('load_after')]
        summary['load_1min'] = {'min': min(loads), 'max': max(loads)} if loads else None
        summary['tool_meta'] = next((row.get('tool_meta') for row in good if row.get('tool_meta')), None)
        workload = workloads.get(cell['workload'], {})
        wall = summary['metrics']['wall_ns']
        # Throughput needs bytes for the same scope: the input tree in dir
        # mode, and only manifest-given Git bytes in git mode.
        size = workload.get('input_bytes') if cell['mode'] == 'dir' else workload.get('git_bytes')
        summary['input_bytes'] = size
        summary['throughput_mib_s'] = (size / 1048576.0) / (wall['median'] / 1e9) if size and wall and wall['median'] else None
        cells.append(summary)
    baselines = lanes_baselines(cells, run['settings'].get('baseline'))
    by_id = {cell['cell_id']: cell for cell in cells}
    for cell in cells:
        base_id = baselines.get((cell['group'], cell['cache']))
        cell['baseline'] = base_id
        cell['ratios'] = {}
        if not base_id or base_id == cell['cell_id'] or cell['status'] not in ('ok', 'partial'):
            continue
        base = by_id[base_id]
        for offset, metric in enumerate(('wall_ns', 'cpu_total_ns', 'peak_rss_bytes')):
            cell['ratios'][metric] = stats_ratio_interval(cell['samples'][metric], base['samples'][metric], seed + offset)
    pairwise = []
    grouped = collections.defaultdict(list)
    for cell in cells:
        if cell['status'] in ('ok', 'partial') and cell['samples']['wall_ns']:
            grouped[(cell['group'], cell['cache'])].append(cell)
    for (group, cache), members in sorted(grouped.items()):
        members.sort(key=lambda cell: cell['cell_id'])
        for a in range(len(members)):
            for b in range(a + 1, len(members)):
                left, right = members[a], members[b]
                pairwise.append({'group': group, 'cache': cache, 'numerator': left['cell_id'],
                                 'denominator': right['cell_id'],
                                 'ratios': {metric: stats_ratio_interval(left['samples'][metric],
                                                                         right['samples'][metric], seed + offset)
                                            for offset, metric in enumerate(('wall_ns', 'cpu_total_ns',
                                                                             'peak_rss_bytes'))}})
    run['pairwise'] = pairwise
    score = None
    score_path = os.path.join(run_dir, 'score.json')
    if os.path.exists(score_path):
        score = read_json(score_path)
    return run, cells, score


def report_flags(run):
    """Every non-default flag, per tool and lane, with its reason."""
    rows = {}
    for cell in run['cells']:
        for item in cell.get('flags') or []:
            key = (cell['tool'], cell['lane'], item['flag'], item['reason'])
            rows.setdefault(key, set()).add(cell['variant'] + ('/' + cell['sub'] if cell.get('sub') else ''))
    return [{'tool': tool, 'lane': lane, 'flag': flag, 'reason': reason, 'variants': sorted(variants)}
            for (tool, lane, flag, reason), variants in sorted(rows.items())]


def report_write(run_dir, seed):
    run, cells, score = report_summary(run_dir, seed)
    summary = {'schema': SCHEMA_SUMMARY, 'run_id': run['run_id'], 'harness_sha256': run['harness_sha256'],
               'host': run['host'],
               'tools': [{key: value for key, value in tool.items() if key != 'binary'} for tool in run['tools']],
               'workloads': [{key: value for key, value in workload.items()
                              if key not in ('target', 'manifest', 'labels_path')} for workload in run['workloads']],
               'cells': cells,
               'flags': report_flags(run), 'protocol_deviations': run.get('protocol_deviations', []),
               'pairwise_ratios': run.get('pairwise', []),
               'measured': REPORT_MEASURED, 'limits': REPORT_LIMITS,
               'score': None if score is None else {
                   'comparisons': [{key: row[key] for key in ('left', 'right', 'group', 'cache', 'matched',
                                                              'left_items', 'right_items', 'agreement',
                                                              'only_left_by_hint', 'only_right_by_hint') if key in row}
                                   for row in score.get('comparisons', [])],
                   'quality': [{key: row[key] for key in ('name', 'workload', 'lane', 'tool', 'overall', 'by_category',
                                                          'by_source', 'by_scope', 'labels', 'labels_complete',
                                                          'label_problems') if key in row}
                               for row in score.get('quality', [])],
                   'not_scored': score.get('not_scored', []), 'score_errors': score.get('score_errors', []),
                   'score_hours': score.get('score_hours')}}
    path = os.path.join(run_dir, 'summary.json')
    write_json(path, summary, exclusive=False)
    write_private(os.path.join(run_dir, 'report.md'), report_markdown(run, cells, score, summary).encode(), exclusive=False)
    return summary


def report_table(headers, rows):
    lines = ['| ' + ' | '.join(headers) + ' |',
             '| ' + ' | '.join('---' for _ in headers) + ' |']
    for row in rows:
        lines.append('| ' + ' | '.join(str(value).replace('|', '\\|') for value in row) + ' |')
    return lines


def report_metric(stats, scale):
    if not stats:
        return '-'
    return '%s (MAD %s; %s to %s)%s' % (scale(stats['median']), scale(stats['mad']), scale(stats['min']),
                                       scale(stats['max']), ' bimodal' if stats['bimodal']['flag'] else '')


def report_ratio(ratio):
    if not ratio:
        return '-'
    return '%.2f [%.2f, %.2f]' % (ratio['ratio'], ratio['low'], ratio['high'])


def report_markdown(run, cells, score, summary):
    host = run['host']
    lines = ['# Scanner comparison report', '',
             'Run `%s`. Harness SHA-256 `%s`.' % (run['run_id'], run['harness_sha256']), '']
    if run.get('dry_run'):
        lines += ['This was a dry run. Nothing was measured.', '']
    deviations = run.get('protocol_deviations') or []
    lines += ['## Status', '']
    if deviations:
        lines += ['These settings depart from the protocol, so the timings are not protocol results:', '']
        lines += ['- ' + item for item in deviations]
    else:
        lines.append('No protocol deviations were recorded by the harness.')
    lines += ['', '## Host', '']
    lines += ['- %s: %s' % (key, host.get(key)) for key in sorted(host)]
    lines += ['- thermal state before and after: %s / %s' % (run.get('thermal_before'), run.get('thermal_after')),
              '- load average before and after the run: %s / %s' % (run.get('load_before'), run.get('load_after')),
              '- build processes before and after the run: %s / %s' % (run.get('background_builds_before'),
                                                                     run.get('background_builds_after')),
              '- git: %s' % ('none' if not run.get('git') else '%s (SHA-256 %s)' % (
                  run['git']['version'], run['git']['sha256'])),
              '- harness source: %s' % run.get('source'), '']
    lines += ['## Tools', '']
    rows = []
    for tool in run['tools']:
        probe = tool.get('probe') or {}
        rules = tool.get('rule_count')
        probed = probe.get('rule_count_probed')
        rows.append([tool['id'], tool['adapter'], tool['version'], tool['build'], tool.get('regex_engine') or '-',
                     '`%s`' % tool['sha256'], {True: 'yes', False: 'CHANGED'}.get(tool.get('sha256_verified'), 'not checked'),
                     probe.get('version_text') or '-',
                     '%s%s' % ('-' if rules is None else '%s declared' % rules,
                               '' if probed is None else '; %s probed' % probed),
                     ', '.join(probe.get('capabilities') or []) or '-'])
    lines += report_table(['Tool', 'Adapter', 'Version', 'Build', 'Regex engine', 'SHA-256', 'Hash same after run',
                           'Version output', 'Rules', 'Capabilities'], rows)
    lines += ['', 'Rule sources and notes from the tools manifest:', '']
    lines += ['- %s: %s' % (tool['id'], tool.get('rule_source') or tool.get('notes') or 'none given') for tool in run['tools']]
    lines += ['', '## Workloads', '']
    rows = [[workload['id'], workload.get('set') or '-', workload.get('family') or '-', ', '.join(workload['modes']),
             workload.get('input_bytes'), workload.get('input_bytes_source'), workload['size'].get('files') or '-',
             workload['size'].get('commits') or '-', 'yes' if workload.get('tuned') else 'no',
             'MISSING' if workload.get('labels_missing') else 'yes' if workload.get('labels_path') else 'no',
             ', '.join(workload.get('target_config_files') or []) or '-'] for workload in run['workloads']]
    lines += report_table(['Workload', 'Set', 'Family', 'Modes', 'Input bytes', 'Bytes source', 'Files', 'Commits',
                           'Tuned', 'Labels', 'Config or ignore files at the scan root'], rows)
    tuned = [workload['id'] for workload in run['workloads'] if workload.get('tuned')]
    lines += ['', 'Tuned inputs (used during Rustleaks development): %s.' % (', '.join(tuned) if tuned else 'none'), '']
    skipped = [item for source in run.get('workload_manifests') or [] for item in source.get('skipped_workloads') or []]
    if skipped:
        lines += ['Workloads in the manifests that this harness does not run:', '']
        lines += ['- %s: %s' % (item['id'], item['reason']) for item in skipped]
        lines += ['']
    for lane in LANES:
        lane_cells = [cell for cell in cells if cell['lane'] == lane]
        if not lane_cells:
            continue
        lines += ['## Lane: %s' % lane, '', LANE_PURPOSE[lane], '']
        rows = []
        for cell in sorted(lane_cells, key=lambda cell: (cell['workload'], cell['mode'], cell['cache'], cell['variant'],
                                                         cell['sub'] or '', cell['tool'])):
            if cell['status'] in ('skipped', 'dropped', 'failed'):
                continue
            metrics = cell['metrics']
            rows.append([cell['workload'], cell['mode'], cell['cache'],
                         cell['variant'] + ('/' + cell['sub'] if cell['sub'] else ''), cell['tool'],
                         cell['measured'], report_metric(metrics['wall_ns'], report_ms),
                         report_metric(metrics['cpu_user_ns'], report_ms), report_metric(metrics['cpu_system_ns'], report_ms),
                         report_metric(metrics['peak_rss_bytes'], report_mib),
                         '-' if cell['throughput_mib_s'] is None else '%.2f' % cell['throughput_mib_s'],
                         '/'.join(str(value) for value in cell['findings']) or '-',
                         'yes' if cell['findings_stable'] else 'NO',
                         '/'.join(str(value) for value in cell['exit_codes']),
                         'baseline' if cell['baseline'] == cell['cell_id'] else report_ratio(cell['ratios'].get('wall_ns')),
                         report_ratio(cell['ratios'].get('cpu_total_ns')), report_ratio(cell['ratios'].get('peak_rss_bytes')),
                         '-' if not cell['load_1min'] else '%.2f to %.2f' % (cell['load_1min']['min'], cell['load_1min']['max'])])
        lines += report_table(['Workload', 'Mode', 'Cache', 'Variant', 'Tool', 'n', 'Wall ms median (MAD; min to max)',
                               'User CPU ms', 'System CPU ms', 'Peak RSS MiB', 'MiB/s', 'Findings', 'Same findings every run',
                               'Exit', 'Wall ratio [95% CI]', 'CPU ratio [95% CI]', 'RSS ratio [95% CI]', 'Load 1 min'], rows)
        lines += ['', 'Ratios are against the baseline cell of the same group and cache state; intervals are '
                      'percentile bootstrap intervals of the ratio of medians (%d resamples, fixed seed).' % BOOTSTRAP_RESAMPLES, '']
        children = [cell for cell in lane_cells if cell.get('children')]
        if children:
            rows = [[cell['cell_id'], cell['children']['processes'], report_ms(cell['children']['cpu_user_ns']),
                     report_ms(cell['children']['cpu_system_ns']), report_mib(cell['children']['peak_rss_bytes']),
                     report_mib(cell['children'].get('scanner_peak_rss_bytes'))]
                    for cell in children]
            lines += ['Git child processes and the scanner process alone, from the instrumented run:', '']
            lines += report_table(['Cell', 'git processes', 'User CPU ms (sum)', 'System CPU ms (sum)', 'git peak RSS MiB (largest)',
                                   'Scanner process peak RSS MiB (sampled every 10 ms)'], rows)
            lines.append('')
    pairs = run.get('pairwise') or []
    if pairs:
        lines += ['## Pairwise ratios', '',
                  'Every pair of cells in the same group and cache state: ratio of medians (first over second) with '
                  'its bootstrap 95 percent interval.', '']
        lines += report_table(['First', 'Second', 'Wall', 'CPU', 'Peak RSS'],
                              [[row['numerator'], row['denominator'], report_ratio(row['ratios']['wall_ns']),
                                report_ratio(row['ratios']['cpu_total_ns']), report_ratio(row['ratios']['peak_rss_bytes'])]
                               for row in pairs])
        lines.append('')
    flagged = [cell for cell in cells if cell.get('non_history_findings') or cell.get('target_config_loaded')
               or not cell['findings_stable']]
    lines += ['## Flagged cells', '']
    if flagged:
        lines += report_table(['Cell', 'Findings without a commit in git mode', 'Root files the tool loaded',
                               'Same findings every run'],
                              [[cell['cell_id'], cell.get('non_history_findings') or 0,
                                ', '.join(cell.get('target_config_loaded') or []) or '-',
                                'yes' if cell['findings_stable'] else 'NO'] for cell in flagged])
    else:
        lines.append('None.')
    lines += ['', '## Failed, dropped and skipped cells', '']
    bad = [cell for cell in cells if cell['status'] not in ('ok', 'planned')]
    if bad:
        lines += report_table(['Cell', 'Status', 'Reason', 'Failed samples'],
                              [[cell['cell_id'], cell['status'], cell.get('reason') or '-', cell['failed_samples']]
                               for cell in bad])
    else:
        lines.append('None.')
    if score and (score.get('not_scored') or score.get('score_errors')):
        lines += ['', '## Not scored', '',
                  'Scoring has a time limit (--score-hours, %s here). Work not finished by then, and reports that '
                  'could not be read, are listed here and are missing from the agreement and quality tables.'
                  % score.get('score_hours'), '']
        rows = [[row['kind'], row['left'], row.get('right') or '-', row['reason']] for row in score.get('not_scored', [])]
        rows += [['report', row['cell'], '-', row['error']] for row in score.get('score_errors', [])]
        lines += report_table(['Kind', 'Cell', 'Other cell', 'Reason'], rows)
    lines += ['', '## Run counts', '']
    counts = collections.Counter((cell['runs_planned'], cell['runs_reason']) for cell in cells if cell.get('runs_planned'))
    lines += ['- %d cells: %s runs (%s)' % (count, runs, reason) for (runs, reason), count in sorted(counts.items())]
    lines += ['- warmups per warm cell: %s; cold cells have no warmups.' % run['settings'].get('warmups'),
              '- order: workload blocks and the cells inside each repetition are shuffled with seed %s.' % run['settings'].get('seed'),
              '']
    if score:
        lines += ['## Identity agreement', '',
                  'One-to-one matching between tools in the same group. Full lists of unmatched items are in `score.md`.', '']
        rows = [[row['left'], row['right'], row['matched'], len(row['only_left']), len(row['only_right']),
                 '%.4f' % row['agreement']] for row in score.get('comparisons', [])]
        lines += report_table(['Left', 'Right', 'Matched', 'Only left', 'Only right', 'Agreement'], rows) if rows else ['None.']
        lines.append('')
        if score.get('quality'):
            lines += ['## Quality against labels', '']
            rows = [[row['name'], 'complete' if row.get('labels_complete', True) else 'partial',
                     row['overall']['findings'], row['overall']['true_positive'], row['overall']['false_negative'],
                     row['overall']['false_positive_on_negative'], row['overall']['unlabeled_findings'],
                     row['overall'].get('unknown_findings', 0), row['overall'].get('excluded_findings', 0),
                     report_rate(row['overall']['precision_strict']),
                     report_rate(row['overall']['recall']), report_rate(row['overall']['f1_strict'])]
                    for row in score['quality']]
            lines += report_table(['Cell', 'Labels', 'Findings', 'TP', 'FN', 'FP on negatives', 'Unlabeled', 'Unknown',
                                   'Excluded', 'Precision (strict)', 'Recall', 'F1 (strict)'], rows)
            lines += ['', 'Results by category, label source and test or other paths are in `score.md`.']
            lines.append('')
    lines += ['## Disclosure', '', '### What is measured', '']
    lines += ['- ' + item for item in REPORT_MEASURED]
    lines += ['', '### Limits', '']
    lines += ['- ' + item for item in REPORT_LIMITS]
    lines += ['', '### Flags that are not tool defaults', '']
    lines += report_table(['Tool', 'Lane', 'Flag', 'Reason', 'Variants'],
                          [[row['tool'], row['lane'], '`%s`' % row['flag'], row['reason'], ', '.join(row['variants'])]
                           for row in summary['flags']])
    lines += ['', 'Every run uses an allowlisted environment: PATH (a private folder with git, then system folders), '
                  'HOME, TMPDIR, XDG_CACHE_HOME, XDG_CONFIG_HOME, LC_ALL=C, TZ=UTC, GIT_CONFIG_NOSYSTEM=1, '
                  'GIT_CONFIG_GLOBAL=/dev/null and GIT_TERMINAL_PROMPT=0, plus GOMAXPROCS in the threads lanes for Go tools. '
                  'No validation or analysis variables reach any tool.', '',
              '### Defaults and scope differences by tool family', '']
    for adapter in sorted({tool['adapter'] for tool in run['tools']}):
        facts = ADAPTER_FACTS[adapter]
        lines += ['%s defaults: %s.' % (adapter, '; '.join('%s %s' % (key.replace('_', ' '), value)
                                                            for key, value in sorted(facts['defaults'].items()))), '']
        lines += ['- ' + item for item in facts['scope']]
        lines.append('')
    lines += ['### Lanes', '']
    lines += ['- %s: %s' % (lane, LANE_PURPOSE[lane]) for lane in LANES if lane in run['settings'].get('lanes', [])]
    lines.append('')
    return '\n'.join(lines)


def report_command(options):
    report_write(os.path.abspath(options.run), options.seed)
    print('wrote %s' % os.path.join(os.path.abspath(options.run), 'report.md'), file=sys.stderr)
    return 0
