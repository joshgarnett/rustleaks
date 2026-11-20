# Comparison harness: command line.

def main_parser():
    parser = argparse.ArgumentParser(prog='cargo xtask compare', description='Cross-scanner comparison harness.')
    commands = parser.add_subparsers(dest='command')
    run = commands.add_parser('run', help='measure tools on workloads')
    run.add_argument('--tools', required=True, help='tools manifest (JSON)')
    run.add_argument('--workloads', required=True, action='append', help='workload manifest (JSON); repeatable')
    run.add_argument('--cache-root', required=True, help='folder that workload paths are relative to')
    run.add_argument('--output', required=True, help='new private run folder')
    run.add_argument('--lanes', default='defaults', help='comma list of: ' + ', '.join(LANES))
    run.add_argument('--tool', action='append', help='only this tool id; repeatable')
    run.add_argument('--workload', action='append', help='only this workload id; repeatable')
    run.add_argument('--modes', default='dir,git', help='comma list of dir, git')
    run.add_argument('--threads', default='1,4,all', help='threads lane values; "all" means every logical CPU')
    run.add_argument('--shared-threads', default='1,4', help='thread values for the shared rules and Rustleaks 2x2 lanes')
    run.add_argument('--features-threads', default='4', help='threads in the features lane, or "default"')
    run.add_argument('--decode-depths', default='0,5', help='decode depths in the features lane')
    run.add_argument('--archive-depth-on', type=int, default=8, help='archive depth when archives are on')
    run.add_argument('--cache', default='warm,cold', help='cache states for the cold lanes: warm, cold')
    run.add_argument('--cold-lanes', default='defaults', help='lanes that also get cold cells')
    run.add_argument('--warmups', type=int, default=1)
    run.add_argument('--runs-fast', type=int, default=3, help='measured runs for cells under 1 s')
    run.add_argument('--runs-slow', type=int, default=3, help='measured runs for cells of 1 s or more')
    run.add_argument('--long-seconds', type=float, default=300, help='cells at least this long are multi-minute cells')
    run.add_argument('--long-runs', type=int, default=3, help='measured runs for multi-minute cells')
    run.add_argument('--runs', type=int, help='override every run count (marks the run as not protocol)')
    run.add_argument('--timeout', type=float, default=3600, help='seconds before a sample is stopped')
    run.add_argument('--max-hours', type=float, default=8,
                     help='run time budget in hours; no sample starts after it and the remaining cells are skipped')
    run.add_argument('--seed', type=int, default=DEFAULT_SEED)
    run.add_argument('--baseline', help='tool id used as the ratio baseline (default: first Rustleaks tool)')
    run.add_argument('--git', help='git executable for git mode (default: found on PATH)')
    run.add_argument('--no-child-instrumentation', action='store_true', help='skip the instrumented git run')
    run.add_argument('--no-score', action='store_true', help='do not score kept reports at the end')
    run.add_argument('--score-hours', type=float, default=SCORE_DEFAULT_HOURS,
                     help='hours before scoring stops; unfinished work is listed as not scored')
    run.add_argument('--dry-run', action='store_true', help='plan cells and write run.json without running tools')
    run.add_argument('--target-config', choices=('skip', 'run'), default='skip',
                     help='cells whose tool would load a configuration or ignore file from the scan root: '
                          'skip them (default) or run them and record it')
    score = commands.add_parser('score', help='match findings one to one')
    score.add_argument('--run', help='score every kept report of a run folder')
    score.add_argument('--left', help='ADAPTER=REPORT for an ad hoc comparison')
    score.add_argument('--right', help='ADAPTER=REPORT for an ad hoc comparison')
    score.add_argument('--target', help='input folder the ad hoc reports scanned')
    score.add_argument('--mode', default='dir', choices=MODES)
    score.add_argument('--labels', help='labels JSONL for quality scoring')
    score.add_argument('--workload', help='workload id to select labels (default: every label)')
    score.add_argument('--labels-partial', action='store_true',
                       help='labels are incomplete: count findings with no label as unknown, not false positives')
    score.add_argument('--git', help='git executable for labels with a commit')
    score.add_argument('--output', help='folder for score.json and score.md (default: the run folder)')
    score.add_argument('--score-hours', type=float, default=SCORE_DEFAULT_HOURS,
                       help='hours before scoring stops; unfinished work is listed as not scored')
    score.add_argument('--seed', type=int, default=DEFAULT_SEED)
    report = commands.add_parser('report', help='write summary.json and report.md for a run folder')
    report.add_argument('--run', required=True)
    report.add_argument('--seed', type=int, default=DEFAULT_SEED)
    commands.add_parser('self-test', help='run the synthetic self-test')
    return parser


def main_normalize(options):
    options.lanes = word_list(options.lanes, LANES, 'lanes')
    options.modes = word_list(options.modes, MODES, 'modes')
    options.caches = word_list(options.cache, ('warm', 'cold'), 'cache states')
    options.cold_lanes = word_list(options.cold_lanes, LANES, 'cold lanes')
    options.threads = number_list(options.threads, '--threads')
    options.shared_threads = number_list(options.shared_threads, '--shared-threads')
    options.features_threads = None if options.features_threads == 'default' else number_list(
        options.features_threads, '--features-threads')[0]
    options.decode_depths = sorted({int(part) for part in options.decode_depths.split(',') if part.strip()})
    if any(value < 0 for value in options.decode_depths) or not options.decode_depths:
        raise HarnessError('--decode-depths takes whole numbers of 0 or more')
    if 'warm' not in options.caches:
        raise HarnessError('--cache must include warm')
    for name in ('warmups', 'runs_fast', 'runs_slow', 'long_runs'):
        if getattr(options, name) < (0 if name == 'warmups' else 1):
            raise HarnessError('--%s is too small' % name.replace('_', '-'))
    if options.runs is not None and options.runs < 1:
        raise HarnessError('--runs must be at least 1')
    for name in ('timeout', 'max_hours'):
        value = getattr(options, name)
        if not (value > 0 and math.isfinite(value)):
            raise HarnessError('--%s must be a finite number more than 0' % name.replace('_', '-'))


def main_score(options):
    if options.run:
        result = score_run(os.path.abspath(options.run), options.seed, options.score_hours)
        output = os.path.abspath(options.output or options.run)
    else:
        if not options.left or not options.target:
            raise HarnessError('score needs --run, or --left (and optionally --right) with --target')
        result = score_adhoc(options)
        if not options.output:
            raise HarnessError('ad hoc score needs --output')
        output = os.path.abspath(options.output)
    private_dir(output)
    write_json(os.path.join(output, 'score.json'), result, exclusive=False)
    write_private(os.path.join(output, 'score.md'), score_markdown(result).encode(), exclusive=False)
    if options.run and os.path.abspath(output) == os.path.abspath(options.run):
        report_write(output, options.seed)
    for comparison in result['comparisons'][:50]:
        print('%s vs %s: matched %d, only left %d %s, only right %d %s' % (
            comparison['left'], comparison['right'], comparison['matched'], len(comparison['only_left']),
            comparison['only_left_by_hint'], len(comparison['only_right']), comparison['only_right_by_hint']))
    for quality in result['quality']:
        overall = quality['overall']
        print('%s: TP %d FN %d FP-neg %d unlabeled %d unknown %d recall %s precision %s' % (
            quality['name'], overall['true_positive'], overall['false_negative'], overall['false_positive_on_negative'],
            overall['unlabeled_findings'], overall['unknown_findings'], report_rate(overall['recall']),
            report_rate(overall['precision_strict'])))
    print('wrote %s' % os.path.join(output, 'score.md'), file=sys.stderr)
    return 0


def comparison_main(arguments):
    parser = main_parser()
    options = parser.parse_args(arguments)
    try:
        if options.command == 'run':
            main_normalize(options)
            return run_command(options)
        if options.command == 'score':
            return main_score(options)
        if options.command == 'report':
            return report_command(options)
        if options.command == 'self-test':
            return selftest_main()
        parser.print_usage(sys.stderr)
        return 2
    except HarnessError as error:
        print('compare: %s' % error, file=sys.stderr)
        return 1


sys.exit(comparison_main(sys.argv[1:]))
