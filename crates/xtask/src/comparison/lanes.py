# Comparison harness: lanes and the cell plan.
#
# A cell is one tool with one set of settings on one workload, mode and cache
# state. Cells in the same group are compared with each other.

LANES = ('defaults', 'threads', 'features', 'shared-rules', 'rustleaks-2x2')

LANE_PURPOSE = {
    'defaults': 'Each tool exactly as shipped: default rules, threads, decode, archive and dedup settings. Validation off.',
    'threads': 'Default rules with the same thread count for every tool, through each tool\'s own mechanism.',
    'features': 'Default rules with the same decode and archive depths for every tool; archives off, then on; Kingfisher dedup on and off.',
    'shared-rules': 'A small common synthetic rule set loaded into every tool, fixed depths, 1 and 4 threads.',
    'rustleaks-2x2': 'Rustleaks only: native packs on or off times --complete-profile on or off, 1 and 4 workers.',
}


def lanes_variants(lane, options, tool):
    """Yield (variant, sub, group_variant, settings) for one tool in one lane."""
    adapter = tool['adapter']
    if lane == 'defaults':
        yield 'default', None, 'default', {}
    elif lane == 'threads':
        for threads in options.threads:
            yield 't%d' % threads, None, 't%d' % threads, {'threads': threads}
    elif lane == 'features':
        depth_on = options.archive_depth_on
        top = max(options.decode_depths)
        combos = [(decode, 0) for decode in options.decode_depths] + [(top, depth_on)]
        for decode, archive in combos:
            variant = 'd%d-a%d' % (decode, archive)
            settings = {'decode': decode, 'archive': archive}
            if options.features_threads:
                settings['threads'] = options.features_threads
            if adapter == 'kingfisher':
                for dedup in (True, False):
                    sub_settings = dict(settings, dedup=dedup)
                    yield variant, 'dedup-on' if dedup else 'dedup-off', variant, sub_settings
            else:
                yield variant, None, variant, settings
    elif lane == 'shared-rules':
        for threads in options.shared_threads:
            settings = {'rules': 'shared', 'threads': threads, 'decode': 0, 'archive': 0}
            if adapter == 'kingfisher':
                settings['dedup'] = False
            yield 'rules-t%d' % threads, None, 'rules-t%d' % threads, settings
    elif lane == 'rustleaks-2x2':
        if adapter != 'rustleaks':
            return
        for threads in options.shared_threads:
            for packs in (False, True):
                for profile in (False, True):
                    if threads != 1 and not profile:
                        continue
                    variant = 'packs-%s.profile-%s.t%d' % ('on' if packs else 'off', 'on' if profile else 'off', threads)
                    settings = {'packs': packs, 'profile': profile}
                    if profile:
                        settings['threads'] = threads
                    yield variant, None, 'all', settings


def lanes_plan(tools, workloads, options):
    cells = []
    for workload in workloads:
        for mode in workload['modes']:
            if mode not in options.modes:
                continue
            for lane in options.lanes:
                caches = options.caches if lane in options.cold_lanes else ['warm']
                for tool in tools:
                    for variant, sub, group_variant, settings in lanes_variants(lane, options, tool):
                        for cache in caches:
                            label = variant + ('/' + sub if sub else '')
                            cells.append({
                                'cell_id': '/'.join((lane, label, tool['id'], workload['id'], mode, cache)),
                                'lane': lane, 'variant': variant, 'sub': sub, 'settings': settings,
                                'tool': tool['id'], 'family': tool['family'], 'adapter': tool['adapter'],
                                'workload': workload['id'], 'mode': mode, 'cache': cache,
                                'group': '/'.join((lane, group_variant, workload['id'], mode)),
                                'baseline_key': (lane == 'rustleaks-2x2' and variant == 'packs-off.profile-off.t1')
                                or (lane != 'rustleaks-2x2' and sub in (None, 'dedup-on'))})
    return cells


def lanes_baselines(cells, baseline_tool):
    """Pick one baseline cell per (group, cache)."""
    chosen = {}
    for cell in cells:
        if not cell['baseline_key'] or cell.get('status') not in ('ok', 'partial'):
            continue
        key = (cell['group'], cell['cache'])
        rank = 0 if cell['tool'] == baseline_tool else 1 if cell['family'] == 'rustleaks' else 2
        if key not in chosen or rank < chosen[key][0]:
            chosen[key] = (rank, cell['cell_id'])
    return {key: value[1] for key, value in chosen.items()}
