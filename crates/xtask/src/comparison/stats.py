# Comparison harness: statistics.

BOOTSTRAP_RESAMPLES = 2000


def stats_median(values):
    ordered = sorted(values)
    count = len(ordered)
    if not count:
        return None
    middle = count // 2
    return ordered[middle] if count % 2 else (ordered[middle - 1] + ordered[middle]) / 2


def stats_mad(values):
    """Median absolute deviation, unscaled."""
    center = stats_median(values)
    return None if center is None else stats_median([abs(value - center) for value in values])


def stats_bimodal(values):
    """Flag samples that split into two separated groups.

    The rule: sort the samples and split them at the largest gap between
    neighbours. The cell is flagged when that gap is at least 3 times the
    larger MAD of the two groups and at least 5 percent of the median, and
    the smaller group holds at least 15 percent of the samples. Needs 8 or
    more samples.
    """
    count = len(values)
    if count < 8:
        return {'flag': False, 'reason': 'fewer than 8 samples'}
    ordered = sorted(values)
    gap, split = max((ordered[index + 1] - ordered[index], index + 1) for index in range(count - 1))
    spread = max(stats_mad(ordered[:split]), stats_mad(ordered[split:]))
    center = stats_median(ordered)
    smaller_side = min(split, count - split)
    flag = (gap > 0 and gap >= 3 * spread and gap >= 0.05 * abs(center)
            and smaller_side >= math.ceil(0.15 * count))
    return {'flag': bool(flag), 'largest_gap': gap, 'low_group': split, 'high_group': count - split}


def stats_summary(values):
    values = [value for value in values if value is not None]
    if not values:
        return None
    return {'n': len(values), 'median': stats_median(values), 'mad': stats_mad(values),
            'min': min(values), 'max': max(values), 'bimodal': stats_bimodal(values)}


def stats_ratio_interval(numerator, denominator, seed, resamples=BOOTSTRAP_RESAMPLES):
    """Ratio of medians with a percentile bootstrap 95 percent interval.

    Each side is resampled with replacement on its own. The random generator
    is seeded, so the interval is the same on every run of the report.
    """
    numerator = [value for value in numerator if value is not None]
    denominator = [value for value in denominator if value is not None]
    if not numerator or not denominator:
        return None
    base = stats_median(denominator)
    if not base:
        return None
    generator = random.Random(seed)
    ratios = []
    for _ in range(resamples):
        top = stats_median([generator.choice(numerator) for _ in numerator])
        bottom = stats_median([generator.choice(denominator) for _ in denominator])
        if bottom:
            ratios.append(top / bottom)
    ratios.sort()
    if not ratios:
        return None
    low = ratios[int(math.floor(0.025 * (len(ratios) - 1)))]
    high = ratios[int(math.ceil(0.975 * (len(ratios) - 1)))]
    return {'ratio': stats_median(numerator) / base, 'low': low, 'high': high,
            'resamples': resamples, 'seed': seed}
