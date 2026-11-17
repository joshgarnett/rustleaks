# Comparison harness: shared helpers.
#
# The xtask binary embeds every file in this folder and runs them with
# `python3 -I`. Only the Python 3.9 standard library is used. The modules share
# one global namespace, so names carry a module prefix where they could clash.
import argparse
import collections
import contextlib
import datetime
import difflib
import hashlib
import io
import json
import math
import os
import platform
import random
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

SCHEMA_TOOLS = 'rustleaks-comparison-tools-v1'
SCHEMA_WORKLOADS = 'rustleaks-comparison-workloads-v1'
SCHEMA_RUN = 'rustleaks-comparison-run-v1'
SCHEMA_SAMPLE = 'rustleaks-comparison-sample-v1'
SCHEMA_SUMMARY = 'rustleaks-comparison-summary-v1'
SCHEMA_SCORE = 'rustleaks-comparison-score-v1'
FAMILIES = ('rustleaks', 'gitleaks', 'betterleaks', 'kingfisher')
MODES = ('dir', 'git')
DEFAULT_SEED = 20261117
SYSTEM_PATH = '/usr/bin:/bin:/usr/sbin:/sbin'


class HarnessError(Exception):
    """A problem with inputs or the environment. The message is printed."""


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_text(text):
    return sha256_bytes(text.encode('utf-8', 'surrogatepass'))


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def json_bytes(value, pretty=False):
    if pretty:
        return (json.dumps(value, sort_keys=True, indent=1, ensure_ascii=False) + '\n').encode('utf-8')
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def write_private(path, data, exclusive=True):
    """Write bytes to a file readable only by the owner."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    descriptor = os.open(str(path), flags, 0o600)
    with os.fdopen(descriptor, 'wb') as handle:
        handle.write(data)


def write_json(path, value, exclusive=True):
    write_private(path, json_bytes(value, pretty=True), exclusive)


def read_json(path):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)


def append_jsonl(path, value):
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, 'ab') as handle:
        handle.write(json_bytes(value) + b'\n')


def read_jsonl(path):
    rows = []
    with open(path, encoding='utf-8') as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError as error:
                raise HarnessError('%s line %d is not JSON: %s' % (path, number, error))
    return rows


def private_dir(path):
    os.makedirs(str(path), mode=0o700, exist_ok=True)
    os.chmod(str(path), 0o700)
    return path


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def load_average():
    try:
        return [round(value, 2) for value in os.getloadavg()]
    except OSError:
        return None


def slug(text):
    return re.sub(r'[^A-Za-z0-9._-]+', '_', text).strip('_')[:150]


def run_text(argv, timeout=20, env=None, cwd=None):
    """Run a short probe and return (exit code, stdout text, stderr text)."""
    try:
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=timeout,
                                   env=env if env is not None else {'PATH': SYSTEM_PATH, 'LC_ALL': 'C'},
                                   cwd=cwd)
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, '', str(error)
    return (completed.returncode, completed.stdout.decode('utf-8', 'replace'),
            completed.stderr.decode('utf-8', 'replace'))


def sysctl(name):
    code, out, _ = run_text(['/usr/sbin/sysctl', '-n', name])
    return out.strip() if code == 0 and out.strip() else None


def host_details():
    """Describe the host without its name or any user data."""
    details = {'platform': sys.platform, 'machine': platform.machine(),
               'kernel_release': platform.release(), 'python': platform.python_version(),
               'logical_cpus': os.cpu_count()}
    if sys.platform == 'darwin':
        details.update({
            'model': sysctl('hw.model'), 'cpu': sysctl('machdep.cpu.brand_string'),
            'performance_cores': sysctl('hw.perflevel0.physicalcpu'),
            'efficiency_cores': sysctl('hw.perflevel1.physicalcpu'),
            'memory_bytes': int(sysctl('hw.memsize') or 0) or None})
        code, out, _ = run_text(['/usr/bin/sw_vers', '-productVersion'])
        details['os'] = 'macOS ' + out.strip() if code == 0 else None
        code, out, _ = run_text(['/usr/bin/sw_vers', '-buildVersion'])
        details['os_build'] = out.strip() if code == 0 else None
    elif sys.platform.startswith('linux'):
        try:
            with open('/proc/cpuinfo', encoding='utf-8', errors='replace') as handle:
                models = re.findall(r'^model name\s*:\s*(.+)$', handle.read(), re.M)
            details['cpu'] = models[0] if models else None
        except OSError:
            details['cpu'] = None
        try:
            with open('/proc/meminfo', encoding='utf-8') as handle:
                match = re.search(r'^MemTotal:\s*(\d+) kB', handle.read(), re.M)
            details['memory_bytes'] = int(match.group(1)) * 1024 if match else None
        except OSError:
            details['memory_bytes'] = None
        try:
            with open('/etc/os-release', encoding='utf-8') as handle:
                match = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', handle.read(), re.M)
            details['os'] = match.group(1) if match else None
        except OSError:
            details['os'] = None
    return details


def thermal_state():
    """Return a short thermal note where the platform offers one without root."""
    if sys.platform == 'darwin' and os.path.exists('/usr/bin/pmset'):
        code, out, _ = run_text(['/usr/bin/pmset', '-g', 'therm'])
        if code == 0:
            lines = [line.strip() for line in out.splitlines() if line.strip()]
            return '; '.join(lines)[:400]
    return 'not recorded on this platform'


BUILD_PROCESS_NAMES = {'cargo', 'rustc', 'bazel', 'bazelisk', 'clang', 'clang++', 'gcc', 'g++',
                       'ld', 'ninja', 'make', 'go', 'java'}


def background_builds():
    """Count build tool processes that are not ancestors of this harness."""
    code, out, _ = run_text(['/bin/ps', '-axo', 'pid=,ppid=,comm='])
    if code != 0:
        return None
    processes = {}
    for line in out.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            processes[int(parts[0])] = (int(parts[1]), os.path.basename(parts[2]))
    ancestors = set()
    pid = os.getpid()
    while pid in processes and pid not in ancestors:
        ancestors.add(pid)
        pid = processes[pid][0]
    counts = collections.Counter(name for pid, (_, name) in processes.items()
                                 if pid not in ancestors and name in BUILD_PROCESS_NAMES)
    return dict(sorted(counts.items()))


def resolve_git(explicit=None):
    """Find the real Git executable. On macOS, skip the /usr/bin trampoline."""
    if explicit:
        path = os.path.abspath(explicit)
    else:
        path = None
        if sys.platform == 'darwin' and os.path.exists('/usr/bin/xcrun'):
            code, out, _ = run_text(['/usr/bin/xcrun', '--find', 'git'])
            if code == 0 and out.strip():
                path = out.strip()
        if path is None:
            path = shutil.which('git', path=os.environ.get('PATH', SYSTEM_PATH))
    if not path or not os.access(path, os.X_OK):
        return None
    path = os.path.realpath(path)
    code, out, _ = run_text([path, '--version'])
    return {'path': path, 'sha256': sha256_file(path),
            'version': out.strip() if code == 0 else None}


def number_list(text, name):
    values = []
    for part in text.split(','):
        part = part.strip()
        if not part:
            continue
        if part == 'all':
            values.append(os.cpu_count() or 1)
        elif part.isdigit() and int(part) > 0:
            values.append(int(part))
        else:
            raise HarnessError('%s takes positive whole numbers or "all", not %r' % (name, part))
    return sorted(set(values))


def word_list(text, allowed, name):
    values = [part.strip() for part in text.split(',') if part.strip()]
    unknown = [value for value in values if value not in allowed]
    if unknown:
        raise HarnessError('unknown %s: %s (allowed: %s)' % (name, ', '.join(unknown), ', '.join(allowed)))
    return values
