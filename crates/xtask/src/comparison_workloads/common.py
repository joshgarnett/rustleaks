# Python 3.9 standard library only. Shared helpers for `cargo xtask
# compare-workloads`. xtask (embedded_python.rs) runs
# embedded_python/support.py and then the modules in this folder in a fixed
# order, in one global namespace, with `python3 -I -`.
import argparse
import array
import base64
import hashlib
import io
import json
import math
import os
import pathlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import zlib

INVENTORY_SCHEMA = 'rustleaks-comparison-inventory-v1'
FETCH_SCHEMA = 'rustleaks-comparison-fetch-v1'
MANIFEST_DIRECTORY = 'benchmarks/comparison/workloads'


class WorkloadError(Exception):
    pass


def fail(message):
    raise WorkloadError(message)


def git_blob_sha1(data):
    return hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def write_json(path, value):
    path = pathlib.Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.partial')
    temporary.write_text(json.dumps(value, indent=1, sort_keys=True, ensure_ascii=True) + '\n',
                         encoding='ascii')
    os.replace(temporary, path)


def read_json(path):
    with open(path, 'rb') as stream:
        return json.loads(stream.read().decode('utf-8'))


def print_line(text):
    sys.stdout.write(text + '\n')
    sys.stdout.flush()


# Deterministic byte stream. SHAKE-256 output in 1 MiB chunks gives the same
# values on every platform and Python version, unlike `random`.
class Stream:
    CHUNK = 1 << 20

    def __init__(self, label):
        self.seed = hashlib.sha256(label.encode('utf-8')).digest()
        self.counter = 0
        self.words = array.array('I')
        self.index = 0
        if self.words.itemsize != 4:
            fail('this platform has no 32-bit unsigned array type')

    def _refill(self):
        data = hashlib.shake_256(self.seed + self.counter.to_bytes(8, 'big')).digest(self.CHUNK)
        self.counter += 1
        words = array.array('I')
        words.frombytes(data)
        if sys.byteorder != 'little':
            words.byteswap()
        self.words = words
        self.index = 0

    def u32(self):
        if self.index >= len(self.words):
            self._refill()
        value = self.words[self.index]
        self.index += 1
        return value

    def below(self, bound):
        return self.u32() % bound

    def between(self, low, high):
        return low + self.below(high - low + 1)

    def choice(self, items):
        return items[self.below(len(items))]

    def text(self, alphabet, count):
        size = len(alphabet)
        return ''.join(alphabet[self.u32() % size] for _ in range(count))

    def raw(self, count):
        out = bytearray()
        while len(out) < count:
            out += self.u32().to_bytes(4, 'little')
        return bytes(out[:count])


# Cache and path safety.

def resolve_cache(cache, source_root):
    if not cache:
        fail('--cache DIR is required')
    path = pathlib.Path(cache).expanduser()
    if not path.is_absolute():
        path = pathlib.Path.cwd() / path
    path = pathlib.Path(os.path.abspath(str(path)))
    if path.is_symlink():
        fail('the cache folder must not be a symlink: %s' % path)
    # Compare file identities, not path text: on a case-insensitive file
    # system a differently cased path can name the repository.
    real = pathlib.Path(os.path.realpath(str(path)))
    for candidate in [real] + list(real.parents):
        if candidate.exists() and os.path.samefile(str(candidate), str(source_root)):
            fail('the cache folder must be outside the repository: %s' % path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def safe_relative(path):
    # Fixture paths come from upstream data. Keep them inside their case
    # folder: drop a leading slash and reject empty or parent components.
    text = path.replace('\\', '/').lstrip('/')
    parts = [part for part in text.split('/') if part not in ('', '.')]
    if not parts or any(part == '..' for part in parts):
        fail('unsafe fixture path: %r' % path)
    return '/'.join(parts)


def write_file(root, relative, data, mode=0o600):
    path = pathlib.Path(root) / relative
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(path, 'xb') as stream:
        stream.write(data)
    path.chmod(mode)
    return path


def remove_tree(path):
    path = pathlib.Path(path)
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        for directory, directories, files in os.walk(path):
            for name in directories:
                os.chmod(os.path.join(directory, name), 0o700)
        shutil.rmtree(path)


def fresh_directory(path):
    path = pathlib.Path(path)
    remove_tree(path)
    path.mkdir(mode=0o700, parents=True)
    return path


# Inventories describe every regular file and symlink under a workload root.
# `.git` storage is summarised by refs and commits, not by pack bytes, because
# pack layout depends on the Git version.

def file_inventory(root, skip_git=True):
    root = pathlib.Path(root)
    entries = []
    total = 0
    for directory, directories, files in os.walk(root):
        if skip_git:
            directories[:] = sorted(name for name in directories if name != '.git')
        else:
            directories[:] = sorted(directories)
        for name in sorted(files):
            if skip_git and name == '.git':
                continue
            path = pathlib.Path(directory) / name
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(path).encode('utf-8', 'surrogateescape')
                entries.append({'path': relative, 'type': 'symlink', 'bytes': len(target),
                                'sha256': sha256_bytes(target)})
            elif stat.S_ISREG(metadata.st_mode):
                entries.append({'path': relative, 'type': 'file', 'bytes': metadata.st_size,
                                'sha256': sha256_file(path)})
                total += metadata.st_size
            else:
                fail('unexpected file type in workload: %s' % path)
        for name in list(directories):
            path = pathlib.Path(directory) / name
            if path.is_symlink():
                target = os.readlink(path).encode('utf-8', 'surrogateescape')
                entries.append({'path': path.relative_to(root).as_posix(), 'type': 'symlink',
                                'bytes': len(target), 'sha256': sha256_bytes(target)})
                directories.remove(name)
    entries.sort(key=lambda item: item['path'])
    return {'files': entries, 'file_count': len(entries), 'bytes': total,
            'files_sha256': sha256_bytes(canonical_json(entries))}


# Git helpers. Every call gets a clean environment without user or system
# configuration, hooks or prompts.

def git_environment(home):
    home = pathlib.Path(home)
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = {
        'HOME': str(home), 'XDG_CONFIG_HOME': str(home),
        'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
        'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
        'GIT_ATTR_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
        'GIT_OPTIONAL_LOCKS': '0', 'GIT_CONFIG_COUNT': '0',
        'GIT_AUTHOR_NAME': 'Synthetic Benchmark',
        'GIT_AUTHOR_EMAIL': 'benchmark@example.invalid',
        'GIT_COMMITTER_NAME': 'Synthetic Benchmark',
        'GIT_COMMITTER_EMAIL': 'benchmark@example.invalid',
        'GIT_AUTHOR_DATE': '946684800 +0000',
        'GIT_COMMITTER_DATE': '946684800 +0000'}
    for name in ('SSL_CERT_FILE', 'SSL_CERT_DIR', 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY',
                 'https_proxy', 'http_proxy', 'no_proxy'):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def require_posix(command):
    if os.name != 'posix':
        fail('%s is supported on macOS and Linux only' % command)


def find_git(explicit=None):
    candidate = explicit or shutil.which('git')
    if not candidate:
        fail('git was not found on PATH')
    return str(pathlib.Path(candidate).resolve())


GIT_FLAGS = ['-c', 'core.logAllRefUpdates=false', '-c', 'gc.auto=0', '-c', 'core.autocrlf=false',
             '-c', 'core.hooksPath=' + os.devnull, '-c', 'advice.detachedHead=false',
             '-c', 'init.defaultBranch=main']


# Every git call has a time limit, so no step can wait forever. The limits are
# far above the time any pinned repository needs. Network calls also stop when
# the transfer stays under 1000 bytes per second for 120 seconds.
GIT_LOCAL_TIMEOUT = 6 * 3600
GIT_NETWORK_TIMEOUT = 4 * 3600
GIT_NETWORK_FLAGS = ['-c', 'http.lowSpeedLimit=1000', '-c', 'http.lowSpeedTime=120']
GIT_STOP_WAIT = 60


def git_run(git, repository, environment, arguments, stdin=None, timeout=None, stdout=None, network=False):
    if timeout is None:
        timeout = GIT_NETWORK_TIMEOUT if network else GIT_LOCAL_TIMEOUT
    command = ([git] + GIT_FLAGS + (GIT_NETWORK_FLAGS if network else [])
               + (['-C', str(repository)] if repository else []) + arguments)
    process = subprocess.Popen(command, env=environment, stdin=stdin,
                               stdout=subprocess.PIPE if stdout is None else stdout,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        output, errors = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_process_group(process, GIT_STOP_WAIT)
        fail('git %s did not finish in %d seconds' % (' '.join(arguments[:3]), timeout))
    except BaseException:
        stop_process_group(process, GIT_STOP_WAIT)
        raise
    if process.returncode:
        fail('git %s failed: %s' % (' '.join(arguments[:3]), errors.decode('utf-8', 'replace')[-2000:]))
    return output


def git_text(git, repository, environment, arguments):
    return git_run(git, repository, environment, arguments).decode('utf-8', 'replace').strip()


def git_refs(git, repository, environment):
    text = git_text(git, repository, environment, ['for-each-ref', '--format=%(objectname) %(refname)'])
    return sorted(line for line in text.splitlines() if line)


def git_summary(git, repository, environment):
    head = git_text(git, repository, environment, ['rev-parse', 'HEAD'])
    refs = git_refs(git, repository, environment)
    commits = git_text(git, repository, environment, ['rev-list', '--all']).split()
    return {'head': head, 'refs': refs, 'commit_count': len(commits),
            'commits_sha256': sha256_bytes(('\n'.join(sorted(commits)) + '\n').encode('ascii')),
            'refs_sha256': sha256_bytes(('\n'.join(refs) + '\n').encode('ascii'))}


# Labels.

def make_label(workload, path, data, start, end, category, label, source='constructed',
               commit=None, secret=None, **extra):
    # Byte offsets index the file at that commit. `secret_sha256` hashes the
    # secret value: the labeled bytes, or the decoded value for encoded text.
    if not 0 <= start <= end <= len(data):
        fail('label range outside its file: %s %d..%d' % (path, start, end))
    value = data[start:end] if secret is None else secret
    record = {'workload': workload, 'path': path, 'commit': commit, 'start': start, 'end': end,
              'line': line_of(data, start),
              'end_line': line_of(data, max(start, end - 1)),
              'secret_sha256': sha256_bytes(value), 'category': category, 'label': label,
              'source': source}
    record.update(extra)
    return record


def write_labels(path, labels):
    path = pathlib.Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.partial')
    with open(temporary, 'wb') as stream:
        for record in labels:
            stream.write(canonical_json(record) + b'\n')
    os.replace(temporary, path)
    return sha256_file(path)


def load_manifest(source_root, name):
    path = pathlib.Path(source_root) / MANIFEST_DIRECTORY / (name + '.json')
    manifest = read_json(path)
    if manifest.get('schema') != WORKLOADS_SCHEMA or manifest.get('set') != name:
        fail('unexpected workload manifest: %s' % path)
    seen = set()
    for workload in manifest['workloads']:
        if workload['id'] in seen:
            fail('duplicate workload id %s in %s' % (workload['id'], path))
        seen.add(workload['id'])
    return manifest


def select_workloads(manifest, only):
    if not only:
        return list(manifest['workloads'])
    wanted = [item for item in only.split(',') if item]
    known = {workload['id']: workload for workload in manifest['workloads']}
    missing = [item for item in wanted if item not in known]
    if missing:
        fail('unknown workload ids: %s' % ', '.join(missing))
    return [known[item] for item in wanted]
