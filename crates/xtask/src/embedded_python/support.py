# Helpers shared by `cargo xtask compare`, `compare-quality` and
# `compare-workloads`.
#
# Python 3.9 standard library only. xtask (embedded_python.rs) runs this file
# first and then the modules of one tool, all in one global namespace, with
# `python3 -I -`. The program is read from standard input.
import hashlib
import os
import signal
import subprocess

# Schema of a workload manifest, written by compare-quality and
# compare-workloads and read by compare.
WORKLOADS_SCHEMA = 'rustleaks-comparison-workloads-v1'

# Fields of one labels file row, in order. Workload sets may add more fields
# after these.
LABEL_FIELDS = ('workload', 'path', 'commit', 'start', 'end', 'line', 'secret_sha256',
                'category', 'label', 'source')


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def line_of(data, offset):
    """One-based line of a byte offset in a label's `line` field.

    Only `\\n` ends a line, so `\\r\\n` counts once and a lone `\\r` does not
    count. The scanners and the scorer count lines the same way."""
    return data.count(b'\n', 0, offset) + 1


def stop_process_group(process, wait):
    """Kill a process started with `start_new_session=True` and everything it
    started, then collect it. Pipes that a process outside the group still
    holds are closed after `wait` seconds."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        process.kill()
    try:
        process.communicate(timeout=wait)
    except (subprocess.TimeoutExpired, ValueError):
        for pipe in (process.stdout, process.stderr):
            if pipe is not None:
                pipe.close()
        try:
            process.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            pass
