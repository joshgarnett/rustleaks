# Comparison harness: process measurement.
#
# What is measured, per sample:
# - wall time from spawn to the return of wait4 for the scanner process;
# - user and system CPU time from the wait4 rusage. On macOS and Linux this
#   includes descendants that the scanner itself waited for (for example git);
# - peak RSS from the same rusage. It is the largest single process among the
#   scanner and its waited-for descendants, not the sum of processes that ran
#   at the same time.
# Child processes are measured on their own only in an extra instrumented run
# that puts a git shim on PATH (see measure_git_shim). That run also samples
# the resident size of the scanner process alone every 10 ms
# (scanner_peak_rss_bytes), because the wait4 peak can be the peak of a git
# child.
#
# Limits: a watchdog kills the process group after the sample timeout, or
# when the logs or the report pass their size limits, and repeats the kill
# every second. If the process is still not reaped MEASURE_GRACE_SECONDS
# after the first kill, the watchdog interrupts the wait in the main thread
# and the sample is recorded as unreaped, so no sample waits forever. None of
# this is on the timed path of a sample that ends by itself.

MEASURE_REPORT_LIMIT = 4 << 30
MEASURE_LOG_LIMIT = 64 << 20
MEASURE_GRACE_SECONDS = 60
MEASURE_SURVIVOR_WAIT_SECONDS = 2
MEASURE_INTERRUPT = signal.SIGUSR1
MEASURE_RSS_INTERVAL = 0.01


class MeasureUnreaped(Exception):
    """Raised in the main thread when the watchdog stops waiting for a child."""


def measure_kill_group(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
        return True
    except OSError:
        return False


def measure_kill_process(pid):
    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except OSError:
        return False


def measure_group_alive(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        # macOS can deny signals to a group whose leader is gone. Treat it as
        # unknown and let the caller record that it could not check.
        return None


def measure_rss_reader():
    """Return a function that gives the resident bytes of one process, or None."""
    if sys.platform == 'darwin':
        import ctypes
        import ctypes.util
        import struct
        try:
            lib = ctypes.CDLL(ctypes.util.find_library('proc') or '/usr/lib/libproc.dylib')
        except OSError:
            return None
        buffer = ctypes.create_string_buffer(512)

        def read(pid):
            # proc_pid_rusage with RUSAGE_INFO_V2; ri_resident_size follows the
            # 16-byte UUID and six 64-bit fields.
            if lib.proc_pid_rusage(ctypes.c_int(pid), ctypes.c_int(2), buffer) != 0:
                return None
            return struct.unpack_from('<Q', buffer.raw, 16 + 6 * 8)[0]
        return read
    if os.path.isdir('/proc/self'):
        def read(pid):
            # VmHWM is the kernel's own high-water mark for the process.
            try:
                with open('/proc/%d/status' % pid, 'rb') as status:
                    for line in status:
                        if line.startswith(b'VmHWM:'):
                            return int(line.split()[1]) * 1024
            except (OSError, ValueError, IndexError):
                return None
            return None
        return read
    return None


def measure_execute(argv, env, cwd, stdout_path, stderr_path, timeout, watch_paths=(), grace=None,
                    track_rss=False):
    """Run one scanner process in its own session and measure it with wait4.

    Call it from the main thread. Only there can the watchdog interrupt the
    wait for a process that SIGKILL does not end."""
    grace = MEASURE_GRACE_SECONDS if grace is None else grace
    boundary = []
    gave_up = threading.Event()
    in_main = threading.current_thread() is threading.main_thread()

    def interrupt(signum, frame):
        if gave_up.is_set():
            raise MeasureUnreaped()

    previous = signal.signal(MEASURE_INTERRUPT, interrupt) if in_main else None
    try:
        return measure_wait(argv, env, cwd, stdout_path, stderr_path, timeout, watch_paths, grace, boundary,
                            gave_up if in_main else None, measure_rss_reader() if track_rss else None)
    except MeasureUnreaped:
        return {'status': (boundary[0] if boundary else 'timeout') + '-unreaped', 'exit_code': None,
                'error': 'the process was not reaped %g s after it was killed' % grace}
    finally:
        if previous is not None:
            signal.signal(MEASURE_INTERRUPT, previous)


def measure_wait(argv, env, cwd, stdout_path, stderr_path, timeout, watch_paths, grace, boundary, gave_up,
                 rss_reader=None):
    finished = threading.Event()
    scanner_rss = []
    main_thread = threading.main_thread().ident
    with open(stdout_path, 'xb') as out, open(stderr_path, 'xb') as err:
        os.chmod(stdout_path, 0o600)
        os.chmod(stderr_path, 0o600)
        start = time.perf_counter_ns()
        try:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                     cwd=cwd, env=env, start_new_session=True)
        except OSError as error:
            return {'status': 'spawn-failed', 'error': str(error)[:300]}

        def stop():
            if not measure_kill_group(child.pid):
                measure_kill_process(child.pid)

        def watchdog():
            stopped_at = None
            last_kill = None
            while not finished.wait(0.05):
                try:
                    now = time.perf_counter_ns()
                    if stopped_at is None:
                        reason = None
                        if now - start > timeout * 1e9:
                            reason = 'timeout'
                        else:
                            try:
                                if (os.fstat(out.fileno()).st_size > MEASURE_LOG_LIMIT
                                        or os.fstat(err.fileno()).st_size > MEASURE_LOG_LIMIT
                                        or any(os.path.exists(path) and os.path.getsize(path) > MEASURE_REPORT_LIMIT
                                               for path in watch_paths)):
                                    reason = 'output-limit'
                            except OSError:
                                pass
                        if reason:
                            boundary.append(reason)
                            stopped_at = last_kill = now
                            stop()
                    elif gave_up is not None and now - stopped_at > grace * 1e9:
                        # SIGKILL did not end the process. Interrupt the wait
                        # in the main thread instead of blocking forever.
                        gave_up.set()
                        signal.pthread_kill(main_thread, MEASURE_INTERRUPT)
                        return
                    elif now - last_kill > 1e9:
                        last_kill = now
                        stop()
                except Exception:
                    # A failed check or kill must not end the watchdog.
                    pass

        def sample_rss():
            # Runs only in the untimed instrumented run. Reading a process
            # that has exited gives None and is ignored.
            while True:
                try:
                    value = rss_reader(child.pid)
                    if value is not None and (not scanner_rss or value > scanner_rss[0]):
                        scanner_rss[:] = [value]
                except Exception:
                    pass
                if finished.wait(MEASURE_RSS_INTERVAL):
                    return

        watcher = threading.Thread(target=watchdog, daemon=True)
        watcher.start()
        sampler = None
        if rss_reader is not None:
            sampler = threading.Thread(target=sample_rss, daemon=True)
            sampler.start()
        try:
            _, status, usage = os.wait4(child.pid, 0)
            end = time.perf_counter_ns()
        finally:
            finished.set()
            watcher.join()
            if sampler is not None:
                sampler.join()
        child.returncode = os.waitstatus_to_exitcode(status)
    leftover = measure_group_alive(child.pid)
    survivors = False
    if leftover:
        boundary.append('orphan-descendants')
        measure_kill_group(child.pid)
        survivors = measure_group_survivors(child.pid)
    rss_scale = 1 if sys.platform == 'darwin' else 1024
    result = {'status': boundary[0] if boundary else 'exited',
              'exit_code': child.returncode,
              'wall_ns': end - start,
              'cpu_user_ns': int(round(usage.ru_utime * 1e9)),
              'cpu_system_ns': int(round(usage.ru_stime * 1e9)),
              'peak_rss_bytes': usage.ru_maxrss * rss_scale,
              'group_cleanup_checked': leftover is not None}
    if rss_reader is not None:
        result['scanner_peak_rss_bytes'] = scanner_rss[0] if scanner_rss else None
    if survivors is not False:
        # True: processes of the group were still there after SIGKILL and a
        # short wait. None: the check was denied.
        result['group_survivors_after_kill'] = survivors
    return result


def measure_group_survivors(pid):
    """Kill and check a process group again until it is gone or a short wait ends.

    macOS can deny the check for a moment while a killed member is reaped, so
    a denied check is retried like a live group. The result is None only when
    every check until the deadline was denied.
    """
    deadline = time.monotonic() + MEASURE_SURVIVOR_WAIT_SECONDS
    while True:
        alive = measure_group_alive(pid)
        if alive is False or time.monotonic() > deadline:
            return alive
        time.sleep(0.05)
        measure_kill_group(pid)


GIT_SHIM = r'''#!%(python)s -I
# Generated by the comparison harness for an instrumented, untimed run.
import json, os, signal, sys, time
real = %(real)r
log = %(log)r
limit = %(limit)d
grace = %(grace)d
start = time.perf_counter_ns()
pid = os.fork()
if pid == 0:
    try:
        os.execv(real, [real] + sys.argv[1:])
    finally:
        os._exit(127)
expired = []


def expire(signum, frame):
    # Past the limit, kill git. If that does not end the wait, stop waiting.
    if expired:
        os._exit(124)
    expired.append(True)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    signal.alarm(grace)


signal.signal(signal.SIGALRM, expire)
signal.alarm(limit)
_, status, usage = os.wait4(pid, 0)
signal.alarm(0)
end = time.perf_counter_ns()
code = os.waitstatus_to_exitcode(status)
scale = 1 if sys.platform == 'darwin' else 1024
record = {'wall_ns': end - start, 'cpu_user_ns': int(usage.ru_utime * 1e9),
          'cpu_system_ns': int(usage.ru_stime * 1e9), 'peak_rss_bytes': usage.ru_maxrss * scale,
          'subcommand': next((arg for arg in sys.argv[1:] if not arg.startswith('-')), ''),
          'exit_code': code}
if expired:
    record['timed_out'] = True
fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
os.write(fd, (json.dumps(record, sort_keys=True) + '\n').encode())
os.close(fd)
sys.exit(code if code >= 0 else 128 - code)
'''


def measure_git_shim(directory, real_git, log_path, timeout=3600):
    """Write a git shim that records the rusage of each git process it runs.

    The shim kills git after `timeout` seconds and stops waiting for it
    MEASURE_GRACE_SECONDS later."""
    private_dir(directory)
    path = os.path.join(directory, 'git')
    write_private(path, (GIT_SHIM % {'python': sys.executable, 'real': real_git, 'log': log_path,
                                     'limit': max(1, int(math.ceil(timeout))),
                                     'grace': MEASURE_GRACE_SECONDS}).encode())
    os.chmod(path, 0o700)
    return path


def measure_git_link(directory, real_git):
    private_dir(directory)
    path = os.path.join(directory, 'git')
    if not os.path.lexists(path):
        os.symlink(real_git, path)
    return path


def measure_child_summary(log_path):
    if not os.path.exists(log_path):
        return {'processes': 0, 'cpu_user_ns': 0, 'cpu_system_ns': 0, 'peak_rss_bytes': 0, 'wall_ns': 0}
    rows = read_jsonl(log_path)
    return {'processes': len(rows),
            'cpu_user_ns': sum(row['cpu_user_ns'] for row in rows),
            'cpu_system_ns': sum(row['cpu_system_ns'] for row in rows),
            'peak_rss_bytes': max([row['peak_rss_bytes'] for row in rows] or [0]),
            'wall_ns': sum(row['wall_ns'] for row in rows),
            'subcommands': sorted(collections.Counter(row['subcommand'] for row in rows).items()),
            'failed': sum(1 for row in rows if row['exit_code'] != 0)}


def measure_environment(home, tmp, bin_dir, extra):
    """Allowlisted environment. Nothing from the caller's environment is copied."""
    env = {'PATH': (bin_dir + ':' if bin_dir else '') + SYSTEM_PATH,
           'HOME': home, 'TMPDIR': tmp,
           'XDG_CACHE_HOME': os.path.join(home, '.cache'),
           'XDG_CONFIG_HOME': os.path.join(home, '.config'),
           'LC_ALL': 'C', 'TZ': 'UTC',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
    env.update(extra)
    return env
