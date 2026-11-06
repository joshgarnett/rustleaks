# Python controller for the bounded investigation protocol. Included by xtask.
import hashlib, json, os, pathlib, re, selectors, signal, stat, subprocess, sys, time

FILE_LIMIT = 16 * 1024 * 1024
STDERR_LIMIT = 65536


def output_sizes(directory):
    # These are polling limits, not a filesystem quota. Recheck after child exit.
    for path in directory.iterdir():
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError('unexpected non-file in private collector output')
        bound = STDERR_LIMIT if path.name == 'worker-stderr.txt' else FILE_LIMIT
        if metadata.st_size > bound:
            raise RuntimeError('private collector output exceeded its byte bound')


def observe_cpu(text, expected_image=None):
    if 'Call graph:\n' not in text:
        return None
    section = text.split('Call graph:\n', 1)[1]
    section = re.split(r'\n(?:Total number in stack|Sort by top of stack|Binary Images:)', section, maxsplit=1)[0]
    threads = [int(count) for count in re.findall(r'^\s*(\d+)\s+Thread_\S+', section, re.M)]
    frames = re.findall(r'^[ \t+!:|]*(\d+)\s+(.+?)\s+\(in ([^)]+)\)', section, re.M)
    symbols = [(int(count), symbol, image) for count, symbol, image in frames
               if int(count) > 0 and symbol.strip() != '???']
    target = [(count, symbol) for count, symbol, image in symbols if image == expected_image]
    if not threads or sum(threads) == 0 or not symbols or expected_image and not target:
        return None
    return {'sampled_thread_sections': len(threads), 'thread_sample_total': sum(threads),
            'symbolized_frame_rows': len(symbols), 'target_symbolized_frame_rows': len(target),
            'scope': 'thread sample counts; nested frame rows are not independent samples'}


def observe_heap(text):
    summary = re.search(r'^All zones:\s+([\d,]+) nodes \(([\d,]+) bytes\)\s*$', text, re.M)
    if not summary or not re.search(r'COUNT\s+BYTES\s+AVG\s+CLASS_NAME', text):
        return None
    nodes, size = [int(value.replace(',', '')) for value in summary.groups()]
    rows = re.findall(r'^\s*([\d,]+)\s+([\d,]+)\s+[\d.]+\s+\S.+$', text, re.M)
    populated = [(int(count.replace(',', '')), int(size.replace(',', ''))) for count, size in rows
                 if int(count.replace(',', '')) > 0 and int(size.replace(',', '')) > 0]
    if nodes <= 0 or size <= 0 or not populated:
        return None
    return {'live_nodes': nodes, 'live_bytes': size, 'populated_class_rows': len(populated),
            'scope': 'live retained heap snapshot; not allocation history'}


def size_bytes(token):
    match = re.fullmatch(r'(\d+(?:\.\d+)?)([KMGT]?)B?', token)
    if not match:
        raise ValueError('unrecognized native size token')
    return round(float(match[1]) * 1024 ** (' KMGT'.index(match[2]) if match[2] else 0))


def observe_vm(text):
    if 'REGION TYPE' not in text:
        return None
    section = text.split('REGION TYPE', 1)[1]
    # Region annotations mention the later table; only its anchored header ends this section.
    section = re.split(r'^[ \t]*MALLOC ZONE[ \t]+SIZE\b', section, maxsplit=1, flags=re.M)[0]
    rows = re.findall(r'^[ \t]*([A-Za-z_][^\n]*?)[ \t]+((?:\d+(?:\.\d+)?[KMGT]?B?[ \t]+){7})([\d,]+)(?:[ \t]+[^\n]*)?$', section, re.M)
    totals = [(values, count) for name, values, count in rows if name.strip() == 'TOTAL']
    populated = [(name, values, count) for name, values, count in rows
                 if name.strip() != 'TOTAL' and int(count.replace(',', '')) > 0]
    if len(totals) != 1 or not populated:
        return None
    values, count = totals[0]
    sizes = [size_bytes(token) for token in values.split()]
    count = int(count.replace(',', ''))
    if sizes[0] <= 0 or sizes[1] <= 0 or count <= 0:
        return None
    return {'virtual_bytes': sizes[0], 'resident_bytes': sizes[1], 'dirty_bytes': sizes[2],
            'regions': count, 'populated_region_rows': len(populated),
            'scope': 'rounded native VM summary; not allocation-site attribution'}


def observe(kind, text, expected_image=None):
    if kind == 'cpu':
        return observe_cpu(text, expected_image)
    if kind == 'heap':
        return observe_heap(text)
    if kind == 'vm':
        return observe_vm(text)
    raise RuntimeError('unknown native observation kind')


def self_test():
    import tempfile
    cpu = 'Call graph:\n    12 Thread_1\n      12 core::scan (in rustleaks_perf) + 8 [0x1]\n\nTotal number in stack:\n'
    heap = 'All zones: 2 nodes (64 bytes)\nCOUNT BYTES AVG CLASS_NAME TYPE BINARY\n 2 64 32.0 non-object\n'
    vm = 'REGION TYPE SIZE SIZE SIZE SIZE SIZE SIZE SIZE COUNT\nMALLOC 4K 2K 1K 0K 0K 0K 0K 1\nTOTAL 4K 2K 1K 0K 0K 0K 0K 1\n'
    for kind, complete in [('cpu', cpu), ('heap', heap), ('vm', vm)]:
        assert observe(kind, complete, 'rustleaks_perf') is not None, kind
        assert observe(kind, '', 'rustleaks_perf') is None, kind
        assert observe(kind, 'Process: test\nPhysical footprint: 1M\n', 'rustleaks_perf') is None, kind
    assert observe_cpu('Call graph:\nBinary Images:\n', 'rustleaks_perf') is None
    assert observe_cpu(cpu.replace('12 Thread_', '0 Thread_'), 'rustleaks_perf') is None
    assert observe_cpu(cpu.replace('core::scan', '???'), 'rustleaks_perf') is None
    assert observe_cpu(cpu.replace('rustleaks_perf', 'another-image'), 'rustleaks_perf') is None
    assert observe_heap('All zones: 2 nodes (64 bytes)\nCOUNT BYTES AVG CLASS_NAME\n') is None
    assert observe_vm('REGION TYPE SIZE\nTOTAL 4K 2K 1K 0K 0K 0K 0K 1\n') is None
    assert observe_vm(vm.replace('TOTAL 4K 2K', 'TOTAL 0K 0K')) is None
    annotated_vm = vm.replace('MALLOC 4K 2K 1K 0K 0K 0K 0K 1',
        'MALLOC_NANO metadata 4K 2K 1K 0K 0K 0K 0K 1  see MALLOC ZONE table below')
    annotated_vm += '\nMALLOC ZONE  SIZE SIZE SIZE SIZE COUNT BYTES FRAG PERCENT COUNT\n'
    assert observe_vm(annotated_vm) == observe_vm(vm)
    with tempfile.TemporaryDirectory(prefix='rustleaks-collector-test-') as scratch:
        root = pathlib.Path(scratch)
        for name, cap in [('cpu-stacks.txt', FILE_LIMIT), ('heap-after.txt', FILE_LIMIT), ('worker-stderr.txt', STDERR_LIMIT)]:
            path = root / name
            with path.open('wb') as stream:
                stream.truncate(cap)
            output_sizes(root)
            with path.open('ab') as stream:
                stream.write(b'x')
            try:
                output_sizes(root)
            except RuntimeError:
                pass
            else:
                raise AssertionError('oversized output was accepted: ' + name)
            path.unlink()
    print('native collector regression controls passed')


if len(sys.argv) == 4 and sys.argv[1] == '--inspect-observation':
    with pathlib.Path(sys.argv[3]).open('rb') as stream:
        contents = stream.read(FILE_LIMIT + 1)
    if len(contents) > FILE_LIMIT:
        raise RuntimeError('native observation exceeds input bound')
    observed = observe(sys.argv[2], contents.decode('utf-8', errors='replace'), 'rustleaks_perf')
    print(json.dumps({'sha256': hashlib.sha256(contents).hexdigest(), 'observation': observed}))
    raise SystemExit(0)


if sys.argv[1:] == ['--self-test']:
    self_test()
    raise SystemExit(0)

os.umask(0o077)
mode, binary, workload, output, limit, setting, extra = sys.argv[1:8]
if mode == 'sample-window':
    if len(sys.argv) != 9:
        raise RuntimeError('window collector requires exactly eight arguments')
    blocks = int(sys.argv[8])
elif len(sys.argv) != 8:
    raise RuntimeError('collector requires exactly seven arguments')
WINDOW_SCOPE = 'investigation-v2-summed-scan-windows'
output = pathlib.Path(output)
started = time.monotonic()
deadline = started + int(limit)
children = []
transcript = (output / 'transcript.jsonl').open('x') if mode == 'sample-window' else None
raw_stdout = (output / 'worker-stdout.jsonl').open('xb') if mode == 'sample-window' else None
observed_finished, observed_eof = None, False
window_pending = bytearray()
collection_error, cleanup_complete = None, False
child = None


def remaining():
    output_sizes(output)
    value = deadline - time.monotonic()
    if value <= 0:
        raise RuntimeError('investigation deadline exceeded')
    return value


def stop(child):
    if mode == 'sample-window':
        if child.poll() is None:
            child.kill()
    elif os.name == 'posix':
        try: os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
    elif child.poll() is None:
        child.kill()
    child.wait(timeout=5)


def receive(child):
    if mode == 'sample-window':
        return receive_window(child)
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        while True:
            # Poll even when stdout is quiet, so stderr and tool side files stay bounded.
            if not selector.select(min(remaining(), .05)):
                continue
            byte = os.read(child.stdout.fileno(), 1)
            if not byte:
                raise RuntimeError('investigation worker exited before its result')
            data += byte
            if len(data) > 65536:
                raise RuntimeError('investigation protocol output exceeds bound')
            if byte == b'\n':
                return json.loads(data)


def receive_window(child):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        while True:
            remaining()
            newline = window_pending.find(b'\n')
            if newline >= 0:
                if newline + 1 > 65536:
                    raise RuntimeError('investigation protocol output exceeds bound')
                line = bytes(window_pending[:newline + 1])
                del window_pending[:newline + 1]
                result = json.loads(line)
                record_event('response', result)
                remaining()
                return result
            if len(window_pending) >= 65536:
                raise RuntimeError('investigation protocol output exceeds bound')
            if not selector.select(min(remaining(), .05)):
                continue
            data = os.read(child.stdout.fileno(), 4096)
            if not data:
                raise RuntimeError('investigation worker exited before its result')
            raw_stdout.write(data)
            raw_stdout.flush()
            window_pending.extend(data)


def send(child, text):
    record_event('command', text)
    child.stdin.write((text + '\n').encode())
    child.stdin.flush()


def native(name, kind, arguments, seconds, evidence_path=None):
    executable = arguments[0]
    if not pathlib.Path(executable).is_file():
        return {'status':'unavailable', 'reason':'tool-not-installed'}
    path = output / (name + '.txt')
    observation_path = evidence_path if evidence_path is not None else path
    with path.open('wb') as log:
        child = subprocess.Popen(arguments, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        children.append(child)
        try:
            while child.poll() is None:
                remaining()
                if time.monotonic() >= seconds:
                    raise RuntimeError('native tool deadline exceeded')
                time.sleep(.02)
            code = child.wait()
            output_sizes(output)
        except Exception:
            stop(child)
            children.remove(child)
            return {'status':'unavailable-or-failed','reason':'tool-deadline-or-output-bound'}
    stop(child)
    children.remove(child)
    result = {'status':'unavailable-or-failed', 'exit_code':code,
              'tool_sha256':hashlib.sha256(pathlib.Path(executable).read_bytes()).hexdigest(),
              'output_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    if code != 0:
        result['reason'] = 'tool-nonzero-exit'
        return result
    if not observation_path.is_file():
        result['reason'] = 'native-observation-missing'
        return result
    output_sizes(output)
    contents = observation_path.read_bytes()
    result['observation_sha256'] = hashlib.sha256(contents).hexdigest()
    observed = observe(kind, contents.decode('utf-8', errors='replace'), pathlib.Path(binary).name)
    if observed is None:
        result['status'] = 'unavailable-or-invalid'
        result['reason'] = 'no-usable-native-observation'
    else:
        result['status'] = 'complete'
        result['observation'] = observed
    return result


def window_integer(value, positive=False):
    if type(value) is not int or not (int(positive) <= value <= (1 << 64) - 1):
        raise RuntimeError('window integer is missing, noninteger or outside u64 bounds')
    return value


def window_fields(value, kind, ready):
    expected = {'schema_version': 2, 'kind': kind, 'scope': WINDOW_SCOPE,
                'window_blocks': blocks, 'iterations_per_block': int(setting),
                'extra_passes': int(extra), 'identity': ready['identity']}
    for key, wanted in expected.items():
        if value.get(key) != wanted or type(value.get(key)) is not type(wanted):
            raise RuntimeError('window component or completion metadata changed: ' + key)


def collect_window(child, ready):
    if not (1 <= blocks <= 16 and 1 <= int(setting) <= 100 and int(extra) in (0, 1)):
        raise RuntimeError('window command bounds invalid')
    if type(ready.get('schema_version')) is not int or ready.get('schema_version') != 1 or ready.get('scope') != 'investigation-v1-steady-scan-only':
        raise RuntimeError('window worker ready metadata changed')
    identity = ready.get('identity', {})
    if identity.get('complete') is not True or window_integer(identity.get('errors')) != 0 or identity.get('workload') != workload:
        raise RuntimeError('window ready identity incomplete or mismatched')
    for field in ['input_bytes', 'rules', 'keywords', 'findings', 'decoded_bytes', 'work_units', 'finding_records']:
        window_integer(identity.get(field))
    for field in ['input_fnv1a64', 'config_fnv1a64', 'outcome_fnv1a64']:
        if not isinstance(identity.get(field), str) or re.fullmatch('[0-9a-fA-F]{16}', identity[field]) is None:
            raise RuntimeError('window ready identity fingerprint invalid')
    if ready.get('provenance', {}).get('binding') != 'unbound-runner':
        raise RuntimeError('window ready provenance is not an unbound worker')
    send(child, 'window ' + str(blocks) + ' ' + setting + ' ' + extra)
    components = []
    elapsed, iterations, scans = 0, 0, 0
    for index in range(blocks):
        component = receive(child)
        window_fields(component, 'window-component', ready)
        if window_integer(component.get('block_index')) != index:
            raise RuntimeError('window component index missing, duplicated or reordered')
        sample = component.get('sample', {})
        if sample.get('kind') != 'sample' or sample.get('scope') != 'investigation-v1-steady-scan-only' or sample.get('identity') != ready['identity']:
            raise RuntimeError('window sample identity or scope changed')
        if window_integer(sample.get('iterations')) != int(setting) or window_integer(sample.get('extra_passes')) != int(extra):
            raise RuntimeError('window sample work changed')
        count = window_integer(sample.get('actual_scan_count'), True)
        if count != int(setting) * (int(extra) + 1):
            raise RuntimeError('window sample scan count changed')
        measured = window_integer(sample.get('elapsed_ns'), True)
        if window_integer(sample.get('ns_per_logical_iteration')) != measured // int(setting):
            raise RuntimeError('window sample iteration quotient changed')
        elapsed = window_integer(elapsed + measured, True)
        iterations = window_integer(iterations + int(setting), True)
        scans = window_integer(scans + count, True)
        components.append(component)
    complete = receive(child)
    window_fields(complete, 'window-complete', ready)
    for key, value in [('elapsed_ns', elapsed), ('total_iterations', iterations), ('actual_scan_count', scans)]:
        if window_integer(complete.get(key), True) != value:
            raise RuntimeError('window completion totals changed: ' + key)
    return {'ready': ready, 'components': components, 'complete': complete}


def record_event(kind, value, check_sizes=True):
    if transcript is not None:
        transcript.write(json.dumps({'kind': kind, 'elapsed_seconds': time.monotonic() - started,
                                     'unix_seconds': time.time(), 'value': value}) + '\n')
        transcript.flush()
        if check_sizes:
            output_sizes(output)


def finish_window(child, result):
    global observed_finished, observed_eof
    send(child, 'quit')
    child.stdin.close()
    observed_finished = receive(child)
    if observed_finished != {'kind': 'finished'}:
        raise RuntimeError('window worker omitted exact finished marker')
    if window_pending:
        raise RuntimeError('window worker emitted trailing protocol bytes')
    while child.poll() is None:
        remaining()
        time.sleep(.02)
    child.wait()
    remaining()
    if child.returncode != 0:
        raise RuntimeError('window worker failed')
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        while True:
            if not selector.select(min(remaining(), .05)):
                continue
            tail = os.read(child.stdout.fileno(), 65536)
            if not tail:
                observed_eof = True
                break
            raw_stdout.write(tail)
            raw_stdout.flush()
            raise RuntimeError('window worker emitted trailing protocol bytes')
    result.update({'finished': observed_finished, 'exit_code': child.returncode, 'stdout_eof': observed_eof})
    return result


try:
    record_event('start', {'limit_seconds': int(limit), 'window_blocks': blocks if mode == 'sample-window' else None})
    with (output / 'worker-stderr.txt').open('wb') as error:
        child = subprocess.Popen([binary, '--investigate', '--workload', workload],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error,
            start_new_session=(os.name == 'posix' and mode != 'sample-window'))
        children.append(child)
        ready = receive(child)
        if ready.get('kind') != 'ready':
            raise RuntimeError('worker omitted prepared-phase marker')
        if mode == 'sample':
            send(child, 'sample ' + setting + ' ' + extra)
            result = {'ready':ready, 'sample':receive(child)}
        elif mode == 'sample-window':
            result = collect_window(child, ready)
        elif mode == 'profile':
            seconds = int(setting)
            if sys.platform != 'darwin':
                result = {'ready':ready,'status':'unsupported-host',
                          'reason':'maintained native collector currently requires macOS; no profile collected'}
            else:
                pid = str(child.pid)
                memory_before = {
                    'heap':native('heap-before', 'heap', ['/usr/bin/heap','-s','--noContent',pid], time.monotonic()+30),
                    'vm':native('vm-before', 'vm', ['/usr/bin/vmmap','-summary',pid], time.monotonic()+30)}
                send(child, 'profile ' + str(seconds+5))
                cpu = native('cpu', 'cpu', ['/usr/bin/sample',pid,str(seconds),'1','-file',str(output/'cpu-stacks.txt')], time.monotonic()+seconds+10, output/'cpu-stacks.txt')
                result = {'ready':ready, 'profile':receive(child), 'cpu':cpu,
                    'memory_before':memory_before, 'memory_after':{
                    'heap':native('heap-after', 'heap', ['/usr/bin/heap','-s','--noContent',pid], time.monotonic()+30),
                    'vm':native('vm-after', 'vm', ['/usr/bin/vmmap','-summary',pid], time.monotonic()+30)},
                    'scope':'steady worker after prepared marker; heap and VM are live retained snapshots, not allocation histories',
                    'cpu_scope':'scan loop including validation, hashing and outcome destruction; setup excluded',
                    'status':'complete'}
                if any(item['status']!='complete' for item in [result['cpu'], *result['memory_before'].values(), *result['memory_after'].values()]):
                    result['status']='completed-with-unavailable-tools'
        else:
            raise RuntimeError('unknown investigation mode')
        if mode == 'sample-window':
            result = finish_window(child, result)
        else:
            send(child, 'quit')
            if receive(child).get('kind') != 'finished':
                raise RuntimeError('worker omitted finished marker')
            while child.poll() is None:
                remaining()
                time.sleep(.02)
            child.wait()
            output_sizes(output)
            if child.returncode != 0:
                raise RuntimeError('investigation worker failed')
            print(json.dumps(result))
except BaseException as error:
    collection_error = str(error)
    raise
finally:
    try:
        for owned_child in reversed(children):
            stop(owned_child)
        cleanup_complete = True
    finally:
        if raw_stdout is not None:
            raw_stdout.flush()
            raw_stdout.close()
        if transcript is not None:
            record_event('cleanup', {'complete': cleanup_complete}, check_sizes=False)
            transcript.close()
            with (output / 'collector-completion.json').open('x') as completion:
                json.dump({'status': 'complete' if collection_error is None and cleanup_complete else 'failed',
                           'exit_code': child.returncode if child is not None else None,
                           'finished': observed_finished, 'stdout_eof': observed_eof,
                           'cleanup_complete': cleanup_complete, 'cleanup_scope': 'direct worker; parent supervises inherited process group', 'error': collection_error,
                           'elapsed_seconds': time.monotonic() - started}, completion)
        output_sizes(output)
if mode == 'sample-window':
    print(json.dumps(result))
