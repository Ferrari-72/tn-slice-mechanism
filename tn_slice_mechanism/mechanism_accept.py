"""SOURCE ONLY / NOT_RUN: v3 fixed-row saved-base mechanism byte acceptance (file evidence).

v3 changes vs v2 (transport/bounds only; audit, validate_arms, selection, certificate
comparison and all math unchanged): the child writes evidence to /output/evidence.jsonl
(<=1 GiB) and its stdout must be empty; records are decoded lazily one at a time;
JSON item bound 64M per record; app 14400 s / wrapper 14700 s / external 15000 s;
request schema -v3; stdout publishes only the control record (raw_bytes/raw_sha256
pin the evidence file).

Exact mount /checks/mechanism_accept.py; /runtime has only five business files
(v1 four plus the hash-pinned iterative qpe_mechanism_stack.py). v2 removes the
depth-128 MECHANISM_IMPLEMENTATION_BLOCKED gate: complete returned trees up to the
20000-input bound go through the unchanged full mechanism gate. A failure of any
external native operation on a deep tree remains incomplete (exit1), never
scientific non-applicability and never a shallow/summary substitute.
CLI: REPLAY REQUEST_RAW_SHA256; /request/request.json selects exact row and raw pins.
LIMITS is parent-attests-270s-1cpu-3gib. seed=row.seed; app210/wrapper240 are fixed.
The guardian owns the absolute270-second lease and entire inherited process group.
Complete-stream buffering preserves bytes/order, not external pre-J commitment.
No main/native/optimizer/offline DP is called by acceptance validation itself.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

ROOT = Path('/runtime')
SELF = Path('/checks/mechanism_accept.py')
ENTRY = ROOT / 'qpe_actual_incumbent_mechanism.py'
IMAGE = 'sha256:286b4627047f20b00b3ddb38580a2fcc10fa82f9ede6a50d8039d84ad66262df'
LIMITS = 'parent-attests-v3-15000s-1cpu'
APP_LIMITS = 'parent-attests-v3-whole-slot-1cpu'
GEN_SHA = None
NATIVE_SHA = None
SOURCE_SHA = 'ce758e8d95c445dfc464c5941d5b9c416b0999a1fda8d1bde97f3736001d38f7'
PINS = {
    'qpe_actual_incumbent_mechanism.py': (28450, '4f14c6f6df6aba0079d2335075ce9d2ec064fad141c22a0f018fe4e76eea78c5'),
    'qpe_j26_trace.py': (65377, '8b38e1317c92fe111cb7d6f12c7f32b6db5c80cea405713242a44e9e58c62903'),
    'qpe_fixed_capacity_trace_adapter.py': (30479, '6918e30663eaab844eaeb220427fc7495c35bfdf4d133d1f6ad2689d50330e8a'),
    'qpe_fixed_capacity_certificate.py': (16205, '920cdda97ec4c197b3aa4d020f9290c8e040b8b69c7444a12aeb482273e73e75'),
    'qpe_mechanism_stack.py': (9855, '8e0844b51f32765ff6ea44ad6e6ed0a59f954286dc8915e50b870c063517f653'),
}
INPUT_PINS = None
REQUEST_PIN = None
SCIENCE_SOURCES = {"1":{"qpe_capacity_opportunity_entry.py":"d7d11b313a18ead56fd92ebcc92df3c9a2e644b2113275dbe0a00e3d97201333","qpe_capacity_opportunity_screen.py":"457b27c16043e907a27b6fc10fc246a6dbbeded2079660bcfd92d4d2404f2a25","qpe_fresh_generator.py":"0d375ede15752b6c01ed086651aff57f79d1707b38b61469e44a4992896dc402","v5_common.py":"7ed003af376239762a49cbe1a7281bbfc2c34d94e4791ff1d49c809641135e90","qpe_calibration_baselines.py":"dc7231eb7b92a1da3b0236af7838378ff0afc7e8176cc6b2c00ff1c14017fc65","qpe_j26_trace.py":"3ebd1fa082d5cba7f56d3f5ef2687708332146365e0e52ad8947507c7f9ff58b"},"2":{"qpe_calibration_baselines.py":"dc7231eb7b92a1da3b0236af7838378ff0afc7e8176cc6b2c00ff1c14017fc65","qpe_capacity_opportunity_entry.py":"830ed56e34d36b9ed066506ab4846145a68d0e250159291e9202eb5426df9a3a","qpe_capacity_opportunity_screen.py":"36d6aff1007b4ce00f7149bde0a55773fd71d1bb912027f4c51d5f87697d8340","qpe_fresh_generator.py":"0d375ede15752b6c01ed086651aff57f79d1707b38b61469e44a4992896dc402","qpe_j26_trace.py":"3ebd1fa082d5cba7f56d3f5ef2687708332146365e0e52ad8947507c7f9ff58b","v5_common.py":"7ed003af376239762a49cbe1a7281bbfc2c34d94e4791ff1d49c809641135e90"},"3":{"qpe_calibration_baselines.py":"dc7231eb7b92a1da3b0236af7838378ff0afc7e8176cc6b2c00ff1c14017fc65","qpe_capacity_opportunity_entry.py":"830ed56e34d36b9ed066506ab4846145a68d0e250159291e9202eb5426df9a3a","qpe_capacity_opportunity_screen.py":"36d6aff1007b4ce00f7149bde0a55773fd71d1bb912027f4c51d5f87697d8340","qpe_fresh_generator.py":"0d375ede15752b6c01ed086651aff57f79d1707b38b61469e44a4992896dc402","qpe_j26_trace.py":"3ebd1fa082d5cba7f56d3f5ef2687708332146365e0e52ad8947507c7f9ff58b","v5_common.py":"7ed003af376239762a49cbe1a7281bbfc2c34d94e4791ff1d49c809641135e90"},"4":{"qpe_calibration_baselines.py":"dc7231eb7b92a1da3b0236af7838378ff0afc7e8176cc6b2c00ff1c14017fc65","qpe_capacity_opportunity_entry.py":"756bbbd6a39ada7cc07da9ab3afd6a676d48fc14405accfc2dc43c7a97ccd21d","qpe_capacity_opportunity_screen.py":"36d6aff1007b4ce00f7149bde0a55773fd71d1bb912027f4c51d5f87697d8340","qpe_fresh_generator.py":"0d375ede15752b6c01ed086651aff57f79d1707b38b61469e44a4992896dc402","qpe_j26_trace.py":"3ebd1fa082d5cba7f56d3f5ef2687708332146365e0e52ad8947507c7f9ff58b","v5_common.py":"7ed003af376239762a49cbe1a7281bbfc2c34d94e4791ff1d49c809641135e90"},"5":{"qpe_capacity_opportunity_entry.py":"140933eb82857ff7c7ee6f49e3127c9729cb46e5054e40ab7d10f4e1e9c7dfe6","qpe_capacity_opportunity_screen.py":"15c9e2ba5ab101f4059416dc2aab785dfa1aad4be1ce188375538d2e6c259336","qpe_fresh_generator.py":"0d375ede15752b6c01ed086651aff57f79d1707b38b61469e44a4992896dc402","v5_common.py":"7ed003af376239762a49cbe1a7281bbfc2c34d94e4791ff1d49c809641135e90","qpe_calibration_baselines.py":"dc7231eb7b92a1da3b0236af7838378ff0afc7e8176cc6b2c00ff1c14017fc65","qpe_j26_trace.py":"3ebd1fa082d5cba7f56d3f5ef2687708332146365e0e52ad8947507c7f9ff58b"},"6":{"qpe_capacity_opportunity_entry.py":"e84a22b487f2e99b1c93fc265c8736d09e5324bade76cc8c5d95f1e7e7933a0c","qpe_capacity_opportunity_screen.py":"15c9e2ba5ab101f4059416dc2aab785dfa1aad4be1ce188375538d2e6c259336","qpe_fresh_generator.py":"0d375ede15752b6c01ed086651aff57f79d1707b38b61469e44a4992896dc402","v5_common.py":"7ed003af376239762a49cbe1a7281bbfc2c34d94e4791ff1d49c809641135e90","qpe_calibration_baselines.py":"dc7231eb7b92a1da3b0236af7838378ff0afc7e8176cc6b2c00ff1c14017fc65","qpe_j26_trace.py":"3ebd1fa082d5cba7f56d3f5ef2687708332146365e0e52ad8947507c7f9ff58b"},"7":{"qpe_capacity_opportunity_entry.py":"eeaba8f5749fa7a041f8c0173132a90761761968ce3cfb53fd020f98be62810c","qpe_capacity_opportunity_screen.py":"457b27c16043e907a27b6fc10fc246a6dbbeded2079660bcfd92d4d2404f2a25","qpe_fresh_generator.py":"0d375ede15752b6c01ed086651aff57f79d1707b38b61469e44a4992896dc402","v5_common.py":"7ed003af376239762a49cbe1a7281bbfc2c34d94e4791ff1d49c809641135e90","qpe_calibration_baselines.py":"dc7231eb7b92a1da3b0236af7838378ff0afc7e8176cc6b2c00ff1c14017fc65","qpe_j26_trace.py":"3ebd1fa082d5cba7f56d3f5ef2687708332146365e0e52ad8947507c7f9ff58b"},"8":{"qpe_capacity_opportunity_entry.py":"c6cd480bece4e7a31a75347ca2bb9e57ef000967f3eba9ec922f0b47bdc72ddd","qpe_capacity_opportunity_screen.py":"457b27c16043e907a27b6fc10fc246a6dbbeded2079660bcfd92d4d2404f2a25","qpe_fresh_generator.py":"0d375ede15752b6c01ed086651aff57f79d1707b38b61469e44a4992896dc402","v5_common.py":"7ed003af376239762a49cbe1a7281bbfc2c34d94e4791ff1d49c809641135e90","qpe_calibration_baselines.py":"dc7231eb7b92a1da3b0236af7838378ff0afc7e8176cc6b2c00ff1c14017fc65","qpe_j26_trace.py":"3ebd1fa082d5cba7f56d3f5ef2687708332146365e0e52ad8947507c7f9ff58b"},"9":{"qpe_capacity_opportunity_entry.py":"d9e1c2e768552a2f19f840c850670f2b1e8687a036a6e4fd52bc751c6138b21a","qpe_capacity_opportunity_screen.py":"457b27c16043e907a27b6fc10fc246a6dbbeded2079660bcfd92d4d2404f2a25","qpe_fresh_generator.py":"0d375ede15752b6c01ed086651aff57f79d1707b38b61469e44a4992896dc402","v5_common.py":"7ed003af376239762a49cbe1a7281bbfc2c34d94e4791ff1d49c809641135e90","qpe_calibration_baselines.py":"dc7231eb7b92a1da3b0236af7838378ff0afc7e8176cc6b2c00ff1c14017fc65","qpe_j26_trace.py":"3ebd1fa082d5cba7f56d3f5ef2687708332146365e0e52ad8947507c7f9ff58b"},"10":{"qpe_capacity_opportunity_entry.py":"0e0058c7a556593685aac93f4ef7df059e7de1842dc93cef921bc3c3362da4f7","qpe_capacity_opportunity_screen.py":"457b27c16043e907a27b6fc10fc246a6dbbeded2079660bcfd92d4d2404f2a25","qpe_fresh_generator.py":"0d375ede15752b6c01ed086651aff57f79d1707b38b61469e44a4992896dc402","v5_common.py":"7ed003af376239762a49cbe1a7281bbfc2c34d94e4791ff1d49c809641135e90","qpe_calibration_baselines.py":"dc7231eb7b92a1da3b0236af7838378ff0afc7e8176cc6b2c00ff1c14017fc65","qpe_j26_trace.py":"3ebd1fa082d5cba7f56d3f5ef2687708332146365e0e52ad8947507c7f9ff58b"},"11":{"qpe_capacity_opportunity_entry.py":"636d5559a647b16a0e8ee5e364214ba3d43dcabb35d40985726ecbd8e52ed5d7","qpe_capacity_opportunity_screen.py":"457b27c16043e907a27b6fc10fc246a6dbbeded2079660bcfd92d4d2404f2a25","qpe_fresh_generator.py":"0d375ede15752b6c01ed086651aff57f79d1707b38b61469e44a4992896dc402","v5_common.py":"7ed003af376239762a49cbe1a7281bbfc2c34d94e4791ff1d49c809641135e90","qpe_calibration_baselines.py":"dc7231eb7b92a1da3b0236af7838378ff0afc7e8176cc6b2c00ff1c14017fc65","qpe_j26_trace.py":"3ebd1fa082d5cba7f56d3f5ef2687708332146365e0e52ad8947507c7f9ff58b"}}
SCHEMA = 'qpe-actual-incumbent-mechanism-v1'
METRICS = ('multiplicity', 'per_slice_work', 'total_work', 'result_only_peak')
K = 2 ** 28
MAX_STDOUT = 32 << 20             # child stdout must be empty in v3; bound kept
MAX_STDERR = 1 << 20
MAX_EVIDENCE = 1 << 30            # equals entry MAX_EVIDENCE_BYTES
EVIDENCE = Path('/output/evidence.jsonl')
MAX_TREE_DEPTH = 19999            # complete binary tree over <=20000 physical inputs
MAX_JSON_DEPTH = MAX_TREE_DEPTH + 32
MAX_JSON_ITEMS = 64_000_000       # one evidence record (certificate leaf lists)
WRAPPER_SECONDS = 14700
APP_SECONDS = 14400
SEED = None
ROW = None


def need(ok, why):
    if not ok:
        raise ValueError(why)


def check(deadline):
    if time.monotonic() >= deadline:
        raise TimeoutError('startup-inclusive mechanism acceptance deadline exhausted')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stack():
    """The pinned /runtime iterative codec, loaded once with exact byte verification."""
    module = sys.modules.get('qpe_mechanism_stack')
    if module is None:
        path = ROOT / 'qpe_mechanism_stack.py'
        raw = read_pin(path, PINS['qpe_mechanism_stack.py'])
        spec = importlib.util.spec_from_file_location('qpe_mechanism_stack', str(path))
        need(spec is not None and spec.loader is not None, 'explicit stack loader unavailable')
        module = importlib.util.module_from_spec(spec)
        module.__qpe_stack_sha256__ = sha(raw)
        sys.modules['qpe_mechanism_stack'] = module
        exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    need(getattr(module, '__qpe_stack_sha256__', None) == PINS['qpe_mechanism_stack.py'][1],
         'loaded mechanism stack identity differs')
    return module


def wire(value):
    # Same compact sorted ASCII bytes as v1 json.dumps; iterative only when deep.
    return stack().dumps(value)


def same(left, right, why):
    # JSON bytes distinguish bool/int and float/int; Python equality does not.
    need(wire(left) == wire(right), why)


def keys(value, names):
    need(type(value) is dict and set(value) == set(names), 'exact record fields required')


def number(value, maximum):
    need(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum,
         'finite nonnegative bounded elapsed time required')
    return value


def integer(value, maximum):
    need(type(value) is int and 0 <= value <= maximum, 'bounded exact integer required')
    return value


def decimal(value):
    need(type(value) is str and re.fullmatch(r'0|[1-9][0-9]*', value, re.ASCII),
         'canonical nonnegative integer metric string required')
    return int(value)


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('nonfinite JSON constant')


def decode(raw, *, canonical=False):
    need(type(raw) is bytes and raw and len(raw) <= MAX_EVIDENCE, 'bounded JSON bytes required')
    raw.decode('ascii')  # ASCII-only wire, as v1
    value = stack().loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        need(depth <= MAX_JSON_DEPTH and count <= MAX_JSON_ITEMS, 'bounded JSON nesting/item count required')
        if type(item) is dict:
            pending.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            pending.extend((v, depth + 1) for v in item)
        elif type(item) is float:
            need(math.isfinite(item), 'overflowed JSON number')
        else:
            need(type(item) in (str, int, bool, type(None)), 'JSON builtin type required')
    encoded = wire(value)
    if canonical:
        need(encoded == raw, 'compact sorted canonical ASCII JSON required')
    return value


def no_link(path):
    for node in (path, *path.parents):
        need(not node.is_symlink(), 'symlink ancestry forbidden: ' + str(node))


def read_pin(path, pin):
    no_link(path)
    size, digest = pin
    need(path.is_file() and path.stat().st_size == size, 'pinned regular file size differs')
    with path.open('rb') as stream:
        need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'regular descriptor required')
        raw = stream.read(size + 1)
    need(len(raw) == size and sha(raw) == digest, 'pinned file bytes differ: ' + str(path))
    return raw


def inventory(deadline):
    check(deadline)
    for directory, pins in ((ROOT, PINS), (Path('/input'), INPUT_PINS), (Path('/request'), {'request.json': REQUEST_PIN})):
        no_link(directory)
        need(directory.is_dir() and {p.name for p in directory.iterdir()} == set(pins),
             'exact individual-file directory inventory differs')
        for name, pin in pins.items():
            check(deadline)
            read_pin(directory / name, pin)
    return {name: PINS[name][1] for name in sorted(PINS)}


def process_start():
    proc = Path('/proc/self/stat').read_text(encoding='ascii')
    ticks = int(proc[proc.rfind(')') + 2:].split()[19])
    hz = os.sysconf('SC_CLK_TCK')
    need(hz > 0, 'positive process-start clock frequency required')
    now = time.monotonic()
    age = time.clock_gettime(time.CLOCK_BOOTTIME) - ticks / hz + 1.0 / hz
    need(math.isfinite(age) and 0 <= age < WRAPPER_SECONDS, 'process-start allowance exhausted')
    return now - age


class Capture:
    def __init__(self):
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.eof = {'stdout': False, 'stderr': False}
        self.exit_code = None

    def run(self, command, deadline):
        # No new session: the existing guardian group continues to own descendants.
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, cwd='/tmp', close_fds=True)
        try:
            with selectors.DefaultSelector() as selector:
                for name, stream in (('stdout', child.stdout), ('stderr', child.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map():
                    check(deadline)
                    for key, _ in selector.select(min(.025, max(0, deadline - time.monotonic()))):
                        try:
                            raw = os.read(key.fileobj.fileno(), 65536)
                        except BlockingIOError:
                            continue
                        if not raw:
                            self.eof[key.data] = True
                            selector.unregister(key.fileobj)
                            continue
                        data = getattr(self, key.data)
                        cap = MAX_STDOUT if key.data == 'stdout' else MAX_STDERR
                        need(len(data) + len(raw) <= cap, 'mechanism ' + key.data + ' capture exceeded')
                        data.extend(raw)
                self.exit_code = child.wait(timeout=max(.001, deadline - time.monotonic()))
                check(deadline)
                need(self.exit_code == 0 and all(self.eof.values()),
                     'mechanism nonzero exit or incomplete raw capture')
        finally:
            if child.poll() is None:
                child.kill()  # Exact retained child only; guardian handles its whole group.
                try:
                    child.wait(timeout=max(.001, min(1.0, deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    pass
            child.stdout.close()
            child.stderr.close()


def load_pure(deadline):
    modules = {}
    stack()  # pinned codec first; adapter, trace and business resolve it via sys.modules
    for name in ('qpe_fixed_capacity_certificate', 'qpe_fixed_capacity_trace_adapter',
                 'qpe_j26_trace', 'qpe_actual_incumbent_mechanism'):
        check(deadline)
        need(name not in sys.modules, 'business namespace already loaded')
        path = ROOT / (name + '.py')
        raw = read_pin(path, PINS[path.name])
        spec = importlib.util.spec_from_file_location(name, str(path))
        need(spec is not None and spec.loader is not None, 'explicit source loader unavailable')
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
        need(sys.modules.get(name) is module and Path(module.__file__).resolve() == path,
             'business source module identity differs')
        modules[name] = module
    return modules


def record_keys(record, fields):
    keys(record, ('schema', 'kind', 'replay_id', *fields))


def snapshot_from_wire(item, structure, trace, deadline):
    need(type(item) is dict and 'path' in item and 'slices' in item, 'complete snapshot required')
    result = trace.collect_exact(structure['inputs'], structure['output'], structure['sizes'],
                                 item['path'], item['slices'], _check=lambda: check(deadline))
    same(item, trace._wire(result), 'snapshot path/tree/integer score mismatch')
    return result


class Records:
    """v3: exact LF records of the evidence file, decoded and checked on access.

    Same canonical/schema/replay checks as v2's eager list. validate_stream reads
    every index 0..len-1, so every record is still decoded and checked; only the
    peak memory (one large decoded record at a time) differs.
    """

    def __init__(self, raw, replay, deadline):
        self.raw, self.replay, self.deadline, self.spans, start = raw, replay, deadline, [], 0
        while start < len(raw):
            end = raw.index(b'\n', start) + 1
            self.spans.append((start, end))
            need(len(self.spans) <= 12, 'bounded complete record count required')
            start = end

    def __len__(self):
        return len(self.spans)

    def __getitem__(self, index):
        check(self.deadline)
        start, end = self.spans[index]
        value = decode(self.raw[start:end - 1], canonical=True)
        need(type(value) is dict and value.get('schema') == SCHEMA and
             value.get('replay_id') == self.replay and type(value.get('kind')) is str,
             'mechanism schema/replay identity differs')
        return value


def validate_stream(raw, replay, sources, generation, native, candidate, modules, deadline):
    need(raw and len(raw) <= MAX_EVIDENCE and raw.endswith(b'\n') and b'\r' not in raw,
         'complete LF mechanism stream required')
    records = Records(raw, replay, deadline)
    need(8 <= len(records) <= 12, 'bounded complete record count required')
    trace = modules['qpe_j26_trace']
    adapter = modules['qpe_fixed_capacity_trace_adapter']
    business = modules['qpe_actual_incumbent_mechanism']
    structure = {name: generation['case'][name] for name in ('inputs', 'output', 'sizes')}
    same(generation['row'], ROW, 'accepted generation row differs')
    same(native['row'], ROW, 'accepted native row differs')
    for value in (generation, native):
        need(value.get('schema') == 'qpe-capacity-opportunity-screen-v1' and
             type(value.get('K')) is int and value['K'] == K and
             value.get('entry_status') == 'PASS' and value.get('stage2_complete') is False,
             'saved accepted input schema differs')
        need(value['structure_sha256'] == sha(wire(structure)), 'ordered input structure binding differs')
    validate_saved_pair(generation, native)
    # Complete direct HIT/NULL returns only; never UNKNOWN, missing or fabricated paths.
    same(native['native_returned_path'], native['diagnostics']['native_returned_path'],
         'direct native path evidence differs')
    same(native['native_returned_sliced'], native['diagnostics']['native_returned_sliced'],
         'direct native slice evidence differs')
    need(native['diagnostics']['execution_evidence'] == 'native_call_completed', 'native completion missing')
    common = trace.collect_exact(structure['inputs'], structure['output'], structure['sizes'],
                                 native['native_returned_path'], native['native_returned_sliced'],
                                 _check=lambda: check(deadline))
    unsliced = trace.collect_exact(structure['inputs'], structure['output'], structure['sizes'],
                                   native['native_returned_path'], [], _check=lambda: check(deadline))
    for label, exact in (('returned', common), ('same_path_unsliced', unsliced)):
        for name in (*METRICS, 'contractions'):
            need(type(native['exact'][label][name]) is int and
                 native['exact'][label][name] == exact[name], 'accepted native score mismatch')
    sliced = native['native_returned_sliced']
    expected = (('NULL', 'NO_NATIVE_SLICES') if not sliced else
                ('NULL', 'SLICES_NOT_NEEDED_BY_THIS_BASE') if unsliced['result_only_peak'] <= K else
                ('HIT_THIS_BASE', 'RETURNED_BASE_CAPACITY_SENSITIVE'))
    same([native['outcome'], native['reason']], list(expected), 'native scientific outcome differs')
    need(common['result_only_peak'] <= K, 'common base is infeasible')
    common_wire = trace._wire(common)
    common_raw = wire(common_wire)
    first = records[0]
    need(first['kind'] == 'common_base', 'common_base must be first and unique')
    record_keys(first, ('common', 'common_snapshot_sha256', 'generation_sha256', 'native_sha256',
                       'source_map', 'source_sha256', 'provenance', 'baseline_origin',
                       'image_id_attested', 'external_limits_verified_inside_child',
                       'base_planning_seconds_charged', 'generation_seconds_charged'))
    same(first['common'], common_wire, 'emitted actual common snapshot differs')
    need(first['common_snapshot_sha256'] == sha(common_raw) and first['generation_sha256'] == GEN_SHA
         and first['native_sha256'] == NATIVE_SHA and first['source_sha256'] == SOURCE_SHA
         and first['image_id_attested'] == IMAGE and first['external_limits_verified_inside_child'] is False
         and first['baseline_origin'] == 'parent-accepted direct native screen return; prefix not rerun',
         'common source/input/image identity differs')
    same(first['source_map'], sources, 'exact five-source map differs')
    for field, value in (('base_planning_seconds_charged', native),
                         ('generation_seconds_charged', generation)):
        number(first[field], 900)
        same(first[field], value['startup_inclusive_elapsed_seconds'], 'charged saved-base time differs')
    _, provenance = business.catalogue_source(candidate, trace)
    same(first['provenance'], provenance, 'pinned catalogue transformation evidence differs')
    rows, bounds, certificates = [], [], []
    pos = 1
    while pos < len(records) and records[pos]['kind'] == 'pre_j_candidate':
        check(deadline)
        row = records[pos]
        record_keys(row, ('native_ordinal', 'domain_id', 'candidate_sha256', 'raw_event_sha256',
                          'actual_semantic_sha256', 'feature', 'raw_event'))
        index = len(rows)
        need(index < 4 and type(row['native_ordinal']) is int and row['native_ordinal'] == index and
             type(row['domain_id']) is int and row['domain_id'] == index + 1, 'candidate order/count differs')
        event = row['raw_event']
        keys(event, ('schema', 'kind', 'domain_id', 'domain'))
        need(event['schema'] == 'qpe-j26-trace-v1' and event['kind'] == 'domain' and
             type(event['domain_id']) is int and event['domain_id'] == index + 1, 'raw event identity differs')
        domain = event['domain']
        keys(domain, (*adapter._DOMAIN_REQUIRED, *adapter._DOMAIN_OPTIONAL))
        need(type(domain) is dict and type(domain.get('sweep')) is int and domain['sweep'] == 0
             and type(domain.get('seed')) is int and domain['seed'] == SEED
             and type(domain.get('cap')) is int and domain['cap'] == K, 'pre-J sweep/seed/K differs')
        same({name: domain[name] for name in structure}, structure, 'candidate ordered inputs differ')
        need(row['candidate_sha256'] == sha(wire(domain)) and
             row['raw_event_sha256'] == sha(wire(event)), 'candidate/event byte identity differs')
        source_snapshot = snapshot_from_wire(domain['source_baseline'], structure, trace, deadline)
        actual_snapshot = snapshot_from_wire(domain['incumbent_before'], structure, trace, deadline)
        same(domain['source_and_incumbent_same_tree'],
             trace._tree_key(source_snapshot['tree']) == trace._tree_key(actual_snapshot['tree']),
             'source/common topology equality flag differs')
        same(domain['source_and_incumbent_same_slices'],
             source_snapshot['slices'] == actual_snapshot['slices'], 'source/common slice flag differs')
        binding = adapter.ActualCommonBaseBinding(
            adapter.CallerBinding(sha(wire(event)), replay, index + 1), SOURCE_SHA,
            sha(common_raw), sha(wire(domain)), sha(wire(structure)))
        bound = adapter.decode_actual_common_base_v1(wire(event), binding=binding,
                    source_bytes=candidate, common_snapshot_json=common_raw)
        need(bound.membership_independently_validated is True and
             bound.scope == adapter.ACTUAL_SCOPE and
             row['actual_semantic_sha256'] == bound.actual_semantic_sha256, 'actual common membership differs')
        physical = [frozenset((i,)) for i in range(len(structure['inputs']))]
        for left, right in domain['source_children'][len(physical):]:
            check(deadline)
            physical.append(physical[left] | physical[right])
        full_domain = dict(domain, fixed_nodes=[
            dict(item, leaves=tuple(sorted(physical[item['node']]))) for item in domain['fixed_nodes']])
        same(domain['actual_incumbent_domain_evidence'],
             trace._wire(trace.domain_evidence(actual_snapshot, full_domain,
                                               _check=lambda: check(deadline))),
             'recorded actual-domain evidence differs from physical integer accounting')
        certificate = adapter.certify_actual_common_base(bound)
        same(row['feature'], business.feature(bound, certificate, check=lambda: check(deadline)),
             'pre-J necessary-only feature differs')
        rows.append(row)
        bounds.append(bound)
        certificates.append(certificate)
        pos += 1
    need(pos < len(records) and records[pos]['kind'] == 'pre_j_selection', 'selection missing or reordered')
    selection = records[pos]
    record_keys(selection, ('slots', 'selection_seed', 'candidate_count', 'catalogue_complete',
                            'catalogue_and_feature_seconds', 'selection', 'limitations'))
    slots = business.select_slots(rows, SEED)
    same(selection['slots'], slots, 'fixed native2/signal/seeded dedup selection differs')
    need(type(selection['selection_seed']) is int and selection['selection_seed'] == SEED and
         type(selection['candidate_count']) is int and selection['candidate_count'] == len(rows)
         and selection['catalogue_complete'] is True and selection['selection'] ==
         'native2+signal1+hash-seeded-other; dedup native fill; retain empty slots', 'selection identity differs')
    selection_seconds = number(selection['catalogue_and_feature_seconds'], APP_SECONDS)
    same(selection['limitations'], [
        'Native top-root budget is at most four; often all candidates are selected.',
        'No unchanged trajectory, equal-time ranking result, or provenance mutation DAG.',
        'Only supplied newly generated development row; no old protected data read.'], 'selection limitations differ')
    pos += 1
    need(pos < len(records) and records[pos]['kind'] == 'base_integer_audit', 'base audit must precede answers')
    record_keys(records[pos], ('audit',))
    expected_base_audit = audit(structure, [('I', common_wire)], business, deadline)
    same(records[pos]['audit'], expected_base_audit, 'independent base integer audit differs')
    pos += 1
    nonempty = 0
    for slot in slots:
        check(deadline)
        need(pos < len(records), 'selected-slot answer missing')
        answer = records[pos]
        same(answer.get('slot'), slot, 'answer order or selected candidate identity differs')
        index = slot['native_ordinal']
        if index is None:
            need(answer['kind'] == 'empty_slot', 'explicit empty slot required')
            record_keys(answer, ('slot',))
        else:
            need(answer['kind'] == 'actual_exact_arms', 'nonempty exact arms required')
            record_keys(answer, ('slot', 'candidate_sha256', 'fixed_certificate', 'audit', 'arms',
                                 'I_alias', 'exact_complete'))
            need(answer['candidate_sha256'] == rows[index]['candidate_sha256'] and
                 answer['I_alias'] == 'arms.baseline' and answer['exact_complete'] is True,
                 'answer identity or completion differs')
            same(answer['fixed_certificate'], certificates[index].to_wire(), 'fixed certificate differs')
            validate_arms(answer['arms'], rows[index]['raw_event']['domain'], bounds[index],
                          common_wire, structure, trace, business, deadline)
            arms = answer['arms']
            items = [('I', arms['baseline']), *((name, arms[name]) for name in ('F', 'S', 'J')),
                     *((name, arms[name]['result']) for name in ('FS', 'SF'))]
            same(answer['audit'], audit(structure, items, business, deadline), 'answer integer audit differs')
            nonempty += 1
            answer = arms = items = None  # v3: release one large decoded record before the next
        pos += 1
    need(pos == len(records) - 1 and records[pos]['kind'] == 'complete', 'unique terminal complete required')
    end = records[pos]
    record_keys(end, ('selected_nonempty_slots', 'candidate_count', 'elapsed_seconds',
                     'stage2_acceptance_claim', 'scope'))
    need(type(end['selected_nonempty_slots']) is int and end['selected_nonempty_slots'] == nonempty
         and type(end['candidate_count']) is int and end['candidate_count'] == len(rows)
         and end['stage2_acceptance_claim'] is False and
         end['scope'] == 'actual_same_base_finite_domain_mechanism_only', 'terminal identity/count/scope differs')
    need(number(end['elapsed_seconds'], APP_SECONDS) >= selection_seconds, 'terminal timing precedes selection')
    return {'application_record_count': len(records), 'candidate_count': len(rows),
            'selected_nonempty_slots': nonempty, 'common_snapshot_sha256': sha(common_raw),
            'structure_sha256': sha(wire(structure)), 'application_elapsed_seconds': end['elapsed_seconds'],
            'mechanism_classification': ('NON_TRIGGERED_NO_APPLICABLE_DOMAIN' if not rows else
                                         'COMPLETED_SAME_BASE_FINITE_DOMAIN'),
            'classification_basis': ('complete frozen sweep0 catalogue on this actual returned base has zero domains'
                                     if not rows else 'complete declared slots and six arms; benefit is not presumed'),
            'native_outcome': native['outcome'], 'native_reason': native['reason']}


def audit(structure, items, business, deadline):
    records = []
    for label, item in items:
        check(deadline)
        need(type(item) is dict, 'complete feasible arm record required')
        actual = business.audit_tree(structure['inputs'], structure['output'], structure['sizes'],
                                     item['tree'], item['slices'], check=lambda: check(deadline))
        for name in METRICS:
            need(decimal(item[name]) == actual[name], 'independent arm metric mismatch')
        records.append({'label': label, **{name: str(actual[name]) for name in METRICS}})
    return {'all_match': True, 'independent_implementation': True, 'records': records}


def validate_arms(arms, domain, bound, common, structure, trace, business, deadline):
    keys(arms, ('scope', 'baseline', 'actual_incumbent_before', 'baseline_selection',
                'actual_incumbent_in_domain', 'baseline_is_actual_incumbent', 'same_incumbent_attribution',
                'F', 'S', 'J', 'FS', 'SF', 'transitions', 'frontier_count', 'editable_count', 'state_count'))
    need(arms['scope'] == 'exact_recorded_finite_domain_only' and
         arms['baseline_selection'] == 'actual_incumbent' and
         all(arms[name] is True for name in ('actual_incumbent_in_domain',
             'baseline_is_actual_incumbent', 'same_incumbent_attribution')), 'actual same-base arms required')
    same(arms['actual_incumbent_before'], domain['incumbent_before'], 'answer actual snapshot differs')
    need(integer(arms['transitions'], 5_000_000) > 0, 'bounded complete transition count required')
    for name, expected in (('frontier_count', len(domain['frontier'])),
                           ('editable_count', len(domain['editable'])),
                           ('state_count', 1 << len(domain['editable']))):
        need(type(arms[name]) is int and arms[name] == expected, 'finite domain dimensions differ')
    fixed = {tuple(node.leaves) for node in bound.problem.fixed_nodes}
    root_leaves = frozenset(domain['root_leaves'])
    atoms = [item['tree'] for item in domain['frontier']]
    atom_groups = [frozenset(item['leaves']) for item in domain['frontier']]

    def expand(tree, used):
        # Regional atom tree (<=10 atoms, so <=19 nodes); explicit stack, same list output.
        pending, values, count = [(tree, False)], [], 0
        while pending:
            check(deadline)
            node, visited = pending.pop()
            count += 1
            need(count <= 64, 'regional tree size exceeds bound')
            if visited:
                right, left = values.pop(), values.pop()
                values.append([left, right])
            elif type(node) is int:
                need(0 <= node < len(atoms) and node not in used, 'regional atom identity differs')
                used.add(node)
                values.append(atoms[node])
            else:
                need(type(node) is list and len(node) == 2, 'binary regional tree required')
                pending.extend(((node, True), (node[1], False), (node[0], False)))
        return values[0]

    def graft(tree, replacement):
        # v1 top-down replacement of the subtree with exactly root_leaves; lists elsewhere.
        pending, values = [(tree, False)], []
        while pending:
            check(deadline)
            node, visited = pending.pop()
            if type(node) is int:
                group = frozenset((node,))
                values.append((group, replacement if group == root_leaves else node))
            elif visited:
                right_group, right = values.pop()
                left_group, left = values.pop()
                group = left_group | right_group
                values.append((group, replacement if group == root_leaves else [left, right]))
            else:
                need(type(node) is list and len(node) == 2, 'binary physical tree required')
                pending.extend(((node, True), (node[1], False), (node[0], False)))
        return values[0][1]

    def result(item):
        need(type(item) is dict, 'feasible baseline-containing domain cannot have null arm')
        exact = trace.exact_tree(structure['inputs'], structure['output'], structure['sizes'],
                                 item['tree'], item['slices'], _check=lambda: check(deadline))
        used = set()
        regional = expand(item['region_tree'], used)
        need(used == set(range(len(atoms))), 'regional tree must use every frontier atom once')
        same(item['tree'], graft(domain['source_baseline']['tree'], regional),
             'answer changes immutable exterior or atom internals')
        present = {tuple(node['leaves']) for node in exact['nodes']}
        need(fixed <= present, 'answer removed immutable physical group')
        changed = present - fixed
        need(len(changed) == len(atoms) - 1, 'answer regional merge count differs')
        for group in changed:
            leaves = frozenset(group)
            contained = [atom for atom in atom_groups if atom <= leaves]
            need(leaves <= root_leaves and len(contained) >= 2 and
                 frozenset().union(*contained) == leaves, 'answer splits an atom or changes exterior')
        sliced = frozenset(item['slices'])
        need(bound.problem.fixed_slices <= sliced <= bound.problem.fixed_slices | set(bound.problem.editable),
             'answer slices outside finite common domain')
        outside = sum(node['work'] for node in exact['nodes'] if tuple(node['leaves']) in fixed)
        expected = trace._wire(exact)
        expected.update(region_tree=item['region_tree'], outside_work=str(outside),
                        local_work=str(exact['per_slice_work'] - outside), feasible=True)
        need(exact['result_only_peak'] <= K, 'answer violates result-only K')
        same(item, expected, 'answer snapshot/integer/feasibility fields differ')
        audit(structure, [('check', item)], business, deadline)
        return exact

    base = result(arms['baseline'])
    same(trace._tree_key(arms['baseline']['tree']), trace._tree_key(common['tree']),
         'offline baseline physical topology differs from actual common base')
    for name in ('slices', 'contractions', *METRICS):
        same(arms['baseline'][name], common[name], 'offline baseline differs from actual common base')
    for name in ('F', 'S', 'J'):
        result(arms[name])
    same(arms['F']['slices'], common['slices'], 'F changes held-fixed slices')
    same(trace._tree_key(arms['S']['tree']), trace._tree_key(common['tree']),
         'S changes held-fixed physical topology')
    for name in ('F', 'S'):
        need(decimal(arms[name]['total_work']) <= base['total_work'],
             'conditional optimum is worse than admitted feasible baseline')
    for name in ('FS', 'SF'):
        alternating = arms[name]
        keys(alternating, ('status', 'result', 'history'))
        need(alternating['status'] == 'strict_fixed_point' and type(alternating['history']) is list
             and len(alternating['history']) <= 128, 'complete bounded strict alternation required')
        final = result(alternating['result'])
        if not alternating['history']:
            same(alternating['result'], arms['baseline'],
                 'empty strict alternation history changes baseline')
        previous = base['total_work']
        previous_slices = common['slices']
        position = -1
        for step in alternating['history']:
            keys(step, ('arm', 'before', 'after', 'slices'))
            need(step['arm'] in ('F', 'S') and decimal(step['before']) == previous
                 and decimal(step['after']) < previous, 'strict alternation work chain differs')
            position += 1
            while name[position % 2] != step['arm']:
                position += 1
            need(position < 128, 'alternation exceeds64 sweeps')
            if step['arm'] == 'F':
                same(step['slices'], previous_slices, 'F alternation changes slices')
            need(type(step['slices']) is list and all(type(x) is str for x in step['slices'])
                 and step['slices'] == sorted(set(step['slices'])), 'canonical history slices required')
            history_slices = frozenset(step['slices'])
            need(bound.problem.fixed_slices <= history_slices <=
                 bound.problem.fixed_slices | set(bound.problem.editable),
                 'strict history leaves finite slice domain')
            previous, previous_slices = decimal(step['after']), step['slices']
        need(final['total_work'] == previous, 'alternation terminal work differs from strict history')
        same(alternating['result']['slices'], previous_slices, 'alternation final slices differ')
    joint = decimal(arms['J']['total_work'])
    for item in (arms['baseline'], arms['F'], arms['S'], arms['FS']['result'], arms['SF']['result']):
        need(joint <= decimal(item['total_work']), 'joint score worse than an admitted domain result')


def write_all(fd, raw, deadline):
    pending = memoryview(raw)
    while pending:
        check(deadline)
        count = os.write(fd, pending)
        need(count > 0, 'short acceptance publication')
        pending = pending[count:]


class MechanismBlocked(ValueError):
    """Implementation bound, never scientific non-applicability."""


def fixed_rows():
    rows = []
    for n in (48, 64, 96):
        for seed in (10, 20):
            for representation in ('L_ADCRS', 'L_no_ADCRS'):
                ordinal = len(rows)
                rows.append({'row_id': f'N{n}-s{seed}-{representation}', 'ordinal': ordinal,
                             'batch': ordinal // 2 + 1, 'N': n, 'seed': seed, 'bit': (n - 1) // 2,
                             'representation': representation, 'parent_id': f'N{n}-s{seed}',
                             'source_group': f'qpe-inexact-N{n}'})
    return rows


def hex_sha(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value, re.ASCII) is not None


def configure_request(replay, request_sha):
    global GEN_SHA, NATIVE_SHA, INPUT_PINS, REQUEST_PIN, ROW, SEED
    need(REQUEST_PIN is None, 'request configuration is single-use')
    need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', replay, re.ASCII) is not None,
         'fresh explicit bounded namespace spelling required')
    need(hex_sha(request_sha), 'exact caller request digest required')
    path = Path('/request/request.json')
    no_link(path)
    size = path.stat().st_size
    need(0 < size <= 65536, 'bounded exact caller request required')
    pin = (size, request_sha)
    request = decode(read_pin(path, pin))
    keys(request, ('schema', 'replay_id', 'row', 'selection_seed', 'runtime_map_sha256',
                   'image_id', 'external_limits', 'inputs'))
    need(request['schema'] == 'qpe-fixed-row-mechanism-request-v3' and request['replay_id'] == replay,
         'exact caller protocol/namespace differs')
    row = request['row']
    need(type(row) is dict and type(row.get('ordinal')) is int and 1 <= row['ordinal'] <= 11,
         'only new fixed row ordinal1..11; R32 ordinal0 is excluded')
    same(row, fixed_rows()[row['ordinal']], 'fixed matrix row mapping differs')
    need(type(request['selection_seed']) is int and request['selection_seed'] == row['seed'],
         'selection seed must equal this fixed row seed')
    need(request['image_id'] == IMAGE and request['external_limits'] == LIMITS,
         'exact existing image/whole-slot attestation required')
    expected_map = sha(wire({name: value[1] for name, value in sorted(PINS.items())}))
    need(request['runtime_map_sha256'] == expected_map, 'fixed five-source digest differs')
    keys(request['inputs'], ('generation.json', 'native.json', 'candidate.py'))
    input_pins = {}
    for name, value in request['inputs'].items():
        keys(value, ('bytes', 'sha256'))
        need(type(value['bytes']) is int and 0 < value['bytes'] <= 8 << 20 and hex_sha(value['sha256']),
             'exact bounded raw input byte count/SHA256 required')
        input_pins[name] = (value['bytes'], value['sha256'])
    same(list(input_pins['candidate.py']), [29623, SOURCE_SHA], 'trusted immutable candidate differs')
    ROW, SEED, INPUT_PINS, REQUEST_PIN = row, row['seed'], input_pins, pin
    GEN_SHA, NATIVE_SHA = input_pins['generation.json'][1], input_pins['native.json'][1]
    return expected_map


def validate_saved_pair(generation, native):
    structure = {name: generation['case'][name] for name in ('inputs', 'output', 'sizes')}
    need(type(structure['inputs']) is list and structure['inputs'] and
         type(structure['output']) is list and type(structure['sizes']) is dict,
         'complete physical ordered structure required')
    expected_sources = SCIENCE_SOURCES[str(ROW['ordinal'])]
    expected_source_map = sha(wire(expected_sources))
    for value, stage in ((generation, 'generation'), (native, 'native')):
        same(value['row'], ROW, 'accepted row differs')
        need(value.get('schema') == 'qpe-capacity-opportunity-screen-v1' and value.get('stage') == stage and
             type(value.get('K')) is int and value['K'] == K and value.get('entry_status') == 'PASS' and
             value.get('entry_schema') == 'qpe-capacity-opportunity-entry-v1' and
             value.get('stage2_complete') is False and value.get('sources_rechecked_after_mode') is True and
             value.get('arrays_exported') is False and value.get('j_search_executed') is False,
             'completed accepted screen entry identity differs')
        same(value['source_sha256_before'], expected_sources, 'frozen science source map before differs')
        same(value['source_sha256_after'], expected_sources, 'frozen science source map after differs')
        need(value['runtime_map_sha256'] == expected_source_map and
             value['image_identity']['caller_attested_image_id'] == IMAGE and
             value['structure_sha256'] == sha(wire(structure)), 'screen source/image/structure differs')
        number(value['startup_inclusive_elapsed_seconds'], 900)
    case = generation['case']
    need(case['name'] == ROW['row_id'] and case['source']['parent_id'] == ROW['parent_id'] and
         case['source']['representation'] == ROW['representation'] and generation['outcome'] == 'READY' and
         native['outcome'] in ('NULL', 'HIT_THIS_BASE') and native['native_call_completed'] is True and
         native['accepted_generation_raw_sha256'] == GEN_SHA,
         'direct completed own-generation native required; UNKNOWN/scalar/missing is inadmissible')
    same(native['native_returned_path'], native['diagnostics']['native_returned_path'],
         'direct returned path diagnostics differ')
    same(native['native_returned_sliced'], native['diagnostics']['native_returned_sliced'],
         'direct returned slices diagnostics differ')
    need(native['diagnostics']['execution_evidence'] == 'native_call_completed', 'native completion missing')
    sliced = native['native_returned_sliced']
    need(type(sliced) is list and all(type(x) is str for x in sliced) and len(sliced) == len(set(sliced)) and
         set(sliced) <= structure['sizes'].keys() and not set(sliced).intersection(structure['output']),
         'real unique physical non-output slice set required')
    for label in ('returned', 'same_path_unsliced'):
        for name in (*METRICS, 'contractions'):
            need(type(native['exact'][label][name]) is int and native['exact'][label][name] >= 0,
                 'accepted native exact integer metrics required')
    need(native['exact']['returned']['result_only_peak'] <= K, 'native returned base must be feasible')
    unsliced_peak = native['exact']['same_path_unsliced']['result_only_peak']
    expected = (('NULL', 'NO_NATIVE_SLICES') if not sliced else
                ('NULL', 'SLICES_NOT_NEEDED_BY_THIS_BASE') if unsliced_peak <= K else
                ('HIT_THIS_BASE', 'RETURNED_BASE_CAPACITY_SENSITIVE'))
    same([native['outcome'], native['reason']], list(expected), 'native receipt classification differs')


def direct_path_depth(path, n, deadline):
    # Diagnose the existing implementation bound without building or truncating a tree.
    need(type(n) is int and 1 <= n <= 20000 and type(path) is list and len(path) == n - 1,
         'complete bounded direct native path required')
    depths = [0] * n
    for step in path:
        check(deadline)
        need(type(step) is list and len(step) == 2 and all(type(x) is int for x in step),
             'exact binary recycled-index native path required')
        a, b = step
        need(a != b and 0 <= a < len(depths) and 0 <= b < len(depths), 'invalid native path position')
        depth = 1 + max(depths[a], depths[b])
        for i in sorted((a, b), reverse=True):
            depths.pop(i)
        depths.append(depth)
    need(len(depths) == 1, 'incomplete native path')
    return depths[0]


def main():
    need(sys.platform == 'linux' and sys.flags.isolated and sys.dont_write_bytecode and
         Path(__file__) == SELF and Path(__file__).resolve() == SELF and len(sys.argv) == 3,
         'exact Linux -I -B /checks/mechanism_accept.py invocation required')
    started = process_start()
    deadline = started + WRAPPER_SECONDS

    def expired(signum, frame):
        os._exit(124)  # No acceptance on timeout; guardian owns inherited descendants.

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, max(.000001, deadline - time.monotonic()))
    capture = Capture()
    publishing = False
    try:
        replay, request_sha = sys.argv[1:]
        expected_map = configure_request(replay, request_sha)
        no_link(SELF)
        need(SELF.is_file() and 0 < SELF.stat().st_size <= 1 << 20, 'bounded separately pinned helper required')
        helper_sha = sha(SELF.read_bytes())
        before = inventory(deadline)
        need(sha(wire(before)) == expected_map, 'five-filename runtime source map differs')
        generation = decode(read_pin(Path('/input/generation.json'), INPUT_PINS['generation.json']))
        native = decode(read_pin(Path('/input/native.json'), INPUT_PINS['native.json']))
        candidate = read_pin(Path('/input/candidate.py'), INPUT_PINS['candidate.py'])
        validate_saved_pair(generation, native)
        depth = direct_path_depth(native['native_returned_path'], len(generation['case']['inputs']), deadline)
        if depth > MAX_TREE_DEPTH:
            raise MechanismBlocked('full actual returned tree depth ' + str(depth) +
                                   ' exceeds the finite physical bound; Stage2 unresolved')
        command = [sys.executable, '-I', '-B', str(ENTRY),
                   '--generation', '/input/generation.json', '--generation-sha256', GEN_SHA,
                   '--native', '/input/native.json', '--native-sha256', NATIVE_SHA,
                   '--source', '/input/candidate.py', '--source-map-sha256', expected_map,
                   '--replay-id', replay, '--selection-seed', str(SEED), '--seconds', str(APP_SECONDS),
                   '--image-id', IMAGE, '--external-limits', APP_LIMITS]
        capture.run(command, deadline)
        for line in bytes(capture.stderr).splitlines():
            try:
                message = stack().loads(line, object_pairs_hook=pairs, parse_constant=reject_constant)
            except (ValueError, UnicodeError):
                continue
            need(type(message) is not dict or message.get('kind') != 'mechanism_incomplete',
                 'child explicitly reported incomplete mechanism')
        same(inventory(deadline), before, 'runtime or input bytes changed during application')
        need(len(capture.stdout) == 0, 'v3 child stdout must be empty; evidence goes to /output')
        out_dir = EVIDENCE.parent
        no_link(EVIDENCE)
        need(out_dir.is_dir() and {p.name for p in out_dir.iterdir()} == {EVIDENCE.name} and
             EVIDENCE.is_file() and 0 < EVIDENCE.stat().st_size <= MAX_EVIDENCE,
             'exact single bounded /output/evidence.jsonl required')
        with EVIDENCE.open('rb') as stream:
            need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'regular evidence descriptor required')
            raw = stream.read(MAX_EVIDENCE + 1)
        need(len(raw) == EVIDENCE.stat().st_size, 'evidence size changed while reading')
        modules = load_pure(deadline)
        summary = validate_stream(raw, replay, before, generation, native, candidate, modules, deadline)
        same(inventory(deadline), before, 'runtime or input bytes changed during acceptance')
        need(sha(SELF.read_bytes()) == helper_sha, 'acceptance helper bytes changed')
        for name, module in modules.items():
            need(sys.modules.get(name) is module, 'validator module identity changed')
        check(deadline)
        control = {'protocol': 'qpe-actual-mechanism-byte-acceptance-v1',
                   'kind': 'MECHANISM_ACCEPTED', 'status': 'PASS', 'replay_id': replay,
                   'scope': 'saved_accepted_fixed_row_same_base_finite_domain_only',
                   'request_sha256': request_sha, 'row': ROW,
                   'raw_bytes': len(raw), 'raw_sha256': sha(raw), 'evidence_file': 'evidence.jsonl',
                   'stderr_bytes': len(capture.stderr), 'stderr_sha256': sha(bytes(capture.stderr)),
                   'runtime_map_sha256': expected_map, 'source_map': before,
                   'generation_sha256': GEN_SHA, 'native_sha256': NATIVE_SHA,
                   'candidate_sha256': SOURCE_SHA, 'helper_sha256': helper_sha, 'image_id_attested': IMAGE,
                   'entry_exit_code': capture.exit_code, 'entry_stdout_eof': capture.eof['stdout'],
                   'entry_stderr_eof': capture.eof['stderr'], 'sources_and_inputs_rechecked': True,
                   'selection_seed': SEED, 'application_seconds': APP_SECONDS,
                   'wrapper_seconds': WRAPPER_SECONDS, 'external_whole_seconds_required': 15000,
                   'startup_clock_verified': True, 'startup_inclusive_elapsed_seconds': time.monotonic() - started,
                   'external_limits_verified_inside_child': False, 'image_identity_verified_inside_child': False,
                   'physical_lineage_certified': False, 'pre_j_external_commitment_certified': False,
                   'offline_optima_recomputed_by_acceptor': False, 'stage2_complete': False,
                   'new_scientific_sample': False, **summary}
        need(len(wire(control)) + 1 <= 16384, 'bounded terminal acceptance control required')
        # v3: evidence stays in /output/evidence.jsonl (host re-hashes it against raw_sha256);
        # stdout carries only the bounded control record.
        publishing = True
        write_all(2, bytes(capture.stderr), deadline)
        write_all(1, wire(control) + b'\n', deadline)
        check(deadline)
        return 0
    except MechanismBlocked as error:
        message = wire({'kind': 'MECHANISM_IMPLEMENTATION_BLOCKED', 'status': 'BLOCKED',
                        'error': str(error), 'request_sha256': REQUEST_PIN[1],
                        'row': ROW, 'scientific_non_applicability': False,
                        'stage2_unresolved': True, 'stage2_complete': False}) + b'\n'
        write_all(2, message, deadline)
        return 2
    except Exception as error:
        # No application stdout or positive acceptance is emitted on validation failure.
        # A failure during publication may leave a prefix; the host must require exit0 + EOF + control.
        message = wire({'kind': 'mechanism_acceptance_incomplete', 'status': 'FAIL',
                        'error_type': type(error).__name__, 'error': str(error)[:1000],
                        'no_partial_optimum_or_stage_completion_claim': True}) + b'\n'
        try:
            diagnostics = b'' if publishing else bytes(capture.stderr[:MAX_STDERR - len(message)])
            write_all(2, diagnostics + message, deadline)
        except Exception:
            pass
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    raise SystemExit(main())
