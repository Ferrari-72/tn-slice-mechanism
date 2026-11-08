"""SOURCE ONLY / tests NOT_RUN: bounded actual-common-base mechanism diagnostic.

v3 (evidence-to-file): records are written byte-for-byte as in v2, but to the
exclusive new file /output/evidence.jsonl (cap 1 GiB) instead of stdout; stdout
stays empty. --seconds bound 1..14400, audit child timeout 600 s, limits token
parent-attests-v3-whole-slot-1cpu. No scientific rule, record or field changed.

Parent-approved invocation in the pinned Linux image (no launch/registration here):
 python -I -B /runtime/qpe_actual_incumbent_mechanism.py \
   --generation /input/generation.json --generation-sha256 G \
   --native /input/native.json --native-sha256 N --source /input/candidate.py \
   --source-map-sha256 M --replay-id NEW --selection-seed SEED --seconds 90 \
   --image-id sha256:286b4627047f20b00b3ddb38580a2fcc10fa82f9ede6a50d8039d84ad66262df \
   --external-limits parent-attests-whole-slot-1cpu-3gib

/runtime must contain exactly this file, qpe_j26_trace.py,
qpe_fixed_capacity_trace_adapter.py, qpe_fixed_capacity_certificate.py and
qpe_mechanism_stack.py (v2). M hashes compact sorted ASCII JSON
{filename: actual lowercase SHA256} for those five. v2 removes the depth-128 tree
limit: full physical trees are validated, scored, copied and serialized iteratively.
Candidate is the explicitly trusted registered fresh J26 source, readonly.
Generation/native are exact parent-accepted screen receipts, not array payloads.
Supports HIT and completed NULL native returns alike, without selecting winners.
A catalogue-only derived source skips DP at the existing pre-DP domain hook;
this is NOT an unchanged native search or equal-time ranking experiment. Frozen
trace source is never modified. Only sweep0 domains are the common-base pool.
All candidates/features and fixed four slots are flushed before offline arms.
Parent must preserve stdout, enforce whole-process-tree time/memory/image/mount
limits, and reject nonzero exit, missing terminal receipt or incomplete capture.
No scientific quality is supplied on budget exhaustion. Image/limit attestations
and byte identities are not proof of accepted provenance or mutation-DAG coverage.
"""
from __future__ import annotations

import argparse
import ast
from contextlib import redirect_stdout
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
from types import ModuleType

ROOT = Path(__file__).resolve().parent
FILES = ("qpe_actual_incumbent_mechanism.py", "qpe_j26_trace.py",
         "qpe_fixed_capacity_trace_adapter.py", "qpe_fixed_capacity_certificate.py",
         "qpe_mechanism_stack.py")
TRACE_SHA = "8b38e1317c92fe111cb7d6f12c7f32b6db5c80cea405713242a44e9e58c62903"
STACK_SHA = "8e0844b51f32765ff6ea44ad6e6ed0a59f954286dc8915e50b870c063517f653"
SOURCE_SHA = "ce758e8d95c445dfc464c5941d5b9c416b0999a1fda8d1bde97f3736001d38f7"
IMAGE = "sha256:286b4627047f20b00b3ddb38580a2fcc10fa82f9ede6a50d8039d84ad66262df"
K = 2 ** 28
MAX_BYTES = 8 << 20
MAX_EVIDENCE_BYTES = 1 << 30  # must equal mechanism_accept.MAX_EVIDENCE
EVIDENCE = Path("/output/evidence.jsonl")
LIMITS_TOKEN = "parent-attests-v3-whole-slot-1cpu"
MAX_SECONDS = 14400
MAX_TREE_DEPTH = 19999  # complete binary tree over <=20000 physical inputs
METRICS = ("multiplicity", "per_slice_work", "total_work", "result_only_peak")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load_stack():
    """Hash-pinned sibling codec, shared through sys.modules with trace/adapter."""
    name = "qpe_mechanism_stack"
    module = sys.modules.get(name)
    if module is None:
        path = ROOT / (name + ".py")
        require(not path.is_symlink() and path.is_file(), "regular stack source required")
        raw = path.read_bytes()
        require(sha(raw) == STACK_SHA, "mechanism stack source pin differs")
        spec = importlib.util.spec_from_file_location(name, str(path))
        module = importlib.util.module_from_spec(spec)
        module.__qpe_stack_sha256__ = sha(raw)
        sys.modules[name] = module
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    require(getattr(module, "__qpe_stack_sha256__", None) == STACK_SHA,
            "loaded mechanism stack identity differs")
    return module


def encode(value):
    # Identical bytes to v1 json.dumps(sort_keys, compact, ASCII); iterative when deep.
    return load_stack().dumps(value)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(raw):
    def bad(value):
        raise ValueError("nonfinite JSON constant")
    result = load_stack().loads(raw, object_pairs_hook=pairs, parse_constant=bad)
    encode(result)  # also refuses overflowed float literals
    return result


def read_pinned(filename, expected):
    path = Path(filename)
    require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode) and
            0 < path.stat().st_size <= MAX_BYTES, "bounded regular input required")
    with path.open("rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "regular input required")
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES and sha(raw) == expected, "input byte SHA256 mismatch")
    return raw


def load(name):
    filename = ROOT / (name + ".py")
    require(name not in sys.modules, "unexpected preloaded sibling module")
    spec = importlib.util.spec_from_file_location(name, filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def catalogue_source(source_bytes, trace):
    """No DP or acceptance: one inserted continue after the real domain hook.

    Verify removal restores the entire trace-derived module AST, whose target
    trace.transform_source independently checks against the original candidate.
    Both sweeps remain unchanged; their common base cannot mutate. Only sweep0
    enters the finite pool, so repeated sweep1 candidates are not extra slots.
    """
    source, provenance = trace.transform_source(source_bytes.decode("utf-8"),
                                                expected_sha256=SOURCE_SHA)
    anchor = "            " + trace.HOOK + "('domain', locals())\n"
    require(source.count(anchor) == 1, "unique real pre-DP domain hook required")
    changed = source.replace(anchor, anchor + "            continue\n", 1)
    tree = ast.parse(changed)
    targets = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == trace.TARGET]
    require(len(targets) == 1, "unique catalogue target required")
    removed = 0
    for node in ast.walk(targets[0]):
        if not isinstance(node, ast.For):
            continue
        for i, statement in enumerate(node.body[:-1]):
            if (isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
                    and isinstance(statement.value.func, ast.Name)
                    and statement.value.func.id == trace.HOOK
                    and statement.value.args and isinstance(statement.value.args[0], ast.Constant)
                    and statement.value.args[0].value == "domain"):
                require(isinstance(node.body[i + 1], ast.Continue), "catalogue skip missing")
                del node.body[i + 1]
                removed += 1
                break
    require(removed == 1 and ast.dump(tree, include_attributes=False) ==
            ast.dump(ast.parse(source), include_attributes=False), "catalogue AST restoration failed")
    return changed, {**provenance, "catalogue_sha256": sha(changed.encode("utf-8")),
                     "catalogue_only_skips_dp": True, "whole_trace_ast_restored": True}


def feature(bound, certificate, check=lambda: None):
    """Owner-only <=64-mask scan; no J answer or feasibility DP is accepted.

    Prefer unrejected masks reducing multiplicity whose unchanged actual regional
    results violate K; then their affected regional work. Same-multiplicity swaps
    remain in the persisted mask table, even when the primary opportunity is zero.
    """
    p = bound.problem
    base_factor = math.prod(p.dims[x] for x in bound.actual_slices)
    region_groups = {frozenset(node.leaves) for node in p.baseline_regional_nodes}
    work = audit_tree(p.inputs, p.output, dict(p.dims), p.tree, bound.actual_slices,
                      check=check, include_nodes=True)
    affected = sum(node[1] for node in work["nodes"] if node[0] in region_groups)
    masks, best = [], (0, 0)
    for config in certificate.configurations:
        check()
        factor = math.prod(p.dims[x] for x in config.slices)
        opportunity = (not config.fixed_witnesses and bool(config.baseline_observation.violations)
                       and factor < base_factor)
        gain = base_factor - factor if opportunity else 0
        best = max(best, (gain, affected if opportunity else 0))
        masks.append({"mask": config.mask, "slices": sorted(config.slices),
                      "multiplicity": str(factor),
                      "fixed_witness_count": len(config.fixed_witnesses),
                      "actual_regional_violation_count": len(config.baseline_observation.violations),
                      "same_multiplicity_swap": factor == base_factor and config.slices != bound.actual_slices})
    return {"rank": [str(best[0]), str(best[1])], "affected_region_work": str(affected),
            "work_only_rank": str(affected), "masks": masks,
            "scope": "necessary_signal_not_feasibility_or_improvement"}


def select_slots(rows, seed):
    require(type(seed) is int and 0 <= seed < 2 ** 32, "explicit uint32 selection seed required")
    native = list(range(len(rows)))
    signal_order = sorted(native, key=lambda i: (-int(rows[i]["feature"]["rank"][0]),
                                                -int(rows[i]["feature"]["rank"][1]), i))
    # Hash-seeded permutation, fully specified without Python random version ties.
    other = sorted(native, key=lambda i: (sha(encode([seed, rows[i]["candidate_sha256"]])), i))
    selected, slots = [], []
    preferences = [("native1", native[:1]), ("native2", native[1:2]),
                   ("signal1", signal_order[:1]), ("seeded_other", other)]
    for role, preferred in preferences:
        choice = next((i for i in preferred if i not in selected), None)
        if choice is None:
            choice = next((i for i in native if i not in selected), None)
        slots.append({"role": role, "native_ordinal": choice,
                      "candidate_sha256": None if choice is None else rows[choice]["candidate_sha256"]})
        if choice is not None:
            selected.append(choice)
    return slots


def audit_tree(inputs, output, dims, tree, slices, *, check=lambda: None, include_nodes=False):
    """Independent iterative integer scorer, not trace.exact_tree/collect_exact.

    Input boundaries use owner incidence too (one-owner output semantics and
    hyperedges); raw leaf volumes never contribute to the result-only peak.
    """
    require(type(inputs) in (tuple, list) and bool(inputs) and type(output) in (tuple, list, str, frozenset),
            "nonempty builtin physical input sequence required")
    require(type(dims) is dict and all(type(x) is str and bool(x) and type(d) is int and d > 0
                                      for x, d in dims.items()), "exact positive integer audit dimensions required")
    require(all(type(term) in (tuple, list, str, frozenset) and all(type(x) is str and bool(x) for x in term)
                and len(term) == len(set(term)) for term in inputs), "audit duplicate/invalid input axes")
    require(set(dims) == {x for term in inputs for x in term} and len(output) == len(set(output))
            and set(output) <= dims.keys(), "audit physical label/output mismatch")
    require(type(slices) in (tuple, list, frozenset) and len(slices) == len(set(slices)),
            "audit unique builtin slice sequence required")
    slices = frozenset(slices)
    require(slices <= dims.keys() and not slices.intersection(output), "invalid audit slices")
    owners = {x: frozenset(i for i, term in enumerate(inputs) if x in term) for x in dims}
    require(all(len(own) >= 2 or x in output for x, own in owners.items()),
            "audit nonoutput unary reductions unsupported")
    # v2: explicit value stack (no per-node root paths); complete finite trees of any
    # depth <= MAX_TREE_DEPTH. Same postorder, same integer accounting as v1.
    pending, values, seen, nodes = [(tree, 0, False)], [], set(), []
    total, peak = 0, 0
    active = set()
    while pending:
        check()
        node, depth, visited = pending.pop()
        require(depth <= MAX_TREE_DEPTH, "audit tree depth exceeds finite physical bound")
        if type(node) is int:
            require(0 <= node < len(inputs) and node not in seen, "audit invalid physical leaf")
            seen.add(node)
            group = frozenset((node,))
        else:
            require(type(node) in (tuple, list) and len(node) == 2, "audit binary tree required")
            if not visited:
                require(id(node) not in active, "audit cyclic tree")
                active.add(id(node))
                pending.extend(((node, depth, True), (node[1], depth + 1, False),
                                (node[0], depth + 1, False)))
                continue
            active.discard(id(node))
            right, left = values.pop(), values.pop()
            group = left[0] | right[0]
        boundary = frozenset(x for x, own in owners.items() if x not in slices and
                             own & group and (x in output or own - group))
        if type(node) is not int:
            merge = math.prod(dims[x] for x in left[1] | right[1])
            size = math.prod(dims[x] for x in boundary)
            total += merge
            peak = max(peak, size)
            if include_nodes:
                nodes.append((group, merge, size))
        values.append((group, boundary))
    require(len(values) == 1 and seen == set(range(len(inputs))), "audit incomplete full tree")
    multiplicity = math.prod(dims[x] for x in slices)
    result = {"multiplicity": multiplicity, "per_slice_work": total,
              "total_work": total * multiplicity, "result_only_peak": peak}
    if include_nodes:
        result["nodes"] = nodes
    return result


def audit_records(payload):
    require(type(payload) is dict and type(payload.get("records")) is list and
            1 <= len(payload["records"]) <= 40, "nonempty bounded audit records required")
    result = []
    for item in payload["records"]:
        actual = audit_tree(payload["inputs"], payload["output"], payload["sizes"],
                            item["tree"], item["slices"])
        require(set(item["expected"]) == set(METRICS), "complete exact metric expectation required")
        require(all(type(v) is str and v.isascii() and v.isdecimal() and
                    (v == "0" or not v.startswith("0")) for v in item["expected"].values()),
                "canonical integer metric strings required")
        require(all(str(actual[k]) == item["expected"][k] for k in METRICS),
                "independent exact audit mismatch")
        result.append({"label": item["label"], **{k: str(actual[k]) for k in METRICS}})
    return {"all_match": True, "independent_implementation": True, "records": result}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-records", action="store_true")
    for name in ("generation", "generation-sha256", "native", "native-sha256", "source",
                 "source-map-sha256", "replay-id", "image-id", "external-limits"):
        parser.add_argument("--" + name)
    parser.add_argument("--selection-seed", type=int)
    parser.add_argument("--seconds", type=int, default=90)
    args = parser.parse_args(argv)
    require(sys.platform == "linux" and sys.flags.isolated and sys.dont_write_bytecode,
            "Linux Python -I -B required")
    load_stack()
    if args.audit_records:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        require(len(raw) <= MAX_BYTES, "audit payload too large")
        print(encode(audit_records(decode(raw))).decode("ascii"), flush=True)
        return 0
    require(ROOT == Path("/runtime") and not ROOT.is_symlink() and
            {p.name for p in ROOT.iterdir()} == set(FILES), "exact five-file readonly runtime required")
    require(args.image_id == IMAGE and args.external_limits == LIMITS_TOKEN,
            "parent image and external whole-slot limit attestations required")
    require(type(args.seconds) is int and 1 <= args.seconds <= MAX_SECONDS, "bounded seconds required")
    require(type(args.replay_id) is str and 0 < len(args.replay_id) <= 256,
            "fresh explicit bounded replay namespace required")
    require(type(args.selection_seed) is int and 0 <= args.selection_seed < 2 ** 32,
            "explicit uint32 selection seed required")
    proc = Path("/proc/self/stat").read_text(encoding="ascii")
    ticks = int(proc[proc.rfind(")") + 2:].split()[19])
    age = time.clock_gettime(time.CLOCK_BOOTTIME) - ticks / os.sysconf("SC_CLK_TCK") + 0.01
    require(0 <= age < args.seconds, "process-start allowance exhausted")
    started = time.monotonic() - age
    deadline = started + args.seconds

    def check():
        if time.monotonic() >= deadline:
            raise TimeoutError("startup-inclusive mechanism budget exhausted")

    def expired(signum, frame):
        raise TimeoutError("mechanism hard alarm exhausted; no complete quality claim")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, deadline - time.monotonic())
    hashes = {}
    for name in FILES:
        path = ROOT / name
        require(not path.is_symlink() and path.is_file() and 0 < path.stat().st_size < (1 << 20),
                "bounded individual runtime source required")
        hashes[name] = sha(path.read_bytes())
    require(sha(encode(hashes)) == args.source_map_sha256 and hashes["qpe_j26_trace.py"] == TRACE_SHA
            and hashes["qpe_mechanism_stack.py"] == STACK_SHA,
            "runtime source map or frozen trace/stack hash mismatch")
    source_bytes = read_pinned(args.source, SOURCE_SHA)
    generation = decode(read_pinned(args.generation, args.generation_sha256))
    native = decode(read_pinned(args.native, args.native_sha256))
    require(generation.get("schema") == native.get("schema") == "qpe-capacity-opportunity-screen-v1" and
            generation.get("stage") == "generation" and generation.get("outcome") == "READY" and
            native.get("stage") == "native" and native.get("native_call_completed") is True and
            native.get("outcome") in ("HIT_THIS_BASE", "NULL"), "completed generation/native receipts required")
    require(generation["row"] == native["row"] and generation["K"] == native["K"] == K,
            "generation/native row or K mismatch")
    case = generation["case"]
    structure = {k: case[k] for k in ("inputs", "output", "sizes")}
    require(sha(encode(structure)) == generation["structure_sha256"] == native["structure_sha256"],
            "generation/native ordered structure mismatch")
    inputs, output, sizes = (case[k] for k in ("inputs", "output", "sizes"))
    path, sliced = native["native_returned_path"], native["native_returned_sliced"]
    require(native["diagnostics"]["native_returned_path"] == path and
            native["diagnostics"]["native_returned_sliced"] == sliced and
            native["diagnostics"]["execution_evidence"] == "native_call_completed", "direct native base required")
    check()
    trace = load("qpe_j26_trace")
    load("qpe_fixed_capacity_certificate")
    adapter = load("qpe_fixed_capacity_trace_adapter")
    common = trace.collect_exact(inputs, output, sizes, path, sliced, _check=check)
    require(common["result_only_peak"] <= K, "actual common base is infeasible")
    native_exact = native["exact"]["returned"]
    require(all(type(native_exact[k]) is int and native_exact[k] == common[k] for k in METRICS),
            "parent-accepted native exact metrics disagree with supplied base")
    common_wire = trace._wire(common)
    common_raw = encode(common_wire)
    changed, provenance = catalogue_source(source_bytes, trace)
    output_bytes = 0
    require(not EVIDENCE.parent.is_symlink() and EVIDENCE.parent.is_dir() and
            not any(EVIDENCE.parent.iterdir()), "empty exclusive /output directory required")
    evidence_fd = os.open(str(EVIDENCE), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)

    def emit(kind, **fields):
        nonlocal output_bytes
        check()
        raw = encode({"schema": "qpe-actual-incumbent-mechanism-v1", "kind": kind,
                      "replay_id": args.replay_id, **fields}) + b"\n"
        output_bytes += len(raw)
        require(output_bytes <= MAX_EVIDENCE_BYTES, "mechanism evidence exceeds 1 GiB; incomplete")
        pending = memoryview(raw)
        while pending:
            count = os.write(evidence_fd, pending)
            require(count > 0, "short evidence write")
            pending = pending[count:]
        os.fsync(evidence_fd)

    emit("common_base", common=common_wire, common_snapshot_sha256=sha(common_raw),
         generation_sha256=args.generation_sha256, native_sha256=args.native_sha256,
         source_map=hashes, source_sha256=SOURCE_SHA, provenance=provenance,
         baseline_origin="parent-accepted direct native screen return; prefix not rerun",
         image_id_attested=args.image_id, external_limits_verified_inside_child=False,
         base_planning_seconds_charged=native["startup_inclusive_elapsed_seconds"],
         generation_seconds_charged=generation["startup_inclusive_elapsed_seconds"])
    rows, domains, bounds, certificates = [], [], [], []

    def hook(kind, state):
        check()
        require(kind == "domain", "catalogue executed DP/acceptance unexpectedly")
        if state["sweep"] != 0:
            return
        require(len(rows) < 4, "native common-base catalogue exceeds four roots")
        domain = trace._domain_record(state, inputs, output, sizes, K)
        wire = trace._wire(domain)
        event = {"schema": "qpe-j26-trace-v1", "kind": "domain",
                 "domain_id": len(rows) + 1, "domain": wire}
        raw = encode(event)
        candidate_hash = sha(encode(wire))
        binding = adapter.ActualCommonBaseBinding(
            adapter.CallerBinding(sha(raw), args.replay_id, event["domain_id"]), SOURCE_SHA,
            sha(common_raw), candidate_hash, sha(encode(structure)))
        bound = adapter.decode_actual_common_base_v1(raw, binding=binding,
                    source_bytes=source_bytes, common_snapshot_json=common_raw)
        certificate = adapter.certify_actual_common_base(bound)
        row = {"native_ordinal": len(rows), "domain_id": event["domain_id"],
               "candidate_sha256": candidate_hash, "raw_event_sha256": sha(raw),
               "actual_semantic_sha256": bound.actual_semantic_sha256,
               "feature": feature(bound, certificate, check), "raw_event": event}
        emit("pre_j_candidate", **row)
        rows.append(row)
        domains.append(domain)
        bounds.append(bound)
        certificates.append(certificate)

    # Any external cotengra/candidate failure on a deep tree propagates to
    # mechanism_incomplete. No rebalance, partial tree or summary substitution.
    namespace = ModuleType("_qpe_actual_catalogue_trusted")
    namespace.__file__ = args.source
    namespace.__dict__[trace.HOOK] = hook
    # This is explicitly trusted source, not an untrusted-plugin sandbox.
    with redirect_stdout(sys.stderr):
        exec(compile(changed, args.source, "exec"), namespace.__dict__)
        require(namespace.CAP == K, "candidate K differs")
        import cotengra as ctg
        base = ctg.ContractionTree.from_path(inputs, output, sizes,
                     path=[tuple(step) for step in path], check=True, autocomplete=False)
        for label in sliced:
            check()
            base = base.remove_ind(label)
        # All catalogue candidates use the identical actual base, with DP skipped.
        returned = getattr(namespace, trace.TARGET)(inputs, output, sizes, base, native["row"]["seed"])
        final = trace.snapshot(inputs, output, sizes, returned)
    require(encode(trace._wire(final)) == common_raw, "catalogue changed the actual base")
    slots = select_slots(rows, args.selection_seed)
    emit("pre_j_selection", slots=slots, selection_seed=args.selection_seed,
         candidate_count=len(rows), catalogue_complete=True,
         catalogue_and_feature_seconds=time.monotonic() - started,
         selection="native2+signal1+hash-seeded-other; dedup native fill; retain empty slots",
         limitations=["Native top-root budget is at most four; often all candidates are selected.",
                      "No unchanged trajectory, equal-time ranking result, or provenance mutation DAG.",
                      "Only supplied newly generated development row; no old protected data read."])
    check()
    # Audit baseline in a fresh process before offline DP, even for an empty pool.
    def audit(records):
        check()
        payload = encode({**structure, "records": records})
        require(len(payload) <= MAX_BYTES, "audit payload exceeds bound")
        child = subprocess.run([sys.executable, "-I", "-B", str(ROOT / FILES[0]), "--audit-records"],
                               input=payload, capture_output=True, cwd="/tmp",
                               timeout=max(0.001, min(600.0, deadline - time.monotonic())), check=True)
        require(len(child.stdout) <= MAX_BYTES and len(child.stderr) <= MAX_BYTES, "audit capture exceeds bound")
        result = decode(child.stdout)
        require(result.get("all_match") is True and result.get("independent_implementation") is True,
                "independent process audit failed")
        return result

    def record(label, item):
        return {"label": label, "tree": item["tree"], "slices": item["slices"],
                "expected": {k: str(item[k]) for k in METRICS}}

    emit("base_integer_audit", audit=audit([record("I", common)]))
    completed = 0
    for slot in slots:
        index = slot["native_ordinal"]
        if index is None:
            emit("empty_slot", slot=slot)
            continue
        check()
        arms = trace.offline_arms(domains[index], baseline="actual", deadline=deadline - 3,
                                  max_transitions=5_000_000, max_alternations=64)
        require(arms["baseline_selection"] == "actual_incumbent" and
                arms["same_incumbent_attribution"] is True, "offline actual base refused")
        require(arms["baseline"] is not None and all(
                arms["baseline"][k] == common[k] for k in METRICS), "offline I disagrees with common")
        records = [record("I", arms["baseline"])]
        for name in ("F", "S", "J"):
            if arms[name] is not None:
                records.append(record(name, arms[name]))
        for name in ("FS", "SF"):
            if arms[name]["result"] is not None:
                records.append(record(name, arms[name]["result"]))
        exact_audit = audit(records)
        emit("actual_exact_arms", slot=slot, candidate_sha256=rows[index]["candidate_sha256"],
             fixed_certificate=certificates[index].to_wire(), audit=exact_audit,
             arms=trace._wire(arms), I_alias="arms.baseline", exact_complete=True)
        completed += 1
    emit("complete", selected_nonempty_slots=completed, candidate_count=len(rows),
         elapsed_seconds=time.monotonic() - started, stage2_acceptance_claim=False,
         scope="actual_same_base_finite_domain_mechanism_only")
    os.close(evidence_fd)
    signal.setitimer(signal.ITIMER_REAL, 0)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"kind": "mechanism_incomplete", "error": str(error)[:2000],
                          "no_partial_optimum_or_stage_completion_claim": True}), file=sys.stderr, flush=True)
        raise SystemExit(1)
