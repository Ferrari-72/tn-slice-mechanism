"""Pure source-baseline adapter; no trace/native/optimizer imports or I/O.

SOURCE_BASELINE_NECESSARY_ONLY: this binds caller-supplied event bytes to a
caller-asserted expected SHA256, NOT to verified historical provenance. replay_id
is a caller namespace; domain_id resets on replay. No START, ENVIRONMENT,
candidate/source pin, input hashes, seed provenance, runtime, or replay completeness
is authenticated here. The actual incumbent is NEVER selected, even if producer
membership/equality flags say it is admissible. Predictions and stored costs are
not mathematical authority. UNREJECTED is not feasibility or improvement.

The separate ACTUAL_COMMON_BASE_V1 entry below is opt-in and fail-closed. It
independently checks physical topology membership and an explicitly pinned
common snapshot. It does not change either historical source-only entry.

TRACE_JSON_V1 and LIVE_DOMAIN_V1 are explicit, different protocols. Live callers
must also supply the actual emitted JSON event bytes; live math fields must agree
with those bytes. All returned mathematical state is an immutable snapshot.
"""

from dataclasses import dataclass, field
from hashlib import sha256
import json
from math import isfinite
import re

from qpe_fixed_capacity_certificate import Problem, CertificateReport, certify
import sys

# v2: the caller (business entry or acceptor) loads the hash-pinned stack first.
stack = sys.modules["qpe_mechanism_stack"]

SCOPE = "SOURCE_BASELINE_NECESSARY_ONLY"
ADAPTER_VERSION = "QPE_FIXED_CAPACITY_TRACE_ADAPTER_V1"
MAX_TREE_DEPTH = 19999  # complete binary tree over <=20000 physical inputs
MAX_CONTAINER_DEPTH = MAX_TREE_DEPTH + 32


class AdapterContractError(ValueError):
    """Malformed, mismatched, or unsupported input, never a CAP rejection."""


def _require(condition, message):
    if not condition:
        raise AdapterContractError(message)


@dataclass(frozen=True)
class CallerBinding:
    """Caller assertions, not independently verified provenance.

    expected_raw_event_sha256 must come from the caller's independent trust
    context. Hash equality proves byte identity only, not origin or truth.
    """

    expected_raw_event_sha256: str
    replay_id: str
    expected_domain_id: int

    def __post_init__(self):
        _require(type(self.expected_raw_event_sha256) is str and
                 re.fullmatch(r"[0-9a-f]{64}", self.expected_raw_event_sha256) is not None,
                 "expected raw event SHA256 must be lowercase hex")
        _require(type(self.replay_id) is str and bool(self.replay_id), "replay_id required")
        _integer(self.expected_domain_id, "expected_domain_id", minimum=1)


@dataclass(frozen=True)
class BoundCertificateProblem:
    problem: Problem
    binding: CallerBinding
    protocol: str
    source_node_paths: tuple[tuple[int, ...], ...]
    root_node: int
    frontier_nodes: tuple[int, ...]
    old_slices: frozenset[str]
    semantic_sha256: str
    scope: str = field(default=SCOPE, init=False)
    selected_baseline: str = field(default="source_baseline", init=False)
    adapter_version: str = field(default=ADAPTER_VERSION, init=False)
    certificate_contract: str = field(default="OWNER_FIXED_RESULT_CAP_NECESSARY_ONLY_V1", init=False)
    source_binding_limitations: tuple[str, ...] = field(default=(
        "Caller-asserted expected SHA256 checked against actual event bytes; byte identity only.",
        "Replay namespace is caller-asserted; historical origin/runtime/completeness not verified.",
        "Producer/candidate source pins and START/ENVIRONMENT/input/seed provenance not verified.",
        "Source baseline only; actual incumbent membership, feasibility and improvement not certified.",
    ), init=False)


@dataclass(frozen=True)
class BoundCertificateReport:
    bound: BoundCertificateProblem
    certificate: CertificateReport
    scope: str = field(default=SCOPE, init=False)


def _integer(value, name, minimum=0):
    _require(type(value) is int and value >= minimum, f"{name}: exact integer >= {minimum} required")
    return value


def _object(value, name, required, optional=()):
    _require(type(value) is dict, f"{name}: exact object required")
    _require(set(required) <= value.keys() <= set(required) | set(optional),
             f"{name}: missing or unknown fields")
    return value


def _sequence(value, name, protocol):
    allowed = (list,) if protocol == "TRACE_JSON_V1" else (tuple, list)
    _require(type(value) in allowed, f"{name}: protocol sequence required")
    return value


def _labels(value, name, protocol):
    values = tuple(_sequence(value, name, protocol))
    _require(all(type(x) is str and bool(x) for x in values), f"{name}: nonempty labels required")
    _require(len(set(values)) == len(values), f"{name}: duplicate labels")
    return values


def _ids(value, name, protocol):
    values = tuple(_sequence(value, name, protocol))
    for item in values:
        _integer(item, name)
    _require(len(set(values)) == len(values), f"{name}: duplicate IDs")
    return values


def _safe_builtins(value):
    """Reject custom objects, cycles, bool-as-number tricks later, nonfinite now.

    Container nesting is bounded separately from (and above) MAX_TREE_DEPTH so a
    complete deep physical tree remains valid inside its event/snapshot. Ancestry
    is tracked as an explicit path set (O(depth) memory), not copied per item.
    """
    pending = [(value, 0, False)]
    active = set()
    while pending:
        item, depth, leaving = pending.pop()
        if leaving:
            active.discard(item)
            continue
        _require(depth <= MAX_CONTAINER_DEPTH, "event container nesting exceeds supported maximum")
        kind = type(item)
        if kind in (dict, list, tuple):
            _require(id(item) not in active, "cyclic event")
            active.add(id(item))
            pending.append((id(item), depth, True))
            if kind is dict:
                _require(all(type(k) is str for k in item), "object keys must be exact strings")
                children = item.values()
            else:
                children = item
            pending.extend((child, depth + 1, False) for child in children)
        else:
            _require(kind in (str, int, float, bool, type(None)), "non-builtin event value")
            _require(kind is not float or isfinite(item), "nonfinite event number")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def _nonfinite(value):
    raise AdapterContractError("nonfinite JSON number: " + value)


def _decode(event_json, binding):
    _require(type(binding) is CallerBinding, "exact CallerBinding required")
    _require(type(event_json) is bytes, "actual raw event bytes required")
    _require(sha256(event_json).hexdigest() == binding.expected_raw_event_sha256,
             "raw event SHA256 mismatch")
    try:
        event = stack.loads(event_json, object_pairs_hook=_pairs, parse_constant=_nonfinite)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise AdapterContractError("invalid trace JSON: " + str(exc)) from exc
    _safe_builtins(event)
    return event


def _tree(value, n, protocol, name):
    """Decode a full or partial physical tree without coercion or recursion."""
    pending, built, groups, seen = [(value, (), False)], {}, {}, set()
    while pending:
        node, path, visited = pending.pop()
        _require(len(path) <= MAX_TREE_DEPTH, f"{name}: tree depth exceeds {MAX_TREE_DEPTH}")
        if type(node) is int:
            _require(0 <= node < n and node not in seen, f"{name}: invalid or repeated leaf")
            seen.add(node)
            built[path], groups[path] = node, frozenset((node,))
        else:
            children = _sequence(node, name, protocol)
            _require(len(children) == 2, f"{name}: binary tree required")
            if not visited:
                pending.extend(((node, path, True), (children[1], path + (1,), False),
                                (children[0], path + (0,), False)))
            else:
                built[path] = (built[path + (0,)], built[path + (1,)])
                groups[path] = groups[path + (0,)] | groups[path + (1,)]
    topology = frozenset(group for path, group in groups.items() if type(built[path]) is tuple)
    return built[()], groups[()], topology


def _path_tree(value, n, protocol):
    live, depths = list(range(n)), [0] * n
    steps = _sequence(value, "source_baseline.path", protocol)
    _require(len(steps) == n - 1, "incomplete recycled-position path")
    for step in steps:
        pair = _sequence(step, "path step", protocol)
        _require(len(pair) == 2, "binary path step required")
        a, b = pair
        _integer(a, "path position")
        _integer(b, "path position")
        _require(a != b and a < len(live) and b < len(live), "invalid recycled-position path")
        depth = 1 + max(depths[a], depths[b])
        _require(depth <= MAX_TREE_DEPTH, f"path tree depth exceeds {MAX_TREE_DEPTH}")
        node = (live[a], live[b])
        for position in sorted((a, b), reverse=True):
            live.pop(position)
            depths.pop(position)
        live.append(node)
        depths.append(depth)
    return live[0]


# Topology comparisons deliberately permit child swaps. Physical source paths
# and certificate orientation always come from source_children, never a cost or
# a canonicalized/reordered baseline. Full internal groups characterize an
# unordered rooted physical binary tree (not merely its total leaf set).
_COSTS = ("multiplicity", "per_slice_work", "total_work", "result_only_peak")


def _cost(value, name, protocol):
    if protocol == "TRACE_JSON_V1":
        _require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]*", value) is not None,
                 f"{name}: canonical nonnegative decimal string required")
    else:
        _integer(value, name)


def _snapshot(record, n, protocol, name):
    _object(record, name, ("tree", "path", "slices", "contractions", *_COSTS),
            ("nodes",) if protocol == "LIVE_DOMAIN_V1" else ())
    tree, leaves, topology = _tree(record["tree"], n, protocol, name + ".tree")
    _require(leaves == frozenset(range(n)), f"{name}: incomplete physical tree")
    _integer(record["contractions"], name + ".contractions")
    _require(record["contractions"] == n - 1, f"{name}: wrong contraction count")
    for cost in _COSTS:
        _cost(record[cost], name + "." + cost, protocol)
    # Stored work/volume values are syntactically checked, not trusted or scored.
    path_tree = _path_tree(record["path"], n, protocol)
    _, _, path_topology = _tree(path_tree, n, "LIVE_DOMAIN_V1", name + ".path tree")
    _require(topology == path_topology, f"{name}: tree/path topology mismatch")
    slices = frozenset(_labels(record["slices"], name + ".slices", protocol))
    return tree, topology, slices


def _source(children, n, protocol):
    entries = _sequence(children, "source_children", protocol)
    _require(len(entries) == 2 * n - 1, "source_children must contain n leaves and n-1 results")
    # The first n entries are unused producer sentinels, deliberately uninterpreted.
    trees = list(range(n))
    groups = [frozenset((i,)) for i in range(n)]
    parents = [0] * len(entries)
    pairs = {}
    for node in range(n, len(entries)):
        pair = _sequence(entries[node], "source child pair", protocol)
        _require(len(pair) == 2, "source child pair must be binary")
        left, right = pair
        _integer(left, "source child")
        _integer(right, "source child")
        _require(left != right and left < node and right < node,
                 "source children must be distinct earlier IDs")
        parents[left] += 1
        parents[right] += 1
        _require(not groups[left] & groups[right], "overlapping source physical subtrees")
        pairs[node] = (left, right)
        trees.append((trees[left], trees[right]))
        groups.append(groups[left] | groups[right])
    _require(parents == [1] * (len(entries) - 1) + [0], "source must be one complete physical tree")
    _require(groups[-1] == frozenset(range(n)), "source root must cover every physical input")
    paths = [None] * len(entries)
    pending = [(len(entries) - 1, ())]
    while pending:
        node, path = pending.pop()
        _require(len(path) <= MAX_TREE_DEPTH, f"source tree depth exceeds {MAX_TREE_DEPTH}")
        paths[node] = path
        if node in pairs:
            left, right = pairs[node]
            pending.extend(((right, path + (1,)), (left, path + (0,))))
    return trees, groups, tuple(paths)


_DOMAIN_REQUIRED = (
    "inputs", "output", "sizes", "cap", "root", "root_tree", "root_leaves",
    "frontier", "branches", "fixed_nodes", "source_children", "editable",
    "fixed_slices", "old_slices", "incumbent_state", "states", "source_baseline",
)
_DOMAIN_OPTIONAL = (
    "seed", "sweep", "region_budget", "sweep_roots", "native_incumbent_work_prediction",
    "incumbent_before", "source_and_incumbent_same_tree", "source_and_incumbent_same_slices",
    "native_prediction_tables", "actual_incumbent_domain_evidence", "limitation",
)


def _adapt(event, binding, protocol):
    _safe_builtins(event)
    _object(event, "event", ("schema", "kind", "domain_id", "domain"))
    _require(event["schema"] == "qpe-j26-trace-v1" and event["kind"] == "domain",
             "expected qpe-j26-trace-v1 domain event")
    _integer(event["domain_id"], "domain_id", minimum=1)
    _require(event["domain_id"] == binding.expected_domain_id, "domain_id assertion mismatch")
    d = _object(event["domain"], "domain", _DOMAIN_REQUIRED, _DOMAIN_OPTIONAL)
    raw_inputs = _sequence(d["inputs"], "inputs", protocol)
    _require(bool(raw_inputs), "nonempty physical inputs required")
    ordered_inputs = tuple(_labels(term, "input axes", protocol) for term in raw_inputs)
    inputs = tuple(frozenset(term) for term in ordered_inputs)
    output_order = _labels(d["output"], "output", protocol)
    output = frozenset(output_order)
    labels = frozenset().union(*inputs)
    dims = d["sizes"]
    _require(type(dims) is dict and set(dims) == labels, "sizes must cover exactly physical labels")
    for label, dim in dims.items():
        _require(type(label) is str and bool(label), "nonempty dimension label required")
        _integer(dim, "dimension", minimum=1)
    _require(output <= labels, "unknown output label")
    owners = {label: frozenset(i for i, term in enumerate(inputs) if label in term) for label in labels}
    _require(all(len(own) >= 2 or label in output for label, own in owners.items()),
             "nonoutput unary reductions unsupported")
    _integer(d["cap"], "cap", minimum=1)
    n = len(inputs)
    trees, groups, paths = _source(d["source_children"], n, protocol)
    root = _integer(d["root"], "root")
    _require(root < len(trees), "root ID out of range")
    root_tree, root_group, _ = _tree(d["root_tree"], n, protocol, "root_tree")
    _require(stack.equal(root_tree, trees[root]) and root_group == groups[root],
             "root tree/source identity mismatch")
    _require(frozenset(_ids(d["root_leaves"], "root_leaves", protocol)) == groups[root],
             "root physical leaves mismatch")
    baseline_tree, baseline_topology, baseline_slices = _snapshot(d["source_baseline"], n, protocol,
                                                                  "source_baseline")
    _require(baseline_topology == frozenset(groups[n:]), "source baseline/source_children topology mismatch")

    def boundary(group):
        return frozenset(label for label, own in owners.items()
                         if own & group and (label in output or own - group))

    frontier = _sequence(d["frontier"], "frontier", protocol)
    _require(3 <= len(frontier) <= 10, "production frontier must contain 3..10 atoms")
    frontier_nodes, covered = [], set()
    for atom in frontier:
        _object(atom, "frontier atom", ("node", "tree", "leaves", "boundary"))
        node = _integer(atom["node"], "frontier node")
        _require(node < len(trees) and node not in frontier_nodes, "invalid or duplicate frontier ID")
        tree, group, _ = _tree(atom["tree"], n, protocol, "frontier tree")
        _require(stack.equal(tree, trees[node]) and group == groups[node],
                 "frontier tree/source identity mismatch")
        _require(frozenset(_ids(atom["leaves"], "frontier leaves", protocol)) == group,
                 "frontier physical leaves mismatch")
        _require(frozenset(_labels(atom["boundary"], "frontier boundary", protocol)) == boundary(group),
                 "frontier unsliced boundary mismatch")
        _require(group <= groups[root] and not covered & group, "frontier is outside region or overlapping")
        covered.update(group)
        frontier_nodes.append(node)
    _require(covered == groups[root], "frontier cut does not cover region")

    def under(path, ancestor):
        return path[:len(ancestor)] == ancestor

    editable_nodes = {node for node in range(n, len(trees))
                      if under(paths[node], paths[root]) and
                      not any(under(paths[node], paths[atom]) for atom in frontier_nodes)}
    _require(len(editable_nodes) == len(frontier) - 1, "unsupported regional cut")
    branches = _ids(d["branches"], "branches", protocol)
    _require(set(branches) == editable_nodes, "branches must be the complete editable internal set")
    expected_fixed = set(range(n, len(trees))) - editable_nodes
    fixed_ids = []
    for item in _sequence(d["fixed_nodes"], "fixed_nodes", protocol):
        _object(item, "fixed node", ("node", "leaves") if protocol == "LIVE_DOMAIN_V1" else ("node",),
                () if protocol == "LIVE_DOMAIN_V1" else ("leaves",))
        node = _integer(item["node"], "fixed node ID")
        _require(node in expected_fixed and node not in fixed_ids, "invalid or duplicate fixed node")
        if "leaves" in item:
            _require(frozenset(_ids(item["leaves"], "fixed leaves", protocol)) == groups[node],
                     "fixed node physical leaves mismatch")
        fixed_ids.append(node)
    _require(set(fixed_ids) == expected_fixed, "fixed_nodes must be the complete fixed internal complement")
    editable = _labels(d["editable"], "editable", protocol)
    fixed = frozenset(_labels(d["fixed_slices"], "fixed_slices", protocol))
    old = frozenset(_labels(d["old_slices"], "old_slices", protocol))
    _require(len(editable) <= 6, "at most 6 editable labels")
    allowed = fixed | frozenset(editable)
    _require(allowed <= labels and not allowed & output and not fixed & set(editable),
             "invalid nonoutput slice domain")
    _require(all(dims[label] > 1 for label in editable), "dimension-one editable label")
    _require(set(editable) <= frozenset().union(*(boundary(groups[v]) for v in frontier_nodes)),
             "editable label absent from unsliced frontier")
    _require(fixed <= old <= allowed and baseline_slices == old, "old/fixed/baseline slices inconsistent")
    state = _integer(d["incumbent_state"], "incumbent_state")
    expected_state = sum(1 << i for i, label in enumerate(editable) if label in old)
    _require(state == expected_state, "incumbent_state disagrees with editable order and old slices")
    states = _ids(d["states"], "states", protocol)
    _require(set(states) == set(range(1 << len(editable))), "states must contain every mask exactly once")
    if "incumbent_before" in d:
        # Schema/topology validation does not confer domain membership. A stale
        # actual incumbent can be structurally valid yet outside this source cut.
        _, _, incumbent_slices = _snapshot(d["incumbent_before"], n, protocol, "incumbent_before")
        _require(incumbent_slices <= labels and not incumbent_slices & output,
                 "invalid actual incumbent slices")
    # Explicitly do not use incumbent_before, equality/membership flags or native
    # predictions to choose a tree or declare the actual incumbent in-domain.
    for name in ("source_and_incumbent_same_tree", "source_and_incumbent_same_slices"):
        if name in d:
            _require(type(d[name]) is bool, name + " must be an exact bool")
    for name in ("seed", "sweep", "region_budget"):
        if name in d:
            _integer(d[name], name)
    if "sweep_roots" in d:
        roots = _ids(d["sweep_roots"], "sweep_roots", protocol)
        _require(root in roots and all(v < len(trees) for v in roots), "invalid sweep_roots")
    if "native_incumbent_work_prediction" in d:
        _cost(d["native_incumbent_work_prediction"], "native incumbent prediction", protocol)
    try:
        problem = Problem(inputs, dict(dims), trees[-1], paths[root],
                          tuple(paths[v] for v in frontier_nodes), d["cap"], editable, output, fixed)
    except ValueError as exc:
        raise AdapterContractError("certificate Problem: " + str(exc)) from exc
    # Cross-check independently derived classifications against the core as well.
    _require({node.path for node in problem.fixed_nodes} == {paths[v] for v in expected_fixed},
             "core/source fixed classification mismatch")
    # Incidence axis order and baseline direction are retained in semantic identity.
    semantic = {"inputs": ordered_inputs, "output": sorted(output), "sizes": dims,
                "source_tree": trees[-1], "baseline_tree": baseline_tree,
                "source_node_paths": paths, "root": root, "frontier": frontier_nodes,
                "cap": d["cap"], "editable": editable, "fixed_slices": sorted(fixed),
                "old_slices": sorted(old)}
    try:
        digest = sha256(stack.dumps(semantic)).hexdigest()
    except (ValueError, RecursionError) as exc:
        raise AdapterContractError("unsupported semantic serialization") from exc
    return BoundCertificateProblem(problem, binding, protocol, paths, root,
                                   tuple(frontier_nodes), old, digest)


def decode_trace_domain_v1(event_json: bytes, *, binding: CallerBinding) -> BoundCertificateProblem:
    """Decode actual trace bytes, check caller-asserted identity, validate source."""
    return _adapt(_decode(event_json, binding), binding, "TRACE_JSON_V1")


def adapt_live_trace_domain_v1(event, *, raw_event_json: bytes,
                               binding: CallerBinding) -> BoundCertificateProblem:
    """Validate live source math AND equality to the bound emitted wire source math.

    Live-only snapshot node evidence and ignored metadata are not authenticated
    through equality: only the complete extracted certificate domain is compared.
    They never influence the Problem, and are not labelled verified provenance.
    """
    wire = decode_trace_domain_v1(raw_event_json, binding=binding)
    live = _adapt(event, binding, "LIVE_DOMAIN_V1")
    _require(live.semantic_sha256 == wire.semantic_sha256,
             "live source domain disagrees with actual bound event bytes")
    return live


def certify_bound_domain(bound: BoundCertificateProblem) -> BoundCertificateReport:
    """Necessary fixed-result scan only; no baseline or CAP overrides."""
    _require(type(bound) is BoundCertificateProblem, "exact BoundCertificateProblem required")
    return BoundCertificateReport(bound, certify(bound.problem))


ACTUAL_SCOPE = "ACTUAL_COMMON_BASE_FIXED_RESULT_NECESSARY_ONLY"


def _canonical_sha256(value):
    return sha256(stack.dumps(value)).hexdigest()


@dataclass(frozen=True)
class ActualCommonBaseBinding:
    """Explicit byte/semantic expectations from the caller, not provenance proof.

    source_bytes are the trusted candidate source, common_snapshot_json is the
    exact persisted compact TRACE_JSON_V1 snapshot, and candidate_sha256 is the
    canonical SHA256 of the ENTIRE domain object (including ignored predictions).
    input_sha256 binds ordered inputs/output and the complete case-sensitive dims.
    No expectation is inferred from a producer membership flag.
    """

    event: CallerBinding
    expected_source_sha256: str
    expected_common_sha256: str
    expected_candidate_sha256: str
    expected_input_sha256: str

    def __post_init__(self):
        _require(type(self.event) is CallerBinding, "exact event CallerBinding required")
        for name in ("expected_source_sha256", "expected_common_sha256",
                     "expected_candidate_sha256", "expected_input_sha256"):
            value = getattr(self, name)
            _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
                     name + ": lowercase SHA256 required")


@dataclass(frozen=True)
class BoundActualCommonBase:
    problem: Problem
    source: BoundCertificateProblem
    binding: ActualCommonBaseBinding
    actual_slices: frozenset[str]
    actual_semantic_sha256: str
    fixed_groups: tuple[tuple[int, ...], ...]
    scope: str = field(default=ACTUAL_SCOPE, init=False)
    selected_baseline: str = field(default="actual_common_base", init=False)
    membership_independently_validated: bool = field(default=True, init=False)


def decode_actual_common_base_v1(event_json: bytes, *, binding: ActualCommonBaseBinding,
                                 source_bytes: bytes, common_snapshot_json: bytes) -> BoundActualCommonBase:
    """Fail closed unless the actual incumbent IS the pinned common base and member.

    This is a NEW opt-in contract. The source-only functions above retain their
    historical semantics. Hashes prove identity only, not historical execution,
    completeness, image limits, source authorization, or numerical truth. Stored
    snapshot costs are syntax checked only; the mechanism runner audits them.
    """
    _require(type(binding) is ActualCommonBaseBinding, "exact ActualCommonBaseBinding required")
    _require(type(source_bytes) is bytes and
             sha256(source_bytes).hexdigest() == binding.expected_source_sha256,
             "actual candidate source SHA256 mismatch")
    _require(type(common_snapshot_json) is bytes and
             sha256(common_snapshot_json).hexdigest() == binding.expected_common_sha256,
             "common snapshot byte SHA256 mismatch")
    event = _decode(event_json, binding.event)
    source = _adapt(event, binding.event, "TRACE_JSON_V1")
    d = event["domain"]
    _require(_canonical_sha256(d) == binding.expected_candidate_sha256,
             "candidate domain SHA256 mismatch")
    _require(_canonical_sha256({k: d[k] for k in ("inputs", "output", "sizes")}) ==
             binding.expected_input_sha256, "ordered input SHA256 mismatch")
    _require("incumbent_before" in d, "actual incumbent snapshot required")
    try:
        common = stack.loads(common_snapshot_json, object_pairs_hook=_pairs,
                             parse_constant=_nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AdapterContractError("invalid common snapshot JSON") from exc
    _safe_builtins(common)
    n = len(source.problem.inputs)
    actual_tree, topology, slices = _snapshot(d["incumbent_before"], n, "TRACE_JSON_V1",
                                             "incumbent_before")
    common_tree, _, common_slices = _snapshot(common, n, "TRACE_JSON_V1", "common_base")
    _require(stack.equal(actual_tree, common_tree) and slices == common_slices,
             "actual incumbent differs from pinned common base")
    p = source.problem
    _require(p.fixed_slices <= slices <= p.fixed_slices | frozenset(p.editable),
             "actual incumbent slices outside source domain")
    # Independently derive ALL actual physical groups/paths. Neither nodes,
    # producer evidence, equality flags nor stored costs enter membership.
    groups, paths, pending = {}, {}, [(actual_tree, (), False)]
    while pending:
        node, path, visited = pending.pop()
        if type(node) is int:
            group = frozenset((node,))
        elif not visited:
            pending.extend(((node, path, True), (node[1], path + (1,), False),
                            (node[0], path + (0,), False)))
            continue
        else:
            group = groups[path + (0,)] | groups[path + (1,)]
        groups[path] = group
        paths[group] = path
    fixed = frozenset(frozenset(node.leaves) for node in p.fixed_nodes)
    _require(fixed <= topology, "actual incumbent missing immutable source groups")
    source_trees, source_groups, _ = _source(d["source_children"], n, "TRACE_JSON_V1")
    root_group = source_groups[source.root_node]
    atoms = tuple(source_groups[v] for v in source.frontier_nodes)
    _require(root_group in paths and all(atom in paths for atom in atoms),
             "actual incumbent missing root/frontier subtree")
    regional = topology - fixed
    _require(len(regional) == len(atoms) - 1, "actual regional merge count mismatch")
    for group in regional:
        contained = tuple(atom for atom in atoms if atom <= group)
        _require(group <= root_group and len(contained) >= 2 and
                 frozenset().union(*contained) == group,
                 "actual merge splits an atom or changes the exterior")
    try:
        actual_problem = Problem(p.inputs, dict(p.dims), actual_tree, paths[root_group],
                                 tuple(paths[atom] for atom in atoms), p.cap, p.editable,
                                 p.output, p.fixed_slices)
    except ValueError as exc:
        raise AdapterContractError("actual Problem: " + str(exc)) from exc
    _require(frozenset(frozenset(node.leaves) for node in actual_problem.fixed_nodes) == fixed,
             "actual fixed-node classification disagrees with source")
    semantic = _canonical_sha256({"candidate": binding.expected_candidate_sha256,
                                  "common": binding.expected_common_sha256,
                                  "tree": actual_tree, "slices": sorted(slices),
                                  "source": binding.expected_source_sha256})
    return BoundActualCommonBase(actual_problem, source, binding, slices, semantic,
                                 tuple(sorted(tuple(sorted(g)) for g in fixed)))


def certify_actual_common_base(bound: BoundActualCommonBase) -> CertificateReport:
    _require(type(bound) is BoundActualCommonBase, "exact BoundActualCommonBase required")
    return certify(bound.problem)
