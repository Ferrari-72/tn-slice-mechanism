"""Read-only, source-pinned instrumentation for the frozen J26 trajectory.

Importing this module does not import cotengra or execute a candidate. Loading a
trusted candidate is an explicit Linux-only operation. No search implementation
is reimplemented here: hooks are inserted into the original function text, with
its AST checked after removing those hooks. ``run_common`` retains the historical
refine prefix verbatim and omits *both* WSX and J26 suffix calls.

Exact accounting uses physical input incidence, never native float scores.
Work is product(involved dimensions), replicated by slice multiplicity (the
cotengra dtype=None convention), not hardware FLOPs. Peak is contraction-result
size only, not input size or live memory. Hyperedges and dimension-one indices
are supported. v2: every full physical tree operation used by the mechanism
(validation, decoding, accounting, keys, copying, grafting, JSON) is iterative,
so complete trees of any finite depth below MAX_TREE_DEPTH are supported without
changing the Python recursion limit. Regional DP trees keep their <=10-atom bound. Empty networks, repeated indices/diagonals,
non-output unary reductions, unary path operations, projected indices and output
slicing fail closed. A one-tensor network has zero binary work and zero result-only peak.

No execution is performed by this file merely existing. Offline arms consume
record dictionaries only, never call a candidate or native tree method, and
are opt-in because a 10-frontier/6-editable domain can be expensive.
"""

from __future__ import annotations

import ast
import hashlib
import sys
import time
from collections.abc import Mapping
import importlib.util
from dataclasses import dataclass
from math import isfinite, prod
from numbers import Integral
from pathlib import Path
from types import ModuleType


FRESH_J26_SHA256 = "ce758e8d95c445dfc464c5941d5b9c416b0999a1fda8d1bde97f3736001d38f7"
TARGET = "_outside_certified_frontier_dp"
HOOK = "__j26_trace_hook__"
COMMON = "__j26_common__"
SCHEMA = "qpe-j26-trace-v1"
MAX_TREE_DEPTH = 19999  # complete binary tree over <=20000 physical inputs


def _load_stack():
    """Exact pinned sibling iterative codec; the same module object for every caller."""
    name = "qpe_mechanism_stack"
    module = sys.modules.get(name)
    if module is None:
        path = Path(__file__).resolve().parent / (name + ".py")
        raw = path.read_bytes()
        _require(hashlib.sha256(raw).hexdigest() == STACK_SHA256, "mechanism stack source pin differs")
        spec = importlib.util.spec_from_file_location(name, str(path))
        module = importlib.util.module_from_spec(spec)
        module.__qpe_stack_sha256__ = STACK_SHA256
        sys.modules[name] = module
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    _require(getattr(module, "__qpe_stack_sha256__", None) == STACK_SHA256,
             "loaded mechanism stack identity differs")
    return module


STACK_SHA256 = "8e0844b51f32765ff6ea44ad6e6ed0a59f954286dc8915e50b870c063517f653"


def deepcopy(value):
    return _load_stack().copy(value)


def _check_tree_depth(tree, check=None):
    """Iterative validation before recursive accounting, copying or encoding."""
    pending = [(tree, 0)]
    while pending:
        if check is not None:
            check()
        node, depth = pending.pop()
        _require(depth <= MAX_TREE_DEPTH,
                 f"binary tree depth exceeds supported maximum {MAX_TREE_DEPTH}")
        if type(node) is int:
            continue
        _require(isinstance(node, (tuple, list)) and len(node) == 2,
                 "expected binary tree or integer physical leaf")
        pending.append((node[0], depth + 1))
        pending.append((node[1], depth + 1))


class TraceContractError(ValueError):
    """Unsupported accounting domain or changed frozen source; do not guess."""


def _require(condition, message):
    if not condition:
        raise TraceContractError(message)


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _checked_items(items, check):
    for item in items:
        if check is not None:
            check()
        yield item


def _problem(inputs, output, sizes, *, _check=None):
    inputs = tuple(tuple(term) for term in _checked_items(inputs, _check))
    output = tuple(output)
    _require(bool(inputs), "zero-tensor networks are unsupported")
    _require(all(len(t) == len(set(t)) for t in inputs),
             "repeated input indices/diagonals are unsupported")
    _require(len(output) == len(set(output)), "repeated output indices")
    labels = set().union(*(set(t) for t in _checked_items(inputs, _check)))
    _require(all(isinstance(x, str) for x in labels), "indices must be strings")
    _require(labels == set(sizes), "size table must have exactly physical indices (no zero owners)")
    _require(set(output) <= labels, "output index has no physical owner")
    _require(all(isinstance(d, Integral) and not isinstance(d, bool) and d >= 1
                 for d in sizes.values()), "dimensions must be positive integers")
    dims = {x: int(sizes[x]) for x in sorted(labels)}
    owners = {x: frozenset(i for i, term in _checked_items(enumerate(inputs), _check) if x in term)
              for x in _checked_items(sorted(labels), _check)}
    _require(all(len(o) >= 2 or x in output for x, o in owners.items()),
             "non-output one-owner/unary reductions are unsupported")
    return inputs, output, dims, owners


def _slices(slices, output, dims):
    result = frozenset(slices)
    _require(result <= dims.keys(), "slice index has no physical owner")
    _require(not result.intersection(output), "output slicing is unsupported")
    return result


def _boundary(group, owners, output, *, _check=None):
    group = frozenset(group)
    return frozenset(x for x, own in _checked_items(owners.items(), _check)
                     if own & group and (x in output or own - group))


def _leaves(tree):
    pending, result = [(tree, 0)], []
    while pending:
        node, depth = pending.pop()
        _require(depth <= MAX_TREE_DEPTH,
                 f"binary tree depth exceeds supported maximum {MAX_TREE_DEPTH}")
        if type(node) is int:
            result.append(node)
            continue
        _require(isinstance(node, (tuple, list)) and len(node) == 2,
                 "expected binary tree or integer physical leaf")
        pending.append((node[1], depth + 1))
        pending.append((node[0], depth + 1))
    return tuple(result)


def tree_from_path(path, n, *, _check=None):
    """Decode native recycled-index path, never a score-derived topology."""
    _require(type(n) is int and n >= 1, "positive tensor count required")
    live = list(range(n))
    depths = [0] * n
    normalized = []
    for step in path:
        if _check is not None:
            _check()
        _require(len(step) == 2, "unary/nonbinary path operations are unsupported")
        _require(all(isinstance(i, Integral) and not isinstance(i, bool) for i in step),
                 "path positions must be integers")
        a, b = (int(i) for i in step)
        _require(a != b and 0 <= a < len(live) and 0 <= b < len(live),
                 "invalid recycled-index path")
        depth = 1 + max(depths[a], depths[b])
        _require(depth <= MAX_TREE_DEPTH,
                 f"binary tree depth exceeds supported maximum {MAX_TREE_DEPTH}")
        node = (live[a], live[b])
        for i in sorted((a, b), reverse=True):
            live.pop(i)
            depths.pop(i)
        live.append(node)
        depths.append(depth)
        normalized.append((a, b))
    _require(len(live) == 1 and len(normalized) == n - 1, "incomplete path")
    return live[0], tuple(normalized)


def exact_tree(inputs, output, sizes, tree, slices=(), *, _check=None):
    """Independent exact full-tree owner accounting, including every fixed node."""
    _check_tree_depth(tree, _check)
    if _check is not None:
        _check()
    inputs, output, dims, owners = _problem(inputs, output, sizes, _check=_check)
    slices = _slices(slices, output, dims)
    _require(sorted(_leaves(tree)) == list(range(len(inputs))),
             "tree must contain each physical input exactly once")
    nodes = []
    # Same postorder (left, right, parent) as v1's recursive visit, explicit stack.
    pending, values = [(tree, False)], []
    while pending:
        if _check is not None:
            _check()
        node, visited = pending.pop()
        if type(node) is int:
            group = frozenset((node,))
            values.append((group, _boundary(group, owners, output, _check=_check) - slices))
            continue
        if not visited:
            pending.extend(((node, True), (node[1], False), (node[0], False)))
            continue
        right_group, right = values.pop()
        left_group, left = values.pop()
        group = left_group | right_group
        boundary = _boundary(group, owners, output, _check=_check) - slices
        work = prod(dims[x] for x in left | right)
        result = prod(dims[x] for x in boundary)
        nodes.append({"leaves": tuple(sorted(group)), "boundary": tuple(sorted(boundary)),
                      "involved": tuple(sorted(left | right)), "work": work,
                      "result_size": result})
        values.append((group, boundary))
    multiplicity = prod(dims[x] for x in slices)
    per_slice = sum(node["work"] for node in nodes)
    return {"tree": deepcopy(tree), "slices": tuple(sorted(slices)),
            "multiplicity": multiplicity, "per_slice_work": per_slice,
            "total_work": multiplicity * per_slice,
            "result_only_peak": max((node["result_size"] for node in nodes), default=0),
            "contractions": len(nodes), "nodes": nodes}


def collect_exact(inputs, output, sizes, path, slices=(), *, _check=None):
    """Collect exact evidence from a binary native path and explicit slice set."""
    tree, path = tree_from_path(path, len(inputs), _check=_check)
    result = exact_tree(inputs, output, sizes, tree, slices, _check=_check)
    result["path"] = path
    return result


def snapshot(inputs, output, sizes, tree):
    """Only native evidence used is get_path() and sliced_inds, not float costs."""
    sliced = tree.sliced_inds
    _require(isinstance(sliced, Mapping), "native sliced_inds must be a mapping")
    for label, info in sliced.items():
        _require(getattr(info, "project", None) is None, "projected indices unsupported")
        _require(getattr(info, "ind", label) == label, "inconsistent slice metadata")
        _require(getattr(info, "size", sizes[label]) == sizes[label], "invalid slice multiplicity")
    return collect_exact(inputs, output, sizes, tree.get_path(), tuple(sliced))


def _single_function(source, name):
    module = ast.parse(source)
    found = [node for node in module.body
             if isinstance(node, ast.FunctionDef) and node.name == name]
    _require(len(found) == 1 and not found[0].decorator_list,
             f"expected one undecorated {name}")
    return found[0]


def _segment(source, node):
    lines = source.splitlines(keepends=True)
    return "".join(lines[node.lineno - 1:node.end_lineno])


def _replace_once(text, anchor, replacement):
    _require(text.count(anchor) == 1, f"changed or ambiguous source anchor: {anchor!r}")
    return text.replace(anchor, replacement, 1)


def transform_source(source, *, expected_sha256=FRESH_J26_SHA256):
    """Pure text/AST operation; validate the trusted digest before any later exec.

    The default pin is ONLY the registered fresh J26 source. Other provenance
    requires an explicit independently trusted digest; this is not a sandbox.
    CRLF is normalized for anchor matching, while the pin covers original text.
    """
    _require(isinstance(expected_sha256, str) and len(expected_sha256) == 64,
             "an independently trusted SHA256 is required")
    digest = _sha(source)
    _require(digest == expected_sha256.lower(), "trusted candidate SHA256 mismatch")
    source = source.replace("\r\n", "\n")
    _require(HOOK not in source and COMMON not in source, "trace global name collision")
    original_node = _single_function(source, TARGET)
    original = _segment(source, original_node)
    expected_args = ["inputs", "output", "sizes", "incumbent", "seed"]
    _require([arg.arg for arg in original_node.args.args] == expected_args,
             "changed J26 function signature")
    for anchor in (
        "    region_budget = max(2, min(4, 2400 // n))\n",
        "    for sweep in range(2):\n",
        "            while len(frontier) < 10:\n",
        "            editable.extend(item[3] for item in additions[:6 - len(editable)])\n",
    ):
        _require(original.count(anchor) == 1, "changed J26 search budget")
    edits = (
        ("            winning_cost = int(best.total_flops())\n",
         "            " + HOOK + "('domain', locals())\n"),
        ("                        winner = (choices, sliced_state)\n",
         "                        " + HOOK + "('prediction', locals())\n"),
        ("            if winner is None:\n",
         "            " + HOOK + "('domain_end', locals())\n"),
        ("            if _better(candidate, best):\n                best = candidate\n",
         "                " + HOOK + "('accepted', locals())\n"),
    )
    changed = original
    for anchor, hook in edits:
        if "if winner is None" in anchor:
            changed = _replace_once(changed, anchor, hook + anchor)
        elif "if _better" in anchor:
            changed = _replace_once(changed, anchor,
                                    anchor.replace("                best = candidate\n",
                                                   hook + "                best = candidate\n"))
        else:
            changed = _replace_once(changed, anchor, anchor + hook)
    changed_node = _single_function(changed, TARGET)

    class RemoveHooks(ast.NodeTransformer):
        def visit_Expr(self, node):
            if (isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == HOOK):
                return None
            return self.generic_visit(node)

    cleaned = RemoveHooks().visit(changed_node)
    _require(ast.dump(cleaned, include_attributes=False)
             == ast.dump(original_node, include_attributes=False),
             "instrumentation changed search AST")
    transformed = _replace_once(source, original, changed)

    # Build a separate common-prefix function; leave original refine untouched.
    refine_node = _single_function(source, "refine")
    refine = _segment(source, refine_node)
    suffix = (
        "    best = _witness_slice_exchange(\n"
        "        inputs, output, sizes, best, seed\n"
        "    )\n"
        "    best = _outside_certified_frontier_dp(\n"
        "        inputs, output, sizes, best, seed\n"
        "    )\n"
        "    return [tuple(int(i) for i in step) for step in best.get_path()], sorted(best.sliced_inds)\n"
    )
    common = _replace_once(refine, suffix, "    return best\n")
    common = _replace_once(common, "def refine(", f"def {COMMON}(")
    transformed += "\n\n" + common
    # Parse complete generated source now, but never execute in this function.
    ast.parse(transformed)
    return transformed, {
        "source_sha256": digest, "normalized_source_sha256": _sha(source),
        "target_sha256": _sha(original), "instrumented_target_sha256": _sha(changed),
        "transformed_sha256": _sha(transformed),
        "common_prefix_sha256": _sha(refine.split("    best = _witness_slice_exchange(\n")[0]),
        "search_ast_unchanged_after_hook_removal": True,
        "budgets": {"sweeps": 2, "frontier": 10, "editable": 6,
                    "roots": "max(2,min(4,2400//n))"},
    }


def _domain_record(state, inputs, output, sizes, cap):
    """Copy the actual sweep source/domain, including stale-source situations."""
    dims = dict(sizes)
    _, _, _, owners = _problem(inputs, output, dims)
    names = state["names"]

    def labels(mask):
        return tuple(name for j, name in enumerate(names) if mask & (1 << j))

    children = state["children"]
    physical = list(range(len(inputs)))
    for pair in children[len(inputs):]:
        physical.append((physical[pair[0]], physical[pair[1]]))
    root = state["root"]
    _check_tree_depth(physical[-1])
    frontier = state["frontier"]
    atoms = tuple({"node": v, "tree": deepcopy(physical[v]),
                   "leaves": tuple(sorted(_leaves(physical[v]))),
                   "boundary": tuple(sorted(_boundary(_leaves(physical[v]), owners, output)))}
                  for v in frontier)
    old_slices = labels(state["old_slices"])
    source = collect_exact(inputs, output, dims, state["source"].get_path(), old_slices)
    before = snapshot(inputs, output, dims, state["best"])
    fixed_nodes = tuple({"node": v, "leaves": tuple(sorted(_leaves(physical[v])))}
                        for v in state["fixed_nodes"])
    record = {
        "inputs": tuple(tuple(term) for term in inputs), "output": tuple(output),
        "sizes": dims, "cap": int(cap), "seed": state["seed"], "sweep": state["sweep"],
        "region_budget": state["region_budget"], "sweep_roots": tuple(state["roots"]),
        "native_incumbent_work_prediction": state["winning_cost"],
        "root": root, "root_tree": deepcopy(physical[root]),
        "root_leaves": tuple(sorted(_leaves(physical[root]))),
        "frontier": atoms, "branches": tuple(sorted(state["branches"])),
        "fixed_nodes": fixed_nodes, "source_children": deepcopy(children),
        "editable": tuple(names[j] for j in state["editable"]),
        "fixed_slices": labels(state["fixed_slices"]),
        "old_slices": old_slices, "incumbent_state": state["incumbent_state"],
        "states": tuple(state["states"]),
        "source_baseline": source, "incumbent_before": before,
        "source_and_incumbent_same_tree": _tree_key(source["tree"]) == _tree_key(before["tree"]),
        "source_and_incumbent_same_slices": source["slices"] == before["slices"],
        # Native DP tables are predictions, not independent cost evidence.
        "native_prediction_tables": {
            "outside": tuple(state["outside"]), "boundary": tuple(state["boundary"]),
            "boundary_base": tuple(state["boundary_base"]),
            "boundary_code": tuple(state["boundary_code"]),
            "factors": tuple(state["factors"]),
            "fixed_multiplicity": state["fixed_multiplicity"],
        },
    }
    record["actual_incumbent_domain_evidence"] = domain_evidence(before, record)
    record["limitation"] = (
        "Each sweep freezes source topology and old slices once; later roots can "
        "use a stale domain relative to evolving best. Offline arms start from "
        "source_baseline, not automatically actual incumbent_before."
    )
    return record


V1_KEY_DEPTH = 128


def _tree_key(tree):
    """Orientation-free tree identity.

    Trees v1 supported (depth <= 128) get v1's exact nested (0,i)/(1,*sorted(...))
    value, built iteratively, so shallow comparisons, caches and tie-break reprs are
    unchanged. Deeper complete trees get a flat exact identity: the sorted tuple of
    every internal node's sorted physical leaf group. For binary trees over distinct
    leaves this set determines the unordered rooted tree, and it never needs a deep
    recursive tuple compare/hash. Depth is orientation-invariant, so the two forms
    can only meet for trees that are already different.
    """
    pending, depth = [(tree, 0)], 0
    while pending:
        node, level = pending.pop()
        depth = max(depth, level)
        if type(node) is not int:
            pending.extend(((node[1], level + 1), (node[0], level + 1)))
    if depth <= V1_KEY_DEPTH:
        # Rebuild the v1 nested form bottom-up (depth <= 128 keeps tuple compares shallow).
        pending, values = [(tree, False)], []
        while pending:
            node, visited = pending.pop()
            if type(node) is int:
                values.append((0, node))
            elif visited:
                b, a = values.pop(), values.pop()
                values.append((1, *sorted((a, b))))
            else:
                pending.extend(((node, True), (node[1], False), (node[0], False)))
        return values[0]
    groups, pending = [], [(tree, False)]
    stack_groups = []
    while pending:
        node, visited = pending.pop()
        if type(node) is int:
            stack_groups.append((node,))
        elif visited:
            b, a = stack_groups.pop(), stack_groups.pop()
            group = tuple(sorted(a + b))
            groups.append(group)
            stack_groups.append(group)
        else:
            pending.extend(((node, True), (node[1], False), (node[0], False)))
    return ("physical-internal-leaf-groups-v2", tuple(sorted(groups)))


def domain_evidence(record, domain, *, _check=None):
    """Test actual topology/slice membership, not mere equality with the source."""
    fixed = {tuple(item["leaves"]) for item in _checked_items(domain["fixed_nodes"], _check)}
    present = {tuple(item["leaves"]) for item in _checked_items(record["nodes"], _check)}
    atoms = tuple(frozenset(atom["leaves"]) for atom in domain["frontier"])
    root = frozenset(domain["root_leaves"])
    regional = [node for node in record["nodes"] if tuple(node["leaves"]) not in fixed]
    valid_regional = True
    for node in _checked_items(regional, _check):
        group = frozenset(node["leaves"])
        selected = [atom for atom in atoms if atom <= group]
        if (not group <= root or len(selected) < 2
                or frozenset().union(*selected) != group):
            valid_regional = False
    topology_member = (fixed <= present and valid_regional
                       and len(regional) == len(atoms) - 1)
    slices = frozenset(record["slices"])
    fixed_slices = frozenset(domain["fixed_slices"])
    slice_member = fixed_slices <= slices <= fixed_slices | set(domain["editable"])
    outside = sum(node["work"] for node in record["nodes"] if tuple(node["leaves"]) in fixed)
    return {"in_domain": topology_member and slice_member,
            "topology_member": topology_member, "slice_member": slice_member,
            "missing_fixed_nodes": tuple(sorted(fixed - present)),
            "outside_work": outside if fixed <= present else None,
            "local_work": record["per_slice_work"] - outside if topology_member else None}


@dataclass
class InstrumentedReplay:
    """One trusted module namespace; no global last-loaded singleton."""

    module: ModuleType
    emit: object
    provenance: dict
    _active: bool = False
    _domain_id: int = 0
    _current: object = None
    _prediction: object = None
    _accepted: int = 0

    def _send(self, kind, **fields):
        self.emit(deepcopy({"schema": SCHEMA, "kind": kind, **fields}))

    def _hook(self, kind, state):
        _require(self._active, "trace hook outside replay")
        inputs, output, sizes = self._inputs, self._output, self._sizes
        if kind == "domain":
            self._domain_id += 1
            self._prediction = None
            self._current = _domain_record(state, inputs, output, sizes, self.module.CAP)
            self._send("domain", domain_id=self._domain_id, domain=self._current)
        elif kind == "prediction":
            self._prediction = {
                "sliced_state": state["sliced_state"], "total_work": state["total"],
                "local_work": state["dp"][state["whole"]],
                "outside_work": state["outside_work"],
                "multiplicity": state["multiplicity"],
                "choices": tuple(state["choices"]),
            }
            self._send("prediction", domain_id=self._domain_id, prediction=self._prediction)
        elif kind == "domain_end":
            self._send("domain_search_end", domain_id=self._domain_id,
                       has_winner=state["winner"] is not None,
                       prediction=self._prediction)
        elif kind == "accepted":
            before = snapshot(inputs, output, sizes, state["best"])
            after = snapshot(inputs, output, sizes, state["candidate"])
            _require(self._prediction is not None, "acceptance without DP prediction")
            self._accepted += 1
            restore_witnesses = []
            for index in sorted(set(before["slices"]) - set(after["slices"])):
                restored = exact_tree(inputs, output, sizes, before["tree"],
                                      set(before["slices"]) - {index})
                violating = [node for node in restored["nodes"]
                             if node["result_size"] > self.module.CAP]
                selected = sorted(violating, key=lambda node: (-node["result_size"], node["leaves"]))[:8]
                restore_witnesses.append({
                    "restored_index": index, "tree": "actual_before_tree",
                    "remaining_slices": restored["slices"], "total_work": restored["total_work"],
                    "result_only_peak": restored["result_only_peak"],
                    "feasible": not violating, "violating_count": len(violating),
                    "total_violating_nodes": len(violating), "detailed_witness_limit": 8,
                    "detailed_witnesses_truncated": len(violating) > 8,
                    "all_violations_catalog": [
                        {"postorder_node": position, "result_size": node["result_size"],
                         "excess_elements": node["result_size"] - self.module.CAP}
                        for position, node in enumerate(restored["nodes"])
                        if node["result_size"] > self.module.CAP],
                    "catalog_reconstruction": "postorder of actual_before path tree with restored_index removed from slices",
                    "witness_limit": 8, "witnesses": [
                        {**node, "cap": int(self.module.CAP),
                         "excess_elements": node["result_size"] - self.module.CAP,
                         "ratio_numerator": node["result_size"],
                         "ratio_denominator": int(self.module.CAP)} for node in selected],
                })
            self._send("accepted", domain_id=self._domain_id, step=self._accepted,
                       slice_restore_witnesses=restore_witnesses,
                       before=before, after=after,
                       prediction=self._prediction,
                       before_domain_evidence=domain_evidence(before, self._current),
                       after_domain_evidence=domain_evidence(after, self._current),
                       independent_agreement=(after["total_work"] == self._prediction["total_work"]),
                       independent_strict_improvement=(after["total_work"] < before["total_work"]),
                       independent_feasible=(after["result_only_peak"] <= self.module.CAP))
        else:
            raise TraceContractError(f"unknown hook {kind}")

    def replay(self, inputs, output, sizes, start_tree, seed=0):
        """Run ONLY the frozen J26 function, retaining its original module globals.

        Return the native final tree. Records are sent synchronously to emit;
        emit/collector failures abort replay rather than silently lose evidence.
        Callbacks must not mutate candidate/module/input state. Not thread-safe.
        """
        _require(sys.platform.startswith("linux"), "candidate replay is Linux-only")
        _require(not self._active, "reentrant replay is unsupported")
        native_inputs, native_output, native_sizes = inputs, output, sizes
        normalized_inputs, normalized_output, normalized_sizes, _ = _problem(inputs, output, sizes)
        self._inputs, self._output, self._sizes = normalized_inputs, normalized_output, normalized_sizes
        # Validate independently without changing the actual container types used
        # by frozen native calls (tuple vs set can change native tie ordering).
        before = snapshot(native_inputs, native_output, native_sizes, start_tree)
        self._domain_id, self._accepted = 0, 0
        self._current = self._prediction = None
        self._active = True
        try:
            self._send("start", seed=seed, provenance=self.provenance, before=before,
                       scope={"hyperedges": True, "dimension_one": True,
                              "nonoutput_unary_reductions": False,
                              "peak": "binary contraction results only", "wsx": False})
            result = getattr(self.module, TARGET)(native_inputs, native_output, native_sizes, start_tree, seed)
            self._send("end", accepted_steps=self._accepted, domains=self._domain_id,
                       after=snapshot(native_inputs, native_output, native_sizes, result))
            return result
        finally:
            self._active = False

    __call__ = replay

    def run_common(self, inputs, output, sizes, path, seed=0):
        """Historical source-derived two-route prefix; no WSX or J26 calls."""
        _require(sys.platform.startswith("linux"), "candidate common stage is Linux-only")
        _require(not self._active, "common stage cannot run during replay")
        _problem(inputs, output, sizes)
        tree_from_path(path, len(inputs))
        return getattr(self.module, COMMON)(inputs, output, sizes, path, seed)


def load_instrumented(source_path, emit, *, expected_sha256=FRESH_J26_SHA256):
    """Explicitly execute a digest-pinned TRUSTED candidate on Linux only.

    This is not safe for untrusted code: exec preserves all original imports,
    constants and globals. No module execution occurs on Windows. There are no
    installs, subprocesses, monkeypatches, candidate writes or implicit runs.
    """
    _require(sys.platform.startswith("linux"), "trusted candidate loading is Linux-only")
    _require(callable(emit), "emit must be callable")
    path = Path(source_path)
    raw = path.read_bytes()
    _require(hashlib.sha256(raw).hexdigest() == expected_sha256,
             "trusted candidate file SHA256 mismatch")
    source = raw.decode("utf-8")
    transformed, provenance = transform_source(source, expected_sha256=expected_sha256)
    provenance["source_path"] = str(path.resolve())
    module = ModuleType("_qpe_j26_trusted_instrumented")
    module.__file__ = str(path.resolve())
    replay_handle = InstrumentedReplay(module, emit, provenance)
    module.__dict__[HOOK] = replay_handle._hook
    exec(compile(transformed, str(path), "exec"), module.__dict__)
    return replay_handle


def replay(inputs, output, sizes, start_tree, seed=0, *, instrumented):
    """Explicit-handle convenience API; never uses a hidden last-loaded module."""
    return instrumented.replay(inputs, output, sizes, start_tree, seed)


class OfflineBudgetExceeded(RuntimeError):
    """No partial result should be reported as an exact finite-arm optimum."""


def offline_arms(domain, *, max_transitions=5_000_000, max_alternations=64,
                 baseline="actual_if_member", deadline=None):
    """Exact F/S/J and strict alternating arms on ONE recorded actual domain.

    F = topology DP at baseline slices; S = all editable states at baseline
    topology; J = topology DP over every editable state. FS/SF alternate strict
    improvements. By default use the actual incumbent if it belongs to the
    domain, otherwise explicitly fall back to the sweep source baseline. Set
    baseline='actual' to fail closed rather than fall back, or 'source' for an
    explicit source-only diagnostic. All fixed atom internals and exterior nodes contribute
    exact work and result capacity. Ties retain the incumbent in alternation.
    Returned optima are conditional on the recorded finite domain, not global
    tensor-network optima or new method runs. No <=5 synthetic oracle is used.
    A budget exhaustion raises, never returns a truncated optimum. Deadline
    checks cover preprocessing and accounting cooperatively; they cannot interrupt
    an individual Python/C primitive and are not a hard process-time limit.
    """
    _require(type(max_transitions) is int and max_transitions > 0, "positive offline budget required")

    def check_deadline():
        if deadline is not None and time.monotonic() >= deadline:
            raise OfflineBudgetExceeded("exact offline wall-clock budget exhausted")

    check_deadline()
    # Reject deep recorded trees before any recursive copying. Compact records
    # carry paths instead, whose depth is checked during reconstruction below.
    for field in ("source_baseline", "incumbent_before"):
        if "tree" in domain[field]:
            _check_tree_depth(domain[field]["tree"], check_deadline)
    _check_tree_depth(domain["root_tree"], check_deadline)
    for atom in domain["frontier"]:
        _check_tree_depth(atom["tree"], check_deadline)

    def checked_copy(value):
        # Iterative builtin copy (dict/list/tuple preserved), deadline checked per item.
        return _load_stack().copy(value, check=check_deadline)

    domain = checked_copy(domain)
    # Rehydrate compact JSONL domains without native calls or a search rerun.
    for field in ("source_baseline", "incumbent_before"):
        if "nodes" not in domain[field]:
            stored = domain[field]
            domain[field] = collect_exact(domain["inputs"], domain["output"], domain["sizes"],
                                          stored["path"], stored["slices"], _check=check_deadline)
    if any("leaves" not in item for item in domain["fixed_nodes"]):
        physical = list(range(len(domain["inputs"])))
        for a, b in domain["source_children"][len(physical):]:
            check_deadline()
            physical.append((physical[a], physical[b]))
        _check_tree_depth(physical[-1], check_deadline)
        domain["fixed_nodes"] = tuple({**item, "leaves": tuple(sorted(_leaves(physical[item["node"]])))}
                                      for item in domain["fixed_nodes"])
    _require(type(max_alternations) is int and max_alternations > 0, "positive alternation bound required")
    _require(baseline in ("actual_if_member", "actual", "source"), "invalid offline baseline selection")
    baseline_selection = baseline
    check_deadline()
    inputs, output, dims, owners = _problem(domain["inputs"], domain["output"], domain["sizes"],
                                           _check=check_deadline)
    check_deadline()
    atoms = tuple(atom["tree"] for atom in domain["frontier"])
    editable = tuple(domain["editable"])
    fixed = _slices(domain["fixed_slices"], output, dims)
    old = _slices(domain["old_slices"], output, dims)
    cap = domain["cap"]
    _require(type(cap) is int and cap > 0, "invalid result capacity")
    _require(3 <= len(atoms) <= 10 and len(editable) <= 6, "outside recorded J26 bounds")
    _require(len(set(editable)) == len(editable) and not fixed.intersection(editable),
             "invalid editable domain")
    _require(set(editable) <= dims.keys() and not set(editable).intersection(output),
             "invalid editable indices")
    _require(all(dims[x] > 1 for x in editable), "editable dimension-one index")
    _require(fixed <= old <= fixed | set(editable), "old slices outside actual domain")
    root_leaves = frozenset(domain["root_leaves"])
    atom_groups = tuple(frozenset(_leaves(atom)) for atom in atoms)
    _require(sum(map(len, atom_groups)) == len(set().union(*atom_groups))
             and set().union(*atom_groups) == root_leaves, "frontier does not partition root")
    source_tree = domain["source_baseline"]["tree"]
    # Check full source tree independently before deriving the fixed exterior.
    exact_tree(inputs, output, dims, source_tree, old, _check=check_deadline)
    transitions = 0

    def tick():
        nonlocal transitions
        transitions += 1
        if transitions > max_transitions:
            raise OfflineBudgetExceeded("exact offline transition budget exhausted")
        check_deadline()

    def graft(node, replacement):
        # Same result as v1's top-down replacement of the subtree whose leaves are exactly
        # root_leaves (leaf groups are disjoint, so at most one subtree matches), rebuilt
        # bottom-up with an explicit stack. Untouched subtrees become tuples, as in v1.
        pending, values = [(node, False)], []
        while pending:
            check_deadline()
            item, visited = pending.pop()
            if type(item) is int:
                group = frozenset((item,))
                values.append((group, replacement if group == root_leaves else item))
            elif visited:
                right_group, right = values.pop()
                left_group, left = values.pop()
                group = left_group | right_group
                values.append((group, replacement if group == root_leaves else (left, right)))
            else:
                pending.extend(((item, True), (item[1], False), (item[0], False)))
        return values[0][1]

    def expand(node):
        check_deadline()
        if type(node) is int:
            return atoms[node]
        return (expand(node[0]), expand(node[1]))

    atom_lookup = {group: j for j, group in enumerate(atom_groups)}

    def collapse(node):
        # Top-down: stop at frontier atom groups; reaching an uncovered leaf fails closed.
        # Only the (<=10-atom) regional subtree is ever collapsed.
        pending, values = [(node, False)], []
        while pending:
            check_deadline()
            item, visited = pending.pop()
            if visited:
                right, left = values.pop(), values.pop()
                values.append((left, right))
                continue
            group = frozenset(_leaves(item))
            if group in atom_lookup:
                values.append(atom_lookup[group])
                continue
            _require(type(item) is not int, "source topology cannot be collapsed to frontier")
            pending.extend(((item, True), (item[1], False), (item[0], False)))
        return values[0]

    baseline_tree = source_tree
    baseline_slices = old
    actual = domain["incumbent_before"]
    actual_member = domain_evidence(actual, domain, _check=check_deadline)["in_domain"]
    _require(baseline_selection != "actual" or actual_member,
             "actual incumbent is outside recorded domain; no same-incumbent four-arm attribution")
    use_actual = baseline_selection != "source" and actual_member
    if use_actual:
        baseline_tree = actual["tree"]
        baseline_slices = frozenset(actual["slices"])

    def find_root(node):
        # Bottom-up group table (one pass) instead of v1's repeated _leaves per node; the
        # first preorder subtree with exactly root_leaves is the unique such subtree.
        pending, values, found = [(node, False)], [], None
        while pending:
            check_deadline()
            item, visited = pending.pop()
            if type(item) is int:
                group = frozenset((item,))
            elif visited:
                right, left = values.pop(), values.pop()
                group = left | right
            else:
                pending.extend(((item, True), (item[1], False), (item[0], False)))
                continue
            if group == root_leaves and found is None:
                found = item
            values.append(group)
        return found

    baseline_root = find_root(baseline_tree)
    _require(baseline_root is not None, "baseline has no recorded root")
    original_region = collapse(baseline_root)
    _require(_tree_key(graft(source_tree, expand(original_region))) == _tree_key(baseline_tree),
             "baseline changed topology outside recorded domain")
    _require(_tree_key(graft(source_tree, domain["root_tree"])) == _tree_key(source_tree),
             "recorded root not present in source topology")
    states = tuple(fixed | frozenset(x for j, x in enumerate(editable) if state & (1 << j))
                   for state in range(1 << len(editable)))
    limit = 1 << len(atoms)
    groups = [frozenset() for _ in range(limit)]
    for mask in range(1, limit):
        check_deadline()
        bit = mask & -mask
        groups[mask] = groups[mask ^ bit] | atom_groups[bit.bit_length() - 1]
    def checked_boundary(group):
        check_deadline()
        return _boundary(group, owners, output, _check=check_deadline)

    boundaries = tuple(checked_boundary(group) for group in groups)
    outside_groups = {tuple(item["leaves"]) for item in domain["fixed_nodes"]}
    source_nodes = exact_tree(inputs, output, dims, source_tree, _check=check_deadline)["nodes"]
    regional_groups = {tuple(sorted(groups[mask])) for mask in range(1, limit)
                       if mask & (mask - 1)}
    _require(outside_groups <= {node["leaves"] for node in source_nodes}, "unknown fixed node")
    # Fixed nodes are precisely all source internal nodes outside the changed branches.
    expected_fixed = {node["leaves"] for node in source_nodes
                      if not (set(node["leaves"]) <= root_leaves
                              and node["leaves"] in regional_groups)}
    _require(outside_groups == expected_fixed, "fixed-node domain mismatch")
    outside_cache, dp_cache, eval_cache = {}, {}, {}

    def outside(slices):
        if slices not in outside_cache:
            record = exact_tree(inputs, output, dims, source_tree, slices, _check=check_deadline)
            nodes = [node for node in record["nodes"] if node["leaves"] in outside_groups]
            outside_cache[slices] = (sum(node["work"] for node in nodes),
                                     max((node["result_size"] for node in nodes), default=0))
        return outside_cache[slices]

    def evaluate(region, slices):
        tick()
        key = (_tree_key(region), slices)
        if key not in eval_cache:
            full = graft(source_tree, expand(region))
            result = exact_tree(inputs, output, dims, full, slices, _check=check_deadline)
            outside_work, _ = outside(slices)
            result.update(region_tree=deepcopy(region), outside_work=outside_work,
                          local_work=result["per_slice_work"] - outside_work,
                          feasible=result["result_only_peak"] <= cap)
            eval_cache[key] = result
        return eval_cache[key] if eval_cache[key]["feasible"] else None

    def topology(slices):
        if slices in dp_cache:
            return dp_cache[slices]
        outside_work, outside_peak = outside(slices)
        if outside_peak > cap:
            dp_cache[slices] = None
            return None
        boundary = tuple(labels - slices for labels in boundaries)
        costs, trees = [None] * limit, [None] * limit
        for j in range(len(atoms)):
            costs[1 << j], trees[1 << j] = 0, j
        for mask in range(1, limit):
            if not mask & (mask - 1):
                continue
            if prod(dims[x] for x in boundary[mask]) > cap:
                continue
            first = mask & -mask
            a = (mask - 1) & mask
            while a:
                if a & first:
                    tick()
                    b = mask ^ a
                    if costs[a] is not None and costs[b] is not None:
                        cost = costs[a] + costs[b] + prod(dims[x] for x in boundary[a] | boundary[b])
                        if costs[mask] is None or cost < costs[mask]:
                            costs[mask], trees[mask] = cost, (trees[a], trees[b])
                a = (a - 1) & mask
        result = None if costs[-1] is None else evaluate(trees[-1], slices)
        if result is not None:
            _require(result["local_work"] == costs[-1]
                     and result["total_work"] == result["multiplicity"] * (outside_work + costs[-1]),
                     "independent offline reconstruction disagrees with DP")
        dp_cache[slices] = result
        return result

    def choose(results):
        valid = [result for result in results if result is not None]
        return min(valid, key=lambda r: (r["total_work"], r["slices"], repr(_tree_key(r["region_tree"])))) if valid else None

    def slicing(region):
        return choose(evaluate(region, slices) for slices in states)

    baseline = evaluate(original_region, baseline_slices)
    f = topology(baseline_slices)
    s = slicing(original_region)
    j = choose(topology(slices) for slices in states)

    def alternate(order):
        current = baseline
        history = []
        if current is None:
            return {"status": "infeasible_source_baseline", "result": None, "history": history}
        for _ in range(max_alternations):
            changed = False
            for arm in order:
                proposed = topology(frozenset(current["slices"])) if arm == "F" else slicing(current["region_tree"])
                if proposed is not None and proposed["total_work"] < current["total_work"]:
                    history.append({"arm": arm, "before": current["total_work"],
                                    "after": proposed["total_work"], "slices": proposed["slices"]})
                    current, changed = proposed, True
            if not changed:
                return {"status": "strict_fixed_point", "result": current, "history": history}
        raise OfflineBudgetExceeded("alternation bound reached before a strict fixed point")

    fs, sf = alternate("FS"), alternate("SF")
    actual_before_copy = checked_copy(domain["incumbent_before"])
    check_deadline()
    return {"scope": "exact_recorded_finite_domain_only", "baseline": baseline,
            "actual_incumbent_before": actual_before_copy,
            "baseline_selection": "actual_incumbent" if use_actual else "source_diagnostic",
            "actual_incumbent_in_domain": actual_member,
            "baseline_is_actual_incumbent": use_actual,
            "same_incumbent_attribution": use_actual,
            "F": f, "S": s, "J": j, "FS": fs, "SF": sf,
            "transitions": transitions, "frontier_count": len(atoms),
            "editable_count": len(editable), "state_count": len(states)}


def _exact_metric(value):
    """Exact nonnegative integer evidence, never bool/float/truncation."""
    if type(value) is int:
        _require(value >= 0, "exact metric must be nonnegative")
        return value
    _require(isinstance(value, str) and value.isascii() and value.isdecimal()
             and (value == "0" or not value.startswith("0")),
             "exact metric must be an integer or canonical decimal-integer string")
    return int(value)


def _historical_metric(value, exact):
    """Disclose rounded float comparison separately from exact evidence."""
    if type(value) is float:
        _require(isfinite(value) and value >= 0, "invalid historical float metric")
        try:
            rounded = float(exact)
        except OverflowError:
            rounded = float("inf")
        return {"comparison": "historical_float_rounded_not_exact",
                "matches": value == rounded, "exact_agreement": None,
                "stored": value}
    matches = _exact_metric(value) == exact
    return {"comparison": "exact_integer", "matches": matches,
            "exact_agreement": matches, "stored": value}


# CLI: only main() performs I/O or candidate execution. Collector subprocesses
# invoke --audit-records and return before any native/candidate import.
def _audit_payload(payload):
    inputs, output, sizes = payload["inputs"], payload["output"], payload["sizes"]
    checked = []
    for item in payload["records"]:
        exact = collect_exact(inputs, output, sizes, item["path"], item["slices"])
        expected = item.get("expected", {})
        matches = {key: _exact_metric(expected[key]) == exact[key]
                   for key in ("total_work", "result_only_peak", "per_slice_work", "multiplicity")
                   if key in expected}
        checked.append({"label": item["label"], "total_work": str(exact["total_work"]),
                        "result_only_peak": str(exact["result_only_peak"]),
                        "multiplicity": str(exact["multiplicity"]),
                        "matches": matches, "all_match": all(matches.values())})
    return {"kind": "independent_process_audit", "stdlib_only": True,
            "all_match": all(item["all_match"] for item in checked), "records": checked}


_WIRE_COSTS = frozenset({
    "total_work", "total_flops", "max_size", "result_only_peak", "per_slice_work",
    "multiplicity", "work", "result_size", "outside_work", "local_work",
    "fixed_multiplicity", "native_incumbent_work_prediction", "before", "after",
    "gain", "sum_gains", "start_work", "end_work", "excess_elements", "ratio_numerator",
    "ratio_denominator"})


def _wire(value, key=""):
    """Decimal strings for exact work/volume evidence; identifiers stay integers.

    v2 explicit-stack form of the v1 recursive rule with identical output: same key
    order, tuple->list, list items inherit the parent key, "sizes" passthrough, and
    snapshot "nodes" / fixed_nodes "leaves" omissions.
    """
    root = [None]
    pending = [(value, key, root, 0)]
    while pending:
        item, name, parent, slot = pending.pop()
        if isinstance(item, bool) or item is None:
            parent[slot] = item
        elif isinstance(item, int):
            parent[slot] = str(item) if name in _WIRE_COSTS else item
        elif isinstance(item, Mapping):
            # Physical labels are opaque strings, including "work" and "nodes".
            if name == "sizes":
                parent[slot] = dict(item)
                continue
            # Only exact snapshot records own an omittable per-node evidence list.
            snapshot_record = "per_slice_work" in item and "tree" in item
            omitted = {"nodes"} if snapshot_record else set()
            if name == "fixed_nodes":
                omitted.add("leaves")
            children = [(str(k), v) for k, v in item.items() if k not in omitted]
            out = {child_key: None for child_key, _ in children}
            parent[slot] = out
            for child_key, child in reversed(children):
                pending.append((child, child_key, out, child_key))
        elif isinstance(item, (tuple, list)):
            out = [None] * len(item)
            parent[slot] = out
            for i in range(len(item) - 1, -1, -1):
                pending.append((item[i], name, out, i))
        else:
            parent[slot] = item
    return root[0]


class _BoundedTraceOutput:
    """Reserve one small terminal record; never retry through the normal emitter."""

    def __init__(self, stream, *, max_line_bytes=8 * 1024 * 1024,
                 max_stream_bytes=14 * 1024 * 1024, error_reserve=2048):
        _require(0 < error_reserve <= max_line_bytes
                 and error_reserve < max_stream_bytes, "invalid output reserve")
        self.stream = stream
        self.max_line_bytes = max_line_bytes
        self.max_stream_bytes = max_stream_bytes
        self.error_reserve = error_reserve
        self.output_bytes = 0
        self.terminal = False

    def send(self, event):
        import json
        _require(not self.terminal, "trace output already terminated")
        text = json.dumps(_wire(event), ensure_ascii=True, separators=(",", ":"))
        size = len(text.encode("utf-8")) + 1
        _require(size <= self.max_line_bytes, "trace event exceeds line limit")
        _require(self.output_bytes + size <= self.max_stream_bytes - self.error_reserve,
                 "trace stream exceeds normal-output allowance")
        self.output_bytes += size
        print(text, file=self.stream, flush=True)

    def fail(self, exc, accepted_steps):
        import json
        if self.terminal:
            return
        self.terminal = True
        event = {"kind": "error", "error_type": type(exc).__name__[:64],
                 "message": str(exc)[:128], "accepted_steps_recorded": accepted_steps,
                 "no_retry": True}
        text = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
        size = len(text.encode("utf-8")) + 1
        if size > self.error_reserve:
            text = '{"kind":"error","message":"terminal error details exceeded reserve","no_retry":true}'
            size = len(text) + 1
        if size > self.error_reserve or self.output_bytes + size > self.max_stream_bytes:
            return
        self.output_bytes += size
        try:
            print(text, file=self.stream, flush=True)
        except (OSError, ValueError):
            pass  # A closed/broken output stream cannot receive a terminal record.


def main(argv=None):
    import argparse
    import json
    import os
    import signal
    import subprocess
    from contextlib import redirect_stdout
    from importlib.metadata import version

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request")
    parser.add_argument("--common")
    parser.add_argument("--historical-j")
    parser.add_argument("--source")
    parser.add_argument("--source-sha256", default=FRESH_J26_SHA256)
    parser.add_argument("--seconds", type=float, default=190)
    parser.add_argument("--arms-seconds", type=float, default=0,
                        help="opt in to offline arms with a positive time budget (default: disabled)")
    parser.add_argument("--audit-records", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.audit_records:
        # No cotengra import, no source load, no search, stdin-only exact scoring.
        print(json.dumps(_audit_payload(json.load(sys.stdin)), separators=(",", ":")), flush=True)
        return 0
    if args.self_test:
        import unittest
        suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent / "tests"),
                                                    pattern="test_qpe_j26_trace.py")
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    _require(all((args.request, args.common, args.historical_j, args.source)),
             "request, common, historical-j, and source paths are required")
    _require(sys.platform.startswith("linux"), "trajectory CLI is Linux-only")
    _require(args.seconds > 0 and isfinite(args.seconds)
             and args.arms_seconds >= 0 and isfinite(args.arms_seconds), "invalid wall-clock budget")
    started = time.monotonic()
    deadline = started + args.seconds
    writer = _BoundedTraceOutput(sys.stdout)
    accepted, domains = [], {}
    audit_records = []
    previous_alarm = None

    def emit(event):
        event = {"elapsed_seconds": time.monotonic() - started, **event}
        writer.send(event)
        if event.get("kind") == "domain":
            domains[event["domain_id"]] = event["domain"]
        elif event.get("kind") == "accepted":
            accepted.append(event)
            for side in ("before", "after"):
                audit_records.append({"label": f"step-{event['step']}-{side}",
                                      "path": event[side]["path"], "slices": event[side]["slices"],
                                      "expected": event[side]})

    def time_limit(signum, frame):
        raise TimeoutError("trajectory total wall-clock budget exhausted")

    def remaining():
        return max(0.0, deadline - time.monotonic())

    def independent_audit(inputs, output, sizes):
        _require(remaining() > 0, "no time remaining for independent process audit")
        payload = {"inputs": inputs, "output": output, "sizes": sizes,
                   "records": [{**item, "expected": {key: item["expected"][key]
                                for key in ("total_work", "result_only_peak", "per_slice_work", "multiplicity")}}
                               for item in audit_records]}
        child = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--audit-records"],
                               input=json.dumps(payload), text=True, capture_output=True,
                               cwd="/tmp", timeout=min(20.0, remaining()), check=True)
        result = json.loads(child.stdout)
        emit(result)
        _require(result["all_match"], "independent process audit mismatch")

    try:
        previous_alarm = signal.signal(signal.SIGALRM, time_limit)
        signal.setitimer(signal.ITIMER_REAL, args.seconds)
        paths = {"request": args.request, "common": args.common, "historical_j": args.historical_j}
        documents, hashes = {}, {}
        for label, filename in paths.items():
            raw = Path(filename).read_bytes()
            hashes[label] = hashlib.sha256(raw).hexdigest()
            documents[label] = json.loads(raw)
        request, common, historical = (documents[key] for key in ("request", "common", "historical_j"))
        inputs, output, sizes = request["inputs"], request["output"], request["sizes"]
        _problem(inputs, output, sizes)
        seed = request.get("candidate_seed", 0)
        _require(type(seed) is int, "candidate seed must be an integer")
        endpoint_snapshots = {}
        for label, saved in (("saved_common", common), ("saved_historical_j", historical)):
            exact = collect_exact(inputs, output, sizes, saved["path"], saved["sliced"])
            endpoint_snapshots[label] = exact
            comparisons = {
                "total_flops": _historical_metric(saved["total_flops"], exact["total_work"]),
                "max_size": _historical_metric(saved["max_size"], exact["result_only_peak"]),
            }
            agreement = {key: value["matches"] for key, value in comparisons.items()}
            emit({"kind": "stored_endpoint_exact", "label": label, "exact": exact,
                  "historical_metric_agreement": agreement,
                  "historical_metric_comparison": comparisons, "input_hashes": hashes})
            audit_records.append({"label": label, "path": exact["path"], "slices": exact["slices"],
                                  "expected": exact})
            _require(all(agreement.values()), "saved endpoint historical metric comparison mismatch")
        # Saved endpoints have been independently scored before any native import.
        emit({"kind": "environment", "python": sys.version, "executable": sys.executable,
              "platform": sys.platform, "hash_info": repr(sys.hash_info),
              "flags": repr(sys.flags), "PYTHONHASHSEED": os.environ.get("PYTHONHASHSEED"),
              "hashseed_environment_honored": not sys.flags.ignore_environment,
              "versions": {name: version(name) for name in ("cotengra", "opt_einsum")},
              "seed": seed, "input_hashes": hashes,
                       "scope": "direct saved-common native J26 replay; no common rerun; no WSX",
              "snapshot_node_lists_omitted_on_wire": "exactly reconstructable from preserved paths, slices, inputs and source_children",
              "historical_pre_j_state_saved": False,
              "historical_2048mb_address_space_limit_replicated": False,
              "runtime_equivalence_claim": False,
              "historical_reproduction_gap": "Historical J independently reran common prefix; exact pre-J state was not saved.",
              "stale_source_limitation": "Frozen sweep domains can lag actual incumbent; domain membership is checked for every accepted step."})
        independent_audit(inputs, output, sizes)
        with redirect_stdout(sys.stderr):
            import cotengra as ctg
        # Keep input conversion explicit in metadata; user can compare frozen runtime.
        native_inputs = inputs
        native_output = output
        emit({"kind": "native_input_contract", "inputs": "JSON list[list[str]] unchanged",
              "output": "JSON list[str] unchanged", "sizes": "request dict insertion order unchanged"})
        with redirect_stdout(sys.stderr):
            start_tree = ctg.ContractionTree.from_path(native_inputs, native_output, sizes,
                                                     path=[tuple(step) for step in common["path"]], check=True, autocomplete=False)
            for index in common["sliced"]:
                start_tree = start_tree.remove_ind(index)
            handle = load_instrumented(args.source, emit, expected_sha256=args.source_sha256)
            result = handle.replay(native_inputs, native_output, sizes, start_tree, seed)
        final = snapshot(inputs, output, sizes, result)
        audit_records.append({"label": "replay_final", "path": final["path"],
                              "slices": final["slices"], "expected": final})
        previous = endpoint_snapshots["saved_common"]
        rows, valid = [], True
        for event in accepted:
            before, after = event["before"], event["after"]
            continuous = (_tree_key(previous["tree"]) == _tree_key(before["tree"])
                          and previous["slices"] == before["slices"]
                          and previous["total_work"] == before["total_work"])
            gain = before["total_work"] - after["total_work"]
            domain = domains[event["domain_id"]]
            rows.append({"step": event["step"], "domain_id": event["domain_id"],
                         "sweep": domain["sweep"], "root": domain["root"],
                         "frontier_count": len(domain["frontier"]), "editable_count": len(domain["editable"]),
                         "before": before["total_work"], "after": after["total_work"], "gain": gain,
                         "continuous": continuous, "before_slices": before["slices"],
                         "after_slices": after["slices"],
                         "before_domain_evidence": event["before_domain_evidence"],
                         "after_domain_evidence": event["after_domain_evidence"],
                         "prediction": event["prediction"]})
            valid = valid and continuous and gain > 0 and event["independent_agreement"] and event["independent_feasible"]
            previous = after
        start_work = endpoint_snapshots["saved_common"]["total_work"]
        total_gain = sum(row["gain"] for row in rows)
        valid = (valid and total_gain == start_work - final["total_work"]
                 and _tree_key(previous["tree"]) == _tree_key(final["tree"])
                 and previous["slices"] == final["slices"])
        emit({"kind": "trajectory_table", "rows": rows, "telescopes": valid,
              "start_work": start_work, "end_work": final["total_work"], "sum_gains": total_gain,
              "historical_j_work_match": final["total_work"] == endpoint_snapshots["saved_historical_j"]["total_work"],
              "historical_j_tree_match": _tree_key(final["tree"]) == _tree_key(endpoint_snapshots["saved_historical_j"]["tree"]),
              "historical_j_slice_match": final["slices"] == endpoint_snapshots["saved_historical_j"]["slices"],
              "historical_pre_j_state_not_saved": True})
        _require(valid, "accepted trajectory failed exact telescoping checks")
        independent_audit(inputs, output, sizes)
        # Trajectory table and independent subprocess audit precede any hypothesis arms.
        arms_deadline = min(deadline - 3.0, time.monotonic() + args.arms_seconds)
        for event in accepted:
            if time.monotonic() >= arms_deadline:
                emit({"kind": "offline_arms_skipped", "domain_id": event["domain_id"],
                      "reason": "remaining offline wall-clock budget"})
                continue
            try:
                arms = offline_arms(domains[event["domain_id"]], deadline=arms_deadline)
                # Full arm trees/costs are exact, but omit per-node repeats on stdout.
                def compact(result):
                    if result is None:
                        return None
                    return {key: value for key, value in result.items() if key != "nodes"}
                for name in ("baseline", "actual_incumbent_before", "F", "S", "J"):
                    arms[name] = compact(arms[name])
                for name in ("FS", "SF"):
                    arms[name]["result"] = compact(arms[name]["result"])
                emit({"kind": "offline_arms_exact", "domain_id": event["domain_id"], "arms": arms})
            except OfflineBudgetExceeded as exc:
                emit({"kind": "offline_arms_incomplete", "domain_id": event["domain_id"],
                      "reason": str(exc), "no_partial_optimum_claim": True})
        emit({"kind": "complete", "trajectory_valid": valid, "accepted_steps": len(accepted),
              "domains": len(domains), "remaining_seconds": remaining(),
              "common_rerun": False, "extra_candidate_method_calls": 0})
        return 0
    except Exception as exc:
        signal.setitimer(signal.ITIMER_REAL, 0)
        writer.fail(exc, len(accepted))
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if previous_alarm is not None:
            signal.signal(signal.SIGALRM, previous_alarm)


if __name__ == "__main__":
    raise SystemExit(main())
