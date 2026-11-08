"""SOURCE ONLY / NOT_RUN. Focused v2 deep-tree differential tests (stdlib only).

Run only inside the pinned Linux image, in one <=90 s slot, with the five rendered
v2 runtime files under /runtime and the frozen v1 trace/business copies under
/v1 (readonly). No cotengra, candidate, results archive, network or ledger access.
Each v1 call is executed at its own unchanged recursion limit; no test changes it.
"""
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

V2 = Path(os.environ.get("QPE_V2_RUNTIME", "/runtime"))
V1 = Path(os.environ.get("QPE_V1_RUNTIME", "/v1"))
DEEP = 20000  # above any CPython C-level JSON recursion limit, so the fallback codec runs


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# v2 stack must be registered under its canonical name before trace/adapter import.
raw = (V2 / "qpe_mechanism_stack.py").read_bytes()
stack = importlib.util.module_from_spec(
    importlib.util.spec_from_file_location("qpe_mechanism_stack", str(V2 / "qpe_mechanism_stack.py")))
import hashlib
stack.__qpe_stack_sha256__ = hashlib.sha256(raw).hexdigest()
sys.modules["qpe_mechanism_stack"] = stack
exec(compile(raw, str(V2 / "qpe_mechanism_stack.py"), "exec", dont_inherit=True), stack.__dict__)
trace2 = _load("qpe_j26_trace_v2_under_test", V2 / "qpe_j26_trace.py")
trace1 = _load("qpe_j26_trace_v1_reference", V1 / "qpe_j26_trace.py")
sys.path.insert(0, str(V2))
cert = _load("qpe_fixed_capacity_certificate", V2 / "qpe_fixed_capacity_certificate.py")
adapter2 = _load("qpe_fixed_capacity_trace_adapter_v2_under_test", V2 / "qpe_fixed_capacity_trace_adapter.py")
business2 = _load("qpe_actual_incumbent_mechanism_v2_under_test", V2 / "qpe_actual_incumbent_mechanism.py")
business1 = _load("qpe_actual_incumbent_mechanism_v1_reference", V1 / "qpe_actual_incumbent_mechanism.py")


def caterpillar(n):
    """Valid hyperedge-free chain network and a maximally deep recycled path (depth n-1).

    After step 0 the accumulated result is always last in the recycled list, and input
    k+1 is first, so step k contracts positions [0, n-1-k].
    """
    inputs = [["e0"]] + [[f"e{i - 1}", f"e{i}"] for i in range(1, n - 1)] + [[f"e{n - 2}"]]
    sizes = {f"e{i}": 2 + (i % 3) for i in range(n - 1)}
    path = [[0, 1]] + [[0, n - 1 - k] for k in range(1, n - 1)]
    return inputs, [], sizes, path


def v1_dumps(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


class ShallowDifferentialTests(unittest.TestCase):
    """v2 must reproduce v1 exactly wherever v1 succeeds."""

    CASES = (
        (("ab", "bc", "cd"), "ad", {"a": 2, "b": 3, "c": 5, "d": 7}, ((0, 1), (0, 1)), ()),
        (("ab", "bc", "cd"), "ad", {"a": 2, "b": 3, "c": 5, "d": 7}, ((0, 1), (0, 1)), ("b",)),
        (("x", "x", "x"), "", {"x": 7}, ((0, 1), (0, 1)), ("x",)),
        (("ax", "ax"), "a", {"a": 2 ** 60 + 1, "x": 1}, ((0, 1),), ()),
    )

    def test_collect_exact_tree_nodes_and_wire_identical(self):
        for inputs, output, sizes, path, slices in self.CASES:
            one = trace1.collect_exact(inputs, output, sizes, path, slices)
            two = trace2.collect_exact(inputs, output, sizes, path, slices)
            self.assertEqual(one, two)
            self.assertEqual(v1_dumps(trace1._wire(one)), stack.dumps(trace2._wire(two)))

    def test_tree_key_identical_on_shallow_trees(self):
        for tree in (0, (0, 1), ((0, 1), 2), (2, (1, 0)), (((0, 3), (1, 2)), 4)):
            self.assertEqual(trace1._tree_key(tree), trace2._tree_key(tree))

    def test_offline_arms_identical_on_v1_fixture(self):
        inputs, output = ("ax", "ab", "by"), "xy"
        dims = {"a": 8, "b": 2, "x": 2, "y": 2}
        for cap in (4, 1024):
            domains = []
            for module in (trace1, trace2):
                source = module.collect_exact(inputs, output, dims, ((0, 1), (0, 1)))
                domains.append({"inputs": inputs, "output": output, "sizes": dims, "cap": cap,
                                "root": 4, "root_tree": source["tree"], "root_leaves": (0, 1, 2),
                                "frontier": tuple({"node": i, "tree": i, "leaves": (i,)} for i in range(3)),
                                "fixed_nodes": (), "editable": ("a", "b"), "fixed_slices": (),
                                "old_slices": (), "source_baseline": source, "incumbent_before": source,
                                "source_and_incumbent_same_tree": True,
                                "source_and_incumbent_same_slices": True})
            one = trace1._wire(trace1.offline_arms(domains[0]))
            two = trace2._wire(trace2.offline_arms(domains[1]))
            self.assertEqual(v1_dumps(one), stack.dumps(two))
            # Compact wire domain round trip.
            self.assertEqual(v1_dumps(trace1._wire(trace1.offline_arms(trace1._wire(domains[0])))),
                             stack.dumps(trace2._wire(trace2.offline_arms(trace2._wire(domains[1])))))

    def test_business_audit_and_codec_identical(self):
        inputs, output, sizes, path = (["a", "b"], ["b", "c"], ["c", "a"]), [], {"a": 2, "b": 3, "c": 5}, [[0, 1], [0, 1]]
        tree, _ = trace2.tree_from_path(path, 3)
        for slices in ((), ("a",)):
            self.assertEqual(business1.audit_tree(inputs, output, sizes, tree, slices, include_nodes=True),
                             business2.audit_tree(inputs, output, sizes, tree, slices, include_nodes=True))
        value = {"z": [1, {"b": None, "a": [True, 2.5, "é"]}], "a": []}
        self.assertEqual(business1.encode(value), business2.encode(value))
        self.assertEqual(business1.decode(business1.encode(value)), business2.decode(business2.encode(value)))


class DeepPathTests(unittest.TestCase):
    """Depth well above v1's 128 guard and above CPython's default recursion limit."""

    N = 1200  # > default recursion limit; O(N*labels) owner scans stay well inside 90 s

    def setUp(self):
        self.inputs, self.output, self.sizes, self.path = caterpillar(self.N)

    def test_v1_refuses_and_v2_scores_exactly(self):
        with self.assertRaises(trace1.TraceContractError):
            trace1.collect_exact(self.inputs, self.output, self.sizes, self.path)
        exact = trace2.collect_exact(self.inputs, self.output, self.sizes, self.path)
        self.assertEqual(exact["contractions"], self.N - 1)
        audit = business2.audit_tree(self.inputs, self.output, self.sizes, exact["tree"], ())
        for key in ("multiplicity", "per_slice_work", "total_work", "result_only_peak"):
            self.assertEqual(audit[key], exact[key])
        sliced = trace2.collect_exact(self.inputs, self.output, self.sizes, self.path, ("e7",))
        self.assertEqual(sliced["multiplicity"], self.sizes["e7"])
        audit = business2.audit_tree(self.inputs, self.output, self.sizes, sliced["tree"], ("e7",))
        self.assertEqual(audit["total_work"], sliced["total_work"])

    def test_deep_wire_codec_round_trip_is_byte_exact(self):
        exact = trace2.collect_exact(self.inputs, self.output, self.sizes, self.path)
        wired = trace2._wire(exact)
        raw = stack.dumps(wired)
        self.assertNotIn(b" ", raw)
        decoded = stack.loads(raw)
        self.assertEqual(stack.dumps(decoded), raw)
        rebuilt = trace2.collect_exact(self.inputs, self.output, self.sizes, decoded["path"], decoded["slices"])
        self.assertEqual(stack.dumps(trace2._wire(rebuilt)), raw)
        self.assertTrue(stack.equal(trace2._wire(rebuilt)["tree"], decoded["tree"]))

    def test_deep_key_copy_and_equality(self):
        tree, _ = trace2.tree_from_path(self.path, self.N)
        copied = stack.copy(tree)
        self.assertIsNot(copied, tree)
        self.assertTrue(stack.equal(copied, tree))
        self.assertEqual(trace2._tree_key(copied), trace2._tree_key(tree))
        swapped = (tree[1], tree[0])
        self.assertFalse(stack.equal(swapped, tree))
        self.assertEqual(trace2._tree_key(swapped), trace2._tree_key(tree))

    def test_adapter_safe_builtins_and_codec_accept_deep_tree(self):
        tree, _ = trace2.tree_from_path(self.path, self.N)
        adapter2._safe_builtins({"tree": tree})
        adapter2._safe_builtins(stack.loads(stack.dumps({"tree": tree})))
        cyclic = [0, None]
        cyclic[1] = cyclic
        with self.assertRaises(adapter2.AdapterContractError):
            adapter2._safe_builtins(cyclic)

    def test_depth_is_really_above_v1_and_interpreter_limits(self):
        tree, _ = trace2.tree_from_path(self.path, self.N)
        depth, pending = 0, [(tree, 0)]
        while pending:
            node, level = pending.pop()
            depth = max(depth, level)
            if type(node) is not int:
                pending.extend(((node[0], level + 1), (node[1], level + 1)))
        self.assertEqual(depth, self.N - 1)
        self.assertGreater(depth, sys.getrecursionlimit())


class MalformedTests(unittest.TestCase):
    def test_codec_rejects_malformed_json(self):
        deep_ok = b"[" * DEEP + b"1" + b"]" * DEEP
        self.assertEqual(stack.dumps(stack.loads(deep_ok)), deep_ok)
        for raw in (b"[" * DEEP + b"1" + b"]" * (DEEP - 1),             # truncated
                    b"[" * DEEP + b"1" + b"]" * (DEEP + 1),             # trailing close
                    b"[" * DEEP + b"NaN" + b"]" * DEEP,           # nonfinite
                    b"[" * DEEP + b"1e999" + b"]" * DEEP,         # overflow
                    b"[" * DEEP + b'{"a":1,"a":2}' + b"]" * DEEP,  # duplicate key
                    b"[" * DEEP + b"1,]" + b"]" * (DEEP - 1),            # trailing comma
                    b"[" * DEEP + b"1" + b"]" * DEEP + b"x"):      # trailing data
            with self.assertRaises(ValueError):
                stack.loads(raw)

    def test_codec_rejects_cycles_and_custom_objects(self):
        a = []
        node = a
        for _ in range(DEEP):
            node.append([])
            node = node[0]
        node.append(a)
        with self.assertRaises(ValueError):
            stack.dumps(a)
        node[0] = object()
        with self.assertRaises((TypeError, ValueError)):
            stack.dumps(a)

    def test_deep_trees_fail_closed(self):
        inputs, output, sizes, path = caterpillar(400)
        bad = [list(step) for step in path]
        bad[-1] = [0, 0]
        with self.assertRaises(trace2.TraceContractError):
            trace2.collect_exact(inputs, output, sizes, bad)
        with self.assertRaises(trace2.TraceContractError):
            trace2.collect_exact(inputs, output, sizes, path[:-1])
        tree, _ = trace2.tree_from_path(path, 400)
        with self.assertRaises(ValueError):
            business2.audit_tree(inputs, output, sizes, (tree, 0), ())   # repeated leaf
        with self.assertRaises(ValueError):
            business2.audit_tree(inputs, output, sizes, tree[0], ())     # incomplete leaves
        with self.assertRaises(ValueError):
            business2.audit_tree(inputs, output, sizes, (tree[0], tree[1], 1), ())  # nonbinary


if __name__ == "__main__":
    unittest.main(verbosity=2)
