"""Owner-only fixed-result CAP certificate for a finite synthetic contract.

This standalone stdlib utility consumes a FULL physical binary contraction tree,
not a tree of frontier positions. Physical leaves are exact integer input IDs.
``region_path`` and ``frontier_paths`` are absolute child paths in that baseline
(0 = left, 1 = right). Frontier subtrees must form a disjoint cut covering exactly
the actual regional subtree. There are 1..10 atoms and at most 6 editable labels.
All 2**len(editable) slice masks are reported; fixed_slices are always retained.
No trees are generated, optimized, ranked, or searched. There is no work/J score.

For physical leaf set G and sliced labels S, the result boundary is exactly
    {x: owners[x] intersects G and (x is output or owners[x] - G)} - S.
Thus EVERY fixed internal leaf-set group has a result boundary/volume invariant
under any permitted regional rewire at the SAME slice configuration. Atom
internals (including an internal atom root) and ALL nonregional internal nodes
(including ancestor result groups) are immutable. Every merge BETWEEN frontier
atoms, INCLUDING the regional root, is editable. With one frontier atom there
are no editable merges: its entire subtree is immutable, even its internal root.
A physical leaf is an input, never a CAP-constrained contraction result. In
particular, a large raw frontier input is NOT a fixed-node witness.

Any fixed result volume > cap proves necessary infeasibility for that mask under
this contract. UNREJECTED_BY_FIXED_NODES means ONLY absence of such a witness,
NEVER feasibility or reachability. Baseline regional violations are observations,
not certificates: rewiring may remove their intermediate groups. Even the
regional output root is deliberately not promoted into this fixed-node test.
The domain status rejects only if EVERY allowed mask has a fixed-node witness.

The supported contract has named indices, positive integral dimensions, physical
owner incidence, retained output labels, and no unary nonoutput reductions.
Slicing removes a nonoutput label globally, including outside the region. Only
labels present on an unsliced frontier boundary may be editable; all other slice
choices are fixed. Dimension-one editable labels are excluded. Fixed nonoutput
slices may have dimension one. Scalar inputs and a one-input tree are supported.
Exact built-in containers/types are required, not coercions (bool is not int).
Dimensions are defensively snapshotted into a read-only mapping; trees and all
other collections are immutable. Owners are derived, never supplied by a caller.

Volumes/CAP/masks are exact Python ints internally. to_wire() emits decimal
strings for ALL integers, even paths and leaf IDs, to avoid lossy JSON consumers.
Node paths identify BASELINE locations; leaf sets identify invariant groups when
an atom moves during rewiring. This is not a native scorer equivalence claim.
Production adapter/integration: NOT_DONE. Authoring tests: NOT_RUN. No CLI, I/O,
protected-input loading, result writing, or compute-account operations are used.
"""

from dataclasses import dataclass, field
from math import prod
from types import MappingProxyType
from typing import Mapping, Union


Tree = Union[int, tuple["Tree", "Tree"]]
Path = tuple[int, ...]
REJECTED_BY_FIXED_NODES = "REJECTED_BY_FIXED_NODES"
UNREJECTED_BY_FIXED_NODES = "UNREJECTED_BY_FIXED_NODES"


def _decimal(value):
    """Nonnegative exact-int conversion without changing global digit limits."""
    if type(value) is not int or value < 0:
        raise ValueError("wire integers must be nonnegative exact ints")
    chunks = []
    while value >= 1_000_000_000:
        value, remainder = divmod(value, 1_000_000_000)
        chunks.append(remainder)
    return str(value) + "".join(f"{chunk:09d}" for chunk in reversed(chunks))


def _label(value):
    return type(value) is str and bool(value)


def _label_set(value, name):
    if type(value) is not frozenset or any(not _label(x) for x in value):
        raise ValueError(f"{name} must be an exact frozenset of nonempty strings")


def _path(value, name):
    if type(value) is not tuple or any(type(x) is not int or x not in (0, 1)
                                       for x in value):
        raise ValueError(f"{name} must be a tuple of exact 0/1 integers")


def _under(path, root):
    return path[:len(root)] == root


@dataclass(frozen=True)
class InternalNode:
    """Baseline location, sorted physical leaf-set identity, and editability role."""

    path: Path
    leaves: tuple[int, ...]
    kind: str  # ATOM_INTERNAL, ANCESTOR_RESULT, NONREGIONAL, EDITABLE_REGIONAL

    def to_wire(self):
        return {"path": [_decimal(x) for x in self.path],
                "leaves": [_decimal(x) for x in self.leaves], "kind": self.kind}


@dataclass(frozen=True)
class Problem:
    """Validated immutable finite domain; see module docstring for exact semantics.

    inputs is a nonempty tuple of frozensets, dims is an exact dict (or the exact
    read-only mapping type used by this class, allowing dataclasses.replace).
    tree is a full binary tuple tree over exactly range(len(inputs)), once each.
    region_path must select an actual subtree, including a leaf if desired.
    frontier_paths is a tuple of absolute paths to actual subtrees of that region.
    Their order does not introduce a new tree or affect mask order. editable is
    an ordered tuple of unique labels; bit i selects editable[i]. output and
    fixed_slices are exact frozensets. All invalid/unsupported inputs raise
    ValueError rather than being normalized into a different finite problem.
    """

    inputs: tuple[frozenset[str], ...]
    dims: Mapping[str, int]
    tree: Tree
    region_path: Path
    frontier_paths: tuple[Path, ...]
    cap: int
    editable: tuple[str, ...] = ()
    output: frozenset[str] = frozenset()
    fixed_slices: frozenset[str] = frozenset()
    owners: Mapping[str, frozenset[int]] = field(init=False, repr=False)
    fixed_nodes: tuple[InternalNode, ...] = field(init=False)
    baseline_regional_nodes: tuple[InternalNode, ...] = field(init=False)

    def __post_init__(self):
        if type(self.inputs) is not tuple or not self.inputs:
            raise ValueError("inputs must be a nonempty exact tuple")
        for tensor in self.inputs:
            _label_set(tensor, "input tensor")
        labels = frozenset().union(*self.inputs)
        if type(self.dims) not in (dict, MappingProxyType):
            raise ValueError("dims must be an exact dict or read-only mapping")
        dims = dict(self.dims)
        if (any(not _label(x) for x in dims) or set(dims) != labels
                or any(type(d) is not int or d < 1 for d in dims.values())):
            raise ValueError("dimensions must cover exactly the input labels with positive ints")
        if type(self.cap) is not int or self.cap < 1:
            raise ValueError("cap must be a positive exact integer")
        _label_set(self.output, "output")
        _label_set(self.fixed_slices, "fixed_slices")
        if not self.output <= labels:
            raise ValueError("unknown output label")
        owners = {x: frozenset(i for i, tensor in enumerate(self.inputs) if x in tensor)
                  for x in sorted(labels)}
        if any(len(own) < 2 and x not in self.output for x, own in owners.items()):
            raise ValueError("unary nonoutput reduction is outside the supported contract")
        if (type(self.editable) is not tuple or len(self.editable) > 6
                or any(not _label(x) for x in self.editable)
                or len(set(self.editable)) != len(self.editable)):
            raise ValueError("editable must be an exact tuple of <=6 unique labels")
        editable = frozenset(self.editable)
        allowed = editable | self.fixed_slices
        if (not allowed <= labels or allowed & self.output
                or editable & self.fixed_slices
                or any(dims[x] <= 1 for x in editable)):
            raise ValueError("invalid nonoutput slice domain")
        _path(self.region_path, "region_path")
        if (type(self.frontier_paths) is not tuple
                or not 1 <= len(self.frontier_paths) <= 10):
            raise ValueError("frontier_paths must be an exact tuple of 1..10 paths")
        for path in self.frontier_paths:
            _path(path, "frontier path")
        if len(set(self.frontier_paths)) != len(self.frontier_paths):
            raise ValueError("duplicate frontier path")

        # Iterative postorder: validate even very deep physical trees without a
        # Python-recursion restriction. Store groups for both leaves and results.
        groups, internal_paths, seen = {}, [], set()
        pending = [(self.tree, (), False)]
        while pending:
            node, path, visited = pending.pop()
            if type(node) is int:
                if not 0 <= node < len(self.inputs) or node in seen:
                    raise ValueError("out-of-range or duplicate physical input leaf")
                seen.add(node)
                groups[path] = frozenset((node,))
            elif type(node) is tuple and len(node) == 2:
                if not visited:
                    pending.extend(((node, path, True),
                                    (node[1], path + (1,), False),
                                    (node[0], path + (0,), False)))
                else:
                    groups[path] = groups[path + (0,)] | groups[path + (1,)]
                    internal_paths.append(path)
            else:
                raise ValueError("tree must contain only exact int leaves and binary tuples")
        if seen != set(range(len(self.inputs))):
            raise ValueError("full tree must cover every physical input exactly once")
        if self.region_path not in groups:
            raise ValueError("region_path does not identify an actual subtree")
        atoms = []
        for path in self.frontier_paths:
            if path not in groups or not _under(path, self.region_path):
                raise ValueError("frontier atom must be an actual regional subtree")
            atoms.append(groups[path])
        covered = set()
        for group in atoms:
            if covered & group:
                raise ValueError("frontier atoms must be disjoint, not nested")
            covered.update(group)
        if covered != groups[self.region_path]:
            raise ValueError("frontier atoms must partition the actual regional subtree")

        def boundary(group):
            return frozenset(x for x, own in owners.items()
                             if own & group and (x in self.output or own - group))

        frontier_labels = frozenset().union(*(boundary(group) for group in atoms))
        if not editable <= frontier_labels:
            raise ValueError("editable labels must occur at the unsliced frontier boundary")
        fixed, regional = [], []
        for path in sorted(internal_paths):
            if any(_under(path, atom) for atom in self.frontier_paths):
                kind = "ATOM_INTERNAL"
            elif _under(path, self.region_path):
                kind = "EDITABLE_REGIONAL"
            elif _under(self.region_path, path):
                kind = "ANCESTOR_RESULT"
            else:
                kind = "NONREGIONAL"
            node = InternalNode(path, tuple(sorted(groups[path])), kind)
            (regional if kind == "EDITABLE_REGIONAL" else fixed).append(node)
        if len(regional) != len(atoms) - 1:
            raise ValueError("unsupported regional frontier cut")
        object.__setattr__(self, "dims", MappingProxyType(dims))
        object.__setattr__(self, "owners", MappingProxyType(owners))
        object.__setattr__(self, "fixed_nodes", tuple(fixed))
        object.__setattr__(self, "baseline_regional_nodes", tuple(regional))


@dataclass(frozen=True)
class NodeVolume:
    """Exact contraction-result volume, NOT input size, live memory, or work."""

    node: InternalNode
    boundary: tuple[str, ...]
    volume: int

    def to_wire(self):
        return {"node": self.node.to_wire(), "boundary": list(self.boundary),
                "volume": _decimal(self.volume)}


@dataclass(frozen=True)
class BaselineObservation:
    """Editable baseline results only; violations here are NOT fixed certificates."""

    results: tuple[NodeVolume, ...]
    violations: tuple[NodeVolume, ...]

    def to_wire(self):
        return {"scope": "BASELINE_REGIONAL_ONLY_NONCERTIFICATE",
                "results": [x.to_wire() for x in self.results],
                "violations": [x.to_wire() for x in self.violations]}


@dataclass(frozen=True)
class ConfigurationReport:
    mask: int
    slices: frozenset[str]
    fixed_results: tuple[NodeVolume, ...]
    fixed_witnesses: tuple[NodeVolume, ...]
    baseline_observation: BaselineObservation

    @property
    def status(self):
        return (REJECTED_BY_FIXED_NODES if self.fixed_witnesses
                else UNREJECTED_BY_FIXED_NODES)

    def to_wire(self):
        return {"mask": _decimal(self.mask), "slices": sorted(self.slices),
                "status": self.status,
                "fixed_results": [x.to_wire() for x in self.fixed_results],
                "fixed_witnesses": [x.to_wire() for x in self.fixed_witnesses],
                "baseline_observation": self.baseline_observation.to_wire()}


@dataclass(frozen=True)
class CertificateReport:
    cap: int
    region_path: Path
    frontier_paths: tuple[Path, ...]
    editable: tuple[str, ...]
    fixed_slices: frozenset[str]
    configurations: tuple[ConfigurationReport, ...]

    @property
    def status(self):
        """Reject the whole finite domain only if EVERY mask has a fixed witness."""
        return (REJECTED_BY_FIXED_NODES
                if all(c.fixed_witnesses for c in self.configurations)
                else UNREJECTED_BY_FIXED_NODES)

    def to_wire(self):
        """JSON-ready builtins; all integers become exact decimal strings."""
        return {"contract": "OWNER_FIXED_RESULT_CAP_NECESSARY_ONLY_V1",
                "cap": _decimal(self.cap), "region_path": [_decimal(x) for x in self.region_path],
                "frontier_paths": [[_decimal(x) for x in p] for p in self.frontier_paths],
                "editable": list(self.editable), "fixed_slices": sorted(self.fixed_slices),
                "status": self.status,
                "configurations": [x.to_wire() for x in self.configurations]}


def certify(problem: Problem) -> CertificateReport:
    """Scan fixed internal groups and baseline regional groups for every mask.

    A fixed witness proves that no permitted regional rewire satisfies CAP for
    that configuration. No converse is computed or implied. All fixed results
    are reported even after a witness, and all masks are retained in bit order.
    No input-leaf volume is tested. Complexity is bounded by 64 scans of the
    supplied internal nodes and label owners, not a search over regional trees.
    """
    if type(problem) is not Problem:
        raise ValueError("certify requires an exact validated Problem")
    p = problem

    def measure(node, slices):
        group = frozenset(node.leaves)
        boundary = tuple(x for x, own in p.owners.items()
                         if x not in slices and own & group
                         and (x in p.output or own - group))
        return NodeVolume(node, boundary, prod(p.dims[x] for x in boundary))

    configurations = []
    for mask in range(1 << len(p.editable)):
        slices = p.fixed_slices | frozenset(x for i, x in enumerate(p.editable)
                                            if mask & (1 << i))
        fixed = tuple(measure(node, slices) for node in p.fixed_nodes)
        baseline = tuple(measure(node, slices) for node in p.baseline_regional_nodes)
        configurations.append(ConfigurationReport(
            mask, slices, fixed, tuple(x for x in fixed if x.volume > p.cap),
            BaselineObservation(baseline, tuple(x for x in baseline if x.volume > p.cap))))
    return CertificateReport(p.cap, p.region_path, p.frontier_paths, p.editable,
                             p.fixed_slices, tuple(configurations))
