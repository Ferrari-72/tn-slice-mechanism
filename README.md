# tn-slice-mechanism

Same-base, finite-domain decomposition of where a sliced contraction plan's improvement comes from: **slice changes, tree changes, or both together**.

Given an actual returned contraction tree I and its slice set, the tool:

1. builds a candidate catalogue of local regions (≤10 frontier nodes, ≤6 editable nodes, ≤64 slice masks) from I alone, before any optimisation;
2. selects domains by native order, by a pre-search capacity signal, and by a fixed-seed permutation;
3. in each domain, solves exactly for
   - **S** – slices only, tree fixed
   - **F** – region tree only, slices fixed
   - **J** – both jointly
   - **FS / SF** – strict alternation;
4. runs a fixed-node capacity certificate that checks whether nodes outside the editable region alone make restoring a slice infeasible;
5. re-scores every arm with an independent integer implementation in a separate process.

The aim is to test, with interventions on the same base, whether gains from "interleaving slicing and reconfiguration" come from **capacity-blocked slice restoration**. In that mechanism, a slice cannot be removed on the original tree because an intermediate would exceed the cap, but a different local tree makes the removal feasible.

## Results on QPE networks (K = 2^28)

All five ADCRS rows of [qpe-tn-benchmark](https://github.com/Ferrari-72/qpe-tn-benchmark) completed. The integer audits all match, and every certificate returned `UNREJECTED_BY_FIXED_NODES`. Each value is the reduction in total work relative to I:

| row / domain | S | F | J | slices I→J |
|---|---:|---:|---:|---|
| N48-s20 native2 | 0.02% | 14.13% | **14.16%** | **2→1** |
| N48-s20 other 3 domains | 0.02% | 3.7–5.3% | 3.8–5.3% | unchanged |
| N64 / N96 ADCRS rows | ≤0.02% | 0.00% | ≤0.03% | unchanged |

Capacity-blocked restoration occurred in 1 of 14 domains. Where gains exist they come almost entirely from tree changes, and the pre-search capacity signal did not choose better domains than native order. See `results/summary.txt` and the per-row control records.

For the `L_no_ADCRS` rows, the certificate evidence would be gigabytes per domain, so those rows were not analysed.

## Layout

| path | content |
|---|---|
| `tn_slice_mechanism/qpe_actual_incumbent_mechanism.py` | catalogue, selection, six arms, evidence writer |
| `tn_slice_mechanism/qpe_fixed_capacity_certificate.py` | fixed-node capacity certificate |
| `tn_slice_mechanism/qpe_fixed_capacity_trace_adapter.py` | adapter between plans and the certificate |
| `tn_slice_mechanism/qpe_j26_trace.py` | iterative exact scoring and tree utilities |
| `tn_slice_mechanism/qpe_mechanism_stack.py` | explicit-stack JSON codec and deep-tree helpers |
| `tn_slice_mechanism/mechanism_accept.py` | acceptance checks and the independent audit |
| `tests/test_mechanism_deep.py` | shallow v1/v2 differential, deep-path and malformed-input tests |

The acceptance script pins exact source hashes and expects the original research layout (`/runtime`, `/checks`, `/input`, `/output`). It is published to document how the results were checked, not as a general library API. Reusing it on other networks needs adaptation.

## License

MIT (see `LICENSE`). The local search region definition comes from a frozen candidate planner that is **not** included here.
